//! Local-disk [`VaultBlobStore`] (Phase 4): opaque vault bytes stored as
//! `<root>/<account-id>/<vault-id>.askrypt`, and — for the archived
//! generations of those files — `<root>/<account-id>/versions/<version-id>.askrypt`.
//!
//! Everything one account has stored therefore sits under a single
//! directory: one tree to back up, one tree to remove when the account goes.
//! The two stores stay distinct all the same, because `versions/` can never
//! collide with a uuid-named vault file.
//!
//! Writes are atomic — bytes go to a temp file in the same directory which
//! is then renamed over the target — so a crash mid-upload never leaves a
//! truncated vault where a good one was. Path components are uuids (plus
//! that one fixed segment), so no user-controlled strings ever reach the
//! filesystem.

use std::io::ErrorKind;
use std::path::PathBuf;

use async_trait::async_trait;
use uuid::Uuid;

use super::{AccountId, StoreError, VaultBlobStore, VaultId};

pub use super::types::DiskVaultBlobStore;

/// Where archived generations live inside an account's own directory.
const VERSIONS_SUBDIR: &str = "versions";

impl DiskVaultBlobStore {
    /// The live vaults: `<root>/<account-id>/<vault-id>.askrypt`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            subdir: None,
        }
    }

    /// The archived generations, keyed by version id and nested inside the
    /// account's own directory: `<root>/<account-id>/versions/<version-id>.askrypt`.
    /// Takes the *same* root as [`Self::new`].
    pub fn versions(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            subdir: Some(VERSIONS_SUBDIR),
        }
    }

    /// The directory this store writes into for `account_id` — which for the
    /// version store is a subdirectory of the account's, so deleting the
    /// account's directory takes the history with it.
    fn account_dir(&self, account_id: AccountId) -> PathBuf {
        let dir = self.root.join(account_id.to_string());
        match self.subdir {
            Some(subdir) => dir.join(subdir),
            None => dir,
        }
    }

    fn vault_path(&self, account_id: AccountId, vault_id: VaultId) -> PathBuf {
        self.account_dir(account_id)
            .join(format!("{vault_id}.askrypt"))
    }
}

fn io_err(e: std::io::Error) -> StoreError {
    StoreError::Backend(format!("blob io: {e}"))
}

#[async_trait]
impl VaultBlobStore for DiskVaultBlobStore {
    async fn put(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let dir = self.account_dir(account_id);
        tokio::fs::create_dir_all(&dir).await.map_err(io_err)?;
        // Random temp name so concurrent writes to the same vault can't
        // step on each other's temp file; the rename decides the winner.
        let tmp = dir.join(format!(".{vault_id}.{}.tmp", Uuid::new_v4()));
        tokio::fs::write(&tmp, bytes).await.map_err(io_err)?;
        if let Err(e) = tokio::fs::rename(&tmp, self.vault_path(account_id, vault_id)).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(io_err(e));
        }
        Ok(())
    }

    async fn get(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        match tokio::fs::read(self.vault_path(account_id, vault_id)).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    async fn delete(&self, account_id: AccountId, vault_id: VaultId) -> Result<(), StoreError> {
        match tokio::fs::remove_file(self.vault_path(account_id, vault_id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(io_err(e)),
        }
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        match tokio::fs::remove_dir_all(self.account_dir(account_id)).await {
            // No directory means no vaults were ever stored — nothing to do.
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, DiskVaultBlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskVaultBlobStore::new(dir.path().join("vaults"));
        (dir, store)
    }

    #[tokio::test]
    async fn blob_lifecycle_on_disk() {
        let (dir, store) = store();
        let account_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();

        store
            .put(account_id, vault_id, b"PK\x03\x04v1")
            .await
            .unwrap();
        assert_eq!(
            store.get(account_id, vault_id).await.unwrap(),
            Some(b"PK\x03\x04v1".to_vec())
        );
        // Overwrite replaces the content and leaves no temp files behind.
        store
            .put(account_id, vault_id, b"PK\x03\x04v2")
            .await
            .unwrap();
        assert_eq!(
            store.get(account_id, vault_id).await.unwrap(),
            Some(b"PK\x03\x04v2".to_vec())
        );
        let account_dir = dir.path().join("vaults").join(account_id.to_string());
        let entries: Vec<_> = std::fs::read_dir(&account_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec![format!("{vault_id}.askrypt")]);

        // Another account cannot see it.
        assert!(store.get(Uuid::new_v4(), vault_id).await.unwrap().is_none());

        store.delete(account_id, vault_id).await.unwrap();
        assert!(store.get(account_id, vault_id).await.unwrap().is_none());
        assert!(matches!(
            store.delete(account_id, vault_id).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn versions_live_under_the_account_directory_not_beside_it() {
        let (dir, live) = store();
        let root = dir.path().join("vaults");
        let versions = DiskVaultBlobStore::versions(&root);
        let account_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();

        live.put(account_id, vault_id, b"PK\x03\x04live")
            .await
            .unwrap();
        versions
            .put(account_id, version_id, b"PK\x03\x04old")
            .await
            .unwrap();

        let account_dir = root.join(account_id.to_string());
        assert!(account_dir.join(format!("{vault_id}.askrypt")).is_file());
        assert!(
            account_dir
                .join("versions")
                .join(format!("{version_id}.askrypt"))
                .is_file()
        );
        // The two stores address different files even for the same id, and
        // neither can read the other's.
        assert!(live.get(account_id, version_id).await.unwrap().is_none());
        assert!(versions.get(account_id, vault_id).await.unwrap().is_none());

        // Dropping the account's directory takes its history with it — the
        // whole point of nesting rather than storing history in a tree of
        // its own.
        live.delete_for_account(account_id).await.unwrap();
        assert!(!account_dir.exists());
        assert!(
            versions
                .get(account_id, version_id)
                .await
                .unwrap()
                .is_none()
        );
        // And removing just the history is still idempotent afterwards.
        versions.delete_for_account(account_id).await.unwrap();
    }

    #[tokio::test]
    async fn delete_for_account_removes_dir_and_is_idempotent() {
        let (dir, store) = store();
        let account_id = Uuid::new_v4();
        store
            .put(account_id, Uuid::new_v4(), b"PK\x03\x04a")
            .await
            .unwrap();
        store
            .put(account_id, Uuid::new_v4(), b"PK\x03\x04b")
            .await
            .unwrap();

        store.delete_for_account(account_id).await.unwrap();
        assert!(
            !dir.path()
                .join("vaults")
                .join(account_id.to_string())
                .exists()
        );
        // Idempotent: an account with no stored vaults is fine.
        store.delete_for_account(account_id).await.unwrap();
    }
}
