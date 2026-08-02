//! Filesystem implementation of [`VaultStorage`].

use super::{StorageError, VaultStorage};
use std::path::{Path, PathBuf};

/// Vault stored as a file on the local filesystem.
pub struct LocalFileStorage {
    path: PathBuf,
}

impl LocalFileStorage {
    /// Create a storage backend for the given file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file path this storage reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl VaultStorage for LocalFileStorage {
    fn read(&self) -> Result<Vec<u8>, StorageError> {
        Ok(std::fs::read(&self.path)?)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), StorageError> {
        Ok(std::fs::write(&self.path, bytes)?)
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn location(&self) -> String {
        self.path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::test_vault;

    #[test]
    fn local_file_storage_read_missing_is_io_error() {
        let storage = LocalFileStorage::new(
            std::env::temp_dir().join("askrypt_storage_missing_does_not_exist.askrypt"),
        );
        assert!(!storage.exists());
        match storage.read() {
            Err(StorageError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn local_file_storage_vault_roundtrip() {
        let (file, _) = test_vault();
        let path = std::env::temp_dir().join(format!(
            "askrypt_storage_roundtrip_{}.askrypt",
            std::process::id()
        ));
        let storage = LocalFileStorage::new(&path);

        storage.save_vault(&file).expect("save failed");
        assert!(storage.exists());
        assert_eq!(storage.location(), path.display().to_string());

        let loaded = storage.load_vault().expect("load failed");
        assert_eq!(loaded, file);

        std::fs::remove_file(&path).ok();
    }
}
