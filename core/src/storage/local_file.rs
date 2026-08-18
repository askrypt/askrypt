//! Filesystem implementation of [`VaultStorage`].

use super::{RemoteRevision, Revision, StorageError, VaultStorage};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Vault stored as a file on the local filesystem.
pub struct LocalFileStorage {
    path: PathBuf,
    /// The revision of the bytes this instance last read or wrote, so a caller
    /// following the file can tell an outside rewrite from its own save.
    last: Mutex<Option<Revision>>,
}

impl LocalFileStorage {
    /// Create a storage backend for the given file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last: Mutex::new(None),
        }
    }

    /// The file path this storage reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file's revision as it is on disk right now, or `None` if it is not
    /// there.
    ///
    /// Modification time plus length. This is a *heuristic*: a rewrite that
    /// lands within the same filesystem timestamp tick and keeps the file
    /// exactly as long goes unnoticed. Hashing the contents would be exact but
    /// costs a full read, and this is asked on a timer — which is the whole
    /// reason it has to stay cheap.
    fn stat_revision(&self) -> Result<Option<Revision>, StorageError> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // A filesystem that cannot report a modification time leaves only the
        // length, which is why the two are joined rather than one preferred.
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        Ok(Some(Revision(format!("{}:{}", modified, metadata.len()))))
    }

    /// Record where we now stand, so our own write is never mistaken for
    /// someone else's.
    fn remember(&self) {
        let seen = self.stat_revision().unwrap_or(None);
        *self.last.lock().expect("local file revision lock poisoned") = seen;
    }
}

impl VaultStorage for LocalFileStorage {
    fn read(&self) -> Result<Vec<u8>, StorageError> {
        // Stat *before* reading: a writer that lands between the two leaves a
        // revision older than the bytes we got, so the next probe re-reads.
        // The other order would record a revision newer than our bytes and
        // miss that write entirely.
        let seen = self.stat_revision().unwrap_or(None);
        let bytes = std::fs::read(&self.path)?;
        *self.last.lock().expect("local file revision lock poisoned") = seen;
        Ok(bytes)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), StorageError> {
        std::fs::write(&self.path, bytes)?;
        self.remember();
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn location(&self) -> String {
        self.path.display().to_string()
    }

    fn revision(&self) -> Option<Revision> {
        self.last
            .lock()
            .expect("local file revision lock poisoned")
            .clone()
    }

    fn current_revision(&self) -> Result<Option<RemoteRevision>, StorageError> {
        // The stamp halves would mean opening and parsing the file, which is
        // exactly what a cheap probe must not do. The caller reads them off
        // the vault once it decides to reload.
        Ok(self.stat_revision()?.map(|revision| RemoteRevision {
            revision,
            host: None,
            saved_at: None,
        }))
    }

    fn adopt_revision(&self, revision: &Revision) {
        *self.last.lock().expect("local file revision lock poisoned") = Some(revision.clone());
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

    /// Each test gets its own path: they run in parallel in one process.
    fn scratch(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "askrypt_storage_{}_{}.askrypt",
            tag,
            std::process::id()
        ))
    }

    #[test]
    fn our_own_write_does_not_read_as_someone_elses() {
        let path = scratch("revision_after_write");
        let (file, _) = test_vault();
        let storage = LocalFileStorage::new(&path);

        storage.save_vault(&file).expect("save failed");

        // The whole point: after writing, what we think we are on and what is
        // actually there agree, so a follower sees no change.
        let ours = storage.revision().expect("no revision after a write");
        let theirs = storage
            .current_revision()
            .expect("probe failed")
            .expect("file is missing");
        assert_eq!(ours, theirs.revision);
        // A local file cannot report the stamp without being opened.
        assert_eq!(theirs.host, None);
        assert_eq!(theirs.saved_at, None);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_outside_rewrite_moves_the_revision() {
        let path = scratch("revision_outside_write");
        let (file, _) = test_vault();
        let storage = LocalFileStorage::new(&path);
        storage.save_vault(&file).expect("save failed");
        let ours = storage.revision().expect("no revision after a write");

        // Stand in for another process. The length has to change too: mtime
        // granularity alone is not enough to guarantee a difference within one
        // test, which is exactly the limitation `stat_revision` documents.
        std::fs::write(&path, b"PK\x03\x04 someone else was here").expect("rewrite failed");

        let theirs = storage
            .current_revision()
            .expect("probe failed")
            .expect("file is missing");
        assert_ne!(ours, theirs.revision);
        // Probing must not move what *we* are on — that is the caller's call.
        assert_eq!(storage.revision(), Some(ours));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn adopting_a_revision_is_what_moves_ours() {
        let path = scratch("revision_adopt");
        let (file, _) = test_vault();
        let storage = LocalFileStorage::new(&path);
        storage.save_vault(&file).expect("save failed");

        std::fs::write(&path, b"PK\x03\x04 someone else was here").expect("rewrite failed");
        let theirs = storage
            .current_revision()
            .expect("probe failed")
            .expect("file is missing")
            .revision;

        storage.adopt_revision(&theirs);
        assert_eq!(storage.revision(), Some(theirs));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_file_probes_as_gone_rather_than_failing() {
        let storage = LocalFileStorage::new(scratch("revision_missing_never_created"));
        assert_eq!(storage.revision(), None);
        assert!(matches!(storage.current_revision(), Ok(None)));
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
