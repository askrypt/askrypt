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
    /// The open handle on the sidecar lock file, while this instance holds it.
    /// Dropping it releases the lock, which is why nothing else needs to.
    lock: Mutex<Option<std::fs::File>>,
}

impl LocalFileStorage {
    /// Create a storage backend for the given file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last: Mutex::new(None),
            lock: Mutex::new(None),
        }
    }

    /// The file path this storage reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Claim this vault for as long as this instance lives.
    ///
    /// An open vault is *read from* the whole time it is open: a save streams
    /// its unchanged attachments straight out of the archive it is about to
    /// replace. Two instances editing one file would each be pulling blobs out
    /// from under the other, so the second one is turned away with
    /// [`StorageError::Locked`].
    ///
    /// The lock is taken on a **sidecar**, `<vault>.lock`, and not on the vault
    /// file itself, for one reason that applies everywhere and one that applies
    /// on Windows.
    ///
    /// The decisive one: **a save replaces the file.** The new archive is
    /// assembled beside the old one and renamed over it — it has to be, since
    /// writing it *reads* the one it replaces. A lock on the vault would then
    /// be held on an inode nothing points at any more, and the very next
    /// process to ask could take a lock on the new file and get it. One save
    /// and the guarantee is gone. The sidecar is never renamed, so it keeps its
    /// identity for the life of the session.
    ///
    /// The Windows one: `LockFileEx` is mandatory, and `File::try_lock` takes
    /// the whole 64-bit range, so a lock on the vault's own bytes would stop
    /// *our own* second handle from reading a carried member out of it. On Unix
    /// `flock` is advisory and this does not arise — which is why it is the
    /// second reason and not the first.
    ///
    /// Calling this twice on one instance is a no-op — the lock is already held
    /// and re-taking it on the same handle would say nothing.
    ///
    /// **Only a lock someone else holds is an error.** If the sidecar cannot be
    /// created (a read-only directory) or the filesystem does not support locks
    /// (some network mounts), this succeeds *without* one: the lock keeps two
    /// apps from writing one archive, and neither situation is one this app
    /// could write in. Refusing would make a vault on read-only media
    /// unopenable, which it never was before the lock existed.
    fn claim(&self) -> Result<(), StorageError> {
        let mut held = self.lock.lock().expect("local file lock poisoned");
        if held.is_some() {
            return Ok(());
        }

        let path = self.lock_path();
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path);

        let file = match opened {
            Ok(file) => file,
            // The sidecar could not be created: a read-only directory, a
            // read-only mount, a folder this user may read but not write.
            // **Not a reason to refuse the vault.** The lock exists to keep two
            // apps from writing one archive, and nothing here can write one
            // anyway — the save would fail long before the lock mattered.
            // Refusing would make a vault on a CD or a read-only share
            // unopenable, which it never was before there was a lock at all.
            Err(_) => return Ok(()),
        };

        match file.try_lock() {
            Ok(()) => {
                *held = Some(file);
                Ok(())
            }
            // Someone really is holding it. The one case that refuses.
            Err(std::fs::TryLockError::WouldBlock) => Err(StorageError::Locked(self.location())),
            // The filesystem does not do locks — some network mounts answer
            // `ENOLCK` or `EOPNOTSUPP`. Same reasoning as above: an advisory
            // lock that cannot be taken is a guarantee we do not get, not a
            // vault we should decline to open.
            Err(std::fs::TryLockError::Error(_)) => Ok(()),
        }
    }

    /// Whether this instance is holding the vault open.
    pub fn holds_lock(&self) -> bool {
        self.lock
            .lock()
            .expect("local file lock poisoned")
            .is_some()
    }

    /// The sidecar the lock is taken on, `<vault>.lock`.
    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        self.path.with_file_name(name)
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

    /// Where a replacement archive is assembled before it takes over.
    ///
    /// Beside the destination, so the hand-over below is a rename within one
    /// filesystem — which is the only way to swap a file without ever leaving a
    /// half-written one in its place. The pid keeps two instances (which the
    /// sidecar lock already forbids for one vault, but not across vaults in one
    /// directory) from colliding.
    fn staging_path(&self) -> PathBuf {
        let mut name = std::ffi::OsString::from(".");
        name.push(self.path.file_name().unwrap_or_default());
        name.push(format!(".tmp-{}", std::process::id()));
        self.path.with_file_name(name)
    }

    /// Move a finished archive into place, atomically where the filesystem
    /// allows it.
    ///
    /// `rename` is the atomic swap and the case that always applies to our own
    /// staging file. A caller staging somewhere else — a save whose scratch
    /// directory is on another filesystem — gets `EXDEV`, and the copy is the
    /// fallback: not atomic, but the alternative is refusing to save at all.
    fn publish(&self, staged: &Path) -> Result<(), StorageError> {
        match std::fs::rename(staged, &self.path) {
            Ok(()) => {}
            Err(_) => {
                std::fs::copy(staged, &self.path)?;
                std::fs::remove_file(staged).ok();
            }
        }
        self.remember();
        Ok(())
    }
}

/// Releasing the lock is dropping the handle, so this only tidies the sidecar
/// away. Best effort on purpose: another instance may already be waiting on it,
/// and a stray zero-byte file is not worth failing anything over.
impl Drop for LocalFileStorage {
    fn drop(&mut self) {
        let held = self
            .lock
            .lock()
            .expect("local file lock poisoned")
            .take()
            .is_some();
        if held {
            std::fs::remove_file(self.lock_path()).ok();
        }
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
        // Staged and renamed rather than written in place: a truncating write
        // that dies half way through — out of space, power cut, a panic —
        // leaves the user with neither the old vault nor the new one.
        let staging = self.staging_path();
        std::fs::write(&staging, bytes)?;
        self.publish(&staging)
    }

    fn acquire_lock(&self) -> Result<(), StorageError> {
        self.claim()
    }

    fn archive_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn read_to_path(&self, dest: &Path) -> Result<(), StorageError> {
        // A caller that wants a copy still gets one, but nothing in this crate
        // asks: `archive_path` already hands over the file itself.
        std::fs::copy(&self.path, dest)?;
        Ok(())
    }

    fn write_from_path(&self, src: &Path) -> Result<(), StorageError> {
        self.publish(src)
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
    use crate::AskryptFile;
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
    fn a_second_instance_cannot_claim_an_open_vault() {
        // An open vault is read from for as long as it is open — a save streams
        // its unchanged attachments out of the archive it is replacing — so two
        // apps holding one file would each be pulling blobs out from under the
        // other.
        let path = scratch("lock_exclusive");
        let (file, _) = test_vault();
        let first = LocalFileStorage::new(&path);
        first.save_vault(&file).expect("save failed");

        first
            .acquire_lock()
            .expect("the first claim should succeed");
        assert!(first.holds_lock());
        // Taking it again on the same handle says nothing and must not fail.
        first.acquire_lock().expect("re-claiming is a no-op");

        let second = LocalFileStorage::new(&path);
        match second.acquire_lock() {
            Err(StorageError::Locked(location)) => {
                assert_eq!(location, path.display().to_string())
            }
            other => panic!("expected Locked, got {:?}", other),
        }
        assert!(!second.holds_lock());

        // Dropping the holder releases it, which is what makes closing a vault
        // enough — nothing has to remember to unlock.
        drop(first);
        second
            .acquire_lock()
            .expect("the lock should be free once the holder is gone");

        drop(second);
        std::fs::remove_file(&path).ok();
    }

    /// A vault the user can read but whose directory they cannot write to —
    /// read-only media, a read-only share — must still open. The lock is there
    /// to stop two apps *writing* one archive, and nothing can write here.
    #[cfg(unix)]
    #[test]
    fn a_vault_in_a_read_only_directory_still_opens() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("askrypt_read_only_{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("vault.askrypt");

        let (file, _) = test_vault();
        LocalFileStorage::new(&path)
            .save_vault(&file)
            .expect("save failed");
        // The sidecar the save's own lock would have left; the point is the
        // *next* open, with nowhere to put one.
        std::fs::remove_file(dir.join("vault.askrypt.lock")).ok();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
            .expect("make the directory read-only");

        let storage = LocalFileStorage::new(&path);
        let claimed = storage.acquire_lock();

        // Restore before asserting, so a failure still leaves a removable dir.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();

        assert!(
            claimed.is_ok(),
            "a vault on read-only media was refused: {:?}",
            claimed.err()
        );
        // No lock was taken — the guarantee is simply unavailable here.
        assert!(!storage.holds_lock());
        // And the vault itself reads back.
        assert!(storage.load_vault().is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_save_lands_whole_or_not_at_all() {
        // Written to a staging file and renamed, never truncated in place: a
        // write that dies half way through used to leave the user with neither
        // the old vault nor the new one.
        let path = scratch("atomic_write");
        let (file, _) = test_vault();
        let storage = LocalFileStorage::new(&path);
        storage.save_vault(&file).expect("save failed");
        let first = std::fs::read(&path).expect("the vault should be there");

        storage.save_vault(&file).expect("second save failed");
        let second = std::fs::read(&path).expect("the vault should still be there");

        // Both are complete archives, and no staging file is left behind.
        assert!(AskryptFile::from_bytes(&first).is_ok());
        assert!(AskryptFile::from_bytes(&second).is_ok());
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".{}", path.file_name().unwrap().to_string_lossy()))
            })
            .collect();
        assert!(leftovers.is_empty(), "a staging file survived the save");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_vault_can_be_saved_over_the_archive_it_is_reading_from() {
        // The ordinary desktop save, and the ordering with the most to go
        // wrong: writing the replacement *reads* the file being replaced,
        // because every unchanged attachment is streamed straight across. Get
        // it wrong — truncate first, or hand the file over before the copy is
        // done — and saving a vault deletes its own attachments.
        let dir =
            std::env::temp_dir().join(format!("askrypt_save_over_self_{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("vault.askrypt");

        let (file, mut secrets) = test_vault();
        let master = {
            let questions_data = file.get_questions_data("Smith".into()).unwrap();
            file.decrypt_with_master(&questions_data, vec!["Fluffy".to_string()])
                .unwrap()
                .1
        };

        // Seal a file, put it in a vault, and write that vault out.
        let plaintext = b"the contents of an attached file";
        let src = dir.join("attach.bin");
        std::fs::write(&src, plaintext).unwrap();
        let sealed = dir.join("attach.sealed");
        let mut meta = crate::seal_attachment_to_file(&src, &sealed, &master).unwrap();
        meta.name = "attach.bin".to_string();
        secrets[0].attachments = vec![meta.clone()];

        let mut attachments = crate::Attachments::new();
        attachments.insert_sealed(meta.id.clone(), sealed);

        let storage = LocalFileStorage::new(&path);
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
        ];
        let answers = vec!["Smith".to_string(), "Fluffy".to_string()];
        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            secrets.clone(),
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap();
        storage.save_vault(&first).unwrap();

        // Reopen — now the attachment is carried by *this* file — and save
        // straight back over it, three times, which is what an afternoon of
        // editing does.
        for round in 0..3 {
            let reopened = AskryptFile::from_path(&path).expect("the vault should reopen");
            assert_eq!(
                reopened.attachments.len(),
                1,
                "the attachment was gone after {round} save(s) over itself"
            );
            let next = AskryptFile::create(
                questions.clone(),
                answers.clone(),
                secrets.clone(),
                Some(6000),
                false,
                Some(&master),
                &reopened.attachments,
            )
            .unwrap();
            storage.save_vault(&next).unwrap();
        }

        // And after all that it still decrypts to what went in.
        let out = dir.join("attach.out");
        crate::extract_attachment(&path, &meta, &master, &out).expect("it should still open");
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);

        std::fs::remove_dir_all(&dir).ok();
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
