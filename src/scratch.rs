//! The running app's scratch directory.
//!
//! Attachments are never held in memory: a freshly attached file is encrypted
//! straight to a file here, and a cloud vault — which has no local archive of
//! its own to stream unchanged attachments out of — gets a copy of its archive
//! here too. Both are ciphertext, so nothing in this directory is a secret in
//! the clear; what they are is *working files*, and the point of this module is
//! that they never outlive the process that made them.
//!
//! Everything lives under one per-process directory, `session-<pid>`, and that
//! directory holds an exclusive lock on a `.lock` file inside it for as long as
//! the app runs. The lock is what makes [`Scratch::sweep`] exact rather than a
//! guess: a sibling session directory whose lock can be *taken* belongs to a
//! process that is no longer running, so it is safe to delete. Age heuristics
//! and pid probing would both risk deleting a live instance's working files, and
//! a deleted sealed attachment is a file the user loses.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::settings::AppSettings;

/// The prefix every session directory carries, and the whole of what
/// [`Scratch::sweep`] considers.
const SESSION_PREFIX: &str = "session-";

/// The lock file inside a session directory, held for the life of the process.
const LOCK_NAME: &str = ".lock";

/// One running app's working directory for attachment and vault scratch.
pub struct Scratch {
    dir: PathBuf,
    /// Held, never read. Dropping it releases the lock, which is what tells the
    /// next instance's sweep that this directory is finished with.
    _lock: File,
    /// Bumped per handed-out path, so two files never collide within a session.
    counter: AtomicU64,
}

impl Scratch {
    /// Claim a scratch directory for this process, sweeping away any left
    /// behind by one that is gone.
    ///
    /// Answers `None` when the platform has no cache directory or it cannot be
    /// created. That is not fatal — see [`crate::manager`], which degrades to
    /// refusing to attach rather than to refusing to open a vault.
    pub fn open() -> Option<Self> {
        let root = AppSettings::cache_dir()?;
        std::fs::create_dir_all(&root).ok()?;

        // Before claiming ours, so a long-running app is not the one holding on
        // to a crashed predecessor's files.
        Self::sweep(&root);

        let dir = root.join(format!("{SESSION_PREFIX}{}", std::process::id()));
        // A pid is reused eventually; whatever wore this one before us is gone.
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).ok()?;
        restrict(&dir);

        let lock = File::create(dir.join(LOCK_NAME)).ok()?;
        lock.try_lock().ok()?;

        Some(Self {
            dir,
            _lock: lock,
            counter: AtomicU64::new(0),
        })
    }

    /// A path for one freshly sealed attachment's ciphertext.
    ///
    /// A counter rather than the attachment's own id, because the id is minted
    /// by the sealing itself and does not exist yet when the destination has to
    /// be named. Either way the name says nothing about the file — which
    /// matters: the scratch directory is on disk like any other, and a listing
    /// of it must reveal no more than the archive's own listing does.
    pub fn sealed_path(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!("blob-{n}"))
    }

    /// A path for a copy of a vault's archive.
    ///
    /// A cloud vault has no local file to stream carried attachments out of, so
    /// it is spilled here on open and again on every reload. The counter is
    /// what stops a reload from writing over the archive the open vault is
    /// still reading from.
    pub fn vault_path(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!("vault-{n}.askrypt"))
    }

    /// A path to assemble a replacement archive at, for a destination that is
    /// not a local file.
    ///
    /// A local vault stages beside itself instead — see
    /// `LocalFileStorage::write_from_path` — because only a rename within one
    /// filesystem can swap a file atomically.
    pub fn staging_path(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!("staging-{n}.askrypt"))
    }

    /// Whether `path` is one of ours.
    ///
    /// The test before deleting a superseded archive, and it has to be this
    /// rather than anything about the backend: a Save As moves a vault between
    /// homes, so the archive being superseded may be a *local vault file the
    /// user owns*. Only a file in here was made by us and is ours to remove.
    pub fn owns(&self, path: &Path) -> bool {
        path.parent() == Some(self.dir.as_path())
    }

    /// Empty this session's directory, keeping the lock.
    ///
    /// The counterpart to [`Self::discard`] for the moment there is nothing
    /// left to discard *for*: with no vault open, every file in here — a
    /// closed cloud vault's copy of its archive, an attachment sealed for an
    /// editor that was cancelled — belongs to nobody, and waiting for
    /// [`Drop`] would leave them on disk for the rest of the run. Only this
    /// session's own directory is touched, so a live sibling is as safe from
    /// it as it is from the sweep.
    ///
    /// Best effort throughout: a file a worker is still writing reappears, and
    /// the directory goes on exit either way.
    pub fn clear(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_name() == LOCK_NAME {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).ok();
            } else {
                std::fs::remove_file(&path).ok();
            }
        }
    }

    /// Delete a working file we no longer need, best effort.
    ///
    /// Never a reason to fail anything: the directory goes on shutdown, and a
    /// sweep takes it after a crash, so the worst a failure here costs is disk
    /// until the app next starts.
    pub fn discard(path: &Path) {
        std::fs::remove_file(path).ok();
    }

    /// Remove every session directory whose owner is gone.
    ///
    /// The lock is the liveness test: if it can be taken, nobody holds it, and
    /// nobody holds it only when the process that did has exited. A directory
    /// with no lock file at all is one whose owner died between creating it and
    /// locking it, which is likewise finished with.
    fn sweep(root: &Path) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let is_session = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(SESSION_PREFIX));
            if !is_session {
                continue;
            }

            match File::open(path.join(LOCK_NAME)) {
                // Still held: a live instance owns this directory.
                Ok(lock) if lock.try_lock().is_err() => continue,
                Ok(lock) => {
                    // Release before removing, so the handle does not outlive
                    // the file on platforms that mind.
                    lock.unlock().ok();
                }
                Err(_) => {}
            }
            std::fs::remove_dir_all(&path).ok();
        }
    }
}

/// Dropping the scratch takes its working files with it — the sealed
/// attachments of a vault that was never saved among them, which is the point:
/// nothing survives the session that made it.
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Make the directory the user's own, where the platform has a notion of it.
///
/// Everything inside is ciphertext, so this is defence in depth rather than the
/// thing keeping an attachment secret — but a shared `/home` with lax defaults
/// has no business handing a vault's blobs to the next account along.
fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets its own root: they run in parallel in one process, and
    /// `Scratch::open` reads the real cache directory.
    fn root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "askrypt_scratch_test_{}_{}",
            tag,
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("test root");
        dir
    }

    /// Stand in for a session directory belonging to a process that has exited:
    /// the lock file is there, nothing holds it.
    fn abandoned(root: &Path, pid: u32) -> PathBuf {
        let dir = root.join(format!("{SESSION_PREFIX}{pid}"));
        std::fs::create_dir_all(&dir).expect("session directory");
        File::create(dir.join(LOCK_NAME)).expect("lock file");
        std::fs::write(dir.join("deadbeef.blob"), b"sealed bytes").expect("blob");
        dir
    }

    #[test]
    fn a_session_nobody_holds_is_swept() {
        let root = root("swept");
        let dead = abandoned(&root, 999_001);
        assert!(dead.exists());

        Scratch::sweep(&root);

        assert!(!dead.exists(), "an abandoned session survived the sweep");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_session_still_held_is_left_alone() {
        let root = root("held");
        let live = abandoned(&root, 999_002);
        // Hold it the way a running instance does.
        let lock = File::open(live.join(LOCK_NAME)).expect("lock file");
        lock.try_lock().expect("lock should be free");

        Scratch::sweep(&root);

        assert!(
            live.exists(),
            "the sweep deleted a live instance's working files"
        );
        lock.unlock().ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// A scratch directory rooted wherever the test wants one, since
    /// `Scratch::open` reads the real cache directory.
    fn scratch_at(dir: PathBuf) -> Scratch {
        std::fs::create_dir_all(&dir).expect("session directory");
        let lock = File::create(dir.join(LOCK_NAME)).expect("lock file");
        lock.try_lock().expect("lock should be free");
        Scratch {
            dir,
            _lock: lock,
            counter: AtomicU64::new(0),
        }
    }

    #[test]
    fn clearing_takes_the_working_files_and_keeps_the_lock() {
        let root = root("clear");
        let scratch = scratch_at(root.join(format!("{SESSION_PREFIX}999003")));
        let vault = scratch.vault_path();
        let blob = scratch.sealed_path();
        std::fs::write(&vault, b"spilled archive").expect("vault copy");
        std::fs::write(&blob, b"sealed bytes").expect("blob");

        scratch.clear();

        assert!(!vault.exists(), "a closed vault's copy survived the clear");
        assert!(!blob.exists(), "an orphaned attachment survived the clear");
        assert!(
            scratch.dir.join(LOCK_NAME).exists(),
            "the clear took the lock the sweep reads"
        );
        drop(scratch);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn clearing_touches_only_this_session() {
        let root = root("clear_siblings");
        let scratch = scratch_at(root.join(format!("{SESSION_PREFIX}999004")));
        let other = abandoned(&root, 999_005);

        scratch.clear();

        assert!(
            other.join("deadbeef.blob").exists(),
            "the clear reached into another session's directory"
        );
        drop(scratch);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn anything_that_is_not_a_session_is_left_alone() {
        // The sweep runs over the whole cache directory, so it must touch only
        // what it put there.
        let root = root("bystanders");
        let other = root.join("something-else");
        std::fs::create_dir_all(&other).expect("directory");
        let file = root.join("a-file");
        std::fs::write(&file, b"not ours").expect("file");

        Scratch::sweep(&root);

        assert!(other.exists());
        assert!(file.exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
