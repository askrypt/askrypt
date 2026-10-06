//! Offline copies of server vaults.
//!
//! Every time a server vault is downloaded or saved, the archive that just
//! crossed the wire is also kept in `<cache>/vaults/` — the same ciphertext the
//! server holds, nothing decrypted. When the server later cannot be reached,
//! the copy is offered instead (`confirm::Kind::OpenOffline`), and opened with a
//! backend pinned to the ETag it was kept at
//! ([`askrypt::ServerStorage::pinned`]), so a save once the server is back is
//! conflict-checked against *that* version rather than whatever the server
//! holds by then.
//!
//! The copy is only ever written from bytes the server has: never from an edit
//! made to the copy itself. Writing it is a courtesy, so a failure — a full
//! disk, a read-only cache — is reported as one status line and never stops
//! the open or the save it rides on.
//!
//! The directory is a sibling of the per-process `session-*` directories in
//! [`crate::scratch`], which `Scratch::sweep` never considers, so the copies
//! survive a restart.

use std::fs;
use std::path::{Path, PathBuf};

use askrypt::{AskryptFile, VaultStorage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::settings::{AppSettings, VaultLocation};

/// Where the copies live, whether or not the setting is on — read it through
/// [`AppSettings::offline_dir`] for anything but removing them.
pub fn dir() -> Option<PathBuf> {
    AppSettings::cache_dir().map(|cache| cache.join("vaults"))
}

/// What is known about one copy, kept beside it as `<key>.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    /// The vault this is a copy of. Stored so the sidecar says whose it is;
    /// lookups go by [`key`], never by reading this back.
    pub location: VaultLocation,
    /// The server's ETag for exactly these bytes.
    pub etag: String,
    /// When the copy was taken, RFC 3339 UTC.
    pub cached_at: String,
}

impl Meta {
    /// The cached-at time, for the dialog and the status line.
    pub fn cached_at_display(&self) -> String {
        crate::data::format_rfc3339_local(&self.cached_at)
    }
}

/// A copy found on disk.
#[derive(Debug, Clone)]
pub struct OfflineCopy {
    pub archive: PathBuf,
    pub meta: Meta,
}

/// The file stem a server vault's copy is kept under, or `None` for a local
/// vault, which needs no copy.
///
/// A hash rather than the name: the name is server-supplied text, and a `..`
/// or a separator in it must not decide where a file is written. Server and
/// account are part of it, so two accounts' vaults of the same name do not
/// share a copy.
fn key(location: &VaultLocation) -> Option<String> {
    let VaultLocation::Server {
        base_url,
        email,
        name,
    } = location
    else {
        return None;
    };
    let mut hash = Sha256::new();
    for part in [base_url, email, name] {
        hash.update(part.as_bytes());
        // A separator no part can contain, so ("ab", "c") and ("a", "bc") differ.
        hash.update([0u8]);
    }
    Some(
        hash.finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// Where one vault's copy should be written: everything a worker needs, built
/// on the main thread so a setting changed mid-task does not apply to it.
#[derive(Debug, Clone)]
pub struct Target {
    dir: PathBuf,
    location: VaultLocation,
}

impl Target {
    /// A target for `location`, or `None` when nothing should be kept — a
    /// local vault, the setting off, or no cache directory.
    pub fn new(settings: &AppSettings, location: &VaultLocation) -> Option<Self> {
        if !location.is_server() {
            return None;
        }
        Some(Target {
            dir: settings.offline_dir()?,
            location: location.clone(),
        })
    }

    /// Keep the archive `file` was just read from or written to.
    /// **Worker-thread only** — it copies the whole archive.
    ///
    /// `storage` is the backend that moved those bytes, and so the one that
    /// knows their ETag. The `Err` is the status-line text.
    pub fn keep(&self, file: &AskryptFile, storage: &dyn VaultStorage) -> Result<(), String> {
        let result = (|| {
            let archive = file
                .attachments
                .origin()
                .ok_or_else(|| "nothing to copy".to_string())?;
            let etag = storage
                .revision()
                .ok_or_else(|| "the server did not name the version".to_string())?;
            store(&self.dir, &self.location, archive, &etag.0)
        })();
        result.map_err(|e| {
            eprintln!("WARNING: Failed to keep an offline copy: {}", e);
            format!("couldn't update the offline copy — {}", e)
        })
    }
}

/// Write `archive` as the copy of `location`, at `etag`.
///
/// Archive first, sidecar second, each staged and renamed into place: a copy
/// is only ever found (see [`load`]) once both halves are whole, and a write
/// that dies halfway leaves the previous copy readable.
fn store(dir: &Path, location: &VaultLocation, archive: &Path, etag: &str) -> Result<(), String> {
    let key = key(location).ok_or_else(|| "not a server vault".to_string())?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;

    let dest = dir.join(format!("{key}.askrypt"));
    let staged = dir.join(format!("{key}.askrypt.tmp"));
    fs::copy(archive, &staged)
        .and_then(|_| fs::rename(&staged, &dest))
        .map_err(|e| {
            fs::remove_file(&staged).ok();
            format!("{}: {}", dest.display(), e)
        })?;

    let meta = Meta {
        location: location.clone(),
        etag: etag.to_string(),
        cached_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    let sidecar = dir.join(format!("{key}.json"));
    let staged = dir.join(format!("{key}.json.tmp"));
    fs::write(&staged, json)
        .and_then(|()| fs::rename(&staged, &sidecar))
        .map_err(|e| {
            fs::remove_file(&staged).ok();
            format!("{}: {}", sidecar.display(), e)
        })
}

/// The copy kept for `location`, if both halves are there and the sidecar
/// still describes this vault.
pub fn load(dir: &Path, location: &VaultLocation) -> Option<OfflineCopy> {
    let key = key(location)?;
    let archive = dir.join(format!("{key}.askrypt"));
    let json = fs::read_to_string(dir.join(format!("{key}.json"))).ok()?;
    let meta: Meta = serde_json::from_str(&json).ok()?;
    (meta.location == *location && archive.is_file()).then_some(OfflineCopy { archive, meta })
}

/// Forget the copy of a vault the server no longer has. Best effort.
pub fn remove(dir: &Path, location: &VaultLocation) {
    let Some(key) = key(location) else {
        return;
    };
    fs::remove_file(dir.join(format!("{key}.json"))).ok();
    fs::remove_file(dir.join(format!("{key}.askrypt"))).ok();
}

/// Delete every copy — the setting was switched off.
pub fn clear_all() -> Result<(), String> {
    let Some(dir) = dir() else {
        return Ok(());
    };
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            eprintln!("WARNING: Failed to delete offline copies: {}", e);
            Err(format!("{}: {}", dir.display(), e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(email: &str, name: &str) -> VaultLocation {
        VaultLocation::Server {
            base_url: "https://askrypt.example.com".to_string(),
            email: email.to_string(),
            name: name.to_string(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "askrypt-offline-test-{}-{}",
            std::process::id(),
            tag
        ));
        fs::remove_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn keys_tell_accounts_and_names_apart() {
        let a = key(&server("a@example.com", "Vault")).unwrap();
        let b = key(&server("b@example.com", "Vault")).unwrap();
        let c = key(&server("a@example.com", "Other")).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, key(&server("a@example.com", "Vault")).unwrap());
        assert_eq!(
            key(&VaultLocation::LocalFile("/tmp/v.askrypt".into())),
            None
        );
    }

    #[test]
    fn a_hostile_name_cannot_choose_the_path() {
        let key = key(&server("a@example.com", "../../evil")).unwrap();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_stored_copy_loads_back_and_can_be_removed() {
        let dir = temp_dir("roundtrip");
        let source = temp_dir("roundtrip-src");
        fs::create_dir_all(&source).unwrap();
        let archive = source.join("v.askrypt");
        fs::write(&archive, b"PK\x03\x04bytes").unwrap();

        let location = server("a@example.com", "Vault");
        assert!(load(&dir, &location).is_none());

        store(&dir, &location, &archive, "etag-1").unwrap();
        let copy = load(&dir, &location).expect("copy not found");
        assert_eq!(copy.meta.etag, "etag-1");
        assert_eq!(copy.meta.location, location);
        assert_eq!(fs::read(&copy.archive).unwrap(), b"PK\x03\x04bytes");
        // Another account's vault of the same name is not this copy.
        assert!(load(&dir, &server("b@example.com", "Vault")).is_none());

        // A newer copy replaces it.
        fs::write(&archive, b"PK\x03\x04newer").unwrap();
        store(&dir, &location, &archive, "etag-2").unwrap();
        let copy = load(&dir, &location).unwrap();
        assert_eq!(copy.meta.etag, "etag-2");
        assert_eq!(fs::read(&copy.archive).unwrap(), b"PK\x03\x04newer");

        remove(&dir, &location);
        assert!(load(&dir, &location).is_none());

        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&source).ok();
    }

    #[test]
    fn a_missing_archive_is_no_copy() {
        let dir = temp_dir("half");
        fs::create_dir_all(&dir).unwrap();
        let location = server("a@example.com", "Vault");
        let meta = Meta {
            location: location.clone(),
            etag: "e".to_string(),
            cached_at: "2026-10-06T10:00:00Z".to_string(),
        };
        fs::write(
            dir.join(format!("{}.json", key(&location).unwrap())),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
        assert!(load(&dir, &location).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
