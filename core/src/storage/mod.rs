//! Storage backends for vault bytes.
//!
//! [`VaultStorage`] abstracts *where* the encrypted vault lives over opaque
//! bytes, so backends never look inside the vault. [`LocalFileStorage`] is the
//! filesystem implementation; [`MemoryStorage`] is an in-memory implementation
//! for tests and fakes; `ServerStorage` (behind the `server-storage` feature)
//! talks to an Askrypt server's zero-knowledge blob API.

mod local_file;
#[cfg(feature = "server-storage")]
mod server;

pub use local_file::LocalFileStorage;
#[cfg(feature = "server-storage")]
pub use server::{
    BrowserLogin, BrowserLoginStatus, RemoteVault, ServerClient, ServerStorage, normalize_base_url,
};

use crate::AskryptFile;
use std::sync::Mutex;

/// Error from a storage backend.
///
/// Marked non-exhaustive so future backends can add variants without a
/// breaking change. The network variants are defined unconditionally, even
/// though only the `server-storage` backend produces them: the error type must
/// not change shape depending on which features a build enables.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// Underlying I/O failure (missing file, permissions, ...). A remote
    /// backend reports "no such vault" as [`std::io::ErrorKind::NotFound`]
    /// here, so callers can treat a missing file and a missing remote vault
    /// alike.
    Io(std::io::Error),
    /// The bytes are not a valid vault (ZIP/JSON/version error).
    Format(String),
    /// Transport failure talking to a remote backend: DNS, TCP, TLS, timeout.
    /// Retrying later may succeed.
    Network(String),
    /// The remote backend rejected our credentials — token missing, expired or
    /// revoked. The caller has to sign in again.
    Auth(String),
    /// The stored vault changed since it was last fetched, so writing it would
    /// silently discard someone else's edit. The caller has to reload.
    Conflict(String),
    /// Any other error reported by a remote backend, carrying its
    /// machine-readable code (`quota_exceeded`, `invalid_vault_name`,
    /// `payload_too_large`, ...) so callers can react to specific cases.
    Remote {
        status: u16,
        code: String,
        message: String,
    },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "storage I/O error: {}", e),
            StorageError::Format(msg) => write!(f, "invalid vault data: {}", msg),
            StorageError::Network(msg) => write!(f, "network error: {}", msg),
            StorageError::Auth(msg) => write!(f, "authentication failed: {}", msg),
            StorageError::Conflict(msg) => write!(f, "conflict: {}", msg),
            StorageError::Remote {
                status,
                code,
                message,
            } => write!(f, "server error {} ({}): {}", status, code, message),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

/// Where vault bytes are read from and written to.
///
/// Object-safe and `Send + Sync` so a `Box<dyn VaultStorage>` can be moved
/// into a worker thread (e.g. `tokio::task::spawn_blocking`). Implementations
/// are synchronous; async backends block internally.
pub trait VaultStorage: Send + Sync {
    /// Read the raw vault bytes.
    fn read(&self) -> Result<Vec<u8>, StorageError>;

    /// Write the raw vault bytes.
    fn write(&self, bytes: &[u8]) -> Result<(), StorageError>;

    /// Whether the target currently exists (best effort).
    fn exists(&self) -> bool;

    /// Human-readable location for titles and status lines (lossy for
    /// non-UTF-8 paths — display only).
    fn location(&self) -> String;

    /// Load and parse an [`AskryptFile`] from this storage.
    fn load_vault(&self) -> Result<AskryptFile, StorageError> {
        AskryptFile::from_bytes(&self.read()?).map_err(|e| StorageError::Format(e.to_string()))
    }

    /// Serialize and write an [`AskryptFile`] to this storage.
    fn save_vault(&self, file: &AskryptFile) -> Result<(), StorageError> {
        let bytes = file
            .to_bytes()
            .map_err(|e| StorageError::Format(e.to_string()))?;
        self.write(&bytes)
    }
}

/// In-memory storage, mainly for tests and fakes.
#[derive(Default)]
pub struct MemoryStorage {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl VaultStorage for MemoryStorage {
    fn read(&self) -> Result<Vec<u8>, StorageError> {
        self.bytes
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| StorageError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))
    }

    fn write(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.bytes.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }

    fn exists(&self) -> bool {
        self.bytes.lock().unwrap().is_some()
    }

    fn location(&self) -> String {
        "memory".to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::SecretEntry;

    /// Build a small vault (low iterations) shared by the storage tests.
    pub(crate) fn test_vault() -> (AskryptFile, Vec<SecretEntry>) {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
        ];
        let answers = vec!["Smith".to_string(), "Fluffy".to_string()];
        let secrets = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
        }];
        let file = AskryptFile::create(questions, answers, secrets.clone(), Some(6000), false)
            .expect("failed to create vault");
        (file, secrets)
    }

    #[test]
    fn memory_storage_roundtrip_via_trait() {
        let (file, secrets) = test_vault();
        let storage: Box<dyn VaultStorage> = Box::new(MemoryStorage::default());

        assert!(!storage.exists());
        storage.save_vault(&file).expect("save failed");
        assert!(storage.exists());
        assert_eq!(storage.location(), "memory");

        let loaded = storage.load_vault().expect("load failed");
        assert_eq!(loaded, file);

        let questions_data = loaded.get_questions_data("Smith".into()).unwrap();
        let decrypted = loaded
            .decrypt(&questions_data, vec!["Fluffy".to_string()])
            .unwrap();
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn memory_storage_read_empty_is_io_error() {
        let storage = MemoryStorage::default();
        match storage.read() {
            Err(StorageError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn load_vault_rejects_garbage_as_format_error() {
        let storage = MemoryStorage::default();
        storage.write(b"not a zip archive").unwrap();
        match storage.load_vault() {
            Err(StorageError::Format(_)) => {}
            other => panic!("expected Format error, got {:?}", other.map(|_| ())),
        }
    }
}
