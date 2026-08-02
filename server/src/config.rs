//! Server configuration, read from environment variables.
//!
//! | Variable           | Default          | Meaning                          |
//! |--------------------|------------------|----------------------------------|
//! | `ASKRYPT_BIND`     | `127.0.0.1:8080` | Socket address to listen on      |
//! | `ASKRYPT_DATA_DIR` | `data`           | Runtime data directory           |
//! | `ASKRYPT_BACKEND`  | `sqlite`         | Storage backend: `sqlite`/`memory` |
//!
//! Logging is configured separately via the standard `RUST_LOG` filter.
//! Secrets (e.g. Google OAuth client ids) join this struct in Phase 2.

use std::net::SocketAddr;
use std::path::PathBuf;

pub const ENV_BIND: &str = "ASKRYPT_BIND";
pub const ENV_DATA_DIR: &str = "ASKRYPT_DATA_DIR";
pub const ENV_BACKEND: &str = "ASKRYPT_BACKEND";

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_DATA_DIR: &str = "data";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// In-memory fakes only; nothing persisted. For development and tests.
    Memory,
    /// SQLite database + on-disk vault blobs under the data directory.
    Sqlite,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid {var}={value:?}: {reason}")]
pub struct ConfigError {
    pub var: &'static str,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub backend: Backend,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_raw = std::env::var(ENV_BIND).unwrap_or_else(|_| DEFAULT_BIND.to_string());
        let bind = bind_raw.parse().map_err(|e| ConfigError {
            var: ENV_BIND,
            value: bind_raw.clone(),
            reason: format!("not a socket address ({e})"),
        })?;

        let data_dir =
            PathBuf::from(std::env::var(ENV_DATA_DIR).unwrap_or_else(|_| DEFAULT_DATA_DIR.into()));

        let backend_raw = std::env::var(ENV_BACKEND).unwrap_or_else(|_| "sqlite".to_string());
        let backend = match backend_raw.as_str() {
            "sqlite" => Backend::Sqlite,
            "memory" => Backend::Memory,
            other => {
                return Err(ConfigError {
                    var: ENV_BACKEND,
                    value: other.to_string(),
                    reason: "expected \"sqlite\" or \"memory\"".to_string(),
                });
            }
        };

        Ok(Config {
            bind,
            data_dir,
            backend,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("askrypt.db")
    }

    /// Root directory for on-disk vault blobs (used from Phase 4 on).
    pub fn vaults_dir(&self) -> PathBuf {
        self.data_dir.join("vaults")
    }
}
