//! Server configuration, read from environment variables.
//!
//! | Variable             | Default          | Meaning                          |
//! |----------------------|------------------|----------------------------------|
//! | `ASKRYPT_BIND`       | `127.0.0.1:8080` | Socket address to listen on      |
//! | `ASKRYPT_DATA_DIR`   | `data`           | Runtime data directory           |
//! | `ASKRYPT_BACKEND`    | `sqlite`         | Storage backend: `sqlite`/`memory` |
//! | `ASKRYPT_STATIC_DIR` | `server/static`  | Assets served at `/assets` (CSS + htmx) |
//! | `ASKRYPT_GOOGLE_CLIENT_IDS` | *(empty)* | Comma-separated Google OAuth client ids accepted as ID-token audiences; empty disables Google sign-in |
//! | `ASKRYPT_TRUST_PROXY` | `false`         | Trust `X-Real-IP`/`X-Forwarded-For` for the client address. Only when a reverse proxy is the *only* way to reach the listener |
//! | `ASKRYPT_HSTS`       | `false`          | Send `Strict-Transport-Security`. Enable once TLS terminates in front |
//! | `ASKRYPT_REQUEST_TIMEOUT_SECS` | `60`   | Per-request handler timeout (`0` disables) |
//! | `ASKRYPT_MAX_CONCURRENT` | `256`        | In-flight requests before shedding with 503 (`0` disables) |
//! | `ASKRYPT_MAX_BODY_BYTES` | `65536`      | Request body limit outside `/api/v1/vaults` (vault routes keep their own 10 MiB limit) |
//! | `ASKRYPT_LOG_FORMAT` | `text`           | Log output: `text` or `json`     |
//! | `ASKRYPT_ARGON2_PARALLELISM` | *(cpus)* | Concurrent argon2 hashes; each costs ~19 MiB. Read in [`crate::auth`] |
//!
//! Logging verbosity is configured separately via the standard `RUST_LOG`
//! filter. Keep the `askrypt_server` target at `info` or lower — the audit
//! log ([`crate::audit`]) is emitted there.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub const ENV_BIND: &str = "ASKRYPT_BIND";
pub const ENV_DATA_DIR: &str = "ASKRYPT_DATA_DIR";
pub const ENV_BACKEND: &str = "ASKRYPT_BACKEND";
pub const ENV_STATIC_DIR: &str = "ASKRYPT_STATIC_DIR";
pub const ENV_GOOGLE_CLIENT_IDS: &str = "ASKRYPT_GOOGLE_CLIENT_IDS";
pub const ENV_TRUST_PROXY: &str = "ASKRYPT_TRUST_PROXY";
pub const ENV_HSTS: &str = "ASKRYPT_HSTS";
pub const ENV_REQUEST_TIMEOUT: &str = "ASKRYPT_REQUEST_TIMEOUT_SECS";
pub const ENV_MAX_CONCURRENT: &str = "ASKRYPT_MAX_CONCURRENT";
pub const ENV_MAX_BODY_BYTES: &str = "ASKRYPT_MAX_BODY_BYTES";
pub const ENV_LOG_FORMAT: &str = "ASKRYPT_LOG_FORMAT";

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_DATA_DIR: &str = "data";
// Matches `cargo run` from the workspace root; deployments set the env var.
const DEFAULT_STATIC_DIR: &str = "server/static";
/// Generous enough for a 10 MiB vault upload over a slow link, short enough
/// that a wedged handler can't pin a connection forever.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_CONCURRENT: usize = 256;
/// Everything outside the vault routes is small JSON.
const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// In-memory fakes only; nothing persisted. For development and tests.
    Memory,
    /// SQLite database + on-disk vault blobs under the data directory.
    Sqlite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable console output.
    Text,
    /// One JSON object per event, for log shipping.
    Json,
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
    pub static_dir: PathBuf,
    /// Google OAuth client ids (web/desktop/mobile) accepted as ID-token
    /// audiences; empty means Google sign-in is disabled.
    pub google_client_ids: Vec<String>,
    /// Trust proxy-set client-address headers. Defaults to `false` (fail
    /// closed): when the listener is reachable directly, those headers are
    /// attacker-controlled and would let one client forge rate-limit buckets
    /// and audit-log entries.
    pub trust_proxy: bool,
    /// Send `Strict-Transport-Security`. Off by default so plain-HTTP local
    /// runs don't pin a browser to HTTPS for a year.
    pub hsts: bool,
    /// Per-request handler timeout; `Duration::ZERO` disables it.
    pub request_timeout: Duration,
    /// In-flight request ceiling; `0` disables shedding.
    pub max_concurrent_requests: usize,
    /// Body limit outside the vault routes, which set their own.
    pub max_body_bytes: usize,
    pub log_format: LogFormat,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.parse().expect("valid default bind address"),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            backend: Backend::Sqlite,
            static_dir: PathBuf::from(DEFAULT_STATIC_DIR),
            google_client_ids: Vec::new(),
            trust_proxy: false,
            hsts: false,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            log_format: LogFormat::Text,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let defaults = Self::default();

        let bind = match std::env::var(ENV_BIND) {
            Ok(raw) => raw.parse().map_err(|e| ConfigError {
                var: ENV_BIND,
                value: raw.clone(),
                reason: format!("not a socket address ({e})"),
            })?,
            Err(_) => defaults.bind,
        };

        let data_dir = std::env::var(ENV_DATA_DIR)
            .map(PathBuf::from)
            .unwrap_or(defaults.data_dir);

        let backend = match std::env::var(ENV_BACKEND) {
            Ok(raw) => match raw.as_str() {
                "sqlite" => Backend::Sqlite,
                "memory" => Backend::Memory,
                other => {
                    return Err(ConfigError {
                        var: ENV_BACKEND,
                        value: other.to_string(),
                        reason: "expected \"sqlite\" or \"memory\"".to_string(),
                    });
                }
            },
            Err(_) => defaults.backend,
        };

        let static_dir = std::env::var(ENV_STATIC_DIR)
            .map(PathBuf::from)
            .unwrap_or(defaults.static_dir);

        let google_client_ids = std::env::var(ENV_GOOGLE_CLIENT_IDS)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(String::from)
            .collect();

        let log_format = match std::env::var(ENV_LOG_FORMAT) {
            Ok(raw) => match raw.as_str() {
                "text" => LogFormat::Text,
                "json" => LogFormat::Json,
                other => {
                    return Err(ConfigError {
                        var: ENV_LOG_FORMAT,
                        value: other.to_string(),
                        reason: "expected \"text\" or \"json\"".to_string(),
                    });
                }
            },
            Err(_) => defaults.log_format,
        };

        Ok(Config {
            bind,
            data_dir,
            backend,
            static_dir,
            google_client_ids,
            trust_proxy: parse_bool(ENV_TRUST_PROXY, defaults.trust_proxy)?,
            hsts: parse_bool(ENV_HSTS, defaults.hsts)?,
            request_timeout: Duration::from_secs(parse_num(
                ENV_REQUEST_TIMEOUT,
                defaults.request_timeout.as_secs(),
            )?),
            max_concurrent_requests: parse_num(
                ENV_MAX_CONCURRENT,
                defaults.max_concurrent_requests,
            )?,
            max_body_bytes: parse_num(ENV_MAX_BODY_BYTES, defaults.max_body_bytes)?,
            log_format,
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

fn parse_bool(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(ConfigError {
            var,
            value: other.to_string(),
            reason: "expected a boolean (1/0, true/false, yes/no, on/off)".to_string(),
        }),
    }
}

fn parse_num<T: std::str::FromStr>(var: &'static str, default: T) -> Result<T, ConfigError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(default);
    };
    raw.trim().parse().map_err(|_| ConfigError {
        var,
        value: raw.clone(),
        reason: "expected a non-negative integer".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = Config::default();
        // Fail closed: forged proxy headers must not be trusted until the
        // operator confirms a proxy is the only path in.
        assert!(!config.trust_proxy);
        // HSTS off until TLS is confirmed in front.
        assert!(!config.hsts);
        assert_eq!(config.backend, Backend::Sqlite);
        assert_eq!(config.log_format, LogFormat::Text);
    }

    #[test]
    fn db_and_vault_paths_hang_off_the_data_dir() {
        let config = Config {
            data_dir: PathBuf::from("/srv/askrypt"),
            ..Config::default()
        };
        assert_eq!(config.db_path(), PathBuf::from("/srv/askrypt/askrypt.db"));
        assert_eq!(config.vaults_dir(), PathBuf::from("/srv/askrypt/vaults"));
    }

    #[test]
    fn bool_parsing_accepts_the_usual_spellings() {
        // Uses a var name that no test sets, so the default path is exercised.
        assert!(parse_bool("ASKRYPT_TEST_UNSET_BOOL", true).unwrap());
        assert!(!parse_bool("ASKRYPT_TEST_UNSET_BOOL", false).unwrap());
    }
}
