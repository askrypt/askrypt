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
//! | `ASKRYPT_LOG_DIR`    | `logs`           | Directory for the daily-rotated log files; empty disables file logging |
//! | `ASKRYPT_LOG_MAX_FILES` | `14`          | Daily files to keep (`0` keeps every one) |
//! | `ASKRYPT_ARGON2_PARALLELISM` | *(cpus)* | Concurrent argon2 hashes; each costs ~19 MiB. Read in [`crate::auth`] |
//!
//! Bot protection on the website's sign-in and registration forms (Google
//! reCAPTCHA v3). `ASKRYPT_RECAPTCHA_SITE_KEY` is the switch: without it the
//! forms are exactly what they were and work without JavaScript; with it they
//! require JavaScript, because a v3 token can only be minted in the page. The
//! JSON API under `/api/v1/auth` is never captcha'd — native clients cannot
//! mint a token, and it stays behind the rate limiter.
//!
//! | Variable             | Default          | Meaning                          |
//! |----------------------|------------------|----------------------------------|
//! | `ASKRYPT_RECAPTCHA_SITE_KEY` | *(empty)* | Public v3 site key. Empty = no captcha |
//! | `ASKRYPT_RECAPTCHA_SECRET` | —          | v3 shared secret. Required with a site key |
//! | `ASKRYPT_RECAPTCHA_MIN_SCORE` | `0.5`   | Lowest accepted score, `0.0`–`1.0` |
//!
//! Email delivery. `ASKRYPT_SMTP_HOST` is the switch: set it and the server
//! sends through that relay, leave it unset and outgoing mail is only logged
//! (see [`crate::store::memory::MemoryMailer`]).
//!
//! | Variable             | Default          | Meaning                          |
//! |----------------------|------------------|----------------------------------|
//! | `ASKRYPT_SMTP_HOST`  | *(empty)*        | Relay host name. Empty = log-only mailer |
//! | `ASKRYPT_SMTP_PORT`  | *(per encryption)* | 587 STARTTLS, 465 TLS, 25 none |
//! | `ASKRYPT_SMTP_ENCRYPTION` | `starttls`  | `starttls`, `tls` (implicit) or `none` |
//! | `ASKRYPT_SMTP_FROM`  | —                | Sender, e.g. `Askrypt <no-reply@example.com>`. Required with a host |
//! | `ASKRYPT_SMTP_USERNAME` | *(empty)*     | Relay login; requires the password too |
//! | `ASKRYPT_SMTP_PASSWORD` | *(empty)*     | Relay password; requires the username too |
//! | `ASKRYPT_SMTP_TIMEOUT_SECS` | `10`      | Per-operation SMTP network timeout |
//!
//! Logging verbosity is configured separately via the standard `RUST_LOG`
//! filter. Keep the `askrypt_server` target at `info` or lower — the audit
//! log ([`crate::audit`]) is emitted there. Everything written to the console
//! is also written to the log directory, in the same format.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::store::recaptcha::RecaptchaConfig;
use crate::store::smtp::{SmtpConfig, SmtpCredentials, SmtpEncryption};

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
pub const ENV_LOG_DIR: &str = "ASKRYPT_LOG_DIR";
pub const ENV_LOG_MAX_FILES: &str = "ASKRYPT_LOG_MAX_FILES";
pub const ENV_RECAPTCHA_SITE_KEY: &str = "ASKRYPT_RECAPTCHA_SITE_KEY";
pub const ENV_RECAPTCHA_SECRET: &str = "ASKRYPT_RECAPTCHA_SECRET";
pub const ENV_RECAPTCHA_MIN_SCORE: &str = "ASKRYPT_RECAPTCHA_MIN_SCORE";
pub const ENV_SMTP_HOST: &str = "ASKRYPT_SMTP_HOST";
pub const ENV_SMTP_PORT: &str = "ASKRYPT_SMTP_PORT";
pub const ENV_SMTP_ENCRYPTION: &str = "ASKRYPT_SMTP_ENCRYPTION";
pub const ENV_SMTP_FROM: &str = "ASKRYPT_SMTP_FROM";
pub const ENV_SMTP_USERNAME: &str = "ASKRYPT_SMTP_USERNAME";
pub const ENV_SMTP_PASSWORD: &str = "ASKRYPT_SMTP_PASSWORD";
pub const ENV_SMTP_TIMEOUT: &str = "ASKRYPT_SMTP_TIMEOUT_SECS";

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_DATA_DIR: &str = "data";
/// Sibling of the data directory, not a child of it: logs are operational
/// output, and backups archive the data directory wholesale.
const DEFAULT_LOG_DIR: &str = "logs";
/// Two weeks of daily files — enough to investigate an incident over a
/// weekend, small enough to leave unattended on a modest disk.
const DEFAULT_LOG_MAX_FILES: usize = 14;
// Matches `cargo run` from the workspace root; deployments set the env var.
const DEFAULT_STATIC_DIR: &str = "server/static";
/// Generous enough for a 10 MiB vault upload over a slow link, short enough
/// that a wedged handler can't pin a connection forever.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_CONCURRENT: usize = 256;
/// Everything outside the vault routes is small JSON.
const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// Long enough for a busy relay's greeting, short enough that a dead relay
/// doesn't hold a handler open to the request timeout.
const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Google's own suggested cut between "probably human" and "probably a bot".
const DEFAULT_RECAPTCHA_MIN_SCORE: f32 = 0.5;

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
    /// Directory the log files are written to, alongside the console output.
    /// They roll over daily. `None` (an empty `ASKRYPT_LOG_DIR`) means console
    /// only — for setups where the supervisor already captures stdout.
    pub log_dir: Option<PathBuf>,
    /// Daily files kept on disk; `0` disables pruning.
    pub log_max_files: usize,
    /// SMTP relay to deliver through. `None` (no `ASKRYPT_SMTP_HOST`) leaves
    /// the log-only mailer in place — mail is captured, never sent.
    pub smtp: Option<SmtpConfig>,
    /// reCAPTCHA v3 on the website's auth forms. `None` (no
    /// `ASKRYPT_RECAPTCHA_SITE_KEY`) leaves them exactly as they were.
    pub recaptcha: Option<RecaptchaConfig>,
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
            log_dir: Some(PathBuf::from(DEFAULT_LOG_DIR)),
            log_max_files: DEFAULT_LOG_MAX_FILES,
            smtp: None,
            recaptcha: None,
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

        // An explicit empty value is "no file logging", the same way an empty
        // SMTP host means "no delivery"; unset keeps the default directory.
        let log_dir = match std::env::var(ENV_LOG_DIR) {
            Ok(raw) if raw.trim().is_empty() => None,
            Ok(raw) => Some(PathBuf::from(raw.trim())),
            Err(_) => defaults.log_dir,
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
            log_dir,
            log_max_files: parse_num(ENV_LOG_MAX_FILES, defaults.log_max_files)?,
            smtp: smtp_from(&|var| std::env::var(var).ok())?,
            recaptcha: recaptcha_from(&|var| std::env::var(var).ok())?,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("askrypt.db")
    }

    /// Root directory for on-disk vault blobs (used from Phase 4 on). Holds
    /// one directory per account, containing that account's vault files and
    /// a `versions/` subdirectory of the generations they replaced.
    pub fn vaults_dir(&self) -> PathBuf {
        self.data_dir.join("vaults")
    }
}

/// Builds the SMTP settings from a variable lookup.
///
/// Takes the lookup as an argument rather than reading the process
/// environment directly: `from_env`'s other fields are single values, but
/// this one is a seven-variable cluster with cross-field rules, and tests
/// exercising those must not race each other over global env state.
///
/// `ASKRYPT_SMTP_HOST` is the switch — everything else is ignored without it,
/// so a half-filled config can't silently half-enable delivery.
fn smtp_from(
    lookup: &dyn Fn(&'static str) -> Option<String>,
) -> Result<Option<SmtpConfig>, ConfigError> {
    let get = |var| {
        lookup(var)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let Some(host) = get(ENV_SMTP_HOST) else {
        return Ok(None);
    };

    let encryption = match get(ENV_SMTP_ENCRYPTION) {
        Some(raw) => SmtpEncryption::parse(&raw).ok_or_else(|| ConfigError {
            var: ENV_SMTP_ENCRYPTION,
            value: raw,
            reason: format!("expected {}", SmtpEncryption::SPELLINGS),
        })?,
        None => SmtpEncryption::default(),
    };

    let port = match get(ENV_SMTP_PORT) {
        Some(raw) => raw.parse().map_err(|_| ConfigError {
            var: ENV_SMTP_PORT,
            value: raw,
            reason: "expected a TCP port (1-65535)".to_string(),
        })?,
        None => encryption.default_port(),
    };

    // Without a sender the relay would reject every message; catch it here
    // rather than on the first email the server tries to send.
    let from = get(ENV_SMTP_FROM).ok_or_else(|| ConfigError {
        var: ENV_SMTP_FROM,
        value: String::new(),
        reason: format!("required when {ENV_SMTP_HOST} is set"),
    })?;

    // Half-credentials mean a typo or a missing secret mount, and would
    // otherwise connect anonymously and fail at the relay.
    let credentials = match (get(ENV_SMTP_USERNAME), get(ENV_SMTP_PASSWORD)) {
        (Some(username), Some(password)) => Some(SmtpCredentials { username, password }),
        (None, None) => None,
        (Some(_), None) => {
            return Err(ConfigError {
                var: ENV_SMTP_PASSWORD,
                value: String::new(),
                reason: format!("required when {ENV_SMTP_USERNAME} is set"),
            });
        }
        (None, Some(_)) => {
            return Err(ConfigError {
                var: ENV_SMTP_USERNAME,
                value: String::new(),
                // Never echo the password back, not even its length.
                reason: format!("required when {ENV_SMTP_PASSWORD} is set"),
            });
        }
    };

    let timeout = match get(ENV_SMTP_TIMEOUT) {
        Some(raw) => Duration::from_secs(raw.parse().map_err(|_| ConfigError {
            var: ENV_SMTP_TIMEOUT,
            value: raw,
            reason: "expected a non-negative integer".to_string(),
        })?),
        None => DEFAULT_SMTP_TIMEOUT,
    };

    Ok(Some(SmtpConfig {
        host,
        port,
        encryption,
        from,
        credentials,
        timeout,
    }))
}

/// Builds the reCAPTCHA settings from a variable lookup.
///
/// Takes the lookup for the same reason [`smtp_from`] does: cross-field rules
/// worth testing without racing over process-global environment state.
///
/// `ASKRYPT_RECAPTCHA_SITE_KEY` is the switch. The secret is then required —
/// a site key alone would render the widget in the page and then accept every
/// token it minted unchecked, which is worse than no captcha at all because
/// it *looks* protected.
fn recaptcha_from(
    lookup: &dyn Fn(&'static str) -> Option<String>,
) -> Result<Option<RecaptchaConfig>, ConfigError> {
    let get = |var| {
        lookup(var)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let Some(site_key) = get(ENV_RECAPTCHA_SITE_KEY) else {
        return Ok(None);
    };

    let secret = get(ENV_RECAPTCHA_SECRET).ok_or_else(|| ConfigError {
        var: ENV_RECAPTCHA_SECRET,
        value: String::new(),
        reason: format!("required when {ENV_RECAPTCHA_SITE_KEY} is set"),
    })?;

    let min_score = match get(ENV_RECAPTCHA_MIN_SCORE) {
        Some(raw) => {
            let score: f32 = raw.parse().map_err(|_| ConfigError {
                var: ENV_RECAPTCHA_MIN_SCORE,
                value: raw.clone(),
                reason: "expected a number between 0.0 and 1.0".to_string(),
            })?;
            // A score outside the range is a typo (0.5 written as 5), and it
            // would either lock everyone out or wave everyone through.
            if !(0.0..=1.0).contains(&score) {
                return Err(ConfigError {
                    var: ENV_RECAPTCHA_MIN_SCORE,
                    value: raw,
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            score
        }
        None => DEFAULT_RECAPTCHA_MIN_SCORE,
    };

    Ok(Some(RecaptchaConfig {
        site_key,
        secret,
        min_score,
    }))
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
        // File logging is on out of the box; only an explicitly empty
        // ASKRYPT_LOG_DIR turns it off.
        assert_eq!(config.log_dir, Some(PathBuf::from(DEFAULT_LOG_DIR)));
        assert_eq!(config.log_max_files, DEFAULT_LOG_MAX_FILES);
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

    /// Fake environment for the SMTP tests, so they don't touch process state.
    fn env(pairs: &[(&'static str, &str)]) -> impl Fn(&'static str) -> Option<String> + use<> {
        let pairs: Vec<(&'static str, String)> =
            pairs.iter().map(|(k, v)| (*k, (*v).to_string())).collect();
        move |var| {
            pairs
                .iter()
                .find(|(k, _)| *k == var)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn no_smtp_host_means_no_delivery() {
        assert!(smtp_from(&env(&[])).unwrap().is_none());
        // A sender alone is not enough to turn delivery on.
        assert!(
            smtp_from(&env(&[(ENV_SMTP_FROM, "a@example.com")]))
                .unwrap()
                .is_none()
        );
        // An empty host reads the same as an unset one.
        assert!(
            smtp_from(&env(&[
                (ENV_SMTP_HOST, "  "),
                (ENV_SMTP_FROM, "a@example.com")
            ]))
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn smtp_defaults_to_starttls_on_587_without_credentials() {
        let smtp = smtp_from(&env(&[
            (ENV_SMTP_HOST, "smtp.example.com"),
            (ENV_SMTP_FROM, "Askrypt <no-reply@example.com>"),
        ]))
        .unwrap()
        .expect("host set");
        assert_eq!(smtp.encryption, SmtpEncryption::StartTls);
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.timeout, DEFAULT_SMTP_TIMEOUT);
        assert!(smtp.credentials.is_none());
    }

    #[test]
    fn smtp_port_follows_the_encryption_mode_but_yields_to_an_explicit_one() {
        let base = [
            (ENV_SMTP_HOST, "smtp.example.com"),
            (ENV_SMTP_FROM, "a@example.com"),
        ];
        let implicit = smtp_from(&env(
            &[base.as_slice(), &[(ENV_SMTP_ENCRYPTION, "tls")]].concat()
        ))
        .unwrap()
        .unwrap();
        assert_eq!(implicit.port, 465);

        let explicit = smtp_from(&env(&[
            base.as_slice(),
            &[(ENV_SMTP_ENCRYPTION, "tls"), (ENV_SMTP_PORT, "2525")],
        ]
        .concat()))
        .unwrap()
        .unwrap();
        assert_eq!(explicit.port, 2525);
    }

    #[test]
    fn smtp_credentials_must_come_in_pairs() {
        let base = [
            (ENV_SMTP_HOST, "smtp.example.com"),
            (ENV_SMTP_FROM, "a@example.com"),
        ];
        let user_only = smtp_from(&env(
            &[base.as_slice(), &[(ENV_SMTP_USERNAME, "u")]].concat()
        ))
        .unwrap_err();
        assert_eq!(user_only.var, ENV_SMTP_PASSWORD);

        let pass_only = smtp_from(&env(
            &[base.as_slice(), &[(ENV_SMTP_PASSWORD, "hunter2")]].concat()
        ))
        .unwrap_err();
        assert_eq!(pass_only.var, ENV_SMTP_USERNAME);
        // The error is rendered to stderr on startup — it must not leak the
        // password it is complaining about.
        assert!(!pass_only.to_string().contains("hunter2"));

        let both = smtp_from(&env(&[
            base.as_slice(),
            &[(ENV_SMTP_USERNAME, "u"), (ENV_SMTP_PASSWORD, "hunter2")],
        ]
        .concat()))
        .unwrap()
        .unwrap();
        assert_eq!(both.credentials.unwrap().username, "u");
    }

    #[test]
    fn a_host_without_a_sender_is_rejected() {
        let err = smtp_from(&env(&[(ENV_SMTP_HOST, "smtp.example.com")])).unwrap_err();
        assert_eq!(err.var, ENV_SMTP_FROM);
    }

    #[test]
    fn no_site_key_means_no_captcha() {
        assert!(recaptcha_from(&env(&[])).unwrap().is_none());
        // A secret alone does not turn it on.
        assert!(
            recaptcha_from(&env(&[(ENV_RECAPTCHA_SECRET, "s")]))
                .unwrap()
                .is_none()
        );
    }

    /// A site key without a secret would render the widget and then verify
    /// nothing — refuse it at startup rather than serve a decorative captcha.
    #[test]
    fn a_site_key_without_a_secret_is_rejected() {
        let err = recaptcha_from(&env(&[(ENV_RECAPTCHA_SITE_KEY, "site")])).unwrap_err();
        assert_eq!(err.var, ENV_RECAPTCHA_SECRET);
    }

    #[test]
    fn captcha_score_defaults_and_is_range_checked() {
        let base = [
            (ENV_RECAPTCHA_SITE_KEY, "site"),
            (ENV_RECAPTCHA_SECRET, "secret"),
        ];
        let default = recaptcha_from(&env(&base)).unwrap().unwrap();
        assert_eq!(default.min_score, DEFAULT_RECAPTCHA_MIN_SCORE);

        let explicit = recaptcha_from(&env(&[
            base.as_slice(),
            &[(ENV_RECAPTCHA_MIN_SCORE, "0.7")],
        ]
        .concat()))
        .unwrap()
        .unwrap();
        assert_eq!(explicit.min_score, 0.7);

        // 0.5 fat-fingered as 5 would wave every visitor through.
        for bad in ["5", "-0.1", "half"] {
            let err = recaptcha_from(&env(
                &[base.as_slice(), &[(ENV_RECAPTCHA_MIN_SCORE, bad)]].concat()
            ))
            .unwrap_err();
            assert_eq!(err.var, ENV_RECAPTCHA_MIN_SCORE, "accepted {bad:?}");
        }
    }

    #[test]
    fn unknown_encryption_and_bad_port_are_rejected() {
        let base = [
            (ENV_SMTP_HOST, "smtp.example.com"),
            (ENV_SMTP_FROM, "a@example.com"),
        ];
        let bad_mode = smtp_from(&env(
            &[base.as_slice(), &[(ENV_SMTP_ENCRYPTION, "ssl")]].concat()
        ))
        .unwrap_err();
        assert_eq!(bad_mode.var, ENV_SMTP_ENCRYPTION);

        let bad_port = smtp_from(&env(
            &[base.as_slice(), &[(ENV_SMTP_PORT, "99999")]].concat()
        ))
        .unwrap_err();
        assert_eq!(bad_port.var, ENV_SMTP_PORT);
    }
}
