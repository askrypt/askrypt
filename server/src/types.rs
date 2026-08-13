//! Every type the crate root defines, in one place.
//!
//! The modules beside this one are behaviour: handlers, extractor impls,
//! middleware, the rules the plan documents. The *shapes* those work over —
//! request and response bodies, extractor wrappers, configuration, shared
//! state — are declared here and re-exported by the module that owns them, so
//! `crate::auth::LoginRequest` and `crate::error::ApiJson` keep working and
//! nothing outside this crate has to learn a new path.
//!
//! Two consequences of the split are worth knowing before editing:
//!
//! - **`impl` blocks stay with their module.** Rust only requires an inherent
//!   or trait impl to live in the same *crate* as the type, not the same
//!   module, so `impl Config` is still in [`crate::config`] next to the
//!   `ASKRYPT_*` constants it reads. Derives are the exception — they are
//!   attributes on the definition, so they moved here with it.
//! - **Field privacy is module privacy.** A field that was private in, say,
//!   [`crate::ratelimit`] is unreachable from there once the struct lives
//!   here, so those fields are `pub(crate)`. They are not part of the public
//!   API: the *types* keep whatever visibility they had.
//!
//! The store and website halves have their own files for the same reason —
//! see [`crate::store::types`] and [`crate::web::types`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::store::recaptcha::RecaptchaConfig;
use crate::store::smtp::SmtpConfig;
use crate::store::{
    Account, AccountId, AccountStore, CaptchaVerifier, DeviceLinkId, DeviceLinkStore,
    IdTokenVerifier, Mailer, RoleStore, Session, SessionStore, SettingsStore, VaultBlobStore,
    VaultId, VaultMetaStore, VaultVersionId, VaultVersionStore,
};

// ---------------------------------------------------------------------------
// error — the JSON error envelope and the body extractors
// ---------------------------------------------------------------------------

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    /// Stable machine-readable code (snake_case), independent of the message.
    pub code: &'static str,
    pub message: String,
    /// Emitted as `Retry-After: <seconds>`; set on the throttling and
    /// overload responses so clients back off instead of hammering.
    pub retry_after: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct ErrorBody<'a> {
    pub(crate) error: ErrorDetail<'a>,
}

#[derive(Serialize)]
pub(crate) struct ErrorDetail<'a> {
    pub(crate) code: &'a str,
    pub(crate) message: &'a str,
}

/// Drop-in replacement for [`axum::Json`] as an extractor whose rejection
/// (malformed/missing body) follows the JSON error envelope instead of
/// axum's plain-text default.
pub struct ApiJson<T>(pub T);

/// Raw-body counterpart of [`ApiJson`]: buffers the request body as
/// [`Bytes`], with rejections (over the body limit, aborted transfers)
/// following the JSON error envelope instead of axum's plain-text default.
pub struct ApiBytes(pub Bytes);

// ---------------------------------------------------------------------------
// clientip — whether proxy-set address headers may be believed
// ---------------------------------------------------------------------------

/// Whether proxy-set client-address headers may be believed. Travels as a
/// request extension installed by the router, so middleware and extractors
/// alike can read it without threading config through every signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientIpPolicy {
    pub trust_forwarded_for: bool,
}

// ---------------------------------------------------------------------------
// audit — who made the request
// ---------------------------------------------------------------------------

/// Who made the request, for the audit record. Infallible — a missing or
/// unreadable header just means less detail, never a rejected request.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub ip: String,
    pub user_agent: Option<String>,
}

// ---------------------------------------------------------------------------
// config — the `ASKRYPT_*` environment
// ---------------------------------------------------------------------------

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
    /// The public host name this server answers on, as the deployment's
    /// `ASKRYPT_DOMAIN` states it. Nothing routes on it — it is there so an
    /// operational notice can say *which* server it is about. `None` when the
    /// variable is unset, which is the normal case for a local run.
    pub domain: Option<String>,
    /// Where operational notices go (today: the startup email in
    /// [`crate::startup`]). `None` falls back to the SMTP sender address, so
    /// a configured relay always has somewhere to send.
    pub admin_email: Option<String>,
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

// ---------------------------------------------------------------------------
// sysinfo — what the host has left
// ---------------------------------------------------------------------------

/// System memory, in bytes. Read once, for a report — nothing in the server
/// makes a decision from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryUsage {
    pub total: u64,
    /// What a new allocation could actually get (`MemAvailable`), which is
    /// not `MemFree`: page cache and reclaimable slab count as available.
    pub available: u64,
}

/// One filesystem's occupancy, in bytes, as `statvfs` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    pub total: u64,
    /// Free space this process may actually use — the unprivileged figure,
    /// so it excludes the root-reserved blocks `used + available < total`
    /// otherwise looks like a rounding error.
    pub available: u64,
    pub used: u64,
}

// ---------------------------------------------------------------------------
// state — one trait object per backend seam
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub accounts: Arc<dyn AccountStore>,
    /// Which accounts hold which roles. The vocabulary itself is seeded by
    /// the migration, so this seam only ever reads it and writes grants.
    pub roles: Arc<dyn RoleStore>,
    pub sessions: Arc<dyn SessionStore>,
    /// Server-wide switches an administrator edits at runtime. Every key is
    /// absent until one is written, so this seam answering `None` is the
    /// normal case rather than an error — see [`crate::settings`].
    pub settings: Arc<dyn SettingsStore>,
    /// Desktop sign-ins in flight: the app creates one, the browser approves
    /// it, the app claims the session it authorizes. Short-lived by
    /// construction — every record is deleted on claim or swept at expiry.
    pub device_links: Arc<dyn DeviceLinkStore>,
    pub vault_meta: Arc<dyn VaultMetaStore>,
    pub vault_blobs: Arc<dyn VaultBlobStore>,
    /// Index over the archived generations of each vault.
    pub vault_versions: Arc<dyn VaultVersionStore>,
    /// The archived bytes — the same trait as [`Self::vault_blobs`], but a
    /// **separate store keyed by *version* id**, writing into a `versions/`
    /// subdirectory of each account's vault directory. History stays out of
    /// the live vault namespace (so "the file for vault X" is a single path
    /// nothing else can occupy) while everything one account stores remains
    /// under one directory.
    pub vault_version_blobs: Arc<dyn VaultBlobStore>,
    pub mailer: Arc<dyn Mailer>,
    pub id_verifier: Arc<dyn IdTokenVerifier>,
    /// Scores the reCAPTCHA tokens the website's sign-in and registration
    /// forms carry. Also the single source of truth for *whether* there is a
    /// captcha at all: its `site_key` is what the templates and the CSP
    /// decision both read.
    pub captcha: Arc<dyn CaptchaVerifier>,
}

// ---------------------------------------------------------------------------
// ratelimit — the fixed-window counter
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    pub(crate) max_per_window: u32,
    pub(crate) window: Duration,
    pub(crate) windows: Mutex<HashMap<String, Window>>,
}

pub(crate) struct Window {
    pub(crate) started: Instant,
    pub(crate) count: u32,
}

// ---------------------------------------------------------------------------
// hardening — the middleware's configuration and its one response marker
// ---------------------------------------------------------------------------

/// Response marker asking for [`crate::hardening::CSP_CAPTCHA`] instead of
/// [`crate::hardening::CSP`].
///
/// A response extension rather than a path match, so the decision stays with
/// the handler that knows whether it actually rendered a captcha — and so
/// that layer, which is the outermost one and therefore the last to touch the
/// headers, is still the only place a CSP is written.
#[derive(Debug, Clone, Copy)]
pub struct RelaxedCsp;

#[derive(Debug, Clone, Copy)]
pub struct SecurityHeaders {
    /// Send HSTS. Only meaningful once TLS terminates in front; on a plain
    /// HTTP origin it would pin browsers to a scheme that doesn't answer.
    pub hsts: bool,
}

// ---------------------------------------------------------------------------
// routes — the two trivial JSON bodies the root serves
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct Health {
    pub(crate) status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct About {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
}

// ---------------------------------------------------------------------------
// auth — registration, login and the bearer-token extractor
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// Shown in the profile's session list ("Pixel 9", "work laptop", ...).
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleLoginRequest {
    pub id_token: String,
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Serialize)]
pub struct AccountInfo {
    pub id: AccountId,
    pub email: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub account: AccountInfo,
}

/// Extractor for protected routes: validates the `Authorization: Bearer`
/// token against the session store and loads the owning account.
pub struct AuthSession {
    pub account: Account,
    pub session: Session,
}

// ---------------------------------------------------------------------------
// devicelink — the browser-completed desktop sign-in
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct StartRequest {
    /// What the app calls itself in the account's device list.
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Serialize)]
pub struct StartResponse {
    /// Public identifier: this is what goes in the browser URL.
    pub link_id: DeviceLinkId,
    /// Secret. Only the app that started the link ever holds it, and only it
    /// can trade the approval for a token.
    pub poll_token: String,
    /// Shown to the user in the app so they can compare it with the page.
    pub user_code: String,
    /// Path to open in the browser. A *path*, not an absolute URL: the client
    /// knows which server it is talking to, and the server has no configured
    /// canonical origin to speak for.
    pub verification_path: String,
    /// Seconds until the link expires.
    pub expires_in: i64,
    /// Seconds the client should wait between polls.
    pub interval: u64,
}

#[derive(Deserialize)]
pub struct PollRequest {
    pub poll_token: String,
}

/// What a poll found.
///
/// `Expired` is deliberately the answer for an unknown token, an expired link
/// and one that has already been claimed alike — see
/// [`crate::devicelink::poll`].
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PollResponse {
    Pending,
    Denied,
    Expired,
    /// An internally tagged newtype variant flattens its struct, so the
    /// approved payload is exactly the shape `/api/v1/auth/login` returns and
    /// clients need one deserializer for both.
    Approved(SessionResponse),
}

// ---------------------------------------------------------------------------
// profile — the `/api/v1/me` bodies
// ---------------------------------------------------------------------------

/// The full profile answered by `GET /api/v1/me` and the email update.
#[derive(Serialize)]
pub struct Profile {
    pub id: AccountId,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub providers: Providers,
}

/// Which login providers are usable on the account.
#[derive(Serialize)]
pub struct Providers {
    pub password: bool,
    pub google: bool,
}

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Required when the account already has a password; Google-created
    /// accounts without one set their first password with just `new_password`.
    #[serde(default)]
    pub current_password: Option<String>,
    pub new_password: String,
}

/// One entry in the `GET /api/v1/me/sessions` device list.
#[derive(Serialize)]
pub struct SessionInfo {
    /// Non-secret session id (SHA-256 of the bearer token, hex); pass it to
    /// `DELETE /api/v1/me/sessions/{id}` to revoke.
    pub id: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Whether this entry is the session making the request.
    pub current: bool,
}

// ---------------------------------------------------------------------------
// admin — one row of the Users page
// ---------------------------------------------------------------------------

/// One row of the user list: the account plus the two facts the page needs
/// that the account record itself does not carry.
pub(crate) struct AdminUser {
    pub account: Account,
    pub is_admin: bool,
    /// Whether the account is on the paid storage tier.
    pub is_payment_user: bool,
    /// True for the administrator doing the looking, whose row offers no
    /// destructive actions.
    pub is_self: bool,
}

// ---------------------------------------------------------------------------
// vaults — the vault-file API bodies
// ---------------------------------------------------------------------------

/// One vault's metadata as answered by the list/upload/rename endpoints.
#[derive(Serialize)]
pub struct VaultInfo {
    pub id: VaultId,
    pub name: String,
    pub size: u64,
    pub etag: String,
    /// When the server stored these bytes.
    pub updated_at: DateTime<Utc>,
    /// The machine that saved the file, from its own unencrypted stamp.
    pub host: Option<String>,
    /// When the file says it was saved, from the same stamp.
    pub saved_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct UploadQuery {
    pub(crate) name: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub name: String,
}

/// One archived generation as answered by the version endpoints.
#[derive(Serialize)]
pub struct VersionInfo {
    pub id: VaultVersionId,
    pub vault_id: VaultId,
    /// The vault's name when this generation was archived.
    pub name: String,
    pub size: u64,
    pub etag: String,
    /// When these bytes were the live vault's last write.
    pub updated_at: DateTime<Utc>,
    /// When they were superseded.
    pub archived_at: DateTime<Utc>,
    /// The machine that saved these bytes, from the file's own stamp.
    pub host: Option<String>,
    /// When the file says they were saved.
    pub saved_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// vaultfile — the one look the server takes inside a vault
// ---------------------------------------------------------------------------

/// What a vault file records about its own last write. Both halves are
/// independently optional: older files carry neither, and a file whose
/// timestamp does not parse can still name its host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultStamp {
    /// Host name of the machine that wrote the file.
    pub host: Option<String>,
    /// When it was written, as the *file* records it — unrelated to when the
    /// server received it.
    pub saved_at: Option<DateTime<Utc>>,
}

/// The sliver of the vault JSON [`crate::vaultfile`] cares about. Unknown
/// fields — which is to say all the rest of the format — are ignored by
/// serde, so this struct does not have to track the format as it grows.
#[derive(Deserialize)]
pub(crate) struct StampedFile {
    #[serde(default)]
    pub(crate) params: StampParams,
}

#[derive(Deserialize, Default)]
pub(crate) struct StampParams {
    #[serde(default)]
    pub(crate) host: Option<String>,
    #[serde(default)]
    pub(crate) updated_at: Option<String>,
}

// ---------------------------------------------------------------------------
// testlog — the test-only tracing capture
// ---------------------------------------------------------------------------

/// One recorded event: its target and every `field=value` pair, rendered the
/// way a subscriber would see them.
#[cfg(test)]
#[derive(Default)]
pub struct Captured {
    pub target: String,
    pub fields: Vec<(String, String)>,
}

#[cfg(test)]
pub(crate) struct CaptureLayer(pub(crate) Arc<Mutex<Vec<Captured>>>);

/// Collects every event emitted on this thread for as long as it is alive.
///
/// The subscriber is installed thread-locally, so tests stay deterministic
/// while the binary runs them in parallel. The guard is held rather than
/// scoped around a closure so `async` tests can `.await` inside the recorded
/// stretch — `#[tokio::test]` polls on the thread that installed it.
#[cfg(test)]
pub struct Capture {
    pub(crate) events: Arc<Mutex<Vec<Captured>>>,
    pub(crate) _guard: tracing::subscriber::DefaultGuard,
}
