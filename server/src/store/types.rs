//! Every type the backend seams define, in one place.
//!
//! [`super`] declares the *traits* — `AccountStore`, `SessionStore`,
//! `Mailer`, `CaptchaVerifier` and the rest — and the sibling modules
//! implement them. The records those traits move around, the error enums they
//! fail with, and the concrete backend handles that carry a pool or a root
//! directory all live here, and each module re-exports what it owns, so
//! `store::Account`, `store::memory::MemoryAccountStore` and
//! `store::smtp::SmtpConfig` all still resolve.
//!
//! The same two rules as [`crate::types`] apply: `impl` blocks stay with their
//! module (including the hand-written `Debug` impls that redact the SMTP and
//! reCAPTCHA secrets, and the `sqlx` row conversions), and fields that were
//! private are `pub(crate)` here because module privacy no longer covers them.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use lettre::Tokio1Executor;
use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use serde::Deserialize;
use sqlx::SqlitePool;
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// The records the traits move around
// ---------------------------------------------------------------------------

pub type AccountId = Uuid;
pub type VaultId = Uuid;
pub type VaultVersionId = Uuid;
pub type DeviceLinkId = Uuid;

/// Error type shared by the persistence traits.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The referenced record does not exist.
    #[error("not found")]
    NotFound,
    /// A uniqueness constraint would be violated (e.g. duplicate email).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The backing store itself failed (I/O, SQL, ...).
    #[error("backend error: {0}")]
    Backend(String),
}

/// A user account. `password_hash` is `None` for Google-created accounts
/// that have not set a password yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub email: String,
    pub password_hash: Option<String>,
    /// Google account id (`sub` claim) when Google sign-in is linked.
    pub google_sub: Option<String>,
    pub created_at: DateTime<Utc>,
    /// When an administrator locked this account out, if they have. A banned
    /// account cannot sign in and its existing sessions stop resolving; its
    /// stored vaults are left alone, so unbanning restores everything.
    pub banned_at: Option<DateTime<Utc>>,
}

/// Input for [`super::AccountStore::create`]; the store assigns id and
/// timestamps.
#[derive(Debug, Clone)]
pub struct NewAccount {
    pub email: String,
    pub password_hash: Option<String>,
    pub google_sub: Option<String>,
}

/// An entry in the role vocabulary. Roles are seeded by the migration, not
/// created at runtime, so there is no `NewRole`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
}

/// One server-wide setting: an operator-editable value keyed by name.
///
/// Rows are written only by an administrator, so a key that has never been
/// touched is simply absent — which every reader must treat as "use the
/// built-in default" rather than as an error. See [`crate::settings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    pub value: String,
    pub updated_at: DateTime<Utc>,
}

/// An authenticated device session, keyed by its opaque bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Opaque bearer token presented by clients. Stored as-is for now;
    /// hashing-at-rest is a Phase 5 hardening decision.
    pub token: String,
    pub account_id: AccountId,
    /// Client-supplied device label shown in the profile's session list.
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Where a device link stands. A link is created `Pending`, and the website
/// moves it to exactly one of the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLinkStatus {
    Pending,
    Approved,
    Denied,
}

/// One desktop sign-in in progress.
///
/// The app creates it, opens `/link/{id}` in a browser, and polls with
/// `poll_token` until the user has signed in and the link is `Approved`.
///
/// **No session token is stored here.** The bearer is minted when the app
/// claims the link, so a user who approves and then closes the browser leaves
/// no live session behind, and this table never holds a second credential. The
/// only secret on the record is `poll_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLink {
    /// Public identifier — this is the one that travels in the browser URL.
    pub id: DeviceLinkId,
    /// Secret held only by the app that started the link; the poll is
    /// authenticated by it alone.
    pub poll_token: String,
    /// Short code shown in both the app and the browser, so the user can see
    /// that the page is about *their* sign-in. Display-only: nothing is ever
    /// looked up by it, and it is deliberately not unique.
    pub user_code: String,
    /// What the app calls itself, for the account's device list.
    pub device_label: Option<String>,
    pub status: DeviceLinkStatus,
    /// Who approved it; `None` while pending.
    pub account_id: Option<AccountId>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Metadata for one stored vault file; the bytes live in a
/// [`super::VaultBlobStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMeta {
    pub id: VaultId,
    pub account_id: AccountId,
    /// User-visible file name (e.g. `personal.askrypt`).
    pub name: String,
    pub size: u64,
    /// Content hash used as the ETag for optimistic concurrency.
    pub etag: String,
    /// When the server last stored these bytes.
    pub updated_at: DateTime<Utc>,
    /// The machine that wrote the file, as the file itself records it in its
    /// unencrypted params ([`crate::vaultfile`]). `None` for files written
    /// before the stamp existed.
    pub host: Option<String>,
    /// When the file says it was written — the client's clock, not the
    /// server's, and about the save rather than the upload.
    pub saved_at: Option<DateTime<Utc>>,
}

/// One archived generation of a vault: the metadata the bytes were stored
/// under before a save replaced them.
///
/// `name` and `updated_at` are copies taken at archival time, not links to
/// the live vault — history describes what the file *was*, so a later rename
/// leaves older entries alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultVersion {
    /// Identifies the version, and is also the key its bytes are stored
    /// under in the version blob store.
    pub id: VaultVersionId,
    pub vault_id: VaultId,
    pub account_id: AccountId,
    pub name: String,
    pub size: u64,
    /// Content hash of the archived bytes — the ETag they were served under
    /// while they were the live vault.
    pub etag: String,
    /// When these bytes were written as the live vault.
    pub updated_at: DateTime<Utc>,
    /// When they were superseded.
    pub archived_at: DateTime<Utc>,
    /// The write stamp these bytes carry, copied from the vault row at
    /// archival time (see [`VaultMeta::host`]).
    pub host: Option<String>,
    pub saved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MailerError {
    #[error("send failed: {0}")]
    Send(String),
    /// The backend could not be built from its settings (bad sender address,
    /// unusable relay). Raised at startup, not per message.
    #[error("mailer configuration: {0}")]
    Config(String),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdTokenError {
    /// The token failed validation (signature, issuer, audience, expiry).
    #[error("invalid id token: {0}")]
    Invalid(String),
    /// Google sign-in is not configured on this server (no client IDs).
    #[error("google sign-in not configured")]
    NotConfigured,
    /// The verifier itself failed (e.g. could not fetch Google's keys).
    #[error("verifier error: {0}")]
    Backend(String),
}

/// Claims extracted from a successfully verified Google ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdToken {
    /// Google's stable account id (`sub` claim).
    pub subject: String,
    pub email: String,
    /// Callers must reject tokens where this is `false` before linking
    /// accounts by email.
    pub email_verified: bool,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptchaError {
    /// The visitor's token was refused: missing, stale, already spent, minted
    /// for a different action, or scored below the threshold. The visitor
    /// sees one generic sentence — the string here is for the log only, and
    /// must stay free of anything that would tell a bot *why* it failed.
    #[error("captcha rejected: {0}")]
    Rejected(String),
    /// Our own fault: a bad secret, a malformed reply, or Google unreachable.
    /// Kept apart from [`Self::Rejected`] because it should page an operator
    /// rather than being read as a bot caught in the act.
    #[error("captcha verifier error: {0}")]
    Backend(String),
}

// ---------------------------------------------------------------------------
// disk — local-disk vault blobs
// ---------------------------------------------------------------------------

pub struct DiskVaultBlobStore {
    pub(crate) root: PathBuf,
    /// Inserted between the account directory and the file name. `None` for
    /// the live vaults; `Some("versions")` for their history.
    pub(crate) subdir: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// google — ID-token verification against Google's JWKS
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct JwkSet {
    pub(crate) keys: Vec<Jwk>,
}

/// The subset of a JWK we need for RS256: base64url modulus + exponent.
#[derive(Deserialize, Clone)]
pub(crate) struct Jwk {
    #[serde(default)]
    pub(crate) kid: String,
    #[serde(default)]
    pub(crate) kty: String,
    #[serde(default)]
    pub(crate) n: String,
    #[serde(default)]
    pub(crate) e: String,
}

#[derive(Deserialize)]
pub(crate) struct GoogleClaims {
    pub(crate) sub: String,
    pub(crate) email: Option<String>,
    #[serde(default)]
    pub(crate) email_verified: bool,
}

#[derive(Default)]
pub(crate) struct KeyCache {
    pub(crate) keys: HashMap<String, Jwk>,
    pub(crate) fetched_at: Option<Instant>,
}

pub struct GoogleIdTokenVerifier {
    /// Accepted `aud` values: the Google OAuth client ids of the web,
    /// desktop and mobile apps. The **first** is also the one the website's
    /// own sign-in button uses — see
    /// [`super::IdTokenVerifier::web_client_id`].
    pub(crate) client_ids: Vec<String>,
    pub(crate) jwks_url: String,
    pub(crate) http: reqwest::Client,
    pub(crate) keys: RwLock<KeyCache>,
}

/// Wired in `main` when no Google client ids are configured: every Google
/// sign-in attempt answers "not configured" instead of hitting the network.
pub struct NotConfiguredIdTokenVerifier;

// ---------------------------------------------------------------------------
// recaptcha — Google reCAPTCHA v3
// ---------------------------------------------------------------------------

/// reCAPTCHA v3 settings. Parsed by `config::recaptcha_from`, which is also
/// where the environment variables are documented.
#[derive(Clone)]
pub struct RecaptchaConfig {
    /// Public key embedded in the pages. Not a secret.
    pub site_key: String,
    /// Shared secret for `siteverify`. Never reaches a template or a log.
    pub secret: String,
    /// Lowest score accepted, in `0.0..=1.0`.
    pub min_score: f32,
}

/// The subset of `siteverify`'s reply we act on. Every field is `default`ed:
/// a reply missing one is a refusal, not a parse error.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct SiteVerify {
    #[serde(default)]
    pub(crate) success: bool,
    /// Absent on a failure, and on the v2 endpoints.
    #[serde(default)]
    pub(crate) score: Option<f32>,
    #[serde(default)]
    pub(crate) action: Option<String>,
    #[serde(default, rename = "error-codes")]
    pub(crate) error_codes: Vec<String>,
}

pub struct RecaptchaVerifier {
    pub(crate) config: RecaptchaConfig,
    pub(crate) verify_url: String,
    pub(crate) http: reqwest::Client,
}

/// Wired in `main` when no site key is configured: the forms render no
/// captcha and every submit passes. Also what [`crate::state::AppState`]'s
/// in-memory wiring uses, so the test suite is unaffected by this feature
/// unless a test asks for it.
pub struct DisabledCaptchaVerifier;

// ---------------------------------------------------------------------------
// smtp — delivery through a relay
// ---------------------------------------------------------------------------

/// How the connection to the relay is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpEncryption {
    /// Connect in the clear, then upgrade with `STARTTLS`. The submission
    /// default, and what most relays expect on port 587.
    #[default]
    StartTls,
    /// TLS from the first byte ("SMTPS"), normally port 465.
    ImplicitTls,
    /// No TLS at all. Only sane for a relay on localhost or a private
    /// network — credentials and message bodies cross the wire in clear.
    None,
}

/// Relay login. Both halves are required together — a username with no
/// password is a configuration mistake, not an anonymous session.
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpCredentials {
    pub username: String,
    pub password: String,
}

/// Everything needed to reach a relay. Built by [`crate::config`] from the
/// `ASKRYPT_SMTP_*` variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub encryption: SmtpEncryption,
    /// Envelope sender, e.g. `Askrypt <no-reply@example.com>` or a bare
    /// address. Parsed at startup so a typo fails fast.
    pub from: String,
    pub credentials: Option<SmtpCredentials>,
    /// Per-operation network timeout.
    pub timeout: Duration,
}

/// Pooled SMTP transport. Cheap to clone-share behind an `Arc`.
pub struct SmtpMailer {
    pub(crate) transport: AsyncSmtpTransport<Tokio1Executor>,
    pub(crate) from: Mailbox,
    /// Kept for the startup log line; never contains the password (see the
    /// `Debug` impl on [`SmtpCredentials`]).
    pub(crate) relay: String,
}

// ---------------------------------------------------------------------------
// memory — the in-memory fakes
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryAccountStore {
    pub(crate) accounts: Mutex<HashMap<AccountId, Account>>,
}

/// In-memory [`super::RoleStore`], seeded with the same embedded roles the
/// migration inserts — including their uuids and descriptions, so the two
/// backends agree on them. Keep this list in step with
/// `migrations/0002_auth.sql`.
#[derive(Debug)]
pub struct MemoryRoleStore {
    pub(crate) roles: Vec<Role>,
    pub(crate) grants: Mutex<HashSet<(AccountId, Uuid)>>,
}

/// In-memory [`super::SettingsStore`]. Starts empty, unlike
/// [`MemoryRoleStore`]: the migration seeds no settings either, and absence
/// is what "the default" means here.
#[derive(Debug, Default)]
pub struct MemorySettingsStore {
    pub(crate) values: Mutex<HashMap<String, Setting>>,
}

#[derive(Debug, Default)]
pub struct MemorySessionStore {
    pub(crate) sessions: Mutex<HashMap<String, Session>>,
}

#[derive(Debug, Default)]
pub struct MemoryDeviceLinkStore {
    pub(crate) links: Mutex<HashMap<DeviceLinkId, DeviceLink>>,
}

#[derive(Debug, Default)]
pub struct MemoryVaultMetaStore {
    pub(crate) metas: Mutex<HashMap<(AccountId, VaultId), VaultMeta>>,
}

#[derive(Debug, Default)]
pub struct MemoryVaultBlobStore {
    pub(crate) blobs: Mutex<HashMap<(AccountId, VaultId), Vec<u8>>>,
}

#[derive(Debug, Default)]
pub struct MemoryVaultVersionStore {
    pub(crate) versions: Mutex<HashMap<(AccountId, VaultVersionId), VaultVersion>>,
}

/// An email captured by [`MemoryMailer`] instead of being delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Records outgoing mail instead of delivering it, and logs every field so a
/// developer can read verification / reset links straight out of the console.
/// Used by tests, by the `memory` backend, and by any run that leaves
/// `ASKRYPT_SMTP_HOST` unset — see [`crate::store::smtp`] for real delivery.
///
/// **Never select this in production**: the log line it writes contains the
/// full message body, tokens and all.
#[derive(Debug, Default)]
pub struct MemoryMailer {
    pub(crate) sent: Mutex<Vec<SentMail>>,
}

/// Fake verifier: accepts exactly the tokens registered via
/// [`super::memory::FakeIdTokenVerifier::register`], rejects everything else.
#[derive(Debug, Default)]
pub struct FakeIdTokenVerifier {
    pub(crate) tokens: Mutex<HashMap<String, VerifiedIdToken>>,
    /// What the website's button is rendered with, if a suite asked for one
    /// via [`super::memory::FakeIdTokenVerifier::with_web_client_id`].
    /// `None` by default, so a suite that says nothing about Google sees no
    /// button and no widened CSP.
    pub(crate) web_client_id: Option<String>,
}

/// Fake captcha: presents a site key (so the forms render exactly as they do
/// in production) and accepts only tokens registered via
/// [`super::memory::FakeCaptchaVerifier::register`], applying the same action
/// and score rules the real verifier does.
///
/// **Not** what [`crate::state::AppState::in_memory`] wires — that uses
/// [`DisabledCaptchaVerifier`], so a suite that says nothing about captchas
/// sees none. Tests opt in by overriding the seam.
#[derive(Debug)]
pub struct FakeCaptchaVerifier {
    pub(crate) site_key: String,
    pub(crate) min_score: f32,
    /// token → (action it was minted for, score it scored)
    pub(crate) tokens: Mutex<HashMap<String, (String, f32)>>,
}

// ---------------------------------------------------------------------------
// sqlite — the pooled handles and the rows they read
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct AccountRow {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) password_hash: Option<String>,
    pub(crate) google_sub: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) banned_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SqliteAccountStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RoleRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
}

#[derive(Clone)]
pub struct SqliteRoleStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SettingRow {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SqliteSettingsStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SessionRow {
    pub(crate) token: String,
    pub(crate) account_id: String,
    pub(crate) label: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SqliteSessionStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct DeviceLinkRow {
    pub(crate) id: String,
    pub(crate) poll_token: String,
    pub(crate) user_code: String,
    pub(crate) device_label: Option<String>,
    pub(crate) status: String,
    pub(crate) account_id: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SqliteDeviceLinkStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct VaultMetaRow {
    pub(crate) id: String,
    pub(crate) account_id: String,
    pub(crate) name: String,
    pub(crate) size: i64,
    pub(crate) etag: String,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) host: Option<String>,
    pub(crate) saved_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SqliteVaultMetaStore {
    pub(crate) pool: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub(crate) struct VaultVersionRow {
    pub(crate) id: String,
    pub(crate) vault_id: String,
    pub(crate) account_id: String,
    pub(crate) name: String,
    pub(crate) size: i64,
    pub(crate) etag: String,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) archived_at: DateTime<Utc>,
    pub(crate) host: Option<String>,
    pub(crate) saved_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SqliteVaultVersionStore {
    pub(crate) pool: SqlitePool,
}
