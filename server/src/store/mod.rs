//! Backend traits — the only surface handlers are allowed to touch.
//!
//! Every external dependency (database, blob storage, email, Google token
//! verification) sits behind a trait defined here. Concrete backends are
//! pluggable implementations selected in `main` from config:
//!
//! - [`memory`] — in-memory fakes; used by integration tests and the
//!   `memory` backend.
//! - [`sqlite`] — SQLite pool + embedded migration runner, plus the SQLite
//!   account/session/vault-metadata store impls.
//! - [`disk`] — local-disk vault blob storage with atomic writes.
//! - [`google`] — real Google ID-token verification against Google's
//!   published JWKS.
//! - [`smtp`] — SMTP email delivery via a relay.
//!
//! Handlers and middleware must depend only on these traits — no `sqlx`
//! or `std::fs` types in handler code.

pub mod disk;
pub mod google;
pub mod memory;
pub mod smtp;
pub mod sqlite;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub type AccountId = Uuid;
pub type VaultId = Uuid;
pub type VaultVersionId = Uuid;

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

impl Account {
    pub fn is_banned(&self) -> bool {
        self.banned_at.is_some()
    }
}

/// Input for [`AccountStore::create`]; the store assigns id and timestamps.
#[derive(Debug, Clone)]
pub struct NewAccount {
    pub email: String,
    pub password_hash: Option<String>,
    pub google_sub: Option<String>,
}

#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Creates an account; fails with [`StoreError::Conflict`] if the email
    /// is already registered.
    async fn create(&self, new: NewAccount) -> Result<Account, StoreError>;
    async fn get(&self, id: AccountId) -> Result<Option<Account>, StoreError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<Account>, StoreError>;
    /// Replaces the stored record with the same id.
    async fn update(&self, account: &Account) -> Result<(), StoreError>;
    async fn delete(&self, id: AccountId) -> Result<(), StoreError>;
    /// One page of accounts, oldest first. Deliberately bounded: the admin
    /// user list must never pull an unbounded result set into memory.
    async fn list(&self, limit: u32, offset: u32) -> Result<Vec<Account>, StoreError>;
    /// How many accounts exist, for paging and the first-account rule.
    async fn count(&self) -> Result<u64, StoreError>;
}

/// Administrative access to the user list. Named rather than looked up by id
/// so callers never carry a uuid literal around; the same goes for
/// [`PAYMENT_USER_ROLE`].
pub const ADMIN_ROLE: &str = "ADMIN";

/// The paid storage tier. Holding it lifts an account's vault quota from
/// [`crate::vaults::ACCOUNT_QUOTA_BYTES`] to
/// [`crate::vaults::PAID_ACCOUNT_QUOTA_BYTES`]; it grants nothing else.
pub const PAYMENT_USER_ROLE: &str = "PAYMENT_USER";

/// An entry in the role vocabulary. Roles are seeded by the migration, not
/// created at runtime, so there is no `NewRole`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
}

/// Which accounts hold which roles. Grants are a set: the same role twice is
/// the same grant, and revoking one that was never held is not an error, so
/// a double-submitted form cannot fail.
#[async_trait]
pub trait RoleStore: Send + Sync {
    /// The whole vocabulary, name-ordered.
    async fn list(&self) -> Result<Vec<Role>, StoreError>;
    /// Role names held by one account, name-ordered.
    async fn roles_for(&self, account: AccountId) -> Result<Vec<String>, StoreError>;
    /// Every account holding `role`. Drives both the admin badge in the user
    /// list and the "don't remove the last admin" guard, so it is one query
    /// rather than a lookup per row. An unknown role name yields an empty
    /// list rather than an error — nobody holds a role that does not exist.
    async fn accounts_with(&self, role: &str) -> Result<Vec<AccountId>, StoreError>;
    /// Idempotent. [`StoreError::NotFound`] if `role` is not in the vocabulary.
    async fn grant(&self, account: AccountId, role: &str) -> Result<(), StoreError>;
    /// Idempotent. [`StoreError::NotFound`] if `role` is not in the vocabulary.
    async fn revoke(&self, account: AccountId, role: &str) -> Result<(), StoreError>;
    /// Drops every grant held by `account`, as account deletion requires.
    async fn delete_for_account(&self, account: AccountId) -> Result<(), StoreError>;
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

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn insert(&self, session: Session) -> Result<(), StoreError>;
    async fn get(&self, token: &str) -> Result<Option<Session>, StoreError>;
    async fn delete(&self, token: &str) -> Result<(), StoreError>;
    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<Session>, StoreError>;
    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError>;
}

pub type DeviceLinkId = Uuid;

/// Where a device link stands. A link is created `Pending`, and the website
/// moves it to exactly one of the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLinkStatus {
    Pending,
    Approved,
    Denied,
}

impl DeviceLinkStatus {
    /// The stored spelling. Both backends persist this string, so it is part of
    /// the on-disk format.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceLinkStatus::Pending => "pending",
            DeviceLinkStatus::Approved => "approved",
            DeviceLinkStatus::Denied => "denied",
        }
    }

    pub fn from_stored(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(DeviceLinkStatus::Pending),
            "approved" => Some(DeviceLinkStatus::Approved),
            "denied" => Some(DeviceLinkStatus::Denied),
            _ => None,
        }
    }
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

impl DeviceLink {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[async_trait]
pub trait DeviceLinkStore: Send + Sync {
    async fn insert(&self, link: DeviceLink) -> Result<(), StoreError>;
    async fn get(&self, id: DeviceLinkId) -> Result<Option<DeviceLink>, StoreError>;
    async fn get_by_poll_token(&self, poll_token: &str) -> Result<Option<DeviceLink>, StoreError>;
    /// Replaces the stored record with the same id.
    async fn update(&self, link: &DeviceLink) -> Result<(), StoreError>;
    async fn delete(&self, id: DeviceLinkId) -> Result<(), StoreError>;
    /// Atomically removes and returns an *approved*, unexpired link.
    ///
    /// One call, not `get` + check + `delete`: two polls racing on the same
    /// link would both read `Approved` and both mint a session. `None` means
    /// the link does not exist, is not approved, has expired, or another poll
    /// already claimed it — the caller must not tell those apart.
    async fn claim(
        &self,
        poll_token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceLink>, StoreError>;
    /// Drops every link past its `expires_at`, whatever its status. There is no
    /// GC task in this server, so this is called from the create path.
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64, StoreError>;
}

/// Metadata for one stored vault file; the bytes live in a [`VaultBlobStore`].
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

#[async_trait]
pub trait VaultMetaStore: Send + Sync {
    /// Inserts or replaces the metadata record for `(account_id, id)`.
    /// Names are unique per account (like files in a directory); reusing
    /// another vault's name fails with [`StoreError::Conflict`].
    async fn upsert(&self, meta: VaultMeta) -> Result<(), StoreError>;
    async fn get(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Option<VaultMeta>, StoreError>;
    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<VaultMeta>, StoreError>;
    async fn delete(&self, account_id: AccountId, vault_id: VaultId) -> Result<(), StoreError>;
    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError>;
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

/// Index over the archived generations of an account's vaults.
///
/// Deliberately has no `update`: a version is written once and then either
/// read or dropped by the retention rules in [`crate::vaults`].
#[async_trait]
pub trait VaultVersionStore: Send + Sync {
    async fn insert(&self, version: VaultVersion) -> Result<(), StoreError>;
    async fn get(
        &self,
        account_id: AccountId,
        version_id: VaultVersionId,
    ) -> Result<Option<VaultVersion>, StoreError>;
    /// One vault's history, newest first.
    async fn list_for_vault(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultVersion>, StoreError>;
    /// Every version the account holds, newest first. The retention rules
    /// need the whole set: the byte budget is per account, not per vault.
    async fn list_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<VaultVersion>, StoreError>;
    async fn delete(
        &self,
        account_id: AccountId,
        version_id: VaultVersionId,
    ) -> Result<(), StoreError>;
    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError>;
}

/// Opaque vault bytes, addressed per user. The server never parses these
/// beyond an optional ZIP-magic sanity check (Phase 4).
///
/// Two instances of this trait are in play (see [`crate::state::AppState`]):
/// one keyed by vault id holding the live files, and one keyed by *version*
/// id holding archived generations, rooted in a separate directory so the
/// two never share a namespace.
#[async_trait]
pub trait VaultBlobStore: Send + Sync {
    async fn put(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
        bytes: &[u8],
    ) -> Result<(), StoreError>;
    async fn get(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Option<Vec<u8>>, StoreError>;
    async fn delete(&self, account_id: AccountId, vault_id: VaultId) -> Result<(), StoreError>;
    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError>;
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

/// Outgoing email delivery (verification / password reset — Phase 2+).
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError>;
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

/// Validates Google ID tokens. The real impl
/// ([`google::GoogleIdTokenVerifier`]) checks signature, issuer, audience
/// and expiry against Google's published keys.
#[async_trait]
pub trait IdTokenVerifier: Send + Sync {
    async fn verify(&self, id_token: &str) -> Result<VerifiedIdToken, IdTokenError>;
}
