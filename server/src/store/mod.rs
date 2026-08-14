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
//! - [`recaptcha`] — real Google reCAPTCHA v3 verification.
//! - [`smtp`] — SMTP email delivery via a relay.
//!
//! Handlers and middleware must depend only on these traits — no `sqlx`
//! or `std::fs` types in handler code.
//!
//! The types the traits move around live in [`types`]; this module keeps the
//! traits themselves, the role-name constants, and the inherent impls.

pub mod disk;
pub mod google;
pub mod memory;
pub mod recaptcha;
pub mod smtp;
pub mod sqlite;
pub mod types;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub use types::{
    Account, AccountId, CaptchaError, DeviceLink, DeviceLinkId, DeviceLinkStatus, IdTokenError,
    MailerError, NewAccount, Role, Session, Setting, StoreError, VaultId, VaultMeta, VaultVersion,
    VaultVersionId, VerifiedIdToken,
};

impl Account {
    pub fn is_banned(&self) -> bool {
        self.banned_at.is_some()
    }
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

/// Whether this server accepts new account registrations. Absent means yes —
/// see [`crate::settings`], which owns that rule and the parsing.
///
/// Named here, next to [`ADMIN_ROLE`], so no caller carries a bare key
/// literal around.
pub const REGISTRATION_ENABLED: &str = "registration_enabled";

/// Server-wide settings an administrator edits at runtime, as opposed to the
/// `ASKRYPT_*` environment [`crate::config`] reads once at startup.
///
/// Deliberately a string key/value seam: the typed reading of each key lives
/// in [`crate::settings`], so a second setting is a constant and an accessor
/// rather than a schema change. There is no `delete` — a setting is either
/// unwritten (the default) or explicitly set, and offering a third state
/// would only invite the two to drift.
#[async_trait]
pub trait SettingsStore: Send + Sync {
    /// `None` when the key was never written, which callers must read as
    /// "use the built-in default" rather than as an error.
    async fn get(&self, key: &str) -> Result<Option<Setting>, StoreError>;
    /// Inserts or replaces. Idempotent, so a double-submitted form cannot fail.
    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn insert(&self, session: Session) -> Result<(), StoreError>;
    async fn get(&self, token: &str) -> Result<Option<Session>, StoreError>;
    async fn delete(&self, token: &str) -> Result<(), StoreError>;
    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<Session>, StoreError>;
    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError>;
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

/// Outgoing email delivery (verification / password reset — Phase 2+).
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError>;
}

/// Validates Google ID tokens. The real impl
/// ([`google::GoogleIdTokenVerifier`]) checks signature, issuer, audience
/// and expiry against Google's published keys.
#[async_trait]
pub trait IdTokenVerifier: Send + Sync {
    async fn verify(&self, id_token: &str) -> Result<VerifiedIdToken, IdTokenError>;

    /// The **public** OAuth client id the website's own "Sign in with Google"
    /// button is rendered with, or `None` when the website has no button —
    /// which is what a template reads to decide whether to render one, and
    /// how the auth pages decide whether they need the widened CSP.
    ///
    /// The mirror of [`CaptchaVerifier::site_key`], and for the same reason:
    /// the seam that will *check* the credential is the one place that knows
    /// whether there is anything to check, so a page cannot offer a widget the
    /// server would then refuse. `None` here never disables the JSON API —
    /// native clients mint their own tokens and only need an audience.
    ///
    /// Defaulted, because only the Google-backed verifier has one to give.
    fn web_client_id(&self) -> Option<&str> {
        None
    }
}

/// Scores a reCAPTCHA v3 token minted by a form.
///
/// The real impl ([`recaptcha::RecaptchaVerifier`]) posts it to Google's
/// `siteverify` endpoint; [`recaptcha::DisabledCaptchaVerifier`] is wired in
/// when no site key is configured and passes everything through.
#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    /// The **public** site key the forms embed, or `None` when no captcha is
    /// configured — which is also how a template knows not to render one and
    /// how the auth pages decide whether they need the widened CSP.
    fn site_key(&self) -> Option<&str>;

    /// Checks one token, bound to the `action` the page minted it for.
    ///
    /// `client_ip` is passed to Google as a scoring hint when it is a real
    /// address; the caller's own placeholder for "unknown" is dropped.
    ///
    /// `Ok(None)` means nothing was checked because no captcha is configured;
    /// `Ok(Some(score))` is the score that passed, for the log.
    async fn verify(
        &self,
        token: &str,
        action: &str,
        client_ip: Option<&str>,
    ) -> Result<Option<f32>, CaptchaError>;
}
