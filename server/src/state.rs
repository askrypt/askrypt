//! Shared application state: one trait object per backend seam.
//!
//! Handlers receive this via axum's `State` extractor and therefore can only
//! reach the traits — never a concrete backend type.

use std::sync::Arc;

use crate::store::memory::{
    FakeIdTokenVerifier, MemoryAccountStore, MemoryDeviceLinkStore, MemoryMailer, MemoryRoleStore,
    MemorySessionStore, MemorySettingsStore, MemoryVaultBlobStore, MemoryVaultMetaStore,
    MemoryVaultVersionStore,
};
use crate::store::recaptcha::DisabledCaptchaVerifier;

pub use crate::types::AppState;

impl AppState {
    /// State wired entirely to the in-memory fakes. Used by tests and the
    /// `memory` backend; `main` overrides individual seams (e.g. the Google
    /// verifier) with struct-update syntax.
    pub fn in_memory() -> Self {
        Self {
            accounts: Arc::new(MemoryAccountStore::default()),
            roles: Arc::new(MemoryRoleStore::default()),
            sessions: Arc::new(MemorySessionStore::default()),
            settings: Arc::new(MemorySettingsStore::default()),
            device_links: Arc::new(MemoryDeviceLinkStore::default()),
            vault_meta: Arc::new(MemoryVaultMetaStore::default()),
            vault_blobs: Arc::new(MemoryVaultBlobStore::default()),
            vault_versions: Arc::new(MemoryVaultVersionStore::default()),
            vault_version_blobs: Arc::new(MemoryVaultBlobStore::default()),
            mailer: Arc::new(MemoryMailer::default()),
            id_verifier: Arc::new(FakeIdTokenVerifier::default()),
            // Off, not faked: a captcha nothing asked for would make every
            // existing sign-in test carry a token. Suites that want one
            // override this seam with `FakeCaptchaVerifier`.
            captcha: Arc::new(DisabledCaptchaVerifier),
        }
    }
}
