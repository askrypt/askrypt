//! Shared application state: one trait object per backend seam.
//!
//! Handlers receive this via axum's `State` extractor and therefore can only
//! reach the traits — never a concrete backend type.

use std::sync::Arc;

use crate::store::memory::{
    FakeIdTokenVerifier, MemoryAccountStore, MemoryMailer, MemorySessionStore,
    MemoryVaultBlobStore, MemoryVaultMetaStore,
};
use crate::store::{
    AccountStore, IdTokenVerifier, Mailer, SessionStore, VaultBlobStore, VaultMetaStore,
};

#[derive(Clone)]
pub struct AppState {
    pub accounts: Arc<dyn AccountStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub vault_meta: Arc<dyn VaultMetaStore>,
    pub vault_blobs: Arc<dyn VaultBlobStore>,
    pub mailer: Arc<dyn Mailer>,
    pub id_verifier: Arc<dyn IdTokenVerifier>,
}

impl AppState {
    /// State wired entirely to the in-memory fakes. Used by tests and the
    /// `memory` backend; `main` overrides individual seams (e.g. the Google
    /// verifier) with struct-update syntax.
    pub fn in_memory() -> Self {
        Self {
            accounts: Arc::new(MemoryAccountStore::default()),
            sessions: Arc::new(MemorySessionStore::default()),
            vault_meta: Arc::new(MemoryVaultMetaStore::default()),
            vault_blobs: Arc::new(MemoryVaultBlobStore::default()),
            mailer: Arc::new(MemoryMailer::default()),
            id_verifier: Arc::new(FakeIdTokenVerifier::default()),
        }
    }
}
