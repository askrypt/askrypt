//! Shared application state: one trait object per backend seam.
//!
//! Handlers receive this via axum's `State` extractor and therefore can only
//! reach the traits — never a concrete backend type.

use std::sync::Arc;

use crate::store::memory::{
    FakeIdTokenVerifier, MemoryAccountStore, MemoryMailer, MemorySessionStore,
    MemoryVaultBlobStore, MemoryVaultMetaStore, MemoryVaultVersionStore,
};
use crate::store::{
    AccountStore, IdTokenVerifier, Mailer, SessionStore, VaultBlobStore, VaultMetaStore,
    VaultVersionStore,
};

#[derive(Clone)]
pub struct AppState {
    pub accounts: Arc<dyn AccountStore>,
    pub sessions: Arc<dyn SessionStore>,
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
            vault_versions: Arc::new(MemoryVaultVersionStore::default()),
            vault_version_blobs: Arc::new(MemoryVaultBlobStore::default()),
            mailer: Arc::new(MemoryMailer::default()),
            id_verifier: Arc::new(FakeIdTokenVerifier::default()),
        }
    }
}
