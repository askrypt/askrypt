//! In-memory fakes for every backend trait.
//!
//! Used as the `memory` backend and by integration tests, so the whole
//! server can run and be tested without SQLite or a real filesystem.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::{
    Account, AccountId, AccountStore, IdTokenError, IdTokenVerifier, Mailer, MailerError,
    NewAccount, Session, SessionStore, StoreError, VaultBlobStore, VaultId, VaultMeta,
    VaultMetaStore, VerifiedIdToken,
};

#[derive(Debug, Default)]
pub struct MemoryAccountStore {
    accounts: Mutex<HashMap<AccountId, Account>>,
}

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn create(&self, new: NewAccount) -> Result<Account, StoreError> {
        let mut accounts = self.accounts.lock().unwrap();
        if accounts.values().any(|a| a.email == new.email) {
            return Err(StoreError::Conflict("email already registered".into()));
        }
        let account = Account {
            id: Uuid::new_v4(),
            email: new.email,
            password_hash: new.password_hash,
            google_sub: new.google_sub,
            created_at: Utc::now(),
        };
        accounts.insert(account.id, account.clone());
        Ok(account)
    }

    async fn get(&self, id: AccountId) -> Result<Option<Account>, StoreError> {
        Ok(self.accounts.lock().unwrap().get(&id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<Account>, StoreError> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.values().find(|a| a.email == email).cloned())
    }

    async fn update(&self, account: &Account) -> Result<(), StoreError> {
        let mut accounts = self.accounts.lock().unwrap();
        match accounts.get_mut(&account.id) {
            Some(existing) => {
                *existing = account.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn delete(&self, id: AccountId) -> Result<(), StoreError> {
        match self.accounts.lock().unwrap().remove(&id) {
            Some(_) => Ok(()),
            None => Err(StoreError::NotFound),
        }
    }
}

#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn insert(&self, session: Session) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.token.clone(), session);
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<Session>, StoreError> {
        Ok(self.sessions.lock().unwrap().get(token).cloned())
    }

    async fn delete(&self, token: &str) -> Result<(), StoreError> {
        match self.sessions.lock().unwrap().remove(token) {
            Some(_) => Ok(()),
            None => Err(StoreError::NotFound),
        }
    }

    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<Session>, StoreError> {
        let sessions = self.sessions.lock().unwrap();
        let mut found: Vec<Session> = sessions
            .values()
            .filter(|s| s.account_id == account_id)
            .cloned()
            .collect();
        found.sort_by_key(|s| s.created_at);
        Ok(found)
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, s| s.account_id != account_id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryVaultMetaStore {
    metas: Mutex<HashMap<(AccountId, VaultId), VaultMeta>>,
}

#[async_trait]
impl VaultMetaStore for MemoryVaultMetaStore {
    async fn upsert(&self, meta: VaultMeta) -> Result<(), StoreError> {
        self.metas
            .lock()
            .unwrap()
            .insert((meta.account_id, meta.id), meta);
        Ok(())
    }

    async fn get(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Option<VaultMeta>, StoreError> {
        Ok(self
            .metas
            .lock()
            .unwrap()
            .get(&(account_id, vault_id))
            .cloned())
    }

    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<VaultMeta>, StoreError> {
        let metas = self.metas.lock().unwrap();
        let mut found: Vec<VaultMeta> = metas
            .values()
            .filter(|m| m.account_id == account_id)
            .cloned()
            .collect();
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    }

    async fn delete(&self, account_id: AccountId, vault_id: VaultId) -> Result<(), StoreError> {
        match self.metas.lock().unwrap().remove(&(account_id, vault_id)) {
            Some(_) => Ok(()),
            None => Err(StoreError::NotFound),
        }
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        self.metas
            .lock()
            .unwrap()
            .retain(|(owner, _), _| *owner != account_id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryVaultBlobStore {
    blobs: Mutex<HashMap<(AccountId, VaultId), Vec<u8>>>,
}

#[async_trait]
impl VaultBlobStore for MemoryVaultBlobStore {
    async fn put(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.blobs
            .lock()
            .unwrap()
            .insert((account_id, vault_id), bytes.to_vec());
        Ok(())
    }

    async fn get(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .get(&(account_id, vault_id))
            .cloned())
    }

    async fn delete(&self, account_id: AccountId, vault_id: VaultId) -> Result<(), StoreError> {
        match self.blobs.lock().unwrap().remove(&(account_id, vault_id)) {
            Some(_) => Ok(()),
            None => Err(StoreError::NotFound),
        }
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        self.blobs
            .lock()
            .unwrap()
            .retain(|(owner, _), _| *owner != account_id);
        Ok(())
    }
}

/// An email captured by [`MemoryMailer`] instead of being delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Logs and records outgoing mail; doubles as the no-op boot-time mailer
/// until a real SMTP/provider impl exists.
#[derive(Debug, Default)]
pub struct MemoryMailer {
    sent: Mutex<Vec<SentMail>>,
}

impl MemoryMailer {
    pub fn sent(&self) -> Vec<SentMail> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl Mailer for MemoryMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError> {
        tracing::info!(to, subject, "mailer: recording email (no delivery backend)");
        self.sent.lock().unwrap().push(SentMail {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        });
        Ok(())
    }
}

/// Fake verifier: accepts exactly the tokens registered via
/// [`FakeIdTokenVerifier::register`], rejects everything else.
#[derive(Debug, Default)]
pub struct FakeIdTokenVerifier {
    tokens: Mutex<HashMap<String, VerifiedIdToken>>,
}

impl FakeIdTokenVerifier {
    pub fn register(&self, id_token: impl Into<String>, claims: VerifiedIdToken) {
        self.tokens.lock().unwrap().insert(id_token.into(), claims);
    }
}

#[async_trait]
impl IdTokenVerifier for FakeIdTokenVerifier {
    async fn verify(&self, id_token: &str) -> Result<VerifiedIdToken, IdTokenError> {
        self.tokens
            .lock()
            .unwrap()
            .get(id_token)
            .cloned()
            .ok_or_else(|| IdTokenError::Invalid("unknown token".into()))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    fn new_account(email: &str) -> NewAccount {
        NewAccount {
            email: email.to_string(),
            password_hash: Some("argon2-hash".to_string()),
            google_sub: None,
        }
    }

    #[tokio::test]
    async fn account_create_get_find_update_delete() {
        let store = MemoryAccountStore::default();
        let account = store.create(new_account("a@example.com")).await.unwrap();

        assert_eq!(store.get(account.id).await.unwrap(), Some(account.clone()));
        assert_eq!(
            store.find_by_email("a@example.com").await.unwrap(),
            Some(account.clone())
        );
        assert_eq!(store.find_by_email("b@example.com").await.unwrap(), None);

        let mut updated = account.clone();
        updated.google_sub = Some("google-sub-1".to_string());
        store.update(&updated).await.unwrap();
        assert_eq!(store.get(account.id).await.unwrap(), Some(updated));

        store.delete(account.id).await.unwrap();
        assert_eq!(store.get(account.id).await.unwrap(), None);
        assert!(matches!(
            store.delete(account.id).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn account_duplicate_email_conflicts() {
        let store = MemoryAccountStore::default();
        store.create(new_account("a@example.com")).await.unwrap();
        assert!(matches!(
            store.create(new_account("a@example.com")).await,
            Err(StoreError::Conflict(_))
        ));
    }

    fn new_session(token: &str, account_id: AccountId) -> Session {
        Session {
            token: token.to_string(),
            account_id,
            label: Some("test device".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
        }
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let store = MemorySessionStore::default();
        let account_id = Uuid::new_v4();
        let other_account = Uuid::new_v4();
        store
            .insert(new_session("tok-1", account_id))
            .await
            .unwrap();
        store
            .insert(new_session("tok-2", account_id))
            .await
            .unwrap();
        store
            .insert(new_session("tok-other", other_account))
            .await
            .unwrap();

        assert!(store.get("tok-1").await.unwrap().is_some());
        assert!(store.get("missing").await.unwrap().is_none());
        assert_eq!(store.list_for_account(account_id).await.unwrap().len(), 2);

        store.delete("tok-1").await.unwrap();
        assert!(store.get("tok-1").await.unwrap().is_none());
        assert!(matches!(
            store.delete("tok-1").await,
            Err(StoreError::NotFound)
        ));

        store.delete_for_account(account_id).await.unwrap();
        assert!(store.list_for_account(account_id).await.unwrap().is_empty());
        assert!(store.get("tok-other").await.unwrap().is_some());
    }

    fn new_meta(account_id: AccountId, name: &str) -> VaultMeta {
        VaultMeta {
            id: Uuid::new_v4(),
            account_id,
            name: name.to_string(),
            size: 1234,
            etag: "etag-1".to_string(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn vault_meta_lifecycle() {
        let store = MemoryVaultMetaStore::default();
        let account_id = Uuid::new_v4();
        let meta = new_meta(account_id, "b.askrypt");
        store.upsert(meta.clone()).await.unwrap();
        store
            .upsert(new_meta(account_id, "a.askrypt"))
            .await
            .unwrap();

        assert_eq!(
            store.get(account_id, meta.id).await.unwrap(),
            Some(meta.clone())
        );
        let listed = store.list_for_account(account_id).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "a.askrypt"); // sorted by name

        let mut renamed = meta.clone();
        renamed.name = "c.askrypt".to_string();
        store.upsert(renamed.clone()).await.unwrap();
        assert_eq!(store.get(account_id, meta.id).await.unwrap(), Some(renamed));

        store.delete(account_id, meta.id).await.unwrap();
        assert!(store.get(account_id, meta.id).await.unwrap().is_none());
        store.delete_for_account(account_id).await.unwrap();
        assert!(store.list_for_account(account_id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn vault_blob_lifecycle() {
        let store = MemoryVaultBlobStore::default();
        let account_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        store
            .put(account_id, vault_id, b"PK\x03\x04data")
            .await
            .unwrap();
        assert_eq!(
            store.get(account_id, vault_id).await.unwrap(),
            Some(b"PK\x03\x04data".to_vec())
        );
        // Another account cannot see it.
        assert!(store.get(Uuid::new_v4(), vault_id).await.unwrap().is_none());

        store.delete(account_id, vault_id).await.unwrap();
        assert!(store.get(account_id, vault_id).await.unwrap().is_none());
        assert!(matches!(
            store.delete(account_id, vault_id).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn mailer_records_sent_mail() {
        let mailer = MemoryMailer::default();
        mailer
            .send("a@example.com", "Verify", "hello")
            .await
            .unwrap();
        assert_eq!(
            mailer.sent(),
            vec![SentMail {
                to: "a@example.com".to_string(),
                subject: "Verify".to_string(),
                body: "hello".to_string(),
            }]
        );
    }

    #[tokio::test]
    async fn id_token_verifier_accepts_registered_rejects_unknown() {
        let verifier = FakeIdTokenVerifier::default();
        let claims = VerifiedIdToken {
            subject: "google-sub-1".to_string(),
            email: "a@example.com".to_string(),
            email_verified: true,
        };
        verifier.register("good-token", claims.clone());

        assert_eq!(verifier.verify("good-token").await.unwrap(), claims);
        assert!(matches!(
            verifier.verify("bad-token").await,
            Err(IdTokenError::Invalid(_))
        ));
    }
}
