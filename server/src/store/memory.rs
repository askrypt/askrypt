//! In-memory fakes for every backend trait.
//!
//! Used as the `memory` backend and by integration tests, so the whole
//! server can run and be tested without SQLite or a real filesystem.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::{
    ADMIN_ROLE, Account, AccountId, AccountStore, IdTokenError, IdTokenVerifier, Mailer,
    MailerError, NewAccount, Role, RoleStore, Session, SessionStore, StoreError, VaultBlobStore,
    VaultId, VaultMeta, VaultMetaStore, VaultVersion, VaultVersionId, VaultVersionStore,
    VerifiedIdToken,
};

#[derive(Debug, Default)]
pub struct MemoryAccountStore {
    accounts: Mutex<HashMap<AccountId, Account>>,
}

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn create(&self, new: NewAccount) -> Result<Account, StoreError> {
        let mut accounts = self.accounts.lock().unwrap();
        check_unique(&accounts, None, &new.email, new.google_sub.as_deref())?;
        let account = Account {
            id: Uuid::new_v4(),
            email: new.email,
            password_hash: new.password_hash,
            google_sub: new.google_sub,
            created_at: Utc::now(),
            banned_at: None,
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
        check_unique(
            &accounts,
            Some(account.id),
            &account.email,
            account.google_sub.as_deref(),
        )?;
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

    async fn list(&self, limit: u32, offset: u32) -> Result<Vec<Account>, StoreError> {
        let accounts = self.accounts.lock().unwrap();
        let mut all: Vec<Account> = accounts.values().cloned().collect();
        // Same order as the SQLite backend, id tiebreak included, so paging
        // behaves identically on both.
        all.sort_by_key(|a| (a.created_at, a.id));
        Ok(all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count(&self) -> Result<u64, StoreError> {
        Ok(self.accounts.lock().unwrap().len() as u64)
    }
}

/// In-memory [`RoleStore`], seeded with the same embedded `ADMIN` role the
/// migration inserts — including its uuid, so the two backends agree on it.
#[derive(Debug)]
pub struct MemoryRoleStore {
    roles: Vec<Role>,
    grants: Mutex<HashSet<(AccountId, Uuid)>>,
}

/// The uuid `migrations/0002_auth.sql` gives the embedded ADMIN role.
const ADMIN_ROLE_ID: Uuid = Uuid::from_u128(0xa000_0000_0000_4000_8000_0000_0000_0001);

impl Default for MemoryRoleStore {
    fn default() -> Self {
        Self {
            roles: vec![Role {
                id: ADMIN_ROLE_ID,
                name: ADMIN_ROLE.to_string(),
                description: "Full administrative access to the user list.".to_string(),
            }],
            grants: Mutex::new(HashSet::new()),
        }
    }
}

impl MemoryRoleStore {
    fn role_id(&self, role: &str) -> Result<Uuid, StoreError> {
        self.roles
            .iter()
            .find(|r| r.name == role)
            .map(|r| r.id)
            .ok_or(StoreError::NotFound)
    }
}

#[async_trait]
impl RoleStore for MemoryRoleStore {
    async fn list(&self) -> Result<Vec<Role>, StoreError> {
        let mut roles = self.roles.clone();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(roles)
    }

    async fn roles_for(&self, account: AccountId) -> Result<Vec<String>, StoreError> {
        let grants = self.grants.lock().unwrap();
        let mut names: Vec<String> = self
            .roles
            .iter()
            .filter(|role| grants.contains(&(account, role.id)))
            .map(|role| role.name.clone())
            .collect();
        names.sort();
        Ok(names)
    }

    async fn accounts_with(&self, role: &str) -> Result<Vec<AccountId>, StoreError> {
        // An unknown role is held by nobody rather than an error, matching
        // the JOIN the SQLite backend does.
        let Ok(role_id) = self.role_id(role) else {
            return Ok(Vec::new());
        };
        let grants = self.grants.lock().unwrap();
        Ok(grants
            .iter()
            .filter(|(_, r)| *r == role_id)
            .map(|(account, _)| *account)
            .collect())
    }

    async fn grant(&self, account: AccountId, role: &str) -> Result<(), StoreError> {
        let role_id = self.role_id(role)?;
        self.grants.lock().unwrap().insert((account, role_id));
        Ok(())
    }

    async fn revoke(&self, account: AccountId, role: &str) -> Result<(), StoreError> {
        let role_id = self.role_id(role)?;
        self.grants.lock().unwrap().remove(&(account, role_id));
        Ok(())
    }

    async fn delete_for_account(&self, account: AccountId) -> Result<(), StoreError> {
        self.grants.lock().unwrap().retain(|(a, _)| *a != account);
        Ok(())
    }
}

/// Mirrors the SQLite unique constraints on `email` and `google_sub`;
/// `exclude` skips the record being updated.
fn check_unique(
    accounts: &HashMap<AccountId, Account>,
    exclude: Option<AccountId>,
    email: &str,
    google_sub: Option<&str>,
) -> Result<(), StoreError> {
    let others = || accounts.values().filter(|a| Some(a.id) != exclude);
    if others().any(|a| a.email == email) {
        return Err(StoreError::Conflict("email already registered".into()));
    }
    if google_sub.is_some() && others().any(|a| a.google_sub.as_deref() == google_sub) {
        return Err(StoreError::Conflict("google account already linked".into()));
    }
    Ok(())
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
        let mut metas = self.metas.lock().unwrap();
        // Mirrors the SQLite UNIQUE (account_id, name) constraint.
        if metas
            .values()
            .any(|m| m.account_id == meta.account_id && m.name == meta.name && m.id != meta.id)
        {
            return Err(StoreError::Conflict("vault name already used".into()));
        }
        metas.insert((meta.account_id, meta.id), meta);
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

#[derive(Debug, Default)]
pub struct MemoryVaultVersionStore {
    versions: Mutex<HashMap<(AccountId, VaultVersionId), VaultVersion>>,
}

/// Newest first, matching the SQLite `ORDER BY archived_at DESC`. Ties break
/// on the id so a listing is stable: tests archive several versions inside
/// one clock tick.
fn newest_first(a: &VaultVersion, b: &VaultVersion) -> std::cmp::Ordering {
    b.archived_at.cmp(&a.archived_at).then(b.id.cmp(&a.id))
}

#[async_trait]
impl VaultVersionStore for MemoryVaultVersionStore {
    async fn insert(&self, version: VaultVersion) -> Result<(), StoreError> {
        self.versions
            .lock()
            .unwrap()
            .insert((version.account_id, version.id), version);
        Ok(())
    }

    async fn get(
        &self,
        account_id: AccountId,
        version_id: VaultVersionId,
    ) -> Result<Option<VaultVersion>, StoreError> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .get(&(account_id, version_id))
            .cloned())
    }

    async fn list_for_vault(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<Vec<VaultVersion>, StoreError> {
        let versions = self.versions.lock().unwrap();
        let mut found: Vec<VaultVersion> = versions
            .values()
            .filter(|v| v.account_id == account_id && v.vault_id == vault_id)
            .cloned()
            .collect();
        found.sort_by(newest_first);
        Ok(found)
    }

    async fn list_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<VaultVersion>, StoreError> {
        let versions = self.versions.lock().unwrap();
        let mut found: Vec<VaultVersion> = versions
            .values()
            .filter(|v| v.account_id == account_id)
            .cloned()
            .collect();
        found.sort_by(newest_first);
        Ok(found)
    }

    async fn delete(
        &self,
        account_id: AccountId,
        version_id: VaultVersionId,
    ) -> Result<(), StoreError> {
        match self
            .versions
            .lock()
            .unwrap()
            .remove(&(account_id, version_id))
        {
            Some(_) => Ok(()),
            None => Err(StoreError::NotFound),
        }
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        self.versions
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

/// Records outgoing mail instead of delivering it, and logs every field so a
/// developer can read verification / reset links straight out of the console.
/// Used by tests, by the `memory` backend, and by any run that leaves
/// `ASKRYPT_SMTP_HOST` unset — see [`crate::store::smtp`] for real delivery.
///
/// **Never select this in production**: the log line below contains the full
/// message body, tokens and all.
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
        let index = {
            let mut sent = self.sent.lock().unwrap();
            sent.push(SentMail {
                to: to.to_string(),
                subject: subject.to_string(),
                body: body.to_string(),
            });
            sent.len() - 1
        };
        // Every field, body included — the whole point of this backend is
        // that a developer can read a verification or reset link off the
        // console. `index` matches the position in `sent()`.
        tracing::info!(
            to,
            subject,
            body,
            body_bytes = body.len(),
            index,
            "mailer: no delivery backend — email captured in full (dev only)"
        );
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

    /// The two backends have to agree on ordering and on the seeded role, or
    /// `memory` stops being a faithful stand-in for tests.
    #[tokio::test]
    async fn accounts_page_oldest_first() {
        let store = MemoryAccountStore::default();
        let mut created = Vec::new();
        for email in ["a@example.com", "b@example.com", "c@example.com"] {
            created.push(store.create(new_account(email)).await.unwrap());
        }
        created.sort_by_key(|a| (a.created_at, a.id));

        assert_eq!(store.count().await.unwrap(), 3);
        assert_eq!(
            store
                .list(2, 0)
                .await
                .unwrap()
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>(),
            created[..2].iter().map(|a| a.id).collect::<Vec<_>>()
        );
        assert_eq!(
            store
                .list(2, 2)
                .await
                .unwrap()
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>(),
            vec![created[2].id]
        );
        // Past the end is empty, not an error: a stale page link is a
        // browser doing something reasonable.
        assert!(store.list(2, 99).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn roles_seed_admin_and_grants_are_a_set() {
        let store = MemoryRoleStore::default();
        let roles = store.list().await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, ADMIN_ROLE);
        // The uuid the migration writes, so both backends name the same role.
        assert_eq!(
            roles[0].id.to_string(),
            "a0000000-0000-4000-8000-000000000001"
        );

        let one = Uuid::new_v4();
        let two = Uuid::new_v4();
        store.grant(one, ADMIN_ROLE).await.unwrap();
        store.grant(one, ADMIN_ROLE).await.unwrap();
        assert_eq!(store.roles_for(one).await.unwrap(), vec![ADMIN_ROLE]);
        assert_eq!(store.accounts_with(ADMIN_ROLE).await.unwrap(), vec![one]);
        assert!(store.roles_for(two).await.unwrap().is_empty());

        // Revoking something never held is a no-op; an unknown role is not a
        // role anyone can hold.
        store.revoke(two, ADMIN_ROLE).await.unwrap();
        assert!(matches!(
            store.grant(two, "NOPE").await,
            Err(StoreError::NotFound)
        ));
        assert!(store.accounts_with("NOPE").await.unwrap().is_empty());

        store.delete_for_account(one).await.unwrap();
        assert!(store.accounts_with(ADMIN_ROLE).await.unwrap().is_empty());
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

    #[tokio::test]
    async fn account_update_enforces_uniqueness() {
        let store = MemoryAccountStore::default();
        let account = store.create(new_account("a@example.com")).await.unwrap();
        let mut linked = new_account("b@example.com");
        linked.google_sub = Some("google-sub-1".to_string());
        store.create(linked).await.unwrap();

        // Updating without changing unique fields is fine (no self-conflict).
        store.update(&account).await.unwrap();

        let mut clash = account.clone();
        clash.email = "b@example.com".to_string();
        assert!(matches!(
            store.update(&clash).await,
            Err(StoreError::Conflict(_))
        ));

        let mut clash = account.clone();
        clash.google_sub = Some("google-sub-1".to_string());
        assert!(matches!(
            store.update(&clash).await,
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
            host: None,
            saved_at: None,
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
    async fn vault_meta_duplicate_name_conflicts() {
        let store = MemoryVaultMetaStore::default();
        let account_id = Uuid::new_v4();
        let meta = new_meta(account_id, "a.askrypt");
        store.upsert(meta.clone()).await.unwrap();

        // Re-upserting the same vault under its own name is fine.
        store.upsert(meta.clone()).await.unwrap();
        // A different vault taking the name conflicts...
        assert!(matches!(
            store.upsert(new_meta(account_id, "a.askrypt")).await,
            Err(StoreError::Conflict(_))
        ));
        // ...but another account may use it freely.
        store
            .upsert(new_meta(Uuid::new_v4(), "a.askrypt"))
            .await
            .unwrap();
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
