//! SQLite backend: connection pool, embedded migration runner, and the
//! SQLite implementations of [`AccountStore`] and [`SessionStore`]
//! (Phase 2). The vault-metadata impl arrives with Phase 4.
//!
//! Uuids are stored as hyphenated TEXT, timestamps as TEXT via sqlx's
//! chrono mapping. Migrations are embedded in the binary from
//! `server/migrations/` at compile time.

use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use uuid::Uuid;

use super::{Account, AccountId, AccountStore, NewAccount, Session, SessionStore, StoreError};

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Opens (creating if missing) the SQLite database at `db_path` and runs all
/// pending migrations.
pub async fn open(db_path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().connect_with(options).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

fn backend_err(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Maps unique-constraint violations on the accounts table to the
/// [`StoreError::Conflict`] messages promised by the trait docs.
fn account_write_err(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(db) = &e
        && db.is_unique_violation()
    {
        let msg = if db.message().contains("email") {
            "email already registered"
        } else {
            "google account already linked"
        };
        return StoreError::Conflict(msg.into());
    }
    backend_err(e)
}

fn parse_uuid(raw: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(raw).map_err(|e| StoreError::Backend(format!("corrupt uuid in database: {e}")))
}

#[derive(sqlx::FromRow)]
struct AccountRow {
    id: String,
    email: String,
    password_hash: Option<String>,
    google_sub: Option<String>,
    created_at: DateTime<Utc>,
}

impl AccountRow {
    fn into_account(self) -> Result<Account, StoreError> {
        Ok(Account {
            id: parse_uuid(&self.id)?,
            email: self.email,
            password_hash: self.password_hash,
            google_sub: self.google_sub,
            created_at: self.created_at,
        })
    }
}

#[derive(Clone)]
pub struct SqliteAccountStore {
    pool: SqlitePool,
}

impl SqliteAccountStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccountStore for SqliteAccountStore {
    async fn create(&self, new: NewAccount) -> Result<Account, StoreError> {
        let account = Account {
            id: Uuid::new_v4(),
            email: new.email,
            password_hash: new.password_hash,
            google_sub: new.google_sub,
            created_at: Utc::now(),
        };
        sqlx::query(
            "INSERT INTO accounts (id, email, password_hash, google_sub, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(account.id.to_string())
        .bind(&account.email)
        .bind(&account.password_hash)
        .bind(&account.google_sub)
        .bind(account.created_at)
        .execute(&self.pool)
        .await
        .map_err(account_write_err)?;
        Ok(account)
    }

    async fn get(&self, id: AccountId) -> Result<Option<Account>, StoreError> {
        let row: Option<AccountRow> = sqlx::query_as(
            "SELECT id, email, password_hash, google_sub, created_at FROM accounts WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend_err)?;
        row.map(AccountRow::into_account).transpose()
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<Account>, StoreError> {
        let row: Option<AccountRow> = sqlx::query_as(
            "SELECT id, email, password_hash, google_sub, created_at FROM accounts \
             WHERE email = ?1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend_err)?;
        row.map(AccountRow::into_account).transpose()
    }

    async fn update(&self, account: &Account) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE accounts SET email = ?2, password_hash = ?3, google_sub = ?4, \
             created_at = ?5 WHERE id = ?1",
        )
        .bind(account.id.to_string())
        .bind(&account.email)
        .bind(&account.password_hash)
        .bind(&account.google_sub)
        .bind(account.created_at)
        .execute(&self.pool)
        .await
        .map_err(account_write_err)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, id: AccountId) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM accounts WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(backend_err)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    token: String,
    account_id: String,
    label: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl SessionRow {
    fn into_session(self) -> Result<Session, StoreError> {
        Ok(Session {
            token: self.token,
            account_id: parse_uuid(&self.account_id)?,
            label: self.label,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

#[derive(Clone)]
pub struct SqliteSessionStore {
    pool: SqlitePool,
}

impl SqliteSessionStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn insert(&self, session: Session) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT OR REPLACE INTO sessions (token, account_id, label, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&session.token)
        .bind(session.account_id.to_string())
        .bind(&session.label)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(backend_err)?;
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<Session>, StoreError> {
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT token, account_id, label, created_at, expires_at FROM sessions \
             WHERE token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend_err)?;
        row.map(SessionRow::into_session).transpose()
    }

    async fn delete(&self, token: &str) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM sessions WHERE token = ?1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(backend_err)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn list_for_account(&self, account_id: AccountId) -> Result<Vec<Session>, StoreError> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            "SELECT token, account_id, label, created_at, expires_at FROM sessions \
             WHERE account_id = ?1 ORDER BY created_at",
        )
        .bind(account_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(backend_err)?;
        rows.into_iter().map(SessionRow::into_session).collect()
    }

    async fn delete_for_account(&self, account_id: AccountId) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM sessions WHERE account_id = ?1")
            .bind(account_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(backend_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    async fn setup() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("test.db")).await.unwrap();
        (dir, pool)
    }

    fn new_account(email: &str) -> NewAccount {
        NewAccount {
            email: email.to_string(),
            password_hash: Some("argon2-hash".to_string()),
            google_sub: None,
        }
    }

    #[tokio::test]
    async fn open_creates_db_and_applies_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let pool = open(&db_path).await.unwrap();
        assert!(db_path.exists());

        let (applied,): (i64,) = sqlx::query_as("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(applied, 2);

        // Re-opening is idempotent: already-applied migrations are skipped.
        let pool2 = open(&db_path).await.unwrap();
        drop(pool2);
    }

    #[tokio::test]
    async fn account_create_get_find_update_delete() {
        let (_dir, pool) = setup().await;
        let store = SqliteAccountStore::new(pool);
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
        assert!(matches!(
            store.update(&account).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn account_duplicate_email_conflicts() {
        let (_dir, pool) = setup().await;
        let store = SqliteAccountStore::new(pool);
        store.create(new_account("a@example.com")).await.unwrap();
        assert!(matches!(
            store.create(new_account("a@example.com")).await,
            Err(StoreError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn account_update_to_taken_email_conflicts() {
        let (_dir, pool) = setup().await;
        let store = SqliteAccountStore::new(pool);
        let account = store.create(new_account("a@example.com")).await.unwrap();
        store.create(new_account("b@example.com")).await.unwrap();

        let mut clash = account.clone();
        clash.email = "b@example.com".to_string();
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
    async fn session_lifecycle_and_account_cascade() {
        let (_dir, pool) = setup().await;
        let accounts = SqliteAccountStore::new(pool.clone());
        let store = SqliteSessionStore::new(pool);
        let account = accounts.create(new_account("a@example.com")).await.unwrap();
        let other = accounts.create(new_account("b@example.com")).await.unwrap();

        let session = new_session("tok-1", account.id);
        store.insert(session.clone()).await.unwrap();
        store
            .insert(new_session("tok-2", account.id))
            .await
            .unwrap();
        store
            .insert(new_session("tok-other", other.id))
            .await
            .unwrap();

        assert_eq!(store.get("tok-1").await.unwrap(), Some(session));
        assert!(store.get("missing").await.unwrap().is_none());
        assert_eq!(store.list_for_account(account.id).await.unwrap().len(), 2);

        store.delete("tok-1").await.unwrap();
        assert!(store.get("tok-1").await.unwrap().is_none());
        assert!(matches!(
            store.delete("tok-1").await,
            Err(StoreError::NotFound)
        ));

        store.delete_for_account(account.id).await.unwrap();
        assert!(store.list_for_account(account.id).await.unwrap().is_empty());
        assert!(store.get("tok-other").await.unwrap().is_some());

        // Deleting the account cascades to its sessions (FK ON DELETE CASCADE).
        accounts.delete(other.id).await.unwrap();
        assert!(store.get("tok-other").await.unwrap().is_none());
    }
}
