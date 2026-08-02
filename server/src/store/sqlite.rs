//! SQLite backend: connection pool + embedded migration runner.
//!
//! Phase 0 ships only the pool and migrations (the schema starts empty);
//! the SQLite implementations of the store traits arrive with Phase 2 and
//! will own clones of this pool. Migrations are embedded in the binary from
//! `server/migrations/` at compile time.

use std::path::Path;

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(applied, 1);

        // Re-opening is idempotent: already-applied migrations are skipped.
        let pool2 = open(&db_path).await.unwrap();
        drop(pool2);
    }
}
