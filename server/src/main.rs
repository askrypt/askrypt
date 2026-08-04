use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askrypt_server::config::{Backend, Config, LogFormat};
use askrypt_server::routes;
use askrypt_server::state::AppState;
use askrypt_server::store::IdTokenVerifier;
use askrypt_server::store::disk::DiskVaultBlobStore;
use askrypt_server::store::google::{GoogleIdTokenVerifier, NotConfiguredIdTokenVerifier};
use askrypt_server::store::memory::MemoryMailer;
use askrypt_server::store::sqlite::{
    self, SqliteAccountStore, SqliteSessionStore, SqliteVaultMetaStore,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Keeps `askrypt_server` (and with it the audit target) at info or better.
const DEFAULT_LOG_FILTER: &str = "askrypt_server=debug,info";

const USAGE: &str = "\
usage:
  askrypt-server                 run the server
  askrypt-server backup <path>   snapshot the SQLite database to <path>
";

#[tokio::main]
async fn main() {
    // Config comes first: it decides the log format, so failures here have
    // to report themselves without a subscriber.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };
    init_tracing(config.log_format);

    let mut args = std::env::args().skip(1);
    let (what, result) = match args.next().as_deref() {
        None => ("server", run(config).await),
        Some("backup") => ("backup", backup(config, args.next().map(PathBuf::from)).await),
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            return;
        }
        Some(other) => {
            eprintln!("unknown subcommand {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(err) = result {
        tracing::error!(error = %err, "{what} failed");
        std::process::exit(1);
    }
}

fn init_tracing(format: LogFormat) {
    let builder = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER)),
    );
    match format {
        LogFormat::Text => builder.init(),
        // One JSON object per event, fields at the top level so audit
        // records are queryable without unwrapping a nested object.
        LogFormat::Json => builder.json().flatten_event(true).init(),
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    info!(?config.backend, data_dir = %config.data_dir.display(), "starting askrypt-server");

    let id_verifier: Arc<dyn IdTokenVerifier> = if config.google_client_ids.is_empty() {
        info!("google sign-in disabled (ASKRYPT_GOOGLE_CLIENT_IDS not set)");
        Arc::new(NotConfiguredIdTokenVerifier)
    } else {
        info!(
            client_ids = config.google_client_ids.len(),
            "google sign-in enabled"
        );
        Arc::new(GoogleIdTokenVerifier::new(config.google_client_ids.clone()))
    };

    // Accounts, sessions and vault metadata persist in SQLite, vault bytes
    // on disk (Phase 4); the mailer stays in-memory until the email phase.
    let state = match config.backend {
        Backend::Sqlite => {
            std::fs::create_dir_all(&config.data_dir)?;
            let pool = sqlite::open(&config.db_path()).await?;
            info!(db = %config.db_path().display(), "sqlite ready, migrations applied");
            AppState {
                accounts: Arc::new(SqliteAccountStore::new(pool.clone())),
                sessions: Arc::new(SqliteSessionStore::new(pool.clone())),
                vault_meta: Arc::new(SqliteVaultMetaStore::new(pool)),
                vault_blobs: Arc::new(DiskVaultBlobStore::new(config.vaults_dir())),
                mailer: Arc::new(MemoryMailer::default()),
                id_verifier,
            }
        }
        Backend::Memory => AppState {
            id_verifier,
            ..AppState::in_memory()
        },
    };

    // The pages themselves are compiled into the binary; only the stylesheet
    // and the vendored htmx are loose files, served at /assets.
    for asset in ["style.css", "htmx.min.js"] {
        if !config.static_dir.join(asset).is_file() {
            tracing::warn!(
                static_dir = %config.static_dir.display(),
                asset,
                "asset missing; the site will render unstyled or without htmx \
                 (set ASKRYPT_STATIC_DIR)"
            );
        }
    }
    if !config.hsts {
        info!("HSTS disabled (set ASKRYPT_HSTS=1 once TLS terminates in front)");
    }
    if config.trust_proxy {
        info!("trusting X-Real-IP/X-Forwarded-For — the listener must not be reachable directly");
    }

    let app = routes::router(state, &config);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(addr = %listener.local_addr()?, "listening");
    // ConnectInfo gives the rate limiter and audit log a per-peer key when
    // no trusted reverse proxy sets the client-address headers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    info!("shut down cleanly");
    Ok(())
}

/// `askrypt-server backup <path>` — a consistent snapshot of the SQLite
/// database via `VACUUM INTO`, safe to run against a live server.
///
/// The vault blobs are plain files and are *not* copied here; see
/// `server/deploy/backup.sh`, which calls this first and then archives the
/// blob directory. Never `cp` the live database instead: it runs in WAL
/// mode, so the `.db` file alone can be stale or torn.
async fn backup(config: Config, dest: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(dest) = dest else {
        return Err(format!("backup needs a destination path\n\n{USAGE}").into());
    };
    if config.backend != Backend::Sqlite {
        return Err("backup requires ASKRYPT_BACKEND=sqlite".into());
    }
    let db_path = config.db_path();
    if !db_path.is_file() {
        return Err(format!("no database at {}", db_path.display()).into());
    }
    // SQLite refuses to overwrite, which is the behaviour we want: backups
    // are timestamped, never clobbered.
    if dest.exists() {
        return Err(format!("{} already exists", dest.display()).into());
    }

    let pool = sqlite::open(&db_path).await?;
    sqlx::query("VACUUM INTO ?1")
        .bind(dest.to_string_lossy().as_ref())
        .execute(&pool)
        .await?;
    pool.close().await;
    info!(source = %db_path.display(), dest = %dest.display(), "database snapshot written");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
