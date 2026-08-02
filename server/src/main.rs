use std::net::SocketAddr;
use std::sync::Arc;

use askrypt_server::config::{Backend, Config};
use askrypt_server::routes;
use askrypt_server::state::AppState;
use askrypt_server::store::IdTokenVerifier;
use askrypt_server::store::google::{GoogleIdTokenVerifier, NotConfiguredIdTokenVerifier};
use askrypt_server::store::memory::{MemoryMailer, MemoryVaultBlobStore, MemoryVaultMetaStore};
use askrypt_server::store::sqlite::{self, SqliteAccountStore, SqliteSessionStore};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("askrypt_server=debug,info")),
        )
        .init();

    if let Err(err) = run().await {
        tracing::error!(error = %err, "server failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
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

    // Accounts and sessions persist in SQLite (Phase 2); the vault stores
    // stay in-memory until Phase 4, the mailer until the email phase.
    let state = match config.backend {
        Backend::Sqlite => {
            std::fs::create_dir_all(&config.data_dir)?;
            let pool = sqlite::open(&config.db_path()).await?;
            info!(db = %config.db_path().display(), "sqlite ready, migrations applied");
            AppState {
                accounts: Arc::new(SqliteAccountStore::new(pool.clone())),
                sessions: Arc::new(SqliteSessionStore::new(pool)),
                vault_meta: Arc::new(MemoryVaultMetaStore::default()),
                vault_blobs: Arc::new(MemoryVaultBlobStore::default()),
                mailer: Arc::new(MemoryMailer::default()),
                id_verifier,
            }
        }
        Backend::Memory => AppState {
            id_verifier,
            ..AppState::in_memory()
        },
    };

    if !config.static_dir.join("index.html").is_file() {
        tracing::warn!(
            static_dir = %config.static_dir.display(),
            "no index.html in static dir; landing page will 404 (set ASKRYPT_STATIC_DIR)"
        );
    }

    let app = routes::router(state, &config.static_dir);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(addr = %listener.local_addr()?, "listening");
    // ConnectInfo gives the rate limiter a per-peer key when no reverse
    // proxy sets X-Forwarded-For.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    info!("shut down cleanly");
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
