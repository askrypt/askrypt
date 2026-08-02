use askrypt_server::config::{Backend, Config};
use askrypt_server::routes;
use askrypt_server::state::AppState;
use askrypt_server::store;
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

    // Phase 0: the trait objects behind AppState are the in-memory fakes for
    // both backends; the sqlite backend additionally opens the pool and runs
    // migrations so the schema is ready for the Phase 2 store impls. Keep the
    // pool alive for the server's lifetime.
    let _db = match config.backend {
        Backend::Sqlite => {
            std::fs::create_dir_all(&config.data_dir)?;
            let pool = store::sqlite::open(&config.db_path()).await?;
            info!(db = %config.db_path().display(), "sqlite ready, migrations applied");
            Some(pool)
        }
        Backend::Memory => None,
    };
    let state = AppState::in_memory();

    if !config.static_dir.join("index.html").is_file() {
        tracing::warn!(
            static_dir = %config.static_dir.display(),
            "no index.html in static dir; landing page will 404 (set ASKRYPT_STATIC_DIR)"
        );
    }

    let app = routes::router(state, &config.static_dir);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, app)
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
