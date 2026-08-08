use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askrypt_server::config::{Backend, Config, LogFormat};
use askrypt_server::routes;
use askrypt_server::state::AppState;
use askrypt_server::store::disk::DiskVaultBlobStore;
use askrypt_server::store::google::{GoogleIdTokenVerifier, NotConfiguredIdTokenVerifier};
use askrypt_server::store::memory::MemoryMailer;
use askrypt_server::store::smtp::SmtpMailer;
use askrypt_server::store::sqlite::{
    self, SqliteAccountStore, SqliteSessionStore, SqliteVaultMetaStore, SqliteVaultVersionStore,
};
use askrypt_server::store::{IdTokenVerifier, Mailer};
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

/// Keeps `askrypt_server` (and with it the audit target) at info or better.
const DEFAULT_LOG_FILTER: &str = "askrypt_server=debug,info";

const USAGE: &str = "\
usage:
  askrypt-server                 run the server
  askrypt-server backup <path>   snapshot the SQLite database to <path>
";

#[tokio::main]
async fn main() {
    // Arguments before configuration: `--help` has to work whatever the
    // environment says.
    let mut args = std::env::args().skip(1);
    let command = match args.next().as_deref() {
        None => Command::Serve,
        Some("backup") => Command::Backup(args.next().map(PathBuf::from)),
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            return;
        }
        Some(other) => {
            eprintln!("unknown subcommand {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    // Config next: it decides the log format, so failures here have to report
    // themselves without a subscriber.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };
    // Only the server writes log files. `backup` is a short-lived command
    // often run from cron as another user, and creating the day's file as
    // root would leave the service unable to append to it.
    let log_to_file = matches!(command, Command::Serve);
    // Held for the whole process: dropping it flushes whatever the
    // non-blocking file writer still has buffered.
    let log_guard = init_tracing(&config, log_to_file);

    let (what, result) = match command {
        Command::Serve => ("server", run(config).await),
        Command::Backup(dest) => ("backup", backup(config, dest).await),
    };

    if let Err(err) = result {
        tracing::error!(error = %err, "{what} failed");
        // `process::exit` runs no destructors, so the guard has to be dropped
        // by hand or the failure never reaches the log file.
        drop(log_guard);
        std::process::exit(1);
    }
}

enum Command {
    Serve,
    Backup(Option<PathBuf>),
}

/// Installs the subscriber: always the console, plus a daily-rotated file in
/// `ASKRYPT_LOG_DIR` when `log_to_file` and the directory is configured.
///
/// Returns the writer guard, which must outlive every event — the file layer
/// hands events to a background thread, and dropping the guard is what flushes
/// the queue.
fn init_tracing(config: &Config, log_to_file: bool) -> Option<WorkerGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));

    // One JSON object per event, fields at the top level so audit records are
    // queryable without unwrapping a nested object.
    let console = match config.log_format {
        LogFormat::Text => fmt::layer().boxed(),
        LogFormat::Json => fmt::layer().json().flatten_event(true).boxed(),
    };

    // A missing or unwritable log directory is an operational problem, not a
    // reason to refuse to serve: warn on stderr (no subscriber exists yet) and
    // carry on with console logging.
    let file = config
        .log_dir
        .as_ref()
        .filter(|_| log_to_file)
        .and_then(|dir| match open_log_file(dir, config.log_max_files) {
            Ok(appender) => Some(appender),
            Err(err) => {
                eprintln!(
                    "warning: cannot write logs to {}: {err}; continuing with console logging only",
                    dir.display()
                );
                None
            }
        });

    let (file_layer, guard) = match file {
        Some(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            // No ANSI escapes in a file, whatever the console does.
            let layer = match config.log_format {
                LogFormat::Text => fmt::layer().with_ansi(false).with_writer(writer).boxed(),
                LogFormat::Json => fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_writer(writer)
                    .boxed(),
            };
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(file_layer)
        .init();

    if let Some(dir) = config.log_dir.as_ref().filter(|_| guard.is_some()) {
        info!(
            dir = %dir.display(),
            keep_days = config.log_max_files,
            "writing logs to file, rotated daily"
        );
    }
    guard
}

fn open_log_file(
    dir: &std::path::Path,
    max_files: usize,
) -> Result<RollingFileAppender, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let mut builder = RollingFileAppender::builder()
        // Daily only: one file per UTC day, `askrypt-server.<date>.log`.
        .rotation(Rotation::DAILY)
        .filename_prefix("askrypt-server")
        .filename_suffix("log");
    // Pruning happens on rollover, so `0` (keep everything) is expressed by
    // not asking for it at all.
    if max_files > 0 {
        builder = builder.max_log_files(max_files);
    }
    Ok(builder.build(dir)?)
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

    // A bad relay or sender address fails here, at startup, rather than on
    // the first email the server tries to send.
    let mailer: Arc<dyn Mailer> = match &config.smtp {
        Some(smtp) => {
            let mailer = SmtpMailer::new(smtp)?;
            info!(
                relay = mailer.relay(),
                ?smtp.encryption,
                authenticated = smtp.credentials.is_some(),
                from = %smtp.from,
                "smtp mailer enabled"
            );
            Arc::new(mailer)
        }
        None => {
            // A warning, not an info line: this is a working configuration
            // for development and a data leak in production — outgoing mail
            // is written to the log, bodies and tokens included.
            tracing::warn!(
                "no SMTP relay configured ({} unset); outgoing email will be \
                 LOGGED IN FULL instead of delivered — development only",
                askrypt_server::config::ENV_SMTP_HOST
            );
            Arc::new(MemoryMailer::default())
        }
    };

    // Accounts, sessions and vault metadata persist in SQLite, vault bytes
    // on disk (Phase 4), and the generations a save replaced beside them.
    let state = match config.backend {
        Backend::Sqlite => {
            // The blob root up front, not on first upload: a backup script
            // tarring a directory that nothing has created yet fails, and
            // that is a bad way to learn about it.
            std::fs::create_dir_all(&config.data_dir)?;
            std::fs::create_dir_all(config.vaults_dir())?;
            let pool = sqlite::open(&config.db_path()).await?;
            info!(db = %config.db_path().display(), "sqlite ready, migrations applied");
            AppState {
                accounts: Arc::new(SqliteAccountStore::new(pool.clone())),
                sessions: Arc::new(SqliteSessionStore::new(pool.clone())),
                vault_meta: Arc::new(SqliteVaultMetaStore::new(pool.clone())),
                vault_blobs: Arc::new(DiskVaultBlobStore::new(config.vaults_dir())),
                vault_versions: Arc::new(SqliteVaultVersionStore::new(pool)),
                // Same root, keyed by version id: archived generations sit in
                // a `versions/` subdirectory of each account's own directory.
                vault_version_blobs: Arc::new(DiskVaultBlobStore::versions(config.vaults_dir())),
                mailer,
                id_verifier,
            }
        }
        Backend::Memory => AppState {
            id_verifier,
            mailer,
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
/// The vault blobs are plain files and are *not* copied here: snapshot the
/// database first, then archive `<data>/vaults/` (see `server/DEPLOY.md`).
/// Uploads write bytes before their metadata row, so that order can only
/// orphan a blob, never strand a row. Never `cp` the live database instead:
/// it runs in WAL mode, so the `.db` file alone can be stale or torn.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn log_file_lands_in_the_configured_directory() {
        let tmp = tempfile::tempdir().unwrap();
        // A nested path the operator hasn't created: the appender is expected
        // to make it rather than fall back to console-only.
        let dir = tmp.path().join("logs");
        let mut appender = open_log_file(&dir, 14).expect("appender");
        writeln!(appender, "hello").unwrap();
        appender.flush().unwrap();

        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "one file per day: {names:?}");
        // `askrypt-server.<YYYY-MM-DD>.log` — the date makes the daily
        // rollover visible, and the suffix keeps log shippers happy.
        let name = &names[0];
        assert!(name.starts_with("askrypt-server."), "{name}");
        assert!(name.ends_with(".log"), "{name}");
        assert!(
            std::fs::read_to_string(dir.join(name))
                .unwrap()
                .contains("hello")
        );
    }

    #[test]
    fn an_unwritable_log_dir_is_reported_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular file where the directory should be: `create_dir_all`
        // fails, and `init_tracing` must degrade to console logging instead of
        // taking the server down.
        let path = tmp.path().join("occupied");
        std::fs::write(&path, b"not a directory").unwrap();
        assert!(open_log_file(&path, 14).is_err());
    }
}
