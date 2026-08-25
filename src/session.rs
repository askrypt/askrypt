//! Shared application state around the vault.
//!
//! [`Session`] holds everything that is *not* specific to a single pane. The
//! vault itself lives in one field, `vault: VaultState` — the typestate in
//! [`crate::manager`], which owns the bytes, where they live, the answers, the
//! entries and the master key, and which of those exist in which state. What is
//! left here is the shell's own business: persistent settings, the system tray,
//! the status/error messages, the background-work spinner, and the signed-in
//! server.
//!
//! Panes borrow `&mut Session` to read or mutate this shared state while keeping
//! their own UI fields in a per-pane `State` struct. Anything to do with the
//! vault goes through `session.vault`, which hands out a handle carrying only
//! the operations the current state allows.
//!
//! One structural rule governs the vault side: **no derivation runs on the main
//! thread**. `AskryptFile::create` runs a 600,000-iteration PBKDF2 twice, so
//! every save is worker-thread work exactly as unlocking is; see the module
//! documentation of [`crate::manager`] for the shape every transition takes.

use crate::manager::{Vault, VaultState};
use crate::scratch::Scratch;
use crate::settings::{AppSettings, ServerSession, VaultLocation};
use crate::tray::AppTray;
use askrypt::{SecretEntry, ServerClient, StorageError, VaultStorage};
use std::sync::Arc;
use std::time::Instant;

/// Default number of iterations for key derivation (OWASP recommendation for 2025)
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const APP_TITLE: &str = concat!("Askrypt ", env!("CARGO_PKG_VERSION"));

/// A storage or encryption failure, classified so it can travel in a `Message`.
///
/// [`StorageError`] carries an `io::Error` and so is neither `Clone` nor
/// `Debug`-cheap; a completion message needs both. The worker thread logs the
/// full error and hands back only the classification the UI actually branches
/// on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// `AskryptFile::create` or a decrypt failed — not a storage problem.
    Crypto,
    Io,
    Format,
    Network,
    Auth,
    Conflict,
    /// The server refused, carrying its own error code (`quota_exceeded`, …).
    Remote(String),
    /// Another Askrypt window has this vault open. Not a failure of the storage
    /// so much as a refusal to let two apps edit one archive, which they would
    /// otherwise do by reading each other's attachments out from under
    /// themselves.
    Locked,
    Other,
}

impl VaultError {
    /// Log the details and keep the classification. Runs on the worker thread,
    /// which is the only place the full error exists.
    pub fn log(context: &str, error: &StorageError) -> Self {
        eprintln!("ERROR: {}: {}", context, error);
        match error {
            StorageError::Io(_) => VaultError::Io,
            StorageError::Format(_) => VaultError::Format,
            StorageError::Network(_) => VaultError::Network,
            StorageError::Auth(_) => VaultError::Auth,
            StorageError::Conflict(_) => VaultError::Conflict,
            StorageError::Remote { code, .. } => VaultError::Remote(code.clone()),
            StorageError::Locked(_) => VaultError::Locked,
            // `StorageError` is `#[non_exhaustive]`.
            _ => VaultError::Other,
        }
    }

    /// Same, for the crypto errors that are plain `Box<dyn Error>`.
    pub fn log_crypto(context: &str, error: &dyn std::error::Error) -> Self {
        eprintln!("ERROR: {}: {}", context, error);
        VaultError::Crypto
    }
}

/// The sentence shown after a failed sign-in, listing or download.
///
/// Deliberately separate from [`Session::report_vault_error`], which words the
/// same variants for a *save*: a 404 while opening means "no such vault", while
/// a 404 while saving means something else entirely.
pub fn describe_sign_in_error(error: &VaultError) -> String {
    match error {
        // No password is ever typed here — signing in happens in the browser —
        // so an `Auth` failure means the token was refused, not mistyped.
        VaultError::Auth => "The server refused this sign-in. Try again.".to_string(),
        VaultError::Network => "Could not reach the server".to_string(),
        VaultError::Format => "The server returned something unexpected".to_string(),
        VaultError::Io => "No such vault on the server".to_string(),
        VaultError::Conflict => "That name is already taken".to_string(),
        VaultError::Remote(code) if code == "quota_exceeded" => {
            "Your server storage quota is full".to_string()
        }
        VaultError::Remote(code) if code == "rate_limited" => {
            "Too many attempts. Try again in a minute.".to_string()
        }
        _ => "The server rejected the request".to_string(),
    }
}

/// The sentence shown when a vault could not be opened. Worded for a file as
/// well as a server, since the wizard reaches both through the same step.
pub fn describe_open_error(error: &VaultError) -> String {
    match error {
        VaultError::Io => "No vault there — it may have been moved or deleted".to_string(),
        VaultError::Format => "That file is not an Askrypt vault".to_string(),
        VaultError::Auth => "Your server session expired. Sign in again.".to_string(),
        VaultError::Network => "Could not reach the server".to_string(),
        VaultError::Locked => {
            "That vault is already open in another Askrypt window. Close it there first."
                .to_string()
        }
        _ => "Failed to open vault".to_string(),
    }
}

/// Shared, screen-independent application state.
pub struct Session {
    /// The vault, in whichever state it is in. Everything about it — the bytes,
    /// its home, the answers, the entries, the master key — lives in here, and
    /// only the state it is actually in can be reached.
    pub vault: VaultState,
    /// Application settings
    pub settings: AppSettings,
    /// The signed-in Askrypt server, if any. Restored from the saved session
    /// on startup and cleared whenever the server rejects the token.
    pub server_client: Option<Arc<ServerClient>>,
    /// The account the current sign-in belongs to, recorded alongside a server
    /// vault's location so `settings.json` says whose vault it is.
    pub server_email: Option<String>,
    /// A browser sign-in in flight. Lives on the session rather than in a pane
    /// because two panes — the wizard's server step and Settings — can both
    /// start one and must both show the same waiting card.
    pub link: Option<crate::link::LinkState>,
    /// Counter identifying the current sign-in attempt. A reply carrying an
    /// older value belongs to a sign-in that was cancelled or restarted, and is
    /// dropped rather than acted on.
    pub link_generation: u64,
    /// Last user activity timestamp for auto Smart Lock
    pub last_user_activity: Option<Instant>,
    /// System tray
    pub tray: Option<AppTray>,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
    pub status_message: Option<String>,
    /// True while a background unlock/decryption/save task is running
    pub busy: bool,
    /// Current frame of the spinner animation
    pub spinner_frame: usize,
    /// Label shown next to the spinner ("Decrypting…", "Saving…", …)
    pub spinner_label: &'static str,
    /// When the current background decryption started (for the timing message)
    pub decrypt_started: Option<Instant>,
    /// A standing message about the stored copy of the open vault — it changed
    /// under us, or it is gone. **Sticky**: `clear_messages` leaves it alone,
    /// because it asks a question the next keystroke does not answer.
    pub follow: Option<crate::follow::Notice>,
    /// The revision the user waved away with "Keep editing". A *further*
    /// change mints a new one and so raises the banner again.
    pub dismissed_revision: Option<askrypt::Revision>,
    /// The line describing the last reload — who wrote the bytes we took, and
    /// when. Sticky for the same reason: a reload the user did not ask for is
    /// worth still seeing a keystroke later.
    pub last_reload: Option<String>,
    /// Whether following has given up on this vault (it is gone, or the token
    /// died). Reset when a vault is opened, locked or closed.
    pub follow_stopped: bool,
    /// This run's scratch directory, where a freshly attached file's ciphertext
    /// and a cloud vault's copy of its own archive live.
    ///
    /// An `Arc` because every worker that touches an attachment needs it and a
    /// `spawn_blocking` closure has to own what it captures. `None` means the
    /// platform offered no cache directory: everything still works, one
    /// fallback down in `manager`, and only attaching a file is worse for it.
    pub scratch: Option<Arc<Scratch>>,
}

impl Session {
    pub fn new() -> Self {
        let settings = AppSettings::load();
        let tray = match AppTray::new() {
            Ok(tray) => Some(tray),
            Err(e) => {
                eprintln!("WARNING: Failed to create system tray: {}", e);
                None
            }
        };

        // Restore a previous sign-in. The token is not validated here — an
        // expired or revoked one surfaces as StorageError::Auth on first use.
        let saved_session = ServerSession::load();
        let server_email = saved_session.as_ref().map(|s| s.email.clone());
        let server_client = saved_session
            .map(|session| Arc::new(ServerClient::with_token(&session.base_url, &session.token)));

        Self {
            vault: VaultState::None,
            settings,
            server_client,
            server_email,
            link: None,
            link_generation: 0,
            last_user_activity: None,
            tray,
            error_message: None,
            success_message: None,
            status_message: None,
            busy: false,
            spinner_frame: 0,
            spinner_label: "Decrypting…",
            decrypt_started: None,
            follow: None,
            dismissed_revision: None,
            last_reload: None,
            follow_stopped: false,
            scratch: Scratch::open().map(Arc::new),
        }
    }

    pub fn title(&self) -> String {
        if let Some(location) = self.vault.location() {
            let mut title = location.title_name();
            if self.vault.is_modified() {
                title.push('*');
            }
            if !self.vault.is_unlocked() {
                title.push_str(" [Locked]");
            }
            title.push_str(" - ");
            title.push_str(APP_TITLE);
            title
        } else {
            APP_TITLE.to_string()
        }
    }

    /// Clear the transient status/error/success messages shown in the status bar.
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
        self.status_message = None;
    }

    /// The status-bar line: the most urgent message, or the vault's own state.
    pub fn status_line(&self) -> String {
        if let Some(message) = self
            .error_message
            .as_ref()
            .or(self.success_message.as_ref())
            .or(self.status_message.as_ref())
        {
            return message.clone();
        }

        // Below the transient three, above the vault's own line: a background
        // reload has something to say, but never over a message about what the
        // user just did.
        if let Some(line) = self.last_reload.as_ref() {
            return line.clone();
        }

        let dirty = if self.vault.is_modified() { "*" } else { "" };
        match self.vault.location() {
            Some(location) => format!(
                "{}{} — {}",
                location.display_name(),
                dirty,
                self.vault.label()
            ),
            // A vault composed in the questions editor has no location yet.
            None if self.vault.is_open() => {
                format!("Untitled vault{} — {}", dirty, self.vault.label())
            }
            None => "No vault open".to_string(),
        }
    }

    /// The decrypted entries, or none at all when the vault is not unlocked.
    ///
    /// The read-only projection the list, the rail's filters and the detail
    /// pane share. Every *write* goes through the unlocked handle, so the
    /// unsaved-changes flag cannot drift out of step with the edits.
    pub fn entries(&self) -> &[SecretEntry] {
        self.vault.unlocked().map_or(&[], Vault::entries)
    }

    /// The vault's short name, for headings.
    pub fn display_name(&self) -> String {
        self.vault
            .location()
            .map(VaultLocation::display_name)
            .unwrap_or_else(|| "Untitled vault".to_string())
    }

    /// The full "where it lives" line, when the vault has a home.
    pub fn display_location(&self) -> Option<String> {
        self.vault.location().map(|location| {
            let prefix = if location.is_server() {
                "Server Vault"
            } else {
                "Vault File"
            };
            format!("{}: {}", prefix, location.display_location())
        })
    }

    // -----------------------------------------------------------------------
    // Vault lifecycle: the parts that are the *session's* rather than the
    // vault's, because they touch the settings file.
    // -----------------------------------------------------------------------

    /// Record the open vault in the MRU. Called only after a *successful*
    /// unlock or save, so a vault that cannot be opened never becomes the one
    /// reopened at startup.
    pub fn remember_vault(&mut self) {
        if let Some(location) = self.vault.location().cloned() {
            self.settings.remember_vault(&location);
        }
    }

    /// Forget the outstanding *question* about the stored copy, but keep
    /// following.
    ///
    /// For the edges that resolve a divergence rather than end it: a save, or
    /// a lock that drops the very edits the banner was asking about. The
    /// dismissal has to go with them — it was permission to ignore one change
    /// while editing, and once the editing is over the change is worth taking.
    ///
    /// Following resumes too. A save proves the backend is reachable and now
    /// holds our bytes, so whatever stopped it — the vault had been deleted,
    /// the token had died — is over; a Save As onto a fresh location is the
    /// way back from exactly that. A lock re-checks once and stops again if
    /// the vault really is still gone, which costs one notice.
    pub fn settle_follow(&mut self) {
        self.follow = None;
        self.dismissed_revision = None;
        self.last_reload = None;
        self.follow_stopped = false;
    }

    /// Forget everything about the *stored* copy of the vault that was open.
    ///
    /// Called wherever the vault itself changes identity or state — opened,
    /// locked, closed — because every one of these fields describes a
    /// particular vault at a particular revision and none of them survives it.
    pub fn reset_follow(&mut self) {
        self.follow = None;
        self.dismissed_revision = None;
        self.last_reload = None;
        self.follow_stopped = false;
    }

    /// The full close: forget the vault entirely, and stop reopening it.
    pub fn close_vault(&mut self) {
        self.vault.close();
        self.settings.last_opened_file = None;
        self.reset_follow();
    }

    /// Update user activity timestamp (for auto Smart Lock after inactivity)
    pub fn update_user_activity(&mut self) {
        if self.vault.is_unlocked() {
            self.last_user_activity = Some(Instant::now());
        }
    }

    /// Whether the configured idle timeout has elapsed and an auto Smart Lock
    /// is due. `LockTimeout::Never` disables the check.
    pub fn should_auto_smart_lock(&self) -> bool {
        let Some(timeout) = self.settings.lock_timeout.duration() else {
            return false;
        };

        self.vault
            .unlocked()
            .is_some_and(|vault| vault.has_key_answer())
            && self
                .last_user_activity
                .is_some_and(|last| last.elapsed() >= timeout)
    }

    /// Whether the 8-hour Smart Lock ceiling has run out and the vault should
    /// drop to a full lock. It outlives the Smart Lock itself: a vault reopened
    /// from one carries the same deadline, so being reachable from a single
    /// answer stays time-limited.
    pub fn smart_lock_timed_out(&self) -> bool {
        match &self.vault {
            VaultState::Smart(vault) => vault.expired(),
            VaultState::Unlocked(vault) => vault.smart_lock_expired(),
            _ => false,
        }
    }

    // -----------------------------------------------------------------------
    // The server
    // -----------------------------------------------------------------------

    /// Sign in to a server, replacing any previous sign-in and persisting the
    /// token for the next launch.
    pub fn sign_in(&mut self, client: Arc<ServerClient>, email: &str) {
        let saved = ServerSession {
            base_url: client.base_url().to_string(),
            email: email.to_string(),
            token: client.token().to_string(),
        };
        if let Err(e) = saved.save() {
            // Not fatal: the session works, it just won't survive a restart.
            eprintln!("WARNING: Failed to save server session: {}", e);
        }
        self.server_client = Some(client);
        self.server_email = Some(email.to_string());
    }

    /// Drop the signed-in server client and the saved token.
    ///
    /// A vault currently open *from* that server is left in place — the user
    /// keeps what they have decrypted; only saving it will ask them to sign in
    /// again.
    pub fn sign_out(&mut self) {
        self.server_client = None;
        self.server_email = None;
        ServerSession::clear();
    }

    /// Whether the session is signed in to a server.
    pub fn is_signed_in(&self) -> bool {
        self.server_client.is_some()
    }

    /// Build the storage backend for a location using this session's server
    /// client (if it needs one).
    pub fn storage_for(
        &self,
        location: &VaultLocation,
    ) -> Result<Arc<dyn VaultStorage>, StorageError> {
        location.storage(self.server_client.as_ref())
    }

    /// Turn a vault failure into the sentence shown in the status bar, and
    /// react to the ones that change session state.
    ///
    /// The details were logged on the worker thread; the user gets something
    /// they can act on.
    pub fn report_vault_error(&mut self, action: &str, error: &VaultError) {
        self.error_message = Some(match error {
            VaultError::Conflict => {
                "This vault was changed elsewhere since you opened it. Reload before saving."
                    .to_string()
            }
            VaultError::Auth => {
                // The token is dead; stop pretending we are signed in.
                self.sign_out();
                "Your server session expired. Sign in again.".to_string()
            }
            VaultError::Network => {
                format!("Could not reach the server to {} the vault", action)
            }
            VaultError::Remote(code) if code == "quota_exceeded" => {
                "Your server storage quota is full".to_string()
            }
            VaultError::Remote(code) if code == "vault_limit_reached" => {
                "You have reached the vault limit on this server".to_string()
            }
            VaultError::Remote(code) if code == "payload_too_large" => {
                "This vault is too large for the server".to_string()
            }
            VaultError::Locked => {
                "That vault is already open in another Askrypt window. Close it there first."
                    .to_string()
            }
            _ => format!("Failed to {} vault", action),
        });
    }

    // -----------------------------------------------------------------------
    // The background-work spinner
    // -----------------------------------------------------------------------

    /// Milliseconds since the current background derivation started, consuming
    /// the mark so a later message cannot re-report it.
    pub fn elapsed_millis(&mut self) -> u128 {
        self.decrypt_started
            .take()
            .map(|started| started.elapsed().as_millis())
            .unwrap_or(0)
    }

    /// Enter a background task: guards re-entry and drives the spinner.
    pub fn begin_work(&mut self, label: &'static str) {
        self.error_message = None;
        self.busy = true;
        self.spinner_label = label;
        self.decrypt_started = Some(Instant::now());
    }

    /// Leave a background task.
    pub fn finish_work(&mut self) {
        self.busy = false;
        self.spinner_label = "Decrypting…";
    }
}
