//! Shared application state and the vault lifecycle.
//!
//! [`Session`] holds everything that is *not* specific to a single pane: the
//! loaded vault, the decrypted secrets, persistent settings, the system tray,
//! the status/error messages, and the background-work spinner. Panes borrow
//! `&mut Session` to read or mutate this shared state while keeping their own UI
//! fields in a per-pane `State` struct.
//!
//! Ported from the shipping app's `src/session.rs`, with one structural change:
//! **saving is no longer synchronous**. `AskryptFile::create` runs a
//! 600,000-iteration PBKDF2 twice, so every save is worker-thread work like
//! unlocking is. [`Session::save_request`] collects the inputs, [`write_vault`]
//! does the work off the main thread, and [`Session::apply_saved`] performs the
//! mutation when the result comes back.

use crate::settings::{AppSettings, ServerSession, VaultLocation};
use crate::tray::AppTray;
use askrypt::{
    AskryptFile, MasterSecret, QuestionsData, SecretEntry, ServerClient, StorageError,
    VaultStorage, calc_pbkdf2, decrypt_with_aes, encode_base64, encrypt_with_aes, generate_bytes,
    normalize_answer, sha256,
};
use rand::RngExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Default number of iterations for key derivation (OWASP recommendation for 2025)
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const APP_TITLE: &str = concat!("Askrypt ", env!("CARGO_PKG_VERSION"));
/// Iterations for Smart Lock encryption (2,000,000 as specified)
pub const SMART_LOCK_ITERATIONS: u32 = 2_000_000;
/// Smart Lock timeout duration (8 hours)
pub const SMART_LOCK_TIMEOUT: Duration = Duration::from_hours(8);

/// Result of a background Smart Lock unlock: the recovered answers (restored
/// into app state) plus the fully decrypted vault.
#[derive(Debug, Clone)]
pub struct SmartUnlockResult {
    pub answer0: String,
    pub answers: Vec<String>,
    pub questions_data: QuestionsData,
    pub entries: Vec<SecretEntry>,
    /// The vault's master key, so the next save re-wraps it rather than
    /// rotating it — see [`Session::master`].
    pub master: MasterSecret,
}

/// Data for Smart Lock mode - stores encrypted answers in RAM
#[derive(Debug, Clone)]
pub struct SmartLockData {
    /// The index of the answer used as the smart lock key (not first answer).
    /// Retained for diagnostics; decryption keys off the stored salt and IVs,
    /// not this.
    #[allow(dead_code)]
    pub key_answer_index: usize,
    /// The question text for the selected answer (stored for display)
    pub key_question: String,
    /// Encrypted first answer (answer0) using the key answer
    pub encrypted_answer0: Vec<u8>,
    /// Encrypted remaining answers using the key answer
    pub encrypted_answers: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// IV for `encrypted_answer0`. The two ciphertexts get an IV each because
    /// they share a key, and CBC under one key *and* one IV makes equal
    /// leading blocks encrypt to equal ciphertext — it would tell a reader of
    /// this blob how far the two plaintexts agree.
    pub iv_answer0: Vec<u8>,
    /// IV for `encrypted_answers`, distinct from `iv_answer0` for that reason.
    pub iv_answers: Vec<u8>,
    /// Timestamp of last activity (for 8-hour timeout)
    pub last_activity: Instant,
}

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
        _ => "Failed to open vault".to_string(),
    }
}

/// Everything needed to rebuild and re-encrypt the vault, collected on the main
/// thread so the worker owns its inputs.
///
/// Holds every answer and every decrypted entry, so it is secret material:
/// it wipes on drop.
pub struct SaveRequest {
    pub questions: Vec<String>,
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    pub iterations: u32,
    pub translit: bool,
    /// The vault's existing master key, or `None` for a vault that has never
    /// had one (a brand-new vault, which mints its key on this first write).
    pub master: Option<MasterSecret>,
}

impl Drop for SaveRequest {
    fn drop(&mut self) {
        self.answers.zeroize();
        // `entries` are `SecretEntry` and `master` is a `MasterSecret`, both of
        // which wipe themselves on drop.
    }
}

/// A vault that has been re-encrypted and written.
///
/// Carries the backend that did the writing, not a description of it: the
/// session must adopt that instance, ETag and all.
#[derive(Clone)]
pub struct VaultHandle {
    pub file: AskryptFile,
    pub location: VaultLocation,
    pub storage: Arc<dyn VaultStorage>,
    /// The master key the write used — the session's own when it had one, and
    /// otherwise the freshly minted one, which the session must adopt so the
    /// *next* save of a brand-new vault does not mint a second key.
    ///
    /// `None` when the handle came from *opening* a vault rather than writing
    /// one: those bytes are still locked, and the key only appears at unlock.
    pub master: Option<MasterSecret>,
}

// `VaultStorage` is not `Debug` (it is an object-safe trait over backends), but
// every payload in a `Message` has to be. Name the location instead.
impl std::fmt::Debug for VaultHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHandle")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

/// Re-encrypt the vault and write it. **Worker-thread only** — this runs two
/// 600k-iteration key derivations plus (for a server vault) an HTTP round trip.
pub fn write_vault(
    request: SaveRequest,
    location: VaultLocation,
    storage: Arc<dyn VaultStorage>,
) -> Result<VaultHandle, VaultError> {
    // A vault that has never been written has no key yet; mint it here rather
    // than inside `create` so the session can adopt the very key this file was
    // built with.
    let master = request
        .master
        .clone()
        .unwrap_or_else(MasterSecret::generate);

    let file = AskryptFile::create(
        request.questions.clone(),
        request.answers.clone(),
        request.entries.clone(),
        Some(request.iterations),
        request.translit,
        Some(&master),
    )
    .map_err(|e| VaultError::log_crypto("Failed to build vault", e.as_ref()))?;

    storage
        .save_vault(&file)
        .map_err(|e| VaultError::log("Failed to save vault", &e))?;

    Ok(VaultHandle {
        file,
        location,
        storage,
        master: Some(master),
    })
}

/// Shared, screen-independent application state.
pub struct Session {
    pub location: Option<VaultLocation>,
    /// The live backend for `location`, created when the vault is opened and
    /// kept for the lifetime of that vault rather than rebuilt per save.
    ///
    /// This matters for server vaults: `ServerStorage` learns the vault's ETag
    /// when it reads, and sends it back as `If-Match` when it writes. Rebuilding
    /// the backend before each save would fetch whatever ETag the server holds
    /// *now* and happily overwrite another device's edit — the conflict check
    /// only works if the same instance does the read and the write.
    pub storage: Option<Arc<dyn VaultStorage>>,
    pub file: Option<AskryptFile>,
    pub questions_data: Option<QuestionsData>,
    pub question0: String,
    pub answer0: String,
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    /// The open vault's master key, recovered by the unlock that opened it (or
    /// minted by the write that created it).
    ///
    /// Saving hands this back to `AskryptFile::create` instead of letting it
    /// mint a new one, so everything encrypted under the master key — the
    /// coming file attachments — survives the write. `None` means there is no
    /// key to keep: no vault is open, or the one that is has never been
    /// written.
    pub master: Option<MasterSecret>,
    pub unlocked: bool,
    /// Track if vault data has been modified
    pub is_modified: bool,
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
    /// Smart Lock state - stores encrypted answers in RAM
    pub smart_lock_data: Option<SmartLockData>,
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
            location: None,
            storage: None,
            file: None,
            questions_data: None,
            question0: String::new(),
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
            master: None,
            unlocked: false,
            is_modified: false,
            settings,
            server_client,
            server_email,
            link: None,
            link_generation: 0,
            smart_lock_data: None,
            last_user_activity: None,
            tray,
            error_message: None,
            success_message: None,
            status_message: None,
            busy: false,
            spinner_frame: 0,
            spinner_label: "Decrypting…",
            decrypt_started: None,
        }
    }

    pub fn title(&self) -> String {
        if let Some(location) = &self.location {
            let mut title = location.title_name();
            if self.is_modified {
                title.push('*');
            }
            if !self.unlocked {
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

        match &self.location {
            Some(location) => format!(
                "{}{} — {}",
                location.display_name(),
                if self.is_modified { "*" } else { "" },
                crate::vault::Status::of(self).label()
            ),
            // A vault composed in the questions editor has no location yet.
            None if self.questions_data.is_some() => "Untitled vault* — Unlocked".to_string(),
            None => "No vault open".to_string(),
        }
    }

    /// The vault's short name, for headings.
    pub fn display_name(&self) -> String {
        self.location
            .as_ref()
            .map(VaultLocation::display_name)
            .unwrap_or_else(|| "Untitled vault".to_string())
    }

    /// The full "where it lives" line, when the vault has a home.
    pub fn display_location(&self) -> Option<String> {
        self.location.as_ref().map(|location| {
            let prefix = if location.is_server() {
                "Server Vault"
            } else {
                "Vault File"
            };
            format!("{}: {}", prefix, location.display_location())
        })
    }

    /// Update user activity timestamp (for auto Smart Lock after inactivity)
    pub fn update_user_activity(&mut self) {
        if self.unlocked {
            self.last_user_activity = Some(Instant::now());
        }
    }

    /// Whether the configured idle timeout has elapsed and an auto Smart Lock
    /// is due. `LockTimeout::Never` disables the check.
    pub fn should_auto_smart_lock(&self) -> bool {
        let Some(timeout) = self.settings.lock_timeout.duration() else {
            return false;
        };

        self.unlocked
            && !self.answers.is_empty()
            && self
                .last_user_activity
                .is_some_and(|last| last.elapsed() >= timeout)
    }

    /// Whether an active Smart Lock has exceeded its timeout and should fully lock.
    pub fn smart_lock_timed_out(&self) -> bool {
        self.smart_lock_data
            .as_ref()
            .is_some_and(|data| data.last_activity.elapsed() >= SMART_LOCK_TIMEOUT)
    }

    /// Point the session at a vault: remember where it lives and keep the live
    /// backend that was used to open it.
    ///
    /// Always pair the two — a `location` without its `storage` would make the
    /// next save rebuild the backend and lose a server vault's ETag.
    pub fn set_vault_location(&mut self, location: VaultLocation, storage: Arc<dyn VaultStorage>) {
        self.location = Some(location);
        self.storage = Some(storage);
    }

    /// Forget where the current vault lives (on close, or when creating a new
    /// one).
    pub fn clear_vault_location(&mut self) {
        self.location = None;
        self.storage = None;
    }

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
            _ => format!("Failed to {} vault", action),
        });
    }

    // -----------------------------------------------------------------------
    // Saving
    // -----------------------------------------------------------------------

    /// Collect everything the worker needs to re-encrypt this vault.
    ///
    /// `None` when there is no vault to save — no questions have been set, so
    /// there is no key to derive.
    pub fn save_request(&self) -> Option<SaveRequest> {
        let questions_data = self.questions_data.as_ref()?;

        let mut questions = vec![self.question0.clone()];
        questions.extend(questions_data.questions.clone());

        let mut answers = vec![self.answer0.clone()];
        answers.extend(self.answers.clone());

        Some(SaveRequest {
            questions,
            answers,
            entries: self.entries.clone(),
            // Keep the vault's own work factor rather than resetting it to the
            // current default, which would silently weaken (or re-cost) a vault
            // saved somewhere new.
            iterations: self
                .file
                .as_ref()
                .map(|f| f.params.iterations)
                .unwrap_or(DEFAULT_ITERATIONS),
            translit: self.file.as_ref().is_some_and(|f| f.params.translit),
            master: self.master.clone(),
        })
    }

    /// Where a plain "Save" writes: the current vault's location paired with the
    /// very backend instance that opened it. `None` means this vault has never
    /// been persisted, so Save has to become Save As.
    pub fn save_target(&self) -> Option<(VaultLocation, Arc<dyn VaultStorage>)> {
        match (&self.location, &self.storage) {
            (Some(location), Some(storage)) => Some((location.clone(), Arc::clone(storage))),
            _ => None,
        }
    }

    /// Adopt a written vault: it is now the session's vault, at its location,
    /// behind the backend that wrote it.
    pub fn apply_saved(&mut self, saved: VaultHandle) {
        self.set_vault_location(saved.location.clone(), saved.storage);
        self.file = Some(saved.file);
        // Usually the key the session already held; on a brand-new vault's first
        // write it is the one that write minted. Always `Some` here — only the
        // *open* path builds a handle without a key, and that goes to
        // `open_vault`.
        self.master = saved.master;
        self.is_modified = false;
        self.settings.remember_vault(&saved.location);
        self.success_message = Some("Vault saved successfully".into());
    }

    // -----------------------------------------------------------------------
    // Lifecycle transitions
    // -----------------------------------------------------------------------

    /// Adopt a freshly downloaded/loaded vault. Takes the storage instance that
    /// performed the read, not a rebuilt one — see [`Session::storage`].
    pub fn open_vault(
        &mut self,
        location: VaultLocation,
        storage: Arc<dyn VaultStorage>,
        file: AskryptFile,
    ) {
        self.zeroize_secrets();
        self.questions_data = None;
        self.smart_lock_data = None;
        self.unlocked = false;
        self.question0 = file.question0.clone();
        self.file = Some(file);
        self.set_vault_location(location, storage);
        self.is_modified = false;
    }

    /// The full close: forget the vault entirely.
    pub fn close_vault(&mut self) {
        self.clear_vault_location();
        self.file = None;
        self.questions_data = None;
        self.smart_lock_data = None;
        self.question0.clear();
        self.zeroize_secrets();
        self.unlocked = false;
        self.is_modified = false;
        self.settings.last_opened_file = None;
    }

    /// Lock: wipe the secrets and drop back to the first question. The vault
    /// bytes, its location and its backend all stay, so unlocking is local.
    pub fn lock(&mut self) {
        self.zeroize_secrets();
        self.questions_data = None;
        self.smart_lock_data = None;
        self.unlocked = false;
        self.is_modified = false;
    }

    /// Arm Smart Lock: the answers stay in RAM, re-encrypted under one of them.
    pub fn apply_smart_lock(&mut self, data: SmartLockData) {
        self.smart_lock_data = Some(data);
        self.zeroize_secrets();
        self.unlocked = false;
        self.questions_data = None;
    }

    /// Restore a session from Smart Lock. The Smart Lock data is deliberately
    /// *kept* and its clock reset, so the 8-hour window slides with use.
    pub fn apply_smart_unlock(&mut self, unlocked: SmartUnlockResult) {
        self.answer0 = unlocked.answer0;
        self.answers = unlocked.answers;
        self.entries = unlocked.entries;
        self.master = Some(unlocked.master);
        self.questions_data = Some(unlocked.questions_data);
        self.unlocked = true;
        self.last_user_activity = Some(Instant::now());
        if let Some(data) = self.smart_lock_data.as_mut() {
            data.last_activity = Instant::now();
        }
    }

    /// A normal unlock completed: adopt the decrypted entries and the master key
    /// that decrypted them.
    pub fn apply_unlock(&mut self, entries: Vec<SecretEntry>, master: MasterSecret) {
        self.entries = entries;
        self.master = Some(master);
        self.unlocked = true;
        self.last_user_activity = Some(Instant::now());
        if let Some(location) = self.location.clone() {
            // Remembered only on a *successful* unlock, so a vault that cannot
            // be opened never becomes the one reopened at startup.
            self.settings.remember_vault(&location);
        }
    }

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

    // -----------------------------------------------------------------------
    // Smart Lock crypto. Associated functions, so they can run on a worker
    // thread with owned inputs instead of borrowing `self`.
    // -----------------------------------------------------------------------

    /// Create Smart Lock data by encrypting all answers with a randomly selected
    /// answer. Uses 2,000,000 iterations for key derivation as specified.
    pub fn create_smart_lock_data(
        answers: &[String],
        answer0: &str,
        questions: &[String],
        translit: bool,
    ) -> Result<SmartLockData, Box<dyn std::error::Error>> {
        // Randomly select an answer index (not the first one)
        // answers vector contains answers for questions 2, 3, etc.
        // So we pick a random index from 1 to answers.len() (inclusive)
        if answers.is_empty() {
            return Err("Need at least 2 questions for Smart Lock".into());
        }

        let mut rng = rand::rng();
        // index 1 corresponds to answers[0], index 2 to answers[1], etc.
        let key_answer_index = rng.random_range(1..=answers.len());
        let key_answer = Zeroizing::new(
            answers
                .get(key_answer_index - 1)
                .cloned()
                .unwrap_or_default(),
        );

        if key_answer.is_empty() {
            return Err("Selected answer is empty".into());
        }
        // Get the question text for display on the Smart Lock screen
        let key_question = questions
            .get(key_answer_index - 1)
            .cloned()
            .unwrap_or_else(|| format!("Question {}", key_answer_index + 1));

        let salt = generate_bytes(16);
        // One IV per ciphertext — see `SmartLockData::iv_answer0`.
        let iv_answer0 = generate_bytes(16);
        let iv_answers = generate_bytes(16);

        // Derive encryption key from the selected answer using PBKDF2
        let normalized_answer = Zeroizing::new(normalize_answer(&key_answer, translit));
        let salt_b64 = encode_base64(&salt);
        let hashed_answer = Zeroizing::new(sha256(&normalized_answer, &salt_b64));
        // Derive the key into a self-zeroizing array (a plain `try_into` would
        // free the PBKDF2 `Vec` without wiping it).
        let key = Zeroizing::new(calc_pbkdf2(&hashed_answer, &salt, SMART_LOCK_ITERATIONS)?);
        if key.len() != 32 {
            return Err("Invalid key length".into());
        }
        let mut key_array = Zeroizing::new([0u8; 32]);
        key_array.copy_from_slice(&key);
        let iv0_array: [u8; 16] = iv_answer0
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid IV length")?;
        let iv1_array: [u8; 16] = iv_answers
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid IV length")?;

        // Serialize answer0 and encrypt
        let encrypted_answer0 = encrypt_with_aes(answer0.as_bytes(), &key_array, &iv0_array)?;

        // Serialize all other answers (excluding the key answer) and encrypt
        // We store all answers but the decryption will know which one was the key
        let answers_json = Zeroizing::new(serde_json::to_string(answers)?);
        let encrypted_answers = encrypt_with_aes(answers_json.as_bytes(), &key_array, &iv1_array)?;

        Ok(SmartLockData {
            key_answer_index,
            key_question,
            encrypted_answer0,
            encrypted_answers,
            salt,
            iv_answer0,
            iv_answers,
            last_activity: Instant::now(),
        })
    }

    /// Decrypt Smart Lock data using the provided answer (2M-iteration PBKDF2).
    /// Returns the decrypted answer0 and answers vector.
    pub fn decrypt_smart_lock_data(
        smart_lock_data: &SmartLockData,
        answer: &str,
        translit: bool,
    ) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        // Derive decryption key from the provided answer
        let normalized_answer = Zeroizing::new(normalize_answer(answer, translit));
        let salt_b64 = encode_base64(&smart_lock_data.salt);
        let hashed_answer = Zeroizing::new(sha256(&normalized_answer, &salt_b64));
        // Derive the key into a self-zeroizing array (a plain `try_into` would
        // free the PBKDF2 `Vec` without wiping it).
        let key = Zeroizing::new(calc_pbkdf2(
            &hashed_answer,
            &smart_lock_data.salt,
            SMART_LOCK_ITERATIONS,
        )?);
        if key.len() != 32 {
            return Err("Invalid key length".into());
        }
        let mut key_array = Zeroizing::new([0u8; 32]);
        key_array.copy_from_slice(&key);
        let iv0_array: [u8; 16] = smart_lock_data
            .iv_answer0
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid IV length")?;
        let iv1_array: [u8; 16] = smart_lock_data
            .iv_answers
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid IV length")?;

        // Decrypt answer0 (returned to the caller, which wipes it on lock)
        let answer0_bytes =
            decrypt_with_aes(&smart_lock_data.encrypted_answer0, &key_array, &iv0_array)?;
        let answer0 = String::from_utf8(answer0_bytes)?;

        // Decrypt answers
        let answers_bytes =
            decrypt_with_aes(&smart_lock_data.encrypted_answers, &key_array, &iv1_array)?;
        // `from_utf8` reuses the decrypted buffer (no copy); wipe the plaintext JSON on drop.
        let answers_json = Zeroizing::new(String::from_utf8(answers_bytes)?);
        let answers: Vec<String> = serde_json::from_str(&answers_json)?;

        Ok((answer0, answers))
    }

    /// Wipe all decrypted secret material from memory. Used by the lock paths.
    pub fn zeroize_secrets(&mut self) {
        self.answer0.zeroize();
        self.answers.zeroize();
        self.entries.zeroize();
        // Dropping the `MasterSecret` wipes it. The next unlock recovers the
        // same key from the file, so nothing is lost by not keeping it here —
        // and a locked session must not hold the key to its own data.
        self.master = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askrypt::LocalFileStorage;

    fn entry(name: &str) -> SecretEntry {
        SecretEntry {
            name: name.to_string(),
            user_name: "testingaccount".to_string(),
            secret: "hunter2".to_string(),
            url: "https://example.com".to_string(),
            notes: String::new(),
            entry_type: "Login".to_string(),
            tags: vec!["work".to_string()],
            created: 1_581_428_873,
            modified: 1_581_428_873,
            hidden: false,
            card: Default::default(),
        }
    }

    /// The whole save path, end to end: what the UI collects, re-encrypted and
    /// written, then read back through the layered unlock the way opening it
    /// again would. A low iteration count keeps it fast; the KDF itself is
    /// `core`'s to test.
    #[test]
    fn a_written_vault_reads_back_through_the_layered_unlock() {
        let path = std::env::temp_dir().join(format!(
            "askrypt-gui-roundtrip-{}.askrypt",
            std::process::id()
        ));
        let storage: Arc<dyn VaultStorage> = Arc::new(LocalFileStorage::new(path.clone()));
        let location = VaultLocation::LocalFile(path.clone());

        let request = SaveRequest {
            questions: vec!["First pet?".to_string(), "First street?".to_string()],
            answers: vec!["Rex".to_string(), "Baker Street".to_string()],
            entries: vec![entry("GitHub")],
            iterations: 1_000,
            translit: false,
            // A vault that has never been written: `write_vault` mints its key.
            master: None,
        };

        let handle = write_vault(request, location.clone(), Arc::clone(&storage))
            .expect("the vault should be written");
        assert_eq!(handle.location, location);

        // Saving stamps the vault unencrypted, which is what the locked screens
        // read to say when it was last written and from where.
        assert!(handle.file.params.updated_at.is_some());

        let reopened = storage.load_vault().expect("the vault should load");
        assert_eq!(reopened.question0, "First pet?");

        let questions_data = reopened
            .get_questions_data("Rex".to_string())
            .expect("the first answer should decrypt the question list");
        assert_eq!(questions_data.questions, vec!["First street?".to_string()]);

        let entries = reopened
            .decrypt(&questions_data, vec!["Baker Street".to_string()])
            .expect("the remaining answers should decrypt the entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
        assert_eq!(entries[0].secret, "hunter2");
        // `created` is carried across a save; only `modified` is ever restamped.
        assert_eq!(entries[0].created, 1_581_428_873);

        // A wrong first answer is not reported — it simply fails to decrypt.
        assert!(reopened.get_questions_data("Fido".to_string()).is_err());

        std::fs::remove_file(&path).ok();
    }

    /// The first write of a brand-new vault mints the master key and hands it
    /// back, and every write after that re-wraps that same key. Without the
    /// hand-back, a new vault would mint a second key on its second save and
    /// orphan anything encrypted under the first.
    #[test]
    fn a_new_vault_keeps_the_key_its_first_write_minted() {
        let path =
            std::env::temp_dir().join(format!("askrypt-gui-master-{}.askrypt", std::process::id()));
        let storage: Arc<dyn VaultStorage> = Arc::new(LocalFileStorage::new(path.clone()));
        let location = VaultLocation::LocalFile(path.clone());

        let request = SaveRequest {
            questions: vec!["First pet?".to_string(), "First street?".to_string()],
            answers: vec!["Rex".to_string(), "Baker Street".to_string()],
            entries: vec![entry("GitHub")],
            iterations: 1_000,
            translit: false,
            master: None,
        };
        let first = write_vault(request, location.clone(), Arc::clone(&storage))
            .expect("the vault should be written");
        let minted = first.master.expect("a first write mints a key");

        // What `Session::apply_saved` then `Session::save_request` would carry.
        let request = SaveRequest {
            questions: vec!["First pet?".to_string(), "First street?".to_string()],
            answers: vec!["Rex".to_string(), "Baker Street".to_string()],
            entries: vec![entry("GitHub"), entry("GitLab")],
            iterations: 1_000,
            translit: false,
            master: Some(minted.clone()),
        };
        let second = write_vault(request, location, Arc::clone(&storage))
            .expect("the vault should be written again");
        assert_eq!(second.master.as_ref(), Some(&minted));

        // And the key really is the one the file on disk is keyed on.
        let reopened = storage.load_vault().expect("the vault should load");
        let questions_data = reopened.get_questions_data("Rex".to_string()).unwrap();
        let (entries, on_disk) = reopened
            .decrypt_with_master(&questions_data, vec!["Baker Street".to_string()])
            .expect("the remaining answers should decrypt the entries");
        assert_eq!(on_disk, minted);
        assert_eq!(entries.len(), 2);

        std::fs::remove_file(&path).ok();
    }

    /// Answers are normalized before they reach the KDF, so the same answer
    /// typed differently still opens the vault.
    #[test]
    fn answers_are_normalized_the_same_way_on_both_sides() {
        let path = std::env::temp_dir().join(format!(
            "askrypt-gui-normalize-{}.askrypt",
            std::process::id()
        ));
        let storage: Arc<dyn VaultStorage> = Arc::new(LocalFileStorage::new(path.clone()));

        let request = SaveRequest {
            questions: vec!["First pet?".to_string(), "First street?".to_string()],
            answers: vec!["Rex".to_string(), "Baker-Street".to_string()],
            entries: vec![entry("GitHub")],
            iterations: 1_000,
            translit: false,
            // A vault that has never been written: `write_vault` mints its key.
            master: None,
        };
        write_vault(
            request,
            VaultLocation::LocalFile(path.clone()),
            Arc::clone(&storage),
        )
        .expect("the vault should be written");

        let reopened = storage.load_vault().expect("the vault should load");
        let questions_data = reopened
            .get_questions_data("  rEx ".to_string())
            .expect("case and spacing should not matter");
        assert!(
            reopened
                .decrypt(&questions_data, vec!["baker street".to_string()])
                .is_ok(),
            "dashes and case should not matter"
        );

        std::fs::remove_file(&path).ok();
    }
}
