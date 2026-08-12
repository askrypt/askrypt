//! Shared application state and vault-lifecycle helpers.
//!
//! [`Session`] holds everything that is *not* specific to a single screen: the
//! loaded vault, the decrypted secrets, persistent settings, the system tray,
//! the status/error messages, and the background-decryption spinner state. Each
//! screen module borrows `&mut Session` to read or mutate this shared state,
//! while keeping its own UI fields in a per-screen `State` struct.

use crate::settings::{AppSettings, ServerSession, VaultLocation};
use crate::tray::AppTray;
use askrypt::{
    AskryptFile, MasterSecret, QuestionsData, SecretEntry, ServerClient, StorageError,
    VaultStorage, calc_pbkdf2, decrypt_with_aes, encode_base64, encrypt_with_aes, generate_bytes,
    normalize_answer, sha256,
};
use rand::RngExt;
use rfd::MessageDialogResult;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Default number of iterations for key derivation (OWASP recommendation for 2025)
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const APP_TITLE: &str = "Askrypt 0.6.2-dev"; // TODO: get version from Cargo.toml
/// Iterations for Smart Lock encryption (2,000,000 as specified)
pub const SMART_LOCK_ITERATIONS: u32 = 2_000_000;
/// Smart Lock timeout duration (8 hours)
pub const SMART_LOCK_TIMEOUT: Duration = Duration::from_hours(8);
/// Inactivity timeout for auto Smart Lock (10 minutes)
pub const INACTIVITY_TIMEOUT: Duration = Duration::from_mins(10);

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
    /// Retained for diagnostics; decryption keys off the stored salt/iv, not this.
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
    /// IV used for encryption
    pub iv: Vec<u8>,
    /// Timestamp of last activity (for 8-hour timeout)
    pub last_activity: Instant,
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
    /// The open vault's master key, recovered by the unlock that opened it.
    ///
    /// Every save hands this back to `AskryptFile::create` instead of letting it
    /// mint a new one, so anything else encrypted under the master key survives
    /// the write. `None` means no vault is open, or the open one has never been
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
    /// Smart Lock state - stores encrypted answers in RAM
    pub smart_lock_data: Option<SmartLockData>,
    /// Last user activity timestamp for auto Smart Lock
    pub last_user_activity: Option<Instant>,
    /// System tray
    pub tray: Option<AppTray>,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
    pub status_message: Option<String>,
    /// True while a background unlock/decryption task is running
    pub decrypting: bool,
    /// Current frame of the spinner animation
    pub spinner_frame: usize,
    /// Label shown next to the spinner ("Decrypting…" or "Locking…")
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
            smart_lock_data: None,
            last_user_activity: None,
            tray,
            error_message: None,
            success_message: None,
            status_message: None,
            decrypting: false,
            spinner_frame: 0,
            spinner_label: "Decrypting…",
            decrypt_started: None,
        }
    }

    pub fn title(&self) -> String {
        if let Some(location) = &self.location {
            let mut title = location.display_name();
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

    /// Update user activity timestamp (for auto Smart Lock after inactivity)
    pub fn update_user_activity(&mut self) {
        if self.unlocked {
            self.last_user_activity = Some(Instant::now());
        }
    }

    /// Whether the inactivity timeout has elapsed and an auto Smart Lock is due.
    pub fn should_auto_smart_lock(&self) -> bool {
        self.unlocked
            && !self.answers.is_empty()
            && self
                .last_user_activity
                .is_some_and(|last| last.elapsed() >= INACTIVITY_TIMEOUT)
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

    /// Turn a storage failure into the sentence shown in the status bar, and
    /// react to the ones that change session state.
    ///
    /// The details go to stderr; the user gets something they can act on.
    fn report_storage_error(&mut self, action: &str, error: &StorageError) {
        eprintln!("ERROR: Failed to {} vault: {}", action, error);
        self.error_message = Some(match error {
            StorageError::Conflict(_) => {
                "This vault was changed elsewhere since you opened it. Reload before saving."
                    .to_string()
            }
            StorageError::Auth(_) => {
                // The token is dead; stop pretending we are signed in.
                self.sign_out();
                "Your server session expired. Sign in again.".to_string()
            }
            StorageError::Network(_) => {
                format!("Could not reach the server to {} the vault", action)
            }
            StorageError::Remote { code, .. } if code == "quota_exceeded" => {
                "Your server storage quota is full".to_string()
            }
            StorageError::Remote { code, .. } if code == "vault_limit_reached" => {
                "You have reached the vault limit on this server".to_string()
            }
            StorageError::Remote { code, .. } if code == "payload_too_large" => {
                "This vault is too large for the server".to_string()
            }
            _ => format!("Failed to {} vault", action),
        });
    }

    /// Save the current vault to its existing location (falling back to
    /// "Save As" when the vault has never been persisted).
    pub fn save_vault(&mut self) {
        let storage = self.storage.clone();
        if let (Some(storage), Some(file), Some(questions_data)) =
            (storage, &self.file, &self.questions_data)
        {
            // Reconstruct questions list
            let mut questions = vec![self.question0.clone()];
            questions.extend(questions_data.questions.clone());

            // Reconstruct answers list
            let mut all_answers = vec![self.answer0.clone()];
            all_answers.extend(self.answers.clone());

            // Re-wrap the vault's own master key rather than minting a new one,
            // so everything encrypted under it survives the write.
            let master = self.master.clone().unwrap_or_else(MasterSecret::generate);

            // Create new AskryptFile with current entries
            match AskryptFile::create(
                questions,
                all_answers,
                self.entries.clone(),
                Some(file.params.iterations),
                file.params.translit,
                Some(&master),
            ) {
                Ok(new_file) => match storage.save_vault(&new_file) {
                    Ok(_) => {
                        self.file = Some(new_file);
                        self.master = Some(master);
                        self.is_modified = false;
                        self.success_message = Some("Vault saved successfully".into());
                    }
                    Err(e) => self.report_storage_error("save", &e),
                },
                Err(e) => {
                    eprintln!("ERROR: Failed to create vault: {}", e);
                    self.error_message = Some("Failed to save vault".into());
                }
            }
        } else if self.questions_data.is_some() {
            self.save_vault_as();
        } else {
            self.error_message = Some("No vault loaded".into());
        }
    }

    /// Prompt for a destination path and save the current vault there.
    pub fn save_vault_as(&mut self) {
        if let Some(new_path) = rfd::FileDialog::new()
            .add_filter("Askrypt Files", &["askrypt"])
            .add_filter("All files", &["*"])
            .set_file_name("MyVault.askrypt")
            .save_file()
        {
            // Reconstruct questions list
            let mut questions = vec![self.question0.clone()];
            if let Some(qs_data) = &self.questions_data {
                questions.extend(qs_data.questions.clone());
            }

            // Reconstruct answers list
            let mut all_answers = vec![self.answer0.clone()];
            all_answers.extend(self.answers.clone());

            let location = VaultLocation::LocalFile(new_path);
            // A local file never needs a client, so this cannot fail.
            let storage = match location.storage(None) {
                Ok(storage) => storage,
                Err(e) => {
                    self.report_storage_error("save", &e);
                    return;
                }
            };

            // A copy of the same vault, so it keeps the same master key.
            let master = self.master.clone().unwrap_or_else(MasterSecret::generate);

            // Create new AskryptFile with current entries
            match AskryptFile::create(
                questions,
                all_answers,
                self.entries.clone(),
                Some(DEFAULT_ITERATIONS), // TODO: allow user to set this iterations
                self.file.as_ref().is_some_and(|f| f.params.translit),
                Some(&master),
            ) {
                Ok(new_file) => match storage.save_vault(&new_file) {
                    Ok(_) => {
                        self.set_vault_location(location.clone(), storage);
                        self.file = Some(new_file);
                        self.master = Some(master);
                        self.is_modified = false;
                        self.success_message = Some("Vault saved successfully".into());
                        self.settings.last_opened_file = Some(location);
                    }
                    Err(e) => self.report_storage_error("save", &e),
                },
                Err(e) => {
                    eprintln!("ERROR: Failed to create vault: {}", e);
                    self.error_message = Some("Failed to save vault".into());
                }
            }
        }
    }

    /// Save the current vault to a *new* server location, then adopt it as the
    /// session's vault location so later saves go to the server too.
    ///
    /// Runs the upload inline (see the note on `save_vault`); vaults are small,
    /// so this is a brief pause rather than a visible freeze.
    pub fn save_vault_to_server(&mut self, name: &str) -> bool {
        let Some(client) = self.server_client.clone() else {
            self.error_message = Some("Not signed in to a server".into());
            return false;
        };

        let location = VaultLocation::Server {
            base_url: client.base_url().to_string(),
            email: self.server_email.clone().unwrap_or_default(),
            name: name.to_string(),
        };
        let storage = match self.storage_for(&location) {
            Ok(storage) => storage,
            Err(e) => {
                self.report_storage_error("save", &e);
                return false;
            }
        };

        // Reconstruct questions list
        let mut questions = vec![self.question0.clone()];
        if let Some(qs_data) = &self.questions_data {
            questions.extend(qs_data.questions.clone());
        }

        // Reconstruct answers list
        let mut all_answers = vec![self.answer0.clone()];
        all_answers.extend(self.answers.clone());

        let iterations = self
            .file
            .as_ref()
            .map(|f| f.params.iterations)
            .unwrap_or(DEFAULT_ITERATIONS);

        // The same vault, stored somewhere else: same master key.
        let master = self.master.clone().unwrap_or_else(MasterSecret::generate);

        match AskryptFile::create(
            questions,
            all_answers,
            self.entries.clone(),
            Some(iterations),
            self.file.as_ref().is_some_and(|f| f.params.translit),
            Some(&master),
        ) {
            Ok(new_file) => match storage.save_vault(&new_file) {
                Ok(_) => {
                    self.set_vault_location(location.clone(), storage);
                    self.file = Some(new_file);
                    self.master = Some(master);
                    self.is_modified = false;
                    self.success_message = Some("Vault saved to the server".into());
                    self.settings.last_opened_file = Some(location);
                    true
                }
                Err(e) => {
                    self.report_storage_error("save", &e);
                    false
                }
            },
            Err(e) => {
                eprintln!("ERROR: Failed to create vault: {}", e);
                self.error_message = Some("Failed to save vault".into());
                false
            }
        }
    }

    /// Ask user about unsaved changes. Returns true if it's okay to proceed, false to cancel.
    pub fn ask_user_about_changes(&mut self) -> bool {
        if self.is_modified {
            let result = rfd::MessageDialog::new()
                .set_title("Unsaved Changes")
                .set_description("You have unsaved changes. Would you like to save them?")
                .set_buttons(rfd::MessageButtons::YesNoCancel)
                .show();

            match result {
                MessageDialogResult::Yes => {
                    self.save_vault();
                }
                MessageDialogResult::Cancel => {
                    return false;
                }
                _ => {
                    // do nothing
                }
            }
        }
        true
    }

    /// Create Smart Lock data by encrypting all answers with a randomly selected
    /// answer. Uses 2,000,000 iterations for key derivation as specified.
    ///
    /// Runs on a worker thread, so it takes owned inputs instead of borrowing
    /// `self`.
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
        let iv = generate_bytes(16);

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
        let iv_array: [u8; 16] = iv.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Serialize answer0 and encrypt
        let encrypted_answer0 = encrypt_with_aes(answer0.as_bytes(), &key_array, &iv_array)?;

        // Serialize all other answers (excluding the key answer) and encrypt
        // We store all answers but the decryption will know which one was the key
        let answers_json = Zeroizing::new(serde_json::to_string(answers)?);
        let encrypted_answers = encrypt_with_aes(answers_json.as_bytes(), &key_array, &iv_array)?;

        Ok(SmartLockData {
            key_answer_index,
            key_question,
            encrypted_answer0,
            encrypted_answers,
            salt,
            iv,
            last_activity: Instant::now(),
        })
    }

    /// Decrypt Smart Lock data using the provided answer (2M-iteration PBKDF2).
    /// Runs on a worker thread, so it borrows plain data instead of `self`.
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
        let iv_array: [u8; 16] = smart_lock_data
            .iv
            .clone()
            .try_into()
            .map_err(|_| "Invalid IV length")?;

        // Decrypt answer0 (returned to the caller, which wipes it on lock)
        let answer0_bytes =
            decrypt_with_aes(&smart_lock_data.encrypted_answer0, &key_array, &iv_array)?;
        let answer0 = String::from_utf8(answer0_bytes)?;

        // Decrypt answers
        let answers_bytes =
            decrypt_with_aes(&smart_lock_data.encrypted_answers, &key_array, &iv_array)?;
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
        // Dropping the `MasterSecret` wipes it; the next unlock recovers the
        // same key from the file.
        self.master = None;
    }
}
