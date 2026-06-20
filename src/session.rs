//! Shared application state and vault-lifecycle helpers.
//!
//! [`Session`] holds everything that is *not* specific to a single screen: the
//! loaded vault, the decrypted secrets, persistent settings, the system tray,
//! the status/error messages, and the background-decryption spinner state. Each
//! screen module borrows `&mut Session` to read or mutate this shared state,
//! while keeping its own UI fields in a per-screen `State` struct.

use crate::settings::AppSettings;
use crate::tray::AppTray;
use askrypt::{
    AskryptFile, QuestionsData, SecretEntry, calc_pbkdf2, decrypt_with_aes, encode_base64,
    encrypt_with_aes, generate_salt, normalize_answer, sha256,
};
use rand::RngExt;
use rfd::MessageDialogResult;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Default number of iterations for key derivation (OWASP recommendation for 2025)
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const APP_TITLE: &str = "Askrypt 0.6.1-dev"; // TODO: get version from Cargo.toml
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
    pub path: Option<PathBuf>,
    pub file: Option<AskryptFile>,
    pub questions_data: Option<QuestionsData>,
    pub question0: String,
    pub answer0: String,
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    pub unlocked: bool,
    /// Track if vault data has been modified
    pub is_modified: bool,
    /// Application settings
    pub settings: AppSettings,
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

        Self {
            path: None,
            file: None,
            questions_data: None,
            question0: String::new(),
            answer0: String::new(),
            answers: Vec::new(),
            entries: Vec::new(),
            unlocked: false,
            is_modified: false,
            settings,
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
        if let Some(path) = &self.path {
            let mut title = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Untitled")
                .to_string();
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

    /// Save the current vault to its existing path (falling back to "Save As"
    /// when the vault has never been written to disk).
    pub fn save_vault(&mut self) {
        if let (Some(path), Some(file), Some(questions_data)) =
            (&self.path, &self.file, &self.questions_data)
        {
            // Reconstruct questions list
            let mut questions = vec![self.question0.clone()];
            questions.extend(questions_data.questions.clone());

            // Reconstruct answers list
            let mut all_answers = vec![self.answer0.clone()];
            all_answers.extend(self.answers.clone());

            // Create new AskryptFile with current entries
            match AskryptFile::create(
                questions,
                all_answers,
                self.entries.clone(),
                Some(file.params.iterations),
                file.params.translit,
            ) {
                Ok(new_file) => match new_file.save_to_file(path) {
                    Ok(_) => {
                        self.file = Some(new_file);
                        self.is_modified = false;
                        self.success_message = Some("Vault saved successfully".into());
                    }
                    Err(e) => {
                        eprintln!("ERROR: Failed to save vault: {}", e);
                        self.error_message = Some("Failed to save vault".into());
                    }
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

            // Create new AskryptFile with current entries
            match AskryptFile::create(
                questions,
                all_answers,
                self.entries.clone(),
                Some(DEFAULT_ITERATIONS), // TODO: allow user to set this iterations
                self.file.as_ref().is_some_and(|f| f.params.translit),
            ) {
                Ok(new_file) => match new_file.save_to_file(&new_path) {
                    Ok(_) => {
                        self.path = Some(new_path.clone());
                        self.file = Some(new_file);
                        self.is_modified = false;
                        self.success_message = Some("Vault saved successfully".into());
                        self.settings.last_opened_file = Some(new_path);
                    }
                    Err(e) => {
                        eprintln!("ERROR: Failed to save vault: {}", e);
                        self.error_message = Some("Failed to save vault".into());
                    }
                },
                Err(e) => {
                    eprintln!("ERROR: Failed to create vault: {}", e);
                    self.error_message = Some("Failed to save vault".into());
                }
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

        let salt = generate_salt(16);
        let iv = generate_salt(16);

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
    }
}
