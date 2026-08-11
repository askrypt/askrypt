//! # Askrypt - Secure Password Manager Library
//!
//! Askrypt is a library for creating and managing encrypted password vaults using
//! a question-and-answer based authentication system.
//!
//! ## Overview
//!
//! The library implements a multi-layered encryption scheme where:
//! - The first answer encrypts additional questions
//! - Remaining answers encrypt the master key
//! - The master key encrypts your actual secret data
//!
//! ## Quick Start Example
//!
//! ```
//! use askrypt::{AskryptFile, SecretEntry};
//!
//! // Define your security questions
//! let questions = vec![
//!     "What is your mother's maiden name?".to_string(),
//!     "What was your first pet's name?".to_string(),
//!     "What city were you born in?".to_string(),
//! ];
//!
//! // Provide answers
//! let answers = vec![
//!     "Smith".to_string(),
//!     "Fluffy".to_string(),
//!     "New York".to_string(),
//! ];
//!
//! // Create secret entries to store
//! let secrets = vec![
//!     SecretEntry {
//!         name: "Gmail".to_string(),
//!         user_name: "user2".to_string(),
//!         secret: "my_super_secret_password".to_string(),
//!         url: "https://gmail.com".to_string(),
//!         notes: "Personal email account".to_string(),
//!         entry_type: "password".to_string(),
//!         tags: vec!["email".to_string(), "personal".to_string()],
//!         created: 1704067200,
//!         modified: 1704067200,
//!         hidden: false,
//!         card: Default::default(),
//!     }
//! ];
//!
//! // Create the encrypted file
//! let askrypt_file = AskryptFile::create(
//!     questions,
//!     answers.clone(),
//!     secrets.clone(),
//!     Some(5000),
//!     false,
//! ).unwrap();
//!
//! // Save to disk
//! askrypt_file.save_to_file("my_vault.askrypt").unwrap();
//!
//! // Later, load and decrypt
//! let loaded = AskryptFile::load_from_file("my_vault.askrypt").unwrap();
//! let question_data = loaded.get_questions_data("Smith".into()).unwrap();
//! let decrypted_secrets = loaded.decrypt(&question_data, answers[1..].into()).unwrap();
//!
//! assert_eq!(decrypted_secrets, secrets);
//! # std::fs::remove_file("my_vault.askrypt").ok();
//! ```

pub mod passgen;
pub mod storage;
pub mod translit;
pub mod types;

#[cfg(feature = "server-storage")]
pub use storage::{
    BrowserLogin, BrowserLoginStatus, RemoteVault, ServerClient, ServerStorage, normalize_base_url,
};
pub use storage::{LocalFileStorage, MemoryStorage, StorageError, VaultStorage};
pub use types::*;

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const DEFAULT_KDF: &str = "pbkdf2";

/// Derive a 32-byte key via PBKDF2 into a self-zeroizing array.
///
/// Both the intermediate PBKDF2 buffer and the returned array wipe themselves on
/// drop, so no plaintext copy of the derived key lingers in freed memory (unlike
/// `calc_pbkdf2(..)?.try_into()`, which frees the `Vec` without wiping it).
fn derive_key(
    secret: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let key = Zeroizing::new(calc_pbkdf2(secret, salt, iterations)?);
    if key.len() != 32 {
        return Err("Invalid key length".into());
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key);
    Ok(key_array)
}

impl AskryptFile {
    /// Create a new AskryptFile from questions, answers, and secret data
    ///
    /// # Arguments
    ///
    /// * `questions` - A vector of at least 2 questions
    /// * `answers` - A vector of answers (same length as questions)
    /// * `secret_data` - A vector of SecretEntry items to encrypt
    /// * `iterations` - Optional iterations for first KDF (default: 600000)
    ///
    /// # Returns
    ///
    /// Returns a Result containing the AskryptFile or an error
    ///
    /// # Example
    ///
    /// ```
    /// use askrypt::{AskryptFile, SecretEntry};
    ///
    /// let questions = vec![
    ///     "What is your mother's maiden name?".to_string(),
    ///     "What was your first pet's name?".to_string(),
    ///     "What city were you born in?".to_string(),
    /// ];
    /// let answers = vec![
    ///     "Smith".to_string(),
    ///     "Fluffy".to_string(),
    ///     "New York".to_string(),
    /// ];
    /// let data = vec![
    ///     SecretEntry {
    ///         name: "example".to_string(),
    ///         user_name: "user5".to_string(),
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: 1704067200,
    ///         modified: 1704067200,
    ///         hidden: false,
    ///         card: Default::default(),
    ///     }
    /// ];
    ///
    /// let askrypt_file = AskryptFile::create(questions, answers, data, Some(6000), false).unwrap();
    /// ```
    pub fn create(
        questions: Vec<String>,
        answers: Vec<String>,
        secret_data: Vec<SecretEntry>,
        iterations: Option<u32>,
        translit: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate inputs
        if questions.len() < 2 {
            return Err("At least 2 questions is required".into());
        }
        if questions.len() != answers.len() {
            return Err("Number of questions and answers must match".into());
        }
        for question in &questions {
            if question.len() > 500 {
                return Err("Question length must not exceed 500 characters".into());
            }
        }

        let answers: Zeroizing<Vec<String>> = Zeroizing::new(
            answers
                .into_iter()
                .map(|a| normalize_answer(&a, translit))
                .collect(),
        );

        let iterations = iterations.unwrap_or(600000);

        // Step 1: Generate random values (the master key is secret)
        let salt0 = generate_salt(16);
        let salt1 = generate_salt(16);
        let master_key_bytes = Zeroizing::new(generate_salt(32));
        let iv_bytes = generate_salt(16);

        // Step 2: Derive first-key from first answer and salt0
        let salt0_b64 = encode_base64(&salt0);
        // first answer is hashed with salt0 before PBKDF2
        let first_hash = Zeroizing::new(sha256(&answers[0], &salt0_b64));
        let first_key_array = derive_key(&first_hash, &salt0, iterations)?;
        let salt0_iv: [u8; 16] = salt0.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 3: Encrypt questions data (all questions except the first) using first-key and salt0 as IV
        let remaining_questions: Vec<String> = questions.iter().skip(1).cloned().collect();
        let questions_data = QuestionsData {
            questions: remaining_questions,
            salt: encode_base64(&salt1),
        };
        let qs = encrypt_to_base64(&questions_data, &first_key_array, &salt0_iv)?;

        // Step 4: Derive second-key from combined remaining answers and salt1
        let combined_answers: Zeroizing<String> =
            Zeroizing::new(answers.iter().skip(1).cloned().collect());
        // combined_answers is hashed with salt0 before PBKDF2
        let second_hash = Zeroizing::new(sha256(&combined_answers, &salt0_b64));
        let second_key_array = derive_key(&second_hash, &salt1, iterations)?;
        let salt1_iv: [u8; 16] = salt1.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 5: Encrypt master key and IV using second-key and salt1 as IV
        let master_data = MasterData {
            master_key: encode_base64(&master_key_bytes),
            iv: encode_base64(&iv_bytes),
        };
        let master = encrypt_to_base64(&master_data, &second_key_array, &salt1_iv)?;

        // Step 6: Encrypt secret data using master key and IV
        let mut master_key_array = Zeroizing::new([0u8; 32]);
        if master_key_bytes.len() != 32 {
            return Err("Invalid master key length".into());
        }
        master_key_array.copy_from_slice(&master_key_bytes);
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;
        let data = encrypt_to_base64(&secret_data, &master_key_array, &iv_array)?;

        // Step 7: Create and return AskryptFile
        let mut file = AskryptFile {
            version: "0.9".to_string(),
            question0: questions[0].clone(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations,
                salt: salt0_b64,
                translit,
                host: None,
                updated_at: None,
            },
            qs,
            master,
            data,
        };
        // Every write goes through `create` (the vault is re-encrypted from
        // scratch on each save), so stamping here keeps the fields current.
        file.touch();
        Ok(file)
    }

    /// Stamp `params.host` and `params.updated_at` with this machine and the
    /// current UTC time.
    ///
    /// Called by [`create`](Self::create); call it directly only when writing a
    /// vault that was not rebuilt through `create`.
    pub fn touch(&mut self) {
        self.params.host = current_host();
        self.params.updated_at = Some(now_utc_rfc3339());
    }

    /// Decrypt an AskryptFile and retrieve the secret data using the answers
    ///
    /// # Arguments
    ///
    /// * `answers` - A vector of answers
    ///
    /// # Returns
    ///
    /// Returns a Result containing the decrypted Vec<SecretEntry> or an error
    ///
    /// # Example
    ///
    /// ```
    /// use askrypt::{AskryptFile, SecretEntry };
    ///
    /// let questions = vec![
    ///     "What is your mother's maiden name?".to_string(),
    ///     "What was your first pet's name?".to_string(),
    ///     "What city were you born in?".to_string(),
    /// ];
    /// let answers = vec![
    ///     "Smith".to_string(),
    ///     "Fluffy".to_string(),
    ///     "New York".to_string(),
    /// ];
    /// let data = vec![
    ///     SecretEntry {
    ///         name: "example".to_string(),
    ///         user_name: "user5".to_string(),
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: 1704067200,
    ///         modified: 1704067200,
    ///         hidden: false,
    ///         card: Default::default(),
    ///     }
    /// ];
    ///
    /// let askrypt_file = AskryptFile::create(questions, answers.clone(), data.clone(), Some(6000), false).unwrap();
    /// let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
    /// let decrypted_data = askrypt_file.decrypt(&questions_data, answers[1..].into()).unwrap();
    /// assert_eq!(decrypted_data, data);
    /// ```
    pub fn decrypt(
        &self,
        questions_data: &QuestionsData,
        answers: Vec<String>,
    ) -> Result<Vec<SecretEntry>, Box<dyn std::error::Error>> {
        // Validate inputs
        if answers.is_empty() {
            return Err("At least 1 answer is required".into());
        }

        if questions_data.questions.len() != answers.len() {
            return Err("Number of questions and answers must match".into());
        }

        // Decode salt1
        let salt1 = decode_base64(&questions_data.salt)?;
        let salt1_iv: [u8; 16] = salt1.try_into().map_err(|_| "Invalid salt1 length")?;

        let answers: Zeroizing<Vec<String>> = Zeroizing::new(
            answers
                .into_iter()
                .map(|a| normalize_answer(&a, self.params.translit))
                .collect(),
        );
        // Derive second-key from combined remaining answers and salt1
        let combined_answers: Zeroizing<String> = Zeroizing::new(answers.iter().cloned().collect());
        // combined_answers is hashed with salt0 before PBKDF2
        let second_hash = Zeroizing::new(sha256(&combined_answers, &self.params.salt));
        let second_key_array = derive_key(&second_hash, &salt1_iv, self.params.iterations)?;

        // Decrypt master key and IV using second-key and salt1
        let master_data: MasterData =
            decrypt_from_base64(&self.master, &second_key_array, &salt1_iv)?;

        // Decode master key and IV
        let master_key_bytes = Zeroizing::new(decode_base64(&master_data.master_key)?);
        let iv_bytes = decode_base64(&master_data.iv)?;
        let mut master_key_array = Zeroizing::new([0u8; 32]);
        if master_key_bytes.len() != 32 {
            return Err("Invalid master key length".into());
        }
        master_key_array.copy_from_slice(&master_key_bytes);
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;

        // Decrypt secret data using master key and IV
        let secret_data: Vec<SecretEntry> =
            decrypt_from_base64(&self.data, &master_key_array, &iv_array)?;

        Ok(secret_data)
    }

    /// Get QuestionsData by first answer from the AskryptFile
    ///
    /// # Arguments
    ///
    /// * `first_answer` - The first answer to decrypt the remaining questions
    ///
    /// # Returns
    ///
    /// Returns a Result containing QuestionsData or an error
    pub fn get_questions_data(
        &self,
        first_answer: String,
    ) -> Result<QuestionsData, Box<dyn std::error::Error>> {
        // Decode salt0
        let salt0 = decode_base64(&self.params.salt)?;
        let salt0_iv: [u8; 16] = salt0.try_into().map_err(|_| "Invalid salt0 length")?;

        // Hash first answer with salt0
        let normalized = Zeroizing::new(normalize_answer(&first_answer, self.params.translit));
        let first_answer = Zeroizing::new(sha256(&normalized, &self.params.salt));
        // Derive first-key from first answer and salt0
        let first_key_array = derive_key(&first_answer, &salt0_iv, self.params.iterations)?;

        // Decrypt questions data
        let questions_data: QuestionsData =
            decrypt_from_base64(&self.qs, &first_key_array, &salt0_iv)?;

        Ok(questions_data)
    }

    /// Serialize the AskryptFile to an in-memory ZIP archive with internal file
    /// name "askrypt.json".
    ///
    /// This is the I/O-agnostic counterpart to [`save_to_file`](Self::save_to_file)
    /// and is the entry point used by non-filesystem platforms (e.g. mobile,
    /// where storage is mediated by the OS rather than raw paths).
    ///
    /// # Returns
    ///
    /// Returns a Result containing the ZIP archive bytes or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();

            zip.start_file("askrypt.json", options)?;
            zip.write_all(json.as_bytes())?;

            zip.finish()?;
        }
        Ok(buf)
    }

    /// Deserialize an AskryptFile from an in-memory ZIP archive containing
    /// "askrypt.json".
    ///
    /// This is the I/O-agnostic counterpart to [`load_from_file`](Self::load_from_file).
    ///
    /// # Arguments
    ///
    /// * `bytes` - The ZIP archive bytes to parse
    ///
    /// # Returns
    ///
    /// Returns a Result containing the loaded AskryptFile or an error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;

        let mut askrypt_json = zip.by_name("askrypt.json")?;
        let mut json = String::new();
        // TODO: Handle large files more efficiently in future
        std::io::Read::read_to_string(&mut askrypt_json, &mut json)?;

        let askrypt_file: AskryptFile = serde_json::from_str(&json)?;
        // TODO: Support multiple versions in future
        if askrypt_file.version != "0.9" {
            return Err(
                format!("Unsupported Askrypt file version: {}", askrypt_file.version).into(),
            );
        }
        Ok(askrypt_file)
    }

    /// Save the AskryptFile to a ZIP file with internal file name "askrypt.json"
    ///
    /// Convenience wrapper over [`storage::LocalFileStorage`]; use a
    /// [`storage::VaultStorage`] directly for backend-agnostic persistence.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path where the ZIP file should be saved
    ///
    /// # Returns
    ///
    /// Returns a Result indicating success or an error
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(LocalFileStorage::new(path.as_ref()).save_vault(self)?)
    }

    /// Load an AskryptFile from a ZIP file containing "askrypt.json"
    ///
    /// Convenience wrapper over [`storage::LocalFileStorage`]; use a
    /// [`storage::VaultStorage`] directly for backend-agnostic persistence.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to load the ZIP file from
    ///
    /// # Returns
    ///
    /// Returns a Result containing the loaded AskryptFile or an error
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(LocalFileStorage::new(path.as_ref()).load_vault()?)
    }
}

/// Label for the machine writing the vault, for [`Params::host`].
///
/// The shape is `os@host` (`ubuntu@mypc`, `windows@workps`), falling back to the
/// OS name alone when the host name is unavailable or not valid UTF-8 — never a
/// dangling `ubuntu@`. Older vaults carry a bare host name with no OS half, so
/// readers must treat the value as opaque display text.
///
/// # Example
///
/// ```
/// let host = askrypt::current_host().expect("the OS name is always known");
/// assert!(!host.starts_with('@') && !host.ends_with('@'));
/// ```
pub fn current_host() -> Option<String> {
    let os = current_os();
    match gethostname::gethostname().into_string() {
        Ok(host) if !host.trim().is_empty() => Some(format!("{os}@{}", host.trim())),
        _ => Some(os),
    }
}

/// Coarse, lowercase OS name used as the `os@host` prefix of [`current_host`].
///
/// On Linux this is the distro (`ubuntu`, `fedora`, `arch`) when
/// `/etc/os-release` names one, since "linux" alone says little about which
/// machine wrote the file.
fn current_os() -> String {
    #[cfg(target_os = "linux")]
    if let Some(id) = linux_distro_id() {
        return id;
    }
    std::env::consts::OS.to_string()
}

/// Distro ID from `os-release`, read once per process.
#[cfg(target_os = "linux")]
fn linux_distro_id() -> Option<String> {
    static ID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        // `/etc/os-release` is the admin-editable copy and takes precedence;
        // distros that ship only the vendor file provide the second path.
        ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .as_deref()
            .and_then(parse_os_release_id)
    })
    .clone()
}

/// Pull the `ID=` value out of an `os-release` file.
///
/// Returns `None` unless the value looks like the IDs the format specifies —
/// lowercase alphanumerics plus `.`, `_` and `-` — because this ends up in the
/// vault's unencrypted stamp and then in a web table cell.
#[cfg(target_os = "linux")]
fn parse_os_release_id(contents: &str) -> Option<String> {
    let raw = contents
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("ID="))?;
    let id = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    let ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ok.then_some(id)
}

/// Current UTC time formatted as RFC 3339 with second precision, for
/// [`Params::updated_at`] (e.g. `2026-08-02T10:15:30Z`).
///
/// # Example
///
/// ```
/// let stamp = askrypt::now_utc_rfc3339();
/// assert!(stamp.ends_with('Z'));
/// ```
pub fn now_utc_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Encrypt a message using AES-256-CBC with a custom IV
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the encrypted ciphertext as Vec<u8> or an error
///
/// # Example
///
/// ```
/// use askrypt::encrypt_with_aes;
///
/// let message = b"Hello, World!";
/// let key = [0u8; 32];
/// let iv = [0u8; 16];
///
/// let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
/// ```
pub fn encrypt_with_aes(
    message: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcEnc::new(key.into(), iv.into());

    // Calculate buffer size with padding. The buffer holds a copy of the
    // plaintext, so wipe it on drop.
    let pos = message.len();
    let mut buffer = Zeroizing::new(vec![0u8; pos + 16]); // Add extra block for padding
    buffer[..pos].copy_from_slice(message);

    let ciphertext = cipher
        .encrypt_padded::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| "Encryption padding error")?;

    Ok(ciphertext.to_vec())
}

/// Decrypt a message using AES-256-CBC with a custom IV
///
/// # Arguments
///
/// * `ciphertext` - The encrypted ciphertext to decrypt
/// * `key` - A 32-byte encryption key (must match encryption key)
/// * `iv` - A 16-byte initialization vector (must match encryption IV)
///
/// # Returns
///
/// Returns a Result containing the decrypted plaintext as Vec<u8> or an error
///
/// # Example
///
/// ```
/// use askrypt::{encrypt_with_aes, decrypt_with_aes};
///
/// let message = b"Hello, World!";
/// let key = [0u8; 32];
/// let iv = [0u8; 16];
///
/// let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
/// let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();
/// assert_eq!(message, &plaintext[..]);
/// ```
pub fn decrypt_with_aes(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    // After decryption `buffer` holds the plaintext, so wipe it on drop. The
    // returned copy is the caller's responsibility to wipe.
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plaintext = cipher
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map_err(|_| "Decryption padding error")?;

    Ok(plaintext.to_vec())
}

/// Calculate PBKDF2 key derivation from secret and salt
///
/// # Arguments
///
/// * `secret` - The password/secret to derive from
/// * `salt` - The salt bytes to use for derivation
/// * `iterations` - Number of iterations to perform
///
/// # Returns
///
/// Returns a Result containing the derived key as a Vec<u8> or an error
pub fn calc_pbkdf2(
    secret: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use pbkdf2::pbkdf2_hmac;

    let mut output = vec![0u8; 32];

    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, iterations, &mut output);

    Ok(output)
}

/// Normalize an answer by removing all whitespace and converting to lowercase
///
/// # Arguments
///
/// * `answer` - The raw answer string
///
/// # Returns
///
/// A normalized answer string
///
/// # Example
///
/// ```
/// use askrypt::normalize_answer;
///
/// let answer = "Hello World";
/// let normalized = normalize_answer(answer, false);
/// assert_eq!(normalized, "helloworld");
/// ```
pub fn normalize_answer(answer: &str, translit: bool) -> String {
    let s: String = answer
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '–' && *c != '—') // remove all types of dashes
        .collect::<String>()
        .to_lowercase();
    if translit {
        translit::transliterate(&s)
    } else {
        s
    }
}

/// Hash a str using SHA256 + salt
///
/// # Arguments
///
/// * `answer` - The answer to hash
///
/// # Returns
///
/// Returns the SHA256 hash of the str as a hex string
///
/// # Example
///
/// ```
/// use askrypt::sha256;
///
/// let str1 = "Hello World";
/// let hashed = sha256(str1, "salt42");
/// assert_eq!(hashed, "6867f8dfd55dcf8b366244cf78fedf3deae645bfef316e393fd79b125bbbe63a");
/// // hashed will be consistent and reproducible
/// ```
pub fn sha256(data: &str, salt: &str) -> String {
    let data = data.to_string() + salt;
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    // digest 0.11 / sha2 0.11 returns an `Array` that no longer implements
    // `LowerHex`, so build the lowercase hex string byte by byte.
    use std::fmt::Write;
    hasher.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Encrypt data to base64-encoded string
///
/// # Arguments
///
/// * `data` - The data to encrypt (will be serialized to JSON)
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the base64-encoded encrypted data
pub fn encrypt_to_base64<T: Serialize>(
    data: &T,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<String, Box<dyn std::error::Error>> {
    // `json` is the serialized plaintext, so wipe it on drop.
    let json = Zeroizing::new(serde_json::to_string(data)?);
    let encrypted = encrypt_with_aes(json.as_bytes(), key, iv)?;
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt base64-encoded encrypted data
///
/// # Arguments
///
/// * `base64_data` - The base64-encoded encrypted data
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the decrypted and deserialized data
pub fn decrypt_from_base64<T: for<'de> Deserialize<'de>>(
    base64_data: &str,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<T, Box<dyn std::error::Error>> {
    let encrypted = general_purpose::STANDARD.decode(base64_data)?;
    let decrypted = decrypt_with_aes(&encrypted, key, iv)?;
    // `from_utf8` reuses the decrypted buffer (no copy); wipe the plaintext on drop.
    let json = Zeroizing::new(String::from_utf8(decrypted)?);
    Ok(serde_json::from_str(&json)?)
}

/// Generate a random salt of specified length
///
/// # Arguments
///
/// * `length` - The length of the salt in bytes
///
/// # Returns
///
/// A vector of random bytes
pub fn generate_salt(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut salt = vec![0u8; length];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Encode bytes to base64 string
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn decode_base64(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(general_purpose::STANDARD.decode(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;

    #[test]
    fn test_encrypt_decrypt_with_custom_iv() {
        let message = b"This is a secret message!";
        let key = [0x42; 32]; // Example key
        let iv = [0x24; 16]; // Example IV

        // Encrypt
        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..], message);

        // Decrypt
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        // Verify decrypted text matches original
        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_different_ivs_produces_different_ciphertexts() {
        let message = b"Same message, different IVs";
        let key = [0x01; 32];
        let iv1 = [0x00; 16];
        let iv2 = [0xFF; 16];

        let ciphertext1 = encrypt_with_aes(message, &key, &iv1).unwrap();
        let ciphertext2 = encrypt_with_aes(message, &key, &iv2).unwrap();

        // Same message with different IVs should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_empty_message() {
        let message = b"";
        let key = [0x10; 32];
        let iv = [0x20; 16];

        let result = encrypt_with_aes(message, &key, &iv);
        assert!(result.is_ok());

        let ciphertext = result.unwrap();
        // Even empty messages get padded
        assert!(!ciphertext.is_empty());
    }

    #[test]
    fn test_decrypt_with_wrong_iv_fails() {
        let message = b"Secret data";
        let key = [0x33; 32];
        let iv_correct = [0x44; 16];
        let iv_wrong = [0x55; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv_correct).unwrap();

        // Decrypting with wrong IV should either fail or produce garbage
        let result = decrypt_with_aes(&ciphertext, &key, &iv_wrong);
        if let Ok(plaintext) = result {
            // If it doesn't fail, it should produce different plaintext
            assert_ne!(&plaintext[..], message);
        }
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let message = b"Another secret";
        let key_correct = [0x66; 32];
        let key_wrong = [0x77; 32];
        let iv = [0x88; 16];

        let ciphertext = encrypt_with_aes(message, &key_correct, &iv).unwrap();

        // Decrypting with wrong key should either fail or produce garbage
        let result = decrypt_with_aes(&ciphertext, &key_wrong, &iv);
        if let Ok(plaintext) = result {
            assert_ne!(&plaintext[..], message);
        }
    }

    #[test]
    fn test_encrypt_long_message() {
        let message = b"This is a much longer message that spans multiple AES blocks. \
                        AES has a block size of 16 bytes, so this message will require \
                        multiple blocks to encrypt. This tests that the encryption works \
                        correctly for messages longer than a single block.";
        let key = [0x99; 32];
        let iv = [0xAA; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_all_zero_iv() {
        let message = b"Testing with zero IV";
        let key = [0xBB; 32];
        let iv = [0x00; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_all_ones_iv() {
        let message = b"Testing with ones IV";
        let key = [0xCC; 32];
        let iv = [0xFF; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_calculate_pbkdf2_custom() {
        let secret = "password";
        let salt = b"salt";
        let iterations = 10_000;

        let result = calc_pbkdf2(secret, salt, iterations);
        assert!(result.is_ok());

        let derived_key = result.unwrap();
        assert_eq!(derived_key.len(), 32);
        assert_eq!(
            "5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b",
            encode(&derived_key)
        );
    }

    #[test]
    fn test_normalize_answer() {
        assert_eq!(normalize_answer("Hello World?", false), "helloworld?");
        assert_eq!(normalize_answer("Test-Answer !?", false), "testanswer!?");
        assert_eq!(normalize_answer("Test–Answer", false), "testanswer");
        assert_eq!(normalize_answer("Test—Answer", false), "testanswer");
        assert_eq!(normalize_answer("Test--—––Ans–wer ", false), "testanswer");
        assert_eq!(normalize_answer("  Spaces  ", false), "spaces");
        assert_eq!(normalize_answer("Mixed-Case Test", false), "mixedcasetest");
        assert_eq!(
            normalize_answer("\t\nTabs\nAnd\tNewlines\n", false),
            "tabsandnewlines"
        );

        // translit = true
        assert_eq!(normalize_answer("Москва", true), "moskva");
        assert_eq!(normalize_answer("Привет Мир", true), "privetmir");
        assert_eq!(normalize_answer("Ёжик-ёжик", true), "yozhikyozhik");
        assert_eq!(normalize_answer("Київ", true), "kiyiv");
        assert_eq!(normalize_answer("Hello World", true), "helloworld");
        assert_eq!(normalize_answer("Объект", true), "obekt");
    }

    #[test]
    fn test_encrypt_decrypt_to_base64() {
        let data = QuestionsData {
            questions: vec!["Question 2".to_string(), "Question 3".to_string()],
            salt: "test_salt".to_string(),
        };
        let key = [0x42; 32];
        let iv = [0x24; 16];

        let encrypted = encrypt_to_base64(&data, &key, &iv).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted: QuestionsData = decrypt_from_base64(&encrypted, &key, &iv).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt(16);
        let salt2 = generate_salt(16);

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be random
    }

    #[test]
    fn test_encode_decode_base64() {
        let data = b"Hello, World!";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_secret_entry_serialization() {
        let entry = SecretEntry {
            name: "test_user".to_string(),
            user_name: "user5".to_string(),
            secret: "test_password".to_string(),
            url: "https://example.com".to_string(),
            notes: "Test notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string(), "important".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_questions_data_serialization() {
        let qs = QuestionsData {
            questions: vec!["Question 1".to_string(), "Question 2".to_string()],
            salt: "test-salt1".to_string(),
        };

        let json = serde_json::to_string(&qs).unwrap();
        let deserialized: QuestionsData = serde_json::from_str(&json).unwrap();
        assert_eq!(qs, deserialized);

        // Verify JSON has correct field names
        assert!(json.contains("\"questions\""));
        assert!(json.contains("\"salt\""));
    }

    #[test]
    fn test_askrypt_file_serialization() {
        let file = AskryptFile {
            version: "0.9".to_string(),
            question0: "What is your mother's maiden name?".to_string(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations: 600000,
                salt: "base64-salt".to_string(),
                translit: false,
                host: Some("test-host".to_string()),
                updated_at: Some("2026-08-02T10:15:30Z".to_string()),
            },
            qs: "base64-encrypted-questions".to_string(),
            master: "base64-encrypted-master".to_string(),
            data: "base64-encrypted-data".to_string(),
        };

        let json = serde_json::to_string(&file).unwrap();
        let deserialized: AskryptFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file, deserialized);
    }

    #[test]
    fn test_askrypt_file_create() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
        )
        .unwrap();

        // Verify basic structure
        assert_eq!(askrypt_file.version, "0.9");
        assert_eq!(askrypt_file.question0, questions[0]);
        assert_eq!(askrypt_file.params.kdf, DEFAULT_KDF);
        assert_eq!(askrypt_file.params.iterations, 6000);
        assert!(!askrypt_file.params.salt.is_empty());
        assert!(!askrypt_file.qs.is_empty());
        assert!(!askrypt_file.master.is_empty());
        assert!(!askrypt_file.data.is_empty());

        // Write stamp
        assert_eq!(askrypt_file.params.host, current_host());
        let updated_at = askrypt_file.params.updated_at.unwrap();
        assert!(updated_at.ends_with('Z'), "not RFC 3339 UTC: {updated_at}");
        assert_eq!(updated_at.len(), "2026-08-02T10:15:30Z".len());
    }

    #[test]
    fn test_askrypt_file_touch_refreshes_stamp() {
        let mut file = AskryptFile {
            version: "0.9".to_string(),
            question0: "Q0".to_string(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations: 600000,
                salt: "base64-salt".to_string(),
                translit: false,
                host: Some("some-other-host".to_string()),
                updated_at: Some("2000-01-01T00:00:00Z".to_string()),
            },
            qs: "qs".to_string(),
            master: "master".to_string(),
            data: "data".to_string(),
        };

        file.touch();

        assert_eq!(file.params.host, current_host());
        assert!(file.params.updated_at.unwrap().as_str() > "2000-01-01T00:00:00Z");
    }

    #[test]
    fn test_params_stamp_is_optional_and_omitted_when_absent() {
        // Files written before the stamp existed must still load.
        let json = r#"{
            "version": "0.9",
            "question0": "Q0",
            "params": {"kdf": "pbkdf2", "iterations": 600000, "salt": "c2FsdA=="},
            "qs": "qs",
            "master": "master",
            "data": "data"
        }"#;
        let file: AskryptFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.params.host, None);
        assert_eq!(file.params.updated_at, None);

        // ...and round-trip without inventing the keys.
        let out = serde_json::to_string(&file).unwrap();
        assert!(!out.contains("host"), "{out}");
        assert!(!out.contains("updated_at"), "{out}");
    }

    #[test]
    fn test_current_host_is_os_at_hostname() {
        let os = current_os();
        assert!(!os.is_empty());
        assert_eq!(os, os.to_ascii_lowercase(), "the OS half is lowercase");

        // The OS name is always known, so there is always a stamp.
        let host = current_host().unwrap();
        assert!(host.starts_with(&os), "{host} does not start with {os}");
        match host.split_once('@') {
            Some((left, right)) => {
                assert_eq!(left, os);
                assert!(!right.is_empty(), "dangling separator: {host}");
                assert!(!right.contains('@'), "more than one separator: {host}");
            }
            // No host name on this machine: the OS name stands alone.
            None => assert_eq!(host, os),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_os_release_id() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(parse_os_release_id(ubuntu).as_deref(), Some("ubuntu"));
        assert_eq!(
            parse_os_release_id("ID=\"fedora\"\n").as_deref(),
            Some("fedora")
        );
        assert_eq!(
            parse_os_release_id("  ID=arch  \n").as_deref(),
            Some("arch")
        );
        // `ID_LIKE=` must not be mistaken for `ID=`.
        assert_eq!(parse_os_release_id("ID_LIKE=debian\n"), None);
        assert_eq!(parse_os_release_id("NAME=\"Some OS\"\n"), None);
        assert_eq!(parse_os_release_id("ID=\n"), None);
        // Anything that is not a well-formed ID is not put in the stamp.
        assert_eq!(parse_os_release_id("ID=my distro\n"), None);
        assert_eq!(parse_os_release_id("ID=<script>alert(1)</script>\n"), None);
        assert_eq!(parse_os_release_id("ID=who@where\n"), None);
    }

    #[test]
    fn test_askrypt_file_create_invalid_questions() {
        // Test with no questions
        let questions = vec![];
        let answers = vec![];
        let data = vec![];

        let result = AskryptFile::create(questions, answers, data, None, false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least 2 questions")
        );

        let questions = vec!["Question 1".to_string()]; // Only 1
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(questions, answers, data2, None, false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least 2 questions")
        );

        let questions = vec!["Question 1".to_string(), "Question 2".to_string()];
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(questions, answers, data2, None, false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Number of questions and answers must match")
        );
    }

    #[test]
    fn test_askrypt_file_create_question_too_long() {
        let long_question = "a".repeat(501);
        let questions = vec![
            long_question,
            "Question 2".to_string(),
            "Question 3".to_string(),
        ];
        let answers = vec![
            "Answer1".to_string(),
            "Answer2".to_string(),
            "Answer3".to_string(),
        ];
        let data = vec![];

        let result = AskryptFile::create(questions, answers, data, None, false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Question length must not exceed 500 characters")
        );
    }

    #[test]
    fn test_askrypt_file_create_and_decrypt() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let original_data = vec![
            SecretEntry {
                name: "example1".to_string(),
                user_name: "user5".to_string(),
                secret: "password123".to_string(),
                url: "https://example.com".to_string(),
                notes: "My account".to_string(),
                entry_type: "password".to_string(),
                tags: vec!["work".to_string()],
                created: 1704067200,
                modified: 1704067200,
                hidden: false,
                card: Default::default(),
            },
            SecretEntry {
                name: "example2".to_string(),
                user_name: "user5".to_string(),
                secret: "secret456".to_string(),
                url: "https://test.com".to_string(),
                notes: "Test notes".to_string(),
                entry_type: "note".to_string(),
                tags: vec!["personal".to_string(), "important".to_string()],
                created: 1704153600,
                modified: 1704153600,
                hidden: false,
                card: Default::default(),
            },
        ];

        // Create AskryptFile
        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            original_data.clone(),
            Some(6000),
            false,
        )
        .unwrap();

        // Decrypt and verify
        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = askrypt_file
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_askrypt_file_decrypt_wrong_answer() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
        )
        .unwrap();

        // Try to decrypt with wrong answer
        let wrong_answers = vec!["Fluffy".to_string(), "New York2".to_string()];

        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let result = askrypt_file.decrypt(&questions_data, wrong_answers);
        // Should fail due to wrong answer (decryption error or invalid JSON)
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Decryption padding error")
        );
    }

    #[test]
    fn test_card_entry_round_trips_through_the_vault() {
        let questions = vec!["Q0".to_string(), "Q1".to_string()];
        let answers = vec!["A0".to_string(), "A1".to_string()];
        let data = vec![SecretEntry {
            name: "Personal Visa".to_string(),
            user_name: String::new(),
            secret: String::new(),
            url: String::new(),
            notes: String::new(),
            entry_type: "Card".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: CardFields {
                holder: "Ruslan A.".to_string(),
                brand: "Visa".to_string(),
                number: "4242 4242 4242 4242".to_string(),
                expiry: "04/29".to_string(),
                cvv: "123".to_string(),
                pin: "9876".to_string(),
            },
        }];

        let file = AskryptFile::create(questions, answers.clone(), data.clone(), Some(6000), false)
            .unwrap();
        let questions_data = file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted = file.decrypt(&questions_data, answers[1..].into()).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_an_entry_without_card_fields_writes_no_card_keys() {
        // The `skip_serializing_if` guarantee: adding the card fields must not
        // change one byte of what a login entry serializes to.
        let entry = SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: String::new(),
            notes: String::new(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("card_"), "unexpected card keys in {json}");
    }

    #[test]
    fn test_entry_json_written_before_cards_parses_with_them_empty() {
        let legacy = r#"{
            "name": "example",
            "user_name": "user5",
            "secret": "password123",
            "url": "https://example.com",
            "notes": "My account",
            "type": "password",
            "tags": [],
            "created": 1704067200,
            "modified": 1704067200
        }"#;

        let entry: SecretEntry = serde_json::from_str(legacy).unwrap();

        assert_eq!(entry.name, "example");
        assert_eq!(entry.card, CardFields::default());
    }

    #[test]
    fn test_askrypt_file_save_and_load() {
        use std::fs;

        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
        )
        .unwrap();

        let temp_file =
            std::env::temp_dir().join(format!("test_askrypt_file_{}.askrypt", std::process::id()));

        // Save to file
        askrypt_file.save_to_file(&temp_file).unwrap();

        // Load from file
        let loaded_file = AskryptFile::load_from_file(&temp_file).unwrap();

        // Verify they match
        assert_eq!(askrypt_file, loaded_file);

        // Verify we can still decrypt with the loaded file
        let questions_data = loaded_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = loaded_file
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted_data, data);

        // Cleanup
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_askrypt_file_zip_contains_askrypt_json() {
        use std::fs;

        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
        ];

        let answers = vec!["Smith".to_string(), "Fluffy".to_string()];

        let data = vec![SecretEntry {
            name: "test".to_string(),
            user_name: "user5".to_string(),
            secret: "secret".to_string(),
            url: "https://test.com".to_string(),
            notes: "notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        }];

        let askrypt_file =
            AskryptFile::create(questions, answers, data, Some(6000), false).unwrap();

        let temp_file =
            std::env::temp_dir().join(format!("test_vault_content_{}.askrypt", std::process::id()));

        // Save to zip file
        askrypt_file.save_to_file(&temp_file).unwrap();

        // Verify the zip file contains askrypt.json
        let file = fs::File::open(&temp_file).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        // Check that askrypt.json exists in the archive
        let result = archive.by_name("askrypt.json");
        assert!(result.is_ok(), "askrypt.json should exist in the zip file");

        // Cleanup
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_askrypt_file_to_from_bytes_roundtrip() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
        )
        .unwrap();

        // Round-trip through the in-memory ZIP buffer
        let bytes = askrypt_file.to_bytes().unwrap();
        let loaded = AskryptFile::from_bytes(&bytes).unwrap();
        assert_eq!(askrypt_file, loaded);

        // The buffer is a valid ZIP archive containing askrypt.json
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        assert!(archive.by_name("askrypt.json").is_ok());

        // Decryption still works on the buffer-loaded file
        let questions_data = loaded.get_questions_data(answers[0].clone()).unwrap();
        let decrypted = loaded
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_askrypt_file_from_bytes_rejects_garbage() {
        assert!(AskryptFile::from_bytes(b"not a zip archive").is_err());
    }
}
