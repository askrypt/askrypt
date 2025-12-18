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
//! // Provide answers (they will be normalized)
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
//!         secret: "my_super_secret_password".to_string(),
//!         url: "https://gmail.com".to_string(),
//!         notes: "Personal email account".to_string(),
//!         entry_type: "password".to_string(),
//!         tags: vec!["email".to_string(), "personal".to_string()],
//!         created: "2024-01-01T00:00:00Z".to_string(),
//!         modified: "2024-01-01T00:00:00Z".to_string(),
//!     }
//! ];
//!
//! // Create the encrypted file
//! let askrypt_file = AskryptFile::create(
//!     questions,
//!     answers.clone(),
//!     secrets.clone(),
//!     Some(5000),
//! ).unwrap();
//!
//! // Save to disk
//! askrypt_file.save_to_file("my_vault.json").unwrap();
//!
//! // Later, load and decrypt
//! let loaded = AskryptFile::load_from_file("my_vault.json").unwrap();
//! let question_data = loaded.get_questions_data("Smith".into()).unwrap();
//! let decrypted_secrets = loaded.decrypt(question_data, answers[1..].into()).unwrap();
//!
//! assert_eq!(decrypted_secrets, secrets);
//! # std::fs::remove_file("my_vault.json").ok();
//! ```

use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Represents a user's secret entry (password, note, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub secret: String,
    pub url: String,
    pub notes: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub tags: Vec<String>,
    pub created: String,
    pub modified: String,
}

/// Represents KDF parameters for the first level (key derivation function, iterations, and salt)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
}

/// Represents the encrypted questions and second-level KDF parameters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionsData {
    pub questions: Vec<String>,
    // sal1 - used to derive a second_key
    pub salt: String,
}

/// Represents the encrypted master key and IV
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MasterData {
    #[serde(rename = "masterKey")]
    pub master_key: String,
    pub iv: String,
}

/// Main Askrypt file structure in JSON format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskryptFile {
    pub version: String,
    pub question0: String,
    pub params: KdfParams,
    pub qs: String,
    pub master: String,
    pub data: String,
}

impl AskryptFile {
    /// Create a new AskryptFile from questions, answers, and secret data
    ///
    /// # Arguments
    ///
    /// * `questions` - A vector of at least 2 questions
    /// * `answers` - A vector of normalized answers (must be pre-normalized, same length as questions)
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
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: "2024-01-01T00:00:00Z".to_string(),
    ///         modified: "2024-01-01T00:00:00Z".to_string(),
    ///     }
    /// ];
    ///
    /// let askrypt_file = AskryptFile::create(questions, answers, data, Some(6000)).unwrap();
    /// ```
    pub fn create(
        questions: Vec<String>,
        answers: Vec<String>,
        secret_data: Vec<SecretEntry>,
        iterations: Option<u32>,
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

        let answers: Vec<String> = answers.into_iter().map(|a| normalize_answer(&a)).collect();

        let iterations = iterations.unwrap_or(600000);

        // Step 1: Generate random values
        let salt0 = generate_salt(16);
        let salt1 = generate_salt(16);
        let master_key_bytes = generate_salt(32);
        let iv_bytes = generate_salt(16);

        // Step 2: Derive first-key from first answer and salt0
        let first_key = calc_pbkdf2(&answers[0], &salt0, iterations)?;
        let first_key_array: [u8; 32] = first_key.try_into().map_err(|_| "Invalid key length")?;
        let salt0_iv: [u8; 16] = salt0.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 3: Encrypt questions data (all questions except the first) using first-key and salt0 as IV
        let remaining_questions: Vec<String> = questions.iter().skip(1).cloned().collect();
        let questions_data = QuestionsData {
            questions: remaining_questions,
            salt: encode_base64(&salt1),
        };
        let qs = encrypt_to_base64(&questions_data, &first_key_array, &salt0_iv)?;

        // Step 4: Derive second-key from combined remaining answers and salt1
        let combined_answers: String = answers.iter().skip(1).cloned().collect();
        let second_key = calc_pbkdf2(&combined_answers, &salt1, iterations)?;
        let second_key_array: [u8; 32] = second_key.try_into().map_err(|_| "Invalid key length")?;
        let salt1_iv: [u8; 16] = salt1.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 5: Encrypt master key and IV using second-key and salt1 as IV
        let master_data = MasterData {
            master_key: encode_base64(&master_key_bytes),
            iv: encode_base64(&iv_bytes),
        };
        let master = encrypt_to_base64(&master_data, &second_key_array, &salt1_iv)?;

        // Step 6: Encrypt secret data using master key and IV
        let master_key_array: [u8; 32] = master_key_bytes
            .try_into()
            .map_err(|_| "Invalid master key length")?;
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;
        let data = encrypt_to_base64(&secret_data, &master_key_array, &iv_array)?;

        // Step 7: Create and return AskryptFile
        Ok(AskryptFile {
            version: "0.9".to_string(),
            question0: questions[0].clone(),
            params: KdfParams {
                kdf: "pbkdf2".to_string(),
                iterations,
                salt: encode_base64(&salt0),
            },
            qs,
            master,
            data,
        })
    }

    /// Decrypt an AskryptFile and retrieve the secret data using the answers
    ///
    /// # Arguments
    ///
    /// * `answers` - A vector of normalized answers (must be pre-normalized)
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
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: "2024-01-01T00:00:00Z".to_string(),
    ///         modified: "2024-01-01T00:00:00Z".to_string(),
    ///     }
    /// ];
    ///
    /// let askrypt_file = AskryptFile::create(questions, answers.clone(), data.clone(), Some(6000)).unwrap();
    /// let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
    /// let decrypted_data = askrypt_file.decrypt(questions_data, answers[1..].into()).unwrap();
    /// assert_eq!(decrypted_data, data);
    /// ```
    pub fn decrypt(
        &self,
        questions_data: QuestionsData,
        answers: Vec<String>,
    ) -> Result<Vec<SecretEntry>, Box<dyn std::error::Error>> {
        // Validate inputs
        if answers.len() < 1 {
            return Err("At least 1 answer is required".into());
        }

        if questions_data.questions.len() != answers.len() {
            return Err("Number of questions and answers must match".into());
        }

        // Decode salt1
        let salt1 = decode_base64(&questions_data.salt)?;
        let salt1_iv: [u8; 16] = salt1.try_into().map_err(|_| "Invalid salt1 length")?;

        let answers: Vec<String> = answers.into_iter().map(|a| normalize_answer(&a)).collect();
        // Derive second-key from combined remaining answers and salt1
        let combined_answers: String = answers.iter().cloned().collect();
        let second_key = calc_pbkdf2(&combined_answers, &salt1_iv, self.params.iterations)?;
        let second_key_array: [u8; 32] = second_key.try_into().map_err(|_| "Invalid key length")?;

        // Decrypt master key and IV using second-key and salt1
        let master_data: MasterData =
            decrypt_from_base64(&self.master, &second_key_array, &salt1_iv)?;

        // Decode master key and IV
        let master_key_bytes = decode_base64(&master_data.master_key)?;
        let iv_bytes = decode_base64(&master_data.iv)?;
        let master_key_array: [u8; 32] = master_key_bytes
            .try_into()
            .map_err(|_| "Invalid master key length")?;
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;

        // Decrypt secret data using master key and IV
        let secret_data: Vec<SecretEntry> =
            decrypt_from_base64(&self.data, &master_key_array, &iv_array)?;

        Ok(secret_data)
    }

    /// Get QuestionsData by first normalized answer from the AskryptFile
    ///
    /// # Arguments
    ///
    /// * `first_answer` - The normalized first answer to decrypt the remaining questions
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

        // Derive first-key from first answer and salt0
        let first_answer = normalize_answer(&first_answer);
        let first_key = calc_pbkdf2(&first_answer, &salt0_iv, self.params.iterations)?;
        let first_key_array: [u8; 32] = first_key.try_into().map_err(|_| "Invalid key length")?;

        // Decrypt questions data
        let questions_data: QuestionsData =
            decrypt_from_base64(&self.qs, &first_key_array, &salt0_iv)?;

        Ok(questions_data)
    }

    /// Save the AskryptFile to a JSON file
    ///
    /// # Arguments
    ///
    /// * `path` - The file path where the JSON file should be saved
    ///
    /// # Returns
    ///
    /// Returns a Result indicating success or an error
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load an AskryptFile from a JSON file
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to load the JSON file from
    ///
    /// # Returns
    ///
    /// Returns a Result containing the loaded AskryptFile or an error
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let askrypt_file: AskryptFile = serde_json::from_str(&json)?;
        // TODO: Support multiple versions in future
        if askrypt_file.version != "0.9" {
            return Err(
                format!("Unsupported Askrypt file version: {}", askrypt_file.version).into(),
            );
        }
        Ok(askrypt_file)
    }
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

    // Calculate buffer size with padding
    let pos = message.len();
    let mut buffer = vec![0u8; pos + 16]; // Add extra block for padding
    buffer[..pos].copy_from_slice(message);

    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
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

    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
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
/// let normalized = normalize_answer(answer);
/// assert_eq!(normalized, "helloworld");
/// ```
pub fn normalize_answer(answer: &str) -> String {
    answer
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '–' && *c != '—') // remove all types of dashes
        .collect::<String>()
        .to_lowercase()
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
    let json = serde_json::to_string(data)?;
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
    let json = String::from_utf8(decrypted)?;
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
    use rand::RngCore;
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
        assert!(ciphertext.len() > 0);
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
        assert_eq!(normalize_answer("Hello World?"), "helloworld?");
        assert_eq!(normalize_answer("Test-Answer !?"), "testanswer!?");
        assert_eq!(normalize_answer("Test–Answer"), "testanswer");
        assert_eq!(normalize_answer("Test—Answer"), "testanswer");
        assert_eq!(normalize_answer("Test--—––Ans–wer "), "testanswer");
        assert_eq!(normalize_answer("  Spaces  "), "spaces");
        assert_eq!(normalize_answer("Mixed-Case Test"), "mixedcasetest");
        assert_eq!(
            normalize_answer("\t\nTabs\nAnd\tNewlines\n"),
            "tabsandnewlines"
        );
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
            secret: "test_password".to_string(),
            url: "https://example.com".to_string(),
            notes: "Test notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string(), "important".to_string()],
            created: "2024-01-01T00:00:00Z".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
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
            params: KdfParams {
                kdf: "pbkdf2".to_string(),
                iterations: 600000,
                salt: "base64-salt".to_string(),
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
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: "2024-01-01T00:00:00Z".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
        }];

        let askrypt_file =
            AskryptFile::create(questions.clone(), answers.clone(), data.clone(), Some(6000))
                .unwrap();

        // Verify basic structure
        assert_eq!(askrypt_file.version, "0.9");
        assert_eq!(askrypt_file.question0, questions[0]);
        assert_eq!(askrypt_file.params.kdf, "pbkdf2");
        assert_eq!(askrypt_file.params.iterations, 6000);
        assert!(!askrypt_file.params.salt.is_empty());
        assert!(!askrypt_file.qs.is_empty());
        assert!(!askrypt_file.master.is_empty());
        assert!(!askrypt_file.data.is_empty());
    }

    #[test]
    fn test_askrypt_file_create_invalid_questions() {
        // Test with no questions
        let questions = vec![];
        let answers = vec![];
        let data = vec![];

        let result = AskryptFile::create(questions, answers, data, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("At least 2 questions"));

        let questions = vec!["Question 1".to_string()]; // Only 1
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(questions, answers, data2, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("At least 2 questions"));

        let questions = vec!["Question 1".to_string(), "Question 2".to_string()];
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(questions, answers, data2, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Number of questions and answers must match"));
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

        let result = AskryptFile::create(questions, answers, data, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Question length must not exceed 500 characters"));
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
                secret: "password123".to_string(),
                url: "https://example.com".to_string(),
                notes: "My account".to_string(),
                entry_type: "password".to_string(),
                tags: vec!["work".to_string()],
                created: "2024-01-01T00:00:00Z".to_string(),
                modified: "2024-01-01T00:00:00Z".to_string(),
            },
            SecretEntry {
                name: "example2".to_string(),
                secret: "secret456".to_string(),
                url: "https://test.com".to_string(),
                notes: "Test notes".to_string(),
                entry_type: "note".to_string(),
                tags: vec!["personal".to_string(), "important".to_string()],
                created: "2024-01-02T00:00:00Z".to_string(),
                modified: "2024-01-02T00:00:00Z".to_string(),
            },
        ];

        // Create AskryptFile
        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            original_data.clone(),
            Some(6000),
        )
            .unwrap();

        // Decrypt and verify
        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = askrypt_file
            .decrypt(questions_data, answers[1..].into())
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
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: "2024-01-01T00:00:00Z".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
        }];

        let askrypt_file =
            AskryptFile::create(questions.clone(), answers.clone(), data.clone(), Some(6000))
                .unwrap();

        // Try to decrypt with wrong answer
        let wrong_answers = vec!["Fluffy".to_string(), "New York2".to_string()];

        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let result = askrypt_file.decrypt(questions_data, wrong_answers);
        // Should fail due to wrong answer (decryption error or invalid JSON)
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Decryption padding error"));
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
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: "2024-01-01T00:00:00Z".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
        }];

        let askrypt_file =
            AskryptFile::create(questions.clone(), answers.clone(), data.clone(), Some(6000))
                .unwrap();

        let temp_file = "test_askrypt_file.json";

        // Save to file
        askrypt_file.save_to_file(temp_file).unwrap();

        // Load from file
        let loaded_file = AskryptFile::load_from_file(temp_file).unwrap();

        // Verify they match
        assert_eq!(askrypt_file, loaded_file);

        // Verify we can still decrypt with the loaded file
        let questions_data = loaded_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = loaded_file
            .decrypt(questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted_data, data);

        // Cleanup
        fs::remove_file(temp_file).ok();
    }
}
