use aes::Aes256;
use sha2::Sha256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Represents the content of an Askrypt file
///
/// According to the Askrypt specification, a file contains:
/// - A version header (e.g., "askrypt-v1.0")
/// - A list of questions
/// - Base64-encoded encrypted data
#[derive(Debug, Clone, PartialEq)]
pub struct AskryptContent {
    /// The version string from the file header
    pub version: String,
    /// The list of questions
    pub questions: Vec<String>,
    /// The base64-encoded encrypted data as raw bytes
    pub base64_data: Vec<u8>,
}

impl AskryptContent {
    /// Read an Askrypt file from the given path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the Askrypt file
    ///
    /// # Returns
    ///
    /// Returns a Result containing the parsed AskryptContent or an error
    ///
    /// # Example
    ///
    /// ```no_run
    /// use askrypt::AskryptContent;
    ///
    /// let content = AskryptContent::from_file("myfile.askrypt").unwrap();
    /// println!("Version: {}", content.version);
    /// println!("Questions: {:?}", content.questions);
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Read version line
        let version = lines
            .next()
            .ok_or("File is empty")??
            .trim()
            .to_string();

        // Validate version format
        if !version.starts_with("askrypt-") {
            return Err("Invalid file format: missing 'askrypt-' header".into());
        }

        // Read first separator
        let separator1 = lines.next().ok_or("Missing first separator")??;
        if separator1.trim() != "---" {
            return Err("Invalid file format: expected '---' separator".into());
        }

        // Read questions until we hit the second separator
        let mut questions = Vec::new();
        for line in lines.by_ref() {
            let line = line?;
            if line.trim() == "---" {
                break;
            }
            let question = line.trim().to_string();
            if !question.is_empty() {
                if question.len() > 255 {
                    return Err(format!(
                        "Question exceeds maximum length of 255 characters: {}",
                        question.len()
                    )
                    .into());
                }
                questions.push(question);
            }
        }

        if questions.is_empty() {
            return Err("No questions found in file".into());
        }

        // Read base64 data (rest of the file)
        let mut base64_data = Vec::new();
        for line in lines {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                base64_data.extend_from_slice(trimmed.as_bytes());
            }
        }

        if base64_data.is_empty() {
            return Err("No encrypted data found in file".into());
        }

        Ok(AskryptContent {
            version,
            questions,
            base64_data,
        })
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


#[cfg(test)]
mod tests {
    use hex::encode;
    use super::*;

    #[test]
    fn test_askrypt_content_from_file() {
        use std::io::Write;
        use std::fs;

        // Create a temporary test file
        let test_content = "askrypt-v1.0\n---\nWhat is your name?\nWhat is your age?\n---\naGVsbG8gd29ybGQ=\n";
        let temp_file = "test_temp_askrypt.txt";

        {
            let mut file = File::create(temp_file).unwrap();
            file.write_all(test_content.as_bytes()).unwrap();
        }

        // Test reading the file
        let content = AskryptContent::from_file(temp_file).unwrap();

        assert_eq!(content.version, "askrypt-v1.0");
        assert_eq!(content.questions.len(), 2);
        assert_eq!(content.questions[0], "What is your name?");
        assert_eq!(content.questions[1], "What is your age?");
        assert_eq!(String::from_utf8_lossy(&content.base64_data), "aGVsbG8gd29ybGQ=");

        // Cleanup
        fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_askrypt_content_invalid_format() {
        use std::io::Write;
        use std::fs;

        // Create a file with invalid format (no version header)
        let test_content = "invalid header\n---\nQuestion?\n---\ndata\n";
        let temp_file = "test_invalid_askrypt.txt";

        {
            let mut file = File::create(temp_file).unwrap();
            file.write_all(test_content.as_bytes()).unwrap();
        }

        // Test that it fails
        let result = AskryptContent::from_file(temp_file);
        assert!(result.is_err());

        // Cleanup
        fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_askrypt_content_question_too_long() {
        use std::io::Write;
        use std::fs;

        // Create a file with a question that's too long
        let long_question = "a".repeat(256);
        let test_content = format!("askrypt-v1.0\n---\n{}\n---\ndata\n", long_question);
        let temp_file = "test_long_question.txt";

        {
            let mut file = File::create(temp_file).unwrap();
            file.write_all(test_content.as_bytes()).unwrap();
        }

        // Test that it fails
        let result = AskryptContent::from_file(temp_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum length"));

        // Cleanup
        fs::remove_file(temp_file).ok();
    }

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
}
