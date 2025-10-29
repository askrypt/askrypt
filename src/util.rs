use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

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
/// use arpwd::util::encrypt_with_aes;
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
/// use arpwd::util::{encrypt_with_aes, decrypt_with_aes};
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

