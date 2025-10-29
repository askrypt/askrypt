use arpwd::hash::calc_pbkdf2;
use arpwd::util::encrypt_with_aes;
use arpwd::util::decrypt_with_aes;
use hex::encode;
use rand::{random};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ARPWD - PBKDF2 Key Derivation Tool");
    println!("==================================");

    // Get secret from user
    print!("Enter secret/password: ");
    io::stdout().flush()?;
    let mut secret = String::new();
    io::stdin().read_line(&mut secret)?;
    let secret = secret.trim();

    let salt = random::<[u8; 16]>();
    print!("Generated salt: {}", encode(&salt));

    println!("\nCalculating PBKDF2...");

    let iterations = 300_000;

    match calc_pbkdf2(secret, &salt, iterations) {
        Ok(derived_key) => {
            println!("\nCalculated PBKDF2:");
            println!("Iterations: {}", iterations);
            println!("Derived key (hex): {}", encode(&derived_key));
            
            // Example encryption using the derived key
            let iv = random::<[u8; 16]>();
            let message = b"Example message to encrypt with utf: \xE6\x97\xA5\xE6\x9C\xAC\xE5\x9B\xBD";// 日本国
            let key: &[u8; 32] = &derived_key.try_into().unwrap();
            let ciphertext = encrypt_with_aes(message, key, &iv)?;
            println!("Ciphertext (hex): {}", encode(&ciphertext));
            // Example decryption using the derived key
            let decrypted_message = decrypt_with_aes(&ciphertext, key, &iv)?;
            println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted_message));
        }
        Err(e) => {
            eprintln!("Error calculating PBKDF2: {}", e);
        }
    }

    Ok(())
}
