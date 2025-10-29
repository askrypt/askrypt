use arpwd::hash::calc_pbkdf2;
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
        }
        Err(e) => {
            eprintln!("Error calculating PBKDF2: {}", e);
        }
    }

    Ok(())
}
