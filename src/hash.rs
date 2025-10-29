use sha2::Sha256;

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
