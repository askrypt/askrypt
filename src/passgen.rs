use rand::Rng;

#[derive(Debug, Clone)]
pub struct PasswordGenConfig {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl Default for PasswordGenConfig {
    fn default() -> Self {
        Self {
            length: 20,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        }
    }
}

impl PasswordGenConfig {
    pub const MIN_LENGTH: usize = 8;
    pub const MAX_LENGTH: usize = 100;

    pub fn set_length(&mut self, length: usize) {
        self.length = length.clamp(Self::MIN_LENGTH, Self::MAX_LENGTH);
    }

    fn get_charset(&self) -> Vec<char> {
        let mut charset = Vec::new();

        if self.use_lowercase {
            charset.extend("abcdefghijklmnopqrstuvwxyz".chars());
        }

        if self.use_uppercase {
            charset.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
        }

        if self.use_numbers {
            charset.extend("0123456789".chars());
        }

        if self.use_symbols {
            charset.extend("!@#$%^&*()_+-=[]{}|;:,.<>?".chars());
        }

        charset
    }

    pub fn has_valid_options(&self) -> bool {
        self.use_uppercase || self.use_lowercase || self.use_numbers || self.use_symbols
    }
}

pub fn generate_password(config: &PasswordGenConfig) -> Result<String, String> {
    if !config.has_valid_options() {
        return Err("At least one character type must be selected".to_string());
    }

    let charset = config.get_charset();
    if charset.is_empty() {
        return Err("No character set available".to_string());
    }

    let mut rng = rand::rng();
    let password: String = (0..config.length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx]
        })
        .collect();

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PasswordGenConfig::default();
        assert_eq!(config.length, 20);
        assert!(config.use_uppercase);
        assert!(config.use_lowercase);
        assert!(config.use_numbers);
        assert!(config.use_symbols);
    }

    #[test]
    fn test_generate_password_length() {
        let config = PasswordGenConfig::default();
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_generate_password_min_length() {
        let mut config = PasswordGenConfig::default();
        config.set_length(5); // Should clamp to MIN_LENGTH
        assert_eq!(config.length, PasswordGenConfig::MIN_LENGTH);
    }

    #[test]
    fn test_generate_password_max_length() {
        let mut config = PasswordGenConfig::default();
        config.set_length(150); // Should clamp to MAX_LENGTH
        assert_eq!(config.length, PasswordGenConfig::MAX_LENGTH);
    }

    #[test]
    fn test_no_options_selected() {
        let config = PasswordGenConfig {
            length: 20,
            use_uppercase: false,
            use_lowercase: false,
            use_numbers: false,
            use_symbols: false,
        };
        let result = generate_password(&config);
        assert!(result.is_err());
    }
}
