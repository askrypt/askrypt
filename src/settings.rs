use askrypt::{LocalFileStorage, VaultStorage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Where a vault lives. Serializable identity for a storage backend;
/// `LocalFile` serializes untagged as a plain path string, keeping existing
/// settings.json files compatible. A future `Server { .. }` variant will
/// serialize as an object, which untagged deserialization distinguishes
/// unambiguously from a string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VaultLocation {
    LocalFile(PathBuf),
}

impl VaultLocation {
    /// Build the storage backend for this location.
    pub fn storage(&self) -> Box<dyn VaultStorage> {
        match self {
            VaultLocation::LocalFile(path) => Box::new(LocalFileStorage::new(path.clone())),
        }
    }

    /// Short name for the window title (file name, or "Untitled").
    pub fn display_name(&self) -> String {
        match self {
            VaultLocation::LocalFile(path) => path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Untitled".to_string()),
        }
    }

    /// Full location string for status lines.
    pub fn display_location(&self) -> String {
        self.storage().location()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppSettings {
    pub last_opened_file: Option<VaultLocation>,
}

impl AppSettings {
    /// Load settings from the config file
    pub fn load() -> Self {
        if let Some(config_path) = Self::get_config_path()
            && config_path.exists()
        {
            match fs::read_to_string(&config_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(settings) => return settings,
                    Err(e) => {
                        eprintln!("Failed to parse settings file: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Failed to read settings file: {}", e);
                }
            }
        }
        Self::default()
    }

    /// Save settings to the config file
    pub fn save(&self) -> Result<(), String> {
        let config_path = Self::get_config_path()
            .ok_or_else(|| "Could not determine config directory".to_string())?;

        // Create config directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;

        fs::write(&config_path, contents)
            .map_err(|e| format!("Failed to write settings file: {}", e))?;

        Ok(())
    }

    /// Get the path to the config file
    fn get_config_path() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA")
                .ok()
                .map(|appdata| PathBuf::from(appdata).join("askrypt").join("settings.json"))
        }

        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME").ok().map(|home| {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("askrypt")
                    .join("settings.json")
            })
        }

        #[cfg(target_os = "linux")]
        {
            // Try XDG_CONFIG_HOME first, fall back to ~/.config
            let config_dir = std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var("HOME")
                        .ok()
                        .map(|home| PathBuf::from(home).join(".config"))
                });

            config_dir.map(|dir| dir.join("askrypt").join("settings.json"))
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_json_backcompat_plain_string_path() {
        let settings: AppSettings =
            serde_json::from_str(r#"{"last_opened_file":"/tmp/v.askrypt"}"#).unwrap();
        assert_eq!(
            settings.last_opened_file,
            Some(VaultLocation::LocalFile(PathBuf::from("/tmp/v.askrypt")))
        );
    }

    #[test]
    fn settings_json_local_file_serializes_as_plain_string() {
        let settings = AppSettings {
            last_opened_file: Some(VaultLocation::LocalFile(PathBuf::from("/tmp/v.askrypt"))),
        };
        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value["last_opened_file"], "/tmp/v.askrypt");
    }

    #[test]
    fn settings_json_null_and_missing_field_are_none() {
        let null: AppSettings = serde_json::from_str(r#"{"last_opened_file":null}"#).unwrap();
        assert_eq!(null.last_opened_file, None);
        let missing: AppSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(missing.last_opened_file, None);
    }
}
