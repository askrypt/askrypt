use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub last_opened_file: Option<PathBuf>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            last_opened_file: None,
        }
    }
}

impl AppSettings {
    /// Load settings from the config file
    pub fn load() -> Self {
        if let Some(config_path) = Self::get_config_path() {
            if config_path.exists() {
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
