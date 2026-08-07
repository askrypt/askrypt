use askrypt::{LocalFileStorage, ServerClient, ServerStorage, StorageError, VaultStorage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

/// Where a vault lives. Serializable identity for a storage backend;
/// `LocalFile` serializes untagged as a plain path string, keeping existing
/// settings.json files compatible. `Server` serializes as an object, which
/// untagged deserialization distinguishes unambiguously from a string — so
/// `LocalFile` must stay the first variant.
///
/// A server vault is identified by its *name*, not by the server-assigned id:
/// the name is what the user sees, and it is what the storage backend resolves
/// against the account's listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VaultLocation {
    LocalFile(PathBuf),
    Server {
        base_url: String,
        email: String,
        name: String,
    },
}

impl VaultLocation {
    /// Build the storage backend for this location.
    ///
    /// `client` is the session's signed-in server client, ignored for local
    /// files. A server location without a matching signed-in client fails with
    /// [`StorageError::Auth`], which callers turn into "sign in again".
    pub fn storage(
        &self,
        client: Option<&Arc<ServerClient>>,
    ) -> Result<Arc<dyn VaultStorage>, StorageError> {
        match self {
            VaultLocation::LocalFile(path) => Ok(Arc::new(LocalFileStorage::new(path.clone()))),
            VaultLocation::Server { base_url, name, .. } => {
                // A client for a *different* server is no use here, so check the
                // base URL rather than just "signed in somewhere".
                let client = client
                    .filter(|client| client.base_url() == base_url)
                    .ok_or_else(|| StorageError::Auth(format!("not signed in to {}", base_url)))?;
                Ok(Arc::new(ServerStorage::by_name(
                    Arc::clone(client),
                    name.clone(),
                )))
            }
        }
    }

    /// Short name for the window title (file name, or "Untitled").
    pub fn display_name(&self) -> String {
        match self {
            VaultLocation::LocalFile(path) => path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Untitled".to_string()),
            VaultLocation::Server { name, .. } => name.clone(),
        }
    }

    /// Full location string for status lines. Formatted directly rather than
    /// via `storage().location()`, which a server location cannot build without
    /// a signed-in client.
    pub fn display_location(&self) -> String {
        match self {
            VaultLocation::LocalFile(path) => path.display().to_string(),
            VaultLocation::Server { base_url, name, .. } => {
                format!("{} @ {}", name, host_of(base_url))
            }
        }
    }

    /// Whether this vault lives on a server (so the UI can say so).
    pub fn is_server(&self) -> bool {
        matches!(self, VaultLocation::Server { .. })
    }
}

/// Host portion of a base URL, for display.
fn host_of(base_url: &str) -> &str {
    base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url)
        .trim_end_matches('/')
}

/// A saved sign-in to an Askrypt server.
///
/// Deliberately *not* part of [`AppSettings`]: the token is a credential, not a
/// preference. It authorizes account operations that never re-ask for the
/// password (changing the account email, deleting the account), so it lives in
/// its own file that is created `0600` on Unix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSession {
    pub base_url: String,
    pub email: String,
    pub token: String,
}

impl ServerSession {
    /// Read the saved session, if any. A malformed or unreadable file is
    /// treated as "not signed in".
    pub fn load() -> Option<Self> {
        let path = Self::path()?;
        let contents = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    /// Persist this session, replacing any previous one.
    pub fn save(&self) -> Result<(), String> {
        let path =
            Self::path().ok_or_else(|| "Could not determine config directory".to_string())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize server session: {}", e))?;

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // Restrict on creation rather than after writing, so the token is never
        // briefly readable by other users on the machine.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        use std::io::Write;
        let mut file = options
            .open(&path)
            .map_err(|e| format!("Failed to open server session file: {}", e))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write server session file: {}", e))
    }

    /// Forget the saved session (after signing out, or after the server
    /// rejected the token).
    pub fn clear() {
        if let Some(path) = Self::path() {
            fs::remove_file(path).ok();
        }
    }

    fn path() -> Option<PathBuf> {
        AppSettings::config_dir().map(|dir| dir.join("server_session.json"))
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
        Self::config_dir().map(|dir| dir.join("settings.json"))
    }

    /// The per-user config directory holding `settings.json` and, when the user
    /// has signed in to a server, `server_session.json`.
    pub(crate) fn config_dir() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA")
                .ok()
                .map(|appdata| PathBuf::from(appdata).join("askrypt"))
        }

        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME").ok().map(|home| {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("askrypt")
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

            config_dir.map(|dir| dir.join("askrypt"))
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

    fn server_location() -> VaultLocation {
        VaultLocation::Server {
            base_url: "https://askrypt.example.com".to_string(),
            email: "me@example.com".to_string(),
            name: "MyVault.askrypt".to_string(),
        }
    }

    #[test]
    fn settings_json_server_location_round_trips_as_an_object() {
        let settings = AppSettings {
            last_opened_file: Some(server_location()),
        };
        let json = serde_json::to_string(&settings).unwrap();
        let parsed: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.last_opened_file, Some(server_location()));
    }

    #[test]
    fn settings_json_distinguishes_a_path_from_a_server() {
        // The whole reason `LocalFile` stays the first untagged variant: a
        // string must never be read as a server location, or vice versa.
        let path: AppSettings =
            serde_json::from_str(r#"{"last_opened_file":"/tmp/v.askrypt"}"#).unwrap();
        assert!(matches!(
            path.last_opened_file,
            Some(VaultLocation::LocalFile(_))
        ));

        let server: AppSettings = serde_json::from_str(
            r#"{"last_opened_file":{"base_url":"https://askrypt.example.com",
                "email":"me@example.com","name":"MyVault.askrypt"}}"#,
        )
        .unwrap();
        assert_eq!(server.last_opened_file, Some(server_location()));
    }

    #[test]
    fn server_location_displays_vault_name_and_host() {
        let location = server_location();
        assert_eq!(location.display_name(), "MyVault.askrypt");
        assert_eq!(
            location.display_location(),
            "MyVault.askrypt @ askrypt.example.com"
        );
        assert!(location.is_server());
    }

    #[test]
    fn server_storage_requires_a_client_for_the_same_server() {
        let location = server_location();

        // Signed out entirely.
        assert!(matches!(
            location.storage(None),
            Err(askrypt::StorageError::Auth(_))
        ));

        // Signed in, but to a different server.
        let elsewhere = Arc::new(ServerClient::with_token("https://other.example.com", "tok"));
        assert!(matches!(
            location.storage(Some(&elsewhere)),
            Err(askrypt::StorageError::Auth(_))
        ));

        // Signed in to the right one.
        let right = Arc::new(ServerClient::with_token(
            "https://askrypt.example.com",
            "tok",
        ));
        let storage = location.storage(Some(&right)).expect("should build");
        assert_eq!(storage.location(), "MyVault.askrypt @ askrypt.example.com");
    }

    #[test]
    fn local_file_storage_needs_no_client() {
        let location = VaultLocation::LocalFile(PathBuf::from("/tmp/v.askrypt"));
        let storage = location.storage(None).expect("should build");

        assert_eq!(storage.location(), "/tmp/v.askrypt");
    }

    #[test]
    fn settings_json_null_and_missing_field_are_none() {
        let null: AppSettings = serde_json::from_str(r#"{"last_opened_file":null}"#).unwrap();
        assert_eq!(null.last_opened_file, None);
        let missing: AppSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(missing.last_opened_file, None);
    }
}
