//! Persistent user settings, and the serializable identity of a vault's
//! storage backend.
//!
//! Ported from the shipping app's `src/settings.rs`. [`VaultLocation`] and
//! [`ServerSession`] are unchanged — they define the on-disk shape of
//! `settings.json` and `server_session.json`, which both binaries read.
//! [`AppSettings`] gained the preferences the three-pane UI exposes, every one
//! of them `#[serde(default)]` so a file written by the old app still parses.

use askrypt::{LocalFileStorage, ServerClient, ServerStorage, StorageError, VaultStorage};
use iced::window::Position;
use iced::{Point, Size};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How many vaults the wizard's "recent" list remembers.
pub const MAX_RECENT_VAULTS: usize = 5;

/// The window size a first run opens at — the width the three panes were laid
/// out against.
const DEFAULT_WINDOW_SIZE: [f32; 2] = [1100.0, 700.0];

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

    /// Window-title name: the file name for a local vault, `name @ host` for a
    /// server one, so the title says which server a vault came from the way the
    /// rest of the UI does. A local vault's full path is too long for a title.
    pub fn title_name(&self) -> String {
        if self.is_server() {
            self.display_location()
        } else {
            self.display_name()
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

/// Which palette the window paints in. Persisted, so it survives a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeChoice {
    #[default]
    Light,
    Dark,
}

impl ThemeChoice {
    pub const ALL: [ThemeChoice; 2] = [ThemeChoice::Light, ThemeChoice::Dark];

    pub fn theme(self) -> iced::Theme {
        match self {
            ThemeChoice::Light => iced::Theme::Light,
            ThemeChoice::Dark => iced::Theme::Dark,
        }
    }
}

impl std::fmt::Display for ThemeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
        })
    }
}

/// How long the vault may sit idle before it Smart Locks itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LockTimeout {
    FiveMinutes,
    #[default]
    TenMinutes,
    ThirtyMinutes,
    Never,
}

impl LockTimeout {
    pub const ALL: [LockTimeout; 4] = [
        LockTimeout::FiveMinutes,
        LockTimeout::TenMinutes,
        LockTimeout::ThirtyMinutes,
        LockTimeout::Never,
    ];

    /// `None` disables the idle check entirely.
    pub fn duration(self) -> Option<Duration> {
        match self {
            LockTimeout::FiveMinutes => Some(Duration::from_secs(5 * 60)),
            LockTimeout::TenMinutes => Some(Duration::from_secs(10 * 60)),
            LockTimeout::ThirtyMinutes => Some(Duration::from_secs(30 * 60)),
            LockTimeout::Never => None,
        }
    }
}

impl std::fmt::Display for LockTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LockTimeout::FiveMinutes => "After 5 minutes",
            LockTimeout::TenMinutes => "After 10 minutes",
            LockTimeout::ThirtyMinutes => "After 30 minutes",
            LockTimeout::Never => "Never",
        })
    }
}

/// Where the window was when the app last exited, so a restart puts it back.
///
/// `size` and `position` are always the *restored* geometry, never the
/// maximized one: a window maximized at exit reopens maximized and unmaximizes
/// back to the box it had before. Iced reports moves and resizes but has no
/// "maximized" event, so `main.rs` asks `window::is_maximized` after every one
/// and only commits the geometry when the answer is `false`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowState {
    /// Logical width and height of the client area.
    pub size: [f32; 2],
    /// Top-left corner of the window area. `None` until the platform reports
    /// one — on Wayland it never does, and the compositor places the window
    /// itself.
    #[serde(default)]
    pub position: Option<[f32; 2]>,
    #[serde(default)]
    pub maximized: bool,
}

impl Default for WindowState {
    fn default() -> Self {
        WindowState {
            size: DEFAULT_WINDOW_SIZE,
            position: None,
            maximized: false,
        }
    }
}

impl WindowState {
    /// Whether a remembered geometry is worth restoring.
    pub fn is_usable(&self) -> bool {
        Self::sane_size(self.size) && self.position.is_none_or(Self::sane_position)
    }

    /// Windows reports a *minimized* window as `0 x 0`, and this app minimizes
    /// to the tray, so that value would otherwise be the last size seen.
    pub fn sane_size([width, height]: [f32; 2]) -> bool {
        (200.0..=20_000.0).contains(&width) && (150.0..=20_000.0).contains(&height)
    }

    /// Likewise a minimized window sits at `-32000, -32000`, and a monitor that
    /// has since been unplugged leaves coordinates pointing at nothing. The
    /// bounds stay loose on purpose: a second monitor above or left of the
    /// primary one gives legitimately negative coordinates.
    pub fn sane_position([x, y]: [f32; 2]) -> bool {
        (-20_000.0..=20_000.0).contains(&x) && (-20_000.0..=20_000.0).contains(&y)
    }

    pub fn logical_size(&self) -> Size {
        Size::new(self.size[0], self.size[1])
    }

    /// Where to open the window. With nothing remembered — a first run, or a
    /// platform that never reports a position — fall back to centering, which
    /// is what the app did before it remembered anything.
    pub fn window_position(&self) -> Position {
        match self.position {
            Some([x, y]) => Position::Specific(Point::new(x, y)),
            None => Position::Centered,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// The vault reopened at startup. Kept as its own field rather than folded
    /// into `recent_vaults` because the shipping app reads it.
    #[serde(default)]
    pub last_opened_file: Option<VaultLocation>,
    /// Most-recently-opened vaults, newest first, capped at
    /// [`MAX_RECENT_VAULTS`]. Feeds the wizard's "recent vaults" picker.
    #[serde(default)]
    pub recent_vaults: Vec<VaultLocation>,
    #[serde(default)]
    pub theme: ThemeChoice,
    #[serde(default)]
    pub lock_timeout: LockTimeout,
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    #[serde(default)]
    pub show_hidden_by_default: bool,
    #[serde(default = "default_true")]
    pub clear_clipboard: bool,
    /// The one Askrypt server this app talks to. Sign-in happens in the
    /// browser, so this is the *only* thing about a server the app asks for.
    ///
    /// Free text as the user typed it; read it back through
    /// [`AppSettings::server_url`], which normalizes it the way `core` does.
    #[serde(default = "default_server_url")]
    pub server_url: String,
    /// Where the window was last seen. `None` on a first run and in any
    /// `settings.json` written by the shipping app, which has no window memory.
    #[serde(default)]
    pub window: Option<WindowState>,
}

fn default_true() -> bool {
    true
}

/// The hosted Askrypt server. Self-hosters change it in Settings.
pub const DEFAULT_SERVER_URL: &str = "https://askrypt.com";

fn default_server_url() -> String {
    DEFAULT_SERVER_URL.to_string()
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            last_opened_file: None,
            recent_vaults: Vec::new(),
            theme: ThemeChoice::default(),
            lock_timeout: LockTimeout::default(),
            minimize_to_tray: true,
            show_hidden_by_default: false,
            clear_clipboard: true,
            // The `#[serde(default)]` above only covers *parsing*; a default
            // built in code needs it spelled out again or the app starts with
            // no server at all.
            server_url: default_server_url(),
            window: None,
        }
    }
}

impl AppSettings {
    /// The configured server, normalized exactly as `core` normalizes a base
    /// URL.
    ///
    /// Must go through `core`'s own function: a saved
    /// [`VaultLocation::Server`] is matched to a signed-in client by *exact*
    /// string, so a second, slightly different normalization here would leave
    /// vaults unopenable.
    pub fn server_url(&self) -> String {
        askrypt::normalize_base_url(&self.server_url)
    }

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

    /// Record a vault as the most recently used one: it becomes
    /// `last_opened_file` and moves to the front of `recent_vaults`.
    ///
    /// Re-opening a vault that is already in the list moves it rather than
    /// duplicating it, so the picker never shows the same vault twice.
    pub fn remember_vault(&mut self, location: &VaultLocation) {
        self.recent_vaults.retain(|known| known != location);
        self.recent_vaults.insert(0, location.clone());
        self.recent_vaults.truncate(MAX_RECENT_VAULTS);
        self.last_opened_file = Some(location.clone());
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

    fn with_location(location: VaultLocation) -> AppSettings {
        AppSettings {
            last_opened_file: Some(location),
            ..AppSettings::default()
        }
    }

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
        let settings = with_location(VaultLocation::LocalFile(PathBuf::from("/tmp/v.askrypt")));
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
        let settings = with_location(server_location());
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
    fn the_window_title_names_the_server_but_never_a_full_path() {
        assert_eq!(
            server_location().title_name(),
            "MyVault.askrypt @ askrypt.example.com"
        );
        assert_eq!(
            VaultLocation::LocalFile(PathBuf::from("/tmp/v.askrypt")).title_name(),
            "v.askrypt"
        );
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

    /// A settings file written by the shipping app carries only
    /// `last_opened_file`; every preference this UI added must fall back to its
    /// default rather than failing the whole parse.
    #[test]
    fn settings_json_from_the_old_app_keeps_the_new_defaults() {
        let settings: AppSettings =
            serde_json::from_str(r#"{"last_opened_file":"/tmp/v.askrypt"}"#).unwrap();

        assert!(settings.recent_vaults.is_empty());
        assert_eq!(settings.theme, ThemeChoice::Light);
        assert_eq!(settings.lock_timeout, LockTimeout::TenMinutes);
        assert!(settings.minimize_to_tray);
        assert!(!settings.show_hidden_by_default);
        assert!(settings.clear_clipboard);
        assert_eq!(settings.window, None);
    }

    #[test]
    fn window_state_round_trips() {
        let window = WindowState {
            size: [1400.0, 900.0],
            position: Some([-1920.0, 40.0]),
            maximized: true,
        };
        let settings = AppSettings {
            window: Some(window),
            ..AppSettings::default()
        };

        let json = serde_json::to_string(&settings).unwrap();
        let parsed: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.window, Some(window));
    }

    /// A window state written before a monitor was unplugged, or by a minimized
    /// window on Windows, must not be restored — the window would open where
    /// nobody can reach it.
    #[test]
    fn nonsense_geometry_is_not_usable() {
        let minimized_on_windows = WindowState {
            size: [0.0, 0.0],
            position: Some([-32_000.0, -32_000.0]),
            maximized: false,
        };
        assert!(!minimized_on_windows.is_usable());

        assert!(
            !WindowState {
                size: [f32::NAN, 700.0],
                ..WindowState::default()
            }
            .is_usable()
        );

        // A monitor above and to the left of the primary one is fine, though.
        assert!(
            WindowState {
                size: [1100.0, 700.0],
                position: Some([-1920.0, -1080.0]),
                maximized: false,
            }
            .is_usable()
        );
    }

    /// Without a remembered position the window keeps the old centered
    /// behaviour rather than landing wherever the platform feels like.
    #[test]
    fn a_missing_position_centers_the_window() {
        assert!(matches!(
            WindowState::default().window_position(),
            Position::Centered
        ));
        assert!(matches!(
            WindowState {
                position: Some([10.0, 20.0]),
                ..WindowState::default()
            }
            .window_position(),
            Position::Specific(point) if point == Point::new(10.0, 20.0)
        ));
    }

    #[test]
    fn remembering_a_vault_moves_it_to_the_front_without_duplicating() {
        let first = VaultLocation::LocalFile(PathBuf::from("/tmp/a.askrypt"));
        let second = VaultLocation::LocalFile(PathBuf::from("/tmp/b.askrypt"));

        let mut settings = AppSettings::default();
        settings.remember_vault(&first);
        settings.remember_vault(&second);
        settings.remember_vault(&first);

        assert_eq!(settings.recent_vaults, vec![first.clone(), second]);
        assert_eq!(settings.last_opened_file, Some(first));
    }

    #[test]
    fn the_recent_list_is_capped() {
        let mut settings = AppSettings::default();
        for index in 0..(MAX_RECENT_VAULTS + 3) {
            settings.remember_vault(&VaultLocation::LocalFile(PathBuf::from(format!(
                "/tmp/{index}.askrypt"
            ))));
        }

        assert_eq!(settings.recent_vaults.len(), MAX_RECENT_VAULTS);
        // Newest first.
        assert_eq!(
            settings.recent_vaults[0],
            VaultLocation::LocalFile(PathBuf::from(format!(
                "/tmp/{}.askrypt",
                MAX_RECENT_VAULTS + 2
            )))
        );
    }

    #[test]
    fn a_fresh_install_points_at_the_hosted_server() {
        // Both paths: the value built in code and the one a `settings.json`
        // written before this field existed parses to.
        assert_eq!(AppSettings::default().server_url(), DEFAULT_SERVER_URL);

        let old: AppSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(old.server_url(), DEFAULT_SERVER_URL);
    }

    #[test]
    fn the_server_url_is_normalized_the_way_core_normalizes_it() {
        // A saved server vault is matched to a signed-in client by exact
        // string, so a stray slash here would leave it unopenable.
        let settings = AppSettings {
            server_url: "  https://askrypt.example.com/  ".to_string(),
            ..AppSettings::default()
        };
        assert_eq!(settings.server_url(), "https://askrypt.example.com");
    }

    #[test]
    fn a_configured_server_survives_a_round_trip() {
        let settings = AppSettings {
            server_url: "https://vault.example.org".to_string(),
            ..AppSettings::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server_url(), "https://vault.example.org");
    }
}
