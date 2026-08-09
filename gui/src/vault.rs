//! The vault lifecycle, modelled but not implemented.
//!
//! This is a *fake* of the state machine the shipping app derives from
//! `src/session.rs` (`file`/`questions_data`/`unlocked`/`smart_lock_data` plus
//! the active `Screen`). Nothing here loads, decrypts or writes anything — the
//! whole point is to have the five states on screen so the controls that
//! depend on them can be designed. See `gui/README.md` for the real logic and
//! the invariants a port has to keep.

/// Where the vault "lives". Mirrors `src/settings.rs::VaultLocation`, plus a
/// `Cloud` placeholder the real enum does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    File(String),
    Server {
        base_url: String,
        name: String,
    },
    /// Reserved: the wizard's cloud-folder card is disabled, so nothing can
    /// produce this yet. It exists so the layout below already handles it.
    #[allow(dead_code)]
    Cloud,
}

impl Source {
    /// The vault's short name — a file's stem-ish tail, or the server name.
    pub fn display_name(&self) -> &str {
        match self {
            Source::File(path) => path.rsplit('/').next().unwrap_or(path),
            Source::Server { name, .. } => name,
            Source::Cloud => "Cloud vault",
        }
    }

    /// The status-line form. The shipping app makes the same distinction in
    /// `src/screens/mod.rs::show_vault_path` so it is obvious at a glance
    /// whether an unlock is about to touch the network.
    pub fn display_location(&self) -> String {
        match self {
            Source::File(path) => format!("Vault File: {path}"),
            Source::Server { base_url, name } => format!("Server Vault: {name} — {base_url}"),
            Source::Cloud => "Cloud Vault".to_string(),
        }
    }
}

/// The five states the real app can be in. Ordered from least to most open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Nothing loaded.
    NoVault,
    /// Bytes loaded; not one answer accepted yet.
    Locked,
    /// The first answer decrypted the *question list* but not the entries —
    /// the real app's layered unlock, not a UI step.
    PartiallyUnlocked,
    /// Entries decrypted and in memory.
    Unlocked,
    /// Answers held re-encrypted in RAM: one answer re-opens the vault.
    SmartLocked,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::NoVault => "No vault",
            Status::Locked => "Locked",
            Status::PartiallyUnlocked => "Partially unlocked",
            Status::Unlocked => "Unlocked",
            Status::SmartLocked => "Smart Locked",
        }
    }
}

pub struct Vault {
    pub status: Status,
    pub source: Option<Source>,
    pub modified: bool,
}

impl Default for Vault {
    /// Boot straight into an unlocked fake vault, so the three-pane layout is
    /// still the first thing the prototype shows.
    fn default() -> Self {
        Vault {
            status: Status::Unlocked,
            source: Some(Source::File("~/vaults/MyVault.askrypt".to_string())),
            modified: false,
        }
    }
}

impl Vault {
    // -----------------------------------------------------------------------
    // Button visibility. The rail asks these; it never matches on `status`
    // itself, so the rules stay in one place.
    // -----------------------------------------------------------------------

    /// Always, like [`Self::can_open`]: starting over is offered in every
    /// state, unlike the shipping app where both live on the Welcome screen
    /// only.
    pub fn can_create(&self) -> bool {
        true
    }

    /// Always: opening another vault is offered in every state, unlike the
    /// shipping app where it lives on the Welcome screen only.
    pub fn can_open(&self) -> bool {
        true
    }

    pub fn can_unlock(&self) -> bool {
        matches!(
            self.status,
            Status::Locked | Status::PartiallyUnlocked | Status::SmartLocked
        )
    }

    pub fn can_smart_lock(&self) -> bool {
        self.status == Status::Unlocked
    }

    /// Covers both depths: `Lock` from unlocked, `Full Lock` out of Smart Lock.
    pub fn can_lock(&self) -> bool {
        matches!(self.status, Status::Unlocked | Status::SmartLocked)
    }

    pub fn lock_label(&self) -> &'static str {
        if self.status == Status::SmartLocked {
            "Full Lock"
        } else {
            "Lock"
        }
    }

    /// Saving needs the decrypted entries, so unlocked only.
    pub fn can_save(&self) -> bool {
        self.status == Status::Unlocked
    }

    pub fn can_save_as(&self) -> bool {
        self.can_save()
    }

    pub fn is_unlocked(&self) -> bool {
        self.status == Status::Unlocked
    }

    pub fn is_open(&self) -> bool {
        self.status != Status::NoVault
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    pub fn display_name(&self) -> &str {
        self.source
            .as_ref()
            .map_or("Untitled vault", Source::display_name)
    }

    pub fn display_location(&self) -> Option<String> {
        self.source.as_ref().map(Source::display_location)
    }

    /// The idle status-bar line: name, state, and the shipping app's `*`
    /// unsaved marker (`src/session.rs::title`).
    pub fn status_line(&self) -> String {
        if self.status == Status::NoVault {
            return "No vault open".to_string();
        }

        let marker = if self.modified { "*" } else { "" };
        format!(
            "{}{} — {}",
            self.display_name(),
            marker,
            self.status.label()
        )
    }

    // -----------------------------------------------------------------------
    // Transitions. Each mirrors a handler in the shipping app; see the README.
    // -----------------------------------------------------------------------

    /// `src/screens/entries.rs::Msg::LockVault` — wipes the secrets and drops
    /// all the way back to the first question, *not* to the partial state.
    pub fn lock(&mut self) {
        self.status = Status::Locked;
    }

    /// `src/app.rs` Smart Lock activation: the answers stay in RAM, encrypted.
    pub fn smart_lock(&mut self) {
        self.status = Status::SmartLocked;
    }

    /// `src/app.rs::GlobalMsg::BackToWelcome` — the full close.
    pub fn close(&mut self) {
        self.status = Status::NoVault;
        self.source = None;
        self.modified = false;
    }

    /// A brand-new vault: born **unlocked** — the user just typed the
    /// questions and answers — with nowhere to live yet, so it is unsaved from
    /// the first moment. The real flow is Welcome's "Create New Vault" →
    /// the questions editor → Save (`src/screens/questions.rs`), and its first
    /// Save silently becomes a Save As because there is no storage
    /// (`src/session.rs:328-329`).
    pub fn create(&mut self) {
        self.status = Status::Unlocked;
        self.source = None;
        self.modified = true;
    }

    /// What an open lands on: bytes loaded, nothing decrypted.
    pub fn opened(&mut self, source: Source) {
        self.status = Status::Locked;
        self.source = Some(source);
        self.modified = false;
    }

    /// Save / Save As both end here; `Save As` also adopts the new source, the
    /// way `src/session.rs::save_vault_as` does.
    pub fn saved(&mut self, source: Source) {
        self.source = Some(source);
        self.modified = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(status: Status) -> Vault {
        Vault {
            status,
            source: Some(Source::File("~/vaults/MyVault.askrypt".to_string())),
            modified: false,
        }
    }

    /// The whole point of the rail's action block: which buttons a state shows.
    #[test]
    fn button_visibility_per_state() {
        // (status, new/open, unlock, smart_lock, lock, save)
        let table = [
            (Status::NoVault, true, false, false, false, false),
            (Status::Locked, true, true, false, false, false),
            (Status::PartiallyUnlocked, true, true, false, false, false),
            (Status::Unlocked, true, false, true, true, true),
            (Status::SmartLocked, true, true, false, true, false),
        ];

        for (status, open, unlock, smart_lock, lock, save) in table {
            let vault = vault(status);
            assert_eq!(vault.can_create(), open, "new in {status:?}");
            assert_eq!(vault.can_open(), open, "open in {status:?}");
            assert_eq!(vault.can_unlock(), unlock, "unlock in {status:?}");
            assert_eq!(
                vault.can_smart_lock(),
                smart_lock,
                "smart lock in {status:?}"
            );
            assert_eq!(vault.can_lock(), lock, "lock in {status:?}");
            assert_eq!(vault.can_save(), save, "save in {status:?}");
            assert_eq!(vault.can_save_as(), save, "save as in {status:?}");
        }
    }

    /// Smart Lock is the only state where the lock button means "go deeper".
    #[test]
    fn lock_label_distinguishes_the_two_depths() {
        assert_eq!(vault(Status::Unlocked).lock_label(), "Lock");
        assert_eq!(vault(Status::SmartLocked).lock_label(), "Full Lock");
    }

    /// Locking keeps the source, so the locked screens can still name the
    /// vault — mirroring `zeroize_secrets` keeping `location`/`question0`.
    #[test]
    fn lock_keeps_the_source_but_close_drops_it() {
        let mut vault = vault(Status::Unlocked);
        vault.lock();
        assert_eq!(vault.status, Status::Locked);
        assert!(vault.source.is_some());

        vault.close();
        assert_eq!(vault.status, Status::NoVault);
        assert!(vault.source.is_none());
    }

    /// A new vault is unlocked and unsaved from the first moment, and has no
    /// location — so its first Save has to become a Save As.
    #[test]
    fn a_new_vault_is_unlocked_and_unsaved() {
        let mut vault = vault(Status::NoVault);
        vault.create();
        assert_eq!(vault.status, Status::Unlocked);
        assert!(vault.source.is_none());
        assert!(vault.modified);
        assert_eq!(vault.display_name(), "Untitled vault");
        assert!(vault.display_location().is_none());
        assert!(vault.status_line().contains('*'));
    }

    /// An open never unlocks: it loads bytes and stops.
    #[test]
    fn opening_lands_locked() {
        let mut vault = vault(Status::NoVault);
        vault.opened(Source::Server {
            base_url: "https://example.com".to_string(),
            name: "Work".to_string(),
        });
        assert_eq!(vault.status, Status::Locked);
        assert_eq!(vault.display_name(), "Work");
    }
}
