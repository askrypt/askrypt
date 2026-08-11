//! The vault lifecycle, as a *view* over [`Session`].
//!
//! The five states are not stored anywhere: they are read off the session's
//! `file` / `questions_data` / `unlocked` / `smart_lock_data` fields, which are
//! what the transitions in `session.rs` actually mutate. Keeping the derivation
//! in one function means the rail's buttons and the pane router can never
//! disagree about which state the app is in.
//!
//! The button-visibility predicates live here too, so the sidebar only ever
//! *asks* — it never matches on the status itself.

use crate::session::Session;

/// The five states the app can be in. Ordered from least to most open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Nothing loaded.
    NoVault,
    /// Bytes loaded; not one answer accepted yet.
    Locked,
    /// The first answer decrypted the *question list* but not the entries —
    /// the layered unlock, a property of the vault format rather than a UI step.
    PartiallyUnlocked,
    /// Entries decrypted and in memory.
    Unlocked,
    /// Answers held re-encrypted in RAM: one answer re-opens the vault.
    SmartLocked,
}

impl Status {
    /// Derive the state from the session.
    ///
    /// A vault being composed in the questions editor has no `file` yet but does
    /// have `questions_data` and is unlocked; it lands in `Unlocked` with no
    /// location, which is exactly what makes its first Save become a Save As.
    pub fn of(session: &Session) -> Status {
        if session.unlocked {
            Status::Unlocked
        } else if session.smart_lock_data.is_some() {
            Status::SmartLocked
        } else if session.file.is_none() {
            Status::NoVault
        } else if session.questions_data.is_some() {
            Status::PartiallyUnlocked
        } else {
            Status::Locked
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::NoVault => "No vault",
            Status::Locked => "Locked",
            Status::PartiallyUnlocked => "Partially unlocked",
            Status::Unlocked => "Unlocked",
            Status::SmartLocked => "Smart Locked",
        }
    }

    // -----------------------------------------------------------------------
    // Button visibility. The rail asks these; it never matches on the status
    // itself, so the rules stay in one place. Buttons are *hidden* rather than
    // disabled when a state disallows them.
    // -----------------------------------------------------------------------

    /// Always, like [`Self::can_open`]: starting over is offered in every
    /// state, unlike the shipping app where both live on the Welcome screen
    /// only.
    pub fn can_create(self) -> bool {
        true
    }

    /// Always: opening another vault is offered in every state.
    pub fn can_open(self) -> bool {
        true
    }

    /// Closing needs something to close: every state but [`Status::NoVault`],
    /// including a vault that has never been written anywhere (the questions
    /// editor's output) — the unsaved-changes gate is what protects that one.
    pub fn can_close(self) -> bool {
        self.is_open()
    }

    pub fn can_unlock(self) -> bool {
        matches!(
            self,
            Status::Locked | Status::PartiallyUnlocked | Status::SmartLocked
        )
    }

    pub fn can_smart_lock(self) -> bool {
        self == Status::Unlocked
    }

    /// Covers both depths: `Lock` from unlocked, `Full Lock` out of Smart Lock.
    pub fn can_lock(self) -> bool {
        matches!(self, Status::Unlocked | Status::SmartLocked)
    }

    pub fn lock_label(self) -> &'static str {
        if self == Status::SmartLocked {
            "Full Lock"
        } else {
            "Lock"
        }
    }

    /// Saving needs the decrypted entries, so unlocked only.
    pub fn can_save(self) -> bool {
        self == Status::Unlocked
    }

    pub fn can_save_as(self) -> bool {
        self.can_save()
    }

    /// Editing the questions re-derives every key, so it needs every answer.
    pub fn can_edit_questions(self) -> bool {
        self == Status::Unlocked
    }

    pub fn is_unlocked(self) -> bool {
        self == Status::Unlocked
    }

    pub fn is_open(self) -> bool {
        self != Status::NoVault
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the rail's action block: which buttons a state shows.
    #[test]
    fn button_visibility_per_state() {
        // (status, new/open, close, unlock, smart_lock, lock, save)
        let table = [
            (Status::NoVault, true, false, false, false, false, false),
            (Status::Locked, true, true, true, false, false, false),
            (
                Status::PartiallyUnlocked,
                true,
                true,
                true,
                false,
                false,
                false,
            ),
            (Status::Unlocked, true, true, false, true, true, true),
            (Status::SmartLocked, true, true, true, false, true, false),
        ];

        for (status, open, close, unlock, smart_lock, lock, save) in table {
            assert_eq!(status.can_create(), open, "new in {status:?}");
            assert_eq!(status.can_open(), open, "open in {status:?}");
            assert_eq!(status.can_close(), close, "close in {status:?}");
            assert_eq!(status.can_unlock(), unlock, "unlock in {status:?}");
            assert_eq!(
                status.can_smart_lock(),
                smart_lock,
                "smart lock in {status:?}"
            );
            assert_eq!(status.can_lock(), lock, "lock in {status:?}");
            assert_eq!(status.can_save(), save, "save in {status:?}");
            assert_eq!(status.can_save_as(), save, "save as in {status:?}");
        }
    }

    /// Smart Lock is the only state where the lock button means "go deeper".
    #[test]
    fn lock_label_distinguishes_the_two_depths() {
        assert_eq!(Status::Unlocked.lock_label(), "Lock");
        assert_eq!(Status::SmartLocked.lock_label(), "Full Lock");
    }
}
