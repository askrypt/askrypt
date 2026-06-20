//! The top-level [`Message`] type.
//!
//! Each screen owns its own message enum (e.g. [`crate::screens::entries::Msg`]);
//! this type wraps them so the Iced runtime sees a single message type. Truly
//! cross-cutting events (window/keyboard, tray, spinner, save, vault lifecycle)
//! live in [`GlobalMsg`] and are handled by the app shell rather than a screen.

use crate::screens::{entries, entry_editor, passgen, questions, smart_lock, unlock, welcome};
use crate::session::SmartLockData;
use iced::event::Event;

#[derive(Debug, Clone)]
pub enum Message {
    Welcome(welcome::Msg),
    Questions(questions::Msg),
    FirstQuestion(unlock::FirstMsg),
    OtherQuestions(unlock::OtherMsg),
    Entries(entries::Msg),
    EntryEditor(entry_editor::Msg),
    PassGen(passgen::Msg),
    SmartLock(smart_lock::Msg),
    Global(GlobalMsg),
}

/// Cross-cutting events not owned by any single screen.
#[derive(Debug, Clone)]
pub enum GlobalMsg {
    Event(Event),
    SpinnerTick,
    InactivityTick,
    CheckTrayEvents,
    TrayOpen,
    TrayQuit,
    ExitApp,
    BackToWelcome,
    SaveVault,
    SaveVaultAs,
    ActivateSmartLock,
    SmartLockCreated(Result<SmartLockData, String>),
    CancelSmartLock,
}
