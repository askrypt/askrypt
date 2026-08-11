//! The three-pane Askrypt desktop UI.
//!
//! The shell owns the [`Session`] — the loaded vault, the decrypted entries, the
//! settings, the tray — and one [`Pane`] telling the working area what to draw.
//! Panes borrow `&mut Session`, mutate the shared state, and hand back a
//! [`panes::Action`] describing where to go next; the shell applies it.
//!
//! Every key derivation and every vault read or write runs on a worker thread
//! through `Task::perform` + `tokio::task::spawn_blocking`, behind the spinner,
//! with `Session::busy` guarding re-entry.
//!
//! Run it with `cargo run -p askrypt-gui`.

#![windows_subsystem = "windows"]

mod data;
mod icon;
mod link;
mod panes;
mod session;
mod settings;
mod theme;
mod tray;
mod vault;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use askrypt::{SecretEntry, VaultStorage};
use iced::event::{self, Event};
use iced::keyboard::key;
use iced::widget::{column, container, operation, row, rule, text_input};
use iced::{
    Element, Length, Point, Size, Subscription, Task, Theme, alignment::Vertical, keyboard,
};
use iced::{time, window};

use crate::panes::Action;
use crate::panes::wizard::Purpose;
use crate::session::{Session, SmartLockData, VaultError, VaultHandle};
use crate::settings::{AppSettings, VaultLocation, WindowState};
use crate::tray::TrayEvent;
use crate::vault::Status;

pub const SEARCH_INPUT_ID: &str = "GUI_SEARCH";

/// How long a copied secret stays on the clipboard when
/// `AppSettings::clear_clipboard` is on.
const CLIPBOARD_LIFETIME: Duration = Duration::from_secs(30);

pub fn main() -> iced::Result {
    // The window is built before `boot` runs, so its remembered geometry is
    // read here; `Session::new` loads the same small file again for everything
    // else. A geometry that no longer makes sense — a monitor unplugged since —
    // is dropped in favour of the default, centered window.
    let window = AppSettings::load()
        .window
        .filter(WindowState::is_usable)
        .unwrap_or_default();

    iced::application(App::boot, App::update, App::view)
        .title(App::title)
        .subscription(App::subscription)
        .window(window::Settings {
            size: window.logical_size(),
            // Deliberately *not* `.centered()`: that would override the saved
            // position. `window_position` centers on its own when there is none.
            position: window.window_position(),
            maximized: window.maximized,
            icon: load_icon(),
            // Closing the window hides to the tray instead; see `handle_event`.
            exit_on_close_request: false,
            ..Default::default()
        })
        .theme(App::theme)
        .font(include_bytes!("../../static/bootstrap-icons.ttf"))
        .run()
}

fn load_icon() -> Option<window::Icon> {
    let bytes = include_bytes!("../../static/logo-128.png");
    let image = image::load_from_memory(bytes).ok()?.to_rgba8();
    let (width, height) = (image.width(), image.height());
    window::icon::from_rgba(image.into_raw(), width, height).ok()
}

/// The left rail's active selection: which slice of the vault the middle pane
/// shows. `Type`/`Tag` are derived from the entries themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    All,
    Hidden,
    Type(String),
    Tag(String),
}

/// What fills the working area right of the rail. `Items` is the list + detail
/// split; everything else is a single full-width pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Items,
    Settings,
    Unlock,
    Wizard,
    Questions,
    PassGen,
}

/// The vault-lifecycle buttons on the rail. Each one only routes — the state
/// changes live in `session.rs`.
#[derive(Debug, Clone, Copy)]
pub enum VaultMsg {
    New,
    Open,
    Close,
    Unlock,
    Lock,
    SmartLock,
    Save,
    SaveAs,
    EditQuestions,
    PassGen,
}

/// Something the user asked for that may have to wait for a save first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    NewVault,
    OpenVault,
    CloseVault,
    Lock,
    SmartLock,
    Exit,
}

#[derive(Debug, Clone)]
pub enum Message {
    SearchChanged(String),
    SearchCleared,
    SectionSelected(Section),
    PaneSelected(Pane),
    EntrySelected(usize),
    ToggleReveal,
    ToggleCvvReveal,
    Copy {
        what: &'static str,
        value: String,
    },
    /// Fired ~30 s after a copy when the clipboard setting is on.
    ClearClipboard,
    OpenUrl(String),
    AddEntry,
    EditEntry(usize),
    DuplicateEntry(usize),
    /// First press: arm the inline confirmation. Second press on the same row
    /// deletes.
    DeleteEntry(usize),
    /// The password generator finished with "use this": write it into the open
    /// editor's draft.
    UseGeneratedPassword(String),
    /// The wizard picked a destination. The shell owns the save, because it also
    /// owns what happens once one lands.
    SaveTo(VaultLocation),
    /// Leave the current pane for whatever the vault's state calls for.
    ReturnToDefaultPane,
    Vault(VaultMsg),
    Unlock(panes::unlock::Msg),
    Wizard(panes::wizard::Msg),
    /// Signing in to a server through the browser. Not a pane message: the
    /// wizard and Settings both start one, and it outlives either.
    Link(link::Msg),
    Settings(panes::settings::Msg),
    Editor(panes::entry_editor::Msg),
    Questions(panes::questions::Msg),
    PassGen(panes::passgen::Msg),
    Global(GlobalMsg),
}

/// Cross-cutting events: the window, the tray, the timers, and the completions
/// of the background tasks the shell itself starts.
#[derive(Debug, Clone)]
pub enum GlobalMsg {
    Event(Event),
    SpinnerTick,
    InactivityTick,
    CheckTrayEvents,
    TrayOpen,
    TrayQuit,
    /// The user asked to quit outright (the rail's Quit, the tray's Quit).
    /// Confirms first, then falls through to [`GlobalMsg::ExitApp`].
    QuitRequested,
    ExitApp,
    SmartLockCreated(Result<SmartLockData, String>),
    Saved(Result<VaultHandle, VaultError>),
    /// The window moved or resized; ask whether it is maximized, since only
    /// then is the geometry the one worth remembering.
    ProbeWindow,
    /// That answer.
    WindowMaximized(bool),
}

pub struct App {
    session: Session,
    query: String,
    section: Section,
    pane: Pane,
    /// Index into `session.entries` — *not* into the filtered view, so filtering
    /// can never invalidate it.
    selected: Option<usize>,
    /// Whether the selected entry's password — or, on a card, its number and
    /// PIN — is revealed. Reset on every selection change, so a reveal never
    /// leaks across entries.
    revealed: bool,
    /// The card's CVV, revealed on its own. Separate from [`Self::revealed`]
    /// because it is the one card field you routinely need to read while the
    /// number stays covered; reset alongside it.
    cvv_revealed: bool,
    /// The row whose Delete button is armed, so deleting takes two presses.
    pending_delete: Option<usize>,
    /// When set, the editor replaces the detail pane and the list stays visible.
    editor: Option<panes::entry_editor::State>,
    /// What to do once the save the user just agreed to has landed.
    after_save: Option<PendingAction>,
    /// The geometry the window last reported, before it is known whether it was
    /// maximized at the time. Committed to `settings.window` by
    /// [`App::commit_geometry`].
    window_size: [f32; 2],
    window_position: Option<[f32; 2]>,
    /// A move or resize is waiting for its `is_maximized` answer.
    probe_window: bool,
    unlock: panes::unlock::State,
    wizard: panes::wizard::State,
    questions: panes::questions::State,
    passgen: panes::passgen::State,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let session = Session::new();
        // Start from what was restored, so a run that never moves the window
        // saves back exactly what it opened with.
        let window = session.settings.window.unwrap_or_default();

        let mut app = App {
            session,
            query: String::new(),
            section: Section::All,
            pane: Pane::Wizard,
            selected: None,
            revealed: false,
            cvv_revealed: false,
            pending_delete: None,
            editor: None,
            after_save: None,
            window_size: window.size,
            window_position: window.position,
            probe_window: false,
            unlock: panes::unlock::State::default(),
            wizard: panes::wizard::State::default(),
            questions: panes::questions::State::default(),
            passgen: panes::passgen::State::default(),
        };

        // Reopen the vault named on the command line, else the last one used —
        // but only if it is actually reachable. A server vault needs a live
        // sign-in: `storage_for` fails without one, and `exists()` is false when
        // the server is unreachable, so either way we fall through to the
        // wizard.
        let location = match std::env::args().nth(1).map(PathBuf::from) {
            Some(path) => Some(VaultLocation::LocalFile(path)),
            None => app
                .session
                .settings
                .last_opened_file
                .clone()
                .filter(|location| {
                    app.session
                        .storage_for(location)
                        .is_ok_and(|storage| storage.exists())
                }),
        };

        if let Some(location) = location {
            match app
                .session
                .storage_for(&location)
                .and_then(|storage| storage.load_vault().map(|file| (storage, file)))
            {
                Ok((storage, file)) => app.session.open_vault(location, storage, file),
                Err(e) => {
                    eprintln!("ERROR: Failed to open the last vault: {}", e);
                    app.session.error_message = Some("Failed to open vault".into());
                }
            }
        }

        app.pane = app.default_pane();
        if app.pane == Pane::Wizard {
            app.wizard.begin(Purpose::Open, &app.session);
        } else {
            app.unlock.reset_for(&app.session);
        }
        let task = operation::focus(app.focus_for(app.pane));

        (app, task)
    }

    fn title(&self) -> String {
        self.session.title()
    }

    fn subscription(&self) -> Subscription<Message> {
        let events = event::listen().map(|e| Message::Global(GlobalMsg::Event(e)));
        let tray = time::every(Duration::from_millis(200))
            .map(|_| Message::Global(GlobalMsg::CheckTrayEvents));

        let mut subs = vec![events, tray];

        // Watch for idleness only while there is something to lock.
        if self.session.unlocked || self.session.smart_lock_data.is_some() {
            subs.push(
                time::every(Duration::from_secs(30))
                    .map(|_| Message::Global(GlobalMsg::InactivityTick)),
            );
        }

        if self.session.busy {
            subs.push(
                time::every(Duration::from_millis(80))
                    .map(|_| Message::Global(GlobalMsg::SpinnerTick)),
            );
        }

        // Only alive between a move or resize and its answer, which also turns
        // a window drag into one probe per quarter second instead of one per
        // frame.
        if self.probe_window {
            subs.push(
                time::every(Duration::from_millis(250))
                    .map(|_| Message::Global(GlobalMsg::ProbeWindow)),
            );
        }

        Subscription::batch(subs)
    }

    /// Driven by the Settings pane's theme picker. Every pane style is
    /// palette-derived, so both palettes work without further changes.
    fn theme(&self) -> Theme {
        self.session.settings.theme.theme()
    }

    fn status(&self) -> Status {
        Status::of(&self.session)
    }

    // -----------------------------------------------------------------------
    // The item list
    // -----------------------------------------------------------------------

    /// The rows the middle pane shows: section filter, then search filter,
    /// newest-modified first. Pairs carry the absolute index so callers can
    /// address `session.entries` directly.
    fn visible(&self) -> Vec<(usize, &SecretEntry)> {
        let show_hidden = self.session.settings.show_hidden_by_default;

        let mut rows: Vec<(usize, &SecretEntry)> = self
            .session
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| match &self.section {
                Section::All => show_hidden || !entry.hidden,
                Section::Hidden => entry.hidden,
                Section::Type(t) => &entry.entry_type == t && (show_hidden || !entry.hidden),
                Section::Tag(t) => entry.tags.contains(t) && (show_hidden || !entry.hidden),
            })
            .filter(|(_, entry)| {
                self.query.is_empty() || data::entry_matches_filter(entry, &self.query)
            })
            .collect();

        rows.sort_by_key(|(_, entry)| std::cmp::Reverse(entry.modified));
        rows
    }

    /// Keep the selection inside the visible list: if a filter change hid the
    /// selected entry, fall back to the first remaining row. The detail pane
    /// therefore never shows an item the list cannot show.
    fn reconcile_selection(&mut self) {
        let visible: Vec<usize> = self.visible().into_iter().map(|(index, _)| index).collect();

        if self.selected.is_some_and(|index| visible.contains(&index)) {
            return;
        }

        self.selected = visible.first().copied();
        self.revealed = false;
        self.cvv_revealed = false;
    }

    /// Distinct entry types, derived from *all* entries (hidden included) so
    /// the Hidden section's types stay reachable from the rail.
    fn types(&self) -> Vec<String> {
        self.session
            .entries
            .iter()
            .map(|entry| entry.entry_type.clone())
            .filter(|t| !t.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Union of all tags, likewise across hidden entries too.
    fn tags(&self) -> Vec<String> {
        self.session
            .entries
            .iter()
            .flat_map(|entry| entry.tags.iter().cloned())
            .filter(|t| !t.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn selected_entry(&self) -> Option<&SecretEntry> {
        self.selected
            .and_then(|index| self.session.entries.get(index))
    }

    /// Whether the password generator has a draft to hand its result to.
    fn has_open_editor(&self) -> bool {
        self.editor.is_some()
    }

    // -----------------------------------------------------------------------
    // Pane routing
    // -----------------------------------------------------------------------

    /// Where the working area lands when nothing else is being done.
    fn default_pane(&self) -> Pane {
        match self.status() {
            Status::Unlocked => Pane::Items,
            Status::NoVault => Pane::Wizard,
            _ => Pane::Unlock,
        }
    }

    /// The pane actually rendered. `Items` over a locked vault would show
    /// decrypted rows that should not exist, so a stale rail selection is
    /// corrected here rather than trusted.
    fn effective_pane(&self) -> Pane {
        let status = self.status();
        match self.pane {
            Pane::Items if !status.is_unlocked() => self.default_pane(),
            Pane::Unlock if !status.can_unlock() => self.default_pane(),
            pane => pane,
        }
    }

    fn focus_for(&self, pane: Pane) -> &'static str {
        match pane {
            Pane::Items => SEARCH_INPUT_ID,
            Pane::Unlock => panes::unlock::focus_target(),
            _ => "",
        }
    }

    /// Switch the working area, giving up anything the old pane was waiting on.
    ///
    /// Returns a task because leaving the sign-in panes cancels a browser
    /// sign-in still in flight: closing the pane says the user does not want it,
    /// and a link left approvable is one somebody could still be talked into
    /// approving.
    fn set_pane(&mut self, pane: Pane) -> Task<Message> {
        let leaving_sign_in =
            matches!(self.pane, Pane::Wizard | Pane::Settings) && pane != self.pane;
        let abandoned = if leaving_sign_in {
            link::abandon(&mut self.session)
        } else {
            Task::none()
        };

        self.pane = pane;
        self.pending_delete = None;
        if pane == Pane::Items {
            self.reconcile_selection();
        }
        abandoned
    }

    /// Leave whatever pane is open and go back to the state's natural one.
    ///
    /// Backing out here also abandons anything queued behind a save the user
    /// started but never completed.
    fn return_to_default(&mut self) -> Action {
        self.after_save = None;
        let pane = self.default_pane();
        match pane {
            Pane::Wizard => {
                self.wizard.begin(Purpose::Open, &self.session);
                Action::Pane(pane)
            }
            Pane::Unlock => {
                self.unlock.reset_for(&self.session);
                Action::pane_run(pane, operation::focus(panes::unlock::focus_target()))
            }
            _ => Action::Pane(pane),
        }
    }

    /// Wipe the pane state that holds secrets. Called on every lock path.
    fn clear_secret_panes(&mut self) {
        self.editor = None;
        self.questions.reset();
        self.passgen.forget();
        self.unlock.reset_for(&self.session);
        self.query.clear();
        self.selected = None;
        self.revealed = false;
        self.cvv_revealed = false;
        self.pending_delete = None;
    }

    // -----------------------------------------------------------------------
    // Update
    // -----------------------------------------------------------------------

    fn update(&mut self, message: Message) -> Task<Message> {
        // Clear the previous line first so a stale status never outlives the
        // action that produced it, and stamp activity — this is what drives the
        // whole idle-lock system, so it has to happen for every message the user
        // actually caused.
        let passive = matches!(
            &message,
            Message::Global(
                GlobalMsg::Event(_)
                    | GlobalMsg::InactivityTick
                    | GlobalMsg::CheckTrayEvents
                    | GlobalMsg::SpinnerTick
                    | GlobalMsg::ProbeWindow
                    | GlobalMsg::WindowMaximized(_)
            ) | Message::ClearClipboard
        );
        if !passive {
            self.session.clear_messages();
            self.session.update_user_activity();
        }

        let action = match message {
            Message::SearchChanged(query) => {
                self.query = query;
                self.reconcile_selection();
                Action::None
            }
            Message::SearchCleared => {
                self.query.clear();
                self.reconcile_selection();
                Action::None
            }
            Message::SectionSelected(section) => {
                self.section = section;
                // Picking a section leaves whatever pane was open, so this may
                // also be the moment a browser sign-in is abandoned.
                Action::Run(self.set_pane(Pane::Items))
            }
            Message::PaneSelected(pane) => {
                if pane == Pane::Wizard {
                    self.wizard.begin(Purpose::Open, &self.session);
                }
                Action::Pane(pane)
            }
            Message::EntrySelected(index) => {
                // The editor occupies the detail pane, so switching rows under
                // it would silently throw the draft away. Make the user finish
                // or cancel instead.
                if self.editor.is_some() {
                    self.session.status_message =
                        Some("Finish or cancel the open item first".into());
                    return Task::none();
                }
                self.selected = Some(index);
                self.revealed = false;
                self.cvv_revealed = false;
                self.pending_delete = None;
                Action::None
            }
            Message::ToggleReveal => {
                self.revealed = !self.revealed;
                Action::None
            }
            Message::ToggleCvvReveal => {
                self.cvv_revealed = !self.cvv_revealed;
                Action::None
            }
            Message::Copy { what, value } => {
                self.session.status_message = Some(format!("Copied {} to clipboard", what));
                let clear = self.session.settings.clear_clipboard;
                Action::Run(Task::batch([
                    iced::clipboard::write(value),
                    if clear {
                        Task::perform(
                            async { tokio::time::sleep(CLIPBOARD_LIFETIME).await },
                            |()| Message::ClearClipboard,
                        )
                    } else {
                        Task::none()
                    },
                ]))
            }
            Message::ClearClipboard => Action::Run(iced::clipboard::write(String::new())),
            Message::OpenUrl(url) => {
                if let Err(e) = open::that(&url) {
                    eprintln!("ERROR: Failed to open {}: {}", url, e);
                    self.session.error_message = Some("Failed to open website".into());
                }
                Action::None
            }
            Message::AddEntry => {
                self.editor = Some(panes::entry_editor::State::new());
                Action::pane_run(Pane::Items, operation::focus_next())
            }
            Message::EditEntry(index) => match self.session.entries.get(index) {
                Some(entry) => {
                    self.editor = Some(panes::entry_editor::State::edit(entry.clone(), index));
                    self.selected = Some(index);
                    Action::pane_run(Pane::Items, operation::focus_next())
                }
                None => Action::None,
            },
            Message::DuplicateEntry(index) => match self.session.entries.get(index) {
                Some(entry) => {
                    self.editor = Some(panes::entry_editor::State::duplicate(entry.clone()));
                    Action::pane_run(Pane::Items, operation::focus_next())
                }
                None => Action::None,
            },
            Message::DeleteEntry(index) => self.delete_entry(index),
            Message::UseGeneratedPassword(password) => match self.editor.as_mut() {
                Some(editor) => {
                    editor.set_secret(password);
                    self.session.status_message =
                        Some("Password copied and applied to the item".into());
                    Action::Pane(Pane::Items)
                }
                None => {
                    self.session.status_message = Some("Password copied to clipboard".into());
                    Action::Pane(self.default_pane())
                }
            },
            Message::SaveTo(location) => match self.session.storage_for(&location) {
                Ok(storage) => self.start_save(location, storage),
                Err(e) => {
                    let error = VaultError::log("Failed to reach the destination", &e);
                    self.after_save = None;
                    self.session.report_vault_error("save", &error);
                    Action::None
                }
            },
            Message::ReturnToDefaultPane => self.return_to_default(),
            Message::Vault(msg) => self.update_vault(msg),
            Message::Unlock(msg) => panes::unlock::update(&mut self.unlock, &mut self.session, msg),
            Message::Wizard(msg) => panes::wizard::update(&mut self.wizard, &mut self.session, msg),
            Message::Link(msg) => link::update(&mut self.session, msg),
            Message::Settings(msg) => panes::settings::update(&mut self.session, msg),
            Message::Editor(msg) => match self.editor.as_mut() {
                Some(editor) => {
                    let (action, close) =
                        panes::entry_editor::update(editor, &mut self.session, msg);
                    if close {
                        self.editor = None;
                        // A saved item is the newest one, so it sorts to the top
                        // of the list; re-derive rather than keeping a selection
                        // that may now point at a different row.
                        self.selected = None;
                        self.reconcile_selection();
                    }
                    action
                }
                None => Action::None,
            },
            Message::Questions(msg) => {
                panes::questions::update(&mut self.questions, &mut self.session, msg)
            }
            Message::PassGen(msg) => {
                panes::passgen::update(&mut self.passgen, &mut self.session, msg)
            }
            Message::Global(msg) => self.update_global(msg),
        };

        self.apply(action)
    }

    /// Apply a pane [`Action`]: switch the working pane if asked, and hand the
    /// task to the Iced runtime.
    fn apply(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::None => Task::none(),
            Action::Run(task) => task,
            Action::Pane(pane) => self.set_pane(pane),
            Action::PaneRun(pane, task) => Task::batch([self.set_pane(pane), task]),
        }
    }

    fn delete_entry(&mut self, index: usize) -> Action {
        if index >= self.session.entries.len() {
            return Action::None;
        }

        // The shipping app deletes with no confirmation at all; here the first
        // press arms the button and the second one commits.
        if self.pending_delete != Some(index) {
            self.pending_delete = Some(index);
            self.session.status_message =
                Some("Press delete again to remove this item".to_string());
            return Action::None;
        }

        let removed = self.session.entries.remove(index);
        self.pending_delete = None;
        self.editor = None;
        self.session.is_modified = true;
        // Indices shift; the selection has to be re-derived, not adjusted.
        self.selected = None;
        self.reconcile_selection();
        self.session.success_message = Some(format!("Deleted '{}'", removed.name));
        Action::None
    }

    // -----------------------------------------------------------------------
    // The rail's vault buttons
    // -----------------------------------------------------------------------

    fn update_vault(&mut self, message: VaultMsg) -> Action {
        match message {
            VaultMsg::New => self.guard(PendingAction::NewVault),
            VaultMsg::Open => self.guard(PendingAction::OpenVault),
            VaultMsg::Close => self.guard(PendingAction::CloseVault),
            VaultMsg::Lock => self.guard(PendingAction::Lock),
            VaultMsg::SmartLock => self.guard(PendingAction::SmartLock),
            VaultMsg::Unlock => {
                self.unlock.reset_for(&self.session);
                Action::pane_run(
                    Pane::Unlock,
                    operation::focus(panes::unlock::focus_target()),
                )
            }
            VaultMsg::Save => self.save_now(),
            VaultMsg::SaveAs => self.start_wizard(Purpose::SaveAs),
            VaultMsg::EditQuestions => {
                self.questions.begin_edit(&self.session);
                Action::pane_run(Pane::Questions, operation::focus_next())
            }
            VaultMsg::PassGen => {
                self.passgen.regenerate(&mut self.session);
                Action::Pane(Pane::PassGen)
            }
        }
    }

    fn start_wizard(&mut self, purpose: Purpose) -> Action {
        self.wizard.begin(purpose, &self.session);
        Action::Pane(Pane::Wizard)
    }

    /// Save to the vault's existing home, or fall back to Save As when it has
    /// never been persisted.
    fn save_now(&mut self) -> Action {
        match self.session.save_target() {
            Some((location, storage)) => self.start_save(location, storage),
            None => {
                self.session.status_message =
                    Some("This vault has no home yet — choose where to save it".into());
                self.start_wizard(Purpose::SaveAs)
            }
        }
    }

    /// Re-encrypt and write the vault on a worker thread. Two 600k-iteration key
    /// derivations plus (for a server vault) a round trip, so never inline.
    fn start_save(&mut self, location: VaultLocation, storage: Arc<dyn VaultStorage>) -> Action {
        if self.session.busy {
            return Action::None;
        }
        let Some(request) = self.session.save_request() else {
            self.session.error_message = Some("No vault loaded".into());
            return Action::None;
        };

        self.session.begin_work("Saving…");
        Action::Run(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    session::write_vault(request, location, storage)
                })
                .await
                .expect("save task panicked")
            },
            |result| Message::Global(GlobalMsg::Saved(result)),
        ))
    }

    /// Ask before quitting outright. Quitting is one click away in the rail and
    /// in the tray, and it wipes the decrypted vault from memory, so an
    /// unmodified vault still deserves the question.
    fn confirm_quit(&self) -> bool {
        matches!(
            rfd::MessageDialog::new()
                .set_title("Quit Askrypt")
                .set_description("Are you sure you want to quit?")
                .set_buttons(rfd::MessageButtons::YesNo)
                .show(),
            rfd::MessageDialogResult::Yes
        )
    }

    /// Ask about unsaved changes before something that would discard them.
    /// Cancel aborts; Yes saves first and replays the action once the save lands.
    fn guard(&mut self, action: PendingAction) -> Action {
        if !self.session.is_modified {
            return self.perform(action);
        }

        let answer = rfd::MessageDialog::new()
            .set_title("Unsaved Changes")
            .set_description("You have unsaved changes. Would you like to save them?")
            .set_buttons(rfd::MessageButtons::YesNoCancel)
            .show();

        match answer {
            rfd::MessageDialogResult::Yes => {
                self.after_save = Some(action);
                self.save_now()
            }
            rfd::MessageDialogResult::Cancel => Action::None,
            // No, or the dialog was dismissed: go ahead and lose the changes.
            _ => self.perform(action),
        }
    }

    fn perform(&mut self, action: PendingAction) -> Action {
        match action {
            PendingAction::NewVault => {
                self.session.close_vault();
                self.clear_secret_panes();
                self.questions.begin_new();
                Action::pane_run(Pane::Questions, operation::focus_next())
            }
            PendingAction::OpenVault => self.start_wizard(Purpose::Open),
            PendingAction::CloseVault => {
                // The deepest of the three lock depths: the bytes go too, so
                // coming back means re-opening the file.
                self.session.close_vault();
                self.clear_secret_panes();
                self.session.status_message =
                    Some("Vault closed — secrets wiped from memory".into());
                self.start_wizard(Purpose::Open)
            }
            PendingAction::Lock => {
                let label = self.status().lock_label();
                self.session.lock();
                self.clear_secret_panes();
                self.session.status_message =
                    Some(format!("{label}ed — secrets wiped from memory"));
                Action::pane_run(
                    Pane::Unlock,
                    operation::focus(panes::unlock::focus_target()),
                )
            }
            PendingAction::SmartLock => self.start_smart_lock(),
            PendingAction::Exit => {
                // Fold in any move or resize the last probe did not cover, so
                // quitting right after dragging the window still remembers it.
                self.commit_geometry(self.was_maximized());

                if let Err(e) = self.session.settings.save() {
                    eprintln!("WARNING: Failed to save settings: {}", e);
                }
                Action::Run(iced::exit())
            }
        }
    }

    /// The idle timeout fired. Smart Lock wipes the decrypted entries, so
    /// unsaved edits would go with them — and nobody is at the keyboard to be
    /// asked about it.
    ///
    /// So: save first when the vault has somewhere to be saved, and refuse to
    /// lock at all when it does not. A vault that has never been written
    /// anywhere exists only in this process; locking it would destroy the only
    /// copy of the questions the user just typed.
    fn auto_smart_lock(&mut self) -> Action {
        if !self.session.is_modified {
            return self.start_smart_lock();
        }

        match self.session.save_target() {
            Some((location, storage)) => {
                self.after_save = Some(PendingAction::SmartLock);
                self.start_save(location, storage)
            }
            None => {
                self.session.status_message = Some(
                    "This vault has never been saved, so it was left unlocked — save it first"
                        .into(),
                );
                Action::None
            }
        }
    }

    /// Encrypt every answer under a randomly chosen one (2M-iteration PBKDF2) on
    /// a worker thread, showing the "Locking…" spinner while it runs.
    fn start_smart_lock(&mut self) -> Action {
        if self.session.busy {
            return Action::None;
        }
        if self.session.answers.is_empty() {
            self.session.error_message = Some("Need at least 2 questions for Smart Lock".into());
            return Action::None;
        }

        let answers = self.session.answers.clone();
        let answer0 = self.session.answer0.clone();
        let questions = self
            .session
            .questions_data
            .as_ref()
            .map(|q| q.questions.clone())
            .unwrap_or_default();
        let translit = self
            .session
            .file
            .as_ref()
            .is_some_and(|f| f.params.translit);

        self.session.begin_work("Locking…");
        Action::Run(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    Session::create_smart_lock_data(&answers, &answer0, &questions, translit)
                        .map_err(|e| e.to_string())
                })
                .await
                .expect("create_smart_lock_data task panicked")
            },
            |result| Message::Global(GlobalMsg::SmartLockCreated(result)),
        ))
    }

    // -----------------------------------------------------------------------
    // Cross-cutting events
    // -----------------------------------------------------------------------

    fn update_global(&mut self, message: GlobalMsg) -> Action {
        match message {
            GlobalMsg::SpinnerTick => {
                self.session.spinner_frame = self.session.spinner_frame.wrapping_add(1);
                Action::None
            }
            GlobalMsg::InactivityTick => {
                if self.session.should_auto_smart_lock() {
                    self.auto_smart_lock()
                } else if self.session.smart_lock_timed_out() {
                    self.session.lock();
                    self.clear_secret_panes();
                    self.session.status_message =
                        Some("Smart Lock expired — the vault is fully locked".into());
                    Action::Pane(Pane::Unlock)
                } else {
                    Action::None
                }
            }
            GlobalMsg::CheckTrayEvents => {
                if let Some(tray) = &self.session.tray
                    && let Ok(event) = tray.receiver.try_recv()
                {
                    return match event {
                        TrayEvent::Open => self.update_global(GlobalMsg::TrayOpen),
                        TrayEvent::Quit => self.update_global(GlobalMsg::TrayQuit),
                    };
                }
                Action::None
            }
            GlobalMsg::TrayOpen => {
                Action::Run(window::oldest().and_then(|id| window::minimize(id, false)))
            }
            GlobalMsg::TrayQuit => self.update_global(GlobalMsg::QuitRequested),
            GlobalMsg::QuitRequested => {
                // A modified vault gets the unsaved-changes dialog, which is a
                // confirmation of its own; asking twice would be noise.
                if self.session.is_modified || self.confirm_quit() {
                    self.update_global(GlobalMsg::ExitApp)
                } else {
                    Action::None
                }
            }
            GlobalMsg::ExitApp => self.guard(PendingAction::Exit),
            GlobalMsg::SmartLockCreated(result) => {
                self.session.finish_work();
                match result {
                    Ok(data) => {
                        self.session.apply_smart_lock(data);
                        self.clear_secret_panes();
                        self.session.status_message = Some("Vault is now Smart Locked".into());
                        Action::pane_run(
                            Pane::Unlock,
                            operation::focus(panes::unlock::focus_target()),
                        )
                    }
                    Err(e) => {
                        eprintln!("ERROR: Failed to create smart lock: {}", e);
                        self.session.error_message = Some("Failed to create Smart Lock".into());
                        Action::Pane(Pane::Items)
                    }
                }
            }
            GlobalMsg::Saved(result) => {
                self.session.finish_work();
                match result {
                    Ok(saved) => {
                        self.session.apply_saved(saved);
                        if let Err(e) = self.session.settings.save() {
                            eprintln!("WARNING: Failed to save settings: {}", e);
                        }
                        match self.after_save.take() {
                            Some(action) => self.perform(action),
                            None => Action::Pane(Pane::Items),
                        }
                    }
                    Err(error) => {
                        // The user agreed to save before doing something else;
                        // the save failed, so that something else must not happen.
                        self.after_save = None;
                        self.session.report_vault_error("save", &error);
                        Action::None
                    }
                }
            }
            GlobalMsg::ProbeWindow => {
                self.probe_window = false;
                Action::Run(
                    window::oldest()
                        .and_then(window::is_maximized)
                        .map(|maximized| Message::Global(GlobalMsg::WindowMaximized(maximized))),
                )
            }
            GlobalMsg::WindowMaximized(maximized) => {
                self.commit_geometry(maximized);
                Action::None
            }
            GlobalMsg::Event(event) => self.handle_event(event),
        }
    }

    /// Take in whatever the window just said about its geometry.
    ///
    /// Nonsense is dropped rather than remembered — see
    /// [`WindowState::sane_size`]. Nothing is probed when nothing was recorded,
    /// which is what keeps a minimize to the tray (all-nonsense values on
    /// Windows) from overwriting the geometry the window will come back to.
    fn record_geometry(&mut self, position: Option<Point>, size: Option<Size>) -> Action {
        let mut seen = false;

        if let Some(size) = size
            && WindowState::sane_size([size.width, size.height])
        {
            self.window_size = [size.width, size.height];
            seen = true;
        }
        if let Some(position) = position
            && WindowState::sane_position([position.x, position.y])
        {
            self.window_position = Some([position.x, position.y]);
            seen = true;
        }

        self.probe_window |= seen;
        Action::None
    }

    /// Whether the window is maximized, as far as the last probe knows — which
    /// at startup is what it was when the app last exited.
    fn was_maximized(&self) -> bool {
        matches!(self.session.settings.window, Some(saved) if saved.maximized)
    }

    /// Fold the geometry seen since the last probe into the settings, to be
    /// written out by the next `settings.save()`.
    ///
    /// A maximized window keeps the size and position it will *unmaximize*
    /// back to, so only the flag moves in that case. Exit cannot wait for one
    /// more `is_maximized` round trip, so it passes [`App::was_maximized`] —
    /// betting that a resize in the last quarter second did not also change
    /// whether the window was maximized.
    fn commit_geometry(&mut self, maximized: bool) {
        let window = self.session.settings.window.get_or_insert_default();
        window.maximized = maximized;
        if !maximized {
            window.size = self.window_size;
            window.position = self.window_position;
        }
    }

    fn handle_event(&mut self, event: Event) -> Action {
        match event {
            Event::Window(window::Event::Opened { position, size }) => {
                let action = self.record_geometry(position, Some(size));

                // `window::Settings::maximized` is a creation-time hint, and
                // some window managers drop it when an explicit position is
                // given alongside it. Ask again now that the window exists,
                // where it is an ordinary request the WM honours.
                if self.was_maximized() {
                    return Action::Run(window::oldest().and_then(|id| window::maximize(id, true)));
                }
                action
            }
            Event::Window(window::Event::Moved(position)) => {
                self.record_geometry(Some(position), None)
            }
            Event::Window(window::Event::Resized(size)) => self.record_geometry(None, Some(size)),
            Event::Window(window::Event::CloseRequested) => {
                if self.session.settings.minimize_to_tray && self.session.tray.is_some() {
                    Action::Run(window::oldest().and_then(|id| window::minimize(id, true)))
                } else {
                    self.session.clear_messages();
                    self.update_global(GlobalMsg::ExitApp)
                }
            }
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(key::Named::Tab),
                modifiers,
                ..
            }) if modifiers.shift() => Action::Run(operation::focus_previous()),
            Event::Keyboard(keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(key::Named::Tab),
                ..
            }) => Action::Run(operation::focus_next()),
            Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                let on_items = self.effective_pane() == Pane::Items;

                if modifiers.control() && key.as_ref() == keyboard::Key::Character("s") {
                    if self.status().can_save() {
                        self.session.clear_messages();
                        return self.save_now();
                    }
                    Action::None
                } else if !modifiers.control()
                    && !modifiers.shift()
                    && key.as_ref() == keyboard::Key::Character("/")
                    && on_items
                    && self.editor.is_none()
                {
                    Action::Run(operation::focus(SEARCH_INPUT_ID))
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    // -----------------------------------------------------------------------
    // View
    // -----------------------------------------------------------------------

    fn view(&self) -> Element<'_, Message> {
        // The working area right of the rail: the item sections split it into a
        // list + a detail pane, every other pane fills it on its own.
        let working: Element<'_, Message> = match self.effective_pane() {
            Pane::Items => row![
                panes::list::view(self),
                rule::vertical(1).style(theme::pane_divider),
                match &self.editor {
                    Some(editor) => panes::entry_editor::view(editor, &self.session),
                    None => panes::detail::view(self),
                },
            ]
            .height(Length::Fill)
            .into(),
            Pane::Settings => panes::settings::view(self),
            Pane::Unlock => panes::unlock::view(self),
            Pane::Wizard => panes::wizard::view(self),
            Pane::Questions => panes::questions::view(self),
            Pane::PassGen => panes::passgen::view(self),
        };

        // Only the panes row is `Fill`, so the search strip keeps its
        // intrinsic height and the status bar stays glued to the bottom edge
        // at every window size. Deliberately *not* wrapped in a centering
        // container — panes are full-bleed.
        let mut root = column![].width(Length::Fill).height(Length::Fill);

        // Searching a vault that is not open would be searching nothing.
        if self.effective_pane() == Pane::Items {
            root = root.push(self.search_bar());
        }

        let status = self.session.status_line();

        root.push(
            row![
                panes::sidebar::view(self),
                rule::vertical(1).style(theme::pane_divider),
                working,
            ]
            .height(Length::Fill),
        )
        .push(panes::statusbar::view(self, &status))
        .into()
    }

    fn search_bar(&self) -> Element<'_, Message> {
        let input = text_input("Search vault", &self.query)
            .id(SEARCH_INPUT_ID)
            .on_input(Message::SearchChanged)
            .icon(text_input::Icon {
                font: icon::BOOTSTRAP_ICONS,
                code_point: icon::SEARCH,
                size: Some(14.0.into()),
                spacing: 8.0,
                side: text_input::Side::Left,
            })
            .padding(8)
            .size(14)
            .width(Length::Fill);

        let clear = theme::text_button_icon(icon::x_lg(12), "Clear search")
            .on_press(Message::SearchCleared);

        container(row![input, clear].spacing(6).align_y(Vertical::Center))
            .padding(8)
            .width(Length::Fill)
            .into()
    }
}
