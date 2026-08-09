//! The new three-pane Askrypt desktop UI.
//!
//! Designed here before it is ported into `src/`: fake data, no crypto, no
//! vault I/O, nothing persisted. The vault lifecycle is *modelled* (see
//! `vault.rs`) so the controls that depend on it can be laid out, but every
//! action only flips in-memory state. `README.md` records the real logic in
//! `src/` and the invariants a port has to keep.
//!
//! Run it with `cargo run -p askrypt-gui`.

#![windows_subsystem = "windows"]

mod data;
mod icon;
mod panes;
mod theme;
mod vault;

use std::collections::BTreeSet;

use iced::widget::{column, container, operation, row, rule, text_input};
use iced::{Element, Length, Size, Task, Theme, alignment::Vertical, window};

use crate::data::Entry;
use crate::panes::wizard::{self, Purpose};

const SEARCH_INPUT_ID: &str = "GUI_SEARCH";

pub fn main() -> iced::Result {
    iced::application(App::boot, App::update, App::view)
        .title("Askrypt")
        .window(window::Settings {
            size: Size::new(1100.0, 700.0),
            ..Default::default()
        })
        .centered()
        .theme(App::theme)
        .font(include_bytes!("../../static/bootstrap-icons.ttf"))
        .run()
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
}

/// The vault-lifecycle buttons on the rail. Each one only routes — the state
/// changes live in `vault.rs` and the panes.
#[derive(Debug, Clone, Copy)]
pub enum VaultMsg {
    New,
    Open,
    Unlock,
    Lock,
    SmartLock,
    Save,
    SaveAs,
}

#[derive(Debug, Clone)]
pub enum Message {
    SearchChanged(String),
    SearchCleared,
    SectionSelected(Section),
    PaneSelected(Pane),
    EntrySelected(usize),
    ToggleReveal,
    Copy {
        what: &'static str,
        value: String,
    },
    OpenUrl(String),
    Vault(VaultMsg),
    Unlock(panes::unlock::Msg),
    Wizard(wizard::Msg),
    Settings(panes::settings::Msg),
    /// A control that has no meaning in the prototype: writes one status line.
    Note(&'static str),
}

pub struct App {
    entries: Vec<Entry>,
    query: String,
    section: Section,
    pane: Pane,
    vault: vault::Vault,
    /// Index into `entries` — *not* into the filtered view, so filtering can
    /// never invalidate it.
    selected: Option<usize>,
    /// Whether the selected entry's password is revealed. Reset on every
    /// selection change, so a reveal never leaks across entries.
    revealed: bool,
    settings: panes::settings::State,
    unlock: panes::unlock::State,
    wizard: wizard::State,
    status: Option<String>,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let mut app = App {
            entries: data::sample_entries(),
            query: String::new(),
            section: Section::All,
            pane: Pane::Items,
            vault: vault::Vault::default(),
            selected: None,
            revealed: false,
            settings: panes::settings::State::default(),
            unlock: panes::unlock::State::default(),
            wizard: wizard::State::default(),
            status: None,
        };
        app.reconcile_selection();

        (app, operation::focus(SEARCH_INPUT_ID))
    }

    /// The rows the middle pane shows: section filter, then search filter,
    /// newest-modified first. Pairs carry the absolute index so callers can
    /// address `entries` directly.
    fn visible(&self) -> Vec<(usize, &Entry)> {
        let mut rows: Vec<(usize, &Entry)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| match &self.section {
                Section::All => !entry.hidden,
                Section::Hidden => entry.hidden,
                Section::Type(t) => &entry.entry_type == t && !entry.hidden,
                Section::Tag(t) => entry.tags.contains(t) && !entry.hidden,
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
    }

    /// Distinct entry types, derived from *all* entries (hidden included) so
    /// the Hidden section's types stay reachable from the rail.
    fn types(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.entry_type.clone())
            .filter(|t| !t.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Union of all tags, likewise across hidden entries too.
    fn tags(&self) -> Vec<String> {
        self.entries
            .iter()
            .flat_map(|entry| entry.tags.iter().cloned())
            .filter(|t| !t.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn selected_entry(&self) -> Option<&Entry> {
        self.selected.and_then(|index| self.entries.get(index))
    }

    /// Driven by the Settings screen's theme picker. Every pane style is
    /// palette-derived, so both palettes work without further changes.
    fn theme(&self) -> Theme {
        self.settings.theme.theme()
    }

    /// Where the working area lands when nothing else is being done: the item
    /// list once the vault is unlocked, the unlock screen while it is locked,
    /// and the Open wizard when there is no vault at all.
    fn default_pane(&self) -> Pane {
        match self.vault.status {
            vault::Status::Unlocked => Pane::Items,
            vault::Status::NoVault => Pane::Wizard,
            _ => Pane::Unlock,
        }
    }

    /// The pane actually rendered. `Items` over a locked vault would show
    /// decrypted rows that should not exist, so a stale rail selection is
    /// corrected here rather than trusted.
    fn effective_pane(&self) -> Pane {
        match self.pane {
            Pane::Items if !self.vault.is_unlocked() => self.default_pane(),
            pane => pane,
        }
    }

    /// Leave whatever pane is open and go back to the state's natural one.
    fn return_to_default(&mut self) {
        self.pane = self.default_pane();
        if self.pane == Pane::Wizard {
            self.wizard.begin(Purpose::Open, &self.vault);
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        // Clear the previous line first so a stale status never outlives the
        // action that produced it — same as `src/app.rs::update`.
        self.status = None;

        match message {
            Message::SearchChanged(query) => {
                self.query = query;
                self.reconcile_selection();
            }
            Message::SearchCleared => {
                self.query.clear();
                self.reconcile_selection();
            }
            Message::SectionSelected(section) => {
                self.section = section;
                self.pane = Pane::Items;
                self.reconcile_selection();
            }
            Message::PaneSelected(pane) => {
                self.pane = pane;
            }
            Message::EntrySelected(index) => {
                self.selected = Some(index);
                self.revealed = false;
            }
            Message::ToggleReveal => {
                self.revealed = !self.revealed;
            }
            Message::Copy { what, value } => {
                self.status = Some(format!("Copied {} to clipboard", what));
                return iced::clipboard::write(value);
            }
            Message::OpenUrl(url) => {
                self.status = Some(format!("Would open {} — not implemented", url));
            }
            Message::Vault(msg) => return self.update_vault(msg),
            Message::Unlock(msg) => {
                if let Some(outcome) = panes::unlock::update(&mut self.unlock, &mut self.vault, msg)
                {
                    return self.apply_unlock(outcome);
                }
            }
            Message::Wizard(msg) => {
                if let Some(outcome) = wizard::update(&mut self.wizard, msg) {
                    return self.apply_wizard(outcome);
                }
            }
            Message::Settings(msg) => {
                panes::settings::update(&mut self.settings, msg);
            }
            Message::Note(note) => {
                self.status = Some(note.to_string());
            }
        }

        Task::none()
    }

    /// The rail's vault buttons. Opening and saving both hand off to the same
    /// wizard; locking is immediate.
    fn update_vault(&mut self, message: VaultMsg) -> Task<Message> {
        match message {
            VaultMsg::New => {
                // A new vault has no entries, which is also the only way to see
                // the list pane's empty state. Opening one puts the samples
                // back.
                self.entries.clear();
                self.vault.create();
                self.section = Section::All;
                self.reconcile_selection();
                self.pane = Pane::Items;
                self.status = Some(
                    "New vault — the questions editor would run first, and Save becomes Save As"
                        .to_string(),
                );
                Task::none()
            }
            VaultMsg::Open => self.start_wizard(Purpose::Open),
            VaultMsg::Save => self.start_wizard(Purpose::Save),
            VaultMsg::SaveAs => self.start_wizard(Purpose::SaveAs),
            VaultMsg::Unlock => {
                self.unlock.reset();
                self.pane = Pane::Unlock;
                operation::focus(panes::unlock::focus_target())
            }
            VaultMsg::Lock => {
                // The real handler asks about unsaved changes first
                // (`src/screens/entries.rs::Msg::LockVault`) and a Cancel there
                // aborts the lock; the prototype has nothing to lose.
                let label = self.vault.lock_label();
                self.vault.lock();
                self.unlock.reset();
                self.pane = Pane::Unlock;
                self.status = Some(format!("{label} — the secrets would be wiped from memory"));
                operation::focus(panes::unlock::focus_target())
            }
            VaultMsg::SmartLock => {
                self.vault.smart_lock();
                self.unlock.reset();
                self.pane = Pane::Unlock;
                self.status = Some("Smart Lock armed — one answer re-opens the vault".to_string());
                operation::focus(panes::unlock::focus_target())
            }
        }
    }

    fn start_wizard(&mut self, purpose: Purpose) -> Task<Message> {
        self.wizard.begin(purpose, &self.vault);
        self.pane = Pane::Wizard;
        Task::none()
    }

    fn apply_unlock(&mut self, outcome: panes::unlock::Outcome) -> Task<Message> {
        match outcome {
            panes::unlock::Outcome::Advanced => {
                self.status = Some(
                    "First answer accepted — the remaining questions are readable".to_string(),
                );
                operation::focus(panes::unlock::focus_target())
            }
            panes::unlock::Outcome::Unlocked => {
                self.pane = Pane::Items;
                self.section = Section::All;
                self.reconcile_selection();
                self.status = Some(format!("Unlocked {}", self.vault.display_name()));
                operation::focus(SEARCH_INPUT_ID)
            }
            panes::unlock::Outcome::Closed => {
                self.return_to_default();
                self.status = Some("Vault closed".to_string());
                Task::none()
            }
        }
    }

    fn apply_wizard(&mut self, outcome: wizard::Outcome) -> Task<Message> {
        match outcome {
            wizard::Outcome::Cancelled => {
                self.return_to_default();
                Task::none()
            }
            wizard::Outcome::Chosen(source) => {
                let where_to = source.display_location();

                match self.wizard.purpose() {
                    Purpose::Open => {
                        // An open never unlocks: it only loads bytes and reads
                        // the plaintext first question. The sample entries come
                        // back with the file — they are what unlocking reveals.
                        self.entries = data::sample_entries();
                        self.vault.opened(source);
                        self.unlock.reset();
                        self.pane = Pane::Unlock;
                        self.status = Some(format!("Opened {where_to}"));
                        operation::focus(panes::unlock::focus_target())
                    }
                    Purpose::Save | Purpose::SaveAs => {
                        self.vault.saved(source);
                        self.pane = Pane::Items;
                        self.status = Some(format!("Saved to {where_to}"));
                        Task::none()
                    }
                }
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        // The working area right of the rail: the item sections split it into a
        // list + a detail pane, every other pane fills it on its own.
        let working: Element<'_, Message> = match self.effective_pane() {
            Pane::Items => row![
                panes::list::view(self),
                rule::vertical(1).style(theme::pane_divider),
                panes::detail::view(self),
            ]
            .height(Length::Fill)
            .into(),
            Pane::Settings => panes::settings::view(self),
            Pane::Unlock => panes::unlock::view(self),
            Pane::Wizard => wizard::view(self),
        };

        // Only the panes row is `Fill`, so the search strip keeps its
        // intrinsic height and the status bar stays glued to the bottom edge
        // at every window size. Deliberately *not* wrapped in a centering
        // container the way `src/app.rs::view` does — panes are full-bleed.
        let mut root = column![].width(Length::Fill).height(Length::Fill);

        // Searching a vault that is not open would be searching nothing.
        if self.vault.is_unlocked() {
            root = root.push(self.search_bar());
        }

        // With nothing to report, the bar falls back to the vault's own state,
        // which is the only place the prototype shows it.
        let status = self
            .status
            .clone()
            .unwrap_or_else(|| self.vault.status_line());

        root.push(
            row![
                panes::sidebar::view(self),
                rule::vertical(1).style(theme::pane_divider),
                working,
            ]
            .height(Length::Fill),
        )
        .push(panes::statusbar::view(Some(&status)))
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
