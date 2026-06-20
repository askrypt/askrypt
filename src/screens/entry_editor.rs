//! Create / edit a single vault entry.

use crate::message::Message;
use crate::screens::{Action, Screen, entries, passgen, show_messages_in_column};
use crate::session::Session;
use crate::ui::{padded_button, security_input_with_toggle, title_h1};
use askrypt::SecretEntry;
use chrono::Utc;
use iced::widget::{checkbox, operation, row, text, text_input};
use iced::{Element, alignment};

/// UI state for the entry editor. The draft entry's secret is wiped on drop via
/// `SecretEntry`'s own `ZeroizeOnDrop`.
#[derive(Clone)]
pub struct State {
    /// Index of the entry being edited (`None` for a new entry).
    pub edited_entry_index: Option<usize>,
    pub editing_entry: SecretEntry,
    pub editing_tags: String,
    pub show_secret_in_edit: bool,
}

impl State {
    /// A blank draft for a brand-new entry.
    pub fn new() -> Self {
        let now = Utc::now().timestamp();
        Self {
            edited_entry_index: None,
            editing_entry: SecretEntry {
                name: String::new(),
                user_name: String::new(),
                secret: String::new(),
                url: String::new(),
                notes: String::new(),
                entry_type: "password".to_string(),
                tags: Vec::new(),
                created: now,
                modified: now,
                hidden: false,
            },
            editing_tags: String::new(),
            show_secret_in_edit: false,
        }
    }

    /// A draft for editing an existing entry at `index`.
    pub fn edit(entry: SecretEntry, index: usize) -> Self {
        let editing_tags = entry.tags.join(", ");
        Self {
            edited_entry_index: Some(index),
            editing_entry: entry,
            editing_tags,
            show_secret_in_edit: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    NameEdited(String),
    UserNameEdited(String),
    SecretEdited(String),
    UrlEdited(String),
    NotesEdited(String),
    TagsEdited(String),
    HiddenToggled(bool),
    ToggleSecret,
    FocusNext,
    Save,
    Back,
    OpenPasswordGenerator,
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::NameEdited(value) => {
            state.editing_entry.name = value;
            Action::None
        }
        Msg::UserNameEdited(value) => {
            state.editing_entry.user_name = value;
            Action::None
        }
        Msg::SecretEdited(value) => {
            state.editing_entry.secret = value;
            Action::None
        }
        Msg::UrlEdited(value) => {
            state.editing_entry.url = value;
            Action::None
        }
        Msg::NotesEdited(value) => {
            state.editing_entry.notes = value;
            Action::None
        }
        Msg::TagsEdited(value) => {
            state.editing_tags = value;
            Action::None
        }
        Msg::HiddenToggled(value) => {
            state.editing_entry.hidden = value;
            Action::None
        }
        Msg::ToggleSecret => {
            state.show_secret_in_edit = !state.show_secret_in_edit;
            Action::None
        }
        Msg::FocusNext => Action::Run(operation::focus_next()),
        Msg::Save => {
            if state.editing_entry.name.trim().is_empty() {
                session.error_message = Some("Item name cannot be empty".into());
                return Action::None;
            }

            state.editing_entry.tags = state
                .editing_tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let now = Utc::now().timestamp();
            let mut new_entry = state.editing_entry.clone();
            new_entry.modified = now;

            if let Some(idx) = state.edited_entry_index {
                if idx < session.entries.len() {
                    session.entries[idx] = new_entry;
                }
            } else {
                session.entries.push(new_entry);
            }

            session.is_modified = true;
            Action::switch(Screen::Entries(entries::State::default()))
        }
        Msg::Back => Action::switch(Screen::Entries(entries::State::default())),
        Msg::OpenPasswordGenerator => {
            let generator = passgen::State::new(Some(state.clone()), session);
            Action::switch(Screen::PassGen(generator))
        }
    }
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let title = if state.edited_entry_index.is_some() {
        "Edit Item"
    } else {
        "Create New Item"
    };

    let entry = &state.editing_entry;

    let mut column = title_h1(title)
        .push(text("Name:").size(14))
        .push(
            text_input("Entry name (e.g., Gmail, Amazon)", &entry.name)
                .on_input(|v| Message::EntryEditor(Msg::NameEdited(v)))
                .on_submit(Message::EntryEditor(Msg::FocusNext))
                .padding(10)
                .width(400)
                .size(12),
        )
        .push(text("Username:").size(14))
        .push(
            text_input("Username or email", &entry.user_name)
                .on_input(|v| Message::EntryEditor(Msg::UserNameEdited(v)))
                .on_submit(Message::EntryEditor(Msg::FocusNext))
                .padding(10)
                .width(400)
                .size(12),
        )
        .push(text("Password:").size(14))
        .push(
            security_input_with_toggle(
                &entry.secret,
                state.show_secret_in_edit,
                Some(|v| Message::EntryEditor(Msg::SecretEdited(v))),
                Some(Message::EntryEditor(Msg::FocusNext)),
                Message::EntryEditor(Msg::ToggleSecret),
                "Password or secret value",
                "Hide Password",
                "Show Password",
                Some(Message::EntryEditor(Msg::OpenPasswordGenerator)),
            )
            .width(400),
        )
        .push(text("Website:").size(14))
        .push(
            text_input("Website (optional)", &entry.url)
                .on_input(|v| Message::EntryEditor(Msg::UrlEdited(v)))
                .on_submit(Message::EntryEditor(Msg::FocusNext))
                .padding(10)
                .width(400)
                .size(12),
        )
        .push(text("Notes:").size(14))
        .push(
            text_input("Additional notes (optional)", &entry.notes)
                .on_input(|v| Message::EntryEditor(Msg::NotesEdited(v)))
                .on_submit(Message::EntryEditor(Msg::FocusNext))
                .padding(10)
                .width(400)
                .size(12),
        )
        // TODO: show entry type as a dropdown selection
        .push(text("Tags (comma separated):").size(14))
        .push(
            text_input("Tags (comma separated)", &state.editing_tags)
                .on_input(|v| Message::EntryEditor(Msg::TagsEdited(v)))
                .on_submit(Message::EntryEditor(Msg::Save))
                .padding(10)
                .width(400)
                .size(12),
        )
        .push(
            checkbox(entry.hidden)
                .label("Hidden")
                .on_toggle(|v| Message::EntryEditor(Msg::HiddenToggled(v)))
                .size(16),
        )
        .align_x(alignment::Horizontal::Center);

    let button_row = row![
        padded_button("Save").on_press(Message::EntryEditor(Msg::Save)),
        padded_button("Cancel").on_press(Message::EntryEditor(Msg::Back)),
    ]
    .spacing(10);

    column = column.push(button_row);
    column = show_messages_in_column(session, column);

    column.into()
}
