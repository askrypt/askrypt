//! The entry editor: a draft item, edited in place of the detail pane.
//!
//! It replaces the right-hand pane rather than the whole working area, so the
//! list stays visible while an item is being written — the one place this UI
//! differs from `src/screens/entry_editor.rs`, which is a full screen.
//!
//! The rules are the shipping app's: the name is required, tags are a
//! comma-separated string split on save, `modified` is stamped and `created` is
//! preserved. Nothing here touches storage; saving edits `session.entries` and
//! marks the vault dirty, and the vault is written only by an explicit Save.

use askrypt::SecretEntry;
use iced::widget::{
    button, checkbox, column, container, pick_list, row, scrollable, text, text_editor, text_input,
};
use iced::{Element, Length, alignment::Vertical};

use crate::panes::Action;
use crate::session::Session;
use crate::{Message, Pane, data, icon, theme};

const NAME_INPUT_ID: &str = "GUI_EDITOR_NAME";

/// Notes get a fixed box — the editor sits inside a `scrollable`, so a growing
/// one would fight the outer scroll; it scrolls within itself instead.
const NOTES_HEIGHT: f32 = 120.0;

pub struct State {
    /// `None` for a new item; otherwise the index in `session.entries` this
    /// draft came from.
    index: Option<usize>,
    /// The draft. `SecretEntry` is `ZeroizeOnDrop`, so the typed secret is wiped
    /// when the editor closes.
    ///
    /// `entry.notes` is *not* live while the editor is open — the notes are a
    /// multi-line `text_editor`, which owns its own buffer; `save` folds it
    /// back in.
    entry: SecretEntry,
    /// Notes as the user types them. A `text_editor` rather than a
    /// `text_input`, so a note can be several lines. Its buffer is
    /// cosmic-text's and cannot be zeroized the way `entry.notes` is — a note
    /// typed here outlives the editor in freed memory.
    notes: text_editor::Content,
    /// Tags as the user types them, comma-separated. Split on save.
    tags: String,
    revealed: bool,
    error: Option<String>,
}

impl State {
    pub fn new() -> Self {
        State {
            index: None,
            entry: data::new_entry(),
            notes: text_editor::Content::new(),
            tags: String::new(),
            revealed: false,
            error: None,
        }
    }

    pub fn edit(entry: SecretEntry, index: usize) -> Self {
        State {
            tags: entry.tags.join(", "),
            notes: text_editor::Content::with_text(&entry.notes),
            index: Some(index),
            entry,
            revealed: false,
            error: None,
        }
    }

    /// A copy of an existing item, saved as a *new* one.
    pub fn duplicate(entry: SecretEntry) -> Self {
        let mut copy = Self::edit(entry, 0);
        copy.index = None;
        copy.entry.name = format!("{} (copy)", copy.entry.name);
        copy.revealed = false;
        copy
    }

    /// Called when the password generator hands one back.
    pub fn set_secret(&mut self, secret: String) {
        self.entry.secret = secret;
        self.revealed = true;
    }

    fn is_new(&self) -> bool {
        self.index.is_none()
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    NameEdited(String),
    UserNameEdited(String),
    SecretEdited(String),
    UrlEdited(String),
    NotesAction(text_editor::Action),
    TagsEdited(String),
    TypeSelected(String),
    HiddenToggled(bool),
    ToggleReveal,
    Save,
    Cancel,
}

/// Returns the action plus whether the editor should close.
pub fn update(state: &mut State, session: &mut Session, message: Msg) -> (Action, bool) {
    match message {
        Msg::NameEdited(value) => {
            state.entry.name = value;
            state.error = None;
            (Action::None, false)
        }
        Msg::UserNameEdited(value) => {
            state.entry.user_name = value;
            (Action::None, false)
        }
        Msg::SecretEdited(value) => {
            state.entry.secret = value;
            (Action::None, false)
        }
        Msg::UrlEdited(value) => {
            state.entry.url = value;
            (Action::None, false)
        }
        // Selections, clicks and scrolling are actions too, so the whole enum
        // goes to the content; `save` is what reads the text back out.
        Msg::NotesAction(action) => {
            state.notes.perform(action);
            (Action::None, false)
        }
        Msg::TagsEdited(value) => {
            state.tags = value;
            (Action::None, false)
        }
        Msg::TypeSelected(value) => {
            state.entry.entry_type = value;
            (Action::None, false)
        }
        Msg::HiddenToggled(value) => {
            state.entry.hidden = value;
            (Action::None, false)
        }
        Msg::ToggleReveal => {
            state.revealed = !state.revealed;
            (Action::None, false)
        }
        Msg::Save => save(state, session),
        Msg::Cancel => (Action::Pane(Pane::Items), true),
    }
}

fn save(state: &mut State, session: &mut Session) -> (Action, bool) {
    if state.entry.name.trim().is_empty() {
        state.error = Some("Item name cannot be empty".to_string());
        return (Action::None, false);
    }

    let mut entry = state.entry.clone();
    entry.notes = state.notes.text();
    entry.tags = state
        .tags
        .split(',')
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect();
    entry.modified = chrono::Utc::now().timestamp();

    match state.index {
        // A stale index means the list changed under the draft; append rather
        // than overwrite whatever moved into that slot.
        Some(index) if index < session.entries.len() => session.entries[index] = entry,
        _ => session.entries.push(entry),
    }

    session.is_modified = true;
    session.success_message = Some(if state.is_new() {
        "Item added".to_string()
    } else {
        "Item saved".to_string()
    });

    (Action::Pane(Pane::Items), true)
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let heading = if state.is_new() {
        "NEW ITEM"
    } else {
        "EDIT ITEM"
    };

    let secret_row = row![
        text_input("", &state.entry.secret)
            .id("GUI_EDITOR_SECRET")
            .on_input(|value| Message::Editor(Msg::SecretEdited(value)))
            .secure(!state.revealed)
            .padding(8)
            .size(14)
            .width(Length::Fill),
        theme::text_button_icon(
            if state.revealed {
                icon::eye_slash(14)
            } else {
                icon::eye(14)
            },
            if state.revealed {
                "Hide password"
            } else {
                "Show password"
            },
        )
        .on_press(Message::Editor(Msg::ToggleReveal)),
        theme::text_button_icon(icon::key(14), "Generate a password")
            .on_press(Message::Vault(crate::VaultMsg::PassGen)),
    ]
    .spacing(6)
    .align_y(Vertical::Center);

    let mut body = column![
        text(heading).size(11).style(text::secondary),
        field(
            "Name",
            text_input("Item name", &state.entry.name)
                .id(NAME_INPUT_ID)
                .on_input(|value| Message::Editor(Msg::NameEdited(value)))
                .on_submit(Message::Editor(Msg::Save))
                .padding(8)
                .size(14)
                .into(),
        ),
        field(
            "Type",
            pick_list(
                data::ENTRY_TYPES.map(str::to_string).to_vec(),
                Some(state.entry.entry_type.clone()),
                |choice| Message::Editor(Msg::TypeSelected(choice)),
            )
            .text_size(13)
            .padding([4, 8])
            .into(),
        ),
        field(
            "Username",
            text_input("", &state.entry.user_name)
                .on_input(|value| Message::Editor(Msg::UserNameEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
        field("Password", secret_row.into()),
        field(
            "Website",
            text_input("https://example.com", &state.entry.url)
                .on_input(|value| Message::Editor(Msg::UrlEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
        field(
            "Tags",
            text_input("work, personal", &state.tags)
                .on_input(|value| Message::Editor(Msg::TagsEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
        field(
            "Notes",
            text_editor(&state.notes)
                .placeholder("Anything else worth keeping with this item")
                .on_action(|action| Message::Editor(Msg::NotesAction(action)))
                .height(NOTES_HEIGHT)
                .padding(8)
                .size(14)
                .into(),
        ),
        checkbox(state.entry.hidden)
            .label("Hidden item")
            .size(16)
            .text_size(13)
            .on_toggle(|value| Message::Editor(Msg::HiddenToggled(value))),
    ]
    .spacing(12)
    .padding(20)
    .max_width(560);

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    if !state.is_new() {
        body = body.push(
            text(format!(
                "Created {} · last changed {}",
                data::format_timestamp_local(state.entry.created),
                data::format_timestamp_local(state.entry.modified),
            ))
            .size(11)
            .style(text::secondary),
        );
    }

    body = body.push(
        row![
            button(text("Save item").size(14))
                .padding([8, 16])
                .on_press(Message::Editor(Msg::Save)),
            button(text("Cancel").size(14))
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::Editor(Msg::Cancel)),
        ]
        .spacing(10),
    );

    // The vault is only written by an explicit Save; say so, since the item
    // itself looks saved the moment it appears in the list.
    if session.is_modified {
        body = body.push(
            text("Changes live in memory until the vault itself is saved.")
                .size(11)
                .style(text::secondary),
        );
    }

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn field<'a>(label: &'a str, control: Element<'a, Message>) -> Element<'a, Message> {
    column![text(label).size(12).style(text::secondary), control]
        .spacing(4)
        .into()
}
