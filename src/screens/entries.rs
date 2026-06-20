//! Entries list: the main screen of an unlocked vault. Search, tags, hidden
//! entries, per-entry copy/reveal, and navigation to the editor, generator,
//! question editor and lock screens.

use crate::icon;
use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, entry_editor, passgen, questions, status_bar, unlock};
use crate::session::Session;
use crate::ui::{
    button_link, caption_block, container_with_border, control_button_icon, controls_block,
    padded_button, text_button_icon,
};
use askrypt::SecretEntry;
use chrono::{DateTime, Local, Utc};
use iced::alignment::Vertical;
use iced::widget::{
    button, checkbox, column, container, operation, row, scrollable, text, text_input,
};
use iced::{Color, Element, Font, Length, clipboard};

pub const FILTER_INPUT_ID: &str = "FILTER_INPUT_ID";

/// UI state for the entries list.
#[derive(Default)]
pub struct State {
    pub entries_filter: String,
    pub show_hidden: bool,
    /// Track which entry's password is currently revealed.
    pub shown_password_index: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum Msg {
    AddNewEntry,
    EditEntry(usize),
    DeleteEntry(usize),
    FilterEdited(String),
    ToggleShowHidden(bool),
    ShowPassword(usize),
    CopyPassword(usize),
    CopyUsername(usize),
    OpenUrl(String),
    ClickTag(String),
    OpenPasswordGenerator,
    EditQuestions,
    LockVault,
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::AddNewEntry => Action::switch_run(
            Screen::EntryEditor(entry_editor::State::new()),
            operation::focus_next(),
        ),
        Msg::EditEntry(index) => {
            if let Some(entry) = session.entries.get(index) {
                Action::switch_run(
                    Screen::EntryEditor(entry_editor::State::edit(entry.clone(), index)),
                    operation::focus_next(),
                )
            } else {
                Action::None
            }
        }
        Msg::DeleteEntry(index) => {
            if index < session.entries.len() {
                session.entries.remove(index);
                session.is_modified = true;
            }
            session.error_message = None;
            state.shown_password_index = None;
            Action::None
        }
        Msg::FilterEdited(value) => {
            state.entries_filter = value;
            Action::None
        }
        Msg::ToggleShowHidden(value) => {
            state.show_hidden = value;
            Action::None
        }
        Msg::ShowPassword(index) => {
            if state.shown_password_index == Some(index) {
                state.shown_password_index = None;
            } else {
                state.shown_password_index = Some(index);
            }
            Action::None
        }
        Msg::CopyPassword(index) => {
            if let Some(entry) = session.entries.get(index) {
                session.success_message = Some(format!("Copied password for '{}'", entry.name));
                Action::Run(clipboard::write(entry.secret.clone()))
            } else {
                Action::None
            }
        }
        Msg::CopyUsername(index) => {
            if let Some(entry) = session.entries.get(index) {
                session.success_message = Some(format!("Copied username for '{}'", entry.name));
                Action::Run(clipboard::write(entry.user_name.clone()))
            } else {
                Action::None
            }
        }
        Msg::OpenUrl(url) => {
            if !url.is_empty()
                && let Err(e) = open::that(&url)
            {
                eprintln!("ERROR: Failed to open URL: {}", e);
                session.error_message = Some("Failed to open website".into());
            }
            Action::None
        }
        Msg::ClickTag(tag) => {
            state.entries_filter = clean_hash_tag(tag);
            Action::None
        }
        Msg::OpenPasswordGenerator => {
            let generator = passgen::State::new(None, session);
            Action::switch(Screen::PassGen(generator))
        }
        Msg::EditQuestions => {
            Action::switch(Screen::Questions(questions::State::from_session(session)))
        }
        Msg::LockVault => {
            if session.ask_user_about_changes() {
                session.zeroize_secrets();
                session.unlocked = false;
                session.questions_data = None;
                session.is_modified = false;
                Action::switch_run(
                    Screen::FirstQuestion(unlock::FirstState::default()),
                    operation::focus_next(),
                )
            } else {
                Action::None
            }
        }
    }
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    // Top section: Fixed control buttons
    let filter_input = container(
        row![
            text_input("Filter items by name, username, ...", &state.entries_filter)
                .on_input(|v| Message::Entries(Msg::FilterEdited(v)))
                .id(FILTER_INPUT_ID)
                .padding(4),
            text_button_icon(icon::x_lg_icon(), "Clear filter")
                .style(button::subtle)
                .padding(6)
                .on_press(Message::Entries(Msg::FilterEdited("".to_string()))),
        ]
        .spacing(3)
        .align_y(Vertical::Center),
    );

    let show_hidden_checkbox = checkbox(state.show_hidden)
        .label("Show hidden")
        .on_toggle(|v| Message::Entries(Msg::ToggleShowHidden(v)))
        .size(16);

    let top_row1 = controls_block(row![
        padded_button("Add New Item").on_press(Message::Entries(Msg::AddNewEntry)),
        padded_button("Password Generator").on_press(Message::Entries(Msg::OpenPasswordGenerator)),
        padded_button("Edit Questions").on_press(Message::Entries(Msg::EditQuestions)),
        padded_button("Save").on_press(Message::Global(GlobalMsg::SaveVault)),
        padded_button("Save As").on_press(Message::Global(GlobalMsg::SaveVaultAs)),
        padded_button("Smart Lock").on_press(Message::Global(GlobalMsg::ActivateSmartLock)),
        padded_button("Lock Vault").on_press(Message::Entries(Msg::LockVault)),
        padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)),
        show_hidden_checkbox,
    ]);
    let top_row2 = controls_block(row![filter_input]);

    // Filter entries based on search text and hidden status
    let mut filtered_entries: Vec<(usize, &SecretEntry)> = session
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            // Filter by hidden status
            if !state.show_hidden && entry.hidden {
                return false;
            }
            // Filter by search text
            if !state.entries_filter.is_empty() {
                return entry_matches_filter(entry, &state.entries_filter);
            }
            true
        })
        .collect();

    // Sort by modified timestamp in descending order (most recent first)
    filtered_entries.sort_by_key(|b| std::cmp::Reverse(b.1.modified));

    // Middle section: Scrollable entries
    let middle_section: Element<'a, Message> = if session.entries.is_empty() {
        caption_block("You have no items. Add a new one...").into()
    } else if filtered_entries.is_empty() {
        caption_block("No items match the filter criteria.").into()
    } else {
        let mut entries_column = column![].spacing(15).padding(15).width(Length::Fill);

        for (index, entry) in filtered_entries {
            let entry_col = column![secret_entry_widget(
                entry,
                state.shown_password_index == Some(index),
                index
            )]
            .spacing(5);

            entries_column = entries_column.push(container(entry_col).width(Length::Fill));
        }

        scrollable(entries_column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    };

    // Bottom section: Fixed status line
    let bottom_section = status_bar(session);

    column![top_row1, top_row2, middle_section, bottom_section]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn secret_entry_widget(
    entry: &SecretEntry,
    show_password: bool,
    index: usize,
) -> Element<'_, Message> {
    const ENTRY_FIXED: f32 = 100.0;
    let name_row = row![
        text("Name:").width(Length::Fixed(ENTRY_FIXED)),
        text(&entry.name).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        }),
        if entry.hidden {
            Some(
                text("hidden")
                    .size(12)
                    .color(Color::from_rgb(0.5, 0.5, 0.5)),
            )
        } else {
            None
        },
    ]
    .width(Length::Fill);
    let user_name_row = row![
        text("Username:").width(Length::Fixed(ENTRY_FIXED)),
        text(&entry.user_name),
        if entry.user_name.is_empty() {
            None
        } else {
            Some(
                text_button_icon(icon::copy_icon(), "Copy username")
                    .on_press(Message::Entries(Msg::CopyUsername(index))),
            )
        },
    ];

    let (show_password_tooltip, secret_text, show_password_icon) = if show_password {
        (
            "Hide Password",
            entry.secret.clone(),
            icon::eye_slash_icon(),
        )
    } else {
        ("Show Password", "••••••••".to_string(), icon::eye_icon())
    };

    let secret_row = row![
        text("Password:").width(Length::Fixed(ENTRY_FIXED)),
        text(secret_text),
        text_button_icon(show_password_icon, show_password_tooltip)
            .on_press(Message::Entries(Msg::ShowPassword(index))),
        text_button_icon(icon::copy_icon(), "Copy password")
            .on_press(Message::Entries(Msg::CopyPassword(index))),
    ];

    let url_row = if !entry.url.is_empty() {
        let elem: Element<Message> = if is_url(&entry.url) {
            button_link(
                entry.url.clone(),
                "Open website",
                Some(icon::box_arrow_up_right_icon()),
            )
            .on_press(Message::Entries(Msg::OpenUrl(entry.url.clone())))
            .into()
        } else {
            text(&entry.url).into()
        };
        Some(row![
            text("Website:").width(Length::Fixed(ENTRY_FIXED)),
            elem,
        ])
    } else {
        // don't show URL row if URL is empty
        None
    };

    let notes_row = if !entry.notes.is_empty() {
        Some(row![
            text("Notes:").width(Length::Fixed(ENTRY_FIXED)),
            text(&entry.notes).width(Length::Fill),
        ])
    } else {
        // don't show notes row if notes are empty
        None
    };

    // TODO: show entry type as a dropdown selection or icon

    let tags_row = if !entry.tags.is_empty() {
        let mut row = row![].spacing(5);
        for tag in &entry.tags {
            row = row.push(
                button_link(make_hash_tag(tag), "Click to filter", None)
                    .on_press(Message::Entries(Msg::ClickTag(tag.clone()))),
            );
        }
        Some(row![text("Tags:").width(Length::Fixed(ENTRY_FIXED)), row])
    } else {
        // don't show tags row if there are no tags
        None
    };

    let created_row = row![
        text("Created:").width(Length::Fixed(ENTRY_FIXED)),
        text(format_timestamp_local(entry.created)).width(Length::Fill),
    ];

    let modified_row = row![
        text("Modified:").width(Length::Fixed(ENTRY_FIXED)),
        text(format_timestamp_local(entry.modified)).width(Length::Fill),
    ];

    let button_row = row![
        control_button_icon(icon::x_lg_icon(), "Delete")
            .style(button::danger)
            .on_press(Message::Entries(Msg::DeleteEntry(index))),
        control_button_icon(icon::pencil_icon(), "Edit")
            .on_press(Message::Entries(Msg::EditEntry(index))),
    ]
    .spacing(10);

    let content = column![
        name_row,
        user_name_row,
        secret_row,
        url_row,
        notes_row,
        tags_row,
        modified_row,
        created_row,
        button_row,
    ]
    .spacing(8);

    container_with_border(content).into()
}

fn entry_matches_filter(entry: &SecretEntry, filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    entry.name.to_lowercase().contains(&filter_lower)
        || entry.user_name.to_lowercase().contains(&filter_lower)
        || entry.url.to_lowercase().contains(&filter_lower)
        || entry.notes.to_lowercase().contains(&filter_lower)
        || entry
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&filter_lower))
}

fn is_url(string: &str) -> bool {
    string.starts_with("http://") || string.starts_with("https://")
}

fn make_hash_tag(tag: &str) -> String {
    if tag.starts_with('#') {
        tag.to_string()
    } else {
        format!("#{}", tag)
    }
}

fn clean_hash_tag(tag: String) -> String {
    if let Some(end) = tag.strip_prefix('#') {
        end.to_string()
    } else {
        tag
    }
}

fn format_timestamp_local(timestamp: i64) -> String {
    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
    let local_datetime = datetime.with_timezone(&Local);
    local_datetime.format("%b. %d, %Y - %T").to_string()
}
