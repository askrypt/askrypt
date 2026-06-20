//! Password generator screen.
//!
//! When opened from the entry editor it carries the editor's state in
//! `return_to` so "Copy and use" can write the generated password back into the
//! draft entry and return to the editor; opened standalone, `return_to` is
//! `None` and it returns to the entries list.

use crate::message::Message;
use crate::screens::entry_editor;
use crate::screens::{Action, Screen, entries, show_messages_in_column};
use crate::session::Session;
use crate::ui::{container_border_r5, padded_button, title_h1};
use askrypt::passgen::{PasswordGenConfig, generate_password};
use iced::widget::{checkbox, container, slider, text};
use iced::{Element, Font, alignment, clipboard};

pub struct State {
    pub config: PasswordGenConfig,
    pub generated: String,
    /// The entry editor to return to (set when launched from the entry editor).
    pub return_to: Option<entry_editor::State>,
}

impl State {
    /// Open the generator, immediately generating an initial password. `return_to`
    /// is the entry editor to resume (or `None` for standalone use).
    pub fn new(return_to: Option<entry_editor::State>, session: &mut Session) -> Self {
        let config = PasswordGenConfig::default();
        let generated = regenerate(&config, session);
        Self {
            config,
            generated,
            return_to,
        }
    }
}

/// Generate a password from `config`, mirroring the old `generate_new_password`:
/// clears the error on success, sets it (and returns empty) on failure.
fn regenerate(config: &PasswordGenConfig, session: &mut Session) -> String {
    match generate_password(config) {
        Ok(password) => {
            session.error_message = None;
            password
        }
        Err(e) => {
            session.error_message = Some(e);
            String::new()
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    LengthChanged(f32),
    ToggleUppercase(bool),
    ToggleLowercase(bool),
    ToggleNumbers(bool),
    ToggleSymbols(bool),
    Generate,
    Copy,
    CopyAndUse,
    Cancel,
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::LengthChanged(value) => {
            state.config.set_length(value as usize);
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::ToggleUppercase(value) => {
            state.config.use_uppercase = value;
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::ToggleLowercase(value) => {
            state.config.use_lowercase = value;
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::ToggleNumbers(value) => {
            state.config.use_numbers = value;
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::ToggleSymbols(value) => {
            state.config.use_symbols = value;
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::Generate => {
            state.generated = regenerate(&state.config, session);
            Action::None
        }
        Msg::Copy => {
            if !state.generated.is_empty() {
                session.success_message = Some("Password copied to clipboard".to_string());
                Action::Run(clipboard::write(state.generated.clone()))
            } else {
                session.error_message = Some("No password to copy".to_string());
                Action::None
            }
        }
        Msg::CopyAndUse => {
            if state.generated.is_empty() {
                session.error_message = Some("No password to copy".to_string());
                Action::None
            } else if let Some(mut editor) = state.return_to.take() {
                editor.editing_entry.secret = state.generated.clone();
                session.success_message =
                    Some("Generated password applied and copied to clipboard".to_string());
                let task = clipboard::write(state.generated.clone());
                Action::switch_run(Screen::EntryEditor(editor), task)
            } else {
                Action::switch(Screen::Entries(entries::State::default()))
            }
        }
        Msg::Cancel => {
            if let Some(editor) = state.return_to.take() {
                Action::switch(Screen::EntryEditor(editor))
            } else {
                Action::switch(Screen::Entries(entries::State::default()))
            }
        }
    }
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let mut column = title_h1("Password Generator").align_x(alignment::Horizontal::Center);

    // Password length slider
    column = column
        .push(text(format!("Password Length: {}", state.config.length)).size(14))
        .push(
            slider(
                PasswordGenConfig::MIN_LENGTH as f32..=PasswordGenConfig::MAX_LENGTH as f32,
                state.config.length as f32,
                |v| Message::PassGen(Msg::LengthChanged(v)),
            )
            .width(400),
        )
        .push(text(" ").size(5)); // Spacing

    // Checkboxes for character types
    column = column
        .push(
            checkbox(state.config.use_uppercase)
                .label("Uppercase (A-Z)")
                .on_toggle(|v| Message::PassGen(Msg::ToggleUppercase(v)))
                .size(16),
        )
        .push(
            checkbox(state.config.use_lowercase)
                .label("Lowercase (a-z)")
                .on_toggle(|v| Message::PassGen(Msg::ToggleLowercase(v)))
                .size(16),
        )
        .push(
            checkbox(state.config.use_numbers)
                .label("Numbers (0-9)")
                .on_toggle(|v| Message::PassGen(Msg::ToggleNumbers(v)))
                .size(16),
        )
        .push(
            checkbox(state.config.use_symbols)
                .label("Symbols (!@#$%...)")
                .on_toggle(|v| Message::PassGen(Msg::ToggleSymbols(v)))
                .size(16),
        )
        .push(text(" ").size(10)); // Spacing

    // Display generated password
    if !state.generated.is_empty() {
        column = column
            .push(text("Generated Password:").size(14))
            .push(
                container(text(&state.generated).size(14).font(Font::MONOSPACE))
                    .padding(10)
                    .width(400)
                    .style(container_border_r5),
            )
            .push(text(" ").size(10)); // Spacing
    }

    // Buttons
    let copy_button = if state.return_to.is_some() {
        padded_button("Copy and use").on_press(Message::PassGen(Msg::CopyAndUse))
    } else {
        padded_button("Copy").on_press(Message::PassGen(Msg::Copy))
    };
    let button_row = iced::widget::row![
        padded_button("Generate").on_press(Message::PassGen(Msg::Generate)),
        copy_button,
        padded_button("Cancel").on_press(Message::PassGen(Msg::Cancel)),
    ]
    .spacing(10);

    column = column.push(button_row);
    column = show_messages_in_column(session, column);

    column.into()
}
