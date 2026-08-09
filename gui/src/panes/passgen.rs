//! The password generator, over `askrypt::passgen`.
//!
//! Every control regenerates immediately, the way `src/screens/passgen.rs` does
//! — the length slider clamps in core, so the pane never has to. "Copy and use"
//! hands the password back through [`Message::UseGeneratedPassword`], which the
//! shell writes into the open entry editor's draft; with no editor open it is
//! just a copy.

use askrypt::passgen::{PasswordGenConfig, generate_password};
use iced::widget::{button, checkbox, column, container, row, scrollable, slider, text};
use iced::{Element, Length, alignment::Vertical};
use zeroize::Zeroize;

use crate::panes::Action;
use crate::session::Session;
use crate::{App, Message, theme};

#[derive(Default)]
pub struct State {
    config: PasswordGenConfig,
    generated: String,
}

/// A generated password is a secret until it is used or discarded.
impl Drop for State {
    fn drop(&mut self) {
        self.generated.zeroize();
    }
}

impl State {
    /// Produce a fresh password, reporting a bad character-set combination
    /// through the session's error line.
    pub fn regenerate(&mut self, session: &mut Session) {
        self.generated.zeroize();
        match generate_password(&self.config) {
            Ok(password) => {
                session.error_message = None;
                self.generated = password;
            }
            Err(e) => {
                session.error_message = Some(e);
                self.generated = String::new();
            }
        }
    }

    /// Wipe the generated password. Called on every lock path.
    pub fn forget(&mut self) {
        self.generated.zeroize();
        self.generated.clear();
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    LengthChanged(u16),
    ToggleUppercase(bool),
    ToggleLowercase(bool),
    ToggleNumbers(bool),
    ToggleSymbols(bool),
    Generate,
    Copy,
    CopyAndUse,
    Cancel,
}

pub fn update(state: &mut State, session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::LengthChanged(value) => {
            state.config.set_length(value as usize);
            state.regenerate(session);
            Action::None
        }
        Msg::ToggleUppercase(value) => {
            state.config.use_uppercase = value;
            state.regenerate(session);
            Action::None
        }
        Msg::ToggleLowercase(value) => {
            state.config.use_lowercase = value;
            state.regenerate(session);
            Action::None
        }
        Msg::ToggleNumbers(value) => {
            state.config.use_numbers = value;
            state.regenerate(session);
            Action::None
        }
        Msg::ToggleSymbols(value) => {
            state.config.use_symbols = value;
            state.regenerate(session);
            Action::None
        }
        Msg::Generate => {
            state.regenerate(session);
            Action::None
        }
        Msg::Copy => {
            if state.generated.is_empty() {
                session.error_message = Some("No password to copy".into());
                return Action::None;
            }
            Action::Run(iced::Task::done(Message::Copy {
                what: "password",
                value: state.generated.clone(),
            }))
        }
        Msg::CopyAndUse => {
            if state.generated.is_empty() {
                session.error_message = Some("No password to copy".into());
                return Action::None;
            }
            let password = state.generated.clone();
            state.forget();
            Action::Run(iced::Task::batch([
                iced::clipboard::write(password.clone()),
                iced::Task::done(Message::UseGeneratedPassword(password)),
            ]))
        }
        Msg::Cancel => {
            state.forget();
            Action::Run(iced::Task::done(Message::ReturnToDefaultPane))
        }
    }
}

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.passgen;
    let config = &state.config;

    let shown = if state.generated.is_empty() {
        "—".to_string()
    } else {
        state.generated.clone()
    };

    let length = row![
        text(format!("Length: {}", config.length))
            .size(13)
            .width(Length::Fixed(110.0)),
        slider(
            (PasswordGenConfig::MIN_LENGTH as u16)..=(PasswordGenConfig::MAX_LENGTH as u16),
            config.length as u16,
            |value| Message::PassGen(Msg::LengthChanged(value)),
        ),
    ]
    .spacing(12)
    .align_y(Vertical::Center);

    let sets = column![
        toggle(
            "Uppercase (A-Z)",
            config.use_uppercase,
            Msg::ToggleUppercase
        ),
        toggle(
            "Lowercase (a-z)",
            config.use_lowercase,
            Msg::ToggleLowercase
        ),
        toggle("Numbers (0-9)", config.use_numbers, Msg::ToggleNumbers),
        toggle("Symbols (!@#…)", config.use_symbols, Msg::ToggleSymbols),
    ]
    .spacing(8);

    let body = column![
        text("PASSWORD GENERATOR").size(11).style(text::secondary),
        theme::card(container(text(shown).size(18).font(theme::bold())).padding(14)),
        length,
        sets,
        row![
            button(text("Generate").size(14))
                .padding([8, 16])
                .on_press(Message::PassGen(Msg::Generate)),
            button(text("Copy").size(14))
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::PassGen(Msg::Copy)),
            button(
                text(if app.has_open_editor() {
                    "Copy and use"
                } else {
                    "Copy and close"
                })
                .size(14)
            )
            .padding([8, 16])
            .style(button::secondary)
            .on_press(Message::PassGen(Msg::CopyAndUse)),
            button(text("Close").size(14))
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::PassGen(Msg::Cancel)),
        ]
        .spacing(10),
    ]
    .spacing(14)
    .padding(20)
    .max_width(560);

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn toggle<'a>(label: &'a str, value: bool, to_message: fn(bool) -> Msg) -> Element<'a, Message> {
    checkbox(value)
        .label(label)
        .size(16)
        .text_size(13)
        .on_toggle(move |v| Message::PassGen(to_message(v)))
        .into()
}
