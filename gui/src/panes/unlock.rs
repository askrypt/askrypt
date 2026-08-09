//! The unlock screen: a *single* working pane, like Settings and the wizard.
//!
//! It renders the shipping app's **layered** unlock, which is a property of the
//! vault format rather than a UI choice: the first answer decrypts only the
//! *question list* (`src/screens/unlock.rs:69`), and all the answers together
//! decrypt the entries (`:186`). That is why `Status::Locked` shows one field
//! and `Status::PartiallyUnlocked` shows the rest.
//!
//! Nothing is derived, checked or wiped here — any non-empty answer advances.

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, alignment::Vertical};

use crate::vault::{Status, Vault};
use crate::{App, Message, data, icon, theme};

const ANSWER_INPUT_ID: &str = "GUI_UNLOCK_ANSWER";

pub struct State {
    /// One slot per question, indexed absolutely so the partial step can write
    /// answers 1.. without re-indexing.
    answers: Vec<String>,
    revealed: bool,
    error: Option<&'static str>,
}

impl Default for State {
    fn default() -> Self {
        State {
            answers: vec![String::new(); data::sample_questions().len()],
            revealed: false,
            error: None,
        }
    }
}

impl State {
    /// Called whenever the pane is entered, so a previous attempt never shows
    /// through. The real app zeroizes here; there is nothing secret to wipe.
    pub fn reset(&mut self) {
        *self = State::default();
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    AnswerChanged(usize, String),
    ToggleReveal,
    Submit,
    CloseVault,
}

/// What the pane asks the shell to do next.
pub enum Outcome {
    /// The first answer was accepted; the other questions are now readable.
    Advanced,
    Unlocked,
    /// Full close — back to no vault at all.
    Closed,
}

pub fn update(state: &mut State, vault: &mut Vault, message: Msg) -> Option<Outcome> {
    match message {
        Msg::AnswerChanged(index, value) => {
            if let Some(slot) = state.answers.get_mut(index) {
                *slot = value;
            }
            state.error = None;
            None
        }
        Msg::ToggleReveal => {
            state.revealed = !state.revealed;
            None
        }
        Msg::Submit => submit(state, vault),
        Msg::CloseVault => {
            vault.close();
            state.reset();
            Some(Outcome::Closed)
        }
    }
}

fn submit(state: &mut State, vault: &mut Vault) -> Option<Outcome> {
    let filled = |indices: &[usize]| {
        indices
            .iter()
            .all(|i| state.answers.get(*i).is_some_and(|a| !a.trim().is_empty()))
    };

    match vault.status {
        Status::Locked => {
            if filled(&[0]) {
                vault.status = Status::PartiallyUnlocked;
                state.error = None;
                Some(Outcome::Advanced)
            } else {
                state.error = Some("Enter an answer to continue.");
                None
            }
        }
        Status::PartiallyUnlocked => {
            let rest: Vec<usize> = (1..state.answers.len()).collect();
            if filled(&rest) {
                vault.status = Status::Unlocked;
                state.reset();
                Some(Outcome::Unlocked)
            } else {
                state.error = Some("Answer every question to unlock the vault.");
                None
            }
        }
        // Smart Lock holds the answers re-encrypted in RAM, so one answer is
        // enough to get back in (`src/session.rs::decrypt_smart_lock_data`).
        Status::SmartLocked => {
            if filled(&[0]) {
                vault.status = Status::Unlocked;
                state.reset();
                Some(Outcome::Unlocked)
            } else {
                state.error = Some("Enter an answer to continue.");
                None
            }
        }
        Status::NoVault | Status::Unlocked => None,
    }
}

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.unlock;
    let questions = data::sample_questions();

    let (heading, note, asked): (&str, Option<&str>, Vec<usize>) = match app.vault.status {
        Status::PartiallyUnlocked => (
            "Answer the remaining questions",
            Some(
                "The first answer decrypted the question list. All of them together decrypt the entries.",
            ),
            (1..questions.len()).collect(),
        ),
        Status::SmartLocked => (
            "Smart Lock is armed",
            Some("The answers are held encrypted in memory — one of them re-opens the vault."),
            vec![0],
        ),
        // `Locked`, and defensively anything else that routes here.
        _ => ("Answer the first security question", None, vec![0]),
    };

    let mut fields = column![].spacing(12).width(Length::Fill);
    for (position, index) in asked.iter().copied().enumerate() {
        fields = fields.push(answer_field(
            questions[index],
            &state.answers[index],
            index,
            state.revealed,
            // Only the first field on the screen gets the shared id, so focus
            // lands somewhere unambiguous.
            position == 0,
        ));
    }

    let mut body = column![
        text("UNLOCK VAULT").size(11).style(text::secondary),
        text(app.vault.display_name().to_string())
            .size(20)
            .font(theme::bold()),
    ]
    .spacing(6)
    .padding(20)
    .max_width(560);

    if let Some(location) = app.vault.display_location() {
        body = body.push(text(location).size(12).style(text::secondary));
    }

    body = body.push(text(heading).size(14).font(theme::bold()));
    if let Some(note) = note {
        body = body.push(text(note).size(12).style(text::secondary));
    }
    body = body.push(theme::card(container(fields).padding(14)));

    if let Some(error) = state.error {
        body = body.push(text(error).size(12).style(text::danger));
    }

    body = body.push(
        row![
            button(
                row![icon::unlock(14), text("Unlock").size(14)]
                    .spacing(8)
                    .align_y(Vertical::Center)
            )
            .padding([8, 16])
            .on_press(Message::Unlock(Msg::Submit)),
            button(text("Close Vault").size(14))
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::Unlock(Msg::CloseVault)),
        ]
        .spacing(10),
    );

    body = body.push(
        text("Prototype: any non-empty answer is accepted, and no key is derived.")
            .size(11)
            .style(text::secondary),
    );

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn answer_field<'a>(
    question: &'a str,
    answer: &'a str,
    index: usize,
    revealed: bool,
    focused: bool,
) -> Element<'a, Message> {
    let mut input = text_input("Answer", answer)
        .on_input(move |value| Message::Unlock(Msg::AnswerChanged(index, value)))
        .on_submit(Message::Unlock(Msg::Submit))
        .secure(!revealed)
        .padding(8)
        .size(14)
        .width(Length::Fill);

    if focused {
        input = input.id(ANSWER_INPUT_ID);
    }

    let toggle = theme::text_button_icon(
        if revealed {
            icon::eye_slash(14)
        } else {
            icon::eye(14)
        },
        "Show or hide the answer",
    )
    .on_press(Message::Unlock(Msg::ToggleReveal));

    column![
        text(question).size(13),
        row![input, toggle].spacing(6).align_y(Vertical::Center),
    ]
    .spacing(6)
    .into()
}

/// The id the shell focuses when it switches to this pane.
pub fn focus_target() -> &'static str {
    ANSWER_INPUT_ID
}
