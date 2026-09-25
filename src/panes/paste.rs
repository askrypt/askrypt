//! The paste pane: answering the questions of a pasted copy of some items.
//!
//! Paste first tries the answers the open vault already holds
//! ([`crate::manager::PasteInputs`]); this pane is only reached when the copy
//! came from a vault with other questions, or other answers. It walks the
//! copy's **layered** unlock exactly as the unlock pane walks a vault's: the
//! first answer decrypts the copy's remaining questions, all of them together
//! decrypt its items. Both steps are 600,000-iteration derivations on a worker.
//!
//! The decrypted items are not merged here: they go back to the shell as
//! [`GlobalMsg::PasteReady`], the one funnel both paste paths share.

use askrypt::{AskryptFile, QuestionsData};
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task, alignment::Vertical};
use zeroize::Zeroize;

use crate::manager::{PasteDecryptInputs, PasteRevealInputs, PastedEntries};
use crate::panes::Action;
use crate::session::Session;
use crate::{App, GlobalMsg, Message, icon, theme};

const ANSWER_INPUT_ID: &str = "GUI_PASTE_ANSWER";

#[derive(Default)]
pub struct State {
    /// The pasted copy. `None` when no paste is waiting for answers — which is
    /// also what makes a late worker reply after Cancel or a lock fall on the
    /// floor.
    file: Option<AskryptFile>,
    /// The copy's remaining questions, once the first answer revealed them.
    questions_data: Option<QuestionsData>,
    /// One slot per question, indexed absolutely as in the unlock pane.
    answers: Vec<String>,
    shown: Option<usize>,
    error: Option<String>,
}

/// Typed answers are secret material even before they decrypt anything.
impl Drop for State {
    fn drop(&mut self) {
        self.answers.zeroize();
    }
}

impl State {
    /// Begin asking for the questions of `file`.
    pub fn start(&mut self, file: AskryptFile) {
        self.reset();
        self.file = Some(file);
        self.answers = vec![String::new()];
    }

    /// Forget the copy and everything typed for it.
    pub fn reset(&mut self) {
        self.answers.zeroize();
        *self = State::default();
    }

    /// Whether a paste is waiting for answers.
    pub fn is_active(&self) -> bool {
        self.file.is_some()
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    AnswerChanged(usize, String),
    ToggleReveal(usize),
    /// Enter in a field that is not the last one: move to the next question.
    FocusNextAnswer,
    Submit,
    Cancel,
    /// The first answer decrypted (or failed to decrypt) the copy's questions.
    Revealed(Result<QuestionsData, String>),
    /// All the answers decrypted (or failed to decrypt) the copy's items.
    Decrypted(Result<PastedEntries, String>),
}

pub fn update(state: &mut State, session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::AnswerChanged(index, value) => {
            if let Some(slot) = state.answers.get_mut(index) {
                slot.zeroize();
                *slot = value;
            }
            state.error = None;
            Action::None
        }
        Msg::ToggleReveal(index) => {
            state.shown = if state.shown == Some(index) {
                None
            } else {
                Some(index)
            };
            Action::None
        }
        Msg::FocusNextAnswer => Action::Run(iced::widget::operation::focus_next()),
        Msg::Submit => submit(state, session),
        Msg::Cancel => {
            state.reset();
            Action::Run(Task::done(Message::ReturnToDefaultPane))
        }
        Msg::Revealed(result) => {
            session.finish_work();
            if !state.is_active() {
                return Action::None;
            }
            match result {
                Ok(questions_data) => {
                    state
                        .answers
                        .resize(1 + questions_data.questions.len(), String::new());
                    state.questions_data = Some(questions_data);
                    state.shown = None;
                    state.error = None;
                    Action::Run(iced::widget::operation::focus(ANSWER_INPUT_ID))
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to read the pasted question list: {}", e);
                    state.error = Some("The answer is incorrect".to_string());
                    Action::None
                }
            }
        }
        Msg::Decrypted(result) => {
            session.finish_work();
            if !state.is_active() {
                return Action::None;
            }
            match result {
                Ok(entries) => {
                    state.reset();
                    Action::Run(Task::done(Message::Global(GlobalMsg::PasteReady(entries))))
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to decrypt the pasted items: {}", e);
                    state.error = Some("One or more answers are incorrect".to_string());
                    Action::None
                }
            }
        }
    }
}

fn submit(state: &mut State, session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }
    let Some(file) = state.file.clone() else {
        return Action::None;
    };

    match state.questions_data.clone() {
        None => {
            let Some(answer0) = state.answers.first().filter(|a| !a.trim().is_empty()) else {
                state.error = Some("Enter an answer to continue.".to_string());
                return Action::None;
            };
            let inputs = match PasteRevealInputs::new(file, answer0.clone()) {
                Ok(inputs) => inputs,
                Err(e) => {
                    state.error = Some(e);
                    return Action::None;
                }
            };
            session.begin_work("Decrypting…");
            Action::Run(Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || inputs.run())
                        .await
                        .expect("paste reveal task panicked")
                },
                |result| Message::Paste(Msg::Revealed(result)),
            ))
        }
        Some(questions_data) => {
            let rest: Vec<String> = state.answers.iter().skip(1).cloned().collect();
            if rest.iter().any(|answer| answer.trim().is_empty()) {
                state.error = Some("Answer every question to paste the items.".to_string());
                return Action::None;
            }
            let inputs = match PasteDecryptInputs::new(file, questions_data, rest) {
                Ok(inputs) => inputs,
                Err(e) => {
                    state.error = Some(e);
                    return Action::None;
                }
            };
            session.begin_work("Decrypting…");
            Action::Run(Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || inputs.run())
                        .await
                        .expect("paste decrypt task panicked")
                },
                |result| Message::Paste(Msg::Decrypted(result)),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.paste;
    let session = &app.session;

    let (heading, asked): (&str, Vec<(usize, String)>) = match &state.questions_data {
        Some(data) => (
            "Answer the remaining questions",
            data.questions
                .iter()
                .enumerate()
                .map(|(offset, question)| (offset + 1, question.clone()))
                .collect(),
        ),
        None => (
            "Answer the first security question",
            vec![(
                0,
                state
                    .file
                    .as_ref()
                    .map(|file| file.question0.clone())
                    .unwrap_or_default(),
            )],
        ),
    };

    let mut fields = column![].spacing(12).width(Length::Fill);
    let asked_count = asked.len();
    for (position, (index, question)) in asked.into_iter().enumerate() {
        let answer = state.answers.get(index).cloned().unwrap_or_default();
        fields = fields.push(answer_field(
            question,
            answer,
            index,
            state.shown == Some(index),
            position == 0,
            position + 1 == asked_count,
        ));
    }

    let mut body = column![
        text("PASTE ITEMS").size(11).style(text::secondary),
        text(
            "These items were copied from a vault with other security questions \
             or answers. Answer its questions to paste them into this vault."
        )
        .size(12)
        .style(text::secondary),
        text(heading).size(14).font(theme::bold()),
        theme::card(container(fields).padding(14)),
    ]
    .spacing(6)
    .padding(20)
    .max_width(560);

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    body = body.push(if session.busy {
        Element::from(theme::spinner_row(
            session.spinner_frame,
            session.spinner_label,
        ))
    } else {
        let label = if state.questions_data.is_some() {
            "Paste"
        } else {
            "Continue"
        };
        Element::from(
            row![
                button(
                    row![icon::unlock(14), text(label).size(14)]
                        .spacing(8)
                        .align_y(Vertical::Center)
                )
                .padding([8, 16])
                .on_press(Message::Paste(Msg::Submit)),
                button(text("Cancel").size(14))
                    .padding([8, 16])
                    .style(button::secondary)
                    .on_press(Message::Paste(Msg::Cancel)),
            ]
            .spacing(10),
        )
    });

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn answer_field<'a>(
    question: String,
    answer: String,
    index: usize,
    revealed: bool,
    focused: bool,
    last: bool,
) -> Element<'a, Message> {
    let mut input = text_input("Answer", &answer)
        .on_input(move |value| Message::Paste(Msg::AnswerChanged(index, value)))
        .on_submit(Message::Paste(if last {
            Msg::Submit
        } else {
            Msg::FocusNextAnswer
        }))
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
        if revealed {
            "Hide answer"
        } else {
            "Show answer"
        },
    )
    .on_press(Message::Paste(Msg::ToggleReveal(index)));

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
