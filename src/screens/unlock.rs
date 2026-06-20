//! The layered unlock flow: answer the first question to reveal the rest
//! ([`FirstState`]), then answer all of them to decrypt the vault
//! ([`OtherState`]). The two screens share this module because they share the
//! answer-input widgets and the `answer0` visibility toggle.

use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, entries, show_messages_in_column, show_vault_path};
use crate::session::Session;
use crate::ui::{padded_button, security_input_with_toggle, spinner_row, title_h1};
use askrypt::{QuestionsData, SecretEntry};
use iced::widget::{operation, row, text};
use iced::{Element, Task, alignment};
use std::time::Instant;

/// State for the first-question screen.
#[derive(Default)]
pub struct FirstState {
    pub show_answer0: bool,
}

/// State for the remaining-questions screen.
#[derive(Default)]
pub struct OtherState {
    pub show_answer0: bool,
    pub shown_answer_index: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum FirstMsg {
    Answer0Edited(String),
    Answer0Finished,
    Answer0Loaded(Result<QuestionsData, String>),
    ToggleAnswer0Visibility,
}

#[derive(Debug, Clone)]
pub enum OtherMsg {
    AnswerEdited(usize, String),
    AnswerFinished(usize),
    UnlockVault,
    VaultDecrypted(Result<Vec<SecretEntry>, String>),
    ToggleAnswer0Visibility,
    ShowAnswer(usize),
}

pub fn first_update(state: &mut FirstState, session: &mut Session, msg: FirstMsg) -> Action {
    match msg {
        FirstMsg::Answer0Edited(value) => {
            session.answer0 = value;
            Action::None
        }
        FirstMsg::Answer0Finished => {
            if session.decrypting {
                return Action::None;
            }
            if let Some(file) = &session.file {
                let file = file.clone();
                let answer0 = session.answer0.clone();
                session.error_message = None;
                session.decrypting = true;
                session.decrypt_started = Some(Instant::now());
                Action::Run(Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            file.get_questions_data(answer0).map_err(|e| e.to_string())
                        })
                        .await
                        .expect("get_questions_data task panicked")
                    },
                    |r| Message::FirstQuestion(FirstMsg::Answer0Loaded(r)),
                ))
            } else {
                Action::None
            }
        }
        FirstMsg::Answer0Loaded(result) => {
            session.decrypting = false;
            match result {
                Ok(questions_data) => {
                    let questions_count = questions_data.questions.len();
                    session.questions_data = Some(questions_data);
                    while session.answers.len() < questions_count {
                        session.answers.push(String::new());
                    }
                    Action::switch_run(
                        Screen::OtherQuestions(OtherState::default()),
                        operation::focus_next(),
                    )
                }
                Err(e) => {
                    eprintln!("ERROR: The answer is incorrect: {}", e);
                    session.error_message = Some("The answer is incorrect".into());
                    Action::None
                }
            }
        }
        FirstMsg::ToggleAnswer0Visibility => {
            state.show_answer0 = !state.show_answer0;
            Action::None
        }
    }
}

pub fn other_update(state: &mut OtherState, session: &mut Session, msg: OtherMsg) -> Action {
    match msg {
        OtherMsg::AnswerEdited(index, value) => {
            if let Some(answer) = session.answers.get_mut(index) {
                *answer = value;
            }
            Action::None
        }
        OtherMsg::AnswerFinished(index) => {
            if index == session.answers.len() - 1 {
                start_unlock(session)
            } else {
                Action::Run(operation::focus_next())
            }
        }
        OtherMsg::UnlockVault => start_unlock(session),
        OtherMsg::VaultDecrypted(result) => {
            session.decrypting = false;
            match result {
                Ok(entries) => {
                    let millis = session
                        .decrypt_started
                        .take()
                        .map(|start| start.elapsed().as_millis())
                        .unwrap_or(0);
                    session.entries = entries;
                    session.unlocked = true;
                    session.last_user_activity = Some(Instant::now());
                    session.settings.last_opened_file = session.path.clone();
                    session.status_message = Some(format!("The Vault unlocked in {} ms", millis));
                    Action::switch(Screen::Entries(entries::State::default()))
                }
                Err(e) => {
                    eprintln!("ERROR: One or more answers are incorrect: {}", e);
                    session.error_message = Some("One or more answers are incorrect".into());
                    Action::None
                }
            }
        }
        OtherMsg::ToggleAnswer0Visibility => {
            state.show_answer0 = !state.show_answer0;
            if state.show_answer0 {
                state.shown_answer_index = None;
            }
            Action::None
        }
        OtherMsg::ShowAnswer(index) => {
            if state.shown_answer_index == Some(index) {
                state.shown_answer_index = None;
            } else {
                state.shown_answer_index = Some(index);
                state.show_answer0 = false;
            }
            Action::None
        }
    }
}

fn start_unlock(session: &mut Session) -> Action {
    if session.decrypting {
        return Action::None;
    }
    if let (Some(data), Some(file)) = (&session.questions_data, &session.file) {
        let file = file.clone();
        let data = data.clone();
        let answers = session.answers.clone();
        session.error_message = None;
        session.decrypting = true;
        session.decrypt_started = Some(Instant::now());
        Action::Run(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    file.decrypt(&data, answers).map_err(|e| e.to_string())
                })
                .await
                .expect("decrypt task panicked")
            },
            |r| Message::OtherQuestions(OtherMsg::VaultDecrypted(r)),
        ))
    } else {
        Action::None
    }
}

pub fn first_view<'a>(state: &'a FirstState, session: &'a Session) -> Element<'a, Message> {
    let mut column = title_h1("Try to unlock the vault")
        .push("Answer the first security question to reveal the other questions")
        .align_x(alignment::Horizontal::Center);

    column = show_vault_path(session, column);

    let answer0_input = security_input_with_toggle(
        &session.answer0,
        state.show_answer0,
        Some(|v| Message::FirstQuestion(FirstMsg::Answer0Edited(v))),
        Some(Message::FirstQuestion(FirstMsg::Answer0Finished)),
        Message::FirstQuestion(FirstMsg::ToggleAnswer0Visibility),
        "Type the first answer...",
        "Hide Answer",
        "Show Answer",
        None,
    )
    .width(400);

    column = column
        .push(text(&session.question0).size(15))
        .push(answer0_input);

    if session.decrypting {
        column = column.push(spinner_row(session.spinner_frame, session.spinner_label));
    } else {
        let controls = row![
            padded_button("Unlock").on_press(Message::FirstQuestion(FirstMsg::Answer0Finished)),
            padded_button("Main menu").on_press(Message::Global(GlobalMsg::BackToWelcome)),
            padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)),
        ]
        .spacing(10);
        column = column.push(controls);
    }
    column = show_messages_in_column(session, column);

    column.into()
}

pub fn other_view<'a>(state: &'a OtherState, session: &'a Session) -> Element<'a, Message> {
    let mut column = title_h1("Try to unlock the file")
        .push("Answer the questions")
        .align_x(alignment::Horizontal::Center);

    column = show_vault_path(session, column);

    if let Some(data) = &session.questions_data {
        let answer0_input = security_input_with_toggle(
            &session.answer0,
            state.show_answer0,
            None::<fn(String) -> Message>,
            None,
            Message::OtherQuestions(OtherMsg::ToggleAnswer0Visibility),
            "Type the first answer...",
            "Hide Answer",
            "Show Answer",
            None,
        )
        .width(400);

        column = column
            .push(text(&session.question0).size(15))
            .push(answer0_input);

        for (i, question) in data.questions.iter().enumerate() {
            let is_answer_shown = state.shown_answer_index == Some(i);

            column = column.push(text(question).size(15));

            let answer_input = security_input_with_toggle(
                &session.answers[i],
                is_answer_shown,
                Some(move |v| Message::OtherQuestions(OtherMsg::AnswerEdited(i, v))),
                Some(Message::OtherQuestions(OtherMsg::AnswerFinished(i))),
                Message::OtherQuestions(OtherMsg::ShowAnswer(i)),
                "Type the answer...",
                "Hide Answer",
                "Show Answer",
                None,
            )
            .width(400);

            column = column.push(answer_input);
        }

        if session.decrypting {
            column = column.push(spinner_row(session.spinner_frame, session.spinner_label));
        } else {
            let controls = row![
                padded_button("Unlock").on_press(Message::OtherQuestions(OtherMsg::UnlockVault)),
                padded_button("Cancel").on_press(Message::Global(GlobalMsg::BackToWelcome)),
                padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)),
            ]
            .spacing(10);
            column = column.push(controls);
        }
        column = show_messages_in_column(session, column);
    }

    column.into()
}
