//! The questions editor: the security questions and answers that *are* the key.
//!
//! This is the one pane that can bring a vault into existence — "New Vault"
//! lands here, and only a successful save from here produces an `AskryptFile`.
//! It is also how an open vault's questions are changed, which re-derives every
//! key in the vault.
//!
//! Because the answers are the key, saving runs `AskryptFile::create` (two
//! 600,000-iteration derivations) plus one `get_questions_data` to read back the
//! authoritative question list — all on a worker thread. A failure there leaves
//! the session untouched rather than proceeding as though it had worked.

use askrypt::{AskryptFile, MasterSecret, QuestionsData, SecretEntry};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task, alignment::Vertical};
use zeroize::Zeroize;

use crate::panes::Action;
use crate::session::{DEFAULT_ITERATIONS, Session};
use crate::{App, Message, Pane, icon, theme};

#[derive(Default)]
pub struct State {
    questions: Vec<String>,
    answers: Vec<String>,
    translit: bool,
    /// Which answer is currently revealed; at most one at a time.
    shown: Option<usize>,
    error: Option<String>,
    /// Whether this run is bringing a vault into existence, rather than editing
    /// the questions of one that already exists. Only changes the wording.
    creating: bool,
}

/// The typed answers are the vault's key material.
impl Drop for State {
    fn drop(&mut self) {
        self.answers.zeroize();
    }
}

impl State {
    /// Start a brand-new vault: one empty question/answer pair to type into.
    pub fn begin_new(&mut self) {
        self.reset();
        self.creating = true;
        self.questions = vec![String::new(), String::new()];
        self.answers = vec![String::new(), String::new()];
    }

    /// Edit the questions of the vault that is currently open.
    pub fn begin_edit(&mut self, session: &Session) {
        self.reset();

        let mut questions = vec![session.question0.clone()];
        if let Some(data) = &session.questions_data {
            questions.extend(data.questions.clone());
        }
        let mut answers = vec![session.answer0.clone()];
        answers.extend(session.answers.clone());

        // Guarantee at least one row so the pane is never empty.
        if questions.is_empty() {
            questions.push(String::new());
            answers.push(String::new());
        }
        answers.resize(questions.len(), String::new());

        self.questions = questions;
        self.answers = answers;
        self.translit = session.file.as_ref().is_some_and(|f| f.params.translit);
    }

    pub fn reset(&mut self) {
        self.answers.zeroize();
        self.questions.clear();
        self.answers.clear();
        self.translit = false;
        self.shown = None;
        self.error = None;
        self.creating = false;
    }
}

/// Everything a successful build produced, applied to the session in one go.
#[derive(Debug, Clone)]
pub struct Built {
    pub file: AskryptFile,
    pub questions_data: QuestionsData,
    pub question0: String,
    pub answer0: String,
    pub answers: Vec<String>,
    /// The master key the built file is keyed on: the open vault's own when the
    /// questions were merely changed, a fresh one when this call created the
    /// vault.
    pub master: MasterSecret,
}

#[derive(Debug, Clone)]
pub enum Msg {
    QuestionEdited(usize, String),
    AnswerEdited(usize, String),
    ShowAnswer(usize),
    FocusNext,
    Add,
    Delete(usize),
    ToggleTranslit(bool),
    Save,
    Cancel,
    Built(Box<Result<Built, String>>),
}

pub fn update(state: &mut State, session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::QuestionEdited(index, value) => {
            if let Some(slot) = state.questions.get_mut(index) {
                *slot = value;
            }
            state.error = None;
            Action::None
        }
        Msg::AnswerEdited(index, value) => {
            if let Some(slot) = state.answers.get_mut(index) {
                slot.zeroize();
                *slot = value;
            }
            state.error = None;
            Action::None
        }
        Msg::ShowAnswer(index) => {
            state.shown = if state.shown == Some(index) {
                None
            } else {
                Some(index)
            };
            Action::None
        }
        // The question and answer fields are the only focusable widgets in this
        // pane — buttons and the checkbox are not — and the view renders them in
        // order, so "next focusable" is the next field down.
        Msg::FocusNext => Action::Run(iced::widget::operation::focus_next()),
        Msg::Add => {
            state.questions.push(String::new());
            state.answers.push(String::new());
            Action::Run(iced::widget::operation::focus_next())
        }
        Msg::Delete(index) => {
            if index < state.questions.len() {
                state.questions.remove(index);
                if index < state.answers.len() {
                    state.answers[index].zeroize();
                    state.answers.remove(index);
                }
            }
            state.error = None;
            Action::None
        }
        Msg::ToggleTranslit(value) => {
            state.translit = value;
            Action::None
        }
        Msg::Save => save(state, session),
        Msg::Cancel => {
            state.reset();
            Action::Run(Task::done(Message::ReturnToDefaultPane))
        }
        Msg::Built(result) => {
            session.finish_work();
            match *result {
                Ok(built) => {
                    session.question0 = built.question0;
                    session.answer0 = built.answer0;
                    session.answers = built.answers;
                    session.master = Some(built.master);
                    session.questions_data = Some(built.questions_data);
                    session.file = Some(built.file);
                    session.unlocked = true;
                    session.is_modified = true;
                    session.smart_lock_data = None;
                    state.reset();
                    session.success_message =
                        Some("Questions set — save the vault to keep them".into());
                    Action::Pane(Pane::Items)
                }
                Err(e) => {
                    // A failure here does *not* move on as though it had
                    // worked.
                    eprintln!("ERROR: Failed to build vault: {}", e);
                    state.error = Some("Could not build the vault from these answers".to_string());
                    Action::None
                }
            }
        }
    }
}

fn save(state: &mut State, session: &mut Session) -> Action {
    if session.busy {
        return Action::None;
    }

    if state.questions.len() < 2 {
        state.error = Some("At least two questions are required".to_string());
        return Action::None;
    }
    if let Some(index) = state.questions.iter().position(|q| q.trim().is_empty()) {
        state.error = Some(format!("Question {} cannot be empty", index + 1));
        return Action::None;
    }
    if let Some(index) = state.answers.iter().position(|a| a.trim().is_empty()) {
        state.error = Some(format!("Answer {} cannot be empty", index + 1));
        return Action::None;
    }

    let questions = state.questions.clone();
    let answers = state.answers.clone();
    let entries: Vec<SecretEntry> = session.entries.clone();
    let translit = state.translit;
    let iterations = session
        .file
        .as_ref()
        .map(|f| f.params.iterations)
        .unwrap_or(DEFAULT_ITERATIONS);
    // Changing the answers re-wraps the *existing* master key rather than
    // rotating it — that is what the master-key indirection is for, and it is
    // what keeps blobs encrypted under it readable. `None` only when this run
    // is bringing a vault into existence.
    let master = session.master.clone();

    session.begin_work("Encrypting…");
    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                build(questions, answers, entries, iterations, translit, master)
            })
            .await
            .expect("build vault task panicked")
        },
        |result| Message::Questions(Msg::Built(Box::new(result))),
    ))
}

/// Worker-thread only: three key derivations.
///
/// The question list is read back out of the freshly built file rather than
/// assembled by hand, so the session's `QuestionsData` — salt included — is
/// exactly the one the file carries.
fn build(
    questions: Vec<String>,
    answers: Vec<String>,
    entries: Vec<SecretEntry>,
    iterations: u32,
    translit: bool,
    master: Option<MasterSecret>,
) -> Result<Built, String> {
    // Minted here rather than left to `create`, so the session can adopt the
    // very key this file was built with.
    let master = master.unwrap_or_else(MasterSecret::generate);

    let file = AskryptFile::create(
        questions.clone(),
        answers.clone(),
        entries,
        Some(iterations),
        translit,
        Some(&master),
    )
    .map_err(|e| e.to_string())?;

    let answer0 = answers.first().cloned().unwrap_or_default();
    let questions_data = file
        .get_questions_data(answer0.clone())
        .map_err(|e| e.to_string())?;

    Ok(Built {
        question0: questions.first().cloned().unwrap_or_default(),
        answer0,
        answers: answers.into_iter().skip(1).collect(),
        questions_data,
        file,
        master,
    })
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.questions;
    let session = &app.session;

    let caption = if state.creating {
        "NEW VAULT"
    } else {
        "EDIT QUESTIONS"
    };

    let mut body = column![
        text(caption).size(11).style(text::secondary),
        text("Security questions").size(20).font(theme::bold()),
        text(
            "The answers are the key — there is no master password. \
             Answers are normalized before use: case, spaces and dashes do not matter."
        )
        .size(12)
        .style(text::secondary),
    ]
    .spacing(8)
    .padding(20)
    .max_width(620);

    let mut rows = column![].spacing(14);
    for index in 0..state.questions.len() {
        rows = rows.push(question_row(
            index,
            &state.questions[index],
            state.answers.get(index).map(String::as_str).unwrap_or(""),
            state.shown == Some(index),
            state.questions.len() > 2,
            index + 1 == state.questions.len(),
        ));
    }
    body = body.push(theme::card(container(rows).padding(14)));

    body = body.push(
        checkbox(state.translit)
            .label("Use transliteration (answers typed in Russian or Ukrainian)")
            .size(16)
            .text_size(13)
            .on_toggle(|value| Message::Questions(Msg::ToggleTranslit(value))),
    );

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    body = body.push(if session.busy {
        Element::from(theme::spinner_row(
            session.spinner_frame,
            session.spinner_label,
        ))
    } else {
        Element::from(
            row![
                button(
                    row![icon::plus_lg(12), text("Add question").size(14)]
                        .spacing(8)
                        .align_y(Vertical::Center)
                )
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::Questions(Msg::Add)),
                button(text("Apply").size(14))
                    .padding([8, 16])
                    .on_press(Message::Questions(Msg::Save)),
                button(text("Cancel").size(14))
                    .padding([8, 16])
                    .style(button::secondary)
                    .on_press(Message::Questions(Msg::Cancel)),
            ]
            .spacing(10),
        )
    });

    body = body.push(
        text("Changing the questions re-encrypts the vault; save it afterwards to keep them.")
            .size(11)
            .style(text::secondary),
    );

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

/// `last` marks the bottom row, whose answer field is the pane's final input:
/// Enter there applies the changes, everywhere else it walks to the next field.
fn question_row<'a>(
    index: usize,
    question: &'a str,
    answer: &'a str,
    revealed: bool,
    can_delete: bool,
    last: bool,
) -> Element<'a, Message> {
    let mut header = row![
        text(format!("Question {}", index + 1))
            .size(12)
            .style(text::secondary)
            .width(Length::Fill),
    ]
    .align_y(Vertical::Center);

    if can_delete {
        header = header.push(
            theme::text_button_icon(icon::trash(12), "Remove this question")
                .on_press(Message::Questions(Msg::Delete(index))),
        );
    }

    column![
        header,
        text_input("Enter your security question", question)
            .on_input(move |value| Message::Questions(Msg::QuestionEdited(index, value)))
            .on_submit(Message::Questions(Msg::FocusNext))
            .padding(8)
            .size(14),
        row![
            text_input("Enter the answer", answer)
                .on_input(move |value| Message::Questions(Msg::AnswerEdited(index, value)))
                .on_submit(Message::Questions(if last {
                    Msg::Save
                } else {
                    Msg::FocusNext
                }))
                .secure(!revealed)
                .padding(8)
                .size(14)
                .width(Length::Fill),
            theme::text_button_icon(
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
            .on_press(Message::Questions(Msg::ShowAnswer(index))),
        ]
        .spacing(6)
        .align_y(Vertical::Center),
    ]
    .spacing(6)
    .into()
}
