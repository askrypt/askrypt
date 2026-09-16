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

use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task, alignment::Vertical};
use zeroize::Zeroize;

use crate::manager::{Built, RekeyInputs};
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

    /// Edit the questions of the vault that is currently open. Only an unlocked
    /// vault has the answers this pane prefills with, and only an unlocked one
    /// can be re-keyed.
    pub fn begin_edit(&mut self, session: &Session) {
        self.reset();

        let Some(vault) = session.vault.unlocked() else {
            return;
        };
        let mut questions = vault.questions();
        let mut answers = vault.answers();

        // Guarantee at least one row so the pane is never empty.
        if questions.is_empty() {
            questions.push(String::new());
            answers.push(String::new());
        }
        answers.resize(questions.len(), String::new());

        self.questions = questions;
        self.answers = answers;
        self.translit = vault.translit();
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

    /// Swap two question/answer rows. The answers trade places rather than
    /// being copied, so there is nothing to zeroize; the revealed answer
    /// follows its row.
    fn swap_rows(&mut self, a: usize, b: usize) {
        let len = self.questions.len();
        if a >= len || b >= len || a == b || self.answers.len() != len {
            return;
        }
        self.questions.swap(a, b);
        self.answers.swap(a, b);
        self.shown = match self.shown {
            Some(i) if i == a => Some(b),
            Some(i) if i == b => Some(a),
            other => other,
        };
        self.error = None;
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    QuestionEdited(usize, String),
    AnswerEdited(usize, String),
    ShowAnswer(usize),
    FocusNext,
    Add,
    Delete(usize),
    MoveUp(usize),
    MoveDown(usize),
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
        // Order is key material too — question 1's answer alone derives the
        // first key — but it only takes effect on Apply, like any other edit.
        // A build already in flight took the old order, so ignore moves then.
        Msg::MoveUp(index) => {
            if !session.busy && index > 0 {
                state.swap_rows(index - 1, index);
            }
            Action::None
        }
        Msg::MoveDown(index) => {
            if !session.busy {
                state.swap_rows(index, index + 1);
            }
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
                    // One call, rather than nine field writes that had to agree
                    // with each other: the built vault lands unlocked, dirty,
                    // and at the home of the vault it replaces (none, for a
                    // vault this run brought into existence).
                    session.vault.adopt_built(built);
                    session.update_user_activity();
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

    // An open vault contributes its entries, its work factor and — crucially —
    // its master key: changing the answers re-wraps the *existing* key rather
    // than rotating it, which is what keeps everything stored under it
    // readable. Its file attachments ride along for exactly that reason: they
    // are already ciphertext under that key, so a change of questions carries
    // them rather than re-encrypting them. All of it is absent when this run is
    // bringing a vault into existence, which is the one place in the app a key
    // is minted.
    let open = session.vault.unlocked();
    let inputs = RekeyInputs {
        questions: state.questions.clone(),
        answers: state.answers.clone(),
        entries: open
            .map(|vault| vault.entries().to_vec())
            .unwrap_or_default(),
        iterations: open.map_or(DEFAULT_ITERATIONS, |vault| vault.iterations()),
        translit: state.translit,
        master: open.map(|vault| vault.master().clone()),
        attachments: open
            .map(|vault| vault.attachments().clone())
            .unwrap_or_default(),
    };

    session.begin_work("Encrypting…");
    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || inputs.run())
                .await
                .expect("build vault task panicked")
        },
        |result| Message::Questions(Msg::Built(Box::new(result))),
    ))
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
             Answers are normalized before use: case, spaces and dashes do not matter. \
             Question 1 is shown before unlocking."
        )
        .size(12)
        .style(text::secondary),
    ]
    .spacing(8)
    .padding(20)
    .max_width(620);

    let mut rows = column![].spacing(14);
    let count = state.questions.len();
    for index in 0..count {
        rows = rows.push(question_row(
            index,
            &state.questions[index],
            state.answers.get(index).map(String::as_str).unwrap_or(""),
            state.shown == Some(index),
            count > 2,
            count,
            session.busy,
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

/// The bottom row's answer field is the pane's final input: Enter there
/// applies the changes, everywhere else it walks to the next field. Move
/// buttons are hidden at the ends and while a build is running.
fn question_row<'a>(
    index: usize,
    question: &'a str,
    answer: &'a str,
    revealed: bool,
    can_delete: bool,
    count: usize,
    busy: bool,
) -> Element<'a, Message> {
    let last = index + 1 == count;
    let mut header = row![
        text(format!("Question {}", index + 1))
            .size(12)
            .style(text::secondary)
            .width(Length::Fill),
    ]
    .spacing(4)
    .align_y(Vertical::Center);

    if !busy && index > 0 {
        header = header.push(
            theme::text_button_icon(icon::arrow_up(12), "Move up")
                .on_press(Message::Questions(Msg::MoveUp(index))),
        );
    }
    if !busy && !last {
        header = header.push(
            theme::text_button_icon(icon::arrow_down(12), "Move down")
                .on_press(Message::Questions(Msg::MoveDown(index))),
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(rows: &[(&str, &str)]) -> State {
        // `State` implements `Drop`, so no struct-update syntax.
        let mut state = State::default();
        state.questions = rows.iter().map(|(q, _)| q.to_string()).collect();
        state.answers = rows.iter().map(|(_, a)| a.to_string()).collect();
        state
    }

    #[test]
    fn swapping_moves_question_and_answer_together() {
        let mut s = state(&[("q1", "a1"), ("q2", "a2"), ("q3", "a3")]);
        s.error = Some("stale".into());
        s.swap_rows(2, 0);
        assert_eq!(s.questions, ["q3", "q2", "q1"]);
        assert_eq!(s.answers, ["a3", "a2", "a1"]);
        assert!(s.error.is_none());
    }

    #[test]
    fn revealed_answer_follows_its_row() {
        let mut s = state(&[("q1", "a1"), ("q2", "a2"), ("q3", "a3")]);
        s.shown = Some(1);
        s.swap_rows(1, 2);
        assert_eq!(s.shown, Some(2));
        s.swap_rows(0, 1);
        assert_eq!(s.shown, Some(2));
        s.swap_rows(2, 0);
        assert_eq!(s.shown, Some(0));
    }

    #[test]
    fn out_of_range_swap_changes_nothing() {
        let mut s = state(&[("q1", "a1"), ("q2", "a2")]);
        s.swap_rows(1, 2);
        s.swap_rows(5, 0);
        assert_eq!(s.questions, ["q1", "q2"]);
        assert_eq!(s.answers, ["a1", "a2"]);
    }
}
