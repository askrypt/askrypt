//! The unlock pane: a *single* working pane, like Settings and the wizard.
//!
//! It renders the vault format's **layered** unlock, which is a property of the
//! format rather than a UI choice: the first answer decrypts only the *question
//! list*, and all the answers together decrypt the entries. That is why
//! `VaultState::Locked` shows one field and `VaultState::Partial` shows the
//! rest.
//!
//! Every derivation here is 600,000 PBKDF2 iterations (2,000,000 for Smart
//! Lock), so all three paths run on a worker thread and come back as one of the
//! completion messages below. A wrong answer is not detected by a check — it is
//! a decryption that fails.

use askrypt::QuestionsData;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task, alignment::Vertical};
use zeroize::Zeroize;

use crate::manager::{Decrypted, SmartUnlockResult, VaultState};
use crate::panes::Action;
use crate::session::Session;
use crate::{App, Message, Pane, SEARCH_INPUT_ID, VaultMsg, data, icon, theme};

const ANSWER_INPUT_ID: &str = "GUI_UNLOCK_ANSWER";

pub struct State {
    /// One slot per question, indexed absolutely so the partial step can write
    /// answers 1.. without re-indexing.
    answers: Vec<String>,
    /// Which answer is currently revealed; at most one at a time.
    shown: Option<usize>,
    error: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            answers: vec![String::new()],
            shown: None,
            error: None,
        }
    }
}

/// Typed answers are secret material even before they unlock anything.
impl Drop for State {
    fn drop(&mut self) {
        self.answers.zeroize();
    }
}

impl State {
    /// Size the answer slots to the questions this vault actually asks, and drop
    /// whatever the last attempt typed.
    ///
    /// The count is `1 + questions_data.questions.len()` once the first answer
    /// has been accepted, and 1 before that — the remaining questions are still
    /// encrypted, so there is nothing to size against.
    pub fn reset_for(&mut self, vault: &VaultState) {
        self.answers.zeroize();
        self.answers = vec![String::new(); slots_for(vault)];
        self.shown = None;
        self.error = None;
    }

    /// Grow to fit a question list that has just been decrypted, keeping the
    /// first answer (it is still needed to re-derive on save).
    fn fit_to(&mut self, vault: &VaultState) {
        self.answers.resize(slots_for(vault), String::new());
    }
}

/// How many answer fields this vault's state can ask for.
fn slots_for(vault: &VaultState) -> usize {
    1 + vault
        .questions_data()
        .map(|data| data.questions.len())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub enum Msg {
    AnswerChanged(usize, String),
    ToggleReveal(usize),
    /// Enter pressed in an answer field that is *not* the last one on screen:
    /// move on to the next question instead of submitting a half-filled set.
    /// The last field submits with [`Msg::Submit`], as does the button.
    FocusNextAnswer,
    Submit,
    CloseVault,
    /// The first answer decrypted (or failed to decrypt) the question list.
    Answer0Loaded(Result<QuestionsData, String>),
    /// All the answers together decrypted (or failed to decrypt) the entries,
    /// and with them the vault's master key — which the vault keeps so the
    /// next save re-wraps it rather than rotating it.
    VaultDecrypted(Result<Decrypted, String>),
    /// One answer recovered the Smart Lock bundle and reopened the vault.
    SmartUnlockDone(Result<SmartUnlockResult, String>),
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
        // The fields are the only focusable widgets in this pane and the view
        // renders them in order, so "next focusable" is the next question.
        Msg::FocusNextAnswer => Action::Run(iced::widget::operation::focus_next()),
        Msg::Submit => submit(state, session),
        // Closing is the shell's, not this pane's: besides wiping the vault it
        // has to arm the wizard for a fresh Open, which this pane cannot reach.
        // Closing here directly left the wizard on whatever step it was last
        // used at — a server listing, or the recent-files step.
        Msg::CloseVault => Action::Run(Task::done(Message::Vault(VaultMsg::Close))),
        // The three completion arms below share a shape: the answers are taken
        // from this pane's own fields rather than carried back by the worker,
        // and the transition is applied only from the `Ok` arm. A wrong answer
        // therefore leaves the vault exactly where it was, holding nothing the
        // user typed.
        Msg::Answer0Loaded(result) => {
            session.finish_work();
            match result {
                Ok(questions_data) => {
                    let answer0 = state.answers.first().cloned().unwrap_or_default();
                    if !session.vault.apply_reveal(answer0, questions_data) {
                        // The vault moved on while the worker ran — closed, or
                        // locked. The stale question list is dropped, and wiped.
                        return Action::None;
                    }
                    state.fit_to(&session.vault);
                    state.error = None;
                    Action::Run(iced::widget::operation::focus_next())
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to read the question list: {}", e);
                    state.error = Some("The answer is incorrect".to_string());
                    Action::None
                }
            }
        }
        Msg::VaultDecrypted(result) => {
            session.finish_work();
            match result {
                Ok(decrypted) => {
                    // The answers go into the unlocked state now that they are
                    // known to be right: a save re-derives the answer-side keys
                    // from them, and re-wraps the master key.
                    let rest: Vec<String> = state.answers.iter().skip(1).cloned().collect();
                    let millis = session.elapsed_millis();
                    if !session
                        .vault
                        .apply_unlock(rest, decrypted.entries, decrypted.master)
                    {
                        return Action::None;
                    }
                    // Remembered only on a *successful* unlock, so a vault that
                    // cannot be opened never becomes the one reopened at startup.
                    session.remember_vault();
                    session.update_user_activity();
                    state.reset_for(&session.vault);
                    session.status_message = Some(format!("The vault unlocked in {} ms", millis));
                    Action::pane_run(Pane::Items, iced::widget::operation::focus(SEARCH_INPUT_ID))
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to decrypt the vault: {}", e);
                    state.error = Some("One or more answers are incorrect".to_string());
                    Action::None
                }
            }
        }
        Msg::SmartUnlockDone(result) => {
            session.finish_work();
            match result {
                Ok(recovered) => {
                    let millis = session.elapsed_millis();
                    if !session.vault.apply_smart_unlock(recovered) {
                        return Action::None;
                    }
                    session.update_user_activity();
                    state.reset_for(&session.vault);
                    session.status_message =
                        Some(format!("Vault unlocked from Smart Lock in {} ms", millis));
                    Action::pane_run(Pane::Items, iced::widget::operation::focus(SEARCH_INPUT_ID))
                }
                Err(e) => {
                    eprintln!("ERROR: Failed to recover the Smart Lock: {}", e);
                    state.error = Some("Incorrect answer".to_string());
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

    // `matches!` rather than a `match` on `&session.vault`: the arms need
    // `&mut session`, which a borrow held across the match would forbid.
    if matches!(session.vault, VaultState::Locked(_)) {
        start_first_answer(state, session)
    } else if matches!(session.vault, VaultState::Partial(_)) {
        start_full_unlock(state, session)
    } else if matches!(session.vault, VaultState::Smart(_)) {
        start_smart_unlock(state, session)
    } else {
        Action::None
    }
}

/// The first answer decrypts the question list — and only that. A failure here
/// *is* the wrong-answer signal; there is no separate check.
fn start_first_answer(state: &mut State, session: &mut Session) -> Action {
    let Some(answer0) = state.answers.first().filter(|a| !a.trim().is_empty()) else {
        state.error = Some("Enter an answer to continue.".to_string());
        return Action::None;
    };
    // Only a locked vault has a first answer left to try — the typestate says
    // so, rather than a comment.
    let Some(inputs) = session
        .vault
        .locked()
        .map(|vault| vault.reveal_inputs(answer0.clone()))
    else {
        return Action::None;
    };

    session.begin_work("Decrypting…");

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || inputs.run())
                .await
                .expect("get_questions_data task panicked")
        },
        |result| Message::Unlock(Msg::Answer0Loaded(result)),
    ))
}

fn start_full_unlock(state: &mut State, session: &mut Session) -> Action {
    let rest: Vec<String> = state.answers.iter().skip(1).cloned().collect();
    if rest.iter().any(|answer| answer.trim().is_empty()) {
        state.error = Some("Answer every question to unlock the vault.".to_string());
        return Action::None;
    }

    // `rest` is answers 1.., which is what `decrypt_with_master` wants —
    // `unlock_inputs` is the only place that off-by-one is written down.
    let Some(inputs) = session
        .vault
        .partial()
        .map(|vault| vault.unlock_inputs(rest))
    else {
        return Action::None;
    };

    session.begin_work("Decrypting…");

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || inputs.run())
                .await
                .expect("decrypt task panicked")
        },
        |result| Message::Unlock(Msg::VaultDecrypted(result)),
    ))
}

/// Smart Lock holds every answer re-encrypted in RAM, so one of them recovers
/// the lot. Three crypto steps, all in the same worker: recover the answers,
/// re-read the question list, then decrypt the entries.
fn start_smart_unlock(state: &mut State, session: &mut Session) -> Action {
    let Some(answer) = state.answers.first().filter(|a| !a.trim().is_empty()) else {
        state.error = Some("Enter an answer to continue.".to_string());
        return Action::None;
    };
    let Some(inputs) = session
        .vault
        .smart()
        .map(|vault| vault.smart_unlock_inputs(answer.clone()))
    else {
        return Action::None;
    };

    session.begin_work("Decrypting…");

    Action::Run(Task::perform(
        async move {
            tokio::task::spawn_blocking(move || inputs.run())
                .await
                .expect("smart unlock task panicked")
        },
        |result| Message::Unlock(Msg::SmartUnlockDone(result)),
    ))
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.unlock;
    let session = &app.session;
    // Which questions are on screen, and their text. Question 0 is stored in the
    // clear; the rest only exist once the first answer decrypted them. Each arm
    // reads through the handle for its own state, so a question list can only be
    // shown by the state that actually has one.
    let (heading, note, asked): (&str, Option<&str>, Vec<(usize, String)>) = match &session.vault {
        VaultState::Partial(vault) => (
            "Answer the remaining questions",
            Some(
                "The first answer decrypted the question list. All of them together decrypt the entries.",
            ),
            vault
                .questions_data()
                .questions
                .iter()
                .enumerate()
                .map(|(offset, question)| (offset + 1, question.clone()))
                .collect(),
        ),
        VaultState::Smart(vault) => (
            "Smart Lock is armed",
            Some("The answers are held encrypted in memory — one of them re-opens the vault."),
            vec![(0, vault.key_question().to_string())],
        ),
        // `Locked`, and defensively anything else that routes here.
        _ => (
            "Answer the first security question",
            None,
            vec![(0, session.vault.question0().unwrap_or_default().to_string())],
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
            // Only the first field on the screen gets the shared id, so focus
            // lands somewhere unambiguous.
            position == 0,
            position + 1 == asked_count,
        ));
    }

    let mut body = column![
        text("UNLOCK VAULT").size(11).style(text::secondary),
        text(session.display_name()).size(20).font(theme::bold()),
    ]
    .spacing(6)
    .padding(20)
    .max_width(560);

    if let Some(location) = session.display_location() {
        body = body.push(text(location).size(12).style(text::secondary));
    }

    // The write stamp is unencrypted, so it is readable before a single answer
    // is given — it says which machine last saved this vault, and when.
    if let Some(stamp) = session.vault.file().and_then(|file| {
        data::format_stamp(
            file.params.host.as_deref(),
            file.params.updated_at.as_deref(),
        )
    }) {
        body = body.push(
            text(format!("Last saved: {stamp}"))
                .size(12)
                .style(text::secondary),
        );
    }

    body = body.push(text(heading).size(14).font(theme::bold()));
    if let Some(note) = note {
        body = body.push(text(note).size(12).style(text::secondary));
    }
    if let Some(remaining) = smart_lock_countdown(session) {
        body = body.push(text(remaining).size(12).style(text::secondary));
    }
    body = body.push(theme::card(container(fields).padding(14)));

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    // While a derivation runs the controls are replaced by the spinner, so the
    // same answer cannot be submitted twice.
    body = body.push(if session.busy {
        Element::from(theme::spinner_row(
            session.spinner_frame,
            session.spinner_label,
        ))
    } else {
        Element::from(
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
        )
    });

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

/// How long the armed Smart Lock has left before it drops to a full lock.
///
/// Only the Smart Locked state has a bundle to count down, so there is no
/// longer an "unless it is also unlocked" check to remember.
fn smart_lock_countdown(session: &Session) -> Option<String> {
    let remaining = session.vault.smart()?.remaining();
    let minutes = remaining.as_secs() / 60;
    Some(format!(
        "Time until full lock: {}h {}m",
        minutes / 60,
        minutes % 60
    ))
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
        .on_input(move |value| Message::Unlock(Msg::AnswerChanged(index, value)))
        // Enter walks down the questions and only unlocks from the last one.
        .on_submit(Message::Unlock(if last {
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
    .on_press(Message::Unlock(Msg::ToggleReveal(index)));

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
