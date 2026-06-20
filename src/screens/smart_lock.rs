//! Smart Lock screen: fast re-unlock by answering a single, randomly chosen
//! security question (the answers are kept encrypted in RAM by the session).

use crate::message::{GlobalMsg, Message};
use crate::screens::{Action, Screen, entries, show_messages_in_column, show_vault_path};
use crate::session::{SMART_LOCK_TIMEOUT, Session, SmartUnlockResult};
use crate::ui::{padded_button, security_input_with_toggle, spinner_row, title_h1};
use iced::widget::{row, text};
use iced::{Color, Element, Task, alignment};
use std::time::Instant;
use zeroize::Zeroize;

/// UI state for the Smart Lock screen. The typed answer is wiped on drop.
#[derive(Default)]
pub struct State {
    pub smart_lock_answer: String,
    pub show_smart_lock_answer: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        self.smart_lock_answer.zeroize();
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    AnswerEdited(String),
    AnswerFinished,
    ToggleAnswerVisibility,
    SmartUnlock,
    SmartUnlockDone(Result<SmartUnlockResult, String>),
}

pub fn update(state: &mut State, session: &mut Session, msg: Msg) -> Action {
    match msg {
        Msg::AnswerEdited(value) => {
            state.smart_lock_answer = value;
            Action::None
        }
        Msg::AnswerFinished => start_unlock(state, session),
        Msg::ToggleAnswerVisibility => {
            state.show_smart_lock_answer = !state.show_smart_lock_answer;
            Action::None
        }
        Msg::SmartUnlock => start_unlock(state, session),
        Msg::SmartUnlockDone(result) => {
            session.decrypting = false;
            match result {
                Ok(unlocked) => {
                    let millis = session
                        .decrypt_started
                        .take()
                        .map(|start| start.elapsed().as_millis())
                        .unwrap_or(0);
                    // Restore the answers recovered from Smart Lock data.
                    session.answer0 = unlocked.answer0;
                    session.answers = unlocked.answers;
                    session.entries = unlocked.entries;
                    session.questions_data = Some(unlocked.questions_data);
                    session.unlocked = true;
                    session.last_user_activity = Some(Instant::now());
                    state.smart_lock_answer.zeroize();
                    // Update last activity time
                    if let Some(data) = session.smart_lock_data.as_mut() {
                        data.last_activity = Instant::now();
                    }
                    session.status_message =
                        Some(format!("Vault unlocked from Smart Lock in {} ms", millis));
                    Action::switch(Screen::Entries(entries::State::default()))
                }
                Err(e) => {
                    eprintln!("ERROR: Smart unlock failed: {}", e);
                    session.error_message = Some("Incorrect answer".into());
                    Action::None
                }
            }
        }
    }
}

fn start_unlock(state: &mut State, session: &mut Session) -> Action {
    if session.decrypting {
        return Action::None;
    }
    // Recovering the answers (2M-iteration PBKDF2) and the full vault unlock both
    // run on a worker thread under a "Decrypting…" spinner.
    if let (Some(smart_lock_data), Some(file)) = (&session.smart_lock_data, &session.file) {
        let smart_lock_data = smart_lock_data.clone();
        let file = file.clone();
        let answer = state.smart_lock_answer.clone();
        let translit = file.params.translit;
        session.error_message = None;
        session.decrypting = true;
        session.decrypt_started = Some(Instant::now());
        Action::Run(Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let (answer0, answers) =
                        Session::decrypt_smart_lock_data(&smart_lock_data, &answer, translit)
                            .map_err(|e| e.to_string())?;
                    let questions_data = file
                        .get_questions_data(answer0.clone())
                        .map_err(|e| e.to_string())?;
                    let entries = file
                        .decrypt(&questions_data, answers.clone())
                        .map_err(|e| e.to_string())?;
                    Ok::<_, String>(SmartUnlockResult {
                        answer0,
                        answers,
                        questions_data,
                        entries,
                    })
                })
                .await
                .expect("smart unlock task panicked")
            },
            |r| Message::SmartLock(Msg::SmartUnlockDone(r)),
        ))
    } else {
        Action::None
    }
}

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let mut column = title_h1("Vault is Smart Locked")
        .push("Enter the selected answer to quickly unlock")
        .align_x(alignment::Horizontal::Center);

    column = show_vault_path(session, column);

    // Show which question is being asked
    if let Some(smart_lock_data) = &session.smart_lock_data {
        column = column.push(text(&smart_lock_data.key_question).size(15));
    }

    let answer_input = security_input_with_toggle(
        &state.smart_lock_answer,
        state.show_smart_lock_answer,
        Some(|v| Message::SmartLock(Msg::AnswerEdited(v))),
        Some(Message::SmartLock(Msg::AnswerFinished)),
        Message::SmartLock(Msg::ToggleAnswerVisibility),
        "Type the answer...",
        "Hide Answer",
        "Show Answer",
        None,
    )
    .width(400);

    column = column.push(answer_input);

    // Show remaining time before full lock
    if let Some(smart_lock_data) = &session.smart_lock_data {
        let elapsed = smart_lock_data.last_activity.elapsed();
        let remaining = SMART_LOCK_TIMEOUT.saturating_sub(elapsed);
        let hours = remaining.as_secs() / 3600;
        let minutes = (remaining.as_secs() % 3600) / 60;
        column = column.push(
            text(format!("Time until full lock: {}h {}m", hours, minutes))
                .size(12)
                .color(Color::from_rgb(0.5, 0.5, 0.5)),
        );
    }

    if session.decrypting {
        column = column.push(spinner_row(session.spinner_frame, session.spinner_label));
    } else {
        let controls = row![
            padded_button("Unlock").on_press(Message::SmartLock(Msg::SmartUnlock)),
            padded_button("Full Lock").on_press(Message::Global(GlobalMsg::CancelSmartLock)),
            padded_button("Exit").on_press(Message::Global(GlobalMsg::ExitApp)),
        ]
        .spacing(10);
        column = column.push(controls);
    }
    column = show_messages_in_column(session, column);

    column.into()
}
