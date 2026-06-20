//! Per-screen modules.
//!
//! Each screen owns a `State` struct (its UI-only fields), a `Msg` enum (the
//! events it produces), an `update(state, session, msg) -> Action` function and
//! a `view(state, session) -> Element<Message>` function. A screen reads and
//! mutates shared state only through `&mut Session`; navigation is requested by
//! returning an [`Action`] rather than by owning the active [`Screen`].

pub mod entries;
pub mod entry_editor;
pub mod passgen;
pub mod questions;
pub mod smart_lock;
pub mod unlock;
pub mod welcome;

use crate::message::Message;
use crate::session::Session;
use iced::widget::{Column, container, text};
use iced::{Element, Font, Length, Task, Theme};

/// The currently displayed screen, owning that screen's local UI state.
pub enum Screen {
    Welcome,
    Questions(questions::State),
    FirstQuestion(unlock::FirstState),
    OtherQuestions(unlock::OtherState),
    Entries(entries::State),
    EntryEditor(entry_editor::State),
    PassGen(passgen::State),
    SmartLock(smart_lock::State),
}

/// The outcome of a screen's `update`: an optional navigation plus a task to
/// run. Returned to the app shell, which applies it (sets the active screen and
/// returns the task to the Iced runtime).
pub enum Action {
    None,
    Run(Task<Message>),
    Switch(Box<Screen>),
    SwitchRun(Box<Screen>, Task<Message>),
}

impl Action {
    pub fn switch(screen: Screen) -> Self {
        Action::Switch(Box::new(screen))
    }

    pub fn switch_run(screen: Screen, task: Task<Message>) -> Self {
        Action::SwitchRun(Box::new(screen), task)
    }
}

/// Append the current error/success messages (bold, colored) to a column. Used
/// by the screens that show messages inline rather than in a status bar.
pub fn show_messages_in_column<'a, M: 'a>(
    session: &Session,
    column: Column<'a, M>,
) -> Column<'a, M> {
    let column = if let Some(error) = &session.error_message {
        column.push(text(error.clone()).style(text::danger).size(14).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        }))
    } else {
        column
    };

    if let Some(success) = &session.success_message {
        column.push(
            text(success.clone())
                .style(text::success)
                .size(14)
                .font(Font {
                    weight: iced::font::Weight::Bold,
                    ..Default::default()
                }),
        )
    } else {
        column
    }
}

/// Append the vault file path (if any) to a column.
pub fn show_vault_path<'a, M: 'a>(session: &Session, mut column: Column<'a, M>) -> Column<'a, M> {
    if let Some(path) = &session.path {
        let text_prefix = text("Vault File:");
        let text_path = text(path.to_str().expect("Invalid vault path").to_owned()).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        });
        column = column.push(iced::widget::row![text_prefix, text_path].spacing(5));
        column = column.push(text(""));
    }
    column
}

/// A bottom status bar that displays the current error/success/status message.
pub fn status_bar<'a, M: 'a>(session: &Session) -> Element<'a, M> {
    let label = if let Some(error) = &session.error_message {
        text(error.clone()).style(text::danger)
    } else if let Some(success) = &session.success_message {
        text(success.clone()).style(text::success)
    } else if let Some(status) = &session.status_message {
        text(status.clone())
    } else {
        text("")
    };

    container(label.size(14))
        .padding(3)
        .width(Length::Fill)
        .style(|theme: &Theme| container::Style {
            border: iced::Border {
                color: theme.extended_palette().background.neutral.color,
                width: 1.0,
                radius: 0.0.into(),
            },
            background: Some(theme.palette().background.into()),
            ..Default::default()
        })
        .into()
}
