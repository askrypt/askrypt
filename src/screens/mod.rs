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
pub mod server;
pub mod smart_lock;
pub mod unlock;
pub mod welcome;

use crate::message::Message;
use crate::session::Session;
use chrono::{DateTime, Local};
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
    Server(server::State),
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

/// Append the vault location (if any) to a column.
pub fn show_vault_path<'a, M: 'a>(session: &Session, mut column: Column<'a, M>) -> Column<'a, M> {
    if let Some(location) = &session.location {
        // Name the backend, so it is obvious at a glance whether an unlock is
        // about to touch the network.
        let text_prefix = if location.is_server() {
            text("Server Vault:")
        } else {
            text("Vault File:")
        };
        let text_path = text(location.display_location()).font(Font {
            weight: iced::font::Weight::Bold,
            ..Default::default()
        });
        column = column.push(iced::widget::row![text_prefix, text_path].spacing(5));
    }
    column
}

/// Append the vault's own write stamp — which host saved it last, and when —
/// to a column. The stamp lives unencrypted in `params`, so it is readable
/// before the vault is unlocked. Both halves are optional (vaults written
/// before the stamp existed carry neither), so a file that records nothing
/// adds no line at all rather than a row of placeholders.
pub fn show_vault_stamp<'a, M: 'a>(session: &Session, column: Column<'a, M>) -> Column<'a, M> {
    let Some(params) = session.file.as_ref().map(|file| &file.params) else {
        return column;
    };
    let when = params.updated_at.as_deref().map(format_stamp_time);
    let stamp = match (params.host.as_deref(), when) {
        (Some(host), Some(when)) => format!("{} · {}", host, when),
        (Some(host), None) => host.to_string(),
        (None, Some(when)) => when,
        (None, None) => return column,
    };
    column.push(
        iced::widget::row![
            text("Last saved:"),
            text(stamp).font(Font {
                weight: iced::font::Weight::Bold,
                ..Default::default()
            }),
        ]
        .spacing(5),
    )
}

/// The stamp's RFC 3339 UTC timestamp shown as local time, which is the clock
/// whoever is reading it is on. A timestamp we cannot parse is shown verbatim.
fn format_stamp_time(updated_at: &str) -> String {
    DateTime::parse_from_rfc3339(updated_at)
        .map(|at| at.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| updated_at.to_string())
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
