//! The always-visible bottom status bar.
//!
//! Visually identical to `src/screens/mod.rs::status_bar`, and follows the same
//! precedence — error, then success, then status — which
//! [`Session::status_line`](crate::session::Session::status_line) resolves. It
//! also carries the spinner, so background work is visible from any pane.

use iced::widget::{container, row, text};
use iced::{Element, Length, alignment::Vertical};

use crate::{App, Message, theme};

pub fn view<'a>(app: &'a App, message: &str) -> Element<'a, Message> {
    let session = &app.session;

    let line = row![text(message.to_owned()).size(14)]
        .spacing(10)
        .align_y(Vertical::Center);

    let line = if session.busy {
        line.push(theme::spinner_row(
            session.spinner_frame,
            session.spinner_label,
        ))
    } else {
        line
    };

    container(line)
        .padding(3)
        .width(Length::Fill)
        .style(theme::status_bar_style)
        .into()
}
