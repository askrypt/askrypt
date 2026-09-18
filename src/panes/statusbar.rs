//! The always-visible bottom status bar.
//!
//! Follows the precedence — error, then success, then status — which
//! [`Session::status_line`](crate::session::Session::status_line) resolves. It
//! also carries the spinner, so background work is visible from any pane, and
//! — while the item list is showing — how many items the current section and
//! search leave in it.

use iced::widget::{container, row, space, text};
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

    // Right-aligned so it stays put while the message beside it changes.
    let line = match app.item_count() {
        Some((shown, total)) => line
            .push(space().width(Length::Fill))
            .push(text(count_label(shown, total)).size(14)),
        None => line,
    };

    container(line)
        .padding(3)
        .width(Length::Fill)
        .style(theme::status_bar_style)
        .into()
}

/// "3 items" when nothing is filtered out, "3 of 10 items" when the section,
/// the hidden rule or the search leaves some behind.
fn count_label(shown: usize, total: usize) -> String {
    let noun = if total == 1 { "item" } else { "items" };
    if shown == total {
        format!("{shown} {noun}")
    } else {
        format!("{shown} of {total} {noun}")
    }
}

#[cfg(test)]
mod tests {
    use super::count_label;

    #[test]
    fn count_label_names_the_filter_only_when_it_hides_something() {
        assert_eq!(count_label(0, 0), "0 items");
        assert_eq!(count_label(1, 1), "1 item");
        assert_eq!(count_label(4, 4), "4 items");
        assert_eq!(count_label(1, 10), "1 of 10 items");
        assert_eq!(count_label(0, 1), "0 of 1 item");
    }
}
