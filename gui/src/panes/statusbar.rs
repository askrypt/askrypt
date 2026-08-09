//! The always-visible bottom status bar.
//!
//! Visually identical to `src/screens/mod.rs::status_bar`, but takes a plain
//! message instead of a `&Session` — porting it back is a one-line adapter.

use iced::widget::{container, text};
use iced::{Element, Length};

use crate::theme;

pub fn view<'a, M: 'a>(message: Option<&str>) -> Element<'a, M> {
    container(text(message.unwrap_or("").to_owned()).size(14))
        .padding(3)
        .width(Length::Fill)
        .style(theme::status_bar_style)
        .into()
}
