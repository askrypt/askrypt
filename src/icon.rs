use iced::widget::Text;
use iced::{Font, alignment};

const BOOTSTRAP_ICONS: Font = Font::with_name("bootstrap-icons");

fn bootstrap_icon(unicode: char) -> Text<'static> {
    Text::new(unicode.to_string())
        .font(BOOTSTRAP_ICONS)
        .align_x(alignment::Horizontal::Center)
        .size(12)
}

pub fn pencil_icon() -> Text<'static> {
    bootstrap_icon('\u{F4CB}')
}

pub fn copy_icon() -> Text<'static> {
    bootstrap_icon('\u{F759}')
}

pub fn eye_icon() -> Text<'static> {
    bootstrap_icon('\u{F341}')
}

pub fn eye_slash_icon() -> Text<'static> {
    bootstrap_icon('\u{F340}')
}

pub fn x_lg_icon() -> Text<'static> {
    bootstrap_icon('\u{F659}')
}

pub fn box_arrow_up_right_icon() -> Text<'static> {
    bootstrap_icon('\u{F1C5}')
}
