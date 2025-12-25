use iced::Theme;
use iced::alignment::{Horizontal, Vertical};
use iced::widget::{Button, Container, Text, button, container, row, text, tooltip};

pub fn content<'a, T: 'a>(icon: Option<Text<'a>>, text: Text<'a>) -> Container<'a, T> {
    match icon {
        None => container(text).align_x(Horizontal::Center).padding(5),
        Some(icn) => container(row![icn, text].spacing(5).align_y(Vertical::Center))
            .align_x(Horizontal::Center),
    }
}

pub fn control_button_icon<'a, T: 'a>(icon: Text<'a>, t: &'static str) -> Button<'a, T> {
    Button::new(content(Some(icon), iced::widget::text(t)))
}

pub fn text_button_icon<'a, T: 'a>(icon: Text<'a>, tooltip: &'static str) -> Button<'a, T> {
    Button::new(iced::widget::tooltip(icon, tooltip, tooltip::Position::Top)).style(button::text)
}

pub fn padded_button<Message: Clone>(label: &str) -> Button<'_, Message> {
    button(text(label)).padding([10, 20])
}

pub fn control_button<Message: Clone, S: Into<String>>(label: S) -> Button<'static, Message> {
    button(text(label.into())).padding([5, 10])
}

pub fn icon_show_hide(show: bool) -> String {
    if show {
        "👁‍🗨".to_string()
    } else {
        "👁".to_string()
    }
}

pub fn container_border_r5(theme: &Theme) -> container::Style {
    container::Style {
        border: iced::Border {
            color: theme.palette().text,
            width: 1.0,
            radius: 5.0.into(),
        },
        background: Some(theme.palette().background.into()),
        ..Default::default()
    }
}
