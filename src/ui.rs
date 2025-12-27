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
    Button::new(iced::widget::tooltip(icon, tooltip, tooltip::Position::Top))
        .style(button::text)
        .padding(3)
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

/// Creates a button that looks like a link with an optional icon and tooltip
pub fn button_link<'a, T: 'a, S: Into<String>>(
    t: S,
    tooltip: &'static str,
    icon: Option<Text<'a>>,
) -> Button<'a, T> {
    let row = row![text(t.into()), icon]
        .spacing(3)
        .align_y(Vertical::Center);
    let content = container(row).align_x(Horizontal::Left);
    Button::new(iced::widget::tooltip(
        content,
        tooltip,
        tooltip::Position::Top,
    ))
    .padding(0)
    .style(button_link_style)
}

/// Style for link-like buttons
fn button_link_style(theme: &Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    let base = button::Style::default();

    match status {
        button::Status::Active | button::Status::Pressed => button::Style {
            text_color: palette.primary.strong.color.scale_alpha(0.8),
            ..base
        },
        button::Status::Hovered => button::Style {
            text_color: palette.primary.strong.color,
            ..base
        },
        button::Status::Disabled => disabled(base),
    }
}

fn disabled(style: button::Style) -> button::Style {
    button::Style {
        background: style
            .background
            .map(|background| background.scale_alpha(0.5)),
        text_color: style.text_color.scale_alpha(0.5),
        ..style
    }
}
