use crate::icon;
use iced::alignment::{Horizontal, Vertical};
use iced::widget::{
    Button, Column, Container, Row, Scrollable, Text, button, column, container, row, scrollable,
    text, text_input, tooltip,
};
use iced::{Element, Font, Length, Theme, alignment};

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
    button(text(label)).padding([7, 14])
}

pub fn control_button<Message: Clone, S: Into<String>>(label: S) -> Button<'static, Message> {
    button(text(label.into())).padding([5, 10])
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

/// Animated progress indicator with a caption (e.g. "Decrypting…"/"Locking…").
/// `frame` selects a spinner glyph; advance it on a timer to animate. Shown in
/// place of the unlock/lock controls while a background crypto task is running.
pub fn spinner_row<'a, T: 'a>(frame: usize, label: &'a str) -> Row<'a, T> {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let glyph = FRAMES[frame % FRAMES.len()];
    row![text(glyph).size(20), text(label.to_owned()).size(16)]
        .spacing(10)
        .align_y(Vertical::Center)
}

/// A centered large heading column (the title shown at the top of each screen).
pub fn title_h1<'a, M: 'a>(title: &str) -> Column<'a, M> {
    column![text(title.to_owned()).size(40)].spacing(10)
}

/// Wrap a row of controls with the standard spacing/padding used by the
/// fixed top-control sections of the entry/question screens.
pub fn controls_block<'a, M: 'a>(row: Row<'a, M>) -> Element<'a, M> {
    row.spacing(10).padding(10).width(Length::Fill).into()
}

/// A centered, scrollable caption block used for empty-state messages.
pub fn caption_block<'a, M: 'a>(caption: &str) -> Scrollable<'a, M> {
    scrollable(
        container(
            text(caption.to_owned())
                .width(Length::Fill)
                .size(15)
                .font(Font {
                    weight: iced::font::Weight::Bold,
                    ..Default::default()
                }),
        )
        .padding(20)
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
}

/// Wrap content in a full-width, rounded, bordered container.
pub fn container_with_border<'a, M: 'a>(item: Column<'a, M>) -> Container<'a, M> {
    container(item)
        .padding(10)
        .width(Length::Fill)
        .style(container_border_r5)
}

/// Creates a security input field with a toggle button to show/hide the input,
/// plus an optional "generate password" button.
#[allow(clippy::too_many_arguments)]
pub fn security_input_with_toggle<'a, M: Clone + 'static>(
    password: &str,
    show_password: bool,
    on_input_msg: Option<impl Fn(String) -> M + 'a>,
    on_submit_msg: Option<M>,
    toggle_msg: M,
    input_placeholder: &'a str,
    hide_tooltip: &'static str,
    show_tooltip: &'static str,
    on_generate_msg: Option<M>,
) -> Row<'a, M> {
    let button_icon = if show_password {
        icon::eye_slash_icon()
    } else {
        icon::eye_icon()
    };
    let toggle_button = tooltip(
        button(button_icon)
            .padding(11)
            .height(36)
            .style(button::subtle)
            .on_press(toggle_msg),
        if show_password {
            hide_tooltip
        } else {
            show_tooltip
        },
        tooltip::Position::Top,
    );

    let mut children: Vec<Element<'a, M>> = vec![
        text_input(input_placeholder, password)
            .on_input_maybe(on_input_msg)
            .on_submit_maybe(on_submit_msg)
            .padding(10)
            .width(Length::Fill)
            .secure(!show_password)
            .size(12)
            .into(),
        toggle_button.into(),
    ];

    if let Some(generate_msg) = on_generate_msg {
        children.push(
            tooltip(
                button(icon::magic_icon())
                    .padding(11)
                    .height(36)
                    .style(button::subtle)
                    .on_press(generate_msg),
                "Generate password",
                tooltip::Position::Top,
            )
            .into(),
        );
    }

    Row::with_children(children)
        .spacing(5)
        .align_y(alignment::Vertical::Center)
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
