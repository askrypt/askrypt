//! Styling for the prototype.
//!
//! The helpers in the first half are copied from `src/ui.rs` so the prototype
//! keeps the shipping app's look without the two crates sharing code; the
//! second half is new, pane-specific styling. The two are expected to diverge.

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{
    Button, Container, Row, Scrollable, Text, button, container, row, rule, scrollable, text,
};
use iced::{Element, Font, Length, Theme};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

pub const SIDEBAR_WIDTH: f32 = 200.0;
pub const LIST_WIDTH: f32 = 300.0;
pub const ROW_HEIGHT: f32 = 44.0;
/// Width of the accent bar on the selected list row.
pub const ACCENT_WIDTH: f32 = 3.0;
/// Column the item icon reserves, so every row's text starts on one line
/// whatever glyph it drew.
pub const ITEM_ICON_WIDTH: f32 = 20.0;

pub fn bold() -> Font {
    Font {
        weight: iced::font::Weight::Bold,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Copied from `src/ui.rs`
// ---------------------------------------------------------------------------

pub fn text_button_icon<'a, T: 'a>(icon: Text<'a>, tooltip: &'static str) -> Button<'a, T> {
    Button::new(iced::widget::tooltip(
        icon,
        tooltip,
        iced::widget::tooltip::Position::Top,
    ))
    .style(button::text)
    .padding(3)
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

/// Creates a button that looks like a link with an optional icon and tooltip.
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
        iced::widget::tooltip::Position::Top,
    ))
    .padding(0)
    .style(button_link_style)
}

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
        button::Status::Disabled => button::Style {
            background: base.background.map(|bg| bg.scale_alpha(0.5)),
            text_color: base.text_color.scale_alpha(0.5),
            ..base
        },
    }
}

/// A centered, scrollable caption block used for empty-state messages.
pub fn caption_block<'a, M: 'a>(caption: &str) -> Scrollable<'a, M> {
    scrollable(
        container(
            text(caption.to_owned())
                .width(Length::Fill)
                .size(15)
                .font(bold()),
        )
        .padding(20)
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
}

/// `frame` selects a spinner glyph; advance it on a timer to animate. Shown in
/// place of the unlock/save controls while a background crypto task runs.
pub fn spinner_row<'a, T: 'a>(frame: usize, label: &'a str) -> Row<'a, T> {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let glyph = FRAMES[frame % FRAMES.len()];
    row![text(glyph).size(20), text(label.to_owned()).size(16)]
        .spacing(10)
        .align_y(Vertical::Center)
}

/// Wrap content in a full-width, rounded, bordered container.
///
/// `src/ui.rs::container_with_border` takes a `Column` specifically, which
/// blocks reuse; this variant takes anything element-shaped and leaves padding
/// to the caller so hairline rules can run edge to edge.
pub fn card<'a, M: 'a>(item: impl Into<Element<'a, M>>) -> Container<'a, M> {
    container(item)
        .width(Length::Fill)
        .style(container_border_r5)
}

// ---------------------------------------------------------------------------
// Pane styling (new)
// ---------------------------------------------------------------------------

pub fn sidebar_background(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.extended_palette().background.weakest.color.into()),
        ..Default::default()
    }
}

pub fn list_background(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.palette().background.into()),
        ..Default::default()
    }
}

pub fn detail_background(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.extended_palette().background.weak.color.into()),
        ..Default::default()
    }
}

pub fn pane_divider(theme: &Theme) -> rule::Style {
    rule::weak(theme)
}

/// The always-visible bottom status bar — visually identical to
/// `src/screens/mod.rs::status_bar`.
pub fn status_bar_style(theme: &Theme) -> container::Style {
    container::Style {
        border: iced::Border {
            color: theme.extended_palette().background.neutral.color,
            width: 1.0,
            radius: 0.0.into(),
        },
        background: Some(theme.palette().background.into()),
        ..Default::default()
    }
}

/// Shared body of [`nav_button`] and [`list_row`]: square, tinted when
/// selected or hovered, accent-colored text when selected.
fn selectable_row(theme: &Theme, status: button::Status, selected: bool) -> button::Style {
    let palette = theme.extended_palette();

    let background = if selected {
        Some(palette.background.weak.color.into())
    } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
        Some(palette.background.weakest.color.into())
    } else {
        None
    };

    button::Style {
        background,
        text_color: if selected {
            palette.primary.strong.color
        } else {
            palette.background.base.text
        },
        border: iced::Border::default(),
        ..button::Style::default()
    }
}

pub fn nav_button(theme: &Theme, status: button::Status, selected: bool) -> button::Style {
    selectable_row(theme, status, selected)
}

pub fn list_row(theme: &Theme, status: button::Status, selected: bool) -> button::Style {
    selectable_row(theme, status, selected)
}

/// A wide, bordered, hoverable card — the wizard's source rows and the
/// recent-vault rows. Disabled rows (the cloud placeholder) fade instead of
/// disappearing, so the slot they reserve stays visible.
pub fn wizard_card(theme: &Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();

    let (background, border_color, text_color) = match status {
        button::Status::Hovered | button::Status::Pressed => (
            palette.background.weak.color,
            palette.primary.strong.color,
            palette.background.base.text,
        ),
        button::Status::Disabled => (
            palette.background.base.color,
            palette.background.neutral.color.scale_alpha(0.5),
            palette.background.base.text.scale_alpha(0.4),
        ),
        button::Status::Active => (
            palette.background.base.color,
            palette.background.neutral.color,
            palette.background.base.text,
        ),
    };

    button::Style {
        background: Some(background.into()),
        text_color,
        border: iced::Border {
            color: border_color,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::Style::default()
    }
}

/// The accent stripe down the left edge of the selected list row.
pub fn accent_bar(theme: &Theme, selected: bool) -> container::Style {
    container::Style {
        background: selected.then(|| theme.palette().primary.into()),
        ..Default::default()
    }
}
