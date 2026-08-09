//! The right pane: read-only detail view of the selected item, with a pinned
//! action toolbar.

use iced::widget::{Row, Text, button, column, container, row, rule, scrollable, space, text};
use iced::{Element, Length, alignment::Vertical};

use crate::data::{self, Entry};
use crate::{App, Message, icon, theme};

/// Placeholder shown in place of a hidden password.
const DOTS: &str = "••••••••";

pub fn view(app: &App) -> Element<'_, Message> {
    let Some(entry) = app.selected_entry() else {
        return container(
            container(text("Select an item").size(14).style(text::secondary))
                .center_x(Length::Fill)
                .center_y(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into();
    };

    let mut content = column![
        text("ITEM INFORMATION").size(11).style(text::secondary),
        main_card(entry, app.revealed),
    ]
    .spacing(14)
    .padding(20)
    .width(Length::Fill);

    if let Some(card) = website_card(entry) {
        content = content.push(card);
    }

    content = content.push(
        row![
            text("Updated:").size(12).font(theme::bold()),
            text(data::format_timestamp_local(entry.modified)).size(12),
        ]
        .spacing(5),
    );

    let body = scrollable(content).width(Length::Fill).height(Length::Fill);

    let toolbar = container(
        row![
            icon_action(
                icon::pencil(14),
                "Edit",
                Message::Note("Edit — not implemented in the prototype"),
            ),
            icon_action(
                icon::files(14),
                "Duplicate",
                Message::Note("Duplicate — not implemented in the prototype"),
            ),
            // Eats the slack, pushing delete flush right.
            space().width(Length::Fill),
            danger_action(
                icon::trash(14),
                "Delete",
                Message::Note("Delete — not implemented in the prototype"),
            ),
        ]
        .spacing(8)
        .align_y(Vertical::Center),
    )
    .padding(8)
    .width(Length::Fill);

    container(
        column![
            body,
            rule::horizontal(1).style(theme::pane_divider),
            toolbar
        ]
        .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(theme::detail_background)
    .into()
}

/// Name / Username / Password, separated by hairlines.
fn main_card(entry: &Entry, revealed: bool) -> Element<'_, Message> {
    let password_actions = row![
        icon_action(
            icon::check_circle(14),
            "Check password",
            Message::Note("Password check — not implemented in the prototype"),
        ),
        icon_action(
            if revealed {
                icon::eye_slash(14)
            } else {
                icon::eye(14)
            },
            if revealed {
                "Hide password"
            } else {
                "Show password"
            },
            Message::ToggleReveal,
        ),
        icon_action(
            icon::copy(14),
            "Copy password",
            Message::Copy {
                what: "password",
                value: entry.secret.clone(),
            },
        ),
    ]
    .spacing(4);

    let password = if revealed {
        entry.secret.clone()
    } else {
        DOTS.to_string()
    };

    let mut fields = column![field_row("Name", text(&entry.name).size(14).into(), row![])];

    // An empty username would render as a labelled blank line; drop the whole
    // row instead, the way `src/screens/entries.rs` drops empty fields.
    if !entry.user_name.is_empty() {
        fields = fields.push(hairline());
        fields = fields.push(field_row(
            "Username",
            text(&entry.user_name).size(14).into(),
            row![icon_action(
                icon::copy(14),
                "Copy username",
                Message::Copy {
                    what: "username",
                    value: entry.user_name.clone(),
                },
            )],
        ));
    }

    fields = fields.push(hairline());
    fields = fields.push(field_row(
        "Password",
        text(password).size(14).into(),
        password_actions,
    ));

    theme::card(fields).into()
}

/// The Website card — absent entirely when the entry has no URL, mirroring
/// `src/screens/entries.rs`.
fn website_card(entry: &Entry) -> Option<Element<'_, Message>> {
    if entry.url.is_empty() {
        return None;
    }

    let value: Element<'_, Message> = if data::is_url(&entry.url) {
        theme::button_link(entry.url.clone(), "Open website", None)
            .on_press(Message::OpenUrl(entry.url.clone()))
            .into()
    } else {
        text(&entry.url).size(14).into()
    };

    let actions = row![
        icon_action(
            icon::box_arrow_up_right(14),
            "Open website",
            Message::OpenUrl(entry.url.clone()),
        ),
        icon_action(
            icon::copy(14),
            "Copy website",
            Message::Copy {
                what: "website",
                value: entry.url.clone(),
            },
        ),
    ]
    .spacing(4);

    Some(theme::card(field_row("Website", value, actions)).into())
}

fn field_row<'a>(
    label: &'a str,
    value: Element<'a, Message>,
    actions: Row<'a, Message>,
) -> Element<'a, Message> {
    container(
        row![
            column![text(label).size(11).style(text::secondary), value]
                .spacing(3)
                .width(Length::Fill),
            actions,
        ]
        .align_y(Vertical::Center),
    )
    .padding([10, 14])
    .width(Length::Fill)
    .into()
}

fn icon_action<'a>(glyph: Text<'a>, tip: &'static str, message: Message) -> Element<'a, Message> {
    theme::text_button_icon(glyph, tip).on_press(message).into()
}

/// Same, tinted red — used for the destructive action in the toolbar.
fn danger_action<'a>(glyph: Text<'a>, tip: &'static str, message: Message) -> Element<'a, Message> {
    theme::text_button_icon(glyph, tip)
        .style(|theme, status| button::Style {
            text_color: match status {
                button::Status::Hovered => theme.palette().danger,
                _ => theme.palette().danger.scale_alpha(0.8),
            },
            ..button::Style::default()
        })
        .on_press(message)
        .into()
}

fn hairline<'a>() -> Element<'a, Message> {
    rule::horizontal(1).style(theme::pane_divider).into()
}
