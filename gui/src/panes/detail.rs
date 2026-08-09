//! The right pane: read-only detail view of the selected item, with a pinned
//! action toolbar.

use iced::widget::{Row, Text, button, column, container, row, rule, scrollable, space, text};
use iced::{Element, Length, alignment::Vertical};

use askrypt::SecretEntry;

use crate::data;
use crate::{App, Message, icon, theme};

/// Placeholder shown in place of a hidden password.
const DOTS: &str = "••••••••";

pub fn view(app: &App) -> Element<'_, Message> {
    let Some(index) = app.selected else {
        return empty_pane();
    };
    let Some(entry) = app.selected_entry() else {
        return empty_pane();
    };

    let mut content = column![
        text("ITEM INFORMATION").size(11).style(text::secondary),
        main_card(entry, app.revealed),
    ]
    .spacing(14)
    .padding(20)
    .width(Length::Fill);

    if !entry.notes.is_empty() {
        content = content.push(theme::card(field_row(
            "Notes",
            text(&entry.notes).size(14).into(),
            row![icon_action(
                icon::copy(14),
                "Copy notes",
                Message::Copy {
                    what: "notes",
                    value: entry.notes.clone(),
                },
            )],
        )));
    }

    if !entry.tags.is_empty() {
        let mut tags = row![].spacing(6).align_y(Vertical::Center);
        for tag in &entry.tags {
            tags = tags.push(
                theme::button_link(data::make_hash_tag(tag), "Filter by this tag", None)
                    .on_press(Message::SectionSelected(crate::Section::Tag(tag.clone()))),
            );
        }
        content = content.push(theme::card(field_row("Tags", tags.into(), row![])));
    }

    if let Some(card) = website_card(entry) {
        content = content.push(card);
    }

    content = content.push(
        column![
            stamp_row("Created:", entry.created),
            stamp_row("Updated:", entry.modified),
        ]
        .spacing(3),
    );

    let body = scrollable(content).width(Length::Fill).height(Length::Fill);

    // Deleting takes two presses: the first arms the button, the second commits.
    let armed = app.pending_delete == Some(index);

    let toolbar = container(
        row![
            icon_action(icon::pencil(14), "Edit", Message::EditEntry(index)),
            icon_action(icon::files(14), "Duplicate", Message::DuplicateEntry(index)),
            // Eats the slack, pushing delete flush right.
            space().width(Length::Fill),
            if armed {
                Element::from(
                    button(text("Confirm delete").size(13))
                        .padding([4, 10])
                        .style(button::danger)
                        .on_press(Message::DeleteEntry(index)),
                )
            } else {
                danger_action(icon::trash(14), "Delete", Message::DeleteEntry(index))
            },
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

fn empty_pane<'a>() -> Element<'a, Message> {
    container(
        container(text("Select an item").size(14).style(text::secondary))
            .center_x(Length::Fill)
            .center_y(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(theme::detail_background)
    .into()
}

/// Name / Username / Password, separated by hairlines.
fn main_card(entry: &SecretEntry, revealed: bool) -> Element<'_, Message> {
    let password_actions = row![
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
fn website_card(entry: &SecretEntry) -> Option<Element<'_, Message>> {
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

/// A labelled timestamp line at the foot of the pane.
fn stamp_row<'a>(label: &'a str, timestamp: i64) -> Element<'a, Message> {
    row![
        text(label).size(12).font(theme::bold()),
        text(data::format_timestamp_local(timestamp)).size(12),
    ]
    .spacing(5)
    .into()
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
