//! The Settings pane: a *single* working pane that replaces the list and detail
//! panes, rather than the two-pane split the item sections use.
//!
//! There is no pane-local state — every control reads and writes
//! `session.settings`, which is persisted to `settings.json` on each change so a
//! crash cannot lose a preference the user just set.

use iced::widget::{checkbox, column, container, pick_list, row, rule, scrollable, text};
use iced::{Element, Length, alignment::Vertical};

use crate::panes::Action;
use crate::session::Session;
use crate::settings::{LockTimeout, ThemeChoice};
use crate::{App, Message, theme};

#[derive(Debug, Clone)]
pub enum Msg {
    ThemeChanged(ThemeChoice),
    LockTimeoutChanged(LockTimeout),
    MinimizeToTrayToggled(bool),
    ShowHiddenToggled(bool),
    ClearClipboardToggled(bool),
}

pub fn update(session: &mut Session, message: Msg) -> Action {
    match message {
        Msg::ThemeChanged(choice) => session.settings.theme = choice,
        Msg::LockTimeoutChanged(timeout) => session.settings.lock_timeout = timeout,
        Msg::MinimizeToTrayToggled(value) => session.settings.minimize_to_tray = value,
        Msg::ShowHiddenToggled(value) => session.settings.show_hidden_by_default = value,
        Msg::ClearClipboardToggled(value) => session.settings.clear_clipboard = value,
    }

    if let Err(e) = session.settings.save() {
        eprintln!("WARNING: Failed to save settings: {}", e);
        session.error_message = Some("Could not save your settings".into());
    }

    Action::None
}

pub fn view(app: &App) -> Element<'_, Message> {
    let settings = &app.session.settings;

    let appearance = theme::card(setting_row(
        "Theme",
        "Applies to the whole window.",
        pick_list(ThemeChoice::ALL, Some(settings.theme), |choice| {
            Message::Settings(Msg::ThemeChanged(choice))
        })
        .text_size(13)
        .padding([4, 8])
        .into(),
    ));

    let security = theme::card(column![
        setting_row(
            "Smart Lock the vault when idle",
            "Wipes the answers and holds them re-encrypted in memory; one answer re-opens it.",
            pick_list(LockTimeout::ALL, Some(settings.lock_timeout), |timeout| {
                Message::Settings(Msg::LockTimeoutChanged(timeout))
            })
            .text_size(13)
            .padding([4, 8])
            .into(),
        ),
        hairline(),
        toggle_row(
            "Clear the clipboard after copying",
            "Wipes a copied password 30 seconds later.",
            settings.clear_clipboard,
            Msg::ClearClipboardToggled,
        ),
    ]);

    let general = theme::card(column![
        toggle_row(
            "Minimize to the tray on close",
            "Closing the window keeps the vault open in the system tray.",
            settings.minimize_to_tray,
            Msg::MinimizeToTrayToggled,
        ),
        hairline(),
        toggle_row(
            "Show hidden items by default",
            "Otherwise they only appear under the Hidden section.",
            settings.show_hidden_by_default,
            Msg::ShowHiddenToggled,
        ),
    ]);

    let body = scrollable(
        column![
            text("SETTINGS").size(11).style(text::secondary),
            group("Appearance"),
            appearance,
            group("Security"),
            security,
            group("General"),
            general,
            text("Saved as you change them.")
                .size(12)
                .style(text::secondary),
        ]
        .spacing(14)
        .padding(20)
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill);

    // One pane filling the whole working area, in place of the list + detail
    // split the item sections use.
    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

fn group<'a>(label: &'a str) -> Element<'a, Message> {
    text(label).size(13).font(theme::bold()).into()
}

/// A label + description on the left, a control flush right.
fn setting_row<'a>(
    label: &'a str,
    description: &'a str,
    control: Element<'a, Message>,
) -> Element<'a, Message> {
    container(
        row![
            column![
                text(label).size(14),
                text(description).size(11).style(text::secondary),
            ]
            .spacing(3)
            .width(Length::Fill),
            control,
        ]
        .spacing(12)
        .align_y(Vertical::Center),
    )
    .padding([10, 14])
    .width(Length::Fill)
    .into()
}

fn toggle_row<'a>(
    label: &'a str,
    description: &'a str,
    value: bool,
    to_message: fn(bool) -> Msg,
) -> Element<'a, Message> {
    setting_row(
        label,
        description,
        checkbox(value)
            .size(16)
            .on_toggle(move |v| Message::Settings(to_message(v)))
            .into(),
    )
}

fn hairline<'a>() -> Element<'a, Message> {
    rule::horizontal(1).style(theme::pane_divider).into()
}
