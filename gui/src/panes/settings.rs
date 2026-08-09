//! The Settings screen: a *single* working pane that replaces the list and
//! detail panes, rather than the two-pane split the item sections use.
//!
//! Like every other control in the prototype, nothing here is persisted — the
//! toggles live in [`State`] for the lifetime of the process. The theme picker
//! is the one exception that has a visible effect, since the whole point of
//! prototyping is to see the panes in both palettes.

use iced::widget::{checkbox, column, container, pick_list, row, rule, scrollable, text};
use iced::{Element, Length, Theme, alignment::Vertical};

use crate::{App, Message, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeChoice {
    Light,
    Dark,
}

impl ThemeChoice {
    pub const ALL: [ThemeChoice; 2] = [ThemeChoice::Light, ThemeChoice::Dark];

    pub fn theme(self) -> Theme {
        match self {
            ThemeChoice::Light => Theme::Light,
            ThemeChoice::Dark => Theme::Dark,
        }
    }
}

impl std::fmt::Display for ThemeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockTimeout {
    FiveMinutes,
    TenMinutes,
    ThirtyMinutes,
    Never,
}

impl LockTimeout {
    pub const ALL: [LockTimeout; 4] = [
        LockTimeout::FiveMinutes,
        LockTimeout::TenMinutes,
        LockTimeout::ThirtyMinutes,
        LockTimeout::Never,
    ];
}

impl std::fmt::Display for LockTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LockTimeout::FiveMinutes => "After 5 minutes",
            LockTimeout::TenMinutes => "After 10 minutes",
            LockTimeout::ThirtyMinutes => "After 30 minutes",
            LockTimeout::Never => "Never",
        })
    }
}

/// The screen's own state, mirroring how `src/screens/*` each own a `State`.
pub struct State {
    pub theme: ThemeChoice,
    pub lock_timeout: LockTimeout,
    pub minimize_to_tray: bool,
    pub show_hidden_by_default: bool,
    pub clear_clipboard: bool,
}

impl Default for State {
    fn default() -> Self {
        State {
            theme: ThemeChoice::Light,
            lock_timeout: LockTimeout::TenMinutes,
            minimize_to_tray: true,
            show_hidden_by_default: false,
            clear_clipboard: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    ThemeChanged(ThemeChoice),
    LockTimeoutChanged(LockTimeout),
    MinimizeToTrayToggled(bool),
    ShowHiddenToggled(bool),
    ClearClipboardToggled(bool),
}

pub fn update(state: &mut State, message: Msg) {
    match message {
        Msg::ThemeChanged(choice) => state.theme = choice,
        Msg::LockTimeoutChanged(timeout) => state.lock_timeout = timeout,
        Msg::MinimizeToTrayToggled(value) => state.minimize_to_tray = value,
        Msg::ShowHiddenToggled(value) => state.show_hidden_by_default = value,
        Msg::ClearClipboardToggled(value) => state.clear_clipboard = value,
    }
}

pub fn view(app: &App) -> Element<'_, Message> {
    let state = &app.settings;

    let appearance = theme::card(setting_row(
        "Theme",
        "Applies to the whole window.",
        pick_list(ThemeChoice::ALL, Some(state.theme), |choice| {
            Message::Settings(Msg::ThemeChanged(choice))
        })
        .text_size(13)
        .padding([4, 8])
        .into(),
    ));

    let security = theme::card(column![
        setting_row(
            "Lock the vault when idle",
            "Re-asks the security questions once the timeout passes.",
            pick_list(LockTimeout::ALL, Some(state.lock_timeout), |timeout| {
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
            state.clear_clipboard,
            Msg::ClearClipboardToggled,
        ),
    ]);

    let general = theme::card(column![
        toggle_row(
            "Minimize to the tray on close",
            "Closing the window keeps the vault open in the system tray.",
            state.minimize_to_tray,
            Msg::MinimizeToTrayToggled,
        ),
        hairline(),
        toggle_row(
            "Show hidden items by default",
            "Otherwise they only appear under the Hidden section.",
            state.show_hidden_by_default,
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
            text("Nothing on this screen is saved — the prototype keeps it in memory only.")
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
