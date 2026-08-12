//! The left navigation rail: item filters on top, the vault actions, then
//! Settings and Quit pinned at the bottom.
//!
//! The item filters exist only while the vault is unlocked — there is nothing
//! to filter otherwise — and each vault action is *hidden*, not disabled, when
//! the current state does not allow it. The rules live in
//! [`crate::manager::VaultState`]; this module only asks.

use iced::widget::{Text, button, column, container, row, rule, scrollable, text};
use iced::{Element, Length, alignment::Vertical};

use crate::data::{TYPE_CARD, TYPE_NOTE, make_hash_tag};
use crate::{App, GlobalMsg, Message, Pane, Section, VaultMsg, icon, theme};

pub fn view(app: &App) -> Element<'_, Message> {
    let vault = &app.session.vault;

    let items = if vault.is_unlocked() {
        filters(app)
    } else {
        let caption = if vault.is_open() {
            "Vault locked — unlock it to browse."
        } else {
            "No vault open."
        };
        column![container(text(caption).size(12).style(text::secondary)).padding([12, 10])]
            .width(Length::Fill)
    };

    // The scrollable eats the vertical slack, which both pins the action block
    // to the bottom edge and lets the tag list scroll once it outgrows the rail.
    let body = scrollable(items).width(Length::Fill).height(Length::Fill);

    container(column![body, pinned(app)].height(Length::Fill))
        .width(Length::Fixed(theme::SIDEBAR_WIDTH))
        .height(Length::Fill)
        .style(theme::sidebar_background)
        .into()
}

/// The item sections — only meaningful over decrypted entries.
fn filters(app: &App) -> iced::widget::Column<'_, Message> {
    let mut items = column![].spacing(2).padding([8, 8]).width(Length::Fill);

    let on_items = app.pane == Pane::Items;

    items = items.push(nav_row(
        icon::grid(14),
        "All Items".to_string(),
        Section::All,
        on_items && app.section == Section::All,
    ));
    items = items.push(nav_row(
        icon::eye_slash(14),
        "Hidden".to_string(),
        Section::Hidden,
        on_items && app.section == Section::Hidden,
    ));

    let types = app.types();
    if !types.is_empty() {
        items = items.push(section_header("TYPES"));
        for entry_type in types {
            let selected = on_items && app.section == Section::Type(entry_type.clone());
            items = items.push(nav_row(
                type_icon(&entry_type),
                entry_type.clone(),
                Section::Type(entry_type),
                selected,
            ));
        }
    }

    let tags = app.tags();
    if !tags.is_empty() {
        items = items.push(section_header("TAGS"));
        for tag in tags {
            let selected = on_items && app.section == Section::Tag(tag.clone());
            items = items.push(nav_row(
                icon::tag(14),
                make_hash_tag(&tag),
                Section::Tag(tag),
                selected,
            ));
        }
    }

    items
}

/// The vault actions, then Settings, then Quit. Which actions appear is the
/// whole readout of the vault's state.
fn pinned(app: &App) -> Element<'_, Message> {
    let vault = &app.session.vault;

    let mut actions = column![].spacing(2).width(Length::Fill);

    if vault.can_create() {
        actions = actions.push(action_row(
            icon::file_earmark_plus(14),
            "New Vault",
            Message::Vault(VaultMsg::New),
        ));
    }
    if vault.can_open() {
        actions = actions.push(action_row(
            icon::folder2_open(14),
            "Open Vault…",
            Message::Vault(VaultMsg::Open),
        ));
    }
    if vault.can_close() {
        actions = actions.push(action_row(
            icon::close(14),
            "Close Vault",
            Message::Vault(VaultMsg::Close),
        ));
    }
    if vault.can_unlock() {
        actions = actions.push(action_row(
            icon::unlock(14),
            "Unlock",
            Message::Vault(VaultMsg::Unlock),
        ));
    }
    if vault.can_smart_lock() {
        actions = actions.push(action_row(
            icon::shield_lock(14),
            "Smart Lock",
            Message::Vault(VaultMsg::SmartLock),
        ));
    }
    if vault.can_lock() {
        actions = actions.push(action_row(
            icon::lock(14),
            vault.lock_label(),
            Message::Vault(VaultMsg::Lock),
        ));
    }
    if vault.can_save() {
        actions = actions.push(action_row(
            icon::save(14),
            "Save",
            Message::Vault(VaultMsg::Save),
        ));
    }
    if vault.can_save_as() {
        actions = actions.push(action_row(
            icon::save2(14),
            "Save As…",
            Message::Vault(VaultMsg::SaveAs),
        ));
    }
    if vault.can_edit_questions() {
        actions = actions.push(action_row(
            icon::key(14),
            "Edit Questions",
            Message::Vault(VaultMsg::EditQuestions),
        ));
    }
    // The generator is useful with or without a vault open.
    actions = actions.push(action_row(
        icon::magic(14),
        "Password Generator",
        Message::Vault(VaultMsg::PassGen),
    ));

    // Settings and Quit sit below the vault actions, each in a band of its own:
    // they are the two rows that are never about the vault in front of you.
    // Quit is on the very bottom edge — it leaves the app rather than doing
    // anything to the vault, and a stray click on it is expensive.
    column![
        rule::horizontal(1).style(theme::pane_divider),
        container(actions).padding([6, 8]),
        rule::horizontal(1).style(theme::pane_divider),
        container(pane_row(
            icon::gear(14),
            "Settings",
            Pane::Settings,
            app.pane == Pane::Settings,
        ))
        .padding([6, 8]),
        rule::horizontal(1).style(theme::pane_divider),
        container(action_row(
            icon::power(14),
            "Quit",
            Message::Global(GlobalMsg::QuitRequested),
        ))
        .padding([6, 8]),
    ]
    .into()
}

fn nav_row<'a>(
    glyph: Text<'a>,
    label: String,
    target: Section,
    selected: bool,
) -> Element<'a, Message> {
    row_button(glyph, label, selected, Message::SectionSelected(target))
}

fn pane_row<'a>(
    glyph: Text<'a>,
    label: &'a str,
    target: Pane,
    selected: bool,
) -> Element<'a, Message> {
    row_button(
        glyph,
        label.to_string(),
        selected,
        Message::PaneSelected(target),
    )
}

/// A vault action: the same look as a nav row, but it never reads as selected —
/// pressing it starts something rather than switching a filter.
fn action_row<'a>(glyph: Text<'a>, label: &'a str, message: Message) -> Element<'a, Message> {
    row_button(glyph, label.to_string(), false, message)
}

fn row_button<'a>(
    glyph: Text<'a>,
    label: String,
    selected: bool,
    message: Message,
) -> Element<'a, Message> {
    button(
        row![glyph, text(label).size(14)]
            .spacing(8)
            .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding([6, 8])
    .style(move |t, s| theme::nav_button(t, s, selected))
    .on_press(message)
    .into()
}

fn section_header<'a>(label: &'a str) -> Element<'a, Message> {
    container(
        row![
            icon::chevron_down(10),
            text(label).size(11).style(text::secondary)
        ]
        .spacing(6)
        .align_y(Vertical::Center),
    )
    .padding([10, 8])
    .into()
}

fn type_icon(entry_type: &str) -> Text<'static> {
    match entry_type {
        TYPE_CARD => icon::credit_card(14),
        TYPE_NOTE => icon::journal_text(14),
        // TYPE_LOGIN and anything unrecognized.
        _ => icon::key(14),
    }
}
