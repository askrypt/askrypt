//! The middle pane: the scrolling item list with a pinned add button, and the
//! ⋯ menu that switches it into selecting mode.
//!
//! ## Selecting mode
//!
//! Off by default. While it is on, a row click checks or unchecks the row
//! instead of opening it, the detail pane shows a summary rather than any one
//! item — so no secret is on screen while the user is picking — and the menu's
//! bulk actions come alive. [`State::checked`] addresses `session.entries`
//! exactly as `App.selected` does, and `App::reconcile_selection` keeps it a
//! subset of the visible rows: Delete never removes an item the list is not
//! showing.

use std::collections::BTreeSet;

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{
    Text, button, column, container, mouse_area, opaque, row, rule, scrollable, space, stack, text,
};
use iced::{Element, Length, Theme};

use askrypt::SecretEntry;

use crate::{App, Message, data, icon, theme};

/// Height of the strip above the rows holding the count and the ⋯ button.
const HEADER_HEIGHT: f32 = 32.0;
const MENU_WIDTH: f32 = 200.0;

#[derive(Debug, Default)]
pub struct State {
    /// The ⋯ popover is open.
    pub menu_open: bool,
    pub selecting: bool,
    /// Indices into `session.entries`, like `App.selected` — not into the
    /// filtered view.
    pub checked: BTreeSet<usize>,
}

impl State {
    /// Back to the default: menu closed, selecting mode off, nothing checked.
    pub fn reset(&mut self) {
        *self = State::default();
    }

    /// Drop checks on rows the list no longer shows.
    pub fn retain_visible(&mut self, visible: &[usize]) {
        self.checked.retain(|index| visible.contains(index));
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    ToggleMenu,
    CloseMenu,
    ToggleSelecting,
    ToggleChecked(usize),
    SelectAllVisible,
    ClearChecked,
    /// Put the checked items — or, outside selecting mode, the open one — on
    /// the clipboard as an `askrypt.json`.
    Copy,
    /// Ask, then delete every checked item.
    DeleteChecked,
}

pub fn view(app: &App) -> Element<'_, Message> {
    let rows = app.visible();
    let state = &app.list;

    let caption = if state.selecting {
        format!("{} selected", state.checked.len())
    } else {
        match rows.len() {
            1 => "1 item".to_string(),
            n => format!("{n} items"),
        }
    };
    let header = container(
        row![
            text(caption).size(12).style(text::secondary),
            space().width(Length::Fill),
            theme::text_button_icon(icon::three_dots_vertical(14), "More")
                .on_press(Message::List(Msg::ToggleMenu)),
        ]
        .align_y(Vertical::Center),
    )
    .padding([0, 8])
    .height(Length::Fixed(HEADER_HEIGHT))
    .center_y(Length::Fixed(HEADER_HEIGHT));

    let body: Element<'_, Message> = if rows.is_empty() {
        // A brand-new vault has nothing in it yet, which is a different empty
        // state from a filter that matched nothing.
        theme::caption_block(if app.session.entries().is_empty() {
            "This vault is empty — add the first item."
        } else {
            "No items match the filter criteria."
        })
        .into()
    } else {
        let mut items = column![].width(Length::Fill);
        for (index, entry) in rows {
            let mark = if state.selecting {
                Mark::Check(state.checked.contains(&index))
            } else {
                Mark::Plain(app.selected == Some(index))
            };
            items = items.push(row_widget(index, entry, mark));
        }
        scrollable(items)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    };

    // The `Fill` wrapper around `body` is what keeps the add button pinned to
    // the bottom even in the empty state. The add button goes while selecting:
    // the editor and selecting mode never share the window.
    let mut content = column![
        header,
        rule::horizontal(1).style(theme::pane_divider),
        container(body).width(Length::Fill).height(Length::Fill),
    ]
    .height(Length::Fill);
    if !state.selecting {
        let add: Element<'_, Message> = container(
            button(container(icon::plus_lg(16)).center_x(Length::Fill))
                .width(Length::Fill)
                .padding([8, 0])
                .style(button::subtle)
                .on_press(Message::AddEntry),
        )
        .padding(8)
        .into();
        content = content
            .push(rule::horizontal(1).style(theme::pane_divider))
            .push(add);
    }

    let pane: Element<'_, Message> = if state.menu_open {
        // A click anywhere else on the list closes the menu; the menu itself is
        // `opaque` so its own clicks never reach that catcher.
        stack![
            content,
            mouse_area(container(space()).width(Length::Fill).height(Length::Fill))
                .on_press(Message::List(Msg::CloseMenu)),
            container(opaque(menu(state, app.copy_targets().is_some())))
                .width(Length::Fill)
                .align_x(Horizontal::Right)
                .padding(iced::Padding {
                    top: HEADER_HEIGHT,
                    right: 8.0,
                    bottom: 0.0,
                    left: 0.0,
                }),
        ]
        .into()
    } else {
        content.into()
    };

    container(pane)
        .width(Length::Fixed(theme::LIST_WIDTH))
        .height(Length::Fill)
        .style(theme::list_background)
        .into()
}

/// The ⋯ popover. The bulk actions are shown but inert until they can act, so
/// the user can see what selecting mode is for before turning it on.
fn menu(state: &State, can_copy: bool) -> Element<'_, Message> {
    let any = !state.checked.is_empty();
    let selecting = state.selecting;

    let toggle = menu_item(
        if selecting {
            icon::check_square_fill(14)
        } else {
            icon::square(14)
        },
        "Selecting mode",
        Some(Msg::ToggleSelecting),
        None,
        false,
    );

    theme::card(
        column![
            toggle,
            rule::horizontal(1).style(theme::pane_divider),
            menu_item(
                icon::check_square_fill(14),
                "Select all visible",
                selecting.then_some(Msg::SelectAllVisible),
                None,
                false,
            ),
            menu_item(
                icon::square(14),
                "Clear selection",
                (selecting && any).then_some(Msg::ClearChecked),
                None,
                false,
            ),
            menu_item(
                icon::copy(14),
                "Copy",
                can_copy.then_some(Msg::Copy),
                Some("Ctrl+C"),
                false,
            ),
            menu_item(
                icon::trash(14),
                "Delete",
                (selecting && any).then_some(Msg::DeleteChecked),
                None,
                true,
            ),
        ]
        .spacing(2)
        .padding(4),
    )
    .width(Length::Fixed(MENU_WIDTH))
    .into()
}

fn menu_item<'a>(
    glyph: Text<'a>,
    label: &'a str,
    msg: Option<Msg>,
    shortcut: Option<&'a str>,
    danger: bool,
) -> Element<'a, Message> {
    let mut content = row![
        container(glyph).width(Length::Fixed(theme::ITEM_ICON_WIDTH)),
        text(label).size(13),
    ]
    .spacing(8)
    .align_y(Vertical::Center);
    if let Some(shortcut) = shortcut {
        content = content
            .push(space().width(Length::Fill))
            .push(text(shortcut).size(11).style(text::secondary));
    }
    button(content)
        .width(Length::Fill)
        .padding([6, 8])
        .style(move |t: &Theme, status| {
            let base = button::subtle(t, status);
            if danger && status != button::Status::Disabled {
                button::Style {
                    text_color: t.palette().danger,
                    ..base
                }
            } else {
                base
            }
        })
        .on_press_maybe(msg.map(Message::List))
        .into()
}

/// How a row marks itself: the accent bar of the open item, or a checkbox.
#[derive(Clone, Copy)]
enum Mark {
    Plain(bool),
    Check(bool),
}

fn row_widget(index: usize, entry: &SecretEntry, mark: Mark) -> Element<'_, Message> {
    let selected = match mark {
        Mark::Plain(on) | Mark::Check(on) => on,
    };
    let accent = container(space())
        .width(Length::Fixed(theme::ACCENT_WIDTH))
        .height(Length::Fill)
        .style(move |t: &Theme| theme::accent_bar(t, selected));

    let mut title = row![text(&entry.name).size(14).font(theme::bold())]
        .spacing(6)
        .align_y(Vertical::Center);
    if entry.hidden {
        title = title.push(text("hidden").size(11).style(text::secondary));
    }

    // A card leaves `user_name` empty, so the second line would be blank; it
    // gets `Visa •••• 4242` instead, and a File entry gets what it holds. The
    // count rather than the first file name: a list row is glanced at, and one
    // name out of several says less than how many there are.
    let subtitle = if data::is_card(entry) {
        data::card_subtitle(entry)
    } else if data::is_file(entry) {
        match entry.attachments.len() {
            0 => "No files".to_string(),
            1 => "1 file".to_string(),
            n => format!("{n} files"),
        }
    } else {
        entry.user_name.clone()
    };

    let labels = column![title, text(subtitle).size(12).style(text::secondary)].spacing(1);

    // What the item's tags say it is first, then its name and URL — Google's
    // mark on *Google*, a bank on *Sberbank* — falling back to the hashed pool
    // when they all say nothing. A File is exempt: its subtitle only counts the
    // files, so the paperclip is the one thing marking it. A Card falls back to
    // the generic card instead of the pool, so a name that matched nothing
    // still reads as a card.
    let icon = if data::is_file(entry) {
        icon::paperclip(16)
    } else if data::is_card(entry) {
        icon::card(&entry.name, &entry.url, &entry.tags, 16)
    } else {
        icon::item(&entry.name, &entry.url, &entry.tags, 16)
    };
    let glyph = container(icon)
        .width(Length::Fixed(theme::ITEM_ICON_WIDTH))
        .center_y(Length::Fill);

    // `padding(0)` on the button is what lets the accent bar touch the row's
    // left edge; the inner container supplies the text's padding instead.
    let mut inner = row![].spacing(10).align_y(Vertical::Center);
    let press = match mark {
        Mark::Plain(_) => Message::EntrySelected(index),
        Mark::Check(checked) => {
            inner = inner.push(
                container(if checked {
                    icon::check_square_fill(14)
                } else {
                    icon::square(14)
                })
                .width(Length::Fixed(theme::ITEM_ICON_WIDTH))
                .center_y(Length::Fill),
            );
            Message::List(Msg::ToggleChecked(index))
        }
    };
    let inner = inner.push(glyph).push(labels);

    button(
        row![accent, container(inner).padding([6, 10])]
            .height(Length::Fixed(theme::ROW_HEIGHT))
            .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding(0)
    .style(move |t, s| theme::list_row(t, s, selected))
    .on_press(press)
    .into()
}

#[cfg(test)]
mod tests {
    use super::State;

    #[test]
    fn checks_on_rows_the_filter_hides_are_dropped() {
        let mut state = State::default();
        state.checked.extend([0, 2, 5]);
        state.retain_visible(&[2, 3, 4]);
        assert_eq!(state.checked.into_iter().collect::<Vec<_>>(), vec![2]);
    }
}
