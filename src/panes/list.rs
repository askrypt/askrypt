//! The middle pane: the scrolling item list with a pinned add button.

use iced::widget::{button, column, container, row, rule, scrollable, space, text};
use iced::{Element, Length, Theme, alignment::Vertical};

use askrypt::SecretEntry;

use crate::{App, Message, data, icon, theme};

pub fn view(app: &App) -> Element<'_, Message> {
    let rows = app.visible();

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
            items = items.push(row_widget(index, entry, app.selected == Some(index)));
        }
        scrollable(items)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    };

    let add = container(
        button(container(icon::plus_lg(16)).center_x(Length::Fill))
            .width(Length::Fill)
            .padding([8, 0])
            .style(button::subtle)
            .on_press(Message::AddEntry),
    )
    .padding(8);

    // The `Fill` wrapper around `body` is what keeps the add button pinned to
    // the bottom even in the empty state.
    container(
        column![
            container(body).width(Length::Fill).height(Length::Fill),
            rule::horizontal(1).style(theme::pane_divider),
            add,
        ]
        .height(Length::Fill),
    )
    .width(Length::Fixed(theme::LIST_WIDTH))
    .height(Length::Fill)
    .style(theme::list_background)
    .into()
}

fn row_widget(index: usize, entry: &SecretEntry, selected: bool) -> Element<'_, Message> {
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
    // gets `Visa •••• 4242` instead.
    let subtitle = if data::is_card(entry) {
        data::card_subtitle(entry)
    } else {
        entry.user_name.clone()
    };

    let labels = column![title, text(subtitle).size(12).style(text::secondary)].spacing(1);

    // A placeholder for the favicon a real item would carry; keyed by name so
    // it stays put across renders. A card has a real glyph already — the issuer
    // logo is what would replace it.
    let icon = if data::is_card(entry) {
        icon::credit_card(16)
    } else {
        icon::placeholder(&entry.name, 16)
    };
    let glyph = container(icon)
        .width(Length::Fixed(theme::ITEM_ICON_WIDTH))
        .center_y(Length::Fill);

    // `padding(0)` on the button is what lets the accent bar touch the row's
    // left edge; the inner container supplies the text's padding instead.
    button(
        row![
            accent,
            container(row![glyph, labels].spacing(10)).padding([6, 10])
        ]
        .height(Length::Fixed(theme::ROW_HEIGHT))
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding(0)
    .style(move |t, s| theme::list_row(t, s, selected))
    .on_press(Message::EntrySelected(index))
    .into()
}
