//! The entry editor: a draft item, edited in place of the detail pane.
//!
//! It replaces the right-hand pane rather than the whole working area, so the
//! list stays visible while an item is being written.
//!
//! The rules are the long-standing ones: the name is required, tags are a
//! comma-separated string split on save, `modified` is stamped and `created` is
//! preserved. Nothing here touches storage; saving edits `session.entries` and
//! marks the vault dirty, and the vault is written only by an explicit Save.

use std::path::PathBuf;

use askrypt::SecretEntry;
use iced::widget::{
    button, checkbox, column, container, pick_list, row, scrollable, text, text_editor, text_input,
};
use iced::{Element, Length, Task, alignment::Vertical};

use crate::panes::Action;
use crate::session::Session;
use crate::{Message, Pane, data, icon, manager, theme};

const NAME_INPUT_ID: &str = "GUI_EDITOR_NAME";

/// Notes get a fixed box — the editor sits inside a `scrollable`, so a growing
/// one would fight the outer scroll; it scrolls within itself instead.
const NOTES_HEIGHT: f32 = 120.0;

pub struct State {
    /// `None` for a new item; otherwise the index in `session.entries` this
    /// draft came from.
    index: Option<usize>,
    /// The draft. `SecretEntry` is `ZeroizeOnDrop`, so the typed secret is wiped
    /// when the editor closes.
    ///
    /// `entry.notes` is *not* live while the editor is open — the notes are a
    /// multi-line `text_editor`, which owns its own buffer; `save` folds it
    /// back in.
    entry: SecretEntry,
    /// Notes as the user types them. A `text_editor` rather than a
    /// `text_input`, so a note can be several lines. Its buffer is
    /// cosmic-text's and cannot be zeroized the way `entry.notes` is — a note
    /// typed here outlives the editor in freed memory.
    notes: text_editor::Content,
    /// Tags as the user types them, comma-separated. Split on save.
    tags: String,
    /// The password, or — on a card — the number and the PIN.
    revealed: bool,
    /// The card's CVV, revealed on its own: it is the one card field you
    /// routinely need to read while the number stays covered.
    cvv_revealed: bool,
    error: Option<String>,
}

impl State {
    pub fn new() -> Self {
        State {
            index: None,
            entry: data::new_entry(),
            notes: text_editor::Content::new(),
            tags: String::new(),
            revealed: false,
            cvv_revealed: false,
            error: None,
        }
    }

    pub fn edit(entry: SecretEntry, index: usize) -> Self {
        State {
            tags: entry.tags.join(", "),
            notes: text_editor::Content::with_text(&entry.notes),
            index: Some(index),
            entry,
            revealed: false,
            cvv_revealed: false,
            error: None,
        }
    }

    /// A copy of an existing item, saved as a *new* one.
    pub fn duplicate(entry: SecretEntry) -> Self {
        let mut copy = Self::edit(entry, 0);
        copy.index = None;
        copy.entry.name = format!("{} (copy)", copy.entry.name);
        copy.revealed = false;
        copy.cvv_revealed = false;
        copy
    }

    /// Called when the password generator hands one back. The field stays
    /// masked: the password is already on the clipboard, so showing it only
    /// puts a fresh secret on screen for whoever is behind the user.
    pub fn set_secret(&mut self, secret: String) {
        self.entry.secret = secret;
        self.revealed = false;
    }

    fn is_new(&self) -> bool {
        self.index.is_none()
    }
}

/// Longest card number in circulation (UnionPay); Visa/Mastercard are 16 and
/// Amex 15.
const MAX_CARD_DIGITS: usize = 19;
/// `MM/YY`.
const MAX_EXPIRY_CHARS: usize = 5;
const MAX_CVV_DIGITS: usize = 4;
const MAX_PIN_DIGITS: usize = 12;

#[derive(Debug, Clone)]
pub enum Msg {
    NameEdited(String),
    UserNameEdited(String),
    SecretEdited(String),
    UrlEdited(String),
    NotesAction(text_editor::Action),
    TagsEdited(String),
    TypeSelected(String),
    HiddenToggled(bool),
    CardHolderEdited(String),
    CardBrandSelected(String),
    CardNumberEdited(String),
    CardExpiryEdited(String),
    CardCvvEdited(String),
    CardPinEdited(String),
    ToggleReveal,
    ToggleCvvReveal,
    /// Open the file picker to attach a file to this draft.
    AttachFile,
    /// The picker closed. `None` is a cancel.
    FilePicked(Option<PathBuf>),
    /// The worker finished reading and encrypting the file.
    Attached(Box<Result<manager::Attached, String>>),
    /// Drop an attachment from this draft, by id.
    RemoveAttachment(String),
    Save,
    Cancel,
}

/// Returns the action plus whether the editor should close.
pub fn update(state: &mut State, session: &mut Session, message: Msg) -> (Action, bool) {
    match message {
        Msg::NameEdited(value) => {
            state.entry.name = value;
            state.error = None;
            (Action::None, false)
        }
        Msg::UserNameEdited(value) => {
            state.entry.user_name = value;
            (Action::None, false)
        }
        Msg::SecretEdited(value) => {
            state.entry.secret = value;
            (Action::None, false)
        }
        Msg::UrlEdited(value) => {
            state.entry.url = value;
            (Action::None, false)
        }
        // Selections, clicks and scrolling are actions too, so the whole enum
        // goes to the content; `save` is what reads the text back out.
        Msg::NotesAction(action) => {
            state.notes.perform(action);
            (Action::None, false)
        }
        Msg::TagsEdited(value) => {
            state.tags = value;
            (Action::None, false)
        }
        // Only the *form* changes. Whatever was typed into the fields the new
        // type does not show stays on the draft and is written by `save`, so
        // Login → Card → Login gives back the password rather than eating it.
        Msg::TypeSelected(value) => {
            state.entry.entry_type = value;
            (Action::None, false)
        }
        Msg::HiddenToggled(value) => {
            state.entry.hidden = value;
            (Action::None, false)
        }
        // The dialog first, the work second: cancelling then costs nothing and
        // never leaves a decrypted copy of anything behind.
        Msg::AttachFile => (
            Action::Run(Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Attach a file to this item")
                        .pick_file()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                |picked| Message::Editor(Msg::FilePicked(picked)),
            )),
            false,
        ),
        Msg::FilePicked(None) => (Action::None, false),
        Msg::FilePicked(Some(path)) => {
            // The key comes off the open vault, not out of the draft: an
            // attachment lives under the vault's master key, which is why that
            // key is preserved for the vault's whole life.
            let Some(vault) = session.vault.unlocked() else {
                state.error = Some("The vault is not unlocked".to_string());
                return (Action::None, false);
            };
            // A cloud vault has a hard ceiling the server enforces, and finding
            // out at save time would mean the user cannot save at all until
            // they work out which file to drop. Said here, before any work,
            // nothing has happened yet. A local vault is uncapped: it is
            // streamed to disk now and never held in memory.
            if let Err(message) = room_for(&path, vault) {
                state.error = Some(message);
                return (Action::None, false);
            }

            let Some(scratch) = session.scratch.clone() else {
                state.error = Some(
                    "Files cannot be attached: this system offers no cache directory to encrypt \
                     them into."
                        .to_string(),
                );
                return (Action::None, false);
            };
            let inputs = manager::AttachInputs {
                dest: scratch.sealed_path(),
                path,
                master: vault.master().clone(),
            };
            session.begin_work("Encrypting file…");
            (
                Action::Run(Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || inputs.run())
                            .await
                            .expect("attachment task panicked")
                    },
                    |result| Message::Editor(Msg::Attached(Box::new(result))),
                )),
                false,
            )
        }
        Msg::Attached(result) => {
            session.finish_work();
            match *result {
                Ok(attached) => {
                    // The bytes go to the vault and the reference to the draft.
                    // Filing the bytes does not make the vault dirty — applying
                    // the item does — so cancelling out of here leaves an orphan
                    // that the next save's prune collects.
                    let Some(vault) = session.vault.unlocked_mut() else {
                        state.error = Some("The vault is not unlocked".to_string());
                        return (Action::None, false);
                    };
                    vault.add_attachment(attached.attachment.id.clone(), attached.sealed);
                    // An unnamed item takes the file's name, extension and all:
                    // an attachment is most of what a `File` entry is, and the
                    // save below would refuse a blank name anyway. Only when the
                    // field is empty, so nothing the user typed is overwritten.
                    if state.entry.name.trim().is_empty() {
                        state.entry.name = attached.attachment.name.clone();
                    }
                    state.entry.attachments.push(attached.attachment);
                    state.error = None;
                }
                Err(message) => state.error = Some(message),
            }
            (Action::None, false)
        }
        // Only the reference is dropped here. The blob stays until a save
        // prunes it, so cancelling the editor puts the file back.
        Msg::RemoveAttachment(id) => {
            state.entry.attachments.retain(|file| file.id != id);
            (Action::None, false)
        }
        Msg::CardHolderEdited(value) => {
            state.entry.card.holder = value;
            (Action::None, false)
        }
        Msg::CardBrandSelected(value) => {
            state.entry.card.brand = value;
            (Action::None, false)
        }
        // The four below filter what they accept here rather than in the view,
        // so a paste is cleaned up exactly like a keystroke.
        Msg::CardNumberEdited(value) => {
            state.entry.card.number = keep_number(&value);
            (Action::None, false)
        }
        Msg::CardExpiryEdited(value) => {
            state.entry.card.expiry = keep_expiry(&value);
            (Action::None, false)
        }
        Msg::CardCvvEdited(value) => {
            state.entry.card.cvv = keep_digits(&value, MAX_CVV_DIGITS);
            (Action::None, false)
        }
        Msg::CardPinEdited(value) => {
            state.entry.card.pin = keep_digits(&value, MAX_PIN_DIGITS);
            (Action::None, false)
        }
        Msg::ToggleReveal => {
            state.revealed = !state.revealed;
            (Action::None, false)
        }
        Msg::ToggleCvvReveal => {
            state.cvv_revealed = !state.cvv_revealed;
            (Action::None, false)
        }
        Msg::Save => save(state, session),
        Msg::Cancel => (Action::Pane(Pane::Items), true),
    }
}

/// Digits only, capped.
fn keep_digits(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(char::is_ascii_digit)
        .take(max)
        .collect()
}

/// Digits and the spaces a card number is usually typed with. The cap counts
/// *digits*, so grouping spaces never cost the user a digit.
fn keep_number(value: &str) -> String {
    let mut digits = 0;
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == ' ')
        .take_while(|c| {
            if c.is_ascii_digit() {
                digits += 1;
            }
            digits <= MAX_CARD_DIGITS
        })
        .collect()
}

/// Digits and the `MM/YY` separator.
///
/// The `/` is deliberately not inserted automatically: an auto-inserted
/// separator fights backspace, and the placeholder carries the format anyway.
fn keep_expiry(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '/')
        .take(MAX_EXPIRY_CHARS)
        .collect()
}

fn save(state: &mut State, session: &mut Session) -> (Action, bool) {
    if state.entry.name.trim().is_empty() {
        state.error = Some("Item name cannot be empty".to_string());
        return (Action::None, false);
    }

    let mut entry = state.entry.clone();
    entry.notes = state.notes.text();
    entry.tags = state
        .tags
        .split(',')
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect();
    entry.modified = chrono::Utc::now().timestamp();

    // Only an unlocked vault has an item list to save into, and it is the one
    // that marks itself modified — there is no separate flag to remember.
    let Some(vault) = session.vault.unlocked_mut() else {
        state.error = Some("The vault is not unlocked".to_string());
        return (Action::None, false);
    };
    match state.index {
        // A stale index means the list changed under the draft; append rather
        // than overwrite whatever moved into that slot.
        Some(index) if index < vault.entries().len() => vault.update_entry(index, entry),
        _ => {
            vault.add_entry(entry);
        }
    }

    session.success_message = Some(if state.is_new() {
        "Item added".to_string()
    } else {
        "Item saved".to_string()
    });

    (Action::Pane(Pane::Items), true)
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

pub fn view<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let heading = if state.is_new() {
        "NEW ITEM"
    } else {
        "EDIT ITEM"
    };

    let mut body = column![
        text(heading).size(11).style(text::secondary),
        field(
            "Name",
            text_input("Item name", &state.entry.name)
                .id(NAME_INPUT_ID)
                .on_input(|value| Message::Editor(Msg::NameEdited(value)))
                .on_submit(Message::Editor(Msg::Save))
                .padding(8)
                .size(14)
                .into(),
        ),
        field(
            "Type",
            pick_list(
                data::ENTRY_TYPES.map(str::to_string).to_vec(),
                Some(state.entry.entry_type.clone()),
                |choice| Message::Editor(Msg::TypeSelected(choice)),
            )
            .width(Length::Fill)
            .text_size(13)
            .padding([4, 8])
            .into(),
        ),
    ]
    .spacing(12)
    .padding(20)
    .max_width(560);

    // The Type picker chooses the middle of the form. Nothing typed into the
    // other set is cleared — `save` writes the whole draft — so switching back
    // brings it all with it.
    for control in if data::is_card(&state.entry) {
        card_fields(state)
    } else if data::is_file(&state.entry) {
        // A File entry has no middle: its name, notes and attachments are the
        // whole of it, and all three are drawn outside this branch.
        Vec::new()
    } else {
        login_fields(state)
    } {
        body = body.push(control);
    }

    body = body.push(
        column![
            field(
                "Tags",
                text_input("work, personal", &state.tags)
                    .on_input(|value| Message::Editor(Msg::TagsEdited(value)))
                    .padding(8)
                    .size(14)
                    .into(),
            ),
            field(
                "Notes",
                text_editor(&state.notes)
                    .placeholder("Anything else worth keeping with this item")
                    .on_action(|action| Message::Editor(Msg::NotesAction(action)))
                    .height(NOTES_HEIGHT)
                    .padding(8)
                    .size(14)
                    .into(),
            ),
            checkbox(state.entry.hidden)
                .label("Hidden item")
                .size(16)
                .text_size(13)
                .on_toggle(|value| Message::Editor(Msg::HiddenToggled(value))),
        ]
        .spacing(12),
    );

    body = body.push(attachments_section(state, session));

    if let Some(error) = &state.error {
        body = body.push(text(error.clone()).size(12).style(text::danger));
    }

    if !state.is_new() {
        body = body.push(
            text(format!(
                "Created {} · last changed {}",
                data::format_timestamp_local(state.entry.created),
                data::format_timestamp_local(state.entry.modified),
            ))
            .size(11)
            .style(text::secondary),
        );
    }

    body = body.push(
        row![
            button(text("Apply item").size(14))
                .padding([8, 16])
                .on_press(Message::Editor(Msg::Save)),
            button(text("Cancel").size(14))
                .padding([8, 16])
                .style(button::secondary)
                .on_press(Message::Editor(Msg::Cancel)),
        ]
        .spacing(10),
    );

    // The vault is only written by an explicit Save; say so, since the item
    // itself looks saved the moment it appears in the list.
    if session.vault.is_modified() {
        body = body.push(
            text("Changes live in memory until the vault itself is saved.")
                .size(11)
                .style(text::secondary),
        );
    }

    container(scrollable(body).width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::detail_background)
        .into()
}

/// The Username / Password / Website middle of the form.
fn login_fields(state: &State) -> Vec<Element<'_, Message>> {
    let secret_row = row![
        text_input("", &state.entry.secret)
            .id("GUI_EDITOR_SECRET")
            .on_input(|value| Message::Editor(Msg::SecretEdited(value)))
            .secure(!state.revealed)
            .padding(8)
            .size(14)
            .width(Length::Fill),
        reveal_button(state.revealed, "Hide password", "Show password"),
        theme::text_button_icon(icon::key(14), "Generate a password")
            .on_press(Message::Vault(crate::VaultMsg::PassGen)),
    ]
    .spacing(6)
    .align_y(Vertical::Center);

    vec![
        field(
            "Username",
            text_input("", &state.entry.user_name)
                .on_input(|value| Message::Editor(Msg::UserNameEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
        field("Password", secret_row.into()),
        field(
            "Website",
            text_input("https://example.com", &state.entry.url)
                .on_input(|value| Message::Editor(Msg::UrlEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
    ]
}

/// The middle of the form for a `Card` entry.
///
/// One reveal toggle covers the number and the PIN together; the CVV has an eye
/// of its own, because it is the field you routinely need to read while the
/// number stays covered.
fn card_fields(state: &State) -> Vec<Element<'_, Message>> {
    let number_row = row![
        text_input("", &state.entry.card.number)
            .on_input(|value| Message::Editor(Msg::CardNumberEdited(value)))
            .secure(!state.revealed)
            .padding(8)
            .size(14)
            .width(Length::Fill),
        reveal_button(state.revealed, "Hide card details", "Show card details"),
    ]
    .spacing(6)
    .align_y(Vertical::Center);

    // Expiry and CVV are five and four characters wide; full-width inputs for
    // them read as a mistake, so they share a row at their real size.
    let expiry_and_cvv = row![
        field(
            "Expiry",
            text_input("MM/YY", &state.entry.card.expiry)
                .on_input(|value| Message::Editor(Msg::CardExpiryEdited(value)))
                .padding(8)
                .size(14)
                .width(Length::Fixed(90.0))
                .into(),
        ),
        field(
            "CVV",
            row![
                text_input("123", &state.entry.card.cvv)
                    .on_input(|value| Message::Editor(Msg::CardCvvEdited(value)))
                    .secure(!state.cvv_revealed)
                    .padding(8)
                    .size(14)
                    .width(Length::Fixed(80.0)),
                cvv_reveal_button(state.cvv_revealed),
            ]
            .spacing(4)
            .align_y(Vertical::Center)
            .into(),
        ),
        field(
            "PIN",
            text_input("", &state.entry.card.pin)
                .on_input(|value| Message::Editor(Msg::CardPinEdited(value)))
                .secure(!state.revealed)
                .padding(8)
                .size(14)
                .width(Length::Fixed(100.0))
                .into(),
        ),
    ]
    .spacing(12);

    vec![
        field(
            "Cardholder",
            text_input("Name on the card", &state.entry.card.holder)
                .on_input(|value| Message::Editor(Msg::CardHolderEdited(value)))
                .padding(8)
                .size(14)
                .into(),
        ),
        field(
            "Brand",
            // `card_brand` is free-form in the format: a brand written by
            // another client is not in this list, and `pick_list` shows it
            // anyway because it renders whatever selection it is handed.
            pick_list(
                data::CARD_BRANDS.map(str::to_string).to_vec(),
                Some(state.entry.card.brand.clone()).filter(|brand| !brand.is_empty()),
                |choice| Message::Editor(Msg::CardBrandSelected(choice)),
            )
            .placeholder("Card network")
            .text_size(13)
            .padding([4, 8])
            .into(),
        ),
        field("Card number", number_row.into()),
        expiry_and_cvv.into(),
    ]
}

fn cvv_reveal_button<'a>(revealed: bool) -> Element<'a, Message> {
    let (glyph, tip) = if revealed {
        (icon::eye_slash(14), "Hide CVV")
    } else {
        (icon::eye(14), "Show CVV")
    };

    theme::text_button_icon(glyph, tip)
        .on_press(Message::Editor(Msg::ToggleCvvReveal))
        .into()
}

/// The attached files, with a way to add one and a way to drop one.
///
/// Shown for **every** entry type, not just `File`: attaching a recovery-codes
/// PDF to the login it belongs to is the ordinary case. On a `File` entry it is
/// the only section there is.
///
/// The rows describe what is attached — name, size, when — rather than offering
/// to open it. Reading a file out is the detail pane's job; this is the editor,
/// and what it edits is the list.
/// Whether this vault has room for the file the user just picked.
///
/// Only a *cloud* vault has a ceiling: the server refuses anything over
/// `MAX_VAULT_BYTES`, and finding that out at save time would leave the user
/// unable to save at all until they worked out which file to drop. Asked here,
/// before a byte has been read, nothing has happened yet.
///
/// A local vault is deliberately uncapped. Nothing is held in memory any more —
/// the file is encrypted straight to disk and streamed into the archive — so
/// the only limit left is the disk's, which the filesystem reports better than
/// a guess here would.
///
/// The estimate is the current archive plus the picked file plus one AES block
/// of padding, and it is an *under*-estimate by the ZIP member's own header. A
/// save that squeaks over anyway is refused by the server with its own message;
/// what this catches is the case worth catching, which is not a near miss.
fn room_for(
    path: &std::path::Path,
    vault: &manager::Vault<manager::Unlocked>,
) -> Result<(), String> {
    if !vault.home().is_some_and(|home| home.location().is_server()) {
        return Ok(());
    }

    let picked = std::fs::metadata(path)
        .map_err(|e| format!("Could not read the file: {e}"))?
        .len();
    let stored = vault
        .attachments()
        .origin()
        .and_then(|origin| std::fs::metadata(origin).ok())
        .map_or(0, |meta| meta.len());

    let total = stored.saturating_add(picked).saturating_add(16);
    if total > askrypt::MAX_VAULT_BYTES as u64 {
        return Err(format!(
            "“{}” does not fit: a vault stored on the server may be at most {}, and this one \
             would come to about {}.",
            path.file_name().unwrap_or_default().to_string_lossy(),
            data::format_size(askrypt::MAX_VAULT_BYTES as u64),
            data::format_size(total),
        ));
    }
    Ok(())
}

fn attachments_section<'a>(state: &'a State, session: &'a Session) -> Element<'a, Message> {
    let stored = session.vault.unlocked().map(|vault| vault.attachments());

    let mut rows = column![].spacing(6);
    for file in &state.entry.attachments {
        // A reference whose blob is not in the archive: `SPEC.md` requires a
        // reader to tolerate one, so it is said plainly rather than hidden.
        let present = stored.is_some_and(|blobs| blobs.source(&file.id).is_some());
        let detail = if present {
            format!(
                "{} · added {}",
                data::format_size(file.size),
                data::format_timestamp_local(file.added)
            )
        } else {
            format!("{} · missing from this vault", data::format_size(file.size))
        };

        rows = rows.push(
            container(
                row![
                    icon::paperclip(14),
                    column![
                        // Out of a file anybody could have written: rendered as
                        // text, never as markup.
                        text(&file.name).size(13),
                        text(detail).size(11).style(text::secondary),
                    ]
                    .spacing(2)
                    .width(Length::Fill),
                    theme::text_button_icon(icon::trash(14), "Remove this file")
                        .on_press(Message::Editor(Msg::RemoveAttachment(file.id.clone()))),
                ]
                .spacing(8)
                .align_y(Vertical::Center),
            )
            .padding([8, 10])
            .style(theme::container_border_r5)
            .width(Length::Fill),
        );
    }

    if state.entry.attachments.is_empty() {
        rows = rows.push(text("No files attached").size(12).style(text::secondary));
    }

    rows = rows.push(
        button(
            row![icon::file_earmark_plus(14), text("Attach file…").size(13)]
                .spacing(6)
                .align_y(Vertical::Center),
        )
        .padding([8, 14])
        .style(button::secondary)
        .on_press(Message::Editor(Msg::AttachFile)),
    );

    field("Files", rows.into())
}

fn reveal_button<'a>(
    revealed: bool,
    hide: &'static str,
    show: &'static str,
) -> Element<'a, Message> {
    let (glyph, tip) = if revealed {
        (icon::eye_slash(14), hide)
    } else {
        (icon::eye(14), show)
    };

    theme::text_button_icon(glyph, tip)
        .on_press(Message::Editor(Msg::ToggleReveal))
        .into()
}

fn field<'a>(label: &'a str, control: Element<'a, Message>) -> Element<'a, Message> {
    column![text(label).size(12).style(text::secondary), control]
        .spacing(4)
        .into()
}
