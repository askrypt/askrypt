//! The confirmation dialog: one look for every question this app asks.
//!
//! ## Why this is not a pane
//!
//! Like [`crate::follow`] and [`crate::link`], it draws *over* whichever pane
//! is showing rather than owning the working area — a question about the open
//! vault is a question whether the item list, the entry editor or the unlock
//! screen happens to be underneath. So it is a [`Dialog`] laid over the whole
//! window by [`overlay`], and the shell's own pending question lives on `App`.
//!
//! ## Why it is not the platform's own message box
//!
//! It used to be: `rfd::MessageDialog`, three times over. A native box carries
//! the platform's chrome, fonts and button order, so the one part of the app
//! that asks *"are you sure?"* was the one part that did not look like the
//! app — and looked different again on each of the three platforms. `rfd` is
//! now used for file pickers alone.
//!
//! ## Who builds one
//!
//! Two callers, one chrome. [`Kind`] is the shell's own vocabulary — quit,
//! unsaved changes, delete an item — and [`crate::follow::dialog`] builds its
//! own from the standing notice, so nothing about following is restated here.

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{button, center, column, container, mouse_area, opaque, row, stack, text};
use iced::{Element, Length};

use crate::{Message, PendingAction, theme};

/// A widget id nothing carries.
///
/// Raising a dialog focuses *this*, which is how the whole tree underneath is
/// unfocused: `operation::focus` focuses its target and unfocuses everything
/// else, and iced 0.14 ships no `Task` wrapper for the bare `unfocus`
/// operation. Without it a `text_input` under the dialog keeps focus and goes
/// on swallowing every keystroke, Escape and Enter included.
pub const NO_FOCUS: &str = "GUI_DIALOG_NO_FOCUS";

/// Which button was pressed.
///
/// Three-valued because the unsaved-changes question genuinely is: save and go,
/// go without saving, and don't go. The two-button dialogs simply never send
/// [`Answer::Deny`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The affirmative — the thing the dialog is offering to do.
    Affirm,
    /// The second, non-cancelling choice. Only the three-button questions.
    Deny,
    /// Back out. Also what Escape and a click on the backdrop send, so it must
    /// always be the answer that changes nothing.
    Cancel,
}

/// The shell's own questions.
///
/// Each carries everything answering it needs, so `App::resolve_confirm` can
/// act without re-deriving anything that may have moved while the dialog stood.
#[derive(Debug, Clone)]
pub enum Kind {
    /// Quitting outright, from the rail or the tray, with nothing unsaved.
    Quit,
    /// Something that would discard unsaved edits. The action waits for the
    /// answer, and on *Save* is replayed once the save lands.
    UnsavedChanges(PendingAction),
    /// Removing one item. The name is captured when the question is raised: it
    /// is what the dialog says, and re-reading it on the way out would be
    /// re-reading a list the answer is about to change.
    DeleteEntry { index: usize, name: String },
    /// Removing every item checked in selecting mode. Indices and names are
    /// captured together when the question is raised, for the same reason.
    DeleteEntries {
        indices: Vec<usize>,
        names: Vec<String>,
    },
    /// Not a question: a copy went to the clipboard without these attached
    /// files. One button, so every answer — OK, Escape, Enter — is Cancel.
    FilesSkipped { names: Vec<String> },
}

/// How many names the bulk-delete question lists before summarising the rest.
const NAMES_SHOWN: usize = 5;
/// The same for the skipped-files warning, which has nothing else to say.
const FILE_NAMES_SHOWN: usize = 10;

impl Kind {
    /// The question, as the user sees it.
    pub fn dialog(&self) -> Dialog {
        match self {
            Kind::Quit => Dialog::new(
                "Quit Askrypt",
                "Quitting wipes the decrypted vault from memory. You will have to \
                 answer the security questions again to reopen it.",
            )
            .affirm("Quit", Message::Confirm(Answer::Affirm))
            .cancel("Cancel", Message::Confirm(Answer::Cancel))
            // Nothing is lost — an unmodified vault is the only way to get
            // here, or `guard` would have asked instead — so Enter may take
            // the affirmative.
            .on_enter(Message::Confirm(Answer::Affirm)),

            Kind::UnsavedChanges(_) => Dialog::new(
                "Unsaved changes",
                "You have unsaved changes in this vault. Would you like to save \
                 them first?",
            )
            .affirm("Save", Message::Confirm(Answer::Affirm))
            .deny("Don't save", Message::Confirm(Answer::Deny))
            .cancel("Cancel", Message::Confirm(Answer::Cancel))
            // The affirmative here is the *safe* one: it saves.
            .on_enter(Message::Confirm(Answer::Affirm)),

            // No `on_enter`: a stray Return must never delete an item.
            Kind::DeleteEntry { name, .. } => Dialog::new(
                "Delete item",
                format!(
                    "Delete \u{201c}{name}\u{201d}? This cannot be undone once the vault is saved."
                ),
            )
            .danger("Delete", Message::Confirm(Answer::Affirm))
            .cancel("Cancel", Message::Confirm(Answer::Cancel)),

            // No `on_enter`, as above.
            Kind::DeleteEntries { names, .. } => {
                Dialog::new("Delete items", delete_entries_body(names))
                    .danger("Delete", Message::Confirm(Answer::Affirm))
                    .cancel("Cancel", Message::Confirm(Answer::Cancel))
            }

            Kind::FilesSkipped { names } => {
                Dialog::new("Files not copied", files_skipped_body(names))
                    .cancel("OK", Message::Confirm(Answer::Cancel))
                    .on_enter(Message::Confirm(Answer::Cancel))
            }
        }
    }
}

fn files_skipped_body(names: &[String]) -> String {
    let mut body = match names.len() {
        1 => "Attached files are not copied. This file was skipped:\n".to_string(),
        n => format!("Attached files are not copied. These {n} files were skipped:\n"),
    };
    push_names(&mut body, names, FILE_NAMES_SHOWN);
    body
}

/// A bullet per name, the first `shown` of them, then how many more.
fn push_names(body: &mut String, names: &[String], shown: usize) {
    for name in names.iter().take(shown) {
        body.push_str(&format!("\n\u{2022} {name}"));
    }
    if names.len() > shown {
        body.push_str(&format!("\n\u{2026}and {} more", names.len() - shown));
    }
}

fn delete_entries_body(names: &[String]) -> String {
    if let [name] = names {
        return format!(
            "Delete \u{201c}{name}\u{201d}? This cannot be undone once the vault is saved."
        );
    }
    let mut body = format!(
        "Delete {} items? This cannot be undone once the vault is saved.\n",
        names.len()
    );
    push_names(&mut body, names, NAMES_SHOWN);
    body
}

/// One question, and the buttons that answer it.
///
/// Built by [`Kind::dialog`] and by [`crate::follow::dialog`]; rendered by
/// [`overlay`], and read by `App::handle_event` for the two keys it binds.
/// Owns its text rather than borrowing, so a dialog can be built from anything
/// — a literal, a formatted name, a notice — without the caller's borrow
/// following it into the view.
pub struct Dialog {
    title: String,
    body: String,
    /// Left to right, as shown. The flag styles a button `button::danger`.
    buttons: Vec<(String, bool, Message)>,
    /// Escape, and a click on the dimmed backdrop.
    escape: Message,
    /// Enter, where there is a safe default. [`None`] for a destructive
    /// affirmative, so a keystroke meant for something else cannot delete an
    /// item or overwrite another device's vault.
    enter: Option<Message>,
}

impl Dialog {
    /// A dialog with no buttons yet. [`Dialog::cancel`] must be called before
    /// it is rendered — it is what supplies the escape answer.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Dialog {
            title: title.into(),
            body: body.into(),
            buttons: Vec::new(),
            // Replaced by `cancel`. A dialog that forgot to call it answers its
            // own escape with a no-op, which is the safe way to be wrong.
            escape: Message::Confirm(Answer::Cancel),
            enter: None,
        }
    }

    /// The thing the dialog is offering to do, styled as the primary action.
    pub fn affirm(mut self, label: &str, message: Message) -> Self {
        self.buttons.push((label.to_string(), false, message));
        self
    }

    /// An affirmative that destroys something. Same slot, `button::danger`.
    pub fn danger(mut self, label: &str, message: Message) -> Self {
        self.buttons.push((label.to_string(), true, message));
        self
    }

    /// The second, non-cancelling choice.
    pub fn deny(mut self, label: &str, message: Message) -> Self {
        self.buttons.push((label.to_string(), false, message));
        self
    }

    /// Backing out. Always last, always secondary, and always what Escape and
    /// the backdrop answer — which is why it is a builder of its own rather
    /// than one more [`Dialog::affirm`].
    pub fn cancel(mut self, label: &str, message: Message) -> Self {
        self.escape = message.clone();
        self.buttons.push((label.to_string(), false, message));
        self
    }

    /// Bind Enter. Omit it wherever the affirmative destroys something.
    pub fn on_enter(mut self, message: Message) -> Self {
        self.enter = Some(message);
        self
    }

    /// What Escape and a backdrop click send.
    pub fn escape(&self) -> Message {
        self.escape.clone()
    }

    /// What Enter sends, if anything.
    pub fn enter(&self) -> Option<Message> {
        self.enter.clone()
    }
}

/// Lay a dialog over the whole window.
///
/// The scrim covers everything and is `opaque`, so no click reaches the panes
/// underneath; the card is `opaque` in turn, so a click on the card itself does
/// not reach the backdrop's `mouse_area` and answer the question. Keyboard
/// input is *not* stopped here — `App::handle_event` swallows it, and raising a
/// dialog runs `operation::focusable::unfocus` so a text input underneath stops
/// holding focus and eating Escape.
pub fn overlay<'a>(base: Element<'a, Message>, dialog: Dialog) -> Element<'a, Message> {
    let Dialog {
        title,
        body,
        buttons,
        escape,
        ..
    } = dialog;

    let mut actions = row![].spacing(10).align_y(Vertical::Center);
    let last = buttons.len().saturating_sub(1);
    for (i, (label, danger, message)) in buttons.into_iter().enumerate() {
        let styled = button(text(label).size(14)).padding([8, 16]);
        // The cancel is always last, and always the quiet one — unless it is
        // the only button (an acknowledgement), which then looks primary.
        let styled = if i == last && last > 0 {
            styled.style(button::secondary)
        } else if danger {
            styled.style(button::danger)
        } else {
            styled
        };
        actions = actions.push(styled.on_press(message));
    }

    let card = theme::card(
        column![
            text(title).size(20).font(theme::bold()),
            text(body).size(13),
            container(actions)
                .width(Length::Fill)
                .align_x(Horizontal::Right),
        ]
        .spacing(16)
        .padding(20),
    )
    .max_width(440);

    stack![
        base,
        opaque(mouse_area(center(opaque(card)).style(theme::modal_scrim)).on_press(escape)),
    ]
    .into()
}

#[cfg(test)]
mod tests {
    use super::files_skipped_body;

    #[test]
    fn the_skipped_files_warning_lists_names_then_counts_the_rest() {
        let names: Vec<String> = (1..=12).map(|i| format!("f{i}.pdf")).collect();
        let one = files_skipped_body(&names[..1]);
        assert!(one.contains("This file was skipped"));
        assert!(one.ends_with("\u{2022} f1.pdf"));

        let many = files_skipped_body(&names);
        assert!(many.contains("These 12 files were skipped"));
        assert!(many.contains("\u{2022} f10.pdf"));
        assert!(!many.contains("f11.pdf"));
        assert!(many.ends_with("\u{2026}and 2 more"));
    }
}
