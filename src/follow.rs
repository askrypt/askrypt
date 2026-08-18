//! Following the open vault where it is stored, and reloading it when it
//! changes.
//!
//! A vault on a server — or in a folder something else syncs — can be written
//! by another device while this app has it open. Without following, the first
//! the user hears of it is a save rejected with
//! [`VaultError::Conflict`](crate::session::VaultError::Conflict), by which
//! point their edits have nowhere to go.
//!
//! So the shell asks the backend, on a timer and whenever the window regains
//! focus, whether it still holds the bytes we last saw
//! ([`VaultStorage::current_revision`]). What happens next depends entirely on
//! whether anything local is at stake — [`decide`] is that whole policy, kept
//! a pure function so the state matrix can be tested without a UI or a
//! network.
//!
//! ## Why this is not a pane
//!
//! Like [`crate::link`], it owns a widget rather than the working area: the
//! banner has to be visible over the item list, the entry editor and the
//! unlock screen alike, because the vault it is talking about is open in all
//! of them. Its state lives on the [`Session`] for the same reason.
//!
//! ## What a probe may not do
//!
//! The probe never reads the vault and never touches the backend's cached
//! revision. That revision is what the next save sends as its conflict check,
//! and a probe that adopted whatever it found would quietly convert the very
//! change it detected into a licence to overwrite it. Adopting is a separate,
//! deliberate act ([`VaultStorage::adopt_revision`]) that only the user
//! pressing *Save mine* performs.

use std::sync::Arc;
use std::time::Duration;

use askrypt::{AskryptFile, RemoteRevision, Revision, VaultStorage};
use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use crate::manager::VaultState;
use crate::session::{Session, VaultError};
use crate::{Message, data, theme};

/// How often an open vault is checked. Slow on purpose: this is a background
/// courtesy, not a sync engine, and every tick is a request someone's server
/// has to answer.
pub const FOLLOW_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/// What the backend said when asked what it holds.
#[derive(Debug, Clone)]
pub enum Probe {
    /// Still the bytes we last read or wrote.
    InSync,
    /// Someone else has written it since.
    Changed(RemoteRevision),
    /// There is nothing there any more — deleted, renamed, or moved away.
    Missing,
}

/// One probe's answer, tagged with the revision it was asked about.
///
/// The tag is the staleness check: a save or a reload that lands while the
/// request is in flight moves the backend on, and this reply is then about a
/// version nobody is on any more.
#[derive(Debug, Clone)]
pub struct Reply {
    pub probed: Revision,
    pub result: Result<Probe, VaultError>,
}

/// Ask the backend what it holds now. **Runs on a worker** — for a server
/// vault this is a network round trip.
pub fn probe(storage: Arc<dyn VaultStorage>, probed: Revision) -> iced::Task<Message> {
    let known = probed.clone();
    iced::Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                let result = match storage.current_revision() {
                    Ok(Some(found)) if found.revision == known => Ok(Probe::InSync),
                    Ok(Some(found)) => Ok(Probe::Changed(found)),
                    Ok(None) => Ok(Probe::Missing),
                    Err(e) => Err(VaultError::log("Failed to check the stored vault", &e)),
                };
                Reply {
                    probed: known,
                    result,
                }
            })
            .await
            .expect("follow probe task panicked")
        },
        |reply| Message::Global(crate::GlobalMsg::Followed(Box::new(reply))),
    )
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// Why a reload is running, which decides how much it is allowed to do.
///
/// A background reload may find the vault no longer opens with the answers
/// held; that is a question for the user, not something to act on unasked. The
/// same outcome after the user pressed a button is the answer to a question
/// already put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Started by the timer. May decline to apply what it finds.
    Follow,
    /// Started by a button. Applies whatever comes back.
    Forced,
}

/// What the shell should do about a probe result.
#[derive(Debug)]
pub enum Follow {
    /// Nothing at all.
    Idle,
    /// Re-read the vault now: nothing local is at stake.
    Reload,
    /// Raise the banner and wait — there is unsaved work to lose.
    Ask(Notice),
    /// Say this once and stop following; further ticks would only repeat it.
    Stop(Notice),
}

/// What the banner is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// The stored copy moved on while there are unsaved changes here.
    Diverged,
    /// The stored copy is gone.
    Missing,
    /// It was re-read, but the answers held no longer open it — the other
    /// device changed the security questions.
    Rekeyed,
    /// The server stopped accepting our token.
    SignedOut,
}

/// A standing message about the stored copy, and the choice it needs.
///
/// Sticky, unlike the three transient message fields on [`Session`]: those are
/// wiped by the next keystroke, and this outlives it by design.
#[derive(Debug, Clone)]
pub struct Notice {
    pub kind: Kind,
    /// The revision this is about. A *newer* change supersedes the notice, so
    /// dismissing one cannot hide the next.
    pub revision: Option<Revision>,
    /// Who wrote it and when, per the file's own unencrypted stamp — display
    /// text, never evidence.
    pub host: Option<String>,
    pub saved_at: Option<String>,
    /// Server or local file, for the wording alone.
    pub server: bool,
}

impl Notice {
    fn new(kind: Kind, server: bool) -> Self {
        Notice {
            kind,
            revision: None,
            host: None,
            saved_at: None,
            server,
        }
    }

    /// The stored copy was re-read but no longer opens with the answers held.
    pub fn rekeyed(server: bool) -> Self {
        Notice::new(Kind::Rekeyed, server)
    }

    /// The server stopped accepting the token, so nothing can be followed.
    pub fn signed_out(server: bool) -> Self {
        Notice::new(Kind::SignedOut, server)
    }

    /// The stored copy was already fetched when the divergence was noticed —
    /// the user started editing while a background reload was in flight.
    ///
    /// The stamp comes off the bytes themselves rather than off a listing row,
    /// and `revision` is the one the read landed on — the version *Save mine*
    /// would be replacing, which the caller must capture before it rolls the
    /// backend back.
    pub fn diverged_after_read(
        file: &AskryptFile,
        revision: Option<Revision>,
        server: bool,
    ) -> Self {
        Notice {
            kind: Kind::Diverged,
            revision,
            host: file.params.host.clone(),
            saved_at: file.params.updated_at.clone(),
            server,
        }
    }

    fn about(kind: Kind, server: bool, found: &RemoteRevision) -> Self {
        Notice {
            kind,
            revision: Some(found.revision.clone()),
            host: found.host.clone(),
            saved_at: found.saved_at.clone(),
            server,
        }
    }

    /// "the server" or "disk" — the same distinction the status line draws.
    fn place(&self) -> &'static str {
        if self.server { "the server" } else { "disk" }
    }

    /// The sentence above the buttons.
    pub fn message(&self) -> String {
        match self.kind {
            Kind::Diverged => {
                let who = match data::format_stamp(self.host.as_deref(), self.saved_at.as_deref()) {
                    Some(stamp) => format!(" by {}", stamp),
                    None => String::new(),
                };
                format!(
                    "This vault was changed on {}{}, and you have unsaved changes here.",
                    self.place(),
                    who
                )
            }
            Kind::Missing => format!(
                "This vault is no longer on {} — it was deleted, renamed or moved. \
                 Use Save As to store it again.",
                self.place()
            ),
            Kind::Rekeyed => format!(
                "This vault was changed on {}, and its security questions no longer \
                 match the answers you gave. Reloading means answering them again.",
                self.place()
            ),
            Kind::SignedOut => {
                "Your server session expired, so this vault is no longer being followed. \
                 Sign in again."
                    .to_string()
            }
        }
    }
}

/// The whole following policy, as one pure function.
///
/// `has_draft` covers unsaved work the dirty flag does not: an entry open in
/// the editor and a question list open in the questions editor are both edits
/// the user has not committed, and a reload would throw either away.
pub fn decide(
    vault: &VaultState,
    has_draft: bool,
    server: bool,
    dismissed: Option<&Revision>,
    probe: Probe,
) -> Follow {
    match probe {
        Probe::InSync => Follow::Idle,
        Probe::Missing => Follow::Stop(Notice::new(Kind::Missing, server)),
        Probe::Changed(found) => {
            // Already waved away. A *further* change makes a new revision and
            // so gets past this.
            if dismissed == Some(&found.revision) {
                return Follow::Idle;
            }

            // The dirty flag lives in the unlocked state, so every other state
            // is clean by construction — a locked or smart-locked vault has
            // nothing decrypted to lose, and arming Smart Lock is itself
            // gated on saving first.
            if vault.is_modified() || has_draft {
                Follow::Ask(Notice::about(Kind::Diverged, server, &found))
            } else {
                Follow::Reload
            }
        }
    }
}

/// The status line written after a successful reload: who wrote the bytes we
/// just took, and when.
///
/// Both halves come from the vault's own unencrypted write stamp, which the
/// reload has already parsed — no extra request, and it reads exactly like the
/// stamp on the locked screen and in the server vault listing. A file too old
/// to carry one degrades to the bare sentence rather than a dangling "saved
/// by".
pub fn reload_line(file: &AskryptFile, server: bool) -> String {
    stamp_line(
        file.params.host.as_deref(),
        file.params.updated_at.as_deref(),
        server,
    )
}

/// The wording, split out so it can be exercised without building a vault.
fn stamp_line(host: Option<&str>, updated_at: Option<&str>, server: bool) -> String {
    let place = if server { "the server" } else { "disk" };
    match data::format_stamp(host, updated_at) {
        Some(stamp) => format!("Reloaded from {} — saved by {}", place, stamp),
        None => format!("Reloaded from {}", place),
    }
}

// ---------------------------------------------------------------------------
// The banner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Msg {
    /// Replace the stored copy with what is in memory.
    SaveMine,
    /// Throw away the local edits and take the stored copy.
    DiscardAndReload,
    /// Leave everything alone.
    Dismiss,
}

/// The banner, when there is something standing to say.
///
/// Rendered above the working area rather than inside a pane: the vault it
/// concerns is open whichever pane is showing.
pub fn view(session: &Session) -> Option<Element<'_, Message>> {
    let notice = session.follow.as_ref()?;

    let mut actions = row![].spacing(8);
    if notice.kind == Kind::Diverged {
        actions = actions
            .push(button(text("Save mine").size(13)).on_press(Message::Follow(Msg::SaveMine)))
            .push(
                button(text("Discard mine & reload").size(13))
                    .on_press(Message::Follow(Msg::DiscardAndReload)),
            );
    }
    if notice.kind == Kind::Rekeyed {
        actions = actions.push(
            button(text("Reload and answer again").size(13))
                .on_press(Message::Follow(Msg::DiscardAndReload)),
        );
    }
    let dismiss = match notice.kind {
        Kind::Diverged => "Keep editing",
        Kind::Rekeyed => "Keep this copy",
        _ => "Dismiss",
    };
    actions = actions.push(button(text(dismiss).size(13)).on_press(Message::Follow(Msg::Dismiss)));

    let body = column![text(notice.message()).size(14), actions]
        .spacing(8)
        .padding(10);

    Some(
        container(theme::card(body))
            .width(Length::Fill)
            .padding([4, 6])
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(etag: &str) -> RemoteRevision {
        RemoteRevision {
            revision: Revision(etag.to_string()),
            host: Some("ubuntu@work-pc".to_string()),
            saved_at: Some("2026-08-18T14:05:00Z".to_string()),
        }
    }

    #[test]
    fn unchanged_is_idle() {
        let follow = decide(&VaultState::None, false, true, None, Probe::InSync);
        assert!(matches!(follow, Follow::Idle));
    }

    #[test]
    fn a_clean_vault_reloads_without_asking() {
        // `VaultState::None` is not modified, which is what the clean branch
        // keys on; the shell only ever calls this for a followable vault.
        let follow = decide(
            &VaultState::None,
            false,
            true,
            None,
            Probe::Changed(found("new")),
        );
        assert!(matches!(follow, Follow::Reload));
    }

    #[test]
    fn an_open_draft_counts_as_unsaved_work() {
        // Nothing is `modified`, but a draft in the editor is still an edit
        // that a reload would silently discard.
        let follow = decide(
            &VaultState::None,
            true,
            true,
            None,
            Probe::Changed(found("new")),
        );
        match follow {
            Follow::Ask(notice) => assert_eq!(notice.kind, Kind::Diverged),
            other => panic!("expected Ask, got {:?}", other),
        }
    }

    #[test]
    fn a_dismissed_revision_stays_dismissed() {
        let dismissed = Revision("new".to_string());
        let follow = decide(
            &VaultState::None,
            true,
            true,
            Some(&dismissed),
            Probe::Changed(found("new")),
        );
        assert!(matches!(follow, Follow::Idle));
    }

    #[test]
    fn a_further_change_gets_past_a_dismissal() {
        let dismissed = Revision("new".to_string());
        let follow = decide(
            &VaultState::None,
            true,
            true,
            Some(&dismissed),
            Probe::Changed(found("newer")),
        );
        assert!(matches!(follow, Follow::Ask(_)));
    }

    #[test]
    fn a_missing_vault_stops_following() {
        let follow = decide(&VaultState::None, false, true, None, Probe::Missing);
        match follow {
            Follow::Stop(notice) => assert_eq!(notice.kind, Kind::Missing),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    #[test]
    fn the_diverged_message_names_who_saved_it() {
        let notice = Notice::about(Kind::Diverged, true, &found("new"));
        let message = notice.message();
        assert!(message.contains("ubuntu@work-pc"), "{}", message);
        assert!(message.contains("unsaved changes"), "{}", message);
    }

    #[test]
    fn the_reload_line_names_the_host_and_renders_the_time_locally() {
        let line = stamp_line(Some("ubuntu@work-pc"), Some("2026-08-18T14:05:00Z"), true);
        assert!(
            line.starts_with("Reloaded from the server — saved by "),
            "{}",
            line
        );
        assert!(line.contains("ubuntu@work-pc"), "{}", line);
        // `format_stamp` runs the timestamp through the app's one local-time
        // rendering, so the raw RFC 3339 text must not survive into the line.
        assert!(!line.contains("2026-08-18T14:05:00Z"), "{}", line);
        assert!(line.contains("Aug 18, 2026"), "{}", line);
    }

    #[test]
    fn a_reload_line_for_a_vault_with_no_write_stamp_still_says_where() {
        // A pre-stamp vault has neither half. The sentence must not trail off
        // into a dangling "saved by".
        let line = stamp_line(None, None, false);
        assert_eq!(line, "Reloaded from disk");
    }

    #[test]
    fn a_reload_line_with_only_a_time_drops_the_host_cleanly() {
        let line = stamp_line(None, Some("2026-08-18T14:05:00Z"), true);
        assert!(
            line.starts_with("Reloaded from the server — saved by "),
            "{}",
            line
        );
        assert!(line.contains("Aug 18, 2026"), "{}", line);
    }

    #[test]
    fn an_unstamped_change_still_reads_as_a_sentence() {
        let bare = RemoteRevision {
            revision: Revision("new".to_string()),
            host: None,
            saved_at: None,
        };
        let notice = Notice::about(Kind::Diverged, false, &bare);
        let message = notice.message();
        // No dangling "by", and it still says where.
        assert!(!message.contains(" by "), "{}", message);
        assert!(message.contains("disk"), "{}", message);
    }
}
