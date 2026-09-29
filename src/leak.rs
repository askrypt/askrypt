//! "Is this password in a known breach?" — the warning under the entry
//! editor's Password field, behind the `check_leaks` setting. Security answers
//! are deliberately not checked.
//!
//! The lookup itself is core's [`askrypt::pwned`] (k-anonymity: five hex
//! characters of a SHA-1 leave the machine). This module is the pacing around
//! it: a check starts [`DEBOUNCE`] after the last keystroke, runs on a worker,
//! and its answer is kept only if the field has not changed since.
//!
//! Every check carries a *generation*, unique across the whole app, so a reply
//! for a value that has since been edited matches nothing and is dropped. The secret
//! never rides in a message: the worker captures its own copy.
//!
//! A failed lookup is logged and shows nothing: the warning is advice, and "we
//! could not ask" is not something the user can act on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iced::widget::{row, text};
use iced::{Element, Task, alignment::Vertical};
use zeroize::Zeroizing;

use crate::{Message, icon};

/// Quiet time after the last keystroke before a lookup goes out.
const DEBOUNCE: Duration = Duration::from_millis(800);

/// Source of generations. Starts at 1 so a fresh [`LeakCheck`] (generation 0)
/// matches no reply.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// What a finished lookup reports: the breach count, or why there is none.
pub type Checked = Result<u64, String>;

/// One field's verdict. `Default` is "nothing known, nothing pending".
#[derive(Debug, Default)]
pub struct LeakCheck {
    generation: u64,
    found: Option<u64>,
}

impl LeakCheck {
    /// The field now holds `value`: forget the old verdict, and — when the
    /// setting is on and there is something to check — schedule a lookup.
    ///
    /// The returned task only waits; `due` names the pane message that asks
    /// for the lookup once the wait is over, and the pane answers it with
    /// [`LeakCheck::run`] if [`LeakCheck::is`] still holds.
    pub fn edited(&mut self, value: &str, enabled: bool, due: fn(u64) -> Message) -> Task<Message> {
        self.generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.found = None;
        if !enabled || value.is_empty() {
            return Task::none();
        }
        let generation = self.generation;
        Task::perform(async { tokio::time::sleep(DEBOUNCE).await }, move |()| {
            due(generation)
        })
    }

    /// Whether a message tagged `generation` is about this field's current
    /// value.
    pub fn is(&self, generation: u64) -> bool {
        self.generation == generation
    }

    /// Look `value` up on a worker. `done` names the pane message carrying the
    /// answer back, tagged with the current generation.
    pub fn run(
        &self,
        value: Zeroizing<String>,
        done: fn(u64, Checked) -> Message,
    ) -> Task<Message> {
        let generation = self.generation;
        if value.is_empty() {
            return Task::none();
        }
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || askrypt::pwned::breach_count(&value))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
            },
            move |result| done(generation, result),
        )
    }

    /// Record a finished lookup. A stale one — the field changed while it ran
    /// — is dropped; a failed one is only logged.
    pub fn finish(&mut self, generation: u64, result: Checked) {
        if !self.is(generation) {
            return;
        }
        match result {
            Ok(count) => self.found = (count > 0).then_some(count),
            Err(e) => eprintln!("WARNING: Leak check failed: {e}"),
        }
    }

    /// The warning line, when the value is known to be leaked and the setting
    /// is (still) on.
    pub fn view<'a>(&self, enabled: bool) -> Option<Element<'a, Message>> {
        let count = self.found.filter(|_| enabled)?;
        let noun = if count == 1 { "breach" } else { "breaches" };
        Some(
            row![
                icon::warning(11).style(text::danger),
                text(format!(
                    "Found in {} known data {noun} — choose another.",
                    group_thousands(count)
                ))
                .size(11)
                .style(text::danger),
            ]
            .spacing(6)
            .align_y(Vertical::Center)
            .into(),
        )
    }
}

/// `9659365` → `9,659,365`.
fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_and_failed_lookups_leave_no_warning() {
        let mut check = LeakCheck::default();
        let _ = check.edited("hunter2", false, |_| Message::ReturnToDefaultPane);
        let first = check.generation;
        let _ = check.edited("hunter22", false, |_| Message::ReturnToDefaultPane);
        check.finish(first, Ok(5));
        assert_eq!(check.found, None, "a reply for an older value is dropped");

        check.finish(check.generation, Err("offline".into()));
        assert_eq!(check.found, None);

        check.finish(check.generation, Ok(0));
        assert_eq!(check.found, None);

        check.finish(check.generation, Ok(3));
        assert_eq!(check.found, Some(3));
        assert!(check.view(false).is_none(), "the setting hides it");

        let _ = check.edited("hunter222", false, |_| Message::ReturnToDefaultPane);
        assert_eq!(check.found, None, "an edit clears the verdict");
    }

    #[test]
    fn generations_are_unique_across_fields() {
        let mut a = LeakCheck::default();
        let mut b = LeakCheck::default();
        let _ = a.edited("x", false, |_| Message::ReturnToDefaultPane);
        let _ = b.edited("x", false, |_| Message::ReturnToDefaultPane);
        assert_ne!(a.generation, b.generation);
        assert!(!LeakCheck::default().is(a.generation));
    }

    #[test]
    fn thousands_are_grouped() {
        assert_eq!(group_thousands(7), "7");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(9659365), "9,659,365");
    }
}
