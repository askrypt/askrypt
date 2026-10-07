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
//!
//! Every verdict also lands in the unlocked vault's [`LeakCache`], so the API
//! is asked about a password once. On unlock (and after an item is saved) a
//! [`LeakSweep`] checks every item password the cache does not know yet; the
//! item list and the detail pane read their warnings off the cache.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use askrypt::SecretEntry;
use iced::widget::{row, text};
use iced::{Element, Task, alignment::Vertical};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::session::Session;
use crate::{GlobalMsg, Message, icon};

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
    /// `cached` is the [`LeakCache`]'s verdict for `value`, if it has one: it
    /// is taken as is, and nothing is scheduled.
    ///
    /// The returned task only waits; `due` names the pane message that asks
    /// for the lookup once the wait is over, and the pane answers it with
    /// [`LeakCheck::run`] if [`LeakCheck::is`] still holds.
    pub fn edited(
        &mut self,
        value: &str,
        enabled: bool,
        cached: Option<u64>,
        due: fn(u64) -> Message,
    ) -> Task<Message> {
        self.generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.found = None;
        if !enabled || value.is_empty() {
            return Task::none();
        }
        if let Some(count) = cached {
            self.found = (count > 0).then_some(count);
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
        self.found.filter(|_| enabled).map(warning)
    }
}

/// The red line under a leaked password: the editor's field and the detail
/// pane's Password row.
pub fn warning<'a>(count: u64) -> Element<'a, Message> {
    let noun = if count == 1 { "breach" } else { "breaches" };
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
    .into()
}

/// A password's place in a [`LeakCache`]: `SHA-256(salt ‖ password)`.
pub type CacheKey = [u8; 32];

/// Bytes per verdict in [`LeakCache::to_bytes`]: the key, then the count.
const RECORD_LEN: usize = 32 + 8;

/// Every breach verdict this unlock has learned, so no password goes to the
/// API twice. Lives in the unlocked vault; a Smart Lock carries it encrypted
/// (see `smartlock`), a full lock drops it.
///
/// Keyed by a salted hash rather than the password, and the salt wipes itself
/// on drop: key bytes left behind in freed memory say nothing without it.
pub struct LeakCache {
    /// Tags a [`LeakSweep`], so a reply meant for an earlier cache — the vault
    /// was locked and unlocked while it ran — is dropped.
    id: u64,
    salt: Zeroizing<[u8; 32]>,
    /// Breach count per password; 0 = checked and clean.
    found: HashMap<CacheKey, u64>,
}

impl Default for LeakCache {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakCache {
    pub fn new() -> Self {
        let mut salt = Zeroizing::new([0u8; 32]);
        salt.copy_from_slice(&askrypt::generate_bytes(32));
        Self::with_salt(salt)
    }

    fn with_salt(salt: Zeroizing<[u8; 32]>) -> Self {
        LeakCache {
            id: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            salt,
            found: HashMap::new(),
        }
    }

    fn key(&self, secret: &str) -> CacheKey {
        let mut hash = Sha256::new();
        hash.update(self.salt.as_slice());
        hash.update(secret.as_bytes());
        hash.finalize().into()
    }

    /// The breach count for `secret`, if it was ever looked up.
    pub fn get(&self, secret: &str) -> Option<u64> {
        if secret.is_empty() {
            return None;
        }
        self.found.get(&self.key(secret)).copied()
    }

    /// Whether `secret` is known to be in a breach.
    pub fn is_leaked(&self, secret: &str) -> bool {
        self.get(secret).is_some_and(|count| count > 0)
    }

    /// Remember a finished lookup.
    pub fn insert(&mut self, secret: &str, count: u64) {
        if !secret.is_empty() {
            let key = self.key(secret);
            self.found.insert(key, count);
        }
    }

    /// Every distinct item password the cache has no verdict for yet.
    pub fn pending(&self, entries: &[SecretEntry]) -> LeakSweep {
        let mut seen = HashSet::new();
        let items = entries
            .iter()
            .filter(|entry| !entry.secret.is_empty())
            .filter_map(|entry| {
                let key = self.key(&entry.secret);
                (!self.found.contains_key(&key) && seen.insert(key))
                    .then(|| (key, Zeroizing::new(entry.secret.clone())))
            })
            .collect();
        LeakSweep { id: self.id, items }
    }

    /// Take a sweep's answers. Failed lookups stay unknown (and are tried
    /// again next time); a sweep for another cache is dropped.
    pub fn adopt(&mut self, swept: Swept) {
        if swept.id != self.id {
            return;
        }
        let mut failed = 0;
        for (key, result) in swept.results {
            match result {
                Ok(count) => {
                    self.found.insert(key, count);
                }
                Err(e) => {
                    failed += 1;
                    if failed == 1 {
                        eprintln!("WARNING: Leak check failed: {e}");
                    }
                }
            }
        }
        if failed > 1 {
            eprintln!("WARNING: {failed} leak checks failed");
        }
    }

    /// The cache as bytes, for the Smart Lock bundle: the salt, then
    /// `key ‖ count (LE u64)` per verdict.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(32 + self.found.len() * RECORD_LEN));
        out.extend_from_slice(self.salt.as_slice());
        for (key, count) in &self.found {
            out.extend_from_slice(key);
            out.extend_from_slice(&count.to_le_bytes());
        }
        out
    }

    /// The inverse of [`Self::to_bytes`]; `None` for anything malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || !(bytes.len() - 32).is_multiple_of(RECORD_LEN) {
            return None;
        }
        let mut salt = Zeroizing::new([0u8; 32]);
        salt.copy_from_slice(&bytes[..32]);
        let mut cache = Self::with_salt(salt);
        for record in bytes[32..].chunks_exact(RECORD_LEN) {
            let key: CacheKey = record[..32].try_into().ok()?;
            let count = u64::from_le_bytes(record[32..].try_into().ok()?);
            cache.found.insert(key, count);
        }
        Some(cache)
    }
}

/// Look up every item password the unlocked vault has no verdict for — on
/// unlock, and after an item is saved. Nothing when either setting is off, the
/// vault is not unlocked, or every password is already known.
pub fn sweep(session: &Session) -> Task<Message> {
    if !session.settings.sweeps_leaks() {
        return Task::none();
    }
    match session.vault.unlocked() {
        Some(vault) => vault
            .leak_sweep()
            .spawn(|swept| Message::Global(GlobalMsg::LeaksSwept(swept))),
        None => Task::none(),
    }
}

/// The passwords a [`LeakCache`] has no verdict for, ready for a worker.
pub struct LeakSweep {
    id: u64,
    items: Vec<(CacheKey, Zeroizing<String>)>,
}

impl LeakSweep {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// **Worker-thread only.** One lookup per password, in turn. Only keys and
    /// counts come back; the passwords are wiped as the sweep drops.
    pub fn run(self) -> Swept {
        let results = self
            .items
            .iter()
            .map(|(key, secret)| (*key, askrypt::pwned::breach_count(secret)))
            .collect();
        Swept {
            id: self.id,
            results,
        }
    }

    /// Run on a worker, unless there is nothing to ask; the answer comes back
    /// as `done`.
    pub fn spawn(self, done: fn(Swept) -> Message) -> Task<Message> {
        if self.is_empty() {
            return Task::none();
        }
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || self.run())
                    .await
                    .expect("leak sweep task panicked")
            },
            done,
        )
    }
}

/// A finished [`LeakSweep`]: salted keys and counts, no passwords.
#[derive(Clone)]
pub struct Swept {
    id: u64,
    results: Vec<(CacheKey, Checked)>,
}

impl std::fmt::Debug for Swept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Swept")
            .field("results", &self.results.len())
            .finish_non_exhaustive()
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
        let _ = check.edited("hunter2", false, None, |_| Message::ReturnToDefaultPane);
        let first = check.generation;
        let _ = check.edited("hunter22", false, None, |_| Message::ReturnToDefaultPane);
        check.finish(first, Ok(5));
        assert_eq!(check.found, None, "a reply for an older value is dropped");

        check.finish(check.generation, Err("offline".into()));
        assert_eq!(check.found, None);

        check.finish(check.generation, Ok(0));
        assert_eq!(check.found, None);

        check.finish(check.generation, Ok(3));
        assert_eq!(check.found, Some(3));
        assert!(check.view(false).is_none(), "the setting hides it");

        let _ = check.edited("hunter222", false, None, |_| Message::ReturnToDefaultPane);
        assert_eq!(check.found, None, "an edit clears the verdict");
    }

    #[test]
    fn generations_are_unique_across_fields() {
        let mut a = LeakCheck::default();
        let mut b = LeakCheck::default();
        let _ = a.edited("x", false, None, |_| Message::ReturnToDefaultPane);
        let _ = b.edited("x", false, None, |_| Message::ReturnToDefaultPane);
        assert_ne!(a.generation, b.generation);
        assert!(!LeakCheck::default().is(a.generation));
    }

    #[test]
    fn thousands_are_grouped() {
        assert_eq!(group_thousands(7), "7");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(9659365), "9,659,365");
    }

    fn entry(secret: &str) -> SecretEntry {
        // `SecretEntry` zeroizes on drop, so no struct-update syntax (E0509).
        let mut entry = SecretEntry::default();
        entry.secret = secret.into();
        entry
    }

    /// A sweep asks about each unknown password once, and only those.
    #[test]
    fn a_sweep_skips_known_empty_and_repeated_passwords() {
        let mut cache = LeakCache::new();
        cache.insert("known", 0);
        let entries = [
            entry("a"),
            entry(""),
            entry("known"),
            entry("a"),
            entry("b"),
        ];
        let sweep = cache.pending(&entries);
        let asked: Vec<&str> = sweep.items.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(asked, ["a", "b"]);
    }

    /// Answers land under the right password; failures stay unknown, and a
    /// sweep for another cache changes nothing.
    #[test]
    fn a_sweep_is_adopted_by_its_own_cache_only() {
        let mut cache = LeakCache::new();
        let sweep = cache.pending(&[entry("a"), entry("b"), entry("c")]);
        let mut results = sweep.items.iter().map(|(key, _)| *key);
        let swept = Swept {
            id: sweep.id,
            results: vec![
                (results.next().unwrap(), Ok(7)),
                (results.next().unwrap(), Ok(0)),
                (results.next().unwrap(), Err("offline".into())),
            ],
        };

        let mut other = LeakCache::new();
        other.adopt(swept.clone());
        assert_eq!(other.get("a"), None, "another cache's sweep is dropped");

        cache.adopt(swept);
        assert!(cache.is_leaked("a"));
        assert_eq!(cache.get("b"), Some(0));
        assert!(!cache.is_leaked("b"));
        assert_eq!(cache.get("c"), None, "a failed lookup is not remembered");
        assert_eq!(cache.pending(&[entry("c")]).items.len(), 1);
    }

    #[test]
    fn the_cache_round_trips_through_bytes() {
        let mut cache = LeakCache::new();
        cache.insert("a", 3);
        cache.insert("b", 0);
        let restored = LeakCache::from_bytes(&cache.to_bytes()).expect("well-formed");
        assert_eq!(restored.get("a"), Some(3));
        assert_eq!(restored.get("b"), Some(0));
        assert_eq!(restored.get("c"), None);
        assert!(LeakCache::from_bytes(&[0; 33]).is_none());
    }

    /// A cached verdict is shown at once, with nothing scheduled.
    #[test]
    fn a_cached_verdict_needs_no_lookup() {
        let mut check = LeakCheck::default();
        let _ = check.edited("x", true, Some(12), |_| Message::ReturnToDefaultPane);
        assert_eq!(check.found, Some(12));
        let _ = check.edited("x", true, Some(0), |_| Message::ReturnToDefaultPane);
        assert_eq!(check.found, None);
    }
}
