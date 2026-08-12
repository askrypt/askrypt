//! The vault lifecycle as a typestate: [`Vault<S>`].
//!
//! The vault's parts — the encrypted file, where it lives, the answers, the
//! decrypted question list, the entries, the master key — are not independent.
//! A locked vault has no master key. A partially unlocked one has the question
//! list but no entries. A vault that has never been written has no home, and
//! that is precisely what makes its first Save a Save As. Held as a dozen loose
//! `Option`s and a `bool`, those rules can only be written down in comments and
//! checked by hand; held as a typestate, most of them stop being expressible.
//!
//! **The state carries its own data.** [`Locked`] is empty,
//! [`PartiallyUnlocked`] holds the first answer and the question list,
//! [`Unlocked`] holds every answer, the entries and the master key, and
//! [`SmartLocked`] holds the re-encrypted bundle. So there is no
//! `master: Option<…>` that happens to be `Some` in one state — while the vault
//! is locked the field does not exist, and the compiler will not let you ask.
//!
//! Three properties follow, and each replaces something previously enforced by
//! prose:
//!
//! - **A method exists only where it is legal.** `save_request` is on
//!   `Vault<Unlocked>` and nowhere else, so "saving needs the decrypted
//!   entries" is a compile error rather than a silent no-op.
//! - **Dropping a state wipes it.** `QuestionsData`, `SecretEntry` and
//!   `MasterSecret` are `ZeroizeOnDrop` in `core`, and the answers are held in
//!   `Zeroizing`. Locking is `vault.lock()`, which drops the old state; there is
//!   no separate "remember to also wipe this" step. Note that the wiping is
//!   composed from the leaves and the states themselves must **not** derive
//!   `ZeroizeOnDrop`: it implies `Drop`, and a type with `Drop` cannot be
//!   destructured (E0509) — which is exactly what `with_state` and every
//!   transition do. `core/src/types.rs` documents the same constraint for
//!   `CardFields`.
//! - **A failed derivation changes nothing.** Transitions consume `self` and
//!   are applied only from the *success* arm of a completion message, so a
//!   wrong answer leaves the vault exactly where it was — it cannot leave
//!   unverified answers behind.
//!
//! ## The enum at the field
//!
//! A typestate cannot be stored in a struct field whose type is fixed, so
//! [`VaultState`] is the erasure: one variant per state, each holding the
//! `Vault<S>` for it. `Session` holds one `VaultState`; a pane matches on it
//! and gets back a `Vault<Unlocked>` (or `<Locked>`, …) carrying only the
//! operations that state allows.
//!
//! ## Transitions are asynchronous
//!
//! Every derivation here is 600,000 PBKDF2 iterations (2,000,000 for Smart
//! Lock), so none of them may run on the main thread. Each transition is a
//! triple:
//!
//! 1. a method on the current state producing an owned, `Send` inputs struct
//!    (`RevealInputs`, `UnlockInputs`, `SaveRequest`, …);
//! 2. that struct's `run`, called on a worker, which converts `core`'s
//!    `Box<dyn Error>` — not `Send`, so it cannot cross the boundary — into a
//!    `String` or a [`VaultError`];
//! 3. a `self`-consuming apply on [`VaultState`], called from the completion
//!    message.
//!
//! The answers never ride in a completion message: the pane already holds what
//! the user typed, and hands it to the apply alongside the worker's result.

use std::sync::Arc;
use std::time::Instant;

use askrypt::{AskryptFile, MasterSecret, QuestionsData, SecretEntry, VaultStorage};
use zeroize::{Zeroize, Zeroizing};

use crate::session::VaultError;
use crate::settings::VaultLocation;
use crate::smartlock::{self, SMART_LOCK_TIMEOUT};

// ---------------------------------------------------------------------------
// Where a vault lives
// ---------------------------------------------------------------------------

/// Where the vault lives **and** the live backend that reads and writes it.
///
/// One value rather than two fields, because the pair is meaningless when only
/// half of it is set. It also has to be the *same* backend instance for the
/// life of the open vault: `ServerStorage` learns the vault's ETag when it
/// reads and sends it back as `If-Match` when it writes, so a rebuilt backend
/// would fetch whatever ETag the server holds *now* and happily overwrite
/// another device's edit.
#[derive(Clone)]
pub struct VaultHome {
    location: VaultLocation,
    storage: Arc<dyn VaultStorage>,
}

impl VaultHome {
    pub fn new(location: VaultLocation, storage: Arc<dyn VaultStorage>) -> Self {
        VaultHome { location, storage }
    }

    pub fn location(&self) -> &VaultLocation {
        &self.location
    }

    pub fn storage(&self) -> &Arc<dyn VaultStorage> {
        &self.storage
    }
}

// `VaultStorage` is an object-safe trait over backends and is not `Debug`, but
// every payload in a `Message` has to be. Name the location instead.
impl std::fmt::Debug for VaultHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHome")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

/// A vault read off a backend. Its bytes are still locked, so there is no key
/// here and no entries — distinct from [`SavedVault`], which is what a *write*
/// produces. Conflating the two is how a session loses its master key.
#[derive(Debug, Clone)]
pub struct OpenedVault {
    pub file: AskryptFile,
    pub home: VaultHome,
}

/// A vault re-encrypted and written, carrying the backend that did the writing
/// rather than a description of it.
#[derive(Debug, Clone)]
pub struct SavedVault {
    pub file: AskryptFile,
    pub home: VaultHome,
}

// ---------------------------------------------------------------------------
// The states
// ---------------------------------------------------------------------------

/// Bytes loaded; not one answer accepted yet.
pub struct Locked;

/// The first answer decrypted the *question list* but not the entries — the
/// layered unlock, a property of the vault format rather than a UI step.
pub struct PartiallyUnlocked {
    answer0: Zeroizing<String>,
    questions_data: QuestionsData,
}

/// Entries decrypted and in memory, with every answer and the master key.
pub struct Unlocked {
    answer0: Zeroizing<String>,
    /// Answers 1.., aligned index-for-index with `questions_data.questions`.
    /// The format treats the first answer separately, so this vector does too.
    answers: Zeroizing<Vec<String>>,
    questions_data: QuestionsData,
    entries: Vec<SecretEntry>,
    /// The vault's master key. **Not** an `Option`: every path into this state
    /// has one — an unlock recovers it from `decrypt_with_master`, and the
    /// questions editor mints it while building the file. `SPEC.md`'s "Master
    /// key lifetime" requires it be handed back to every save rather than
    /// rotated, and a key that cannot be absent cannot be forgotten.
    master: MasterSecret,
    modified: bool,
    /// When an earlier Smart Lock's 8-hour ceiling runs out, for a vault that
    /// reached this state through one. The bundle itself is *not* kept: only
    /// this deadline was ever read from it, and holding the re-encrypted
    /// answers beside the plaintext ones buys nothing.
    smart_lock_deadline: Option<Instant>,
}

/// Answers held re-encrypted in RAM: one answer re-opens the vault.
///
/// Not a vault state as far as the *format* is concerned — the file on disk is
/// untouched. It is a shallower lock than a full one: the entries and the
/// master key are gone, and what is left is the answer set encrypted under one
/// of its own members, plus what the unlock pane needs to ask for that one.
/// [`crate::smartlock`] builds this and reads it back; the fields are `pub` for
/// exactly that.
///
/// Ciphertext, salt and IVs only — nothing here wants zeroizing, and the
/// state must stay `Drop`-free so `with_state` can destructure it (E0509).
#[derive(Debug, Clone)]
pub struct SmartLocked {
    /// The index of the answer used as the key (never the first one).
    /// Retained for diagnostics; decryption keys off the stored salt and IVs,
    /// not this.
    #[allow(dead_code)]
    pub key_answer_index: usize,
    /// The question text for the selected answer (stored for display).
    pub key_question: String,
    /// Encrypted first answer (answer0) using the key answer.
    pub encrypted_answer0: Vec<u8>,
    /// Encrypted remaining answers using the key answer.
    pub encrypted_answers: Vec<u8>,
    /// Salt used for key derivation.
    pub salt: Vec<u8>,
    /// IV for `encrypted_answer0`. The two ciphertexts get an IV each because
    /// they share a key, and CBC under one key *and* one IV makes equal
    /// leading blocks encrypt to equal ciphertext — it would tell a reader of
    /// this blob how far the two plaintexts agree.
    pub iv_answer0: Vec<u8>,
    /// IV for `encrypted_answers`, distinct from `iv_answer0` for that reason.
    pub iv_answers: Vec<u8>,
    /// When the bundle was armed, which starts the 8-hour clock.
    pub armed_at: Instant,
}

impl SmartLocked {
    /// How long is left before this bundle drops to a full lock.
    pub fn remaining(&self) -> std::time::Duration {
        SMART_LOCK_TIMEOUT.saturating_sub(self.armed_at.elapsed())
    }

    /// Whether the 8-hour window has run out.
    pub fn expired(&self) -> bool {
        self.armed_at.elapsed() >= SMART_LOCK_TIMEOUT
    }
}

/// A vault, in exactly one of its states.
///
/// The type parameter is the state, and it carries that state's data — see the
/// module documentation. Construct one with [`Vault::opened`] or
/// [`Vault::created`] — the two ways a vault comes into being, reading one and
/// composing one; move between states with the transitions on [`VaultState`].
pub struct Vault<S = Locked> {
    /// The encrypted vault as last read or written.
    ///
    /// Never absent, in any state: the questions editor builds a real
    /// `AskryptFile` on its worker before the session ever adopts one, so even
    /// a vault that exists nowhere but this process has its bytes.
    file: AskryptFile,
    /// `None` for a vault that has never been written anywhere — exactly the
    /// case that makes the first Save become a Save As.
    home: Option<VaultHome>,
    state: S,
}

// ---------------------------------------------------------------------------
// What every state can do
// ---------------------------------------------------------------------------

impl<S> Vault<S> {
    /// The encrypted vault. Readable in every state — it is ciphertext.
    pub fn file(&self) -> &AskryptFile {
        &self.file
    }

    /// Where this vault lives, or `None` if it has never been written.
    pub fn home(&self) -> Option<&VaultHome> {
        self.home.as_ref()
    }

    /// The first question, which the format stores in the clear.
    pub fn question0(&self) -> &str {
        &self.file.question0
    }

    /// Whether this vault transliterates answers before hashing them. A
    /// derivation input, so it is read off the file rather than from settings.
    pub fn translit(&self) -> bool {
        self.file.params.translit
    }

    /// The vault's own work factor. Kept rather than reset to the current
    /// default, which would silently weaken (or re-cost) a vault saved
    /// somewhere new.
    pub fn iterations(&self) -> u32 {
        self.file.params.iterations
    }

    /// Wipe the secrets and drop back to the first question, keeping the bytes,
    /// the location and the backend — so unlocking again is local.
    ///
    /// This *is* the wipe: dropping `self.state` drops the answers, the
    /// entries, the question list and the master key, every one of which
    /// zeroizes itself.
    pub fn lock(self) -> Vault<Locked> {
        self.with_state(Locked)
    }

    /// Move to another state, carrying the file and the home across. Private:
    /// the public transitions below are the only legal moves.
    fn with_state<T>(self, state: T) -> Vault<T> {
        Vault {
            file: self.file,
            home: self.home,
            state,
        }
    }
}

// ---------------------------------------------------------------------------
// Locked
// ---------------------------------------------------------------------------

impl Vault<Locked> {
    /// Adopt a vault just read off a backend. Named for the pair it forms with
    /// [`Vault::created`], and so as not to read like `VaultState::open`, which
    /// is the `&mut` transition rather than a constructor.
    pub fn opened(opened: OpenedVault) -> Self {
        Vault {
            file: opened.file,
            home: Some(opened.home),
            state: Locked,
        }
    }

    /// What the worker needs to try the first answer.
    pub fn reveal_inputs(&self, answer0: String) -> RevealInputs {
        RevealInputs {
            file: self.file.clone(),
            answer0: Zeroizing::new(answer0),
        }
    }

    /// The first answer decrypted the question list. Takes the answer back from
    /// the caller rather than off the worker's reply, so an answer that turned
    /// out to be wrong is never stored.
    pub fn reveal(
        self,
        answer0: String,
        questions_data: QuestionsData,
    ) -> Vault<PartiallyUnlocked> {
        self.with_state(PartiallyUnlocked {
            answer0: Zeroizing::new(answer0),
            questions_data,
        })
    }
}

// ---------------------------------------------------------------------------
// PartiallyUnlocked
// ---------------------------------------------------------------------------

impl Vault<PartiallyUnlocked> {
    /// The remaining questions, decrypted by the first answer.
    pub fn questions_data(&self) -> &QuestionsData {
        &self.state.questions_data
    }

    /// What the worker needs to try the remaining answers.
    ///
    /// `answers` is answers 1.. — `decrypt_with_master` wants exactly as many
    /// as `questions_data.questions`, never the full list. That off-by-one is
    /// the format's, and this is the only place the app spells it out.
    pub fn unlock_inputs(&self, answers: Vec<String>) -> UnlockInputs {
        UnlockInputs {
            file: self.file.clone(),
            questions_data: self.state.questions_data.clone(),
            answers: Zeroizing::new(answers),
        }
    }

    /// Every answer together decrypted the entries and the master key.
    pub fn unlock(
        self,
        answers: Vec<String>,
        entries: Vec<SecretEntry>,
        master: MasterSecret,
    ) -> Vault<Unlocked> {
        let questions_data = self.state.questions_data.clone();
        let answer0 = self.state.answer0.clone();
        self.with_state(Unlocked {
            answer0,
            answers: Zeroizing::new(answers),
            questions_data,
            entries,
            master,
            modified: false,
            smart_lock_deadline: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Unlocked
// ---------------------------------------------------------------------------

impl Vault<Unlocked> {
    /// Adopt a vault the questions editor just built. The only way to reach
    /// [`Unlocked`] without an unlock, and the only place a master key is
    /// minted.
    pub fn created(built: Built, home: Option<VaultHome>) -> Self {
        Vault {
            file: built.file,
            home,
            state: Unlocked {
                answer0: Zeroizing::new(built.answer0),
                answers: Zeroizing::new(built.answers),
                questions_data: built.questions_data,
                entries: built.entries,
                master: built.master,
                // The built file exists only in memory until it is written.
                modified: true,
                smart_lock_deadline: None,
            },
        }
    }

    pub fn questions_data(&self) -> &QuestionsData {
        &self.state.questions_data
    }

    /// Every question, first one included — the shape `AskryptFile::create`
    /// wants, as opposed to the `questions_data` shape `decrypt` wants.
    pub fn questions(&self) -> Vec<String> {
        let mut questions = vec![self.file.question0.clone()];
        questions.extend(self.state.questions_data.questions.clone());
        questions
    }

    /// Every answer, first one included, to match [`Self::questions`]. The
    /// questions editor prefills from this.
    pub fn answers(&self) -> Vec<String> {
        let mut answers = vec![self.state.answer0.to_string()];
        answers.extend(self.state.answers.iter().cloned());
        answers
    }

    pub fn master(&self) -> &MasterSecret {
        &self.state.master
    }

    pub fn entries(&self) -> &[SecretEntry] {
        &self.state.entries
    }

    /// Append an entry, returning its index.
    pub fn add_entry(&mut self, entry: SecretEntry) -> usize {
        self.state.entries.push(entry);
        self.state.modified = true;
        self.state.entries.len() - 1
    }

    /// Replace an entry. Out-of-range indices are ignored rather than
    /// panicking: the index comes from a list the user may have just filtered.
    pub fn update_entry(&mut self, index: usize, entry: SecretEntry) {
        if let Some(slot) = self.state.entries.get_mut(index) {
            *slot = entry;
            self.state.modified = true;
        }
    }

    /// Delete an entry. The removed `SecretEntry` is dropped here, which wipes
    /// it — callers get a bool rather than the secret back.
    pub fn remove_entry(&mut self, index: usize) -> bool {
        if index >= self.state.entries.len() {
            return false;
        }
        self.state.entries.remove(index);
        self.state.modified = true;
        true
    }

    pub fn is_modified(&self) -> bool {
        self.state.modified
    }

    /// Collect everything the worker needs to re-encrypt this vault.
    ///
    /// Unconditional — an unlocked vault always has answers and a key, so there
    /// is no "nothing to save" case to handle at the call site. This is the one
    /// place the `[question0, ..rest]` / `[answer0, ..rest]` reassembly the
    /// format wants is written down.
    pub fn save_request(&self) -> SaveRequest {
        SaveRequest {
            questions: self.questions(),
            answers: self.answers(),
            entries: self.state.entries.clone(),
            iterations: self.iterations(),
            translit: self.translit(),
            master: self.state.master.clone(),
        }
    }

    /// Where a plain "Save" writes. `None` means this vault has never been
    /// persisted, so Save has to become Save As.
    pub fn save_target(&self) -> Option<VaultHome> {
        self.home.clone()
    }

    /// Adopt a written vault: new bytes, its home, and no unsaved changes.
    pub fn saved(mut self, saved: SavedVault) -> Self {
        self.file = saved.file;
        self.home = Some(saved.home);
        self.state.modified = false;
        self
    }

    /// What the worker needs to arm Smart Lock.
    pub fn smart_lock_inputs(&self) -> SmartLockInputs {
        SmartLockInputs {
            answer0: self.state.answer0.clone(),
            answers: self.state.answers.clone(),
            questions: self.state.questions_data.questions.clone(),
            translit: self.translit(),
        }
    }

    /// Whether Smart Lock has an answer to key on. It deliberately never uses
    /// the first one, so a two-question vault is the minimum.
    ///
    /// Distinct from [`VaultState::can_smart_lock`], which is the *rail's*
    /// question — whether to draw the button at all. The button is drawn for
    /// any unlocked vault and this is what the handler checks, so a
    /// one-question vault gets a sentence rather than a silently missing
    /// control.
    pub fn has_key_answer(&self) -> bool {
        !self.state.answers.is_empty()
    }

    /// Arm Smart Lock. Dropping the old state wipes the entries and the key;
    /// the answers survive only inside the bundle, re-encrypted.
    pub fn smart_lock(self, bundle: SmartLocked) -> Vault<SmartLocked> {
        self.with_state(bundle)
    }

    /// Whether the 8-hour ceiling inherited from a Smart Lock has run out. A
    /// vault opened by an ordinary unlock has no such ceiling.
    pub fn smart_lock_expired(&self) -> bool {
        self.state
            .smart_lock_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

// ---------------------------------------------------------------------------
// SmartLocked
// ---------------------------------------------------------------------------

impl Vault<SmartLocked> {
    /// The one question whose answer reopens the vault.
    pub fn key_question(&self) -> &str {
        &self.state.key_question
    }

    /// How long the armed Smart Lock has left before it drops to a full lock.
    pub fn remaining(&self) -> std::time::Duration {
        self.state.remaining()
    }

    pub fn expired(&self) -> bool {
        self.state.expired()
    }

    /// What the worker needs to recover the vault from one answer.
    pub fn smart_unlock_inputs(&self, answer: String) -> SmartUnlockInputs {
        SmartUnlockInputs {
            file: self.file.clone(),
            bundle: self.state.clone(),
            answer: Zeroizing::new(answer),
            translit: self.translit(),
        }
    }

    /// One answer recovered the whole set and reopened the vault. The bundle is
    /// consumed; only its deadline carries over, so the 8-hour ceiling still
    /// applies to the session it reopened.
    pub fn smart_unlock(self, recovered: SmartUnlockResult) -> Vault<Unlocked> {
        self.with_state(Unlocked {
            answer0: Zeroizing::new(recovered.answer0),
            answers: Zeroizing::new(recovered.answers),
            questions_data: recovered.questions_data,
            entries: recovered.entries,
            master: recovered.master,
            modified: false,
            smart_lock_deadline: Some(Instant::now() + SMART_LOCK_TIMEOUT),
        })
    }
}

// ---------------------------------------------------------------------------
// The enum at the field
// ---------------------------------------------------------------------------

/// A vault in whichever state it is in, as one value that can live in a struct
/// field.
///
/// Panes match on this and get a handle carrying only the operations their
/// state allows. The `apply_*` methods are the only places a state is consumed;
/// each one is a no-op (returning `false`) when the vault is not in the state
/// that transition starts from, so a stale completion message cannot corrupt
/// the vault it arrives at.
#[derive(Default)]
pub enum VaultState {
    /// No vault at all — nothing opened yet, or the last one was closed. The
    /// only state holding no bytes, which is why every read below starts by
    /// ruling it out. New Vault and Open Vault are the ways out.
    #[default]
    None,
    /// [`Locked`]: the ciphertext is here and nothing has been decrypted. The
    /// unlock pane can ask the first question (`question0` is stored in the
    /// clear); answering it correctly moves to `Partial`.
    Locked(Vault<Locked>),
    /// [`PartiallyUnlocked`]: the first answer opened the *question list* but
    /// not the entries — the format's layered unlock, not a UI step. The pane
    /// can now show the remaining questions; all the answers together move to
    /// `Unlocked`, and a wrong one leaves this state untouched.
    Partial(Vault<PartiallyUnlocked>),
    /// [`Unlocked`]: entries in memory, with every answer and the master key.
    /// The only state that can save, edit or re-key, and the only one carrying
    /// the dirty flag — so unsaved changes cannot outlive the edits. Leaving it
    /// drops the secrets (`lock`, `apply_smart_lock`, closing the vault).
    Unlocked(Vault<Unlocked>),
    /// [`SmartLocked`]: the answers held re-encrypted in RAM under one of their
    /// own members, so a single answer reopens the vault. The file on disk is
    /// untouched — this is a shallower lock than `Locked`, and it decays into
    /// one after 8 hours (`smart_lock_expired`).
    Smart(Vault<SmartLocked>),
}

impl VaultState {
    // -- reads available whatever the state ---------------------------------

    pub fn is_open(&self) -> bool {
        !matches!(self, VaultState::None)
    }

    /// The encrypted vault, in every state but [`VaultState::None`].
    pub fn file(&self) -> Option<&AskryptFile> {
        match self {
            VaultState::None => None,
            VaultState::Locked(vault) => Some(vault.file()),
            VaultState::Partial(vault) => Some(vault.file()),
            VaultState::Unlocked(vault) => Some(vault.file()),
            VaultState::Smart(vault) => Some(vault.file()),
        }
    }

    pub fn home(&self) -> Option<&VaultHome> {
        match self {
            VaultState::None => None,
            VaultState::Locked(vault) => vault.home(),
            VaultState::Partial(vault) => vault.home(),
            VaultState::Unlocked(vault) => vault.home(),
            VaultState::Smart(vault) => vault.home(),
        }
    }

    pub fn location(&self) -> Option<&VaultLocation> {
        self.home().map(VaultHome::location)
    }

    pub fn question0(&self) -> Option<&str> {
        match self {
            VaultState::None => None,
            VaultState::Locked(vault) => Some(vault.question0()),
            VaultState::Partial(vault) => Some(vault.question0()),
            VaultState::Unlocked(vault) => Some(vault.question0()),
            VaultState::Smart(vault) => Some(vault.question0()),
        }
    }

    /// The question list the unlock pane is asking for, once the first answer
    /// has revealed it. `None` before that, and once fully unlocked the
    /// unlocked handle carries its own.
    pub fn questions_data(&self) -> Option<&QuestionsData> {
        match self {
            VaultState::Partial(vault) => Some(vault.questions_data()),
            VaultState::Unlocked(vault) => Some(vault.questions_data()),
            _ => None,
        }
    }

    /// Unsaved changes. Only an unlocked vault can have any — every lock path
    /// drops the state that held the edits, so the flag goes with them.
    pub fn is_modified(&self) -> bool {
        self.unlocked().is_some_and(Vault::is_modified)
    }

    // -- typed handles ------------------------------------------------------

    pub fn unlocked(&self) -> Option<&Vault<Unlocked>> {
        match self {
            VaultState::Unlocked(vault) => Some(vault),
            _ => None,
        }
    }

    pub fn unlocked_mut(&mut self) -> Option<&mut Vault<Unlocked>> {
        match self {
            VaultState::Unlocked(vault) => Some(vault),
            _ => None,
        }
    }

    pub fn locked(&self) -> Option<&Vault<Locked>> {
        match self {
            VaultState::Locked(vault) => Some(vault),
            _ => None,
        }
    }

    pub fn partial(&self) -> Option<&Vault<PartiallyUnlocked>> {
        match self {
            VaultState::Partial(vault) => Some(vault),
            _ => None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self, VaultState::Unlocked(_))
    }

    pub fn smart(&self) -> Option<&Vault<SmartLocked>> {
        match self {
            VaultState::Smart(vault) => Some(vault),
            _ => None,
        }
    }

    // -- what the UI may offer ----------------------------------------------
    //
    // These used to be a separate `vault::Status` enum re-derived from the
    // session's fields. It had exactly these five values, so it was a copy of
    // this enum's discriminant kept in step by hand; the rules moved here and
    // it is gone. Buttons are *hidden*, not disabled, when a state disallows
    // them, and `panes::sidebar` only ever asks — it never matches on the
    // variants itself, so the rules stay in one place.

    /// The state's name, for the status bar.
    pub fn label(&self) -> &'static str {
        match self {
            VaultState::None => "No vault",
            VaultState::Locked(_) => "Locked",
            VaultState::Partial(_) => "Partially unlocked",
            VaultState::Unlocked(_) => "Unlocked",
            VaultState::Smart(_) => "Smart Locked",
        }
    }

    /// Always, like [`Self::can_open`]: starting over is offered in every
    /// state, rather than only from a dedicated Welcome screen the way the
    /// previous UI did it.
    pub fn can_create(&self) -> bool {
        true
    }

    /// Always: opening another vault is offered in every state.
    pub fn can_open(&self) -> bool {
        true
    }

    /// Closing needs something to close: every state but [`VaultState::None`],
    /// including a vault that has never been written anywhere (the questions
    /// editor's output) — the unsaved-changes gate is what protects that one.
    pub fn can_close(&self) -> bool {
        self.is_open()
    }

    pub fn can_unlock(&self) -> bool {
        matches!(
            self,
            VaultState::Locked(_) | VaultState::Partial(_) | VaultState::Smart(_)
        )
    }

    /// Offered for any unlocked vault. Whether there is an answer to key on is
    /// [`Vault::has_key_answer`], checked by the handler so a one-question
    /// vault gets a sentence rather than a button that quietly is not there.
    pub fn can_smart_lock(&self) -> bool {
        self.is_unlocked()
    }

    /// Covers both depths: `Lock` from unlocked, `Full Lock` out of Smart Lock.
    /// Also reads as "there is something worth locking", which is what decides
    /// whether the idle timer runs.
    pub fn can_lock(&self) -> bool {
        matches!(self, VaultState::Unlocked(_) | VaultState::Smart(_))
    }

    pub fn lock_label(&self) -> &'static str {
        match self {
            VaultState::Smart(_) => "Full Lock",
            _ => "Lock",
        }
    }

    /// Saving needs the decrypted entries, so unlocked only.
    pub fn can_save(&self) -> bool {
        self.is_unlocked()
    }

    pub fn can_save_as(&self) -> bool {
        self.can_save()
    }

    /// Editing the questions re-derives every key, so it needs every answer.
    pub fn can_edit_questions(&self) -> bool {
        self.is_unlocked()
    }

    /// Whether the source wizard's Cancel button leads anywhere. With no vault
    /// open the shell's default pane *is* the wizard (`App::default_pane`), so
    /// cancelling would dismiss the pane onto itself; the button is hidden
    /// there rather than left to do nothing.
    pub fn can_cancel_wizard(&self) -> bool {
        self.is_open()
    }

    // -- transitions --------------------------------------------------------

    /// Adopt a freshly read vault, discarding whatever was open.
    pub fn open(&mut self, opened: OpenedVault) {
        *self = VaultState::Locked(Vault::opened(opened));
    }

    /// Adopt a vault the questions editor built, keeping the home of the vault
    /// it replaces: changing the questions does not move the file, and a vault
    /// created from nothing has no home to keep.
    pub fn adopt_built(&mut self, built: Built) {
        let home = match std::mem::take(self) {
            VaultState::None => None,
            VaultState::Locked(vault) => vault.home,
            VaultState::Partial(vault) => vault.home,
            VaultState::Unlocked(vault) => vault.home,
            VaultState::Smart(vault) => vault.home,
        };
        *self = VaultState::Unlocked(Vault::created(built, home));
    }

    /// The first answer decrypted the question list.
    pub fn apply_reveal(&mut self, answer0: String, questions_data: QuestionsData) -> bool {
        match std::mem::take(self) {
            VaultState::Locked(vault) => {
                *self = VaultState::Partial(vault.reveal(answer0, questions_data));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// Every answer together decrypted the entries.
    pub fn apply_unlock(
        &mut self,
        answers: Vec<String>,
        entries: Vec<SecretEntry>,
        master: MasterSecret,
    ) -> bool {
        match std::mem::take(self) {
            VaultState::Partial(vault) => {
                *self = VaultState::Unlocked(vault.unlock(answers, entries, master));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// The vault was written: adopt the new bytes and its home.
    pub fn apply_saved(&mut self, saved: SavedVault) -> bool {
        match std::mem::take(self) {
            VaultState::Unlocked(vault) => {
                *self = VaultState::Unlocked(vault.saved(saved));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// Arm Smart Lock.
    pub fn apply_smart_lock(&mut self, bundle: SmartLocked) -> bool {
        match std::mem::take(self) {
            VaultState::Unlocked(vault) => {
                *self = VaultState::Smart(vault.smart_lock(bundle));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// One answer reopened the vault from Smart Lock.
    pub fn apply_smart_unlock(&mut self, recovered: SmartUnlockResult) -> bool {
        match std::mem::take(self) {
            VaultState::Smart(vault) => {
                *self = VaultState::Unlocked(vault.smart_unlock(recovered));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// Wipe the secrets and drop back to the first question, keeping the bytes
    /// and the home so unlocking again is local.
    pub fn lock(&mut self) {
        *self = match std::mem::take(self) {
            VaultState::None => VaultState::None,
            VaultState::Locked(vault) => VaultState::Locked(vault),
            VaultState::Partial(vault) => VaultState::Locked(vault.lock()),
            VaultState::Unlocked(vault) => VaultState::Locked(vault.lock()),
            VaultState::Smart(vault) => VaultState::Locked(vault.lock()),
        };
    }

    /// The deepest of the three lock depths: the bytes go too, so coming back
    /// means re-opening the file.
    pub fn close(&mut self) {
        *self = VaultState::None;
    }
}

// ---------------------------------------------------------------------------
// Worker inputs and results
// ---------------------------------------------------------------------------

/// Inputs for the first-answer step: one 600k-iteration derivation.
pub struct RevealInputs {
    file: AskryptFile,
    answer0: Zeroizing<String>,
}

impl RevealInputs {
    /// **Worker-thread only.** A wrong answer is not detected by a check — it
    /// is a decryption that fails.
    pub fn run(self) -> Result<QuestionsData, String> {
        self.file
            .get_questions_data(self.answer0.to_string())
            .map_err(|e| e.to_string())
    }
}

/// Inputs for the full unlock: one 600k-iteration derivation, then the entries.
pub struct UnlockInputs {
    file: AskryptFile,
    questions_data: QuestionsData,
    answers: Zeroizing<Vec<String>>,
}

impl UnlockInputs {
    /// **Worker-thread only.**
    pub fn run(self) -> Result<Decrypted, String> {
        let (entries, master) = self
            .file
            .decrypt_with_master(&self.questions_data, self.answers.to_vec())
            .map_err(|e| e.to_string())?;
        Ok(Decrypted { entries, master })
    }
}

/// What a full unlock recovered.
#[derive(Clone)]
pub struct Decrypted {
    pub entries: Vec<SecretEntry>,
    pub master: MasterSecret,
}

// This rides inside a `Message`, and every `Message` derives `Debug`.
// `SecretEntry` derives a plain `Debug` that prints the secret, so this must
// not: printing one message would print every password in the vault.
impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field(
                "entries",
                &format_args!("<{} redacted>", self.entries.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Inputs for arming Smart Lock: one 2M-iteration derivation.
pub struct SmartLockInputs {
    answer0: Zeroizing<String>,
    answers: Zeroizing<Vec<String>>,
    questions: Vec<String>,
    translit: bool,
}

impl SmartLockInputs {
    /// **Worker-thread only.**
    pub fn run(self) -> Result<SmartLocked, String> {
        smartlock::create(&self.answers, &self.answer0, &self.questions, self.translit)
            .map_err(|e| e.to_string())
    }
}

/// Inputs for reopening from Smart Lock: three derivations in a row.
pub struct SmartUnlockInputs {
    file: AskryptFile,
    bundle: SmartLocked,
    answer: Zeroizing<String>,
    translit: bool,
}

impl SmartUnlockInputs {
    /// **Worker-thread only.** Recover the answers, re-read the question list,
    /// then decrypt the entries — 2M + 600k + 600k iterations.
    pub fn run(self) -> Result<SmartUnlockResult, String> {
        let (answer0, answers) = smartlock::recover(&self.bundle, &self.answer, self.translit)
            .map_err(|e| e.to_string())?;
        let questions_data = self
            .file
            .get_questions_data(answer0.clone())
            .map_err(|e| e.to_string())?;
        let (entries, master) = self
            .file
            .decrypt_with_master(&questions_data, answers.clone())
            .map_err(|e| e.to_string())?;

        Ok(SmartUnlockResult {
            answer0,
            answers,
            questions_data,
            entries,
            master,
        })
    }
}

/// What a Smart Lock recovery produced: the answers, and the vault they opened.
#[derive(Clone)]
pub struct SmartUnlockResult {
    pub answer0: String,
    pub answers: Vec<String>,
    pub questions_data: QuestionsData,
    pub entries: Vec<SecretEntry>,
    /// The vault's master key, so the next save re-wraps it rather than
    /// rotating it.
    pub master: MasterSecret,
}

// This rides inside a `Message`, and every `Message` derives `Debug`. It is
// nothing but secrets, so say how many there are and not what they are.
impl std::fmt::Debug for SmartUnlockResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartUnlockResult")
            .field(
                "answers",
                &format_args!("<{} redacted>", self.answers.len()),
            )
            .field(
                "entries",
                &format_args!("<{} redacted>", self.entries.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Inputs for building a vault out of questions and answers: two 600k-iteration
/// derivations, plus one more to read the authoritative question list back.
pub struct RekeyInputs {
    pub questions: Vec<String>,
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    pub iterations: u32,
    pub translit: bool,
    /// The open vault's existing key, re-wrapped rather than rotated — that is
    /// what the master-key indirection is for. `None` only when this run is
    /// bringing a vault into existence, which is the one place in the app a key
    /// is minted.
    pub master: Option<MasterSecret>,
}

impl RekeyInputs {
    /// **Worker-thread only.**
    ///
    /// The question list is read back out of the freshly built file rather than
    /// assembled by hand, so the `QuestionsData` the session adopts — salt
    /// included — is exactly the one the file carries.
    pub fn run(self) -> Result<Built, String> {
        // Minted here rather than left to `create`, so the session can adopt
        // the very key this file was built with.
        let master = self.master.unwrap_or_else(MasterSecret::generate);

        let file = AskryptFile::create(
            self.questions.clone(),
            self.answers.clone(),
            self.entries.clone(),
            Some(self.iterations),
            self.translit,
            Some(&master),
        )
        .map_err(|e| e.to_string())?;

        let answer0 = self.answers.first().cloned().unwrap_or_default();
        let questions_data = file
            .get_questions_data(answer0.clone())
            .map_err(|e| e.to_string())?;

        Ok(Built {
            file,
            questions_data,
            answer0,
            answers: self.answers.into_iter().skip(1).collect(),
            entries: self.entries,
            master,
        })
    }
}

/// Everything a successful build produced, adopted in one go by
/// [`VaultState::adopt_built`].
#[derive(Clone)]
pub struct Built {
    pub file: AskryptFile,
    pub questions_data: QuestionsData,
    pub answer0: String,
    /// Answers 1.., matching `questions_data.questions`.
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    /// The master key the built file is keyed on: the open vault's own when the
    /// questions were merely changed, a fresh one when this call created the
    /// vault.
    pub master: MasterSecret,
}

// Rides inside a `Message`; see `SmartUnlockResult`.
impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built")
            .field("questions", &(self.questions_data.questions.len() + 1))
            .field(
                "entries",
                &format_args!("<{} redacted>", self.entries.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Everything needed to rebuild and re-encrypt the vault, collected on the main
/// thread so the worker owns its inputs.
///
/// Holds every answer and every decrypted entry, so it is secret material: it
/// wipes on drop.
pub struct SaveRequest {
    pub questions: Vec<String>,
    pub answers: Vec<String>,
    pub entries: Vec<SecretEntry>,
    pub iterations: u32,
    pub translit: bool,
    /// The vault's existing master key. Not an `Option`: only an unlocked vault
    /// can be saved, and an unlocked vault always has one.
    pub master: MasterSecret,
}

impl Drop for SaveRequest {
    fn drop(&mut self) {
        self.answers.zeroize();
        // `entries` are `SecretEntry` and `master` is a `MasterSecret`, both of
        // which wipe themselves on drop.
    }
}

/// Re-encrypt the vault and write it. **Worker-thread only** — this runs two
/// 600k-iteration key derivations plus (for a server vault) an HTTP round trip.
pub fn write_vault(request: SaveRequest, home: VaultHome) -> Result<SavedVault, VaultError> {
    let file = AskryptFile::create(
        request.questions.clone(),
        request.answers.clone(),
        request.entries.clone(),
        Some(request.iterations),
        request.translit,
        Some(&request.master),
    )
    .map_err(|e| VaultError::log_crypto("Failed to build vault", e.as_ref()))?;

    home.storage()
        .save_vault(&file)
        .map_err(|e| VaultError::log("Failed to save vault", &e))?;

    Ok(SavedVault { file, home })
}

#[cfg(test)]
mod tests {
    use super::*;
    use askrypt::MemoryStorage;

    /// A low iteration count keeps these fast; the KDF itself is `core`'s to
    /// test.
    const ITERATIONS: u32 = 1_000;

    fn entry(name: &str) -> SecretEntry {
        SecretEntry {
            name: name.to_string(),
            user_name: "testingaccount".to_string(),
            secret: "hunter2".to_string(),
            url: "https://example.com".to_string(),
            notes: String::new(),
            entry_type: "Login".to_string(),
            tags: vec!["work".to_string()],
            created: 1_581_428_873,
            modified: 1_581_428_873,
            hidden: false,
            card: Default::default(),
        }
    }

    fn questions() -> Vec<String> {
        vec!["First pet?".to_string(), "First street?".to_string()]
    }

    fn answers() -> Vec<String> {
        vec!["Rex".to_string(), "Baker Street".to_string()]
    }

    fn home() -> VaultHome {
        VaultHome::new(
            VaultLocation::LocalFile("/dev/null".into()),
            Arc::new(MemoryStorage::default()),
        )
    }

    /// What the questions editor does: build a vault from nothing.
    fn build_new(entries: Vec<SecretEntry>) -> Built {
        RekeyInputs {
            questions: questions(),
            answers: answers(),
            entries,
            iterations: ITERATIONS,
            translit: false,
            master: None,
        }
        .run()
        .expect("the vault should build")
    }

    /// One of each state, built by hand rather than through the transitions.
    ///
    /// The button rules have nothing to do with the crypto, and reaching
    /// `Smart` honestly would cost a 2,000,000-iteration derivation for a test
    /// that never looks inside the bundle.
    fn every_state() -> [VaultState; 5] {
        let file = AskryptFile::create(
            questions(),
            answers(),
            vec![],
            Some(ITERATIONS),
            false,
            None,
        )
        .expect("the vault should build");
        let questions_data = file
            .get_questions_data("Rex".to_string())
            .expect("the first answer should decrypt the question list");

        [
            VaultState::None,
            VaultState::Locked(Vault {
                file: file.clone(),
                home: None,
                state: Locked,
            }),
            VaultState::Partial(Vault {
                file: file.clone(),
                home: None,
                state: PartiallyUnlocked {
                    answer0: Zeroizing::new("Rex".to_string()),
                    questions_data: questions_data.clone(),
                },
            }),
            VaultState::Unlocked(Vault {
                file: file.clone(),
                home: None,
                state: Unlocked {
                    answer0: Zeroizing::new("Rex".to_string()),
                    answers: Zeroizing::new(vec!["Baker Street".to_string()]),
                    questions_data,
                    entries: vec![],
                    master: MasterSecret::generate(),
                    modified: false,
                    smart_lock_deadline: None,
                },
            }),
            VaultState::Smart(Vault {
                file,
                home: None,
                state: SmartLocked {
                    key_answer_index: 1,
                    key_question: "First street?".to_string(),
                    encrypted_answer0: Vec::new(),
                    encrypted_answers: Vec::new(),
                    salt: Vec::new(),
                    iv_answer0: Vec::new(),
                    iv_answers: Vec::new(),
                    armed_at: Instant::now(),
                },
            }),
        ]
    }

    /// A vault sitting in a `MemoryStorage`, plus that storage as its home.
    fn stored_vault() -> (VaultState, VaultHome) {
        let home = home();
        let mut vault = VaultState::default();
        vault.adopt_built(build_new(vec![entry("GitHub")]));

        let request = vault.unlocked().unwrap().save_request();
        let saved = write_vault(request, home.clone()).expect("the vault should be written");
        vault.apply_saved(saved);

        (vault, home)
    }

    /// The layered unlock, one state at a time, over a vault that was really
    /// written and really read back.
    #[test]
    fn a_written_vault_reads_back_through_the_layered_unlock() {
        let (_, home) = stored_vault();

        let file = home.storage().load_vault().expect("the vault should load");
        let mut vault = VaultState::default();
        vault.open(OpenedVault {
            file,
            home: home.clone(),
        });

        // Locked: the first question is readable, nothing else is.
        let locked = vault.locked().expect("the vault should be locked");
        assert_eq!(locked.question0(), "First pet?");
        assert_eq!(locked.iterations(), ITERATIONS);
        assert!(vault.questions_data().is_none());
        assert!(!vault.is_modified());

        // A wrong first answer is not reported — it simply fails to decrypt.
        assert!(
            vault
                .locked()
                .unwrap()
                .reveal_inputs("Fido".to_string())
                .run()
                .is_err()
        );

        let questions_data = vault
            .locked()
            .unwrap()
            .reveal_inputs("Rex".to_string())
            .run()
            .expect("the first answer should decrypt the question list");
        assert!(vault.apply_reveal("Rex".to_string(), questions_data));

        // Partially unlocked: the remaining questions, and only those.
        let partial = vault.partial().expect("the vault should be partial");
        assert_eq!(
            partial.questions_data().questions,
            vec!["First street?".to_string()]
        );
        assert!(vault.unlocked().is_none());

        let rest = vec!["Baker Street".to_string()];
        let decrypted = vault
            .partial()
            .unwrap()
            .unlock_inputs(rest.clone())
            .run()
            .expect("the remaining answers should decrypt the entries");
        assert!(vault.apply_unlock(rest, decrypted.entries, decrypted.master));

        let unlocked = vault.unlocked().expect("the vault should be unlocked");
        assert_eq!(unlocked.entries().len(), 1);
        assert_eq!(unlocked.entries()[0].name, "GitHub");
        assert_eq!(unlocked.entries()[0].secret, "hunter2");
        // `created` is carried across a save; only `modified` is ever restamped.
        assert_eq!(unlocked.entries()[0].created, 1_581_428_873);
        // Just opened and read: nothing to save.
        assert!(!vault.is_modified());
    }

    /// `SPEC.md`, "Master key lifetime": the key is minted once and preserved
    /// for the life of the vault. Without the hand-back, a second save would
    /// mint a second key and orphan anything encrypted under the first.
    #[test]
    fn saving_preserves_the_master_key() {
        let (mut vault, home) = stored_vault();
        let minted = vault.unlocked().unwrap().master().clone();

        vault.unlocked_mut().unwrap().add_entry(entry("GitLab"));
        assert!(vault.is_modified());

        let request = vault.unlocked().unwrap().save_request();
        // The request carries the key it must re-wrap, not an absent one.
        assert_eq!(request.master, minted);
        let saved = write_vault(request, home.clone()).expect("the vault should be written again");
        assert!(vault.apply_saved(saved));
        assert!(!vault.is_modified(), "a save clears the dirty flag");
        assert_eq!(vault.unlocked().unwrap().master(), &minted);

        // And the key really is the one the file now on disk is keyed on.
        let reopened = home.storage().load_vault().expect("the vault should load");
        let questions_data = reopened.get_questions_data("Rex".to_string()).unwrap();
        let (entries, on_disk) = reopened
            .decrypt_with_master(&questions_data, vec!["Baker Street".to_string()])
            .expect("the remaining answers should decrypt the entries");
        assert_eq!(on_disk, minted);
        assert_eq!(entries.len(), 2);
    }

    /// Changing the questions re-wraps the same key under the new answers, so
    /// everything stored under it stays readable — and the old answers stop
    /// working.
    #[test]
    fn changing_the_questions_keeps_the_master_key() {
        let (mut vault, home) = stored_vault();
        let minted = vault.unlocked().unwrap().master().clone();

        let built = RekeyInputs {
            questions: vec!["New first?".to_string(), "New second?".to_string()],
            answers: vec!["alpha".to_string(), "beta".to_string()],
            entries: vault.unlocked().unwrap().entries().to_vec(),
            iterations: ITERATIONS,
            translit: false,
            master: Some(minted.clone()),
        }
        .run()
        .expect("the vault should rebuild");
        vault.adopt_built(built);

        let unlocked = vault.unlocked().expect("re-keying lands unlocked");
        assert_eq!(unlocked.master(), &minted);
        assert_eq!(unlocked.question0(), "New first?");
        // A rebuilt file exists only in memory until it is written.
        assert!(vault.is_modified());
        // The home is kept: changing the questions does not move the file.
        assert!(vault.home().is_some());

        let request = vault.unlocked().unwrap().save_request();
        assert_eq!(request.questions, vec!["New first?", "New second?"]);
        assert_eq!(request.answers, vec!["alpha", "beta"]);
        let saved = write_vault(request, home.clone()).expect("the vault should be written");
        vault.apply_saved(saved);

        let reopened = home.storage().load_vault().expect("the vault should load");
        assert!(
            reopened.get_questions_data("Rex".to_string()).is_err(),
            "the old answers must stop working"
        );
        let questions_data = reopened.get_questions_data("alpha".to_string()).unwrap();
        let (_, on_disk) = reopened
            .decrypt_with_master(&questions_data, vec!["beta".to_string()])
            .expect("the new answers should decrypt the entries");
        assert_eq!(on_disk, minted);
    }

    /// A vault built from nothing has no home, which is what makes its first
    /// Save a Save As.
    #[test]
    fn a_vault_built_from_nothing_has_no_home() {
        let mut vault = VaultState::default();
        vault.adopt_built(build_new(vec![]));

        let unlocked = vault.unlocked().expect("re-keying lands unlocked");
        assert!(unlocked.save_target().is_none());
        assert!(vault.is_modified());
    }

    /// A transition applied from the wrong state changes nothing — a stale
    /// completion message cannot corrupt the vault it arrives at.
    #[test]
    fn a_transition_from_the_wrong_state_is_a_no_op() {
        let (mut vault, _) = stored_vault();
        let questions_data = vault.unlocked().unwrap().questions_data().clone();

        // Already unlocked: a first-answer result has nothing to do.
        assert!(!vault.apply_reveal("Rex".to_string(), questions_data));
        assert!(vault.unlocked().is_some(), "the vault stays where it was");

        vault.lock();
        assert!(vault.locked().is_some());
        // Locked: an unlock result cannot skip the partial step.
        assert!(!vault.apply_unlock(vec![], vec![], MasterSecret::generate()));
        assert!(vault.locked().is_some());
    }

    /// Locking keeps the bytes and the home so unlocking again is local, and
    /// takes the unsaved-changes flag with the state that owned the edits.
    #[test]
    fn locking_keeps_the_bytes_and_drops_the_secrets() {
        let (mut vault, _) = stored_vault();
        vault.unlocked_mut().unwrap().add_entry(entry("GitLab"));
        assert!(vault.is_modified());

        vault.lock();
        assert!(vault.locked().is_some());
        assert!(vault.file().is_some(), "the bytes stay");
        assert!(vault.home().is_some(), "so does where they live");
        assert!(vault.questions_data().is_none());
        assert!(!vault.is_modified());

        vault.close();
        assert!(!vault.is_open());
        assert!(vault.file().is_none());
    }

    /// Smart Lock: arm it, then one answer brings the whole vault back.
    #[test]
    fn smart_lock_reopens_from_one_answer() {
        let (mut vault, _) = stored_vault();
        let minted = vault.unlocked().unwrap().master().clone();
        assert!(vault.unlocked().unwrap().has_key_answer());

        let bundle = vault
            .unlocked()
            .unwrap()
            .smart_lock_inputs()
            .run()
            .expect("the bundle should be built");
        assert!(vault.apply_smart_lock(bundle));

        let smart = vault.smart().expect("the vault should be smart locked");
        // Two questions, so the only answer it can key on is the second.
        assert_eq!(smart.key_question(), "First street?");
        assert!(!smart.expired());
        assert!(vault.unlocked().is_none(), "the entries are gone");

        let recovered = vault
            .smart()
            .unwrap()
            .smart_unlock_inputs("Baker Street".to_string())
            .run()
            .expect("the key answer should reopen the vault");
        assert!(vault.apply_smart_unlock(recovered));

        let unlocked = vault.unlocked().expect("the vault should be unlocked");
        assert_eq!(unlocked.entries().len(), 1);
        assert_eq!(unlocked.master(), &minted);
        assert_eq!(unlocked.answers(), answers());
        // The 8-hour ceiling carries over, but has not run out.
        assert!(!unlocked.smart_lock_expired());
    }

    /// Entry edits mark the vault dirty and survive into the save request.
    #[test]
    fn entry_edits_reach_the_save_request() {
        let (mut state, _) = stored_vault();
        let vault = state.unlocked_mut().unwrap();

        assert_eq!(vault.add_entry(entry("GitLab")), 1);
        vault.update_entry(0, entry("GitHub Enterprise"));
        assert!(!vault.remove_entry(9), "an out-of-range delete is ignored");
        assert!(vault.remove_entry(1));

        assert_eq!(vault.entries().len(), 1);
        assert_eq!(vault.entries()[0].name, "GitHub Enterprise");
        assert_eq!(vault.save_request().entries.len(), 1);
        assert!(state.is_modified());
    }

    // -----------------------------------------------------------------------
    // The rules the nav rail asks about. These moved off a `vault::Status`
    // enum whose five values were a hand-kept copy of `VaultState`'s.
    // -----------------------------------------------------------------------

    /// The whole point of the rail's action block: which buttons a state shows.
    #[test]
    fn button_visibility_per_state() {
        // (new/open, close, unlock, smart_lock, lock, save)
        let expected = [
            //  new/open, close, unlock, smart, lock, save
            (true, false, false, false, false, false), // None
            (true, true, true, false, false, false),   // Locked
            (true, true, true, false, false, false),   // Partial
            (true, true, false, true, true, true),     // Unlocked
            (true, true, true, false, true, false),    // Smart
        ];

        for (state, (open, close, unlock, smart_lock, lock, save)) in
            every_state().iter().zip(expected)
        {
            let label = state.label();
            assert_eq!(state.can_create(), open, "new in {label}");
            assert_eq!(state.can_open(), open, "open in {label}");
            assert_eq!(state.can_close(), close, "close in {label}");
            assert_eq!(state.can_unlock(), unlock, "unlock in {label}");
            assert_eq!(state.can_smart_lock(), smart_lock, "smart lock in {label}");
            assert_eq!(state.can_lock(), lock, "lock in {label}");
            assert_eq!(state.can_save(), save, "save in {label}");
            assert_eq!(state.can_save_as(), save, "save as in {label}");
            assert_eq!(state.can_edit_questions(), save, "questions in {label}");
        }
    }

    /// Cancelling the wizard with nothing open would land back on the wizard.
    #[test]
    fn the_wizard_offers_cancel_only_when_it_has_somewhere_to_go() {
        for (index, state) in every_state().iter().enumerate() {
            assert_eq!(
                state.can_cancel_wizard(),
                index > 0,
                "cancel in {}",
                state.label()
            );
        }
    }

    /// Smart Lock is the only state where the lock button means "go deeper".
    #[test]
    fn lock_label_distinguishes_the_two_depths() {
        for state in every_state() {
            let expected = if matches!(state, VaultState::Smart(_)) {
                "Full Lock"
            } else {
                "Lock"
            };
            assert_eq!(state.lock_label(), expected, "in {}", state.label());
        }
    }

    /// Each variant names itself, which the status bar prints verbatim.
    #[test]
    fn every_state_has_a_label() {
        let labels: Vec<&str> = every_state().iter().map(VaultState::label).collect();
        assert_eq!(
            labels,
            [
                "No vault",
                "Locked",
                "Partially unlocked",
                "Unlocked",
                "Smart Locked"
            ]
        );
    }
}
