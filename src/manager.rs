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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use askrypt::{
    AskryptFile, Attachment, AttachmentSource, Attachments, MasterSecret, QuestionsData,
    SecretEntry, StorageError, VaultStorage,
};
use zeroize::{Zeroize, Zeroizing};

use crate::scratch::Scratch;
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
    /// What became of the local copy a cloud save leaves behind: where it
    /// landed, or why it did not.
    ///
    /// `None` when none was asked for — the setting is off, or this vault is a
    /// local file already. A failed copy is reported *here* rather than as an
    /// error from the write, because the vault itself was saved and the session
    /// must adopt the new bytes either way.
    pub backup: Option<Result<PathBuf, String>>,
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

    /// Where each of the vault's attachments can be read from.
    ///
    /// Never the bytes — an attachment is a *source*: a member of the archive
    /// this vault was read from, or a file of ciphertext in the app's scratch
    /// directory. That is what keeps a vault with gigabytes of attachments open
    /// in the same memory as an empty one.
    ///
    /// It lives on `self.file` rather than on the state, because none of it is
    /// secret: a locked vault carries the same sources, and nothing has to be
    /// decrypted to keep them across a lock.
    pub fn attachments(&self) -> &Attachments {
        &self.file.attachments
    }

    /// File a freshly sealed attachment's ciphertext file under its id.
    ///
    /// Deliberately does **not** set `modified`. What makes a vault dirty is
    /// the entry that refers to the blob, which the editor writes through
    /// [`add_entry`](Self::add_entry) / [`update_entry`](Self::update_entry).
    /// So attaching a file and then cancelling the editor leaves an orphan
    /// rather than a phantom unsaved change — and the next save's prune
    /// collects it, sealed file and all.
    ///
    /// There is deliberately no `remove_attachment` to pair with this. Dropping
    /// an attachment is dropping the *reference* on the entry; the source goes
    /// when [`AskryptFile::create`] next prunes, which is also what makes a
    /// cancelled removal put the file back.
    pub fn add_attachment(&mut self, id: String, sealed: PathBuf) {
        self.file.attachments.insert_sealed(id, sealed);
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
            attachments: self.file.attachments.clone(),
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

    /// Adopt a vault re-read from its home after someone else wrote it.
    ///
    /// Everything derived from the bytes is replaced — including the master
    /// key, which is the one the *other* device preserved through its own save
    /// and therefore the key these entries are actually under. The answers and
    /// the home stay: they still open it (that is what made this a `Reloaded`
    /// rather than a `Rekeyed`), and the home holds the very storage instance
    /// that did the reading, whose revision is now current.
    pub fn reloaded(mut self, reloaded: Reloaded) -> Self {
        self.file = reloaded.file;
        self.state.questions_data = reloaded.questions_data;
        self.state.entries = reloaded.entries;
        self.state.master = reloaded.master;
        // These entries came off the backend, so there is nothing local left
        // to write. Anything the user had typed was discarded by their own
        // choice before this ran.
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

    /// Everything a worker needs to re-read this vault from its home, or
    /// `None` when there is nothing to follow — no vault, or one that has
    /// never been written anywhere.
    ///
    /// The state decides how much can be re-opened without asking the user:
    /// a locked vault only needs the bytes, while an unlocked one still holds
    /// every answer and so can be rebuilt outright.
    pub fn reload_inputs(&self, scratch: Option<Arc<Scratch>>) -> Option<ReloadInputs> {
        let storage = self.home()?.storage().clone();
        let keys = match self {
            VaultState::None => return None,
            VaultState::Locked(_) | VaultState::Smart(_) => ReloadKeys::None,
            VaultState::Partial(vault) => ReloadKeys::First(vault.state.answer0.clone()),
            VaultState::Unlocked(vault) => ReloadKeys::All {
                answer0: vault.state.answer0.clone(),
                answers: vault.state.answers.clone(),
            },
        };
        Some(ReloadInputs {
            storage,
            keys,
            scratch,
        })
    }

    /// New bytes for a vault that had nothing decrypted to invalidate.
    pub fn apply_refreshed(&mut self, file: AskryptFile) -> bool {
        match self {
            VaultState::Locked(vault) => {
                vault.file = file;
                true
            }
            VaultState::Smart(vault) => {
                // The answer bundle is keyed off itself, not off the file, so
                // it survives new bytes. Should the other device have changed
                // the questions, the smart unlock fails at `get_questions_data`
                // and falls back to a full one — the existing behaviour.
                vault.file = file;
                true
            }
            _ => false,
        }
    }

    /// New bytes whose question list the held first answer still opens.
    pub fn apply_requestioned(&mut self, file: AskryptFile, questions_data: QuestionsData) -> bool {
        match self {
            VaultState::Partial(vault) => {
                vault.file = file;
                vault.state.questions_data = questions_data;
                true
            }
            _ => false,
        }
    }

    /// New bytes, re-decrypted with the answers already held.
    pub fn apply_reloaded(&mut self, reloaded: Reloaded) -> bool {
        match std::mem::take(self) {
            VaultState::Unlocked(vault) => {
                *self = VaultState::Unlocked(vault.reloaded(reloaded));
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// Drop to [`Locked`] on *new* bytes: the vault was re-read but the held
    /// answers no longer open it, so it has to be unlocked from scratch.
    ///
    /// Distinct from [`lock`](Self::lock), which keeps the bytes it had.
    pub fn relock_with(&mut self, file: AskryptFile) -> bool {
        if matches!(self, VaultState::None) {
            return false;
        }
        self.lock();
        if let VaultState::Locked(vault) = self {
            vault.file = file;
            return true;
        }
        false
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
    /// The open vault's attachment blobs, carried across the rebuild for the
    /// same reason the master key is: they are encrypted under it, and a
    /// change of questions is still a save. Empty when this run is creating
    /// the vault.
    pub attachments: Attachments,
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
            &self.attachments,
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

/// What the current state can contribute towards re-opening freshly read bytes.
///
/// A reload asks the user for nothing: whatever the vault already holds is
/// exactly what it needs, and a state that holds nothing simply takes the
/// bytes and stays locked.
enum ReloadKeys {
    /// Locked or Smart-locked: nothing was decrypted, so nothing is stale.
    None,
    /// Partially unlocked: the first answer, to re-read the question list.
    First(Zeroizing<String>),
    /// Unlocked: every answer, to rebuild the entries outright.
    All {
        answer0: Zeroizing<String>,
        answers: Zeroizing<Vec<String>>,
    },
}

/// Inputs for re-reading a vault that changed where it is stored.
///
/// Holds answers, so it is secret material — the `Zeroizing` inside
/// [`ReloadKeys`] wipes them. Deliberately **no** `Drop` impl of its own:
/// `run` destructures `keys`, and a `Drop` type cannot be destructured
/// (E0509), the same constraint `SecretEntry`'s `CardFields` documents.
pub struct ReloadInputs {
    storage: Arc<dyn VaultStorage>,
    keys: ReloadKeys,
    /// Where a server vault's fresh copy of the archive is spilled. A local
    /// vault re-reads itself in place and never touches this.
    scratch: Option<Arc<Scratch>>,
}

impl ReloadInputs {
    /// **Worker-thread only.** A backend round trip, then up to two
    /// 600k-iteration derivations.
    ///
    /// Reads through the storage instance the vault was opened with — never a
    /// fresh one — so the backend also learns the revision it just fetched and
    /// the next save is conflict-checked against *that* rather than against
    /// the version this reload replaced.
    pub fn run(self) -> Result<ReloadOutcome, VaultError> {
        let file = read_vault(&self.storage, self.scratch.as_ref())
            .map_err(|e| VaultError::log("Failed to re-read vault", &e))?;

        match self.keys {
            ReloadKeys::None => Ok(ReloadOutcome::Refreshed(Box::new(file))),
            ReloadKeys::First(answer0) => match file.get_questions_data(answer0.to_string()) {
                Ok(questions_data) => Ok(ReloadOutcome::Requestioned {
                    file: Box::new(file),
                    questions_data,
                }),
                Err(_) => Ok(ReloadOutcome::Rekeyed(Box::new(file))),
            },
            ReloadKeys::All { answer0, answers } => {
                let Ok(questions_data) = file.get_questions_data(answer0.to_string()) else {
                    return Ok(ReloadOutcome::Rekeyed(Box::new(file)));
                };
                match file.decrypt_with_master(&questions_data, answers.to_vec()) {
                    Ok((entries, master)) => Ok(ReloadOutcome::Reloaded(Box::new(Reloaded {
                        file,
                        questions_data,
                        entries,
                        master,
                    }))),
                    Err(_) => Ok(ReloadOutcome::Rekeyed(Box::new(file))),
                }
            }
        }
    }
}

/// How far a reload got. Every variant means the bytes were fetched — a
/// backend failure is the `Err` half of [`ReloadInputs::run`].
#[derive(Debug, Clone)]
pub enum ReloadOutcome {
    /// Bytes only; the vault had nothing decrypted to replace.
    Refreshed(Box<AskryptFile>),
    /// The held first answer still opens the new question list.
    Requestioned {
        file: Box<AskryptFile>,
        questions_data: QuestionsData,
    },
    /// Re-decrypted in full with the answers already held.
    Reloaded(Box<Reloaded>),
    /// The bytes arrived but the held answers no longer open them — the other
    /// device changed the questions or the answers (or, far less likely, the
    /// file is damaged). Carries the new bytes so the vault can relock onto
    /// them and ask afresh, rather than sitting on a version known to be
    /// superseded.
    Rekeyed(Box<AskryptFile>),
}

/// What a successful reload of an unlocked vault recovered.
#[derive(Clone)]
pub struct Reloaded {
    file: AskryptFile,
    questions_data: QuestionsData,
    entries: Vec<SecretEntry>,
    master: MasterSecret,
}

// Rides inside a `Message`, and every `Message` derives `Debug`. `SecretEntry`
// and `QuestionsData` both print their contents, so this must not.
impl std::fmt::Debug for Reloaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloaded")
            .field(
                "entries",
                &format_args!("<{} redacted>", self.entries.len()),
            )
            .finish_non_exhaustive()
    }
}

impl Reloaded {
    /// The re-read bytes, for the write stamp that says who saved them.
    pub fn file(&self) -> &AskryptFile {
        &self.file
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
    /// Where each of the vault's attachments can be read from, exactly as the
    /// open vault has it. They are already ciphertext under `master`, so a save
    /// streams them across rather than re-encrypting them — which is the whole
    /// reason the master key is preserved, and why this is a list of sources
    /// rather than a heap of bytes.
    pub attachments: Attachments,
}

impl Drop for SaveRequest {
    fn drop(&mut self) {
        self.answers.zeroize();
        // `entries` are `SecretEntry` and `master` is a `MasterSecret`, both of
        // which wipe themselves on drop.
    }
}

/// What a worker needs to attach one file to an entry.
///
/// Reading the file and encrypting it are both potentially slow — an
/// attachment can be megabytes — so this follows the same gather-owned-inputs →
/// `run()` on a worker → apply-on-the-main-thread shape as every other
/// derivation in this module.
pub struct AttachInputs {
    /// The file the user picked.
    pub path: PathBuf,
    /// Where its ciphertext goes — a file in this session's scratch directory,
    /// which is the *only* copy of it until a save folds it into the archive.
    pub dest: PathBuf,
    /// The vault's master key. Attachments live under it, which is the reason
    /// it is preserved for the life of the vault.
    pub master: MasterSecret,
}

/// Rides inside a `Message`, whose enum derives `Debug`. The key must not
/// print, and neither should the path spelling be assumed harmless to log.
impl std::fmt::Debug for AttachInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachInputs").finish_non_exhaustive()
    }
}

/// One sealed attachment: the metadata for the entry, and where its ciphertext
/// was written for the vault.
///
/// A path rather than the bytes, which is what lets this ride inside a
/// `Message` — iced messages are `Clone`, and the old shape meant a multi-
/// megabyte copy every time the runtime touched one.
#[derive(Clone)]
pub struct Attached {
    pub attachment: Attachment,
    pub sealed: PathBuf,
}

impl std::fmt::Debug for Attached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attached")
            .field("name", &self.attachment.name)
            .field("size", &self.attachment.size)
            .finish_non_exhaustive()
    }
}

impl AttachInputs {
    /// **Worker-thread only.**
    ///
    /// Streams the picked file through AES straight into `dest`: neither the
    /// plaintext nor the ciphertext is ever held whole, so the size of the file
    /// the user picked is not a claim on memory.
    pub fn run(self) -> Result<Attached, String> {
        let name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "attachment".to_string());

        let mut attachment = askrypt::seal_attachment_to_file(&self.path, &self.dest, &self.master)
            .map_err(|e| {
                // A half-written blob is worse than none: it would be filed as
                // a perfectly good attachment and decrypt to nothing.
                crate::scratch::Scratch::discard(&self.dest);
                format!("Could not encrypt the file: {e}")
            })?;
        attachment.name = name;

        Ok(Attached {
            attachment,
            sealed: self.dest,
        })
    }
}

/// What a worker needs to write one attachment back out to disk.
pub struct ExtractInputs {
    pub attachment: Attachment,
    /// Where the ciphertext is: a member of `origin`, or a sealed file.
    pub source: AttachmentSource,
    /// The archive a carried attachment is read out of. `None` only for a
    /// sealed one, which needs no archive.
    pub origin: Option<PathBuf>,
    pub master: MasterSecret,
    /// Where the save dialog said to put it.
    pub dest: PathBuf,
}

impl std::fmt::Debug for ExtractInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractInputs")
            .field("name", &self.attachment.name)
            .finish_non_exhaustive()
    }
}

impl ExtractInputs {
    /// **Worker-thread only.** Answers the name that was written, for the
    /// status line.
    ///
    /// A failure to decrypt here is not a wrong answer — the vault is already
    /// open — so it means the blob is damaged. The format offers no integrity
    /// (`SPEC.md`), so that is the most a reader can say.
    pub fn run(self) -> Result<String, String> {
        let damaged = || {
            format!(
                "Could not decrypt “{}”. The stored file may be damaged.",
                self.attachment.name
            )
        };

        // Its own handle on the archive rather than a shared one, so two
        // extracts running at once never contend — and neither blocks a save.
        let opened = match &self.source {
            AttachmentSource::Sealed(path) => {
                let sealed = std::fs::File::open(path)
                    .map_err(|e| format!("Could not read the stored file: {e}"))?;
                askrypt::open_attachment_to_file(sealed, &self.attachment, &self.master, &self.dest)
            }
            AttachmentSource::Carried => {
                let origin = self
                    .origin
                    .as_ref()
                    .ok_or_else(|| "The vault this file came from is no longer open".to_string())?;
                askrypt::extract_attachment(origin, &self.attachment, &self.master, &self.dest)
            }
        };

        opened.map_err(|_| {
            // Never leave a truncated or garbage file behind under the name the
            // user chose: they would have no way to tell it apart from the real
            // thing.
            std::fs::remove_file(&self.dest).ok();
            damaged()
        })?;

        Ok(self.attachment.name)
    }
}

/// Re-encrypt the vault and write it. **Worker-thread only** — this runs two
/// 600k-iteration key derivations plus (for a server vault) an HTTP round trip.
///
/// `backup_dir` is the directory Settings asked for a local copy in
/// ([`AppSettings::local_backup_dir`](crate::settings::AppSettings::local_backup_dir)).
/// The copy is made only for a *server* vault — a local one is already a file
/// on this machine — and only after the real save landed, so a vault is never
/// backed up in a state the server never accepted.
pub fn write_vault(
    request: SaveRequest,
    home: VaultHome,
    backup_dir: Option<PathBuf>,
    scratch: Option<Arc<Scratch>>,
) -> Result<SavedVault, VaultError> {
    let mut file = AskryptFile::create(
        request.questions.clone(),
        request.answers.clone(),
        request.entries.clone(),
        Some(request.iterations),
        request.translit,
        Some(&request.master),
        &request.attachments,
    )
    .map_err(|e| VaultError::log_crypto("Failed to build vault", e.as_ref()))?;

    // Every sealed file this save is about to fold into the archive, and the
    // archive it is about to supersede. Both are collected *before* the write,
    // because `adopt` below is what makes them redundant — and both are deleted
    // only *after* it, because until then they are the only copies.
    let sealed: Vec<PathBuf> = file
        .attachments
        .sealed_paths()
        .map(Path::to_path_buf)
        .collect();
    let previous = file.attachments.origin().map(Path::to_path_buf);

    // Assembled in full before anything is replaced, because assembling it is
    // what *reads* the archive being replaced: every unchanged attachment is
    // streamed straight across from the old file into the new one.
    let staged = staging_path(&home, scratch.as_deref());
    let landed = write_archive_to(&file, &staged).and_then(|()| {
        home.storage()
            .write_from_path(&staged)
            .map_err(|e| VaultError::log("Failed to save vault", &e))
    });
    if let Err(e) = landed {
        Scratch::discard(&staged);
        return Err(e);
    }

    // The archive that just landed is where every attachment now lives. For a
    // local vault that is the vault file; for a server vault the staging file
    // stays behind as this session's copy, since there is nothing else on this
    // machine to stream a carried attachment out of next time.
    match home.storage().archive_path() {
        Some(path) => {
            file.attachments.adopt(path);
            Scratch::discard(&staged);
        }
        None => file.attachments.adopt(staged),
    }

    // Only now: until the write landed, these were the only copies.
    for path in &sealed {
        Scratch::discard(path);
    }
    retire_origin(previous, scratch.as_deref());

    let backup = backup_dir
        .filter(|_| home.location().is_server())
        .map(|dir| back_up_locally(&file, home.location(), &dir));

    Ok(SavedVault { file, home, backup })
}

/// Where a replacement archive is assembled.
///
/// Beside the destination when there is one, so handing it over is a rename
/// within a single filesystem and the vault is never briefly half-written.
/// Everything else — a server vault — stages in the scratch directory, and
/// stays there afterwards as the session's copy of the archive.
fn staging_path(home: &VaultHome, scratch: Option<&Scratch>) -> PathBuf {
    if let Some(path) = home.storage().archive_path() {
        let mut name = std::ffi::OsString::from(".");
        name.push(path.file_name().unwrap_or_default());
        name.push(format!(".tmp-{}", std::process::id()));
        return path.with_file_name(name);
    }
    match scratch {
        Some(scratch) => scratch.staging_path(),
        // No cache directory on this platform. The system temp directory is a
        // poor place for this — see `AppSettings::cache_dir` — but refusing to
        // save at all would be far worse.
        None => std::env::temp_dir().join(format!("askrypt-staging-{}", fallback_tag())),
    }
}

/// A name nothing else in this process will pick.
///
/// The fallback paths below have no [`Scratch`] to hand out unique names, and
/// two saves of two vaults can be in flight at once — one overwriting the
/// other's half-built archive is not a failure mode worth having.
fn fallback_tag() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Drop a spilled or staged archive this vault has finished with.
///
/// Called once a *newer* one has taken over, and the test is **did we make
/// it** — nothing about the backend, and nothing about the path being
/// different from the current one. A Save As moves a vault between homes, so
/// the archive being superseded is quite often a local vault file the *user*
/// owns; the scratch directory is the only place a file this app is free to
/// delete can be.
///
/// With no scratch directory nothing is retired, and a session that saves a
/// cloud vault repeatedly leaves a copy per save in the temp directory. That is
/// the cost of a platform with nowhere to cache, and it is bounded by the run.
pub fn retire_origin(previous: Option<PathBuf>, scratch: Option<&Scratch>) {
    let (Some(previous), Some(scratch)) = (previous, scratch) else {
        return;
    };
    if scratch.owns(&previous) {
        Scratch::discard(&previous);
    }
}

/// Stream one vault into a file, creating its directory if it is missing.
fn write_archive_to(file: &AskryptFile, dest: &Path) -> Result<(), VaultError> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let out = std::fs::File::create(dest)
        .map_err(|e| VaultError::log("Failed to save vault", &StorageError::Io(e)))?;
    // Buffered for the reason `askrypt::buffered_read` gives on the other side:
    // the ZIP layer writes straight through, and a carried attachment is moved
    // across in `io::copy`'s 8 KiB steps.
    file.write_archive(std::io::BufWriter::with_capacity(1024 * 1024, out))
        .map_err(|e| VaultError::log_crypto("Failed to write vault", e.as_ref()))
}

/// Read a vault through `storage`, giving it a file its attachments can be
/// streamed out of. **Worker-thread only.**
///
/// This is the single way the app opens a vault, and the whole reason it exists
/// is the last part: an attachment is only ever read from a seekable archive,
/// so a backend that *is* a file (`archive_path`) is used in place, and one
/// that is not — a server vault — is spilled to a copy in the scratch
/// directory first. It also claims the vault, so a second Askrypt window cannot
/// be reading the same archive that this one is about to replace.
pub fn read_vault(
    storage: &Arc<dyn VaultStorage>,
    scratch: Option<&Arc<Scratch>>,
) -> Result<AskryptFile, StorageError> {
    storage.acquire_lock()?;

    match storage.archive_path() {
        Some(path) => {
            // Read anyway, and throw the bytes away: it is what moves the
            // backend onto the revision it just saw, which is what the change
            // follower compares against.
            storage.read()?;
            AskryptFile::from_path(&path).map_err(|e| StorageError::Format(e.to_string()))
        }
        None => {
            let spill = match scratch {
                Some(scratch) => scratch.vault_path(),
                None => std::env::temp_dir().join(format!("askrypt-vault-{}", fallback_tag())),
            };
            storage.read_to_path(&spill)?;
            match AskryptFile::from_path(&spill) {
                Ok(file) => Ok(file),
                Err(e) => {
                    Scratch::discard(&spill);
                    Err(StorageError::Format(e.to_string()))
                }
            }
        }
    }
}

/// Write the just-saved bytes into the user's backup directory.
///
/// Errors come back as text rather than as a [`VaultError`]: the vault *was*
/// saved, so this can only ever be a warning next to a success.
fn back_up_locally(
    file: &AskryptFile,
    location: &VaultLocation,
    dir: &Path,
) -> Result<PathBuf, String> {
    let path = dir.join(backup_file_name(location));

    // The directory was picked in a file dialog, so it existed then — an
    // unplugged drive or a since-deleted folder is what this covers.
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;

    // A copy of the archive that just landed rather than a second run of the
    // writer: re-serializing would assemble the whole thing again — every
    // attachment included — for bytes that already exist.
    let source = file
        .attachments
        .origin()
        .ok_or_else(|| format!("{}: nothing to copy", path.display()))?;
    std::fs::copy(source, &path).map_err(|e| {
        eprintln!("WARNING: Failed to write local backup copy: {}", e);
        format!("{}: {}", path.display(), e)
    })?;

    Ok(path)
}

/// What the local copy is called.
///
/// A server vault's name is user text the *server* stores, so it is treated as
/// untrusted here: it names a file in a directory of the user's choosing, and a
/// separator or a `..` in it would put that file somewhere else entirely. Only
/// the last component survives, control characters and separators go, and a
/// name left with nothing usable falls back to a fixed one.
fn backup_file_name(location: &VaultLocation) -> String {
    let name = location.display_name();
    let name: String = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    let name = name.trim().trim_matches('.').trim();

    if name.is_empty() {
        return "vault.askrypt".to_string();
    }
    if name.to_ascii_lowercase().ends_with(".askrypt") {
        return name.to_string();
    }
    format!("{}.askrypt", name)
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
            attachments: Vec::new(),
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
            attachments: Attachments::new(),
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
            &Attachments::new(),
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
        let saved =
            write_vault(request, home.clone(), None, None).expect("the vault should be written");
        vault.apply_saved(saved);

        (vault, home)
    }

    /// A directory of this test's own for the files an attachment now needs:
    /// the one being attached, its ciphertext, and what it decrypts back to.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "askrypt_manager_test_{}_{}",
                tag,
                std::process::id()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).expect("test directory");
            Self(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Attach `bytes` under `name` the way the editor does: seal to a scratch
    /// file, file the source on the vault, then put the reference on the entry.
    fn attach(vault: &mut VaultState, dir: &TestDir, name: &str, bytes: &[u8]) -> Attachment {
        let src = dir.join(&format!("{name}.src"));
        std::fs::write(&src, bytes).expect("the file to attach");
        let sealed = dir.join(&format!("{name}.sealed"));

        let unlocked = vault.unlocked_mut().unwrap();
        let mut meta = askrypt::seal_attachment_to_file(&src, &sealed, unlocked.master())
            .expect("the file should seal");
        meta.name = name.to_string();

        unlocked.add_attachment(meta.id.clone(), sealed);
        let mut entry = unlocked.entries()[0].clone();
        entry.attachments.push(meta.clone());
        unlocked.update_entry(0, entry);
        meta
    }

    /// Save through the real write path and take the result.
    fn save(vault: &mut VaultState, home: &VaultHome) {
        let request = vault.unlocked().unwrap().save_request();
        let saved =
            write_vault(request, home.clone(), None, None).expect("the vault should be written");
        // The staging archive a `MemoryStorage` home leaves behind is this
        // vault's origin now, so it is cleaned up by the caller's `TestDir`
        // only if it lives there — it does not, so take it out of the way here.
        vault.apply_saved(saved);
    }

    /// Whether the bytes on the backend still carry a `files/` member for `id`.
    fn stored(home: &VaultHome, id: &str) -> bool {
        let bytes = home.storage().read().expect("the vault should be there");
        AskryptFile::from_bytes(&bytes)
            .expect("the vault should parse")
            .attachments
            .source(id)
            .is_some()
    }

    /// An attachment attached in the editor, saved, and read back off the
    /// storage backend — the desktop's own path end to end, and the one that
    /// proves a *sealed* source becomes a real member of the archive.
    #[test]
    fn an_attachment_survives_the_save_path() {
        let dir = TestDir::new("attachment_survives");
        let (mut vault, home) = stored_vault();

        let before = vault.unlocked().unwrap().is_modified();
        assert!(!before);
        let meta = attach(&mut vault, &dir, "codes.txt", b"recovery codes");
        // Filing the source is not itself an edit; applying the item is, and
        // `attach` does both.
        assert!(vault.unlocked().unwrap().is_modified());

        save(&mut vault, &home);

        // Read it back the way a fresh open would: off the stored bytes, with
        // nothing but the master key and the metadata.
        let reopened = dir.join("reopened.askrypt");
        std::fs::write(&reopened, home.storage().read().unwrap()).unwrap();
        let out = dir.join("codes.out");
        let master = vault.unlocked().unwrap().master().clone();
        askrypt::extract_attachment(&reopened, &meta, &master, &out).expect("it should open");
        assert_eq!(std::fs::read(&out).unwrap(), b"recovery codes");

        cleanup(&vault);
    }

    /// The point of the redesign: a *carried* attachment — one already in the
    /// archive — survives a second save without ever being decrypted, and comes
    /// out byte-identical.
    #[test]
    fn a_carried_attachment_survives_a_second_save_untouched() {
        let dir = TestDir::new("carried_survives");
        let (mut vault, home) = stored_vault();

        let meta = attach(
            &mut vault,
            &dir,
            "passport.pdf",
            b"scanned passport, page 1",
        );
        save(&mut vault, &home);
        let first = home.storage().read().unwrap();

        // After a save every source is carried: the sealed file is gone and the
        // next save has to stream the member across from the archive itself.
        assert!(matches!(
            vault.unlocked().unwrap().attachments().source(&meta.id),
            Some(AttachmentSource::Carried)
        ));
        assert!(
            !dir.join("passport.pdf.sealed").exists(),
            "the sealed file outlived the save that folded it in"
        );

        // Touch something else and save again.
        {
            let unlocked = vault.unlocked_mut().unwrap();
            let mut entry = unlocked.entries()[0].clone();
            entry.notes = "changed".to_string();
            unlocked.update_entry(0, entry);
        }
        save(&mut vault, &home);
        let second = home.storage().read().unwrap();

        assert!(
            second.len().abs_diff(first.len()) < 512,
            "carrying the attachment across rewrote it: {} then {} bytes",
            first.len(),
            second.len()
        );

        // And it still decrypts, which is the half that matters here — that the
        // copied member is byte-identical is pinned in `core`.
        let reopened = dir.join("reopened.askrypt");
        std::fs::write(&reopened, &second).unwrap();
        let out = dir.join("passport.out");
        let master = vault.unlocked().unwrap().master().clone();
        askrypt::extract_attachment(&reopened, &meta, &master, &out).expect("it should open");
        assert_eq!(std::fs::read(&out).unwrap(), b"scanned passport, page 1");

        cleanup(&vault);
    }

    /// Dropping the reference is enough: the next save is what actually drops
    /// the member, which is also what makes cancelling a removal harmless.
    #[test]
    fn dropping_the_reference_drops_the_blob_on_the_next_save() {
        let dir = TestDir::new("reference_dropped");
        let (mut vault, home) = stored_vault();

        let meta = attach(&mut vault, &dir, "codes.txt", b"recovery codes");
        save(&mut vault, &home);
        assert!(stored(&home, &meta.id));

        // Now take the reference off the entry and save again.
        {
            let unlocked = vault.unlocked_mut().unwrap();
            let mut entry = unlocked.entries()[0].clone();
            entry.attachments.clear();
            unlocked.update_entry(0, entry);
        }
        save(&mut vault, &home);

        assert!(!stored(&home, &meta.id), "the blob outlived the reference");
        cleanup(&vault);
    }

    /// Remove the staging archive a `MemoryStorage` home leaves behind.
    ///
    /// In the app that file is the session's copy of a cloud vault and the
    /// scratch directory takes it on exit; here there is no scratch, so the
    /// test does it.
    fn cleanup(vault: &VaultState) {
        if let Some(origin) = vault.file().and_then(|file| file.attachments.origin()) {
            std::fs::remove_file(origin).ok();
        }
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
        let saved = write_vault(request, home.clone(), None, None)
            .expect("the vault should be written again");
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
            attachments: Attachments::new(),
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
        let saved =
            write_vault(request, home.clone(), None, None).expect("the vault should be written");
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

    // -----------------------------------------------------------------------
    // Following the stored vault
    // -----------------------------------------------------------------------

    /// A vault open from shared storage, as the app has it after an unlock.
    fn unlocked_on(storage: Arc<MemoryStorage>) -> VaultState {
        let built = build_new(vec![entry("GitHub")]);
        let home = VaultHome::new(VaultLocation::LocalFile("/dev/null".into()), storage);
        let vault = Vault::created(built, Some(home));
        // Write it out so the backend holds the same bytes the vault does.
        let request = vault.save_request();
        let saved = write_vault(request, vault.home().unwrap().clone(), None, None)
            .expect("the vault should save");
        VaultState::Unlocked(vault.saved(saved))
    }

    /// Stand in for another device: rebuild the vault with different entries
    /// and write it straight to the shared backend.
    fn write_from_elsewhere(
        storage: &Arc<MemoryStorage>,
        entries: Vec<SecretEntry>,
        master: Option<&MasterSecret>,
    ) {
        let file = AskryptFile::create(
            questions(),
            answers(),
            entries,
            Some(ITERATIONS),
            false,
            master,
            &Attachments::new(),
        )
        .expect("the vault should build");
        storage.save_vault(&file).expect("the write should land");
    }

    #[test]
    fn reloading_picks_up_what_another_device_wrote() {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = unlocked_on(storage.clone());
        let master = state.unlocked().unwrap().master().clone();

        write_from_elsewhere(
            &storage,
            vec![entry("GitHub"), entry("Bank")],
            Some(&master),
        );

        let outcome = state
            .reload_inputs(None)
            .expect("an open vault with a home is followable")
            .run()
            .expect("the re-read should succeed");

        let reloaded = match outcome {
            ReloadOutcome::Reloaded(reloaded) => reloaded,
            other => panic!("expected Reloaded, got {:?}", other),
        };
        assert!(state.apply_reloaded(*reloaded));

        let vault = state.unlocked().expect("still unlocked");
        assert_eq!(vault.entries().len(), 2);
        assert_eq!(vault.entries()[1].name, "Bank");
        // The entries came off the backend, so there is nothing left to write.
        assert!(!vault.is_modified());
    }

    #[test]
    fn a_reload_does_not_ask_the_user_for_anything() {
        // The point of holding the answers in `Unlocked`: re-opening freshly
        // written bytes needs no typing. Covered by the fact that
        // `reload_inputs` takes no arguments and the reload above succeeded —
        // asserted here as the absence of a home being the only way to fail.
        let storage = Arc::new(MemoryStorage::default());
        let state = unlocked_on(storage);
        assert!(state.reload_inputs(None).is_some());

        // A vault that has never been written anywhere has nothing to follow.
        let homeless = VaultState::Unlocked(Vault::created(build_new(vec![]), None));
        assert!(homeless.reload_inputs(None).is_none());
    }

    #[test]
    fn changed_questions_come_back_as_rekeyed_rather_than_as_an_error() {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = unlocked_on(storage.clone());

        // The other device changed the security answers, so ours no longer
        // open the file — the master key is preserved but unreachable.
        let file = AskryptFile::create(
            vec!["First pet?".to_string(), "First street?".to_string()],
            vec!["Fido".to_string(), "Elm Street".to_string()],
            vec![entry("GitHub")],
            Some(ITERATIONS),
            false,
            None,
            &Attachments::new(),
        )
        .expect("the vault should build");
        storage.save_vault(&file).expect("the write should land");

        let outcome = state
            .reload_inputs(None)
            .expect("followable")
            .run()
            .expect("the bytes should still be fetched");

        let new_file = match outcome {
            ReloadOutcome::Rekeyed(file) => file,
            other => panic!("expected Rekeyed, got {:?}", other),
        };

        // The entries in memory are untouched until something is applied — a
        // failed reload must never be a silent lock.
        assert!(state.is_unlocked());

        // Relocking lands on the *new* bytes, not the superseded ones.
        assert!(state.relock_with(*new_file.clone()));
        assert!(matches!(state, VaultState::Locked(_)));
        assert_eq!(state.file(), Some(&*new_file));
    }

    #[test]
    fn a_locked_vault_reloads_without_decrypting_anything() {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = unlocked_on(storage.clone());
        let master = state.unlocked().unwrap().master().clone();
        state.lock();

        write_from_elsewhere(&storage, vec![entry("Bank")], Some(&master));

        let outcome = state
            .reload_inputs(None)
            .expect("a locked vault still has a home")
            .run()
            .expect("the re-read should succeed");

        match outcome {
            ReloadOutcome::Refreshed(file) => assert!(state.apply_refreshed(*file)),
            other => panic!("expected Refreshed, got {:?}", other),
        }
        assert!(matches!(state, VaultState::Locked(_)));
    }

    #[test]
    fn an_apply_arriving_in_the_wrong_state_is_dropped() {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = unlocked_on(storage.clone());
        let master = state.unlocked().unwrap().master().clone();

        write_from_elsewhere(&storage, vec![entry("Bank")], Some(&master));
        let outcome = state.reload_inputs(None).unwrap().run().unwrap();
        let reloaded = match outcome {
            ReloadOutcome::Reloaded(reloaded) => reloaded,
            other => panic!("expected Reloaded, got {:?}", other),
        };

        // The user locked the vault while the worker ran. The result is about
        // a state that no longer exists and must not resurrect it.
        state.lock();
        assert!(!state.apply_reloaded(*reloaded));
        assert!(matches!(state, VaultState::Locked(_)));
    }

    // -----------------------------------------------------------------------
    // The local copy of a cloud save
    // -----------------------------------------------------------------------

    fn server_home(storage: Arc<MemoryStorage>, name: &str) -> VaultHome {
        VaultHome::new(
            VaultLocation::Server {
                base_url: "https://askrypt.example.com".to_string(),
                email: "me@example.com".to_string(),
                name: name.to_string(),
            },
            storage,
        )
    }

    /// Each test gets its own directory: they run in parallel in one process.
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("askrypt_backup_{}_{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory should be created");
        dir
    }

    #[test]
    fn a_cloud_save_leaves_a_readable_copy_in_the_backup_directory() {
        let dir = scratch_dir("copy");
        let vault = Vault::created(
            build_new(vec![entry("GitHub")]),
            Some(server_home(Arc::new(MemoryStorage::default()), "MyVault")),
        );

        let saved = write_vault(
            vault.save_request(),
            vault.home().unwrap().clone(),
            Some(dir.clone()),
            None,
        )
        .expect("the vault should save");

        // The name carries no extension on the server; the copy is a file on
        // disk, so it gets one.
        let path = dir.join("MyVault.askrypt");
        assert_eq!(saved.backup.as_ref().unwrap().as_ref().unwrap(), &path);

        let copied = AskryptFile::load_from_file(&path).expect("the copy should be a vault");
        let questions_data = copied
            .get_questions_data(answers()[0].clone())
            .expect("the copy should open with the same answers");
        assert_eq!(questions_data.questions, questions()[1..]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_local_vault_is_not_copied_next_to_itself() {
        let dir = scratch_dir("local");
        let vault = Vault::created(build_new(vec![entry("GitHub")]), Some(home()));

        let saved = write_vault(
            vault.save_request(),
            vault.home().unwrap().clone(),
            Some(dir.clone()),
            None,
        )
        .expect("the vault should save");

        assert!(saved.backup.is_none());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failed_copy_does_not_fail_the_save() {
        // A file where the directory should be: `create_dir_all` refuses it.
        let dir = scratch_dir("blocked").join("wall");
        std::fs::write(&dir, b"not a directory").expect("the blocker should be written");

        let vault = Vault::created(
            build_new(vec![entry("GitHub")]),
            Some(server_home(Arc::new(MemoryStorage::default()), "MyVault")),
        );

        let saved = write_vault(
            vault.save_request(),
            vault.home().unwrap().clone(),
            Some(dir.clone()),
            None,
        )
        .expect("the vault itself should still save");
        assert!(saved.backup.unwrap().is_err());

        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }

    #[test]
    fn a_backup_file_name_cannot_escape_the_chosen_directory() {
        let named = |name: &str| {
            backup_file_name(&VaultLocation::Server {
                base_url: "https://askrypt.example.com".to_string(),
                email: "me@example.com".to_string(),
                name: name.to_string(),
            })
        };

        assert_eq!(named("MyVault"), "MyVault.askrypt");
        assert_eq!(named("MyVault.askrypt"), "MyVault.askrypt");
        assert_eq!(named("MyVault.ASKRYPT"), "MyVault.ASKRYPT");
        // The server stores whatever name it was given, so these are the ones
        // that matter: nothing may name a directory of its own.
        assert_eq!(named("../../etc/passwd"), "passwd.askrypt");
        assert_eq!(named("..\\..\\secrets"), "secrets.askrypt");
        assert_eq!(named(".."), "vault.askrypt");
        assert_eq!(named("   "), "vault.askrypt");
    }

    #[test]
    fn refreshing_is_refused_from_a_state_that_has_decrypted_entries() {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = unlocked_on(storage.clone());
        let file = state.file().expect("open").clone();

        // `apply_refreshed` swaps bytes and nothing else, so an unlocked vault
        // must reject it — the entries would silently describe another file.
        assert!(!state.apply_refreshed(file));
        assert!(state.is_unlocked());
    }
}
