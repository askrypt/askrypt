use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One file attached to an entry — the metadata half, which rides inside the
/// encrypted `data` blob. The bytes live in their own ZIP member, `files/<id>`,
/// encrypted under the vault's [`MasterSecret`]; see `SPEC.md`, "File
/// attachments".
///
/// `id` is what ties the two halves together and is also the whole of the
/// member's name: 32 lowercase hex characters, drawn at random, so that anyone
/// holding the `.askrypt` file learns nothing from the archive listing. The
/// real `name` is in here, where it is encrypted.
///
/// `iv` is stored beside the metadata rather than prefixed to the blob, which
/// is how [`MasterData`] already carries the `data` blob's IV. It is redrawn
/// every time the plaintext is encrypted — reusing one under the long-lived
/// master key would let a holder of two versions of a vault see how much of an
/// attachment went unchanged.
///
/// This object is also the extension point the future AEAD migration needs
/// (`SPEC.md`, "TODO: authenticated encryption"): a per-blob `nonce` and `tag`
/// are two more fields here and move nothing.
///
/// Derives `Zeroize` but deliberately **not** `ZeroizeOnDrop`, for the reason
/// [`CardFields`] gives: a `Drop` impl would forbid `..Default::default()`
/// (E0509).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct Attachment {
    /// 32 lowercase hex characters, naming the `files/<id>` ZIP member.
    pub id: String,
    /// The file's real name, as it was attached.
    pub name: String,
    /// Length of the **plaintext** in bytes.
    pub size: u64,
    /// When the file was attached, Unix time in seconds.
    pub added: i64,
    /// Base64 of the 16-byte AES-CBC IV this attachment was encrypted under.
    pub iv: String,
}

/// Where one attachment's ciphertext currently lives.
///
/// The app never holds an attachment's bytes: what it keeps is this, one value
/// per attached file, and a save streams each blob from its source straight
/// into the archive being written. Both variants are only ever ciphertext, so
/// neither is a secret in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentSource {
    /// A `files/<id>` member of the archive named by [`Attachments::origin`].
    ///
    /// A writer copies such a member across **verbatim** — same compression
    /// method, same CRC — so carrying an attachment through a save costs a
    /// stream copy and no crypto at all. That is only legal because the master
    /// key is never rotated (`SPEC.md`, "Master key lifetime").
    Carried,
    /// A file holding exactly this attachment's ciphertext and nothing else,
    /// written by [`crate::seal_attachment_to_file`] into the caller's own
    /// scratch directory. This is what a freshly attached file is until the
    /// next save folds it into the archive.
    Sealed(PathBuf),
}

/// Where each of a vault's attachments can be read from, keyed by
/// [`Attachment::id`].
///
/// This is the *blob* half of the feature and is deliberately not part of
/// `askrypt.json`: it is carried on [`AskryptFile`] as a `#[serde(skip)]` field
/// and turned into ZIP members by [`AskryptFile::write_archive`].
///
/// It holds no bytes. This used to be a `BTreeMap<String, Vec<u8>>`, which put
/// every attachment in memory for the life of the open vault and a vault with a
/// few large files beyond what the app could hold. Now an attachment is a
/// *source*: either a member of the archive the vault was read from, or a file
/// of ciphertext on disk. Everything in here is cheap to clone, compare and
/// print, which is why this type can ride inside message enums without copying
/// megabytes.
///
/// `BTreeMap` rather than `HashMap` so a save writes its members in a stable
/// order, which keeps two saves of an unchanged vault from differing for no
/// reason.
///
/// [`AskryptFile::write_archive`]: crate::AskryptFile::write_archive
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachments {
    /// The archive [`AttachmentSource::Carried`] blobs are read from.
    ///
    /// `None` means this vault was parsed from a byte slice with no file behind
    /// it ([`AskryptFile::from_bytes`]). Writing such a vault while it still
    /// carries a blob fails loudly rather than dropping the file: `SPEC.md`
    /// rule 4 makes silent loss the worst possible outcome here.
    ///
    /// [`AskryptFile::from_bytes`]: crate::AskryptFile::from_bytes
    origin: Option<PathBuf>,
    sources: BTreeMap<String, AttachmentSource>,
}

impl Attachments {
    /// An empty store — what a vault with no attachments carries, and what
    /// every caller of [`AskryptFile::create`] that has none passes.
    ///
    /// [`AskryptFile::create`]: crate::AskryptFile::create
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `id` in `ids`, carried by the archive at `origin`.
    ///
    /// This is what [`AskryptFile::from_path`] builds after listing the
    /// archive's `files/` members, without inflating one of them.
    ///
    /// [`AskryptFile::from_path`]: crate::AskryptFile::from_path
    pub fn from_origin<P, I, S>(origin: P, ids: I) -> Self
    where
        P: Into<PathBuf>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            origin: Some(origin.into()),
            sources: ids
                .into_iter()
                .map(|id| (id.into(), AttachmentSource::Carried))
                .collect(),
        }
    }

    /// Where the blob filed under `id` can be read from, if this vault has one.
    ///
    /// `None` is a **dangling reference** — an entry naming a blob the archive
    /// does not have. Readers must tolerate it (`SPEC.md`); it is not a reason
    /// to refuse the vault.
    pub fn source(&self, id: &str) -> Option<&AttachmentSource> {
        self.sources.get(id)
    }

    /// The archive [`AttachmentSource::Carried`] blobs are read from, if any.
    pub fn origin(&self) -> Option<&Path> {
        self.origin.as_deref()
    }

    /// File a freshly sealed attachment's ciphertext file under `id`.
    pub fn insert_sealed(&mut self, id: String, path: PathBuf) {
        self.sources.insert(id, AttachmentSource::Sealed(path));
    }

    /// Note that `id` is carried by an archive that is **not a file**.
    ///
    /// Only [`AskryptFile::from_bytes`] uses this, and only because a byte slice
    /// is not somewhere a blob can be read from a second time. Such an
    /// attachment lists and decrypts fine but cannot be written back out —
    /// [`AskryptFile::write_archive`] refuses rather than dropping the file.
    ///
    /// [`AskryptFile::from_bytes`]: crate::AskryptFile::from_bytes
    /// [`AskryptFile::write_archive`]: crate::AskryptFile::write_archive
    pub fn carry_without_origin(&mut self, id: String) {
        self.sources.insert(id, AttachmentSource::Carried);
    }

    /// Whether this vault holds no attachments at all.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// How many blobs are stored.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Every `(id, source)` pair, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &AttachmentSource)> {
        self.sources.iter()
    }

    /// Every sealed ciphertext file this store points at.
    ///
    /// A save folds them all into the archive it writes, so the caller deletes
    /// what this answers once the write has landed. Nothing else may: a sealed
    /// file is the *only* copy of a freshly attached file's ciphertext.
    pub fn sealed_paths(&self) -> impl Iterator<Item = &Path> {
        self.sources.values().filter_map(|source| match source {
            AttachmentSource::Sealed(path) => Some(path.as_path()),
            AttachmentSource::Carried => None,
        })
    }

    /// Re-point every source at the archive just written to `origin`.
    ///
    /// Called after a save lands: whatever a blob's source was a moment ago, it
    /// is now a member of the new archive. This is what makes the *next* save a
    /// stream copy rather than a re-encryption, and what lets the caller delete
    /// the sealed files [`sealed_paths`](Self::sealed_paths) named.
    pub fn adopt(&mut self, origin: PathBuf) {
        self.origin = Some(origin);
        for source in self.sources.values_mut() {
            *source = AttachmentSource::Carried;
        }
    }

    /// Drop every blob no entry in `entries` refers to.
    ///
    /// This is the garbage collection, and `SPEC.md` states it as a rule a
    /// writer **must** follow: deleting an attachment — or the entry holding
    /// it — has to actually shrink the vault. Doing it at write time rather
    /// than at the moment of deletion makes it self-healing, so a client that
    /// orphaned a blob (by cancelling an editor, say) does not leak it
    /// forever.
    pub fn retain_referenced(&mut self, entries: &[SecretEntry]) {
        let referenced: std::collections::HashSet<&str> = entries
            .iter()
            .flat_map(|entry| entry.attachments.iter())
            .map(|attachment| attachment.id.as_str())
            .collect();
        self.sources
            .retain(|id, _| referenced.contains(id.as_str()));
    }
}

/// The card fields of an entry, written into the entry's own JSON object as
/// `card_holder`, `card_brand`, `card_number`, `card_expiry`, `card_cvv` and
/// `card_pin` — see `SPEC.md`. There is no `card` object on the wire; the
/// `#[serde(flatten)]` on [`SecretEntry::card`] is what spreads them out.
///
/// They are grouped into a struct on the Rust side for one reason: `SecretEntry`
/// zeroizes on drop, and Rust forbids `..Default::default()` on a type that
/// implements `Drop` (E0509). Six loose fields would therefore have to be
/// spelled out in all fifteen-odd places that build an entry by literal; one
/// grouped field costs each of them a single `card: Default::default()`.
///
/// Every field is omitted from the JSON when empty, so an entry that is not a
/// card serializes exactly as it did before these existed, and a vault written
/// by an older build parses with all six blank. They carry meaning only for
/// entries whose `type` is `"Card"`.
///
/// Derives `Zeroize` but deliberately **not** `ZeroizeOnDrop`: `SecretEntry`'s
/// own `ZeroizeOnDrop` reaches in and wipes these three secrets (`number`,
/// `cvv`, `pin`) with the rest, and staying free of a `Drop` impl is what keeps
/// `..Default::default()` usable on *this* struct.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CardFields {
    /// Name embossed on the card.
    #[serde(
        rename = "card_holder",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub holder: String,
    /// Card network, e.g. `Visa`. Free-form: clients offer a list, the format
    /// does not constrain it.
    #[serde(
        rename = "card_brand",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub brand: String,
    /// Card number as typed, spaces and all. Secret.
    #[serde(
        rename = "card_number",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub number: String,
    /// Expiry as `MM/YY`. Stored as typed and never parsed.
    #[serde(
        rename = "card_expiry",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub expiry: String,
    /// Card security code (CVV/CVC). Secret.
    #[serde(rename = "card_cvv", default, skip_serializing_if = "String::is_empty")]
    pub cvv: String,
    /// Card PIN. Secret.
    #[serde(rename = "card_pin", default, skip_serializing_if = "String::is_empty")]
    pub pin: String,
}

/// Represents a user's secret entry (password, note, etc.)
///
/// `ZeroizeOnDrop` wipes the secret-bearing fields from memory when an entry is
/// dropped instead of leaving them in freed allocations. That reaches into
/// [`CardFields`] too, three of whose members are as sensitive as `secret`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretEntry {
    pub name: String,
    pub user_name: String,
    pub secret: String,
    pub url: String,
    pub notes: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub tags: Vec<String>,
    pub created: i64,
    pub modified: i64,
    #[serde(default)]
    pub hidden: bool,
    /// Files attached to this entry. Empty on an entry that has none, and
    /// omitted from the JSON entirely when it is, so an entry without
    /// attachments serializes exactly as it did before they existed and a
    /// vault written by an older build parses with none.
    ///
    /// These are the *references*: the bytes live in [`Attachments`], on the
    /// [`AskryptFile`] rather than on the entry, because they are ciphertext
    /// and belong to the archive rather than to the decrypted entry list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// The card fields, spread across the entry's own JSON object rather than
    /// nested under a `card` key. Empty on everything that is not a card.
    ///
    /// Kept last by convention: a flattened field is the catch-all for keys the
    /// named fields did not claim, so reading it after them is how the struct
    /// reads on the page.
    #[serde(flatten)]
    pub card: CardFields,
}

/// Represents open parameters for [AskryptFile]
///
/// Note that these are stored **unencrypted** in the vault, so `host` is
/// visible to anyone holding the file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Params {
    /// Key derivation function name (e.g. "pbkdf2-sha256")
    pub kdf: String,
    /// Number of KDF iterations
    pub iterations: u32,
    /// Base64-encoded salt
    pub salt: String,
    /// Whether to apply Russian/Ukrainian transliteration to answers
    #[serde(default)]
    pub translit: bool,
    /// Label for the machine that last wrote the vault, `os@host` (e.g.
    /// `ubuntu@mypc`) or the OS name alone when the host name is unknown.
    /// Opaque display text: older files carry a bare host name with no OS
    /// half, and older files still may omit the field entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// When the vault was last written, RFC 3339 UTC with second precision
    /// (e.g. `2026-08-02T10:15:30Z`); absent in older files
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Represents the encrypted questions and second-level KDF parameters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct QuestionsData {
    pub questions: Vec<String>,
    // sal1 - used to derive a second_key
    pub salt: String,
}

/// Represents the encrypted master key and IV
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MasterData {
    #[serde(rename = "masterKey")]
    pub master_key: String,
    pub iv: String,
}

/// A vault's 32-byte master key, in the clear.
///
/// This is the key the `data` blob — and every encrypted file attachment — is
/// encrypted under. It is minted **once**, when the vault is
/// created, and preserved for the life of the vault: [`AskryptFile::create`]
/// takes it back as `Option<&MasterSecret>` so a save re-wraps the existing key
/// under the answers instead of rotating it. Rotating it would mean decrypting
/// and re-encrypting every blob beneath it on every save.
///
/// [`AskryptFile::decrypt_with_master`] is how a caller gets one: it falls out
/// of the same derivation that opens the vault, so recovering it costs nothing
/// extra.
///
/// [`AskryptFile::create`]: crate::AskryptFile::create
/// [`AskryptFile::decrypt_with_master`]: crate::AskryptFile::decrypt_with_master
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    /// Mint a fresh master key. Only a brand-new vault should call this.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self(key)
    }

    /// Adopt 32 decoded bytes, rejecting any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        let key: [u8; 32] = bytes.try_into().map_err(|_| "Invalid master key length")?;
        Ok(Self(key))
    }

    /// The raw key, for encrypting blobs that live under it.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hand-written so the key never reaches a log or a `{:?}` of some message
/// enum: this value is carried in the desktop apps' `Message` types, every one
/// of which derives `Debug`.
impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// Main Askrypt file structure in JSON format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskryptFile {
    pub version: String,
    pub question0: String,
    pub params: Params,
    pub qs: String,
    pub master: String,
    pub data: String,
    /// Where to read every file attached to an entry of this vault — never the
    /// bytes themselves.
    ///
    /// **Not part of `askrypt.json`** — `#[serde(skip)]`, because these are ZIP
    /// members of their own. [`AskryptFile::from_path`] fills this in by
    /// *listing* the `files/` members it finds, inflating none of them, and
    /// [`AskryptFile::write_archive`] streams each one back out from wherever it
    /// currently lives. That is what keeps the [`crate::storage::VaultStorage`]
    /// seam unaware that attachments exist at all while keeping a vault of any
    /// size within reach.
    ///
    /// [`AskryptFile::from_path`]: crate::AskryptFile::from_path
    /// [`AskryptFile::write_archive`]: crate::AskryptFile::write_archive
    #[serde(skip)]
    pub attachments: Attachments,
}
