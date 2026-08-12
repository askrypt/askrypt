use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// The card fields, spread across the entry's own JSON object rather than
    /// nested under a `card` key. Empty on everything that is not a card.
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
/// This is the key the `data` blob — and, in future, every encrypted file
/// attachment — is encrypted under. It is minted **once**, when the vault is
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
}
