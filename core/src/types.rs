use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents a user's secret entry (password, note, etc.)
///
/// `ZeroizeOnDrop` wipes the secret-bearing fields from memory when an entry is
/// dropped instead of leaving them in freed allocations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
