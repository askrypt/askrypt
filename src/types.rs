use serde::{Deserialize, Serialize};

/// Represents a user's secret entry (password, note, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Represents KDF parameters for the first level (key derivation function, iterations, and salt)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
}

/// Represents the encrypted questions and second-level KDF parameters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionsData {
    pub questions: Vec<String>,
    // sal1 - used to derive a second_key
    pub salt: String,
}

/// Represents the encrypted master key and IV
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub params: KdfParams,
    pub qs: String,
    pub master: String,
    pub data: String,
}
