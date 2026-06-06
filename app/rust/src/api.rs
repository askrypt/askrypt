//! Session-oriented API exposed to Flutter via flutter_rust_bridge.
//!
//! Typical flow mirrors the desktop app:
//! 1. [`load_vault`] the `.askrypt` bytes -> [`LoadedVault`] (exposes `question0`).
//! 2. [`LoadedVault::remaining_questions`] with the first answer to reveal the
//!    rest of the questions.
//! 3. [`LoadedVault::unlock`] with all answers -> [`UnlockedVault`] holding the
//!    decrypted entries.
//! 4. Mutate via add/update/delete/set_hidden, then [`UnlockedVault::to_bytes`]
//!    and persist on the platform side.

use askrypt::passgen::{self, PasswordGenConfig};
use askrypt::{AskryptFile, SecretEntry};
use flutter_rust_bridge::frb;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const DEFAULT_ITERATIONS: u32 = 600_000;

/// Current unix time in seconds, used for entry created/modified stamps.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// DTOs crossing the FFI boundary
// ---------------------------------------------------------------------------

/// A secret entry as shown in lists — deliberately excludes the secret value,
/// which must be fetched on demand via [`UnlockedVault::reveal_secret`].
pub struct EntryView {
    pub name: String,
    pub user_name: String,
    pub url: String,
    pub notes: String,
    pub entry_type: String,
    pub tags: Vec<String>,
    pub created: i64,
    pub modified: i64,
    pub hidden: bool,
}

impl From<&SecretEntry> for EntryView {
    fn from(e: &SecretEntry) -> Self {
        Self {
            name: e.name.clone(),
            user_name: e.user_name.clone(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            entry_type: e.entry_type.clone(),
            tags: e.tags.clone(),
            created: e.created,
            modified: e.modified,
            hidden: e.hidden,
        }
    }
}

/// Fields supplied by the UI when creating or updating an entry. Timestamps are
/// managed by Rust (created preserved on update, modified bumped to now).
pub struct EntryInput {
    pub name: String,
    pub user_name: String,
    pub secret: String,
    pub url: String,
    pub notes: String,
    pub entry_type: String,
    pub tags: Vec<String>,
    pub hidden: bool,
}

/// Mirror of [`PasswordGenConfig`] for the FFI boundary.
pub struct PassGenOptions {
    pub length: u32,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl From<&PassGenOptions> for PasswordGenConfig {
    fn from(o: &PassGenOptions) -> Self {
        let mut cfg = PasswordGenConfig {
            length: 0,
            use_uppercase: o.use_uppercase,
            use_lowercase: o.use_lowercase,
            use_numbers: o.use_numbers,
            use_symbols: o.use_symbols,
        };
        // Route through set_length so the core's min/max clamping applies.
        cfg.set_length(o.length as usize);
        cfg
    }
}

// ---------------------------------------------------------------------------
// Stateless helpers
// ---------------------------------------------------------------------------

/// Generate a password using the core generator. Returns an error string when
/// no character classes are selected.
pub fn generate_password(options: PassGenOptions) -> Result<String, String> {
    passgen::generate_password(&PasswordGenConfig::from(&options))
}

/// Create a brand-new vault from questions/answers and return the `.askrypt`
/// ZIP bytes for the platform layer to persist. `iterations` defaults to
/// 600,000 when `None`.
pub fn create_vault(
    questions: Vec<String>,
    answers: Vec<String>,
    entries: Vec<EntryInput>,
    iterations: Option<u32>,
    translit: bool,
) -> Result<Vec<u8>, String> {
    let now = now_unix();
    let secrets: Vec<SecretEntry> = entries
        .into_iter()
        .map(|e| secret_from_input(e, now, now))
        .collect();
    let file = AskryptFile::create(
        questions,
        answers,
        secrets,
        Some(iterations.unwrap_or(DEFAULT_ITERATIONS)),
        translit,
    )
    .map_err(|e| e.to_string())?;
    file.to_bytes().map_err(|e| e.to_string())
}

/// Parse `.askrypt` ZIP bytes into a [`LoadedVault`] (not yet decrypted).
pub fn load_vault(bytes: Vec<u8>) -> Result<LoadedVault, String> {
    let file = AskryptFile::from_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok(LoadedVault { file })
}

fn secret_from_input(e: EntryInput, created: i64, modified: i64) -> SecretEntry {
    SecretEntry {
        name: e.name,
        user_name: e.user_name,
        secret: e.secret,
        url: e.url,
        notes: e.notes,
        entry_type: e.entry_type,
        tags: e.tags,
        created,
        modified,
        hidden: e.hidden,
    }
}

// ---------------------------------------------------------------------------
// Loaded (locked) vault
// ---------------------------------------------------------------------------

/// A parsed but still-encrypted vault. Opaque to Dart.
#[frb(opaque)]
pub struct LoadedVault {
    file: AskryptFile,
}

impl LoadedVault {
    /// The first security question (always available without any answer).
    pub fn question0(&self) -> String {
        self.file.question0.clone()
    }

    /// Whether answers are transliterated before normalization.
    pub fn translit(&self) -> bool {
        self.file.params.translit
    }

    /// PBKDF2 iteration count used by this vault.
    pub fn iterations(&self) -> u32 {
        self.file.params.iterations
    }

    /// Reveal the remaining questions by supplying the first answer. Fails if
    /// the first answer is wrong.
    pub fn remaining_questions(&self, first_answer: String) -> Result<Vec<String>, String> {
        self.file
            .get_questions_data(first_answer)
            .map(|qd| qd.questions)
            .map_err(|e| e.to_string())
    }

    /// Decrypt the vault with all answers (first answer first). On success
    /// returns an [`UnlockedVault`] holding the decrypted entries in Rust.
    pub fn unlock(&self, answers: Vec<String>) -> Result<UnlockedVault, String> {
        if answers.is_empty() {
            return Err("At least one answer is required".to_string());
        }
        let questions_data = self
            .file
            .get_questions_data(answers[0].clone())
            .map_err(|e| e.to_string())?;
        let entries = self
            .file
            .decrypt(&questions_data, answers[1..].to_vec())
            .map_err(|e| e.to_string())?;

        let mut questions = vec![self.file.question0.clone()];
        questions.extend(questions_data.questions);

        Ok(UnlockedVault {
            questions,
            answers,
            entries,
            iterations: self.file.params.iterations,
            translit: self.file.params.translit,
        })
    }
}

// ---------------------------------------------------------------------------
// Unlocked vault (holds plaintext)
// ---------------------------------------------------------------------------

/// A decrypted vault session. Holds answers and plaintext secrets in Rust;
/// these are zeroized on drop. Opaque to Dart.
#[frb(opaque)]
pub struct UnlockedVault {
    questions: Vec<String>, // full list incl. question0
    answers: Vec<String>,   // full list incl. first answer (sensitive)
    entries: Vec<SecretEntry>,
    iterations: u32,
    translit: bool,
}

impl UnlockedVault {
    /// The entries without their secret values, for list rendering.
    pub fn list_entries(&self) -> Vec<EntryView> {
        self.entries.iter().map(EntryView::from).collect()
    }

    /// Number of entries.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Whether the vault has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reveal a single secret by index (e.g. for show/copy).
    pub fn reveal_secret(&self, index: u32) -> Result<String, String> {
        self.entries
            .get(index as usize)
            .map(|e| e.secret.clone())
            .ok_or_else(|| "Entry index out of range".to_string())
    }

    /// Append a new entry; returns its index.
    pub fn add_entry(&mut self, entry: EntryInput) -> u32 {
        let now = now_unix();
        self.entries.push(secret_from_input(entry, now, now));
        (self.entries.len() - 1) as u32
    }

    /// Update an existing entry in place (created preserved, modified bumped).
    pub fn update_entry(&mut self, index: u32, entry: EntryInput) -> Result<(), String> {
        let slot = self
            .entries
            .get_mut(index as usize)
            .ok_or_else(|| "Entry index out of range".to_string())?;
        let created = slot.created;
        slot.secret.zeroize();
        *slot = secret_from_input(entry, created, now_unix());
        Ok(())
    }

    /// Delete an entry by index.
    pub fn delete_entry(&mut self, index: u32) -> Result<(), String> {
        let i = index as usize;
        if i >= self.entries.len() {
            return Err("Entry index out of range".to_string());
        }
        let mut removed = self.entries.remove(i);
        removed.secret.zeroize();
        Ok(())
    }

    /// Toggle an entry's hidden flag.
    pub fn set_hidden(&mut self, index: u32, hidden: bool) -> Result<(), String> {
        let slot = self
            .entries
            .get_mut(index as usize)
            .ok_or_else(|| "Entry index out of range".to_string())?;
        slot.hidden = hidden;
        slot.modified = now_unix();
        Ok(())
    }

    /// Re-encrypt the current state and return `.askrypt` ZIP bytes to persist.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let file = AskryptFile::create(
            self.questions.clone(),
            self.answers.clone(),
            self.entries.clone(),
            Some(self.iterations),
            self.translit,
        )
        .map_err(|e| e.to_string())?;
        file.to_bytes().map_err(|e| e.to_string())
    }
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        for a in &mut self.answers {
            a.zeroize();
        }
        for e in &mut self.entries {
            e.secret.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input(name: &str, secret: &str) -> EntryInput {
        EntryInput {
            name: name.to_string(),
            user_name: "user".to_string(),
            secret: secret.to_string(),
            url: "https://example.com".to_string(),
            notes: String::new(),
            entry_type: "password".to_string(),
            tags: vec!["t".to_string()],
            hidden: false,
        }
    }

    #[test]
    fn full_session_roundtrip() {
        let questions = vec![
            "q0".to_string(),
            "q1".to_string(),
            "q2".to_string(),
        ];
        let answers = vec!["a0".to_string(), "a1".to_string(), "a2".to_string()];

        let bytes = create_vault(
            questions.clone(),
            answers.clone(),
            vec![sample_input("Gmail", "pw123")],
            Some(6000),
            false,
        )
        .unwrap();

        let loaded = load_vault(bytes).unwrap();
        assert_eq!(loaded.question0(), "q0");
        assert_eq!(loaded.remaining_questions("a0".to_string()).unwrap(), vec!["q1", "q2"]);

        let mut session = loaded.unlock(answers.clone()).unwrap();
        assert_eq!(session.len(), 1);
        let listed = session.list_entries();
        assert_eq!(listed[0].name, "Gmail");
        assert_eq!(session.reveal_secret(0).unwrap(), "pw123");

        // Mutate, persist, reload and verify.
        session.add_entry(sample_input("GitHub", "ghpw"));
        session.update_entry(0, sample_input("Gmail2", "newpw")).unwrap();
        assert_eq!(session.len(), 2);

        let saved = session.to_bytes().unwrap();
        let reloaded = load_vault(saved).unwrap().unlock(answers).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.reveal_secret(0).unwrap(), "newpw");
        assert_eq!(reloaded.list_entries()[1].name, "GitHub");
    }

    #[test]
    fn unlock_with_wrong_answer_fails() {
        let bytes = create_vault(
            vec!["q0".to_string(), "q1".to_string()],
            vec!["a0".to_string(), "a1".to_string()],
            vec![],
            Some(6000),
            false,
        )
        .unwrap();
        let loaded = load_vault(bytes).unwrap();
        assert!(loaded.unlock(vec!["a0".to_string(), "wrong".to_string()]).is_err());
    }

    #[test]
    fn delete_out_of_range_errors() {
        let bytes = create_vault(
            vec!["q0".to_string(), "q1".to_string()],
            vec!["a0".to_string(), "a1".to_string()],
            vec![],
            Some(6000),
            false,
        )
        .unwrap();
        let mut session = load_vault(bytes)
            .unwrap()
            .unlock(vec!["a0".to_string(), "a1".to_string()])
            .unwrap();
        assert!(session.delete_entry(0).is_err());
    }

    #[test]
    fn generate_password_respects_options() {
        let pw = generate_password(PassGenOptions {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: false,
        })
        .unwrap();
        assert_eq!(pw.len(), 16);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

        let err = generate_password(PassGenOptions {
            length: 16,
            use_uppercase: false,
            use_lowercase: false,
            use_numbers: false,
            use_symbols: false,
        });
        assert!(err.is_err());
    }
}
