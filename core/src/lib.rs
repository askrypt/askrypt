//! # Askrypt - Secure Password Manager Library
//!
//! Askrypt is a library for creating and managing encrypted password vaults using
//! a question-and-answer based authentication system.
//!
//! ## Overview
//!
//! The library implements a multi-layered encryption scheme where:
//! - The first answer encrypts additional questions
//! - Remaining answers encrypt the master key
//! - The master key encrypts your actual secret data
//!
//! ## Quick Start Example
//!
//! ```
//! use askrypt::{Attachments, AskryptFile, SecretEntry};
//!
//! // Define your security questions
//! let questions = vec![
//!     "What is your mother's maiden name?".to_string(),
//!     "What was your first pet's name?".to_string(),
//!     "What city were you born in?".to_string(),
//! ];
//!
//! // Provide answers
//! let answers = vec![
//!     "Smith".to_string(),
//!     "Fluffy".to_string(),
//!     "New York".to_string(),
//! ];
//!
//! // Create secret entries to store
//! let secrets = vec![
//!     SecretEntry {
//!         name: "Gmail".to_string(),
//!         user_name: "user2".to_string(),
//!         secret: "my_super_secret_password".to_string(),
//!         url: "https://gmail.com".to_string(),
//!         notes: "Personal email account".to_string(),
//!         entry_type: "password".to_string(),
//!         tags: vec!["email".to_string(), "personal".to_string()],
//!         created: 1704067200,
//!         modified: 1704067200,
//!         hidden: false,
//!         attachments: Vec::new(),
//!         card: Default::default(),
//!     }
//! ];
//!
//! // Create the encrypted file
//! let askrypt_file = AskryptFile::create(
//!     questions,
//!     answers.clone(),
//!     secrets.clone(),
//!     Some(5000),
//!     false,
//!     None, // no existing master key: mint one
//!     &Attachments::new(), // no file attachments
//! ).unwrap();
//!
//! // Save to disk
//! askrypt_file.save_to_file("my_vault.askrypt").unwrap();
//!
//! // Later, load and decrypt
//! let loaded = AskryptFile::load_from_file("my_vault.askrypt").unwrap();
//! let question_data = loaded.get_questions_data("Smith".into()).unwrap();
//! let decrypted_secrets = loaded.decrypt(&question_data, answers[1..].into()).unwrap();
//!
//! assert_eq!(decrypted_secrets, secrets);
//! # std::fs::remove_file("my_vault.askrypt").ok();
//! ```

pub mod passgen;
pub mod storage;
pub mod translit;
pub mod types;

#[cfg(feature = "server-storage")]
pub use storage::{
    BrowserLogin, BrowserLoginStatus, MAX_VAULT_BYTES, RemoteVault, ServerClient, ServerStorage,
    normalize_base_url,
};
pub use storage::{
    LocalFileStorage, MemoryStorage, RemoteRevision, Revision, StorageError, VaultStorage,
};
pub use types::*;

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const DEFAULT_KDF: &str = "pbkdf2";

/// The one ZIP member the format has always had: the vault's JSON.
const VAULT_ENTRY: &str = "askrypt.json";

/// The prefix every file-attachment member carries. The rest of the name is the
/// attachment's [`Attachment::id`] and nothing else, so the archive listing of a
/// vault reveals how many files it holds but never what they are called.
const ATTACHMENT_PREFIX: &str = "files/";

/// Ceiling on the inflated `askrypt.json`.
///
/// This is the one member a reader has no choice but to hold whole, so it is
/// the one a **crafted** archive can use to make it allocate: a few hundred
/// bytes of deflated zeros expand to gigabytes. A megabyte is orders of
/// magnitude above any real vault's metadata — the entries are one base64
/// string, however many there are — and it is the same figure the server's own
/// reader (`server/src/vaultfile.rs`) and the browser port use.
///
/// There is deliberately **no ceiling on the attachments** any more. There used
/// to be one, 256 MiB across the archive, and it was a bound on what a reader
/// would allocate — back when opening a vault inflated every blob into memory.
/// Nothing does now: opening lists the members, saving copies them across
/// compressed, and extracting one streams it to the file the user named. A
/// crafted archive can therefore make this crate write a large file to a
/// destination the user chose, which is what any archiver does, and the cap
/// would only have stopped legitimate vaults from opening. The Dart and browser
/// ports still inflate, so they still cap; that is a property of a reader, not
/// of the format.
const MAX_JSON_BYTES: u64 = 1024 * 1024;

/// Derive a 32-byte key via PBKDF2 into a self-zeroizing array.
///
/// Both the intermediate PBKDF2 buffer and the returned array wipe themselves on
/// drop, so no plaintext copy of the derived key lingers in freed memory (unlike
/// `calc_pbkdf2(..)?.try_into()`, which frees the `Vec` without wiping it).
fn derive_key(
    secret: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let key = Zeroizing::new(calc_pbkdf2(secret, salt, iterations)?);
    if key.len() != 32 {
        return Err("Invalid key length".into());
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key);
    Ok(key_array)
}

impl AskryptFile {
    /// Create a new AskryptFile from questions, answers, and secret data
    ///
    /// # Arguments
    ///
    /// * `questions` - A vector of at least 2 questions
    /// * `answers` - A vector of answers (same length as questions)
    /// * `secret_data` - A vector of SecretEntry items to encrypt
    /// * `iterations` - Optional iterations for first KDF (default: 600000)
    /// * `master` - The vault's existing master key, or `None` to mint a fresh
    ///   one. Pass `None` **only for a brand-new vault**: every save of an
    ///   already-open vault must hand back the key
    ///   [`decrypt_with_master`](Self::decrypt_with_master) recovered, so that
    ///   blobs encrypted under it (the file attachments) survive the
    ///   write. Changing the questions and answers is still a save in this
    ///   sense — the answers re-wrap the same key, which is the whole point of
    ///   the master-key indirection.
    /// * `attachments` - The vault's attachment ciphertexts. Every save must
    ///   hand these back for the same reason it must hand back the master key:
    ///   they are encrypted under it and this call rebuilds the whole archive.
    ///   Pass [`Attachments::new`] when there are none. Blobs no entry in
    ///   `secret_data` refers to are **dropped** here rather than written —
    ///   `SPEC.md` makes that a rule, so that deleting an attachment shrinks
    ///   the vault.
    ///
    /// `salt0`, `salt1` and the `data` IV are always regenerated, even when the
    /// master key is kept. The IV especially: AES-CBC under a repeated key *and*
    /// IV would let anyone holding two versions of a vault read off how long a
    /// prefix of the entry list went unchanged.
    ///
    /// # Returns
    ///
    /// Returns a Result containing the AskryptFile or an error
    ///
    /// # Example
    ///
    /// ```
    /// use askrypt::{Attachments, AskryptFile, SecretEntry};
    ///
    /// let questions = vec![
    ///     "What is your mother's maiden name?".to_string(),
    ///     "What was your first pet's name?".to_string(),
    ///     "What city were you born in?".to_string(),
    /// ];
    /// let answers = vec![
    ///     "Smith".to_string(),
    ///     "Fluffy".to_string(),
    ///     "New York".to_string(),
    /// ];
    /// let data = vec![
    ///     SecretEntry {
    ///         name: "example".to_string(),
    ///         user_name: "user5".to_string(),
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: 1704067200,
    ///         modified: 1704067200,
    ///         hidden: false,
    ///         attachments: Vec::new(),
    ///         card: Default::default(),
    ///     }
    /// ];
    ///
    /// let askrypt_file =
    ///     AskryptFile::create(questions, answers, data, Some(6000), false, None, &Attachments::new()).unwrap();
    /// ```
    pub fn create(
        questions: Vec<String>,
        answers: Vec<String>,
        secret_data: Vec<SecretEntry>,
        iterations: Option<u32>,
        translit: bool,
        master: Option<&MasterSecret>,
        attachments: &Attachments,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate inputs
        if questions.len() < 2 {
            return Err("At least 2 questions is required".into());
        }
        if questions.len() != answers.len() {
            return Err("Number of questions and answers must match".into());
        }
        for question in &questions {
            if question.len() > 500 {
                return Err("Question length must not exceed 500 characters".into());
            }
        }

        let answers: Zeroizing<Vec<String>> = Zeroizing::new(
            answers
                .into_iter()
                .map(|a| normalize_answer(&a, translit))
                .collect(),
        );

        let iterations = iterations.unwrap_or(600000);

        // Step 1: Generate random values. The salts and the IV are always fresh;
        // the master key is only minted when the caller has none to keep.
        let salt0 = generate_bytes(16);
        let salt1 = generate_bytes(16);
        let master_key = master.cloned().unwrap_or_else(MasterSecret::generate);
        let iv_bytes = generate_bytes(16);

        // Step 2: Derive first-key from first answer and salt0
        let salt0_b64 = encode_base64(&salt0);
        // first answer is hashed with salt0 before PBKDF2
        let first_hash = Zeroizing::new(sha256(&answers[0], &salt0_b64));
        let first_key_array = derive_key(&first_hash, &salt0, iterations)?;
        let salt0_iv: [u8; 16] = salt0.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 3: Encrypt questions data (all questions except the first) using first-key and salt0 as IV
        let remaining_questions: Vec<String> = questions.iter().skip(1).cloned().collect();
        let questions_data = QuestionsData {
            questions: remaining_questions,
            salt: encode_base64(&salt1),
        };
        let qs = encrypt_to_base64(&questions_data, &first_key_array, &salt0_iv)?;

        // Step 4: Derive second-key from combined remaining answers and salt1
        let combined_answers: Zeroizing<String> =
            Zeroizing::new(answers.iter().skip(1).cloned().collect());
        // combined_answers is hashed with salt0 before PBKDF2
        let second_hash = Zeroizing::new(sha256(&combined_answers, &salt0_b64));
        let second_key_array = derive_key(&second_hash, &salt1, iterations)?;
        let salt1_iv: [u8; 16] = salt1.clone().try_into().map_err(|_| "Invalid IV length")?;

        // Step 5: Encrypt master key and IV using second-key and salt1 as IV
        let master_data = MasterData {
            master_key: encode_base64(master_key.as_bytes()),
            iv: encode_base64(&iv_bytes),
        };
        let master = encrypt_to_base64(&master_data, &second_key_array, &salt1_iv)?;

        // Step 6: Encrypt secret data using master key and IV
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;
        let data = encrypt_to_base64(&secret_data, master_key.as_bytes(), &iv_array)?;

        // Step 7: Carry the attachment blobs across, less any the entries being
        // written no longer refer to.
        let mut attachments = attachments.clone();
        attachments.retain_referenced(&secret_data);

        // Step 8: Create and return AskryptFile
        let mut file = AskryptFile {
            version: "0.9".to_string(),
            question0: questions[0].clone(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations,
                salt: salt0_b64,
                translit,
                host: None,
                updated_at: None,
            },
            qs,
            master,
            data,
            attachments,
        };
        // Every write goes through `create` (the vault's blobs are re-encrypted
        // on each save), so stamping here keeps the fields current.
        file.touch();
        Ok(file)
    }

    /// Stamp `params.host` and `params.updated_at` with this machine and the
    /// current UTC time.
    ///
    /// Called by [`create`](Self::create); call it directly only when writing a
    /// vault that was not rebuilt through `create`.
    pub fn touch(&mut self) {
        self.params.host = current_host();
        self.params.updated_at = Some(now_utc_rfc3339());
    }

    /// Decrypt an AskryptFile and retrieve the secret data using the answers
    ///
    /// # Arguments
    ///
    /// * `answers` - A vector of answers
    ///
    /// # Returns
    ///
    /// Returns a Result containing the decrypted Vec<SecretEntry> or an error
    ///
    /// # Example
    ///
    /// ```
    /// use askrypt::{Attachments, AskryptFile, SecretEntry};
    ///
    /// let questions = vec![
    ///     "What is your mother's maiden name?".to_string(),
    ///     "What was your first pet's name?".to_string(),
    ///     "What city were you born in?".to_string(),
    /// ];
    /// let answers = vec![
    ///     "Smith".to_string(),
    ///     "Fluffy".to_string(),
    ///     "New York".to_string(),
    /// ];
    /// let data = vec![
    ///     SecretEntry {
    ///         name: "example".to_string(),
    ///         user_name: "user5".to_string(),
    ///         secret: "password123".to_string(),
    ///         url: "https://example.com".to_string(),
    ///         notes: "My account".to_string(),
    ///         entry_type: "password".to_string(),
    ///         tags: vec![],
    ///         created: 1704067200,
    ///         modified: 1704067200,
    ///         hidden: false,
    ///         attachments: Vec::new(),
    ///         card: Default::default(),
    ///     }
    /// ];
    ///
    /// let askrypt_file =
    ///     AskryptFile::create(questions, answers.clone(), data.clone(), Some(6000), false, None, &Attachments::new())
    ///         .unwrap();
    /// let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
    /// let decrypted_data = askrypt_file.decrypt(&questions_data, answers[1..].into()).unwrap();
    /// assert_eq!(decrypted_data, data);
    /// ```
    pub fn decrypt(
        &self,
        questions_data: &QuestionsData,
        answers: Vec<String>,
    ) -> Result<Vec<SecretEntry>, Box<dyn std::error::Error>> {
        Ok(self.decrypt_with_master(questions_data, answers)?.0)
    }

    /// Decrypt an AskryptFile, handing back the vault's [`MasterSecret`] along
    /// with the secret data.
    ///
    /// This is the call an app that intends to *save* the vault again should
    /// make: feeding the recovered key back into
    /// [`create`](Self::create) keeps every blob encrypted under it readable
    /// across the write. The key falls out of the same derivation that opens the
    /// vault, so this costs nothing over [`decrypt`](Self::decrypt) — asking for
    /// the entries and the key separately would pay for the (expensive) second
    /// KDF pass twice.
    pub fn decrypt_with_master(
        &self,
        questions_data: &QuestionsData,
        answers: Vec<String>,
    ) -> Result<(Vec<SecretEntry>, MasterSecret), Box<dyn std::error::Error>> {
        // Validate inputs
        if answers.is_empty() {
            return Err("At least 1 answer is required".into());
        }

        if questions_data.questions.len() != answers.len() {
            return Err("Number of questions and answers must match".into());
        }

        // Decode salt1
        let salt1 = decode_base64(&questions_data.salt)?;
        let salt1_iv: [u8; 16] = salt1.try_into().map_err(|_| "Invalid salt1 length")?;

        let answers: Zeroizing<Vec<String>> = Zeroizing::new(
            answers
                .into_iter()
                .map(|a| normalize_answer(&a, self.params.translit))
                .collect(),
        );
        // Derive second-key from combined remaining answers and salt1
        let combined_answers: Zeroizing<String> = Zeroizing::new(answers.iter().cloned().collect());
        // combined_answers is hashed with salt0 before PBKDF2
        let second_hash = Zeroizing::new(sha256(&combined_answers, &self.params.salt));
        let second_key_array = derive_key(&second_hash, &salt1_iv, self.params.iterations)?;

        // Decrypt master key and IV using second-key and salt1
        let master_data: MasterData =
            decrypt_from_base64(&self.master, &second_key_array, &salt1_iv)?;

        // Decode master key and IV
        let master_key_bytes = Zeroizing::new(decode_base64(&master_data.master_key)?);
        let iv_bytes = decode_base64(&master_data.iv)?;
        let master_key = MasterSecret::from_slice(&master_key_bytes)?;
        let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;

        // Decrypt secret data using master key and IV
        let secret_data: Vec<SecretEntry> =
            decrypt_from_base64(&self.data, master_key.as_bytes(), &iv_array)?;

        Ok((secret_data, master_key))
    }

    /// Get QuestionsData by first answer from the AskryptFile
    ///
    /// # Arguments
    ///
    /// * `first_answer` - The first answer to decrypt the remaining questions
    ///
    /// # Returns
    ///
    /// Returns a Result containing QuestionsData or an error
    pub fn get_questions_data(
        &self,
        first_answer: String,
    ) -> Result<QuestionsData, Box<dyn std::error::Error>> {
        // Decode salt0
        let salt0 = decode_base64(&self.params.salt)?;
        let salt0_iv: [u8; 16] = salt0.try_into().map_err(|_| "Invalid salt0 length")?;

        // Hash first answer with salt0
        let normalized = Zeroizing::new(normalize_answer(&first_answer, self.params.translit));
        let first_answer = Zeroizing::new(sha256(&normalized, &self.params.salt));
        // Derive first-key from first answer and salt0
        let first_key_array = derive_key(&first_answer, &salt0_iv, self.params.iterations)?;

        // Decrypt questions data
        let questions_data: QuestionsData =
            decrypt_from_base64(&self.qs, &first_key_array, &salt0_iv)?;

        Ok(questions_data)
    }

    /// Stream the whole archive into `out`, taking each attachment from its
    /// source rather than from memory.
    ///
    /// This is the writer every other write path goes through. `askrypt.json`
    /// is written first, then one `files/<id>` member per attachment in id
    /// order, each taken from wherever [`Attachments`] says it currently lives:
    ///
    /// * [`AttachmentSource::Carried`] — copied **verbatim** out of the archive
    ///   at [`Attachments::origin`], compressed bytes, method and CRC intact.
    ///   Nothing is inflated, deflated or decrypted, which is what makes
    ///   carrying a large attachment across a save nearly free. It is legal
    ///   because a vault holding an attachment does not rotate its master key
    ///   (`SPEC.md`, "Master key lifetime"), so a member encrypted under it
    ///   stays valid for as long as the vault holds it.
    /// * [`AttachmentSource::Sealed`] — copied from its ciphertext file and
    ///   deflated, like `askrypt.json`. Every member of the archive is written
    ///   the same way. It buys no space (the body is AES-CBC ciphertext, which
    ///   does not compress; deflate falls back to stored blocks and adds a few
    ///   bytes per 64 KB), so this is uniformity rather than economy, and
    ///   readers handle both methods regardless.
    ///
    /// A carried member the origin archive turns out not to hold is skipped,
    /// with the same tolerance the reader has for a dangling reference
    /// (`SPEC.md` rule 3). A carried member with **no origin at all** is an
    /// error rather than a silent omission: dropping it would delete the user's
    /// file, which `SPEC.md` rule 4 exists to prevent.
    pub fn write_archive<W: Write + std::io::Seek>(
        &self,
        out: W,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;

        let mut zip = zip::ZipWriter::new(out);
        let options = SimpleFileOptions::default();

        zip.start_file(VAULT_ENTRY, options)?;
        zip.write_all(json.as_bytes())?;

        // Opened lazily and once: a vault with no carried attachments — a brand
        // new one, or one whose origin is the file we are replacing — must not
        // pay for opening an archive it never reads.
        let mut origin: Option<zip::ZipArchive<std::io::BufReader<std::fs::File>>> = None;

        for (id, source) in self.attachments.iter() {
            let name = format!("{ATTACHMENT_PREFIX}{id}");
            match source {
                AttachmentSource::Sealed(path) => {
                    let mut sealed = buffered_read(std::fs::File::open(path)?);
                    zip.start_file(&name, options)?;
                    std::io::copy(&mut sealed, &mut zip)?;
                }
                AttachmentSource::Carried => {
                    let archive = match &mut origin {
                        Some(archive) => archive,
                        None => {
                            let path = self.attachments.origin().ok_or(
                                "The archive these attachments came from is no longer open",
                            )?;
                            origin.insert(zip::ZipArchive::new(buffered_read(
                                std::fs::File::open(path)?,
                            ))?)
                        }
                    };
                    let Some(index) = archive.index_for_name(&name) else {
                        continue;
                    };
                    zip.raw_copy_file(archive.by_index_raw(index)?)?;
                }
            }
        }

        // `finish` writes the central directory but does not flush the writer
        // it was handed; a `BufWriter` dropped afterwards would swallow the
        // error from its own last write, which is the one that matters.
        let mut out = zip.finish()?;
        out.flush()?;
        Ok(())
    }

    /// Serialize the AskryptFile to an in-memory ZIP archive with internal file
    /// name "askrypt.json".
    ///
    /// The buffered convenience over [`write_archive`](Self::write_archive), for
    /// callers that genuinely want the bytes: the server backend (whose vaults
    /// are capped at 10 MiB anyway), the golden-vector generator, and tests.
    /// Anything writing to a file should use `write_archive` directly, since
    /// this holds the whole archive — attachments and all — in one allocation.
    ///
    /// # Returns
    ///
    /// Returns a Result containing the ZIP archive bytes or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        self.write_archive(std::io::Cursor::new(&mut buf))?;
        Ok(buf)
    }

    /// Parse the archive at `path`, indexing its attachments without reading
    /// one of them.
    ///
    /// This is the reader for anything backed by a file, and the only one that
    /// yields a vault whose attachments can be written back out. It reads
    /// `askrypt.json` and *lists* the `files/` members; each becomes an
    /// [`AttachmentSource::Carried`] against `path`, so their bytes stay on disk
    /// until something actually asks for one. A vault holding a gigabyte of
    /// attachments therefore opens in the same memory as an empty one.
    ///
    /// The caller must keep `path` valid for as long as the vault is open — the
    /// desktop app holds a write lock on it for exactly that reason.
    pub fn from_path<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        let mut zip = zip::ZipArchive::new(buffered_read(std::fs::File::open(path)?))?;
        let mut askrypt_file = Self::read_json(&mut zip)?;
        askrypt_file.attachments = Attachments::from_origin(path, attachment_ids(&zip));
        Ok(askrypt_file)
    }

    /// Deserialize an AskryptFile from an in-memory ZIP archive containing
    /// "askrypt.json".
    ///
    /// The buffered counterpart to [`from_path`](Self::from_path), kept for
    /// callers that only ever hold bytes: the [`storage::VaultStorage`] default
    /// `load_vault`, the parity fixtures, tests.
    ///
    /// Its attachments are indexed as [`AttachmentSource::Carried`] with **no
    /// origin**, because a byte slice is not somewhere they can be read from
    /// again. Such a vault opens, decrypts and lists its attachments perfectly
    /// well; what it cannot do is be written back out, and
    /// [`write_archive`](Self::write_archive) says so with an error rather than
    /// quietly dropping the files (`SPEC.md` rule 4). Spill the bytes to a file
    /// and use `from_path` when the vault has to survive a save.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The ZIP archive bytes to parse
    ///
    /// # Returns
    ///
    /// Returns a Result containing the loaded AskryptFile or an error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let mut askrypt_file = Self::read_json(&mut zip)?;
        for id in attachment_ids(&zip) {
            askrypt_file.attachments.carry_without_origin(id);
        }
        Ok(askrypt_file)
    }

    /// Read and validate `askrypt.json` out of an open archive.
    ///
    /// The attachments field is left empty; the two readers above fill it in
    /// the way that suits where their bytes came from.
    fn read_json<R: std::io::Read + std::io::Seek>(
        zip: &mut zip::ZipArchive<R>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut json = String::new();
        {
            let askrypt_json = zip.by_name(VAULT_ENTRY)?;
            // Checked against the *declared* size before reading, so a bomb is
            // refused rather than expanded and then measured — and capped again
            // while reading, since that figure comes out of the archive and a
            // liar is exactly what this is guarding against.
            if askrypt_json.size() > MAX_JSON_BYTES {
                return Err("The vault's metadata is implausibly large".into());
            }
            std::io::Read::read_to_string(
                &mut std::io::Read::take(askrypt_json, MAX_JSON_BYTES + 1),
                &mut json,
            )?;
            if json.len() as u64 > MAX_JSON_BYTES {
                return Err("The vault's metadata is implausibly large".into());
            }
        }

        let askrypt_file: AskryptFile = serde_json::from_str(&json)?;
        // TODO: Support multiple versions in future
        if askrypt_file.version != "0.9" {
            return Err(
                format!("Unsupported Askrypt file version: {}", askrypt_file.version).into(),
            );
        }
        Ok(askrypt_file)
    }

    /// Save the AskryptFile to a ZIP file with internal file name "askrypt.json"
    ///
    /// Convenience wrapper over [`storage::LocalFileStorage`]; use a
    /// [`storage::VaultStorage`] directly for backend-agnostic persistence.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path where the ZIP file should be saved
    ///
    /// # Returns
    ///
    /// Returns a Result indicating success or an error
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(LocalFileStorage::new(path.as_ref()).save_vault(self)?)
    }

    /// Load an AskryptFile from a ZIP file containing "askrypt.json"
    ///
    /// Convenience wrapper over [`storage::LocalFileStorage`]; use a
    /// [`storage::VaultStorage`] directly for backend-agnostic persistence.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to load the ZIP file from
    ///
    /// # Returns
    ///
    /// Returns a Result containing the loaded AskryptFile or an error
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(LocalFileStorage::new(path.as_ref()).load_vault()?)
    }
}

/// The ids of every `files/` member in an open archive.
///
/// Anything that is not a `files/<something>` member is ignored, exactly as it
/// was before attachments existed. The names are read off the archive rather
/// than off the entry list because the entries are still encrypted at this
/// point — and names are *all* that is read: not one member is opened, which is
/// what lets a vault holding gigabytes of attachments open in the memory an
/// empty one does.
fn attachment_ids<R: std::io::Read + std::io::Seek>(zip: &zip::ZipArchive<R>) -> Vec<String> {
    zip.file_names()
        .filter_map(|name| name.strip_prefix(ATTACHMENT_PREFIX))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

/// Label for the machine writing the vault, for [`Params::host`].
///
/// The shape is `os@host` (`ubuntu@mypc`, `windows@workps`), falling back to the
/// OS name alone when the host name is unavailable or not valid UTF-8 — never a
/// dangling `ubuntu@`. Older vaults carry a bare host name with no OS half, so
/// readers must treat the value as opaque display text.
///
/// # Example
///
/// ```
/// let host = askrypt::current_host().expect("the OS name is always known");
/// assert!(!host.starts_with('@') && !host.ends_with('@'));
/// ```
pub fn current_host() -> Option<String> {
    let os = current_os();
    match gethostname::gethostname().into_string() {
        Ok(host) if !host.trim().is_empty() => Some(format!("{os}@{}", host.trim())),
        _ => Some(os),
    }
}

/// Coarse, lowercase OS name used as the `os@host` prefix of [`current_host`].
///
/// On Linux this is the distro (`ubuntu`, `fedora`, `arch`) when
/// `/etc/os-release` names one, since "linux" alone says little about which
/// machine wrote the file.
fn current_os() -> String {
    #[cfg(target_os = "linux")]
    if let Some(id) = linux_distro_id() {
        return id;
    }
    std::env::consts::OS.to_string()
}

/// Distro ID from `os-release`, read once per process.
#[cfg(target_os = "linux")]
fn linux_distro_id() -> Option<String> {
    static ID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        // `/etc/os-release` is the admin-editable copy and takes precedence;
        // distros that ship only the vendor file provide the second path.
        ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .as_deref()
            .and_then(parse_os_release_id)
    })
    .clone()
}

/// Pull the `ID=` value out of an `os-release` file.
///
/// Returns `None` unless the value looks like the IDs the format specifies —
/// lowercase alphanumerics plus `.`, `_` and `-` — because this ends up in the
/// vault's unencrypted stamp and then in a web table cell.
#[cfg(target_os = "linux")]
fn parse_os_release_id(contents: &str) -> Option<String> {
    let raw = contents
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("ID="))?;
    let id = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    let ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ok.then_some(id)
}

/// Current UTC time formatted as RFC 3339 with second precision, for
/// [`Params::updated_at`] (e.g. `2026-08-02T10:15:30Z`).
///
/// # Example
///
/// ```
/// let stamp = askrypt::now_utc_rfc3339();
/// assert!(stamp.ends_with('Z'));
/// ```
pub fn now_utc_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Encrypt a message using AES-256-CBC with a custom IV
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the encrypted ciphertext as Vec<u8> or an error
///
/// # Example
///
/// ```
/// use askrypt::encrypt_with_aes;
///
/// let message = b"Hello, World!";
/// let key = [0u8; 32];
/// let iv = [0u8; 16];
///
/// let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
/// ```
pub fn encrypt_with_aes(
    message: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcEnc::new(key.into(), iv.into());

    // Calculate buffer size with padding. The buffer holds a copy of the
    // plaintext, so wipe it on drop.
    let pos = message.len();
    let mut buffer = Zeroizing::new(vec![0u8; pos + 16]); // Add extra block for padding
    buffer[..pos].copy_from_slice(message);

    let ciphertext = cipher
        .encrypt_padded::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| "Encryption padding error")?;

    Ok(ciphertext.to_vec())
}

/// Decrypt a message using AES-256-CBC with a custom IV
///
/// # Arguments
///
/// * `ciphertext` - The encrypted ciphertext to decrypt
/// * `key` - A 32-byte encryption key (must match encryption key)
/// * `iv` - A 16-byte initialization vector (must match encryption IV)
///
/// # Returns
///
/// Returns a Result containing the decrypted plaintext as Vec<u8> or an error
///
/// # Example
///
/// ```
/// use askrypt::{encrypt_with_aes, decrypt_with_aes};
///
/// let message = b"Hello, World!";
/// let key = [0u8; 32];
/// let iv = [0u8; 16];
///
/// let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
/// let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();
/// assert_eq!(message, &plaintext[..]);
/// ```
pub fn decrypt_with_aes(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcDec::new(key.into(), iv.into());

    // After decryption `buffer` holds the plaintext, so wipe it on drop. The
    // returned copy is the caller's responsibility to wipe.
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plaintext = cipher
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map_err(|_| "Decryption padding error")?;

    Ok(plaintext.to_vec())
}

/// Encrypt one file's bytes as a vault attachment, minting its id and IV.
///
/// This is the only place an attachment is sealed. It draws 16 random bytes for
/// the id (rendered as 32 lowercase hex characters, which is the whole of the
/// ZIP member's name) and 16 more for a **fresh** IV, then encrypts under the
/// vault's long-lived master key. The IV must be fresh every time: reusing one
/// under a key that never rotates would let anyone holding two versions of a
/// vault read off how much of the attachment went unchanged, which is the same
/// reason `SPEC.md` regenerates the `data` IV on every write.
///
/// The returned [`Attachment`] carries an **empty `name`** — this function
/// deals in bytes and has no opinion about what the file is called. The caller
/// fills it in, along with `added` if it wants something other than now.
///
/// # Returns
///
/// The metadata and the ciphertext, which the caller files into
/// [`Attachments`] under the returned id.
///
/// # Example
///
/// ```
/// use askrypt::{MasterSecret, open_attachment, seal_attachment};
///
/// let master = MasterSecret::generate();
/// let (mut meta, ciphertext) = seal_attachment(b"scan of my passport", &master).unwrap();
/// meta.name = "passport.pdf".to_string();
///
/// let opened = open_attachment(&ciphertext, &meta, &master).unwrap();
/// assert_eq!(&opened[..], b"scan of my passport");
/// ```
pub fn seal_attachment(
    plaintext: &[u8],
    master: &MasterSecret,
) -> Result<(Attachment, Vec<u8>), Box<dyn std::error::Error>> {
    use std::fmt::Write;

    let id = generate_bytes(16).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    let iv_bytes = generate_bytes(16);
    let iv: [u8; 16] = iv_bytes
        .clone()
        .try_into()
        .map_err(|_| "Invalid IV length")?;

    let ciphertext = encrypt_with_aes(plaintext, master.as_bytes(), &iv)?;

    Ok((
        Attachment {
            id,
            name: String::new(),
            size: plaintext.len() as u64,
            added: chrono::Utc::now().timestamp(),
            iv: encode_base64(&iv_bytes),
        },
        ciphertext,
    ))
}

/// Decrypt one attachment's bytes, given its metadata and the vault's key.
///
/// The plaintext is returned in a [`Zeroizing`] because it is the file itself:
/// [`decrypt_with_aes`] wipes its own working buffer but explicitly leaves the
/// returned copy to the caller, and an attachment is exactly the kind of
/// payload that should not linger in a freed allocation.
///
/// `attachment.size` is **not** checked against the result. The format offers no
/// integrity (`SPEC.md`, "Integrity: not provided"), so a mismatch would be a
/// hint rather than a verdict, and refusing on one would turn a recoverable
/// file into an unreadable one.
pub fn open_attachment(
    ciphertext: &[u8],
    attachment: &Attachment,
    master: &MasterSecret,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let iv_bytes = decode_base64(&attachment.iv)?;
    let iv: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;
    Ok(Zeroizing::new(decrypt_with_aes(
        ciphertext,
        master.as_bytes(),
        &iv,
    )?))
}

/// How much of a file is held in memory at a time while it is being encrypted
/// or decrypted.
///
/// The whole point of the streaming pair below is that this number, and not the
/// file's size, is what an attachment costs. It is a multiple of the AES block
/// size, so a chunk is always a whole number of blocks.
const CRYPTO_CHUNK: usize = 64 * 1024;

/// The AES block size, in bytes. CBC advances a block at a time, which is why
/// both streaming functions carry a partial one between chunks.
const AES_BLOCK: usize = 16;

/// Encrypt one file as a vault attachment, streaming it, and mint its metadata.
///
/// The streaming twin of [`seal_attachment`]: same id, same fresh IV, same
/// AES-256-CBC under the vault's long-lived master key, and byte-for-byte the
/// same ciphertext — but neither the plaintext nor the ciphertext is ever held
/// whole. `src` is read and `dest` written in [`CRYPTO_CHUNK`] pieces, which is
/// what lets an attachment be larger than the machine's memory.
///
/// `dest` is a file holding *only* this attachment's ciphertext. It is the sole
/// copy of it until a save folds it into the archive, so nothing may delete it
/// until then — see [`Attachments::sealed_paths`].
///
/// Like [`seal_attachment`] the returned [`Attachment`] carries an **empty
/// `name`**: this function deals in bytes and has no opinion about what the file
/// is called. The caller fills it in.
pub fn seal_attachment_to_file(
    src: &std::path::Path,
    dest: &std::path::Path,
    master: &MasterSecret,
) -> Result<Attachment, Box<dyn std::error::Error>> {
    use std::fmt::Write as _;

    let id = generate_bytes(16).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    let iv_bytes = generate_bytes(16);
    let iv: [u8; 16] = iv_bytes
        .clone()
        .try_into()
        .map_err(|_| "Invalid IV length")?;

    let mut cipher = Aes256CbcEnc::new(master.as_bytes().into(), (&iv).into());

    let mut input = std::io::BufReader::new(std::fs::File::open(src)?);
    let mut output = std::io::BufWriter::new(std::fs::File::create(dest)?);

    // Both hold plaintext, so both wipe on drop. `carry` is the partial block
    // left over from the previous chunk: CBC only ever advances whole blocks,
    // and the *final* partial one belongs to `encrypt_padded`.
    let mut chunk = Zeroizing::new(vec![0u8; CRYPTO_CHUNK]);
    let mut carry = Zeroizing::new(Vec::<u8>::with_capacity(CRYPTO_CHUNK + AES_BLOCK));
    let mut size: u64 = 0;

    loop {
        let read = read_up_to(&mut input, &mut chunk)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        carry.extend_from_slice(&chunk[..read]);

        let whole = (carry.len() / AES_BLOCK) * AES_BLOCK;
        if whole > 0 {
            encrypt_blocks_in_place(&mut cipher, &mut carry[..whole]);
            // Ciphertext now, so draining it needs no wipe.
            std::io::Write::write_all(&mut output, &carry[..whole])?;
            carry.drain(..whole);
        }
    }

    // Whatever is left is under one block, and PKCS#7 always adds a final one —
    // including when nothing is left at all, which is why an empty file still
    // seals to sixteen bytes.
    let leftover = carry.len();
    let mut tail = Zeroizing::new(vec![0u8; 2 * AES_BLOCK]);
    tail[..leftover].copy_from_slice(&carry[..leftover]);
    let final_block = cipher
        .encrypt_padded::<Pkcs7>(&mut tail, leftover)
        .map_err(|_| "Encryption padding error")?;
    std::io::Write::write_all(&mut output, final_block)?;
    std::io::Write::flush(&mut output)?;

    Ok(Attachment {
        id,
        name: String::new(),
        size,
        added: chrono::Utc::now().timestamp(),
        iv: encode_base64(&iv_bytes),
    })
}

/// Decrypt one attachment, streaming it, straight into the file at `dest`.
///
/// The streaming twin of [`open_attachment`]. `src` is any reader over the
/// attachment's ciphertext — a `files/` member of an open archive, or a sealed
/// file — so nothing has to be buffered to get at it, and the plaintext goes to
/// disk a chunk at a time rather than through a `Vec`.
///
/// `attachment.size` is **not** checked against what was written, for the reason
/// [`open_attachment`] gives: the format offers no integrity (`SPEC.md`,
/// "Integrity: not provided"), so a mismatch would be a hint rather than a
/// verdict, and refusing on one would turn a recoverable file into an
/// unreadable one.
pub fn open_attachment_to_file<R: std::io::Read>(
    src: R,
    attachment: &Attachment,
    master: &MasterSecret,
    dest: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let iv_bytes = decode_base64(&attachment.iv)?;
    let iv: [u8; 16] = iv_bytes.try_into().map_err(|_| "Invalid IV length")?;

    let mut cipher = Aes256CbcDec::new(master.as_bytes().into(), (&iv).into());

    let mut input = std::io::BufReader::new(src);
    let mut output = std::io::BufWriter::new(std::fs::File::create(dest)?);

    // Ciphertext on the way in, so neither buffer starts out secret; what comes
    // out of `decrypt_blocks_in_place` is the file itself, and is wiped as soon
    // as it has been written.
    let mut chunk = vec![0u8; CRYPTO_CHUNK];
    let mut carry: Vec<u8> = Vec::with_capacity(CRYPTO_CHUNK + AES_BLOCK);

    loop {
        let read = read_up_to(&mut input, &mut chunk)?;
        if read == 0 {
            break;
        }
        carry.extend_from_slice(&chunk[..read]);

        // Always hold the last whole block back: the PKCS#7 padding lives in it
        // and can only be stripped once we know no more ciphertext is coming.
        if carry.len() > AES_BLOCK {
            let whole = ((carry.len() - 1) / AES_BLOCK) * AES_BLOCK;
            if whole > 0 {
                decrypt_blocks_in_place(&mut cipher, &mut carry[..whole]);
                std::io::Write::write_all(&mut output, &carry[..whole])?;
                zeroize::Zeroize::zeroize(&mut carry[..whole]);
                carry.drain(..whole);
            }
        }
    }

    // Only whole blocks were ever taken out, so what is left is a multiple of
    // the block size unless the ciphertext never was one.
    if carry.is_empty() || !carry.len().is_multiple_of(AES_BLOCK) {
        return Err("Decryption padding error".into());
    }
    let mut tail = Zeroizing::new(carry);
    let final_block = cipher
        .decrypt_padded::<Pkcs7>(&mut tail)
        .map_err(|_| "Decryption padding error")?;
    std::io::Write::write_all(&mut output, final_block)?;
    std::io::Write::flush(&mut output)?;

    Ok(())
}

/// The master key the next write of this vault must use.
///
/// **A vault holding no attachments gets a fresh key on every write.** Nothing
/// but the entry list lives under the key, and that is re-encrypted from
/// plaintext on every save regardless, so rotating costs a single random draw —
/// and it buys the guarantee that a key recovered from one version of a vault
/// does not open the next.
///
/// **A vault holding at least one attachment keeps the key it has.** Its blobs
/// are already sealed under that key and are carried across a save verbatim
/// (`SPEC.md`, "File attachments" rule 5). Minting a new key would mean
/// decrypting and re-encrypting every attached file on every save — a vault
/// with a gigabyte attached would move a gigabyte per save — which is precisely
/// the cost the master-key indirection exists to avoid.
///
/// `current` is the key the vault is under now, recovered by
/// [`AskryptFile::decrypt_with_master`]. There is no `None` case: a vault with
/// no key yet has nothing to decide, and its first
/// [`create`](AskryptFile::create) mints one by being handed `None`.
///
/// The **entries** decide this, not the attachment store, and the test is
/// deliberately "does any entry refer to a file" rather than "does any blob
/// exist": a blob no entry refers to is pruned by `create`, so a vault whose
/// last reference was just removed is attachment-free here and rotates on the
/// save that drops it. A *dangling* reference — an entry naming a blob the
/// archive does not hold — counts as an attachment and keeps the key, which is
/// the conservative way round: keeping a key can never make a file unreadable,
/// minting one can.
pub fn master_for_write(entries: &[SecretEntry], current: &MasterSecret) -> MasterSecret {
    if entries.iter().any(|entry| !entry.attachments.is_empty()) {
        current.clone()
    } else {
        MasterSecret::generate()
    }
}

/// Decrypt one carried attachment straight out of the archive at `origin`.
///
/// The pairing of [`open_attachment_to_file`] with the archive layout, kept
/// here so that knowing a blob lives in a `files/<id>` member stays this
/// crate's business. Nothing is buffered: the member's reader is handed to the
/// streaming decryptor as it inflates.
///
/// A member the archive does not hold is a **dangling reference**, and the
/// error says so; `SPEC.md` requires a reader to tolerate one, which here means
/// telling the caller rather than refusing the vault.
pub fn extract_attachment(
    origin: &std::path::Path,
    attachment: &Attachment,
    master: &MasterSecret,
    dest: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = zip::ZipArchive::new(buffered_read(std::fs::File::open(origin)?))?;
    let member = archive
        .by_name(&format!("{ATTACHMENT_PREFIX}{}", attachment.id))
        .map_err(|_| "This file is not stored in the vault")?;
    open_attachment_to_file(member, attachment, master, dest)
}

/// Wrap a file in a buffer big enough that copying a member is not a syscall
/// storm.
///
/// The ZIP layer reads and writes straight through whatever it is handed, and
/// `raw_copy_file` — the streaming copy that carries an attachment from one
/// archive into the next — moves the whole member through `io::copy`, whose
/// default buffer is 8 KiB. Unbuffered, a gigabyte of attachment is a quarter
/// of a million syscalls on each side; buffered, it is a few thousand.
fn buffered_read(file: std::fs::File) -> std::io::BufReader<std::fs::File> {
    std::io::BufReader::with_capacity(IO_BUFFER, file)
}

/// Buffer size for the archive reads and writes above.
const IO_BUFFER: usize = 1024 * 1024;

/// Fill as much of `buf` as the reader will give, answering how many bytes.
///
/// [`std::io::Read::read`] is free to return fewer bytes than asked for at any
/// time, and a short read would silently misalign the block stream — so this
/// loops until the buffer is full or the reader is done. A returned length
/// below `buf.len()` therefore means end of input and nothing else.
fn read_up_to<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Encrypt `blocks` in place, advancing the CBC chain. Length must be a
/// multiple of [`AES_BLOCK`]; a trailing partial block is silently ignored,
/// which is why every caller splits on a block boundary first.
fn encrypt_blocks_in_place(cipher: &mut Aes256CbcEnc, blocks: &mut [u8]) {
    let (whole, tail) = cipher::InOutBuf::from(blocks).into_chunks();
    debug_assert!(tail.is_empty(), "not a whole number of AES blocks");
    cipher.encrypt_blocks_inout(whole);
}

/// Decrypt `blocks` in place, advancing the CBC chain. Same length rule as
/// [`encrypt_blocks_in_place`].
fn decrypt_blocks_in_place(cipher: &mut Aes256CbcDec, blocks: &mut [u8]) {
    let (whole, tail) = cipher::InOutBuf::from(blocks).into_chunks();
    debug_assert!(tail.is_empty(), "not a whole number of AES blocks");
    cipher.decrypt_blocks_inout(whole);
}

/// Calculate PBKDF2 key derivation from secret and salt
///
/// # Arguments
///
/// * `secret` - The password/secret to derive from
/// * `salt` - The salt bytes to use for derivation
/// * `iterations` - Number of iterations to perform
///
/// # Returns
///
/// Returns a Result containing the derived key as a Vec<u8> or an error
pub fn calc_pbkdf2(
    secret: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use pbkdf2::pbkdf2_hmac;

    let mut output = vec![0u8; 32];

    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, iterations, &mut output);

    Ok(output)
}

/// Normalize an answer by removing all whitespace and converting to lowercase
///
/// # Arguments
///
/// * `answer` - The raw answer string
///
/// # Returns
///
/// A normalized answer string
///
/// # Example
///
/// ```
/// use askrypt::normalize_answer;
///
/// let answer = "Hello World";
/// let normalized = normalize_answer(answer, false);
/// assert_eq!(normalized, "helloworld");
/// ```
pub fn normalize_answer(answer: &str, translit: bool) -> String {
    let s: String = answer
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '–' && *c != '—') // remove all types of dashes
        .collect::<String>()
        .to_lowercase();
    if translit {
        translit::transliterate(&s)
    } else {
        s
    }
}

/// Hash a str using SHA256 + salt
///
/// # Arguments
///
/// * `answer` - The answer to hash
///
/// # Returns
///
/// Returns the SHA256 hash of the str as a hex string
///
/// # Example
///
/// ```
/// use askrypt::sha256;
///
/// let str1 = "Hello World";
/// let hashed = sha256(str1, "salt42");
/// assert_eq!(hashed, "6867f8dfd55dcf8b366244cf78fedf3deae645bfef316e393fd79b125bbbe63a");
/// // hashed will be consistent and reproducible
/// ```
pub fn sha256(data: &str, salt: &str) -> String {
    let data = data.to_string() + salt;
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    // digest 0.11 / sha2 0.11 returns an `Array` that no longer implements
    // `LowerHex`, so build the lowercase hex string byte by byte.
    use std::fmt::Write;
    hasher.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Encrypt data to base64-encoded string
///
/// # Arguments
///
/// * `data` - The data to encrypt (will be serialized to JSON)
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the base64-encoded encrypted data
pub fn encrypt_to_base64<T: Serialize>(
    data: &T,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<String, Box<dyn std::error::Error>> {
    // `json` is the serialized plaintext, so wipe it on drop.
    let json = Zeroizing::new(serde_json::to_string(data)?);
    let encrypted = encrypt_with_aes(json.as_bytes(), key, iv)?;
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt base64-encoded encrypted data
///
/// # Arguments
///
/// * `base64_data` - The base64-encoded encrypted data
/// * `key` - A 32-byte encryption key
/// * `iv` - A 16-byte initialization vector
///
/// # Returns
///
/// Returns a Result containing the decrypted and deserialized data
pub fn decrypt_from_base64<T: for<'de> Deserialize<'de>>(
    base64_data: &str,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<T, Box<dyn std::error::Error>> {
    let encrypted = general_purpose::STANDARD.decode(base64_data)?;
    let decrypted = decrypt_with_aes(&encrypted, key, iv)?;
    // `from_utf8` reuses the decrypted buffer (no copy); wipe the plaintext on drop.
    let json = Zeroizing::new(String::from_utf8(decrypted)?);
    Ok(serde_json::from_str(&json)?)
}

/// Generate a random salt of specified length
///
/// # Arguments
///
/// * `length` - The length of the salt in bytes
///
/// # Returns
///
/// A vector of random bytes
pub fn generate_bytes(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut salt = vec![0u8; length];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Encode bytes to base64 string
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn decode_base64(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(general_purpose::STANDARD.decode(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;

    #[test]
    fn test_encrypt_decrypt_with_custom_iv() {
        let message = b"This is a secret message!";
        let key = [0x42; 32]; // Example key
        let iv = [0x24; 16]; // Example IV

        // Encrypt
        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..], message);

        // Decrypt
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        // Verify decrypted text matches original
        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_different_ivs_produces_different_ciphertexts() {
        let message = b"Same message, different IVs";
        let key = [0x01; 32];
        let iv1 = [0x00; 16];
        let iv2 = [0xFF; 16];

        let ciphertext1 = encrypt_with_aes(message, &key, &iv1).unwrap();
        let ciphertext2 = encrypt_with_aes(message, &key, &iv2).unwrap();

        // Same message with different IVs should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_empty_message() {
        let message = b"";
        let key = [0x10; 32];
        let iv = [0x20; 16];

        let result = encrypt_with_aes(message, &key, &iv);
        assert!(result.is_ok());

        let ciphertext = result.unwrap();
        // Even empty messages get padded
        assert!(!ciphertext.is_empty());
    }

    #[test]
    fn test_decrypt_with_wrong_iv_fails() {
        let message = b"Secret data";
        let key = [0x33; 32];
        let iv_correct = [0x44; 16];
        let iv_wrong = [0x55; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv_correct).unwrap();

        // Decrypting with wrong IV should either fail or produce garbage
        let result = decrypt_with_aes(&ciphertext, &key, &iv_wrong);
        if let Ok(plaintext) = result {
            // If it doesn't fail, it should produce different plaintext
            assert_ne!(&plaintext[..], message);
        }
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let message = b"Another secret";
        let key_correct = [0x66; 32];
        let key_wrong = [0x77; 32];
        let iv = [0x88; 16];

        let ciphertext = encrypt_with_aes(message, &key_correct, &iv).unwrap();

        // Decrypting with wrong key should either fail or produce garbage
        let result = decrypt_with_aes(&ciphertext, &key_wrong, &iv);
        if let Ok(plaintext) = result {
            assert_ne!(&plaintext[..], message);
        }
    }

    #[test]
    fn test_encrypt_long_message() {
        let message = b"This is a much longer message that spans multiple AES blocks. \
                        AES has a block size of 16 bytes, so this message will require \
                        multiple blocks to encrypt. This tests that the encryption works \
                        correctly for messages longer than a single block.";
        let key = [0x99; 32];
        let iv = [0xAA; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_all_zero_iv() {
        let message = b"Testing with zero IV";
        let key = [0xBB; 32];
        let iv = [0x00; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_encrypt_with_all_ones_iv() {
        let message = b"Testing with ones IV";
        let key = [0xCC; 32];
        let iv = [0xFF; 16];

        let ciphertext = encrypt_with_aes(message, &key, &iv).unwrap();
        let plaintext = decrypt_with_aes(&ciphertext, &key, &iv).unwrap();

        assert_eq!(&plaintext[..], message);
    }

    #[test]
    fn test_calculate_pbkdf2_custom() {
        let secret = "password";
        let salt = b"salt";
        let iterations = 10_000;

        let result = calc_pbkdf2(secret, salt, iterations);
        assert!(result.is_ok());

        let derived_key = result.unwrap();
        assert_eq!(derived_key.len(), 32);
        assert_eq!(
            "5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b",
            encode(&derived_key)
        );
    }

    #[test]
    fn test_normalize_answer() {
        assert_eq!(normalize_answer("Hello World?", false), "helloworld?");
        assert_eq!(normalize_answer("Test-Answer !?", false), "testanswer!?");
        assert_eq!(normalize_answer("Test–Answer", false), "testanswer");
        assert_eq!(normalize_answer("Test—Answer", false), "testanswer");
        assert_eq!(normalize_answer("Test--—––Ans–wer ", false), "testanswer");
        assert_eq!(normalize_answer("  Spaces  ", false), "spaces");
        assert_eq!(normalize_answer("Mixed-Case Test", false), "mixedcasetest");
        assert_eq!(
            normalize_answer("\t\nTabs\nAnd\tNewlines\n", false),
            "tabsandnewlines"
        );

        // translit = true
        assert_eq!(normalize_answer("Москва", true), "moskva");
        assert_eq!(normalize_answer("Привет Мир", true), "privetmir");
        assert_eq!(normalize_answer("Ёжик-ёжик", true), "yozhikyozhik");
        assert_eq!(normalize_answer("Київ", true), "kiyiv");
        assert_eq!(normalize_answer("Hello World", true), "helloworld");
        assert_eq!(normalize_answer("Объект", true), "obekt");
    }

    #[test]
    fn test_encrypt_decrypt_to_base64() {
        let data = QuestionsData {
            questions: vec!["Question 2".to_string(), "Question 3".to_string()],
            salt: "test_salt".to_string(),
        };
        let key = [0x42; 32];
        let iv = [0x24; 16];

        let encrypted = encrypt_to_base64(&data, &key, &iv).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted: QuestionsData = decrypt_from_base64(&encrypted, &key, &iv).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_generate_bytes() {
        let bytes1 = generate_bytes(16);
        let bytes2 = generate_bytes(16);

        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 16);
        assert_ne!(bytes1, bytes2); // Should be random
    }

    #[test]
    fn test_encode_decode_base64() {
        let data = b"Hello, World!";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_secret_entry_serialization() {
        let entry = SecretEntry {
            name: "test_user".to_string(),
            user_name: "user5".to_string(),
            secret: "test_password".to_string(),
            url: "https://example.com".to_string(),
            notes: "Test notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string(), "important".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_questions_data_serialization() {
        let qs = QuestionsData {
            questions: vec!["Question 1".to_string(), "Question 2".to_string()],
            salt: "test-salt1".to_string(),
        };

        let json = serde_json::to_string(&qs).unwrap();
        let deserialized: QuestionsData = serde_json::from_str(&json).unwrap();
        assert_eq!(qs, deserialized);

        // Verify JSON has correct field names
        assert!(json.contains("\"questions\""));
        assert!(json.contains("\"salt\""));
    }

    #[test]
    fn test_askrypt_file_serialization() {
        let file = AskryptFile {
            version: "0.9".to_string(),
            question0: "What is your mother's maiden name?".to_string(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations: 600000,
                salt: "base64-salt".to_string(),
                translit: false,
                host: Some("test-host".to_string()),
                updated_at: Some("2026-08-02T10:15:30Z".to_string()),
            },
            qs: "base64-encrypted-questions".to_string(),
            master: "base64-encrypted-master".to_string(),
            data: "base64-encrypted-data".to_string(),
            attachments: Attachments::new(),
        };

        let json = serde_json::to_string(&file).unwrap();
        let deserialized: AskryptFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file, deserialized);
    }

    #[test]
    fn test_askrypt_file_create() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        // Verify basic structure
        assert_eq!(askrypt_file.version, "0.9");
        assert_eq!(askrypt_file.question0, questions[0]);
        assert_eq!(askrypt_file.params.kdf, DEFAULT_KDF);
        assert_eq!(askrypt_file.params.iterations, 6000);
        assert!(!askrypt_file.params.salt.is_empty());
        assert!(!askrypt_file.qs.is_empty());
        assert!(!askrypt_file.master.is_empty());
        assert!(!askrypt_file.data.is_empty());

        // Write stamp
        assert_eq!(askrypt_file.params.host, current_host());
        let updated_at = askrypt_file.params.updated_at.unwrap();
        assert!(updated_at.ends_with('Z'), "not RFC 3339 UTC: {updated_at}");
        assert_eq!(updated_at.len(), "2026-08-02T10:15:30Z".len());
    }

    #[test]
    fn test_askrypt_file_touch_refreshes_stamp() {
        let mut file = AskryptFile {
            version: "0.9".to_string(),
            question0: "Q0".to_string(),
            params: Params {
                kdf: DEFAULT_KDF.to_string(),
                iterations: 600000,
                salt: "base64-salt".to_string(),
                translit: false,
                host: Some("some-other-host".to_string()),
                updated_at: Some("2000-01-01T00:00:00Z".to_string()),
            },
            qs: "qs".to_string(),
            master: "master".to_string(),
            data: "data".to_string(),
            attachments: Attachments::new(),
        };

        file.touch();

        assert_eq!(file.params.host, current_host());
        assert!(file.params.updated_at.unwrap().as_str() > "2000-01-01T00:00:00Z");
    }

    #[test]
    fn test_params_stamp_is_optional_and_omitted_when_absent() {
        // Files written before the stamp existed must still load.
        let json = r#"{
            "version": "0.9",
            "question0": "Q0",
            "params": {"kdf": "pbkdf2", "iterations": 600000, "salt": "c2FsdA=="},
            "qs": "qs",
            "master": "master",
            "data": "data"
        }"#;
        let file: AskryptFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.params.host, None);
        assert_eq!(file.params.updated_at, None);

        // ...and round-trip without inventing the keys.
        let out = serde_json::to_string(&file).unwrap();
        assert!(!out.contains("host"), "{out}");
        assert!(!out.contains("updated_at"), "{out}");
    }

    #[test]
    fn test_current_host_is_os_at_hostname() {
        let os = current_os();
        assert!(!os.is_empty());
        assert_eq!(os, os.to_ascii_lowercase(), "the OS half is lowercase");

        // The OS name is always known, so there is always a stamp.
        let host = current_host().unwrap();
        assert!(host.starts_with(&os), "{host} does not start with {os}");
        match host.split_once('@') {
            Some((left, right)) => {
                assert_eq!(left, os);
                assert!(!right.is_empty(), "dangling separator: {host}");
                assert!(!right.contains('@'), "more than one separator: {host}");
            }
            // No host name on this machine: the OS name stands alone.
            None => assert_eq!(host, os),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_os_release_id() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(parse_os_release_id(ubuntu).as_deref(), Some("ubuntu"));
        assert_eq!(
            parse_os_release_id("ID=\"fedora\"\n").as_deref(),
            Some("fedora")
        );
        assert_eq!(
            parse_os_release_id("  ID=arch  \n").as_deref(),
            Some("arch")
        );
        // `ID_LIKE=` must not be mistaken for `ID=`.
        assert_eq!(parse_os_release_id("ID_LIKE=debian\n"), None);
        assert_eq!(parse_os_release_id("NAME=\"Some OS\"\n"), None);
        assert_eq!(parse_os_release_id("ID=\n"), None);
        // Anything that is not a well-formed ID is not put in the stamp.
        assert_eq!(parse_os_release_id("ID=my distro\n"), None);
        assert_eq!(parse_os_release_id("ID=<script>alert(1)</script>\n"), None);
        assert_eq!(parse_os_release_id("ID=who@where\n"), None);
    }

    #[test]
    fn test_askrypt_file_create_invalid_questions() {
        // Test with no questions
        let questions = vec![];
        let answers = vec![];
        let data = vec![];

        let result = AskryptFile::create(
            questions,
            answers,
            data,
            None,
            false,
            None,
            &Attachments::new(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least 2 questions")
        );

        let questions = vec!["Question 1".to_string()]; // Only 1
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(
            questions,
            answers,
            data2,
            None,
            false,
            None,
            &Attachments::new(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least 2 questions")
        );

        let questions = vec!["Question 1".to_string(), "Question 2".to_string()];
        let answers = vec!["Answer1".to_string()];
        let data2 = vec![];

        let result = AskryptFile::create(
            questions,
            answers,
            data2,
            None,
            false,
            None,
            &Attachments::new(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Number of questions and answers must match")
        );
    }

    #[test]
    fn test_askrypt_file_create_question_too_long() {
        let long_question = "a".repeat(501);
        let questions = vec![
            long_question,
            "Question 2".to_string(),
            "Question 3".to_string(),
        ];
        let answers = vec![
            "Answer1".to_string(),
            "Answer2".to_string(),
            "Answer3".to_string(),
        ];
        let data = vec![];

        let result = AskryptFile::create(
            questions,
            answers,
            data,
            None,
            false,
            None,
            &Attachments::new(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Question length must not exceed 500 characters")
        );
    }

    #[test]
    fn test_askrypt_file_create_and_decrypt() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let original_data = vec![
            SecretEntry {
                name: "example1".to_string(),
                user_name: "user5".to_string(),
                secret: "password123".to_string(),
                url: "https://example.com".to_string(),
                notes: "My account".to_string(),
                entry_type: "password".to_string(),
                tags: vec!["work".to_string()],
                created: 1704067200,
                modified: 1704067200,
                hidden: false,
                attachments: Vec::new(),
                card: Default::default(),
            },
            SecretEntry {
                name: "example2".to_string(),
                user_name: "user5".to_string(),
                secret: "secret456".to_string(),
                url: "https://test.com".to_string(),
                notes: "Test notes".to_string(),
                entry_type: "note".to_string(),
                tags: vec!["personal".to_string(), "important".to_string()],
                created: 1704153600,
                modified: 1704153600,
                hidden: false,
                attachments: Vec::new(),
                card: Default::default(),
            },
        ];

        // Create AskryptFile
        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            original_data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        // Decrypt and verify
        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = askrypt_file
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_askrypt_file_decrypt_wrong_answer() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        // Try to decrypt with wrong answer
        let wrong_answers = vec!["Fluffy".to_string(), "New York2".to_string()];

        let questions_data = askrypt_file.get_questions_data(answers[0].clone()).unwrap();
        let result = askrypt_file.decrypt(&questions_data, wrong_answers);
        // Should fail due to wrong answer (decryption error or invalid JSON)
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Decryption padding error")
        );
    }

    #[test]
    fn test_card_entry_round_trips_through_the_vault() {
        let questions = vec!["Q0".to_string(), "Q1".to_string()];
        let answers = vec!["A0".to_string(), "A1".to_string()];
        let data = vec![SecretEntry {
            name: "Personal Visa".to_string(),
            user_name: String::new(),
            secret: String::new(),
            url: String::new(),
            notes: String::new(),
            entry_type: "Card".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: CardFields {
                holder: "Ruslan A.".to_string(),
                brand: "Visa".to_string(),
                number: "4242 4242 4242 4242".to_string(),
                expiry: "04/29".to_string(),
                cvv: "123".to_string(),
                pin: "9876".to_string(),
            },
        }];

        let file = AskryptFile::create(
            questions,
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let questions_data = file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted = file.decrypt(&questions_data, answers[1..].into()).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_an_entry_without_card_fields_writes_no_card_keys() {
        // The `skip_serializing_if` guarantee: adding the card fields must not
        // change one byte of what a login entry serializes to.
        let entry = SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: String::new(),
            notes: String::new(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("card_"), "unexpected card keys in {json}");
    }

    #[test]
    fn test_entry_json_written_before_cards_parses_with_them_empty() {
        let legacy = r#"{
            "name": "example",
            "user_name": "user5",
            "secret": "password123",
            "url": "https://example.com",
            "notes": "My account",
            "type": "password",
            "tags": [],
            "created": 1704067200,
            "modified": 1704067200
        }"#;

        let entry: SecretEntry = serde_json::from_str(legacy).unwrap();

        assert_eq!(entry.name, "example");
        assert_eq!(entry.card, CardFields::default());
    }

    #[test]
    fn test_askrypt_file_save_and_load() {
        use std::fs;

        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        let temp_file =
            std::env::temp_dir().join(format!("test_askrypt_file_{}.askrypt", std::process::id()));

        // Save to file
        askrypt_file.save_to_file(&temp_file).unwrap();

        // Load from file
        let loaded_file = AskryptFile::load_from_file(&temp_file).unwrap();

        // Verify they match
        assert_eq!(askrypt_file, loaded_file);

        // Verify we can still decrypt with the loaded file
        let questions_data = loaded_file.get_questions_data(answers[0].clone()).unwrap();
        let decrypted_data = loaded_file
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted_data, data);

        // Cleanup
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_askrypt_file_zip_contains_askrypt_json() {
        use std::fs;

        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
        ];

        let answers = vec!["Smith".to_string(), "Fluffy".to_string()];

        let data = vec![SecretEntry {
            name: "test".to_string(),
            user_name: "user5".to_string(),
            secret: "secret".to_string(),
            url: "https://test.com".to_string(),
            notes: "notes".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions,
            answers,
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        let temp_file =
            std::env::temp_dir().join(format!("test_vault_content_{}.askrypt", std::process::id()));

        // Save to zip file
        askrypt_file.save_to_file(&temp_file).unwrap();

        // Verify the zip file contains askrypt.json
        let file = fs::File::open(&temp_file).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        // Check that askrypt.json exists in the archive
        let result = archive.by_name("askrypt.json");
        assert!(result.is_ok(), "askrypt.json should exist in the zip file");

        // Cleanup
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_askrypt_file_to_from_bytes_roundtrip() {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["work".to_string()],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];

        let askrypt_file = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        // Round-trip through the in-memory ZIP buffer
        let bytes = askrypt_file.to_bytes().unwrap();
        let loaded = AskryptFile::from_bytes(&bytes).unwrap();
        assert_eq!(askrypt_file, loaded);

        // The buffer is a valid ZIP archive containing askrypt.json
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        assert!(archive.by_name("askrypt.json").is_ok());

        // Decryption still works on the buffer-loaded file
        let questions_data = loaded.get_questions_data(answers[0].clone()).unwrap();
        let decrypted = loaded
            .decrypt(&questions_data, answers[1..].into())
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_askrypt_file_from_bytes_rejects_garbage() {
        assert!(AskryptFile::from_bytes(b"not a zip archive").is_err());
    }

    // -----------------------------------------------------------------------
    // Master key preservation
    //
    // The master key is minted once, at vault creation, and every later save
    // re-wraps that same key. This is what will let file attachments live under
    // the master key without being re-encrypted on every save.
    // -----------------------------------------------------------------------

    /// Questions, answers and one entry, for the master-key tests below.
    fn master_test_vault() -> (Vec<String>, Vec<String>, Vec<SecretEntry>) {
        let questions = vec![
            "What is your mother's maiden name?".to_string(),
            "What was your first pet's name?".to_string(),
            "What city were you born in?".to_string(),
        ];
        let answers = vec![
            "Smith".to_string(),
            "Fluffy".to_string(),
            "New York".to_string(),
        ];
        let data = vec![SecretEntry {
            name: "example".to_string(),
            user_name: "user5".to_string(),
            secret: "password123".to_string(),
            url: "https://example.com".to_string(),
            notes: "My account".to_string(),
            entry_type: "password".to_string(),
            tags: vec![],
            created: 1704067200,
            modified: 1704067200,
            hidden: false,
            attachments: Vec::new(),
            card: Default::default(),
        }];
        (questions, answers, data)
    }

    /// A directory of this test's own, since tests run in parallel in one
    /// process and the attachment paths below are real files.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "askrypt_core_test_{}_{}",
                tag,
                std::process::id()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).expect("scratch directory");
            Self(dir)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }

        /// A file holding `bytes`, for something to attach.
        fn file(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = self.join(name);
            std::fs::write(&path, bytes).expect("scratch file");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Seal `plaintext` into the scratch directory the way the app does, and
    /// answer the metadata plus a store pointing at it.
    fn seal_into(
        scratch: &Scratch,
        tag: &str,
        plaintext: &[u8],
        master: &MasterSecret,
    ) -> (Attachment, Attachments) {
        let src = scratch.file(&format!("{tag}.plain"), plaintext);
        let dest = scratch.join(&format!("{tag}.sealed"));
        let meta = seal_attachment_to_file(&src, &dest, master).unwrap();
        let mut attachments = Attachments::new();
        attachments.insert_sealed(meta.id.clone(), dest);
        (meta, attachments)
    }

    /// The ciphertext of one member of an archive on disk.
    fn member_bytes(path: &std::path::Path, name: &str) -> Option<Vec<u8>> {
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).ok()?).ok()?;
        let mut member = zip.by_name(name).ok()?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut member, &mut bytes).ok()?;
        Some(bytes)
    }

    /// Open a vault the way an app does, returning the entries and the key.
    fn open(file: &AskryptFile, answers: &[String]) -> (Vec<SecretEntry>, MasterSecret) {
        let questions_data = file.get_questions_data(answers[0].clone()).unwrap();
        file.decrypt_with_master(&questions_data, answers[1..].into())
            .unwrap()
    }

    #[test]
    fn test_saving_an_open_vault_keeps_its_master_key() {
        let (questions, answers, data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (entries, master) = open(&first, &answers);

        // A save: same questions, same answers, the key handed back.
        let second = AskryptFile::create(
            questions,
            answers.clone(),
            entries.clone(),
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        let (reopened, master_again) = open(&second, &answers);
        assert_eq!(
            master_again, master,
            "a save must not rotate the master key"
        );
        assert_eq!(reopened, entries);
    }

    #[test]
    fn test_a_blob_under_the_master_key_survives_a_save() {
        // The reason the key is preserved at all: encrypted file attachments
        // will live under it, and must not need re-encrypting on every save.
        let (questions, answers, data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (entries, master) = open(&first, &answers);

        let attachment = b"the contents of an attached file";
        let attachment_iv = generate_bytes(16);
        let attachment_iv: [u8; 16] = attachment_iv.try_into().unwrap();
        let sealed = encrypt_with_aes(attachment, master.as_bytes(), &attachment_iv).unwrap();

        let second = AskryptFile::create(
            questions,
            answers.clone(),
            entries,
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        let (_, master_after_save) = open(&second, &answers);
        let opened =
            decrypt_with_aes(&sealed, master_after_save.as_bytes(), &attachment_iv).unwrap();
        assert_eq!(opened, attachment);
    }

    // -----------------------------------------------------------------------
    // Master key rotation
    //
    // A vault with no attachments mints a fresh key on every write; one that
    // holds a file keeps its key, so the blobs under it stay readable and a
    // save still carries them across verbatim. See `SPEC.md`, "Master key
    // lifetime".
    // -----------------------------------------------------------------------

    #[test]
    fn a_vault_without_attachments_rotates_on_every_write() {
        let (_, _, data) = master_test_vault();
        let current = MasterSecret::generate();

        let first = master_for_write(&data, &current);
        assert_ne!(first, current);
        // ...and again, so it is per write rather than once.
        let second = master_for_write(&data, &current);
        assert_ne!(second, current);
        assert_ne!(first, second);
    }

    #[test]
    fn a_vault_with_an_attachment_keeps_its_key() {
        // The whole point: the blobs are sealed under it and are carried across
        // a save without being decrypted.
        let (_, _, mut data) = master_test_vault();
        let current = MasterSecret::generate();

        data[0].attachments = vec![Attachment {
            id: "00112233445566778899aabbccddeeff".to_string(),
            name: "passport.pdf".to_string(),
            size: 10,
            added: 1704067200,
            iv: encode_base64(&generate_bytes(16)),
        }];

        assert_eq!(master_for_write(&data, &current), current);
    }

    #[test]
    fn dropping_the_last_reference_lets_the_next_write_rotate() {
        // `create` prunes a blob no entry refers to, so a vault that has just
        // lost its last attachment is attachment-free for this purpose.
        let (_, _, mut data) = master_test_vault();
        let current = MasterSecret::generate();

        data[0].attachments = vec![Attachment {
            id: "00112233445566778899aabbccddeeff".to_string(),
            name: "passport.pdf".to_string(),
            size: 10,
            added: 1704067200,
            iv: encode_base64(&generate_bytes(16)),
        }];
        assert_eq!(master_for_write(&data, &current), current);

        data[0].attachments.clear();
        assert_ne!(master_for_write(&data, &current), current);
    }

    #[test]
    fn a_rotated_vault_reopens_and_the_old_key_is_left_behind() {
        // End to end: write, rotate, write again, and check the file on disk is
        // under the new key and opens with nothing but the answers.
        let (questions, answers, data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (entries, previous) = open(&first, &answers);

        let next = master_for_write(&entries, &previous);
        let second = AskryptFile::create(
            questions,
            answers.clone(),
            entries,
            Some(6000),
            false,
            Some(&next),
            &Attachments::new(),
        )
        .unwrap();

        let (reopened, on_disk) = open(&second, &answers);
        assert_eq!(on_disk, next);
        assert_ne!(on_disk, previous);
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn an_attachment_survives_a_full_save_and_reload() {
        // The end-to-end version of the test above: through `create`, through
        // the ZIP, and back out again, with only the answers to open it.
        let (questions, answers, mut data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (_, master) = open(&first, &answers);

        let scratch = Scratch::new("survives_save_and_reload");
        let plaintext = b"the contents of an attached file";
        let (mut meta, attachments) = seal_into(&scratch, "passport", plaintext, &master);
        meta.name = "passport.pdf".to_string();
        data[0].attachments = vec![meta.clone()];

        let saved = AskryptFile::create(
            questions,
            answers.clone(),
            data,
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap();

        let vault = scratch.join("vault.askrypt");
        saved
            .write_archive(std::fs::File::create(&vault).unwrap())
            .unwrap();

        let reloaded = AskryptFile::from_path(&vault).unwrap();
        let (entries, master_after) = open(&reloaded, &answers);

        assert_eq!(entries[0].attachments.len(), 1);
        let carried = &entries[0].attachments[0];
        assert_eq!(carried.name, "passport.pdf");
        assert_eq!(carried.size, plaintext.len() as u64);

        // The reloaded vault points at the archive it came out of, not at bytes.
        assert!(matches!(
            reloaded.attachments.source(&carried.id),
            Some(AttachmentSource::Carried)
        ));
        assert_eq!(reloaded.attachments.origin(), Some(vault.as_path()));

        let out = scratch.join("passport.out");
        let blob = member_bytes(&vault, &format!("files/{}", carried.id)).expect("blob is there");
        open_attachment_to_file(&blob[..], carried, &master_after, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    }

    #[test]
    fn an_attachment_id_never_names_the_file() {
        // The whole point of the random id: the archive listing of a vault must
        // not say what is in it.
        let (questions, answers, mut data) = master_test_vault();
        let master = MasterSecret::generate();

        let scratch = Scratch::new("id_never_names_the_file");
        let (mut meta, attachments) = seal_into(&scratch, "taxes", b"secret bytes", &master);
        meta.name = "my-tax-return-2025.pdf".to_string();
        data[0].attachments = vec![meta.clone()];

        let bytes = AskryptFile::create(
            questions,
            answers,
            data,
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap()
        .to_bytes()
        .unwrap();

        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        let names: Vec<String> = zip.file_names().map(str::to_string).collect();
        assert!(names.contains(&format!("files/{}", meta.id)));
        assert!(
            !names.iter().any(|name| name.contains("tax-return")),
            "the real file name reached the archive listing: {names:?}"
        );
        // Nor is it anywhere in the clear in the bytes.
        assert!(
            !bytes
                .windows("my-tax-return".len())
                .any(|w| w == b"my-tax-return"),
            "the real file name is readable in the vault bytes"
        );
        // Deflated, like every other member this crate writes.
        let member = zip.by_name(&format!("files/{}", meta.id)).unwrap();
        assert_eq!(member.compression(), zip::CompressionMethod::Deflated);
    }

    #[test]
    fn a_blob_no_entry_refers_to_is_dropped_on_write() {
        // Deleting an attachment has to shrink the vault, so a save writes only
        // what the entries it is writing still point at.
        let (questions, answers, data) = master_test_vault();
        let master = MasterSecret::generate();

        let scratch = Scratch::new("orphan_dropped_on_write");
        let (orphan, attachments) = seal_into(&scratch, "orphan", b"nobody refers to me", &master);

        // `data` carries no attachment references at all.
        let file = AskryptFile::create(
            questions,
            answers,
            data,
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap();

        assert!(file.attachments.is_empty());
        let reloaded = AskryptFile::from_bytes(&file.to_bytes().unwrap()).unwrap();
        assert!(reloaded.attachments.source(&orphan.id).is_none());
    }

    #[test]
    fn an_implausible_askrypt_json_is_refused() {
        // `askrypt.json` is the one member a reader has no choice but to hold
        // whole, so it is the one a crafted archive can use to make it
        // allocate: a few hundred bytes of deflated zeros expand to gigabytes.
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            zip.start_file(
                "askrypt.json",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            let chunk = vec![b' '; 1024 * 1024];
            for _ in 0..64 {
                zip.write_all(&chunk).unwrap();
            }
            zip.finish().unwrap();
        }

        let err = AskryptFile::from_bytes(&buf).expect_err("a zip bomb should be refused");
        assert!(
            err.to_string().contains("implausibly large"),
            "refused for the wrong reason: {err}"
        );
    }

    #[test]
    fn a_large_attachment_no_longer_stops_a_vault_opening() {
        // The counterpart, and the point of the redesign: a *big* attachment is
        // not a bomb, because opening the vault never inflates one. There used
        // to be a 256 MiB ceiling across the archive, and it would have made
        // exactly the vaults this exists for unopenable.
        let scratch = Scratch::new("large_attachment_opens");
        let (questions, answers, mut data) = master_test_vault();
        let master = MasterSecret::generate();

        let file = AskryptFile::create(
            questions,
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        // Not a real 300 MiB file — a member that *claims* to be one, which is
        // all the old check ever looked at.
        let vault = scratch.join("huge.askrypt");
        {
            let mut zip = zip::ZipWriter::new(std::fs::File::create(&vault).unwrap());
            zip.start_file("askrypt.json", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(serde_json::to_string(&file).unwrap().as_bytes())
                .unwrap();
            zip.start_file(
                "files/0123456789abcdef0123456789abcdef",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            let chunk = vec![0u8; 1024 * 1024];
            for _ in 0..300 {
                zip.write_all(&chunk).unwrap();
            }
            zip.finish().unwrap();
        }

        let reopened = AskryptFile::from_path(&vault).expect("a big vault should still open");
        assert_eq!(reopened.attachments.len(), 1);

        // And it can still be saved: the huge member is copied across without
        // being inflated, so the writer holds no more than the reader did.
        data[0].attachments = vec![Attachment {
            id: "0123456789abcdef0123456789abcdef".to_string(),
            name: "huge.bin".to_string(),
            size: 300 * 1024 * 1024,
            added: 1704067200,
            iv: encode_base64(&[0u8; 16]),
        }];
        let again = scratch.join("again.askrypt");
        AskryptFile::create(
            vec![
                "What is your mother's maiden name?".to_string(),
                "What was your first pet's name?".to_string(),
                "What city were you born in?".to_string(),
            ],
            answers,
            data,
            Some(6000),
            false,
            Some(&master),
            &reopened.attachments,
        )
        .unwrap()
        .write_archive(std::fs::File::create(&again).unwrap())
        .unwrap();
        assert_eq!(AskryptFile::from_path(&again).unwrap().attachments.len(), 1);
    }

    #[test]
    fn a_dangling_reference_still_opens_the_vault() {
        // A reference whose blob is missing is a row a UI marks, never a reason
        // to refuse the vault.
        let (questions, answers, mut data) = master_test_vault();
        let master = MasterSecret::generate();

        data[0].attachments = vec![Attachment {
            id: "0123456789abcdef0123456789abcdef".to_string(),
            name: "gone.pdf".to_string(),
            size: 12,
            added: 1704067200,
            iv: encode_base64(&[0u8; 16]),
        }];

        let file = AskryptFile::create(
            questions,
            answers.clone(),
            data,
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        let reloaded = AskryptFile::from_bytes(&file.to_bytes().unwrap()).unwrap();
        let (entries, _) = open(&reloaded, &answers);
        assert_eq!(entries[0].attachments.len(), 1);
        assert!(
            reloaded
                .attachments
                .source("0123456789abcdef0123456789abcdef")
                .is_none()
        );
    }

    #[test]
    fn streaming_and_one_shot_encryption_agree_byte_for_byte() {
        // The streaming pair is the one the desktop uses now, so it has to be
        // the *same* cipher and not merely a working one — a vault sealed by
        // one and opened by the other, or by another implementation, must
        // agree. The sizes straddle every boundary in the implementation: the
        // AES block, the 64 KiB chunk, and one either side of each.
        let scratch = Scratch::new("streaming_agrees");
        let key = [9u8; 32];
        let iv = [3u8; 16];

        for size in [
            0usize,
            1,
            15,
            16,
            17,
            255,
            CRYPTO_CHUNK - 1,
            CRYPTO_CHUNK,
            CRYPTO_CHUNK + 1,
            CRYPTO_CHUNK + 16,
            2 * CRYPTO_CHUNK + 7,
        ] {
            // Not all one byte: a repeated block would hide a chaining bug.
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            let expected = encrypt_with_aes(&plaintext, &key, &iv).unwrap();

            // The streaming half, driven through the public functions by
            // pinning the id and IV afterwards — `seal_attachment_to_file`
            // draws its own, so this exercises the cipher rather than the mint.
            let src = scratch.file(&format!("plain-{size}"), &plaintext);
            let dest = scratch.join(&format!("sealed-{size}"));
            let master = MasterSecret::from_slice(&key).unwrap();
            let meta = seal_attachment_to_file(&src, &dest, &master).unwrap();
            assert_eq!(meta.size, size as u64, "size at {size}");

            // Same cipher, same key, this time under the IV it drew.
            let drawn: [u8; 16] = decode_base64(&meta.iv).unwrap().try_into().unwrap();
            let streamed = std::fs::read(&dest).unwrap();
            assert_eq!(
                streamed,
                encrypt_with_aes(&plaintext, &key, &drawn).unwrap(),
                "streamed ciphertext differs from the one-shot at {size} bytes"
            );

            // And the streaming decryptor reads what the one-shot wrote.
            let fixed = Attachment {
                id: "0".repeat(32),
                name: String::new(),
                size: size as u64,
                added: 0,
                iv: encode_base64(&iv),
            };
            let out = scratch.join(&format!("out-{size}"));
            open_attachment_to_file(&expected[..], &fixed, &master, &out).unwrap();
            assert_eq!(
                std::fs::read(&out).unwrap(),
                plaintext,
                "streamed decryption differs at {size} bytes"
            );
        }
    }

    #[test]
    fn a_carried_attachment_is_copied_across_verbatim() {
        // The heart of the redesign: an attachment already in the archive is
        // moved into the next one as *compressed bytes*, never inflated,
        // decrypted or re-encrypted. If that copy were not exact, every vault
        // with an attachment would quietly rot one save at a time.
        let scratch = Scratch::new("carried_verbatim");
        let (questions, answers, mut data) = master_test_vault();
        let master = MasterSecret::generate();

        let plaintext = b"scanned passport, page 1";
        let (mut meta, attachments) = seal_into(&scratch, "passport", plaintext, &master);
        meta.name = "passport.pdf".to_string();
        data[0].attachments = vec![meta.clone()];

        let first_path = scratch.join("first.askrypt");
        AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap()
        .write_archive(std::fs::File::create(&first_path).unwrap())
        .unwrap();

        // Reopen it, so every attachment is now `Carried`, and save again.
        let reopened = AskryptFile::from_path(&first_path).unwrap();
        assert!(matches!(
            reopened.attachments.source(&meta.id),
            Some(AttachmentSource::Carried)
        ));

        let second_path = scratch.join("second.askrypt");
        AskryptFile::create(
            questions,
            answers.clone(),
            data,
            Some(6000),
            false,
            Some(&master),
            &reopened.attachments,
        )
        .unwrap()
        .write_archive(std::fs::File::create(&second_path).unwrap())
        .unwrap();

        let name = format!("files/{}", meta.id);
        assert_eq!(
            raw_member(&first_path, &name),
            raw_member(&second_path, &name),
            "the carried member was not copied verbatim"
        );

        // Belt and braces: it still decrypts, out of the second archive.
        let out = scratch.join("passport.out");
        extract_attachment(&second_path, &meta, &master, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    }

    #[test]
    fn a_vault_read_from_bytes_refuses_to_drop_its_attachments() {
        // `from_bytes` has nowhere to read a blob from a second time. Writing
        // such a vault must fail rather than silently emit an archive with the
        // `files/` members missing — which is exactly the deletion `SPEC.md`
        // rule 4 exists to prevent.
        let scratch = Scratch::new("no_origin_refuses");
        let (questions, answers, mut data) = master_test_vault();
        let master = MasterSecret::generate();

        let (mut meta, attachments) = seal_into(&scratch, "codes", b"recovery codes", &master);
        meta.name = "codes.txt".to_string();
        data[0].attachments = vec![meta.clone()];

        let file = AskryptFile::create(
            questions,
            answers,
            data,
            Some(6000),
            false,
            Some(&master),
            &attachments,
        )
        .unwrap();
        let bytes = file.to_bytes().unwrap();

        // Round-tripped through bytes, the attachment is known but unreadable.
        let orphaned = AskryptFile::from_bytes(&bytes).unwrap();
        assert!(orphaned.attachments.source(&meta.id).is_some());
        assert_eq!(orphaned.attachments.origin(), None);

        let err = orphaned
            .to_bytes()
            .expect_err("writing a vault with no origin should be refused");
        assert!(
            err.to_string().contains("no longer open"),
            "refused for the wrong reason: {err}"
        );
    }

    /// The raw, still-compressed bytes of one member of an archive on disk.
    fn raw_member(path: &std::path::Path, name: &str) -> Vec<u8> {
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        let index = zip
            .index_for_name(name)
            .expect("the member should be there");
        let mut member = zip.by_index_raw(index).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut member, &mut out).unwrap();
        out
    }

    #[test]
    fn sealing_the_same_bytes_twice_draws_a_fresh_iv() {
        // CBC under a key that never rotates: a repeated IV would let a holder
        // of two versions of a vault see how much of an attachment changed.
        let master = MasterSecret::generate();
        let (first, first_bytes) = seal_attachment(b"identical contents", &master).unwrap();
        let (second, second_bytes) = seal_attachment(b"identical contents", &master).unwrap();

        assert_ne!(first.iv, second.iv);
        assert_ne!(first.id, second.id);
        assert_ne!(first_bytes, second_bytes);
    }

    #[test]
    fn test_changing_the_answers_keeps_the_master_key() {
        // Re-keying is exactly what the master-key indirection is for: the new
        // answers re-wrap the small `master` blob, and everything under it stays
        // readable.
        let (questions, answers, data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (entries, master) = open(&first, &answers);

        let new_questions = vec![
            "Favourite book?".to_string(),
            "First school?".to_string(),
            "Street you grew up on?".to_string(),
        ];
        let new_answers = vec![
            "Dune".to_string(),
            "Oakwood".to_string(),
            "Baker Street".to_string(),
        ];
        let rekeyed = AskryptFile::create(
            new_questions,
            new_answers.clone(),
            entries.clone(),
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        // The old answers no longer open it, but the key underneath is the same.
        assert!(rekeyed.get_questions_data(answers[0].clone()).is_err());
        let (reopened, master_again) = open(&rekeyed, &new_answers);
        assert_eq!(master_again, master);
        assert_eq!(reopened, entries);
    }

    #[test]
    fn test_creating_two_vaults_mints_two_master_keys() {
        let (questions, answers, data) = master_test_vault();

        let a = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data.clone(),
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let b = AskryptFile::create(
            questions,
            answers.clone(),
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();

        assert_ne!(open(&a, &answers).1, open(&b, &answers).1);
    }

    #[test]
    fn test_a_save_rotates_the_salts_and_the_data_iv() {
        // Keeping the master key must not mean keeping the IV: AES-CBC under a
        // repeated key *and* IV lets anyone holding two versions of a vault read
        // off how long a prefix of the entry list went unchanged.
        let (questions, answers, data) = master_test_vault();

        let first = AskryptFile::create(
            questions.clone(),
            answers.clone(),
            data,
            Some(6000),
            false,
            None,
            &Attachments::new(),
        )
        .unwrap();
        let (entries, master) = open(&first, &answers);

        let second = AskryptFile::create(
            questions,
            answers.clone(),
            entries,
            Some(6000),
            false,
            Some(&master),
            &Attachments::new(),
        )
        .unwrap();

        assert_ne!(first.params.salt, second.params.salt, "salt0 must rotate");
        assert_ne!(first.qs, second.qs);
        assert_ne!(first.master, second.master);
        assert_ne!(
            first.data, second.data,
            "identical entries under a repeated key and IV would encrypt identically"
        );

        // And specifically the IV, not just the ciphertext around it.
        let iv_of = |file: &AskryptFile| {
            let questions_data = file.get_questions_data(answers[0].clone()).unwrap();
            let salt1: [u8; 16] = decode_base64(&questions_data.salt)
                .unwrap()
                .try_into()
                .unwrap();
            let combined: String = answers[1..]
                .iter()
                .map(|a| normalize_answer(a, file.params.translit))
                .collect();
            let second_hash = sha256(&combined, &file.params.salt);
            let key = derive_key(&second_hash, &salt1, file.params.iterations).unwrap();
            let master_data: MasterData = decrypt_from_base64(&file.master, &key, &salt1).unwrap();
            master_data.iv.clone()
        };
        assert_ne!(iv_of(&first), iv_of(&second), "the data IV must rotate");
    }
}
