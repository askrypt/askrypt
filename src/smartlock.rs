//! Smart Lock: every answer held in RAM, re-encrypted under one of them.
//!
//! The bundle is not a vault state of its own as far as the format is
//! concerned — the file on disk is untouched. It is a *shallower* lock than a
//! full one: the decrypted entries and the master key are wiped, but one
//! answer out of the set brings the vault back without retyping the rest.
//!
//! These were associated functions on `Session`. They live here because they
//! borrow nothing: the derivations are 2,000,000 PBKDF2 iterations and must run
//! on a worker thread with owned inputs. [`crate::manager`] owns the *state* —
//! the bundle *is* [`SmartLocked`], one of the vault's typestates, carrying its
//! own data like every other one — and this module owns the crypto that
//! produces and consumes it.

use std::time::{Duration, Instant};

use askrypt::{
    calc_pbkdf2, decrypt_with_aes, encode_base64, encrypt_with_aes, generate_bytes,
    normalize_answer, sha256,
};
use rand::RngExt;
use zeroize::Zeroizing;

use crate::manager::SmartLocked;

/// Iterations for Smart Lock encryption (2,000,000 as specified).
///
/// Deliberately far above the vault's own work factor: this key is derived
/// from a *single* answer, so it has less entropy behind it than the layered
/// unlock does.
pub const SMART_LOCK_ITERATIONS: u32 = 2_000_000;

/// How long an armed Smart Lock lasts before it drops to a full lock.
pub const SMART_LOCK_TIMEOUT: Duration = Duration::from_hours(8);

/// Create Smart Lock data by encrypting all answers with a randomly selected
/// answer. Uses 2,000,000 iterations for key derivation as specified.
///
/// **Worker-thread only.** `answers` holds answers 1.., aligned with
/// `questions`; `answer0` is separate because the format treats it separately.
pub fn create(
    answers: &[String],
    answer0: &str,
    questions: &[String],
    translit: bool,
) -> Result<SmartLocked, Box<dyn std::error::Error>> {
    // Randomly select an answer index (not the first one).
    // `answers` holds the answers to questions 2, 3, …, so index 1 corresponds
    // to `answers[0]`, index 2 to `answers[1]`, and so on.
    if answers.is_empty() {
        return Err("Need at least 2 questions for Smart Lock".into());
    }

    let mut rng = rand::rng();
    let key_answer_index = rng.random_range(1..=answers.len());
    let key_answer = Zeroizing::new(
        answers
            .get(key_answer_index - 1)
            .cloned()
            .unwrap_or_default(),
    );

    if key_answer.is_empty() {
        return Err("Selected answer is empty".into());
    }
    // Get the question text for display on the Smart Lock screen.
    let key_question = questions
        .get(key_answer_index - 1)
        .cloned()
        .unwrap_or_else(|| format!("Question {}", key_answer_index + 1));

    let salt = generate_bytes(16);
    // One IV per ciphertext — see `SmartLocked::iv_answer0`.
    let iv_answer0 = generate_bytes(16);
    let iv_answers = generate_bytes(16);

    // Derive encryption key from the selected answer using PBKDF2.
    let normalized_answer = Zeroizing::new(normalize_answer(&key_answer, translit));
    let salt_b64 = encode_base64(&salt);
    let hashed_answer = Zeroizing::new(sha256(&normalized_answer, &salt_b64));
    // Derive the key into a self-zeroizing array (a plain `try_into` would
    // free the PBKDF2 `Vec` without wiping it).
    let key = Zeroizing::new(calc_pbkdf2(&hashed_answer, &salt, SMART_LOCK_ITERATIONS)?);
    if key.len() != 32 {
        return Err("Invalid key length".into());
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key);
    let iv0_array: [u8; 16] = iv_answer0
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid IV length")?;
    let iv1_array: [u8; 16] = iv_answers
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid IV length")?;

    let encrypted_answer0 = encrypt_with_aes(answer0.as_bytes(), &key_array, &iv0_array)?;

    // Every remaining answer, the key answer among them — the unlock knows
    // which one it was from the salt and IVs, not from the plaintext.
    let answers_json = Zeroizing::new(serde_json::to_string(answers)?);
    let encrypted_answers = encrypt_with_aes(answers_json.as_bytes(), &key_array, &iv1_array)?;

    Ok(SmartLocked {
        key_answer_index,
        key_question,
        encrypted_answer0,
        encrypted_answers,
        salt,
        iv_answer0,
        iv_answers,
        armed_at: Instant::now(),
    })
}

/// Recover the answers from a Smart Lock bundle (2M-iteration PBKDF2).
/// Returns the decrypted `answer0` and the remaining answers.
///
/// **Worker-thread only.** A wrong answer is not reported as such — it simply
/// fails to decrypt, exactly like the layered unlock.
pub fn recover(
    data: &SmartLocked,
    answer: &str,
    translit: bool,
) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    let normalized_answer = Zeroizing::new(normalize_answer(answer, translit));
    let salt_b64 = encode_base64(&data.salt);
    let hashed_answer = Zeroizing::new(sha256(&normalized_answer, &salt_b64));
    // Derive the key into a self-zeroizing array (a plain `try_into` would
    // free the PBKDF2 `Vec` without wiping it).
    let key = Zeroizing::new(calc_pbkdf2(
        &hashed_answer,
        &data.salt,
        SMART_LOCK_ITERATIONS,
    )?);
    if key.len() != 32 {
        return Err("Invalid key length".into());
    }
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key);
    let iv0_array: [u8; 16] = data
        .iv_answer0
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid IV length")?;
    let iv1_array: [u8; 16] = data
        .iv_answers
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid IV length")?;

    // Decrypted answer0 (returned to the caller, which wipes it on lock).
    let answer0_bytes = decrypt_with_aes(&data.encrypted_answer0, &key_array, &iv0_array)?;
    let answer0 = String::from_utf8(answer0_bytes)?;

    let answers_bytes = decrypt_with_aes(&data.encrypted_answers, &key_array, &iv1_array)?;
    // `from_utf8` reuses the decrypted buffer (no copy); wipe the plaintext
    // JSON on drop.
    let answers_json = Zeroizing::new(String::from_utf8(answers_bytes)?);
    let answers: Vec<String> = serde_json::from_str(&answers_json)?;

    Ok((answer0, answers))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle round-trips under the answer it was keyed on, and refuses
    /// every other one. Which answer that is comes out of `key_question`.
    #[test]
    fn a_bundle_reopens_under_its_own_key_answer() {
        let questions = vec!["First street?".to_string(), "First school?".to_string()];
        let answers = vec!["Baker Street".to_string(), "Hogwarts".to_string()];

        let data = create(&answers, "Rex", &questions, false).expect("the bundle should be built");

        let key_answer = &answers[data.key_answer_index - 1];
        let (answer0, recovered) =
            recover(&data, key_answer, false).expect("the key answer should recover the bundle");
        assert_eq!(answer0, "Rex");
        assert_eq!(recovered, answers);

        assert!(
            recover(&data, "not the answer", false).is_err(),
            "any other answer must fail to decrypt"
        );
    }

    /// The same normalization the vault format applies, so an answer typed with
    /// different spacing or case still opens the bundle.
    #[test]
    fn the_key_answer_is_normalized_before_it_is_hashed() {
        let questions = vec!["First street?".to_string()];
        let answers = vec!["Baker-Street".to_string()];

        let data = create(&answers, "Rex", &questions, false).expect("the bundle should be built");
        assert_eq!(data.key_answer_index, 1);
        assert_eq!(data.key_question, "First street?");

        assert!(recover(&data, "  baker street ", false).is_ok());
    }

    /// One question means no answer to key on: Smart Lock needs at least two.
    #[test]
    fn a_single_question_cannot_be_smart_locked() {
        assert!(create(&[], "Rex", &[], false).is_err());
    }
}
