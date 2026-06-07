//! Golden cross-implementation test-vector generator (mobile PLAN Phase 1).
//!
//! Emits `app/test/fixtures/vectors.json`: deterministic vectors for every
//! pure stage of the vault crypto (normalize, transliterate, sha256, pbkdf2,
//! aes-256-cbc) plus a full known-good `vault.askrypt` (base64) that the Dart
//! port must be able to open. The Dart parity suite asserts byte/value equality
//! against this file so the two implementations cannot silently diverge.
//!
//! Run: `cargo run -p askrypt-core --example gen_vectors`

use askrypt::types::SecretEntry;
use askrypt::{
    AskryptFile, calc_pbkdf2, encode_base64, encrypt_with_aes, normalize_answer, sha256,
    translit::transliterate,
};
use serde_json::json;

fn pbkdf2_case(secret: &str, salt: &[u8], iterations: u32) -> serde_json::Value {
    let key = calc_pbkdf2(secret, salt, iterations).unwrap();
    json!({
        "secret": secret,
        "salt_b64": encode_base64(salt),
        "iterations": iterations,
        "key_hex": hex::encode(key),
    })
}

fn aes_case(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> serde_json::Value {
    let ct = encrypt_with_aes(plaintext, key, iv).unwrap();
    json!({
        "plaintext_b64": encode_base64(plaintext),
        "key_b64": encode_base64(key),
        "iv_b64": encode_base64(iv),
        "ciphertext_b64": encode_base64(&ct),
    })
}

fn main() {
    // --- normalization (with and without transliteration) ---
    let normalize: Vec<_> = [
        ("Hello World", false),
        ("  Smith-Jones  ", false),
        ("New\tYork", false),
        ("Café—Bar", false),
        ("Москва", true),
        ("Пётр Чайковский", true),
        ("Київ", true),
        ("Объект ь", true),
    ]
    .iter()
    .map(|(input, translit)| {
        json!({
            "input": input,
            "translit": translit,
            "expected": normalize_answer(input, *translit),
        })
    })
    .collect();

    // --- raw transliteration (already-lowercased input, as normalize feeds it) ---
    let translit: Vec<_> = [
        "москва",
        "россия",
        "пётр",
        "щука",
        "абвгдежзийклмнопрстуфхцчшщъыьэюя",
        "україна",
        "їжак",
        "hello мир!",
    ]
    .iter()
    .map(|s| json!({ "input": s, "expected": transliterate(s) }))
    .collect();

    // --- sha256(data + salt) as lowercase hex ---
    let sha256_cases: Vec<_> = [
        ("Hello World", "salt42"),
        ("helloworld", "c2FsdDA="),
        ("", ""),
        ("пароль", "YmFzZTY0c2FsdA=="),
    ]
    .iter()
    .map(|(data, salt)| {
        json!({ "data": data, "salt": salt, "expected_hex": sha256(data, salt) })
    })
    .collect();

    // --- pbkdf2-hmac-sha256 (secret is an ASCII string; salt is raw bytes) ---
    let salt16: Vec<u8> = (0u8..16).collect();
    let pbkdf2_cases = json!([
        pbkdf2_case("password", &salt16, 1),
        pbkdf2_case("password", &salt16, 1000),
        pbkdf2_case(&sha256("helloworld", "c2FsdDA="), &salt16, 2048),
        // one realistic count to confirm parity at production cost (kept single):
        pbkdf2_case("answer", &salt16, 600_000),
    ]);

    // --- aes-256-cbc + pkcs7 (deterministic given fixed key/iv) ---
    let key32: [u8; 32] = core::array::from_fn(|i| i as u8);
    let iv16: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0xAA);
    let aes_cases = json!([
        aes_case(b"", &key32, &iv16),
        aes_case(b"hello", &key32, &iv16),
        aes_case(b"exactly16bytes!!", &key32, &iv16), // full block -> extra pad block
        aes_case("unicode: пароль".as_bytes(), &key32, &iv16),
    ]);

    // --- full known-good vault (Dart must open this) ---
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
    let entries = vec![
        SecretEntry {
            name: "Example".to_string(),
            user_name: "user5".to_string(),
            secret: "p@ssw0rd123".to_string(),
            url: "https://example.com".to_string(),
            notes: "primary account".to_string(),
            entry_type: "password".to_string(),
            tags: vec!["email".to_string(), "work".to_string()],
            created: 1_704_067_200,
            modified: 1_704_153_600,
            hidden: false,
        },
        SecretEntry {
            name: "Secret note".to_string(),
            user_name: String::new(),
            secret: "hidden secret \u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}".to_string(),
            url: String::new(),
            notes: "multi\nline\nnotes".to_string(),
            entry_type: "note".to_string(),
            tags: vec![],
            created: 1_704_067_200,
            modified: 1_704_067_200,
            hidden: true,
        },
    ];
    let iterations = 1000u32; // keep tests fast; production default is 600_000
    let file = AskryptFile::create(
        questions.clone(),
        answers.clone(),
        entries.clone(),
        Some(iterations),
        false,
    )
    .unwrap();
    let vault_bytes = file.to_bytes().unwrap();

    let vault = json!({
        "questions": questions,
        "answers": answers,
        "iterations": iterations,
        "translit": false,
        "expected_entries": serde_json::to_value(&entries).unwrap(),
        "vault_b64": encode_base64(&vault_bytes),
    });

    let out = json!({
        "_comment": "Generated by `cargo run -p askrypt-core --example gen_vectors`. \
                     Do not edit by hand. Source of truth for Dart crypto parity.",
        "format_version": "0.9",
        "normalize": normalize,
        "transliterate": translit,
        "sha256": sha256_cases,
        "pbkdf2": pbkdf2_cases,
        "aes_cbc_pkcs7": aes_cases,
        "vault": vault,
    });

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../app/test/fixtures/vectors.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    println!("wrote {path}");
}
