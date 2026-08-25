//! Golden cross-implementation test-vector generator (mobile PLAN Phase 1).
//!
//! Emits `app/test/fixtures/vectors.json`: deterministic vectors for every
//! pure stage of the vault crypto (normalize, transliterate, sha256, pbkdf2,
//! aes-256-cbc) plus a full known-good `vault.askrypt` (base64) that the Dart
//! port must be able to open. The Dart parity suite asserts byte/value equality
//! against this file so the two implementations cannot silently diverge.
//!
//! Run: `cargo run -p askrypt-core --example gen_vectors`

use askrypt::types::{Attachment, Attachments, CardFields, MasterSecret, SecretEntry};
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

/// The `files/<id>` member the fixture vault carries, and its contents. Both
/// are fixed so the fixture is byte-stable across runs.
const ATTACHMENT_ID: &str = "0123456789abcdef0123456789abcdef";
const ATTACHMENT_PLAINTEXT: &str = "scanned passport, page 1";

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
    .map(|(data, salt)| json!({ "data": data, "salt": salt, "expected_hex": sha256(data, salt) }))
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
    // The attachment the `File` entry below carries. Everything about it is
    // pinned rather than drawn: a fixture that changed on every run would prove
    // nothing about a port.
    let master = MasterSecret::from_slice(&[42u8; 32]).unwrap();
    let attachment_iv = [7u8; 16];
    // The blob reaches the archive the way every freshly attached file does:
    // as a *sealed file*, since nothing holds an attachment's bytes any more.
    // The ciphertext is still pinned — same plaintext, key and IV — so the
    // emitted vault stays byte-identical to the one earlier builds produced.
    let sealed = std::env::temp_dir().join(format!("askrypt-vector-blob-{}", std::process::id()));
    std::fs::write(
        &sealed,
        encrypt_with_aes(
            ATTACHMENT_PLAINTEXT.as_bytes(),
            master.as_bytes(),
            &attachment_iv,
        )
        .unwrap(),
    )
    .unwrap();
    let mut attachments = Attachments::new();
    attachments.insert_sealed(ATTACHMENT_ID.to_string(), sealed.clone());

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
            attachments: Vec::new(),
            card: Default::default(),
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
            attachments: Vec::new(),
            card: Default::default(),
        },
        // A card, so the Dart port is pinned to carrying the six `card_*` keys.
        // Without a vector holding them, a Dart model that silently dropped
        // them would still pass every parity test.
        SecretEntry {
            name: "Personal Visa".to_string(),
            user_name: String::new(),
            secret: String::new(),
            url: String::new(),
            notes: String::new(),
            entry_type: "Card".to_string(),
            tags: vec!["finance".to_string()],
            created: 1_704_067_200,
            modified: 1_704_153_600,
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
        },
        // A `File` entry carrying an attachment, so both ports are pinned to
        // carrying the `attachments` key *and* the `files/` ZIP member. Without
        // one, a port that dropped either — deleting every attached file in the
        // vault on its next save — would still pass every parity test. This is
        // the same trap the card entry above exists to close.
        SecretEntry {
            name: "Passport".to_string(),
            user_name: String::new(),
            secret: String::new(),
            url: String::new(),
            notes: "Scanned before the trip".to_string(),
            entry_type: "File".to_string(),
            tags: vec!["travel".to_string()],
            created: 1_704_067_200,
            modified: 1_704_153_600,
            hidden: false,
            attachments: vec![Attachment {
                id: ATTACHMENT_ID.to_string(),
                name: "passport.txt".to_string(),
                size: ATTACHMENT_PLAINTEXT.len() as u64,
                added: 1_704_153_600,
                // Pinned rather than drawn, like everything else in a fixture.
                iv: encode_base64(&[7u8; 16]),
            }],
            card: Default::default(),
        },
    ];
    let iterations = 1000u32; // keep tests fast; production default is 600_000
    let mut file = AskryptFile::create(
        questions.clone(),
        answers.clone(),
        entries.clone(),
        Some(iterations),
        false,
        // Minted here rather than left to `create`, because the attachment
        // below has to be encrypted under the very key the vault carries.
        Some(&master),
        &attachments,
    )
    .unwrap();
    // `create` stamps params.host/params.updated_at with this machine and the
    // current time; pin them so the fixture stays deterministic (and doesn't
    // bake the generating machine's host name into the repo).
    let host = "vector-host";
    let updated_at = "2026-01-02T03:04:05Z";
    file.params.host = Some(host.to_string());
    file.params.updated_at = Some(updated_at.to_string());
    let vault_bytes = file.to_bytes().unwrap();
    // The sealed blob has been folded into the archive; nothing needs it now.
    std::fs::remove_file(&sealed).ok();

    let vault = json!({
        "questions": questions,
        // The attachment's plaintext, so a port can prove it decrypted the
        // `files/` member rather than merely carried it.
        "expected_attachment_id": ATTACHMENT_ID,
        "expected_attachment_plaintext": ATTACHMENT_PLAINTEXT,
        "answers": answers,
        "iterations": iterations,
        "translit": false,
        "expected_host": host,
        "expected_updated_at": updated_at,
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

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../app/test/fixtures/vectors.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    println!("wrote {path}");
}
