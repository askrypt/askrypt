//! Real vault files, built and encrypted here.
//!
//! Every upload in the run is a genuine `AskryptFile`: the server's website
//! upload gate looks for an `askrypt.json` member inside the ZIP
//! (`vaultfile::is_vault`), the listing lifts the unencrypted `host`/`saved_at`
//! write stamp off it, and a byte-identical download only proves something if
//! the bytes were a vault to begin with. The server never sees any of the
//! contents — that is the whole point of the format — but it does see the
//! archive's shape.

use askrypt::{AskryptFile, SecretEntry};

pub const QUESTIONS: [&str; 2] = ["Favourite city?", "First pet?"];
pub const ANSWERS: [&str; 2] = ["Kyiv", "Fluffy"];

/// A low iteration count on purpose: this fixture is rebuilt several times per
/// run and none of it is protecting anything. Production vaults use 600,000.
const ITERATIONS: u32 = 6_000;

/// A vault holding one entry, whose secret is `secret` so two generations can
/// be told apart by content.
pub fn fixture(secret: &str) -> Result<AskryptFile, String> {
    padded_fixture(secret, 0)
}

/// The same, with `pad` bytes of filler in the entry's notes.
///
/// The filler is compressible but the archive stores *ciphertext*, so the file
/// really does grow by roughly `pad` — which is what makes it usable for
/// testing the body limits.
pub fn padded_fixture(secret: &str, pad: usize) -> Result<AskryptFile, String> {
    let mut notes = "written by the server_roundtrip conformance run".to_string();
    notes.push_str(&"x".repeat(pad));
    build(secret, notes)
}

fn build(secret: &str, notes: String) -> Result<AskryptFile, String> {
    AskryptFile::create(
        QUESTIONS.iter().map(|q| (*q).to_string()).collect(),
        ANSWERS.iter().map(|a| (*a).to_string()).collect(),
        vec![SecretEntry {
            name: "example".into(),
            user_name: "user".into(),
            secret: secret.into(),
            url: "https://example.com".into(),
            notes,
            entry_type: "password".into(),
            tags: vec![],
            created: 1_704_067_200,
            modified: 1_704_067_200,
            hidden: false,
            card: Default::default(),
        }],
        Some(ITERATIONS),
        false,
        None,
    )
    .map_err(|e| format!("could not build a vault fixture: {e}"))
}

pub fn fixture_bytes(secret: &str) -> Result<Vec<u8>, String> {
    to_bytes(&fixture(secret)?)
}

pub fn to_bytes(file: &AskryptFile) -> Result<Vec<u8>, String> {
    file.to_bytes()
        .map_err(|e| format!("could not serialize a vault fixture: {e}"))
}

/// Opens a vault the way a client would, and returns the one entry's secret.
/// This is the only proof that matters for a round trip: the bytes came back
/// *and* they still decrypt.
pub fn open(file: &AskryptFile) -> Result<String, String> {
    let questions = file
        .get_questions_data(ANSWERS[0].to_string())
        .map_err(|e| format!("first answer did not open the vault: {e}"))?;
    let entries = file
        .decrypt(&questions, vec![ANSWERS[1].to_string()])
        .map_err(|e| format!("remaining answers did not open the vault: {e}"))?;
    match entries.as_slice() {
        [entry] => Ok(entry.secret.clone()),
        other => Err(format!("expected 1 entry, found {}", other.len())),
    }
}

/// A ZIP archive that is not a vault: the right magic bytes, no
/// `askrypt.json`. The JSON API accepts it (its contract is the magic and
/// nothing further) and the website's upload form must not.
pub fn zip_without_manifest() -> Vec<u8> {
    // A minimal stored-entry archive holding `notes.txt`, hand-assembled so
    // this needs no writer. Fields are little-endian.
    let name = b"notes.txt";
    let data = b"not a vault";
    let crc = crc32(data);

    let mut local = Vec::new();
    local.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local file header
    local.extend_from_slice(&20u16.to_le_bytes()); // version needed
    local.extend_from_slice(&0u16.to_le_bytes()); // flags
    local.extend_from_slice(&0u16.to_le_bytes()); // stored
    local.extend_from_slice(&0u16.to_le_bytes()); // mod time
    local.extend_from_slice(&0u16.to_le_bytes()); // mod date
    local.extend_from_slice(&crc.to_le_bytes());
    local.extend_from_slice(&(data.len() as u32).to_le_bytes());
    local.extend_from_slice(&(data.len() as u32).to_le_bytes());
    local.extend_from_slice(&(name.len() as u16).to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes()); // extra length
    local.extend_from_slice(name);
    local.extend_from_slice(data);

    let mut central = Vec::new();
    central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central directory
    central.extend_from_slice(&20u16.to_le_bytes()); // version made by
    central.extend_from_slice(&20u16.to_le_bytes()); // version needed
    central.extend_from_slice(&0u16.to_le_bytes()); // flags
    central.extend_from_slice(&0u16.to_le_bytes()); // stored
    central.extend_from_slice(&0u16.to_le_bytes()); // mod time
    central.extend_from_slice(&0u16.to_le_bytes()); // mod date
    central.extend_from_slice(&crc.to_le_bytes());
    central.extend_from_slice(&(data.len() as u32).to_le_bytes());
    central.extend_from_slice(&(data.len() as u32).to_le_bytes());
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes()); // extra
    central.extend_from_slice(&0u16.to_le_bytes()); // comment
    central.extend_from_slice(&0u16.to_le_bytes()); // disk number
    central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    central.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    central.extend_from_slice(name);

    let mut end = Vec::new();
    end.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // end of central directory
    end.extend_from_slice(&0u16.to_le_bytes()); // disk number
    end.extend_from_slice(&0u16.to_le_bytes()); // disk with central directory
    end.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    end.extend_from_slice(&1u16.to_le_bytes()); // entries total
    end.extend_from_slice(&(central.len() as u32).to_le_bytes());
    end.extend_from_slice(&(local.len() as u32).to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes()); // comment length

    let mut zip = local;
    zip.extend_from_slice(&central);
    zip.extend_from_slice(&end);
    zip
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
