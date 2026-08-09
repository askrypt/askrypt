//! The one look the server takes inside a vault file.
//!
//! Vault bytes are opaque here — that is the whole point of the store — but
//! the format keeps two fields *outside* the encryption: `params.host` and
//! `params.updated_at`, the name of the machine that last wrote the file and
//! when. Those two answer "where and when was this saved?", which is exactly
//! what a listing of several devices' saves needs, so they are read once on
//! upload and kept in the metadata.
//!
//! This is a reader and only a reader, written here rather than borrowed
//! from `askrypt-core`: the scope rule ([`crate`] docs) says the server never
//! links the crypto core, and reading two strings does not need it. It knows
//! about one entry in the archive and two fields in it; everything else in
//! the file — the salts, the encrypted questions, the master key, the data —
//! is none of its business and is not deserialized.
//!
//! Nothing in here can fail loudly. A file that is not a ZIP, has no
//! `askrypt.json`, or was written by a version predating the stamp simply has
//! no stamp, and a save is never refused over it.

use std::io::{Cursor, Read};

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// What a vault file records about its own last write. Both halves are
/// independently optional: older files carry neither, and a file whose
/// timestamp does not parse can still name its host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultStamp {
    /// Host name of the machine that wrote the file.
    pub host: Option<String>,
    /// When it was written, as the *file* records it — unrelated to when the
    /// server received it.
    pub saved_at: Option<DateTime<Utc>>,
}

impl VaultStamp {
    pub fn is_empty(&self) -> bool {
        self.host.is_none() && self.saved_at.is_none()
    }
}

/// The archive member holding the vault's JSON.
const ENTRY: &str = "askrypt.json";
/// Cap on the JSON read out of the archive. Real vaults are tens of KB in
/// total; this bounds what a crafted archive can make the server decompress
/// (the entry is streamed through `take`, so the limit applies to the
/// *inflated* bytes, not the stored ones).
const MAX_JSON_BYTES: u64 = 1024 * 1024;
/// Host names are at most 253 characters; anything longer is not a host name
/// and has no business in a table cell.
const MAX_HOST_CHARS: usize = 128;

/// The sliver of the vault JSON this module cares about. Unknown fields —
/// which is to say all the rest of the format — are ignored by serde, so
/// this struct does not have to track the format as it grows.
#[derive(Deserialize)]
struct StampedFile {
    #[serde(default)]
    params: StampParams,
}

#[derive(Deserialize, Default)]
struct StampParams {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

/// Reads the write stamp out of vault bytes, or an empty stamp if there is
/// none to read.
pub fn read_stamp(bytes: &[u8]) -> VaultStamp {
    stamp(bytes).unwrap_or_default()
}

/// The fallible half of [`read_stamp`]: every `None` here means "this file
/// does not tell us", never "the upload is bad".
fn stamp(bytes: &[u8]) -> Option<VaultStamp> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let entry = archive.by_name(ENTRY).ok()?;
    let mut json = String::new();
    entry.take(MAX_JSON_BYTES).read_to_string(&mut json).ok()?;
    let params = serde_json::from_str::<StampedFile>(&json).ok()?.params;
    Some(VaultStamp {
        host: clean_host(params.host.as_deref()),
        saved_at: parse_time(params.updated_at.as_deref()),
    })
}

/// A host name written by another machine is untrusted text on its way to a
/// table cell and a log line: control characters go, and the length is
/// capped. HTML escaping is the template engine's job and it does it.
fn clean_host(raw: Option<&str>) -> Option<String> {
    let cleaned: String = raw?
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_HOST_CHARS)
        .collect();
    let cleaned = cleaned.trim_end().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The format writes RFC 3339 UTC with second precision; anything else is
/// treated as no timestamp at all rather than guessed at.
fn parse_time(raw: Option<&str>) -> Option<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(raw?.trim()).ok()?;
    Some(parsed.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    use super::*;

    /// Builds a vault-shaped archive: one `askrypt.json` member holding the
    /// given text, deflated exactly as the apps write it.
    fn archive_with(entry: &str, contents: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
            zip.start_file(entry, SimpleFileOptions::default()).unwrap();
            zip.write_all(contents.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        buf
    }

    /// A vault file as `askrypt-core` writes one, trimmed to the fields this
    /// reader looks at plus enough of the rest to prove they are skipped.
    fn vault_json(stamp: &str) -> String {
        format!(
            r#"{{"version":"1","question0":"aGFzaA==","params":{{"kdf":"pbkdf2-sha256",
            "iterations":600000,"salt":"c2FsdA==","translit":false{stamp}}},
            "qs":"encrypted","master":"encrypted","data":"encrypted"}}"#
        )
    }

    #[test]
    fn a_stamped_vault_reports_where_and_when_it_was_saved() {
        let bytes = archive_with(
            ENTRY,
            &vault_json(r#","host":"lenovo-x1","updated_at":"2026-08-08T10:15:30Z""#),
        );
        let stamp = read_stamp(&bytes);
        assert_eq!(stamp.host.as_deref(), Some("lenovo-x1"));
        assert_eq!(
            stamp.saved_at.map(|at| at.to_rfc3339()),
            Some("2026-08-08T10:15:30+00:00".to_string())
        );
    }

    #[test]
    fn an_offset_timestamp_is_normalized_to_utc() {
        let bytes = archive_with(
            ENTRY,
            &vault_json(r#","updated_at":"2026-08-08T12:15:30+02:00""#),
        );
        assert_eq!(
            read_stamp(&bytes).saved_at.map(|at| at.to_rfc3339()),
            Some("2026-08-08T10:15:30+00:00".to_string())
        );
    }

    #[test]
    fn the_two_halves_are_independent() {
        let host_only = archive_with(ENTRY, &vault_json(r#","host":"desktop""#));
        assert_eq!(read_stamp(&host_only).host.as_deref(), Some("desktop"));
        assert!(read_stamp(&host_only).saved_at.is_none());

        // A timestamp the format would never write does not take the host
        // down with it.
        let bad_time = archive_with(
            ENTRY,
            &vault_json(r#","host":"desktop","updated_at":"last tuesday""#),
        );
        assert_eq!(read_stamp(&bad_time).host.as_deref(), Some("desktop"));
        assert!(read_stamp(&bad_time).saved_at.is_none());
    }

    #[test]
    fn files_without_a_stamp_are_ordinary_not_broken() {
        // A vault written before the stamp existed.
        assert!(read_stamp(&archive_with(ENTRY, &vault_json(""))).is_empty());
        // A ZIP that is not a vault.
        assert!(read_stamp(&archive_with("notes.txt", "hello")).is_empty());
        // The JSON member is not JSON.
        assert!(read_stamp(&archive_with(ENTRY, "not json at all")).is_empty());
        // Not an archive at all — what the API's magic check lets through
        // and every other test in the suite uploads.
        assert!(read_stamp(b"PK\x03\x04 pretend vault").is_empty());
        assert!(read_stamp(b"").is_empty());
    }

    #[test]
    fn a_hostile_host_name_is_trimmed_capped_and_stripped() {
        assert_eq!(clean_host(Some("  box  ")).as_deref(), Some("box"));
        assert_eq!(clean_host(Some("bo\nx\u{7}")).as_deref(), Some("box"));
        assert_eq!(clean_host(Some("   ")), None);
        assert_eq!(clean_host(None), None);
        let long = clean_host(Some(&"h".repeat(500))).unwrap();
        assert_eq!(long.chars().count(), MAX_HOST_CHARS);
        // Multi-byte characters are counted, not sliced through.
        let cyrillic = clean_host(Some(&"я".repeat(500))).unwrap();
        assert_eq!(cyrillic.chars().count(), MAX_HOST_CHARS);
    }

    #[test]
    fn a_huge_json_member_is_not_read_past_the_cap() {
        // Compresses to almost nothing, inflates to far more than the cap:
        // the reader must give up rather than buffer it.
        let padded = format!(
            r#"{{"params":{{"host":"box"}},"pad":"{}"}}"#,
            "a".repeat(MAX_JSON_BYTES as usize + 1)
        );
        let bytes = archive_with(ENTRY, &padded);
        assert!(bytes.len() < 64 * 1024, "fixture should be a small archive");
        assert!(read_stamp(&bytes).is_empty());
    }
}
