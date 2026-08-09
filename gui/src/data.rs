//! Item helpers over [`SecretEntry`], the vault's own entry type.
//!
//! Ported from `src/screens/entries.rs`, which keeps these as private functions
//! next to the view that uses them. They are pure, so they live on their own
//! here and the panes share them.

use askrypt::SecretEntry;
use chrono::{DateTime, Local, Utc};

/// The entry types the editor offers. `SecretEntry::entry_type` is a free-form
/// string in the format, so this is a convenience, not a constraint — a vault
/// written elsewhere may carry any type and the rail will still list it.
pub const ENTRY_TYPES: [&str; 3] = [TYPE_LOGIN, TYPE_CARD, TYPE_NOTE];
pub const TYPE_LOGIN: &str = "Login";
pub const TYPE_CARD: &str = "Card";
pub const TYPE_NOTE: &str = "Note";

/// A blank entry, stamped with the current time.
pub fn new_entry() -> SecretEntry {
    let now = Utc::now().timestamp();
    SecretEntry {
        name: String::new(),
        user_name: String::new(),
        secret: String::new(),
        url: String::new(),
        notes: String::new(),
        entry_type: TYPE_LOGIN.to_string(),
        tags: Vec::new(),
        created: now,
        modified: now,
        hidden: false,
    }
}

pub fn entry_matches_filter(entry: &SecretEntry, filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    // Tags are displayed with a leading `#` but stored without one, so a query
    // copied off the screen has to match too.
    let tag_filter = clean_hash_tag(&filter_lower);

    entry.name.to_lowercase().contains(&filter_lower)
        || entry.user_name.to_lowercase().contains(&filter_lower)
        || entry.url.to_lowercase().contains(&filter_lower)
        || entry.notes.to_lowercase().contains(&filter_lower)
        || entry
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&tag_filter))
}

pub fn is_url(string: &str) -> bool {
    string.starts_with("http://") || string.starts_with("https://")
}

pub fn make_hash_tag(tag: &str) -> String {
    if tag.starts_with('#') {
        tag.to_string()
    } else {
        format!("#{}", tag)
    }
}

pub fn clean_hash_tag(tag: &str) -> String {
    tag.strip_prefix('#').unwrap_or(tag).to_string()
}

pub fn format_timestamp_local(timestamp: i64) -> String {
    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
    let local_datetime = datetime.with_timezone(&Local);
    local_datetime.format("%b. %d, %Y - %T").to_string()
}

/// The vault's unencrypted write stamp, rendered for a locked screen.
///
/// `params.host` and `params.updated_at` are the two fields the format leaves in
/// the clear, so this is readable before a single answer is given. Either half
/// may be missing; both missing means no stamp at all.
pub fn format_stamp(host: Option<&str>, updated_at: Option<&str>) -> Option<String> {
    let when = updated_at.map(format_stamp_time);
    match (host, when) {
        (Some(host), Some(when)) => Some(format!("{} · {}", host, when)),
        (Some(host), None) => Some(host.to_string()),
        (None, Some(when)) => Some(when),
        (None, None) => None,
    }
}

/// RFC 3339 UTC → local `YYYY-MM-DD HH:MM`, verbatim if it will not parse.
fn format_stamp_time(raw: &str) -> String {
    DateTime::parse_from_rfc3339(raw)
        .map(|parsed| {
            parsed
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> SecretEntry {
        SecretEntry {
            name: name.to_string(),
            user_name: "testingaccount".to_string(),
            secret: "hunter2".to_string(),
            url: "https://example.com".to_string(),
            notes: "some notes".to_string(),
            entry_type: TYPE_LOGIN.to_string(),
            tags: vec!["work".to_string()],
            created: 0,
            modified: 0,
            hidden: false,
        }
    }

    #[test]
    fn the_filter_searches_every_visible_field_but_not_the_secret() {
        let entry = entry("GitHub");

        assert!(entry_matches_filter(&entry, "git"));
        assert!(entry_matches_filter(&entry, "TESTINGACCOUNT"));
        assert!(entry_matches_filter(&entry, "example.com"));
        assert!(entry_matches_filter(&entry, "notes"));
        assert!(entry_matches_filter(&entry, "work"));
        // Tags read `#work` on screen but are stored bare.
        assert!(entry_matches_filter(&entry, "#work"));
        // The password itself is deliberately not searchable.
        assert!(!entry_matches_filter(&entry, "hunter2"));
    }

    #[test]
    fn hash_tags_round_trip() {
        assert_eq!(make_hash_tag("work"), "#work");
        assert_eq!(make_hash_tag("#work"), "#work");
        assert_eq!(clean_hash_tag("#work"), "work");
        assert_eq!(clean_hash_tag("work"), "work");
    }

    #[test]
    fn a_stamp_drops_the_half_it_does_not_have() {
        assert_eq!(
            format_stamp(Some("thinkpad"), None),
            Some("thinkpad".to_string())
        );
        assert_eq!(format_stamp(None, None), None);
        assert!(
            format_stamp(Some("thinkpad"), Some("2026-08-09T10:11:12Z"))
                .is_some_and(|stamp| stamp.starts_with("thinkpad · "))
        );
    }

    #[test]
    fn an_unparseable_stamp_time_is_shown_verbatim() {
        assert_eq!(
            format_stamp(None, Some("whenever")),
            Some("whenever".into())
        );
    }
}
