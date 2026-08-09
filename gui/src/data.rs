//! Hard-coded sample data for the prototype.
//!
//! [`Entry`] mirrors `askrypt::SecretEntry`'s field names so porting this
//! layout back into `src/` is mechanical — but it is a plain struct with no
//! `zeroize` and no `serde`: none of this is real, and deriving `ZeroizeOnDrop`
//! here would falsely imply the prototype has a security posture.

use chrono::{DateTime, Local, Utc};

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub user_name: String,
    pub secret: String,
    pub url: String,
    pub notes: String,
    pub entry_type: String,
    pub tags: Vec<String>,
    /// Unused by the prototype; kept so the field list mirrors `SecretEntry`.
    #[allow(dead_code)]
    pub created: i64,
    pub modified: i64,
    pub hidden: bool,
}

/// Entry types the sidebar groups by.
pub const TYPE_LOGIN: &str = "Login";
pub const TYPE_CARD: &str = "Card";
pub const TYPE_NOTE: &str = "Note";

#[allow(clippy::too_many_arguments)]
fn entry(
    name: &str,
    user_name: &str,
    secret: &str,
    url: &str,
    notes: &str,
    entry_type: &str,
    tags: &[&str],
    modified: i64,
    hidden: bool,
) -> Entry {
    Entry {
        name: name.to_string(),
        user_name: user_name.to_string(),
        secret: secret.to_string(),
        url: url.to_string(),
        notes: notes.to_string(),
        entry_type: entry_type.to_string(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        created: modified - 86_400 * 30,
        modified,
        hidden,
    }
}

/// A dozen fake entries mirroring `uisample.jpg`.
///
/// `modified` values are fixed literals so the "Updated:" line is stable
/// across runs, and distinct so the newest-first sort visibly reorders them.
/// One entry has an empty `url` and one an empty `user_name` to exercise the
/// empty-field paths; one is `hidden` so the Hidden section is non-empty.
pub fn sample_entries() -> Vec<Entry> {
    vec![
        entry(
            "Amazon",
            "testingaccount",
            "hunter2-amazon",
            "https://amazon.com",
            "Prime renews in March.",
            TYPE_LOGIN,
            &["shopping"],
            1_581_428_873,
            false,
        ),
        entry(
            "Apple",
            "testingaccount",
            "correct-horse-battery",
            "https://appleid.apple.com",
            "",
            TYPE_LOGIN,
            &["personal"],
            1_581_515_273,
            false,
        ),
        entry(
            "Bestbuy",
            "testingaccount",
            "s3cr3t-bestbuy",
            "https://bestbuy.com",
            "Store pickup only.",
            TYPE_LOGIN,
            &["shopping"],
            1_581_601_673,
            false,
        ),
        entry(
            "Dropbox",
            "testingaccount",
            "dr0pb0x-pass",
            "https://dropbox.com",
            "",
            TYPE_LOGIN,
            &["work"],
            1_581_688_073,
            false,
        ),
        entry(
            "Facebook",
            "testingaccount",
            "fb-pass-9182",
            "https://facebook.com",
            "",
            TYPE_LOGIN,
            &["personal"],
            1_581_774_473,
            false,
        ),
        entry(
            "Google",
            "testingaccount",
            "g00gle-pass",
            "https://accounts.google.com",
            "Recovery phone ends 4471.",
            TYPE_LOGIN,
            &["work", "personal"],
            1_581_860_873,
            false,
        ),
        entry(
            "Netflix",
            "testingaccount",
            "netflix-and-chill",
            "https://netflix.com",
            "Shared with family.",
            TYPE_LOGIN,
            &["personal"],
            1_581_947_273,
            false,
        ),
        entry(
            "Strava",
            "testingaccount",
            "strava-pass-11",
            "https://strava.com",
            "",
            TYPE_LOGIN,
            &["personal"],
            1_582_033_673,
            false,
        ),
        entry(
            "Target",
            "testingaccount",
            "t4rget-pass",
            "https://target.com",
            "",
            TYPE_LOGIN,
            &["shopping"],
            1_582_120_073,
            false,
        ),
        // No username: exercises the empty-field path in the detail pane.
        entry(
            "Visa •••• 4242",
            "",
            "4242 4242 4242 4242",
            "https://mybank.example.com",
            "Expires 09/29, CVV in the note above.",
            TYPE_CARD,
            &["finance"],
            1_582_206_473,
            false,
        ),
        // No URL: the Website card should drop out entirely.
        entry(
            "Recovery codes",
            "",
            "8fj2-19dk-22as-9wke",
            "",
            "Backup codes for the work account. Use once, then regenerate.",
            TYPE_NOTE,
            &["work"],
            1_582_292_873,
            false,
        ),
        entry(
            "Old bank login",
            "r.absaliamov",
            "retired-pass-2019",
            "https://oldbank.example.com",
            "Account closed, kept for the statements.",
            TYPE_LOGIN,
            &["finance"],
            1_582_379_273,
            true,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Vault lifecycle sample data
// ---------------------------------------------------------------------------

/// The security questions the unlock pane asks.
///
/// In the real vault the first one is stored in the clear and the rest only
/// appear once the first answer decrypts them — which is why the unlock pane
/// shows question 0 alone before it shows these.
pub fn sample_questions() -> &'static [&'static str] {
    &[
        "What was the name of your first pet?",
        "What street did you grow up on?",
        "What was your first employer called?",
    ]
}

/// Fake recent files for the Open wizard: (display name, folder).
pub fn sample_recent_files() -> &'static [(&'static str, &'static str)] {
    &[
        ("MyVault.askrypt", "~/vaults"),
        ("Work.askrypt", "~/Documents/askrypt"),
        ("Archive-2024.askrypt", "/media/backup/vaults"),
    ]
}

/// Fake account vaults for the server step: (name, last saved).
pub fn sample_server_vaults() -> &'static [(&'static str, &'static str)] {
    &[
        ("MyVault", "saved from thinkpad · 2 hours ago"),
        ("Work", "saved from desktop · yesterday"),
        ("Shared", "saved from phone · last week"),
    ]
}

/// The server the wizard prefills, matching `ServerSession`'s remembered
/// sign-in in the shipping app.
pub const SAMPLE_SERVER_URL: &str = "https://askrypt.example.com";
pub const SAMPLE_SERVER_EMAIL: &str = "me@example.com";

// ---------------------------------------------------------------------------
// Helpers copied from `src/screens/entries.rs`
// ---------------------------------------------------------------------------

pub fn entry_matches_filter(entry: &Entry, filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    entry.name.to_lowercase().contains(&filter_lower)
        || entry.user_name.to_lowercase().contains(&filter_lower)
        || entry.url.to_lowercase().contains(&filter_lower)
        || entry.notes.to_lowercase().contains(&filter_lower)
        || entry
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&filter_lower))
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

pub fn format_timestamp_local(timestamp: i64) -> String {
    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
    let local_datetime = datetime.with_timezone(&Local);
    local_datetime.format("%b. %d, %Y - %T").to_string()
}
