//! Item helpers over [`SecretEntry`], the vault's own entry type.
//!
//! These were private functions next to the view that used them in the UI this
//! replaced. They are pure, so they live on their own here and the panes share
//! them.

use askrypt::SecretEntry;
use chrono::{DateTime, Local, Utc};

/// The entry types the editor offers. `SecretEntry::entry_type` is a free-form
/// string in the format, so this is a convenience, not a constraint — a vault
/// written elsewhere may carry any type and the rail will still list it.
pub const ENTRY_TYPES: [&str; 3] = [TYPE_LOGIN, TYPE_CARD, TYPE_NOTE];
pub const TYPE_LOGIN: &str = "Login";
pub const TYPE_CARD: &str = "Card";
pub const TYPE_NOTE: &str = "Note";

/// The card networks the editor offers. Like [`ENTRY_TYPES`], a convenience
/// rather than a constraint: `card_brand` is a free string in the format, and a
/// brand written by another client still displays, because `pick_list` renders
/// whatever selection it is handed.
pub const CARD_BRANDS: [&str; 8] = [
    "Visa",
    "Mastercard",
    "American Express",
    "Discover",
    "Maestro",
    "Mir",
    "JCB",
    "UnionPay",
];

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
        card: Default::default(),
    }
}

/// Whether an entry should be drawn with the card fields rather than the login
/// ones.
///
/// Compared case-insensitively on purpose: the three clients already disagree
/// about the spelling of a type — `src/` writes `"password"`, the mobile app
/// `"login"`, this crate `"Login"` — so a `"card"` from anywhere must read as
/// one here.
pub fn is_card(entry: &SecretEntry) -> bool {
    entry.entry_type.eq_ignore_ascii_case(TYPE_CARD)
}

/// The search over an entry's *visible* fields.
///
/// The card number, CVV and PIN are left out for the same reason `secret` is:
/// typing a secret into a search box and watching a row appear confirms the
/// secret. The cardholder and the brand are on screen anyway, so they match.
pub fn entry_matches_filter(entry: &SecretEntry, filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    // Tags are displayed with a leading `#` but stored without one, so a query
    // copied off the screen has to match too.
    let tag_filter = clean_hash_tag(&filter_lower);

    entry.name.to_lowercase().contains(&filter_lower)
        || entry.user_name.to_lowercase().contains(&filter_lower)
        || entry.url.to_lowercase().contains(&filter_lower)
        || entry.notes.to_lowercase().contains(&filter_lower)
        || entry.card.holder.to_lowercase().contains(&filter_lower)
        || entry.card.brand.to_lowercase().contains(&filter_lower)
        || entry
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&tag_filter))
}

// ---------------------------------------------------------------------------
// Card rendering
// ---------------------------------------------------------------------------

/// The dot the masked renderings are built from.
const CARD_DOT: &str = "•";

/// The digits of a card number, with the spaces (or anything else) taken out.
///
/// The format stores the number as typed, so this is what a copy hands to the
/// clipboard and what every rendering below counts.
pub fn card_digits(number: &str) -> String {
    number.chars().filter(char::is_ascii_digit).collect()
}

/// The last four digits, when there are at least four.
pub fn card_last4(number: &str) -> Option<String> {
    let digits = card_digits(number);
    (digits.len() >= 4).then(|| digits[digits.len() - 4..].to_string())
}

/// A card number with everything but the last four digits dotted:
/// `•••• •••• •••• 4242`. A number too short to have a last four is dotted
/// whole, so a half-typed one never shows through.
pub fn mask_card_number(number: &str) -> String {
    let digits = card_digits(number);
    if digits.is_empty() {
        return String::new();
    }

    let masked = match card_last4(number) {
        Some(last4) => format!("{}{}", CARD_DOT.repeat(digits.len() - 4), last4),
        None => CARD_DOT.repeat(digits.len()),
    };

    group_in_fours(&masked)
}

/// A card number in groups of four, the way it is printed on the card.
pub fn group_card_number(number: &str) -> String {
    group_in_fours(&card_digits(number))
}

/// Groups from the **right**, so the trailing group is always the four digits
/// that are worth reading. A 16-digit number splits 4-4-4-4 either way, but a
/// 15-digit Amex splits 3-4-4-4 rather than leaving `0005` broken across two
/// groups.
fn group_in_fours(value: &str) -> String {
    let length = value.chars().count();
    value
        .chars()
        .enumerate()
        .flat_map(|(index, character)| {
            let space = (index > 0 && (length - index).is_multiple_of(4)).then_some(' ');
            space.into_iter().chain(std::iter::once(character))
        })
        .collect()
}

/// The second line of a card's row in the item list — `Visa •••• 4242`.
///
/// A card leaves `user_name` empty, which is what the list draws for every
/// other entry, so without this a card row has a blank second line. Falls back
/// through what the entry actually has.
pub fn card_subtitle(entry: &SecretEntry) -> String {
    let last4 =
        card_last4(&entry.card.number).map(|last4| format!("{}{}", CARD_DOT.repeat(4), last4));

    match (entry.card.brand.trim(), last4) {
        ("", Some(last4)) => last4,
        (brand, Some(last4)) => format!("{} {}", brand, last4),
        ("", None) => entry.card.holder.clone(),
        (brand, None) => brand.to_string(),
    }
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

/// The one datetime format the UI uses, everywhere it shows a date and time:
/// local time zone, `Aug 9, 2026 14:32`. Every rendering path below goes
/// through it, so entry stamps, the vault write stamp and the server vault
/// listing all read the same.
pub const DATETIME_FORMAT: &str = "%b %-d, %Y %H:%M";

/// A Unix timestamp (seconds, UTC) in [`DATETIME_FORMAT`].
pub fn format_timestamp_local(timestamp: i64) -> String {
    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
    let local_datetime = datetime.with_timezone(&Local);
    local_datetime.format(DATETIME_FORMAT).to_string()
}

/// An RFC 3339 timestamp in [`DATETIME_FORMAT`], verbatim if it will not parse.
///
/// Both the vault's own write stamp and the server's `updated_at` arrive as
/// RFC 3339 text, so neither is trusted to be well-formed: an unparseable value
/// is shown as it came rather than swallowed.
pub fn format_rfc3339_local(raw: &str) -> String {
    DateTime::parse_from_rfc3339(raw)
        .map(|parsed| {
            parsed
                .with_timezone(&Local)
                .format(DATETIME_FORMAT)
                .to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

/// The vault's unencrypted write stamp, rendered for a locked screen.
///
/// `params.host` and `params.updated_at` are the two fields the format leaves in
/// the clear, so this is readable before a single answer is given. Either half
/// may be missing; both missing means no stamp at all.
pub fn format_stamp(host: Option<&str>, updated_at: Option<&str>) -> Option<String> {
    let when = updated_at.map(format_rfc3339_local);
    match (host, when) {
        (Some(host), Some(when)) => Some(format!("{} · {}", host, when)),
        (Some(host), None) => Some(host.to_string()),
        (None, Some(when)) => Some(when),
        (None, None) => None,
    }
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
            card: Default::default(),
        }
    }

    fn card(name: &str) -> SecretEntry {
        let mut card = new_entry();
        card.name = name.to_string();
        card.entry_type = TYPE_CARD.to_string();
        card.card = askrypt::CardFields {
            holder: "Ruslan A.".to_string(),
            brand: "Visa".to_string(),
            number: "4242 4242 4242 4242".to_string(),
            expiry: "04/29".to_string(),
            cvv: "123".to_string(),
            pin: "9876".to_string(),
        };
        card
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
    fn the_filter_reaches_a_cards_visible_fields_only() {
        let card = card("Personal Visa");

        assert!(entry_matches_filter(&card, "ruslan"));
        assert!(entry_matches_filter(&card, "VISA"));
        // The three secrets are as unsearchable as a password: a row appearing
        // for a typed number would confirm the number.
        assert!(!entry_matches_filter(&card, "4242"));
        assert!(!entry_matches_filter(&card, "123"));
        assert!(!entry_matches_filter(&card, "9876"));
    }

    #[test]
    fn a_card_is_recognized_however_its_type_is_spelled() {
        assert!(is_card(&card("Personal Visa")));

        // The mobile app writes lowercase type names.
        let mut lowercase = card("Personal Visa");
        lowercase.entry_type = "card".to_string();
        assert!(is_card(&lowercase));

        assert!(!is_card(&entry("GitHub")));
    }

    #[test]
    fn a_card_number_shows_only_its_last_four() {
        assert_eq!(card_digits("4242 4242 4242 4242"), "4242424242424242");
        assert_eq!(card_last4("4242 4242 4242 4242"), Some("4242".to_string()));
        assert_eq!(
            mask_card_number("4242 4242 4242 4242"),
            "•••• •••• •••• 4242"
        );
        assert_eq!(group_card_number("4242424242424242"), "4242 4242 4242 4242");
        // Amex is 15 digits and groups short at the front.
        assert_eq!(mask_card_number("378282246310005"), "••• •••• •••• 0005");
    }

    #[test]
    fn a_half_typed_card_number_never_shows_through() {
        assert_eq!(card_last4("42"), None);
        assert_eq!(mask_card_number("42"), "••");
        assert_eq!(mask_card_number(""), "");
    }

    #[test]
    fn a_cards_subtitle_falls_back_to_what_it_has() {
        assert_eq!(card_subtitle(&card("Personal Visa")), "Visa ••••4242");

        let mut no_brand = card("Personal Visa");
        no_brand.card.brand.clear();
        assert_eq!(card_subtitle(&no_brand), "••••4242");

        let mut holder_only = card("Personal Visa");
        holder_only.card.brand.clear();
        holder_only.card.number.clear();
        assert_eq!(card_subtitle(&holder_only), "Ruslan A.");

        assert_eq!(card_subtitle(&new_entry()), "");
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
        assert_eq!(format_rfc3339_local("whenever"), "whenever");
    }

    #[test]
    fn both_clocks_render_the_same_instant_the_same_way() {
        // The server listing hands over RFC 3339 text and an entry carries a
        // Unix timestamp; the same moment has to read identically either way.
        let raw = "2026-08-09T10:11:12Z";
        let unix = DateTime::parse_from_rfc3339(raw).unwrap().timestamp();

        assert_eq!(format_rfc3339_local(raw), format_timestamp_local(unix));
    }
}
