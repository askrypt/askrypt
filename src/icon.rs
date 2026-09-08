//! Bootstrap icon glyphs, and the rule that picks one for an item.
//!
//! Every codepoint below was read out of this repo's
//! `static/bootstrap-icons.ttf` (its `cmap`/`post` tables), not copied from a
//! web listing — an unmapped codepoint renders as tofu rather than failing to
//! compile, so any glyph added later must be eyeballed once in the running app.
//! Note there is **no bare `plus` glyph** in this font, only `plus-lg`.

use iced::widget::Text;
use iced::{Font, alignment};

use askrypt::translit::transliterate;

pub const BOOTSTRAP_ICONS: Font = Font::with_name("bootstrap-icons");

fn glyph(unicode: char, size: u16) -> Text<'static> {
    Text::new(unicode.to_string())
        .font(BOOTSTRAP_ICONS)
        .align_x(alignment::Horizontal::Center)
        // `Pixels` has no `From<u16>` — only `f32`/`u32`.
        .size(f32::from(size))
}

/// `search` — the magnifier drawn inside the search input.
pub const SEARCH: char = '\u{F52A}';

pub fn gear(size: u16) -> Text<'static> {
    glyph('\u{F3E5}', size)
}

pub fn grid(size: u16) -> Text<'static> {
    glyph('\u{F3F8}', size)
}

pub fn eye(size: u16) -> Text<'static> {
    glyph('\u{F341}', size)
}

pub fn eye_slash(size: u16) -> Text<'static> {
    glyph('\u{F340}', size)
}

pub fn chevron_down(size: u16) -> Text<'static> {
    glyph('\u{F282}', size)
}

pub fn tag(size: u16) -> Text<'static> {
    glyph('\u{F5B0}', size)
}

pub fn key(size: u16) -> Text<'static> {
    glyph('\u{F44F}', size)
}

pub fn credit_card(size: u16) -> Text<'static> {
    glyph('\u{F2DC}', size)
}

pub fn paperclip(size: u16) -> Text<'static> {
    glyph('\u{F4B3}', size)
}

pub fn file_earmark(size: u16) -> Text<'static> {
    glyph('\u{F392}', size)
}

pub fn file_earmark_arrow_down(size: u16) -> Text<'static> {
    glyph('\u{F356}', size)
}

pub fn plus_lg(size: u16) -> Text<'static> {
    glyph('\u{F64D}', size)
}

pub fn trash(size: u16) -> Text<'static> {
    glyph('\u{F5DE}', size)
}

pub fn files(size: u16) -> Text<'static> {
    glyph('\u{F3C2}', size)
}

pub fn pencil(size: u16) -> Text<'static> {
    glyph('\u{F4CB}', size)
}

pub fn copy(size: u16) -> Text<'static> {
    glyph('\u{F759}', size)
}

pub fn x_lg(size: u16) -> Text<'static> {
    glyph('\u{F659}', size)
}

pub fn box_arrow_up_right(size: u16) -> Text<'static> {
    glyph('\u{F1C5}', size)
}

// ---------------------------------------------------------------------------
// Item icons
// ---------------------------------------------------------------------------

/// How a keyword may appear in the text it is matched against.
#[derive(Clone, Copy)]
enum Where {
    /// Anywhere in the squashed text. This is what makes `bank` find
    /// *Sberbank* and `stackoverflow` find *Stack Overflow* — the separators
    /// are gone by then, so a keyword spanning two written words still lands.
    Any,
    /// Only as a whole word. This is what stops `car` firing on *Oscar*,
    /// `team` on *Steam*, `ups` on *backups* and `api` on *capital*; every
    /// keyword short or common enough to hide inside an unrelated word is
    /// declared this way.
    Word,
}

use Where::{Any, Word};

/// What an item's name (or URL) says it is, and the glyph for it.
///
/// The **longest matching keyword wins**, ties going to the earlier row. That
/// single rule settles the collisions this table would otherwise be full of:
/// `google` beats `mail` on *Google Mail*, `facebook` beats `book`,
/// `photoshop` beats both `photo` and `shop`, `coursera` beats `course`. It is
/// also why the brands come first — *Facebook password* is a tie at eight
/// characters, and the brand is the better answer.
///
/// Every codepoint here was read out of this repo's `bootstrap-icons.ttf`, per
/// the module doc: an unmapped one renders as tofu rather than failing to
/// compile. Note there is no `apple` glyph in this font, which is why the
/// obvious keyword is missing.
const KEYWORDS: &[(&str, Where, char)] = &[
    // --- Brands ------------------------------------------------------------
    ("google", Any, '\u{F3F0}'), // google
    ("gmail", Any, '\u{F3F0}'),
    ("youtube", Any, '\u{F62B}'),   // youtube
    ("github", Any, '\u{F3ED}'),    // github
    ("gitlab", Any, '\u{F7E5}'),    // gitlab
    ("facebook", Any, '\u{F344}'),  // facebook
    ("instagram", Any, '\u{F437}'), // instagram
    ("twitter", Any, '\u{F8DB}'),   // twitter-x
    ("linkedin", Any, '\u{F472}'),  // linkedin
    ("microsoft", Any, '\u{F65D}'), // microsoft
    ("outlook", Any, '\u{F65D}'),
    ("onedrive", Any, '\u{F65D}'),
    ("hotmail", Any, '\u{F65D}'),
    ("windows", Any, '\u{F65E}'), // windows
    ("amazon", Any, '\u{F68D}'),  // amazon
    ("aws", Word, '\u{F68D}'),
    ("paypal", Any, '\u{F662}'),        // paypal
    ("stripe", Any, '\u{F847}'),        // stripe
    ("spotify", Any, '\u{F666}'),       // spotify
    ("reddit", Any, '\u{F650}'),        // reddit
    ("discord", Any, '\u{F300}'),       // discord
    ("slack", Any, '\u{F565}'),         // slack
    ("telegram", Any, '\u{F5B3}'),      // telegram
    ("whatsapp", Any, '\u{F618}'),      // whatsapp
    ("signal", Any, '\u{F664}'),        // signal
    ("skype", Any, '\u{F656}'),         // skype
    ("steam", Any, '\u{F6C1}'),         // steam
    ("dropbox", Any, '\u{F7ED}'),       // dropbox
    ("mastodon", Any, '\u{F647}'),      // mastodon
    ("tiktok", Any, '\u{F6CC}'),        // tiktok
    ("twitch", Any, '\u{F5EE}'),        // twitch
    ("vimeo", Any, '\u{F66A}'),         // vimeo
    ("wordpress", Any, '\u{F669}'),     // wordpress
    ("medium", Word, '\u{F661}'),       // medium
    ("pinterest", Any, '\u{F663}'),     // pinterest
    ("wechat", Any, '\u{F829}'),        // wechat
    ("behance", Any, '\u{F65C}'),       // behance
    ("dribbble", Any, '\u{F65F}'),      // dribbble
    ("stackoverflow", Any, '\u{F667}'), // stack-overflow
    ("strava", Any, '\u{F668}'),        // strava
    ("trello", Any, '\u{F84A}'),        // trello
    ("playstation", Any, '\u{F6A9}'),   // playstation
    ("psn", Word, '\u{F6A9}'),
    ("xbox", Any, '\u{F6D4}'),     // xbox
    ("nintendo", Any, '\u{F6A4}'), // nintendo-switch
    ("android", Any, '\u{F7D0}'),  // android
    ("ubuntu", Any, '\u{F822}'),   // ubuntu
    ("chrome", Any, '\u{F7D4}'),   // browser-chrome
    ("firefox", Any, '\u{F7D6}'),  // browser-firefox
    ("mozilla", Any, '\u{F7D6}'),
    ("safari", Any, '\u{F7D7}'), // browser-safari
    ("weibo", Any, '\u{F8CA}'),  // sina-weibo
    // --- Money -------------------------------------------------------------
    ("bank", Any, '\u{F62E}'), // bank
    ("visa", Any, '\u{F2DC}'), // credit-card
    ("mastercard", Any, '\u{F2DC}'),
    ("amex", Any, '\u{F2DC}'),
    ("creditcard", Any, '\u{F2DC}'),
    ("card", Word, '\u{F2DC}'),
    ("wallet", Any, '\u{F614}'),  // wallet
    ("bitcoin", Any, '\u{F635}'), // currency-bitcoin
    ("btc", Word, '\u{F635}'),
    ("crypto", Any, '\u{F635}'),
    ("ethereum", Any, '\u{F635}'),
    ("coinbase", Any, '\u{F635}'),
    ("binance", Any, '\u{F635}'),
    ("metamask", Any, '\u{F635}'),
    ("currency", Any, '\u{F638}'), // currency-exchange
    ("cash", Any, '\u{F247}'),     // cash
    ("savings", Any, '\u{F64A}'),  // piggy-bank
    ("invest", Any, '\u{F3F2}'),   // graph-up
    ("broker", Any, '\u{F3F2}'),
    ("trading", Any, '\u{F3F2}'),
    ("stock", Word, '\u{F3F2}'),
    ("invoice", Any, '\u{F50F}'), // receipt
    ("receipt", Any, '\u{F50F}'),
    ("bill", Word, '\u{F50F}'),
    // --- Identity and officialdom ------------------------------------------
    ("passport", Any, '\u{F8F5}'), // passport
    ("license", Any, '\u{F8C9}'),  // person-vcard
    ("id", Word, '\u{F8C9}'),
    ("government", Any, '\u{F1DD}'), // building
    ("tax", Word, '\u{F1DD}'),
    ("irs", Word, '\u{F1DD}'),
    ("gov", Word, '\u{F1DD}'),
    ("insurance", Any, '\u{F53B}'), // shield-shaded
    // --- Communication -----------------------------------------------------
    ("mail", Any, '\u{F32F}'), // envelope
    ("email", Any, '\u{F32F}'),
    ("webmail", Any, '\u{F32F}'),
    ("inbox", Any, '\u{F32F}'),
    ("imap", Any, '\u{F32F}'),
    ("smtp", Any, '\u{F32F}'),
    ("chat", Any, '\u{F24A}'), // chat-dots
    ("messenger", Any, '\u{F24A}'),
    ("phone", Word, '\u{F5C1}'), // telephone
    ("mobile", Any, '\u{F5C1}'),
    ("telecom", Any, '\u{F5C1}'),
    ("sim", Word, '\u{F54C}'),  // sim
    ("zoom", Word, '\u{F21F}'), // camera-video
    ("webex", Any, '\u{F21F}'),
    ("meeting", Any, '\u{F21F}'),
    ("forum", Any, '\u{F4D0}'), // people
    ("community", Any, '\u{F4D0}'),
    ("team", Word, '\u{F4D0}'),
    ("contact", Any, '\u{F4E1}'), // person
    // --- Networks and machines ---------------------------------------------
    ("wifi", Any, '\u{F61C}'), // wifi
    ("ssid", Any, '\u{F61C}'),
    ("wlan", Any, '\u{F61C}'),
    ("router", Any, '\u{F6EC}'), // router
    ("modem", Any, '\u{F6EC}'),
    ("password", Any, '\u{F538}'), // shield-lock
    ("keepass", Any, '\u{F538}'),
    ("bitwarden", Any, '\u{F538}'),
    ("lastpass", Any, '\u{F538}'),
    ("1password", Any, '\u{F538}'),
    ("vpn", Word, '\u{F538}'),
    ("2fa", Word, '\u{F538}'),
    ("otp", Word, '\u{F538}'),
    ("server", Any, '\u{F52C}'), // server
    ("hosting", Any, '\u{F52C}'),
    ("ssh", Word, '\u{F52C}'),
    ("vps", Word, '\u{F52C}'),
    ("database", Any, '\u{F8C4}'), // database
    ("postgres", Any, '\u{F8C4}'),
    ("mysql", Any, '\u{F8C4}'),
    ("mongo", Any, '\u{F8C4}'),
    ("redis", Any, '\u{F8C4}'),
    ("sqlite", Any, '\u{F8C4}'),
    ("sql", Word, '\u{F8C4}'),
    ("cloud", Any, '\u{F2C1}'), // cloud
    ("azure", Any, '\u{F2C1}'),
    ("backup", Any, '\u{F412}'), // hdd
    ("storage", Any, '\u{F412}'),
    ("synology", Any, '\u{F412}'),
    ("nas", Word, '\u{F412}'),
    ("domain", Any, '\u{F3EE}'), // globe
    ("website", Any, '\u{F3EE}'),
    ("cloudflare", Any, '\u{F3EE}'),
    ("godaddy", Any, '\u{F3EE}'),
    ("namecheap", Any, '\u{F3EE}'),
    ("dns", Word, '\u{F3EE}'),
    ("laptop", Any, '\u{F456}'), // laptop
    ("macbook", Any, '\u{F456}'),
    ("computer", Any, '\u{F456}'),
    ("desktop", Word, '\u{F456}'),
    ("printer", Any, '\u{F501}'), // printer
    ("print", Word, '\u{F501}'),
    ("docker", Any, '\u{F2C6}'), // code-slash
    ("jenkins", Any, '\u{F2C6}'),
    ("bitbucket", Any, '\u{F2C6}'),
    ("jira", Any, '\u{F2C6}'),
    ("npm", Word, '\u{F2C6}'),
    ("api", Word, '\u{F2C6}'),
    ("apikey", Any, '\u{F44F}'), // key
    ("token", Word, '\u{F44F}'),
    // --- Everyday life -----------------------------------------------------
    ("employer", Any, '\u{F1CC}'), // briefcase
    ("payroll", Any, '\u{F1CC}'),
    ("work", Word, '\u{F1CC}'),
    ("job", Word, '\u{F1CC}'),
    ("office", Word, '\u{F1CC}'),
    ("hr", Word, '\u{F1CC}'),
    ("mortgage", Any, '\u{F425}'), // house
    ("apartment", Any, '\u{F425}'),
    ("landlord", Any, '\u{F425}'),
    ("home", Word, '\u{F425}'),
    ("rent", Word, '\u{F425}'),
    ("school", Any, '\u{F6FE}'), // mortarboard
    ("university", Any, '\u{F6FE}'),
    ("college", Any, '\u{F6FE}'),
    ("student", Any, '\u{F6FE}'),
    ("course", Any, '\u{F6FE}'),
    ("udemy", Any, '\u{F6FE}'),
    ("coursera", Any, '\u{F6FE}'),
    ("duolingo", Any, '\u{F6FE}'),
    ("book", Any, '\u{F194}'), // book
    ("kindle", Any, '\u{F194}'),
    ("goodreads", Any, '\u{F194}'),
    ("audible", Any, '\u{F194}'),
    ("music", Any, '\u{F49E}'), // music-note-beamed
    ("audio", Any, '\u{F49E}'),
    ("itunes", Any, '\u{F49E}'),
    ("soundcloud", Any, '\u{F49E}'),
    ("gaming", Any, '\u{F2D4}'), // controller
    ("epicgames", Any, '\u{F2D4}'),
    ("roblox", Any, '\u{F2D4}'),
    ("minecraft", Any, '\u{F2D4}'),
    ("game", Word, '\u{F2D4}'),
    ("gog", Word, '\u{F2D4}'),
    ("photo", Any, '\u{F220}'), // camera
    ("camera", Any, '\u{F220}'),
    ("flickr", Any, '\u{F220}'),
    ("netflix", Any, '\u{F3C3}'), // film
    ("movie", Any, '\u{F3C3}'),
    ("cinema", Any, '\u{F3C3}'),
    ("hulu", Any, '\u{F3C3}'),
    ("disney", Any, '\u{F3C3}'),
    ("imdb", Any, '\u{F3C3}'),
    ("tv", Word, '\u{F5ED}'),  // tv
    ("shop", Any, '\u{F242}'), // cart
    ("ebay", Any, '\u{F242}'),
    ("etsy", Any, '\u{F242}'),
    ("aliexpress", Any, '\u{F242}'),
    ("store", Word, '\u{F242}'),
    ("coffee", Any, '\u{F7EB}'), // cup-hot
    ("cafe", Any, '\u{F7EB}'),
    ("starbucks", Any, '\u{F7EB}'),
    ("delivery", Any, '\u{F5EA}'), // truck
    ("shipping", Any, '\u{F5EA}'),
    ("fedex", Any, '\u{F5EA}'),
    ("dhl", Word, '\u{F5EA}'),
    ("ups", Word, '\u{F5EA}'),
    ("gift", Any, '\u{F3EC}'),   // gift
    ("ticket", Any, '\u{F6CA}'), // ticket-perforated
    ("eventbrite", Any, '\u{F6CA}'),
    ("event", Word, '\u{F6CA}'),
    ("navigation", Any, '\u{F3E8}'), // geo-alt
    ("maps", Word, '\u{F3E8}'),
    ("gps", Word, '\u{F3E8}'),
    ("news", Any, '\u{F4A3}'), // newspaper
    ("blog", Any, '\u{F4A3}'),
    ("substack", Any, '\u{F4A3}'),
    ("rss", Word, '\u{F4A3}'),
    ("notion", Any, '\u{F444}'), // journal-text
    ("evernote", Any, '\u{F444}'),
    ("journal", Any, '\u{F444}'),
    ("diary", Any, '\u{F444}'),
    ("obsidian", Any, '\u{F444}'),
    ("notes", Word, '\u{F444}'),
    ("figma", Any, '\u{F4B1}'), // palette
    ("canva", Any, '\u{F4B1}'),
    ("adobe", Any, '\u{F4B1}'),
    ("photoshop", Any, '\u{F4B1}'),
    ("design", Word, '\u{F4B1}'),
    ("charity", Any, '\u{F417}'), // heart
    ("donation", Any, '\u{F417}'),
    ("patreon", Any, '\u{F417}'),
    ("vault", Word, '\u{F65A}'),   // safe
    ("calendar", Any, '\u{F1E8}'), // calendar-event
    // --- Russian and Ukrainian, spelled the way `words_of` romanizes them ---
    // Both halves are needed: people type these names in Latin as often as in
    // Cyrillic, and `transliterate` is BGN/PCGN, so Яндекс arrives as `yandeks`.
    ("pochta", Any, '\u{F32F}'), // envelope
    ("poshta", Any, '\u{F32F}'),
    ("novaposhta", Any, '\u{F5EA}'), // truck
    ("gosuslugi", Any, '\u{F1DD}'),  // building
    ("diia", Word, '\u{F1DD}'),
    ("yandex", Any, '\u{F3EE}'), // globe
    ("yandeks", Any, '\u{F3EE}'),
    ("tinkoff", Any, '\u{F62E}'), // bank
    ("vtb", Word, '\u{F62E}'),
    ("wildberries", Any, '\u{F242}'), // cart
    ("vayldberriz", Any, '\u{F242}'),
    ("avito", Any, '\u{F242}'),
    ("ozon", Word, '\u{F242}'),
    ("vkontakte", Any, '\u{F4D0}'), // people
    ("odnoklassniki", Any, '\u{F4D0}'),
    ("megafon", Any, '\u{F5C1}'), // telephone
    ("beeline", Any, '\u{F5C1}'),
    ("bilayn", Any, '\u{F5C1}'),
    ("mts", Word, '\u{F5C1}'),
    ("aeroflot", Any, '\u{F7CD}'), // airplane
    ("rzhd", Word, '\u{F81D}'),    // train-front
    ("zdorove", Any, '\u{F774}'),  // hospital
    ("rabota", Any, '\u{F1CC}'),   // briefcase
    ("kvartira", Any, '\u{F425}'), // house
    ("shkola", Any, '\u{F6FE}'),   // mortarboard
    // --- Travel and transport ----------------------------------------------
    ("flight", Any, '\u{F7CD}'), // airplane
    ("airline", Any, '\u{F7CD}'),
    ("airport", Any, '\u{F7CD}'),
    ("airbnb", Any, '\u{F7CD}'),
    ("hotel", Any, '\u{F7CD}'),
    ("travel", Any, '\u{F7CD}'),
    ("railway", Any, '\u{F81D}'), // train-front
    ("train", Word, '\u{F81D}'),
    ("rail", Word, '\u{F81D}'),
    ("transit", Any, '\u{F87F}'), // bus-front
    ("bus", Word, '\u{F87F}'),
    ("uber", Any, '\u{F7E1}'), // car-front
    ("lyft", Any, '\u{F7E1}'),
    ("taxi", Any, '\u{F7E1}'),
    ("vehicle", Any, '\u{F7E1}'),
    ("car", Word, '\u{F7E1}'),
    ("auto", Word, '\u{F7E1}'),
    ("dmv", Word, '\u{F7E1}'),
    ("fuel", Any, '\u{F83E}'), // fuel-pump
    ("petrol", Any, '\u{F83E}'),
    ("gas", Word, '\u{F83E}'),
    // --- Health and utilities ----------------------------------------------
    ("hospital", Any, '\u{F774}'), // hospital
    ("clinic", Any, '\u{F774}'),
    ("medical", Any, '\u{F774}'),
    ("health", Any, '\u{F774}'),
    ("doctor", Any, '\u{F774}'),
    ("dentist", Any, '\u{F774}'),
    ("pharmacy", Any, '\u{F80B}'), // prescription2
    ("prescription", Any, '\u{F80B}'),
    ("fitness", Any, '\u{F76F}'), // heart-pulse
    ("workout", Any, '\u{F76F}'),
    ("gym", Word, '\u{F76F}'),
    ("electric", Any, '\u{F46F}'), // lightning
    ("energy", Any, '\u{F46F}'),
    ("utility", Any, '\u{F46F}'),
    ("utilities", Any, '\u{F46F}'),
    ("power", Word, '\u{F46F}'),
    ("water", Any, '\u{F30D}'), // droplet
];

/// The words an item's name and URL are made of: lowercased, split on
/// everything that is not a letter or a digit, and romanized when they are not
/// ASCII — the keywords are, so *Сбербанк* can only ever match through the
/// same transliteration the vault already applies to answers.
fn words_of(name: &str, url: &str) -> Vec<String> {
    let mut words = Vec::new();
    for field in [name, url] {
        for raw in field.split(|c: char| !c.is_alphanumeric()) {
            if raw.is_empty() {
                continue;
            }
            let lower = raw.to_lowercase();
            words.push(if lower.is_ascii() {
                lower
            } else {
                transliterate(&lower)
            });
        }
    }
    words
}

/// The glyph an item's name and URL name, if any.
///
/// Split out of [`item`] and [`card`] because it is the whole of the logic and
/// answers a plain `char`: a `Text` widget cannot be compared in a test.
fn lookup(name: &str, url: &str) -> Option<char> {
    let words = words_of(name, url);
    // The separators are gone, so a keyword may span what were two words:
    // `Stack Overflow` and `stackoverflow.com` reduce to the same haystack.
    let squashed = words.concat();

    let mut best: Option<(usize, char)> = None;
    for &(keyword, position, found) in KEYWORDS {
        let hit = match position {
            Any => squashed.contains(keyword),
            Word => words.iter().any(|word| word == keyword),
        };
        if hit && best.is_none_or(|(len, _)| keyword.len() > len) {
            best = Some((keyword.len(), found));
        }
    }
    best.map(|(_, found)| found)
}

/// The icon for an item: what its name or URL says it is, else [`placeholder`].
pub fn item(name: &str, url: &str, size: u16) -> Text<'static> {
    match lookup(name, url) {
        Some(found) => glyph(found, size),
        None => placeholder(name, size),
    }
}

/// The icon for a card: the issuer's own mark when the name names one — which
/// is what [`credit_card`] was always standing in for — and the generic card
/// otherwise. Never the hashed pool: a card that matched nothing is still
/// unmistakably a card, and an arbitrary glyph would say less than that.
pub fn card(name: &str, url: &str, size: u16) -> Text<'static> {
    match lookup(name, url) {
        Some(found) => glyph(found, size),
        None => credit_card(size),
    }
}

/// The fallback pool, for an item [`KEYWORDS`] had nothing to say about — a
/// stand-in for the favicon or issuer logo a real item would carry. It only
/// has to look varied.
const PLACEHOLDERS: [char; 16] = [
    '\u{F3EE}', // globe
    '\u{F32F}', // envelope
    '\u{F62E}', // bank
    '\u{F242}', // cart
    '\u{F24A}', // chat-dots
    '\u{F220}', // camera
    '\u{F49E}', // music-note-beamed
    '\u{F2D4}', // controller
    '\u{F1CC}', // briefcase
    '\u{F425}', // house
    '\u{F194}', // book
    '\u{F588}', // star
    '\u{F4E1}', // person
    '\u{F5C1}', // telephone
    '\u{F456}', // laptop
    '\u{F7EB}', // cup-hot
];

/// An arbitrary but *stable* icon for an item [`lookup`] did not recognize.
///
/// Derived from the seed rather than actually randomized, because `view` runs
/// on every frame — a real random pick would make the list flicker. Seeded on
/// the name alone, never the URL, so editing a URL cannot reshuffle the icon of
/// a row that still matches nothing.
pub fn placeholder(seed: &str, size: u16) -> Text<'static> {
    // FNV-1a, inline: the seed is a display string, not a security input.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }

    glyph(
        PLACEHOLDERS[(hash % PLACEHOLDERS.len() as u64) as usize],
        size,
    )
}

// ---------------------------------------------------------------------------
// Vault lifecycle: the rail's action buttons and the source wizard.
// ---------------------------------------------------------------------------

pub fn file_earmark_plus(size: u16) -> Text<'static> {
    glyph('\u{F37D}', size)
}

pub fn folder2_open(size: u16) -> Text<'static> {
    glyph('\u{F3D8}', size)
}

pub fn close(size: u16) -> Text<'static> {
    glyph('\u{F623}', size)
}

pub fn lock(size: u16) -> Text<'static> {
    glyph('\u{F47B}', size)
}

pub fn unlock(size: u16) -> Text<'static> {
    glyph('\u{F600}', size)
}

pub fn shield_lock(size: u16) -> Text<'static> {
    glyph('\u{F538}', size)
}

pub fn save(size: u16) -> Text<'static> {
    glyph('\u{F525}', size)
}

pub fn save2(size: u16) -> Text<'static> {
    glyph('\u{F527}', size)
}

pub fn server(size: u16) -> Text<'static> {
    glyph('\u{F52C}', size)
}

pub fn cloud(size: u16) -> Text<'static> {
    glyph('\u{F2C1}', size)
}

pub fn file_earmark_lock(size: u16) -> Text<'static> {
    glyph('\u{F36F}', size)
}

pub fn arrow_left(size: u16) -> Text<'static> {
    glyph('\u{F12F}', size)
}

pub fn chevron_right(size: u16) -> Text<'static> {
    glyph('\u{F285}', size)
}

/// `power` — the Quit row at the bottom of the rail.
pub fn power(size: u16) -> Text<'static> {
    glyph('\u{F4FF}', size)
}

/// The wand that marks the password generator.
pub fn magic(size: u16) -> Text<'static> {
    glyph('\u{F675}', size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The glyphs the assertions below name, so a test reads as words rather
    /// than as codepoints.
    const GOOGLE: char = '\u{F3F0}';
    const BANK: char = '\u{F62E}';
    const ENVELOPE: char = '\u{F32F}';
    const FACEBOOK: char = '\u{F344}';
    const BOOK: char = '\u{F194}';
    const CAR: char = '\u{F7E1}';
    const PEOPLE: char = '\u{F4D0}';
    const STEAM: char = '\u{F6C1}';
    const TRUCK: char = '\u{F5EA}';
    const HDD: char = '\u{F412}';
    const PALETTE: char = '\u{F4B1}';
    const INSURANCE: char = '\u{F53B}';
    const MUSIC: char = '\u{F49E}';

    #[test]
    fn the_url_can_supply_the_match() {
        assert_eq!(lookup("Work mail", "https://mail.google.com"), Some(GOOGLE));
    }

    #[test]
    fn a_keyword_is_found_inside_a_longer_word() {
        assert_eq!(lookup("Sberbank", ""), Some(BANK));
        assert_eq!(lookup("Bank of America", ""), Some(BANK));
    }

    #[test]
    fn a_keyword_may_span_two_written_words() {
        assert_eq!(
            lookup("Stack Overflow", ""),
            lookup("stackoverflow.com", "")
        );
        assert!(lookup("Stack Overflow", "").is_some());
    }

    #[test]
    fn a_cyrillic_name_matches_through_transliteration() {
        assert_eq!(lookup("Сбербанк", ""), Some(BANK));
    }

    #[test]
    fn a_word_keyword_does_not_hide_inside_another_word() {
        // `car` is Word-mode precisely so this pair splits.
        assert_eq!(lookup("Car service", ""), Some(CAR));
        assert_ne!(lookup("Oscar", ""), Some(CAR));
        // `team` would otherwise fire on Steam, and `ups` on backups.
        assert_eq!(lookup("Steam", ""), Some(STEAM));
        assert_eq!(lookup("Team drive", ""), Some(PEOPLE));
        assert_eq!(lookup("UPS", ""), Some(TRUCK));
        assert_eq!(lookup("Nightly backups", ""), Some(HDD));
    }

    #[test]
    fn the_longest_keyword_wins() {
        // google over mail, facebook over book, photoshop over photo and shop.
        assert_eq!(lookup("Google Mail", ""), Some(GOOGLE));
        assert_eq!(lookup("Webmail", ""), Some(ENVELOPE));
        assert_eq!(lookup("Facebook", ""), Some(FACEBOOK));
        assert_eq!(lookup("Book club", ""), Some(BOOK));
        assert_eq!(lookup("Photoshop", ""), Some(PALETTE));
        // And where the longer keyword names the *category* rather than the
        // thing: car insurance is insurance.
        assert_eq!(lookup("Car insurance", ""), Some(INSURANCE));
    }

    #[test]
    fn a_tie_goes_to_the_earlier_row_which_is_the_brand() {
        // `facebook` and `password` are both eight characters.
        assert_eq!(lookup("Facebook password", ""), Some(FACEBOOK));
    }

    #[test]
    fn an_unrecognized_name_matches_nothing() {
        assert_eq!(lookup("Zzzq", ""), None);
        assert_eq!(lookup("", ""), None);
    }

    #[test]
    fn every_glyph_is_in_the_font_s_mapped_range() {
        // The font maps U+F101..=U+F91E; anything outside it is certainly tofu,
        // and anything inside it still has to be eyeballed once.
        for (keyword, _, found) in KEYWORDS {
            assert!(
                ('\u{F101}'..='\u{F91E}').contains(found),
                "{keyword}: {found:?} is outside the font's range"
            );
        }
    }

    #[test]
    fn every_keyword_is_lowercase_alphanumeric_and_unique() {
        // `words_of` lowercases and strips everything else, so a keyword with a
        // capital or a separator in it could never match anything.
        let mut seen = std::collections::HashSet::new();
        for (keyword, _, _) in KEYWORDS {
            assert!(!keyword.is_empty(), "an empty keyword matches everything");
            assert!(
                keyword
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{keyword} can never match: `words_of` would not produce it"
            );
            assert!(seen.insert(*keyword), "{keyword} is listed twice");
        }
    }

    #[test]
    fn a_qualifier_does_not_outrank_the_noun_beside_it() {
        // `personal` and `library` were both in this table and both hijacked
        // what they qualify. An adjective does not classify an item.
        assert_eq!(lookup("Personal email", ""), Some(ENVELOPE));
        assert_eq!(lookup("Music library", ""), Some(MUSIC));
    }

    #[test]
    fn a_cyrillic_brand_matches_in_either_alphabet() {
        assert_eq!(lookup("Яндекс", ""), lookup("Yandex", ""));
        assert_eq!(lookup("Тинькофф", ""), Some(BANK));
        assert_eq!(lookup("Почта России", ""), Some(ENVELOPE));
        assert_eq!(lookup("Альфа-Банк", ""), Some(BANK));
    }
}
