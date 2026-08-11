//! Bootstrap icon glyphs, mirroring `src/icon.rs` but with a size parameter.
//!
//! Every codepoint below was read out of this repo's
//! `static/bootstrap-icons.ttf` (its `cmap`/`post` tables), not copied from a
//! web listing — an unmapped codepoint renders as tofu rather than failing to
//! compile, so any glyph added later must be eyeballed once in the running app.
//! Note there is **no bare `plus` glyph** in this font, only `plus-lg`.

use iced::widget::Text;
use iced::{Font, alignment};

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

pub fn journal_text(size: u16) -> Text<'static> {
    glyph('\u{F444}', size)
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

/// Stand-ins for the per-item icon a real vault would show — a site favicon, a
/// card issuer's logo, whatever the entry is *of*. Nothing derives them yet, so
/// [`placeholder`] just picks one; the pool only has to look varied.
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

/// An arbitrary but *stable* icon for an item.
///
/// Derived from the seed rather than actually randomized, because `view` runs
/// on every frame — a real random pick would make the list flicker. Replace the
/// whole function once items carry an icon of their own.
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

/// The wand the shipping app uses for the password generator
/// (`src/icon.rs::magic_icon`).
pub fn magic(size: u16) -> Text<'static> {
    glyph('\u{F675}', size)
}
