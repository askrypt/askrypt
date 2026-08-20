//! The in-browser vault viewer and editor.
//!
//! This is the one page on the site that opens a vault. Everything the
//! decryption needs happens in `static/vault-format.js` over the Web
//! Cryptography API; the server renders a picker, hands over encrypted bytes
//! through the routes it already had, and never sees an answer, a master key
//! or a plaintext entry.
//!
//! It reverses a decision recorded with the Phase 7 stack — "the site never
//! decrypts" — and the reversal has a cost that no amount of care removes:
//! the page is JavaScript the server sends, so a compromised or dishonest
//! server could send different JavaScript. The desktop and mobile apps do not
//! have that exposure, and the page says so. What is bounded instead: no CDN,
//! no inline script, no widened CSP (`script-src 'self'`, `connect-src
//! 'self'` cover it as-is), no dependency, and nothing persisted anywhere in
//! the browser.
//!
//! There is deliberately **no POST here at all**. Reading a stored vault is
//! [`crate::web::vaults::download`], the cookie-authed route that already
//! exists because a browser cannot set an `Authorization` header; saving one
//! is `POST /vaults/{id}/replace`, which carries the row's ETag into the same
//! `If-Match` check the apps use and runs the same quota, versioning and
//! upload gates. A second write door would be a second place for those rules
//! to drift.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;
use crate::web::error::WebResult;
use crate::web::render::{Page, Shell, timestamp, with_cookies};
use crate::web::session::{MaybeWebSession, WebSession};
use crate::web::types::{OpenPage, OpenRow};
use crate::web::vaults::{human_bytes, saved_stamp};

pub use crate::web::types::OpenListing;

pub const OPEN_PATH: &str = "/open";

/// `GET /open`
///
/// Signed-out visitors get the page too: opening a `.askrypt` file from the
/// device needs no account, and that is the case this page is most useful in
/// — someone on a borrowed phone with their vault on a memory stick.
pub async fn page(
    State(state): State<AppState>,
    session: MaybeWebSession,
    headers: HeaderMap,
) -> WebResult<Response> {
    let (chrome, cookies) = Shell::build(&headers, session.email())
        .as_admin(session.is_admin())
        .into_parts();

    let vaults = match session.0.as_ref() {
        Some(web) => Some(listing(&state, web).await?),
        None => None,
    };

    Ok(with_cookies(
        Page(OpenPage { chrome, vaults }).into_response(),
        cookies,
    ))
}

/// `GET /open/vaults` — the picker on its own.
///
/// A save changes the file's ETag, so the value this page was rendered with
/// is stale the moment it succeeds and the next save would be refused with a
/// conflict the visitor did not cause. Re-reading the fragment is how the
/// controller adopts the new one. It also backs the Refresh button, for the
/// same reason the desktop's wizard refetches its listing every time it opens:
/// a listing cached per sign-in hides vaults saved since.
pub async fn vault_list(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
) -> WebResult<Response> {
    let (_, cookies) = Shell::build(&headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    let listing = listing(&state, &web).await?;
    Ok(with_cookies(Page(listing).into_response(), cookies))
}

/// The account's vaults, newest change first — the file someone just saved
/// from another device is the one they came here to open. Mirrors the file
/// manager's ordering so the two pages list alike.
async fn listing(state: &AppState, web: &WebSession) -> WebResult<OpenListing> {
    let mut metas = crate::vaults::list_for(state, web.account.id).await?;
    metas.sort_by_key(|meta| std::cmp::Reverse(meta.updated_at));
    Ok(OpenListing {
        vaults: metas
            .iter()
            .map(|meta| OpenRow {
                id: meta.id.to_string(),
                name: meta.name.clone(),
                size: human_bytes(meta.size),
                updated: timestamp(meta.updated_at),
                saved: saved_stamp(meta.host.as_deref(), meta.saved_at),
                etag: meta.etag.clone(),
            })
            .collect(),
    })
}
