//! Desktop sign-in handed to the browser.
//!
//! The desktop app has no business asking for an account password: the website
//! already owns login, registration, Google sign-in, rate limiting and login
//! timing equalization. So the app does not sign in at all — it opens a *device
//! link* and lets a browser do it:
//!
//! 1. the app calls [`start`], getting a public `link_id` and a secret
//!    `poll_token`;
//! 2. it opens `/link/{link_id}` in the user's browser
//!    ([`crate::web::devicelink`]), where signing in approves the link;
//! 3. it calls [`poll`] until the link is approved, and *that* is where the
//!    bearer token is minted.
//!
//! ## Why the token is minted at poll time
//!
//! Approving records only "account X said yes to link Y". Issuing the session
//! at approval instead would leave a live 30-day credential behind every time
//! someone approved and then closed the laptop before the app collected it —
//! and would put a second bearer token at rest in a second table. Minting on
//! claim means a token exists only once a device is actually holding it.
//!
//! The cost is that a ban can land between approval and claim, so [`poll`]
//! re-checks it: [`crate::auth::issue_session`] does not, and without the check
//! this would be the one path by which a banned account still gets a fresh
//! token.
//!
//! ## What the user code is for
//!
//! [`start`] needs no authentication — it cannot, since the point is to get a
//! token — so anyone can create a link and try to talk a signed-in user into
//! opening its URL. The short code shown in both the app and the browser is the
//! comparison that defeats that. It is display-only: nothing is ever looked up
//! by it, precisely so it never becomes a second, short, guessable credential.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{Duration, Utc};

use crate::audit::{self, ClientInfo};
use crate::auth::{self, SessionResponse};
use crate::error::{ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{Account, DeviceLink, DeviceLinkId, DeviceLinkStatus, StoreError};

pub use crate::types::{PollRequest, PollResponse, StartRequest, StartResponse};

/// How long a link stays usable. A full day, so a user who walks away from the
/// browser can still finish later — and a link nobody ever completes is *gone*
/// at that point rather than lingering for good.
pub const DEVICE_LINK_TTL_HOURS: i64 = 24;

/// Seconds the app should wait between polls. Handed to the client rather than
/// agreed by convention, so the cadence and the device rate limit in
/// [`crate::routes`] cannot drift apart.
pub const POLL_INTERVAL_SECS: u64 = 3;

/// Longest device label kept. Client-supplied text that lands on a web page and
/// in the account's device list, so it is bounded here rather than trusted.
const MAX_DEVICE_LABEL: usize = 64;

/// Characters a user code is drawn from: digits and upper-case letters, minus
/// the ones people mix up reading a code off one screen and onto another
/// (`0`/`O`, `1`/`I`/`L`, and `U` for how often it is heard as `V`).
const USER_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a user code, before the hyphen is inserted.
const USER_CODE_LEN: usize = 8;

/// `POST /api/v1/auth/device` — open a device link.
///
/// Unauthenticated by construction: this is how a client with no credentials
/// asks for some.
pub async fn start(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<StartRequest>,
) -> ApiResult<(StatusCode, Json<StartResponse>)> {
    // The only sweep there is. This server runs no background jobs, and the
    // create path is both the busiest moment for this table and the only one
    // an abandoned link is guaranteed to be followed by.
    sweep_expired(&state).await;

    let now = Utc::now();
    let link = DeviceLink {
        id: DeviceLinkId::new_v4(),
        poll_token: auth::new_session_token(),
        user_code: new_user_code(),
        device_label: clean_label(req.device_label),
        status: DeviceLinkStatus::Pending,
        account_id: None,
        created_at: now,
        expires_at: now + Duration::hours(DEVICE_LINK_TTL_HOURS),
    };

    state.device_links.insert(link.clone()).await?;
    audit::emit(
        audit::DEVICE_LINK_STARTED,
        &client,
        None,
        link.device_label.as_deref().unwrap_or("-"),
    );

    Ok((
        StatusCode::CREATED,
        Json(StartResponse {
            link_id: link.id,
            poll_token: link.poll_token,
            user_code: link.user_code,
            verification_path: verification_path(link.id),
            expires_in: (link.expires_at - now).num_seconds(),
            interval: POLL_INTERVAL_SECS,
        }),
    ))
}

/// `POST /api/v1/auth/device/poll` — ask whether the link has been approved,
/// and collect the session when it has.
///
/// Unknown, expired and already-claimed links all answer `expired`. Telling
/// them apart would make this endpoint an oracle for whether a guessed poll
/// token ever existed; the real reason goes to the log instead, the way
/// [`crate::auth::resolve_session`] handles its four rejections.
pub async fn poll(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<PollRequest>,
) -> ApiResult<Json<PollResponse>> {
    let now = Utc::now();

    // One atomic step, so two polls racing on the same link cannot both come
    // away with a session.
    if let Some(link) = state.device_links.claim(&req.poll_token, now).await? {
        return Ok(Json(claim_session(&state, &client, link).await?));
    }

    let Some(link) = state
        .device_links
        .get_by_poll_token(&req.poll_token)
        .await?
    else {
        return Ok(Json(PollResponse::Expired));
    };

    if link.is_expired(now) {
        // Best effort: the answer is `expired` whether or not the row goes.
        let _ = state.device_links.delete(link.id).await;
        return Ok(Json(PollResponse::Expired));
    }

    Ok(Json(match link.status {
        DeviceLinkStatus::Pending => PollResponse::Pending,
        DeviceLinkStatus::Denied => {
            let _ = state.device_links.delete(link.id).await;
            PollResponse::Denied
        }
        // `claim` above takes every approved link that is still valid, so
        // reaching here means another poll got there first.
        DeviceLinkStatus::Approved => PollResponse::Expired,
    }))
}

/// Turns a claimed link into a session. The link row is already gone — `claim`
/// removed it — so every exit from here is terminal for that link.
async fn claim_session(
    state: &AppState,
    client: &ClientInfo,
    link: DeviceLink,
) -> ApiResult<PollResponse> {
    let Some(account_id) = link.account_id else {
        // An approved link always names its approver; a row without one is a
        // bug or a hand-edited database, not a client error.
        tracing::warn!(link = %link.id, "approved device link has no account");
        return Ok(PollResponse::Expired);
    };

    let Some(account) = state.accounts.get(account_id).await? else {
        // The account was deleted between approving and claiming.
        return Ok(PollResponse::Expired);
    };

    // `issue_session` does not ban-check — only `authenticate` and
    // `resolve_session` do — and a ban can land in the window between approval
    // and this call. Without this, the device link would be the one way a
    // banned account still gets a fresh token.
    if account.is_banned() {
        audit::emit(
            audit::DEVICE_LINK_REFUSED,
            client,
            Some(account.id),
            "banned",
        );
        return Err(auth::account_banned());
    }

    let session = auth::issue_session(
        state,
        &account,
        link.device_label.clone(),
        auth::SESSION_TTL_DAYS,
    )
    .await?;
    audit::emit(
        audit::DEVICE_LINK_CLAIMED,
        client,
        Some(account.id),
        link.device_label.as_deref().unwrap_or("-"),
    );

    Ok(PollResponse::Approved(SessionResponse::new(
        session, &account,
    )))
}

/// `POST /api/v1/auth/device/cancel` — the app is no longer waiting.
///
/// Closing the sign-in pane means the user does not want this link any more, so
/// it goes now rather than sitting approvable for the rest of its 24 hours.
/// Answers `204` whatever it found: like [`poll`], it must not report whether a
/// given poll token ever named anything.
pub async fn cancel(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<PollRequest>,
) -> ApiResult<StatusCode> {
    if let Some(link) = state
        .device_links
        .get_by_poll_token(&req.poll_token)
        .await?
    {
        // Best effort: a link that has just been claimed is already gone, and
        // that is the same outcome.
        let _ = state.device_links.delete(link.id).await;
        audit::emit(
            audit::DEVICE_LINK_CANCELLED,
            &client,
            link.account_id,
            link.device_label.as_deref().unwrap_or("-"),
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Marks a link approved by `account`. The website's half of the flow; no token
/// is issued here.
pub(crate) async fn approve(
    state: &AppState,
    client: &ClientInfo,
    link: &DeviceLink,
    account: &Account,
) -> ApiResult<()> {
    let approved = DeviceLink {
        status: DeviceLinkStatus::Approved,
        account_id: Some(account.id),
        ..link.clone()
    };
    settle(state, &approved).await?;
    audit::emit(
        audit::DEVICE_LINK_APPROVED,
        client,
        Some(account.id),
        link.device_label.as_deref().unwrap_or("-"),
    );
    Ok(())
}

/// Marks a link denied, so the waiting app is told rather than left to time
/// out.
pub(crate) async fn deny(
    state: &AppState,
    client: &ClientInfo,
    link: &DeviceLink,
    account: &Account,
) -> ApiResult<()> {
    let denied = DeviceLink {
        status: DeviceLinkStatus::Denied,
        account_id: Some(account.id),
        ..link.clone()
    };
    settle(state, &denied).await?;
    audit::emit(
        audit::DEVICE_LINK_DENIED,
        client,
        Some(account.id),
        link.device_label.as_deref().unwrap_or("-"),
    );
    Ok(())
}

/// Writes a settled link back, treating a row that has vanished as fine: the
/// app may have given up and the sweep taken it, which is not the user's
/// problem to hear about.
async fn settle(state: &AppState, link: &DeviceLink) -> ApiResult<()> {
    match state.device_links.update(link).await {
        Ok(()) | Err(StoreError::NotFound) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// Fetches a link for the website, refusing the ones a page must not act on.
///
/// Returns `Ok(None)` when the link is unknown or expired — the page words
/// both the same way, since a link id is not a secret and a "no such link"
/// page would say nothing a "that expired" page does not.
pub(crate) async fn usable(state: &AppState, id: DeviceLinkId) -> ApiResult<Option<DeviceLink>> {
    let Some(link) = state.device_links.get(id).await? else {
        return Ok(None);
    };
    if link.is_expired(Utc::now()) {
        let _ = state.device_links.delete(link.id).await;
        return Ok(None);
    }
    Ok(Some(link))
}

/// The browser path for a link. One definition, so the API response and the
/// website's own links cannot disagree.
pub(crate) fn verification_path(id: DeviceLinkId) -> String {
    format!("/link/{id}")
}

/// Best-effort removal of everything past its expiry. Logs and continues: a
/// full table is a housekeeping problem, and failing the user's sign-in over
/// one would be worse.
async fn sweep_expired(state: &AppState) {
    match state.device_links.delete_expired(Utc::now()).await {
        Ok(0) => {}
        Ok(removed) => tracing::debug!(removed, "swept expired device links"),
        Err(e) => tracing::warn!(error = %e, "failed to sweep expired device links"),
    }
}

/// Trims and bounds a client-supplied device label, dropping an empty one.
fn clean_label(label: Option<String>) -> Option<String> {
    let label = label?;
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_DEVICE_LABEL).collect())
}

/// A code the user can read off one screen and recognize on another.
fn new_user_code() -> String {
    let mut bytes = [0u8; USER_CODE_LEN];
    getrandom::fill(&mut bytes).expect("OS RNG unavailable");

    let mut code = String::with_capacity(USER_CODE_LEN + 1);
    for (index, byte) in bytes.iter().enumerate() {
        if index == USER_CODE_LEN / 2 {
            code.push('-');
        }
        // The alphabet's length does not divide 256, so this is very slightly
        // biased. It costs nothing to care about here: the code is a
        // comparison aid, not a secret, and nothing is looked up by it.
        code.push(USER_CODE_ALPHABET[*byte as usize % USER_CODE_ALPHABET.len()] as char);
    }
    code
}

/// A link id that is not a valid uuid never matched anything, so callers get
/// the same "no such link" answer rather than a parser's 400.
pub(crate) fn parse_link_id(raw: &str) -> Option<DeviceLinkId> {
    DeviceLinkId::parse_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_is_readable_and_split() {
        let code = new_user_code();
        assert_eq!(code.len(), USER_CODE_LEN + 1);
        assert_eq!(code.chars().nth(USER_CODE_LEN / 2), Some('-'));
        for c in code.chars().filter(|c| *c != '-') {
            assert!(
                USER_CODE_ALPHABET.contains(&(c as u8)),
                "unexpected character {c:?} in {code}",
            );
        }
    }

    #[test]
    fn user_codes_differ() {
        // Not a randomness test — just that the generator is not a constant.
        assert_ne!(new_user_code(), new_user_code());
    }

    #[test]
    fn labels_are_trimmed_bounded_and_optional() {
        assert_eq!(clean_label(None), None);
        assert_eq!(clean_label(Some("   ".into())), None);
        assert_eq!(
            clean_label(Some("  laptop  ".into())),
            Some("laptop".into())
        );

        let long = clean_label(Some("x".repeat(MAX_DEVICE_LABEL * 2))).unwrap();
        assert_eq!(long.chars().count(), MAX_DEVICE_LABEL);
    }

    #[test]
    fn label_bound_counts_characters_not_bytes() {
        // `take` on chars, so a multi-byte label is not cut mid-character.
        let long = clean_label(Some("é".repeat(MAX_DEVICE_LABEL * 2))).unwrap();
        assert_eq!(long.chars().count(), MAX_DEVICE_LABEL);
    }

    #[test]
    fn verification_path_is_a_rooted_path() {
        let path = verification_path(DeviceLinkId::nil());
        assert!(path.starts_with('/'));
        assert!(!path.starts_with("//"));
        assert!(!path.contains(':'));
    }
}
