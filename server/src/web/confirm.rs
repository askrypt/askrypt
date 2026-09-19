//! The email-confirmation pages (plan Phase 15).
//!
//! The rules live in [`crate::confirm`]. This module is the presentation half,
//! as [`crate::web::auth`] is over [`crate::auth`]:
//!
//! - `GET /confirm/{token}` is where the mailed link lands. It shows one
//!   button and does not confirm: mail scanners and link previews open
//!   links on their own, and a GET that confirmed would let them use the
//!   link up.
//! - `POST /confirm` does the confirming, then sends the browser to sign in.
//!   Confirming does not sign anyone in. The link proves the inbox, not the
//!   password.
//! - `POST /confirm/resend` mails a new link and answers the same whatever
//!   the address was.
//!
//! [`notice`] also renders the "check your inbox" card that registration and
//! a blocked sign-in answer with.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::ClientInfo;
use crate::confirm;
use crate::state::AppState;
use crate::web::WebError;
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{Page, Shell, is_htmx, with_cookies};
use crate::web::session::LOGIN_PATH;
use crate::web::types::ConfirmPage;

pub use crate::web::types::{ConfirmInput, ConfirmKind, ConfirmNotice, ResendInput};

/// `GET /confirm/{token}` — the landing page of a mailed link.
pub async fn page(headers: HeaderMap, Path(token): Path<String>) -> Response {
    notice(&headers, ConfirmKind::Confirm, String::new(), token)
}

/// `POST /confirm` — uses the link.
pub async fn submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<ConfirmInput>,
) -> Result<Response, WebError> {
    match confirm::confirm_token(&state, &client, &form.token).await {
        Ok(_) => Ok(with_cookies(
            Redirect::to(LOGIN_PATH).into_response(),
            vec![flash::set(Flash::EmailConfirmed)],
        )),
        Err(err) if err.code == "invalid_confirmation" => Ok(notice(
            &headers,
            ConfirmKind::Invalid,
            String::new(),
            String::new(),
        )),
        Err(err) => Err(err.into()),
    }
}

/// `POST /confirm/resend` — mails a new link if the address is waiting for
/// one. The answer never says whether it was.
pub async fn resend(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<ResendInput>,
) -> Result<Response, WebError> {
    confirm::resend(&state, &client, &form.email).await?;
    Ok(notice(
        &headers,
        ConfirmKind::Resent,
        form.email.trim().to_ascii_lowercase(),
        String::new(),
    ))
}

/// Renders the confirmation card: the fragment alone for htmx, which swaps
/// it in for the card that was submitted, and the whole page otherwise.
///
/// Answers 200 for the same reason `auth::rejected` does: htmx swaps only
/// successful responses, and all of these are normal outcomes.
pub(crate) fn notice(
    headers: &HeaderMap,
    kind: ConfirmKind,
    email: String,
    token: String,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, None).into_parts();
    let notice = ConfirmNotice {
        kind,
        csrf: chrome.csrf.clone(),
        email,
        token,
    };
    let body = if is_htmx(headers) {
        Page(notice).into_response()
    } else {
        Page(ConfirmPage { chrome, notice }).into_response()
    };
    with_cookies(body, cookies)
}
