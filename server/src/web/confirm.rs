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
//!   the address was. It carries a reCAPTCHA token where one is configured
//!   ([`crate::web::captcha`]): like `POST /forgot`, what it spends is mail
//!   to an address the submitter names. `POST /confirm` does not — it already
//!   holds a single-use token out of an inbox.
//!
//! [`notice`] also renders the "check your inbox" card that registration and
//! a blocked sign-in answer with.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::ClientInfo;
use crate::confirm;
use crate::hardening;
use crate::state::AppState;
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{Page, Shell, is_htmx, with_cookies};
use crate::web::session::LOGIN_PATH;
use crate::web::types::ConfirmPage;
use crate::web::{self, WebError, captcha};

pub use crate::web::types::{ConfirmInput, ConfirmKind, ConfirmNotice, ResendInput};

/// `GET /confirm/{token}` — the landing page of a mailed link.
pub async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    notice(&state, &headers, ConfirmKind::Confirm, String::new(), token)
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
            &state,
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
    // Before the address is looked up: what a resend spends is mail to
    // somebody else's inbox, and the per-account cooldown caps how often one
    // address can be hit, not how many addresses can be.
    if let Err(message) =
        captcha::check(&state, &client, &form.captcha_token, captcha::RESEND_ACTION).await
    {
        return Ok(refused(
            &state,
            &headers,
            form.email.trim().to_ascii_lowercase(),
            message.to_string(),
        ));
    }
    confirm::resend(&state, &client, &form.email).await?;
    Ok(notice(
        &state,
        &headers,
        ConfirmKind::Resent,
        form.email.trim().to_ascii_lowercase(),
        String::new(),
    ))
}

/// The card a resend the anti-bot check turned away comes back as: the same
/// form, the reason, and no claim that anything was sent — because nothing
/// was, and no address was even looked up.
fn refused(state: &AppState, headers: &HeaderMap, email: String, message: String) -> Response {
    render(
        state,
        headers,
        ConfirmKind::Refused,
        email,
        String::new(),
        Some(message),
    )
}

/// Renders the confirmation card: the fragment alone for htmx, which swaps
/// it in for the card that was submitted, and the whole page otherwise.
///
/// Answers 200 for the same reason `auth::rejected` does: htmx swaps only
/// successful responses, and all of these are normal outcomes.
pub(crate) fn notice(
    state: &AppState,
    headers: &HeaderMap,
    kind: ConfirmKind,
    email: String,
    token: String,
) -> Response {
    render(state, headers, kind, email, token, None)
}

fn render(
    state: &AppState,
    headers: &HeaderMap,
    kind: ConfirmKind,
    email: String,
    token: String,
    error: Option<String>,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, None).into_parts();
    let notice = ConfirmNotice {
        kind,
        csrf: chrome.csrf.clone(),
        email,
        token,
        error,
        // Asked of the verifier seam, like `AuthForm::with_captcha`, so a
        // page can only offer a field this server would check.
        captcha_key: state.captcha.site_key().map(str::to_owned),
        captcha_action: captcha::RESEND_ACTION,
    };
    // Only the card that renders the resend form loads Google's script, so
    // only it may widen the policy.
    let relaxed = hardening::RelaxedCsp {
        captcha: notice.captcha_field().is_some(),
        google: false,
    };
    let body = if is_htmx(headers) {
        Page(notice).into_response()
    } else {
        Page(ConfirmPage { chrome, notice }).into_response()
    };
    with_cookies(web::relax_csp(body, relaxed), cookies)
}

impl ConfirmNotice {
    /// The site key the hidden captcha field is rendered with, or `None` when
    /// this card has no form that needs one — or no captcha is configured.
    ///
    /// The template and the CSP decision read the *same* answer, for the
    /// reason [`crate::web::reset::ResetCard::captcha_field`] does.
    /// [`ConfirmKind::Confirm`] carries a mailed token instead of a score, so
    /// it keeps the strict policy.
    pub(crate) fn captcha_field(&self) -> Option<&str> {
        match self.kind {
            // Every kind but this one renders the resend form below the
            // message; `Confirm` renders the button that spends a link.
            ConfirmKind::Confirm => None,
            _ => self.captcha_key.as_deref(),
        }
    }
}
