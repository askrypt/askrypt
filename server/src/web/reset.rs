//! The password-reset pages (plan Phase 16).
//!
//! The rules live in [`crate::reset`]; this module is the presentation half,
//! and mirrors [`crate::web::confirm`] page for page:
//!
//! - `GET /forgot` asks for an address, `POST /forgot` answers with the same
//!   sentence whatever the address was.
//! - `GET /reset/{token}` is where the mailed link lands. It shows the
//!   new-password form and *checks nothing*: a link opened by a mail scanner
//!   must still work for the person it was sent to, and a GET that spent the
//!   token would let a scanner use it up. Nothing is read or written until
//!   the form is posted back.
//! - `POST /reset` sets the password, then sends the browser to sign in.
//!   A reset signs nobody in: the link proves the inbox, and the new password
//!   is there to be typed once.
//!
//! `POST /forgot` carries a reCAPTCHA token where one is configured
//! ([`crate::web::captcha`]), because it is the form that sends mail to an
//! address the submitter names. `POST /reset` does not: it already holds a
//! single-use token out of an inbox.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::ClientInfo;
use crate::hardening;
use crate::reset;
use crate::state::AppState;
use crate::web::csrf::CsrfForm;
use crate::web::flash::{self, Flash};
use crate::web::render::{Page, Shell, is_htmx, with_cookies};
use crate::web::session::LOGIN_PATH;
use crate::web::types::ResetPage;
use crate::web::{self, WebError, captcha};

pub use crate::web::types::{ForgotInput, ResetCard, ResetInput, ResetKind};

impl ResetCard {
    /// The site key the hidden captcha field is rendered with, or `None`
    /// when this card has no form that needs one — or no captcha is
    /// configured at all.
    ///
    /// The template and the CSP decision above read the *same* answer, so a
    /// page can never widen its policy without rendering the field, or render
    /// a field the policy would then block. [`ResetKind::Choose`] posts a
    /// mailed token instead of a score, and so keeps the strict policy.
    pub(crate) fn captcha_field(&self) -> Option<&str> {
        match self.kind {
            ResetKind::Ask | ResetKind::Invalid => self.captcha_key.as_deref(),
            ResetKind::Sent | ResetKind::Choose => None,
        }
    }
}

/// `GET /forgot` — the "which address?" form.
pub async fn forgot_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    card(
        &state,
        &headers,
        ResetKind::Ask,
        String::new(),
        String::new(),
        None,
    )
}

/// `POST /forgot` — mails a link if the address can have one. The answer
/// never says whether it did.
pub async fn forgot_submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<ForgotInput>,
) -> Result<Response, WebError> {
    // Before the address is looked up, for the reason the sign-in form checks
    // before the password: what this form spends is somebody else's inbox.
    if let Err(message) =
        captcha::check(&state, &client, &form.captcha_token, captcha::FORGOT_ACTION).await
    {
        return Ok(card(
            &state,
            &headers,
            ResetKind::Ask,
            form.email.trim().to_ascii_lowercase(),
            String::new(),
            Some(message.to_string()),
        ));
    }
    reset::request_reset(&state, &client, &form.email).await?;
    Ok(card(
        &state,
        &headers,
        ResetKind::Sent,
        form.email.trim().to_ascii_lowercase(),
        String::new(),
        None,
    ))
}

/// `GET /reset/{token}` — the landing page of a mailed link.
pub async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    card(
        &state,
        &headers,
        ResetKind::Choose,
        String::new(),
        token,
        None,
    )
}

/// `POST /reset` — spends the link and sets the password.
pub async fn submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<ResetInput>,
) -> Result<Response, WebError> {
    match reset::complete_reset(&state, &client, &form.token, form.password).await {
        Ok(_) => Ok(with_cookies(
            Redirect::to(LOGIN_PATH).into_response(),
            vec![flash::set(Flash::PasswordReset)],
        )),
        // The link is gone: there is nothing left to re-submit, so the form
        // goes with it.
        Err(err) if err.code == "invalid_reset" => Ok(card(
            &state,
            &headers,
            ResetKind::Invalid,
            String::new(),
            String::new(),
            None,
        )),
        // The link is still good — a refused password (too short) has not
        // spent it. Re-render the form with the token and say why.
        Err(err) if err.code == "invalid_password" => Ok(card(
            &state,
            &headers,
            ResetKind::Choose,
            String::new(),
            form.token,
            Some(err.message),
        )),
        Err(err) => Err(err.into()),
    }
}

/// Renders the reset card: the fragment alone for htmx, which swaps it in for
/// the card that was submitted, and the whole page otherwise.
///
/// Answers 200 for the reason [`crate::web::auth::rejected`] does: htmx swaps
/// only successful responses, and every outcome here is a normal one.
fn card(
    state: &AppState,
    headers: &HeaderMap,
    kind: ResetKind,
    email: String,
    token: String,
    error: Option<String>,
) -> Response {
    let (chrome, cookies) = Shell::build(headers, None).into_parts();
    let card = ResetCard {
        kind,
        csrf: chrome.csrf.clone(),
        email,
        token,
        error,
        // Asked of the verifier seam, like `AuthForm::with_captcha`, so a
        // page can only offer a field this server would check.
        captcha_key: state.captcha.site_key().map(str::to_owned),
        captcha_action: captcha::FORGOT_ACTION,
    };
    // Only the kinds that render the request form load Google's script, so
    // only they may widen the policy. `POST /reset`'s own card keeps the
    // strict one.
    let relaxed = hardening::RelaxedCsp {
        captcha: card.captcha_field().is_some(),
        google: false,
    };
    let body = if is_htmx(headers) {
        Page(card).into_response()
    } else {
        Page(ResetPage { chrome, card }).into_response()
    };
    with_cookies(web::relax_csp(body, relaxed), cookies)
}
