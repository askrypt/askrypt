//! "Sign in with Google" on the website (plan Phase 13).
//!
//! The browser half of what `/api/v1/auth/google` has always done for native
//! clients, and it reuses that path whole: Google Identity Services mints an
//! **ID token** in the page, this handler verifies it through the same
//! [`crate::store::IdTokenVerifier`] seam and hands the claims to
//! [`crate::auth::upsert_google_account`], which is where creating, linking,
//! the registration switch and the ban check all live. Nothing about the
//! account rules is re-implemented here — this module is the browser's share
//! of the work and nothing else.
//!
//! ## Why an ID token in a same-origin form, and not the redirect flow
//!
//! Google offers to POST the credential to us itself (`ux_mode: redirect`).
//! That arrives as a **cross-site** form post, which means the browser sends
//! none of our `SameSite=Lax` cookies — including the CSRF cookie — so the
//! form would have to be exempted from [`crate::web::csrf`] and re-protected
//! with Google's own `g_csrf_token`, a second CSRF scheme guarding the one
//! endpoint that hands out sessions. Signing in through a popup and posting
//! the credential to our own origin keeps the site down to one CSRF scheme,
//! and this form is checked by exactly the same [`CsrfForm`] every other
//! mutation on the site goes through.
//!
//! The cost is one relaxed header: a popup cannot answer its opener under a
//! plain `same-origin` opener policy, so these two pages send
//! `Cross-Origin-Opener-Policy: same-origin-allow-popups` — see the constants
//! beside [`crate::hardening::policy`].
//!
//! An authorization-code flow would need a **client secret** and a token
//! exchange; an ID token needs neither, and the server already knows how to
//! verify one.
//!
//! ## What it does not do
//!
//! There is no `GET` here. A sign-in that a link could trigger is a sign-in a
//! prefetcher or a link checker can trigger, and this one mints a session.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::audit::{self, ClientInfo};
use crate::auth;
use crate::devicelink;
use crate::error::ApiError;
use crate::state::AppState;
use crate::web::auth::{after_auth, rejected, sign_in};
use crate::web::csrf::CsrfForm;
use crate::web::error::is_backend_failure;
use crate::web::render::with_cookies;
use crate::web::types::AuthForm;
use crate::web::{WebError, types::GoogleCredential};

pub use crate::web::types::GoogleCredential as Credential;

/// Wording on Google's own button for the sign-in form.
pub const SIGN_IN_TEXT: &str = "signin_with";

/// Wording on the registration form. Cosmetic only — a Google sign-in
/// creates the account when there isn't one, whichever page it started from.
pub const SIGN_UP_TEXT: &str = "signup_with";

/// Shown when the page sent no credential at all — the scriptless case, and
/// the one a visitor can do something about. Worded like the captcha's twin
/// for the same reason.
const NO_CREDENTIAL: &str = "Google sign-in did not complete. Check that \
JavaScript is enabled, then try again — or sign in with your email and \
password.";

/// Shown when a credential arrived and did not hold up. Never says *why*: a
/// bad signature, a wrong audience and an expired token are all the same
/// event to the visitor, and telling them apart only helps whoever is probing.
const REJECTED: &str = "We could not verify that Google sign-in. Please try \
again.";

/// `POST /auth/google` — sign in (or register) with a Google ID token minted
/// by the button on the sign-in or registration page.
///
/// Answers exactly like the password form does: a 303 to wherever the visitor
/// was headed, or the sign-in form re-rendered at 200 with a sentence on it.
/// The form it re-renders is always the *sign-in* one, whichever page the
/// button was on — the address is already known to Google, so there is
/// nothing for a registration form to collect that this refusal did not
/// already have.
pub async fn submit(
    State(state): State<AppState>,
    client: ClientInfo,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<GoogleCredential>,
) -> Response {
    let link = form.link.as_deref().and_then(devicelink::parse_link_id);
    let refuse = |message: &str| {
        rejected(
            &state,
            &headers,
            AuthForm::login,
            String::new(),
            message.to_string(),
            link,
            false,
        )
    };

    if form.credential.trim().is_empty() {
        return refuse(NO_CREDENTIAL);
    }

    let claims = match state.id_verifier.verify(&form.credential).await {
        Ok(claims) => claims,
        Err(error) => {
            // The same audit event the JSON handler emits, so one query
            // covers both surfaces.
            audit::emit(audit::LOGIN_GOOGLE_DENIED, &client, None, "invalid_token");
            tracing::debug!(%error, "browser google sign-in presented a bad token");
            return refuse(REJECTED);
        }
    };

    let (account, outcome) = match auth::upsert_google_account(&state, &client, claims).await {
        Ok(pair) => pair,
        // Already audited by `upsert_google_account`, which is also where the
        // wording comes from: a ban, a closed server and an address linked to
        // a different Google account each say their own piece.
        Err(error) => return refused(&state, &headers, error, link),
    };

    match sign_in(&state, &client, &account, audit::LOGIN_GOOGLE_OK, outcome).await {
        Ok(cookies) => with_cookies(Redirect::to(&after_auth(link)).into_response(), cookies),
        Err(error) => error.into_response(),
    }
}

/// Turns an [`ApiError`] from the shared account rules into the answer this
/// form should give.
///
/// A refusal the visitor can act on is a sentence on the form they were just
/// looking at; a backend failure is the error page, because re-rendering the
/// form under it would invite them to try again into a server that is down.
/// Same split as [`crate::web::vaults::refused`], and it uses the same
/// predicate rather than a second reading of the status.
fn refused(
    state: &AppState,
    headers: &HeaderMap,
    error: ApiError,
    link: Option<crate::store::DeviceLinkId>,
) -> Response {
    if is_backend_failure(error.status) {
        return WebError::from(error).into_response();
    }
    rejected(
        state,
        headers,
        AuthForm::login,
        String::new(),
        error.message,
        link,
        false,
    )
}
