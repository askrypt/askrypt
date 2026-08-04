//! The plain pages: landing, account, and the HTML 404.

use askama::Template;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::store::Account;
use crate::web::render::{Chrome, Page, Shell, with_cookies};
use crate::web::session::{MaybeWebSession, WEB_SESSION_TTL_DAYS, WebSession};

#[derive(Template)]
#[template(path = "landing.html")]
struct Landing {
    chrome: Chrome,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    chrome: Chrome,
    email: String,
    providers: String,
    session_days: i64,
}

#[derive(Template)]
#[template(path = "error.html")]
struct NotFound {
    chrome: Chrome,
    status: u16,
    title: &'static str,
    message: String,
}

pub async fn landing(session: MaybeWebSession, headers: HeaderMap) -> Response {
    let shell = Shell::build(&headers, session.email());
    let (chrome, cookies) = shell.into_parts();
    with_cookies(Page(Landing { chrome }).into_response(), cookies)
}

/// The signed-in landing spot.
///
/// Phase 7.2 keeps this deliberately thin — email, how you sign in, and how
/// long this browser stays signed in. Changing the email or password,
/// reviewing devices and managing vault files are Phase 7.3 and 7.4.
pub async fn account(web: WebSession, headers: HeaderMap) -> Response {
    let email = web.account.email.clone();
    let shell = Shell::build(&headers, Some(email.clone()));
    let (chrome, cookies) = shell.into_parts();
    let page = AccountPage {
        chrome,
        providers: describe_providers(&web.account),
        email,
        session_days: WEB_SESSION_TTL_DAYS,
    };
    with_cookies(Page(page).into_response(), cookies)
}

/// Router fallback for paths that aren't pages.
///
/// A real handler rather than a bare [`crate::web::WebError`] so a signed-in
/// visitor still sees their own nav on a mistyped URL.
pub async fn not_found(session: MaybeWebSession, headers: HeaderMap) -> Response {
    let shell = Shell::build(&headers, session.email());
    let (chrome, cookies) = shell.into_parts();
    let error = crate::web::WebError::not_found();
    let page = Page(NotFound {
        chrome,
        status: error.status.as_u16(),
        title: error.title,
        message: error.message,
    });
    with_cookies((StatusCode::NOT_FOUND, page).into_response(), cookies)
}

fn describe_providers(account: &Account) -> String {
    match (
        account.password_hash.is_some(),
        account.google_sub.is_some(),
    ) {
        (true, true) => "password and Google".to_string(),
        (true, false) => "password".to_string(),
        (false, true) => "Google".to_string(),
        // Not reachable today: an account is created by one route or the
        // other, and neither leaves it with no way in.
        (false, false) => "no sign-in method".to_string(),
    }
}
