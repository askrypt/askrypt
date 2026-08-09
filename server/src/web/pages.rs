//! The plain pages: landing and the HTML 404. The account tree lives in
//! [`crate::web::account`], the file manager in [`crate::web::vaults`].

use askama::Template;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::web::render::{Chrome, Page, Shell, with_cookies};
use crate::web::session::MaybeWebSession;

#[derive(Template)]
#[template(path = "landing.html")]
struct Landing {
    chrome: Chrome,
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
    let shell = Shell::build(&headers, session.email()).as_admin(session.is_admin());
    let (chrome, cookies) = shell.into_parts();
    with_cookies(Page(Landing { chrome }).into_response(), cookies)
}

/// Router fallback for paths that aren't pages.
///
/// A real handler rather than a bare [`crate::web::WebError`] so a signed-in
/// visitor still sees their own nav on a mistyped URL.
pub async fn not_found(session: MaybeWebSession, headers: HeaderMap) -> Response {
    let shell = Shell::build(&headers, session.email()).as_admin(session.is_admin());
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
