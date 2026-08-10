//! Turning askama templates into responses, plus the shared page chrome.
//!
//! askama 0.16 has no axum integration of its own (`askama_axum` is gone),
//! so [`Page`] is the one place that renders a [`Template`] and decides what
//! a rendering failure looks like.

use askama::Template;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};

use crate::web::csrf;
use crate::web::flash;

/// Set by htmx on every request it makes.
pub const HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");

/// Tells htmx to navigate the whole window. Used where a swap would leave
/// stale chrome behind — a changed email in the nav, or a session that no
/// longer exists.
pub const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

const HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");

/// Last-resort body when a template fails to render. Deliberately not a
/// template itself.
const RENDER_FAILURE: &str = "<!doctype html><html lang=\"en\"><head>\
<meta charset=\"utf-8\"><title>Askrypt</title></head><body>\
<h1>Something went wrong</h1><p>The page could not be rendered.</p>\
</body></html>";

/// Renders `T` as an HTML response.
pub struct Page<T>(pub T);

impl<T: Template> IntoResponse for Page<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => ([(header::CONTENT_TYPE, HTML)], html).into_response(),
            Err(error) => {
                // A template that doesn't render is a bug in *our* markup,
                // not something the visitor did — log it with detail and
                // show them nothing but an apology.
                tracing::error!(%error, "template rendering failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, HTML)],
                    RENDER_FAILURE,
                )
                    .into_response()
            }
        }
    }
}

/// True when htmx made this request, meaning the handler should answer with
/// a fragment instead of a whole page.
///
/// Nothing may *depend* on this being true: with JavaScript disabled the
/// same form posts normally and gets the full page back.
pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get(HX_REQUEST).is_some_and(|value| value == "true")
}

/// Everything `layout.html` needs. Every page template carries one.
pub struct Chrome {
    /// Signed-in address, shown in the nav; `None` when signed out.
    pub email: Option<String>,
    /// Token embedded in every mutating form on the page.
    pub csrf: String,
    /// One-shot message carried over from the previous request.
    pub flash: Option<&'static str>,
    /// Whether the nav offers "Sign in" / "Create account". Off on the auth
    /// pages themselves, and on error pages, where the signed-in state
    /// isn't known.
    pub auth_links: bool,
    /// Whether the nav offers the admin Users link. Defaults to off, so a
    /// page that forgets to set it hides the link rather than advertising a
    /// route the visitor would only be refused at.
    pub is_admin: bool,
}

impl Chrome {
    /// Chrome for a response rendered outside a normal page handler — error
    /// pages produced by an extractor rejection, which have no session
    /// lookup and no CSRF cookie to echo.
    pub fn anonymous() -> Self {
        Self {
            email: None,
            csrf: String::new(),
            flash: None,
            auth_links: false,
            is_admin: false,
        }
    }
}

/// Page chrome plus the cookies the response has to carry back: a freshly
/// minted CSRF cookie when the visitor didn't have one, and the expiry of a
/// flash that has now been shown.
pub struct Shell {
    pub chrome: Chrome,
    cookies: Vec<String>,
}

impl Shell {
    pub fn build(headers: &HeaderMap, email: Option<String>) -> Self {
        let mut cookies = Vec::new();
        let (csrf, minted) = csrf::ensure_token(headers);
        cookies.extend(minted);
        let (flash, cleared) = flash::take(headers);
        cookies.extend(cleared);
        Self {
            chrome: Chrome {
                email,
                csrf,
                flash: flash.map(flash::Flash::message),
                auth_links: true,
                is_admin: false,
            },
            cookies,
        }
    }

    /// Drops the "Sign in" / "Create account" nav links — used on the auth
    /// pages, where they would point at the page you are already on.
    pub fn without_auth_links(mut self) -> Self {
        self.chrome.auth_links = false;
        self
    }

    /// Offers the admin Users link in the nav. A chained setter rather than
    /// another `build` argument, because most callers have nothing to say
    /// about it and the default is the safe one.
    pub fn as_admin(mut self, is_admin: bool) -> Self {
        self.chrome.is_admin = is_admin;
        self
    }

    /// Splits into the chrome a template needs and the cookies the response
    /// has to carry. Use when a template wants the chrome moved into it and
    /// the cookies attached afterwards.
    pub fn into_parts(self) -> (Chrome, Vec<String>) {
        (self.chrome, self.cookies)
    }

    /// Finishes a response built from this shell's chrome, attaching the
    /// cookies the chrome implies.
    pub fn finish(self, response: impl IntoResponse) -> Response {
        with_cookies(response.into_response(), self.cookies)
    }
}

/// Sends the browser to `location`, whether or not htmx made the request.
///
/// A plain POST gets the usual POST-redirect-GET 303. htmx gets `HX-Redirect`
/// instead: a 303 would be followed by `fetch` and the whole page swapped
/// into whatever slot the fragment was headed for. Used after any change the
/// surrounding chrome depends on.
/// `location` is `&str` rather than `&'static str` because a device-link
/// sign-in redirects to a path carrying the link's id. Every other caller
/// passes a literal and coerces. A location that cannot be a header value at
/// all falls back to `/` — the only way to get one is a bug here, and sending
/// the visitor home beats a 500.
pub fn redirect_either_way(headers: &HeaderMap, location: &str, cookies: Vec<String>) -> Response {
    let response = if is_htmx(headers) {
        let mut response = StatusCode::OK.into_response();
        response.headers_mut().insert(
            HX_REDIRECT,
            HeaderValue::from_str(location).unwrap_or(HeaderValue::from_static("/")),
        );
        response
    } else {
        Redirect::to(location).into_response()
    };
    with_cookies(response, cookies)
}

/// Timestamps as the pages show them: UTC, to the minute. No locale
/// handling, and deliberately no client-side clock code — the CSP forbids
/// the script that would do it.
pub fn timestamp(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// Appends `Set-Cookie` headers to a finished response.
pub fn with_cookies(mut response: Response, cookies: Vec<String>) -> Response {
    let headers = response.headers_mut();
    for cookie in cookies {
        match HeaderValue::from_str(&cookie) {
            Ok(value) => {
                headers.append(header::SET_COOKIE, value);
            }
            // Every cookie we build is ASCII by construction, so this is
            // unreachable; dropping it beats panicking in a handler.
            Err(error) => tracing::error!(%error, "refusing to send a malformed cookie"),
        }
    }
    response
}
