//! Browser sessions (plan Phase 7.2).
//!
//! A web login is not a second kind of session: it is the *same* opaque
//! token [`crate::auth`] already issues, carried in a cookie instead of an
//! `Authorization` header. One session model, one `SessionStore`, one
//! revocation path — the browser shows up in the profile's device list
//! beside the desktop and mobile apps and can be killed from there.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};

use crate::admin;
use crate::auth;
use crate::state::AppState;
use crate::web::error::WebError;
use crate::web::render::{HX_REDIRECT, is_htmx, with_cookies};

pub use crate::web::types::{AdminSession, MaybeWebSession, WebSession};

pub const SESSION_COOKIE: &str = "askrypt_session";

/// Browser sessions are deliberately shorter-lived than the 30-day API
/// sessions: a browser is likelier to be shared or left signed in, and
/// re-entering a password costs a web visitor far less than it costs a
/// syncing app.
pub const WEB_SESSION_TTL_DAYS: i64 = 7;

/// What the browser is called in the session list. Deliberately generic: a
/// user-agent string would say more about the visitor than the feature is
/// worth.
pub const WEB_SESSION_LABEL: &str = "Web browser";

pub const LOGIN_PATH: &str = "/login";

impl FromRequestParts<AppState> for WebSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        match lookup(&parts.headers, state).await {
            Some(session) => Ok(session),
            None => Err(redirect_to_login(&parts.headers)),
        }
    }
}

impl FromRequestParts<AppState> for AdminSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let web = WebSession::from_request_parts(parts, state).await?;
        if !web.is_admin {
            return Err(
                WebError::forbidden("This page is only available to administrators.")
                    .into_response(),
            );
        }
        Ok(Self(web))
    }
}

impl MaybeWebSession {
    pub fn email(&self) -> Option<String> {
        self.0.as_ref().map(|s| s.account.email.clone())
    }

    /// Whether the nav should offer the admin link on a page that renders
    /// for signed-out visitors too.
    pub fn is_admin(&self) -> bool {
        self.0.as_ref().is_some_and(|s| s.is_admin)
    }
}

impl FromRequestParts<AppState> for MaybeWebSession {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(lookup(&parts.headers, state).await))
    }
}

async fn lookup(headers: &HeaderMap, state: &AppState) -> Option<WebSession> {
    let token = cookie_value(headers, SESSION_COOKIE)?;
    // Same expiry handling, ban check and best-effort cleanup as the bearer
    // path.
    let (account, session) = auth::resolve_session(state, &token).await.ok()?;
    // A store failure here must not sign the visitor out — it costs them the
    // Users link, not the session.
    let is_admin = admin::is_admin(state, account.id).await.unwrap_or(false);
    Some(WebSession {
        account,
        session,
        is_admin,
    })
}

/// Rejection response for a missing, expired or revoked session.
///
/// Also clears the cookie: whatever was in it is worthless, and leaving it
/// there means paying for a store lookup on every subsequent request.
fn redirect_to_login(headers: &HeaderMap) -> Response {
    let response = if is_htmx(headers) {
        // htmx follows `HX-Redirect` on a 2xx. A 303 would be followed by
        // `fetch` and the sign-in page swapped into the fragment's slot.
        let mut response = StatusCode::OK.into_response();
        response
            .headers_mut()
            .insert(HX_REDIRECT, HeaderValue::from_static(LOGIN_PATH));
        response
    } else {
        Redirect::to(LOGIN_PATH).into_response()
    };
    with_cookies(response, vec![cleared_session_cookie()])
}

/// Reads one cookie out of a `Cookie` header.
///
/// Hand-rolled rather than via `axum-extra`'s `CookieJar` so that reading
/// and writing use the same handful of lines; the values we care about are
/// hex tokens, so there is no percent-decoding to get right.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().to_string())
}

/// Builds a hardened `Set-Cookie` value.
///
/// `Secure` is unconditional. Browsers make an exception for `localhost` and
/// `127.0.0.1`, treating them as secure contexts, so `cargo run` still works
/// without TLS — but any real deployment needs the reverse proxy from
/// `DEPLOY.md` in front, or nothing will stay signed in.
pub(crate) fn set_cookie(name: &str, value: &str, max_age_secs: i64) -> String {
    format!("{name}={value}; Max-Age={max_age_secs}; Path=/; HttpOnly; Secure; SameSite=Lax")
}

pub(crate) fn clear_cookie(name: &str) -> String {
    set_cookie(name, "", 0)
}

/// The `Set-Cookie` that signs a browser in.
pub fn session_cookie(token: &str, expires_at: DateTime<Utc>) -> String {
    let max_age = (expires_at - Utc::now()).num_seconds().max(0);
    set_cookie(SESSION_COOKIE, token, max_age)
}

pub fn cleared_session_cookie() -> String {
    clear_cookie(SESSION_COOKIE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_carries_every_hardening_attribute() {
        let cookie = session_cookie("deadbeef", Utc::now() + chrono::Duration::days(7));
        assert!(
            cookie.starts_with("askrypt_session=deadbeef; Max-Age=6"),
            "{cookie}"
        );
        for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(
                cookie.contains(attribute),
                "{attribute} missing from {cookie}"
            );
        }
    }

    #[test]
    fn clearing_expires_the_cookie_immediately() {
        assert!(cleared_session_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn cookie_values_are_read_out_of_a_multi_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; askrypt_session=abc123; askrypt_csrf=xyz"),
        );
        assert_eq!(
            cookie_value(&headers, SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            cookie_value(&headers, "askrypt_csrf").as_deref(),
            Some("xyz")
        );
        assert_eq!(cookie_value(&headers, "nope"), None);
    }
}
