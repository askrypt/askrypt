//! CSRF protection for the cookie-authenticated HTML layer.
//!
//! Applies to cookie requests only: a bearer token is never attached by the
//! browser on its own, so `/api/v1` is not CSRF-able and must not be
//! burdened with any of this.
//!
//! ## Why a random token rather than one derived from the session
//!
//! The obvious trick — hashing the session token into a CSRF token —
//! collides with [`crate::profile`], which identifies sessions to clients as
//! `sha256(token)` and *publishes* that digest in the device list. A scheme
//! that derived the CSRF token the same way would be handing every listed
//! session id out as a valid token. So this is a plain double-submit
//! cookie: 256 random bits in an `HttpOnly` cookie, echoed in a hidden form
//! field, compared on every mutation. It works signed-out (sign-in and
//! registration are themselves worth protecting) as well as signed-in.
//!
//! `Origin`/`Referer` are checked as a backstop, and `SameSite=Lax` on the
//! session cookie is a third layer.

use std::collections::HashMap;

use axum::extract::{FromRequest, Multipart, RawForm, Request};
use axum::http::{HeaderMap, header};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::web::error::WebError;
use crate::web::session::{cookie_value, set_cookie};

pub const CSRF_COOKIE: &str = "askrypt_csrf";

/// The hidden input every mutating form carries.
pub const CSRF_FIELD: &str = "csrf";

/// Long enough that a form left open over a coffee break still submits,
/// short enough that an abandoned public-terminal token doesn't linger.
const CSRF_TTL_SECS: i64 = 12 * 60 * 60;

/// Reads the visitor's CSRF token, minting one if they don't have it yet.
///
/// Returns the token to embed in forms and, when it was freshly minted, the
/// `Set-Cookie` the response has to carry.
pub fn ensure_token(headers: &HeaderMap) -> (String, Option<String>) {
    match cookie_value(headers, CSRF_COOKIE).filter(|token| token.len() == TOKEN_HEX_LEN) {
        Some(token) => (token, None),
        None => {
            let token = new_token();
            let cookie = set_cookie(CSRF_COOKIE, &token, CSRF_TTL_SECS);
            (token, Some(cookie))
        }
    }
}

/// Issues a fresh token, discarding any existing one. Called when the
/// session changes hands (sign-in, sign-out) so a token minted before the
/// privilege change can't be replayed after it.
pub fn rotate() -> (String, String) {
    let token = new_token();
    let cookie = set_cookie(CSRF_COOKIE, &token, CSRF_TTL_SECS);
    (token, cookie)
}

const TOKEN_HEX_LEN: usize = 64;

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Form extractor that refuses to hand over `T` until the request has proven
/// it wasn't made by another site.
///
/// Use it for *every* mutating HTML route; there is no way to read the form
/// body without going through the check.
pub struct CsrfForm<T>(pub T);

#[derive(Deserialize)]
struct CsrfField {
    csrf: String,
}

impl<T, S> FromRequest<S> for CsrfForm<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let cookie = cookie_value(request.headers(), CSRF_COOKIE);
        check_origin(request.headers())?;

        let RawForm(body) = RawForm::from_request(request, state)
            .await
            .map_err(|_| WebError::bad_request("That form could not be read."))?;

        let field: CsrfField = serde_urlencoded::from_bytes(&body).map_err(|_| csrf_rejected())?;
        let cookie = cookie.ok_or_else(csrf_rejected)?;
        if !constant_time_eq(cookie.as_bytes(), field.csrf.as_bytes()) {
            return Err(csrf_rejected());
        }

        let value = serde_urlencoded::from_bytes(&body)
            .map_err(|_| WebError::bad_request("That form was missing something."))?;
        Ok(Self(value))
    }
}

/// A `multipart/form-data` submission whose CSRF token has been checked.
///
/// The file upload in Phase 7.4 can't go through [`CsrfForm`] — a file is
/// not urlencoded — so this is its twin, and the same rule holds: it is the
/// only way to read a multipart body.
///
/// The token has to arrive *before* any other part. That is how the
/// templates are written (the hidden input precedes the file input), and it
/// means a forged cross-origin upload is refused before its megabytes are
/// buffered rather than after.
pub struct CsrfMultipart(pub MultipartForm);

/// A whole multipart body, read into memory: the named text fields plus at
/// most one file. Vault files are capped at
/// [`crate::vaults::MAX_VAULT_BYTES`] by the route's body limit, so there is
/// nothing here worth streaming to disk.
#[derive(Default)]
pub struct MultipartForm {
    fields: HashMap<String, String>,
    /// The uploaded file's own name, as the browser reported it.
    pub file_name: Option<String>,
    pub file: Vec<u8>,
}

/// Cap on a text field. Names and ETags are the only ones the site sends;
/// anything larger is a client that has lost the plot.
const MAX_TEXT_FIELD_BYTES: usize = 1024;

impl MultipartForm {
    /// A trimmed text field, or `""` when it wasn't sent.
    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", |value| value.trim())
    }
}

impl<S> FromRequest<S> for CsrfMultipart
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let cookie = cookie_value(request.headers(), CSRF_COOKIE);
        check_origin(request.headers())?;

        let mut multipart = Multipart::from_request(request, state)
            .await
            .map_err(|_| WebError::bad_request("That upload could not be read."))?;
        let mut form = MultipartForm::default();
        let mut verified = false;
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|err| multipart_rejected(&err))?
        {
            let name = field.name().unwrap_or_default().to_string();
            let file_name = field.file_name().map(str::to_string);
            if name == CSRF_FIELD {
                let token = field.text().await.map_err(|err| multipart_rejected(&err))?;
                let cookie = cookie.as_deref().ok_or_else(csrf_rejected)?;
                if !constant_time_eq(cookie.as_bytes(), token.as_bytes()) {
                    return Err(csrf_rejected());
                }
                verified = true;
                continue;
            }
            if !verified {
                return Err(csrf_rejected());
            }
            match file_name {
                Some(file_name) => {
                    let bytes = field
                        .bytes()
                        .await
                        .map_err(|err| multipart_rejected(&err))?;
                    form.file_name = Some(file_name);
                    form.file = bytes.to_vec();
                }
                None => {
                    let text = field.text().await.map_err(|err| multipart_rejected(&err))?;
                    if text.len() > MAX_TEXT_FIELD_BYTES {
                        return Err(WebError::bad_request("That form field is too long."));
                    }
                    form.fields.insert(name, text);
                }
            }
        }
        if !verified {
            return Err(csrf_rejected());
        }
        Ok(Self(form))
    }
}

/// Turns a multipart read failure into a page.
///
/// A body over the limit surfaces here rather than at the outer body-limit
/// layer, because the multipart reader is what hits it first.
fn multipart_rejected(err: &axum::extract::multipart::MultipartError) -> WebError {
    let status = err.status();
    if status == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return WebError::new(
            status,
            "That file is too large",
            format!(
                "Vault files are limited to {} MiB.",
                crate::vaults::MAX_VAULT_BYTES / (1024 * 1024)
            ),
        );
    }
    WebError::bad_request("That upload could not be read.")
}

fn csrf_rejected() -> WebError {
    WebError::forbidden(
        "That form has expired or came from somewhere else. Reload the page and try again.",
    )
}

/// `Origin`/`Referer` backstop.
///
/// Only enforced when the browser sent one: some clients omit both, and the
/// double-submit token is the real defense — this catches the case where a
/// token leaked but the request still came from another origin.
///
/// Compares against the `Host` header, which the reverse proxy in
/// `deploy/Caddyfile` passes through unchanged.
fn check_origin(headers: &HeaderMap) -> Result<(), WebError> {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return Ok(());
    };
    let stated = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    let Some(stated) = stated else {
        return Ok(());
    };
    if host_of(stated).is_some_and(|origin_host| origin_host == host) {
        Ok(())
    } else {
        Err(WebError::forbidden(
            "That request came from another site and was refused.",
        ))
    }
}

/// Authority component of an absolute URL, without scheme, path or fragment.
fn host_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|s| !s.is_empty())?;
    Some(authority)
}

/// Comparison whose running time doesn't depend on where the first
/// difference is. Both inputs are fixed-length hex here, so length alone
/// leaks nothing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::HeaderValue;

    fn headers_with(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn tokens_are_long_and_unique() {
        let token = new_token();
        assert_eq!(token.len(), TOKEN_HEX_LEN);
        assert_ne!(token, new_token());
    }

    #[test]
    fn a_token_is_minted_once_and_then_reused() {
        let (token, cookie) = ensure_token(&HeaderMap::new());
        assert!(cookie.unwrap().contains("HttpOnly"));

        let headers = headers_with(&[(header::COOKIE, &format!("{CSRF_COOKIE}={token}"))]);
        let (same, cookie) = ensure_token(&headers);
        assert_eq!(same, token);
        assert!(cookie.is_none(), "an existing token must not be replaced");
    }

    #[test]
    fn a_truncated_cookie_is_replaced_rather_than_trusted() {
        let headers = headers_with(&[(header::COOKIE, &format!("{CSRF_COOKIE}=short"))]);
        let (token, cookie) = ensure_token(&headers);
        assert_eq!(token.len(), TOKEN_HEX_LEN);
        assert!(cookie.is_some());
    }

    #[test]
    fn same_origin_passes_and_a_foreign_one_does_not() {
        let same = headers_with(&[
            (header::HOST, "askrypt.example"),
            (header::ORIGIN, "https://askrypt.example"),
        ]);
        assert!(check_origin(&same).is_ok());

        let foreign = headers_with(&[
            (header::HOST, "askrypt.example"),
            (header::ORIGIN, "https://evil.example"),
        ]);
        assert!(check_origin(&foreign).is_err());

        // A prefix match must not be enough.
        let lookalike = headers_with(&[
            (header::HOST, "askrypt.example"),
            (header::ORIGIN, "https://askrypt.example.evil.test"),
        ]);
        assert!(check_origin(&lookalike).is_err());
    }

    #[test]
    fn a_referer_is_accepted_when_there_is_no_origin() {
        let headers = headers_with(&[
            (header::HOST, "askrypt.example"),
            (
                header::REFERER,
                "https://askrypt.example/login?next=/account",
            ),
        ]);
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn missing_origin_and_referer_fall_through_to_the_token() {
        let headers = headers_with(&[(header::HOST, "askrypt.example")]);
        assert!(check_origin(&headers).is_ok());
    }

    #[test]
    fn constant_time_eq_still_compares_correctly() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
