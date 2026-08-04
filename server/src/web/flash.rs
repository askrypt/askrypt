//! One-shot messages carried across a redirect.
//!
//! The cookie holds a *code*, never text: the message strings live in Rust,
//! so nothing a request can influence is ever echoed back into a page, and
//! there is no encoding to get right.

use axum::http::HeaderMap;

use crate::web::session::{clear_cookie, cookie_value, set_cookie};

pub const FLASH_COOKIE: &str = "askrypt_flash";

/// Long enough to survive the redirect it was set on, short enough that a
/// stale one never surfaces later.
const FLASH_TTL_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flash {
    AccountCreated,
    SignedOut,
    AlreadySignedIn,
}

impl Flash {
    fn code(self) -> &'static str {
        match self {
            Self::AccountCreated => "created",
            Self::SignedOut => "out",
            Self::AlreadySignedIn => "in",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "created" => Some(Self::AccountCreated),
            "out" => Some(Self::SignedOut),
            "in" => Some(Self::AlreadySignedIn),
            _ => None,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::AccountCreated => "Account created. You're signed in.",
            Self::SignedOut => "You're signed out.",
            Self::AlreadySignedIn => "You're already signed in.",
        }
    }
}

/// The `Set-Cookie` that carries `flash` to the next request.
pub fn set(flash: Flash) -> String {
    set_cookie(FLASH_COOKIE, flash.code(), FLASH_TTL_SECS)
}

/// Reads and consumes the pending flash, returning it plus the `Set-Cookie`
/// that clears it so the same message is never shown twice.
pub fn take(headers: &HeaderMap) -> (Option<Flash>, Option<String>) {
    match cookie_value(headers, FLASH_COOKIE)
        .as_deref()
        .and_then(Flash::from_code)
    {
        Some(flash) => (Some(flash), Some(clear_cookie(FLASH_COOKIE))),
        // An unrecognized value is left alone: it expires on its own, and
        // clearing it would be a write on every page view.
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::{HeaderValue, header};

    #[test]
    fn every_variant_round_trips_through_its_code() {
        for flash in [
            Flash::AccountCreated,
            Flash::SignedOut,
            Flash::AlreadySignedIn,
        ] {
            assert_eq!(Flash::from_code(flash.code()), Some(flash));
        }
    }

    #[test]
    fn taking_a_flash_also_clears_it() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("askrypt_flash=out"),
        );
        let (flash, cleared) = take(&headers);
        assert_eq!(flash, Some(Flash::SignedOut));
        assert!(cleared.unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn an_unknown_code_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("askrypt_flash=nonsense"),
        );
        assert_eq!(take(&headers), (None, None));
    }
}
