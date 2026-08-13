//! One-shot messages carried across a redirect.
//!
//! The cookie holds a *code*, never text: the message strings live in Rust,
//! so nothing a request can influence is ever echoed back into a page, and
//! there is no encoding to get right.

use axum::http::HeaderMap;

use crate::web::session::{clear_cookie, cookie_value, set_cookie};

pub use crate::web::types::Flash;

pub const FLASH_COOKIE: &str = "askrypt_flash";

/// Long enough to survive the redirect it was set on, short enough that a
/// stale one never surfaces later.
const FLASH_TTL_SECS: i64 = 60;

impl Flash {
    fn code(self) -> &'static str {
        match self {
            Self::AccountCreated => "created",
            Self::SignedOut => "out",
            Self::AlreadySignedIn => "in",
            Self::EmailChanged => "email",
            Self::PasswordChanged => "pwchanged",
            Self::PasswordSet => "pwset",
            Self::SessionRevoked => "revoked",
            Self::AccountDeleted => "gone",
            Self::VaultUploaded => "vup",
            Self::VaultReplaced => "vrep",
            Self::VaultRenamed => "vren",
            Self::VaultDeleted => "vdel",
            Self::VaultRestored => "vres",
            Self::UserBanned => "uban",
            Self::UserUnbanned => "uunban",
            Self::UserDeleted => "udel",
            Self::AdminGranted => "agrant",
            Self::AdminRevoked => "arevoke",
            Self::PaymentGranted => "pgrant",
            Self::PaymentRevoked => "prevoke",
            Self::RegistrationOpened => "regon",
            Self::RegistrationClosed => "regoff",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "created" => Some(Self::AccountCreated),
            "out" => Some(Self::SignedOut),
            "in" => Some(Self::AlreadySignedIn),
            "email" => Some(Self::EmailChanged),
            "pwchanged" => Some(Self::PasswordChanged),
            "pwset" => Some(Self::PasswordSet),
            "revoked" => Some(Self::SessionRevoked),
            "gone" => Some(Self::AccountDeleted),
            "vup" => Some(Self::VaultUploaded),
            "vrep" => Some(Self::VaultReplaced),
            "vren" => Some(Self::VaultRenamed),
            "vdel" => Some(Self::VaultDeleted),
            "vres" => Some(Self::VaultRestored),
            "uban" => Some(Self::UserBanned),
            "uunban" => Some(Self::UserUnbanned),
            "udel" => Some(Self::UserDeleted),
            "agrant" => Some(Self::AdminGranted),
            "arevoke" => Some(Self::AdminRevoked),
            "pgrant" => Some(Self::PaymentGranted),
            "prevoke" => Some(Self::PaymentRevoked),
            "regon" => Some(Self::RegistrationOpened),
            "regoff" => Some(Self::RegistrationClosed),
            _ => None,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::AccountCreated => "Account created. You're signed in.",
            Self::SignedOut => "You're signed out.",
            Self::AlreadySignedIn => "You're already signed in.",
            Self::EmailChanged => "Your email address has been updated.",
            Self::PasswordChanged => {
                "Password changed. Every other signed-in device has been signed out."
            }
            Self::PasswordSet => "Password set. You can now sign in with it.",
            Self::SessionRevoked => "That device has been signed out.",
            Self::AccountDeleted => "Your account and every stored vault have been deleted.",
            Self::VaultUploaded => "Vault uploaded.",
            Self::VaultReplaced => "Vault updated.",
            Self::VaultRenamed => "Vault renamed.",
            Self::VaultDeleted => "Vault deleted.",
            Self::VaultRestored => {
                "Earlier version restored. The version it replaced was kept in the history."
            }
            Self::UserBanned => "That account is suspended and has been signed out everywhere.",
            Self::UserUnbanned => "That account can sign in again.",
            Self::UserDeleted => "That account and every vault it stored have been deleted.",
            Self::AdminGranted => "That account is now an administrator.",
            Self::AdminRevoked => "That account is no longer an administrator.",
            Self::PaymentGranted => "That account is now on the paid storage tier.",
            Self::PaymentRevoked => "That account is back on the standard storage quota.",
            Self::RegistrationOpened => "Anyone can create an account on this server again.",
            Self::RegistrationClosed => {
                "New accounts are closed. Everyone who already has one can still sign in."
            }
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
        let all = [
            Flash::AccountCreated,
            Flash::SignedOut,
            Flash::AlreadySignedIn,
            Flash::EmailChanged,
            Flash::PasswordChanged,
            Flash::PasswordSet,
            Flash::SessionRevoked,
            Flash::AccountDeleted,
            Flash::VaultUploaded,
            Flash::VaultReplaced,
            Flash::VaultRenamed,
            Flash::VaultDeleted,
            Flash::VaultRestored,
            Flash::UserBanned,
            Flash::UserUnbanned,
            Flash::UserDeleted,
            Flash::AdminGranted,
            Flash::AdminRevoked,
            Flash::PaymentGranted,
            Flash::PaymentRevoked,
            Flash::RegistrationOpened,
            Flash::RegistrationClosed,
        ];
        for flash in all {
            assert_eq!(Flash::from_code(flash.code()), Some(flash));
        }
        // Two variants sharing a code would silently show the wrong message.
        let mut codes: Vec<&str> = all.iter().map(|f| f.code()).collect();
        codes.sort_unstable();
        let unique = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), unique, "duplicate flash code");
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
