//! Structured audit log for account-security events (plan Phase 5).
//!
//! Events go out as `tracing` records on the [`TARGET`] target, so they ride
//! the same subscriber as everything else and turn into one JSON object per
//! event under `ASKRYPT_LOG_FORMAT=json`. The target sits *under*
//! `askrypt_server`, so any `RUST_LOG=askrypt_server=…` directive keeps them
//! (a bare `audit` target would be silently dropped by such a filter) while
//! still being greppable and routable on its own.
//!
//! **What is deliberately not logged:** bearer tokens (sessions appear as the
//! same SHA-256 digest the profile API exposes), passwords, vault bytes, and
//! the email address on a *failed* login — that last one would turn the log
//! into a ready-made list of which addresses have accounts.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use std::convert::Infallible;

use crate::clientip;
use crate::store::AccountId;

/// Tracing target carrying audit events.
pub const TARGET: &str = "askrypt_server::audit";

/// Long user-agent strings are attacker-controlled; cap what reaches the log.
const MAX_USER_AGENT: usize = 256;

/// Who made the request, for the audit record. Infallible — a missing or
/// unreadable header just means less detail, never a rejected request.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub ip: String,
    pub user_agent: Option<String>,
}

impl ClientInfo {
    fn from_parts(parts: &Parts) -> Self {
        Self {
            ip: clientip::client_ip(
                &parts.headers,
                &parts.extensions,
                clientip::policy_of(&parts.extensions),
            ),
            user_agent: parts
                .headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.chars().take(MAX_USER_AGENT).collect()),
        }
    }
}

// Generic over the state so the Phase 7 HTML handlers can use it too.
impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_parts(parts))
    }
}

/// Records one audit event.
///
/// `detail` carries the event-specific reason or subject (`"bad_password"`,
/// a session id, the new email address); it must never contain a secret.
pub fn emit(event: &'static str, client: &ClientInfo, account: Option<AccountId>, detail: &str) {
    tracing::info!(
        target: TARGET,
        event,
        ip = %client.ip,
        user_agent = client.user_agent.as_deref().unwrap_or("-"),
        account = account.map(|id| id.to_string()).unwrap_or_default(),
        detail,
    );
}

// Event names. Constants rather than string literals at the call sites so
// the vocabulary stays greppable and typo-proof.
pub const REGISTER_OK: &str = "register.ok";
pub const REGISTER_DENIED: &str = "register.denied";
pub const LOGIN_OK: &str = "login.ok";
pub const LOGIN_FAILED: &str = "login.failed";
pub const LOGIN_GOOGLE_OK: &str = "login.google.ok";
pub const LOGIN_GOOGLE_DENIED: &str = "login.google.denied";
pub const LOGOUT: &str = "logout";
/// A website auth form was refused before its credentials were even looked
/// at, because its captcha token did not hold up. No account is named — at
/// this point none has been resolved, and the submitted address is exactly
/// what a failed login must not put in the log.
pub const CAPTCHA_FAILED: &str = "captcha.failed";
pub const PASSWORD_CHANGED: &str = "password.changed";
pub const PASSWORD_SET: &str = "password.set";
pub const PASSWORD_REAUTH_FAILED: &str = "password.reauth_failed";
pub const EMAIL_CHANGED: &str = "email.changed";
pub const SESSION_REVOKED: &str = "session.revoked";
pub const SESSIONS_REVOKED_BULK: &str = "session.revoked_bulk";
pub const ACCOUNT_DELETE_STARTED: &str = "account.delete_started";
pub const ACCOUNT_DELETED: &str = "account.deleted";
// Administrative actions (Phase 8). `account` names the account acted *on*;
// the acting administrator goes in `detail`, so the log answers both halves
// of "who did this to whom".
pub const ACCOUNT_BANNED: &str = "account.banned";
pub const ACCOUNT_UNBANNED: &str = "account.unbanned";
pub const ACCOUNT_DELETED_BY_ADMIN: &str = "account.deleted_by_admin";
pub const ROLE_GRANTED: &str = "role.granted";
pub const ROLE_REVOKED: &str = "role.revoked";
// Desktop sign-in handed to the browser. `account` is empty on `started`,
// which needs no authentication and so belongs to nobody yet; `detail` carries
// the device label the app asked for. The poll token and the issued session
// token are never logged.
pub const DEVICE_LINK_STARTED: &str = "device_link.started";
pub const DEVICE_LINK_APPROVED: &str = "device_link.approved";
pub const DEVICE_LINK_DENIED: &str = "device_link.denied";
pub const DEVICE_LINK_CLAIMED: &str = "device_link.claimed";
pub const DEVICE_LINK_CANCELLED: &str = "device_link.cancelled";
pub const DEVICE_LINK_REFUSED: &str = "device_link.refused";

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::Request;

    use crate::testlog::Capture;

    fn client() -> ClientInfo {
        let request = Request::builder()
            .uri("/")
            .header(header::USER_AGENT, "askrypt-desktop/0.6")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        ClientInfo::from_parts(&parts)
    }

    #[test]
    fn emitted_events_carry_target_and_fields() {
        let capture = Capture::start();
        emit(LOGIN_FAILED, &client(), None, "bad_password");

        let events = capture.events();
        let event = events.first().expect("one event recorded");
        assert_eq!(event.target, TARGET);
        assert_eq!(event.get("event"), LOGIN_FAILED);
        assert_eq!(event.get("detail"), "bad_password");
        assert_eq!(event.get("user_agent"), "askrypt-desktop/0.6");
        // No resolvable peer in an in-process request.
        assert_eq!(event.get("ip"), clientip::UNKNOWN);
        // An account-less event still records the field, empty.
        assert_eq!(event.get("account"), "");
    }

    #[test]
    fn user_agent_is_truncated() {
        let request = Request::builder()
            .uri("/")
            .header(header::USER_AGENT, "x".repeat(MAX_USER_AGENT * 2))
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let info = ClientInfo::from_parts(&parts);
        assert_eq!(info.user_agent.unwrap().len(), MAX_USER_AGENT);
    }
}
