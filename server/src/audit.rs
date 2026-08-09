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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use axum::http::Request;
    use tracing::field::{Field, Visit};
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry::Registry;

    /// Collects `field=value` pairs plus the target of every event.
    #[derive(Default)]
    struct Captured {
        target: String,
        fields: Vec<(String, String)>,
    }

    struct CaptureLayer(Arc<Mutex<Vec<Captured>>>);

    impl Visit for Captured {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut captured = Captured {
                target: event.metadata().target().to_string(),
                ..Default::default()
            };
            event.record(&mut captured);
            self.0.lock().unwrap().push(captured);
        }
    }

    /// Installs a do-nothing subscriber as the process-wide default.
    ///
    /// Without one, `tracing` caches `Interest::never()` for a callsite the
    /// first time it is reached with no subscriber at all — which other tests
    /// in this binary do, since they call `emit` freely. A cached "never" is
    /// not undone by a later *thread-local* subscriber, so the event below
    /// would be dropped. With a global default in place the callsite resolves
    /// to "sometimes" instead, and every event consults the dispatcher that
    /// is actually current on its own thread.
    ///
    /// Registry with no layers records nothing, so this changes no other
    /// test's behaviour; it exists purely to keep the cache honest.
    fn keep_callsites_live() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            // Another module setting one first is fine — any global default
            // does the job.
            let _ = tracing::subscriber::set_global_default(Registry::default());
        });
        tracing::callsite::rebuild_interest_cache();
    }

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
        keep_callsites_live();
        let events = Arc::new(Mutex::new(Vec::new()));
        // `with_default` is thread-local, so this stays deterministic even
        // though other tests in the binary run in parallel.
        with_default(
            Registry::default().with(CaptureLayer(Arc::clone(&events))),
            || {
                emit(LOGIN_FAILED, &client(), None, "bad_password");
            },
        );

        let events = events.lock().unwrap();
        let event = events.first().expect("one event recorded");
        assert_eq!(event.target, TARGET);
        let field = |name: &str| {
            event
                .fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| panic!("missing field {name}"))
        };
        assert_eq!(field("event"), LOGIN_FAILED);
        assert_eq!(field("detail"), "bad_password");
        assert_eq!(field("user_agent"), "askrypt-desktop/0.6");
        // No resolvable peer in an in-process request.
        assert_eq!(field("ip"), clientip::UNKNOWN);
        // An account-less event still records the field, empty.
        assert_eq!(field("account"), "");
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
