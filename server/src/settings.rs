//! Server-wide settings: runtime state an administrator edits, as opposed to
//! the `ASKRYPT_*` environment [`crate::config`] reads once at startup.
//!
//! Same split as [`crate::admin`] — the rules live here as `pub(crate)` free
//! functions over [`AppState`], and [`crate::web::settings`] is a thin set of
//! handlers over them. There is deliberately no JSON surface: like the rest of
//! administration, this is a website capability.
//!
//! [`crate::store::SettingsStore`] moves plain strings; the typed reading of
//! each key lives here, so adding a setting is a constant plus an accessor
//! rather than a schema change.
//!
//! **An unwritten key means the default.** Nothing seeds the table, so every
//! existing deployment reads exactly as it behaved before the key existed.

use crate::audit::{self, ClientInfo};
use crate::error::ApiResult;
use crate::state::AppState;
use crate::store::{Account, REGISTRATION_ENABLED};

/// The stored spellings. Written out rather than `to_string()`-ed off a bool
/// so the on-disk vocabulary is visible in one place.
const TRUE: &str = "true";
const FALSE: &str = "false";

/// Is this server accepting new accounts?
///
/// True unless an administrator has explicitly turned registration off. Three
/// cases read as "open": the key was never written (the documented default),
/// its value is not one this build understands (a hand-edited row must not
/// quietly close a server), and the store itself failed. That last one is a
/// deliberate fail-*open*: registration is not a security boundary the way
/// authentication is, and a database that cannot answer this question could
/// not have created the account either.
pub(crate) async fn registration_enabled(state: &AppState) -> bool {
    match state.settings.get(REGISTRATION_ENABLED).await {
        Ok(None) => true,
        Ok(Some(setting)) => match setting.value.as_str() {
            TRUE => true,
            FALSE => false,
            other => {
                tracing::warn!(
                    key = REGISTRATION_ENABLED,
                    value = other,
                    "unrecognised setting value; treating registration as open"
                );
                true
            }
        },
        Err(err) => {
            tracing::warn!(
                key = REGISTRATION_ENABLED,
                error = %err,
                "could not read setting; treating registration as open"
            );
            true
        }
    }
}

/// Opens or closes registration, auditing the change.
///
/// Idempotent, because the store's `set` is: submitting the form twice writes
/// the same value twice rather than failing the second time.
pub(crate) async fn set_registration_enabled(
    state: &AppState,
    client: &ClientInfo,
    caller: &Account,
    enabled: bool,
) -> ApiResult<()> {
    let value = if enabled { TRUE } else { FALSE };
    state.settings.set(REGISTRATION_ENABLED, value).await?;
    audit::emit(
        audit::SETTING_CHANGED,
        client,
        Some(caller.id),
        &format!("{REGISTRATION_ENABLED}={value} by {}", caller.email),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;

    use crate::store::AccountId;

    fn client() -> ClientInfo {
        ClientInfo {
            ip: "127.0.0.1".into(),
            user_agent: None,
        }
    }

    fn account() -> Account {
        Account {
            id: AccountId::new_v4(),
            email: "admin@example.com".to_string(),
            password_hash: Some("hash".to_string()),
            google_sub: None,
            created_at: Utc::now(),
            banned_at: None,
        }
    }

    #[tokio::test]
    async fn registration_is_open_until_someone_closes_it() {
        let state = AppState::in_memory();
        assert!(registration_enabled(&state).await);

        set_registration_enabled(&state, &client(), &account(), false)
            .await
            .unwrap();
        assert!(!registration_enabled(&state).await);

        set_registration_enabled(&state, &client(), &account(), true)
            .await
            .unwrap();
        assert!(registration_enabled(&state).await);
    }

    #[tokio::test]
    async fn a_value_this_build_does_not_understand_reads_as_open() {
        // A hand-edited row must not be able to close a server quietly.
        let state = AppState::in_memory();
        state
            .settings
            .set(REGISTRATION_ENABLED, "nope")
            .await
            .unwrap();
        assert!(registration_enabled(&state).await);
    }
}
