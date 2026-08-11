//! Profile endpoints (plan Phase 3).
//!
//! The authenticated account manages itself here: full profile with linked
//! login providers, email update, change/set password, the active-session
//! list with per-session revocation, and account deletion (which cascades to
//! every stored vault). Sessions are identified to clients by a SHA-256
//! digest of their bearer token, so listing sessions never echoes a raw
//! token that could hijack another device.
//!
//! As in [`crate::auth`], the handlers are wrappers and the rules live in
//! `pub(crate)` free functions over [`AppState`] — [`set_email`],
//! [`set_password`], [`active_sessions`], [`revoke_session_id`] and
//! [`delete_account_data`]. The Phase 7.3 profile pages in
//! [`crate::web::account`] call those same functions, so the re-auth
//! requirement, the bulk session revocation on a password change and the
//! delete cascade have exactly one implementation.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::audit::{self, ClientInfo};
use crate::auth::{self, AuthSession};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{Account, AccountId, StoreError};

pub use crate::types::{
    ChangePasswordRequest, Profile, Providers, SessionInfo, UpdateEmailRequest,
};

impl From<&Account> for Profile {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id,
            email: account.email.clone(),
            created_at: account.created_at,
            providers: Providers {
                password: account.password_hash.is_some(),
                google: account.google_sub.is_some(),
            },
        }
    }
}

/// `GET /api/v1/me` — the current account's profile.
pub async fn me(auth: AuthSession) -> Json<Profile> {
    Json(Profile::from(&auth.account))
}

/// `PUT /api/v1/me/email` — change the account email (normalized and
/// validated like registration; 409 if another account already uses it).
pub async fn update_email(
    State(state): State<AppState>,
    client: ClientInfo,
    auth: AuthSession,
    ApiJson(req): ApiJson<UpdateEmailRequest>,
) -> ApiResult<Json<Profile>> {
    let account = set_email(&state, &client, auth.account, &req.email).await?;
    Ok(Json(Profile::from(&account)))
}

/// Validates, normalizes and stores a new account email, returning the
/// updated account. A no-op when the address is unchanged.
pub(crate) async fn set_email(
    state: &AppState,
    client: &ClientInfo,
    mut account: Account,
    raw_email: &str,
) -> ApiResult<Account> {
    let email = auth::validate_email(raw_email)?;
    if account.email != email {
        // Captured before the move: the audit record has to show what the
        // address was, since the new one is where recovery mail now goes.
        let previous = std::mem::replace(&mut account.email, email);
        state.accounts.update(&account).await?;
        audit::emit(
            audit::EMAIL_CHANGED,
            client,
            Some(account.id),
            &format!("{previous} -> {}", account.email),
        );
    }
    Ok(account)
}

/// `PUT /api/v1/me/password` — change the password, or set the first one on
/// a Google-created account. Re-auth with the current password applies only
/// to accounts that have one.
///
/// Changing an existing password also revokes every *other* session: a
/// password change is how a user reacts to a suspected compromise, so
/// leaving the attacker's bearer token alive would defeat the point. The
/// caller's own session survives, so the device doing the change stays
/// logged in; other devices must sign in again.
pub async fn change_password(
    State(state): State<AppState>,
    client: ClientInfo,
    auth: AuthSession,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    set_password(
        &state,
        &client,
        auth.account,
        req.current_password,
        req.new_password,
        &auth.session.token,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The password change itself, shared with the HTML form.
///
/// `keep_token` is the caller's own session: every *other* session is
/// revoked when an existing password is replaced, so the device doing the
/// change stays signed in and a stolen token does not.
pub(crate) async fn set_password(
    state: &AppState,
    client: &ClientInfo,
    mut account: Account,
    current_password: Option<String>,
    new_password: String,
    keep_token: &str,
) -> ApiResult<()> {
    auth::validate_password(&new_password)?;
    let had_password = account.password_hash.is_some();
    if let Some(hash) = account.password_hash.clone() {
        let Some(current) = current_password else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "current_password_required",
                "current password is required to change the password",
            ));
        };
        if !auth::verify_password(hash, current).await? {
            // Someone holding a stolen bearer token guessing the password.
            audit::emit(
                audit::PASSWORD_REAUTH_FAILED,
                client,
                Some(account.id),
                "invalid_current_password",
            );
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_current_password",
                "current password is incorrect",
            ));
        }
    }
    account.password_hash = Some(auth::hash_password(new_password).await?);
    state.accounts.update(&account).await?;
    audit::emit(
        if had_password {
            audit::PASSWORD_CHANGED
        } else {
            audit::PASSWORD_SET
        },
        client,
        Some(account.id),
        "",
    );
    if had_password {
        let revoked = revoke_other_sessions(state, account.id, keep_token).await?;
        if revoked > 0 {
            audit::emit(
                audit::SESSIONS_REVOKED_BULK,
                client,
                Some(account.id),
                &revoked.to_string(),
            );
        }
    }
    Ok(())
}

/// Deletes every session of the account except `keep`, returning how many
/// went. Best-effort per session: one already-gone token must not fail the
/// password change that has already been committed.
async fn revoke_other_sessions(
    state: &AppState,
    account: AccountId,
    keep: &str,
) -> ApiResult<usize> {
    let sessions = state.sessions.list_for_account(account).await?;
    let mut revoked = 0;
    for session in sessions.into_iter().filter(|s| s.token != keep) {
        match state.sessions.delete(&session.token).await {
            Ok(()) => revoked += 1,
            Err(StoreError::NotFound) => {}
            Err(other) => return Err(other.into()),
        }
    }
    Ok(revoked)
}

/// `GET /api/v1/me/sessions` — the account's active (non-expired) sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthSession,
) -> ApiResult<Json<Vec<SessionInfo>>> {
    Ok(Json(
        active_sessions(&state, auth.account.id, &auth.session.token).await?,
    ))
}

/// The account's unexpired sessions, newest first, with `current` set for
/// `caller_token`. Shared with the HTML device list.
pub(crate) async fn active_sessions(
    state: &AppState,
    account: AccountId,
    caller_token: &str,
) -> ApiResult<Vec<SessionInfo>> {
    let now = Utc::now();
    let mut sessions = state.sessions.list_for_account(account).await?;
    sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
    Ok(sessions
        .into_iter()
        .filter(|s| s.expires_at > now)
        .map(|s| SessionInfo {
            id: session_id(&s.token),
            current: s.token == caller_token,
            label: s.label,
            created_at: s.created_at,
            expires_at: s.expires_at,
        })
        .collect())
}

/// `DELETE /api/v1/me/sessions/{id}` — revoke one of the account's sessions
/// (including, like logout, the current one).
pub async fn revoke_session(
    State(state): State<AppState>,
    client: ClientInfo,
    auth: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    revoke_session_id(&state, &client, auth.account.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revokes one of the account's sessions by its published digest, returning
/// the token that was revoked so a caller can tell whether it just signed
/// *itself* out.
pub(crate) async fn revoke_session_id(
    state: &AppState,
    client: &ClientInfo,
    account: AccountId,
    id: &str,
) -> ApiResult<String> {
    let sessions = state.sessions.list_for_account(account).await?;
    let Some(target) = sessions.into_iter().find(|s| session_id(&s.token) == id) else {
        return Err(ApiError::not_found("no such session"));
    };
    match state.sessions.delete(&target.token).await {
        Ok(()) | Err(StoreError::NotFound) => {
            // The digest, never the token itself.
            audit::emit(audit::SESSION_REVOKED, client, Some(account), id);
            Ok(target.token)
        }
        Err(other) => Err(other.into()),
    }
}

/// `DELETE /api/v1/me` — delete the account and everything it owns: vault
/// bytes, vault metadata, and all sessions.
pub async fn delete_account(
    State(state): State<AppState>,
    client: ClientInfo,
    auth: AuthSession,
) -> ApiResult<StatusCode> {
    delete_account_data(&state, &client, &auth.account).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The delete cascade, shared with the HTML confirmation form.
pub(crate) async fn delete_account_data(
    state: &AppState,
    client: &ClientInfo,
    account: &Account,
) -> ApiResult<()> {
    let id = account.id;
    // Logged before and after: the cascade is irreversible, and a failure
    // part-way leaves a half-deleted account that only the log explains.
    audit::emit(
        audit::ACCOUNT_DELETE_STARTED,
        client,
        Some(id),
        &account.email,
    );
    // Owned data first, account record last, so a failure part-way never
    // leaves orphaned vaults behind a deleted account. Archived versions are
    // owned data too: "every stored vault" includes the ones this site kept
    // after they were replaced.
    state.vault_version_blobs.delete_for_account(id).await?;
    state.vault_versions.delete_for_account(id).await?;
    state.vault_blobs.delete_for_account(id).await?;
    state.vault_meta.delete_for_account(id).await?;
    state.sessions.delete_for_account(id).await?;
    // SQLite cascades this from the foreign key, but the in-memory backend
    // does not, and the explicit order is what the cascade is documented by.
    state.roles.delete_for_account(id).await?;
    match state.accounts.delete(id).await {
        Ok(()) | Err(StoreError::NotFound) => {
            audit::emit(audit::ACCOUNT_DELETED, client, Some(id), "");
            Ok(())
        }
        Err(other) => Err(other.into()),
    }
}

/// The public identity of a session token: a SHA-256 digest, so listing
/// devices never hands back a usable credential. `pub(crate)` because
/// [`crate::auth::session_fingerprint`] logs a prefix of the same value —
/// one digest, so a log line and a device-list row can be matched up.
pub(crate) fn session_id(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_stable_hex_and_token_hiding() {
        let id = session_id("some-bearer-token");
        assert_eq!(id.len(), 64);
        assert_eq!(id, session_id("some-bearer-token"));
        assert_ne!(id, session_id("other-token"));
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
