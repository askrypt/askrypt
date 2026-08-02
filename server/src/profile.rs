//! Profile endpoints (plan Phase 3).
//!
//! The authenticated account manages itself here: full profile with linked
//! login providers, email update, change/set password, the active-session
//! list with per-session revocation, and account deletion (which cascades to
//! every stored vault). Sessions are identified to clients by a SHA-256
//! digest of their bearer token, so listing sessions never echoes a raw
//! token that could hijack another device.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{self, AuthSession};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{Account, AccountId, StoreError};

/// The full profile answered by `GET /api/v1/me` and the email update.
#[derive(Serialize)]
pub struct Profile {
    pub id: AccountId,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub providers: Providers,
}

/// Which login providers are usable on the account.
#[derive(Serialize)]
pub struct Providers {
    pub password: bool,
    pub google: bool,
}

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

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    pub email: String,
}

/// `PUT /api/v1/me/email` — change the account email (normalized and
/// validated like registration; 409 if another account already uses it).
pub async fn update_email(
    State(state): State<AppState>,
    auth: AuthSession,
    ApiJson(req): ApiJson<UpdateEmailRequest>,
) -> ApiResult<Json<Profile>> {
    let email = auth::validate_email(&req.email)?;
    let mut account = auth.account;
    if account.email != email {
        account.email = email;
        state.accounts.update(&account).await?;
    }
    Ok(Json(Profile::from(&account)))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Required when the account already has a password; Google-created
    /// accounts without one set their first password with just `new_password`.
    #[serde(default)]
    pub current_password: Option<String>,
    pub new_password: String,
}

/// `PUT /api/v1/me/password` — change the password, or set the first one on
/// a Google-created account. Re-auth with the current password applies only
/// to accounts that have one.
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthSession,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    auth::validate_password(&req.new_password)?;
    let mut account = auth.account;
    if let Some(hash) = account.password_hash.clone() {
        let Some(current) = req.current_password else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "current_password_required",
                "current password is required to change the password",
            ));
        };
        if !auth::verify_password(hash, current).await? {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_current_password",
                "current password is incorrect",
            ));
        }
    }
    account.password_hash = Some(auth::hash_password(req.new_password).await?);
    state.accounts.update(&account).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One entry in the `GET /api/v1/me/sessions` device list.
#[derive(Serialize)]
pub struct SessionInfo {
    /// Non-secret session id (SHA-256 of the bearer token, hex); pass it to
    /// `DELETE /api/v1/me/sessions/{id}` to revoke.
    pub id: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Whether this entry is the session making the request.
    pub current: bool,
}

/// `GET /api/v1/me/sessions` — the account's active (non-expired) sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthSession,
) -> ApiResult<Json<Vec<SessionInfo>>> {
    let now = Utc::now();
    let sessions = state.sessions.list_for_account(auth.account.id).await?;
    let infos = sessions
        .into_iter()
        .filter(|s| s.expires_at > now)
        .map(|s| SessionInfo {
            id: session_id(&s.token),
            current: s.token == auth.session.token,
            label: s.label,
            created_at: s.created_at,
            expires_at: s.expires_at,
        })
        .collect();
    Ok(Json(infos))
}

/// `DELETE /api/v1/me/sessions/{id}` — revoke one of the account's sessions
/// (including, like logout, the current one).
pub async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let sessions = state.sessions.list_for_account(auth.account.id).await?;
    let Some(target) = sessions.into_iter().find(|s| session_id(&s.token) == id) else {
        return Err(ApiError::not_found("no such session"));
    };
    match state.sessions.delete(&target.token).await {
        Ok(()) | Err(StoreError::NotFound) => Ok(StatusCode::NO_CONTENT),
        Err(other) => Err(other.into()),
    }
}

/// `DELETE /api/v1/me` — delete the account and everything it owns: vault
/// bytes, vault metadata, and all sessions.
pub async fn delete_account(
    State(state): State<AppState>,
    auth: AuthSession,
) -> ApiResult<StatusCode> {
    let id = auth.account.id;
    // Owned data first, account record last, so a failure part-way never
    // leaves orphaned vaults behind a deleted account.
    state.vault_blobs.delete_for_account(id).await?;
    state.vault_meta.delete_for_account(id).await?;
    state.sessions.delete_for_account(id).await?;
    match state.accounts.delete(id).await {
        Ok(()) | Err(StoreError::NotFound) => Ok(StatusCode::NO_CONTENT),
        Err(other) => Err(other.into()),
    }
}

fn session_id(token: &str) -> String {
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
