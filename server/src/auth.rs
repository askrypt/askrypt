//! Auth endpoints and session plumbing (plan Phase 2).
//!
//! Registration, email+password login, Google sign-in, logout, and the
//! [`AuthSession`] extractor protected routes use. Passwords are hashed
//! with argon2 on the blocking pool so the async executor is never stalled;
//! sessions are opaque random bearer tokens persisted via the
//! `SessionStore` trait — no cookies, so native apps drive the same flow
//! as the SPA.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{Account, AccountId, NewAccount, Session, StoreError};

/// How long a login session stays valid. Long-lived per-device sessions per
/// the plan's client-access rule; clients re-login after expiry.
const SESSION_TTL_DAYS: i64 = 30;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 512;
const MAX_EMAIL_LEN: usize = 254;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// Shown in the profile's session list ("Pixel 9", "work laptop", ...).
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleLoginRequest {
    pub id_token: String,
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Serialize)]
pub struct AccountInfo {
    pub id: AccountId,
    pub email: String,
}

impl From<&Account> for AccountInfo {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id,
            email: account.email.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub account: AccountInfo,
}

/// `POST /api/v1/auth/register` — create an email+password account.
pub async fn register(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<AccountInfo>)> {
    let email = validate_email(&req.email)?;
    validate_password(&req.password)?;
    let password_hash = hash_password(req.password).await?;
    let account = state
        .accounts
        .create(NewAccount {
            email,
            password_hash: Some(password_hash),
            google_sub: None,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(AccountInfo::from(&account))))
}

/// `POST /api/v1/auth/login` — email+password login returning a bearer token.
pub async fn login(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let email = req.email.trim().to_ascii_lowercase();
    // Unknown email, password-less (Google-only) account, and wrong password
    // all answer the same 401 so responses don't reveal which emails are
    // registered. (Timing still differs — equalizing is a Phase 5 concern.)
    let Some(account) = state.accounts.find_by_email(&email).await? else {
        return Err(invalid_credentials());
    };
    let Some(hash) = account.password_hash.clone() else {
        return Err(invalid_credentials());
    };
    if !verify_password(hash, req.password).await? {
        return Err(invalid_credentials());
    }
    let response = create_session(&state, &account, req.device_label).await?;
    Ok(Json(response))
}

/// `POST /api/v1/auth/google` — exchange a verified Google ID token for the
/// same opaque bearer token as password login. Creates the account on first
/// sign-in, or links Google to the existing account with the same verified
/// email.
pub async fn google_login(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<GoogleLoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let claims = state.id_verifier.verify(&req.id_token).await?;
    if !claims.email_verified {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "email_not_verified",
            "the Google account's email address is not verified",
        ));
    }
    let email = claims.email.trim().to_ascii_lowercase();
    let account = match state.accounts.find_by_email(&email).await? {
        Some(mut account) => match account.google_sub.as_deref() {
            Some(sub) if sub == claims.subject => account,
            Some(_) => {
                return Err(ApiError::conflict(
                    "this email is already linked to a different Google account",
                ));
            }
            None => {
                account.google_sub = Some(claims.subject);
                state.accounts.update(&account).await?;
                account
            }
        },
        None => {
            state
                .accounts
                .create(NewAccount {
                    email,
                    password_hash: None,
                    google_sub: Some(claims.subject),
                })
                .await?
        }
    };
    let response = create_session(&state, &account, req.device_label).await?;
    Ok(Json(response))
}

/// `POST /api/v1/auth/logout` — revoke the presented session token.
pub async fn logout(State(state): State<AppState>, auth: AuthSession) -> ApiResult<StatusCode> {
    match state.sessions.delete(&auth.session.token).await {
        Ok(()) | Err(StoreError::NotFound) => Ok(StatusCode::NO_CONTENT),
        Err(other) => Err(other.into()),
    }
}

/// `GET /api/v1/me` — minimal authenticated endpoint; Phase 3 grows it into
/// the full profile.
pub async fn me(auth: AuthSession) -> Json<AccountInfo> {
    Json(AccountInfo::from(&auth.account))
}

/// Extractor for protected routes: validates the `Authorization: Bearer`
/// token against the session store and loads the owning account.
pub struct AuthSession {
    pub account: Account,
    pub session: Session,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?;
        let session = state
            .sessions
            .get(token)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        if session.expires_at <= Utc::now() {
            // Best-effort cleanup; the token is rejected either way.
            let _ = state.sessions.delete(token).await;
            return Err(ApiError::unauthorized());
        }
        let account = state
            .accounts
            .get(session.account_id)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(AuthSession { account, session })
    }
}

async fn create_session(
    state: &AppState,
    account: &Account,
    label: Option<String>,
) -> ApiResult<SessionResponse> {
    let now = Utc::now();
    let session = Session {
        token: new_session_token(),
        account_id: account.id,
        label,
        created_at: now,
        expires_at: now + Duration::days(SESSION_TTL_DAYS),
    };
    state.sessions.insert(session.clone()).await?;
    Ok(SessionResponse {
        token: session.token,
        expires_at: session.expires_at,
        account: AccountInfo::from(account),
    })
}

/// 256 bits from the OS RNG, hex-encoded.
fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn invalid_credentials() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "invalid email or password",
    )
}

/// Normalizes (trim + lowercase) and sanity-checks an email address. Full
/// RFC 5322 validation is a rabbit hole; ownership is what verification
/// emails are for.
fn validate_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_ascii_lowercase();
    let ok = !email.is_empty()
        && email.len() <= MAX_EMAIL_LEN
        && !email.contains(char::is_whitespace)
        && matches!(email.split_once('@'), Some((local, domain))
            if !local.is_empty()
                && !domain.contains('@')
                && domain.split('.').count() >= 2
                && domain.split('.').all(|part| !part.is_empty()));
    if ok {
        Ok(email)
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_email",
            "not a valid email address",
        ))
    }
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            format!("password must be at least {MIN_PASSWORD_LEN} characters"),
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            format!("password must be at most {MAX_PASSWORD_LEN} bytes"),
        ));
    }
    Ok(())
}

async fn hash_password(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes).expect("OS RNG unavailable");
        let salt = SaltString::encode_b64(&salt_bytes)?;
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(join_err)?
    .map_err(|e| {
        tracing::error!(error = %e, "argon2 hashing failed");
        ApiError::internal()
    })
}

async fn verify_password(hash: String, password: String) -> ApiResult<bool> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash).map_err(|e| e.to_string())?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(join_err)?
    .map_err(|e: String| {
        tracing::error!(error = %e, "stored password hash is unparseable");
        ApiError::internal()
    })
}

fn join_err(e: tokio::task::JoinError) -> ApiError {
    tracing::error!(error = %e, "blocking task panicked");
    ApiError::internal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation_normalizes_and_rejects() {
        assert_eq!(
            validate_email(" User@Example.COM ").unwrap(),
            "user@example.com"
        );
        for bad in ["", "nope", "a@b", "a@b.", "a@.b", "a b@c.com", "a@b@c.com"] {
            assert!(validate_email(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn password_policy() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn session_tokens_are_long_and_unique() {
        let a = new_session_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_session_token());
    }

    #[tokio::test]
    async fn password_hash_roundtrip() {
        let hash = hash_password("correct horse battery".into()).await.unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(
            verify_password(hash.clone(), "correct horse battery".into())
                .await
                .unwrap()
        );
        assert!(
            !verify_password(hash, "wrong password".into())
                .await
                .unwrap()
        );
    }
}
