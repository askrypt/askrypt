//! Auth endpoints and session plumbing (plan Phase 2).
//!
//! Registration, email+password login, Google sign-in, logout, and the
//! [`AuthSession`] extractor protected routes use. Passwords are hashed
//! with argon2 on the blocking pool so the async executor is never stalled;
//! sessions are opaque random bearer tokens persisted via the
//! `SessionStore` trait — no cookies, so native apps drive the same flow
//! as the website.
//!
//! ## Handlers are wrappers; the logic lives in free functions
//!
//! Everything security-relevant — [`authenticate`]'s timing equalization,
//! [`upsert_google_account`]'s link-or-create rules, [`resolve_session`]'s
//! expiry handling — is a plain `async fn` over [`AppState`], with the
//! `/api/v1` handler below it doing nothing but extraction and JSON
//! shaping. The Phase 7 HTML handlers in [`crate::web`] call the *same*
//! functions rather than making HTTP calls back into the API, so there is
//! exactly one implementation of each rule and one set of audit events.

use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::audit::{self, ClientInfo};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{Account, AccountId, NewAccount, Session, StoreError, VerifiedIdToken};

/// How long an API login session stays valid. Long-lived per-device sessions
/// per the plan's client-access rule; clients re-login after expiry. Browser
/// sessions are shorter — see [`crate::web::session::WEB_SESSION_TTL_DAYS`].
const SESSION_TTL_DAYS: i64 = 30;
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 512;
const MAX_EMAIL_LEN: usize = 254;

/// A real argon2id hash of a throwaway password, verified against when no
/// usable account hash exists so that unknown-email and wrong-password
/// logins cost the same. A `const` rather than a lazily computed hash: the
/// latter would charge one unlucky request ~19 MiB and a full hash.
///
/// Its parameters must match `Argon2::default()` — see the unit test.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YXNrcnlwdC1kdW1teS0wMQ$+wPV+26MRHinLIfLssyqlAinHuesHKQihpFRfjuueMM";

/// Concurrent argon2 operations.
///
/// Each hash holds ~19 MiB (`Params::DEFAULT`'s `m_cost`) for its duration,
/// and tokio's blocking pool would happily run 512 of them — about 10 GB —
/// under a login flood. Bounding the *hashes* rather than the requests is
/// what actually caps that; waiters queue, and the request timeout
/// ([`crate::hardening::request_timeout`]) bounds the wait.
static ARGON2_SLOTS: LazyLock<Semaphore> = LazyLock::new(|| {
    let permits = std::env::var("ASKRYPT_ARGON2_PARALLELISM")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|permits| *permits > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));
    tracing::debug!(permits, "argon2 concurrency limit");
    Semaphore::new(permits)
});

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

impl SessionResponse {
    fn new(session: Session, account: &Account) -> Self {
        Self {
            token: session.token,
            expires_at: session.expires_at,
            account: AccountInfo::from(account),
        }
    }
}

/// `POST /api/v1/auth/register` — create an email+password account.
pub async fn register(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<AccountInfo>)> {
    let account = register_account(&state, &client, &req.email, req.password).await?;
    Ok((StatusCode::CREATED, Json(AccountInfo::from(&account))))
}

/// `POST /api/v1/auth/login` — email+password login returning a bearer token.
pub async fn login(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let account = authenticate(&state, &client, &req.email, req.password).await?;
    let session = issue_session(&state, &account, req.device_label, SESSION_TTL_DAYS).await?;
    audit::emit(audit::LOGIN_OK, &client, Some(account.id), "password");
    Ok(Json(SessionResponse::new(session, &account)))
}

/// `POST /api/v1/auth/google` — exchange a verified Google ID token for the
/// same opaque bearer token as password login. Creates the account on first
/// sign-in, or links Google to the existing account with the same verified
/// email.
pub async fn google_login(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(req): ApiJson<GoogleLoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let claims = state
        .id_verifier
        .verify(&req.id_token)
        .await
        .inspect_err(|_| {
            audit::emit(audit::LOGIN_GOOGLE_DENIED, &client, None, "invalid_token");
        })?;
    let (account, outcome) = upsert_google_account(&state, &client, claims).await?;
    let session = issue_session(&state, &account, req.device_label, SESSION_TTL_DAYS).await?;
    audit::emit(audit::LOGIN_GOOGLE_OK, &client, Some(account.id), outcome);
    Ok(Json(SessionResponse::new(session, &account)))
}

/// `POST /api/v1/auth/logout` — revoke the presented session token.
pub async fn logout(
    State(state): State<AppState>,
    client: ClientInfo,
    auth: AuthSession,
) -> ApiResult<StatusCode> {
    revoke_session_token(&state, &client, &auth.session, auth.account.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Creates an email+password account, auditing every rejection.
///
/// Shared with the HTML register form, which must not re-derive the
/// validation or the "email taken" audit.
pub(crate) async fn register_account(
    state: &AppState,
    client: &ClientInfo,
    raw_email: &str,
    password: String,
) -> ApiResult<Account> {
    let email = validate_email(raw_email).inspect_err(|err| {
        audit::emit(audit::REGISTER_DENIED, client, None, err.code);
    })?;
    validate_password(&password).inspect_err(|err| {
        audit::emit(audit::REGISTER_DENIED, client, None, err.code);
    })?;
    let password_hash = hash_password(password).await?;
    let account = state
        .accounts
        .create(NewAccount {
            email,
            password_hash: Some(password_hash),
            google_sub: None,
        })
        .await
        // Matched rather than `?`-ed so a taken email is audited: it is the
        // signal that someone is probing which addresses exist.
        .inspect_err(|err| {
            if matches!(err, StoreError::Conflict(_)) {
                audit::emit(audit::REGISTER_DENIED, client, None, "email_taken");
            }
        })?;
    audit::emit(audit::REGISTER_OK, client, Some(account.id), &account.email);
    Ok(account)
}

/// Checks an email+password pair, returning the account on success.
///
/// Audits every *failure* itself; the caller emits [`audit::LOGIN_OK`] once
/// it has actually issued a session, so a store failure between the two
/// doesn't log a login that never happened.
///
/// Reimplementing this in the HTML layer would be the easy way to lose the
/// timing defense below, which is why it lives here.
pub(crate) async fn authenticate(
    state: &AppState,
    client: &ClientInfo,
    raw_email: &str,
    password: String,
) -> ApiResult<Account> {
    // Normalized, not validated: a malformed address must fail the same way
    // as a well-formed unknown one.
    let email = raw_email.trim().to_ascii_lowercase();
    // Unknown email, password-less (Google-only) account, and wrong password
    // all answer the same 401 so responses don't reveal which emails are
    // registered — and the two account-less paths still pay for an argon2
    // verify against DUMMY_PASSWORD_HASH so the *timing* doesn't reveal it
    // either. The failure reason goes to the audit log, never to the client.
    let account = match state.accounts.find_by_email(&email).await? {
        Some(account) => account,
        None => {
            let _ = verify_password(DUMMY_PASSWORD_HASH.to_string(), password).await;
            audit::emit(audit::LOGIN_FAILED, client, None, "unknown_email");
            return Err(invalid_credentials());
        }
    };
    let hash = match account.password_hash.clone() {
        Some(hash) => hash,
        None => {
            let _ = verify_password(DUMMY_PASSWORD_HASH.to_string(), password).await;
            audit::emit(audit::LOGIN_FAILED, client, Some(account.id), "no_password");
            return Err(invalid_credentials());
        }
    };
    if !verify_password(hash, password).await? {
        audit::emit(
            audit::LOGIN_FAILED,
            client,
            Some(account.id),
            "bad_password",
        );
        return Err(invalid_credentials());
    }
    Ok(account)
}

/// Creates or links the account behind a *verified* Google ID token,
/// returning it plus the audit outcome (`existing` / `linked` /
/// `new_account`) for the caller to emit alongside its own event.
///
/// The browser authorization-code flow will land here too, so the
/// link-or-create rules — including the 409 when the address is already tied
/// to a different Google account — stay in one place.
pub(crate) async fn upsert_google_account(
    state: &AppState,
    client: &ClientInfo,
    claims: VerifiedIdToken,
) -> ApiResult<(Account, &'static str)> {
    if !claims.email_verified {
        audit::emit(
            audit::LOGIN_GOOGLE_DENIED,
            client,
            None,
            "email_not_verified",
        );
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "email_not_verified",
            "the Google account's email address is not verified",
        ));
    }
    let email = claims.email.trim().to_ascii_lowercase();
    // Distinguishes first-time linking and account creation in the log:
    // both change what a compromised Google account can reach.
    let mut outcome = "existing";
    let account = match state.accounts.find_by_email(&email).await? {
        Some(mut account) => match account.google_sub.as_deref() {
            Some(sub) if sub == claims.subject => account,
            Some(_) => {
                audit::emit(
                    audit::LOGIN_GOOGLE_DENIED,
                    client,
                    Some(account.id),
                    "linked_to_other_google_account",
                );
                return Err(ApiError::conflict(
                    "this email is already linked to a different Google account",
                ));
            }
            None => {
                account.google_sub = Some(claims.subject);
                state.accounts.update(&account).await?;
                outcome = "linked";
                account
            }
        },
        None => {
            outcome = "new_account";
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
    Ok((account, outcome))
}

/// Revokes one session, tolerating a token that is already gone, and audits
/// the logout. Shared with the HTML sign-out form, which additionally clears
/// the browser cookie.
pub(crate) async fn revoke_session_token(
    state: &AppState,
    client: &ClientInfo,
    session: &Session,
    account_id: AccountId,
) -> ApiResult<()> {
    match state.sessions.delete(&session.token).await {
        Ok(()) | Err(StoreError::NotFound) => {
            audit::emit(
                audit::LOGOUT,
                client,
                Some(account_id),
                session.label.as_deref().unwrap_or("-"),
            );
            Ok(())
        }
        Err(other) => Err(other.into()),
    }
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
        let (account, session) = resolve_session(state, token).await?;
        Ok(AuthSession { account, session })
    }
}

/// Resolves an opaque session token to its session and owning account,
/// rejecting expired ones.
///
/// Shared with the cookie-based `WebSession` extractor, which carries the
/// same token by a different means and needs identical expiry semantics but
/// a redirect instead of a 401.
pub(crate) async fn resolve_session(
    state: &AppState,
    token: &str,
) -> ApiResult<(Account, Session)> {
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
    Ok((account, session))
}

/// Mints and persists a session token.
///
/// `ttl_days` is a parameter rather than [`SESSION_TTL_DAYS`] because
/// browser sessions are deliberately shorter than API ones.
pub(crate) async fn issue_session(
    state: &AppState,
    account: &Account,
    label: Option<String>,
    ttl_days: i64,
) -> ApiResult<Session> {
    let now = Utc::now();
    let session = Session {
        token: new_session_token(),
        account_id: account.id,
        label,
        created_at: now,
        expires_at: now + Duration::days(ttl_days),
    };
    state.sessions.insert(session.clone()).await?;
    Ok(session)
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
pub(crate) fn validate_email(raw: &str) -> Result<String, ApiError> {
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

pub(crate) fn validate_password(password: &str) -> Result<(), ApiError> {
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

pub(crate) async fn hash_password(password: String) -> ApiResult<String> {
    let _slot = argon2_slot().await;
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

pub(crate) async fn verify_password(hash: String, password: String) -> ApiResult<bool> {
    let _slot = argon2_slot().await;
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

/// Reserves one of the [`ARGON2_SLOTS`]. The permit is held by the caller
/// for as long as its binding lives, i.e. across the `spawn_blocking`.
async fn argon2_slot() -> tokio::sync::SemaphorePermit<'static> {
    ARGON2_SLOTS
        .acquire()
        .await
        .expect("argon2 semaphore is never closed")
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

    #[test]
    fn dummy_hash_matches_the_default_argon2_params() {
        // If the defaults ever move, the dummy verify would cost less than
        // a real one and the login timing signal would come back. Only the
        // three cost knobs matter here; `output_len` is `Some(32)` when
        // parsed from a PHC string and `None` (meaning the same 32) in the
        // defaults, which is not a cost difference.
        let parsed = PasswordHash::new(DUMMY_PASSWORD_HASH).unwrap();
        let params = argon2::Params::try_from(&parsed).unwrap();
        let defaults = argon2::Params::DEFAULT;
        assert_eq!(params.m_cost(), defaults.m_cost());
        assert_eq!(params.t_cost(), defaults.t_cost());
        assert_eq!(params.p_cost(), defaults.p_cost());
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
    }

    #[tokio::test]
    async fn dummy_hash_verifies_as_a_failure_not_an_error() {
        // The unknown-email path relies on this: a parse error there would
        // turn a 401 into a 500.
        assert!(
            !verify_password(DUMMY_PASSWORD_HASH.to_string(), "anything".into())
                .await
                .unwrap()
        );
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
