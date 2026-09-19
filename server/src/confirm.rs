//! Email confirmation for password accounts (plan Phase 15).
//!
//! Registration mails a single-use link; [`crate::auth::authenticate`]
//! refuses the account until it has been followed. The rules live here as
//! free functions, called by the registration path in [`crate::auth`] and by
//! the confirmation pages in [`crate::web::confirm`] — the same split as the
//! rest of the server, so there is one implementation of each.
//!
//! - The token is 256 bits from the OS RNG, like a session token. Only its
//!   SHA-256 is stored; the token itself exists in the mail and nowhere else.
//! - One pending link per account: every send replaces the previous one, so
//!   only the newest mail works.
//! - Using a link is one atomic `take`, so it works exactly once.
//! - Nothing here answers differently for an unknown address, a confirmed
//!   one and a pending one — see [`resend`].
//!
//! Google accounts never pass through here: Google has verified the address,
//! so they are created confirmed (see [`crate::auth::upsert_google_account`]).

use axum::http::StatusCode;
use chrono::{Duration, Utc};

use crate::audit::{self, ClientInfo};
use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::profile;
use crate::state::AppState;
use crate::store::{Account, EmailConfirmation};

/// How long a mailed link stays usable.
pub const CONFIRMATION_TTL_HOURS: i64 = 24;

/// Minimum spacing of resends for one account, so the resend form cannot be
/// turned into a way to flood someone's inbox.
pub const RESEND_COOLDOWN_SECS: i64 = 60;

/// Where a mailed link lands; the token follows as the last path segment.
pub const CONFIRM_PATH: &str = "/confirm";

const SUBJECT: &str = "Confirm your Askrypt account";

/// Mints a fresh link for `account`, stores it (replacing any earlier one)
/// and mails it.
///
/// Never fails its caller: the account already exists by the time this runs,
/// and a relay that is down must not turn a successful registration into an
/// error page. Failures are logged, and the user can ask for a new link.
pub(crate) async fn send_confirmation(state: &AppState, client: &ClientInfo, account: &Account) {
    let now = Utc::now();
    // No GC task in this server; the send path sweeps, like device links.
    if let Err(err) = state.email_confirmations.delete_expired(now).await {
        tracing::warn!(error = %err, "failed to sweep expired email confirmations");
    }
    let token = auth::new_session_token();
    let pending = EmailConfirmation {
        account_id: account.id,
        token_hash: profile::session_id(&token),
        created_at: now,
        expires_at: now + Duration::hours(CONFIRMATION_TTL_HOURS),
    };
    if let Err(err) = state.email_confirmations.put(pending).await {
        tracing::warn!(error = %err, account = %account.id, "failed to store an email confirmation");
        return;
    }
    let body = mail_body(&confirmation_url(&state.public_url, &token));
    match state.mailer.send(&account.email, SUBJECT, &body).await {
        Ok(()) => audit::emit(audit::EMAIL_CONFIRM_SENT, client, Some(account.id), "-"),
        // The relay's reason, never the body: it holds the token.
        Err(err) => tracing::warn!(
            error = %err,
            account = %account.id,
            "failed to send the email confirmation",
        ),
    }
}

/// Mails a new link to `raw_email` if, and only if, it belongs to an account
/// still waiting for confirmation, at most once per [`RESEND_COOLDOWN_SECS`].
///
/// The caller shows the same page whatever happened, so the form cannot be
/// used to learn which addresses are registered. The mail itself goes out on
/// a spawned task, so the time the request takes does not tell either.
pub(crate) async fn resend(
    state: &AppState,
    client: &ClientInfo,
    raw_email: &str,
) -> ApiResult<()> {
    let email = raw_email.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Ok(());
    }
    let Some(account) = state.accounts.find_by_email(&email).await? else {
        return Ok(());
    };
    if account.is_confirmed() || account.is_banned() {
        return Ok(());
    }
    if let Some(pending) = state.email_confirmations.get(account.id).await? {
        let age = Utc::now() - pending.created_at;
        if age < Duration::seconds(RESEND_COOLDOWN_SECS) {
            tracing::debug!(account = %account.id, "confirmation resend inside the cooldown");
            return Ok(());
        }
    }
    let state = state.clone();
    let client = client.clone();
    tokio::spawn(async move { send_confirmation(&state, &client, &account).await });
    Ok(())
}

/// Uses a mailed link: marks its account confirmed and returns it.
///
/// Unknown, expired and already-used tokens all fail with the same
/// [`invalid_confirmation`] — there is nothing a client could do differently
/// about any of them except ask for a new link.
pub(crate) async fn confirm_token(
    state: &AppState,
    client: &ClientInfo,
    token: &str,
) -> ApiResult<Account> {
    let hash = profile::session_id(token.trim());
    let Some(pending) = state.email_confirmations.take(&hash, Utc::now()).await? else {
        audit::emit(audit::EMAIL_CONFIRM_FAILED, client, None, "invalid_token");
        return Err(invalid_confirmation());
    };
    let Some(mut account) = state.accounts.get(pending.account_id).await? else {
        audit::emit(
            audit::EMAIL_CONFIRM_FAILED,
            client,
            Some(pending.account_id),
            "account_missing",
        );
        return Err(invalid_confirmation());
    };
    if !account.is_confirmed() {
        account.email_confirmed_at = Some(Utc::now());
        state.accounts.update(&account).await?;
    }
    audit::emit(
        audit::EMAIL_CONFIRMED,
        client,
        Some(account.id),
        &account.email,
    );
    Ok(account)
}

/// The refusal a correct password gets while its account is unconfirmed.
/// Reached only after the password check, like `auth::account_banned`, so it
/// tells nobody anything they did not already know.
pub(crate) fn email_not_confirmed() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        EMAIL_NOT_CONFIRMED,
        "confirm your email address before signing in — we sent you a link",
    )
}

/// The error code of [`email_not_confirmed`], which the sign-in form matches
/// on to show the confirmation page instead of the form.
pub const EMAIL_NOT_CONFIRMED: &str = "email_not_confirmed";

pub(crate) fn invalid_confirmation() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_confirmation",
        "this confirmation link is invalid, expired, or already used",
    )
}

fn confirmation_url(public_url: &str, token: &str) -> String {
    format!("{public_url}{CONFIRM_PATH}/{token}")
}

fn mail_body(url: &str) -> String {
    format!(
        "Welcome to Askrypt.\n\
         \n\
         Confirm your email address to finish creating your account:\n\
         \n\
         {url}\n\
         \n\
         The link works once and expires in {CONFIRMATION_TTL_HOURS} hours.\n\
         \n\
         If you did not create an Askrypt account, ignore this message: \
         nothing happens unless the link is opened and confirmed.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mail_carries_the_link_and_no_trailing_noise() {
        let url = confirmation_url("https://askrypt.example", "abc123");
        assert_eq!(url, "https://askrypt.example/confirm/abc123");
        let body = mail_body(&url);
        assert!(body.contains("\nhttps://askrypt.example/confirm/abc123\n"));
    }
}
