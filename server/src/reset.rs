//! Password reset by mailed link (plan Phase 16).
//!
//! The twin of [`crate::confirm`], and built to the same rules — the token is
//! 256 bits from the OS RNG, only its SHA-256 is stored, one pending link per
//! account, using it is one atomic `take`, and nothing answers differently
//! for an unknown address. What differs is what the link authorizes, which is
//! why it lives in its own table and expires in an hour rather than a day: a
//! confirmation link proves an inbox, this one sets a credential.
//!
//! Two accounts get no link, and both say so nowhere:
//!
//! - **No password to reset.** A Google-created account that never set one
//!   signs in with Google; mailing it a way to mint a password would add a
//!   credential its owner never asked for. It can still set one from the
//!   account page once signed in.
//! - **Banned.** Like [`crate::confirm::resend`], a suspended account is left
//!   alone.
//!
//! An *unconfirmed* account does get one, and using the link confirms it:
//! whoever opened the mail holds the inbox, which is exactly what the
//! confirmation link would have proved. That is also how the owner of an
//! address someone else registered takes it back.
//!
//! **A reset does not unlock anything.** The password here guards the
//! account on this server; vault files stay encrypted under the security
//! answers, which this server never sees. The mail says so.

use chrono::{Duration, Utc};

use crate::audit::{self, ClientInfo};
use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::profile;
use crate::state::AppState;
use crate::store::{Account, PasswordReset};

/// How long a mailed link stays usable. Short on purpose: it is a password
/// waiting to be set, sitting in an inbox.
pub const RESET_TTL_MINUTES: i64 = 60;

/// Minimum spacing of reset mails for one account, so the form cannot be
/// turned into a way to flood someone's inbox.
pub const REQUEST_COOLDOWN_SECS: i64 = 60;

/// Where a mailed link lands; the token follows as the last path segment.
pub const RESET_PATH: &str = "/reset";

const SUBJECT: &str = "Reset your Askrypt password";

/// Mails a reset link to `raw_email` if, and only if, it belongs to an
/// account that can use one, at most once per [`REQUEST_COOLDOWN_SECS`].
///
/// Always `Ok(())` short of a store failure, and the caller shows the same
/// page whatever happened: this form must not become a way to learn which
/// addresses are registered. The mail goes out on a spawned task, so the time
/// the request takes does not tell either.
pub(crate) async fn request_reset(
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
    if account.is_banned() || account.password_hash.is_none() {
        return Ok(());
    }
    if let Some(pending) = state.password_resets.get(account.id).await? {
        let age = Utc::now() - pending.created_at;
        if age < Duration::seconds(REQUEST_COOLDOWN_SECS) {
            tracing::debug!(account = %account.id, "password reset inside the cooldown");
            return Ok(());
        }
    }
    let state = state.clone();
    let client = client.clone();
    tokio::spawn(async move { send_reset(&state, &client, &account).await });
    Ok(())
}

/// Mints a fresh link for `account`, stores it (replacing any earlier one)
/// and mails it.
///
/// Never fails its caller, for the reason
/// [`crate::confirm::send_confirmation`] does not: there is nothing the user
/// could do about a relay being down except ask again, and the answer they
/// get must not depend on it.
async fn send_reset(state: &AppState, client: &ClientInfo, account: &Account) {
    let now = Utc::now();
    // No GC task in this server; the send path sweeps, like device links.
    if let Err(err) = state.password_resets.delete_expired(now).await {
        tracing::warn!(error = %err, "failed to sweep expired password resets");
    }
    let token = auth::new_session_token();
    let pending = PasswordReset {
        account_id: account.id,
        token_hash: profile::session_id(&token),
        created_at: now,
        expires_at: now + Duration::minutes(RESET_TTL_MINUTES),
    };
    if let Err(err) = state.password_resets.put(pending).await {
        tracing::warn!(error = %err, account = %account.id, "failed to store a password reset");
        return;
    }
    let body = mail_body(&reset_url(&state.public_url, &token));
    match state.mailer.send(&account.email, SUBJECT, &body).await {
        Ok(()) => audit::emit(audit::PASSWORD_RESET_SENT, client, Some(account.id), "-"),
        // The relay's reason, never the body: it holds the token.
        Err(err) => tracing::warn!(
            error = %err,
            account = %account.id,
            "failed to send the password reset",
        ),
    }
}

/// Spends a mailed link: sets `new_password` on its account and signs every
/// device out.
///
/// The password is validated **before** the token is taken, so a too-short
/// one costs nothing — the link is still there to try again with. Every
/// session goes, without exception: a reset is what someone does when they
/// have lost control of the account, and the device driving it has no session
/// to keep (nobody is signed in on this page).
///
/// Unknown, expired and already-used tokens all fail with the same
/// [`invalid_reset`].
pub(crate) async fn complete_reset(
    state: &AppState,
    client: &ClientInfo,
    token: &str,
    new_password: String,
) -> ApiResult<Account> {
    auth::validate_password(&new_password)?;
    let hash = profile::session_id(token.trim());
    let Some(pending) = state.password_resets.take(&hash, Utc::now()).await? else {
        audit::emit(audit::PASSWORD_RESET_FAILED, client, None, "invalid_token");
        return Err(invalid_reset());
    };
    let Some(mut account) = state.accounts.get(pending.account_id).await? else {
        audit::emit(
            audit::PASSWORD_RESET_FAILED,
            client,
            Some(pending.account_id),
            "account_missing",
        );
        return Err(invalid_reset());
    };
    // Suspended between asking and answering: the link is spent either way,
    // and the honest refusal is the one a correct password would get.
    if account.is_banned() {
        audit::emit(
            audit::PASSWORD_RESET_FAILED,
            client,
            Some(account.id),
            "account_banned",
        );
        return Err(auth::account_banned());
    }
    account.password_hash = Some(auth::hash_password(new_password).await?);
    // Opening the mail proved the inbox, which is all a confirmation link
    // proves. Nobody has to chase a second one.
    if !account.is_confirmed() {
        account.email_confirmed_at = Some(Utc::now());
    }
    state.accounts.update(&account).await?;
    audit::emit(audit::PASSWORD_RESET, client, Some(account.id), "");
    let revoked = profile::revoke_sessions(state, account.id, None).await?;
    if revoked > 0 {
        audit::emit(
            audit::SESSIONS_REVOKED_BULK,
            client,
            Some(account.id),
            &revoked.to_string(),
        );
    }
    Ok(account)
}

pub(crate) fn invalid_reset() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "invalid_reset",
        "this reset link is invalid, expired, or already used",
    )
}

fn reset_url(public_url: &str, token: &str) -> String {
    format!("{public_url}{RESET_PATH}/{token}")
}

fn mail_body(url: &str) -> String {
    format!(
        "Someone asked to reset the password of your Askrypt account.\n\
         \n\
         Choose a new password here:\n\
         \n\
         {url}\n\
         \n\
         The link works once and expires in {RESET_TTL_MINUTES} minutes. \
         Setting a new password signs you out everywhere else.\n\
         \n\
         This password protects your account on this server. It does not \
         unlock your vault files: those stay encrypted with your security \
         answers, which this server never receives and cannot reset.\n\
         \n\
         If you did not ask for this, ignore this message — your password \
         stays as it is unless the link is opened and a new one is set.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mail_carries_the_link_and_says_what_it_cannot_do() {
        let url = reset_url("https://askrypt.example", "abc123");
        assert_eq!(url, "https://askrypt.example/reset/abc123");
        let body = mail_body(&url);
        assert!(body.contains("\nhttps://askrypt.example/reset/abc123\n"));
        // The one sentence that keeps a reset from being read as vault
        // recovery.
        assert!(body.contains("security answers"));
    }
}
