//! reCAPTCHA v3 on the sign-in and registration forms.
//!
//! The website's only bot protection beyond the rate limiter, and the only
//! place on the site where JavaScript is *required* rather than an
//! enhancement: a v3 token can only be minted in the page, so with a site key
//! configured these two forms stop working without it. That exception is
//! deliberate and it is confined here — every other page and form still
//! renders and submits with scripts off.
//!
//! What is checked, and what is not:
//!
//! - **The two website forms**, before the password is looked at. Verifying
//!   first is the point: it is what keeps a flood of guesses from spending an
//!   argon2 hash each.
//! - **Not `/api/v1/auth/*`.** The desktop and mobile clients cannot mint a
//!   token, and the desktop's browser sign-in already lands on `/login`,
//!   which is captcha'd. The JSON endpoints keep the 20 req/min limiter they
//!   have always had. This is a known gap: a bot willing to post JSON skips
//!   the captcha entirely.
//!
//! The visitor-facing sentence is the same whatever went wrong. A message
//! that distinguished "no token" from "score too low" would be a tuning
//! signal handed straight to whoever is probing.

use crate::audit::{self, ClientInfo};
use crate::state::AppState;
use crate::store::CaptchaError;

/// v3 action for the sign-in form. A token carries the action it was minted
/// for and the verifier insists the two match, so these strings are what stop
/// a token from one form being replayed at the other.
pub const LOGIN_ACTION: &str = "login";

/// v3 action for the registration form.
pub const REGISTER_ACTION: &str = "register";

/// Shown when a submit's token does not hold up. Names JavaScript because
/// that is the one cause a visitor can actually do something about, and an
/// empty token is exactly what a scriptless browser sends.
const REFUSED: &str = "We could not confirm that you are a real person. \
Check that JavaScript is enabled, then try again.";

/// Shown when the check itself failed — a bad secret, or Google unreachable.
/// Separate wording because nothing the visitor does will help.
const UNAVAILABLE: &str = "We could not run the anti-bot check just now. \
Please try again in a moment.";

/// Checks the token a form carried.
///
/// `Err` is the sentence to re-render the form with; the reason it actually
/// failed goes to the log and the audit trail and never to the visitor.
pub async fn check(
    state: &AppState,
    client: &ClientInfo,
    token: &str,
    action: &'static str,
) -> Result<(), &'static str> {
    match state.captcha.verify(token, action, Some(&client.ip)).await {
        // `None` is "no captcha configured" — nothing was checked, and
        // nothing should be logged either.
        Ok(None) => Ok(()),
        Ok(Some(score)) => {
            tracing::debug!(action, score, "captcha passed");
            Ok(())
        }
        Err(CaptchaError::Rejected(reason)) => {
            tracing::info!(action, %reason, "captcha refused a submission");
            audit::emit(audit::CAPTCHA_FAILED, client, None, action);
            Err(REFUSED)
        }
        Err(error @ CaptchaError::Backend(_)) => {
            // Fail *closed*: a verifier we cannot reach means we cannot tell
            // a person from a bot, and this is the endpoint worth protecting.
            // Logged at `error` because it refuses every visitor until fixed.
            tracing::error!(action, %error, "captcha verification unavailable");
            Err(UNAVAILABLE)
        }
    }
}
