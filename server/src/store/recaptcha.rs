//! Real Google reCAPTCHA v3 verification.
//!
//! v3 mints a token in the page and scores it server-side; there is no
//! challenge to solve and no user interaction, which is why the two auth
//! forms need JavaScript once a site key is configured (see
//! [`crate::web::captcha`]).
//!
//! Three checks make a token acceptable, and all three matter:
//!
//! - `success` — the token verified at all: not forged, not expired, not
//!   already spent. v3 tokens are single-use and live two minutes.
//! - **the action matches** — a v3 token carries the action the page asked
//!   for. Without this check a token minted on some cheap public page could
//!   be replayed against `/login`, and the score would say nothing about the
//!   submit it is standing in for.
//! - **the score clears the floor** — 1.0 is very likely human, 0.0 very
//!   likely a bot. Google's own default cut is 0.5.
//!
//! Verification is a network call in the login path, so it carries a short
//! timeout: a slow relay must not hold the handler open to the request
//! timeout.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;

use super::types::SiteVerify;
use super::{CaptchaError, CaptchaVerifier};

pub use super::types::{DisabledCaptchaVerifier, RecaptchaConfig, RecaptchaVerifier};

const VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Error codes `siteverify` returns that mean *we* are misconfigured rather
/// than that the visitor failed. They are the ones worth an operator's
/// attention: everything else is an ordinary refusal.
const OUR_FAULT: [&str; 3] = [
    "invalid-input-secret",
    "missing-input-secret",
    "bad-request",
];

/// Hand-written so the secret cannot ride out in `Config`'s derived `Debug`,
/// which is rendered at startup.
impl fmt::Debug for RecaptchaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecaptchaConfig")
            .field("site_key", &self.site_key)
            .field("secret", &"<redacted>")
            .field("min_score", &self.min_score)
            .finish()
    }
}

impl RecaptchaVerifier {
    pub fn new(config: RecaptchaConfig) -> Self {
        Self {
            config,
            verify_url: VERIFY_URL.to_string(),
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait]
impl CaptchaVerifier for RecaptchaVerifier {
    fn site_key(&self) -> Option<&str> {
        Some(&self.config.site_key)
    }

    async fn verify(
        &self,
        token: &str,
        action: &str,
        client_ip: Option<&str>,
    ) -> Result<Option<f32>, CaptchaError> {
        // An empty field is the no-JavaScript case and the scripted-POST
        // case alike. Refuse it here rather than spending a round trip on a
        // token Google would refuse anyway.
        if token.is_empty() {
            return Err(CaptchaError::Rejected("no token submitted".into()));
        }

        let mut form = vec![("secret", self.config.secret.as_str()), ("response", token)];
        // Only a real address is a useful hint; `clientip`'s placeholder for
        // an unresolvable peer would just be a malformed parameter.
        if let Some(ip) = client_ip.filter(|ip| ip.parse::<IpAddr>().is_ok()) {
            form.push(("remoteip", ip));
        }

        let reply: SiteVerify = self
            .http
            .post(&self.verify_url)
            .form(&form)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| CaptchaError::Backend(format!("siteverify request failed: {e}")))?
            .json()
            .await
            .map_err(|e| CaptchaError::Backend(format!("siteverify parse failed: {e}")))?;

        assess(&reply, action, self.config.min_score)
    }
}

/// Turns a `siteverify` reply into a verdict.
///
/// Split out of the request so the rules can be tested without a network or
/// a fake HTTP server — the request itself has nothing in it worth testing.
fn assess(
    reply: &SiteVerify,
    expected_action: &str,
    min_score: f32,
) -> Result<Option<f32>, CaptchaError> {
    if !reply.success {
        let codes = reply.error_codes.join(",");
        // A bad secret refuses *every* visitor, so it must not look like a
        // caught bot in the log.
        if reply
            .error_codes
            .iter()
            .any(|c| OUR_FAULT.contains(&c.as_str()))
        {
            return Err(CaptchaError::Backend(format!(
                "siteverify refused our request: {codes}"
            )));
        }
        return Err(CaptchaError::Rejected(format!("not successful: {codes}")));
    }

    // A v3 token names the action it was minted for. A mismatch means the
    // token came from somewhere else on the site (or from a page an attacker
    // controls a copy of) and says nothing about this submit.
    match reply.action.as_deref() {
        Some(action) if action == expected_action => {}
        other => {
            return Err(CaptchaError::Rejected(format!(
                "action mismatch: expected {expected_action}, got {}",
                other.unwrap_or("none")
            )));
        }
    }

    // No score at all means this is not a v3 reply — treat it as a refusal
    // rather than silently accepting an unscored token.
    let score = reply
        .score
        .ok_or_else(|| CaptchaError::Rejected("reply carried no score".into()))?;
    if score < min_score {
        return Err(CaptchaError::Rejected(format!(
            "score {score} below {min_score}"
        )));
    }
    Ok(Some(score))
}

#[async_trait]
impl CaptchaVerifier for DisabledCaptchaVerifier {
    fn site_key(&self) -> Option<&str> {
        None
    }

    async fn verify(
        &self,
        _token: &str,
        _action: &str,
        _client_ip: Option<&str>,
    ) -> Result<Option<f32>, CaptchaError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_reply(score: f32, action: &str) -> SiteVerify {
        SiteVerify {
            success: true,
            score: Some(score),
            action: Some(action.to_string()),
            error_codes: Vec::new(),
        }
    }

    #[test]
    fn a_good_token_passes_and_reports_its_score() {
        assert_eq!(
            assess(&ok_reply(0.9, "login"), "login", 0.5).unwrap(),
            Some(0.9)
        );
        // Exactly at the floor is accepted: the threshold is a minimum.
        assert_eq!(
            assess(&ok_reply(0.5, "login"), "login", 0.5).unwrap(),
            Some(0.5)
        );
    }

    #[test]
    fn a_low_score_is_rejected() {
        assert!(matches!(
            assess(&ok_reply(0.1, "login"), "login", 0.5),
            Err(CaptchaError::Rejected(_))
        ));
    }

    /// The replay guard: a token minted for one form must not authorize
    /// another.
    #[test]
    fn a_token_for_another_action_is_rejected() {
        assert!(matches!(
            assess(&ok_reply(1.0, "register"), "login", 0.5),
            Err(CaptchaError::Rejected(_))
        ));
        // And a reply naming no action at all, which is what a v2 token
        // posted at this endpoint would look like.
        let mut reply = ok_reply(1.0, "login");
        reply.action = None;
        assert!(matches!(
            assess(&reply, "login", 0.5),
            Err(CaptchaError::Rejected(_))
        ));
    }

    #[test]
    fn a_successful_reply_without_a_score_is_not_trusted() {
        let mut reply = ok_reply(1.0, "login");
        reply.score = None;
        assert!(matches!(
            assess(&reply, "login", 0.5),
            Err(CaptchaError::Rejected(_))
        ));
    }

    /// A misconfigured secret refuses every visitor; it must be told apart
    /// from a bot so it reads as an outage and not as the feature working.
    #[test]
    fn our_own_misconfiguration_is_a_backend_error() {
        let reply = SiteVerify {
            error_codes: vec!["invalid-input-secret".into()],
            ..SiteVerify::default()
        };
        assert!(matches!(
            assess(&reply, "login", 0.5),
            Err(CaptchaError::Backend(_))
        ));

        let stale = SiteVerify {
            error_codes: vec!["timeout-or-duplicate".into()],
            ..SiteVerify::default()
        };
        assert!(matches!(
            assess(&stale, "login", 0.5),
            Err(CaptchaError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn an_empty_token_costs_no_round_trip() {
        let verifier = RecaptchaVerifier::new(RecaptchaConfig {
            site_key: "site".into(),
            secret: "secret".into(),
            min_score: 0.5,
        });
        // Would hang or fail on the network if it got that far; the guard
        // returns first.
        assert!(matches!(
            verifier.verify("", "login", None).await,
            Err(CaptchaError::Rejected(_))
        ));
    }

    #[test]
    fn the_secret_is_redacted_from_debug_output() {
        let config = RecaptchaConfig {
            site_key: "public-site-key".into(),
            secret: "super-secret".into(),
            min_score: 0.5,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("public-site-key"));
    }

    #[tokio::test]
    async fn the_disabled_verifier_offers_no_key_and_checks_nothing() {
        assert_eq!(DisabledCaptchaVerifier.site_key(), None);
        assert_eq!(
            DisabledCaptchaVerifier
                .verify("", "login", None)
                .await
                .unwrap(),
            None
        );
    }
}
