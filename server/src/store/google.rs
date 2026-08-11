//! Real Google ID-token verification (Phase 2).
//!
//! [`GoogleIdTokenVerifier`] validates signature, issuer, audience and
//! expiry against Google's published JWKS, caching the keys in memory and
//! refetching when a token names an unknown key id (Google rotates keys).
//! Whether the email may be trusted (`email_verified`) is left to the
//! caller, per the [`IdTokenVerifier`] contract.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use tokio::sync::RwLock;

use super::types::{GoogleClaims, Jwk, JwkSet, KeyCache};
use super::{IdTokenError, IdTokenVerifier, VerifiedIdToken};

pub use super::types::{GoogleIdTokenVerifier, NotConfiguredIdTokenVerifier};

const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Floor between JWKS refetches, so a flood of tokens with bogus key ids
/// cannot make us hammer Google.
const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

impl GoogleIdTokenVerifier {
    pub fn new(client_ids: Vec<String>) -> Self {
        Self {
            client_ids,
            jwks_url: JWKS_URL.to_string(),
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .expect("reqwest client"),
            keys: RwLock::new(KeyCache::default()),
        }
    }

    async fn cached_key(&self, kid: &str) -> Option<Jwk> {
        self.keys.read().await.keys.get(kid).cloned()
    }

    async fn refresh_keys(&self) -> Result<(), IdTokenError> {
        {
            let cache = self.keys.read().await;
            if let Some(at) = cache.fetched_at
                && at.elapsed() < MIN_REFETCH_INTERVAL
            {
                return Ok(());
            }
        }
        let set: JwkSet = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| IdTokenError::Backend(format!("jwks fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| IdTokenError::Backend(format!("jwks parse failed: {e}")))?;

        let mut cache = self.keys.write().await;
        cache.keys = set
            .keys
            .into_iter()
            .filter(|k| k.kty == "RSA" && !k.kid.is_empty())
            .map(|k| (k.kid.clone(), k))
            .collect();
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}

#[async_trait]
impl IdTokenVerifier for GoogleIdTokenVerifier {
    async fn verify(&self, id_token: &str) -> Result<VerifiedIdToken, IdTokenError> {
        let header = decode_header(id_token)
            .map_err(|e| IdTokenError::Invalid(format!("bad token header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| IdTokenError::Invalid("token has no key id".into()))?;

        let jwk = match self.cached_key(&kid).await {
            Some(jwk) => jwk,
            None => {
                self.refresh_keys().await?;
                self.cached_key(&kid)
                    .await
                    .ok_or_else(|| IdTokenError::Invalid("unknown key id".into()))?
            }
        };
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| IdTokenError::Backend(format!("bad jwk from google: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&self.client_ids);
        validation.set_issuer(&ISSUERS);
        let claims = decode::<GoogleClaims>(id_token, &key, &validation)
            .map_err(|e| IdTokenError::Invalid(e.to_string()))?
            .claims;

        let email = claims
            .email
            .ok_or_else(|| IdTokenError::Invalid("token has no email claim".into()))?;
        Ok(VerifiedIdToken {
            subject: claims.sub,
            email,
            email_verified: claims.email_verified,
        })
    }
}

#[async_trait]
impl IdTokenVerifier for NotConfiguredIdTokenVerifier {
    async fn verify(&self, _id_token: &str) -> Result<VerifiedIdToken, IdTokenError> {
        Err(IdTokenError::NotConfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn garbage_token_is_invalid_without_network() {
        let verifier = GoogleIdTokenVerifier::new(vec!["client-id".into()]);
        assert!(matches!(
            verifier.verify("not-a-jwt").await,
            Err(IdTokenError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn not_configured_verifier_always_fails() {
        assert!(matches!(
            NotConfiguredIdTokenVerifier.verify("anything").await,
            Err(IdTokenError::NotConfigured)
        ));
    }
}
