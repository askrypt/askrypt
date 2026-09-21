//! Fixed-window, per-client rate limiting for the auth endpoints (Phase 2).
//!
//! Deliberately simple: an in-memory counter per client key, good enough to
//! blunt credential stuffing on a single-node deployment. The client key
//! comes from [`crate::clientip`], which only believes proxy headers when
//! the deployment says a proxy is in front (Phase 5); otherwise the peer
//! address is used, so the buckets can't be forged.
//!
//! Counters live in process memory: they reset on restart, and a multi-node
//! deployment would need a shared store.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::clientip;
use crate::error::ApiError;
use crate::types::Window;

pub use crate::types::RateLimiter;

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit for `key`; `false` means over the limit.
    pub fn try_acquire(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap();
        // Keep the map bounded: drop windows that have already expired.
        if windows.len() >= 1024 {
            let window = self.window;
            windows.retain(|_, w| now.duration_since(w.started) < window);
        }
        let entry = windows.entry(key.to_string()).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.count = 0;
        }
        entry.count += 1;
        entry.count <= self.max_per_window
    }

    /// Window length, sent as the `Retry-After` hint on a 429.
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs().max(1)
    }
}

pub async fn middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !limiter.try_acquire(&client_key(&request)) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests; try again later",
        )
        .with_retry_after(limiter.window_secs()));
    }
    Ok(next.run(request).await)
}

/// Bucket key for a request. Shared with [`crate::web`], whose HTML auth
/// routes hit the *same* limiter instance as `/api/v1/auth` so a browser and
/// an API client can't be used to double an attacker's budget.
///
/// IPv6 clients are bucketed by /64: that is what one subscriber is handed,
/// so keying on the full address would give a single host 2^64 budgets.
pub(crate) fn client_key(request: &Request) -> String {
    let extensions = request.extensions();
    bucket(clientip::client_ip(
        request.headers(),
        extensions,
        clientip::policy_of(extensions),
    ))
}

/// Folds an IPv6 address to its /64; anything else (IPv4, a v4-mapped v6, a
/// value that is not an address at all) is its own bucket, unchanged.
fn bucket(ip: String) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let prefix = u128::from(v6) & !(u128::from(u64::MAX));
            format!("{}/64", Ipv6Addr::from(prefix))
        }
        _ => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks_per_key() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.try_acquire("a"));
        }
        assert!(!limiter.try_acquire("a"));
        assert!(limiter.try_acquire("b")); // other clients unaffected
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let a = bucket("2001:db8:1:2:aaaa::1".into());
        let b = bucket("2001:db8:1:2:ffff:ffff:ffff:ffff".into());
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_ne!(a, bucket("2001:db8:1:3::1".into()));
    }

    #[test]
    fn other_keys_pass_through() {
        assert_eq!(bucket("203.0.113.7".into()), "203.0.113.7");
        assert_eq!(bucket("::ffff:203.0.113.7".into()), "::ffff:203.0.113.7");
        assert_eq!(bucket("unknown".into()), "unknown");
    }

    #[test]
    fn window_resets_after_elapsing() {
        let limiter = RateLimiter::new(1, Duration::from_millis(20));
        assert!(limiter.try_acquire("a"));
        assert!(!limiter.try_acquire("a"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.try_acquire("a"));
    }
}
