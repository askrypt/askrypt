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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::clientip;
use crate::error::ApiError;

pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    windows: Mutex<HashMap<String, Window>>,
}

struct Window {
    started: Instant,
    count: u32,
}

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

fn client_key(request: &Request) -> String {
    let extensions = request.extensions();
    clientip::client_ip(
        request.headers(),
        extensions,
        clientip::policy_of(extensions),
    )
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
    fn window_resets_after_elapsing() {
        let limiter = RateLimiter::new(1, Duration::from_millis(20));
        assert!(limiter.try_acquire("a"));
        assert!(!limiter.try_acquire("a"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.try_acquire("a"));
    }
}
