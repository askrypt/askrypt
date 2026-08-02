//! Fixed-window, per-client rate limiting for the auth endpoints (Phase 2).
//!
//! Deliberately simple: an in-memory counter per client key, good enough to
//! blunt credential stuffing on a single-node deployment. The client key is
//! the first `X-Forwarded-For` address when present (the expected reverse-
//! proxy setup — spoofable if the server is exposed directly, a Phase 5
//! hardening concern), else the peer address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

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
        ));
    }
    Ok(next.run(request).await)
}

fn client_key(request: &Request) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
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
