//! The website: server-rendered HTML with htmx (plan Phase 7).
//!
//! A *second* consumer of the same account and vault logic, never a
//! constraint on it. Everything browser-shaped — the session cookie, CSRF,
//! redirects, flash messages, HTML errors — lives in here; `/api/v1` stays
//! exactly what the desktop and mobile apps already talk to.
//!
//! Two rules the templates in `server/templates/` are written to:
//!
//! - **The CSP is not negotiable.** `script-src 'self'` / `style-src 'self'`
//!   with no `unsafe-inline` means no inline `<script>` or `<style>`, no
//!   `hx-on:` handlers, and no `js:`-prefixed htmx expressions. See
//!   [`crate::hardening`].
//! - **htmx is an enhancement.** Every page and form works when it isn't
//!   loaded: an `HX-Request` gets a fragment, a plain request gets the whole
//!   page, and the plain path is the one that has to be correct.
//!
//! Phase 7.2 ships sign-in, registration and sign-out. The profile pages
//! (7.3), the vault file manager (7.4) and browser Google sign-in are still
//! to come; the JSON API already covers all three for native clients.

pub mod auth;
pub mod csrf;
pub mod error;
pub mod flash;
pub mod pages;
pub mod render;
pub mod session;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::hardening;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;

pub use error::{WebError, WebResult};
pub use pages::not_found;
pub use session::{MaybeWebSession, WebSession};

/// The HTML routes.
///
/// `auth_limiter` is the *same* [`RateLimiter`] instance the `/api/v1/auth`
/// routes use: sign-in over a form and sign-in over JSON must share one
/// budget, or an attacker just alternates between them.
pub fn routes(auth_limiter: Arc<RateLimiter>) -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        .route_layer(middleware::from_fn_with_state(auth_limiter, rate_limit));

    Router::new()
        .route("/", get(pages::landing))
        .route("/account", get(pages::account))
        .route("/logout", post(auth::logout))
        .merge(auth_routes)
        // Pages are per-session by definition; none of them may sit in a
        // shared cache. `/assets` is mounted outside this router and keeps
        // ordinary caching.
        .layer(middleware::from_fn(hardening::no_store))
}

/// HTML twin of [`ratelimit::middleware`].
///
/// Identical bucketing — it calls the same [`RateLimiter`] with the same key
/// — but answers with a page instead of the JSON envelope, which would be a
/// strange thing for a browser to be shown.
async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, WebError> {
    if limiter.try_acquire(&ratelimit::client_key(&request)) {
        return Ok(next.run(request).await);
    }
    Err(WebError::too_many_requests(format!(
        "Too many attempts from your network. Try again in about {} seconds.",
        limiter.window_secs()
    )))
}
