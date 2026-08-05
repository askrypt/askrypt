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
//! Phase 7.2 shipped sign-in, registration and sign-out; 7.3 the profile
//! pages ([`account`]); 7.4 the vault file manager ([`vaults`]). Browser
//! Google sign-in is still missing — the JSON API covers it for native
//! clients, and the redirect flow needs configuration the server doesn't
//! have yet (see `server/PLAN.md`).

pub mod account;
pub mod auth;
pub mod csrf;
pub mod error;
pub mod flash;
pub mod pages;
pub mod render;
pub mod session;
pub mod vaults;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::hardening;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;

pub use error::{WebError, WebResult};
pub use pages::not_found;
pub use session::{MaybeWebSession, WebSession};

/// Headroom over [`crate::vaults::MAX_VAULT_BYTES`] for the multipart
/// envelope: part headers, boundaries and the handful of text fields that
/// travel with the file.
const MULTIPART_OVERHEAD_BYTES: usize = 64 * 1024;

/// The HTML routes.
///
/// Both limiters are the *same* [`RateLimiter`] instances the `/api/v1`
/// routes use: sign-in over a form and sign-in over JSON must share one
/// budget, or an attacker just alternates between them. The same goes for
/// the current-password re-auth behind the profile limiter.
pub fn routes(
    auth_limiter: Arc<RateLimiter>,
    profile_limiter: Arc<RateLimiter>,
) -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        .route_layer(middleware::from_fn_with_state(auth_limiter, rate_limit));

    // Email and password changes are the two forms worth guessing at, so
    // they sit behind the same bucket as their JSON twins.
    let account_sensitive = Router::new()
        .route("/account/email", post(account::update_email))
        .route("/account/password", post(account::update_password))
        .route_layer(middleware::from_fn_with_state(profile_limiter, rate_limit));

    let account_routes = Router::new()
        .route("/account", get(account::page))
        .route("/account/devices/{id}", post(account::revoke_device))
        .route("/account/delete", post(account::delete_account))
        .merge(account_sensitive);

    let vault_routes = Router::new()
        .route("/vaults", get(vaults::page).post(vaults::upload))
        .route("/vaults/{id}/replace", post(vaults::replace))
        .route("/vaults/{id}/name", post(vaults::rename))
        .route("/vaults/{id}/delete", post(vaults::remove))
        .route("/vaults/{id}/download", get(vaults::download))
        // Same trick as the API's vault routes: declared here, inside the
        // router's global limit, so it overrides it for uploads only.
        .layer(DefaultBodyLimit::max(
            crate::vaults::MAX_VAULT_BYTES + MULTIPART_OVERHEAD_BYTES,
        ));

    Router::new()
        .route("/", get(pages::landing))
        .route("/logout", post(auth::logout))
        .merge(auth_routes)
        .merge(account_routes)
        .merge(vault_routes)
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
