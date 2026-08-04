//! Router assembly.
//!
//! Namespacing (Phase 1): everything dynamic lives under `/api/v1`, which
//! answers unknown paths with a JSON 404 per the error convention in
//! [`crate::error`]. `/healthz` stays at the root as an infrastructure
//! endpoint.
//!
//! Website (Phase 7): the HTML pages in [`crate::web`] are explicit routes at
//! the root, the configured static dir is mounted at `/assets` for the
//! stylesheet and the vendored htmx, and unknown paths get an HTML 404. The
//! Phase 1 SPA fallback (every unknown path served `index.html`) is gone —
//! the site is server-rendered, so there are no client-side routes to
//! rescue.
//!
//! Auth (Phase 2): the handlers live in [`crate::auth`]; everything under
//! `/api/v1/auth` shares one fixed-window rate limiter.
//!
//! Profile (Phase 3): the `/api/v1/me` tree lives in [`crate::profile`]; the
//! email/password mutation endpoints get their own rate limiter so a stolen
//! bearer token can't brute-force the current password unthrottled.
//!
//! Vaults (Phase 4): the `/api/v1/vaults` tree lives in [`crate::vaults`];
//! its routes carry a raised request-body limit sized to the max vault file.
//!
//! Hardening (Phase 5): the cross-cutting layers from [`crate::hardening`]
//! wrap everything. Order matters and is documented at the call site below.

use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{delete, get, post, put};
use serde::Serialize;
use tokio::sync::Semaphore;
use tower_http::services::ServeDir;

use crate::auth;
use crate::clientip::ClientIpPolicy;
use crate::config::Config;
use crate::error::ApiError;
use crate::hardening::{self, SecurityHeaders};
use crate::profile;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;
use crate::vaults;
use crate::web;

const AUTH_RATE_LIMIT: u32 = 20;
const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);

pub fn router(state: AppState, config: &Config) -> Router {
    let auth_limiter = Arc::new(RateLimiter::new(AUTH_RATE_LIMIT, AUTH_RATE_WINDOW));
    let auth_api = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/google", post(auth::google_login))
        .route("/logout", post(auth::logout))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&auth_limiter),
            ratelimit::middleware,
        ));

    let profile_limiter = Arc::new(RateLimiter::new(AUTH_RATE_LIMIT, AUTH_RATE_WINDOW));
    let profile_sensitive = Router::new()
        .route("/me/email", put(profile::update_email))
        .route("/me/password", put(profile::change_password))
        .route_layer(middleware::from_fn_with_state(
            profile_limiter,
            ratelimit::middleware,
        ));

    let vaults_api = Router::new()
        .route("/", get(vaults::list).post(vaults::upload))
        .route(
            "/{id}",
            get(vaults::download)
                .put(vaults::replace)
                .delete(vaults::remove),
        )
        .route("/{id}/name", put(vaults::rename))
        .layer(DefaultBodyLimit::max(vaults::MAX_VAULT_BYTES));

    let api_v1 = Router::new()
        .route("/about", get(about))
        .route("/me", get(profile::me).delete(profile::delete_account))
        .route("/me/sessions", get(profile::list_sessions))
        .route("/me/sessions/{id}", delete(profile::revoke_session))
        .merge(profile_sensitive)
        .nest("/auth", auth_api)
        .nest("/vaults", vaults_api)
        .fallback(api_fallback)
        // After every nest/fallback, so it covers the whole API surface.
        .layer(middleware::from_fn(hardening::no_store));

    Router::new()
        .route("/healthz", get(healthz))
        .nest("/api/v1", api_v1)
        // Anything else under /api is not a page — keep 404s JSON there too.
        .route("/api/{*rest}", get(api_fallback).fallback(api_fallback))
        // The stylesheet and the vendored htmx, and nothing else: templates
        // are compiled into the binary.
        .nest_service("/assets", ServeDir::new(&config.static_dir))
        .merge(web::routes(auth_limiter))
        .fallback(web::not_found)
        // Layers wrap what was declared before them, so the LAST `.layer`
        // call is the FIRST middleware a request meets. Listed innermost
        // first:
        //   - the body limit must stay inside the vault routes' own, larger
        //     limit, which overwrites it for `/api/v1/vaults/*`;
        //   - the IP policy must be installed before the rate limiters read
        //     it;
        //   - shedding happens before any work, and security headers are
        //     outermost so the 429/503/504 short-circuits carry them too.
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .layer(Extension(ClientIpPolicy {
            trust_forwarded_for: config.trust_proxy,
        }))
        .layer(middleware::from_fn_with_state(
            config.request_timeout,
            hardening::request_timeout,
        ))
        .layer(middleware::from_fn_with_state(
            concurrency_semaphore(config.max_concurrent_requests),
            hardening::concurrency_limit,
        ))
        .layer(middleware::from_fn_with_state(
            SecurityHeaders { hsts: config.hsts },
            hardening::security_headers,
        ))
        .with_state(state)
}

/// `0` means "don't shed"; model it as an effectively unbounded semaphore
/// rather than branching the layer stack.
fn concurrency_semaphore(max: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(if max == 0 {
        Semaphore::MAX_PERMITS
    } else {
        max
    }))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

#[derive(Serialize)]
struct About {
    name: &'static str,
    version: &'static str,
}

async fn about() -> Json<About> {
    Json(About {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn api_fallback() -> ApiError {
    ApiError::not_found("no such endpoint")
}
