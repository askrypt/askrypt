//! Router assembly.
//!
//! Namespacing (Phase 1): everything dynamic lives under `/api/v1`, which
//! answers unknown paths with a JSON 404 per the error convention in
//! [`crate::error`]. Everything else falls back to the static assets in the
//! configured static dir, with unknown paths served `index.html` (SPA
//! fallback routing) so client-side routes work after Phase 7. `/healthz`
//! stays at the root as an infrastructure endpoint.
//!
//! Auth (Phase 2): the handlers live in [`crate::auth`]; everything under
//! `/api/v1/auth` shares one fixed-window rate limiter.
//!
//! Profile (Phase 3): the `/api/v1/me` tree lives in [`crate::profile`]; the
//! email/password mutation endpoints get their own rate limiter so a stolen
//! bearer token can't brute-force the current password unthrottled.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, post, put};
use serde::Serialize;
use tower_http::services::{ServeDir, ServeFile};

use crate::auth;
use crate::error::ApiError;
use crate::profile;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;

const AUTH_RATE_LIMIT: u32 = 20;
const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);

pub fn router(state: AppState, static_dir: &Path) -> Router {
    let auth_limiter = Arc::new(RateLimiter::new(AUTH_RATE_LIMIT, AUTH_RATE_WINDOW));
    let auth_api = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/google", post(auth::google_login))
        .route("/logout", post(auth::logout))
        .route_layer(middleware::from_fn_with_state(
            auth_limiter,
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

    let api_v1 = Router::new()
        .route("/about", get(about))
        .route("/me", get(profile::me).delete(profile::delete_account))
        .route("/me/sessions", get(profile::list_sessions))
        .route("/me/sessions/{id}", delete(profile::revoke_session))
        .merge(profile_sensitive)
        .nest("/auth", auth_api)
        .fallback(api_fallback);

    let static_assets =
        ServeDir::new(static_dir).fallback(ServeFile::new(static_dir.join("index.html")));

    Router::new()
        .route("/healthz", get(healthz))
        .nest("/api/v1", api_v1)
        // Anything else under /api is not a page — keep 404s JSON there too.
        .route("/api/{*rest}", get(api_fallback).fallback(api_fallback))
        .fallback_service(static_assets)
        .with_state(state)
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
