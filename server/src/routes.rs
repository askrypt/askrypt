//! Router assembly and the Phase 0/1 handlers.
//!
//! Namespacing (Phase 1): everything dynamic lives under `/api/v1`, which
//! answers unknown paths with a JSON 404 per the error convention in
//! [`crate::error`]. Everything else falls back to the static assets in the
//! configured static dir, with unknown paths served `index.html` (SPA
//! fallback routing) so client-side routes work after Phase 7. `/healthz`
//! stays at the root as an infrastructure endpoint.

use std::path::Path;

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;
use tower_http::services::{ServeDir, ServeFile};

use crate::error::ApiError;
use crate::state::AppState;

pub fn router(state: AppState, static_dir: &Path) -> Router {
    let api_v1 = Router::new()
        .route("/about", get(about))
        .fallback(api_fallback);

    let static_assets = ServeDir::new(static_dir)
        .fallback(ServeFile::new(static_dir.join("index.html")));

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
