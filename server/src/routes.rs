//! Router assembly and the Phase 0 handlers.
//!
//! Everything dynamic will live under `/api/v1` (Phase 1+); for now the
//! router exposes the health check and a JSON 404 fallback so every response
//! the server produces follows the error convention in [`crate::error`].

use axum::Router;
use axum::routing::get;
use axum::Json;
use serde::Serialize;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(fallback)
        .with_state(state)
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn fallback() -> ApiError {
    ApiError::not_found("no such endpoint")
}
