//! Uniform JSON error responses.
//!
//! Every error leaving the API has the shape
//! `{"error": {"code": "<machine_code>", "message": "<human text>"}}` with a
//! matching HTTP status. Handlers return [`ApiResult`] and convert domain
//! errors via the `From` impls below.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::store::StoreError;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    /// Stable machine-readable code (snake_case), independent of the message.
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// Internal errors get logged with detail but answer with a generic
    /// message — backend specifics never leak to clients.
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
        )
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: &self.message,
            },
        });
        (self.status, body).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound => Self::not_found("resource not found"),
            StoreError::Conflict(msg) => Self::conflict(msg),
            other => {
                tracing::error!(error = %other, "store backend error");
                Self::internal()
            }
        }
    }
}
