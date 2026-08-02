//! Uniform JSON error responses.
//!
//! Every error leaving the API has the shape
//! `{"error": {"code": "<machine_code>", "message": "<human text>"}}` with a
//! matching HTTP status. Handlers return [`ApiResult`] and convert domain
//! errors via the `From` impls below.

use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::store::{IdTokenError, StoreError};

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

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        )
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

impl From<IdTokenError> for ApiError {
    fn from(err: IdTokenError) -> Self {
        match err {
            IdTokenError::Invalid(msg) => Self::new(
                StatusCode::UNAUTHORIZED,
                "invalid_google_token",
                format!("Google sign-in failed: {msg}"),
            ),
            IdTokenError::NotConfigured => Self::new(
                StatusCode::NOT_IMPLEMENTED,
                "google_signin_not_configured",
                "Google sign-in is not configured on this server",
            ),
            other => {
                tracing::error!(error = %other, "id token verifier error");
                Self::internal()
            }
        }
    }
}

/// Drop-in replacement for [`axum::Json`] as an extractor whose rejection
/// (malformed/missing body) follows the JSON error envelope instead of
/// axum's plain-text default.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::new(
                rejection.status(),
                "bad_request",
                rejection.body_text(),
            )),
        }
    }
}
