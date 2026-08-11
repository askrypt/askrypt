//! Uniform JSON error responses.
//!
//! Every error leaving the API has the shape
//! `{"error": {"code": "<machine_code>", "message": "<human text>"}}` with a
//! matching HTTP status. Handlers return [`ApiResult`] and convert domain
//! errors via the `From` impls below.
//!
//! The shapes themselves — [`ApiError`], [`ApiJson`], [`ApiBytes`] and the
//! serialized envelope — are declared in [`crate::types`] and re-exported
//! here; everything below is behaviour over them.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;

use crate::store::{IdTokenError, StoreError};
use crate::types::{ErrorBody, ErrorDetail};

pub use crate::types::{ApiBytes, ApiError, ApiJson, ApiResult};

impl ApiError {
    /// Every other constructor funnels through here, which makes this the one
    /// place that can log *all* of them — including the errors that never
    /// become a response, like the one `web::session::lookup` discards with
    /// `.ok()?` to redirect instead.
    ///
    /// `#[track_caller]` puts the raising site in the log rather than this
    /// file. Two known blind spots: passing a constructor as a function
    /// pointer (`ok_or_else(ApiError::unauthorized)`) resolves the location
    /// through a shim, and the `From` impls below raise from inside this
    /// module — their own `tracing::error!` lines name the cause instead.
    #[track_caller]
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        let message = message.into();
        let caller = std::panic::Location::caller();
        // Client errors are chatter; server errors are the ones worth seeing
        // with the crate at its default `info` in production.
        if status.is_server_error() {
            tracing::warn!(%status, code, message, %caller, "api error");
        } else {
            tracing::debug!(%status, code, message, %caller, "api error");
        }
        Self {
            status,
            code,
            message,
            retry_after: None,
        }
    }

    /// Attaches a `Retry-After` hint (seconds) to the response.
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    #[track_caller]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    #[track_caller]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    #[track_caller]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    #[track_caller]
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
        )
    }

    /// Internal errors get logged with detail but answer with a generic
    /// message — backend specifics never leak to clients.
    #[track_caller]
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Destructured up front: the body borrows `message` while `status`
        // moves into the response tuple.
        let ApiError {
            status,
            code,
            message,
            retry_after,
        } = self;
        let body = Json(ErrorBody {
            error: ErrorDetail {
                code,
                message: &message,
            },
        });
        let mut response = (status, body).into_response();
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

impl From<StoreError> for ApiError {
    #[track_caller]
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
    #[track_caller]
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
                body_error_code(rejection.status()),
                rejection.body_text(),
            )),
        }
    }
}

impl<S> FromRequest<S> for ApiBytes
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Bytes::from_request(req, state).await {
            Ok(bytes) => Ok(Self(bytes)),
            Err(rejection) => Err(ApiError::new(
                rejection.status(),
                body_error_code(rejection.status()),
                rejection.body_text(),
            )),
        }
    }
}

/// Error code for a body-extractor rejection. Requests over the body limit
/// get their own code so clients can tell "too big" from "malformed".
fn body_error_code(status: StatusCode) -> &'static str {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        "payload_too_large"
    } else {
        "bad_request"
    }
}
