//! Uniform JSON error responses.
//!
//! Every error leaving the API has the shape
//! `{"error": {"code": "<machine_code>", "message": "<human text>"}}` with a
//! matching HTTP status. Handlers return [`ApiResult`] and convert domain
//! errors via the `From` impls below.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode, header};
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
    /// Emitted as `Retry-After: <seconds>`; set on the throttling and
    /// overload responses so clients back off instead of hammering.
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Attaches a `Retry-After` hint (seconds) to the response.
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
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
                body_error_code(rejection.status()),
                rejection.body_text(),
            )),
        }
    }
}

/// Raw-body counterpart of [`ApiJson`]: buffers the request body as
/// [`Bytes`], with rejections (over the body limit, aborted transfers)
/// following the JSON error envelope instead of axum's plain-text default.
pub struct ApiBytes(pub Bytes);

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
