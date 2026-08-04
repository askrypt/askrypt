//! HTML error responses.
//!
//! The JSON `{"error": {code, message}}` envelope stays exclusive to
//! `/api/v1`; a browser gets a page. The shared service functions in
//! [`crate::auth`] and friends keep returning [`ApiError`], and
//! `From<ApiError>` below is the seam that turns one into the other — so
//! there is still exactly one implementation of every rule.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::store::StoreError;
use crate::web::render::{Chrome, Page};

pub type WebResult<T> = Result<T, WebError>;

#[derive(Debug)]
pub struct WebError {
    pub status: StatusCode,
    pub title: &'static str,
    pub message: String,
}

impl WebError {
    pub fn new(status: StatusCode, title: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            title,
            message: message.into(),
        }
    }

    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "Page not found",
            "That page doesn't exist. It may have moved, or the link may be wrong.",
        )
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "That didn't work", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "Request refused", message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "Slow down", message)
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "The server hit a problem. Nothing was changed; please try again.",
        )
    }
}

impl From<ApiError> for WebError {
    fn from(err: ApiError) -> Self {
        // 5xx messages are deliberately generic in `ApiError` too, but going
        // through `internal()` keeps the copy in one voice and guarantees no
        // backend detail can reach a page by accident.
        if err.status.is_server_error() {
            return Self::internal();
        }
        let title = match err.status {
            StatusCode::NOT_FOUND => "Not found",
            StatusCode::UNAUTHORIZED => "Sign in to continue",
            StatusCode::FORBIDDEN => "Request refused",
            StatusCode::CONFLICT => "That's already taken",
            StatusCode::TOO_MANY_REQUESTS => "Slow down",
            _ => "That didn't work",
        };
        // `ApiError` messages are written for humans and never carry
        // internals, so they can be shown as-is.
        Self::new(err.status, title, err.message)
    }
}

impl From<StoreError> for WebError {
    fn from(err: StoreError) -> Self {
        ApiError::from(err).into()
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    chrome: Chrome,
    status: u16,
    title: &'static str,
    message: String,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        // Rendered with anonymous chrome: an error can surface from an
        // extractor rejection, which has no session lookup to draw the nav
        // from. The 404 page reached through the router fallback is a real
        // handler and gets proper chrome — see `web::pages::not_found`.
        let page = Page(ErrorTemplate {
            chrome: Chrome::anonymous(),
            status: self.status.as_u16(),
            title: self.title,
            message: self.message,
        });
        (self.status, page).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_errors_never_carry_their_message_across() {
        let leaky = ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "connection refused to /var/lib/askrypt/askrypt.db",
        );
        let web = WebError::from(leaky);
        assert_eq!(web.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!web.message.contains("askrypt.db"), "{}", web.message);
    }

    #[test]
    fn client_errors_keep_their_wording() {
        let web = WebError::from(ApiError::bad_request("password must be longer"));
        assert_eq!(web.status, StatusCode::BAD_REQUEST);
        assert_eq!(web.message, "password must be longer");
    }
}
