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

/// True when `status` means the *server* failed, rather than telling the
/// visitor something about their own request.
///
/// Deliberately not [`StatusCode::is_server_error`]: 507 sits in the 5xx
/// range but says the account is out of room, which is the visitor's to act
/// on and perfectly safe to word. Reading it as a backend failure is what
/// turned an over-quota upload into a "Something went wrong" page.
pub(crate) fn is_backend_failure(status: StatusCode) -> bool {
    status.is_server_error() && status != StatusCode::INSUFFICIENT_STORAGE
}

impl From<ApiError> for WebError {
    fn from(err: ApiError) -> Self {
        // 5xx messages are deliberately generic in `ApiError` too, but going
        // through `internal()` keeps the copy in one voice and guarantees no
        // backend detail can reach a page by accident.
        if is_backend_failure(err.status) {
            return Self::internal();
        }
        let title = match err.status {
            StatusCode::NOT_FOUND => "Not found",
            StatusCode::UNAUTHORIZED => "Sign in to continue",
            StatusCode::FORBIDDEN => "Request refused",
            StatusCode::CONFLICT => "That's already taken",
            StatusCode::TOO_MANY_REQUESTS => "Slow down",
            // Reached only when a caller has no better wording of its own;
            // `web::vaults::refused` explains the quota in the visitor's own
            // figures before it gets here.
            StatusCode::INSUFFICIENT_STORAGE => "Not enough space",
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

/// A rendered [`WebError`], riding along on the response so that
/// `web::htmx_error_fragment` can render it a second time as a fragment.
///
/// A response extension is the only channel available: `IntoResponse` cannot
/// see the request, so it cannot know htmx made it, and by the time a layer
/// can tell, the error is already a whole page.
#[derive(Clone)]
pub(crate) struct ErrorInfo {
    status: StatusCode,
    title: &'static str,
    message: String,
}

#[derive(Template)]
#[template(path = "fragments/error_notice.html")]
struct ErrorNotice {
    status: u16,
    title: &'static str,
    message: String,
    back: String,
}

impl ErrorInfo {
    /// The same words as the page, as one element htmx can swap in. `back`
    /// is where the "reload" link points.
    pub(crate) fn fragment(&self, back: String) -> Response {
        Page(ErrorNotice {
            status: self.status.as_u16(),
            title: self.title,
            message: self.message.clone(),
            back,
        })
        .into_response()
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let info = ErrorInfo {
            status: self.status,
            title: self.title,
            message: self.message.clone(),
        };
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
        let mut response = (self.status, page).into_response();
        response.extensions_mut().insert(info);
        response
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

    /// 507 is in the 5xx range but is a refusal, not a failure. Treating it
    /// as the latter is what made an over-quota upload answer 500.
    #[test]
    fn running_out_of_space_is_not_a_server_failure() {
        assert!(!is_backend_failure(StatusCode::INSUFFICIENT_STORAGE));
        assert!(is_backend_failure(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_backend_failure(StatusCode::BAD_GATEWAY));
        assert!(!is_backend_failure(StatusCode::BAD_REQUEST));

        let web = WebError::from(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "quota_exceeded",
            "account storage quota of 1048576 bytes exceeded",
        ));
        assert_eq!(web.status, StatusCode::INSUFFICIENT_STORAGE);
        assert_ne!(web.title, "Something went wrong");
        assert!(web.message.contains("quota"), "{}", web.message);
    }
}
