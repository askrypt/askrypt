//! The website: server-rendered HTML with htmx (plan Phase 7).
//!
//! A *second* consumer of the same account and vault logic, never a
//! constraint on it. Everything browser-shaped — the session cookie, CSRF,
//! redirects, flash messages, HTML errors — lives in here; `/api/v1` stays
//! exactly what the desktop and mobile apps already talk to.
//!
//! Two rules the templates in `server/templates/` are written to:
//!
//! - **The CSP is not negotiable.** `script-src 'self'` / `style-src 'self'`
//!   with no `unsafe-inline` means no inline `<script>` or `<style>`, no
//!   `hx-on:` handlers, and no `js:`-prefixed htmx expressions. See
//!   [`crate::hardening`].
//! - **htmx is an enhancement.** Every page and form works when it isn't
//!   loaded: an `HX-Request` gets a fragment, a plain request gets the whole
//!   page, and the plain path is the one that has to be correct.
//!
//! Phase 7.2 shipped sign-in, registration and sign-out; 7.3 the profile
//! pages ([`account`]); 7.4 the vault file manager ([`vaults`]). Browser
//! Google sign-in is still missing — the JSON API covers it for native
//! clients, and the redirect flow needs configuration the server doesn't
//! have yet (see `server/PLAN.md`).

pub mod account;
pub mod admin;
pub mod auth;
pub mod csrf;
pub mod devicelink;
pub mod error;
pub mod flash;
pub mod pages;
pub mod render;
pub mod session;
pub mod vaults;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::hardening;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;
use crate::web::error::ErrorInfo;
use crate::web::render::is_htmx;

pub use error::{WebError, WebResult};
pub use pages::not_found;
pub use session::{AdminSession, MaybeWebSession, WebSession};

/// Headroom over [`crate::vaults::MAX_VAULT_BYTES`] for the multipart
/// envelope: part headers, boundaries and the handful of text fields that
/// travel with the file.
const MULTIPART_OVERHEAD_BYTES: usize = 64 * 1024;

/// Overrides the requesting element's `hx-target` for this one response.
const HX_RETARGET: HeaderName = HeaderName::from_static("hx-retarget");

/// Overrides the requesting element's `hx-swap` for this one response.
const HX_RESWAP: HeaderName = HeaderName::from_static("hx-reswap");

/// The URL the browser is showing, sent by htmx on every request it makes.
const HX_CURRENT_URL: HeaderName = HeaderName::from_static("hx-current-url");

/// The HTML routes.
///
/// Both limiters are the *same* [`RateLimiter`] instances the `/api/v1`
/// routes use: sign-in over a form and sign-in over JSON must share one
/// budget, or an attacker just alternates between them. The same goes for
/// the current-password re-auth behind the profile limiter.
pub fn routes(
    auth_limiter: Arc<RateLimiter>,
    profile_limiter: Arc<RateLimiter>,
    device_limiter: Arc<RateLimiter>,
) -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        .route_layer(middleware::from_fn_with_state(auth_limiter, rate_limit));

    // The browser half of the desktop sign-in, on the same budget as the API
    // half rather than the login one: a visitor arriving here has not typed a
    // password and is not guessing at one.
    let link_routes = Router::new()
        .route("/link/{id}", get(devicelink::page))
        .route("/link/{id}/deny", post(devicelink::deny))
        .route_layer(middleware::from_fn_with_state(device_limiter, rate_limit));

    // Email and password changes are the two forms worth guessing at, so
    // they sit behind the same bucket as their JSON twins.
    let account_sensitive = Router::new()
        .route("/account/email", post(account::update_email))
        .route("/account/password", post(account::update_password))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&profile_limiter),
            rate_limit,
        ));

    let account_routes = Router::new()
        .route("/account", get(account::page))
        .route("/account/devices/{id}", post(account::revoke_device))
        .route("/account/delete", post(account::delete_account))
        .merge(account_sensitive);

    // Administration is gated by role, not by guessing, so the limiter here
    // is only about a runaway client: it shares the sensitive-action bucket
    // rather than getting one of its own.
    let admin_routes = Router::new()
        .route("/admin/users", get(admin::page))
        .route("/admin/users/{id}/ban", post(admin::ban))
        .route("/admin/users/{id}/unban", post(admin::unban))
        .route("/admin/users/{id}/role", post(admin::set_role))
        .route("/admin/users/{id}/delete", post(admin::delete))
        .route_layer(middleware::from_fn_with_state(profile_limiter, rate_limit));

    let vault_routes = Router::new()
        .route("/vaults", get(vaults::page).post(vaults::upload))
        .route("/vaults/{id}/replace", post(vaults::replace))
        .route("/vaults/{id}/name", post(vaults::rename))
        .route("/vaults/{id}/delete", post(vaults::remove))
        .route("/vaults/{id}/download", get(vaults::download))
        .route(
            "/vaults/{id}/versions/{version_id}/download",
            get(vaults::download_version),
        )
        .route(
            "/vaults/{id}/versions/{version_id}/restore",
            post(vaults::restore),
        )
        // Same trick as the API's vault routes: declared here, inside the
        // router's global limit, so it overrides it for uploads only.
        .layer(DefaultBodyLimit::max(
            crate::vaults::MAX_VAULT_BYTES + MULTIPART_OVERHEAD_BYTES,
        ));

    Router::new()
        .route("/", get(pages::landing))
        .route("/logout", post(auth::logout))
        .merge(auth_routes)
        .merge(link_routes)
        .merge(account_routes)
        .merge(admin_routes)
        .merge(vault_routes)
        // Pages are per-session by definition; none of them may sit in a
        // shared cache. `/assets` is mounted outside this router and keeps
        // ordinary caching.
        .layer(middleware::from_fn(hardening::no_store))
        // Outermost, so it sees every finished error response — including
        // the ones an extractor rejection produced before a handler ran.
        .layer(middleware::from_fn(htmx_error_fragment))
}

/// Makes a [`WebError`] visible when htmx is driving the form.
///
/// htmx does not swap a 4xx or 5xx response, so an error page answering an
/// `hx-post` is received and thrown away: the visitor watches the form do
/// nothing at all. This re-renders the error as a fragment htmx will show —
/// retargeted at `<main>`, because an error belongs to the page rather than
/// to the `#vault-list` slot the form was aiming at — and answers 200,
/// which is what makes htmx swap it.
///
/// Nothing but the htmx path changes. Without `HX-Request` — the no-JS path,
/// which is the one that has to be correct — the real status and the whole
/// page go out exactly as before.
async fn htmx_error_fragment(request: Request, next: Next) -> Response {
    if !is_htmx(request.headers()) {
        return next.run(request).await;
    }
    let back = current_page(request.headers());
    let mut response = next.run(request).await;
    let Some(info) = response.extensions_mut().remove::<ErrorInfo>() else {
        return response;
    };
    let (fragment, body) = info.fragment(back).into_parts();
    // A fragment that failed to render is `Page`'s own apology, at 500;
    // leaving the original response alone beats swapping that in.
    if fragment.status != StatusCode::OK {
        return response;
    }
    let (mut parts, _) = response.into_parts();
    parts.status = StatusCode::OK;
    parts
        .headers
        .insert(HX_RETARGET, HeaderValue::from_static("main"));
    parts
        .headers
        .insert(HX_RESWAP, HeaderValue::from_static("innerHTML"));
    // The rest of the headers are kept as they were: the `Set-Cookie`s an
    // error can still owe (a freshly minted CSRF token) and the cache
    // directives `no_store` put there both still apply.
    Response::from_parts(parts, body)
}

/// The page the visitor is looking at, for the "reload" link on an error
/// fragment.
///
/// htmx sends its own URL on every request, but that header is
/// client-supplied and this value ends up in an `href`, so only a plain
/// absolute path is accepted; anything else falls back to the landing page.
/// `//host` in particular would be read as protocol-relative and leave the
/// site.
fn current_page(headers: &HeaderMap) -> String {
    let path = headers
        .get(HX_CURRENT_URL)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.parse::<Uri>().ok())
        .map_or_else(String::new, |uri| uri.path().to_string());
    if !path.starts_with('/') || path.starts_with("//") {
        return "/".to_string();
    }
    path
}

/// HTML twin of [`ratelimit::middleware`].
///
/// Identical bucketing — it calls the same [`RateLimiter`] with the same key
/// — but answers with a page instead of the JSON envelope, which would be a
/// strange thing for a browser to be shown.
async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, WebError> {
    if limiter.try_acquire(&ratelimit::client_key(&request)) {
        return Ok(next.run(request).await);
    }
    Err(WebError::too_many_requests(format!(
        "Too many attempts from your network. Try again in about {} seconds.",
        limiter.window_secs()
    )))
}
