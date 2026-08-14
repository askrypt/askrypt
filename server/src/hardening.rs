//! Cross-cutting hardening middleware (plan Phase 5).
//!
//! Everything here is a plain `async fn` used with
//! [`axum::middleware::from_fn_with_state`], matching [`crate::ratelimit`].
//! That is deliberate: `tower_http`'s `TimeoutLayer` answers with a bodyless
//! 408 and `tower`'s load-shed surfaces overload as a service *error*, both
//! of which would escape the `{"error": {code, message}}` envelope that
//! [`crate::error`] guarantees for every response under `/api/v1`. Returning
//! [`ApiError`] keeps the contract.
//!
//! ## The CSP is a commitment
//!
//! [`CSP`] is written now so the Phase 7 pages (askama templates + a
//! vendored `htmx.min.js`) fit it *without loosening*. Consequences for
//! whoever writes those templates:
//!
//! - `script-src 'self'` with no `unsafe-inline`: no inline `<script>`, no
//!   `hx-on:` handlers, and no `js:`-prefixed `hx-vals`/`hx-headers`
//!   expressions (htmx evaluates those, which the policy forbids).
//! - `style-src 'self'`: no inline `style=` blocks. htmx also injects an
//!   inline stylesheet for `htmx-indicator` unless the page sets
//!   `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>`.
//!
//! The documented exceptions are [`CSP_CAPTCHA`], [`CSP_GOOGLE`] and
//! [`CSP_CAPTCHA_GOOGLE`], sent only by the two auth pages and only for the
//! widgets those pages actually rendered. They are *separate* policies, not a
//! loosening of the first: every other route, including the rest of the
//! website, still gets [`CSP`] byte for byte, and a page that renders one
//! widget gives up nothing on account of the other. [`policy`] is the whole
//! selection, and [`RelaxedCsp`] is how a handler opts in.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use tokio::sync::Semaphore;

use crate::error::ApiError;

pub use crate::types::{RelaxedCsp, SecurityHeaders};

/// Content Security Policy sent with every response. `'self'`-only, with no
/// `unsafe-inline` anywhere — see the module docs before relaxing it.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; \
base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The policy the sign-in and registration pages send **when reCAPTCHA is
/// configured**, and nowhere else.
///
/// reCAPTCHA cannot run under [`CSP`]: it loads two Google scripts, opens an
/// iframe, calls home over XHR, and injects a `<style>` element for its badge
/// — the last of which is why `'unsafe-inline'` appears in `style-src` here
/// and must never appear in [`CSP`]. Google's alternative is a per-request
/// nonce propagated from the script tag, which would turn the policy into a
/// value built per response; scoping the widening to two pages buys the same
/// containment far more cheaply.
///
/// Everything not required by reCAPTCHA stays exactly as strict, `script-src`
/// included: the two hosts are named, not a wildcard, and `'unsafe-inline'`
/// and `'unsafe-eval'` are still absent from it. A page opts in by attaching
/// [`RelaxedCsp`] to its response.
pub const CSP_CAPTCHA: &str = "default-src 'self'; \
script-src 'self' https://www.google.com https://www.gstatic.com; \
style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
connect-src 'self' https://www.google.com; font-src 'self'; object-src 'none'; \
base-uri 'none'; form-action 'self'; frame-src https://www.google.com; \
frame-ancestors 'none'";

/// The policy the sign-in and registration pages send when the **Google
/// Identity Services** button is configured, and reCAPTCHA is not.
///
/// Tighter than [`CSP_CAPTCHA`] despite naming the same vendor, because
/// Google publishes an exact source list for this library and it is
/// path-scoped: `accounts.google.com/gsi/client` is the only script, `gsi/`
/// the only frame and XHR target, and `gsi/style` the only stylesheet — so
/// `style-src` keeps `'self'` alone and **no `'unsafe-inline'` appears
/// anywhere**. Nothing here is a wildcard and nothing else is widened.
pub const CSP_GOOGLE: &str = "default-src 'self'; \
script-src 'self' https://accounts.google.com/gsi/client; \
style-src 'self' https://accounts.google.com/gsi/style; img-src 'self' data:; \
connect-src 'self' https://accounts.google.com/gsi/; font-src 'self'; \
object-src 'none'; base-uri 'none'; form-action 'self'; \
frame-src https://accounts.google.com/gsi/; frame-ancestors 'none'";

/// Both widgets on one page: the union of [`CSP_CAPTCHA`] and [`CSP_GOOGLE`],
/// and nothing beyond it.
///
/// Written out rather than assembled at runtime so the policy a browser is
/// sent stays a string that can be read in the source and asserted on in a
/// test, exactly like the other three.
pub const CSP_CAPTCHA_GOOGLE: &str = "default-src 'self'; \
script-src 'self' https://www.google.com https://www.gstatic.com \
https://accounts.google.com/gsi/client; \
style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style; \
img-src 'self' data:; \
connect-src 'self' https://www.google.com https://accounts.google.com/gsi/; \
font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
frame-src https://www.google.com https://accounts.google.com/gsi/; \
frame-ancestors 'none'";

/// Every policy this server sends, for the tests that assert on all of them
/// at once. Adding one means adding it here.
pub const POLICIES: [&str; 4] = [CSP, CSP_CAPTCHA, CSP_GOOGLE, CSP_CAPTCHA_GOOGLE];

/// The policy for a response, given what it said it rendered.
///
/// The four are a cross product of two independent widgets, so a page with a
/// captcha and no Google button must not be handed the Google hosts, and the
/// other way round.
pub fn policy(relaxed: Option<&RelaxedCsp>) -> &'static str {
    match relaxed {
        Some(RelaxedCsp {
            captcha: true,
            google: true,
        }) => CSP_CAPTCHA_GOOGLE,
        Some(RelaxedCsp { captcha: true, .. }) => CSP_CAPTCHA,
        Some(RelaxedCsp { google: true, .. }) => CSP_GOOGLE,
        _ => CSP,
    }
}

/// Default `Cross-Origin-Opener-Policy`: this document gets its own browsing
/// context group, so a window it opens — or one that opened it — cannot reach
/// it through `window.opener`.
const COOP: &str = "same-origin";

/// The one relaxation, on the two auth pages when the Google button is there.
///
/// Google Identity Services signs in through a popup that posts the
/// credential back to its opener. Under plain `same-origin` that reference is
/// severed and the sign-in silently never completes. `same-origin-allow-popups`
/// keeps this page unreachable from anything that opened *it* — the direction
/// that matters for cross-origin attacks — while letting popups it opens
/// itself answer back.
const COOP_ALLOW_POPUPS: &str = "same-origin-allow-popups";

const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
magnetometer=(), microphone=(), payment=(), usb=()";

/// Full referrer to ourselves, nothing at all to anyone else.
///
/// **Not `no-referrer`**, which looks stricter and is a trap. Fetch's
/// "append a request `Origin` header" step sets the header to `null` for any
/// non-CORS request with a method other than GET/HEAD when the referrer
/// policy is `no-referrer` — that is, for every ordinary HTML form
/// submission. [`crate::web::csrf::check_origin`] then sees an opaque origin
/// and refuses the request, so the sign-out button (the one form on the site
/// that is a plain navigation rather than an htmx `XMLHttpRequest`, which is
/// exempt because its mode is `cors`) returned 403 to every visitor.
///
/// `same-origin` leaks exactly as little cross-origin — the header is
/// omitted entirely off-site — while leaving same-origin form posts stamped
/// with the real origin. Cross-origin posts still arrive as `null` and are
/// still refused.
pub(crate) const REFERRER_POLICY: &str = "same-origin";

/// One year, the usual preload-eligible value.
const HSTS: &str = "max-age=31536000; includeSubDomains";

/// Path exempt from shedding: an overloaded server that fails its own health
/// check gets killed by the orchestrator instead of recovering.
const HEALTH_PATH: &str = "/healthz";

/// Adds the security headers to every response, including the error
/// responses produced by the middleware below it.
pub async fn security_headers(
    State(config): State<SecurityHeaders>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let relaxed = response.extensions().get::<RelaxedCsp>().copied();
    let csp = policy(relaxed.as_ref());
    let coop = match relaxed {
        Some(RelaxedCsp { google: true, .. }) => COOP_ALLOW_POPUPS,
        _ => COOP,
    };
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY),
    );
    // Redundant with `frame-ancestors 'none'` for modern browsers, kept for
    // the ones that only understand this.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static(coop),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if config.hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    response
}

/// Keeps API responses out of caches. Uses `or_insert`, so a handler that
/// set its own directive keeps it — vault downloads need `no-cache` (not
/// `no-store`) for `ETag`/`If-None-Match` revalidation to work in a browser.
pub async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Makes the loose files under `/assets` revalidate before they are reused.
///
/// `ServeDir` sends no `Cache-Control` at all, which leaves the browser free
/// to invent one — the heuristic is a fraction of the file's age — so an
/// edited `style.css` sitting behind an unchanged URL can stay stale for
/// hours. `no-cache` is not "don't cache": the copy is kept, only every use
/// has to be revalidated first, and `ServeDir`'s `Last-Modified` answers that
/// with a bodyless 304. Two small same-origin files make that round trip
/// cheaper than ever shipping an old stylesheet.
pub async fn revalidate(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-cache"));
    response
}

/// Bounds how long a handler may take to produce a response.
///
/// Covers request-body reading too (extractors run downstream), so it is
/// also the slow-upload defense — hence a limit generous enough for a
/// 10 MiB vault on a slow link. It does *not* bound streaming of the
/// response body: once the handler returns, `ServeDir`'s file stream is on
/// its own, and body/idle timeouts belong in the reverse proxy.
///
/// Cancellation drops the handler future mid-flight. Every write here is a
/// single statement, so an abandoned one leaves no partial state.
pub async fn request_timeout(
    State(limit): State<Duration>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if limit.is_zero() {
        return Ok(next.run(request).await);
    }
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => Err(ApiError::new(
            // Not 408: that means the *client* was slow to send its request.
            StatusCode::GATEWAY_TIMEOUT,
            "timeout",
            "the request took too long to process",
        )),
    }
}

/// Sheds load past a fixed number of in-flight requests, so a burst answers
/// 503 quickly instead of queueing until everything times out.
pub async fn concurrency_limit(
    State(semaphore): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if request.uri().path() == HEALTH_PATH {
        return Ok(next.run(request).await);
    }
    // Bound to a named local: the permit must live across `next.run`, and
    // `let _ = ...` would drop it immediately, making this a no-op.
    let Ok(_permit) = Arc::clone(&semaphore).try_acquire_owned() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "server is busy; retry shortly",
        )
        .with_retry_after(1));
    };
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::get;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    /// Whatever a page opted into, the parts of the policy that are not about
    /// third-party widgets stay identical. Written over every policy at once
    /// so a fifth one cannot be added without meeting the same bar.
    #[test]
    fn every_policy_keeps_the_non_negotiable_directives() {
        for csp in POLICIES {
            assert!(csp.starts_with("default-src 'self'; "), "{csp}");
            assert!(csp.contains("object-src 'none'"), "{csp}");
            assert!(csp.contains("base-uri 'none'"), "{csp}");
            assert!(csp.contains("form-action 'self'"), "{csp}");
            assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
            assert!(csp.contains("img-src 'self' data:;"), "{csp}");
            // Script is the one a widening would be worth most: no inline, no
            // eval, and every host named rather than matched.
            assert!(!csp.contains("script-src 'self' 'unsafe-inline'"), "{csp}");
            assert!(!csp.contains("unsafe-eval"), "{csp}");
            assert!(!csp.contains('*'), "{csp}");
        }
    }

    /// The two widgets are independent, and a page that renders one must not
    /// be handed the other's hosts.
    #[test]
    fn the_policy_matches_what_the_page_actually_rendered() {
        let relaxed = |captcha, google| RelaxedCsp { captcha, google };
        assert_eq!(policy(None), CSP);
        assert_eq!(policy(Some(&relaxed(false, false))), CSP);
        assert_eq!(policy(Some(&relaxed(true, false))), CSP_CAPTCHA);
        assert_eq!(policy(Some(&relaxed(false, true))), CSP_GOOGLE);
        assert_eq!(policy(Some(&relaxed(true, true))), CSP_CAPTCHA_GOOGLE);

        // A captcha alone never names the sign-in host, and the button alone
        // never buys reCAPTCHA's inline-style concession.
        assert!(!CSP_CAPTCHA.contains("accounts.google.com"));
        assert!(!CSP_GOOGLE.contains("'unsafe-inline'"));
        assert!(!CSP_GOOGLE.contains("www.gstatic.com"));
    }

    async fn status_of(app: &Router, path: &str) -> StatusCode {
        app.clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn timeout_fires_on_a_slow_handler_and_spares_a_fast_one() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    "done"
                }),
            )
            .route("/fast", get(|| async { "done" }))
            .layer(middleware::from_fn_with_state(
                Duration::from_millis(50),
                request_timeout,
            ));

        assert_eq!(status_of(&app, "/slow").await, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(status_of(&app, "/fast").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn zero_timeout_disables_the_limit() {
        let app = Router::new()
            .route("/fast", get(|| async { "done" }))
            .layer(middleware::from_fn_with_state(
                Duration::ZERO,
                request_timeout,
            ));
        assert_eq!(status_of(&app, "/fast").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn concurrency_limit_sheds_while_a_permit_is_held_and_recovers_after() {
        // The parked handler holds the only permit until we release it,
        // which is what proves the permit spans `next.run`.
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let app = Router::new()
            .route(
                "/park",
                get(move || {
                    let slot = Arc::clone(&release_rx);
                    async move {
                        let rx = slot.lock().await.take();
                        if let Some(rx) = rx {
                            let _ = rx.await;
                        }
                        "done"
                    }
                }),
            )
            .route("/quick", get(|| async { "done" }))
            .route(HEALTH_PATH, get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                Arc::new(Semaphore::new(1)),
                concurrency_limit,
            ));

        let parked = tokio::spawn({
            let app = app.clone();
            async move { status_of(&app, "/park").await }
        });
        // Let the parked request take the permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/quick")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        // Health checks are never shed, even while saturated.
        assert_eq!(status_of(&app, HEALTH_PATH).await, StatusCode::OK);

        let _ = release_tx.send(());
        assert_eq!(parked.await.unwrap(), StatusCode::OK);
        assert_eq!(status_of(&app, "/quick").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn security_headers_land_on_every_response() {
        let app = Router::new().route("/x", get(|| async { "hi" })).layer(
            middleware::from_fn_with_state(SecurityHeaders { hsts: true }, security_headers),
        );
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::STRICT_TRANSPORT_SECURITY], HSTS);
    }

    #[tokio::test]
    async fn no_store_does_not_overwrite_a_handler_directive() {
        let app = Router::new()
            .route("/default", get(|| async { "hi" }))
            .route(
                "/explicit",
                get(|| async {
                    (
                        [(header::CACHE_CONTROL, "private, no-cache")],
                        "revalidate me",
                    )
                }),
            )
            .layer(middleware::from_fn(no_store));

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/default")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/explicit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-cache"
        );
    }
}
