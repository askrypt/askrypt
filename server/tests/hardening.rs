//! Phase 5 gate tests: the cross-cutting hardening layers as seen from the
//! wire — security headers on every response shape, cache directives, the
//! body-limit split between the API and the vault routes, `Retry-After` on
//! throttled responses, and the client-IP trust policy driving rate-limit
//! buckets. Runs against the in-memory fakes over `oneshot`, like the other
//! suites.
//!
//! The middleware behaviours that need a slow or parked handler (timeout,
//! load shedding) are unit-tested inside `src/hardening.rs` instead, where
//! a purpose-built router can provide one.

use std::path::Path;

use askrypt_server::config::Config;
use askrypt_server::hardening::CSP;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::vaults::MAX_VAULT_BYTES;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn test_config() -> Config {
    Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    }
}

fn app() -> Router {
    router(AppState::in_memory(), &test_config())
}

fn app_with(config: Config) -> Router {
    router(AppState::in_memory(), &config)
}

async fn send_raw(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let (status, _, bytes) = send_raw(app, request).await;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn register_and_login(app: &Router, email: &str) -> String {
    let (status, body) = send(
        app,
        post_json(
            "/api/v1/auth/register",
            json!({"email": email, "password": "hunter2hunter2"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");
    let (status, body) = send(
        app,
        post_json(
            "/api/v1/auth/login",
            json!({"email": email, "password": "hunter2hunter2"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn security_headers_ride_every_response_shape() {
    let app = app();
    // A JSON endpoint, an error envelope, a static file, and the SPA
    // fallback — the four ways a response can be produced.
    for path in ["/healthz", "/api/v1/about", "/api/v1/nope", "/", "/some/page"] {
        let (status, headers, _) =
            send_raw(&app, Request::get(path).body(Body::empty()).unwrap()).await;
        assert!(
            status.is_success() || status == StatusCode::NOT_FOUND,
            "{path} answered {status}"
        );
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP, "{path}");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer", "{path}");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY", "{path}");
        assert!(headers.contains_key("permissions-policy"), "{path}");
        assert!(headers.contains_key("cross-origin-opener-policy"), "{path}");
        // Off by default: HSTS only makes sense once TLS is in front.
        assert!(
            !headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
            "{path}"
        );
    }
}

#[tokio::test]
async fn hsts_is_sent_when_configured() {
    let app = app_with(Config {
        hsts: true,
        ..test_config()
    });
    let (_, headers, _) =
        send_raw(&app, Request::get("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(
        headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=31536000; includeSubDomains"
    );
}

#[tokio::test]
async fn the_csp_has_no_unsafe_escape_hatches() {
    // Phase 7's templates have to fit this policy rather than loosen it.
    assert!(!CSP.contains("unsafe-inline"));
    assert!(!CSP.contains("unsafe-eval"));
    assert!(CSP.contains("script-src 'self'"));
    assert!(CSP.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn api_responses_are_not_cached_but_vault_downloads_stay_revalidatable() {
    let app = app();
    let (_, headers, _) = send_raw(
        &app,
        Request::get("/api/v1/about").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");

    let token = register_and_login(&app, "cache@example.com").await;
    let (status, body) = send(
        &app,
        Request::post("/api/v1/vaults?name=v.askrypt")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(b"PK\x03\x04 tiny vault".to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_string();

    // `no-store` would defeat the ETag round-trip the sync clients rely on.
    let (status, headers, _) = send_raw(
        &app,
        Request::get(format!("/api/v1/vaults/{id}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
    let etag = headers[header::ETAG].to_str().unwrap().to_string();

    let (status, headers, _) = send_raw(
        &app,
        Request::get(format!("/api/v1/vaults/{id}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
}

#[tokio::test]
async fn body_limit_is_small_for_the_api_and_large_for_vault_uploads() {
    let app = app();
    let config = test_config();

    // The global limit applies to ordinary API routes...
    let oversized = "x".repeat(config.max_body_bytes * 2);
    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/register",
            json!({"email": "big@example.com", "password": oversized}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "payload_too_large");

    // ...while the vault routes keep their own, much larger one. This is
    // the regression test for the layer ordering in `routes::router`: the
    // vault limit is applied inside the global one and must win.
    let token = register_and_login(&app, "big-vault@example.com").await;
    let mut vault = b"PK\x03\x04".to_vec();
    vault.resize(config.max_body_bytes * 8, b'z');
    assert!(vault.len() < MAX_VAULT_BYTES);
    let (status, body) = send(
        &app,
        Request::post("/api/v1/vaults?name=big.askrypt")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(vault))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn throttled_responses_carry_retry_after() {
    let app = app();
    let hammer = || {
        send_raw(
            &app,
            Request::post("/api/v1/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
    };
    for _ in 0..20 {
        let (status, _, _) = hammer().await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, headers, body) = hammer().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers[header::RETRY_AFTER], "60");
    // The envelope survives the middleware short-circuit...
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
    // ...and so do the security headers.
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
}

#[tokio::test]
async fn forged_forwarded_for_cannot_split_rate_limit_buckets() {
    let app = app();
    // Untrusted by default, so every one of these lands in the same bucket
    // no matter what address it claims to come from.
    for i in 0..20 {
        let (status, _, _) = send_raw(
            &app,
            Request::post("/api/v1/auth/logout")
                .header("x-forwarded-for", format!("10.0.0.{i}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = send_raw(
        &app,
        Request::post("/api/v1/auth/logout")
            .header("x-forwarded-for", "10.0.0.99")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn trusted_forwarded_for_gives_each_client_its_own_bucket() {
    let app = app_with(Config {
        trust_proxy: true,
        ..test_config()
    });
    // The proxy appends, so the *last* element is the observed address —
    // a client forging a leading entry still shares one bucket per real IP.
    for i in 0..20 {
        let (status, _, _) = send_raw(
            &app,
            Request::post("/api/v1/auth/logout")
                .header("x-forwarded-for", format!("1.2.3.{i}, 203.0.113.7"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = send_raw(
        &app,
        Request::post("/api/v1/auth/logout")
            .header("x-forwarded-for", "1.2.3.99, 203.0.113.7")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // A genuinely different client is unaffected.
    let (status, _, _) = send_raw(
        &app,
        Request::post("/api/v1/auth/logout")
            .header("x-forwarded-for", "1.2.3.99, 203.0.113.8")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
