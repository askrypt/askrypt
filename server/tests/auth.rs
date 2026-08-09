//! Phase 2 gate tests: register → login → authenticated request → logout,
//! driven exactly as a headless native client would (JSON + bearer token, no
//! cookies), against the in-memory store fakes. Google sign-in (new account
//! and link-to-existing) runs against the fake `IdTokenVerifier`.

use std::path::Path;
use std::sync::Arc;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::VerifiedIdToken;
use askrypt_server::store::memory::FakeIdTokenVerifier;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

struct TestApp {
    app: Router,
    verifier: Arc<FakeIdTokenVerifier>,
}

fn test_app() -> TestApp {
    let verifier = Arc::new(FakeIdTokenVerifier::default());
    let state = AppState {
        id_verifier: verifier.clone(),
        ..AppState::in_memory()
    };
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    TestApp {
        app: router(state, &config),
        verifier,
    }
}

/// Sends a request and returns `(status, parsed JSON body)`; empty bodies
/// parse as `Value::Null`.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
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

fn get_authed(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_authed(uri: &str, token: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn register(app: &Router, email: &str, password: &str) -> Value {
    let (status, body) = send(
        app,
        post_json(
            "/api/v1/auth/register",
            json!({"email": email, "password": password}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");
    body
}

async fn login(app: &Router, email: &str, password: &str) -> (StatusCode, Value) {
    send(
        app,
        post_json(
            "/api/v1/auth/login",
            json!({"email": email, "password": password}),
        ),
    )
    .await
}

#[tokio::test]
async fn register_login_me_logout_flow() {
    let t = test_app();

    // Email is normalized (trimmed + lowercased) on registration.
    let body = register(&t.app, " User@Example.COM ", "hunter2hunter2").await;
    assert_eq!(body["email"], "user@example.com");
    assert!(body["id"].is_string());

    let (status, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/login",
            json!({
                "email": "user@example.com",
                "password": "hunter2hunter2",
                "device_label": "integration test",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["account"]["email"], "user@example.com");
    assert!(body["expires_at"].is_string());
    let token = body["token"].as_str().unwrap().to_string();

    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "user@example.com");

    let (status, _) = send(&t.app, post_authed("/api/v1/auth/logout", &token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The revoked token no longer authenticates.
    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn register_validates_input() {
    let t = test_app();

    for bad_email in ["", "nope", "a@b", "a b@c.com"] {
        let (status, body) = send(
            &t.app,
            post_json(
                "/api/v1/auth/register",
                json!({"email": bad_email, "password": "long enough password"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "email {bad_email:?}");
        assert_eq!(body["error"]["code"], "invalid_email");
    }

    let (status, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/register",
            json!({"email": "a@example.com", "password": "short"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_password");

    // Malformed body still answers with the JSON error envelope.
    let (status, body) = send(
        &t.app,
        post_json("/api/v1/auth/register", json!({"email": "a@example.com"})),
    )
    .await;
    assert!(status.is_client_error());
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn register_duplicate_email_conflicts() {
    let t = test_app();
    register(&t.app, "a@example.com", "hunter2hunter2").await;
    let (status, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/register",
            json!({"email": "A@example.com", "password": "hunter2hunter2"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn login_rejects_bad_credentials() {
    let t = test_app();
    register(&t.app, "a@example.com", "hunter2hunter2").await;

    for (email, password) in [
        ("a@example.com", "wrong password"),
        ("unknown@example.com", "hunter2hunter2"),
    ] {
        let (status, body) = login(&t.app, email, password).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_credentials");
    }
}

#[tokio::test]
async fn me_rejects_missing_or_invalid_tokens() {
    let t = test_app();

    let (status, body) = send(
        &t.app,
        Request::get("/api/v1/me").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    let (status, _) = send(&t.app, get_authed("/api/v1/me", "not-a-real-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn google_login_creates_account() {
    let t = test_app();
    t.verifier.register(
        "good-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "New.User@Example.com".into(),
            email_verified: true,
        },
    );

    let (status, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/google",
            json!({"id_token": "good-token", "device_label": "phone"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "google login failed: {body}");
    assert_eq!(body["account"]["email"], "new.user@example.com");
    let token = body["token"].as_str().unwrap().to_string();

    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "new.user@example.com");

    // A Google-only account has no password to log in with.
    let (status, _) = login(&t.app, "new.user@example.com", "anything at all").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn google_login_links_existing_account_by_email() {
    let t = test_app();
    let registered = register(&t.app, "a@example.com", "hunter2hunter2").await;
    t.verifier.register(
        "good-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "A@Example.com".into(),
            email_verified: true,
        },
    );

    let (status, body) = send(
        &t.app,
        post_json("/api/v1/auth/google", json!({"id_token": "good-token"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Linked to the existing account, not a duplicate.
    assert_eq!(body["account"]["id"], registered["id"]);

    // Password login still works after linking.
    let (status, _) = login(&t.app, "a@example.com", "hunter2hunter2").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn google_login_rejects_unverified_invalid_and_mismatched() {
    let t = test_app();
    t.verifier.register(
        "unverified-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "a@example.com".into(),
            email_verified: false,
        },
    );
    let (status, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/google",
            json!({"id_token": "unverified-token"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "email_not_verified");

    let (status, body) = send(
        &t.app,
        post_json("/api/v1/auth/google", json!({"id_token": "unknown-token"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "invalid_google_token");

    // Same email from a *different* Google account than the linked one.
    t.verifier.register(
        "sub-1-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "b@example.com".into(),
            email_verified: true,
        },
    );
    t.verifier.register(
        "sub-2-token",
        VerifiedIdToken {
            subject: "google-sub-2".into(),
            email: "b@example.com".into(),
            email_verified: true,
        },
    );
    let (status, _) = send(
        &t.app,
        post_json("/api/v1/auth/google", json!({"id_token": "sub-1-token"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &t.app,
        post_json("/api/v1/auth/google", json!({"id_token": "sub-2-token"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited() {
    let t = test_app();
    // Hammers token-less logout: the limiter is a `route_layer`, so it
    // counts the request before the (cheap) auth rejection. Logins would
    // cost a full argon2 verify each — unknown emails included, since
    // Phase 5 equalized that timing.
    let unauthed_logout = || {
        send(
            &t.app,
            Request::post("/api/v1/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
    };
    // The limiter allows 20/min per client; everything after that is 429.
    for _ in 0..20 {
        let (status, _) = unauthed_logout().await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = unauthed_logout().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
    // Every request in the test shares one bucket: with no ConnectInfo
    // under `oneshot` and proxy headers untrusted by default, the client
    // key is the same for all of them.
    let (status, _) = login(&t.app, "unknown@example.com", "whatever pass").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Unauthenticated /me is not under the auth limiter.
    let (status, _) = send(
        &t.app,
        Request::get("/api/v1/me").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
