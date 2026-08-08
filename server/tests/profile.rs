//! Phase 3 gate tests: profile CRUD driven as a headless client — full
//! profile with linked providers, email update, change/set password,
//! session list + revocation, and account deletion cascading to the vault
//! stores. Runs against the in-memory fakes.

use std::path::Path;
use std::sync::Arc;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::memory::FakeIdTokenVerifier;
use askrypt_server::store::{VaultMeta, VerifiedIdToken};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

struct TestApp {
    app: Router,
    /// Kept so tests can seed/inspect the stores behind the API.
    state: AppState,
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
        app: router(state.clone(), &config),
        state,
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

fn put_json_authed(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::put(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
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

fn delete_authed(uri: &str, token: &str) -> Request<Body> {
    Request::delete(uri)
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

/// Registers + logs in, returning the bearer token.
async fn register_and_login(app: &Router, email: &str, password: &str) -> String {
    register(app, email, password).await;
    let (status, body) = login(app, email, password).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

async fn google_login(app: &Router, id_token: &str) -> String {
    let (status, body) = send(
        app,
        post_json("/api/v1/auth/google", json!({"id_token": id_token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "google login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn profile_shows_linked_providers() {
    let t = test_app();

    let token = register_and_login(&t.app, "pw@example.com", "hunter2hunter2").await;
    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "pw@example.com");
    assert!(body["id"].is_string());
    assert!(body["created_at"].is_string());
    assert_eq!(body["providers"]["password"], true);
    assert_eq!(body["providers"]["google"], false);

    t.verifier.register(
        "g-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "google@example.com".into(),
            email_verified: true,
        },
    );
    let token = google_login(&t.app, "g-token").await;
    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["providers"]["password"], false);
    assert_eq!(body["providers"]["google"], true);
}

#[tokio::test]
async fn update_email_normalizes_validates_and_conflicts() {
    let t = test_app();
    register(&t.app, "taken@example.com", "hunter2hunter2").await;
    let token = register_and_login(&t.app, "a@example.com", "hunter2hunter2").await;

    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/email",
            &token,
            json!({"email": " New@Example.COM "}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update failed: {body}");
    assert_eq!(body["email"], "new@example.com");

    // Login now works with the new address only; password is untouched.
    let (status, _) = login(&t.app, "new@example.com", "hunter2hunter2").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = login(&t.app, "a@example.com", "hunter2hunter2").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = send(
        &t.app,
        put_json_authed("/api/v1/me/email", &token, json!({"email": "not-an-email"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_email");

    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/email",
            &token,
            json!({"email": "taken@example.com"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn change_password_requires_correct_current_password() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com", "old password 1").await;

    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"new_password": "new password 1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "current_password_required");

    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"current_password": "wrong password", "new_password": "new password 1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "invalid_current_password");

    // The new password must still satisfy the registration policy.
    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"current_password": "old password 1", "new_password": "short"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_password");

    let (status, _) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"current_password": "old password 1", "new_password": "new password 1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = login(&t.app, "a@example.com", "old password 1").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = login(&t.app, "a@example.com", "new password 1").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn google_account_sets_first_password_without_current() {
    let t = test_app();
    t.verifier.register(
        "g-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "g@example.com".into(),
            email_verified: true,
        },
    );
    let token = google_login(&t.app, "g-token").await;

    let (status, _) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"new_password": "first password 1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Password login now works and the profile shows both providers.
    let (status, _) = login(&t.app, "g@example.com", "first password 1").await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["providers"]["password"], true);
    assert_eq!(body["providers"]["google"], true);
}

#[tokio::test]
async fn sessions_are_listed_and_revocable_without_leaking_tokens() {
    let t = test_app();
    register(&t.app, "a@example.com", "hunter2hunter2").await;
    let mut tokens = Vec::new();
    for label in ["laptop", "phone"] {
        let (status, body) = send(
            &t.app,
            post_json(
                "/api/v1/auth/login",
                json!({
                    "email": "a@example.com",
                    "password": "hunter2hunter2",
                    "device_label": label,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        tokens.push(body["token"].as_str().unwrap().to_string());
    }

    let (status, body) = send(&t.app, get_authed("/api/v1/me/sessions", &tokens[0])).await;
    assert_eq!(status, StatusCode::OK);
    let sessions = body.as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    // Exactly one entry is the caller's, ids never contain a bearer token.
    let currents: Vec<bool> = sessions
        .iter()
        .map(|s| s["current"].as_bool().unwrap())
        .collect();
    assert_eq!(currents.iter().filter(|c| **c).count(), 1);
    for session in sessions {
        let id = session["id"].as_str().unwrap();
        assert!(tokens.iter().all(|t| t != id));
        assert!(session["created_at"].is_string());
        assert!(session["expires_at"].is_string());
    }
    let phone = sessions
        .iter()
        .find(|s| s["label"] == "phone")
        .expect("device labels are listed");
    assert_eq!(phone["current"], false);
    let phone_id = phone["id"].as_str().unwrap();

    // Unknown session id → 404.
    let (status, body) = send(
        &t.app,
        delete_authed("/api/v1/me/sessions/deadbeef", &tokens[0]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Revoking the phone session kills its token but not the laptop's.
    let (status, _) = send(
        &t.app,
        delete_authed(&format!("/api/v1/me/sessions/{phone_id}"), &tokens[0]),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(&t.app, get_authed("/api/v1/me/sessions", &tokens[0])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    let (status, _) = send(&t.app, get_authed("/api/v1/me", &tokens[1])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(&t.app, get_authed("/api/v1/me", &tokens[0])).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn delete_account_cascades_to_sessions_and_vaults() {
    let t = test_app();
    let registered = register(&t.app, "a@example.com", "hunter2hunter2").await;
    let account_id: Uuid = registered["id"].as_str().unwrap().parse().unwrap();
    let (_, body) = login(&t.app, "a@example.com", "hunter2hunter2").await;
    let token = body["token"].as_str().unwrap().to_string();

    // Seed a stored vault behind the API, as Phase 4 will.
    let vault_id = Uuid::new_v4();
    t.state
        .vault_meta
        .upsert(VaultMeta {
            id: vault_id,
            account_id,
            name: "personal.askrypt".into(),
            size: 8,
            etag: "etag-1".into(),
            updated_at: Utc::now(),
            host: None,
            saved_at: None,
        })
        .await
        .unwrap();
    t.state
        .vault_blobs
        .put(account_id, vault_id, b"PK\x03\x04data")
        .await
        .unwrap();

    let (status, _) = send(&t.app, delete_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The session is gone, the credentials are gone, the vault is gone.
    let (status, _) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = login(&t.app, "a@example.com", "hunter2hunter2").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        t.state
            .vault_meta
            .list_for_account(account_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        t.state
            .vault_blobs
            .get(account_id, vault_id)
            .await
            .unwrap()
            .is_none()
    );

    // The email is free for a fresh registration again.
    register(&t.app, "a@example.com", "hunter2hunter2").await;
}

#[tokio::test]
async fn profile_mutations_are_rate_limited() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com", "hunter2hunter2").await;

    // Missing current_password fails fast (no argon2), so hammer that. The
    // limiter allows 20/min per client; everything after answers 429.
    for _ in 0..20 {
        let (status, _) = send(
            &t.app,
            put_json_authed(
                "/api/v1/me/password",
                &token,
                json!({"new_password": "new password 1"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, body) = send(
        &t.app,
        put_json_authed(
            "/api/v1/me/password",
            &token,
            json!({"new_password": "new password 1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");

    // The read-only profile endpoints are not under the limiter.
    let (status, _) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    assert_eq!(status, StatusCode::OK);
}
