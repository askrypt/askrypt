//! HTTP-level tests against the router with in-memory backends — no socket,
//! no SQLite, no filesystem.

use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn healthz_answers_ok() {
    let app = router(AppState::in_memory());
    let response = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn unknown_route_is_json_404_with_error_envelope() {
    let app = router(AppState::in_memory());
    let response = app
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "not_found");
    assert!(body["error"]["message"].is_string());
}
