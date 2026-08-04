//! HTTP-level tests against the router with in-memory backends — no socket,
//! no SQLite. Static-asset tests use the real `server/static/` directory via
//! `CARGO_MANIFEST_DIR`, so they exercise the shipped assets.
//!
//! The website's own routes live in `web.rs`; this file covers the API
//! namespacing and the boundary between the two.

use std::path::Path;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> Router {
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    router(AppState::in_memory(), &config)
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn healthz_answers_ok() {
    let response = app()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        serde_json::json!({"status": "ok"})
    );
}

#[tokio::test]
async fn about_reports_name_and_version() {
    let response = app()
        .oneshot(Request::get("/api/v1/about").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["name"], "askrypt-server");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn unknown_api_v1_route_is_json_404_with_error_envelope() {
    let response = app()
        .oneshot(Request::get("/api/v1/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "not_found");
    assert!(body["error"]["message"].is_string());
}

#[tokio::test]
async fn unknown_api_route_outside_v1_is_json_404() {
    for request in [
        Request::get("/api/v2/about").body(Body::empty()).unwrap(),
        Request::post("/api/v1/nope").body(Body::empty()).unwrap(),
        Request::post("/api/other").body(Body::empty()).unwrap(),
    ] {
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn root_serves_the_landing_page_from_a_template() {
    let response = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(content_type.starts_with("text/html"), "got {content_type}");
    assert!(body_text(response).await.contains("Askrypt"));
}

/// Phase 1 answered every unknown path with `index.html` so a client-side
/// router could pick it up. The site is server-rendered, so a wrong URL is
/// now simply wrong — while `/api/*` keeps its JSON 404.
#[tokio::test]
async fn unknown_page_is_an_html_404_and_the_api_stays_json() {
    let response = app()
        .oneshot(
            Request::get("/profile/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(content_type.starts_with("text/html"), "got {content_type}");

    let response = app()
        .oneshot(Request::get("/api/profile").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["error"]["code"], "not_found");
}
