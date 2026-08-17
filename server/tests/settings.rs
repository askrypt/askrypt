//! The Phase 12 gate: the server settings table and the registration switch.
//!
//! Both halves at once, because the point of the feature is where they meet:
//! an administrator closes registration on the website, and every path that
//! could create an account — the browser form, the JSON API, Google sign-in —
//! stops creating one, while everybody who already has an account carries on.
//!
//! Integration tests are separate binaries and cannot share `admin.rs`'s
//! helpers, so the handful this needs are repeated here.

use std::sync::Arc;

use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::VerifiedIdToken;
use askrypt_server::store::memory::FakeIdTokenVerifier;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const SETTINGS: &str = "/admin/settings";

struct TestApp {
    app: Router,
    verifier: Arc<FakeIdTokenVerifier>,
}

fn app() -> TestApp {
    let verifier = Arc::new(FakeIdTokenVerifier::default());
    let state = AppState {
        id_verifier: verifier.clone(),
        ..AppState::in_memory()
    };
    TestApp {
        app: router(state, &common::password_api_config()),
        verifier,
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap()
}

fn get_with_cookies(uri: &str, cookies: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookies)
        .body(Body::empty())
        .unwrap()
}

fn post_form(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header(header::COOKIE, cookies)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_form_htmx(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    let mut request = post_form(uri, cookies, body);
    request
        .headers_mut()
        .insert("hx-request", "true".parse().unwrap());
    request
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn jar(previous: &str, headers: &HeaderMap) -> String {
    let mut pairs: Vec<(String, String)> = previous
        .split("; ")
        .filter(|s| !s.is_empty())
        .filter_map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    for cookie in set_cookies(headers) {
        let Some((pair, attrs)) = cookie.split_once("; ") else {
            continue;
        };
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        pairs.retain(|(k, _)| k != key);
        if !attrs.contains("Max-Age=0") {
            pairs.push((key.to_string(), value.to_string()));
        }
    }
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn csrf_field(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("no csrf field in the page") + marker.len();
    let rest = &html[start..];
    rest[..rest.find('"').unwrap()].to_string()
}

/// Registers through the website and returns the resulting cookie jar.
async fn register(app: &Router, email: &str) -> String {
    let (status, headers, html) = send(app, get("/register")).await;
    assert_eq!(status, StatusCode::OK);
    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email={email}&password={PASSWORD}",
        csrf_field(&html)
    );

    let (status, headers, _) = send(app, post_form("/register", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "registration was refused");
    jar(&cookies, &headers)
}

/// The settings page as the administrator sees it, plus a refreshed jar and
/// the CSRF token its forms carry.
async fn settings_page(app: &Router, cookies: &str) -> (String, String, String) {
    let (status, headers, html) = send(app, get_with_cookies(SETTINGS, cookies)).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    let cookies = jar(cookies, &headers);
    let token = csrf_field(&html);
    (cookies, token, html)
}

/// Flips the switch through the website, the way a browser without JavaScript
/// would.
async fn set_registration(app: &Router, cookies: &str, enabled: bool) -> String {
    let (cookies, token, _) = settings_page(app, cookies).await;
    let body = format!("csrf={token}&enabled={enabled}");
    let (status, headers, html) = send(app, post_form(SETTINGS, &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{html}");
    jar(&cookies, &headers)
}

/// A JSON registration, the surface a desktop or mobile client uses.
async fn api_register(app: &Router, email: &str) -> (StatusCode, String) {
    let (status, _, body) = send(
        app,
        post_json(
            "/api/v1/auth/register",
            serde_json::json!({"email": email, "password": PASSWORD}),
        ),
    )
    .await;
    (status, body)
}

/// A JSON login, to prove sign-in is untouched by a closed registration.
async fn api_login(app: &Router, email: &str) -> StatusCode {
    let (status, _, _) = send(
        app,
        post_json(
            "/api/v1/auth/login",
            serde_json::json!({"email": email, "password": PASSWORD}),
        ),
    )
    .await;
    status
}

// -------------------------------------------------------------- the page

#[tokio::test]
async fn registration_is_open_on_a_server_nobody_has_configured() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;

    // Nothing seeded the table, and the page says so.
    let (_, _, html) = settings_page(&t.app, &admin).await;
    assert!(html.contains("can create an account"), "{html}");
    assert!(html.contains("Close registration"), "{html}");

    // And a second account can still be made, on both surfaces.
    register(&t.app, "second@example.com").await;
    let (status, body) = api_register(&t.app, "third@example.com").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn the_settings_page_is_advertised_and_reachable_only_by_administrators() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    let plain = register(&t.app, "second@example.com").await;

    let (_, _, html) = send(&t.app, get_with_cookies("/account", &admin)).await;
    assert!(html.contains(SETTINGS), "the admin has no Settings link");
    let (_, _, html) = send(&t.app, get_with_cookies("/account", &plain)).await;
    assert!(
        !html.contains(SETTINGS),
        "a plain user was offered the link"
    );

    let (status, _, html) = send(&t.app, get_with_cookies(SETTINGS, &plain)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("administrators"), "{html}");

    let (status, headers, _) = send(&t.app, get(SETTINGS)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
}

#[tokio::test]
async fn the_switch_survives_and_can_be_flipped_back() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;

    let admin = set_registration(&t.app, &admin, false).await;
    let (admin, _, html) = settings_page(&t.app, &admin).await;
    assert!(html.contains("New accounts are closed"), "{html}");
    assert!(html.contains("Open registration"), "{html}");
    assert_eq!(
        api_register(&t.app, "nope@example.com").await.0,
        StatusCode::FORBIDDEN
    );

    let admin = set_registration(&t.app, &admin, true).await;
    let (_, _, html) = settings_page(&t.app, &admin).await;
    assert!(html.contains("can create an account"), "{html}");
    let (status, body) = api_register(&t.app, "later@example.com").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn flipping_the_switch_over_htmx_returns_the_swapped_card() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    let (admin, token, _) = settings_page(&t.app, &admin).await;

    let (status, _, html) = send(
        &t.app,
        post_form_htmx(SETTINGS, &admin, &format!("csrf={token}&enabled=false")),
    )
    .await;
    // 200 and the fragment, not a redirect: htmx swaps this into the page.
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("id=\"server-settings\""), "{html}");
    assert!(html.contains("New accounts are closed"), "{html}");
    // A fragment, not a whole document.
    assert!(!html.contains("<!doctype"), "{html}");
}

#[tokio::test]
async fn the_switch_cannot_be_flipped_without_a_csrf_token() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    let (admin, _, _) = settings_page(&t.app, &admin).await;

    let (status, _, _) = send(&t.app, post_form(SETTINGS, &admin, "enabled=false")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The forgery changed nothing.
    assert_eq!(
        api_register(&t.app, "second@example.com").await.0,
        StatusCode::CREATED
    );
}

// ------------------------------------------------- what "closed" refuses

#[tokio::test]
async fn a_closed_server_still_shows_the_register_form_and_refuses_the_submit() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    set_registration(&t.app, &admin, false).await;

    // The form still renders — someone who already has an account needs the
    // sign-in link on it — with the warning above it.
    let (status, headers, html) = send(&t.app, get("/register")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("not accepting new accounts"), "{html}");
    assert!(
        html.contains("name=\"password\""),
        "the form is gone: {html}"
    );

    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email=second@example.com&password={PASSWORD}",
        csrf_field(&html)
    );
    // 200 with the refusal re-rendered, not a redirect and not a 4xx: htmx
    // only swaps successful responses, and this is a normal outcome here.
    let (status, _, html) = send(&t.app, post_form("/register", &cookies, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("not accepting new accounts"), "{html}");
    assert_eq!(
        api_login(&t.app, "second@example.com").await,
        StatusCode::UNAUTHORIZED,
        "the account was created anyway"
    );
}

#[tokio::test]
async fn a_closed_server_refuses_the_json_registration_api() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    set_registration(&t.app, &admin, false).await;

    let (status, body) = api_register(&t.app, "second@example.com").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "registration_disabled");
}

#[tokio::test]
async fn a_closed_server_refuses_a_new_google_account_but_not_an_existing_one() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    register(&t.app, "existing@example.com").await;
    set_registration(&t.app, &admin, false).await;

    // An address nobody has registered: Google sign-in would create it.
    t.verifier.register(
        "new-token",
        VerifiedIdToken {
            subject: "google-sub-1".into(),
            email: "stranger@example.com".into(),
            email_verified: true,
        },
    );
    let (status, _, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/google",
            serde_json::json!({"id_token": "new-token"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "registration_disabled");

    // An address that already has an account: this *links* Google to it
    // rather than creating anything, so it must still work.
    t.verifier.register(
        "known-token",
        VerifiedIdToken {
            subject: "google-sub-2".into(),
            email: "existing@example.com".into(),
            email_verified: true,
        },
    );
    let (status, _, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/google",
            serde_json::json!({"id_token": "known-token"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_closed_server_still_signs_existing_accounts_in() {
    let t = app();
    let admin = register(&t.app, "first@example.com").await;
    register(&t.app, "second@example.com").await;
    set_registration(&t.app, &admin, false).await;

    // The JSON surface.
    assert_eq!(
        api_login(&t.app, "second@example.com").await,
        StatusCode::OK
    );

    // And the browser one.
    let (status, headers, html) = send(&t.app, get("/login")).await;
    assert_eq!(status, StatusCode::OK);
    // The sign-in form has nothing to say about registration being closed.
    assert!(!html.contains("not accepting new accounts"), "{html}");
    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email=second@example.com&password={PASSWORD}",
        csrf_field(&html)
    );
    let (status, _, html) = send(&t.app, post_form("/login", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{html}");
}
