//! The gate for browser-driven desktop sign-in.
//!
//! Covers both halves at once, because the point of the feature is that they
//! meet: the JSON endpoints a desktop app drives, and the page a browser lands
//! on. Runs over `tower`'s `oneshot` against the in-memory fakes, like the other
//! suites, and each test builds its own `app()` so the shared rate-limit bucket
//! never leaks between them.

use std::path::Path;
use std::sync::Arc;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::{Account, DeviceLink, DeviceLinkStatus, DeviceLinkStore, NewAccount};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";

fn state() -> AppState {
    AppState::in_memory()
}

fn app_with(state: AppState) -> Router {
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    router(state, &config)
}

fn app() -> Router {
    app_with(state())
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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
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

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// Folds a response's cookies into a `Cookie` header for the next request.
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

fn field_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let rest = &html[start..];
    Some(rest[..rest.find('"')?].to_string())
}

fn csrf_field(html: &str) -> String {
    field_value(html, "csrf").expect("no csrf field in the page")
}

/// The desktop half: open a link and keep what the app would keep.
async fn start_link(app: &Router, label: &str) -> (String, String, String) {
    let (status, _, body) = send(
        app,
        post_json("/api/v1/auth/device", json!({ "device_label": label })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let started: Value = serde_json::from_str(&body).unwrap();
    let link_id = started["link_id"].as_str().unwrap().to_string();
    let poll_token = started["poll_token"].as_str().unwrap().to_string();
    let user_code = started["user_code"].as_str().unwrap().to_string();

    assert_eq!(
        started["verification_path"].as_str().unwrap(),
        format!("/link/{link_id}")
    );
    assert!(started["interval"].as_u64().unwrap() >= 1);
    // A full day, so a user who wanders off can still finish.
    assert_eq!(started["expires_in"].as_i64().unwrap(), 24 * 60 * 60);

    (link_id, poll_token, user_code)
}

async fn poll(app: &Router, poll_token: &str) -> Value {
    let (status, _, body) = send(
        app,
        post_json(
            "/api/v1/auth/device/poll",
            json!({ "poll_token": poll_token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// Registers through the website, optionally carrying a device link, and
/// returns the browser's cookie jar.
async fn register(app: &Router, email: &str, link: Option<&str>) -> String {
    let path = match link {
        Some(id) => format!("/register?link={id}"),
        None => "/register".to_string(),
    };
    let (status, headers, html) = send(app, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    let cookies = jar("", &headers);
    let token = csrf_field(&html);

    // The link travels in the form body, not in the action's query string.
    if let Some(id) = link {
        assert_eq!(field_value(&html, "link").as_deref(), Some(id));
    }

    let mut body = format!("csrf={token}&email={email}&password={PASSWORD}");
    if let Some(id) = link {
        body.push_str(&format!("&link={id}"));
    }

    let (status, headers, _) = send(app, post_form("/register", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let expected = match link {
        Some(id) => format!("/link/{id}"),
        None => "/account".to_string(),
    };
    assert_eq!(headers[header::LOCATION], expected);
    jar(&cookies, &headers)
}

/// Uses a bearer token the way a desktop app would.
async fn me(app: &Router, token: &str) -> (StatusCode, String) {
    let request = Request::get("/api/v1/me")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(app, request).await;
    (status, body)
}

#[tokio::test]
async fn a_browser_sign_in_hands_the_app_a_working_token() {
    let app = app();
    let (link_id, poll_token, user_code) = start_link(&app, "ubuntu@mypc").await;

    // Nothing has happened yet.
    assert_eq!(poll(&app, &poll_token).await["status"], "pending");

    // The browser arrives signed out: it is offered sign-in, and nothing is
    // approved by merely looking.
    let (status, _, html) = send(&app, get(&format!("/link/{link_id}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(&user_code), "the page must show the code");
    assert!(html.contains(&format!("/login?link={link_id}")));
    assert!(html.contains(&format!("/register?link={link_id}")));
    assert!(
        !html.contains(&poll_token),
        "the poll token must never reach the page"
    );
    assert_eq!(poll(&app, &poll_token).await["status"], "pending");

    // Registering carries the link through and lands back on it, which
    // approves it.
    let cookies = register(&app, "me@example.com", Some(&link_id)).await;
    let (status, _, html) = send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("signed in"), "{html}");
    assert!(html.contains(&user_code));

    // And the app collects a session that actually authenticates.
    let approved = poll(&app, &poll_token).await;
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["account"]["email"], "me@example.com");
    let token = approved["token"].as_str().unwrap();

    let (status, body) = me(&app, token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("me@example.com"));

    // The device label the app sent is what the account's device list shows.
    let request = Request::get("/api/v1/me/sessions")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, sessions) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(sessions.contains("ubuntu@mypc"), "{sessions}");
}

#[tokio::test]
async fn a_link_can_only_be_collected_once() {
    let app = app();
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;
    let cookies = register(&app, "me@example.com", Some(&link_id)).await;
    send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;

    assert_eq!(poll(&app, &poll_token).await["status"], "approved");
    // A second collection is refused, and refused as `expired` — a claimed
    // link and one that never existed must look the same.
    assert_eq!(poll(&app, &poll_token).await["status"], "expired");
}

#[tokio::test]
async fn reloading_the_page_does_not_mint_a_second_session() {
    let app = app();
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;
    let cookies = register(&app, "me@example.com", Some(&link_id)).await;

    for _ in 0..3 {
        let (status, _, _) = send(
            &app,
            get_with_cookies(&format!("/link/{link_id}"), &cookies),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    assert_eq!(poll(&app, &poll_token).await["status"], "approved");
    assert_eq!(poll(&app, &poll_token).await["status"], "expired");
}

#[tokio::test]
async fn the_link_id_alone_does_not_yield_a_token() {
    // The id travels in a URL — in the browser's history, maybe in a chat
    // message. Only the poll token, which never leaves the app, can collect.
    let app = app();
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;
    let cookies = register(&app, "me@example.com", Some(&link_id)).await;
    send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;

    assert_eq!(poll(&app, &link_id).await["status"], "expired");
    // And the real token still works afterwards.
    assert_eq!(poll(&app, &poll_token).await["status"], "approved");
}

#[tokio::test]
async fn an_unknown_poll_token_is_indistinguishable_from_an_expired_one() {
    let app = app();
    let answer = poll(
        &app,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .await;
    assert_eq!(answer["status"], "expired");
    assert!(answer.get("token").is_none());
}

#[tokio::test]
async fn denying_in_the_browser_tells_the_app() {
    let app = app();
    let (link_id, poll_token, _) = start_link(&app, "somebody elses app").await;
    let cookies = register(&app, "me@example.com", None).await;

    // Visiting approves; "that wasn't me" then denies, and no token was ever
    // issued to be revoked.
    let (_, headers, html) = send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    let cookies = jar(&cookies, &headers);
    let token = csrf_field(&html);

    let (status, _, _) = send(
        &app,
        post_form(
            &format!("/link/{link_id}/deny"),
            &cookies,
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    assert_eq!(poll(&app, &poll_token).await["status"], "denied");
    // Terminal: the app is told once and the record is gone.
    assert_eq!(poll(&app, &poll_token).await["status"], "expired");
}

#[tokio::test]
async fn denying_needs_a_csrf_token() {
    let app = app();
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;
    let cookies = register(&app, "me@example.com", None).await;
    let (_, headers, _) = send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    let cookies = jar(&cookies, &headers);

    let (status, _, _) = send(
        &app,
        post_form(&format!("/link/{link_id}/deny"), &cookies, "csrf=nonsense"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The approval from the visit stands: a forged deny changed nothing.
    assert_eq!(poll(&app, &poll_token).await["status"], "approved");
}

#[tokio::test]
async fn cancelling_from_the_app_removes_the_link_at_once() {
    // Closing the sign-in pane means the user is done with it: the link must
    // stop being approvable now, not in 24 hours.
    let state = state();
    let app = app_with(state.clone());
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;

    let (status, _, _) = send(
        &app,
        post_json(
            "/api/v1/auth/device/cancel",
            json!({ "poll_token": poll_token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert!(
        state
            .device_links
            .get(link_id.parse().unwrap())
            .await
            .unwrap()
            .is_none(),
        "a cancelled link outlived the cancel",
    );

    // And the page it pointed at approves nothing afterwards.
    let cookies = register(&app, "me@example.com", None).await;
    let (_, _, html) = send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    assert!(html.contains("expired"), "{html}");
    assert_eq!(poll(&app, &poll_token).await["status"], "expired");
}

#[tokio::test]
async fn cancelling_an_unknown_link_is_not_an_error_or_an_oracle() {
    let app = app();
    let (status, _, body) = send(
        &app,
        post_json(
            "/api/v1/auth/device/cancel",
            json!({ "poll_token": "nope" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn an_expired_link_approves_nothing() {
    let state = state();
    let app = app_with(state.clone());
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;

    // Age it past its expiry, the way a day of waiting would.
    let stored = state
        .device_links
        .get(link_id.parse().unwrap())
        .await
        .unwrap()
        .expect("link was not stored");
    state
        .device_links
        .update(&DeviceLink {
            expires_at: Utc::now() - Duration::minutes(1),
            ..stored
        })
        .await
        .unwrap();

    let cookies = register(&app, "me@example.com", None).await;
    let (status, _, html) = send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("expired"), "{html}");

    assert_eq!(poll(&app, &poll_token).await["status"], "expired");
}

#[tokio::test]
async fn starting_a_link_sweeps_the_ones_nobody_finished() {
    let state = state();
    let app = app_with(state.clone());

    let account = signed_up(&state, "me@example.com").await;
    let stale_pending = stale_link(&state, "stale-pending", None).await;
    let stale_approved = stale_link(&state, "stale-approved", Some(&account)).await;
    let (fresh_id, _, _) = start_link(&app, "fresh").await;

    // The sweep runs on the create path — the only busy moment this table has.
    start_link(&app, "another").await;

    assert!(
        state
            .device_links
            .get(stale_pending)
            .await
            .unwrap()
            .is_none(),
        "an abandoned pending link outlived its 24 hours",
    );
    assert!(
        state
            .device_links
            .get(stale_approved)
            .await
            .unwrap()
            .is_none(),
        "an approved link nobody collected outlived its 24 hours",
    );
    assert!(
        state
            .device_links
            .get(fresh_id.parse().unwrap())
            .await
            .unwrap()
            .is_some(),
        "the sweep took a link that is still good",
    );
}

#[tokio::test]
async fn a_banned_account_cannot_collect_an_approved_link() {
    // The ban can land between approving in the browser and the app's next
    // poll; `issue_session` does not check, so this path has to.
    let state = state();
    let app = app_with(state.clone());
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;
    let cookies = register(&app, "me@example.com", Some(&link_id)).await;
    send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;

    let account = state
        .accounts
        .find_by_email("me@example.com")
        .await
        .unwrap()
        .unwrap();
    state
        .accounts
        .update(&Account {
            banned_at: Some(Utc::now()),
            ..account
        })
        .await
        .unwrap();

    let (status, _, body) = send(
        &app,
        post_json(
            "/api/v1/auth/device/poll",
            json!({ "poll_token": poll_token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("account_banned"), "{body}");
}

#[tokio::test]
async fn signing_in_with_a_password_also_carries_the_link() {
    let app = app();
    // An account that already exists: the visitor signs in rather than
    // registering, and must still land back on the link.
    register(&app, "me@example.com", None).await;
    let (link_id, poll_token, _) = start_link(&app, "laptop").await;

    let (status, headers, html) = send(&app, get(&format!("/login?link={link_id}"))).await;
    assert_eq!(status, StatusCode::OK);
    let cookies = jar("", &headers);
    let token = csrf_field(&html);
    assert_eq!(
        field_value(&html, "link").as_deref(),
        Some(link_id.as_str())
    );

    let body = format!("csrf={token}&email=me@example.com&password={PASSWORD}&link={link_id}");
    let (status, headers, _) = send(&app, post_form("/login", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], format!("/link/{link_id}"));

    let cookies = jar(&cookies, &headers);
    send(
        &app,
        get_with_cookies(&format!("/link/{link_id}"), &cookies),
    )
    .await;
    assert_eq!(poll(&app, &poll_token).await["status"], "approved");
}

#[tokio::test]
async fn an_already_signed_in_visitor_is_sent_to_the_link_not_to_their_account() {
    let app = app();
    let cookies = register(&app, "me@example.com", None).await;
    let (link_id, _, _) = start_link(&app, "laptop").await;

    let (status, headers, _) = send(
        &app,
        get_with_cookies(&format!("/login?link={link_id}"), &cookies),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], format!("/link/{link_id}"));
}

#[tokio::test]
async fn a_malformed_link_id_is_a_page_not_a_parser_error() {
    let app = app();
    let (status, _, html) = send(&app, get("/link/not-a-uuid")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("expired"), "{html}");
}

/// An account created straight through the store, for the cases that need one
/// without a browser.
async fn signed_up(state: &AppState, email: &str) -> Account {
    state
        .accounts
        .create(NewAccount {
            email: email.to_string(),
            password_hash: None,
            google_sub: None,
        })
        .await
        .unwrap()
}

/// A link that expired yesterday.
async fn stale_link(
    state: &AppState,
    poll_token: &str,
    approved_by: Option<&Account>,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let created = Utc::now() - Duration::hours(30);
    state
        .device_links
        .insert(DeviceLink {
            id,
            poll_token: poll_token.to_string(),
            user_code: "AAAA-BBBB".to_string(),
            device_label: None,
            status: match approved_by {
                Some(_) => DeviceLinkStatus::Approved,
                None => DeviceLinkStatus::Pending,
            },
            account_id: approved_by.map(|a| a.id),
            created_at: created,
            expires_at: created + Duration::hours(24),
        })
        .await
        .unwrap();
    id
}

/// Keeps `Arc` in scope for the store handles the tests reach through.
#[allow(dead_code)]
fn _assert_state_is_shareable(state: AppState) -> Arc<dyn DeviceLinkStore> {
    state.device_links
}
