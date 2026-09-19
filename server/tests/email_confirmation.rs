//! Email confirmation (Phase 15): registering mails a link, and a password
//! account cannot sign in until the link has been used.
//!
//! Unlike the other suites this one keeps the production default, with
//! confirmation on. It holds the mailer and the confirmation store so it can
//! read the link out of the "sent" mail and backdate a pending link, the one
//! state no request can create.
//!
//! As in `tests/web.rs`, every test builds its own app: without `ConnectInfo`
//! all requests share one rate-limit bucket.

use std::sync::Arc;
use std::time::Duration;

use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::memory::{
    FakeIdTokenVerifier, MemoryAccountStore, MemoryEmailConfirmationStore, MemoryMailer,
};
use askrypt_server::store::{AccountStore, EmailConfirmationStore, VerifiedIdToken};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const PUBLIC_URL: &str = "https://askrypt.test";

struct TestApp {
    app: Router,
    mailer: Arc<MemoryMailer>,
    accounts: Arc<MemoryAccountStore>,
    pending: Arc<MemoryEmailConfirmationStore>,
    verifier: Arc<FakeIdTokenVerifier>,
}

fn test_app() -> TestApp {
    let mailer = Arc::new(MemoryMailer::default());
    let accounts = Arc::new(MemoryAccountStore::default());
    let pending = Arc::new(MemoryEmailConfirmationStore::default());
    let verifier = Arc::new(FakeIdTokenVerifier::default());
    let state = AppState {
        mailer: Arc::clone(&mailer) as _,
        accounts: Arc::clone(&accounts) as _,
        email_confirmations: Arc::clone(&pending) as _,
        id_verifier: Arc::clone(&verifier) as _,
        email_confirmation: true,
        public_url: PUBLIC_URL.to_string(),
        ..AppState::in_memory()
    };
    TestApp {
        app: router(state, &common::password_api_config()),
        mailer,
        accounts,
        pending,
        verifier,
    }
}

// ------------------------------------------------------------------ helpers

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

fn post_form(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header(header::COOKIE, cookies)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::post(uri)
        .header(header::HOST, HOST)
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

/// The cookies a response set, as a `Cookie` header — enough for a fresh
/// signed-out browser, which is all these tests drive.
fn jar(headers: &HeaderMap) -> String {
    set_cookies(headers)
        .iter()
        .filter_map(|c| c.split_once("; ").map(|(pair, _)| pair.to_string()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn field_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let rest = &html[start..];
    Some(rest[..rest.find('"')?].to_string())
}

/// A signed-out browser that has loaded `path`: its cookies and CSRF token.
async fn visit(app: &Router, path: &str) -> (String, String) {
    let (status, headers, html) = send(app, get(path)).await;
    assert_eq!(status, StatusCode::OK, "{path}");
    (
        jar(&headers),
        field_value(&html, "csrf").expect("no csrf field"),
    )
}

fn has_session_cookie(headers: &HeaderMap) -> bool {
    set_cookies(headers)
        .iter()
        .any(|c| c.starts_with("askrypt_session=") && !c.contains("Max-Age=0"))
}

async fn register(app: &Router, email: &str, password: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf) = visit(app, "/register").await;
    send(
        app,
        post_form(
            "/register",
            &cookies,
            &format!("csrf={csrf}&email={email}&password={password}"),
        ),
    )
    .await
}

async fn login(app: &Router, email: &str, password: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf) = visit(app, "/login").await;
    send(
        app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email={email}&password={password}"),
        ),
    )
    .await
}

/// The token out of the `n`th mail sent.
fn token_in_mail(t: &TestApp, n: usize) -> String {
    let mail = &t.mailer.sent()[n];
    let prefix = format!("{PUBLIC_URL}/confirm/");
    let start = mail.body.find(&prefix).expect("no link in the mail") + prefix.len();
    mail.body[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Uses a link the way a browser does: open the landing page, press the
/// button.
async fn confirm(app: &Router, token: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf) = visit(app, &format!("/confirm/{token}")).await;
    send(
        app,
        post_form("/confirm", &cookies, &format!("csrf={csrf}&token={token}")),
    )
    .await
}

/// Resends are mailed from a spawned task, so give it a moment.
async fn wait_for_mail(t: &TestApp, count: usize) {
    for _ in 0..100 {
        if t.mailer.sent().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {count} mails, have {}", t.mailer.sent().len());
}

/// Moves the pending link of `email` back in time, so it is past the resend
/// cooldown or, with `expire`, past its expiry.
async fn backdate(t: &TestApp, email: &str, expire: bool) {
    let account = t.accounts.find_by_email(email).await.unwrap().unwrap();
    let mut pending = t.pending.get(account.id).await.unwrap().unwrap();
    pending.created_at = Utc::now() - chrono::Duration::hours(2);
    if expire {
        pending.expires_at = Utc::now() - chrono::Duration::seconds(1);
    }
    t.pending.put(pending).await.unwrap();
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn registering_shows_the_check_inbox_page_and_mails_a_link() {
    let t = test_app();
    let (status, headers, html) = register(&t.app, "new@example.com", PASSWORD).await;

    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Check your inbox"), "{html}");
    assert!(html.contains("new@example.com"));
    assert!(
        !has_session_cookie(&headers),
        "registration must not sign in"
    );

    let sent = t.mailer.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "new@example.com");
    assert_eq!(token_in_mail(&t, 0).len(), 64);
}

#[tokio::test]
async fn sign_in_is_refused_until_the_link_is_used() {
    let t = test_app();
    register(&t.app, "wait@example.com", PASSWORD).await;

    let (status, headers, html) = login(&t.app, "wait@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Confirm your email first"), "{html}");
    assert!(html.contains("Send a new link"));
    assert!(!has_session_cookie(&headers));

    // A wrong password still gets the ordinary refusal, not the hint.
    let (_, _, html) = login(&t.app, "wait@example.com", "wrong-password").await;
    assert!(!html.contains("Confirm your email first"));

    // The JSON login answers the same way.
    let (status, _, body) = send(
        &t.app,
        post_json(
            "/api/v1/auth/login",
            json!({ "email": "wait@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("email_not_confirmed"), "{body}");
}

#[tokio::test]
async fn opening_the_link_does_not_confirm_but_pressing_the_button_does() {
    let t = test_app();
    register(&t.app, "click@example.com", PASSWORD).await;
    let token = token_in_mail(&t, 0);

    // A mail scanner fetching the link changes nothing.
    let (status, _, html) = send(&t.app, get(&format!("/confirm/{token}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Confirm my email"));
    let account = t
        .accounts
        .find_by_email("click@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(!account.is_confirmed());

    let (status, headers, _) = confirm(&t.app, &token).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
    // Confirming proves the inbox, not the password: nobody is signed in.
    assert!(!has_session_cookie(&headers));

    let (status, headers, _) = login(&t.app, "click@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(has_session_cookie(&headers));
}

#[tokio::test]
async fn a_link_works_once_and_bad_or_expired_links_are_refused_alike() {
    let t = test_app();
    register(&t.app, "once@example.com", PASSWORD).await;
    let token = token_in_mail(&t, 0);

    let (status, _, _) = confirm(&t.app, &token).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _, used) = confirm(&t.app, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(used.contains("This link can't be used"), "{used}");

    let (_, _, garbage) = confirm(&t.app, "not-a-token").await;
    assert!(garbage.contains("This link can't be used"));

    register(&t.app, "late@example.com", PASSWORD).await;
    let late = token_in_mail(&t, 1);
    backdate(&t, "late@example.com", true).await;
    let (_, _, expired) = confirm(&t.app, &late).await;
    assert!(expired.contains("This link can't be used"));
}

#[tokio::test]
async fn resending_replaces_the_link_and_says_the_same_for_any_address() {
    let t = test_app();
    register(&t.app, "again@example.com", PASSWORD).await;
    let first = token_in_mail(&t, 0);

    let resend = |email: &'static str| {
        let app = t.app.clone();
        async move {
            let (cookies, csrf) = visit(&app, "/login").await;
            send(
                &app,
                post_form(
                    "/confirm/resend",
                    &cookies,
                    &format!("csrf={csrf}&email={email}"),
                ),
            )
            .await
        }
    };

    // Inside the cooldown: same answer, no mail.
    let (status, _, inside) = resend("again@example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert!(inside.contains("If that address has an account waiting"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.mailer.sent().len(), 1);

    // Unknown address: same answer, no mail.
    let (_, _, unknown) = resend("nobody@example.com").await;
    assert!(unknown.contains("If that address has an account waiting"));

    // Past the cooldown: a new link, and the old one is dead.
    backdate(&t, "again@example.com", false).await;
    resend("again@example.com").await;
    wait_for_mail(&t, 2).await;
    let second = token_in_mail(&t, 1);
    assert_ne!(first, second);
    let (_, _, dead) = confirm(&t.app, &first).await;
    assert!(dead.contains("This link can't be used"));
    let (status, _, _) = confirm(&t.app, &second).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Confirmed now: no link is left, resending sends nothing, and the
    // answer is still the same.
    assert_no_pending_link(&t, "again@example.com").await;
    let (_, _, confirmed) = resend("again@example.com").await;
    assert!(confirmed.contains("If that address has an account waiting"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.mailer.sent().len(), 2);
}

async fn assert_no_pending_link(t: &TestApp, email: &str) {
    let account = t.accounts.find_by_email(email).await.unwrap().unwrap();
    assert!(t.pending.get(account.id).await.unwrap().is_none());
}

#[tokio::test]
async fn an_unconfirmed_address_can_be_registered_again_but_a_confirmed_one_cannot() {
    let t = test_app();
    register(&t.app, "squat@example.com", "squatter-password").await;

    // The real owner registers over the squatter's pending account.
    let (status, _, html) = register(&t.app, "squat@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Check your inbox"), "{html}");
    assert_eq!(t.accounts.list(10, 0).await.unwrap().len(), 1);

    // Only the newest link works, and it goes with the newest password.
    let (_, _, dead) = confirm(&t.app, &token_in_mail(&t, 0)).await;
    assert!(dead.contains("This link can't be used"));
    let (status, _, _) = confirm(&t.app, &token_in_mail(&t, 1)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = login(&t.app, "squat@example.com", "squatter-password").await;
    assert_eq!(status, StatusCode::OK, "the old password must not work");
    let (status, _, _) = login(&t.app, "squat@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Confirmed addresses are taken.
    let (_, _, taken) = register(&t.app, "squat@example.com", PASSWORD).await;
    assert!(taken.contains("already"), "{taken}");
    assert_eq!(t.mailer.sent().len(), 2);
}

#[tokio::test]
async fn google_confirms_an_unconfirmed_account_and_drops_its_password() {
    let t = test_app();
    // Someone registers an address that is not theirs.
    register(&t.app, "victim@example.com", "attacker-password").await;

    // Its owner signs in with Google.
    t.verifier.register(
        "google-token",
        VerifiedIdToken {
            subject: "sub-victim".into(),
            email: "victim@example.com".into(),
            email_verified: true,
        },
    );
    let (status, _, body) = send(
        &t.app,
        post_json("/api/v1/auth/google", json!({ "id_token": "google-token" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let account = t
        .accounts
        .find_by_email("victim@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(account.is_confirmed());
    assert!(
        account.password_hash.is_none(),
        "the registrant's password must go"
    );
    let (status, _, _) = login(&t.app, "victim@example.com", "attacker-password").await;
    assert_eq!(status, StatusCode::OK, "the registrant must not get in");
}

#[tokio::test]
async fn the_confirmation_pages_carry_no_inline_script() {
    let t = test_app();
    let (_, _, sent) = register(&t.app, "csp@example.com", PASSWORD).await;
    let (_, _, landing) = send(&t.app, get("/confirm/some-token")).await;
    for html in [sent, landing] {
        assert!(!html.contains("<script>"), "inline script in {html}");
        assert!(!html.contains("<style"), "inline style in {html}");
        assert!(!html.contains("hx-on"), "inline handler in {html}");
    }
}
