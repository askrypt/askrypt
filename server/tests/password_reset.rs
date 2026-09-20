//! Password reset (Phase 16): a mailed single-use link sets a new password
//! and signs every device out.
//!
//! The suite holds the mailer, the account store, the reset store and the
//! session store, so it can read the link out of the "sent" mail, backdate a
//! pending link (the one state no request can create), plant accounts that
//! cannot have one, and check that sessions really went.
//!
//! As in `tests/web.rs`, every test builds its own app: without `ConnectInfo`
//! all requests share one rate-limit bucket.

use std::sync::Arc;
use std::time::Duration;

use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::memory::{
    MemoryAccountStore, MemoryMailer, MemoryPasswordResetStore, MemorySessionStore,
};
use askrypt_server::store::{AccountStore, NewAccount, PasswordResetStore, SessionStore};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const NEW_PASSWORD: &str = "a-brand-new-password";
const PUBLIC_URL: &str = "https://askrypt.test";

struct TestApp {
    app: Router,
    mailer: Arc<MemoryMailer>,
    accounts: Arc<MemoryAccountStore>,
    pending: Arc<MemoryPasswordResetStore>,
    sessions: Arc<MemorySessionStore>,
}

/// The app under test. `confirmation` keeps the production email-confirmation
/// default on; most tests switch it off so registering signs the visitor
/// straight in and there is a session to lose.
fn test_app(confirmation: bool) -> TestApp {
    let mailer = Arc::new(MemoryMailer::default());
    let accounts = Arc::new(MemoryAccountStore::default());
    let pending = Arc::new(MemoryPasswordResetStore::default());
    let sessions = Arc::new(MemorySessionStore::default());
    let state = AppState {
        mailer: Arc::clone(&mailer) as _,
        accounts: Arc::clone(&accounts) as _,
        password_resets: Arc::clone(&pending) as _,
        sessions: Arc::clone(&sessions) as _,
        email_confirmation: confirmation,
        public_url: PUBLIC_URL.to_string(),
        ..AppState::in_memory()
    };
    TestApp {
        app: router(state, &common::config()),
        mailer,
        accounts,
        pending,
        sessions,
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

/// A signed-out browser that has loaded `path`: its cookies, CSRF token and
/// the HTML it got.
async fn visit(app: &Router, path: &str) -> (String, String, String) {
    let (status, headers, html) = send(app, get(path)).await;
    assert_eq!(status, StatusCode::OK, "{path}");
    (
        jar(&headers),
        field_value(&html, "csrf").expect("no csrf field"),
        html,
    )
}

fn has_session_cookie(headers: &HeaderMap) -> bool {
    set_cookies(headers)
        .iter()
        .any(|c| c.starts_with("askrypt_session=") && !c.contains("Max-Age=0"))
}

async fn register(app: &Router, email: &str, password: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf, _) = visit(app, "/register").await;
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
    let (cookies, csrf, _) = visit(app, "/login").await;
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

/// Asks for a link the way a browser does: open the form, submit it.
async fn forgot(app: &Router, email: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf, _) = visit(app, "/forgot").await;
    send(
        app,
        post_form("/forgot", &cookies, &format!("csrf={csrf}&email={email}")),
    )
    .await
}

/// Uses a link the way a browser does: open the landing page, type a
/// password, submit it.
async fn reset(app: &Router, token: &str, password: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf, _) = visit(app, &format!("/reset/{token}")).await;
    send(
        app,
        post_form(
            "/reset",
            &cookies,
            &format!("csrf={csrf}&token={token}&password={password}"),
        ),
    )
    .await
}

/// The reset token out of the `n`th mail sent.
fn token_in_mail(t: &TestApp, n: usize) -> String {
    let mail = &t.mailer.sent()[n];
    let prefix = format!("{PUBLIC_URL}/reset/");
    let start = mail.body.find(&prefix).expect("no link in the mail") + prefix.len();
    mail.body[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Reset mails go out from a spawned task, so give it a moment.
async fn wait_for_mail(t: &TestApp, count: usize) {
    for _ in 0..100 {
        if t.mailer.sent().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {count} mails, have {}", t.mailer.sent().len());
}

/// Long enough for a mail that must *not* be sent to have been sent.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Moves the pending link of `email` back in time, so it is past the request
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

async fn session_count(t: &TestApp, email: &str) -> usize {
    let account = t.accounts.find_by_email(email).await.unwrap().unwrap();
    t.sessions.list_for_account(account.id).await.unwrap().len()
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn asking_mails_a_link_and_says_the_same_for_any_address() {
    let t = test_app(false);
    register(&t.app, "known@example.com", PASSWORD).await;

    let (status, _, html) = forgot(&t.app, "known@example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Check your inbox"), "{html}");
    wait_for_mail(&t, 1).await;
    assert_eq!(t.mailer.sent()[0].to, "known@example.com");
    assert_eq!(token_in_mail(&t, 0).len(), 64);

    // An address nobody registered: same answer, no mail.
    let (_, _, unknown) = forgot(&t.app, "nobody@example.com").await;
    assert!(
        unknown.contains("If that address has an account"),
        "{unknown}"
    );
    settle().await;
    assert_eq!(t.mailer.sent().len(), 1);

    // Inside the cooldown: same answer, no second mail.
    let (_, _, again) = forgot(&t.app, "known@example.com").await;
    assert!(again.contains("If that address has an account"));
    settle().await;
    assert_eq!(t.mailer.sent().len(), 1);

    // Past it: a new link, and the first one is dead.
    backdate(&t, "known@example.com", false).await;
    forgot(&t.app, "known@example.com").await;
    wait_for_mail(&t, 2).await;
    let first = token_in_mail(&t, 0);
    let second = token_in_mail(&t, 1);
    assert_ne!(first, second);
    let (_, _, dead) = reset(&t.app, &first, NEW_PASSWORD).await;
    assert!(dead.contains("This link can't be used"), "{dead}");
}

#[tokio::test]
async fn the_link_sets_the_password_and_signs_every_device_out() {
    let t = test_app(false);
    let (_, headers, _) = register(&t.app, "lost@example.com", PASSWORD).await;
    assert!(has_session_cookie(&headers), "registration signs you in");
    assert_eq!(session_count(&t, "lost@example.com").await, 1);

    forgot(&t.app, "lost@example.com").await;
    wait_for_mail(&t, 1).await;
    let token = token_in_mail(&t, 0);

    // A mail scanner fetching the link changes nothing: the form is shown,
    // the token is still spendable afterwards.
    let (status, _, landing) = send(&t.app, get(&format!("/reset/{token}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(landing.contains("Choose a new password"), "{landing}");
    assert!(
        t.pending
            .get(account_id(&t, "lost@example.com").await)
            .await
            .unwrap()
            .is_some()
    );

    let (status, headers, _) = reset(&t.app, &token, NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
    // A reset proves the inbox, not that the browser is the account's: it
    // signs nobody in, and it signs everybody out.
    assert!(!has_session_cookie(&headers));
    assert_eq!(session_count(&t, "lost@example.com").await, 0);

    let (status, _, _) = login(&t.app, "lost@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "the old password must not work");
    let (status, headers, _) = login(&t.app, "lost@example.com", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(has_session_cookie(&headers));
}

async fn account_id(t: &TestApp, email: &str) -> uuid::Uuid {
    t.accounts.find_by_email(email).await.unwrap().unwrap().id
}

#[tokio::test]
async fn a_link_works_once_and_bad_or_expired_links_are_refused_alike() {
    let t = test_app(false);
    register(&t.app, "once@example.com", PASSWORD).await;
    forgot(&t.app, "once@example.com").await;
    wait_for_mail(&t, 1).await;
    let token = token_in_mail(&t, 0);

    let (status, _, _) = reset(&t.app, &token, NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _, used) = reset(&t.app, &token, "yet-another-password").await;
    assert_eq!(status, StatusCode::OK);
    assert!(used.contains("This link can't be used"), "{used}");

    let (_, _, garbage) = reset(&t.app, "not-a-token", NEW_PASSWORD).await;
    assert!(garbage.contains("This link can't be used"));

    register(&t.app, "late@example.com", PASSWORD).await;
    forgot(&t.app, "late@example.com").await;
    wait_for_mail(&t, 2).await;
    let late = token_in_mail(&t, 1);
    backdate(&t, "late@example.com", true).await;
    let (_, _, expired) = reset(&t.app, &late, NEW_PASSWORD).await;
    assert!(expired.contains("This link can't be used"));
    // The old password still works: an expired link changed nothing.
    let (status, _, _) = login(&t.app, "late@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_refused_password_leaves_the_link_usable() {
    let t = test_app(false);
    register(&t.app, "short@example.com", PASSWORD).await;
    forgot(&t.app, "short@example.com").await;
    wait_for_mail(&t, 1).await;
    let token = token_in_mail(&t, 0);

    let (status, _, refused) = reset(&t.app, &token, "short").await;
    assert_eq!(status, StatusCode::OK);
    assert!(refused.contains("at least 8 characters"), "{refused}");
    // The form comes back carrying the same token, because it was never spent.
    assert_eq!(field_value(&refused, "token").as_deref(), Some(&token[..]));

    let (status, _, _) = reset(&t.app, &token, NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn accounts_without_a_password_and_suspended_ones_get_no_link() {
    let t = test_app(false);
    // A Google-created account has no password to reset.
    t.accounts
        .create(NewAccount {
            email: "google@example.com".into(),
            password_hash: None,
            google_sub: Some("sub-1".into()),
            email_confirmed_at: Some(Utc::now()),
        })
        .await
        .unwrap();
    let (_, _, html) = forgot(&t.app, "google@example.com").await;
    assert!(html.contains("Check your inbox"), "{html}");

    // A suspended account is left alone, like a confirmation resend.
    register(&t.app, "banned@example.com", PASSWORD).await;
    let mut account = t
        .accounts
        .find_by_email("banned@example.com")
        .await
        .unwrap()
        .unwrap();
    account.banned_at = Some(Utc::now());
    t.accounts.update(&account).await.unwrap();
    forgot(&t.app, "banned@example.com").await;

    settle().await;
    assert!(t.mailer.sent().is_empty(), "{:?}", t.mailer.sent());
}

#[tokio::test]
async fn resetting_also_confirms_an_unconfirmed_address() {
    // With confirmation on, registering leaves the account unconfirmed and
    // unable to sign in. Opening a reset link proves the same inbox a
    // confirmation link would, so it counts.
    let t = test_app(true);
    register(&t.app, "unconfirmed@example.com", PASSWORD).await;
    wait_for_mail(&t, 1).await; // the confirmation link

    forgot(&t.app, "unconfirmed@example.com").await;
    wait_for_mail(&t, 2).await;
    let mail = &t.mailer.sent()[1];
    let prefix = format!("{PUBLIC_URL}/reset/");
    let start = mail.body.find(&prefix).expect("no reset link") + prefix.len();
    let token = mail.body[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let (status, _, _) = reset(&t.app, &token, NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        t.accounts
            .find_by_email("unconfirmed@example.com")
            .await
            .unwrap()
            .unwrap()
            .is_confirmed()
    );
    let (status, headers, _) = login(&t.app, "unconfirmed@example.com", NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(has_session_cookie(&headers));
}

#[tokio::test]
async fn the_sign_in_page_offers_the_link_and_the_register_page_does_not() {
    let t = test_app(false);
    let (_, _, login_page) = visit(&t.app, "/login").await;
    assert!(login_page.contains("href=\"/forgot\""), "{login_page}");
    let (_, _, register_page) = visit(&t.app, "/register").await;
    assert!(!register_page.contains("href=\"/forgot\""));
}

#[tokio::test]
async fn the_reset_pages_carry_no_inline_script() {
    let t = test_app(false);
    let (_, _, ask) = visit(&t.app, "/forgot").await;
    let (_, _, landing) = visit(&t.app, "/reset/some-token").await;
    for html in [ask, landing] {
        assert!(!html.contains("<script>"), "inline script in {html}");
        assert!(!html.contains("<style"), "inline style in {html}");
        assert!(!html.contains("hx-on"), "inline handler in {html}");
    }
}
