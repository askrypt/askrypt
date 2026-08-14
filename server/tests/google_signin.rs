//! "Sign in with Google" on the website (Phase 13).
//!
//! Runs over `tower`'s `oneshot` against the in-memory fakes, with the
//! id-token seam given a web client id so the pages render exactly what a
//! configured deployment renders — the real verifier is RS256 against
//! Google's JWKS and its rules are unit-tested in `store/google.rs`.
//!
//! Both halves are asserted here on purpose, because the point of the feature
//! is where they meet: the page has to offer a button the server will accept a
//! credential from, and the handler has to reach the *same* account rules the
//! JSON API reaches. So: what the two pages render and what headers they send,
//! then create / sign in again / link to an existing password account, then
//! the refusals — a bad credential, no credential at all, an unverified Google
//! address, a banned account, a closed server, a missing CSRF token — and
//! finally that a server without a web client id is completely unchanged.

use std::path::Path;
use std::sync::Arc;

use askrypt_server::config::Config;
use askrypt_server::hardening::{CSP, CSP_GOOGLE};
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::memory::{FakeIdTokenVerifier, MemoryAccountStore};
use askrypt_server::store::{AccountStore, REGISTRATION_ENABLED, VerifiedIdToken};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt;
use tower::ServiceExt;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const CLIENT_ID: &str = "web-client-id.apps.googleusercontent.com";
const COOP: &str = "cross-origin-opener-policy";

struct TestApp {
    app: Router,
    verifier: Arc<FakeIdTokenVerifier>,
    accounts: Arc<MemoryAccountStore>,
    state: AppState,
}

fn config() -> Config {
    Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    }
}

/// A server whose website offers the Google button. The stores are kept so a
/// test can reach past the HTTP surface for the two states no request can put
/// the server into for itself — a banned account and a closed registration.
fn app_with_google() -> TestApp {
    let verifier = Arc::new(FakeIdTokenVerifier::default().with_web_client_id(CLIENT_ID));
    let accounts = Arc::new(MemoryAccountStore::default());
    let state = AppState {
        id_verifier: Arc::clone(&verifier) as _,
        accounts: Arc::clone(&accounts) as _,
        ..AppState::in_memory()
    };
    TestApp {
        app: router(state.clone(), &config()),
        verifier,
        accounts,
        state,
    }
}

/// The default wiring: Google configured for the JSON API's sake, or not at
/// all — either way the website has no button.
fn app_without_google() -> Router {
    router(AppState::in_memory(), &config())
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

fn get_with(uri: &str, cookies: &str) -> Request<Body> {
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

fn csrf_field(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("no csrf field in the form") + marker.len();
    let rest = &html[start..];
    rest[..rest.find('"').unwrap()].to_string()
}

/// Fetches a form page and returns `(cookies, csrf token)`.
async fn open_form(app: &Router, path: &str) -> (String, String) {
    let (status, headers, html) = send(app, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    (jar("", &headers), csrf_field(&html))
}

/// Teaches the fake verifier one credential.
fn credential(t: &TestApp, token: &str, subject: &str, email: &str, verified: bool) {
    t.verifier.register(
        token,
        VerifiedIdToken {
            subject: subject.into(),
            email: email.into(),
            email_verified: verified,
        },
    );
}

/// Signs in with a Google credential from the sign-in page, exactly as the
/// button does: fetch the page for a CSRF token, post the credential to our
/// own origin. Returns the whole response.
async fn sign_in_with(t: &TestApp, token: &str) -> (StatusCode, HeaderMap, String) {
    let (cookies, csrf) = open_form(&t.app, "/login").await;
    send(
        &t.app,
        post_form(
            "/auth/google",
            &cookies,
            &format!("csrf={csrf}&credential={token}"),
        ),
    )
    .await
}

/// Registers an email+password account through the website.
async fn register(app: &Router, email: &str) {
    let (cookies, csrf) = open_form(app, "/register").await;
    let (status, _, body) = send(
        app,
        post_form(
            "/register",
            &cookies,
            &format!("csrf={csrf}&email={email}&password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "registration failed: {body}");
}

// ------------------------------------------------------------- the page

#[tokio::test]
async fn both_auth_pages_carry_the_button_and_its_scripts() {
    let t = app_with_google();
    for path in ["/login", "/register"] {
        let (status, _, html) = send(&t.app, get(path)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains(&format!("data-google-client-id=\"{CLIENT_ID}\"")),
            "no client id on {path}"
        );
        assert!(
            html.contains("https://accounts.google.com/gsi/client"),
            "no Google library on {path}"
        );
        assert!(html.contains("/assets/google.js"), "no helper on {path}");
        // The hidden form the credential is posted through, on our own origin.
        assert!(
            html.contains("action=\"/auth/google\""),
            "no credential form on {path}"
        );
        assert!(html.contains("name=\"credential\""), "no field on {path}");
    }

    // Google's own button wording differs per page; both do the same thing.
    let (_, _, login) = send(&t.app, get("/login")).await;
    assert!(login.contains("data-google-text=\"signin_with\""));
    let (_, _, register) = send(&t.app, get("/register")).await;
    assert!(register.contains("data-google-text=\"signup_with\""));
}

/// The credential form is a *sibling* of the password form, never a child:
/// nested forms are invalid HTML and the inner one would simply not submit.
#[tokio::test]
async fn the_two_forms_are_siblings_inside_one_card() {
    let (_, _, html) = send(&app_with_google().app, get("/login")).await;
    let card = html.find("id=\"auth-form\"").expect("no card");
    let password_form = html.find("action=\"/login\"").expect("no password form");
    let password_end = html[password_form..].find("</form>").unwrap() + password_form;
    let google_form = html
        .find("action=\"/auth/google\"")
        .expect("no google form");
    assert!(card < password_form, "the card must wrap both forms");
    assert!(
        password_end < google_form,
        "the Google form is nested inside the password form"
    );
}

/// The widening is scoped to the two pages that render the button, and to
/// what that button actually loads. Everything else keeps the strict policy
/// and the strict opener policy.
#[tokio::test]
async fn only_the_auth_pages_relax_the_headers_and_only_with_a_button() {
    let t = app_with_google();
    for path in ["/login", "/register"] {
        let (_, headers, _) = send(&t.app, get(path)).await;
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CSP_GOOGLE,
            "{path}"
        );
        // The sign-in popup has to be able to answer its opener.
        assert_eq!(headers[COOP], "same-origin-allow-popups", "{path}");
    }
    for path in ["/", "/account", "/nope"] {
        let (_, headers, _) = send(&t.app, get(path)).await;
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP, "{path}");
        assert_eq!(headers[COOP], "same-origin", "{path}");
    }
}

// ------------------------------------------------------------- signing in

#[tokio::test]
async fn a_valid_credential_creates_the_account_and_signs_in() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "New.User@Example.com", true);

    let (status, headers, body) = sign_in_with(&t, "tok").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(headers[header::LOCATION], "/account");

    // The session cookie really signs the visitor in, under the normalized
    // address the token carried.
    let cookies = jar("", &headers);
    let (status, _, html) = send(&t.app, get_with("/account", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("new.user@example.com"), "{html}");
}

/// The second sign-in is the same account, not a second one — the whole
/// point of keying on the Google `sub`.
#[tokio::test]
async fn signing_in_again_reuses_the_account() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "user@example.com", true);

    let (first, _, _) = sign_in_with(&t, "tok").await;
    let (second, _, _) = sign_in_with(&t, "tok").await;
    assert_eq!(first, StatusCode::SEE_OTHER);
    assert_eq!(second, StatusCode::SEE_OTHER);

    let accounts = t.accounts.list(100, 0).await.unwrap();
    assert_eq!(accounts.len(), 1, "a second account was created");
}

/// Google sign-in on an address that already has a password account *links*
/// the two, and the password keeps working afterwards.
#[tokio::test]
async fn a_matching_email_links_to_the_existing_account() {
    let t = app_with_google();
    register(&t.app, "both@example.com").await;
    credential(&t, "tok", "sub-1", "Both@Example.com", true);

    let (status, _, body) = sign_in_with(&t, "tok").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(t.accounts.list(100, 0).await.unwrap().len(), 1);
    let account = t
        .accounts
        .find_by_email("both@example.com")
        .await
        .unwrap()
        .expect("account");
    assert_eq!(account.google_sub.as_deref(), Some("sub-1"));
    assert!(account.password_hash.is_some(), "the password was dropped");

    let (cookies, csrf) = open_form(&t.app, "/login").await;
    let (status, _, _) = send(
        &t.app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=both@example.com&password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the password stopped working"
    );
}

/// A visitor who arrived from a desktop sign-in lands back on the device link
/// rather than on their account page — the same carry-through the password
/// form does, through the hidden field in the *Google* form.
#[tokio::test]
async fn a_device_link_survives_the_round_trip() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "user@example.com", true);
    let link = "11111111-2222-3333-4444-555555555555";

    let (status, headers, html) = send(&t.app, get(&format!("/login?link={link}"))).await;
    assert_eq!(status, StatusCode::OK);
    let cookies = jar("", &headers);
    let csrf = csrf_field(&html);
    // Both forms carry it, so whichever the visitor uses comes back here.
    assert_eq!(
        html.matches(&format!("name=\"link\" value=\"{link}\""))
            .count(),
        2,
        "{html}"
    );

    let (status, headers, _) = send(
        &t.app,
        post_form(
            "/auth/google",
            &cookies,
            &format!("csrf={csrf}&credential=tok&link={link}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], format!("/link/{link}"));
}

// ------------------------------------------------------------- refusals

/// The scriptless case, and the dismissed-popup case: nothing was minted. The
/// form comes back with advice, not a 4xx.
#[tokio::test]
async fn a_missing_credential_is_refused_with_advice() {
    let t = app_with_google();
    let (cookies, csrf) = open_form(&t.app, "/login").await;
    let (status, headers, html) = send(
        &t.app,
        post_form(
            "/auth/google",
            &cookies,
            &format!("csrf={csrf}&credential="),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.contains("JavaScript"), "unhelpful message: {html}");
}

/// A credential that does not verify says so and no more. A forged token, an
/// expired one and one minted for another site are one event to the visitor.
#[tokio::test]
async fn a_credential_that_does_not_verify_is_refused() {
    let t = app_with_google();
    let (status, headers, html) = sign_in_with(&t, "forged").await;

    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.contains("could not verify"), "{html}");
    assert_eq!(t.accounts.list(100, 0).await.unwrap().len(), 0);
}

/// An address Google has not verified would let anyone who can receive at it
/// — or claim it — take over the matching account.
#[tokio::test]
async fn an_unverified_google_address_is_refused() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "unverified@example.com", false);

    let (status, headers, html) = sign_in_with(&t, "tok").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION));
    assert!(html.contains("not verified"), "{html}");
    assert_eq!(t.accounts.list(100, 0).await.unwrap().len(), 0);
}

#[tokio::test]
async fn a_banned_account_cannot_sign_in_with_google() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "banned@example.com", true);
    assert_eq!(sign_in_with(&t, "tok").await.0, StatusCode::SEE_OTHER);

    let mut account = t
        .accounts
        .find_by_email("banned@example.com")
        .await
        .unwrap()
        .expect("account");
    account.banned_at = Some(Utc::now());
    t.accounts.update(&account).await.unwrap();

    let (status, headers, html) = sign_in_with(&t, "tok").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.to_lowercase().contains("suspend"), "{html}");
}

/// A closed server refuses the address it has never seen, and keeps letting
/// the accounts it already has back in — the same split
/// `auth::upsert_google_account` applies to the JSON API.
#[tokio::test]
async fn a_closed_server_refuses_new_google_accounts_only() {
    let t = app_with_google();
    credential(&t, "old", "sub-1", "already@example.com", true);
    assert_eq!(sign_in_with(&t, "old").await.0, StatusCode::SEE_OTHER);

    t.state
        .settings
        .set(REGISTRATION_ENABLED, "false")
        .await
        .unwrap();

    credential(&t, "new", "sub-2", "newcomer@example.com", true);
    let (status, headers, html) = sign_in_with(&t, "new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION));
    assert!(html.contains("not accepting new accounts"), "{html}");
    assert_eq!(t.accounts.list(100, 0).await.unwrap().len(), 1);

    // The account that already exists is unaffected.
    assert_eq!(sign_in_with(&t, "old").await.0, StatusCode::SEE_OTHER);
}

/// The form is same-origin precisely so it can be covered by the site's one
/// CSRF scheme. This is that check doing its job.
#[tokio::test]
async fn a_credential_without_a_csrf_token_is_refused() {
    let t = app_with_google();
    credential(&t, "tok", "sub-1", "user@example.com", true);
    let (cookies, csrf) = open_form(&t.app, "/login").await;

    let (status, _, _) = send(
        &t.app,
        post_form("/auth/google", &cookies, "credential=tok"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = send(
        &t.app,
        post_form(
            "/auth/google",
            &cookies,
            &format!("csrf={}0&credential=tok", &csrf[..csrf.len() - 1]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(t.accounts.list(100, 0).await.unwrap().len(), 0);
}

/// No `GET`: a sign-in a link could trigger is one a prefetcher or a link
/// checker could trigger, and this route mints a session.
#[tokio::test]
async fn the_route_is_post_only() {
    let (status, _, _) = send(&app_with_google().app, get("/auth/google")).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

// ------------------------------------------------------------- switched off

/// Off means invisible: no button, no scripts, no widened headers, and a POST
/// that cannot be talked into signing anyone in.
#[tokio::test]
async fn without_a_web_client_id_the_pages_are_exactly_as_they_were() {
    let app = app_without_google();
    for path in ["/login", "/register"] {
        let (status, headers, html) = send(&app, get(path)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!html.contains("google"), "google markup on {path}: {html}");
        assert!(!html.contains("/auth/google"), "credential form on {path}");
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP, "{path}");
        assert_eq!(headers[COOP], "same-origin", "{path}");
    }

    // The route still exists — it is the verifier, not the router, that is
    // switched off — and answers the way an unverifiable credential does.
    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/auth/google",
            &cookies,
            &format!("csrf={csrf}&credential=anything"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.contains("could not verify"), "{html}");
}
