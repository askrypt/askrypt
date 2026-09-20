//! The reCAPTCHA gate on the four website forms a stranger can submit:
//! sign-in, registration, *Forgot your password?* and the confirmation
//! resend.
//!
//! Runs over `tower`'s `oneshot` against the in-memory fakes, with the
//! captcha seam swapped for [`FakeCaptchaVerifier`] — the real verifier is a
//! network call to Google and its rules are unit-tested in
//! `store/recaptcha.rs`. What is asserted here is the wiring: that a token is
//! demanded, that it is demanded *before* the password is looked at (and,
//! on the two mail forms, before an address is looked up or a mail sent),
//! that a token minted for one form cannot be spent on another, that the
//! pages carry the site key and the widened CSP — and only the pages whose
//! form needs it — and that a server without a configured captcha is
//! completely unchanged.

use std::sync::Arc;

use askrypt_server::hardening::{CSP, CSP_CAPTCHA};
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::memory::{FakeCaptchaVerifier, MemoryMailer};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const SITE_KEY: &str = "test-site-key";
const GOOD_LOGIN_TOKEN: &str = "login-token";
const GOOD_REGISTER_TOKEN: &str = "register-token";
const GOOD_FORGOT_TOKEN: &str = "forgot-token";
const GOOD_RESEND_TOKEN: &str = "resend-token";

/// A server with a captcha, and a handle on the fake so a test can mint more
/// tokens. Both auth actions get one good token up front, since most tests
/// need to get *past* the captcha to reach what they are about.
fn app_with_captcha() -> (Router, Arc<FakeCaptchaVerifier>) {
    let captcha = Arc::new(FakeCaptchaVerifier::new(SITE_KEY, 0.5));
    captcha.register(GOOD_LOGIN_TOKEN, "login", 0.9);
    captcha.register(GOOD_REGISTER_TOKEN, "register", 0.9);
    let state = AppState {
        captcha: Arc::clone(&captcha) as _,
        ..common::state()
    };
    (router(state, &common::password_api_config()), captcha)
}

/// The same, plus a handle on the mailer and the production
/// email-confirmation default — what the two mail-sending forms need to be
/// worth testing: a registration that leaves a link pending, and a way to see
/// whether anything was actually sent.
fn app_with_mail() -> (Router, Arc<FakeCaptchaVerifier>, Arc<MemoryMailer>) {
    let captcha = Arc::new(FakeCaptchaVerifier::new(SITE_KEY, 0.5));
    captcha.register(GOOD_REGISTER_TOKEN, "register", 0.9);
    captcha.register(GOOD_FORGOT_TOKEN, "forgot", 0.9);
    captcha.register(GOOD_RESEND_TOKEN, "resend", 0.9);
    let mailer = Arc::new(MemoryMailer::default());
    let state = AppState {
        captcha: Arc::clone(&captcha) as _,
        mailer: Arc::clone(&mailer) as _,
        email_confirmation: true,
        ..AppState::in_memory()
    };
    (
        router(state, &common::password_api_config()),
        captcha,
        mailer,
    )
}

/// Registers through the website with confirmation on, which answers with the
/// "check your inbox" card rather than a redirect. Returns that card's
/// cookies and HTML, so a test can post the resend form it carries.
async fn register_unconfirmed(app: &Router, email: &str) -> (String, String) {
    let (cookies, csrf) = open_form(app, "/register").await;
    let (status, headers, html) = send(
        app,
        post_form(
            "/register",
            &cookies,
            &format!(
                "csrf={csrf}&email={email}&password={PASSWORD}&captcha_token={GOOD_REGISTER_TOKEN}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "registration failed: {html}");
    assert!(html.contains("Check your inbox"), "{html}");
    (jar(&cookies, &headers), html)
}

/// Mail from the resend and reset paths goes out on a spawned task.
async fn wait_for_mail(mailer: &MemoryMailer, count: usize) {
    for _ in 0..100 {
        if mailer.sent().len() >= count {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("expected {count} mails, have {}", mailer.sent().len());
}

/// Long enough for a mail that must *not* be sent to have been sent.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

/// A server with no captcha configured — the default wiring, and what every
/// other suite runs against.
fn app_without_captcha() -> Router {
    router(common::state(), &common::password_api_config())
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

/// Registers an account through the website, which is the only way to make
/// one here — and exercises the register captcha on the way.
async fn register(app: &Router, email: &str) {
    let (cookies, csrf) = open_form(app, "/register").await;
    let (status, _, body) = send(
        app,
        post_form(
            "/register",
            &cookies,
            &format!(
                "csrf={csrf}&email={email}&password={PASSWORD}&captcha_token={GOOD_REGISTER_TOKEN}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "registration failed: {body}");
}

#[tokio::test]
async fn the_auth_pages_carry_the_site_key_and_the_loader() {
    let (app, _) = app_with_captcha();
    for path in ["/login", "/register"] {
        let (status, _, html) = send(&app, get(path)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains(&format!("data-captcha-key=\"{SITE_KEY}\"")),
            "no site key on {path}"
        );
        assert!(
            html.contains("https://www.google.com/recaptcha/api.js?render="),
            "no reCAPTCHA loader on {path}"
        );
        assert!(
            html.contains("/assets/captcha.js"),
            "no captcha helper on {path}"
        );
    }
    // Each form asks for a token minted for itself — this is what makes the
    // action check in the verifier mean anything.
    let (_, _, login) = send(&app, get("/login")).await;
    assert!(login.contains("data-captcha-action=\"login\""));
    let (_, _, register) = send(&app, get("/register")).await;
    assert!(register.contains("data-captcha-action=\"register\""));
}

/// The auth pages widen their policy only while a captcha is configured, and
/// the pages that render no captcha'd form never do — see
/// `only_the_cards_that_render_a_captcha_relax_the_csp` for the mail forms.
#[tokio::test]
async fn the_auth_pages_relax_the_csp_only_with_a_captcha() {
    let (app, _) = app_with_captcha();
    for path in ["/login", "/register"] {
        let (_, headers, _) = send(&app, get(path)).await;
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CSP_CAPTCHA,
            "{path} did not relax its CSP"
        );
    }
    for path in ["/", "/account", "/nope"] {
        let (_, headers, _) = send(&app, get(path)).await;
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CSP,
            "{path} relaxed its CSP"
        );
    }

    let plain = app_without_captcha();
    for path in ["/login", "/register"] {
        let (_, headers, html) = send(&plain, get(path)).await;
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CSP,
            "{path} relaxed its CSP without a captcha configured"
        );
        assert!(!html.contains("captcha"), "captcha markup on {path}");
        assert!(!html.contains("google.com"), "google script on {path}");
    }
}

/// The widened policy is a *second* policy, not a weakened one: it must still
/// forbid inline and eval'd script, and still refuse to be framed.
#[tokio::test]
async fn the_relaxed_csp_gives_up_only_what_recaptcha_needs() {
    assert!(!CSP_CAPTCHA.contains("script-src 'self' 'unsafe-inline'"));
    assert!(!CSP_CAPTCHA.contains("unsafe-eval"));
    assert!(CSP_CAPTCHA.contains("frame-ancestors 'none'"));
    assert!(CSP_CAPTCHA.contains("form-action 'self'"));
    assert!(CSP_CAPTCHA.contains("base-uri 'none'"));
    assert!(CSP_CAPTCHA.contains("object-src 'none'"));
    // No wildcard hosts: the two Google origins are named.
    assert!(!CSP_CAPTCHA.contains('*'));
    // The one concession beyond the two hosts, needed for reCAPTCHA's
    // injected badge stylesheet.
    assert!(CSP_CAPTCHA.contains("style-src 'self' 'unsafe-inline'"));
}

#[tokio::test]
async fn a_valid_token_signs_in() {
    let (app, _) = app_with_captcha();
    register(&app, "a@example.com").await;

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, _) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!(
                "csrf={csrf}&email=a@example.com&password={PASSWORD}\
                 &captcha_token={GOOD_LOGIN_TOKEN}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
}

/// The no-JavaScript case: the field is submitted empty. The form comes back
/// with a message that says what to do about it, not a 4xx.
#[tokio::test]
async fn a_missing_token_is_refused_with_advice() {
    let (app, _) = app_with_captcha();
    register(&app, "a@example.com").await;

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password={PASSWORD}&captcha_token="),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION));
    assert!(html.contains("JavaScript"), "unhelpful message: {html}");
    // The address is kept so a refused visitor doesn't retype it; the
    // password never is.
    assert!(html.contains("value=\"a@example.com\""));
    assert!(!html.contains(PASSWORD));
}

/// The reason the check comes first: with a bad token the password is never
/// looked at, so a flood of guesses buys no argon2 hashes. Observable as the
/// captcha message rather than "invalid email or password" when *both* are
/// wrong.
#[tokio::test]
async fn the_captcha_is_checked_before_the_password() {
    let (app, _) = app_with_captcha();
    register(&app, "a@example.com").await;

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, _, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password=wrong&captcha_token=forged"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("real person"), "wrong refusal: {html}");
    assert!(
        !html.to_lowercase().contains("invalid email"),
        "the password was checked anyway: {html}"
    );
}

/// A v3 token names the form it was minted for. Without this the token from
/// any captcha'd page would open the login form.
#[tokio::test]
async fn a_token_minted_for_the_other_form_is_refused() {
    let (app, _) = app_with_captcha();
    register(&app, "a@example.com").await;

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!(
                "csrf={csrf}&email=a@example.com&password={PASSWORD}\
                 &captcha_token={GOOD_REGISTER_TOKEN}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.contains("real person"));
}

#[tokio::test]
async fn a_token_scoring_below_the_floor_is_refused() {
    let (app, captcha) = app_with_captcha();
    register(&app, "a@example.com").await;
    captcha.register("botlike", "login", 0.1);

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password={PASSWORD}&captcha_token=botlike"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "signed in anyway");
    assert!(html.contains("real person"));
}

#[tokio::test]
async fn registration_needs_its_own_token() {
    let (app, _) = app_with_captcha();
    let (cookies, csrf) = open_form(&app, "/register").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/register",
            &cookies,
            &format!(
                "csrf={csrf}&email=new@example.com&password={PASSWORD}\
                 &captcha_token={GOOD_LOGIN_TOKEN}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION), "account created");
    assert!(html.contains("real person"));

    // And the account really was not created: the right token now works.
    register(&app, "new@example.com").await;
}

/// A refused submit re-renders the form with an *empty* token field. A v3
/// token is single-use, so echoing the spent one back would guarantee the
/// retry fails too.
#[tokio::test]
async fn a_refused_form_comes_back_ready_to_mint_a_new_token() {
    let (app, _) = app_with_captcha();
    let (cookies, csrf) = open_form(&app, "/login").await;
    let (_, _, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password={PASSWORD}&captcha_token=forged"),
        ),
    )
    .await;
    assert!(
        html.contains("data-captcha-key"),
        "no captcha field: {html}"
    );
    assert!(!html.contains("forged"), "the spent token was echoed back");
    assert!(!html.contains("name=\"captcha_token\" value="));
}

/// The JSON API is deliberately not captcha'd: native clients cannot mint a
/// token, and the desktop's browser sign-in goes through `/login` instead.
#[tokio::test]
async fn the_json_auth_api_is_unaffected() {
    let (app, _) = app_with_captcha();
    let json = |uri: &str, body: String| {
        Request::post(uri)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let body = format!(r#"{{"email":"api@example.com","password":"{PASSWORD}"}}"#);

    let (status, _, _) = send(&app, json("/api/v1/auth/register", body.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(&app, json("/api/v1/auth/login", body)).await;
    assert_eq!(status, StatusCode::OK);
}

/// The whole feature is off by default, and off means *invisible*: no field,
/// no script, no behaviour change on either form.
#[tokio::test]
async fn without_a_site_key_the_forms_are_exactly_as_they_were() {
    let app = app_without_captcha();

    let (cookies, csrf) = open_form(&app, "/register").await;
    let (status, _, _) = send(
        &app,
        post_form(
            "/register",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, headers, _) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={csrf}&email=a@example.com&password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
}

// --------------------------------------------- the two forms that send mail

/// Both mail forms carry a field, each minted for its own action, and both
/// pages load the loader and the helper.
#[tokio::test]
async fn the_mail_forms_carry_the_site_key_and_the_loader() {
    let (app, _, _) = app_with_mail();

    let (status, _, forgot) = send(&app, get("/forgot")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(forgot.contains(&format!("data-captcha-key=\"{SITE_KEY}\"")));
    assert!(forgot.contains("data-captcha-action=\"forgot\""));
    assert!(forgot.contains("https://www.google.com/recaptcha/api.js?render="));
    assert!(forgot.contains("/assets/captcha.js"));

    // The resend form lives on the confirmation card, which is what a dead
    // link answers with — and `POST /confirm` itself takes no captcha token,
    // because the link it spends came out of an inbox.
    let (cookies, csrf) = open_form(&app, "/login").await;
    let (status, _, invalid) = send(
        &app,
        post_form("/confirm", &cookies, &format!("csrf={csrf}&token=nonsense")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(invalid.contains("This link can't be used"), "{invalid}");
    assert!(invalid.contains(&format!("data-captcha-key=\"{SITE_KEY}\"")));
    assert!(invalid.contains("data-captcha-action=\"resend\""));
    assert!(invalid.contains("/assets/captcha.js"));
}

/// The point of the gate on this form: no token, no address lookup, no mail.
#[tokio::test]
async fn a_reset_request_without_a_token_sends_nothing() {
    let (app, _, mailer) = app_with_mail();
    register_unconfirmed(&app, "known@example.com").await;

    let (cookies, csrf) = open_form(&app, "/forgot").await;
    let (status, headers, html) = send(
        &app,
        post_form(
            "/forgot",
            &cookies,
            &format!("csrf={csrf}&email=known@example.com&captcha_token="),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::LOCATION));
    assert!(html.contains("JavaScript"), "unhelpful message: {html}");
    // Not the "check your inbox" card: nothing was sent, and the answer must
    // not pretend otherwise.
    assert!(!html.contains("Check your inbox"), "{html}");
    // Ready to mint a fresh token — the spent one is never echoed back.
    assert!(html.contains("data-captcha-key"));
    assert!(!html.contains("name=\"captcha_token\" value="));

    settle().await;
    assert_eq!(mailer.sent().len(), 1, "only the registration link");
}

/// A token minted for the sign-in form cannot be spent on the reset form, and
/// the right one goes through.
#[tokio::test]
async fn the_reset_request_needs_its_own_token() {
    let (app, captcha, mailer) = app_with_mail();
    captcha.register(GOOD_LOGIN_TOKEN, "login", 0.9);
    register_unconfirmed(&app, "known@example.com").await;

    let (cookies, csrf) = open_form(&app, "/forgot").await;
    let (_, _, wrong) = send(
        &app,
        post_form(
            "/forgot",
            &cookies,
            &format!("csrf={csrf}&email=known@example.com&captcha_token={GOOD_LOGIN_TOKEN}"),
        ),
    )
    .await;
    assert!(wrong.contains("real person"), "{wrong}");
    settle().await;
    assert_eq!(mailer.sent().len(), 1, "a login token mailed a reset link");

    let (cookies, csrf) = open_form(&app, "/forgot").await;
    let (status, _, right) = send(
        &app,
        post_form(
            "/forgot",
            &cookies,
            &format!("csrf={csrf}&email=known@example.com&captcha_token={GOOD_FORGOT_TOKEN}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(right.contains("Check your inbox"), "{right}");
    wait_for_mail(&mailer, 2).await;
    assert!(mailer.sent()[1].subject.contains("Reset"));
}

/// The same gate on the confirmation resend, which is the other way to make
/// this server mail a stranger.
#[tokio::test]
async fn the_resend_needs_its_own_token() {
    let (app, _, mailer) = app_with_mail();
    let (cookies, card) = register_unconfirmed(&app, "waiting@example.com").await;
    let csrf = csrf_field(&card);

    let (status, _, refused) = send(
        &app,
        post_form(
            "/confirm/resend",
            &cookies,
            &format!("csrf={csrf}&email=waiting@example.com&captcha_token=forged"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(refused.contains("didn't go through"), "{refused}");
    assert!(refused.contains("real person"));
    // The uniform "a new link is on its way" sentence would be a lie here.
    assert!(!refused.contains("on its way"), "{refused}");
    settle().await;
    assert_eq!(mailer.sent().len(), 1, "only the registration link");

    let (status, _, sent) = send(
        &app,
        post_form(
            "/confirm/resend",
            &cookies,
            &format!("csrf={csrf}&email=waiting@example.com&captcha_token={GOOD_RESEND_TOKEN}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(sent.contains("on its way"), "{sent}");
}

/// The widening follows the *form*, not the page: a card whose only form
/// posts a token that came out of an inbox asks for no score and keeps the
/// strict policy.
#[tokio::test]
async fn only_the_cards_that_render_a_captcha_relax_the_csp() {
    let (app, _, _) = app_with_mail();

    let (_, headers, _) = send(&app, get("/forgot")).await;
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP_CAPTCHA);

    for path in ["/reset/some-token", "/confirm/some-token"] {
        let (_, headers, html) = send(&app, get(path)).await;
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CSP,
            "{path} relaxed its CSP"
        );
        assert!(
            !html.contains("data-captcha-key"),
            "captcha field on {path}"
        );
        assert!(!html.contains("google.com"), "google script on {path}");
    }

    // The card that answers a dead confirmation link does render the resend
    // form, so that one does relax.
    let (cookies, csrf) = open_form(&app, "/login").await;
    let (_, headers, _) = send(
        &app,
        post_form("/confirm", &cookies, &format!("csrf={csrf}&token=nonsense")),
    )
    .await;
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP_CAPTCHA);
}

/// With no site key configured the two mail forms are exactly what they were
/// before the gate existed: no field, no script, and a plain submit works.
#[tokio::test]
async fn without_a_site_key_the_mail_forms_are_unchanged() {
    let app = app_without_captcha();

    let (_, headers, html) = send(&app, get("/forgot")).await;
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
    assert!(!html.contains("captcha"), "captcha markup on /forgot");
    assert!(!html.contains("google.com"), "google script on /forgot");

    let (cookies, csrf) = open_form(&app, "/forgot").await;
    let (status, _, sent) = send(
        &app,
        post_form(
            "/forgot",
            &cookies,
            &format!("csrf={csrf}&email=nobody@example.com"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(sent.contains("Check your inbox"), "{sent}");
}
