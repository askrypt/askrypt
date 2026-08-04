//! The Phase 7.1/7.2 gate: the server-rendered website.
//!
//! Runs over `tower`'s `oneshot` against the in-memory fakes — no socket, no
//! SQLite, no browser. What is asserted here is exactly what a browser
//! depends on: status codes, redirect targets, `Set-Cookie` attributes, CSRF
//! rejection, and enough of the markup to know the right template rendered.
//!
//! Note the shared rate-limit bucket: without `ConnectInfo` every request
//! keys the same client, and the auth limiter allows 20 per minute. Each
//! test therefore builds its own `app()`, as the other suites do.

use std::path::Path;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";

fn app() -> Router {
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    router(AppState::in_memory(), &config)
}

/// Sends a request, keeping the headers — cookies and `Location` are half of
/// what these tests are about.
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

/// A form POST as a browser makes it: same-origin, urlencoded, with the
/// cookies the page was rendered with.
fn post_form(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header(header::COOKIE, cookies)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// All `Set-Cookie` values on a response.
fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// The value of one cookie from a response, ignoring the attributes.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    set_cookies(headers).into_iter().find_map(|cookie| {
        let (pair, _) = cookie.split_once("; ")?;
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

/// Folds a response's cookies into a `Cookie` header for the next request,
/// dropping the ones that were just expired.
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

/// A signed-out browser that has loaded `path`: its cookie jar plus the CSRF
/// token from the form on that page. The two belong together — a token from
/// one browser is worthless in another, which is the point of the scheme.
async fn visit(app: &Router, path: &str) -> (String, String) {
    let (status, headers, html) = send(app, get(path)).await;
    assert_eq!(status, StatusCode::OK, "{path}");
    (jar("", &headers), csrf_field(&html))
}

/// Registers through the *website* and returns the resulting cookie jar.
async fn register(app: &Router, email: &str) -> String {
    let (cookies, token) = visit(app, "/register").await;
    let body = format!("csrf={token}&email={email}&password={PASSWORD}");

    let (status, headers, _) = send(app, post_form("/register", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
    jar(&cookies, &headers)
}

// ---------------------------------------------------------------- 7.1

#[tokio::test]
async fn the_landing_page_renders_from_a_template() {
    let (status, headers, html) = send(&app(), get("/")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(html.starts_with("<!doctype html>"), "not a full page");
    assert!(html.contains("/assets/style.css"), "stylesheet not linked");
    assert!(html.contains("/assets/htmx.min.js"), "htmx not linked");
    // The CSP forbids htmx's injected indicator stylesheet.
    assert!(html.contains("includeIndicatorStyles"));
}

#[tokio::test]
async fn the_vendored_assets_are_served_under_assets() {
    let app = app();
    for (path, expected) in [
        ("/assets/style.css", "text/css"),
        ("/assets/htmx.min.js", "javascript"),
    ] {
        let (status, headers, body) = send(&app, get(path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let content_type = headers[header::CONTENT_TYPE].to_str().unwrap().to_string();
        assert!(content_type.contains(expected), "{path} got {content_type}");
        assert!(!body.is_empty(), "{path} is empty");
    }
}

/// No markup may rely on an inline script or style, because the CSP shipped
/// in Phase 5 forbids them and is not going to be loosened.
#[tokio::test]
async fn no_page_carries_an_inline_script_or_style() {
    let app = app();
    for path in ["/", "/login", "/register", "/nope"] {
        let (_, _, html) = send(&app, get(path)).await;
        assert!(!html.contains("<script>"), "inline <script> on {path}");
        assert!(!html.contains("<style"), "inline <style> on {path}");
        assert!(!html.contains("hx-on:"), "hx-on: handler on {path}");
    }
}

// ---------------------------------------------------------------- 7.2

#[tokio::test]
async fn registering_signs_the_browser_in_with_a_hardened_cookie() {
    let app = app();
    let (_, headers, html) = send(&app, get("/register")).await;
    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email=new@example.com&password={PASSWORD}",
        csrf_field(&html)
    );

    let (status, headers, _) = send(&app, post_form("/register", &cookies, &body)).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
    let session = set_cookies(&headers)
        .into_iter()
        .find(|c| c.starts_with("askrypt_session="))
        .expect("no session cookie");
    for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age="] {
        assert!(
            session.contains(attribute),
            "{attribute} missing: {session}"
        );
    }
}

#[tokio::test]
async fn signing_in_again_from_a_fresh_browser_works() {
    let app = app();
    register(&app, "returning@example.com").await;

    let (cookies, token) = visit(&app, "/login").await;
    let body = format!("csrf={token}&email=returning@example.com&password={PASSWORD}");

    let (status, headers, _) = send(&app, post_form("/login", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
    assert!(cookie_value(&headers, "askrypt_session").is_some());
}

#[tokio::test]
async fn a_protected_page_redirects_when_signed_out_and_renders_when_signed_in() {
    let app = app();

    let (status, headers, _) = send(&app, get("/account")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");

    let cookies = register(&app, "protected@example.com").await;
    let (status, headers, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("protected@example.com"), "{html}");
    // The flash set on the register redirect is shown exactly once: the
    // response that shows it also expires its cookie.
    assert!(html.contains("Account created"));
    let cookies = jar(&cookies, &headers);
    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert!(!html.contains("Account created"), "flash was shown twice");
}

#[tokio::test]
async fn a_wrong_password_re_renders_the_form_without_revealing_anything() {
    let app = app();
    register(&app, "known@example.com").await;
    let (cookies, token) = visit(&app, "/login").await;

    let (status, headers, html) = send(
        &app,
        post_form(
            "/login",
            &cookies,
            &format!("csrf={token}&email=known@example.com&password=wrongwrongwrong"),
        ),
    )
    .await;

    // 200, not 4xx: htmx only swaps successful responses, and a refused
    // sign-in is an ordinary outcome of this page.
    assert_eq!(status, StatusCode::OK);
    assert!(cookie_value(&headers, "askrypt_session").is_none());
    assert!(html.contains("invalid email or password"), "{html}");
    // The typed address survives, the password never does.
    assert!(html.contains("value=\"known@example.com\""));
    assert!(!html.contains("wrongwrongwrong"));
}

/// The same rejection an unknown address gets, word for word — the page must
/// not become an account-existence oracle where the API refuses to be one.
#[tokio::test]
async fn an_unknown_address_is_refused_identically_to_a_wrong_password() {
    let app = app();
    register(&app, "known@example.com").await;
    let (cookies, token) = visit(&app, "/login").await;

    let mut bodies = Vec::new();
    for email in ["known@example.com", "stranger@example.com"] {
        let (status, _, html) = send(
            &app,
            post_form(
                "/login",
                &cookies,
                &format!("csrf={token}&email={email}&password=definitelywrong"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        bodies.push(html.replace(email, "EMAIL"));
    }
    assert_eq!(bodies[0], bodies[1]);
}

#[tokio::test]
async fn htmx_gets_the_fragment_and_a_plain_request_gets_the_page() {
    let app = app();
    register(&app, "swap@example.com").await;
    let (cookies, token) = visit(&app, "/login").await;
    let body = format!("csrf={token}&email=swap@example.com&password=stillwrongxx");

    let plain = send(&app, post_form("/login", &cookies, &body)).await.2;
    assert!(plain.starts_with("<!doctype html>"), "expected a full page");

    let mut request = post_form("/login", &cookies, &body);
    request
        .headers_mut()
        .insert("hx-request", "true".parse().unwrap());
    let fragment = send(&app, request).await.2;

    assert!(!fragment.contains("<!doctype"), "fragment was a full page");
    assert!(fragment.trim_start().starts_with("<form"), "{fragment}");
    assert!(fragment.contains("invalid email or password"));
}

// ---------------------------------------------------------------- CSRF

#[tokio::test]
async fn a_post_without_a_csrf_token_is_refused() {
    let app = app();
    let (_, headers, _) = send(&app, get("/register")).await;
    let cookies = jar("", &headers);

    let (status, headers, _) = send(
        &app,
        post_form(
            "/register",
            &cookies,
            &format!("email=nocsrf@example.com&password={PASSWORD}"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&headers, "askrypt_session").is_none());
}

#[tokio::test]
async fn a_post_with_someone_elses_csrf_token_is_refused() {
    let app = app();
    let (_, headers, _) = send(&app, get("/register")).await;
    let cookies = jar("", &headers);
    // A token that is well-formed but not the one in this browser's cookie.
    let forged = "0".repeat(64);

    let (status, _, _) = send(
        &app,
        post_form(
            "/register",
            &cookies,
            &format!("csrf={forged}&email=forged@example.com&password={PASSWORD}"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_post_from_another_origin_is_refused_even_with_a_valid_token() {
    let app = app();
    let (_, headers, html) = send(&app, get("/register")).await;
    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email=crossorigin@example.com&password={PASSWORD}",
        csrf_field(&html)
    );

    let mut request = post_form("/register", &cookies, &body);
    request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let (status, _, _) = send(&app, request).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Bearer requests are not CSRF-able and must not be made to carry a token.
#[tokio::test]
async fn the_json_api_is_untouched_by_the_csrf_layer() {
    let app = app();
    let request = Request::post("/api/v1/auth/register")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"email": "api@example.com", "password": PASSWORD}).to_string(),
        ))
        .unwrap();

    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::CREATED);
}

// ------------------------------------------- one session model, one list

/// The Phase 7.2 gate: a browser login is the same session the API issues,
/// visible in the device list and killable from there.
#[tokio::test]
async fn the_web_session_is_listed_by_the_api_and_revoking_it_signs_the_browser_out() {
    let app = app();
    let cookies = register(&app, "listed@example.com").await;
    let token = cookies
        .split("; ")
        .find_map(|p| p.strip_prefix("askrypt_session="))
        .expect("no session cookie")
        .to_string();

    let request = Request::get("/api/v1/me/sessions")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    let sessions: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sessions.as_array().unwrap().len(), 1);
    assert_eq!(sessions[0]["label"], "Web browser");
    assert_eq!(sessions[0]["current"], true);
    let id = sessions[0]["id"].as_str().unwrap();

    let request = Request::delete(format!("/api/v1/me/sessions/{id}"))
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, headers, _) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
    // The worthless cookie is cleared rather than left to be re-checked.
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|c| c.starts_with("askrypt_session=") && c.contains("Max-Age=0"))
    );
}

#[tokio::test]
async fn signing_out_clears_the_cookie_and_kills_the_session() {
    let app = app();
    let cookies = register(&app, "byebye@example.com").await;
    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;

    let (status, headers, _) = send(
        &app,
        post_form("/logout", &cookies, &format!("csrf={}", csrf_field(&html))),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/");
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|c| c.starts_with("askrypt_session=") && c.contains("Max-Age=0"))
    );

    // The token is gone server-side too, not merely forgotten by the browser.
    let (status, _, _) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn an_already_signed_in_visitor_is_sent_on_from_the_auth_pages() {
    let app = app();
    let cookies = register(&app, "again@example.com").await;

    for path in ["/login", "/register"] {
        let (status, headers, _) = send(&app, get_with_cookies(path, &cookies)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(headers[header::LOCATION], "/account", "{path}");
    }
}

#[tokio::test]
async fn pages_are_never_cached() {
    let app = app();
    let cookies = register(&app, "nocache@example.com").await;

    for (path, jar) in [("/", ""), ("/login", ""), ("/account", cookies.as_str())] {
        let (_, headers, _) = send(&app, get_with_cookies(path, jar)).await;
        assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
    }
}
