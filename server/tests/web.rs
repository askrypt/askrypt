//! The Phase 7.1–7.4 gate: the server-rendered website.
//!
//! Runs over `tower`'s `oneshot` against the in-memory fakes — no socket, no
//! SQLite, no browser. What is asserted here is exactly what a browser
//! depends on: status codes, redirect targets, `Set-Cookie` attributes, CSRF
//! rejection, and enough of the markup to know the right template rendered.
//!
//! Note the shared rate-limit bucket: without `ConnectInfo` every request
//! keys the same client, and the auth limiter allows 20 per minute. Each
//! test therefore builds its own `app()`, as the other suites do.

use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

mod common;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";

fn app() -> Router {
    router(AppState::in_memory(), &common::password_api_config())
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
    field_value(html, "csrf").expect("no csrf field in the form")
}

/// The value of the first hidden/text input named `name`.
fn field_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let rest = &html[start..];
    Some(rest[..rest.find('"')?].to_string())
}

/// The id of the first vault in the table, read out of its rename form's
/// action — the same way a browser would find it.
fn first_vault_id(html: &str) -> String {
    let marker = "action=\"/vaults/";
    let start = html.find(marker).expect("no vault row in the page") + marker.len();
    let rest = &html[start..];
    rest[..rest.find('/').unwrap()].to_string()
}

/// A form POST with an `HX-Request` header, i.e. what htmx sends.
fn post_form_htmx(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    let mut request = post_form(uri, cookies, body);
    request
        .headers_mut()
        .insert("hx-request", "true".parse().unwrap());
    request
}

const BOUNDARY: &str = "askrypttestboundary";

/// A `multipart/form-data` POST as the upload forms make it: the CSRF token
/// first, then the other text fields, then the file.
fn post_multipart(
    uri: &str,
    cookies: &str,
    csrf: &str,
    fields: &[(&str, &str)],
    file: Option<(&str, &[u8])>,
) -> Request<Body> {
    let mut body: Vec<u8> = Vec::new();
    let mut part = |name: &str, value: &[u8], filename: Option<&str>| {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(filename) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    };
    part("csrf", csrf.as_bytes(), None);
    for (name, value) in fields {
        part(name, value.as_bytes(), None);
    }
    if let Some((filename, bytes)) = file {
        part("file", bytes, Some(filename));
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

    Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header(header::COOKIE, cookies)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap()
}

/// The same upload with the headers htmx adds, i.e. what the page really
/// sends when JavaScript is on.
fn post_multipart_htmx(
    uri: &str,
    cookies: &str,
    csrf: &str,
    fields: &[(&str, &str)],
    file: Option<(&str, &[u8])>,
) -> Request<Body> {
    let mut request = post_multipart(uri, cookies, csrf, fields, file);
    let headers = request.headers_mut();
    headers.insert("hx-request", "true".parse().unwrap());
    headers.insert(
        "hx-current-url",
        format!("https://{HOST}/vaults").parse().unwrap(),
    );
    request
}

/// A vault as far as the website is concerned: an archive holding the
/// `askrypt.json` member the upload form checks for. Everything a real vault
/// keeps in there is encrypted and plays no part here, so the marker — which
/// is only there to tell two uploads apart — stands in for all of it.
fn vault_bytes(marker: u8) -> Vec<u8> {
    vault_archive(&format!(r#"{{"version":"0.9","marker":{marker}}}"#), 0)
}

/// The same archive with the two unencrypted stamp fields the server lifts
/// off an upload for the listing's `Saved` column.
fn stamped_vault_bytes(host: &str, saved_at: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "version": "1",
        "params": {
            "kdf": "pbkdf2-sha256",
            "iterations": 600_000,
            "salt": "c2FsdA==",
            "host": host,
            "updated_at": saved_at,
        },
    })
    .to_string();
    vault_archive(&json, 0)
}

/// A vault archive of a given size: `askrypt.json` plus, when `pad` is set, a
/// stored member of that many bytes. Padding *inside* the archive is what
/// keeps a big fixture a readable ZIP — bytes appended after the end record
/// would make it something the upload form refuses for the wrong reason.
fn vault_archive(json: &str, pad: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        zip.start_file("askrypt.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, json.as_bytes()).unwrap();
        if pad > 0 {
            zip.start_file(
                "data",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            std::io::Write::write_all(&mut zip, &vec![b'x'; pad]).unwrap();
        }
        zip.finish().unwrap();
    }
    buf
}

/// A valid vault archive of at least `size` bytes.
fn vault_bytes_of(size: usize) -> Vec<u8> {
    vault_archive(r#"{"version":"0.9"}"#, size)
}

/// A download, kept as bytes. [`send`] renders a body as lossy UTF-8, which
/// is right for every page here and wrong for a vault archive: the deflated
/// bytes are not text, and comparing them through a `String` compares two
/// runs of replacement characters.
async fn download_bytes(app: &Router, uri: &str, cookies: &str) -> Vec<u8> {
    let response = app
        .clone()
        .oneshot(get_with_cookies(uri, cookies))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// Signs in through the browser and returns the jar plus the `/vaults` page.
async fn with_vaults_page(app: &Router, email: &str) -> (String, String) {
    let cookies = register(app, email).await;
    let (status, headers, html) = send(app, get_with_cookies("/vaults", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    (jar(&cookies, &headers), html)
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
        // Cacheable, but never reused without asking: the file changes while
        // its URL does not, and a stale stylesheet is a visible bug.
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{path}");
    }
}

/// No markup may rely on an inline script or style, because the CSP shipped
/// in Phase 5 forbids them and is not going to be loosened.
#[tokio::test]
async fn no_page_carries_an_inline_script_or_style() {
    let app = app();
    let cookies = register(&app, "csp@example.com").await;
    let signed_out = ["/", "/login", "/register", "/nope", "/open"];
    // The first account registered on a server is its administrator, so this
    // jar reaches the Users page too.
    let signed_in = [
        "/account",
        "/vaults",
        "/admin/users",
        "/admin/settings",
        "/open",
    ];
    for (path, jar) in signed_out
        .iter()
        .map(|p| (*p, ""))
        .chain(signed_in.iter().map(|p| (*p, cookies.as_str())))
    {
        let (_, _, html) = send(&app, get_with_cookies(path, jar)).await;
        assert!(!html.contains("<script>"), "inline <script> on {path}");
        assert!(!html.contains("<style"), "inline <style> on {path}");
        assert!(!html.contains("hx-on:"), "hx-on: handler on {path}");
        // htmx evaluates `js:`/`javascript:` expressions, which the CSP
        // forbids just as firmly as an inline handler.
        assert!(!html.contains("\"js:"), "js: expression on {path}");
    }
}

/// The upload route's own body limit sits inside the global one; a file over
/// it has to come back as a page a person can read.
#[tokio::test]
async fn an_oversized_upload_is_refused_with_a_readable_page() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "toobig@example.com").await;
    let huge = vault_bytes_of(11 * 1024 * 1024);

    let (status, _, body) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "huge.askrypt")],
            Some(("huge.askrypt", &huge)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.starts_with("<!doctype html>"), "not an HTML page");
    assert!(body.contains("too large"), "{body}");
    // The JSON envelope belongs to /api/v1 and must not surface on a page.
    assert!(!body.contains("\"error\""), "{body}");
}

/// The same upload over htmx. htmx refuses to swap a 4xx, so the error page
/// above would be received and discarded — the visitor would watch the form
/// do nothing. It has to arrive as a fragment, at a status htmx will swap,
/// pointed at the main region rather than at the form's own `#vault-list`.
#[tokio::test]
async fn an_oversized_upload_over_htmx_comes_back_as_a_swappable_fragment() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "toobig-htmx@example.com").await;
    let huge = vault_bytes_of(11 * 1024 * 1024);

    let (status, headers, body) = send(
        &app,
        post_multipart_htmx(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "huge.askrypt")],
            Some(("huge.askrypt", &huge)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["hx-retarget"], "main");
    assert_eq!(headers["hx-reswap"], "innerHTML");
    assert!(body.contains("too large"), "{body}");
    // A fragment, not a document: swapping a whole page into <main> would
    // nest a second <head> in the one already on screen.
    assert!(!body.contains("<!doctype html>"), "{body}");
    // The link back points at the page the visitor was on, not at whatever
    // the client-supplied header said.
    assert!(body.contains("href=\"/vaults\""), "{body}");
}

/// The free quota is a tenth of the per-file limit, so "too big" in practice
/// means over quota, not over `MAX_VAULT_BYTES`. That refusal answers 507,
/// which is a 5xx and used to be laundered into a "Something went wrong"
/// page — the one the visitor could not see, because htmx dropped it.
#[tokio::test]
async fn an_over_quota_upload_explains_itself_instead_of_failing() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "quota-page@example.com").await;
    // Comfortably over the 1 MiB free quota and comfortably under the 10 MiB
    // per-file limit: the whole band this test exists for.
    let big = vault_bytes_of(3 * 1024 * 1024);

    let (status, _, body) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "big.askrypt")],
            Some(("big.askrypt", &big)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("of storage"), "{body}");
    assert!(!body.contains("Something went wrong"), "{body}");
    // Still the vault page, with the upload form ready for another go.
    assert!(body.contains("id=\"vault-upload\""), "{body}");
}

/// The same refusal over htmx: the listing fragment, carrying the notice,
/// swapped into the slot the form was already aiming at. No retarget here —
/// this is an answer about the visitor's files, not an error page.
#[tokio::test]
async fn an_over_quota_upload_over_htmx_returns_the_listing_with_a_notice() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "quota-htmx@example.com").await;
    let big = vault_bytes_of(3 * 1024 * 1024);

    let (status, headers, body) = send(
        &app,
        post_multipart_htmx(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "big.askrypt")],
            Some(("big.askrypt", &big)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        !headers.contains_key("hx-retarget"),
        "retargeted needlessly"
    );
    assert!(body.starts_with("<section"), "not a fragment: {body}");
    assert!(body.contains("id=\"vault-list\""), "{body}");
    assert!(body.contains("of storage"), "{body}");
    assert!(!body.contains("Something went wrong"), "{body}");
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
    // One element, and the one the form's `hx-target` names: the card, which
    // holds the password form and — where Google sign-in is configured — the
    // hidden form its button submits.
    assert!(
        fragment.trim_start().starts_with("<div id=\"auth-form\""),
        "{fragment}"
    );
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

/// `Origin: null` is an opaque origin — a sandboxed frame, or a post that
/// crossed a redirect. It is also what a browser sends for *any* plain form
/// submission when the page carried `Referrer-Policy: no-referrer`, which is
/// why `hardening::REFERRER_POLICY` doesn't.
#[tokio::test]
async fn a_post_from_an_opaque_origin_is_refused() {
    let app = app();
    let (_, headers, html) = send(&app, get("/register")).await;
    let cookies = jar("", &headers);
    let body = format!(
        "csrf={}&email=opaque@example.com&password={PASSWORD}",
        csrf_field(&html)
    );

    let mut request = post_form("/register", &cookies, &body);
    request
        .headers_mut()
        .insert(header::ORIGIN, "null".parse().unwrap());
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

// ---------------------------------------------------------------- 7.3

/// The Phase 7.3 gate, part one: every Phase 3 capability except deletion
/// (its own test) driven from the browser, end to end.
#[tokio::test]
async fn the_profile_page_can_change_the_email_and_the_password() {
    let app = app();
    let cookies = register(&app, "profile@example.com").await;

    let (status, headers, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("/account/email"), "no email form");
    assert!(html.contains("/account/password"), "no password form");
    assert!(html.contains("Web browser"), "the device list is missing");
    let cookies = jar(&cookies, &headers);
    let token = csrf_field(&html);

    // Email.
    let (status, headers, _) = send(
        &app,
        post_form(
            "/account/email",
            &cookies,
            &format!("csrf={token}&email=moved@example.com"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/account");
    // The redirect carries the flash cookie; a browser sends it back on the
    // GET that follows.
    let cookies = jar(&cookies, &headers);
    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert!(html.contains("moved@example.com"), "{html}");
    assert!(html.contains("email address has been updated"));

    // Password: the wrong current password is refused...
    let body = format!(
        "csrf={token}&current_password=notitnotit&new_password=freshpassword\
         &confirm_password=freshpassword"
    );
    let (status, _, html) = send(&app, post_form("/account/password", &cookies, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("current password is incorrect"), "{html}");

    // ...and so is a mistyped confirmation.
    let body = format!(
        "csrf={token}&current_password={PASSWORD}&new_password=freshpassword\
         &confirm_password=freshpasswerd"
    );
    let (_, _, html) = send(&app, post_form("/account/password", &cookies, &body)).await;
    assert!(html.contains("do not match"), "{html}");

    // The real change goes through, and the new password is the one that works.
    let body = format!(
        "csrf={token}&current_password={PASSWORD}&new_password=freshpassword\
         &confirm_password=freshpassword"
    );
    let (status, _, _) = send(&app, post_form("/account/password", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (fresh, token) = visit(&app, "/login").await;
    let (status, _, _) = send(
        &app,
        post_form(
            "/login",
            &fresh,
            &format!("csrf={token}&email=moved@example.com&password=freshpassword"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the new password should work"
    );
}

/// A password change is how someone reacts to a suspected compromise, so the
/// browser form has to revoke the other devices exactly as the API does.
#[tokio::test]
async fn changing_the_password_in_the_browser_signs_the_other_devices_out() {
    let app = app();
    let cookies = register(&app, "shared@example.com").await;

    let request = Request::post("/api/v1/auth/login")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"email": "shared@example.com", "password": PASSWORD}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    let session: Value = serde_json::from_str(&body).unwrap();
    let device_token = session["token"].as_str().unwrap().to_string();

    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    let body = format!(
        "csrf={}&current_password={PASSWORD}&new_password=brandnewpassword\
         &confirm_password=brandnewpassword",
        csrf_field(&html)
    );
    let (status, _, _) = send(&app, post_form("/account/password", &cookies, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // The app's bearer token is dead; the browser that made the change is not.
    let request = Request::get("/api/v1/me")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {device_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, _) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
}

/// The Phase 7.3 gate, part two: revoking the *current* session from the
/// device list signs this browser out cleanly rather than leaving it holding
/// a dead cookie.
#[tokio::test]
async fn revoking_this_browser_from_the_device_list_signs_it_out() {
    let app = app();
    let cookies = register(&app, "devices@example.com").await;
    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert!(html.contains("this browser"), "{html}");

    // The revoke form's action carries the session's published digest.
    let marker = "action=\"/account/devices/";
    let start = html.find(marker).expect("no revoke form") + marker.len();
    let id = &html[start..][..64];

    let (status, headers, _) = send(
        &app,
        post_form(
            &format!("/account/devices/{id}"),
            &cookies,
            &format!("csrf={}", csrf_field(&html)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/");
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|c| c.starts_with("askrypt_session=") && c.contains("Max-Age=0"))
    );
    let (status, _, _) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the session should be gone");
}

#[tokio::test]
async fn deleting_the_account_needs_the_typed_email_and_takes_the_vaults_with_it() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "doomed@example.com").await;
    let (status, _, _) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "doomed.askrypt")],
            Some(("doomed.askrypt", &vault_bytes(1))),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;
    let token = csrf_field(&html);

    // A confirmation that isn't the address changes nothing.
    let (status, _, html) = send(
        &app,
        post_form(
            "/account/delete",
            &cookies,
            &format!("csrf={token}&confirm=yes"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Type your email address exactly"), "{html}");
    let (status, _, _) = send(&app, get_with_cookies("/account", &cookies)).await;
    assert_eq!(status, StatusCode::OK, "the account should still be there");

    let (status, headers, _) = send(
        &app,
        post_form(
            "/account/delete",
            &cookies,
            &format!("csrf={token}&confirm=doomed@example.com"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/");
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|c| c.starts_with("askrypt_session=") && c.contains("Max-Age=0"))
    );

    // Gone for good: the address is free to register again, which it would
    // not be if the account row had survived.
    let (fresh, token) = visit(&app, "/register").await;
    let (status, _, _) = send(
        &app,
        post_form(
            "/register",
            &fresh,
            &format!("csrf={token}&email=doomed@example.com&password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_refused_profile_form_swaps_back_only_that_section() {
    let app = app();
    let cookies = register(&app, "swapback@example.com").await;
    let (_, _, html) = send(&app, get_with_cookies("/account", &cookies)).await;

    let (status, _, fragment) = send(
        &app,
        post_form_htmx(
            "/account/email",
            &cookies,
            &format!("csrf={}&email=not-an-address", csrf_field(&html)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!fragment.contains("<!doctype"), "fragment was a full page");
    assert!(fragment.trim_start().starts_with("<section"), "{fragment}");
    assert!(fragment.contains("not a valid email address"), "{fragment}");
    // The other sections stayed where they were.
    assert!(!fragment.contains("/account/password"), "{fragment}");
}

// ---------------------------------------------------------------- 7.4

/// The Phase 7.4 gate: upload → list → download (byte-identical) → rename →
/// delete, all from the browser.
#[tokio::test]
async fn a_vault_can_be_uploaded_listed_downloaded_renamed_and_deleted() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "files@example.com").await;
    assert!(html.contains("No vault files yet"), "{html}");
    let token = csrf_field(&html);
    let bytes = vault_bytes(7);

    let (status, headers, _) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &token,
            &[("name", "")],
            Some(("personal.askrypt", &bytes)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/vaults");

    let cookies = jar(&cookies, &headers);
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    // The file's own name is the default, and the size and version show.
    assert!(html.contains("value=\"personal.askrypt\""), "{html}");
    assert!(html.contains("Vault uploaded"));
    assert!(html.contains(&format!("{} B", bytes.len())), "{html}");
    let id = first_vault_id(&html);
    let token = csrf_field(&html);

    // Download: the same bytes back, as a file.
    let (status, headers, _) = send(
        &app,
        get_with_cookies(&format!("/vaults/{id}/download"), &cookies),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"personal.askrypt\""
    );
    let downloaded = download_bytes(&app, &format!("/vaults/{id}/download"), &cookies).await;
    assert_eq!(downloaded, bytes, "bytes changed");

    // Rename.
    let (status, _, _) = send(
        &app,
        post_form(
            &format!("/vaults/{id}/name"),
            &cookies,
            &format!("csrf={token}&name=work.askrypt"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("value=\"work.askrypt\""), "{html}");

    // Delete.
    let (status, _, _) = send(
        &app,
        post_form(
            &format!("/vaults/{id}/delete"),
            &cookies,
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("No vault files yet"), "{html}");
}

/// The desktop app stores a server vault under a bare name, with no
/// extension. Downloading one still has to land a `.askrypt` file in the
/// downloads folder — including the archived generations, whose names carry
/// the stamp between the stem and the extension.
#[tokio::test]
async fn a_vault_stored_without_an_extension_downloads_with_one() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "bare@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            // The name the desktop would have stored it under.
            &[("name", "personal")],
            Some(("personal.askrypt", &vault_bytes(1))),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);
    let token = csrf_field(&html);
    let etag = field_value(&html, "etag").expect("no etag in the replace form");
    assert!(html.contains("value=\"personal\""), "{html}");

    let (status, headers, _) = send(
        &app,
        get_with_cookies(&format!("/vaults/{id}/download"), &cookies),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"personal.askrypt\""
    );

    // Replacing archives the bytes above under the same bare name; the
    // generation's download gets the extension too.
    send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &token,
            &[("etag", &etag)],
            Some(("personal.askrypt", &vault_bytes(2))),
        ),
    )
    .await;
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let marker = format!("/vaults/{id}/versions/");
    let start = html.find(&marker).expect("no archived generation") + marker.len();
    let version_id = &html[start..][..html[start..].find('/').unwrap()];
    let (status, headers, _) = send(
        &app,
        get_with_cookies(
            &format!("/vaults/{id}/versions/{version_id}/download"),
            &cookies,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(disposition.starts_with("attachment; filename=\"personal."));
    assert!(disposition.ends_with(".askrypt\""), "{disposition}");
}

/// Replacing carries the row's ETag, so the Phase 4 `If-Match` path applies:
/// a version that moved on elsewhere is explained, not shown as a raw 412.
#[tokio::test]
async fn replacing_a_vault_that_changed_elsewhere_explains_the_conflict() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "conflict@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "shared.askrypt")],
            Some(("shared.askrypt", &vault_bytes(1))),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);
    let token = csrf_field(&html);
    let stale_etag = field_value(&html, "etag").expect("no etag in the replace form");

    // Another device gets there first, through the API.
    send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &token,
            &[("etag", &stale_etag)],
            Some(("shared.askrypt", &vault_bytes(2))),
        ),
    )
    .await;

    // This page still holds the version from before that.
    let (status, _, html) = send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &token,
            &[("etag", &stale_etag)],
            Some(("shared.askrypt", &vault_bytes(3))),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "a conflict is a page, not a 412");
    assert!(html.contains("changed on another device"), "{html}");
    assert!(!html.contains("412"), "{html}");

    // And the file kept the version that won.
    let bytes = download_bytes(&app, &format!("/vaults/{id}/download"), &cookies).await;
    assert_eq!(bytes, vault_bytes(2));
}

#[tokio::test]
async fn a_file_that_is_not_a_vault_is_refused_in_plain_words() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "notazip@example.com").await;

    let (status, _, html) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "notes.txt")],
            Some(("notes.txt", b"just some text")),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("is not an Askrypt vault"), "{html}");
    assert!(!html.contains("invalid_vault_file"), "raw API code leaked");
    assert!(html.starts_with("<!doctype html>"), "expected a full page");
    assert!(html.contains("No vault files yet"), "it was stored anyway");
}

/// The other half of the same gate: the name promises a vault and the bytes
/// are an ordinary archive. The API stops at the ZIP magic — which this file
/// has — so a page upload has to look further, or the account collects files
/// no app can open.
#[tokio::test]
async fn an_archive_without_the_vault_entry_is_refused_too() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "notavault@example.com").await;
    let mut not_a_vault = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut not_a_vault));
        zip.start_file("holiday.jpg", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, b"not a vault").unwrap();
        zip.finish().unwrap();
    }

    let (status, _, html) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[],
            Some(("photos.askrypt", &not_a_vault)),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("askrypt.json"), "{html}");
    assert!(html.contains("No vault files yet"), "it was stored anyway");
}

/// Replacing takes a file off the disk the same way uploading does, so it is
/// gated the same way — and a refusal must leave the vault it was aimed at
/// exactly as it was.
#[tokio::test]
async fn replacing_a_vault_with_something_that_is_not_one_is_refused() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "replace-junk@example.com").await;
    let token = csrf_field(&html);
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &token,
            &[],
            Some(("personal.askrypt", &vault_bytes(1))),
        ),
    )
    .await;
    // A plain upload answers with a redirect, so the row comes off the page.
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);

    let (status, _, page) = send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &csrf_field(&html),
            &[("etag", &field_value(&html, "etag").unwrap())],
            Some(("notes.txt", b"just some text")),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("is not an Askrypt vault"), "{page}");
    let bytes = download_bytes(&app, &format!("/vaults/{id}/download"), &cookies).await;
    assert_eq!(bytes, vault_bytes(1), "the stored file was touched");
}

/// The history disclosure a row grows once it has been replaced: read a
/// version out of the page, fetch those bytes, and put them back.
#[tokio::test]
async fn the_file_manager_can_download_and_restore_an_earlier_version() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "history@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "notes.askrypt")],
            Some(("notes.askrypt", &vault_bytes(1))),
        ),
    )
    .await;

    // A file that was never replaced says so instead of showing an empty list.
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);
    assert!(html.contains("No earlier versions yet"), "{html}");

    let (status, _, html) = send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &csrf_field(&html),
            &[("etag", &field_value(&html, "etag").unwrap())],
            Some(("notes.askrypt", &vault_bytes(2))),
        ),
    )
    .await;
    // A plain (non-htmx) form post redirects back to the listing.
    assert_eq!(status, StatusCode::SEE_OTHER, "{html}");

    // The replaced copy is now offered in the row's history.
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let marker = format!("/vaults/{id}/versions/");
    let start = html.find(&marker).expect("no history entry in the page") + marker.len();
    let version_id = html[start..][..html[start..].find('/').unwrap()].to_string();

    // Its bytes are the ones the replace displaced, under a dated name.
    let uri = format!("/vaults/{id}/versions/{version_id}/download");
    let (status, headers, _) = send(&app, get_with_cookies(&uri, &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(download_bytes(&app, &uri, &cookies).await, vault_bytes(1));
    let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(disposition.contains("notes."), "{disposition}");
    assert!(disposition.ends_with(".askrypt\""), "{disposition}");

    // Restoring answers with the refreshed listing and swaps the file back.
    let (status, _, html) = send(
        &app,
        post_form_htmx(
            &format!("/vaults/{id}/versions/{version_id}/restore"),
            &cookies,
            &format!(
                "csrf={}&etag={}",
                csrf_field(&html),
                field_value(&html, "etag").unwrap()
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("Earlier version restored"), "{html}");
    let bytes = download_bytes(&app, &format!("/vaults/{id}/download"), &cookies).await;
    assert_eq!(bytes, vault_bytes(1));
}

/// The listing tells the visitor where and when a file was saved, taken from
/// the vault's own unencrypted stamp — the point being that several devices
/// write to one account and the table has to say which one wrote last.
#[tokio::test]
async fn the_listing_shows_the_device_and_time_a_file_records() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "stamped@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "stamped.askrypt")],
            Some((
                "stamped.askrypt",
                &stamped_vault_bytes("lenovo-x1", "2026-08-08T10:15:30Z"),
            )),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);
    assert!(html.contains("lenovo-x1 · 2026-08-08 10:15 UTC"), "{html}");

    // A save from a second device takes over the row, and the copy it
    // replaced keeps its own stamp in the history.
    let (status, _, html) = send(
        &app,
        post_multipart(
            &format!("/vaults/{id}/replace"),
            &cookies,
            &csrf_field(&html),
            &[("etag", &field_value(&html, "etag").unwrap())],
            Some((
                "stamped.askrypt",
                &stamped_vault_bytes("pixel-8", "2026-08-08T18:40:00Z"),
            )),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{html}");

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("pixel-8 · 2026-08-08 18:40 UTC"), "{html}");
    assert!(
        html.contains("Saved lenovo-x1 · 2026-08-08 10:15 UTC"),
        "the replaced generation should keep its own stamp: {html}"
    );

    // A file with no stamp — every other upload in this suite — says so
    // rather than showing a blank cell.
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "plain.askrypt")],
            Some(("plain.askrypt", &vault_bytes(1))),
        ),
    )
    .await;
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("Not recorded"), "{html}");
}

/// The host name is text another machine wrote, and it lands in a table
/// cell: it must be escaped like any other untrusted string.
#[tokio::test]
async fn a_host_name_from_a_file_cannot_inject_markup() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "xss@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "evil.askrypt")],
            Some((
                "evil.askrypt",
                &stamped_vault_bytes("<script>alert(1)</script>", "2026-08-08T10:15:30Z"),
            )),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(html.contains("&#60;script&#62;alert(1)"), "{html}");
}

/// The listing shows what is left of the quota; the count limit and the byte
/// quota themselves are the API suite's gate. A fresh account is on the
/// standard tier, so the meter reads against that allowance.
#[tokio::test]
async fn the_listing_shows_quota_usage() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "usage@example.com").await;
    assert!(html.contains("0 B of 1.0 MB"), "{html}");
    assert!(html.contains("0 of 100 files"), "{html}");

    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "one.askrypt")],
            Some(("one.askrypt", &vault_bytes(1))),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("1 of 100 files"), "{html}");
}

/// The table is ordered by when the server last stored each file, newest
/// first — the upload order reversed, which here is neither the name order
/// nor its reverse.
#[tokio::test]
async fn the_listing_shows_the_most_recently_updated_file_first() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "recency@example.com").await;
    let token = csrf_field(&html);

    for (marker, name) in [
        (1, "gamma.askrypt"),
        (2, "alpha.askrypt"),
        (3, "beta.askrypt"),
    ] {
        send(
            &app,
            post_multipart(
                "/vaults",
                &cookies,
                &token,
                &[("name", name)],
                Some((name, &vault_bytes(marker))),
            ),
        )
        .await;
    }

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let at = |name: &str| html.find(name).unwrap_or_else(|| panic!("{name} missing"));
    assert!(at("beta.askrypt") < at("alpha.askrypt"), "{html}");
    assert!(at("alpha.askrypt") < at("gamma.askrypt"), "{html}");
}

/// An upload that skips the token is refused, and so is a `multipart` body
/// that puts the token after the file — the check has to happen before the
/// bytes are taken.
#[tokio::test]
async fn a_multipart_upload_without_a_valid_csrf_token_is_refused() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "forged@example.com").await;
    let token = csrf_field(&html);

    for bad_token in ["", &"0".repeat(64)] {
        let (status, _, _) = send(
            &app,
            post_multipart(
                "/vaults",
                &cookies,
                bad_token,
                &[("name", "x.askrypt")],
                Some(("x.askrypt", &vault_bytes(1))),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "token {bad_token:?}");
    }

    let mut request = post_multipart(
        "/vaults",
        &cookies,
        &token,
        &[("name", "x.askrypt")],
        Some(("x.askrypt", &vault_bytes(1))),
    );
    request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    assert!(html.contains("No vault files yet"), "nothing may be stored");
}

#[tokio::test]
async fn the_vault_pages_need_a_session() {
    let app = app();
    for path in [
        "/vaults",
        "/vaults/00000000-0000-0000-0000-000000000000/download",
    ] {
        let (status, headers, _) = send(&app, get(path)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(headers[header::LOCATION], "/login", "{path}");
    }
}

/// One account may never see another's files, whichever door it comes
/// through.
#[tokio::test]
async fn vaults_are_invisible_to_another_account() {
    let app = app();
    let (owner, html) = with_vaults_page(&app, "owner@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &owner,
            &csrf_field(&html),
            &[("name", "private.askrypt")],
            Some(("private.askrypt", &vault_bytes(9))),
        ),
    )
    .await;
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &owner)).await;
    let id = first_vault_id(&html);

    let (stranger, html) = with_vaults_page(&app, "stranger@example.com").await;
    assert!(html.contains("No vault files yet"), "{html}");

    let (status, _, _) = send(
        &app,
        get_with_cookies(&format!("/vaults/{id}/download"), &stranger),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &app,
        post_form(
            &format!("/vaults/{id}/delete"),
            &stranger,
            &format!("csrf={}", csrf_field(&html)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a 404 renders as a page here");
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &owner)).await;
    assert!(html.contains("private.askrypt"), "the file must survive");
}

#[tokio::test]
async fn pages_are_never_cached() {
    let app = app();
    let cookies = register(&app, "nocache@example.com").await;

    for (path, jar) in [
        ("/", ""),
        ("/login", ""),
        ("/open", ""),
        ("/account", cookies.as_str()),
    ] {
        let (_, headers, _) = send(&app, get_with_cookies(path, jar)).await;
        assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
    }
}

// ---------------------------------------------------------------- /open

/// The one page on the site that decrypts. What the server owes it is a
/// picker, the two modules, and no part of a vault's contents — it has none.

#[tokio::test]
async fn the_viewer_serves_a_signed_out_visitor() {
    let (status, _, html) = send(&app(), get("/open")).await;

    assert_eq!(status, StatusCode::OK);
    // The whole point of serving it signed-out: a file from the device needs
    // no account.
    assert!(html.contains(r#"id="open-file""#), "no file input");
    assert!(
        !html.contains(r#"id="open-vault-list""#),
        "listed vaults for nobody"
    );
    assert!(html.contains("/login"), "no way to sign in offered");
    // The entry point, and as a module — a classic script would not resolve the
    // `import`s of vault-format.js and vault-smartlock.js.
    assert!(html.contains(r#"<script type="module" src="/assets/vault-open.js">"#));
    // The page needs JavaScript, which no other page on the site does, so it
    // has to say so to a visitor who has it switched off.
    assert!(html.contains("<noscript>"));
}

#[tokio::test]
async fn the_viewer_lists_the_account_s_vaults_with_their_etags() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "viewer@example.com").await;
    let (status, _, _) = send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "phone.askrypt")],
            Some(("phone.askrypt", &vault_bytes(7))),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _, html) = send(&app, get_with_cookies("/open", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"data-vault-name="phone.askrypt""#),
        "row missing"
    );
    // The ETag is what the save sends as `If-Match`; without it on the row the
    // page could only overwrite blindly.
    assert!(html.contains(r#"data-vault-etag=""#), "no ETag on the row");
    assert!(html.contains(r#"data-vault-id=""#), "no id on the row");
    // The CSRF token the save posts with.
    assert!(
        html.contains(r#"id="open-csrf""#),
        "no CSRF token for the save"
    );
}

#[tokio::test]
async fn a_new_vault_can_be_started_with_or_without_an_account() {
    let app = app();

    // Creating one needs no account at all: the questions, the answers and the
    // key never leave the page, and the result is a file to download.
    let (_, _, html) = send(&app, get("/open")).await;
    assert!(html.contains(r#"id="open-new""#), "no way to start one");
    assert!(html.contains(r#"id="open-create-form""#), "no create form");
    // The rows are built by the controller, so the form ships with the
    // container and nothing else — a fixed pair of fields here would be a
    // second place the count of questions is decided.
    assert!(html.contains(r#"id="open-create-questions""#));

    // Signed in, the same form is offered, and the token the upload posts with
    // is on the page — saving a created vault to the account is `POST /vaults`,
    // the file manager's own route.
    let cookies = register(&app, "starter@example.com").await;
    let (status, _, html) = send(&app, get_with_cookies("/open", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"id="open-create-form""#));
    assert!(
        html.contains(r#"id="open-csrf""#),
        "no CSRF token for the save"
    );
}

#[tokio::test]
async fn the_viewer_ships_the_smart_lock_controls() {
    let app = app();

    // Smart Lock is entirely in the page — the server has no route for it and
    // never sees the bundle — so what it owes is the markup the controller
    // drives, on a signed-out visitor's page as much as an account holder's.
    for html in [send(&app, get("/open")).await.2, {
        let cookies = register(&app, "smartlock@example.com").await;
        send(&app, get_with_cookies("/open", &cookies)).await.2
    }] {
        assert!(html.contains(r#"id="open-smart-arm""#), "no way to arm it");
        assert!(html.contains(r#"id="open-smart-form""#), "no unlock form");
        assert!(
            html.contains(r#"id="open-smart-question""#),
            "no key question"
        );
        assert!(
            html.contains(r#"id="open-smart-full""#),
            "no way out to a full lock"
        );
        // The armed card starts hidden like every other step: the controller
        // reveals one at a time, and a visible one here would be a card with
        // no bundle behind it.
        assert!(
            html.contains(r#"<section class="card" id="open-smart" hidden>"#),
            "the armed card is not hidden"
        );
    }
}

#[tokio::test]
async fn the_viewer_ships_the_password_generator() {
    let app = app();

    // Like Smart Lock, the generator is entirely in the page — the server has
    // no route for it and never sees a password — so the markup is all it
    // owes, and it owes it to a signed-out visitor too: creating a vault and
    // filling it in needs no account.
    for html in [send(&app, get("/open")).await.2, {
        let cookies = register(&app, "passgen@example.com").await;
        send(&app, get_with_cookies("/open", &cookies)).await.2
    }] {
        // The way in: beside Show and Copy on the Secret field, which is the
        // one place a generated password is wanted.
        assert!(html.contains(r#"id="entry-generate""#), "no way to open it");
        // The panel starts hidden, like every other step's markup.
        assert!(
            html.contains(r#"<div class="passgen" id="entry-passgen" hidden>"#),
            "the generator panel is not hidden"
        );
        for id in [
            "passgen-value",
            "passgen-length",
            "passgen-upper",
            "passgen-lower",
            "passgen-numbers",
            "passgen-symbols",
            "passgen-generate",
            "passgen-copy",
            "passgen-use",
            "passgen-close",
        ] {
            assert!(html.contains(&format!(r#"id="{id}""#)), "no {id}");
        }
        // The panel lives inside the entry form, so a button that defaults to
        // `submit` would apply the entry instead of generating a password.
        // The panel nests a div of its own, so it is bounded by what follows
        // it in the form rather than by the first closing tag.
        let panel = html
            .split_once(r#"id="entry-passgen""#)
            .and_then(|(_, rest)| rest.split_once(r#"<label for="entry-url">"#))
            .expect("the panel is not in the page")
            .0;
        assert_eq!(
            panel.matches("<button").count(),
            panel.matches(r#"type="button""#).count(),
            "a generator button submits the entry form: {panel}"
        );
    }
}

#[tokio::test]
async fn an_empty_account_is_not_the_same_as_a_signed_out_one() {
    let app = app();
    let cookies = register(&app, "empty@example.com").await;
    let (_, _, html) = send(&app, get_with_cookies("/open", &cookies)).await;

    // The list is rendered and says it is empty, rather than being absent —
    // which is what a signed-out visitor gets, and means something else.
    assert!(html.contains(r#"id="open-vault-list""#));
    assert!(html.contains("No vault files on this account yet"));
}

#[tokio::test]
async fn the_picker_can_be_re_read_on_its_own() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "refresh@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "one.askrypt")],
            Some(("one.askrypt", &vault_bytes(1))),
        ),
    )
    .await;

    // A fragment, not a page: this is how the viewer adopts the fresh ETag
    // after a save without reloading and losing the unlocked vault.
    let (status, _, fragment) = send(&app, get_with_cookies("/open/vaults", &cookies)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        fragment.starts_with(r#"<div id="open-vault-list">"#),
        "not a fragment"
    );
    assert!(
        !fragment.contains("<!doctype html>"),
        "a whole page came back"
    );
    assert!(fragment.contains(r#"data-vault-name="one.askrypt""#));
}

#[tokio::test]
async fn the_picker_fragment_is_not_public() {
    let (status, headers, _) = send(&app(), get("/open/vaults")).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
}

#[tokio::test]
async fn the_file_manager_links_each_row_to_the_viewer() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "deeplink@example.com").await;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", "linked.askrypt")],
            Some(("linked.askrypt", &vault_bytes(3))),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/vaults", &cookies)).await;
    let id = first_vault_id(&html);
    assert!(
        html.contains(&format!(r#"href="/open?vault={id}""#)),
        "no deep link from the row to the viewer"
    );
}

#[tokio::test]
async fn a_vault_name_out_of_the_store_cannot_inject_markup() {
    let app = app();
    let (cookies, html) = with_vaults_page(&app, "escape@example.com").await;
    // The name is stored user text and lands in a `data-` attribute the
    // controller reads, so the escaping matters twice over.
    let hostile = r#""><script>x</script>.askrypt"#;
    send(
        &app,
        post_multipart(
            "/vaults",
            &cookies,
            &csrf_field(&html),
            &[("name", hostile)],
            Some(("ok.askrypt", &vault_bytes(4))),
        ),
    )
    .await;

    let (_, _, html) = send(&app, get_with_cookies("/open", &cookies)).await;
    assert!(
        !html.contains("<script>x</script>"),
        "name rendered as markup"
    );
}
