//! The Phase 8 gate: roles, the first-account rule, and the Users page.
//!
//! Driven through the website exactly as a browser drives it — cookies, CSRF
//! tokens read out of the rendered forms, plain POSTs and htmx ones — because
//! the administrative surface is HTML only. The one place this reaches for
//! the JSON API is to prove that a suspension blocks a *fresh* login, not
//! only an existing session.
//!
//! Integration tests are separate binaries and cannot share `web.rs`'s
//! helpers, so the handful this needs are repeated here.

use std::path::Path;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

const HOST: &str = "askrypt.test";
const PASSWORD: &str = "hunter2hunter2";
const USERS: &str = "/admin/users";

fn app() -> Router {
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    router(AppState::in_memory(), &config)
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    jar(&cookies, &headers)
}

/// The Users page as the administrator sees it, plus a refreshed jar and the
/// CSRF token its forms carry.
async fn users_page(app: &Router, cookies: &str) -> (String, String, String) {
    let (status, headers, html) = send(app, get_with_cookies(USERS, cookies)).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    let cookies = jar(cookies, &headers);
    let token = csrf_field(&html);
    (cookies, token, html)
}

/// The account id of the row for `email`, read out of one of its action
/// forms — the same way a browser would find it.
fn row_id(html: &str, email: &str) -> String {
    let cell = html
        .find(email)
        .unwrap_or_else(|| panic!("no row for {email} in the page"));
    let marker = "action=\"/admin/users/";
    let start = html[cell..]
        .find(marker)
        .unwrap_or_else(|| panic!("no action form in the row for {email}"))
        + marker.len()
        + cell;
    let rest = &html[start..];
    rest[..rest.find('/').unwrap()].to_string()
}

/// A JSON login, to prove a suspension blocks a *fresh* sign-in and not only
/// the session it revoked.
async fn api_login(app: &Router, email: &str) -> StatusCode {
    let request = Request::post("/api/v1/auth/login")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"email": email, "password": PASSWORD}).to_string(),
        ))
        .unwrap();
    send(app, request).await.0
}

// ------------------------------------------------------- the ADMIN role

#[tokio::test]
async fn the_first_registered_account_is_the_administrator() {
    let app = app();
    let admin = register(&app, "first@example.com").await;
    let plain = register(&app, "second@example.com").await;

    // The nav advertises the page to one of them and not the other.
    let (_, _, html) = send(&app, get_with_cookies("/account", &admin)).await;
    assert!(html.contains(USERS), "the admin has no Users link: {html}");
    let (_, _, html) = send(&app, get_with_cookies("/account", &plain)).await;
    assert!(!html.contains(USERS), "a plain user was offered the link");

    // And the page itself agrees, which is the part that matters.
    let (status, _, _) = send(&app, get_with_cookies(USERS, &admin)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_signed_in_non_admin_is_refused_rather_than_redirected() {
    let app = app();
    register(&app, "first@example.com").await;
    let plain = register(&app, "second@example.com").await;

    let (status, _, html) = send(&app, get_with_cookies(USERS, &plain)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("administrators"), "{html}");
    // Not the list: a refusal must not leak the account table.
    assert!(!html.contains("first@example.com"), "{html}");
}

#[tokio::test]
async fn a_signed_out_visitor_is_sent_to_the_sign_in_page() {
    let app = app();
    register(&app, "first@example.com").await;

    let (status, headers, _) = send(&app, get(USERS)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
}

// ------------------------------------------------------------ suspension

#[tokio::test]
async fn suspending_an_account_signs_it_out_and_blocks_new_logins() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    let victim = register(&app, "victim@example.com").await;
    assert_eq!(api_login(&app, "victim@example.com").await, StatusCode::OK);

    let (admin, token, html) = users_page(&app, &admin).await;
    let id = row_id(&html, "victim@example.com");
    let (status, headers, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{id}/ban"),
            &admin,
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], USERS);

    // The session it held is gone...
    let (status, headers, _) = send(&app, get_with_cookies("/account", &victim)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/login");
    // ...and the correct password no longer opens a new one.
    assert_eq!(
        api_login(&app, "victim@example.com").await,
        StatusCode::FORBIDDEN
    );

    // The table says so, and lifting it restores both.
    let (admin, token, html) = users_page(&app, &admin).await;
    assert!(html.contains("Suspended"), "{html}");
    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{id}/unban"),
            &admin,
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(api_login(&app, "victim@example.com").await, StatusCode::OK);
}

// -------------------------------------------------------------- guardrails

#[tokio::test]
async fn an_administrator_cannot_act_on_their_own_row() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    register(&app, "other@example.com").await;

    let (admin, token, html) = users_page(&app, &admin).await;
    // The page does not even offer it.
    assert!(html.contains("<span class=\"tag\">you</span>"), "{html}");
    assert!(html.contains("account page"), "{html}");

    // Forging the request anyway is refused. The id comes from the *other*
    // row's form; the admin's own row has none, so it is read from the API.
    let admin_id = own_account_id(&app, &admin).await;
    let (status, _, html) = send(
        &app,
        post_form_htmx(
            &format!("{USERS}/{admin_id}/ban"),
            &admin,
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("your own account"), "{html}");
}

/// Promotion and demotion end to end.
///
/// Note what is *not* asserted here: the `last_admin` guard. Through the
/// website it is unreachable, because the only account that can act on the
/// sole administrator is that administrator, and the self-guard fires first.
/// It is defense in depth for the CLI and for future callers, and
/// `src/admin.rs`'s unit tests exercise it directly.
#[tokio::test]
async fn admin_rights_can_be_granted_and_taken_away() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    let second = register(&app, "second@example.com").await;
    let admin_id = own_account_id(&app, &admin).await;

    // `second` is promoted, then does the refusing — so it is the last-admin
    // rule under test, not the self-guard.
    let (admin, token, html) = users_page(&app, &admin).await;
    let second_id = row_id(&html, "second@example.com");
    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{second_id}/role"),
            &admin,
            &format!("csrf={token}&action=grant"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Two administrators now, so demoting the first is allowed...
    let (second, token, _) = users_page(&app, &second).await;
    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{admin_id}/role"),
            &second,
            &format!("csrf={token}&action=revoke"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // ...and the demotion is real: the first admin can no longer reach the
    // page at all, and the nav stops offering it.
    let (status, _, _) = send(&app, get_with_cookies(USERS, &admin)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, _, html) = send(&app, get_with_cookies("/account", &admin)).await;
    assert!(
        !html.contains(USERS),
        "a demoted admin kept the link: {html}"
    );

    // `second` now holds the role and the page.
    let (_, _, html) = users_page(&app, &second).await;
    assert!(html.contains("second@example.com"), "{html}");
}

/// The markup of one account's row, from its email cell to the end of the
/// row — enough to tell one account's badges and buttons from another's.
fn row(html: &str, email: &str) -> String {
    let start = html
        .find(email)
        .unwrap_or_else(|| panic!("no row for {email} in the page"));
    let rest = &html[start..];
    rest[..rest.find("</tr>").expect("unterminated row")].to_string()
}

/// The paid storage tier is the second role the page manages, so the toggle
/// has to name it: the same route, the same CSRF door, a different `role`.
#[tokio::test]
async fn the_paid_storage_tier_can_be_granted_and_taken_away() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    register(&app, "second@example.com").await;

    let (admin, token, html) = users_page(&app, &admin).await;
    let second_id = row_id(&html, "second@example.com");
    assert!(
        !row(&html, "second@example.com").contains(">paid</span>"),
        "a new account must not start on the paid tier: {html}"
    );

    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{second_id}/role"),
            &admin,
            &format!("csrf={token}&role=PAYMENT_USER&action=grant"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (admin, token, html) = users_page(&app, &admin).await;
    let paid = row(&html, "second@example.com");
    assert!(paid.contains(">paid</span>"), "{html}");
    // The tier says nothing about administrative access.
    assert!(!paid.contains(">admin</span>"), "{html}");
    assert!(paid.contains("Remove paid tier"), "{html}");

    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{second_id}/role"),
            &admin,
            &format!("csrf={token}&role=PAYMENT_USER&action=revoke"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, _, html) = users_page(&app, &admin).await;
    assert!(
        !row(&html, "second@example.com").contains(">paid</span>"),
        "{html}"
    );
}

/// A hand-made POST cannot name a role the page does not offer. It is
/// refused with a readable notice rather than reaching the store, which
/// would answer an unknown name with a misleading 404.
#[tokio::test]
async fn an_unknown_role_is_refused_rather_than_granted() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    register(&app, "second@example.com").await;

    let (admin, token, html) = users_page(&app, &admin).await;
    let second_id = row_id(&html, "second@example.com");
    let (status, _, body) = send(
        &app,
        post_form(
            &format!("{USERS}/{second_id}/role"),
            &admin,
            &format!("csrf={token}&role=SUPERUSER&action=grant"),
        ),
    )
    .await;
    // Not a redirect: the refusal is worded above the table it re-renders.
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("not a role this page can grant"), "{body}");

    let (_, _, html) = users_page(&app, &admin).await;
    let untouched = row(&html, "second@example.com");
    assert!(!untouched.contains(">paid</span>"), "{html}");
    assert!(!untouched.contains(">admin</span>"), "{html}");
}

/// The signed-in account's own id, via the JSON profile — the Users page
/// offers no *destructive* form on the caller's own row to read it from, and
/// its paid-tier form is not one this helper should depend on.
async fn own_account_id(app: &Router, cookies: &str) -> String {
    let token = cookies
        .split("; ")
        .find_map(|p| p.strip_prefix("askrypt_session="))
        .expect("no session cookie");
    let request = Request::get("/api/v1/me")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let profile: serde_json::Value = serde_json::from_str(&body).unwrap();
    profile["id"].as_str().unwrap().to_string()
}

// ------------------------------------------------------------- deletion

#[tokio::test]
async fn deleting_a_user_needs_their_typed_email_and_takes_their_vaults() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    let victim = register(&app, "victim@example.com").await;

    // Give the victim something to lose.
    let (status, _, _) = send(
        &app,
        upload(&victim, &vaults_csrf(&app, &victim).await, "doomed.askrypt"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (admin, token, html) = users_page(&app, &admin).await;
    let id = row_id(&html, "victim@example.com");

    // A confirmation that isn't the address changes nothing.
    let (status, _, html) = send(
        &app,
        post_form_htmx(
            &format!("{USERS}/{id}/delete"),
            &admin,
            &format!("csrf={token}&confirm=yes"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("email address exactly"), "{html}");
    assert!(
        html.contains("victim@example.com"),
        "the row is still there"
    );

    let (status, _, _) = send(
        &app,
        post_form(
            &format!("{USERS}/{id}/delete"),
            &admin,
            &format!("csrf={token}&confirm=victim@example.com"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Gone from the table, gone from the store: the address is free again,
    // and the new account holds none of the old one's files.
    let (_, _, html) = users_page(&app, &admin).await;
    assert!(!html.contains("victim@example.com"), "{html}");
    let reborn = register(&app, "victim@example.com").await;
    let (_, _, html) = send(&app, get_with_cookies("/vaults", &reborn)).await;
    assert!(!html.contains("doomed.askrypt"), "{html}");
}

// ------------------------------------------------------------- plumbing

#[tokio::test]
async fn a_ban_without_a_valid_csrf_token_is_refused() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    register(&app, "victim@example.com").await;
    let (admin, _, html) = users_page(&app, &admin).await;
    let id = row_id(&html, "victim@example.com");
    let route = format!("{USERS}/{id}/ban");

    for body in [String::new(), format!("csrf={}", "0".repeat(64))] {
        let (status, _, _) = send(&app, post_form(&route, &admin, &body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "accepted {body:?}");
    }

    // A good token from a foreign origin is refused too.
    let (admin, token, _) = users_page(&app, &admin).await;
    let mut request = post_form(&route, &admin, &format!("csrf={token}"));
    request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_htmx_action_swaps_back_the_list_and_not_a_whole_page() {
    let app = app();
    let admin = register(&app, "admin@example.com").await;
    register(&app, "victim@example.com").await;
    let (admin, token, html) = users_page(&app, &admin).await;
    let id = row_id(&html, "victim@example.com");

    let (status, _, fragment) = send(
        &app,
        post_form_htmx(
            &format!("{USERS}/{id}/ban"),
            &admin,
            &format!("csrf={token}"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!fragment.contains("<!doctype"), "fragment was a full page");
    assert!(fragment.trim_start().starts_with("<section"), "{fragment}");
    assert!(fragment.contains("id=\"user-list\""), "{fragment}");
    assert!(fragment.contains("Suspended"), "{fragment}");
    // A fragment swap never renders the layout, so the flash cookie would go
    // unread: the confirmation has to travel in the fragment itself.
    assert!(
        fragment.contains("signed out everywhere"),
        "no confirmation in the swapped fragment: {fragment}"
    );
}

// --------------------------------------------------- multipart upload glue

const BOUNDARY: &str = "askrypttestboundary";

async fn vaults_csrf(app: &Router, cookies: &str) -> String {
    let (status, _, html) = send(app, get_with_cookies("/vaults", cookies)).await;
    assert_eq!(status, StatusCode::OK);
    csrf_field(&html)
}

/// A vault as the upload form checks for one: an archive with the
/// `askrypt.json` member in it. Its contents are none of the server's
/// business, so there is nothing else in here.
fn vault_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        zip.start_file("askrypt.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, br#"{"version":"0.9"}"#).unwrap();
        zip.finish().unwrap();
    }
    buf
}

fn upload(cookies: &str, csrf: &str, name: &str) -> Request<Body> {
    let mut body: Vec<u8> = Vec::new();
    let mut part = |field: &str, value: &[u8], filename: Option<&str>| {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(filename) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{field}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    };
    // The CSRF part has to come first: it is verified before the file is
    // buffered.
    part("csrf", csrf.as_bytes(), None);
    part("name", name.as_bytes(), None);
    part("file", &vault_bytes(), Some(name));
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

    Request::post("/vaults")
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
