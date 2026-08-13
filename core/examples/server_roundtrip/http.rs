//! A thin HTTP client for the endpoints `ServerClient` has no method for.
//!
//! `ServerClient` covers sign-in and the vault blob routes, and where it does
//! the checks use it — it is the client half under test. Everything else the
//! server exposes (register, the profile tree, version history, the whole
//! website, the administrator's pages) has no core API by design, so this
//! module talks to it directly.
//!
//! Two construction details are load-bearing:
//!
//! - **Redirects are not followed** (`max_redirects(0)`). Status codes are the
//!   signal this tool asserts on, and on the website a successful mutation is a
//!   **303** while a *refused* one re-renders at **200** — see
//!   `web::auth::login_submit` against `web::auth::rejected`, and
//!   `web::admin::finish`. Following the redirect would erase the distinction.
//! - **`HX-Request` is never sent.** `web::htmx_error_fragment` rewrites 4xx
//!   into 200 for htmx clients so the browser can see the error; the no-JS path
//!   keeps the real status, and that is the one worth asserting on.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use ureq::Agent;

/// Generous: the vault routes move up to 10 MiB and a debug-built server
/// hashes passwords with argon2 on the request path.
const TIMEOUT: Duration = Duration::from_secs(60);

/// How many times a 429 is waited out before the check is failed.
///
/// The website and the API share a 20/minute bucket for sensitive actions, and
/// the admin group alone posts more than that — from one address, since every
/// identity in the run comes from this machine. Waiting is therefore the normal
/// path through that group, not a fault.
const RATE_LIMIT_RETRIES: u32 = 3;

/// What to wait when the server does not say. The rate limiter's window is a
/// minute, and anything shorter simply burns a retry: the fixed window has not
/// rolled over yet.
const DEFAULT_RETRY_WAIT: u64 = 60;

/// Ceiling on an honoured wait, so a misconfigured server cannot park the run
/// for an hour.
const MAX_RETRY_WAIT: u64 = 70;

/// One HTTP identity: its own cookie jar and its own bearer token.
///
/// The website and the JSON API share a session model — the same opaque token,
/// carried in a cookie one way and an `Authorization` header the other — so a
/// single handle can drive both halves for one account.
pub struct Http {
    base: String,
    origin: String,
    agent: Agent,
    bearer: RefCell<Option<String>>,
    cookies: RefCell<BTreeMap<String, String>>,
}

/// A response, fully read into memory. Vault bodies are capped at 10 MiB by
/// the server, so nothing here needs streaming.
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http {
    pub fn new(base_url: &str) -> Self {
        let base = base_url.trim().trim_end_matches('/').to_string();
        Self {
            origin: base.clone(),
            base,
            agent: Agent::config_builder()
                .http_status_as_error(false)
                // See the module doc: the 303-vs-200 split is the assertion.
                .max_redirects(0)
                .timeout_global(Some(TIMEOUT))
                .build()
                .into(),
            bearer: RefCell::new(None),
            cookies: RefCell::new(BTreeMap::new()),
        }
    }

    /// A second handle onto the same server with no session of any kind.
    pub fn anonymous(&self) -> Self {
        Self::new(&self.base)
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn set_bearer(&self, token: Option<String>) {
        *self.bearer.borrow_mut() = token;
    }

    pub fn bearer(&self) -> Option<String> {
        self.bearer.borrow().clone()
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies.borrow().get(name).cloned()
    }

    pub fn set_cookie(&self, name: &str, value: &str) {
        self.cookies
            .borrow_mut()
            .insert(name.to_string(), value.to_string());
    }

    pub fn clear_cookies(&self) {
        self.cookies.borrow_mut().clear();
    }

    // -- requests -----------------------------------------------------------

    pub fn get(&self, path: &str) -> Result<Resp, String> {
        self.send("GET", path, &[], None)
    }

    pub fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Result<Resp, String> {
        self.send("GET", path, headers, None)
    }

    pub fn delete(&self, path: &str) -> Result<Resp, String> {
        self.send("DELETE", path, &[], None)
    }

    pub fn post_json(&self, path: &str, body: &Value) -> Result<Resp, String> {
        self.json("POST", path, body)
    }

    pub fn put_json(&self, path: &str, body: &Value) -> Result<Resp, String> {
        self.json("PUT", path, body)
    }

    fn json(&self, method: &str, path: &str, body: &Value) -> Result<Resp, String> {
        self.send(
            method,
            path,
            &[("Content-Type", "application/json")],
            Some(body.to_string().into_bytes()),
        )
    }

    /// A raw-bytes vault upload or overwrite.
    pub fn blob(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Resp, String> {
        let mut all = vec![("Content-Type", "application/octet-stream")];
        all.extend_from_slice(headers);
        self.send(method, path, &all, Some(body))
    }

    /// A website form post, with the CSRF token filled in from the jar.
    ///
    /// The double-submit check compares the cookie against the field, so the
    /// cookie *is* the valid token; scraping the page for it would test the
    /// template rather than the client. [`Self::csrf_field`] exists for the
    /// checks that do want to compare the two.
    pub fn form(&self, path: &str, fields: &[(&str, &str)]) -> Result<Resp, String> {
        let token = self.csrf_token()?;
        self.form_with(path, &token, fields, &[])
    }

    /// A form post with an explicit token and extra headers, for the checks
    /// that deliberately send the wrong one.
    pub fn form_with(
        &self,
        path: &str,
        csrf: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<Resp, String> {
        let mut body = format!("csrf={}", urlencode(csrf));
        for (key, value) in fields {
            body.push('&');
            body.push_str(&urlencode(key));
            body.push('=');
            body.push_str(&urlencode(value));
        }
        let mut all = vec![("Content-Type", "application/x-www-form-urlencoded")];
        all.extend_from_slice(headers);
        self.send("POST", path, &all, Some(body.into_bytes()))
    }

    /// A multipart upload. `csrf` is written first, which `CsrfMultipart`
    /// requires: it refuses any part that arrives before the token.
    pub fn multipart(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        file: Option<(&str, &[u8])>,
    ) -> Result<Resp, String> {
        let token = self.csrf_token()?;
        let boundary = format!("----askrypt{:x}", std::process::id());
        let mut body: Vec<u8> = Vec::new();
        let part = |name: &str, file_name: Option<&str>, value: &[u8], body: &mut Vec<u8>| {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match file_name {
                Some(file_name) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; \
                         filename=\"{file_name}\"\r\n\
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
        part("csrf", None, token.as_bytes(), &mut body);
        for (name, value) in fields {
            part(name, None, value.as_bytes(), &mut body);
        }
        if let Some((file_name, bytes)) = file {
            part("file", Some(file_name), bytes, &mut body);
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let content_type = format!("multipart/form-data; boundary={boundary}");
        self.send("POST", path, &[("Content-Type", &content_type)], Some(body))
    }

    /// The CSRF token this identity holds, minting one by loading the landing
    /// page if it has none yet.
    pub fn csrf_token(&self) -> Result<String, String> {
        if let Some(token) = self.cookie(CSRF_COOKIE) {
            return Ok(token);
        }
        self.get("/")?;
        self.cookie(CSRF_COOKIE)
            .ok_or_else(|| "the server never set a CSRF cookie".to_string())
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Resp, String> {
        for attempt in 0..=RATE_LIMIT_RETRIES {
            let resp = self.send_once(method, path, headers, body.clone())?;
            if resp.status != 429 || attempt == RATE_LIMIT_RETRIES {
                return Ok(resp);
            }
            let wait = resp.retry_after().clamp(1, MAX_RETRY_WAIT);
            println!("    (rate limited; waiting {wait}s)");
            std::thread::sleep(Duration::from_secs(wait));
        }
        unreachable!("the loop returns on its last attempt")
    }

    fn send_once(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Resp, String> {
        let url = format!("{}{path}", self.base);
        let mut request = ureq::http::Request::builder().method(method).uri(&url);
        if let Some(token) = self.bearer.borrow().as_deref() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(cookie) = self.cookie_header() {
            request = request.header("Cookie", cookie);
        }
        // `check_origin` only bites when a request states one, and a real
        // browser always does on a form post. Stating the site's own origin is
        // what a same-origin submit looks like — unless the caller is
        // deliberately claiming another one, in which case theirs is the only
        // `Origin` that may go out: the builder *appends* headers, and two
        // would leave the server reading the first and the check proving
        // nothing.
        let states_origin = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("origin"));
        if body.is_some() && !states_origin {
            request = request.header("Origin", &self.origin);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request
            .body(body.unwrap_or_default())
            .map_err(|e| format!("could not build {method} {path}: {e}"))?;

        let mut response = self
            .agent
            .run(request)
            .map_err(|e| format!("{method} {path}: {e}"))?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let bytes = response
            .body_mut()
            .with_config()
            // A vault may be a full 10 MiB; +1 so a maximal one still reads,
            // and a server streaming forever still stops.
            .limit(11 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| format!("{method} {path}: could not read the body: {e}"))?;

        let resp = Resp {
            status,
            headers,
            body: bytes,
        };
        self.absorb_cookies(&resp);
        Ok(resp)
    }

    fn cookie_header(&self) -> Option<String> {
        let cookies = self.cookies.borrow();
        if cookies.is_empty() {
            return None;
        }
        Some(
            cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Applies every `Set-Cookie` on a response to the jar.
    ///
    /// `Max-Age=0` is a deletion, which is how sign-out and the session
    /// extractor's rejection both clear the session cookie. Values here are
    /// hex tokens, so there is no percent-decoding to get right.
    fn absorb_cookies(&self, resp: &Resp) {
        for (name, value) in &resp.headers {
            if name != "set-cookie" {
                continue;
            }
            let mut parts = value.split(';');
            let Some((key, token)) = parts.next().and_then(|pair| pair.split_once('=')) else {
                continue;
            };
            let expired = value
                .split(';')
                .any(|attr| attr.trim().eq_ignore_ascii_case("Max-Age=0"));
            let mut cookies = self.cookies.borrow_mut();
            if expired || token.is_empty() {
                cookies.remove(key.trim());
            } else {
                cookies.insert(key.trim().to_string(), token.trim().to_string());
            }
        }
    }
}

pub const SESSION_COOKIE: &str = "askrypt_session";
pub const CSRF_COOKIE: &str = "askrypt_csrf";

/// The hidden `csrf` input out of a rendered page.
pub fn csrf_field(html: &str) -> Option<String> {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every `Set-Cookie` on the response, unparsed.
    pub fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == "set-cookie")
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// The ETag, without its quotes or weak-validator prefix.
    pub fn etag(&self) -> Option<String> {
        self.header("etag").map(|value| {
            value
                .trim()
                .strip_prefix("W/")
                .unwrap_or(value.trim())
                .trim_matches('"')
                .to_string()
        })
    }

    /// How long to wait before retrying a 429.
    ///
    /// The JSON API answers with a `Retry-After`; the website's twin renders a
    /// page instead and states the window in the sentence on it, which is the
    /// only place the number appears. Failing that, wait the window this server
    /// is built with.
    fn retry_after(&self) -> u64 {
        if let Some(seconds) = self
            .header("retry-after")
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            return seconds;
        }
        let text = self.text();
        let Some(rest) = text.split_once("about ").map(|(_, rest)| rest) else {
            return DEFAULT_RETRY_WAIT;
        };
        rest.split_whitespace()
            .next()
            .and_then(|word| word.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RETRY_WAIT)
    }

    /// The `code` out of the `{"error":{"code","message"}}` envelope.
    pub fn error_code(&self) -> String {
        self.json()
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn expect(&self, status: u16) -> Result<&Self, String> {
        if self.status == status {
            return Ok(self);
        }
        Err(format!(
            "expected {status}, got {} ({})",
            self.status,
            self.summary()
        ))
    }

    /// A 4xx/5xx carrying a particular envelope code.
    pub fn expect_error(&self, status: u16, code: &str) -> Result<&Self, String> {
        self.expect(status)?;
        let seen = self.error_code();
        if seen == code {
            return Ok(self);
        }
        Err(format!("expected error code {code:?}, got {seen:?}"))
    }

    /// A 303 to a particular path — the shape of every successful website
    /// mutation on the no-JS path.
    pub fn expect_redirect(&self, to: &str) -> Result<&Self, String> {
        self.expect(303)?;
        match self.location() {
            Some(location) if location == to => Ok(self),
            other => Err(format!("expected a redirect to {to}, got {other:?}")),
        }
    }

    pub fn expect_contains(&self, needle: &str) -> Result<&Self, String> {
        if self.text().contains(needle) {
            return Ok(self);
        }
        Err(format!("response does not contain {needle:?}"))
    }

    pub fn expect_missing(&self, needle: &str) -> Result<&Self, String> {
        if self.text().contains(needle) {
            return Err(format!("response unexpectedly contains {needle:?}"));
        }
        Ok(self)
    }

    /// A short, log-safe description for a failure message.
    fn summary(&self) -> String {
        let code = self.error_code();
        if !code.is_empty() {
            return code;
        }
        let text = self.text();
        let trimmed: String = text.trim().chars().take(120).collect();
        if trimmed.is_empty() {
            "empty body".to_string()
        } else {
            trimmed.replace('\n', " ")
        }
    }
}

/// Percent-encode a form value. Hand-rolled for the same reason core's own
/// encoder is: the set that matters is small and the dependency is not worth it.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
