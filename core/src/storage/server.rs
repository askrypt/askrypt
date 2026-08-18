//! Askrypt-server implementation of [`VaultStorage`].
//!
//! The server is a zero-knowledge blob store: it holds `*.askrypt` files as
//! opaque bytes and never sees questions, answers or keys. All crypto stays
//! here on the client, which is why this backend only moves the bytes that
//! [`AskryptFile::to_bytes`](crate::AskryptFile::to_bytes) already produced.
//!
//! [`ServerClient`] is the transport — one authenticated handle to a server's
//! `/api/v1`, cheap to share between vaults. [`ServerStorage`] is one vault on
//! such a server, addressed by name; it learns the vault's id and ETag as it
//! goes and uses them to make every overwrite conflict-checked.
//!
//! ```no_run
//! use askrypt::{ServerClient, ServerStorage, VaultStorage};
//! use std::sync::Arc;
//!
//! let client = Arc::new(ServerClient::login(
//!     "https://askrypt.example.com",
//!     "me@example.com",
//!     "hunter2",
//!     Some("desktop"),
//! )?);
//! let storage = ServerStorage::by_name(client, "MyVault.askrypt");
//! let vault = storage.load_vault()?;
//! # Ok::<(), askrypt::StorageError>(())
//! ```

use super::{RemoteRevision, Revision, StorageError, VaultStorage};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ureq::Agent;
use ureq::http::Response;

/// Largest vault the server accepts (`MAX_VAULT_BYTES` in `server/src/vaults.rs`).
/// Checked locally so an oversize vault fails before the upload is paid for.
pub const MAX_VAULT_BYTES: usize = 10 * 1024 * 1024;

/// Ceiling on any single request, so a hung server cannot wedge the caller's
/// thread forever. Generous enough for a 10 MiB upload on a slow link.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// One vault's metadata, as the server reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteVault {
    /// Server-assigned uuid; the vault's identity in every URL.
    pub id: String,
    /// File name, unique within the account.
    pub name: String,
    pub size: u64,
    /// SHA-256 of the stored bytes, *unquoted* (headers carry it quoted).
    pub etag: String,
    /// RFC 3339 timestamp of the last write, as the *server* recorded it.
    pub updated_at: String,
    /// The machine that wrote the file, lifted by the server from the vault's
    /// own unencrypted stamp. Absent for a pre-stamp file, or for a server too
    /// old to report one — hence the `default`, which is what lets this type
    /// keep parsing a listing from either.
    #[serde(default)]
    pub host: Option<String>,
    /// When the file itself says it was saved, from that same stamp. Not the
    /// same instant as `updated_at`: a restore, or an upload of an older file
    /// from another device, moves one without the other.
    #[serde(default)]
    pub saved_at: Option<String>,
}

/// The server's uniform error envelope: `{"error": {"code", "message"}}`.
#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct SessionResponse {
    token: String,
}

/// An authenticated handle to an Askrypt server's `/api/v1`.
///
/// Holds a bearer token, so treat it as a secret: it authorizes account
/// operations (including changing the account email) as well as vault access.
/// Cheap to wrap in an [`Arc`] and share between several [`ServerStorage`]s —
/// the underlying agent pools connections.
pub struct ServerClient {
    /// Server root without a trailing slash, e.g. `https://askrypt.example.com`.
    base_url: String,
    token: String,
    agent: Agent,
}

impl std::fmt::Debug for ServerClient {
    /// Redacts the token: `ServerClient` ends up inside other types' `Debug`
    /// output, and a bearer token in a log line is a credential leak.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ServerClient {
    /// Sign in with email and password, returning a client holding the issued
    /// session token (see [`ServerClient::token`] to persist it).
    ///
    /// `device_label` shows up in the account's device list on the website.
    pub fn login(
        base_url: &str,
        email: &str,
        password: &str,
        device_label: Option<&str>,
    ) -> Result<Self, StorageError> {
        let base_url = normalize_base_url(base_url);
        let agent = build_agent();

        let body = serde_json::json!({
            "email": email,
            "password": password,
            "device_label": device_label,
        });
        let response = agent
            .post(format!("{base_url}/api/v1/auth/login"))
            .send_json(&body)
            .map_err(transport_error)?;
        let session: SessionResponse = read_json(check_status(response)?)?;

        Ok(Self {
            base_url,
            token: session.token,
            agent,
        })
    }

    /// Start a sign-in that happens in the user's browser.
    ///
    /// Preferred over [`login`](Self::login): the app never handles the account
    /// password, and the user can *register* as part of the same flow, which no
    /// password prompt can offer. The returned [`BrowserLogin`] carries the URL
    /// to open and the code to display.
    ///
    /// `device_label` names this machine in the account's device list —
    /// [`crate::current_host`] (`os@host`) is what the desktop app passes.
    pub fn begin_browser_login(
        base_url: &str,
        device_label: Option<&str>,
    ) -> Result<BrowserLogin, StorageError> {
        let base_url = normalize_base_url(base_url);
        let agent = build_link_agent();

        let response = agent
            .post(format!("{base_url}/api/v1/auth/device"))
            .send_json(serde_json::json!({ "device_label": device_label }))
            .map_err(transport_error)?;
        let started: StartLinkResponse = read_json(check_status(response)?)?;

        Ok(BrowserLogin {
            verification_url: verification_url(&base_url, &started.verification_path)?,
            base_url,
            poll_token: started.poll_token,
            user_code: started.user_code,
            interval: Duration::from_secs(started.interval.clamp(1, 60)),
            expires_in: started.expires_in,
            agent,
        })
    }

    /// Reuse a token issued by an earlier [`ServerClient::login`].
    ///
    /// Does not contact the server; an expired or revoked token surfaces as
    /// [`StorageError::Auth`] on the first request.
    pub fn with_token(base_url: &str, token: &str) -> Self {
        Self {
            base_url: normalize_base_url(base_url),
            token: token.to_string(),
            agent: build_agent(),
        }
    }

    /// The session token, for persisting across restarts. Secret — see the
    /// type-level note.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The server root this client talks to, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Host portion of the base URL, for display (falls back to the whole URL).
    pub fn host(&self) -> &str {
        self.base_url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.base_url)
    }

    /// Revoke this session's token. Consumes the client: the token is dead
    /// afterwards.
    pub fn logout(self) -> Result<(), StorageError> {
        let response = self
            .agent
            .post(format!("{}/api/v1/auth/logout", self.base_url))
            .header("Authorization", self.bearer())
            .send_empty()
            .map_err(transport_error)?;
        check_status(response)?;
        Ok(())
    }

    /// All vaults in the account, as the server sorts them (by name).
    pub fn list(&self) -> Result<Vec<RemoteVault>, StorageError> {
        let response = self
            .agent
            .get(format!("{}/api/v1/vaults", self.base_url))
            .header("Authorization", self.bearer())
            .call()
            .map_err(transport_error)?;
        read_json(check_status(response)?)
    }

    /// Upload a new vault. Fails with a `conflict` [`StorageError::Remote`] if
    /// the account already has one by this name.
    pub fn create(&self, name: &str, bytes: &[u8]) -> Result<RemoteVault, StorageError> {
        check_size(bytes)?;
        let response = self
            .agent
            .post(format!(
                "{}/api/v1/vaults?name={}",
                self.base_url,
                percent_encode(name)
            ))
            .header("Authorization", self.bearer())
            .header("Content-Type", "application/octet-stream")
            .send(bytes)
            .map_err(transport_error)?;
        read_json(check_status(response)?)
    }

    /// Download a vault's bytes along with its current ETag.
    pub fn download(&self, id: &str) -> Result<(Vec<u8>, String), StorageError> {
        let response = self
            .agent
            .get(format!("{}/api/v1/vaults/{}", self.base_url, id))
            .header("Authorization", self.bearer())
            .call()
            .map_err(transport_error)?;
        let mut response = check_status(response)?;

        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(unquote_etag)
            .unwrap_or_default();
        let bytes = response
            .body_mut()
            .with_config()
            // The default cap is exactly MAX_VAULT_BYTES, which would reject a
            // legitimately maximal vault; +1 lets it through and still stops a
            // server that streams forever.
            .limit(MAX_VAULT_BYTES as u64 + 1)
            .read_to_vec()
            .map_err(transport_error)?;

        Ok((bytes, etag))
    }

    /// Replace a vault's bytes, but only if it still matches `if_match` (the
    /// ETag last seen). A stale ETag comes back as [`StorageError::Conflict`]
    /// rather than silently discarding the other writer's version.
    pub fn overwrite(
        &self,
        id: &str,
        bytes: &[u8],
        if_match: &str,
    ) -> Result<RemoteVault, StorageError> {
        check_size(bytes)?;
        let response = self
            .agent
            .put(format!("{}/api/v1/vaults/{}", self.base_url, id))
            .header("Authorization", self.bearer())
            .header("Content-Type", "application/octet-stream")
            .header("If-Match", quote_etag(if_match))
            .send(bytes)
            .map_err(transport_error)?;
        read_json(check_status(response)?)
    }

    /// Rename a vault. The ETag is a content hash, so it does not change.
    pub fn rename(&self, id: &str, name: &str) -> Result<RemoteVault, StorageError> {
        let response = self
            .agent
            .put(format!("{}/api/v1/vaults/{}/name", self.base_url, id))
            .header("Authorization", self.bearer())
            .send_json(serde_json::json!({ "name": name }))
            .map_err(transport_error)?;
        read_json(check_status(response)?)
    }

    /// Delete a vault and its bytes.
    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        let response = self
            .agent
            .delete(format!("{}/api/v1/vaults/{}", self.base_url, id))
            .header("Authorization", self.bearer())
            .call()
            .map_err(transport_error)?;
        check_status(response)?;
        Ok(())
    }

    /// The `Authorization` value. Format is exact — the server matches
    /// `Bearer ` case-sensitively with a single space and does not trim.
    fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

// ---------------------------------------------------------------------------
// Browser sign-in
// ---------------------------------------------------------------------------

/// Ceiling on a device-link request. Far shorter than [`REQUEST_TIMEOUT`],
/// which is sized for a 10 MiB upload: these are two tiny JSON round trips, one
/// of them repeated on a timer, and a wedged server must not pile up threads.
const LINK_TIMEOUT: Duration = Duration::from_secs(15);

/// What the server answers when a device link is opened.
#[derive(Deserialize)]
struct StartLinkResponse {
    poll_token: String,
    user_code: String,
    verification_path: String,
    expires_in: i64,
    interval: u64,
}

/// A poll answer, read flat rather than as a tagged enum so that a status this
/// build has never heard of degrades to "keep waiting" instead of a hard parse
/// error.
#[derive(Deserialize)]
struct PollLinkResponse {
    status: String,
    token: Option<String>,
    account: Option<PollAccount>,
}

#[derive(Deserialize)]
struct PollAccount {
    email: String,
}

/// A sign-in that is happening in the user's browser.
///
/// Created by [`ServerClient::begin_browser_login`]. Open
/// [`verification_url`](Self::verification_url) in a browser, show
/// [`user_code`](Self::user_code) so the user can check the page is about
/// *this* app, and call [`poll`](Self::poll) every
/// [`poll_interval`](Self::poll_interval) until it stops answering
/// [`BrowserLoginStatus::Pending`].
///
/// The app never sees the account password: the browser does the signing in,
/// and this hands back the same session token `login` would have produced.
pub struct BrowserLogin {
    base_url: String,
    /// Secret: whoever holds this collects the session the browser authorized.
    poll_token: String,
    verification_url: String,
    user_code: String,
    interval: Duration,
    expires_in: i64,
    agent: Agent,
}

impl std::fmt::Debug for BrowserLogin {
    /// Redacts the poll token. It is bearer-equivalent for the session it will
    /// claim, and this type travels inside UI message enums that derive
    /// `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserLogin")
            .field("base_url", &self.base_url)
            .field("verification_url", &self.verification_url)
            .field("user_code", &self.user_code)
            .field("poll_token", &"<redacted>")
            .finish()
    }
}

/// Where a browser sign-in stands.
#[derive(Debug)]
pub enum BrowserLoginStatus {
    /// Nobody has approved it yet. Keep polling.
    Pending,
    /// Signed in — the client holds the issued token.
    Approved { client: ServerClient, email: String },
    /// The user said this was not their app.
    Denied,
    /// Too old, already used, or never existed. Terminal: start a new one.
    Expired,
}

impl BrowserLogin {
    /// The page to open in the user's browser.
    pub fn verification_url(&self) -> &str {
        &self.verification_url
    }

    /// The code to show in the app, for the user to compare with the page.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// How long to wait between [`poll`](Self::poll) calls. The server's own
    /// figure, so the cadence cannot outrun its rate limit.
    pub fn poll_interval(&self) -> Duration {
        self.interval
    }

    /// Seconds this link stays usable, as the server reported them when it was
    /// created.
    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }

    /// Tell the server this sign-in is not wanted after all.
    ///
    /// A user who closes the sign-in pane is done with the link, so it should
    /// stop being approvable now rather than at the end of its 24 hours. Best
    /// effort by nature — the app may be closing — so callers can ignore the
    /// result; the link expires on its own regardless.
    pub fn cancel(&self) -> Result<(), StorageError> {
        let response = self
            .agent
            .post(format!("{}/api/v1/auth/device/cancel", self.base_url))
            .send_json(serde_json::json!({ "poll_token": self.poll_token }))
            .map_err(transport_error)?;
        check_status(response)?;
        Ok(())
    }

    /// One round trip. The caller owns the waiting, so a UI can cancel between
    /// polls without a half-finished request to abandon.
    pub fn poll(&self) -> Result<BrowserLoginStatus, StorageError> {
        let response = self
            .agent
            .post(format!("{}/api/v1/auth/device/poll", self.base_url))
            .send_json(serde_json::json!({ "poll_token": self.poll_token }))
            .map_err(transport_error)?;
        let answer: PollLinkResponse = read_json(check_status(response)?)?;

        Ok(match answer.status.as_str() {
            "approved" => {
                let (Some(token), Some(account)) = (answer.token, answer.account) else {
                    return Err(StorageError::Format(
                        "server approved the sign-in without returning a session".to_string(),
                    ));
                };
                BrowserLoginStatus::Approved {
                    client: ServerClient {
                        base_url: self.base_url.clone(),
                        token,
                        agent: build_agent(),
                    },
                    email: account.email,
                }
            }
            "denied" => BrowserLoginStatus::Denied,
            "expired" => BrowserLoginStatus::Expired,
            // "pending", and anything a newer server might add: waiting is the
            // answer that cannot be wrong.
            _ => BrowserLoginStatus::Pending,
        })
    }
}

/// Build the browser URL from the server's answer, refusing anything that is
/// not a plain path on the server we asked.
///
/// The result is handed to the OS to open, so it is a redirect primitive: a
/// hostile or compromised server answering `//evil.example/x` would otherwise
/// launch the user's browser at somebody else's site. The rule mirrors the one
/// the server applies to client-supplied URLs.
fn verification_url(base_url: &str, path: &str) -> Result<String, StorageError> {
    let looks_like_a_path = path.starts_with('/') && !path.starts_with("//") && !path.contains(':');
    if !looks_like_a_path {
        return Err(StorageError::Format(format!(
            "server asked us to open {path:?}, which is not a path on it"
        )));
    }
    Ok(format!("{base_url}{path}"))
}

/// What we know about the remote side of a [`ServerStorage`]: which vault it
/// is, and the ETag of the bytes we last saw. The two are learned together, so
/// an id without an ETag is unrepresentable and every overwrite can be
/// conflict-checked.
#[derive(Debug, Clone)]
struct Remote {
    id: String,
    etag: String,
}

/// One vault stored on an Askrypt server, addressed by file name.
///
/// The first [`read`](VaultStorage::read) or [`write`](VaultStorage::write)
/// resolves the name to a vault id (or creates the vault), after which the id
/// and the last-seen ETag are remembered for conflict detection.
///
/// Because that memory is what makes writes conflict-checked, keep the same
/// instance for the life of an open vault — a fresh one would re-read whatever
/// ETag the server holds *now* and overwrite another device's edit.
#[derive(Debug)]
pub struct ServerStorage {
    client: Arc<ServerClient>,
    name: String,
    remote: Mutex<Option<Remote>>,
}

impl ServerStorage {
    /// A vault identified by name. It need not exist yet — the first write
    /// creates it.
    pub fn by_name(client: Arc<ServerClient>, name: impl Into<String>) -> Self {
        Self {
            client,
            name: name.into(),
            remote: Mutex::new(None),
        }
    }

    /// A vault already known from [`ServerClient::list`], pre-seeded with its
    /// id and ETag so opening it costs a single request.
    pub fn existing(client: Arc<ServerClient>, vault: &RemoteVault) -> Self {
        Self {
            client,
            name: vault.name.clone(),
            remote: Mutex::new(Some(Remote {
                id: vault.id.clone(),
                etag: vault.etag.clone(),
            })),
        }
    }

    /// The vault's file name on the server.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The server-assigned id, once known.
    pub fn vault_id(&self) -> Option<String> {
        self.remote.lock().unwrap().as_ref().map(|r| r.id.clone())
    }

    /// The client this storage talks through.
    pub fn client(&self) -> &Arc<ServerClient> {
        &self.client
    }

    /// Look the vault up by name, returning what the server knows about it, or
    /// `None` if the account has no vault by that name.
    fn resolve(&self) -> Result<Option<Remote>, StorageError> {
        if let Some(remote) = self.remote.lock().unwrap().clone() {
            return Ok(Some(remote));
        }

        let found = self
            .client
            .list()?
            .into_iter()
            .find(|vault| vault.name == self.name)
            .map(|vault| Remote {
                id: vault.id,
                etag: vault.etag,
            });

        if let Some(remote) = &found {
            *self.remote.lock().unwrap() = Some(remote.clone());
        }
        Ok(found)
    }
}

impl VaultStorage for ServerStorage {
    fn read(&self) -> Result<Vec<u8>, StorageError> {
        let remote = self.resolve()?.ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no vault named \"{}\" on the server", self.name),
            ))
        })?;

        let (bytes, etag) = self.client.download(&remote.id)?;
        *self.remote.lock().unwrap() = Some(Remote {
            id: remote.id,
            etag,
        });
        Ok(bytes)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let vault = match self.resolve()? {
            // Known vault: overwrite, but only if nobody else has written since
            // we last read it.
            Some(remote) => self.client.overwrite(&remote.id, bytes, &remote.etag)?,
            // Unknown name: this is the vault's first upload.
            None => self.client.create(&self.name, bytes)?,
        };

        *self.remote.lock().unwrap() = Some(Remote {
            id: vault.id,
            etag: vault.etag,
        });
        Ok(())
    }

    fn exists(&self) -> bool {
        // Best effort per the trait: an unreachable server is reported as
        // "no", not as an error, and must not poison a cached id.
        match self.resolve() {
            Ok(found) => found.is_some(),
            Err(_) => false,
        }
    }

    fn location(&self) -> String {
        format!("{} @ {}", self.name, self.client.host())
    }

    fn revision(&self) -> Option<Revision> {
        self.remote
            .lock()
            .unwrap()
            .as_ref()
            .map(|remote| Revision(remote.etag.clone()))
    }

    fn current_revision(&self) -> Result<Option<RemoteRevision>, StorageError> {
        // Deliberately not `resolve()`: that caches whatever it finds, and the
        // cached ETag is precisely what the next write sends as `If-Match`.
        // Adopting the server's current version here would turn the probe into
        // a silent licence to overwrite the very edit it just detected.
        //
        // The listing already carries the write stamp, so naming who saved it
        // and when costs no extra request.
        Ok(self
            .client
            .list()?
            .into_iter()
            .find(|vault| vault.name == self.name)
            .map(|vault| RemoteRevision {
                revision: Revision(vault.etag),
                host: vault.host,
                saved_at: vault.saved_at,
            }))
    }

    fn adopt_revision(&self, revision: &Revision) {
        // Only the ETag moves: the vault is the same one, and an id we have
        // not learned yet is not something a revision can teach us.
        if let Some(remote) = self.remote.lock().unwrap().as_mut() {
            remote.etag = revision.0.clone();
        }
    }
}

/// A connection-pooling agent that reports HTTP error statuses as ordinary
/// responses.
///
/// `http_status_as_error(false)` is load-bearing: the server's error envelope
/// (`{"error": {"code", "message"}}`) is in the *body* of a 4xx/5xx, and ureq's
/// default turns those into a bodyless `Error::StatusCode`, throwing away the
/// code we need to tell a quota failure from a bad name.
fn build_agent() -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into()
}

/// The same agent, timed out for the short JSON round trips of a browser
/// sign-in rather than for a vault upload.
fn build_link_agent() -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(LINK_TIMEOUT))
        .build()
        .into()
}

/// Strip a trailing slash so `{base}/api/v1/...` never doubles up.
///
/// Public because callers store server URLs alongside vault locations and
/// compare them by string: a second, slightly different normalization on the
/// caller's side is a mismatch waiting to happen.
pub fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

/// Turn a 4xx/5xx response into the matching [`StorageError`], passing 1xx–3xx
/// through untouched.
///
/// The mapping is what callers branch on, so it is deliberately coarse:
/// re-authenticate, reload, retry, or give up with the server's own code.
fn check_status(mut response: Response<ureq::Body>) -> Result<Response<ureq::Body>, StorageError> {
    let status = response.status().as_u16();
    if status < 400 {
        return Ok(response);
    }

    let (code, message) = read_error_envelope(&mut response);
    Err(match status {
        // Token missing, expired, revoked, or not permitted.
        401 | 403 => StorageError::Auth(message),
        // Unknown vault (or unknown endpoint) — same shape as a missing file.
        404 => StorageError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, message)),
        // 409 name taken, 412 stale If-Match, 428 If-Match missing. All mean
        // "the caller's view of the server is out of date".
        409 | 412 | 428 => StorageError::Conflict(message),
        _ => StorageError::Remote {
            status,
            code,
            message,
        },
    })
}

/// Pull `(code, message)` out of an error response, falling back to the status
/// text when the body is not the expected envelope (a proxy's own 502 page,
/// say).
fn read_error_envelope(response: &mut Response<ureq::Body>) -> (String, String) {
    let status = response.status();
    let fallback = || {
        (
            "unexpected_response".to_string(),
            format!(
                "server returned {}",
                status.canonical_reason().unwrap_or(status.as_str())
            ),
        )
    };

    match response.body_mut().read_to_string() {
        Ok(body) => match serde_json::from_str::<ErrorEnvelope>(&body) {
            Ok(envelope) => (envelope.error.code, envelope.error.message),
            Err(_) => fallback(),
        },
        Err(_) => fallback(),
    }
}

/// Parse a successful response body as JSON.
fn read_json<T: serde::de::DeserializeOwned>(
    mut response: Response<ureq::Body>,
) -> Result<T, StorageError> {
    response
        .body_mut()
        .read_json()
        .map_err(|e| StorageError::Format(format!("unexpected response from server: {e}")))
}

/// Map a ureq transport failure onto [`StorageError::Network`].
fn transport_error(error: ureq::Error) -> StorageError {
    StorageError::Network(error.to_string())
}

/// Reject an oversize vault before uploading it, so the caller gets a clear
/// error instead of paying for the transfer and receiving a 413.
fn check_size(bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() > MAX_VAULT_BYTES {
        return Err(StorageError::Remote {
            status: 413,
            code: "payload_too_large".to_string(),
            message: format!(
                "vault is {} bytes; the server accepts at most {}",
                bytes.len(),
                MAX_VAULT_BYTES
            ),
        });
    }
    Ok(())
}

/// Header form of an ETag: quoted, as the server sends and expects it.
fn quote_etag(etag: &str) -> String {
    format!("\"{}\"", etag.trim_matches('"'))
}

/// Strip the quotes and any weak-validator prefix from a received ETag,
/// leaving the bare hash we store and compare.
fn unquote_etag(value: &str) -> String {
    value
        .trim()
        .strip_prefix("W/")
        .unwrap_or(value.trim())
        .trim_matches('"')
        .to_string()
}

/// Percent-encode a vault name for the `?name=` query.
///
/// Hand-rolled rather than pulling in a dependency: the set that matters is
/// small, and the server independently rejects the characters that would be
/// dangerous anyway (`/`, `\`, control characters, `.`/`..`).
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char)
            }
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::test_vault;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A request as the fake server saw it on the wire.
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        /// Path plus query string, exactly as sent.
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Recorded {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Reply {
        fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.into(),
            }
        }

        fn json(status: u16, body: &str) -> Self {
            Self::new(status, body).with_header("Content-Type", "application/json")
        }

        fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
    }

    /// A minimal HTTP/1.1 server on loopback, driven by a closure.
    ///
    /// Hand-rolled for the same reason the SMTP tests hand-roll a relay: it
    /// keeps the tests dependency-free and lets them assert on the exact bytes
    /// we put on the wire — the `Authorization` and `If-Match` headers are the
    /// whole point. Plain HTTP, so no TLS setup in tests; TLS is ureq's
    /// business, not ours.
    struct FakeServer {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<Recorded>>>,
        running: Arc<AtomicBool>,
    }

    impl FakeServer {
        fn new<F>(handler: F) -> Self
        where
            F: Fn(&Recorded) -> Reply + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
            let addr = listener.local_addr().expect("local_addr failed");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let running = Arc::new(AtomicBool::new(true));

            let thread_requests = Arc::clone(&requests);
            let thread_running = Arc::clone(&running);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if !thread_running.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    if let Some(request) = read_request(&stream) {
                        let reply = handler(&request);
                        thread_requests.lock().unwrap().push(request);
                        write_reply(&stream, &reply);
                    }
                    stream.shutdown(Shutdown::Both).ok();
                }
            });

            Self {
                addr,
                requests,
                running,
            }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn client(&self) -> Arc<ServerClient> {
            Arc::new(ServerClient::with_token(&self.url(), TOKEN))
        }

        fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FakeServer {
        fn drop(&mut self) {
            // Unblock the accept loop so the thread exits with the test rather
            // than living until the process does.
            self.running.store(false, Ordering::SeqCst);
            TcpStream::connect(self.addr).ok();
        }
    }

    fn read_request(stream: &TcpStream) -> Option<Recorded> {
        let mut reader = BufReader::new(stream);

        let mut request_line = String::new();
        if reader.read_line(&mut request_line).ok()? == 0 {
            return None;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let target = parts.next()?.to_string();

        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        let length: usize = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        if length > 0 {
            reader.read_exact(&mut body).ok()?;
        }

        Some(Recorded {
            method,
            target,
            headers,
            body,
        })
    }

    fn write_reply(mut stream: &TcpStream, reply: &Reply) {
        let mut head = format!("HTTP/1.1 {} Status\r\n", reply.status);
        for (name, value) in &reply.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        // One request per connection keeps the fake simple; ureq copes.
        head.push_str("Connection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).ok();
        stream.write_all(&reply.body).ok();
        stream.flush().ok();
    }

    const TOKEN: &str = "0123456789abcdef";
    const VAULT_ID: &str = "11111111-2222-3333-4444-555555555555";
    const VAULT_NAME: &str = "My Vault.askrypt";

    /// One vault as the current server serializes it — write stamp included,
    /// and the two stamp keys always present even when the file carries none.
    fn vault_json(etag: &str) -> String {
        format!(
            r#"{{"id":"{VAULT_ID}","name":"{VAULT_NAME}","size":42,"etag":"{etag}",
                 "updated_at":"2026-08-07T10:00:00Z",
                 "host":"ubuntu@mypc","saved_at":"2026-08-07T09:59:00Z"}}"#
        )
    }

    fn error_json(code: &str, message: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#)
    }

    #[test]
    fn login_posts_credentials_and_keeps_the_token() {
        let server = FakeServer::new(|_| {
            Reply::json(
                200,
                r#"{"token":"tok-abc","expires_at":"2026-09-06T10:00:00Z",
                    "account":{"id":"a","email":"me@example.com"}}"#,
            )
        });

        let client =
            ServerClient::login(&server.url(), "me@example.com", "hunter2", Some("desktop"))
                .expect("login failed");

        assert_eq!(client.token(), "tok-abc");

        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/v1/auth/login");
        let sent: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(sent["email"], "me@example.com");
        assert_eq!(sent["password"], "hunter2");
        assert_eq!(sent["device_label"], "desktop");
    }

    #[test]
    fn login_rejects_bad_credentials_as_auth_error() {
        let server = FakeServer::new(|_| {
            Reply::json(
                401,
                &error_json("invalid_credentials", "invalid email or password"),
            )
        });

        match ServerClient::login(&server.url(), "me@example.com", "wrong", None) {
            Err(StorageError::Auth(message)) => assert!(message.contains("invalid email")),
            other => panic!("expected Auth, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn every_request_carries_the_exact_bearer_header() {
        let server = FakeServer::new(|_| Reply::json(200, "[]"));

        server.client().list().expect("list failed");

        // Byte-exact: the server matches "Bearer " case-sensitively, with a
        // single space, and does not trim.
        assert_eq!(
            server.requests()[0].header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }

    #[test]
    fn first_write_creates_the_vault_with_an_encoded_name() {
        let server = FakeServer::new(|request| match request.method.as_str() {
            // The name is unknown to the account, so the lookup comes back empty.
            "GET" => Reply::json(200, "[]"),
            _ => Reply::json(201, &vault_json("aaaa")),
        });

        let storage = ServerStorage::by_name(server.client(), VAULT_NAME);
        storage.write(b"PK\x03\x04vault").expect("write failed");

        let requests = server.requests();
        assert_eq!(requests[0].target, "/api/v1/vaults");
        let upload = &requests[1];
        assert_eq!(upload.method, "POST");
        assert_eq!(upload.target, "/api/v1/vaults?name=My%20Vault.askrypt");
        assert_eq!(
            upload.header("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(upload.body, b"PK\x03\x04vault");
        // Nothing to conflict with yet, so no precondition is sent.
        assert_eq!(upload.header("if-match"), None);

        // The id and ETag from the response are remembered.
        assert_eq!(storage.vault_id().as_deref(), Some(VAULT_ID));
    }

    #[test]
    fn read_captures_the_etag_and_the_next_write_sends_it() {
        let server = FakeServer::new(|request| match request.method.as_str() {
            "GET" => {
                Reply::new(200, b"PK\x03\x04current".to_vec()).with_header("ETag", "\"fresh-etag\"")
            }
            _ => Reply::json(200, &vault_json("newer-etag")),
        });

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "stale-etag".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        assert_eq!(storage.read().unwrap(), b"PK\x03\x04current");
        storage.write(b"PK\x03\x04updated").expect("write failed");

        let requests = server.requests();
        // Pre-seeded, so opening it costs exactly one request — no list.
        assert_eq!(requests[0].target, format!("/api/v1/vaults/{VAULT_ID}"));
        let update = &requests[1];
        assert_eq!(update.method, "PUT");
        // The ETag just read wins over the stale one we were seeded with, and
        // goes out quoted the way the server expects.
        assert_eq!(update.header("if-match"), Some("\"fresh-etag\""));
        assert_eq!(update.body, b"PK\x03\x04updated");
    }

    #[test]
    fn probing_reports_the_listing_etag_and_the_write_stamp() {
        let server = FakeServer::new(|_| {
            Reply::json(
                200,
                &format!(
                    r#"[{{"id":"{VAULT_ID}","name":"{VAULT_NAME}","size":42,"etag":"theirs",
                          "updated_at":"2026-08-18T14:05:00Z","host":"ubuntu@work-pc",
                          "saved_at":"2026-08-18T14:04:58Z"}}]"#
                ),
            )
        });

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "ours".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        let found = storage
            .current_revision()
            .expect("probe failed")
            .expect("vault is missing");

        assert_eq!(found.revision, Revision("theirs".to_string()));
        // The listing already knows who wrote it, so naming them in the notice
        // costs no second request.
        assert_eq!(found.host.as_deref(), Some("ubuntu@work-pc"));
        assert_eq!(found.saved_at.as_deref(), Some("2026-08-18T14:04:58Z"));
    }

    #[test]
    fn probing_leaves_the_conflict_check_armed() {
        // The regression this whole design turns on: a probe that adopted what
        // it found would make the next save overwrite the very edit it just
        // detected, silently.
        let server = FakeServer::new(|request| match request.method.as_str() {
            "GET" => Reply::json(
                200,
                &format!(
                    r#"[{{"id":"{VAULT_ID}","name":"{VAULT_NAME}","size":42,"etag":"theirs",
                          "updated_at":"2026-08-18T14:05:00Z","host":null,"saved_at":null}}]"#
                ),
            ),
            _ => Reply::json(200, &vault_json("newer")),
        });

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "ours".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        storage.current_revision().expect("probe failed");

        // Neither what we are on nor what the next write will claim has moved.
        assert_eq!(storage.revision(), Some(Revision("ours".to_string())));
        storage.write(b"PK\x03\x04mine").expect("write failed");
        let update = server
            .requests()
            .into_iter()
            .find(|request| request.method == "PUT")
            .expect("no PUT");
        assert_eq!(update.header("if-match"), Some("\"ours\""));
    }

    #[test]
    fn adopting_a_revision_is_what_lets_a_write_replace_it() {
        let server = FakeServer::new(|_| Reply::json(200, &vault_json("newer")));

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "ours".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        storage.adopt_revision(&Revision("theirs".to_string()));
        storage.write(b"PK\x03\x04mine").expect("write failed");

        let update = &server.requests()[0];
        assert_eq!(update.method, "PUT");
        // The deliberate overwrite: we named the version we meant to replace.
        assert_eq!(update.header("if-match"), Some("\"theirs\""));
    }

    #[test]
    fn a_vault_absent_from_the_listing_probes_as_gone() {
        let server = FakeServer::new(|_| Reply::json(200, "[]"));

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "ours".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        assert!(matches!(storage.current_revision(), Ok(None)));
    }

    #[test]
    fn stale_etag_is_reported_as_a_conflict() {
        let server = FakeServer::new(|_| {
            Reply::json(
                412,
                &error_json(
                    "precondition_failed",
                    "the stored vault changed since it was last fetched",
                ),
            )
        });

        let seed = RemoteVault {
            id: VAULT_ID.to_string(),
            name: VAULT_NAME.to_string(),
            size: 7,
            etag: "stale".to_string(),
            updated_at: "2026-08-07T10:00:00Z".to_string(),
            host: None,
            saved_at: None,
        };
        let storage = ServerStorage::existing(server.client(), &seed);

        match storage.write(b"PK\x03\x04updated") {
            Err(StorageError::Conflict(message)) => assert!(message.contains("changed")),
            other => panic!("expected Conflict, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn expired_token_is_reported_as_an_auth_error() {
        let server = FakeServer::new(|_| {
            Reply::json(
                401,
                &error_json("unauthorized", "missing or invalid bearer token"),
            )
        });

        let storage = ServerStorage::by_name(server.client(), VAULT_NAME);
        match storage.read() {
            Err(StorageError::Auth(_)) => {}
            other => panic!("expected Auth, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn unknown_name_reads_as_not_found() {
        let server = FakeServer::new(|_| Reply::json(200, "[]"));

        let storage = ServerStorage::by_name(server.client(), VAULT_NAME);
        match storage.read() {
            Err(StorageError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn deleted_vault_downloads_as_not_found() {
        let server =
            FakeServer::new(|_| Reply::json(404, &error_json("not_found", "no such vault")));

        match server.client().download(VAULT_ID) {
            Err(StorageError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn quota_failure_keeps_the_servers_code() {
        let server = FakeServer::new(|request| match request.method.as_str() {
            "GET" => Reply::json(200, "[]"),
            _ => Reply::json(
                507,
                &error_json("quota_exceeded", "account storage quota exceeded"),
            ),
        });

        let storage = ServerStorage::by_name(server.client(), VAULT_NAME);
        match storage.write(b"PK\x03\x04vault") {
            Err(StorageError::Remote { status, code, .. }) => {
                assert_eq!(status, 507);
                assert_eq!(code, "quota_exceeded");
            }
            other => panic!("expected Remote, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn non_envelope_error_body_still_maps_to_a_remote_error() {
        // A reverse proxy's own error page, not the API's envelope.
        let server = FakeServer::new(|_| Reply::new(502, "<html>Bad Gateway</html>"));

        match server.client().list() {
            Err(StorageError::Remote { status, code, .. }) => {
                assert_eq!(status, 502);
                assert_eq!(code, "unexpected_response");
            }
            other => panic!("expected Remote, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn oversize_vault_is_rejected_before_uploading() {
        let server = FakeServer::new(|_| Reply::json(200, "[]"));
        let client = server.client();

        let too_big = vec![0u8; MAX_VAULT_BYTES + 1];
        match client.create(VAULT_NAME, &too_big) {
            Err(StorageError::Remote { status, code, .. }) => {
                assert_eq!(status, 413);
                assert_eq!(code, "payload_too_large");
            }
            other => panic!("expected Remote, got {:?}", other.map(|_| ())),
        }
        // The point of the local check: nothing went over the wire.
        assert!(server.requests().is_empty());
    }

    #[test]
    fn listing_carries_the_files_own_write_stamp() {
        let server = FakeServer::new(|_| Reply::json(200, &format!("[{}]", vault_json("aaaa"))));
        let listed = server.client().list().expect("list failed");

        let vault = &listed[0];
        assert_eq!(vault.updated_at, "2026-08-07T10:00:00Z");
        assert_eq!(vault.host.as_deref(), Some("ubuntu@mypc"));
        assert_eq!(vault.saved_at.as_deref(), Some("2026-08-07T09:59:00Z"));
    }

    #[test]
    fn listing_without_a_write_stamp_still_parses() {
        // Two shapes have to keep working: an unstamped file, which the current
        // server reports as explicit nulls, and a server old enough to omit the
        // keys altogether.
        let nulls = FakeServer::new(|_| {
            Reply::json(
                200,
                &format!(
                    r#"[{{"id":"{VAULT_ID}","name":"{VAULT_NAME}","size":42,"etag":"aaaa",
                          "updated_at":"2026-08-07T10:00:00Z","host":null,"saved_at":null}}]"#
                ),
            )
        });
        let listed = nulls.client().list().expect("list failed");
        assert_eq!(listed[0].host, None);
        assert_eq!(listed[0].saved_at, None);

        let omitted = FakeServer::new(|_| {
            Reply::json(
                200,
                &format!(
                    r#"[{{"id":"{VAULT_ID}","name":"{VAULT_NAME}","size":42,"etag":"aaaa",
                          "updated_at":"2026-08-07T10:00:00Z"}}]"#
                ),
            )
        });
        let listed = omitted.client().list().expect("list failed");
        assert_eq!(listed[0].host, None);
        assert_eq!(listed[0].saved_at, None);
    }

    #[test]
    fn exists_reflects_the_listing() {
        let present = FakeServer::new(|_| Reply::json(200, &format!("[{}]", vault_json("aaaa"))));
        assert!(ServerStorage::by_name(present.client(), VAULT_NAME).exists());

        let absent = FakeServer::new(|_| Reply::json(200, "[]"));
        assert!(!ServerStorage::by_name(absent.client(), VAULT_NAME).exists());
    }

    #[test]
    fn exists_is_false_when_the_server_is_unreachable() {
        // Bind and drop, so the port is almost certainly free and refusing.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let client = Arc::new(ServerClient::with_token(&format!("http://{addr}"), TOKEN));

        assert!(!ServerStorage::by_name(client, VAULT_NAME).exists());
    }

    #[test]
    fn unreachable_server_reads_as_a_network_error() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let client = Arc::new(ServerClient::with_token(&format!("http://{addr}"), TOKEN));

        match ServerStorage::by_name(client, VAULT_NAME).read() {
            Err(StorageError::Network(_)) => {}
            other => panic!("expected Network, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn location_names_the_vault_and_its_host() {
        let client = Arc::new(ServerClient::with_token(
            "https://askrypt.example.com/",
            TOKEN,
        ));
        let storage = ServerStorage::by_name(client, VAULT_NAME);

        assert_eq!(storage.location(), "My Vault.askrypt @ askrypt.example.com");
    }

    #[test]
    fn vault_roundtrip_through_a_trait_object() {
        // A fake that actually stores the bytes, so the trait's default
        // save_vault/load_vault are exercised end to end over HTTP.
        let stored: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let server_stored = Arc::clone(&stored);
        let server = FakeServer::new(move |request| {
            let mut stored = server_stored.lock().unwrap();
            match (request.method.as_str(), stored.is_some()) {
                ("POST", _) => {
                    *stored = Some(request.body.clone());
                    Reply::json(201, &vault_json("etag-1"))
                }
                ("PUT", _) => {
                    *stored = Some(request.body.clone());
                    Reply::json(200, &vault_json("etag-2"))
                }
                // The listing route and the download route are both GETs; the
                // listing is the one without an id in the path.
                ("GET", _) if request.target == "/api/v1/vaults" => match stored.as_ref() {
                    Some(_) => Reply::json(200, &format!("[{}]", vault_json("etag-1"))),
                    None => Reply::json(200, "[]"),
                },
                ("GET", true) => {
                    Reply::new(200, stored.clone().unwrap()).with_header("ETag", "\"etag-1\"")
                }
                _ => Reply::json(404, &error_json("not_found", "no such vault")),
            }
        });

        let (file, secrets) = test_vault();
        let storage: Box<dyn VaultStorage> =
            Box::new(ServerStorage::by_name(server.client(), VAULT_NAME));

        assert!(!storage.exists());
        storage.save_vault(&file).expect("save failed");
        assert!(storage.exists());

        let loaded = storage.load_vault().expect("load failed");
        assert_eq!(loaded, file);

        // The bytes survived the round trip well enough to decrypt.
        let questions_data = loaded.get_questions_data("Smith".into()).unwrap();
        let decrypted = loaded
            .decrypt(&questions_data, vec!["Fluffy".to_string()])
            .unwrap();
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn a_second_device_cannot_clobber_the_first() {
        // A fake that enforces If-Match the way the real server does, so this
        // exercises the whole conflict protocol rather than a canned 412.
        let etag: Arc<Mutex<String>> = Arc::new(Mutex::new("v1".to_string()));
        let server_etag = Arc::clone(&etag);
        let server = FakeServer::new(move |request| {
            let mut etag = server_etag.lock().unwrap();
            match request.method.as_str() {
                "GET" if request.target == "/api/v1/vaults" => {
                    Reply::json(200, &format!("[{}]", vault_json(&etag)))
                }
                "GET" => Reply::new(200, b"PK\x03\x04stored".to_vec())
                    .with_header("ETag", &format!("\"{}\"", etag)),
                "PUT" => {
                    let sent = request.header("if-match").map(unquote_etag);
                    if sent.as_deref() != Some(etag.as_str()) {
                        return Reply::json(
                            412,
                            &error_json(
                                "precondition_failed",
                                "the stored vault changed since it was last fetched",
                            ),
                        );
                    }
                    // A successful write moves the vault on to a new version.
                    *etag = "v2".to_string();
                    Reply::json(200, &vault_json(&etag))
                }
                _ => Reply::json(404, &error_json("not_found", "no such vault")),
            }
        });

        let client = server.client();
        // Two devices open the same vault at v1.
        let first = ServerStorage::by_name(Arc::clone(&client), VAULT_NAME);
        let second = ServerStorage::by_name(client, VAULT_NAME);
        first.read().expect("first read failed");
        second.read().expect("second read failed");

        // The first one saves, moving the server to v2.
        first.write(b"PK\x03\x04first").expect("first write failed");

        // The second is still holding v1, so its save must be refused rather
        // than silently discarding the first device's edit.
        match second.write(b"PK\x03\x04second") {
            Err(StorageError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {:?}", other.map(|_| ())),
        }

        // Re-reading picks up v2, and then the write goes through.
        second.read().expect("re-read failed");
        second
            .write(b"PK\x03\x04second")
            .expect("write after reload failed");
    }

    #[test]
    fn etag_quoting_round_trips() {
        assert_eq!(unquote_etag("\"abc\""), "abc");
        assert_eq!(unquote_etag("W/\"abc\""), "abc");
        assert_eq!(unquote_etag("abc"), "abc");
        assert_eq!(quote_etag("abc"), "\"abc\"");
        // Already-quoted input must not gain a second pair of quotes.
        assert_eq!(quote_etag("\"abc\""), "\"abc\"");
    }

    #[test]
    fn percent_encoding_covers_the_characters_a_name_may_contain() {
        assert_eq!(percent_encode("MyVault.askrypt"), "MyVault.askrypt");
        assert_eq!(percent_encode("My Vault.askrypt"), "My%20Vault.askrypt");
        assert_eq!(percent_encode("a&b=c?d#e"), "a%26b%3Dc%3Fd%23e");
        assert_eq!(percent_encode("сейф"), "%D1%81%D0%B5%D0%B9%D1%84");
    }

    #[test]
    fn base_url_trailing_slash_is_ignored() {
        assert_eq!(
            normalize_base_url("https://example.com/"),
            "https://example.com"
        );
        assert_eq!(
            normalize_base_url("  https://example.com  "),
            "https://example.com"
        );
    }

    #[test]
    fn debug_output_never_leaks_the_token() {
        let client = ServerClient::with_token("https://example.com", "super-secret-token");
        let debug = format!("{client:?}");

        assert!(
            !debug.contains("super-secret-token"),
            "token leaked: {debug}"
        );
        assert!(debug.contains("example.com"));
    }

    // -----------------------------------------------------------------------
    // Browser sign-in
    // -----------------------------------------------------------------------

    const LINK_ID: &str = "9f8e7d6c-5b4a-4938-8271-605f4e3d2c1b";

    fn start_link_json() -> String {
        format!(
            r#"{{"link_id":"{LINK_ID}","poll_token":"poll-secret","user_code":"K4PZ-9QT2",
                "verification_path":"/link/{LINK_ID}","expires_in":86400,"interval":3}}"#
        )
    }

    #[test]
    fn beginning_a_browser_login_asks_for_a_link_and_builds_the_url() {
        let server = FakeServer::new(|_| Reply::json(201, &start_link_json()));

        let login = ServerClient::begin_browser_login(&server.url(), Some("ubuntu@mypc"))
            .expect("begin failed");

        assert_eq!(login.user_code(), "K4PZ-9QT2");
        assert_eq!(
            login.verification_url(),
            format!("{}/link/{LINK_ID}", server.url())
        );
        assert_eq!(login.poll_interval(), Duration::from_secs(3));
        assert_eq!(login.expires_in(), 86400);

        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/v1/auth/device");
        // The device label is how the account's device list names this machine.
        let sent: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(sent["device_label"], "ubuntu@mypc");
    }

    #[test]
    fn a_verification_path_that_is_not_a_path_is_refused() {
        // A hostile server would otherwise get the client to open the user's
        // browser at somebody else's site.
        for hostile in [
            "//evil.example/x",
            "https://evil.example/x",
            "javascript:alert(1)",
        ] {
            assert!(
                verification_url("https://askrypt.example.com", hostile).is_err(),
                "{hostile} should have been refused",
            );
        }
        assert_eq!(
            verification_url("https://askrypt.example.com", "/link/abc").unwrap(),
            "https://askrypt.example.com/link/abc"
        );
    }

    #[test]
    fn polling_reports_pending_then_hands_over_the_session() {
        let approved = Arc::new(AtomicBool::new(false));
        let server_flag = Arc::clone(&approved);
        let server = FakeServer::new(move |request| {
            if request.target == "/api/v1/auth/device" {
                return Reply::json(201, &start_link_json());
            }
            if server_flag.load(Ordering::SeqCst) {
                Reply::json(
                    200,
                    r#"{"status":"approved","token":"tok-xyz",
                        "expires_at":"2026-09-06T10:00:00Z",
                        "account":{"id":"a","email":"me@example.com"}}"#,
                )
            } else {
                Reply::json(200, r#"{"status":"pending"}"#)
            }
        });

        let login = ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");

        assert!(matches!(
            login.poll().expect("poll failed"),
            BrowserLoginStatus::Pending
        ));

        approved.store(true, Ordering::SeqCst);
        match login.poll().expect("poll failed") {
            BrowserLoginStatus::Approved { client, email } => {
                assert_eq!(client.token(), "tok-xyz");
                assert_eq!(client.base_url(), server.url());
                assert_eq!(email, "me@example.com");
            }
            other => panic!("expected Approved, got {other:?}"),
        }

        // The poll is authenticated by the poll token alone — no bearer header
        // exists yet to carry.
        let poll = &server.requests()[1];
        assert_eq!(poll.target, "/api/v1/auth/device/poll");
        assert!(poll.header("Authorization").is_none());
        let sent: serde_json::Value = serde_json::from_slice(&poll.body).unwrap();
        assert_eq!(sent["poll_token"], "poll-secret");
    }

    #[test]
    fn denied_and_expired_are_outcomes_rather_than_errors() {
        for (status, expected) in [("denied", "Denied"), ("expired", "Expired")] {
            let body = format!(r#"{{"status":"{status}"}}"#);
            let server = FakeServer::new(move |request| {
                if request.target == "/api/v1/auth/device" {
                    Reply::json(201, &start_link_json())
                } else {
                    Reply::json(200, &body)
                }
            });

            let login =
                ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");
            let outcome = login.poll().expect("poll must not fail");
            assert!(
                format!("{outcome:?}").starts_with(expected),
                "expected {expected}, got {outcome:?}",
            );
        }
    }

    #[test]
    fn an_unknown_status_keeps_the_client_waiting() {
        // A newer server growing a status this build has never heard of must
        // not turn into a parse error mid-sign-in.
        let server = FakeServer::new(|request| {
            if request.target == "/api/v1/auth/device" {
                Reply::json(201, &start_link_json())
            } else {
                Reply::json(200, r#"{"status":"something_new"}"#)
            }
        });

        let login = ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");
        assert!(matches!(
            login.poll().expect("poll failed"),
            BrowserLoginStatus::Pending
        ));
    }

    #[test]
    fn rate_limiting_a_poll_is_reported_as_a_remote_error_not_an_auth_failure() {
        // The caller has to keep polling through a 429; treating it as a
        // terminal failure would abandon a sign-in the user is completing.
        let server = FakeServer::new(|request| {
            if request.target == "/api/v1/auth/device" {
                Reply::json(201, &start_link_json())
            } else {
                Reply::json(429, &error_json("rate_limited", "too many requests"))
            }
        });

        let login = ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");
        match login.poll() {
            Err(StorageError::Remote { status, code, .. }) => {
                assert_eq!(status, 429);
                assert_eq!(code, "rate_limited");
            }
            other => panic!("expected Remote 429, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn an_approval_without_a_session_is_a_format_error() {
        let server = FakeServer::new(|request| {
            if request.target == "/api/v1/auth/device" {
                Reply::json(201, &start_link_json())
            } else {
                Reply::json(200, r#"{"status":"approved"}"#)
            }
        });

        let login = ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");
        assert!(matches!(login.poll(), Err(StorageError::Format(_))));
    }

    #[test]
    fn browser_login_debug_never_leaks_the_poll_token() {
        let server = FakeServer::new(|_| Reply::json(201, &start_link_json()));
        let login = ServerClient::begin_browser_login(&server.url(), None).expect("begin failed");

        let debug = format!("{login:?}");
        assert!(!debug.contains("poll-secret"), "poll token leaked: {debug}");
        assert!(debug.contains("K4PZ-9QT2"));
    }

    #[test]
    fn browser_login_can_be_polled_from_another_thread() {
        // The desktop UI parks one behind an `Arc` and polls it on a worker.
        fn assert_shared<T: Send + Sync + 'static>() {}
        assert_shared::<BrowserLogin>();
    }
}
