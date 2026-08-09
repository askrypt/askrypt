//! The vault file manager (plan Phase 7.4).
//!
//! A file listing and nothing more: upload, download, rename, replace,
//! delete, the generations each save replaced, and how much of the quota is
//! gone. The site cannot open a vault — there is no decryption in the
//! browser by design — so this page is deliberately shaped like a folder,
//! not like a password manager.
//!
//! The rules are [`crate::vaults`]'s, called as free functions: the name
//! validation, the ZIP-magic check, the count and byte quotas, and the
//! `If-Match` conflict semantics. What this module adds is browser shape —
//! `multipart/form-data` instead of a raw body, an ETag carried in a hidden
//! field instead of a header, and a "changed on another device" message
//! instead of a bare 412.

use std::cmp::Reverse;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::ApiError;
use crate::state::AppState;
use crate::store::{VaultMeta, VaultVersion};
use crate::vaults::{
    ACCOUNT_QUOTA_BYTES, MAX_VAULT_BYTES, MAX_VAULT_VERSIONS, MAX_VAULTS_PER_ACCOUNT,
    parse_vault_id, parse_version_id,
};
use crate::web::WebResult;
use crate::web::csrf::{CsrfForm, CsrfMultipart};
use crate::web::flash::{self, Flash};
use crate::web::render::{self, Chrome, Page, Shell, is_htmx, timestamp, with_cookies};
use crate::web::session::WebSession;

pub const VAULTS_PATH: &str = "/vaults";

#[derive(Template)]
#[template(path = "vaults.html")]
struct VaultsPage {
    chrome: Chrome,
    listing: Listing,
    upload: UploadForm,
}

/// The table plus the usage figures. Every mutation re-renders this whole
/// fragment rather than a single row: a change moves the totals too, and one
/// swap keeps them honest.
#[derive(Template)]
#[template(path = "fragments/vault_list.html")]
pub struct Listing {
    csrf: String,
    vaults: Vec<Row>,
    count: usize,
    max_count: usize,
    /// How many superseded generations each file keeps.
    max_versions: usize,
    used: String,
    /// The share of `used` held by superseded generations.
    archived: String,
    quota: String,
    /// Percentage of the byte quota in use, for the meter.
    used_percent: u64,
    notice: Option<Notice>,
}

#[derive(Template)]
#[template(path = "fragments/vault_upload.html")]
pub struct UploadForm {
    csrf: String,
    max_size: String,
    error: Option<String>,
}

struct Row {
    id: String,
    name: String,
    size: String,
    updated: String,
    /// Where and when the file itself says it was saved, `None` when it
    /// carries no stamp. This is the client's own account of the save; the
    /// `updated` column is the server's account of the upload.
    saved: Option<String>,
    /// First 12 hex characters of the content hash — enough to tell two
    /// versions apart by eye, and it is not a secret.
    short_etag: String,
    /// The full ETag, carried in the replace form so the overwrite goes
    /// through the same `If-Match` check the apps use.
    etag: String,
    /// The kept generations of this file, newest first.
    history: Vec<HistoryRow>,
}

impl Row {
    fn new(meta: &VaultMeta, history: &[VaultVersion]) -> Self {
        Self {
            id: meta.id.to_string(),
            name: meta.name.clone(),
            size: human_bytes(meta.size),
            updated: timestamp(meta.updated_at),
            saved: saved_stamp(meta.host.as_deref(), meta.saved_at),
            short_etag: meta.etag.chars().take(12).collect(),
            etag: meta.etag.clone(),
            history: history.iter().map(HistoryRow::from).collect(),
        }
    }
}

/// One superseded generation, as a line in a row's history disclosure.
struct HistoryRow {
    id: String,
    size: String,
    /// When these bytes stopped being the current file — the useful date
    /// when picking which one to go back to.
    archived: String,
    short_etag: String,
    /// The write stamp these bytes carry, as on the live row. Picking a
    /// version to go back to is much easier when the line says which device
    /// wrote it.
    saved: Option<String>,
}

impl From<&VaultVersion> for HistoryRow {
    fn from(version: &VaultVersion) -> Self {
        Self {
            id: version.id.to_string(),
            size: human_bytes(version.size),
            archived: timestamp(version.archived_at),
            short_etag: version.etag.chars().take(12).collect(),
            saved: saved_stamp(version.host.as_deref(), version.saved_at),
        }
    }
}

/// The file's own "saved here, then" line, as one cell's worth of text.
///
/// The two halves are independent — an older app writes neither, a file with
/// an unreadable timestamp still names its host — so each combination gets a
/// sentence and a file that says nothing gets `None` rather than a row of
/// placeholders.
fn saved_stamp(host: Option<&str>, saved_at: Option<DateTime<Utc>>) -> Option<String> {
    match (host, saved_at) {
        (Some(host), Some(at)) => Some(format!("{host} · {}", timestamp(at))),
        (Some(host), None) => Some(host.to_string()),
        (None, Some(at)) => Some(timestamp(at)),
        (None, None) => None,
    }
}

/// A message rendered above the table: the outcome of the last change, or
/// why it was refused.
pub struct Notice {
    text: String,
    danger: bool,
}

/// `GET /vaults`
pub async fn page(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
) -> WebResult<Response> {
    let (chrome, cookies) = Shell::build(&headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    let page = VaultsPage {
        listing: listing(&state, &web, chrome.csrf.clone(), None).await?,
        upload: UploadForm {
            csrf: chrome.csrf.clone(),
            max_size: human_bytes(MAX_VAULT_BYTES as u64),
            error: None,
        },
        chrome,
    };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

/// `POST /vaults` — upload a new vault file.
///
/// The name defaults to the uploaded file's own name, which is what a
/// visitor expects and what the desktop app would have sent.
pub async fn upload(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
    CsrfMultipart(form): CsrfMultipart,
) -> WebResult<Response> {
    let name = match form.field("name") {
        "" => form.file_name.clone().unwrap_or_default(),
        typed => typed.to_string(),
    };
    match crate::vaults::create(&state, web.account.id, &name, &form.file).await {
        Ok(_) => finish(&state, &web, &headers, Flash::VaultUploaded).await,
        Err(err) => refused(&state, &web, &headers, err).await,
    }
}

/// `POST /vaults/{id}/replace` — overwrite a vault with a newer file.
pub async fn replace(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
    Path(id): Path<String>,
    CsrfMultipart(form): CsrfMultipart,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    // The ETag the row was rendered with. Missing rather than stale would
    // mean a hand-made form, so it is treated as a mismatch, not as `*`.
    let expected = form.field("etag").to_string();
    match crate::vaults::overwrite(
        &state,
        web.account.id,
        vault_id,
        Some(&expected),
        &form.file,
    )
    .await
    {
        Ok(_) => finish(&state, &web, &headers, Flash::VaultReplaced).await,
        Err(err) => refused(&state, &web, &headers, err).await,
    }
}

#[derive(Deserialize)]
pub struct RenameInput {
    #[serde(default)]
    name: String,
}

/// `POST /vaults/{id}/name` — rename a vault file.
pub async fn rename(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
    Path(id): Path<String>,
    CsrfForm(input): CsrfForm<RenameInput>,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    match crate::vaults::set_name(&state, web.account.id, vault_id, &input.name).await {
        Ok(_) => finish(&state, &web, &headers, Flash::VaultRenamed).await,
        Err(err) => refused(&state, &web, &headers, err).await,
    }
}

/// A form carrying nothing but its CSRF token.
#[derive(Deserialize)]
pub struct TokenOnly {}

/// `POST /vaults/{id}/delete`
pub async fn remove(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<TokenOnly>,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    match crate::vaults::destroy(&state, web.account.id, vault_id).await {
        Ok(()) => finish(&state, &web, &headers, Flash::VaultDeleted).await,
        Err(err) => refused(&state, &web, &headers, err).await,
    }
}

/// `GET /vaults/{id}/download` — the encrypted bytes, as a file.
///
/// A browser cannot set an `Authorization` header on a plain link, which is
/// the whole reason this route exists next to the API's: same bytes, cookie
/// authentication, and a `Content-Disposition` so the file lands in the
/// downloads folder under its own name.
pub async fn download(
    State(state): State<AppState>,
    web: WebSession,
    Path(id): Path<String>,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let (meta, bytes) = crate::vaults::read(&state, web.account.id, vault_id).await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", sanitize_filename(&meta.name)),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `POST /vaults/{id}/versions/{version_id}/restore` — make a superseded
/// generation the current file again.
///
/// The row's ETag rides along in a hidden field, exactly as `replace` does:
/// restoring is an overwrite, and it must lose the same race for the same
/// reason.
pub async fn restore(
    State(state): State<AppState>,
    web: WebSession,
    headers: HeaderMap,
    Path((id, version_id)): Path<(String, String)>,
    CsrfForm(input): CsrfForm<RestoreInput>,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let version_id = parse_version_id(&version_id)?;
    match crate::vaults::restore_version(
        &state,
        web.account.id,
        vault_id,
        version_id,
        Some(&input.etag),
    )
    .await
    {
        Ok(_) => finish(&state, &web, &headers, Flash::VaultRestored).await,
        Err(err) => refused(&state, &web, &headers, err).await,
    }
}

#[derive(Deserialize)]
pub struct RestoreInput {
    /// The current file's ETag as the row was drawn. Missing rather than
    /// stale means a hand-made form, so it is treated as a mismatch.
    #[serde(default)]
    etag: String,
}

/// `GET /vaults/{id}/versions/{version_id}/download` — an archived
/// generation, as a file.
///
/// Same cookie-authenticated shape as [`download`]; the file name carries the
/// archived date so several downloaded generations don't collide in the
/// downloads folder.
pub async fn download_version(
    State(state): State<AppState>,
    web: WebSession,
    Path((id, version_id)): Path<(String, String)>,
) -> WebResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let version_id = parse_version_id(&version_id)?;
    let (version, bytes) =
        crate::vaults::read_version(&state, web.account.id, vault_id, version_id).await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    sanitize_filename(&version_filename(&version))
                ),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `personal.askrypt` archived on 2026-08-08 becomes
/// `personal.2026-08-08T101500Z.askrypt` — the stem keeps the file
/// recognizable, the stamp keeps generations apart, and the extension stays
/// where apps look for it.
fn version_filename(version: &VaultVersion) -> String {
    let stamp = version.archived_at.format("%Y-%m-%dT%H%M%SZ");
    match version.name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.{stamp}.{ext}"),
        _ => format!("{}.{stamp}", version.name),
    }
}

/// A change that went through: the refreshed listing for htmx, a
/// POST-redirect-GET with a flash otherwise.
async fn finish(
    state: &AppState,
    web: &WebSession,
    headers: &HeaderMap,
    flash: Flash,
) -> WebResult<Response> {
    if !is_htmx(headers) {
        return Ok(render::redirect_either_way(
            headers,
            VAULTS_PATH,
            vec![flash::set(flash)],
        ));
    }
    let (chrome, cookies) = Shell::build(headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    let notice = Notice {
        text: flash.message().to_string(),
        danger: false,
    };
    let listing = listing(state, web, chrome.csrf.clone(), Some(notice)).await?;
    Ok(with_cookies(Page(listing).into_response(), cookies))
}

/// A change that was refused. The listing comes back either way — the point
/// of the message is what the files look like *now*, which for a stale ETag
/// is precisely the question.
async fn refused(
    state: &AppState,
    web: &WebSession,
    headers: &HeaderMap,
    err: ApiError,
) -> WebResult<Response> {
    // A backend failure is not a message about the visitor's files; it goes
    // through `WebError`, which replaces 5xx wording wholesale.
    if err.status.is_server_error() {
        return Err(err.into());
    }
    let notice = Notice {
        text: explain(&err),
        danger: true,
    };
    let (chrome, cookies) = Shell::build(headers, Some(web.account.email.clone()))
        .as_admin(web.is_admin)
        .into_parts();
    let listing = listing(state, web, chrome.csrf.clone(), Some(notice)).await?;
    if is_htmx(headers) {
        return Ok(with_cookies(Page(listing).into_response(), cookies));
    }
    let page = VaultsPage {
        upload: UploadForm {
            csrf: chrome.csrf.clone(),
            max_size: human_bytes(MAX_VAULT_BYTES as u64),
            error: None,
        },
        listing,
        chrome,
    };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

/// Turns an [`ApiError`] into something worth reading on a page.
///
/// The API's wording is written for a developer reading JSON; the three
/// cases a visitor actually hits get a sentence instead. A 5xx never reaches
/// here — [`crate::web::WebError`] replaces those wholesale — so nothing
/// internal can leak through this.
fn explain(err: &ApiError) -> String {
    match err.code {
        "precondition_failed" => "This vault changed on another device since this page was \
             loaded. Reload to see the current file before replacing it."
            .to_string(),
        "quota_exceeded" => format!(
            "That would put you over your {} of storage. Delete a vault first.",
            human_bytes(ACCOUNT_QUOTA_BYTES)
        ),
        "vault_limit_reached" => {
            format!("You already have the maximum of {MAX_VAULTS_PER_ACCOUNT} vault files.")
        }
        // Written without an apostrophe on purpose: askama escapes it to
        // `&#39;`, which is correct HTML and unpleasant to read in a test.
        "invalid_vault_file" => {
            "That file is not an Askrypt vault. Vaults are the .askrypt files your app saves."
                .to_string()
        }
        "payload_too_large" => format!(
            "Vault files are limited to {}.",
            human_bytes(MAX_VAULT_BYTES as u64)
        ),
        _ => err.message.clone(),
    }
}

async fn listing(
    state: &AppState,
    web: &WebSession,
    csrf: String,
    notice: Option<Notice>,
) -> WebResult<Listing> {
    let mut metas = crate::vaults::list_for(state, web.account.id).await?;
    // The table reads newest-change-first: the file someone just saved from
    // another device is the one they came here to look at. `list_for` hands
    // them over name-sorted, so equal timestamps keep that order.
    metas.sort_by_key(|meta| Reverse(meta.updated_at));
    // One query for the whole page's history, not one per row.
    let mut history = crate::vaults::versions_by_vault(state, web.account.id).await?;
    let live: u64 = metas.iter().map(|m| m.size).sum();
    // History shares the account's quota, so the meter has to count it or it
    // would read as free space that isn't.
    let archived: u64 = history.values().flatten().map(|v| v.size).sum();
    let used = live + archived;
    Ok(Listing {
        csrf,
        vaults: metas
            .iter()
            .map(|meta| {
                Row::new(
                    meta,
                    history.remove(&meta.id).unwrap_or_default().as_slice(),
                )
            })
            .collect(),
        count: metas.len(),
        max_count: MAX_VAULTS_PER_ACCOUNT,
        max_versions: MAX_VAULT_VERSIONS,
        used: human_bytes(used),
        archived: human_bytes(archived),
        quota: human_bytes(ACCOUNT_QUOTA_BYTES),
        used_percent: (used.saturating_mul(100) / ACCOUNT_QUOTA_BYTES).min(100),
        notice,
    })
}

/// Sizes as a person reads them. Vaults are tens of KB, so one decimal is
/// plenty and there is no need to go past MiB.
fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    match bytes {
        0..KIB => format!("{bytes} B"),
        KIB..MIB => format!("{:.1} KB", bytes as f64 / KIB as f64),
        _ => format!("{:.1} MB", bytes as f64 / MIB as f64),
    }
}

/// Keeps a stored name from breaking out of the `Content-Disposition`
/// quoting. `validate_name` already refuses control characters and path
/// separators; quotes and backslashes are what is left.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '"' && *c != '\\')
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_the_way_a_person_expects() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(10 * 1024 * 1024), "10.0 MB");
    }

    #[test]
    fn the_saved_cell_says_what_the_file_knows_and_no_more() {
        let at = DateTime::parse_from_rfc3339("2026-08-08T10:15:30Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            saved_stamp(Some("lenovo-x1"), Some(at)).as_deref(),
            Some("lenovo-x1 · 2026-08-08 10:15 UTC")
        );
        assert_eq!(
            saved_stamp(Some("lenovo-x1"), None).as_deref(),
            Some("lenovo-x1")
        );
        assert_eq!(
            saved_stamp(None, Some(at)).as_deref(),
            Some("2026-08-08 10:15 UTC")
        );
        // A file that carries no stamp gets no cell text at all — the
        // template shows "Not recorded" rather than an empty date.
        assert_eq!(saved_stamp(None, None), None);
    }

    #[test]
    fn a_filename_cannot_escape_the_content_disposition_quoting() {
        assert_eq!(sanitize_filename("my\"vault\\.askrypt"), "myvault.askrypt");
    }

    #[test]
    fn the_conflict_is_explained_rather_than_shown_as_a_412() {
        let message = explain(&ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "the stored vault changed since it was last fetched",
        ));
        assert!(message.contains("another device"), "{message}");
    }
}
