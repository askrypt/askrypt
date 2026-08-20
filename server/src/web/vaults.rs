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
//!
//! [`check_upload`] is the one rule that is this module's own rather than a
//! stricter reading of one of those, and it is here because the difference is
//! the browser: a file arriving on the API was written by the app that is
//! sending it, while a file arriving here was picked out of a folder by hand.
//! So the two ways of picking the wrong one — the wrong extension and an
//! archive that is not a vault — are caught before anything is stored.

use std::cmp::Reverse;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

use crate::error::ApiError;
use crate::state::AppState;
use crate::store::{VaultMeta, VaultVersion};
use crate::vaults::{
    MAX_VAULT_BYTES, MAX_VAULT_VERSIONS, MAX_VAULTS_PER_ACCOUNT, parse_vault_id, parse_version_id,
};
use crate::web::WebResult;
use crate::web::csrf::{CsrfForm, CsrfMultipart};
use crate::web::flash::{self, Flash};
use crate::web::render::{self, Page, Shell, is_htmx, timestamp, with_cookies};
use crate::web::session::WebSession;
use crate::web::types::{HistoryRow, Row, VaultsPage};

pub use crate::web::types::{Listing, Notice, RenameInput, RestoreInput, TokenOnly, UploadForm};

pub const VAULTS_PATH: &str = "/vaults";

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
pub(crate) fn saved_stamp(host: Option<&str>, saved_at: Option<DateTime<Utc>>) -> Option<String> {
    match (host, saved_at) {
        (Some(host), Some(at)) => Some(format!("{host} · {}", timestamp(at))),
        (Some(host), None) => Some(host.to_string()),
        (None, Some(at)) => Some(timestamp(at)),
        (None, None) => None,
    }
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
    // The picked file's own name, which is what the extension is about; the
    // typed name stands in only for a client that sent no file name at all.
    let picked = form.file_name.as_deref().unwrap_or(name.as_str());
    if let Err(err) = check_upload(picked, &form.file) {
        return refused(&state, &web, &headers, err).await;
    }
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
    // Replacing is picking a file out of a folder too, and the file it lands
    // on is one the visitor already cares about, so the same gate applies.
    if let Err(err) = check_upload(form.file_name.as_deref().unwrap_or_default(), &form.file) {
        return refused(&state, &web, &headers, err).await;
    }
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
                format!(
                    "attachment; filename=\"{}\"",
                    sanitize_filename(&download_filename(&meta.name))
                ),
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
///
/// The name is put through [`download_filename`] first, so a vault stored
/// under a bare name gets its extension here too rather than landing as
/// `personal.2026-08-08T101500Z`.
fn version_filename(version: &VaultVersion) -> String {
    let stamp = version.archived_at.format("%Y-%m-%dT%H%M%SZ");
    let name = download_filename(&version.name);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.{stamp}.{ext}"),
        _ => format!("{name}.{stamp}"),
    }
}

/// The name a downloaded vault lands under.
///
/// A stored name need not carry the extension: the desktop app addresses a
/// server vault by a bare name, so `personal` is the common case rather than
/// the odd one, and a browser saves exactly what this header says. Appending
/// `.askrypt` when it is absent is what makes the downloaded file open on a
/// double-click and re-upload without being refused by [`check_upload`]. A
/// name that already ends in it — in whatever case it came back in — is left
/// alone, so nothing ever gets `.askrypt.askrypt`.
fn download_filename(name: &str) -> String {
    if vault_extension_stem(name).is_some() {
        return name.to_string();
    }
    format!("{name}{VAULT_EXTENSION}")
}

/// Splits the vault extension off a name, case-insensitively, returning what
/// precedes it. `None` when the name does not end in one — including when it
/// is shorter than the extension, and when the extension's length lands
/// inside a multi-byte character, which is why the boundary is tested rather
/// than the name sliced.
fn vault_extension_stem(name: &str) -> Option<&str> {
    let stem = name.len().checked_sub(VAULT_EXTENSION.len())?;
    (name.is_char_boundary(stem) && name[stem..].eq_ignore_ascii_case(VAULT_EXTENSION))
        .then(|| &name[..stem])
}

/// The extension every app writes a vault under. Matched case-insensitively:
/// the apps write it in lower case, but a file that has been round-tripped
/// through Windows, a mail client or a cloud drive can come back shouting.
const VAULT_EXTENSION: &str = ".askrypt";

/// Refuses a browser upload that is not a vault file, before it is stored.
///
/// Two things are checked, and they catch different mistakes. The extension
/// catches the wrong file entirely — the `.zip` next to it in the folder, a
/// photo, a text file — and it is checked against the *uploaded file's* name,
/// not the name the vault will be stored under: those differ on purpose (the
/// desktop app stores server vaults under a bare name, no extension), and it
/// is the thing on disk this is about. The contents then have to actually be
/// a vault archive, since an extension is a claim and nothing more.
///
/// A missing file part reads as an empty name and empty bytes, so it is
/// refused here rather than being stored as a zero-byte vault.
fn check_upload(file_name: &str, bytes: &[u8]) -> Result<(), ApiError> {
    let name = file_name.trim();
    // A bare `.askrypt` is an extension with nothing in front of it, so the
    // stem has to be non-empty.
    let named_like_a_vault = vault_extension_stem(name).is_some_and(|stem| !stem.is_empty());
    if !named_like_a_vault {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_vault_extension",
            "vault files are named *.askrypt",
        ));
    }
    if !crate::vaultfile::is_vault(bytes) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_vault_file",
            "not an askrypt vault file",
        ));
    }
    Ok(())
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
    // through `WebError`, which replaces 5xx wording wholesale. Note the
    // test is `is_backend_failure` and not `is_server_error`: the two quota
    // refusals below answer 507, which is a 5xx and is nonetheless exactly
    // the kind of thing this function exists to explain.
    if crate::web::error::is_backend_failure(err.status) {
        return Err(err.into());
    }
    let notice = Notice {
        // The quota sentence names the account's own allowance, so it has to
        // be looked up rather than read off a constant.
        text: explain(&err, crate::vaults::quota_for(state, web.account.id).await?),
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
        },
        listing,
        chrome,
    };
    Ok(with_cookies(Page(page).into_response(), cookies))
}

/// Turns an [`ApiError`] into something worth reading on a page.
///
/// The API's wording is written for a developer reading JSON; the cases a
/// visitor actually hits get a sentence instead. A backend failure never
/// reaches here — [`crate::web::WebError`] replaces those wholesale — so
/// nothing internal can leak through this.
fn explain(err: &ApiError, quota: u64) -> String {
    match err.code {
        "precondition_failed" => "This vault changed on another device since this page was \
             loaded. Reload to see the current file before replacing it."
            .to_string(),
        "quota_exceeded" => format!(
            "That would put you over your {} of storage. Delete a vault first.",
            human_bytes(quota)
        ),
        "vault_limit_reached" => {
            format!("You already have the maximum of {MAX_VAULTS_PER_ACCOUNT} vault files.")
        }
        // Written without an apostrophe on purpose: askama escapes it to
        // `&#39;`, which is correct HTML and unpleasant to read in a test.
        "invalid_vault_extension" => {
            "That file is not an Askrypt vault. Vaults are the .askrypt files your app saves."
                .to_string()
        }
        // The name promised a vault and the bytes did not deliver one, which
        // is worth saying differently: the file is plausibly the right kind
        // of thing and is still not openable.
        "invalid_vault_file" => "That file is not an Askrypt vault. It is missing the \
             askrypt.json every vault archive contains, so no app could open it."
            .to_string(),
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
    // The account's own allowance, which the paid tier raises.
    let quota = crate::vaults::quota_for(state, web.account.id).await?;
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
        quota: human_bytes(quota),
        used_percent: (used.saturating_mul(100) / quota).min(100),
        notice,
    })
}

/// Sizes as a person reads them. Vaults are tens of KB, so one decimal is
/// plenty and there is no need to go past MiB. Shared with
/// [`crate::web::admin`], so the storage figures read alike on both pages.
pub(crate) fn human_bytes(bytes: u64) -> String {
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
    use crate::vaults::{ACCOUNT_QUOTA_BYTES, PAID_ACCOUNT_QUOTA_BYTES};

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

    /// A vault stored under a bare name — which is how the desktop app stores
    /// them — still has to land in the downloads folder as a `.askrypt` file.
    #[test]
    fn a_download_always_carries_the_vault_extension() {
        assert_eq!(download_filename("personal"), "personal.askrypt");
        assert_eq!(download_filename("personal.askrypt"), "personal.askrypt");
        // Already named like a vault, whatever case it came back in.
        assert_eq!(download_filename("PERSONAL.ASKRYPT"), "PERSONAL.ASKRYPT");
        // A dot in the name is not an extension; only ours counts.
        assert_eq!(download_filename("personal.zip"), "personal.zip.askrypt");
        // Shorter than the extension, and ending mid-character: neither may
        // panic, and both get the extension.
        assert_eq!(download_filename("p"), "p.askrypt");
        assert_eq!(download_filename("сейф"), "сейф.askrypt");
    }

    #[test]
    fn an_archived_generation_keeps_its_extension_too() {
        let archived_at = DateTime::parse_from_rfc3339("2026-08-08T10:15:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let named = |name: &str| {
            version_filename(&VaultVersion {
                id: uuid::Uuid::nil(),
                vault_id: uuid::Uuid::nil(),
                account_id: uuid::Uuid::nil(),
                name: name.to_string(),
                size: 0,
                etag: String::new(),
                updated_at: archived_at,
                archived_at,
                host: None,
                saved_at: None,
            })
        };
        assert_eq!(
            named("personal.askrypt"),
            "personal.2026-08-08T101500Z.askrypt"
        );
        // The bare name the desktop app stores under gets the same shape.
        assert_eq!(named("personal"), "personal.2026-08-08T101500Z.askrypt");
    }

    #[test]
    fn a_filename_cannot_escape_the_content_disposition_quoting() {
        assert_eq!(sanitize_filename("my\"vault\\.askrypt"), "myvault.askrypt");
    }

    /// A vault-shaped archive: the entry the check looks for, and nothing
    /// else worth reading.
    fn vault_archive() -> Vec<u8> {
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

    #[test]
    fn an_upload_must_be_named_like_a_vault_and_be_one() {
        let vault = vault_archive();
        assert!(check_upload("personal.askrypt", &vault).is_ok());
        // A file that has been through something that shouts.
        assert!(check_upload("PERSONAL.ASKRYPT", &vault).is_ok());
        assert!(check_upload("  personal.askrypt  ", &vault).is_ok());

        // The wrong file out of the folder.
        for name in ["notes.txt", "personal.zip", "personal", "askrypt", ""] {
            let err = check_upload(name, &vault).unwrap_err();
            assert_eq!(err.code, "invalid_vault_extension", "{name:?}");
        }
        // An extension is a claim; the bytes are the evidence.
        let err = check_upload("personal.askrypt", b"just some text").unwrap_err();
        assert_eq!(err.code, "invalid_vault_file");
        // Neither is a form that arrived with no file part at all.
        assert!(check_upload("", b"").is_err());
    }

    /// A name ending in a multi-byte character is shorter than the extension
    /// in bytes at exactly the wrong place; it must be refused, not panicked
    /// on.
    #[test]
    fn a_multibyte_name_is_refused_rather_than_sliced_through() {
        assert!(check_upload("сейф", &vault_archive()).is_err());
        assert!(check_upload("хранилище.askrypt", &vault_archive()).is_ok());
    }

    /// Both refusals name the thing the visitor picked, and neither leaks the
    /// API's code.
    #[test]
    fn a_file_that_is_not_a_vault_is_explained_two_ways() {
        let explain_code = |code| {
            explain(
                &ApiError::new(StatusCode::BAD_REQUEST, code, "not an askrypt vault file"),
                ACCOUNT_QUOTA_BYTES,
            )
        };
        let extension = explain_code("invalid_vault_extension");
        assert!(extension.contains(".askrypt"), "{extension}");
        let contents = explain_code("invalid_vault_file");
        assert!(contents.contains("askrypt.json"), "{contents}");
    }

    #[test]
    fn the_conflict_is_explained_rather_than_shown_as_a_412() {
        let message = explain(
            &ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
                "the stored vault changed since it was last fetched",
            ),
            ACCOUNT_QUOTA_BYTES,
        );
        assert!(message.contains("another device"), "{message}");
    }

    /// The quota sentence quotes the account's own allowance, not a constant,
    /// so a paid account is not told to free up space it has.
    #[test]
    fn the_quota_message_names_the_accounts_own_allowance() {
        let err = || {
            ApiError::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "quota_exceeded",
                "account storage quota exceeded",
            )
        };
        assert!(explain(&err(), ACCOUNT_QUOTA_BYTES).contains("1.0 MB"));
        assert!(explain(&err(), PAID_ACCOUNT_QUOTA_BYTES).contains("100.0 MB"));
    }
}
