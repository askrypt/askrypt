//! Vault cloud-storage endpoints (plan Phase 4).
//!
//! Plain file semantics over HTTP so desktop and mobile apps can sync with
//! a basic HTTP client: raw bytes up (`POST /vaults?name=`, `PUT
//! /vaults/{id}`) and down (`GET /vaults/{id}`), metadata list, rename,
//! delete. Everything is scoped to the authenticated account, and the
//! bytes stay opaque — the only inspection is the ZIP-magic sanity check
//! and the two unencrypted stamp fields [`crate::vaultfile`] reads on the
//! way in, so a listing can say which machine saved a file and when.
//!
//! Optimistic concurrency for multi-device sync: every stored vault has a
//! content-hash ETag, served on upload and download. Overwrites must send
//! `If-Match` (428 without it) and answer 412 when the stored version
//! changed under the client; downloads honor `If-None-Match` with 304.
//!
//! Every save keeps the bytes it replaced: the previous
//! [`MAX_VAULT_VERSIONS`] generations of a vault stay readable through
//! `/{id}/versions`, and any of them can be made current again. History is
//! written on a best-effort basis and trimmed after the fact — a save is
//! never refused, and never fails, because of it.
//!
//! Every operation that moves bytes or changes state leaves a structured
//! log line ([`log_op`] and friends) on this module's own target,
//! `askrypt_server::vaults`. Those lines carry **ids and byte counts only**:
//! never the file name, never the bytes, never the ETag or the write stamp —
//! see [`log_op`] for why each of those is left out.
//!
//! As in [`crate::auth`] and [`crate::profile`], the handlers are wrappers
//! around `pub(crate)` free functions ([`list_for`], [`create`],
//! [`overwrite`], [`set_name`], [`destroy`], [`read`], [`versions_for`],
//! [`read_version`], [`restore_version`]) that take an account id instead of
//! an extractor. The Phase 7.4 file manager in [`crate::web::vaults`] drives
//! those, so the name rules, the ZIP check, the quota arithmetic, the
//! retention rules and the conflict semantics exist once.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AuthSession;
use crate::error::{ApiBytes, ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::store::{AccountId, StoreError, VaultId, VaultMeta, VaultVersion, VaultVersionId};
use crate::vaultfile;

/// Hard cap on a single vault file. Real vaults are small ZIPs (tens of
/// KBs); 10 MiB is deliberately generous. Also enforced as the request
/// body limit on the vault routes.
pub const MAX_VAULT_BYTES: usize = 10 * 1024 * 1024;
/// Total bytes one account may store across all its vaults.
pub const ACCOUNT_QUOTA_BYTES: u64 = 100 * 1024 * 1024;
/// Maximum number of vault files per account.
pub const MAX_VAULTS_PER_ACCOUNT: usize = 100;
/// How many superseded generations of a vault are kept. The newest is the
/// state before the last save, so this many undo steps are available.
pub const MAX_VAULT_VERSIONS: usize = 5;
const MAX_NAME_BYTES: usize = 255;
/// Vault downloads opt out of the blanket `no-store`
/// ([`crate::hardening::no_store`]): the bytes are encrypted, and
/// `no-cache` still forces revalidation while letting the `ETag` round-trip
/// save a re-download. `private` keeps shared caches out of it.
const CACHE_CONTROL_VAULT: &str = "private, no-cache";

/// Operation names for the vault log. Constants rather than literals at the
/// call sites, for the same reason [`crate::audit`] keeps its event names in
/// one place: the vocabulary stays greppable and typo-proof.
mod op {
    pub const CREATED: &str = "vault.created";
    pub const OVERWRITTEN: &str = "vault.overwritten";
    pub const DOWNLOADED: &str = "vault.downloaded";
    pub const RENAMED: &str = "vault.renamed";
    pub const DELETED: &str = "vault.deleted";
    pub const LISTED: &str = "vault.listed";
    pub const VERSION_ARCHIVED: &str = "vault.version.archived";
    pub const VERSION_DOWNLOADED: &str = "vault.version.downloaded";
    pub const VERSION_RESTORED: &str = "vault.version.restored";
    pub const VERSIONS_TRIMMED: &str = "vault.versions.trimmed";
}

/// Records one vault operation: what happened, to which row, for which
/// account, and how many bytes it involved.
///
/// **Identifiers and byte counts, nothing else** — every logging site in this
/// module goes through here or its two siblings so that rule holds in one
/// place. What is deliberately absent, and why:
///
/// - the **name**, because it is text the account holder typed and often says
///   what the vault is for ("work-vpn.askrypt"); a uuid names the same row
///   without describing it;
/// - the **bytes**, which are the secret this server is built never to read;
/// - the **ETag**, a content hash: logging it would let anyone holding the log
///   tell when two files are byte-identical, or when a save put back a
///   previous state, without ever decrypting anything;
/// - the **write stamp** (`host`/`saved_at`), which names the user's machine
///   and is foreign text besides.
///
/// The size stays: it comes from the metadata row rather than the plaintext,
/// it is what explains a quota refusal, and the account already sees it in its
/// own listing.
fn log_op(op: &'static str, account_id: AccountId, vault_id: VaultId, bytes: u64) {
    tracing::info!(op, %account_id, %vault_id, bytes, "vault operation");
}

/// [`log_op`] for the operations that name an archived generation as well as
/// its vault. Same rule: ids and sizes only.
fn log_version_op(
    op: &'static str,
    account_id: AccountId,
    vault_id: VaultId,
    version_id: VaultVersionId,
    bytes: u64,
) {
    tracing::info!(op, %account_id, %vault_id, %version_id, bytes, "vault operation");
}

/// Listings are the one read that says nothing about a particular vault, so
/// they log a count instead of an id — and at `debug`, because a listing is
/// re-rendered after every change the file manager makes.
fn log_list(account_id: AccountId, count: usize) {
    tracing::debug!(op = op::LISTED, %account_id, count, "vault operation");
}

/// One vault's metadata as answered by the list/upload/rename endpoints.
#[derive(Serialize)]
pub struct VaultInfo {
    pub id: VaultId,
    pub name: String,
    pub size: u64,
    pub etag: String,
    /// When the server stored these bytes.
    pub updated_at: DateTime<Utc>,
    /// The machine that saved the file, from its own unencrypted stamp.
    pub host: Option<String>,
    /// When the file says it was saved, from the same stamp.
    pub saved_at: Option<DateTime<Utc>>,
}

impl From<&VaultMeta> for VaultInfo {
    fn from(meta: &VaultMeta) -> Self {
        Self {
            id: meta.id,
            name: meta.name.clone(),
            size: meta.size,
            etag: meta.etag.clone(),
            updated_at: meta.updated_at,
            host: meta.host.clone(),
            saved_at: meta.saved_at,
        }
    }
}

/// `GET /api/v1/vaults` — the account's vaults, metadata only.
pub async fn list(
    State(state): State<AppState>,
    auth: AuthSession,
) -> ApiResult<Json<Vec<VaultInfo>>> {
    let metas = list_for(&state, auth.account.id).await?;
    Ok(Json(metas.iter().map(VaultInfo::from).collect()))
}

/// The account's vaults, name-sorted so the file manager's table has a
/// stable order across requests.
pub(crate) async fn list_for(state: &AppState, account_id: AccountId) -> ApiResult<Vec<VaultMeta>> {
    let mut metas = state.vault_meta.list_for_account(account_id).await?;
    metas.sort_by_key(|meta| meta.name.to_lowercase());
    log_list(account_id, metas.len());
    Ok(metas)
}

#[derive(Deserialize)]
pub struct UploadQuery {
    name: Option<String>,
}

/// `POST /api/v1/vaults?name=<file name>` — upload a new vault file (raw
/// bytes body). 201 with the metadata (ETag also as a header).
pub async fn upload(
    State(state): State<AppState>,
    auth: AuthSession,
    Query(query): Query<UploadQuery>,
    body: ApiBytes,
) -> ApiResult<Response> {
    let meta = create(
        &state,
        auth.account.id,
        query.name.as_deref().unwrap_or_default(),
        &body.0,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        [(header::ETAG, http_etag(&meta.etag))],
        Json(VaultInfo::from(&meta)),
    )
        .into_response())
}

/// Stores a new vault file, enforcing the name rules, the ZIP check, the
/// per-account count limit, name uniqueness and the byte quota.
pub(crate) async fn create(
    state: &AppState,
    account_id: AccountId,
    raw_name: &str,
    bytes: &[u8],
) -> ApiResult<VaultMeta> {
    let name = validate_name(raw_name)?;
    check_vault_bytes(bytes)?;
    let existing = state.vault_meta.list_for_account(account_id).await?;
    if existing.len() >= MAX_VAULTS_PER_ACCOUNT {
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "vault_limit_reached",
            format!("at most {MAX_VAULTS_PER_ACCOUNT} vaults per account"),
        ));
    }
    if existing.iter().any(|m| m.name == name) {
        return Err(name_taken());
    }
    check_quota(&existing, None, bytes.len())?;

    let stamp = vaultfile::read_stamp(bytes);
    let meta = VaultMeta {
        id: Uuid::new_v4(),
        account_id,
        name,
        size: bytes.len() as u64,
        etag: content_etag(bytes),
        updated_at: Utc::now(),
        host: stamp.host,
        saved_at: stamp.saved_at,
    };
    // Bytes first, metadata second: a failure in between leaves an
    // invisible orphan blob (reaped with the account), never a listed
    // vault with no bytes.
    state.vault_blobs.put(account_id, meta.id, bytes).await?;
    state.vault_meta.upsert(meta.clone()).await?;
    log_op(op::CREATED, account_id, meta.id, meta.size);
    Ok(meta)
}

/// `GET /api/v1/vaults/{id}` — download the vault bytes. Honors
/// `If-None-Match` (304 when the client's copy is current).
pub async fn download(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let account_id = auth.account.id;
    let meta = state
        .vault_meta
        .get(account_id, vault_id)
        .await?
        .ok_or_else(no_such_vault)?;
    if let Some(if_none_match) = etag_header(&headers, header::IF_NONE_MATCH)
        && (if_none_match == "*" || if_none_match == meta.etag)
    {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, http_etag(&meta.etag)),
                (header::CACHE_CONTROL, CACHE_CONTROL_VAULT.to_string()),
            ],
        )
            .into_response());
    }
    let bytes = blob_of(&state, &meta).await?;
    Ok((
        StatusCode::OK,
        [
            (header::ETAG, http_etag(&meta.etag)),
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CACHE_CONTROL, CACHE_CONTROL_VAULT.to_string()),
        ],
        bytes,
    )
        .into_response())
}

/// A vault's metadata and its bytes. Used by the browser download route,
/// which has no conditional-request handling to do.
pub(crate) async fn read(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
) -> ApiResult<(VaultMeta, Vec<u8>)> {
    let meta = state
        .vault_meta
        .get(account_id, vault_id)
        .await?
        .ok_or_else(no_such_vault)?;
    let bytes = blob_of(state, &meta).await?;
    Ok((meta, bytes))
}

/// Fetches the bytes behind a metadata row. A missing blob is a server-side
/// inconsistency, not a 404: the vault is listed, so the user did nothing
/// wrong.
///
/// Both ways of handing a vault out — the API download and the browser's —
/// end here, which makes it the one place worth logging a read: a line
/// appears exactly when bytes actually leave the server, and not for the 304
/// that says none did.
async fn blob_of(state: &AppState, meta: &VaultMeta) -> ApiResult<Vec<u8>> {
    match state.vault_blobs.get(meta.account_id, meta.id).await? {
        Some(bytes) => {
            log_op(op::DOWNLOADED, meta.account_id, meta.id, bytes.len() as u64);
            Ok(bytes)
        }
        None => {
            let (account_id, vault_id) = (meta.account_id, meta.id);
            tracing::error!(%account_id, %vault_id, "vault metadata exists but blob is missing");
            Err(ApiError::internal())
        }
    }
}

/// `PUT /api/v1/vaults/{id}` — overwrite the vault bytes. Requires
/// `If-Match` with the last seen ETag (or `*`); 412 when the stored
/// version changed since.
pub async fn replace(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: ApiBytes,
) -> ApiResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let expected = etag_header(&headers, header::IF_MATCH);
    if expected.is_none() {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "overwriting a vault requires If-Match with the last seen ETag",
        ));
    }
    let updated = overwrite(
        &state,
        auth.account.id,
        vault_id,
        expected.as_deref(),
        &body.0,
    )
    .await?;
    Ok((
        StatusCode::OK,
        [(header::ETAG, http_etag(&updated.etag))],
        Json(VaultInfo::from(&updated)),
    )
        .into_response())
}

/// Replaces a vault's bytes under optimistic concurrency.
///
/// `expected` is the ETag the caller last saw (`*` for "whatever is there");
/// `None` skips the check and is only for callers that have already refused
/// an unconditional overwrite themselves — the JSON `PUT` demands
/// `If-Match`, and the browser form always carries the row's ETag.
pub(crate) async fn overwrite(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    expected: Option<&str>,
    bytes: &[u8],
) -> ApiResult<VaultMeta> {
    let existing = state.vault_meta.list_for_account(account_id).await?;
    let Some(meta) = existing.iter().find(|m| m.id == vault_id) else {
        return Err(no_such_vault());
    };
    if let Some(expected) = expected
        && expected != "*"
        && expected != meta.etag
    {
        return Err(stale_vault());
    }
    check_vault_bytes(bytes)?;
    check_quota(&existing, Some(vault_id), bytes.len())?;

    let stamp = vaultfile::read_stamp(bytes);
    let updated = VaultMeta {
        size: bytes.len() as u64,
        etag: content_etag(bytes),
        updated_at: Utc::now(),
        // The new bytes bring their own stamp, or none: a file saved by a
        // device that does not write one must not inherit the last device's
        // name.
        host: stamp.host,
        saved_at: stamp.saved_at,
        ..meta.clone()
    };
    // Only a real change is worth a generation: re-uploading identical bytes
    // (a client that syncs on a timer) would otherwise push the actual
    // history out of the window.
    if updated.etag != meta.etag {
        archive_current(state, meta).await;
    }
    state.vault_blobs.put(account_id, vault_id, bytes).await?;
    state.vault_meta.upsert(updated.clone()).await?;
    log_op(op::OVERWRITTEN, account_id, vault_id, updated.size);
    // Trimming happens after the save has landed, so a full history can
    // never be the reason a save fails.
    trim_history(
        state,
        account_id,
        used_bytes(&existing, Some(vault_id)) + updated.size,
    )
    .await;
    Ok(updated)
}

/// Files the vault's current bytes away as a version.
///
/// Best effort by design: history is a convenience, the save is the point.
/// A failure here is logged and the save goes ahead, which is the right
/// trade in both directions — the user keeps their data, and the operator
/// learns the version store is unwell.
async fn archive_current(state: &AppState, meta: &VaultMeta) {
    if let Err(err) = archive(state, meta).await {
        let (account_id, vault_id) = (meta.account_id, meta.id);
        tracing::warn!(%account_id, %vault_id, %err, "could not archive the previous vault version");
    }
}

async fn archive(state: &AppState, meta: &VaultMeta) -> Result<(), StoreError> {
    let Some(bytes) = state.vault_blobs.get(meta.account_id, meta.id).await? else {
        // Nothing stored to keep. `blob_of` reports this inconsistency on
        // the paths where it matters; here there is simply no history to
        // write.
        return Ok(());
    };
    let version = VaultVersion {
        id: Uuid::new_v4(),
        vault_id: meta.id,
        account_id: meta.account_id,
        name: meta.name.clone(),
        // Measured from the bytes actually archived, not from the metadata
        // row: this figure drives the quota trim.
        size: bytes.len() as u64,
        etag: meta.etag.clone(),
        updated_at: meta.updated_at,
        archived_at: Utc::now(),
        // Copied, not re-read: these are the same bytes the vault row was
        // written from, so its stamp is theirs.
        host: meta.host.clone(),
        saved_at: meta.saved_at,
    };
    // Bytes first, index second — same order as the live vault, and with the
    // same consequence: a failure between the two leaves an unreferenced
    // blob, never an index entry pointing at nothing.
    state
        .vault_version_blobs
        .put(meta.account_id, version.id, &bytes)
        .await?;
    let (account_id, vault_id, version_id, size) = (
        version.account_id,
        version.vault_id,
        version.id,
        version.size,
    );
    state.vault_versions.insert(version).await?;
    log_version_op(op::VERSION_ARCHIVED, account_id, vault_id, version_id, size);
    Ok(())
}

/// Applies both retention rules and drops whatever they exclude.
///
/// Walks the account's versions newest first and keeps each one only while
/// its vault is under [`MAX_VAULT_VERSIONS`] *and* it fits in what is left of
/// [`ACCOUNT_QUOTA_BYTES`] after the live files. So history never pushes an
/// account past the quota it already had, and the generations that survive a
/// squeeze are the recent ones.
///
/// `live_used` is the total size of the account's live vaults *after* the
/// save that triggered this. Like archiving, failures are logged rather than
/// propagated: the save has already succeeded.
async fn trim_history(state: &AppState, account_id: AccountId, live_used: u64) {
    if let Err(err) = trim(state, account_id, live_used).await {
        tracing::warn!(%account_id, %err, "could not trim vault version history");
    }
}

async fn trim(state: &AppState, account_id: AccountId, live_used: u64) -> Result<(), StoreError> {
    let versions = state.vault_versions.list_for_account(account_id).await?;
    let mut budget = ACCOUNT_QUOTA_BYTES.saturating_sub(live_used);
    let mut kept: HashMap<VaultId, usize> = HashMap::new();
    let mut doomed = Vec::new();
    for version in versions {
        let count = kept.entry(version.vault_id).or_default();
        if *count >= MAX_VAULT_VERSIONS || version.size > budget {
            doomed.push(version);
            continue;
        }
        *count += 1;
        budget -= version.size;
    }
    if doomed.is_empty() {
        return Ok(());
    }
    // One line for the sweep rather than one per generation: which ids fell
    // out of the window is not what an operator reads this for, and each of
    // them was announced when it was archived.
    let dropped = doomed.len();
    for version in doomed {
        drop_version(state, &version).await?;
    }
    tracing::info!(
        op = op::VERSIONS_TRIMMED,
        %account_id,
        dropped,
        "vault operation"
    );
    Ok(())
}

/// Removes one archived generation, bytes and index entry both. Already-gone
/// halves are not an error: this runs from cleanup paths that must be safe to
/// retry.
async fn drop_version(state: &AppState, version: &VaultVersion) -> Result<(), StoreError> {
    match state
        .vault_version_blobs
        .delete(version.account_id, version.id)
        .await
    {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(other) => return Err(other),
    }
    match state
        .vault_versions
        .delete(version.account_id, version.id)
        .await
    {
        Ok(()) | Err(StoreError::NotFound) => Ok(()),
        Err(other) => Err(other),
    }
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub name: String,
}

/// `PUT /api/v1/vaults/{id}/name` — rename the vault file. The ETag is a
/// content hash, so renaming does not change it.
pub async fn rename(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<RenameRequest>,
) -> ApiResult<Json<VaultInfo>> {
    let vault_id = parse_vault_id(&id)?;
    let updated = set_name(&state, auth.account.id, vault_id, &req.name).await?;
    Ok(Json(VaultInfo::from(&updated)))
}

/// Renames a vault file. The ETag is a content hash, so this leaves it alone.
pub(crate) async fn set_name(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    raw_name: &str,
) -> ApiResult<VaultMeta> {
    let name = validate_name(raw_name)?;
    let existing = state.vault_meta.list_for_account(account_id).await?;
    let Some(meta) = existing.iter().find(|m| m.id == vault_id) else {
        return Err(no_such_vault());
    };
    if existing.iter().any(|m| m.id != vault_id && m.name == name) {
        return Err(name_taken());
    }
    let mut updated = meta.clone();
    if updated.name != name {
        updated.name = name;
        updated.updated_at = Utc::now();
        state.vault_meta.upsert(updated.clone()).await?;
        // Neither the old name nor the new one: the log says a rename
        // happened, the account holder's own listing says to what.
        log_op(op::RENAMED, account_id, vault_id, updated.size);
    }
    Ok(updated)
}

/// `DELETE /api/v1/vaults/{id}` — delete the vault file.
pub async fn remove(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    destroy(&state, auth.account.id, parse_vault_id(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a vault: history, then bytes, then metadata.
pub(crate) async fn destroy(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
) -> ApiResult<()> {
    let Some(meta) = state.vault_meta.get(account_id, vault_id).await? else {
        return Err(no_such_vault());
    };
    // History goes first and explicitly. SQLite would cascade the index rows
    // off the vault row, but the archived *bytes* are the server's to remove,
    // and deleting a vault has to mean the copies stored here are gone.
    let versions = state
        .vault_versions
        .list_for_vault(account_id, vault_id)
        .await?;
    let dropped = versions.len();
    for version in versions {
        drop_version(state, &version).await?;
    }
    // Bytes first (tolerating already-gone) so a failure part-way is healed
    // by retrying; the metadata row keeps the vault addressable until both
    // halves are gone.
    match state.vault_blobs.delete(account_id, vault_id).await {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(other) => return Err(other.into()),
    }
    match state.vault_meta.delete(account_id, vault_id).await {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(other) => return Err(other.into()),
    }
    tracing::info!(
        op = op::DELETED,
        %account_id,
        %vault_id,
        bytes = meta.size,
        // How much history went with it — the one figure that is gone for
        // good and cannot be read off anything afterwards.
        dropped,
        "vault operation"
    );
    Ok(())
}

/// One archived generation as answered by the version endpoints.
#[derive(Serialize)]
pub struct VersionInfo {
    pub id: VaultVersionId,
    pub vault_id: VaultId,
    /// The vault's name when this generation was archived.
    pub name: String,
    pub size: u64,
    pub etag: String,
    /// When these bytes were the live vault's last write.
    pub updated_at: DateTime<Utc>,
    /// When they were superseded.
    pub archived_at: DateTime<Utc>,
    /// The machine that saved these bytes, from the file's own stamp.
    pub host: Option<String>,
    /// When the file says they were saved.
    pub saved_at: Option<DateTime<Utc>>,
}

impl From<&VaultVersion> for VersionInfo {
    fn from(version: &VaultVersion) -> Self {
        Self {
            id: version.id,
            vault_id: version.vault_id,
            name: version.name.clone(),
            size: version.size,
            etag: version.etag.clone(),
            updated_at: version.updated_at,
            archived_at: version.archived_at,
            host: version.host.clone(),
            saved_at: version.saved_at,
        }
    }
}

/// `GET /api/v1/vaults/{id}/versions` — the vault's kept generations,
/// newest first.
pub async fn list_versions(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<VersionInfo>>> {
    let versions = versions_for(&state, auth.account.id, parse_vault_id(&id)?).await?;
    Ok(Json(versions.iter().map(VersionInfo::from).collect()))
}

/// A vault's kept generations, newest first. An unknown vault is a 404 —
/// "no history" and "no such vault" are different answers.
pub(crate) async fn versions_for(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
) -> ApiResult<Vec<VaultVersion>> {
    if state.vault_meta.get(account_id, vault_id).await?.is_none() {
        return Err(no_such_vault());
    }
    Ok(state
        .vault_versions
        .list_for_vault(account_id, vault_id)
        .await?)
}

/// Every kept generation the account holds, grouped by vault and newest
/// first. One store round trip for a whole listing — the file manager draws
/// history inside each row and would otherwise query per vault.
pub(crate) async fn versions_by_vault(
    state: &AppState,
    account_id: AccountId,
) -> ApiResult<HashMap<VaultId, Vec<VaultVersion>>> {
    let mut grouped: HashMap<VaultId, Vec<VaultVersion>> = HashMap::new();
    for version in state.vault_versions.list_for_account(account_id).await? {
        grouped.entry(version.vault_id).or_default().push(version);
    }
    Ok(grouped)
}

/// `GET /api/v1/vaults/{id}/versions/{version_id}` — the archived bytes.
///
/// Archived bytes never change, so the ETag is as strong as it gets and
/// `If-None-Match` is worth honoring.
pub async fn download_version(
    State(state): State<AppState>,
    auth: AuthSession,
    Path((id, version_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let vault_id = parse_vault_id(&id)?;
    let version_id = parse_version_id(&version_id)?;
    if let Some(if_none_match) = etag_header(&headers, header::IF_NONE_MATCH) {
        let version = version_of(&state, auth.account.id, vault_id, version_id).await?;
        if if_none_match == "*" || if_none_match == version.etag {
            return Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, http_etag(&version.etag)),
                    (header::CACHE_CONTROL, CACHE_CONTROL_VAULT.to_string()),
                ],
            )
                .into_response());
        }
    }
    let (version, bytes) = read_version(&state, auth.account.id, vault_id, version_id).await?;
    Ok((
        StatusCode::OK,
        [
            (header::ETAG, http_etag(&version.etag)),
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CACHE_CONTROL, CACHE_CONTROL_VAULT.to_string()),
        ],
        bytes,
    )
        .into_response())
}

/// An archived generation and its bytes, on their way out to a client.
pub(crate) async fn read_version(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    version_id: VaultVersionId,
) -> ApiResult<(VaultVersion, Vec<u8>)> {
    let (version, bytes) = version_bytes(state, account_id, vault_id, version_id).await?;
    log_version_op(
        op::VERSION_DOWNLOADED,
        account_id,
        vault_id,
        version_id,
        bytes.len() as u64,
    );
    Ok((version, bytes))
}

/// The same fetch without the log line, for [`restore_version`]: those bytes
/// are being written back, not handed out, and saying "downloaded" for an
/// internal read would make the log claim a copy left the server.
async fn version_bytes(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    version_id: VaultVersionId,
) -> ApiResult<(VaultVersion, Vec<u8>)> {
    let version = version_of(state, account_id, vault_id, version_id).await?;
    match state
        .vault_version_blobs
        .get(account_id, version.id)
        .await?
    {
        Some(bytes) => Ok((version, bytes)),
        None => {
            tracing::error!(%account_id, %vault_id, %version_id, "vault version indexed but bytes are missing");
            Err(ApiError::internal())
        }
    }
}

/// Looks up a version, checking it belongs to the vault in the path. A
/// version id from another vault is not that vault's history, so it 404s
/// like an unknown one.
async fn version_of(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    version_id: VaultVersionId,
) -> ApiResult<VaultVersion> {
    match state.vault_versions.get(account_id, version_id).await? {
        Some(version) if version.vault_id == vault_id => Ok(version),
        _ => Err(no_such_version()),
    }
}

/// `POST /api/v1/vaults/{id}/versions/{version_id}/restore` — make an
/// archived generation the live vault again.
///
/// `If-Match` is honored when sent but not required: the caller picked a
/// version out of a listing, which is a deliberate act, unlike a blind
/// overwrite.
pub async fn restore(
    State(state): State<AppState>,
    auth: AuthSession,
    Path((id, version_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let updated = restore_version(
        &state,
        auth.account.id,
        parse_vault_id(&id)?,
        parse_version_id(&version_id)?,
        etag_header(&headers, header::IF_MATCH).as_deref(),
    )
    .await?;
    Ok((
        StatusCode::OK,
        [(header::ETAG, http_etag(&updated.etag))],
        Json(VaultInfo::from(&updated)),
    )
        .into_response())
}

/// Writes an archived generation back as the live vault.
///
/// This is an ordinary overwrite with old bytes, which means the state it
/// replaces is itself archived first: restoring the wrong version is undone
/// by restoring again.
pub(crate) async fn restore_version(
    state: &AppState,
    account_id: AccountId,
    vault_id: VaultId,
    version_id: VaultVersionId,
    expected: Option<&str>,
) -> ApiResult<VaultMeta> {
    let (_, bytes) = version_bytes(state, account_id, vault_id, version_id).await?;
    let updated = overwrite(state, account_id, vault_id, expected, &bytes).await?;
    // After the overwrite, so the pair of lines reads in the order the work
    // happened: the displaced state was archived, the new bytes landed, and
    // this says which generation they came from.
    log_version_op(
        op::VERSION_RESTORED,
        account_id,
        vault_id,
        version_id,
        updated.size,
    );
    Ok(updated)
}

/// Vault ids are uuids; anything else can't name a stored vault, so it
/// gets the same 404 as an unknown id.
pub(crate) fn parse_vault_id(raw: &str) -> Result<VaultId, ApiError> {
    Uuid::parse_str(raw).map_err(|_| no_such_vault())
}

pub(crate) fn parse_version_id(raw: &str) -> Result<VaultVersionId, ApiError> {
    Uuid::parse_str(raw).map_err(|_| no_such_version())
}

fn no_such_version() -> ApiError {
    ApiError::not_found("no such vault version")
}

fn no_such_vault() -> ApiError {
    ApiError::not_found("no such vault")
}

/// The overwrite conflict. `PRECONDITION_FAILED` is what the API answers;
/// the browser turns the same error into a "changed on another device"
/// message rather than showing a bare 412.
fn stale_vault() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "precondition_failed",
        "the stored vault changed since it was last fetched",
    )
}

fn name_taken() -> ApiError {
    ApiError::conflict("a vault with this name already exists")
}

/// Validates a user-supplied vault file name: plain file names only, no
/// path separators or control characters.
fn validate_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\');
    if ok {
        Ok(name.to_string())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_vault_name",
            "vault name must be a plain, non-empty file name (max 255 bytes)",
        ))
    }
}

/// The opaque-bytes contract allows exactly one peek: vault files are ZIP
/// archives, so anything without the ZIP magic is rejected outright.
fn check_vault_bytes(bytes: &[u8]) -> Result<(), ApiError> {
    // Backstop; the routes' body limit normally rejects oversize first.
    if bytes.len() > MAX_VAULT_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("vault files are limited to {MAX_VAULT_BYTES} bytes"),
        ));
    }
    if !bytes.starts_with(b"PK") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_vault_file",
            "not an askrypt vault file",
        ));
    }
    Ok(())
}

/// Enforces the per-account byte quota; `replacing` excludes the vault
/// being overwritten from the current usage.
fn check_quota(
    existing: &[VaultMeta],
    replacing: Option<VaultId>,
    new_size: usize,
) -> Result<(), ApiError> {
    let used = used_bytes(existing, replacing);
    if used + new_size as u64 > ACCOUNT_QUOTA_BYTES {
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "quota_exceeded",
            format!("account storage quota of {ACCOUNT_QUOTA_BYTES} bytes exceeded"),
        ));
    }
    Ok(())
}

/// Live bytes held by an account, optionally excluding the vault about to be
/// replaced. Only the live files count here — history is measured separately
/// and trimmed to whatever this leaves over.
fn used_bytes(existing: &[VaultMeta], replacing: Option<VaultId>) -> u64 {
    existing
        .iter()
        .filter(|m| Some(m.id) != replacing)
        .map(|m| m.size)
        .sum()
}

fn content_etag(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The stored etag in HTTP header form (quoted, per RFC 9110).
fn http_etag(etag: &str) -> String {
    format!("\"{etag}\"")
}

/// Reads a single-ETag conditional header, tolerating quotes and a weak
/// (`W/`) prefix. Multi-ETag lists are not supported — clients here track
/// one version per vault.
fn etag_header(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let raw = headers.get(name)?.to_str().ok()?.trim();
    let raw = raw.strip_prefix("W/").unwrap_or(raw);
    Some(raw.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert_eq!(
            validate_name(" personal.askrypt ").unwrap(),
            "personal.askrypt"
        );
        for bad in ["", ".", "..", "a/b", "a\\b", "a\nb", &"x".repeat(256)] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn vault_bytes_must_look_like_zip_and_fit() {
        assert!(check_vault_bytes(b"PK\x03\x04rest").is_ok());
        assert!(check_vault_bytes(b"").is_err());
        assert!(check_vault_bytes(b"not a zip").is_err());
        let huge = vec![b'P'; MAX_VAULT_BYTES + 1];
        assert!(check_vault_bytes(&huge).is_err());
    }

    #[test]
    fn quota_counts_all_but_the_replaced_vault() {
        let meta = |id, size| VaultMeta {
            id,
            account_id: Uuid::new_v4(),
            name: format!("{id}.askrypt"),
            size,
            etag: "e".into(),
            updated_at: Utc::now(),
            host: None,
            saved_at: None,
        };
        let big = Uuid::new_v4();
        let existing = vec![
            meta(big, ACCOUNT_QUOTA_BYTES - 10),
            meta(Uuid::new_v4(), 10),
        ];
        assert!(check_quota(&existing, None, 1).is_err());
        assert!(check_quota(&existing, Some(big), 100).is_ok());
        assert!(check_quota(&existing[..1], None, 10).is_ok());
    }

    /// Files a version away with a controlled size and archival time. The
    /// bytes are a stand-in: the retention rules read sizes from the index,
    /// which is exactly what makes quota-sized fixtures affordable here.
    async fn seed_version(
        state: &AppState,
        account_id: AccountId,
        vault_id: VaultId,
        age_secs: i64,
        size: u64,
    ) -> VaultVersionId {
        let id = Uuid::new_v4();
        let archived_at = Utc::now() - chrono::Duration::seconds(age_secs);
        state
            .vault_version_blobs
            .put(account_id, id, b"PK\x03\x04")
            .await
            .unwrap();
        state
            .vault_versions
            .insert(VaultVersion {
                id,
                vault_id,
                account_id,
                name: "v.askrypt".into(),
                size,
                etag: format!("etag-{age_secs}"),
                updated_at: archived_at,
                archived_at,
                host: None,
                saved_at: None,
            })
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn trimming_keeps_the_newest_generations_within_the_cap() {
        let state = AppState::in_memory();
        let (account_id, vault_id) = (Uuid::new_v4(), Uuid::new_v4());
        // Three more generations than the history is deep, youngest first.
        let seeded = MAX_VAULT_VERSIONS as i64 + 3;
        let mut ids = Vec::new();
        for age in 0..seeded {
            ids.push(seed_version(&state, account_id, vault_id, age, 10).await);
        }

        trim(&state, account_id, 0).await.unwrap();

        let kept = state
            .vault_versions
            .list_for_account(account_id)
            .await
            .unwrap();
        assert_eq!(kept.len(), MAX_VAULT_VERSIONS);
        let kept_ids: Vec<VaultVersionId> = kept.iter().map(|v| v.id).collect();
        assert_eq!(
            kept_ids,
            ids[..MAX_VAULT_VERSIONS],
            "the newest must survive"
        );
        // The bytes go with the index entry — a trim that only forgot the
        // row would leak disk forever.
        for dropped in &ids[MAX_VAULT_VERSIONS..] {
            assert!(
                state
                    .vault_version_blobs
                    .get(account_id, *dropped)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn history_gives_way_to_the_live_files_under_the_quota() {
        let state = AppState::in_memory();
        let (account_id, vault_id) = (Uuid::new_v4(), Uuid::new_v4());
        let size = ACCOUNT_QUOTA_BYTES / 10;
        for age in 0..4 {
            seed_version(&state, account_id, vault_id, age, size).await;
        }

        // Live files leave room for two generations, so three of the four go.
        trim(&state, account_id, ACCOUNT_QUOTA_BYTES - 2 * size)
            .await
            .unwrap();
        let kept = state
            .vault_versions
            .list_for_account(account_id)
            .await
            .unwrap();
        assert_eq!(kept.len(), 2);

        // A full account keeps no history at all rather than exceeding the
        // quota it always had.
        trim(&state, account_id, ACCOUNT_QUOTA_BYTES).await.unwrap();
        assert!(
            state
                .vault_versions
                .list_for_account(account_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The whole point of the vault log: an operator can follow what happened
    /// to which file without the log describing any of them.
    #[tokio::test]
    async fn the_log_identifies_a_vault_and_describes_nothing_about_it() {
        let state = AppState::in_memory();
        let account_id = Uuid::new_v4();
        let name = "work-vpn.askrypt";
        let capture = crate::testlog::Capture::start();

        let meta = create(&state, account_id, name, b"PK\x03\x04first")
            .await
            .unwrap();
        overwrite(
            &state,
            account_id,
            meta.id,
            Some(&meta.etag),
            b"PK\x03\x04second",
        )
        .await
        .unwrap();
        set_name(&state, account_id, meta.id, "holiday-photos.askrypt")
            .await
            .unwrap();
        read(&state, account_id, meta.id).await.unwrap();
        destroy(&state, account_id, meta.id).await.unwrap();

        let events = capture.events();
        let ops: Vec<&str> = events.iter().map(|event| event.get("op")).collect();
        assert_eq!(
            ops,
            [
                op::CREATED,
                op::VERSION_ARCHIVED,
                op::OVERWRITTEN,
                op::RENAMED,
                op::DOWNLOADED,
                op::DELETED,
            ]
        );
        let vault_id = meta.id.to_string();
        for event in events.iter() {
            assert_eq!(event.get("account_id"), account_id.to_string());
            assert_eq!(event.get("vault_id"), vault_id);
            // Neither name it was known by, nor the content hashes that would
            // let a log reader match files up or spot a rollback.
            for (field, value) in &event.fields {
                for forbidden in [name, "holiday-photos", &meta.etag] {
                    assert!(
                        !value.contains(forbidden),
                        "{field}={value} leaks {forbidden}"
                    );
                }
            }
        }
    }

    #[test]
    fn etag_helpers_roundtrip() {
        let etag = content_etag(b"bytes");
        assert_eq!(etag.len(), 64);
        assert_eq!(etag, content_etag(b"bytes"));
        assert_ne!(etag, content_etag(b"other"));

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, http_etag(&etag).parse().unwrap());
        assert_eq!(etag_header(&headers, header::IF_MATCH), Some(etag.clone()));
        headers.insert(header::IF_MATCH, format!("W/\"{etag}\"").parse().unwrap());
        assert_eq!(etag_header(&headers, header::IF_MATCH), Some(etag));
        assert_eq!(etag_header(&headers, header::IF_NONE_MATCH), None);
    }
}
