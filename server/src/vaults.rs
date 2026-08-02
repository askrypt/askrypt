//! Vault cloud-storage endpoints (plan Phase 4).
//!
//! Plain file semantics over HTTP so desktop and mobile apps can sync with
//! a basic HTTP client: raw bytes up (`POST /vaults?name=`, `PUT
//! /vaults/{id}`) and down (`GET /vaults/{id}`), metadata list, rename,
//! delete. Everything is scoped to the authenticated account, and the
//! bytes stay opaque — the only inspection is the ZIP-magic sanity check
//! on upload.
//!
//! Optimistic concurrency for multi-device sync: every stored vault has a
//! content-hash ETag, served on upload and download. Overwrites must send
//! `If-Match` (428 without it) and answer 412 when the stored version
//! changed under the client; downloads honor `If-None-Match` with 304.

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
use crate::store::{StoreError, VaultId, VaultMeta};

/// Hard cap on a single vault file. Real vaults are small ZIPs (tens of
/// KBs); 10 MiB is deliberately generous. Also enforced as the request
/// body limit on the vault routes.
pub const MAX_VAULT_BYTES: usize = 10 * 1024 * 1024;
/// Total bytes one account may store across all its vaults.
pub const ACCOUNT_QUOTA_BYTES: u64 = 100 * 1024 * 1024;
/// Maximum number of vault files per account.
pub const MAX_VAULTS_PER_ACCOUNT: usize = 100;
const MAX_NAME_BYTES: usize = 255;

/// One vault's metadata as answered by the list/upload/rename endpoints.
#[derive(Serialize)]
pub struct VaultInfo {
    pub id: VaultId,
    pub name: String,
    pub size: u64,
    pub etag: String,
    pub updated_at: DateTime<Utc>,
}

impl From<&VaultMeta> for VaultInfo {
    fn from(meta: &VaultMeta) -> Self {
        Self {
            id: meta.id,
            name: meta.name.clone(),
            size: meta.size,
            etag: meta.etag.clone(),
            updated_at: meta.updated_at,
        }
    }
}

/// `GET /api/v1/vaults` — the account's vaults, metadata only.
pub async fn list(
    State(state): State<AppState>,
    auth: AuthSession,
) -> ApiResult<Json<Vec<VaultInfo>>> {
    let metas = state.vault_meta.list_for_account(auth.account.id).await?;
    Ok(Json(metas.iter().map(VaultInfo::from).collect()))
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
    let name = validate_name(query.name.as_deref().unwrap_or_default())?;
    check_vault_bytes(&body.0)?;
    let account_id = auth.account.id;
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
    check_quota(&existing, None, body.0.len())?;

    let meta = VaultMeta {
        id: Uuid::new_v4(),
        account_id,
        name,
        size: body.0.len() as u64,
        etag: content_etag(&body.0),
        updated_at: Utc::now(),
    };
    // Bytes first, metadata second: a failure in between leaves an
    // invisible orphan blob (reaped with the account), never a listed
    // vault with no bytes.
    state.vault_blobs.put(account_id, meta.id, &body.0).await?;
    state.vault_meta.upsert(meta.clone()).await?;
    Ok((
        StatusCode::CREATED,
        [(header::ETAG, http_etag(&meta.etag))],
        Json(VaultInfo::from(&meta)),
    )
        .into_response())
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
            [(header::ETAG, http_etag(&meta.etag))],
        )
            .into_response());
    }
    let Some(bytes) = state.vault_blobs.get(account_id, vault_id).await? else {
        tracing::error!(%account_id, %vault_id, "vault metadata exists but blob is missing");
        return Err(ApiError::internal());
    };
    Ok((
        StatusCode::OK,
        [
            (header::ETAG, http_etag(&meta.etag)),
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        ],
        bytes,
    )
        .into_response())
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
    let account_id = auth.account.id;
    let existing = state.vault_meta.list_for_account(account_id).await?;
    let Some(meta) = existing.iter().find(|m| m.id == vault_id) else {
        return Err(no_such_vault());
    };
    let Some(expected) = etag_header(&headers, header::IF_MATCH) else {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "overwriting a vault requires If-Match with the last seen ETag",
        ));
    };
    if expected != "*" && expected != meta.etag {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "the stored vault changed since it was last fetched",
        ));
    }
    check_vault_bytes(&body.0)?;
    check_quota(&existing, Some(vault_id), body.0.len())?;

    let updated = VaultMeta {
        size: body.0.len() as u64,
        etag: content_etag(&body.0),
        updated_at: Utc::now(),
        ..meta.clone()
    };
    state.vault_blobs.put(account_id, vault_id, &body.0).await?;
    state.vault_meta.upsert(updated.clone()).await?;
    Ok((
        StatusCode::OK,
        [(header::ETAG, http_etag(&updated.etag))],
        Json(VaultInfo::from(&updated)),
    )
        .into_response())
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
    let name = validate_name(&req.name)?;
    let existing = state.vault_meta.list_for_account(auth.account.id).await?;
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
    }
    Ok(Json(VaultInfo::from(&updated)))
}

/// `DELETE /api/v1/vaults/{id}` — delete the vault file.
pub async fn remove(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let vault_id = parse_vault_id(&id)?;
    let account_id = auth.account.id;
    if state.vault_meta.get(account_id, vault_id).await?.is_none() {
        return Err(no_such_vault());
    }
    // Bytes first (tolerating already-gone) so a failure part-way is healed
    // by retrying; the metadata row keeps the vault addressable until both
    // halves are gone.
    match state.vault_blobs.delete(account_id, vault_id).await {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(other) => return Err(other.into()),
    }
    match state.vault_meta.delete(account_id, vault_id).await {
        Ok(()) | Err(StoreError::NotFound) => Ok(StatusCode::NO_CONTENT),
        Err(other) => Err(other.into()),
    }
}

/// Vault ids are uuids; anything else can't name a stored vault, so it
/// gets the same 404 as an unknown id.
fn parse_vault_id(raw: &str) -> Result<VaultId, ApiError> {
    Uuid::parse_str(raw).map_err(|_| no_such_vault())
}

fn no_such_vault() -> ApiError {
    ApiError::not_found("no such vault")
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
        && !name.chars().any(|c| c.is_control() || c == '/' || c == '\\');
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
    let used: u64 = existing
        .iter()
        .filter(|m| Some(m.id) != replacing)
        .map(|m| m.size)
        .sum();
    if used + new_size as u64 > ACCOUNT_QUOTA_BYTES {
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "quota_exceeded",
            format!("account storage quota of {ACCOUNT_QUOTA_BYTES} bytes exceeded"),
        ));
    }
    Ok(())
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
        assert_eq!(validate_name(" personal.askrypt ").unwrap(), "personal.askrypt");
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
        };
        let big = Uuid::new_v4();
        let existing = vec![meta(big, ACCOUNT_QUOTA_BYTES - 10), meta(Uuid::new_v4(), 10)];
        assert!(check_quota(&existing, None, 1).is_err());
        assert!(check_quota(&existing, Some(big), 100).is_ok());
        assert!(check_quota(&existing[..1], None, 10).is_ok());
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
