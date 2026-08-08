//! Phase 4 gate tests: the vault file API driven as a headless client —
//! upload → list → download → rename → delete lifecycle, ETag optimistic
//! concurrency, per-account isolation, the size/quota limits, and the
//! version history a save leaves behind. Runs against the in-memory fakes.

use std::path::Path;

use askrypt_server::config::Config;
use askrypt_server::routes::router;
use askrypt_server::state::AppState;
use askrypt_server::store::VaultMeta;
use askrypt_server::vaults::{
    ACCOUNT_QUOTA_BYTES, MAX_VAULT_BYTES, MAX_VAULT_VERSIONS, MAX_VAULTS_PER_ACCOUNT,
};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const VAULT_V1: &[u8] = b"PK\x03\x04 pretend vault v1";
const VAULT_V2: &[u8] = b"PK\x03\x04 pretend vault v2, a bit longer";

struct TestApp {
    app: Router,
    /// Kept so tests can seed the stores behind the API (limit tests).
    state: AppState,
}

fn test_app() -> TestApp {
    let state = AppState::in_memory();
    let config = Config {
        static_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("static"),
        ..Config::default()
    };
    TestApp {
        app: router(state.clone(), &config),
        state,
    }
}

/// Sends a request, returning `(status, headers, raw body)`.
async fn send_raw(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

/// Sends a request, returning `(status, parsed JSON body)`; empty bodies
/// parse as `Value::Null`.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let (status, _, bytes) = send_raw(app, request).await;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

async fn register_and_login(app: &Router, email: &str) -> String {
    let (status, body) = send(
        app,
        Request::post("/api/v1/auth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"email": email, "password": "hunter2hunter2"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {body}");
    let (status, body) = send(
        app,
        Request::post("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"email": email, "password": "hunter2hunter2"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

fn upload(name: &str, token: &str, bytes: &[u8]) -> Request<Body> {
    Request::post(format!("/api/v1/vaults?name={name}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes.to_vec()))
        .unwrap()
}

fn replace(id: &str, token: &str, if_match: Option<&str>, bytes: &[u8]) -> Request<Body> {
    let mut request = Request::put(format!("/api/v1/vaults/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream");
    if let Some(etag) = if_match {
        request = request.header(header::IF_MATCH, etag);
    }
    request.body(Body::from(bytes.to_vec())).unwrap()
}

fn get_authed(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn delete_authed(uri: &str, token: &str) -> Request<Body> {
    Request::delete(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn rename_req(id: &str, token: &str, name: &str) -> Request<Body> {
    Request::put(format!("/api/v1/vaults/{id}/name"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"name": name}).to_string()))
        .unwrap()
}

#[tokio::test]
async fn vault_lifecycle_upload_list_download_rename_delete() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;

    // Empty to start with.
    let (status, body) = send(&t.app, get_authed("/api/v1/vaults", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));

    // Upload answers 201 with metadata and the ETag header.
    let (status, headers, bytes) =
        send_raw(&t.app, upload("personal.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["name"], "personal.askrypt");
    assert_eq!(body["size"], VAULT_V1.len());
    let id = body["id"].as_str().unwrap().to_string();
    let etag = body["etag"].as_str().unwrap().to_string();
    assert_eq!(
        headers[header::ETAG].to_str().unwrap(),
        format!("\"{etag}\"")
    );

    // Listed with the same metadata.
    let (status, body) = send(&t.app, get_authed("/api/v1/vaults", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], id.as_str());
    assert_eq!(body[0]["etag"], etag.as_str());
    assert!(body[0]["updated_at"].is_string());

    // Download is byte-identical, tagged, and honors If-None-Match.
    let (status, headers, bytes) =
        send_raw(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, VAULT_V1);
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(
        headers[header::ETAG].to_str().unwrap(),
        format!("\"{etag}\"")
    );
    let (status, _, bytes) = send_raw(
        &t.app,
        Request::get(format!("/api/v1/vaults/{id}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::IF_NONE_MATCH, format!("\"{etag}\""))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(bytes.is_empty());

    // Rename keeps the content ETag.
    let (status, body) = send(&t.app, rename_req(&id, &token, "renamed.askrypt")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "renamed.askrypt");
    assert_eq!(body["etag"], etag.as_str());

    // Delete, then everything about it is gone.
    let (status, _) = send(&t.app, delete_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(&t.app, get_authed("/api/v1/vaults", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
    let (status, _) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&t.app, delete_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn overwrite_requires_matching_if_match() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;
    let (status, body) = send(&t.app, upload("v.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().unwrap().to_string();
    let etag = body["etag"].as_str().unwrap().to_string();

    // No If-Match → 428; stale If-Match → 412; neither touched the bytes.
    let (status, body) = send(&t.app, replace(&id, &token, None, VAULT_V2)).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["error"]["code"], "precondition_required");
    let (status, body) = send(&t.app, replace(&id, &token, Some("\"stale\""), VAULT_V2)).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["error"]["code"], "precondition_failed");
    let (_, _, bytes) =
        send_raw(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(bytes, VAULT_V1);

    // Matching If-Match overwrites and rotates the ETag.
    let (status, body) = send(
        &t.app,
        replace(&id, &token, Some(&format!("\"{etag}\"")), VAULT_V2),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_etag = body["etag"].as_str().unwrap().to_string();
    assert_ne!(new_etag, etag);
    assert_eq!(body["size"], VAULT_V2.len());
    let (_, headers, bytes) =
        send_raw(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(bytes, VAULT_V2);
    assert_eq!(
        headers[header::ETAG].to_str().unwrap(),
        format!("\"{new_etag}\"")
    );

    // The old ETag is now stale — a second device syncing must conflict.
    let (status, _) = send(
        &t.app,
        replace(&id, &token, Some(&format!("\"{etag}\"")), VAULT_V1),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    // `*` (any current version) is accepted.
    let (status, _) = send(&t.app, replace(&id, &token, Some("*"), VAULT_V1)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn upload_validates_input_and_requires_auth() {
    let t = test_app();

    // No token → 401 for every vault route.
    let (status, _) = send(
        &t.app,
        Request::get("/api/v1/vaults").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let token = register_and_login(&t.app, "a@example.com").await;

    // Missing or bad names are rejected.
    let (status, body) = send(&t.app, upload("", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_vault_name");
    let (status, body) = send(&t.app, upload("a%2Fb.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Non-ZIP bytes fail the vault sanity check.
    let (status, body) = send(&t.app, upload("v.askrypt", &token, b"plain text")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_vault_file");

    // Duplicate names conflict.
    let (status, _) = send(&t.app, upload("v.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(&t.app, upload("v.askrypt", &token, VAULT_V2)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn vaults_are_isolated_per_account() {
    let t = test_app();
    let alice = register_and_login(&t.app, "alice@example.com").await;
    let bob = register_and_login(&t.app, "bob@example.com").await;

    let (status, body) = send(&t.app, upload("alice.askrypt", &alice, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().unwrap().to_string();

    // Bob sees an empty listing and cannot reach Alice's vault by id.
    let (status, body) = send(&t.app, get_authed("/api/v1/vaults", &bob)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
    for request in [
        get_authed(&format!("/api/v1/vaults/{id}"), &bob),
        replace(&id, &bob, Some("*"), VAULT_V2),
        rename_req(&id, &bob, "stolen.askrypt"),
        delete_authed(&format!("/api/v1/vaults/{id}"), &bob),
    ] {
        let (status, _) = send(&t.app, request).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Alice's vault is untouched.
    let (status, _, bytes) =
        send_raw(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &alice)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, VAULT_V1);
}

/// Seeds a metadata row directly (no bytes) — the limit checks only read
/// metadata, so this stands in for previously uploaded vaults.
async fn seed_meta(state: &AppState, account_id: Uuid, name: &str, size: u64) {
    state
        .vault_meta
        .upsert(VaultMeta {
            id: Uuid::new_v4(),
            account_id,
            name: name.into(),
            size,
            etag: "seeded".into(),
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn size_quota_and_count_limits_are_enforced() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;
    let (_, me) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    let account_id: Uuid = me["id"].as_str().unwrap().parse().unwrap();

    // A single oversize file is rejected by the request body limit.
    let huge = [b"PK\x03\x04".as_slice(), &vec![0u8; MAX_VAULT_BYTES]].concat();
    let (status, body) = send(&t.app, upload("huge.askrypt", &token, &huge)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "payload_too_large");

    // Byte quota: leave room for exactly one small vault — the upload that
    // fits is accepted, the next one over the line answers 507.
    let headroom = VAULT_V1.len() as u64 + 5;
    seed_meta(&t.state, account_id, "big.askrypt", ACCOUNT_QUOTA_BYTES - headroom).await;
    let (status, body) = send(&t.app, upload("fits.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    let etag = body["etag"].as_str().unwrap().to_string();
    let (status, body) = send(&t.app, upload("nope.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(body["error"]["code"], "quota_exceeded");
    // Overwriting an existing vault is charged net of its old size...
    let (status, _) = send(
        &t.app,
        replace(&id, &token, Some(&format!("\"{etag}\"")), VAULT_V1),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // ...but cannot grow past the quota either.
    let grown = [VAULT_V1, &[0u8; 200]].concat();
    let (status, body) = send(&t.app, replace(&id, &token, Some("*"), &grown)).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");

    // Count limit: at MAX_VAULTS_PER_ACCOUNT files, new uploads are refused.
    let t = test_app();
    let token = register_and_login(&t.app, "b@example.com").await;
    let (_, me) = send(&t.app, get_authed("/api/v1/me", &token)).await;
    let account_id: Uuid = me["id"].as_str().unwrap().parse().unwrap();
    for i in 0..MAX_VAULTS_PER_ACCOUNT {
        seed_meta(&t.state, account_id, &format!("v{i}.askrypt"), 1).await;
    }
    let (status, body) = send(&t.app, upload("one-more.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(body["error"]["code"], "vault_limit_reached");
}

fn restore_req(id: &str, version_id: &str, token: &str) -> Request<Body> {
    Request::post(format!(
        "/api/v1/vaults/{id}/versions/{version_id}/restore"
    ))
    .header(header::AUTHORIZATION, format!("Bearer {token}"))
    .body(Body::empty())
    .unwrap()
}

/// Uploads a vault and overwrites it with each of `revisions` in turn,
/// answering the vault id and the ETag of the file as it stands at the end.
async fn upload_and_revise(app: &Router, token: &str, revisions: &[&[u8]]) -> (String, String) {
    let (status, body) = send(app, upload("history.askrypt", token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    let mut etag = body["etag"].as_str().unwrap().to_string();
    for bytes in revisions {
        let (status, body) = send(app, replace(&id, token, Some(&format!("\"{etag}\"")), bytes)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        etag = body["etag"].as_str().unwrap().to_string();
    }
    (id, etag)
}

#[tokio::test]
async fn a_save_keeps_the_bytes_it_replaced_and_can_put_them_back() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;

    // A brand-new vault has no history: there is nothing it replaced.
    let (status, body) = send(&t.app, upload("history.askrypt", &token, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().unwrap().to_string();
    let v1_etag = body["etag"].as_str().unwrap().to_string();
    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));

    // Overwriting files the previous generation away.
    let (status, body) = send(
        &t.app,
        replace(&id, &token, Some(&format!("\"{v1_etag}\"")), VAULT_V2),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v2_etag = body["etag"].as_str().unwrap().to_string();

    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["etag"], v1_etag.as_str());
    assert_eq!(body[0]["size"], VAULT_V1.len());
    assert_eq!(body[0]["vault_id"], id.as_str());
    assert_eq!(body[0]["name"], "history.askrypt");
    assert!(body[0]["archived_at"].is_string());
    let version_id = body[0]["id"].as_str().unwrap().to_string();

    // The archived bytes come back exactly as they went in, under their own
    // ETag, and revalidate.
    let uri = format!("/api/v1/vaults/{id}/versions/{version_id}");
    let (status, headers, bytes) = send_raw(&t.app, get_authed(&uri, &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, VAULT_V1);
    assert_eq!(
        headers[header::ETAG].to_str().unwrap(),
        format!("\"{v1_etag}\"")
    );
    let (status, _, bytes) = send_raw(
        &t.app,
        Request::get(&uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::IF_NONE_MATCH, format!("\"{v1_etag}\""))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(bytes.is_empty());

    // Restoring makes it current again — and keeps what it displaced, so the
    // restore is itself undoable.
    let (status, body) = send(&t.app, restore_req(&id, &version_id, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["etag"], v1_etag.as_str());
    assert_eq!(body["size"], VAULT_V1.len());
    let (status, _, bytes) = send_raw(&t.app, get_authed(&format!("/api/v1/vaults/{id}"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, VAULT_V1);

    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    // Newest first: the v2 that the restore replaced.
    assert_eq!(body[0]["etag"], v2_etag.as_str());
    assert_eq!(body[1]["etag"], v1_etag.as_str());
}

#[tokio::test]
async fn re_uploading_identical_bytes_does_not_add_a_generation() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;
    // A client syncing on a timer sends the same file over and over; only a
    // real change is worth a slot in a five-deep history.
    let (id, _) = upload_and_revise(&t.app, &token, &[VAULT_V1, VAULT_V1, VAULT_V2]).await;

    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body[0]["size"], VAULT_V1.len());
}

#[tokio::test]
async fn only_the_newest_generations_are_kept() {
    let t = test_app();
    let token = register_and_login(&t.app, "a@example.com").await;

    // Two more saves than the history is deep.
    let revisions: Vec<Vec<u8>> = (0..MAX_VAULT_VERSIONS + 2)
        .map(|i| format!("PK\x03\x04 revision {i}").into_bytes())
        .collect();
    let borrowed: Vec<&[u8]> = revisions.iter().map(|v| v.as_slice()).collect();
    let (id, _) = upload_and_revise(&t.app, &token, &borrowed).await;

    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    let listed = body.as_array().unwrap();
    assert_eq!(listed.len(), MAX_VAULT_VERSIONS);
    // Newest first, and the ones that fell off are the oldest: the last
    // kept generation is the revision before the current one.
    let sizes: Vec<u64> = listed.iter().map(|v| v["size"].as_u64().unwrap()).collect();
    assert_eq!(
        sizes[0],
        revisions[revisions.len() - 2].len() as u64,
        "newest kept generation should be what the last save replaced"
    );
    let archived: Vec<&str> = listed.iter().map(|v| v["archived_at"].as_str().unwrap()).collect();
    let mut sorted = archived.clone();
    sorted.sort_unstable();
    sorted.reverse();
    assert_eq!(archived, sorted, "history must read newest first");

    // The dropped generations are unreachable, not merely unlisted.
    let (status, _) = send(
        &t.app,
        get_authed(&format!("/api/v1/vaults/{id}/versions/{}", Uuid::new_v4()), &token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn history_belongs_to_one_vault_one_account_and_dies_with_the_file() {
    let t = test_app();
    let alice = register_and_login(&t.app, "alice@example.com").await;
    let bob = register_and_login(&t.app, "bob@example.com").await;

    let (id, _) = upload_and_revise(&t.app, &alice, &[VAULT_V2]).await;
    let (status, body) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &alice)).await;
    assert_eq!(status, StatusCode::OK);
    let version_id = body[0]["id"].as_str().unwrap().to_string();

    // Bob cannot list, read or restore any of it.
    for request in [
        get_authed(&format!("/api/v1/vaults/{id}/versions"), &bob),
        get_authed(&format!("/api/v1/vaults/{id}/versions/{version_id}"), &bob),
        restore_req(&id, &version_id, &bob),
    ] {
        let (status, _) = send(&t.app, request).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Neither can Alice reach it through a different vault of her own: a
    // version id is only meaningful under the file it belongs to.
    let (status, body) = send(&t.app, upload("other.askrypt", &alice, VAULT_V1)).await;
    assert_eq!(status, StatusCode::CREATED);
    let other_id = body["id"].as_str().unwrap().to_string();
    let (status, _) = send(
        &t.app,
        get_authed(&format!("/api/v1/vaults/{other_id}/versions/{version_id}"), &alice),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleting the vault takes its history with it, bytes included.
    let (status, _) = send(&t.app, delete_authed(&format!("/api/v1/vaults/{id}"), &alice)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&t.app, get_authed(&format!("/api/v1/vaults/{id}/versions"), &alice)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Behind the API too: no index row survives, and neither do the bytes.
    let (_, me) = send(&t.app, get_authed("/api/v1/me", &alice)).await;
    let account_id: Uuid = me["id"].as_str().unwrap().parse().unwrap();
    assert!(
        t.state
            .vault_versions
            .list_for_account(account_id)
            .await
            .unwrap()
            .is_empty()
    );
    let orphan_id: Uuid = version_id.parse().unwrap();
    assert!(
        t.state
            .vault_version_blobs
            .get(account_id, orphan_id)
            .await
            .unwrap()
            .is_none()
    );
}
