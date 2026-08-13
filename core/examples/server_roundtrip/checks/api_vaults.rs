//! `/api/v1/vaults` — the vault file API, through the client that ships with
//! the desktop app and then through raw HTTP for the parts it has no method
//! for.
//!
//! This group runs on the account named on the command line, exactly as the
//! original round-trip example did: it creates vaults under a name carrying
//! this process's id and deletes them again in teardown.

use std::sync::Arc;

use askrypt::{ServerClient, ServerStorage, StorageError, VaultStorage, normalize_base_url};

use crate::report::Report;
use crate::{Ctx, vault};

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    report.group("vaults");

    let Some(client) = report.probe("the core client signs in", || {
        // `ServerClient::login` is the password form the desktop no longer
        // uses (it signs in through the browser), but it is still exported and
        // is the only non-interactive way in.
        ServerClient::login(
            &ctx.base,
            &ctx.main.email,
            &ctx.main.password,
            Some("server_roundtrip"),
        )
        .map(Arc::new)
        .map_err(|e| format!("{e}"))
    }) else {
        return;
    };

    report.check("the base URL normalizes to what was asked for", || {
        if client.base_url() == normalize_base_url(&ctx.base) {
            Ok(())
        } else {
            Err(format!(
                "client says {}, expected {}",
                client.base_url(),
                normalize_base_url(&ctx.base)
            ))
        }
    });

    let name = ctx.vault_name("api");
    let storage = ServerStorage::by_name(Arc::clone(&client), &name);

    report.check("the vault does not exist yet", || {
        if storage.exists() {
            return Err(format!("{name} is already on the server"));
        }
        Ok(())
    });

    let Some(original) = report.probe("a real vault is built and uploaded", || {
        let file = vault::fixture("first-generation")?;
        storage.save_vault(&file).map_err(|e| format!("{e}"))?;
        Ok(file)
    }) else {
        return;
    };

    let Some(vault_id) = report.probe("the upload was assigned an id", || {
        storage
            .vault_id()
            .ok_or_else(|| "no id after a successful upload".to_string())
    }) else {
        return;
    };
    ctx.vaults.push(vault_id.clone());

    report.check("it comes back byte-identical and still decrypts", || {
        let loaded = storage.load_vault().map_err(|e| format!("{e}"))?;
        if loaded != original {
            return Err("the vault did not survive the round trip".to_string());
        }
        let secret = vault::open(&loaded)?;
        if secret != "first-generation" {
            return Err(format!("decrypted the wrong secret: {secret:?}"));
        }
        Ok(())
    });

    report.check("it appears in the listing with a write stamp", || {
        let listed = client.list().map_err(|e| format!("{e}"))?;
        let row = listed
            .iter()
            .find(|vault| vault.name == name)
            .ok_or("the vault is not listed")?;
        if row.etag.is_empty() {
            return Err("the listing carries no ETag".to_string());
        }
        // The server lifts `params.host`/`params.updated_at` off the bytes;
        // core stamps both on every save, so both must be here.
        match (&row.host, &row.saved_at) {
            (Some(host), Some(saved)) => {
                println!("    saved by {host} at {saved}");
                Ok(())
            }
            (host, saved) => Err(format!(
                "expected a write stamp, got host={host:?} saved_at={saved:?}"
            )),
        }
    });

    report.check("a stale writer is refused", || {
        // A second handle holding the *current* ETag, which the first handle
        // then moves out from under it. The intervening write has to carry
        // different contents: the ETag is a content hash, so re-saving the
        // same vault leaves it exactly where it was and there would be no
        // conflict to detect.
        let listed = client.list().map_err(|e| format!("{e}"))?;
        let row = listed
            .iter()
            .find(|vault| vault.name == name)
            .ok_or("the vault is not listed")?;
        let stale = ServerStorage::existing(Arc::clone(&client), row);

        let moved_on = vault::fixture("second-generation")?;
        storage.save_vault(&moved_on).map_err(|e| format!("{e}"))?;
        let outcome = match stale.save_vault(&original) {
            Err(StorageError::Conflict(_)) => Ok(()),
            Err(e) => Err(format!("expected a conflict, got {e}")),
            Ok(()) => Err("the stale write was accepted".to_string()),
        };
        // Back to the generation the rest of the group expects.
        storage.save_vault(&original).map_err(|e| format!("{e}"))?;
        outcome
    });

    // Below here: the raw endpoints, which `ServerClient` does not cover.
    let vaults = format!("/api/v1/vaults/{vault_id}");

    let etag = report.probe("a download reports its ETag", || {
        let resp = ctx.main.http.get(&vaults)?;
        resp.expect(200)?;
        resp.etag()
            .filter(|etag| !etag.is_empty())
            .ok_or_else(|| "no ETag on the download".to_string())
    });

    if let Some(etag) = &etag {
        report.check("If-None-Match with the current ETag is a 304", || {
            let quoted = format!("\"{etag}\"");
            let resp = ctx
                .main
                .http
                .get_with(&vaults, &[("If-None-Match", &quoted)])?;
            resp.expect(304)?;
            if !resp.body.is_empty() {
                return Err("a 304 carried a body".to_string());
            }
            Ok(())
        });

        report.check(
            "a download opts out of no-store but keeps revalidating",
            || {
                let resp = ctx.main.http.get(&vaults)?;
                match resp.header("cache-control") {
                    Some(value) if value.contains("private") && value.contains("no-cache") => {
                        Ok(())
                    }
                    other => Err(format!("unexpected cache directive {other:?}")),
                }
            },
        );
    }

    report.check("an overwrite with no If-Match is refused", || {
        let bytes = vault::fixture_bytes("second-generation")?;
        let resp = ctx.main.http.blob("PUT", &vaults, &[], bytes)?;
        resp.expect_error(428, "precondition_required")?;
        Ok(())
    });

    report.check("an overwrite with a stale If-Match is refused", || {
        let bytes = vault::fixture_bytes("second-generation")?;
        let stale = format!("\"{}\"", "0".repeat(64));
        let resp = ctx
            .main
            .http
            .blob("PUT", &vaults, &[("If-Match", &stale)], bytes)?;
        resp.expect_error(412, "precondition_failed")?;
        Ok(())
    });

    report.check("a duplicate name is refused", || {
        let bytes = vault::fixture_bytes("duplicate")?;
        let path = format!("/api/v1/vaults?name={name}");
        let resp = ctx.main.http.blob("POST", &path, &[], bytes)?;
        resp.expect_error(409, "conflict")?;
        Ok(())
    });

    report.check("a name with a path separator is refused", || {
        let path = "/api/v1/vaults?name=..%2Fescape.askrypt";
        let bytes = vault::fixture_bytes("escape")?;
        let resp = ctx.main.http.blob("POST", path, &[], bytes)?;
        resp.expect_error(400, "invalid_vault_name")?;
        Ok(())
    });

    report.check("bytes that are not an archive are refused", || {
        let path = format!("/api/v1/vaults?name={}", ctx.vault_name("garbage"));
        let resp = ctx
            .main
            .http
            .blob("POST", &path, &[], b"not a zip at all".to_vec())?;
        resp.expect_error(400, "invalid_vault_file")?;
        Ok(())
    });

    report.check("the global body limit refuses an oversize request", || {
        // Any route outside the vault subtree, which raises its own limit.
        let body = serde_json::json!({ "email": "x@y.zz", "password": "z".repeat(100 * 1024) });
        let resp = ctx.main.http.post_json("/api/v1/auth/login", &body)?;
        resp.expect_error(413, "payload_too_large")?;
        Ok(())
    });

    // The regression test for the layer ordering: the vault routes' own,
    // larger limit is declared *inside* the global one and must override it.
    let big_name = ctx.vault_name("big");
    if let Some(id) = report.probe("a vault past the global limit is still accepted", || {
        let bytes = vault::to_bytes(&vault::padded_fixture("big", 200 * 1024)?)?;
        if bytes.len() < 64 * 1024 {
            return Err(format!("the fixture is only {} bytes", bytes.len()));
        }
        let path = format!("/api/v1/vaults?name={big_name}");
        let resp = ctx.main.http.blob("POST", &path, &[], bytes)?;
        resp.expect(201)?;
        resp.json()
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .ok_or_else(|| "no id in the upload response".to_string())
    }) {
        ctx.vaults.push(id);
    }

    report.check("renaming keeps the ETag, which is a content hash", || {
        let renamed = ctx.vault_name("api-renamed");
        let before = ctx.main.http.get(&vaults)?.etag();
        client
            .rename(&vault_id, &renamed)
            .map_err(|e| format!("{e}"))?;
        let after = ctx.main.http.get(&vaults)?.etag();
        if before != after {
            return Err("the ETag moved when only the name did".to_string());
        }
        let listed = client.list().map_err(|e| format!("{e}"))?;
        if !listed.iter().any(|vault| vault.name == renamed) {
            return Err("the new name is not listed".to_string());
        }
        // Put it back so the later groups can find it by its original name.
        client
            .rename(&vault_id, &name)
            .map_err(|e| format!("{e}"))?;
        Ok(())
    });

    if let Some(b) = &ctx.b {
        report.check("another account cannot see this vault", || {
            // Not 403: the server must not confirm that the id exists.
            b.http.get(&vaults)?.expect_error(404, "not_found")?;
            let bytes = vault::fixture_bytes("intruder")?;
            b.http
                .blob("PUT", &vaults, &[("If-Match", "\"whatever\"")], bytes)?
                .expect_error(404, "not_found")?;
            b.http.delete(&vaults)?.expect_error(404, "not_found")?;
            Ok(())
        });
    } else {
        report.skip(
            "another account cannot see this vault",
            "no throwaway account",
        );
    }
}
