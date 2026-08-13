//! `/api/v1/vaults/{id}/versions` — the generations a save replaced.
//!
//! The interesting properties are not "a list came back" but the three rules
//! the archive is built on: an overwrite that changes nothing makes no
//! generation, an archived generation is the exact bytes it displaced, and a
//! restore is an ordinary overwrite — so it archives what *it* displaces and
//! is itself undoable.

use serde_json::Value;

use crate::report::Report;
use crate::{Ctx, vault};

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    report.group("versions");

    let name = ctx.vault_name("versions");
    let Some((id, first)) = report.probe("a vault is uploaded to build history on", || {
        let bytes = vault::fixture_bytes("generation-1")?;
        let path = format!("/api/v1/vaults?name={name}");
        let resp = ctx.main.http.blob("POST", &path, &[], bytes.clone())?;
        resp.expect(201)?;
        let id = resp
            .json()
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or("no id in the upload response")?
            .to_string();
        Ok((id, bytes))
    }) else {
        return;
    };
    ctx.vaults.push(id.clone());

    let vault_path = format!("/api/v1/vaults/{id}");
    let versions_path = format!("{vault_path}/versions");

    report.check("a fresh vault has no history", || {
        let resp = ctx.main.http.get(&versions_path)?;
        resp.expect(200)?;
        match resp.json().as_array().map(Vec::len) {
            Some(0) => Ok(()),
            other => Err(format!("expected no versions, found {other:?}")),
        }
    });

    let Some(second) = report.probe("an overwrite archives what it replaced", || {
        let etag = current_etag(ctx, &vault_path)?;
        let bytes = vault::fixture_bytes("generation-2")?;
        let resp = ctx.main.http.blob(
            "PUT",
            &vault_path,
            &[("If-Match", &quoted(&etag))],
            bytes.clone(),
        )?;
        resp.expect(200)?;
        let versions = list(ctx, &versions_path)?;
        if versions.len() != 1 {
            return Err(format!("expected 1 generation, found {}", versions.len()));
        }
        Ok(bytes)
    }) else {
        return;
    };

    report.check("the archived bytes are the ones it displaced", || {
        let versions = list(ctx, &versions_path)?;
        let version_id = version_id(&versions[0])?;
        let resp = ctx
            .main
            .http
            .get(&format!("{versions_path}/{version_id}"))?;
        resp.expect(200)?;
        if resp.body != first {
            return Err("the archived generation is not the bytes it replaced".to_string());
        }
        Ok(())
    });

    report.check("re-uploading identical bytes makes no generation", || {
        let etag = current_etag(ctx, &vault_path)?;
        let resp = ctx.main.http.blob(
            "PUT",
            &vault_path,
            &[("If-Match", &quoted(&etag))],
            second.clone(),
        )?;
        resp.expect(200)?;
        let versions = list(ctx, &versions_path)?;
        if versions.len() != 1 {
            return Err(format!(
                "expected the history to stay at 1, found {}",
                versions.len()
            ));
        }
        Ok(())
    });

    report.check("history is newest first", || {
        // A third generation, so there are two to order.
        let etag = current_etag(ctx, &vault_path)?;
        let bytes = vault::fixture_bytes("generation-3")?;
        ctx.main
            .http
            .blob("PUT", &vault_path, &[("If-Match", &quoted(&etag))], bytes)?
            .expect(200)?;
        let versions = list(ctx, &versions_path)?;
        if versions.len() != 2 {
            return Err(format!("expected 2 generations, found {}", versions.len()));
        }
        let archived: Vec<&str> = versions
            .iter()
            .filter_map(|version| version.get("archived_at").and_then(Value::as_str))
            .collect();
        if archived.len() != 2 {
            return Err("a generation has no archival timestamp".to_string());
        }
        if archived[0] < archived[1] {
            return Err(format!("history is oldest first: {archived:?}"));
        }
        Ok(())
    });

    report.check("restoring writes an old generation back", || {
        let versions = list(ctx, &versions_path)?;
        // The oldest kept generation, which is the very first upload.
        let oldest = versions.last().ok_or("no history to restore from")?;
        let version_id = version_id(oldest)?;
        let etag = current_etag(ctx, &vault_path)?;
        let resp = ctx.main.http.blob(
            "POST",
            &format!("{versions_path}/{version_id}/restore"),
            &[("If-Match", &quoted(&etag))],
            Vec::new(),
        )?;
        resp.expect(200)?;

        let live = ctx.main.http.get(&vault_path)?;
        live.expect(200)?;
        if live.body != first {
            return Err("the live vault is not the restored generation".to_string());
        }
        // And it still opens — a restore that returned unusable bytes would
        // pass every byte comparison above and still be a broken feature.
        let file = askrypt::AskryptFile::from_bytes(&live.body)
            .map_err(|e| format!("the restored vault does not parse: {e}"))?;
        let secret = vault::open(&file)?;
        if secret != "generation-1" {
            return Err(format!("restored the wrong generation: {secret:?}"));
        }
        Ok(())
    });

    report.check("a restore is itself undoable", || {
        // The restore displaced generation-3, so that must now be in history.
        let versions = list(ctx, &versions_path)?;
        if versions.len() < 3 {
            return Err(format!(
                "expected the displaced state to be archived, found {} generations",
                versions.len()
            ));
        }
        let newest = version_id(&versions[0])?;
        let resp = ctx.main.http.get(&format!("{versions_path}/{newest}"))?;
        resp.expect(200)?;
        let file = askrypt::AskryptFile::from_bytes(&resp.body)
            .map_err(|e| format!("the archived vault does not parse: {e}"))?;
        if vault::open(&file)? != "generation-3" {
            return Err("the newest generation is not the state the restore replaced".to_string());
        }
        Ok(())
    });

    report.check("an unknown version id is a 404", || {
        let unknown = "00000000-0000-4000-8000-000000000000";
        ctx.main
            .http
            .get(&format!("{versions_path}/{unknown}"))?
            .expect_error(404, "not_found")?;
        Ok(())
    });

    if let Some(b) = &ctx.b {
        report.check("another account cannot read this history", || {
            b.http.get(&versions_path)?.expect_error(404, "not_found")?;
            Ok(())
        });
    } else {
        report.skip(
            "another account cannot read this history",
            "no throwaway account",
        );
    }
}

fn list(ctx: &Ctx, path: &str) -> Result<Vec<Value>, String> {
    let resp = ctx.main.http.get(path)?;
    resp.expect(200)?;
    resp.json()
        .as_array()
        .cloned()
        .ok_or_else(|| "the version listing is not an array".to_string())
}

fn version_id(version: &Value) -> Result<String, String> {
    version
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "a version has no id".to_string())
}

fn current_etag(ctx: &Ctx, vault_path: &str) -> Result<String, String> {
    let resp = ctx.main.http.get(vault_path)?;
    resp.expect(200)?;
    resp.etag()
        .ok_or_else(|| "the download carried no ETag".to_string())
}

fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}
