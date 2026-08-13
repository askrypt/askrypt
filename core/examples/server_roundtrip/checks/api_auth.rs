//! `/api/v1/auth` and the API's shape rules, plus the throwaway accounts the
//! later groups act on.

use serde_json::json;

use super::{register, sign_in_api};
use crate::Ctx;
use crate::report::Report;

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    report.group("auth");

    report.check("an unknown /api/v1 path is a JSON 404", || {
        let resp = ctx.main.http.get("/api/v1/nope")?;
        resp.expect_error(404, "not_found")?;
        Ok(())
    });

    report.check("an unknown /api path is a JSON 404 too", || {
        // The fallback covers everything under /api, not just the versioned
        // nest — a page would be a strange thing to hand an API client.
        let resp = ctx.main.http.get("/api/nope")?;
        resp.expect_error(404, "not_found")?;
        Ok(())
    });

    report.check("there is no JSON admin API", || {
        // Administration is a website capability. If this ever answers
        // anything but 404, a whole surface has appeared without a gate.
        for path in ["/api/v1/admin", "/api/v1/admin/users", "/api/v1/settings"] {
            ctx.main.http.get(path)?.expect_error(404, "not_found")?;
        }
        Ok(())
    });

    report.check("a request with no bearer is refused", || {
        let resp = ctx.main.http.anonymous().get("/api/v1/me")?;
        resp.expect_error(401, "unauthorized")?;
        Ok(())
    });

    report.check("a garbage bearer gets the same opaque 401", || {
        let anon = ctx.main.http.anonymous();
        anon.set_bearer(Some("0123456789abcdef".to_string()));
        let resp = anon.get("/api/v1/me")?;
        resp.expect_error(401, "unauthorized")?;
        Ok(())
    });

    report.check("the wrong password is refused", || {
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/login",
            &json!({ "email": ctx.main.email, "password": "not-the-password" }),
        )?;
        // Uniform with an unknown address: the endpoint must not say which
        // half was wrong.
        resp.expect_error(401, "invalid_credentials")?;
        Ok(())
    });

    report.check("an unknown address gets the identical refusal", || {
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/login",
            &json!({ "email": "nobody@roundtrip.invalid", "password": "not-the-password" }),
        )?;
        resp.expect_error(401, "invalid_credentials")?;
        Ok(())
    });

    // Registration. Everything below needs it, so a closed server skips the
    // rest of the group rather than failing it.
    if ctx.restore_registration.is_none() && !registration_open(ctx) {
        report.skip(
            "throwaway accounts are registered",
            "registration is closed",
        );
        return;
    }

    if let Some(account) = report.probe("a throwaway account registers (A)", || register(ctx, "a"))
    {
        ctx.a = Some(account);
    }
    if let Some(account) = report.probe("a second one registers (B)", || register(ctx, "b")) {
        ctx.b = Some(account);
    }

    if let Some(a) = &ctx.a {
        report.check("the same address cannot register twice", || {
            let resp = ctx.main.http.anonymous().post_json(
                "/api/v1/auth/register",
                &json!({ "email": a.email, "password": a.password }),
            )?;
            resp.expect_error(409, "conflict")?;
            Ok(())
        });
    }

    report.check("a short password is refused", || {
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/register",
            &json!({ "email": format!("short-{}@roundtrip.invalid", ctx.run_id), "password": "1234567" }),
        )?;
        resp.expect_error(400, "invalid_password")?;
        Ok(())
    });

    report.check("a malformed address is refused", || {
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/register",
            &json!({ "email": "not-an-address", "password": "long-enough-password" }),
        )?;
        resp.expect_error(400, "invalid_email")?;
        Ok(())
    });

    if let Some(a) = &ctx.a {
        report.check("logging out kills the token", || {
            // A second session, so the account keeps the one the later groups
            // use.
            let handle = a.http.anonymous();
            let token = super::api_token(&handle, &a.email, &a.password)?;
            handle.set_bearer(Some(token));
            handle.get("/api/v1/me")?.expect(200)?;
            handle
                .post_json("/api/v1/auth/logout", &json!({}))?
                .expect(204)?;
            handle
                .get("/api/v1/me")?
                .expect_error(401, "unauthorized")?;
            Ok(())
        });

        report.check("the throwaway's own session still works", || {
            // Logging one session out must not touch the others.
            sign_in_api(a)?;
            a.http.get("/api/v1/me")?.expect(200)?;
            Ok(())
        });
    }
}

/// Whether a register call would be accepted, without creating anything.
fn registration_open(ctx: &Ctx) -> bool {
    let Ok(resp) = ctx.main.http.anonymous().post_json(
        "/api/v1/auth/register",
        &json!({ "email": format!("probe2-{}@roundtrip.invalid", ctx.run_id), "password": "x" }),
    ) else {
        return false;
    };
    resp.error_code() != "registration_disabled"
}
