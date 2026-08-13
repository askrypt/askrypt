//! The administrator's pages — and, whatever the given account turns out to
//! be, the proof that a plain account cannot reach them.
//!
//! Administration is a website capability: there is no JSON admin API, so
//! every one of these goes through the cookie-authenticated forms. Both halves
//! run in a single pass — the non-admin assertions use the given account when
//! it is not an administrator and throwaway A when it is, so one run always
//! covers both.

use serde_json::json;

use super::{need_throwaway, set_registration, sign_in_api, web_sign_in};
use crate::http::Http;
use crate::report::Report;
use crate::{Account, Ctx, vault};

/// How many listing pages to walk looking for an account. The page shows 50
/// at a time; a dev server with a thousand accounts is not what this is for.
const MAX_PAGES: u32 = 20;

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    if ctx.captcha {
        report.skip_group(
            "admin",
            "reCAPTCHA is configured; no browser session can be established",
        );
        return;
    }
    report.group("admin");
    // Every `/admin/*` route shares one 20/minute bucket with the profile
    // mutations, and every identity in this run comes from one address, so the
    // group will stop to wait more than once. That is the limiter working.
    println!("  (rate limited to 20/minute; this group pauses)");

    report.check("a signed-out visitor is redirected, not refused", || {
        // Deliberately different from the 403 a signed-in non-administrator
        // gets: one needs to sign in, the other needs a role.
        let anon = ctx.main.http.anonymous();
        anon.get("/admin/users")?.expect_redirect("/login")?;
        anon.get("/admin/settings")?.expect_redirect("/login")?;
        Ok(())
    });

    refusals(report, ctx);

    if ctx.is_admin {
        privileges(report, ctx);
    } else {
        report.skip(
            "the administrative actions",
            "the given account is not an administrator",
        );
    }
}

/// Everything a plain account must not be able to do.
fn refusals(report: &mut Report, ctx: &Ctx) {
    // When the given account is an administrator, a throwaway stands in for
    // the ordinary visitor, so one run covers both halves.
    let plain: Option<&Account> = if ctx.is_admin {
        ctx.a.as_ref()
    } else {
        Some(&ctx.main)
    };
    let Some(plain) = plain else {
        need_throwaway(report, "admin");
        return;
    };

    if ctx.is_admin {
        let signed_in = report.check("a plain account has a browser session", || {
            web_sign_in(&plain.http, &plain.email, &plain.password)
        });
        if !signed_in {
            return;
        }
    }

    report.check("a plain account is refused the Users page", || {
        let resp = plain.http.get("/admin/users")?;
        resp.expect(403)?;
        // A refusal that still rendered the table would be the worse bug.
        resp.expect_missing("id=\"user-list\"")?;
        Ok(())
    });

    report.check("a plain account is refused the Settings page", || {
        let resp = plain.http.get("/admin/settings")?;
        resp.expect(403)?;
        resp.expect_missing("id=\"server-settings\"")?;
        Ok(())
    });

    report.check("the nav offers no administrative links", || {
        let resp = plain.http.get("/account")?;
        resp.expect(200)?;
        resp.expect_missing("/admin/users")?;
        resp.expect_missing("/admin/settings")?;
        Ok(())
    });

    // Every mutating route, with a *valid* CSRF token: the refusal has to be
    // the role gate rather than the token check, or this would prove nothing.
    // The target is the caller's own id, which is harmless — `AdminSession`
    // rejects before any handler runs.
    let id = &plain.id;
    let posts: Vec<(String, Vec<(&str, &str)>)> = vec![
        (format!("/admin/users/{id}/ban"), vec![]),
        (format!("/admin/users/{id}/unban"), vec![]),
        (
            format!("/admin/users/{id}/role"),
            vec![("role", "ADMIN"), ("action", "grant")],
        ),
        (
            format!("/admin/users/{id}/role"),
            vec![("role", "PAYMENT_USER"), ("action", "grant")],
        ),
        (
            format!("/admin/users/{id}/delete"),
            vec![("confirm", plain.email.as_str())],
        ),
        ("/admin/settings".to_string(), vec![("enabled", "false")]),
    ];
    for (path, fields) in &posts {
        report.check(&format!("POST {path} is refused"), || {
            plain.http.form(path, fields)?.expect(403)?;
            Ok(())
        });
    }

    report.check("none of that changed anything", || {
        // Still signed in, still not an administrator, still there: a refusal
        // with a side effect would pass every check above.
        plain.http.get("/account")?.expect(200)?;
        plain.http.get("/admin/users")?.expect(403)?;
        let resp = plain.http.get("/api/v1/me")?;
        if resp.status == 401 {
            // Its bearer may legitimately have been revoked earlier in the
            // run (a password change does that); the cookie session above is
            // the evidence that matters.
            return Ok(());
        }
        resp.expect(200)?;
        Ok(())
    });
}

/// Everything an administrator must be able to do, all of it aimed at
/// throwaway B.
fn privileges(report: &mut Report, ctx: &mut Ctx) {
    // Taken out of the context for the duration: deleting B at the end has to
    // be able to tell teardown there is nothing left to clean up.
    let target = ctx.b.take();
    let deleted = with_target(report, ctx, target.as_ref());
    if !deleted {
        ctx.b = target;
    }
}

/// Returns whether the target account was deleted by the run.
fn with_target(report: &mut Report, ctx: &Ctx, b: Option<&Account>) -> bool {
    let admin = &ctx.main.http;

    report.check("the Users page lists accounts", || {
        let resp = admin.get("/admin/users")?;
        resp.expect(200)?;
        resp.expect_contains("id=\"user-list\"")?;
        resp.expect_contains(&ctx.main.email)?;
        Ok(())
    });

    report.check("the nav offers the administrative links", || {
        let resp = admin.get("/account")?;
        resp.expect(200)?;
        resp.expect_contains("/admin/users")?;
        resp.expect_contains("/admin/settings")?;
        Ok(())
    });

    report.check("acting on your own account is refused", || {
        // 200 rather than a 4xx: the page re-renders with the refusal above
        // the table, which is how every guard reads on the no-JS path.
        let resp = admin.form(&format!("/admin/users/{}/ban", ctx.main.id), &[])?;
        resp.expect(200)?;
        resp.expect_contains("cannot ban your own account")?;
        if find_row(admin, &ctx.main.email)?.contains("Suspended") {
            return Err("the refused ban landed anyway".to_string());
        }
        Ok(())
    });

    report.check("the settings page renders", || {
        let resp = admin.get("/admin/settings")?;
        resp.expect(200)?;
        resp.expect_contains("id=\"server-settings\"")?;
        Ok(())
    });

    report.check("the registration switch closes the server", || {
        set_registration(admin, false)?;
        let resp = admin.anonymous().post_json(
            "/api/v1/auth/register",
            &json!({
                "email": format!("closed-{}@roundtrip.invalid", ctx.run_id),
                "password": "long-enough-password",
            }),
        )?;
        resp.expect_error(403, "registration_disabled")?;
        // The browser form still renders — a visitor who really came to sign
        // in still needs the link on it — but it says so.
        let page = admin.anonymous().get("/register")?;
        page.expect(200)?;
        page.expect_contains("not accepting new accounts")?;
        Ok(())
    });

    report.check("and opens it again", || {
        set_registration(admin, true)?;
        let resp = admin.anonymous().post_json(
            "/api/v1/auth/register",
            &json!({ "email": "not-an-address", "password": "long-enough-password" }),
        )?;
        // Reaching the *validation* is the proof that the gate is open again.
        resp.expect_error(400, "invalid_email")?;
        Ok(())
    });

    let Some(b) = b else {
        report.skip(
            "the actions that need a target account",
            "no second throwaway account",
        );
        return false;
    };

    report.check("an unknown role is refused", || {
        let resp = admin.form(
            &format!("/admin/users/{}/role", b.id),
            &[("role", "SUPERUSER"), ("action", "grant")],
        )?;
        resp.expect(200)?;
        resp.expect_contains("not a role this page can grant")?;
        Ok(())
    });

    report.check("suspending an account signs it out everywhere", || {
        admin
            .form(&format!("/admin/users/{}/ban", b.id), &[])?
            .expect_redirect("/admin/users")?;
        if !find_row(admin, &b.email)?.contains("Suspended") {
            return Err("the row does not show the suspension".to_string());
        }
        // A ban has to bite on the very next request, on both surfaces.
        b.http
            .get("/api/v1/me")?
            .expect_error(401, "unauthorized")?;
        let resp = b.http.anonymous().post_json(
            "/api/v1/auth/login",
            &json!({ "email": b.email, "password": b.password }),
        )?;
        resp.expect_error(403, "account_banned")?;
        Ok(())
    });

    report.check("lifting the suspension restores both", || {
        admin
            .form(&format!("/admin/users/{}/unban", b.id), &[])?
            .expect_redirect("/admin/users")?;
        if find_row(admin, &b.email)?.contains("Suspended") {
            return Err("the row still shows a suspension".to_string());
        }
        sign_in_api(b)?;
        b.http.get("/api/v1/me")?.expect(200)?;
        Ok(())
    });

    report.check("the paid tier can be granted and revoked", || {
        set_role(admin, b, "PAYMENT_USER", true)?;
        if !find_row(admin, &b.email)?.contains(">paid<") {
            return Err("the row does not show the paid tag".to_string());
        }
        set_role(admin, b, "PAYMENT_USER", false)?;
        if find_row(admin, &b.email)?.contains(">paid<") {
            return Err("the paid tag survived the revoke".to_string());
        }
        Ok(())
    });

    report.check("the administrator role can be granted and revoked", || {
        set_role(admin, b, "ADMIN", true)?;
        if !find_row(admin, &b.email)?.contains(">admin<") {
            return Err("the row does not show the admin tag".to_string());
        }
        // And it is a real role, not a badge: B can reach the page with it.
        web_sign_in(&b.http, &b.email, &b.password)?;
        b.http.get("/admin/users")?.expect(200)?;

        set_role(admin, b, "ADMIN", false)?;
        b.http.get("/admin/users")?.expect(403)?;
        Ok(())
    });

    report.check("a delete with the wrong confirmation is refused", || {
        let resp = admin.form(
            &format!("/admin/users/{}/delete", b.id),
            &[("confirm", "not-the-address")],
        )?;
        resp.expect(200)?;
        resp.expect_contains("exactly to confirm")?;
        find_row(admin, &b.email)?;
        Ok(())
    });

    let stored = report.probe("the target account stores a vault", || {
        let bytes = vault::fixture_bytes("belongs-to-b")?;
        let path = format!("/api/v1/vaults?name={}", ctx.vault_name("b"));
        let resp = b.http.blob("POST", &path, &[], bytes)?;
        resp.expect(201)?;
        resp.json()
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .ok_or_else(|| "no id in the upload response".to_string())
    });

    // Last, because everything above needs the account.
    let deleted = report.check("a delete with the exact address goes through", || {
        admin
            .form(
                &format!("/admin/users/{}/delete", b.id),
                &[("confirm", &b.email)],
            )?
            .expect_redirect("/admin/users")?;
        match find_row(admin, &b.email) {
            Ok(_) => Err("the account is still listed".to_string()),
            Err(_) => Ok(()),
        }
    });

    if deleted {
        report.check("its vaults went with it", || {
            let Some(stored) = &stored else {
                return Ok(());
            };
            // Asked as the administrator, whose own account never held it:
            // the id must now belong to nobody.
            admin
                .get(&format!("/api/v1/vaults/{stored}"))?
                .expect_error(404, "not_found")?;
            Ok(())
        });
        report.check("it can no longer sign in", || {
            let resp = b.http.anonymous().post_json(
                "/api/v1/auth/login",
                &json!({ "email": b.email, "password": b.password }),
            )?;
            resp.expect_error(401, "invalid_credentials")?;
            Ok(())
        });
    }
    deleted
}

/// One role change, through the single route both buttons post to.
fn set_role(admin: &Http, target: &Account, role: &str, grant: bool) -> Result<(), String> {
    let action = if grant { "grant" } else { "revoke" };
    admin
        .form(
            &format!("/admin/users/{}/role", target.id),
            &[("role", role), ("action", action)],
        )?
        .expect_redirect("/admin/users")?;
    Ok(())
}

/// The listing row for an address, walking the pages if it is not on the
/// first: the listing is ordered by creation, so a freshly registered account
/// is on the *last* page of a server with a real number of accounts.
fn find_row(admin: &Http, email: &str) -> Result<String, String> {
    for page in 1..=MAX_PAGES {
        let resp = admin.get(&format!("/admin/users?page={page}"))?;
        resp.expect(200)?;
        let html = resp.text();
        if let Some(row) = row_of(&html, email) {
            return Ok(row);
        }
        if !html.contains(&format!("page={}", page + 1)) {
            break;
        }
    }
    Err(format!("no row for {email} in the listing"))
}

/// The `<tr>` an address appears in.
fn row_of(html: &str, email: &str) -> Option<String> {
    html.split("<tr>")
        .find(|row| row.contains(email))
        .map(|row| row.split("</tr>").next().unwrap_or(row).to_string())
}
