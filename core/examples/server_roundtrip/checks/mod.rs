//! The check groups, plus the preflight that decides which of them can run
//! and the teardown that puts the server back.

pub mod admin;
pub mod api_auth;
pub mod api_profile;
pub mod api_vaults;
pub mod api_versions;
pub mod devicelink;
pub mod web_site;

use serde_json::json;

use crate::http::{Http, SESSION_COOKIE};
use crate::report::Report;
use crate::{Account, Ctx};

/// Probes the server, signs the given account in on both surfaces, works out
/// whether it is an administrator, and creates the throwaway accounts.
///
/// Returns `false` when nothing further is worth attempting.
pub fn preflight(report: &mut Report, ctx: &mut Ctx) -> bool {
    report.group("preflight");

    let alive = report.check("the server answers /healthz", || {
        let resp = ctx.main.http.get("/healthz")?;
        resp.expect(200)?;
        match resp.json().get("status").and_then(|s| s.as_str()) {
            Some("ok") => Ok(()),
            other => Err(format!("unexpected health payload: {other:?}")),
        }
    });
    if !alive {
        return false;
    }

    report.check("GET /api/v1/about names the server", || {
        let resp = ctx.main.http.get("/api/v1/about")?;
        resp.expect(200)?;
        let body = resp.json();
        match (body.get("name"), body.get("version")) {
            (Some(name), Some(version)) => {
                println!("    {} {}", name.as_str().unwrap_or("?"), version);
                Ok(())
            }
            _ => Err(format!("unexpected about payload: {body}")),
        }
    });

    // Whether the website's forms are usable by a client that cannot run
    // JavaScript. With a site key configured they are not, and every check
    // that needs a browser session has to be skipped rather than failed.
    ctx.captcha = report
        .probe("reCAPTCHA is not configured", || {
            let resp = ctx.main.http.get("/login")?;
            resp.expect(200)?;
            let configured = resp.text().contains("data-captcha-key");
            if configured {
                println!("    a site key is configured: the website checks will be skipped");
            }
            Ok(configured)
        })
        .unwrap_or(false);

    let signed_in = report.check("the given account signs in over the JSON API", || {
        let resp = ctx.main.http.post_json(
            "/api/v1/auth/login",
            &json!({
                "email": ctx.main.email,
                "password": ctx.main.password,
                "device_label": "server_roundtrip",
            }),
        )?;
        resp.expect(200)?;
        let body = resp.json();
        let token = body
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or("no token in the session response")?;
        ctx.main.http.set_bearer(Some(token.to_string()));
        Ok(())
    });
    if !signed_in {
        return false;
    }

    if let Some(id) = report.probe("GET /api/v1/me identifies the account", || {
        let resp = ctx.main.http.get("/api/v1/me")?;
        resp.expect(200)?;
        resp.json()
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .ok_or_else(|| "no id in the profile".to_string())
    }) {
        ctx.main.id = id;
    }

    if ctx.captcha {
        report.skip(
            "the given account signs in over the website",
            "reCAPTCHA is configured",
        );
    } else {
        report.check("the given account signs in over the website", || {
            web_sign_in(&ctx.main.http, &ctx.main.email, &ctx.main.password)
        });

        // 200 or 403 — the two answers `AdminSession` gives a signed-in
        // visitor. A 303 means the cookie never took, and guessing from the
        // nav markup instead would be a worse answer than saying so.
        ctx.is_admin = report
            .probe("the account's role is known", || {
                let resp = ctx.main.http.get("/admin/users")?;
                match resp.status {
                    200 => {
                        println!("    this account IS an administrator");
                        Ok(true)
                    }
                    403 => {
                        println!("    this account is NOT an administrator");
                        Ok(false)
                    }
                    303 => Err("the browser session did not take (303 to /login)".to_string()),
                    other => Err(format!("unexpected status {other} from /admin/users")),
                }
            })
            .unwrap_or(false);
    }

    open_registration_if_needed(report, ctx);
    true
}

/// Registration may be closed. An administrator can open it for the run and
/// owes it back in teardown; anyone else has to do without throwaways.
fn open_registration_if_needed(report: &mut Report, ctx: &mut Ctx) {
    let Some(closed) = report.probe("registration is open", || {
        // A deliberately invalid password: `register_account` checks the
        // switch *before* validating anything, so a closed server answers
        // `registration_disabled` and an open one answers `invalid_password`
        // — and neither creates an account.
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/register",
            &json!({ "email": format!("probe-{}@roundtrip.invalid", ctx.run_id), "password": "x" }),
        )?;
        match (resp.status, resp.error_code().as_str()) {
            (403, "registration_disabled") => Ok(true),
            (400, "invalid_password") => Ok(false),
            (status, code) => Err(format!("unexpected probe answer {status} {code:?}")),
        }
    }) else {
        return;
    };
    if !closed {
        return;
    }
    if !ctx.is_admin {
        report.skip(
            "registration is opened for the run",
            "registration is closed and this account cannot open it",
        );
        return;
    }
    if report.check("registration is opened for the run", || {
        set_registration(&ctx.main.http, true)
    }) {
        ctx.restore_registration = Some(false);
    }
}

/// Signs a handle in through the website's form.
///
/// A successful submit is a **303**; a refused one re-renders the form at 200,
/// which is what makes the status alone a verdict.
pub fn web_sign_in(handle: &Http, email: &str, password: &str) -> Result<(), String> {
    handle.get("/login")?.expect(200)?;
    let resp = handle.form("/login", &[("email", email), ("password", password)])?;
    if resp.status == 200 {
        return Err("the form was refused (check the password)".to_string());
    }
    resp.expect_redirect("/account")?;
    handle
        .cookie(SESSION_COOKIE)
        .ok_or_else(|| "no session cookie was set".to_string())?;
    Ok(())
}

/// Flips the server-wide registration switch through the administrator's page.
pub fn set_registration(admin: &Http, enabled: bool) -> Result<(), String> {
    admin.get("/admin/settings")?.expect(200)?;
    let value = if enabled { "true" } else { "false" };
    admin
        .form("/admin/settings", &[("enabled", value)])?
        .expect_redirect("/admin/settings")?;
    Ok(())
}

/// Registers a throwaway account and signs it in over the JSON API.
pub fn register(ctx: &Ctx, suffix: &str) -> Result<Account, String> {
    let email = format!("roundtrip-{}-{suffix}@roundtrip.invalid", ctx.run_id);
    let password = format!("roundtrip-{}-{suffix}-pw", ctx.run_id);
    let handle = Http::new(&ctx.base);

    let resp = handle.post_json(
        "/api/v1/auth/register",
        &json!({ "email": email, "password": password }),
    )?;
    resp.expect(201)?;
    let id = resp
        .json()
        .get("id")
        .and_then(|id| id.as_str())
        .ok_or("no id in the register response")?
        .to_string();

    let account = Account {
        email,
        password,
        id,
        http: handle,
    };
    sign_in_api(&account)?;
    Ok(account)
}

/// Gives an account a fresh bearer token on its own handle.
pub fn sign_in_api(account: &Account) -> Result<(), String> {
    let token = api_token(&account.http, &account.email, &account.password)?;
    account.http.set_bearer(Some(token));
    Ok(())
}

/// A bearer token for an account, without disturbing any handle's state.
pub fn api_token(handle: &Http, email: &str, password: &str) -> Result<String, String> {
    let resp = handle.anonymous().post_json(
        "/api/v1/auth/login",
        &json!({ "email": email, "password": password, "device_label": "server_roundtrip" }),
    )?;
    resp.expect(200)?;
    resp.json()
        .get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| "no token in the session response".to_string())
}

/// Reports a group as unrunnable because a throwaway account is missing.
pub fn need_throwaway(report: &mut Report, group: &str) {
    report.skip_group(
        group,
        "no throwaway account (registration is closed on this server)",
    );
}

/// Puts the server back: the vaults this run created, the accounts it
/// registered, the switch it flipped, and the sessions it opened.
///
/// Every step is itself a reported check, so a leak is visible rather than
/// silent.
pub fn teardown(report: &mut Report, ctx: &mut Ctx) {
    report.group("teardown");

    let vaults = std::mem::take(&mut ctx.vaults);
    for id in vaults {
        report.check(&format!("vault {id} is deleted"), || {
            let resp = ctx.main.http.delete(&format!("/api/v1/vaults/{id}"))?;
            // Already gone is the outcome we wanted either way.
            if resp.status == 204 || resp.status == 404 {
                Ok(())
            } else {
                Err(format!("unexpected status {}", resp.status))
            }
        });
    }

    for (label, account) in [("A", ctx.a.take()), ("B", ctx.b.take())] {
        let Some(account) = account else { continue };
        report.check(&format!("throwaway {label} is deleted"), || {
            // Its token may have been revoked by a check along the way (a
            // password change, a ban, a deletion); a fresh one is what makes
            // teardown independent of what happened earlier.
            if sign_in_api(&account).is_err() {
                // Already gone, or banned and unbannable from here. Say so
                // rather than failing: an account this run deleted on purpose
                // is the expected case.
                let resp = account.http.get("/api/v1/me")?;
                return if resp.status == 401 {
                    Ok(())
                } else {
                    Err(format!("cannot sign in to delete it ({})", resp.status))
                };
            }
            let resp = account.http.delete("/api/v1/me")?;
            resp.expect(204)?;
            Ok(())
        });
    }

    if let Some(enabled) = ctx.restore_registration.take() {
        report.check("the registration switch is restored", || {
            set_registration(&ctx.main.http, enabled)
        });
    }

    if !ctx.captcha {
        report.check("the website session is signed out", || {
            let resp = ctx.main.http.form("/logout", &[])?;
            resp.expect_redirect("/")?;
            if ctx.main.http.cookie(SESSION_COOKIE).is_some() {
                return Err("the session cookie survived sign-out".to_string());
            }
            Ok(())
        });
    }

    report.check("the API session is signed out", || {
        let resp = ctx.main.http.post_json("/api/v1/auth/logout", &json!({}))?;
        resp.expect(204)?;
        ctx.main.http.set_bearer(None);
        Ok(())
    });
}
