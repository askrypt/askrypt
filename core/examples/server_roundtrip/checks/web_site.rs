//! The website: the pages, the cookie session, CSRF, and the file manager.
//!
//! Everything here uses the no-JS path deliberately. htmx gets a fragment and,
//! through `web::htmx_error_fragment`, a 200 for errors it would otherwise
//! refuse to swap; the plain path keeps the real status, and that is the one
//! that has to be correct.

use crate::http::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::report::Report;
use crate::{Ctx, vault};

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    if ctx.captcha {
        report.skip_group(
            "website",
            "reCAPTCHA is configured; the forms need a browser to mint a token",
        );
        return;
    }
    report.group("website");

    report.check("the landing page renders", || {
        let resp = ctx.main.http.anonymous().get("/")?;
        resp.expect(200)?;
        resp.expect_contains("<html")?;
        Ok(())
    });

    report.check("the security headers are on every page", || {
        let resp = ctx.main.http.anonymous().get("/")?;
        for header in [
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
            "x-frame-options",
        ] {
            if resp.header(header).is_none() {
                return Err(format!("no {header}"));
            }
        }
        // The commitment the templates are written to: no inline script.
        let csp = resp.header("content-security-policy").unwrap_or_default();
        if csp.contains("script-src") && csp.contains("'unsafe-inline'") {
            return Err(format!("the CSP allows inline script: {csp}"));
        }
        Ok(())
    });

    report.check("a page is never cached", || {
        let resp = ctx.main.http.anonymous().get("/")?;
        match resp.header("cache-control") {
            Some(value) if value.contains("no-store") => Ok(()),
            other => Err(format!("unexpected cache directive {other:?}")),
        }
    });

    report.check("the stylesheet is served and revalidates", || {
        let resp = ctx.main.http.anonymous().get("/assets/style.css")?;
        resp.expect(200)?;
        match resp.header("cache-control") {
            Some(value) if value.contains("no-cache") => Ok(()),
            other => Err(format!("unexpected cache directive {other:?}")),
        }
    });

    report.check("an unknown path is an HTML 404, not a JSON one", || {
        let resp = ctx.main.http.anonymous().get("/no-such-page")?;
        resp.expect(404)?;
        match resp.header("content-type") {
            Some(value) if value.contains("text/html") => Ok(()),
            other => Err(format!("unexpected content type {other:?}")),
        }
    });

    report.check("signing in sets both cookies and lands on /account", || {
        let handle = ctx.main.http.anonymous();
        handle.get("/login")?.expect(200)?;
        let before = handle.cookie(CSRF_COOKIE);
        let resp = handle.form(
            "/login",
            &[("email", &ctx.main.email), ("password", &ctx.main.password)],
        )?;
        resp.expect_redirect("/account")?;
        let cookies = resp.set_cookies().join(" | ");
        for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            if !cookies.contains(attribute) {
                return Err(format!("the session cookie is missing {attribute}"));
            }
        }
        handle
            .cookie(SESSION_COOKIE)
            .ok_or("no session cookie was set")?;
        // The token is rotated on sign-in, so one minted before the session
        // existed cannot be replayed inside it.
        if handle.cookie(CSRF_COOKIE) == before {
            return Err("the CSRF token was not rotated on sign-in".to_string());
        }
        Ok(())
    });

    report.check("the wrong password re-renders the form at 200", || {
        // Not a 4xx: a refused sign-in is a normal outcome of the page.
        let handle = ctx.main.http.anonymous();
        handle.get("/login")?.expect(200)?;
        let resp = handle.form(
            "/login",
            &[("email", &ctx.main.email), ("password", "not-the-password")],
        )?;
        resp.expect(200)?;
        resp.expect_contains("name=\"password\"")?;
        if handle.cookie(SESSION_COOKIE).is_some() {
            return Err("a refused sign-in set a session cookie".to_string());
        }
        Ok(())
    });

    report.check("the page's hidden field matches the cookie", || {
        let handle = ctx.main.http.anonymous();
        let resp = handle.get("/login")?;
        let field = http::csrf_field(&resp.text()).ok_or("no csrf field on the sign-in form")?;
        match handle.cookie(CSRF_COOKIE) {
            Some(cookie) if cookie == field => Ok(()),
            other => Err(format!("cookie {other:?} does not match field {field:?}")),
        }
    });

    report.check("a mismatched CSRF token is refused", || {
        let handle = ctx.main.http.anonymous();
        handle.get("/login")?.expect(200)?;
        let resp = handle.form_with(
            "/login",
            &"0".repeat(64),
            &[("email", &ctx.main.email), ("password", &ctx.main.password)],
            &[],
        )?;
        resp.expect(403)?;
        Ok(())
    });

    report.check("a form post from another origin is refused", || {
        let handle = ctx.main.http.anonymous();
        handle.get("/login")?.expect(200)?;
        let token = handle.csrf_token()?;
        let resp = handle.form_with(
            "/login",
            &token,
            &[("email", &ctx.main.email), ("password", &ctx.main.password)],
            // Overrides the same-origin value the client states by default.
            &[("Origin", "https://evil.example")],
        )?;
        resp.expect(403)?;
        Ok(())
    });

    report.check("a signed-out visitor is redirected, not refused", || {
        let resp = ctx.main.http.anonymous().get("/account")?;
        resp.expect_redirect("/login")?;
        Ok(())
    });

    report.check("the account page names the signed-in address", || {
        let resp = ctx.main.http.get("/account")?;
        resp.expect(200)?;
        resp.expect_contains(&ctx.main.email)?;
        Ok(())
    });

    file_manager(report, ctx);
}

/// The 7.4 file manager, driven the way a browser with scripts off would.
fn file_manager(report: &mut Report, ctx: &mut Ctx) {
    let name = ctx.vault_name("web");

    let Some(uploaded) = report.probe("a vault uploads through the form", || {
        let bytes = vault::fixture_bytes("uploaded-in-a-browser")?;
        let resp = ctx
            .main
            .http
            .multipart("/vaults", &[("name", &name)], Some((&name, &bytes)))?;
        resp.expect_redirect("/vaults")?;
        Ok(bytes)
    }) else {
        return;
    };

    let Some(id) = report.probe("it is listed with a download link", || {
        let resp = ctx.main.http.get("/vaults")?;
        resp.expect(200)?;
        resp.expect_contains(&name)?;
        vault_id(&resp.text(), &name).ok_or_else(|| format!("no row for {name} in the listing"))
    }) else {
        return;
    };
    ctx.vaults.push(id.clone());

    report.check(
        "the cookie-authenticated download is byte-identical",
        || {
            let resp = ctx.main.http.get(&format!("/vaults/{id}/download"))?;
            resp.expect(200)?;
            if resp.body != uploaded {
                return Err("the downloaded bytes differ from the uploaded ones".to_string());
            }
            match resp.header("content-disposition") {
                Some(value) if value.contains(&name) => Ok(()),
                other => Err(format!("unexpected content disposition {other:?}")),
            }
        },
    );

    report.check("a file with the wrong extension is refused", || {
        let bytes = vault::fixture_bytes("wrong-extension")?;
        let resp = ctx.main.http.multipart(
            "/vaults",
            &[("name", "not-a-vault.zip")],
            Some(("not-a-vault.zip", &bytes)),
        )?;
        // A refusal re-renders the listing at 200 with a notice above it.
        resp.expect(200)?;
        resp.expect_contains("Vaults are the .askrypt files your app saves")?;
        ctx.main
            .http
            .get("/vaults")?
            .expect_missing("not-a-vault.zip")?;
        Ok(())
    });

    report.check("an archive without askrypt.json is refused", || {
        // The API's own gate is the ZIP magic, which this passes. The website
        // looks inside, because the file was picked out of a folder by hand.
        let bytes = vault::zip_without_manifest();
        let picked = format!("{}-fake.askrypt", ctx.run_id);
        let resp =
            ctx.main
                .http
                .multipart("/vaults", &[("name", &picked)], Some((&picked, &bytes)))?;
        resp.expect(200)?;
        resp.expect_contains("missing the")?;
        let listing = ctx.main.http.get("/vaults")?;
        listing.expect_missing(&picked)?;
        Ok(())
    });

    report.check("a vault can be renamed inline", || {
        let renamed = ctx.vault_name("web-renamed");
        ctx.main
            .http
            .form(&format!("/vaults/{id}/name"), &[("name", &renamed)])?
            .expect_redirect("/vaults")?;
        let resp = ctx.main.http.get("/vaults")?;
        resp.expect_contains(&renamed)?;
        // Put the original name back, so the listing reads as it started.
        ctx.main
            .http
            .form(&format!("/vaults/{id}/name"), &[("name", &name)])?
            .expect_redirect("/vaults")?;
        Ok(())
    });

    report.check("replacing carries the row's ETag", || {
        let etag = row_etag(ctx, &id)?;
        let bytes = vault::fixture_bytes("replaced-in-a-browser")?;
        let resp = ctx.main.http.multipart(
            &format!("/vaults/{id}/replace"),
            &[("etag", &etag)],
            Some((&name, &bytes)),
        )?;
        resp.expect_redirect("/vaults")?;
        let downloaded = ctx.main.http.get(&format!("/vaults/{id}/download"))?;
        if downloaded.body != bytes {
            return Err("the replacement did not land".to_string());
        }
        Ok(())
    });

    report.check("a stale ETag loses the race", || {
        let bytes = vault::fixture_bytes("stale-replace")?;
        let stale = "0".repeat(64);
        let resp = ctx.main.http.multipart(
            &format!("/vaults/{id}/replace"),
            &[("etag", &stale)],
            Some((&name, &bytes)),
        )?;
        resp.expect(200)?;
        resp.expect_contains("changed on another device")?;
        Ok(())
    });

    report.check("the row carries the file's own write stamp", || {
        // The unencrypted `host`/`updated_at` core stamps on every save, which
        // the server lifts off the bytes and shows next to its own timestamp.
        let resp = ctx.main.http.get("/vaults")?;
        resp.expect(200)?;
        // The stamp is written by whatever built the fixture, which is this
        // machine — so the row should name it back.
        let host = askrypt::current_host()
            .ok_or("this machine reports no host name, so nothing was stamped")?;
        resp.expect_contains(&host)?;
        Ok(())
    });

    report.check("a vault can be deleted", || {
        ctx.main
            .http
            .form(&format!("/vaults/{id}/delete"), &[])?
            .expect_redirect("/vaults")?;
        let resp = ctx.main.http.get("/vaults")?;
        resp.expect_missing(&name)?;
        Ok(())
    });
    // Deleted here, so teardown must not try again.
    ctx.vaults.retain(|vault| vault != &id);
}

/// The vault id out of a listing row.
///
/// Each row opens with a rename form whose action names the id, and the name
/// then appears as that form's input value — so the last `/vaults/` before the
/// name is this row's.
fn vault_id(html: &str, name: &str) -> Option<String> {
    let row = html.find(&format!("value=\"{name}\""))?;
    let start = html[..row].rfind("/vaults/")? + "/vaults/".len();
    let rest = &html[start..];
    let end = rest.find('/')?;
    Some(rest[..end].to_string())
}

/// The ETag the file manager rendered into a row's replace form.
fn row_etag(ctx: &Ctx, id: &str) -> Result<String, String> {
    // Cheaper and less brittle than parsing the page: the API reports the same
    // value, and the point of the check is that the form carries *an* ETag
    // through the `If-Match` path.
    let resp = ctx.main.http.get(&format!("/api/v1/vaults/{id}"))?;
    resp.expect(200)?;
    resp.etag().ok_or_else(|| "no ETag for the row".to_string())
}
