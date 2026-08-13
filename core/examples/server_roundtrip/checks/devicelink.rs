//! The browser device link — both halves at once, which is the point of the
//! feature: the app opens a link, a browser approves it, and the app collects
//! a bearer token it never asked a password for.
//!
//! The app half goes through `core`'s own `BrowserLogin`, since that is the
//! client the desktop actually ships.

use askrypt::{BrowserLogin, BrowserLoginStatus, ServerClient};
use serde_json::json;

use crate::Ctx;
use crate::report::Report;

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    if ctx.captcha {
        report.skip_group(
            "devicelink",
            "the approving browser cannot sign in with reCAPTCHA configured",
        );
        return;
    }
    report.group("devicelink");

    let Some(link) = report.probe("an app opens a device link", || start(ctx)) else {
        return;
    };

    report.check("it polls as pending before anyone approves", || match link
        .poll()
        .map_err(|e| format!("{e}"))?
    {
        BrowserLoginStatus::Pending => Ok(()),
        other => Err(format!("expected Pending, got {other:?}")),
    });

    report.check("the link id is not usable as a poll token", || {
        // The id is public — it travels in a URL and is displayed on a page.
        // Confirming it as a poll token would make the URL a credential.
        let id = link_id(&link)?;
        let resp = ctx
            .main
            .http
            .anonymous()
            .post_json("/api/v1/auth/device/poll", &json!({ "poll_token": id }))?;
        resp.expect(200)?;
        expect_status(&resp.json(), "expired")
    });

    report.check("an unknown poll token is indistinguishable", || {
        let resp = ctx.main.http.anonymous().post_json(
            "/api/v1/auth/device/poll",
            &json!({ "poll_token": "0".repeat(64) }),
        )?;
        resp.expect(200)?;
        expect_status(&resp.json(), "expired")
    });

    report.check("the page shows the code without approving it", || {
        // Signed out, `/link/{id}` must render rather than approve: approval
        // is what a *session* means, and a link checker carries none.
        let id = link_id(&link)?;
        let resp = ctx.main.http.anonymous().get(&format!("/link/{id}"))?;
        resp.expect(200)?;
        resp.expect_contains(link.user_code())?;
        match link.poll().map_err(|e| format!("{e}"))? {
            BrowserLoginStatus::Pending => Ok(()),
            other => Err(format!("a signed-out visit changed it to {other:?}")),
        }
    });

    let approved = report.probe("visiting it while signed in approves it", || {
        let id = link_id(&link)?;
        ctx.main.http.get(&format!("/link/{id}"))?.expect(200)?;
        match link.poll().map_err(|e| format!("{e}"))? {
            BrowserLoginStatus::Approved { client, email } => {
                if email != ctx.main.email {
                    return Err(format!("approved as {email}, expected {}", ctx.main.email));
                }
                Ok(client)
            }
            other => Err(format!("expected Approved, got {other:?}")),
        }
    });

    if let Some(client) = &approved {
        report.check("the collected token authenticates", || {
            let handle = ctx.main.http.anonymous();
            handle.set_bearer(Some(client.token().to_string()));
            let resp = handle.get("/api/v1/me")?;
            resp.expect(200)?;
            match resp.json().get("email").and_then(|e| e.as_str()) {
                Some(email) if email == ctx.main.email => Ok(()),
                other => Err(format!("the token belongs to {other:?}")),
            }
        });

        report.check("the new session is listed under the label sent", || {
            let resp = ctx.main.http.get("/api/v1/me/sessions")?;
            resp.expect(200)?;
            let label = device_label();
            if resp.text().contains(&label) {
                Ok(())
            } else {
                Err(format!("no session labelled {label:?} in the listing"))
            }
        });

        report.check("a link is collected exactly once", || {
            // The bearer is minted on claim and the row is deleted in the same
            // store call, so a second poll can never mint a second session.
            match link.poll().map_err(|e| format!("{e}"))? {
                BrowserLoginStatus::Expired => Ok(()),
                other => Err(format!(
                    "expected Expired on the second poll, got {other:?}"
                )),
            }
        });
    }

    if let Some(client) = approved {
        report.check("the collected session can be signed out", || {
            client.logout().map_err(|e| format!("{e}"))
        });
    }

    report.check("denying a link tells the app so", || {
        // Denied without visiting the page first: the button belongs to a
        // visitor who did not start this sign-in, and a visit would approve it.
        let link = start(ctx)?;
        let id = link_id(&link)?;
        ctx.main
            .http
            .form(&format!("/link/{id}/deny"), &[])?
            .expect_redirect(&format!("/link/{id}"))?;
        match link.poll().map_err(|e| format!("{e}"))? {
            BrowserLoginStatus::Denied => Ok(()),
            other => Err(format!("expected Denied, got {other:?}")),
        }
    });

    report.check("a denial needs a CSRF token", || {
        let link = start(ctx)?;
        let id = link_id(&link)?;
        let resp =
            ctx.main
                .http
                .form_with(&format!("/link/{id}/deny"), "not-the-token", &[], &[])?;
        resp.expect(403)?;
        Ok(())
    });

    report.check("cancelling makes a link unapprovable at once", || {
        // An app that closes its sign-in pane should not leave an approvable
        // link lying around for the rest of the day.
        let link = start(ctx)?;
        let id = link_id(&link)?;
        link.cancel().map_err(|e| format!("{e}"))?;
        let resp = ctx.main.http.get(&format!("/link/{id}"))?;
        resp.expect(200)?;
        resp.expect_missing(link.user_code())?;
        match link.poll().map_err(|e| format!("{e}"))? {
            BrowserLoginStatus::Expired => Ok(()),
            other => Err(format!("expected Expired after cancel, got {other:?}")),
        }
    });
}

fn start(ctx: &Ctx) -> Result<BrowserLogin, String> {
    let link = ServerClient::begin_browser_login(&ctx.base, Some(&device_label()))
        .map_err(|e| format!("{e}"))?;
    if link.user_code().is_empty() {
        return Err("the link carries no user code".to_string());
    }
    if link.expires_in() <= 0 {
        return Err(format!("the link expires in {}s", link.expires_in()));
    }
    Ok(link)
}

fn device_label() -> String {
    format!("server_roundtrip-{}", std::process::id())
}

/// The link's public id, taken back out of the verification URL.
///
/// `BrowserLogin` deliberately exposes the URL rather than the id — the app
/// only ever opens it — so this run reads the id off the end of it.
fn link_id(link: &BrowserLogin) -> Result<String, String> {
    link.verification_url()
        .rsplit('/')
        .next()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("no link id in {}", link.verification_url()))
}

fn expect_status(body: &serde_json::Value, want: &str) -> Result<(), String> {
    match body.get("status").and_then(|s| s.as_str()) {
        Some(seen) if seen == want => Ok(()),
        other => Err(format!("expected status {want:?}, got {other:?}")),
    }
}
