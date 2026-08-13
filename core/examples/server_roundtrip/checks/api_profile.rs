//! `/api/v1/me` — the profile tree.
//!
//! Every mutation here runs on throwaway A. Changing the email or password of
//! the account named on the command line would leave the operator locked out
//! of their own dev server if the run died halfway.

use serde_json::{Value, json};

use super::{api_token, need_throwaway, sign_in_api};
use crate::report::Report;
use crate::{Account, Ctx};

pub fn run(report: &mut Report, ctx: &mut Ctx) {
    if ctx.a.is_none() {
        need_throwaway(report, "profile");
        return;
    }
    report.group("profile");

    // What the server currently believes about A. The checks below change
    // both, and everything after a change has to sign in with the new value —
    // `a.email`/`a.password` still hold what the run started with, and are
    // updated once at the end.
    let mut live_email;
    let mut live_password;

    {
        let a = ctx.a.as_ref().expect("checked above");
        live_email = a.email.clone();
        live_password = a.password.clone();

        report.check("the profile names its providers", || {
            let resp = a.http.get("/api/v1/me")?;
            resp.expect(200)?;
            let body = resp.json();
            let providers = body.get("providers").ok_or("no providers in the profile")?;
            if providers.get("password") != Some(&Value::Bool(true)) {
                return Err(format!("expected a password provider, got {providers}"));
            }
            if providers.get("google") != Some(&Value::Bool(false)) {
                return Err(format!("expected no google provider, got {providers}"));
            }
            Ok(())
        });

        // A second session, opened here so the checks below can watch what
        // happens to it.
        let other = report.probe("a second session can be opened", || {
            let handle = a.http.anonymous();
            let token = api_token(&handle, &live_email, &live_password)?;
            handle.set_bearer(Some(token));
            handle.get("/api/v1/me")?.expect(200)?;
            Ok(handle)
        });

        report.check("sessions are listed by digest, never by token", || {
            let resp = a.http.get("/api/v1/me/sessions")?;
            resp.expect(200)?;
            let sessions = resp.json();
            let rows = sessions.as_array().ok_or("sessions are not an array")?;
            let current = rows
                .iter()
                .filter(|row| row.get("current") == Some(&Value::Bool(true)))
                .count();
            if current != 1 {
                return Err(format!(
                    "expected exactly 1 current session, found {current}"
                ));
            }
            let token = a.http.bearer().unwrap_or_default();
            if sessions.to_string().contains(&token) {
                return Err("the listing leaked a bearer token".to_string());
            }
            // The published id is the digest of the token, which is what lets
            // a client match a log line to a device row without ever handling
            // the credential.
            let want = session_id(&token);
            let listed = rows
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(want.as_str()));
            if !listed {
                return Err("the current session is not listed under sha256(token)".to_string());
            }
            Ok(())
        });

        if let Some(other) = &other {
            report.check("a session can be revoked by id", || {
                let token = other.bearer().unwrap_or_default();
                a.http
                    .delete(&format!("/api/v1/me/sessions/{}", session_id(&token)))?
                    .expect(204)?;
                other.get("/api/v1/me")?.expect_error(401, "unauthorized")?;
                a.http.get("/api/v1/me")?.expect(200)?;
                Ok(())
            });
        }

        let wanted = format!("roundtrip-{}-a2@roundtrip.invalid", ctx.run_id);
        let changed = report.check("the email can be changed", || {
            let resp = a
                .http
                .put_json("/api/v1/me/email", &json!({ "email": wanted }))?;
            resp.expect(200)?;
            match resp.json().get("email").and_then(Value::as_str) {
                Some(seen) if seen == wanted => Ok(()),
                other => Err(format!("the profile still says {other:?}")),
            }
        });
        if changed {
            report.check("the new address signs in", || {
                api_token(&a.http.anonymous(), &wanted, &live_password).map(|_| ())
            });
            report.check("the old address no longer does", || {
                let resp = a.http.anonymous().post_json(
                    "/api/v1/auth/login",
                    &json!({ "email": live_email, "password": live_password }),
                )?;
                resp.expect_error(401, "invalid_credentials")?;
                Ok(())
            });
            live_email = wanted;
        }

        if let Some(b) = &ctx.b {
            report.check("an address another account holds is refused", || {
                let resp = a
                    .http
                    .put_json("/api/v1/me/email", &json!({ "email": b.email }))?;
                resp.expect_error(409, "conflict")?;
                Ok(())
            });
        }

        report.check("the wrong current password is refused", || {
            let resp = a.http.put_json(
                "/api/v1/me/password",
                &json!({
                    "current_password": "not-the-password",
                    "new_password": "another-password",
                }),
            )?;
            resp.expect_error(403, "invalid_current_password")?;
            Ok(())
        });

        report.check("omitting the current password is refused", || {
            let resp = a.http.put_json(
                "/api/v1/me/password",
                &json!({ "new_password": "another-password" }),
            )?;
            resp.expect_error(400, "current_password_required")?;
            Ok(())
        });

        // The rule worth an end-to-end check: a real password change revokes
        // every *other* session and spares the caller's.
        let bystander = report.probe("a bystander session exists", || {
            let handle = a.http.anonymous();
            handle.set_bearer(Some(api_token(&handle, &live_email, &live_password)?));
            handle.get("/api/v1/me")?.expect(200)?;
            Ok(handle)
        });

        let wanted = format!("{live_password}-changed");
        let changed = report.check("the password can be changed", || {
            let resp = a.http.put_json(
                "/api/v1/me/password",
                &json!({ "current_password": live_password, "new_password": wanted }),
            )?;
            resp.expect(204)?;
            Ok(())
        });
        if changed {
            if let Some(bystander) = &bystander {
                report.check("changing it revoked the other sessions", || {
                    bystander
                        .get("/api/v1/me")?
                        .expect_error(401, "unauthorized")?;
                    Ok(())
                });
            }
            report.check("the caller's own session survived", || {
                a.http.get("/api/v1/me")?.expect(200)?;
                Ok(())
            });
            live_password = wanted;
        }
    }

    // Teardown and the later groups sign A in again, so the recorded
    // credentials have to follow what the server now believes.
    if let Some(a) = ctx.a.as_mut() {
        a.email = live_email;
        a.password = live_password;
    }
    let a: &Account = ctx.a.as_ref().expect("checked above");
    report.check("the recorded credentials are the live ones", || {
        sign_in_api(a)
    });
}

/// How the server identifies a session to clients: the SHA-256 of the bearer
/// token, hex-encoded. Computed here rather than read out of a listing, so a
/// revoke names exactly the session it means.
fn session_id(token: &str) -> String {
    askrypt::sha256(token, "")
}
