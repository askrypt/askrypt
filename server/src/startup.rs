//! The "server is up" email.
//!
//! Sent once, after the listener binds, to whoever runs the deployment: which
//! server came up (`ASKRYPT_DOMAIN`), where it listens, and how much memory
//! and disk the host has left. A restart nobody ordered is the thing this is
//! meant to make visible — an OOM kill, a reboot, a container the supervisor
//! keeps recycling all announce themselves.
//!
//! Two rules keep it from being a liability:
//!
//! - **It only sends through a real relay.** With no `ASKRYPT_SMTP_HOST` the
//!   mailer is [`MemoryMailer`](crate::store::memory::MemoryMailer), which
//!   *logs* messages in full; a startup notice there would be noise in every
//!   developer's console for no delivery at all.
//! - **It cannot delay or fail startup.** The send runs on its own task after
//!   the socket is bound, and a refused delivery is a `warn!` and nothing
//!   more. A dead relay must not keep a password manager offline.
//!
//! The body carries no account data, no counts and no secrets — a host name,
//! an address and two capacity figures — so it is safe to send to a mailbox
//! that is not the operator's own.

use std::net::SocketAddr;

use chrono::{DateTime, FixedOffset, Local};

use crate::config::Config;
use crate::store::Mailer;
use crate::sysinfo::{self, format_bytes};
use crate::types::{DiskUsage, MemoryUsage};

/// The revision the image was built from, as `server/Dockerfile` bakes it in.
/// Unset outside the container, where the checkout answers the question.
const ENV_BUILD_REV: &str = "ASKRYPT_BUILD_REV";

/// Sends the startup notice, if there is a relay to send it through and an
/// address to send it to.
///
/// Never returns an error: every failure is reported to the log. Call it from
/// a spawned task — the SMTP timeout is seconds long, and nothing about
/// serving requests should wait on it.
pub async fn notify_started(mailer: &dyn Mailer, config: &Config, bind: SocketAddr) {
    let Some(to) = recipient(config) else {
        return;
    };
    let (subject, body) = compose(
        config,
        bind,
        sysinfo::memory(),
        sysinfo::disk(&config.data_dir),
        // The server's own clock, offset and all — a container running on UTC
        // and a host running on local time are told apart by the offset, and a
        // clock that has drifted is visible the moment the mail arrives.
        Local::now().fixed_offset(),
    );

    match mailer.send(to, &subject, &body).await {
        Ok(()) => tracing::info!(to, "startup notice sent"),
        // A warning, not an error: the server is up and serving, which is the
        // whole point. But a relay that refuses this one would also refuse
        // every account email, so it wants to be visible.
        Err(err) => tracing::warn!(to, error = %err, "startup notice not delivered"),
    }
}

/// Where the notice goes: `ASKRYPT_ADMIN_EMAIL`, or the SMTP sender itself.
///
/// `None` whenever no relay is configured — not merely "no recipient": the
/// fallback exists so that configuring a relay is enough, and sending to the
/// sender address is the convention an operator expects from a `no-reply`
/// mailbox they own.
fn recipient(config: &Config) -> Option<&str> {
    let smtp = config.smtp.as_ref()?;
    Some(
        config
            .admin_email
            .as_deref()
            .unwrap_or(smtp.from.as_str())
            .trim(),
    )
}

/// Builds the message. Pure, and takes the probes as arguments, so the wording
/// is testable on a host whose real figures are nobody's business.
fn compose(
    config: &Config,
    bind: SocketAddr,
    memory: Option<MemoryUsage>,
    disk: Option<DiskUsage>,
    started: DateTime<FixedOffset>,
) -> (String, String) {
    // The domain names the deployment in the subject line, so a mailbox
    // collecting notices from several servers can be read at a glance. With
    // none configured the bind address is the next most identifying thing.
    let who = config.domain.clone().unwrap_or_else(|| bind.to_string());
    let subject = format!("Askrypt server started on {who}");

    let mut body = String::from("askrypt-server has started.\n\n");
    line(
        &mut body,
        "Domain:",
        config
            .domain
            .as_deref()
            .unwrap_or("(ASKRYPT_DOMAIN not set)"),
    );
    line(&mut body, "Listening:", &bind.to_string());
    line(
        &mut body,
        "Backend:",
        &format!("{:?}", config.backend).to_lowercase(),
    );
    line(
        &mut body,
        "Data dir:",
        &config.data_dir.display().to_string(),
    );
    if let Ok(revision) = std::env::var(ENV_BUILD_REV)
        && !revision.is_empty()
    {
        line(&mut body, "Build:", &revision);
    }
    // Both readings of one instant: the server's own wall clock, which is
    // what an operator compares against their watch, and UTC, which is what
    // every log line and audit record is stamped in.
    line(
        &mut body,
        "Server time:",
        &format!(
            "{} ({} UTC)",
            started.format("%Y-%m-%d %H:%M:%S %:z"),
            started.to_utc().format("%H:%M:%S"),
        ),
    );

    body.push('\n');
    match memory {
        Some(memory) => line(
            &mut body,
            "Memory:",
            &format!(
                "{} used of {} ({} free)",
                format_bytes(memory.used()),
                format_bytes(memory.total),
                format_bytes(memory.available),
            ),
        ),
        None => line(&mut body, "Memory:", "unavailable on this host"),
    }
    match disk {
        Some(disk) => line(
            &mut body,
            "Disk:",
            &format!(
                "{} used of {} ({} free) on the data directory's filesystem",
                format_bytes(disk.used),
                format_bytes(disk.total),
                format_bytes(disk.available),
            ),
        ),
        None => line(&mut body, "Disk:", "unavailable on this host"),
    }

    (subject, body)
}

/// One `label   value` row, padded so the values line up in a plain-text
/// mail read in a proportional font as often as a monospaced one. The width
/// clears the longest label (`Server time:`) by one space.
fn line(body: &mut String, label: &str, value: &str) {
    body.push_str(&format!("{label:<13}{value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::smtp::{SmtpConfig, SmtpEncryption};
    use std::time::Duration;

    fn smtp() -> SmtpConfig {
        SmtpConfig {
            host: "relay.example.com".into(),
            port: 587,
            encryption: SmtpEncryption::StartTls,
            from: "Askrypt <no-reply@example.com>".into(),
            credentials: None,
            timeout: Duration::from_secs(10),
        }
    }

    fn config() -> Config {
        Config {
            domain: Some("askrypt.example.com".into()),
            smtp: Some(smtp()),
            ..Config::default()
        }
    }

    fn bind() -> SocketAddr {
        "0.0.0.0:8080".parse().unwrap()
    }

    /// A server whose clock is not UTC, so the offset is actually exercised.
    fn started() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-08-13T12:12:44+03:00").unwrap()
    }

    #[test]
    fn no_relay_means_no_notice() {
        // The log-only mailer prints whatever it is handed; a notice sent
        // there is console noise and nothing else.
        let config = Config {
            smtp: None,
            admin_email: Some("ops@example.com".into()),
            ..config()
        };
        assert_eq!(recipient(&config), None);
    }

    #[test]
    fn a_configured_relay_needs_no_recipient_of_its_own() {
        assert_eq!(
            recipient(&config()),
            Some("Askrypt <no-reply@example.com>"),
            "the sender address is the fallback"
        );
        let config = Config {
            admin_email: Some("ops@example.com".into()),
            ..config()
        };
        assert_eq!(recipient(&config), Some("ops@example.com"));
    }

    #[test]
    fn the_notice_names_the_deployment_and_its_capacity() {
        let memory = MemoryUsage {
            total: 16 * 1024 * 1024 * 1024,
            available: 12 * 1024 * 1024 * 1024,
        };
        let disk = DiskUsage {
            total: 40 * 1024 * 1024 * 1024,
            available: 26 * 1024 * 1024 * 1024,
            used: 12 * 1024 * 1024 * 1024,
        };
        let (subject, body) = compose(&config(), bind(), Some(memory), Some(disk), started());

        assert_eq!(subject, "Askrypt server started on askrypt.example.com");
        assert!(body.contains("askrypt.example.com"), "{body}");
        assert!(body.contains("0.0.0.0:8080"), "{body}");
        // The server's own clock, with the offset that makes it comparable to
        // the UTC every log line is stamped in.
        assert!(
            body.contains("2026-08-13 12:12:44 +03:00 (09:12:44 UTC)"),
            "{body}"
        );
        assert!(
            body.contains("4.0 GiB used of 16.0 GiB (12.0 GiB free)"),
            "{body}"
        );
        assert!(
            body.contains("12.0 GiB used of 40.0 GiB (26.0 GiB free)"),
            "{body}"
        );
    }

    #[test]
    fn without_a_domain_the_bind_address_identifies_the_server() {
        let config = Config {
            domain: None,
            ..config()
        };
        let (subject, body) = compose(&config, bind(), None, None, started());
        assert_eq!(subject, "Askrypt server started on 0.0.0.0:8080");
        assert!(body.contains("ASKRYPT_DOMAIN not set"), "{body}");
    }

    #[test]
    fn unreadable_probes_say_so_rather_than_reporting_zero() {
        let (_, body) = compose(&config(), bind(), None, None, started());
        assert!(body.contains("Memory:      unavailable"), "{body}");
        assert!(body.contains("Disk:        unavailable"), "{body}");
    }
}
