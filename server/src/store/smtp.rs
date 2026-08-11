//! SMTP implementation of the [`Mailer`] seam.
//!
//! Selected in `main` when `ASKRYPT_SMTP_HOST` is set; otherwise the server
//! keeps the logging [`MemoryMailer`](super::memory::MemoryMailer). The
//! settings type lives here rather than in [`crate::config`] so everything
//! SMTP knows about itself stays in one place — `config` only parses the
//! environment into it.
//!
//! Transport is `lettre` over rustls. Connections are pooled and reused, so
//! `SmtpMailer` should be built once at startup and shared.

use std::fmt;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncTransport, Message, Tokio1Executor};

use super::{Mailer, MailerError};

pub use super::types::{SmtpConfig, SmtpCredentials, SmtpEncryption, SmtpMailer};

impl SmtpEncryption {
    /// The conventional submission port for this mode, used when
    /// `ASKRYPT_SMTP_PORT` is not set.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::StartTls => 587,
            Self::ImplicitTls => 465,
            Self::None => 25,
        }
    }

    /// Parses the `ASKRYPT_SMTP_ENCRYPTION` spelling; `None` if unrecognized.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "starttls" => Some(Self::StartTls),
            "tls" | "implicit" | "smtps" => Some(Self::ImplicitTls),
            "none" | "plain" | "insecure" => Some(Self::None),
            _ => None,
        }
    }

    /// The accepted spellings, for error messages.
    pub const SPELLINGS: &'static str = "\"starttls\", \"tls\" or \"none\"";
}

/// Hides the password: `Config` derives `Debug` and gets logged on startup.
impl fmt::Debug for SmtpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Hand-written so the transport — which holds the relay credentials — is
/// never formatted.
impl fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpMailer")
            .field("relay", &self.relay)
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl SmtpMailer {
    /// Resolves the relay and validates the sender address. Fails fast at
    /// startup rather than on the first email.
    pub fn new(config: &SmtpConfig) -> Result<Self, MailerError> {
        let from: Mailbox = config.from.parse().map_err(|e| {
            MailerError::Config(format!("invalid from address {:?}: {e}", config.from))
        })?;

        let builder = match config.encryption {
            SmtpEncryption::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            }
            SmtpEncryption::ImplicitTls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
            }
            // No TLS negotiation to set up, so this one can't fail.
            SmtpEncryption::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
                &config.host,
            )),
        }
        .map_err(|e| MailerError::Config(format!("smtp relay {:?}: {e}", config.host)))?;

        let mut builder = builder.port(config.port).timeout(Some(config.timeout));
        if let Some(creds) = &config.credentials {
            builder = builder.credentials(Credentials::new(
                creds.username.clone(),
                creds.password.clone(),
            ));
        }

        Ok(Self {
            transport: builder.build(),
            from,
            relay: format!("{}:{}", config.host, config.port),
        })
    }

    /// `host:port`, for logging.
    pub fn relay(&self) -> &str {
        &self.relay
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError> {
        let recipient: Mailbox = to
            .parse()
            .map_err(|e| MailerError::Send(format!("invalid recipient: {e}")))?;

        let email = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| MailerError::Send(e.to_string()))?;

        // Deliberately not the body: verification and reset mails carry
        // single-use tokens. Only the dev mailer logs those.
        tracing::debug!(to, subject, relay = %self.relay, "smtp: sending");
        self.transport
            .send(email)
            .await
            .map_err(|e| MailerError::Send(e.to_string()))?;
        tracing::debug!(to, relay = %self.relay, "smtp: sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn config() -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            encryption: SmtpEncryption::StartTls,
            from: "Askrypt <no-reply@example.com>".to_string(),
            credentials: Some(SmtpCredentials {
                username: "user".to_string(),
                password: "hunter2".to_string(),
            }),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn encryption_spellings_and_ports() {
        assert_eq!(
            SmtpEncryption::parse("StartTLS"),
            Some(SmtpEncryption::StartTls)
        );
        assert_eq!(
            SmtpEncryption::parse(" tls "),
            Some(SmtpEncryption::ImplicitTls)
        );
        assert_eq!(SmtpEncryption::parse("none"), Some(SmtpEncryption::None));
        assert_eq!(SmtpEncryption::parse("ssl"), None);

        assert_eq!(SmtpEncryption::StartTls.default_port(), 587);
        assert_eq!(SmtpEncryption::ImplicitTls.default_port(), 465);
        assert_eq!(SmtpEncryption::None.default_port(), 25);
    }

    /// `Config` is `Debug` and startup logs it; the relay password must not
    /// ride along.
    #[test]
    fn debug_redacts_the_password() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("user"), "{rendered}");
    }

    /// `#[tokio::test]`, not `#[test]`: the connection pool spawns onto the
    /// current runtime when it is built and again when it is dropped.
    #[tokio::test]
    async fn builds_for_every_encryption_mode() {
        for encryption in [
            SmtpEncryption::StartTls,
            SmtpEncryption::ImplicitTls,
            SmtpEncryption::None,
        ] {
            let mailer = SmtpMailer::new(&SmtpConfig {
                encryption,
                port: encryption.default_port(),
                ..config()
            })
            .expect("builds without touching the network");
            assert_eq!(
                mailer.relay(),
                format!("smtp.example.com:{}", encryption.default_port())
            );
        }
    }

    #[test]
    fn a_bad_from_address_fails_at_construction() {
        let err = SmtpMailer::new(&SmtpConfig {
            from: "not an address".to_string(),
            ..config()
        })
        .expect_err("invalid sender");
        assert!(matches!(err, MailerError::Config(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_bad_recipient_is_rejected_before_connecting() {
        let mailer = SmtpMailer::new(&config()).unwrap();
        // No relay is listening; reaching the network would hang for the
        // timeout instead of returning promptly.
        let err = mailer
            .send("not an address", "hi", "body")
            .await
            .expect_err("invalid recipient");
        assert!(err.to_string().contains("invalid recipient"), "{err}");
    }

    /// Accepts exactly one unencrypted session, answers every verb the
    /// happy path needs, and returns the transcript it was sent.
    ///
    /// It stops at the end of `DATA` rather than waiting for `QUIT`: the
    /// transport pools connections, so it hands the socket back to the pool
    /// after a message instead of closing it, and a server waiting for
    /// `QUIT` would block until the pool's idle timeout expires.
    async fn fake_relay() -> (u16, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (read, mut write) = socket.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut transcript = String::new();

            write.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            // Announcing no extensions keeps the client on the plain path:
            // no STARTTLS upgrade to negotiate, no AUTH to offer.
            let mut in_data = false;
            while let Some(line) = lines.next_line().await.unwrap() {
                if in_data {
                    if line == "." {
                        write.write_all(b"250 queued\r\n").await.unwrap();
                        break;
                    }
                    transcript.push_str(&line);
                    transcript.push('\n');
                    continue;
                }
                transcript.push_str(&line);
                transcript.push('\n');
                match line
                    .split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_uppercase()
                    .as_str()
                {
                    "DATA" => {
                        in_data = true;
                        write.write_all(b"354 go ahead\r\n").await.unwrap();
                    }
                    "QUIT" => {
                        write.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    }
                    _ => write.write_all(b"250 ok\r\n").await.unwrap(),
                }
            }
            transcript
        });

        (port, handle)
    }

    /// The one test that drives a real SMTP conversation end to end, so the
    /// envelope and body the relay actually receives are under test — not
    /// just that the transport builds.
    #[tokio::test]
    async fn delivers_the_message_to_a_relay() {
        let (port, server) = fake_relay().await;
        let mailer = SmtpMailer::new(&SmtpConfig {
            host: "127.0.0.1".to_string(),
            port,
            encryption: SmtpEncryption::None,
            // Unauthenticated: the fake advertises no AUTH extension.
            credentials: None,
            ..config()
        })
        .unwrap();

        mailer
            .send(
                "Someone <user@example.org>",
                "Reset your password",
                "token 123",
            )
            .await
            .expect("delivered");

        let transcript = server.await.unwrap();
        assert!(
            transcript.contains("MAIL FROM:<no-reply@example.com>"),
            "{transcript}"
        );
        assert!(
            transcript.contains("RCPT TO:<user@example.org>"),
            "{transcript}"
        );
        assert!(
            transcript.contains("Subject: Reset your password"),
            "{transcript}"
        );
        assert!(transcript.contains("token 123"), "{transcript}");
    }
}
