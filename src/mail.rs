// SPDX-License-Identifier: AGPL-3.0-only
//! Email delivery via SMTP (`lettre`). Without `TAVRN_SMTP_URL`, mails are only logged.

use std::sync::{Arc, Mutex};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

use crate::{config::Config, models::UserRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpSecurity {
    Plain,
    Tls,
    StartTls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub credentials: Option<(String, String)>,
}

impl SmtpSettings {
    /// `smtp://[user:pass@]host[:port]`, `smtps://…`, `smtp+starttls://…`.
    pub fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let (security, default_port) = match scheme {
            "smtp" => (SmtpSecurity::Plain, 25),
            "smtps" => (SmtpSecurity::Tls, 465),
            "smtp+starttls" => (SmtpSecurity::StartTls, 587),
            _ => return None,
        };
        let rest = rest.trim_end_matches('/');
        let (credentials, hostport) = match rest.rsplit_once('@') {
            Some((cred, hp)) => {
                let (u, p) = cred.split_once(':')?;
                (Some((percent_decode(u), percent_decode(p))), hp)
            }
            None => (None, rest),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse().ok()?),
            _ => (hostport, default_port),
        };
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if host.is_empty() {
            return None;
        }
        Some(Self { host: host.to_string(), port, security, credentials })
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone)]
pub struct Mailer {
    public_url: String,
    from: String,
    node_name: String,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    /// Most recently sent mails (recipient, subject, body), for development and tests.
    pub outbox: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl Mailer {
    pub fn from_config(config: &Config) -> Self {
        let transport = config
            .smtp_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .and_then(SmtpSettings::parse)
            .and_then(|s| build_transport(&s));
        Self {
            public_url: config.public_url(),
            from: config.smtp_from(),
            node_name: config.name.clone(),
            transport,
            outbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn smtp_enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub async fn send_verification(&self, user: &UserRow, token: &str) {
        let Some(email) = &user.email else { return };
        let link = format!("{}/verify-email?token={token}", self.public_url);
        let subject = format!("{}: Confirm your email address", self.node_name);
        let body = format!(
            "Hello {},\n\nplease confirm the email address of your tavrn account:\n{link}\n\nThe link is valid for 24 hours. If you did not create an account, ignore this mail.",
            user.display_name
        );
        if let Err(e) = self.deliver(email, subject, body).await {
            tracing::error!(error = %e, to = email, "email delivery failed");
        }
    }

    pub async fn send_password_reset(&self, user: &UserRow, token: &str) {
        let Some(email) = &user.email else { return };
        let link = format!("{}/reset-password?token={token}", self.public_url);
        let subject = format!("{}: Reset your password", self.node_name);
        let body = format!(
            "Hello {},\n\nyou can set a new password via this link:\n{link}\n\nThe link is valid for one hour. If you did not request this, ignore this mail.",
            user.display_name
        );
        if let Err(e) = self.deliver(email, subject, body).await {
            tracing::error!(error = %e, to = email, "email delivery failed");
        }
    }

    /// A plain-text mail of the legal flows (notices, statements of reasons, account deletion). Failures are logged and
    /// never returned: the action the mail reports has happened either way.
    pub async fn send(&self, to: &str, subject: &str, body: &str) {
        let subject = format!("{}: {subject}", self.node_name);
        if let Err(e) = self.deliver(to, subject, body.to_string()).await {
            tracing::error!(error = %e, to, "email delivery failed");
        }
    }

    /// The node's public URL (links in mails).
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// Test mail, e.g. via `tavrn-node send-test-mail <address>`.
    pub async fn send_test(&self, to: &str) -> anyhow::Result<()> {
        self.deliver(
            to,
            format!("{}: Test mail", self.node_name),
            format!("This test mail was sent by {} via the configured SMTP relay.", self.public_url),
        )
        .await
    }

    async fn deliver(&self, to: &str, subject: String, body: String) -> anyhow::Result<()> {
        if let Ok(mut o) = self.outbox.lock() {
            o.push((to.to_string(), subject.clone(), body.clone()));
            if o.len() > 100 {
                o.remove(0);
            }
        }
        match &self.transport {
            None => {
                tracing::info!(to, subject, "email (no SMTP configured):\n{body}");
                Ok(())
            }
            Some(transport) => {
                let message = Message::builder()
                    .from(self.from.parse::<Mailbox>()?)
                    .to(to.parse::<Mailbox>()?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body)?;
                transport.send(message).await?;
                tracing::info!(to, "email sent");
                Ok(())
            }
        }
    }
}

fn build_transport(s: &SmtpSettings) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
    let builder = match s.security {
        SmtpSecurity::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&s.host),
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&s.host).ok()?,
        SmtpSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&s.host).ok()?,
    };
    let mut builder = builder.port(s.port).timeout(Some(std::time::Duration::from_secs(15)));
    if let Some((u, p)) = &s.credentials {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }
    Some(builder.build())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_smtp_urls() {
        assert_eq!(
            SmtpSettings::parse("smtp://192.0.2.10:8025").unwrap(),
            SmtpSettings { host: "192.0.2.10".into(), port: 8025, security: SmtpSecurity::Plain, credentials: None }
        );
        assert_eq!(SmtpSettings::parse("smtps://mail.example.org").unwrap().port, 465);
        let s = SmtpSettings::parse("smtp+starttls://user:p%40ss@mail.example.org:2525/").unwrap();
        assert_eq!(s.security, SmtpSecurity::StartTls);
        assert_eq!(s.port, 2525);
        assert_eq!(s.credentials, Some(("user".into(), "p@ss".into())));
        assert_eq!(percent_decode("a%2"), "a%2", "an incomplete sequence is kept");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(SmtpSettings::parse("smtp://[::1]:25").unwrap().host, "::1");
        assert!(SmtpSettings::parse("http://x").is_none());
        assert!(SmtpSettings::parse("smtp://").is_none());
        assert!(SmtpSettings::parse("smtp://host:abc").is_none());
    }

    #[tokio::test]
    async fn links_use_the_public_url_and_the_sender_the_identity_domain() {
        let config = Config {
            domain: "tavrn.org".into(),
            public_url: Some("https://app.tavrn.org".into()),
            database_url: "postgres://x".into(),
            ..Config::default()
        };
        let m = Mailer::from_config(&config);
        assert_eq!(m.from, "noreply@tavrn.org");
        m.send_test("a@b.c").await.unwrap();
        assert!(m.outbox.lock().unwrap()[0].2.contains("https://app.tavrn.org"));
    }

    #[tokio::test]
    async fn without_smtp_mails_are_only_logged() {
        let config = Config { domain: "t.local".into(), database_url: "postgres://x".into(), ..Config::default() };
        let m = Mailer::from_config(&config);
        assert!(!m.smtp_enabled());
        m.send_test("a@b.c").await.unwrap();
        assert_eq!(m.outbox.lock().unwrap()[0].0, "a@b.c");
    }
}
