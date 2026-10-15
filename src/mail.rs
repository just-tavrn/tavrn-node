// SPDX-License-Identifier: AGPL-3.0-only
//! Email delivery via SMTP (`lettre`). Without `TAVRN_SMTP_URL` nothing is sent: development nodes log the mails,
//! production nodes only note that a mail was not sent (never its body, which may carry a token). The texts are localized
//! templates (`mail_templates.rs`).

use crate::util::percent_decode;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

use crate::{
    config::Config,
    mail_templates::{self, Rendered},
    models::UserRow,
};

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

#[derive(Clone)]
pub struct Mailer {
    public_url: String,
    from: String,
    node_name: String,
    domain: String,
    /// Operator overrides of the templates (`TAVRN_MAIL_TEMPLATES_DIR`).
    templates_dir: std::path::PathBuf,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    /// Development mode (`--dev`, tests): without SMTP the mails are logged in full and kept in [`Mailer::outbox`].
    dev: bool,
    /// Most recently sent mails (recipient, subject, body); development mode and tests only (mails carry tokens).
    pub outbox: Arc<Mutex<Vec<(String, String, String)>>>,
    /// Mails handed to [`Mailer::send_in_background`] whose delivery has not finished yet.
    in_flight: Arc<AtomicUsize>,
}

/// Counts one background delivery while it lives; dropped also when the task panics or is cancelled.
struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
            domain: config.domain.clone(),
            templates_dir: mail_templates::dir_of(config),
            transport,
            dev: config.dev,
            outbox: Arc::new(Mutex::new(Vec::new())),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Runs `send` (a delivery) in a background task, so the request that triggered it answers without waiting for
    /// the SMTP relay. Account mails go this way: a request that sends a mail must take as long as one that does not,
    /// or the response time tells which accounts exist. Delivery errors are logged by the mailer itself; a panic ends
    /// only the task.
    pub fn send_in_background(&self, send: impl std::future::Future<Output = ()> + Send + 'static) {
        let in_flight = InFlight::new(&self.in_flight);
        tokio::spawn(async move {
            let _in_flight = in_flight;
            send.await;
        });
    }

    /// Background deliveries not finished yet (tests wait for 0 before they look at the outbox).
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn smtp_enabled(&self) -> bool {
        self.transport.is_some()
    }

    /// `true` if a mail can reach its recipient: SMTP is configured, or development mode (the log and the outbox).
    pub fn can_deliver(&self) -> bool {
        self.transport.is_some() || self.dev
    }

    /// The confirmation mail of a new email address, in the user's language.
    pub async fn send_verification(&self, user: &UserRow, locale: Option<&str>, token: &str) {
        let Some(email) = &user.email else { return };
        let link = format!("{}/verify-email?token={token}", self.public_url);
        self.send_template(email, locale, "verify_email", &[("name", &user.display_name), ("link", &link)]).await;
    }

    /// The password reset mail, in the user's language.
    pub async fn send_password_reset(&self, user: &UserRow, locale: Option<&str>, token: &str) {
        let Some(email) = &user.email else { return };
        let link = format!("{}/reset-password?token={token}", self.public_url);
        self.send_template(email, locale, "password_reset", &[("name", &user.display_name), ("link", &link)]).await;
    }

    /// Renders the template `name` in `locale` (falling back to English) with `vars` and the common variables.
    pub fn render(&self, locale: Option<&str>, name: &str, vars: &[(&str, &str)]) -> Rendered {
        let mut all = vars.to_vec();
        all.extend([
            ("node", self.node_name.as_str()),
            ("domain", self.domain.as_str()),
            ("public_url", self.public_url.as_str()),
        ]);
        mail_templates::render(Some(&self.templates_dir), locale, name, &all)
    }

    /// Sends a rendered mail (the subject gets the node's name in front). Failures are logged and never returned: the
    /// action the mail reports has happened either way.
    pub async fn send_rendered(&self, to: &str, mail: &Rendered) {
        let subject = format!("{}: {}", self.node_name, mail.subject);
        if let Err(e) = self.deliver(to, subject, mail.body.clone()).await {
            tracing::error!(error = %e, to, "email delivery failed");
        }
    }

    /// Renders and sends the template `name`; returns what was sent.
    pub async fn send_template(&self, to: &str, locale: Option<&str>, name: &str, vars: &[(&str, &str)]) -> Rendered {
        let mail = self.render(locale, name, vars);
        self.send_rendered(to, &mail).await;
        mail
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
        if self.dev
            && let Ok(mut o) = self.outbox.lock()
        {
            o.push((to.to_string(), subject.clone(), body.clone()));
            if o.len() > 100 {
                o.remove(0);
            }
        }
        match &self.transport {
            // Development: the whole mail in the log (links to click). Production: never the body, it may carry a
            // reset or verification token.
            None if self.dev => {
                tracing::info!(to, subject, "email (no SMTP configured):\n{body}");
                Ok(())
            }
            None => {
                tracing::info!(to, subject, "email not sent: no SMTP configured (TAVRN_SMTP_URL)");
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
    #![allow(clippy::unwrap_used, clippy::panic)]
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
            dev: true,
            ..Config::default()
        };
        let m = Mailer::from_config(&config);
        assert_eq!(m.from, "noreply@tavrn.org");
        m.send_test("a@b.c").await.unwrap();
        assert!(m.outbox.lock().unwrap()[0].2.contains("https://app.tavrn.org"));
    }

    #[tokio::test]
    async fn background_deliveries_are_counted_until_they_end_also_after_a_panic() {
        let config =
            Config { domain: "t.local".into(), database_url: "postgres://x".into(), dev: true, ..Config::default() };
        let m = Mailer::from_config(&config);
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let sender = m.clone();
        m.send_in_background(async move {
            let _ = wait.await;
            sender.send_test("a@b.c").await.unwrap();
        });
        m.send_in_background(async { panic!("a broken delivery") });
        assert_eq!(m.in_flight(), 2);
        release.send(()).unwrap();
        for _ in 0..200 {
            if m.in_flight() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(m.in_flight(), 0, "the delivery ended and the panic released its count");
        assert_eq!(m.outbox.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn without_smtp_mails_are_only_logged_and_kept_in_development_only() {
        let config = Config { domain: "t.local".into(), database_url: "postgres://x".into(), ..Config::default() };
        let m = Mailer::from_config(&config);
        assert!(!m.smtp_enabled());
        assert!(!m.can_deliver(), "production without SMTP delivers nothing");
        m.send_test("a@b.c").await.unwrap();
        assert!(m.outbox.lock().unwrap().is_empty(), "no mail (no token) kept in memory in production");
        let dev = Mailer::from_config(&Config { dev: true, ..config });
        assert!(dev.can_deliver());
        dev.send_test("a@b.c").await.unwrap();
        assert_eq!(dev.outbox.lock().unwrap()[0].0, "a@b.c");
    }
}
