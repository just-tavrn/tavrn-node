// SPDX-License-Identifier: AGPL-3.0-only
//! Hook requests: everything this node sends to an application's URL (protocol/APPLICATIONS.md §6.3), today the
//! event subscriptions of §6.2 (the interactions URL of §5.6 uses the same client and token).
//!
//! - **URL rules**: `https://` only (development nodes also accept `http://`), a host, no credentials, no
//!   fragment, at most [`MAX_URL`] characters (`400 app.url_invalid`).
//! - **Outbound client**: the vetting resolver of `federation::client` (every DNS answer must be a public
//!   address unless `TAVRN_APP_ALLOW_PRIVATE_URLS`; reqwest connects only to the vetted addresses, so a second DNS
//!   answer cannot move the request to an internal host), IP literals checked the same way, no redirects (a
//!   `3xx` is a failure), no proxies, no cookies, the answer read up to [`MAX_RESPONSE_BYTES`], timeouts per
//!   purpose ([`VERIFY_TIMEOUT`], [`EVENT_TIMEOUT`]).
//! - **Signature**: every request carries `Tavrn-Signature: <hook token>`, an EdDSA JWT of this node
//!   (`typ = "hook"`, `aud = "app:<application id>"`, `htu` = the exact URL, `body_sha256` of the exact body, a
//!   fresh `jti` per attempt, 300 seconds), plus `Tavrn-Event-Type`, `Tavrn-Event-Id` and the node's
//!   `User-Agent`. Applications verify it against the node's `.well-known` keys (`verifyHookRequest()` of the
//!   SDK).
//! - **Verification** of a URL: `{ "type": "ping", "challenge": "<base64url 32 bytes>" }` must be answered with
//!   `200 { "challenge": "<same>" }` within 5 seconds (`400 app.url_verification_failed`), so a node cannot be
//!   pointed at a third party's server.

use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

use reqwest::{Url, header};
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    config::Config,
    error::ApiError,
    federation::client::{AddressForbidden, Lookup, SystemLookup, VettingResolver, forbidden_ip, user_agent},
    jwt::{self, StandardClaims},
    util,
};

pub const MAX_URL: usize = 2048;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// URL verification (the ping) must be answered within this time.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// Event deliveries succeed with a `2xx` within this time.
pub const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Command invocations (§5.6, step 3).
pub const INVOKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Lifetime of a hook token.
pub const HOOK_TTL_SECS: i64 = 300;
pub const SIGNATURE_HEADER: &str = "tavrn-signature";
pub const EVENT_TYPE_HEADER: &str = "tavrn-event-type";
pub const EVENT_ID_HEADER: &str = "tavrn-event-id";

/// Why a hook request failed. [`HookError::label`] is what `last_error` shows (never the receiver's content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookError {
    /// The URL breaks the URL rules.
    Invalid,
    /// The host is (or resolves to) a private, loopback or otherwise non-public address.
    AddressForbidden,
    Unreachable,
    Timeout,
    /// A `3xx` answer: redirects are never followed.
    Redirect,
    TooLarge,
    Status {
        status: u16,
        retry_after: Option<u64>,
    },
}

impl HookError {
    pub fn label(&self) -> String {
        match self {
            Self::Invalid => "url_invalid".into(),
            Self::AddressForbidden => "address_forbidden".into(),
            Self::Unreachable => "unreachable".into(),
            Self::Timeout => "timeout".into(),
            Self::Redirect => "redirect".into(),
            Self::TooLarge => "too_large".into(),
            Self::Status { status, .. } => format!("status {status}"),
        }
    }

    /// Network errors, timeouts, 408, 429 and 5xx are retried (FEDERATION.md §5.3); everything else is final.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Unreachable | Self::Timeout => true,
            Self::Status { status, .. } => matches!(status, 408 | 429) || *status >= 500,
            _ => false,
        }
    }

    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

pub fn url_invalid(detail: impl Into<String>) -> ApiError {
    ApiError::BadRequest { code: "app.url_invalid", detail: detail.into() }
}

pub fn verification_failed(detail: impl Into<String>) -> ApiError {
    ApiError::BadRequest { code: "app.url_verification_failed", detail: detail.into() }
}

/// A `2xx` answer of an application URL.
#[derive(Debug, Clone)]
pub struct HookResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The outbound client for application URLs.
pub struct HookClient {
    http: reqwest::Client,
    resolver: VettingResolver,
    allow_private: bool,
    allow_http: bool,
}

impl HookClient {
    /// The production client: system DNS, private addresses only with `TAVRN_APP_ALLOW_PRIVATE_URLS`.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        Self::new(config, Arc::new(SystemLookup))
    }

    /// A client with its own DNS lookup (tests).
    pub fn new(config: &Config, lookup: Arc<dyn Lookup>) -> anyhow::Result<Self> {
        let resolver = VettingResolver::new(lookup, config.app_allow_private_urls, HashSet::new());
        let http = reqwest::Client::builder()
            .user_agent(user_agent(&config.domain))
            .dns_resolver(Arc::new(resolver.clone()))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(VERIFY_TIMEOUT)
            .timeout(EVENT_TIMEOUT)
            .no_proxy()
            .build()?;
        Ok(Self { http, resolver, allow_private: config.app_allow_private_urls, allow_http: config.dev })
    }

    /// Checks the URL rules and returns the parsed URL (`400 app.url_invalid`).
    pub fn check_url(&self, raw: &str) -> Result<Url, ApiError> {
        check_url(raw, self.allow_http)
    }

    /// The addresses of the URL's host must be public (unless private URLs are allowed).
    async fn check_target(&self, url: &Url) -> Result<(), HookError> {
        let host = url.host_str().ok_or(HookError::Invalid)?.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if !self.allow_private && forbidden_ip(ip) { Err(HookError::AddressForbidden) } else { Ok(()) };
        }
        match self.resolver.vetted(host).await {
            Ok(_) => Ok(()),
            Err(e) if e.is::<AddressForbidden>() => Err(HookError::AddressForbidden),
            Err(_) => Err(HookError::Unreachable),
        }
    }

    /// POSTs `body` with the given headers; a `2xx` answer is read up to [`MAX_RESPONSE_BYTES`].
    pub async fn post(
        &self,
        url: &Url,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<HookResponse, HookError> {
        if check_url(url.as_str(), self.allow_http).is_err() {
            return Err(HookError::Invalid);
        }
        self.check_target(url).await?;
        let mut request = self
            .http
            .post(url.clone())
            .timeout(timeout)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let classify = |e: reqwest::Error| {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
            while let Some(err) = source {
                if err.downcast_ref::<AddressForbidden>().is_some() {
                    return HookError::AddressForbidden;
                }
                source = err.source();
            }
            if e.is_timeout() { HookError::Timeout } else { HookError::Unreachable }
        };
        let send = async {
            let mut response = request.body(body).send().await.map_err(classify)?;
            let status = response.status();
            if status.is_redirection() {
                return Err(HookError::Redirect);
            }
            if !status.is_success() {
                let retry_after = response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse().ok());
                return Err(HookError::Status { status: status.as_u16(), retry_after });
            }
            if response.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
                return Err(HookError::TooLarge);
            }
            let mut out = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(classify)? {
                if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(HookError::TooLarge);
                }
                out.extend_from_slice(&chunk);
            }
            Ok(HookResponse { status: status.as_u16(), body: out })
        };
        // The client timeout covers the request; this one also covers a slowly trickling body.
        tokio::time::timeout(timeout, send).await.map_err(|_| HookError::Timeout)?
    }
}

/// The URL rules of §6.3 (`http://` only when `allow_http`, i.e. on development nodes).
pub fn check_url(raw: &str, allow_http: bool) -> Result<Url, ApiError> {
    if raw.is_empty() || raw.len() > MAX_URL {
        return Err(url_invalid(format!("url: 1 to {MAX_URL} characters")));
    }
    if raw.contains('#') {
        return Err(url_invalid("url must not have a fragment"));
    }
    let url = Url::parse(raw).map_err(|_| url_invalid("url is not a valid URL"))?;
    let scheme_ok = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !scheme_ok {
        return Err(url_invalid("url must start with https://"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(url_invalid("url must not contain credentials"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(url_invalid("url needs a host"));
    }
    Ok(url)
}

/// Claims of a hook token (§6.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    /// The exact target URL.
    pub htu: String,
    /// base64url SHA-256 of the exact body.
    pub body_sha256: String,
}

/// The audience of hook tokens for an application.
pub fn audience(application_id: &str) -> String {
    format!("app:{application_id}")
}

/// Signs a hook token for one request of `body` to `url` (a fresh `jti` per attempt).
pub fn issue_token(state: &AppState, application_id: &str, url: &str, body: &[u8]) -> Result<String, ApiError> {
    let now = jwt::now_unix();
    let claims = HookClaims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: state.config.domain.clone(),
            aud: audience(application_id),
            exp: now + HOOK_TTL_SECS,
            iat: now,
            jti: util::ulid(),
            typ: "hook".into(),
        },
        htu: url.to_string(),
        body_sha256: crate::federation::tokens::body_sha256(body),
    };
    let key = state.signing_key();
    jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))
}

/// Sends one signed hook request (`event_type` and `event_id` go into the headers).
pub async fn send(
    state: &AppState,
    application_id: &str,
    url: &Url,
    event_type: &str,
    event_id: &str,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<HookResponse, HookError> {
    let token = issue_token(state, application_id, url.as_str(), &body).map_err(|_| HookError::Unreachable)?;
    let headers = [
        (SIGNATURE_HEADER, token),
        (EVENT_TYPE_HEADER, event_type.to_string()),
        (EVENT_ID_HEADER, event_id.to_string()),
    ];
    state.hooks.post(url, &headers, body, timeout).await
}

#[derive(Deserialize)]
struct PingAnswer {
    challenge: String,
}

/// URL verification (§6.3): a ping with a fresh challenge that the URL must echo with `200` within 5 seconds.
pub async fn verify_url(state: &AppState, application_id: &str, url: &Url) -> Result<(), ApiError> {
    let challenge = util::random_token(32);
    let body = serde_json::to_vec(&serde_json::json!({ "type": "ping", "challenge": challenge }))
        .map_err(|e| ApiError::Internal(e.into()))?;
    let id = util::ulid();
    let answer = send(state, application_id, url, "ping", &id, body, VERIFY_TIMEOUT).await;
    let answer = match answer {
        Ok(a) if a.status == 200 => a,
        Ok(a) => return Err(verification_failed(format!("The URL answered {} instead of 200", a.status))),
        Err(HookError::AddressForbidden) => {
            return Err(verification_failed("The URL points to a private or local address"));
        }
        Err(e) => return Err(verification_failed(format!("The URL did not answer the ping ({})", e.label()))),
    };
    match serde_json::from_slice::<PingAnswer>(&answer.body) {
        Ok(p) if p.challenge == challenge => Ok(()),
        _ => Err(verification_failed("The URL did not echo the challenge")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn url_rules() {
        let code = |u: &str, http: bool| check_url(u, http).map(|_| ()).map_err(|e| e.code().to_string());
        assert_eq!(code("https://bot.example/hook", false), Ok(()));
        assert_eq!(code("https://bot.example:8443/hook?x=1", false), Ok(()));
        let bad = Err("app.url_invalid".to_string());
        for u in [
            "",
            "http://bot.example/hook",
            "ftp://bot.example/",
            "https://user:pw@bot.example/",
            "https://user@bot.example/",
            "https://bot.example/#frag",
            "https://bot.example/#",
            "javascript:alert(1)",
            "https://",
        ] {
            assert_eq!(code(u, false), bad, "{u}");
        }
        assert_eq!(code(&format!("https://bot.example/{}", "a".repeat(2048)), false), bad);
        assert_eq!(code("http://127.0.0.1:9/hook", true), Ok(()), "development nodes accept http");
        assert_eq!(code("http://user:pw@127.0.0.1/", true), bad);
    }

    #[test]
    fn retry_classes() {
        assert!(HookError::Timeout.retryable());
        assert!(HookError::Unreachable.retryable());
        assert!(HookError::Status { status: 503, retry_after: None }.retryable());
        assert!(HookError::Status { status: 429, retry_after: Some(60) }.retryable());
        assert!(!HookError::Status { status: 404, retry_after: None }.retryable());
        assert!(!HookError::Redirect.retryable());
        assert!(!HookError::AddressForbidden.retryable());
        assert_eq!(HookError::Status { status: 410, retry_after: None }.label(), "status 410");
    }
}
