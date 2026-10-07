// SPDX-License-Identifier: AGPL-3.0-only
//! Thin HTTP client for the node API: accounts with TOTP, rooms, messages, MLS.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

/// An account created by the load generator.
#[derive(Debug, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub token: String,
    pub device_id: String,
    /// Source address sent as `X-Forwarded-For` (the node trusts loopback proxies), so that the
    /// per-IP rate limits of production apply per simulated user, as with real clients.
    pub ip: String,
}

impl User {
    pub fn address(&self) -> String {
        format!("{}@localhost", self.username)
    }
}

/// Address of simulated client `i` in the benchmarking range 198.18.0.0/15 (RFC 2544).
pub fn client_ip(i: usize) -> String {
    format!("198.18.{}.{}", (i / 250) % 256, i % 250 + 1)
}

/// TOTP code (SHA-1, 6 digits, 30 s) for a base32 secret, as an authenticator app computes it.
pub fn totp_now(secret_base32: &str) -> Result<String> {
    let secret = totp_rs::Secret::try_from_base32(secret_base32).map_err(|e| anyhow!("TOTP secret: {e:?}"))?;
    let totp = totp_rs::Builder::new().with_secret(secret).build().map_err(|e| anyhow!("TOTP: {e:?}"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(totp.generate(now).to_string())
}

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    pub base: String,
}

impl Api {
    pub fn new(base: &str) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).pool_max_idle_per_host(512).build()?;
        Ok(Self { http, base: base.trim_end_matches('/').into() })
    }

    /// One request; returns status, JSON body (Null when empty) and the latency in milliseconds.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        ip: Option<&str>,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value, f64)> {
        let mut req = self.http.request(method, format!("{}/api/v1{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(ip) = ip {
            req = req.header("X-Forwarded-For", ip);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let start = Instant::now();
        let resp = req.send().await.with_context(|| format!("request {path}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        let json = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
        Ok((status, json, ms))
    }

    /// Like [`Api::call`] but fails on a non-success status.
    pub async fn ok(&self, method: Method, path: &str, user: Option<&User>, body: Option<Value>) -> Result<Value> {
        let (status, json, _) = self
            .call(method.clone(), path, user.map(|u| u.token.as_str()), user.map(|u| u.ip.as_str()), body.as_ref())
            .await?;
        if !status.is_success() {
            bail!("{method} {path}: {status} {json}");
        }
        Ok(json)
    }

    /// Registers `username` and enrolls TOTP (the second factor is mandatory); returns the session.
    pub async fn register(&self, username: &str, ip: &str) -> Result<User> {
        let password = format!("perf-{username}-password");
        let body = json!({ "username": username, "password": password, "device_name": "loadgen" });
        let (status, pre, _) = self.call(Method::POST, "/auth/register", None, Some(ip), Some(&body)).await?;
        if status != StatusCode::CREATED {
            bail!("register {username}: {status} {pre}");
        }
        let preauth = pre["preauth_token"].as_str().ok_or_else(|| anyhow!("register: no preauth_token"))?;
        let (status, enroll, _) =
            self.call(Method::POST, "/auth/totp/enroll", Some(preauth), Some(ip), Some(&json!({}))).await?;
        if !status.is_success() {
            bail!("totp/enroll {username}: {status} {enroll}");
        }
        let secret = enroll["secret"].as_str().ok_or_else(|| anyhow!("totp/enroll: no secret"))?;
        let code = totp_now(secret)?;
        let (status, confirmed, _) = self
            .call(Method::POST, "/auth/totp/confirm", Some(preauth), Some(ip), Some(&json!({ "code": code })))
            .await?;
        if !status.is_success() {
            bail!("totp/confirm {username}: {status} {confirmed}");
        }
        let session = &confirmed["session"];
        let field = |k: &str| -> Result<String> {
            session[k].as_str().map(String::from).ok_or_else(|| anyhow!("totp/confirm: session.{k} missing"))
        };
        Ok(User {
            username: username.into(),
            password,
            token: field("access_token")?,
            device_id: field("device_id")?,
            ip: ip.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ips_are_distinct_and_in_the_benchmark_range() {
        let ips: std::collections::HashSet<String> = (0..2000).map(client_ip).collect();
        assert_eq!(ips.len(), 2000);
        assert!(ips.iter().all(|ip| ip.starts_with("198.18.")));
        assert!(ips.iter().all(|ip| !ip.ends_with(".0")));
    }

    #[test]
    fn totp_codes_have_six_digits() -> Result<()> {
        let code = totp_now("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")?;
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(totp_now("not base32!").is_err());
        Ok(())
    }
}
