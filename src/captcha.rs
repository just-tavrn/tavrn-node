// SPDX-License-Identifier: AGPL-3.0-only
//! Captcha verification (Cloudflare Turnstile). The node asks the provider server-side whether the token
//! supplied by the client is valid. Without a provider, nothing is required.

use std::time::Duration;

use serde::Deserialize;

use crate::{
    config::{CaptchaProvider, Config},
    error::ApiError,
};

const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Clone)]
pub enum CaptchaVerifier {
    Disabled,
    Turnstile {
        secret: String,
        http: reqwest::Client,
        url: String,
    },
    /// Tests only: exactly this token counts as valid.
    Static {
        accept: String,
    },
}

#[derive(Deserialize)]
struct SiteVerify {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

impl CaptchaVerifier {
    pub fn from_config(config: &Config) -> Self {
        match config.captcha_provider {
            CaptchaProvider::None => Self::Disabled,
            CaptchaProvider::Turnstile => Self::Turnstile {
                secret: config.turnstile_secret_key.clone().unwrap_or_default(),
                http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default(),
                url: TURNSTILE_VERIFY_URL.into(),
            },
        }
    }

    /// Checks the token. `required = false` lets the request through without a token.
    pub async fn check(&self, required: bool, token: Option<&str>, client_ip: &str) -> Result<(), ApiError> {
        if !required || matches!(self, Self::Disabled) {
            return Ok(());
        }
        let token = token
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(ApiError::BadRequest { code: "auth.captcha_required", detail: "Please solve the captcha".into() })?;
        if token.len() > 4096 {
            return Err(invalid());
        }
        match self {
            Self::Disabled => unreachable!("handled above"),
            Self::Static { accept } => {
                if token == accept {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::Turnstile { secret, http, url } => {
                let mut form = vec![("secret", secret.as_str()), ("response", token)];
                if client_ip != "unknown" {
                    form.push(("remoteip", client_ip));
                }
                let resp = http.post(url).form(&form).send().await.map_err(|e| {
                    tracing::warn!(error = %e, "Turnstile unreachable");
                    ApiError::Unavailable {
                        code: "auth.captcha_unavailable",
                        detail: "Captcha service unreachable, please try again later".into(),
                    }
                })?;
                // An error status or an unreadable answer (an outage page, a quota) is the service's problem, not
                // a wrong token and not a fault of the node.
                let unavailable = || ApiError::Unavailable {
                    code: "auth.captcha_unavailable",
                    detail: "Captcha service unavailable, please try again later".into(),
                };
                if !resp.status().is_success() {
                    tracing::warn!(status = resp.status().as_u16(), "Turnstile answered with an error");
                    return Err(unavailable());
                }
                let verdict: SiteVerify = resp.json().await.map_err(|_| {
                    tracing::warn!("unreadable Turnstile answer");
                    unavailable()
                })?;
                if verdict.success {
                    Ok(())
                } else {
                    tracing::debug!(codes = ?verdict.error_codes, "captcha rejected");
                    Err(invalid())
                }
            }
        }
    }
}

fn invalid() -> ApiError {
    ApiError::BadRequest {
        code: "auth.captcha_invalid",
        detail: "Captcha invalid or expired, please solve it again".into(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn disabled_and_static_verifiers() {
        assert!(CaptchaVerifier::Disabled.check(true, None, "1.2.3.4").await.is_ok());
        let v = CaptchaVerifier::Static { accept: "ok".into() };
        assert!(v.check(false, None, "x").await.is_ok());
        assert_eq!(v.check(true, None, "x").await.unwrap_err().code(), "auth.captcha_required");
        assert_eq!(v.check(true, Some("  "), "x").await.unwrap_err().code(), "auth.captcha_required");
        assert_eq!(v.check(true, Some("wrong"), "x").await.unwrap_err().code(), "auth.captcha_invalid");
        assert!(v.check(true, Some("ok"), "x").await.is_ok());
        assert_eq!(v.check(true, Some(&"a".repeat(5000)), "x").await.unwrap_err().code(), "auth.captcha_invalid");
    }

    #[tokio::test]
    async fn turnstile_talks_to_siteverify() {
        // Local fake endpoint: answers success=true only for the token "good".
        use axum::{Form, Json, Router, routing::post};
        #[derive(serde::Deserialize)]
        struct F {
            secret: String,
            response: String,
        }
        let app = Router::new()
            .route(
                "/verify",
                post(|Form(f): Form<F>| async move { Json(serde_json::json!({ "success": f.secret == "secret" && f.response == "good", "error-codes": ["invalid-input-response"] })) }),
            )
            .route(
                "/broken",
                post(|| async { (axum::http::StatusCode::BAD_GATEWAY, axum::response::Html("<h1>down</h1>")) }),
            )
            .route("/garbled", post(|| async { "not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let v = CaptchaVerifier::Turnstile {
            secret: "secret".into(),
            http: reqwest::Client::new(),
            url: format!("http://{addr}/verify"),
        };
        assert!(v.check(true, Some("good"), "1.2.3.4").await.is_ok());
        assert_eq!(v.check(true, Some("bad"), "1.2.3.4").await.unwrap_err().code(), "auth.captcha_invalid");
        let down = CaptchaVerifier::Turnstile {
            secret: "x".into(),
            http: reqwest::Client::new(),
            url: "http://127.0.0.1:1/verify".into(),
        };
        assert_eq!(down.check(true, Some("good"), "x").await.unwrap_err().code(), "auth.captcha_unavailable");
        // An error page or an unreadable answer: unavailable (503), not a fault of the node.
        for path in ["broken", "garbled"] {
            let v = CaptchaVerifier::Turnstile {
                secret: "secret".into(),
                http: reqwest::Client::new(),
                url: format!("http://{addr}/{path}"),
            };
            let e = v.check(true, Some("good"), "x").await.unwrap_err();
            assert_eq!((e.code(), e.status().as_u16()), ("auth.captcha_unavailable", 503), "{path}");
        }
    }
}
