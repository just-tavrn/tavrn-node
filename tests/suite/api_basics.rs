// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{StatusCode, header};
use common::{body_json, test_node, test_node_with};

#[tokio::test]
async fn healthz_and_readyz_report_ok() {
    // Without voice, readiness depends on the database only (voice_flow.rs covers LiveKit).
    let node = test_node_with("test.local", |c| c.voice_enabled = false).await;
    let resp = node.get("/healthz").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "ok");
    let resp = node.get("/readyz").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["ready"], true);
    assert_eq!(json["database"], true);
}

#[tokio::test]
async fn well_known_describes_node_and_keys() {
    let node = test_node("test.local").await;
    let resp = node.get("/.well-known/tavrn").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "public, max-age=300");
    let json = body_json(resp).await;
    assert_eq!(json["tavrn"], 1);
    assert_eq!(json["domain"], "test.local");
    assert_eq!(json["api"], "http://test.local:8080/api/v1");
    assert_eq!(json["ws"], "ws://test.local:8080/api/v1/ws");
    assert_eq!(json["keys"].as_array().unwrap().len(), 1);
    assert_eq!(json["keys"][0]["alg"], "EdDSA");
    assert_eq!(json["registration"], "open");
    assert_eq!(json["policies"]["upload_max_bytes"], 26_214_400);
    assert!(json["capabilities"].as_array().unwrap().iter().any(|c| c == "federation"));
}

#[tokio::test]
async fn node_info_is_available() {
    let node = test_node("test.local").await;
    let json = body_json(node.get("/api/v1/node").await).await;
    assert_eq!(json["domain"], "test.local");
    assert_eq!(json["name"], "Test node test.local");
    assert_eq!(json["protocol"], 1);
}

#[tokio::test]
async fn non_api_paths_fall_back_to_web_client_or_404() {
    let node = test_node("test.local").await;
    let resp = node.get("/rooms/whatever").await;
    // Without a built web client: a clear hint instead of Problem Details.
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_FOUND);
    if resp.status() == StatusCode::OK {
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/html");
        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(
            csp.contains("frame-src https://challenges.cloudflare.com https://*.challenges.cloudflare.com"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"));
    }
}

#[tokio::test]
async fn unknown_route_returns_problem_details() {
    let node = test_node("test.local").await;
    let resp = node.get("/api/v1/does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/problem+json");
    let json = body_json(resp).await;
    assert_eq!(json["code"], "route.not_found");
    assert_eq!(json["status"], 404);
}

#[tokio::test]
async fn every_response_carries_a_request_id_and_cors() {
    let node = test_node("test.local").await;
    let resp = node.get("/api/v1/node").await;
    assert!(resp.headers().contains_key("x-request-id"));
    assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

#[tokio::test]
async fn signing_key_persists_across_restarts() {
    let node = test_node("test.local").await;
    let first = node.state.signing_key().public_info();
    let config = node.state.config.as_ref().clone();
    let again = tavrn_node::app::AppState::init(config).await.unwrap();
    assert_eq!(again.signing_key().public_info(), first);
}

#[tokio::test]
async fn node_info_and_well_known_publish_the_webauthn_relying_party_id() {
    // Default: the identity domain.
    let node = test_node("test.local").await;
    let info = body_json(node.get("/api/v1/node").await).await;
    assert_eq!(info["webauthn"]["rp_id"], "test.local");
    let wk = body_json(node.get("/.well-known/tavrn").await).await;
    assert_eq!(wk["webauthn"]["rp_id"], "test.local");

    // Delegation: the web client runs on a subdomain, passkeys belong to the parent domain
    // (TAVRN_WEBAUTHN_RP_ID); clients pass it as `rpId` on their own assertions.
    let node = test_node_with("app.tavrn.test", |c| {
        c.public_url = Some("http://app.tavrn.test:8080".into());
        c.webauthn_rp_id = Some("tavrn.test".into());
    })
    .await;
    let info = body_json(node.get("/api/v1/node").await).await;
    assert_eq!(info["webauthn"]["rp_id"], "tavrn.test");
    let wk = body_json(node.get("/.well-known/tavrn").await).await;
    assert_eq!(wk["webauthn"]["rp_id"], "tavrn.test");
}

/// Every response carries the security headers; the web client's pages get a CSP that names the captcha hosts only
/// when a captcha is configured and allows no plugins.
#[tokio::test]
async fn security_headers_and_the_web_client_csp() {
    let node = common::test_node("t.local").await;
    let resp = node.get("/api/v1/node").await;
    let h = resp.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    let pp = h["permissions-policy"].to_str().unwrap();
    for p in ["camera=(self)", "microphone=(self)", "display-capture=(self)", "geolocation=()", "payment=()", "usb=()"]
    {
        assert!(pp.contains(p), "{p} in {pp}");
    }
    let page = node.get("/some/client/route").await;
    if let Some(csp) = page.headers().get("content-security-policy") {
        let csp = csp.to_str().unwrap();
        assert!(csp.contains("object-src 'none'"), "{csp}");
        assert!(!csp.contains("cloudflare") && !csp.contains("fonts.g"), "{csp}");
    }
    let captcha = common::test_node_with("c.local", |c| {
        c.captcha_provider = tavrn_node::config::CaptchaProvider::Turnstile;
        c.turnstile_site_key = Some("site".into());
        c.turnstile_secret_key = Some("secret".into());
    })
    .await;
    let page = captcha.get("/some/client/route").await;
    if let Some(csp) = page.headers().get("content-security-policy") {
        assert!(csp.to_str().unwrap().contains("https://challenges.cloudflare.com"));
    }
}
