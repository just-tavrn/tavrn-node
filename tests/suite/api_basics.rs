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
        // The Turnstile hosts are allowed only when a captcha is configured (security_headers below).
        assert!(!csp.contains("challenges.cloudflare.com"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("object-src 'none'"), "{csp}");
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

/// Malformed bodies and query strings answer Problem Details with a stable code like every other error
/// (PROTOCOL.md §4), and every Problem Details body names the request id the response carries in `x-request-id`.
#[tokio::test]
async fn malformed_input_answers_problem_details_with_the_request_id() {
    use axum::http::Method;
    let node = test_node("test.local").await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let channel = common::TestNode::text_channel(&room);
    let messages = format!("/api/v1/conversations/{channel}/messages");
    let json = [("content-type", "application/json")];
    for (method, path, headers, body, code) in [
        (Method::POST, messages.clone(), &json[..], b"{".to_vec(), "request.invalid_json"),
        (Method::POST, messages.clone(), &json[..], br#"[1]"#.to_vec(), "request.invalid_json"),
        (Method::POST, messages.clone(), &[][..], br#"{"content": "x"}"#.to_vec(), "request.invalid_json"),
        (Method::GET, format!("{messages}?limit=abc"), &[][..], Vec::new(), "request.invalid_query"),
    ] {
        let (status, headers, body) = node.raw(method.clone(), &path, &alice.token, headers, body).await;
        let what = format!("{method} {path}");
        assert!(status.is_client_error(), "{what}: {status}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json", "{what}");
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!((status, problem["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{what}: {problem}");
        let id = headers["x-request-id"].to_str().unwrap();
        assert!(!id.is_empty());
        assert_eq!(problem["request_id"], id, "{what}: {problem}");
    }
    // Errors of the handlers carry it as well.
    let (status, headers, body) =
        node.raw(Method::GET, "/api/v1/rooms/01J9AAAAAAAAAAAAAAAAAAAAAA", &alice.token, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["request_id"], headers["x-request-id"].to_str().unwrap(), "{problem}");
}

/// `tavrn-node health` (the image's health check) probes the running server on its listen port: healthy while it
/// answers, unhealthy when nothing answers.
#[tokio::test]
async fn the_health_probe_checks_the_running_server() {
    let node = test_node_with("test.local", |c| c.voice_enabled = false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let listen = format!("0.0.0.0:{port}");
    tavrn_node::routes::health::probe(&listen, false).await.unwrap();
    tavrn_node::routes::health::probe(&listen, true).await.unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let err = tavrn_node::routes::health::probe(&format!("0.0.0.0:{closed}"), false).await.unwrap_err();
    assert!(err.contains(&format!("127.0.0.1:{closed}/healthz")), "{err}");
}
