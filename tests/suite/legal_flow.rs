// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Legal pages, terms acceptance and takedown notices (protocol/LEGAL.md).
use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, body_bytes, federation::two_nodes_with, password, test_node, test_node_with};
use serde_json::{Value, json};

const NOTICES: &str = "/api/v1/legal/notices";

async fn publish(node: &TestNode, token: &str, kind: &str, markdown: &str) -> (StatusCode, Value) {
    node.put(&format!("/api/v1/admin/legal/documents/{kind}"), token, json!({ "markdown": markdown, "lang": "de" }))
        .await
}

async fn admin_token(node: &TestNode, admin: &Session) -> String {
    let (s, j) = node
        .post(
            "/api/v1/admin/tokens",
            &admin.token,
            json!({ "name": "Ops", "scopes": ["users:read", "users:write", "invites", "entitlements"] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j["secret"].as_str().unwrap().to_string()
}

fn notice(location: &str) -> Value {
    json!({
        "basis": "copyright",
        "reporter_name": "Rita Reporter",
        "reporter_email": "rita@example.org",
        "reporter_address": "Main Street 1, Town",
        "work": "My photo 'Sunset'",
        "locations": [{ "kind": "message", "value": location }],
        "good_faith": true,
        "accuracy": true,
        "perjury": true,
        "signature": "Rita Reporter",
    })
}

async fn submit(node: &TestNode, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, NOTICES, None, Some(body)).await
}

/// The status link of the last confirmation mail: (case id, token).
fn status_link(node: &TestNode) -> (String, String) {
    let outbox = node.state.mailer.outbox.lock().unwrap().clone();
    let (_, _, body) = outbox.iter().rev().find(|(_, s, _)| s.contains("Notice received")).unwrap().clone();
    let link = body.lines().find(|l| l.contains("/legal/notice/")).unwrap().trim().to_string();
    let rest = link.split("/legal/notice/").nth(1).unwrap();
    let (case, token) = rest.split_once("?token=").unwrap();
    (case.to_string(), token.to_string())
}

async fn notices_node() -> TestNode {
    test_node_with("t.local", |c| c.legal_notices = tavrn_node::config::Switch::On).await
}

// ---------------------------------------------------------------- legal pages

#[tokio::test]
async fn admins_publish_sanitized_pages_that_everyone_can_read() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let md = "# Impressum\n\nMax Muster\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) <img src=x onerror=alert(2)>";

    // Permissions: signed out, a member, an admin API token (fail closed).
    let (s, _) =
        node.req(Method::PUT, "/api/v1/admin/legal/documents/imprint", None, Some(json!({ "markdown": md }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, j) = publish(&node, &bob.token, "imprint", md).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")));
    let token = admin_token(&node, &admin).await;
    let (s, j) = publish(&node, &token, "imprint", md).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("admin_token.route_forbidden")), "{j}");
    let (s, j) = node.get_auth("/api/v1/admin/legal/notices", &token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("admin_token.route_forbidden")));

    let (s, j) = publish(&node, &admin.token, "imprint", md).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["version"], 1);
    let html = j["html"].as_str().unwrap();
    assert!(html.contains("<h1>Impressum</h1>"), "{html}");
    for bad in ["<script", "<img", "javascript:", "onerror=alert(2)>"] {
        assert!(!html.contains(bad), "{bad} in {html}");
    }
    let (_, j) = publish(&node, &admin.token, "imprint", "# Impressum\n\nNeu").await;
    assert_eq!(j["version"], 2);
    let (s, j) = publish(&node, &admin.token, "nonsense", "x").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("legal.page_not_found")));
    let (s, j) = node
        .put("/api/v1/admin/legal/documents/privacy", &admin.token, json!({ "markdown": "x", "lang": "\"><script>" }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.lang_invalid")));
    let big = "a".repeat(tavrn_node::legal::markdown::MAX_MARKDOWN_BYTES + 1);
    let (s, _) = publish(&node, &admin.token, "privacy", &big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    // Public: JSON, GET /node, the standalone HTML page.
    let (s, pages) = node.req(Method::GET, "/api/v1/legal/pages", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(pages[0]["kind"], "imprint");
    assert_eq!(pages[0]["url"], "/legal/imprint");
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["legal"]["pages"]["imprint"]["version"], 2, "{info}");
    assert!(info["legal"]["pages"]["terms"].is_null());
    assert_eq!(info["legal"]["notices"]["enabled"], false);
    let resp = node.get("/legal/imprint").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
    let csp = resp.headers()["content-security-policy"].to_str().unwrap().to_string();
    assert!(csp.contains("default-src 'none'") && !csp.contains("script-src"), "{csp}");
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(body.contains("<html lang=\"de\">") && body.contains("Neu") && !body.contains("<script"), "{body}");
    let resp = node.get("/legal/terms").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unpublished");
    // Other paths below /legal/ belong to the web client (the notice form).
    let resp = node.get("/legal/notice").await;
    assert_ne!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!String::from_utf8(body_bytes(resp).await.to_vec()).unwrap().contains("not been published"));

    // Template with the placeholders the node knows; unpublish keeps the version counter.
    let (_, c) = node
        .put(
            "/api/v1/admin/legal/contact",
            &admin.token,
            json!({ "name": "Op GmbH", "address": "Str. 1", "email": "legal@t.local" }),
        )
        .await;
    assert_eq!(c["email"], "legal@t.local");
    let (s, j) = node.put("/api/v1/admin/legal/contact", &admin.token, json!({ "email": "x\r\nBcc: y@z" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.email_invalid")));
    let (_, t) = node.get_auth("/api/v1/admin/legal/templates/privacy?locale=de", &admin.token).await;
    let t = t["markdown"].as_str().unwrap();
    assert!(t.contains("Vorlage") && t.contains("legal@t.local") && t.contains("t.local"), "{t}");
    assert!(!t.contains("{{contact_email}}"));
    let (s, _) = node.delete("/api/v1/admin/legal/documents/imprint", &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.req(Method::GET, "/api/v1/legal/pages/imprint", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, j) = publish(&node, &admin.token, "imprint", "again").await;
    assert_eq!(j["version"], 3, "versions only grow");
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["legal"]["notices"]["contact"]["name"], "Op GmbH");
    // Audit entries.
    let (_, log) = node.get_auth("/api/v1/admin/audit-log?limit=50", &admin.token).await;
    assert!(log.as_array().unwrap().iter().any(|e| e["action"] == "legal.document_publish"));
}

// ---------------------------------------------------------------- terms

/// Registration with an accepted terms version; returns the full session.
async fn register_accepting(node: &TestNode, username: &str, version: Option<i64>) -> (StatusCode, Value) {
    let mut body = json!({ "username": username, "password": password(username), "device_name": "t" });
    if let Some(v) = version {
        body["accept_terms"] = json!(v);
    }
    node.req(Method::POST, "/api/v1/auth/register", None, Some(body)).await
}

#[tokio::test]
async fn registration_needs_the_current_terms_and_new_versions_are_accepted_once() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let (_, terms) = publish(&node, &admin.token, "terms", "# Terms\n\nBe nice.").await;
    assert_eq!(terms["version"], 1);

    let (s, j) = register_accepting(&node, "carol", None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.terms_not_accepted")), "{j}");
    assert_eq!(j["meta"]["version"], 1);
    let (s, _) = register_accepting(&node, "carol", Some(7)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, j) = register_accepting(&node, "carol", Some(1)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, confirmed) = node.enroll_totp(j["preauth_token"].as_str().unwrap()).await;
    let carol = confirmed["session"]["access_token"].as_str().unwrap().to_string();
    let (_, st) = node.get_auth("/api/v1/users/me/terms", &carol).await;
    assert_eq!((st["accepted_version"].as_i64(), st["pending"].as_bool()), (Some(1), Some(false)), "{st}");
    assert_eq!(st["mode"], "notice");

    // The admin registered before the terms existed: pending, but nothing is blocked in `notice` mode.
    let (_, st) = node.get_auth("/api/v1/users/me/terms", &admin.token).await;
    assert_eq!(st["pending"], true);
    let (s, _) = node.get_auth("/api/v1/rooms", &admin.token).await;
    assert_eq!(s, StatusCode::OK);

    // A new version: everyone is asked once; an outdated version is refused.
    publish(&node, &admin.token, "terms", "# Terms\n\nBe very nice.").await;
    let (_, st) = node.get_auth("/api/v1/users/me/terms", &carol).await;
    assert_eq!((st["current_version"].as_i64(), st["pending"].as_bool()), (Some(2), Some(true)));
    let (s, j) = node.post("/api/v1/users/me/terms/accept", &carol, json!({ "version": 1 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("legal.terms_version_mismatch")));
    let (s, st) = node.post("/api/v1/users/me/terms/accept", &carol, json!({ "version": 2 })).await;
    assert_eq!((s, st["pending"].as_bool()), (StatusCode::OK, Some(false)), "{st}");
    let (s, _) = node.req(Method::GET, "/api/v1/users/me/terms", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_mode_refuses_everything_but_the_legal_flow_until_accepted() {
    let node = test_node_with("t.local", |c| c.legal_terms_mode = tavrn_node::config::TermsMode::Require).await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&admin.token, "Hall").await;
    publish(&node, &admin.token, "terms", "# Terms").await;

    for (method, path) in [
        (Method::GET, "/api/v1/rooms".to_string()),
        (Method::GET, "/api/v1/users/me".to_string()),
        (Method::GET, format!("/api/v1/rooms/{}", room["id"].as_str().unwrap())),
        (Method::GET, "/api/v1/admin/overview".to_string()),
    ] {
        let (s, j) = node.req(method.clone(), &path, Some(&bob.token), None).await;
        if path.contains("admin") {
            assert_eq!(s, StatusCode::FORBIDDEN);
            continue;
        }
        assert_eq!(
            (s, j["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("legal.terms_required")),
            "{method} {path}: {j}"
        );
        assert_eq!(j["meta"]["version"], 1);
    }
    let (s, j) = node.get_auth("/api/v1/admin/overview", &admin.token).await;
    assert_eq!(j["code"], "legal.terms_required", "admins accept too: {s}");
    // Still allowed: the status, the pages, the acceptance and logout.
    let (s, st) = node.get_auth("/api/v1/users/me/terms", &bob.token).await;
    assert_eq!((s, st["mode"].as_str()), (StatusCode::OK, Some("require")));
    let (s, _) = node.req(Method::GET, "/api/v1/legal/pages/terms", None, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node.post("/api/v1/users/me/terms/accept", &bob.token, json!({ "version": 1 })).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node.get_auth("/api/v1/rooms", &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node.post("/api/v1/auth/logout", &admin.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "logout stays possible");
}

#[tokio::test]
async fn sso_users_accept_at_their_first_login() {
    use common::oidc::{FakeIdp, Login, configure, flow};
    let idp = FakeIdp::start().await;
    let i = idp.clone();
    let node = test_node_with("sso.test", move |c| {
        configure(c, &i);
        c.legal_terms_mode = tavrn_node::config::TermsMode::Require;
    })
    .await;
    let admin = node.register("admin").await;
    publish(&node, &admin.token, "terms", "# Terms").await;
    idp.set_login(Login::new("sub-sam", "sam"));
    let session = flow(&node, "login", None).await.ok();
    let token = session["access_token"].as_str().unwrap();
    let (s, j) = node.get_auth("/api/v1/rooms", token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("legal.terms_required")), "{j}");
    let (_, st) = node.get_auth("/api/v1/users/me/terms", token).await;
    assert_eq!(st["pending"], true);
    node.post("/api/v1/users/me/terms/accept", token, json!({ "version": 1 })).await;
    let (s, _) = node.get_auth("/api/v1/rooms", token).await;
    assert_eq!(s, StatusCode::OK);
}

// ---------------------------------------------------------------- notices: the public form

#[tokio::test]
async fn the_notice_form_checks_fields_limits_and_answers_without_an_oracle() {
    let off = test_node("t.local").await;
    let (s, j) = submit(&off, notice("01JAAAAAAAAAAAAAAAAAAAAAAA")).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("legal.notices_disabled")));

    let node = notices_node().await;
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["legal"]["notices"]["enabled"], true);
    let (s, created) = submit(&node, notice("01JAAAAAAAAAAAAAAAAAAAAAAA")).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    assert_eq!(created["state"], "received");
    let case = created["case_id"].as_str().unwrap();
    let (mail_case, token) = status_link(&node);
    assert_eq!(mail_case, case);

    let (s, st) = node.req(Method::GET, &format!("{NOTICES}/{case}?token={token}"), None, None).await;
    assert_eq!((s, st["state"].as_str()), (StatusCode::OK, Some("received")), "{st}");
    assert!(st.get("reporter_email").is_none(), "no reporter data on the status page");
    // Wrong token, no token, unknown or malformed case: the same answer.
    let unknown = tavrn_node::util::ulid();
    let mut answers = Vec::new();
    for path in [
        format!("{NOTICES}/{case}?token=wrong"),
        format!("{NOTICES}/{case}"),
        format!("{NOTICES}/{unknown}?token={token}"),
        format!("{NOTICES}/not-a-ulid?token={token}"),
    ] {
        let (s, j) = node.req(Method::GET, &path, None, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
        answers.push((j["code"].clone(), j["detail"].clone()));
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");

    // Field validation.
    let mut b = notice("x");
    b["perjury"] = json!(false);
    assert_eq!(submit(&node, b).await.1["code"], "legal.perjury_required");
    let mut b = notice("x");
    b["basis"] = json!("illegal");
    assert_eq!(submit(&node, b).await.1["code"], "legal.explanation_required");
    let mut b = notice("x");
    b["reporter_email"] = json!("rita@example.org\r\nBcc: all@example.org");
    assert_eq!(submit(&node, b).await.1["code"], "legal.email_invalid");
    let mut b = notice("x");
    b["good_faith"] = json!(false);
    assert_eq!(submit(&node, b).await.1["code"], "legal.statements_required");
    let mut b = notice("x");
    b["locations"] = json!((0..21).map(|_| json!({ "kind": "other", "value": "x" })).collect::<Vec<_>>());
    assert_eq!(submit(&node, b).await.1["code"], "legal.locations_invalid");
    // Body limit (32 KiB) before any parsing.
    let mut b = notice("x");
    b["work"] = json!("a".repeat(40 * 1024));
    let (s, _) = submit(&node, b).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    // Markup is stored as text and never rendered (the admin page escapes it).
    let mut b = notice("<script>alert(1)</script>");
    b["reporter_name"] = json!("<img src=x onerror=alert(1)>");
    let (s, _) = submit(&node, b).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn the_notice_form_is_rate_limited_and_uses_the_captcha() {
    let node = test_node_with("t.local", |c| {
        c.legal_notices = tavrn_node::config::Switch::On;
        c.legal_notice_rate_per_hour = 2;
    })
    .await;
    for _ in 0..2 {
        assert_eq!(submit(&node, notice("x")).await.0, StatusCode::CREATED);
    }
    let (s, j) = submit(&node, notice("x")).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));

    let mut node = test_node_with("t.local", |c| {
        c.legal_notices = tavrn_node::config::Switch::On;
        c.captcha_provider = tavrn_node::config::CaptchaProvider::Turnstile;
        c.turnstile_site_key = Some("site".into());
        c.turnstile_secret_key = Some("secret".into());
    })
    .await;
    node.state.captcha = tavrn_node::captcha::CaptchaVerifier::Static { accept: "gut".into() };
    node.router = tavrn_node::app::router(node.state.clone());
    assert_eq!(submit(&node, notice("x")).await.1["code"], "auth.captcha_required");
    let mut b = notice("x");
    b["captcha_token"] = json!("wrong");
    assert_eq!(submit(&node, b).await.1["code"], "auth.captcha_invalid");
    let mut b = notice("x");
    b["captcha_token"] = json!("gut");
    assert_eq!(submit(&node, b).await.0, StatusCode::CREATED);
}

// ---------------------------------------------------------------- notices: the admin side

struct Case {
    node: TestNode,
    admin: Session,
    bob: Session,
    room_id: String,
    channel: String,
    message_id: String,
}

/// Admin, uploader bob with a plaintext message, and a notice naming the message by its link.
async fn reported() -> (Case, String) {
    let node = notices_node().await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&bob.token, "Photos").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, m) = node.send(&bob.token, &room_id, &channel, "stolen sunset photo").await;
    let message_id = m["id"].as_str().unwrap().to_string();
    let link = format!("https://t.local/rooms/{room_id}/channels/{channel}?message={message_id}");
    let (_, created) = submit(&node, notice(&link)).await;
    let case = created["case_id"].as_str().unwrap().to_string();
    (Case { node, admin, bob, room_id, channel, message_id }, case)
}

async fn act(c: &Case, case: &str, body: Value) -> (StatusCode, Value) {
    c.node.post(&format!("/api/v1/admin/legal/notices/{case}/actions"), &c.admin.token, body).await
}

#[tokio::test]
async fn admins_review_remove_and_the_uploader_gets_a_statement_and_may_counter() {
    let (c, case) = reported().await;
    let node = &c.node;
    // Only node admins.
    let (s, j) = node.get_auth("/api/v1/admin/legal/notices", &c.bob.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")));
    let (s, _) = node.get_auth(&format!("/api/v1/admin/legal/notices/{case}"), &c.bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = node
        .post(
            &format!("/api/v1/admin/legal/notices/{case}/actions"),
            &c.bob.token,
            json!({ "action": "reject", "reason": "x" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // List with filters, detail with the plaintext content inline.
    let (_, list) = node.get_auth("/api/v1/admin/legal/notices?state=received", &c.admin.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (_, list) = node.get_auth("/api/v1/admin/legal/notices?state=rejected", &c.admin.token).await;
    assert!(list.as_array().unwrap().is_empty());
    let (_, list) = node.get_auth("/api/v1/admin/legal/notices?q=RITA", &c.admin.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (_, list) = node.get_auth("/api/v1/admin/legal/notices?q=%25", &c.admin.token).await;
    assert!(list.as_array().unwrap().is_empty(), "wildcards are literal");
    let (s, j) = node.get_auth("/api/v1/admin/legal/notices?state=bogus", &c.admin.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.enum")));
    let (_, d) = node.get_auth(&format!("/api/v1/admin/legal/notices/{case}"), &c.admin.token).await;
    assert_eq!(d["locations"][0]["local"], true, "{d}");
    assert_eq!(d["locations"][0]["id"], c.message_id.as_str());
    assert_eq!(d["locations"][0]["author"], "bob@t.local");
    assert_eq!(d["content"][0]["text"], "stolen sunset photo");
    assert_eq!(d["content"][0]["encrypted"], false);
    assert_eq!(d["events"][0]["action"], "received");

    // Removing needs the statement of reasons.
    let (s, j) = act(&c, &case, json!({ "action": "remove_content", "reason": "Infringes" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.statement_required")));
    let (s, r) = act(&c, &case, json!({ "action": "remove_content", "reason": "Infringes", "statement": "Your post copies a protected photo." })).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["notice"]["state"], "actioned");
    assert_eq!(r["notice"]["target_address"], "bob@t.local");
    assert!(r["notice"]["counter_deadline"].is_string());
    let (_, msgs) =
        node.get_auth(&format!("/api/v1/rooms/{}/channels/{}/messages", c.room_id, c.channel), &c.bob.token).await;
    assert!(!msgs.as_array().unwrap().iter().any(|m| m["id"] == c.message_id.as_str()), "removed");
    let (_, log) = node.get_auth("/api/v1/admin/audit-log?limit=50", &c.admin.token).await;
    assert!(
        log.as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "legal.remove_content" && e["target"] == c.message_id.as_str())
    );
    let mails = node.state.mailer.outbox.lock().unwrap().clone();
    assert!(mails.iter().any(|(to, s, _)| to == "rita@example.org" && s.contains("Content removed")));

    // The uploader sees the statement and may answer within the window.
    let (_, mine) = node.get_auth("/api/v1/users/me/legal-notices", &c.bob.token).await;
    let entry = &mine[0];
    assert_eq!(entry["case_id"], case.as_str());
    assert!(entry["statement"].as_str().unwrap().contains("protected photo"), "{entry}");
    assert!(entry["statement"].as_str().unwrap().contains("counter-notice"));
    assert_eq!(entry["can_counter"], true);
    assert!(entry.get("reporter_email").is_none());
    let counter = |name: &str| json!({ "name": name, "address": "Bob Street 2", "statement": "I took this photo myself.", "consent": true, "signature": "Bob" });
    let path = format!("/api/v1/users/me/legal-notices/{case}/counter-notice");
    let (s, _) = node.post(&path, &c.admin.token, counter("Admin")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "only the uploader");
    let mut incomplete = counter("Bob");
    incomplete["consent"] = json!(false);
    let (s, j) = node.post(&path, &c.bob.token, incomplete).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.counter_incomplete")));
    let (s, j) = node.post(&path, &c.bob.token, counter("Bob")).await;
    assert_eq!((s, j["state"].as_str()), (StatusCode::OK, Some("counter_notice")), "{j}");
    let (s, j) = node.post(&path, &c.bob.token, counter("Bob")).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("legal.counter_closed")));
    assert!(
        node.state
            .mailer
            .outbox
            .lock()
            .unwrap()
            .iter()
            .any(|(to, s, _)| to == "rita@example.org" && s.contains("Counter-notice"))
    );

    let decision = format!("/api/v1/admin/legal/notices/{case}/counter-notice/decision");
    let (s, n) = node
        .post(&decision, &c.admin.token, json!({ "decision": "uphold", "reason": "Metadata shows otherwise" }))
        .await;
    assert_eq!((s, n["state"].as_str()), (StatusCode::OK, Some("actioned")), "{n}");
    let (s, j) = node.post(&decision, &c.admin.token, json!({ "decision": "uphold", "reason": "again" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("legal.no_counter_notice")));
    let (_, d) = node.get_auth(&format!("/api/v1/admin/legal/notices/{case}"), &c.admin.token).await;
    let actions: Vec<&str> = d["events"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for a in ["received", "mail.reporter", "remove_content", "statement", "counter_notice", "counter_decision"] {
        assert!(actions.contains(&a), "{a} in {actions:?}");
    }
    assert_eq!(d["counter_notices"][0]["decision"], "uphold");

    // The JSON export carries the trail.
    let resp = node.get_with("/api/v1/admin/legal/notices/export", &c.admin.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["content-disposition"].to_str().unwrap().contains("attachment"));
    let all: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(all[0]["case_id"], case.as_str());
    assert!(all[0]["events"].as_array().unwrap().len() >= 6);
}

#[tokio::test]
async fn notice_mails_speak_the_reporters_and_the_uploaders_language() {
    use tower::ServiceExt;
    let node = notices_node().await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let (s, _) = node.patch("/api/v1/users/me", &bob.token, json!({ "locale": "de" })).await;
    assert_eq!(s, StatusCode::OK);
    let room = node.plaintext_room(&bob.token, "Fotos").await;
    let (room_id, channel) = (room["id"].as_str().unwrap().to_string(), TestNode::text_channel(&room));
    let (_, m) = node.send(&bob.token, &room_id, &channel, "geklautes Foto").await;
    let link = format!("https://t.local/rooms/{room_id}/channels/{channel}?message={}", m["id"].as_str().unwrap());
    // The reporter has no account: the notice's Accept-Language decides.
    let req = axum::http::Request::post(NOTICES)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::ACCEPT_LANGUAGE, "de-AT,de;q=0.9")
        .body(axum::body::Body::from(notice(&link).to_string()))
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let case = created["case_id"].as_str().unwrap().to_string();
    let (_, subject, body) = node.state.mailer.outbox.lock().unwrap().last().unwrap().clone();
    assert_eq!(subject, format!("Test node t.local: Meldung erhalten ({case})"));
    assert!(body.contains("Wir haben Ihre Meldung erhalten") && body.contains("/legal/notice/"), "{body}");

    let (s, r) = node
        .post(
            &format!("/api/v1/admin/legal/notices/{case}/actions"),
            &admin.token,
            json!({ "action": "remove_content", "reason": "Verletzt Urheberrecht", "statement": "Das Foto ist geschützt." }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let mails = node.state.mailer.outbox.lock().unwrap().clone();
    assert!(mails.iter().any(|(to, s, _)| to == "rita@example.org" && s.ends_with(&format!("Inhalte entfernt ({case})"))));
    // The statement of reasons is stored (and mailed) in the uploader's language.
    let (_, mine) = node.get_auth("/api/v1/users/me/legal-notices", &bob.token).await;
    let statement = mine[0]["statement"].as_str().unwrap();
    assert!(statement.starts_with("Entscheidung: Inhalte entfernt") && statement.contains("Das Foto ist geschützt."), "{statement}");
    assert!(statement.contains("Gegendarstellung"), "{statement}");
}

#[tokio::test]
async fn reject_disable_set_state_repeat_counter_window_and_retention() {
    let (c, case) = reported().await;
    let node = &c.node;
    // Reject needs a reason, which goes to the reporter.
    let (s, j) = act(&c, &case, json!({ "action": "reject" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.reason_required")));
    let (s, r) = act(&c, &case, json!({ "action": "reject", "reason": "Quotation is allowed" })).await;
    assert_eq!((s, r["notice"]["state"].as_str()), (StatusCode::OK, Some("rejected")));
    assert!(node.state.mailer.outbox.lock().unwrap().iter().any(|(_, _, b)| b.contains("Quotation is allowed")));
    let (s, j) = act(&c, &case, json!({ "action": "set_state", "state": "nonsense" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.enum")));
    let (s, r) = act(&c, &case, json!({ "action": "set_state", "state": "in_review", "reason": "reopened" })).await;
    assert_eq!((s, r["notice"]["state"].as_str()), (StatusCode::OK, Some("in_review")));
    let (s, j) = act(&c, &case, json!({ "action": "launch_missiles" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.enum")));
    let (s, j) = act(&c, &tavrn_node::util::ulid(), json!({ "action": "reject", "reason": "x" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("legal.notice_not_found")));
    // Content of another node cannot be removed here.
    let (_, other) = submit(node, notice("https://other.example/rooms/01JAAAAAAAAAAAAAAAAAAAAAAA/channels/01JBBBBBBBBBBBBBBBBBBBBBBB?message=01JCCCCCCCCCCCCCCCCCCCCCCC")).await;
    let other = other["case_id"].as_str().unwrap();
    let (_, d) = node.get_auth(&format!("/api/v1/admin/legal/notices/{other}"), &c.admin.token).await;
    assert_eq!(
        (d["locations"][0]["node"].as_str(), d["locations"][0]["local"].as_bool()),
        (Some("other.example"), Some(false))
    );
    let (s, j) = act(&c, other, json!({ "action": "remove_content", "statement": "x" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("legal.nothing_removed")));

    // Repeat infringer: actioned cases against bob reach the threshold (3): a suggestion only.
    let mut last = String::new();
    for i in 0..3 {
        let (_, m) = node.send(&c.bob.token, &c.room_id, &c.channel, &format!("copy {i}")).await;
        let (_, n) = submit(node, notice(m["id"].as_str().unwrap())).await;
        last = n["case_id"].as_str().unwrap().to_string();
        let (s, r) = act(&c, &last, json!({ "action": "remove_content", "statement": "Copy." })).await;
        assert_eq!(s, StatusCode::OK, "{r}");
    }
    let (_, d) = node.get_auth(&format!("/api/v1/admin/legal/notices/{last}"), &c.admin.token).await;
    assert_eq!((d["repeat_count"].as_i64(), d["repeat_suggest_disable"].as_bool()), (Some(3), Some(true)), "{d}");
    let (s, _) = node.get_auth("/api/v1/rooms", &c.bob.token).await;
    assert_eq!(s, StatusCode::OK, "never automatic");

    // The counter-notice window closes.
    sqlx::query("UPDATE legal_notices SET counter_deadline = '2000-01-01T00:00:00Z' WHERE id = $1")
        .bind(&last)
        .execute(&node.state.db)
        .await
        .unwrap();
    let body = json!({ "name": "Bob", "address": "x", "statement": "It is mine, really.", "consent": true, "signature": "Bob" });
    let (s, j) = node.post(&format!("/api/v1/users/me/legal-notices/{last}/counter-notice"), &c.bob.token, body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("legal.counter_closed")));

    // Disabling the account (with a statement); the admin cannot disable itself.
    let (s, j) = act(
        &c,
        &last,
        json!({ "action": "disable_account", "statement": "Repeated infringements.", "user_id": c.admin.user_id }),
    )
    .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("admin.self")));
    let (s, r) = act(
        &c,
        &last,
        json!({ "action": "disable_account", "statement": "Repeated infringements.", "reason": "repeat" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (s, j) = node.get_auth("/api/v1/rooms", &c.bob.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.account_disabled")));

    // Retention: cases past `retain_until` are deleted by housekeeping.
    sqlx::query("UPDATE legal_notices SET retain_until = '2000-01-01T00:00:00Z' WHERE id = $1")
        .bind(&case)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (pruned, _, _) = tavrn_node::legal::housekeeping(&node.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(pruned, 1);
    let (s, _) = node.get_auth(&format!("/api/v1/admin/legal/notices/{case}"), &c.admin.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn encrypted_content_is_never_shown_but_can_be_named() {
    let node = notices_node().await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&bob.token, "Secret").await;
    let channel = TestNode::text_channel(&room);
    // An encrypted message row (ciphertext only), as an MLS client would store it.
    let id = tavrn_node::util::ulid();
    sqlx::query("INSERT INTO messages (id, conversation_id, author_id, device_id, encrypted, content, content_size, created_at) VALUES ($1, $2, $3, $4, 1, 'Y2lwaGVy', 6, $5)")
        .bind(&id)
        .bind(&channel)
        .bind(&bob.user_id)
        .bind(&bob.device_id)
        .bind(tavrn_node::util::now())
        .execute(&node.state.db)
        .await
        .unwrap();
    let (_, n) = submit(&node, notice(&id)).await;
    let case = n["case_id"].as_str().unwrap();
    let (_, d) = node.get_auth(&format!("/api/v1/admin/legal/notices/{case}"), &admin.token).await;
    assert_eq!(d["content"][0]["encrypted"], true, "{d}");
    assert!(d["content"][0]["text"].is_null());
    assert!(!d.to_string().contains("Y2lwaGVy"), "no ciphertext either");
    let (s, _) = node
        .post(
            &format!("/api/v1/admin/legal/notices/{case}/actions"),
            &admin.token,
            json!({ "action": "remove_content", "statement": "Reported." }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "removable all the same");
}

#[tokio::test]
async fn notices_about_federated_content_are_forwarded_to_its_node() {
    let on = |c: &mut tavrn_node::config::Config| c.legal_notices = tavrn_node::config::Switch::On;
    let (a, b) = two_nodes_with(on, |_| {}).await;
    let admin_a = a.register("admina").await;
    let admin_b = b.register("adminb").await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "B room").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (_, m) = b.send(&carol.token, room_id, &channel, "illegal stuff on b").await;
    let link =
        format!("http://a.test/n/b.test/rooms/{room_id}/channels/{channel}?message={}", m["id"].as_str().unwrap());
    let mut body = notice(&link);
    body["basis"] = json!("illegal");
    body["explanation"] = json!("Insult");
    let (s, n) = a.req(Method::POST, NOTICES, None, Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{n}");
    let case = n["case_id"].as_str().unwrap();
    let path = format!("/api/v1/admin/legal/notices/{case}/actions");
    let (s, j) = a.post(&path, &admin_a.token, json!({ "action": "forward", "node": "evil.test" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("legal.forward_node_invalid")));
    let (s, r) = a.post(&path, &admin_a.token, json!({ "action": "forward" })).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["done"], json!(["b.test"]));
    assert_eq!(r["notice"]["forwarded_to"], "b.test");
    assert_eq!(r["notice"]["state"], "in_review");
    a.deliver().await;

    let (_, list) = b.get_auth("/api/v1/admin/legal/notices", &admin_b.token).await;
    let opened = &list[0];
    assert_eq!((opened["origin"].as_str(), opened["origin_case"].as_str()), (Some("a.test"), Some(case)), "{list}");
    assert_eq!(opened["state"], "received");
    let (_, d) = b
        .get_auth(&format!("/api/v1/admin/legal/notices/{}", opened["case_id"].as_str().unwrap()), &admin_b.token)
        .await;
    assert_eq!(d["locations"][0]["local"], true, "{d}");
    assert_eq!(d["content"][0]["text"], "illegal stuff on b");
    // The receiving node opens its own case even with its form switched off; a replay is a no-op.
    let replay = json!({ "case_id": case });
    assert_eq!(tavrn_node::legal::notices::receive(&b.state, "a.test", &replay).await.unwrap(), "duplicate");
    let incomplete = json!({ "case_id": tavrn_node::util::ulid(), "basis": "copyright" });
    let err = tavrn_node::legal::notices::receive(&b.state, "a.test", &incomplete).await.unwrap_err();
    assert_eq!(err.code(), "federation.payload_invalid");
}
