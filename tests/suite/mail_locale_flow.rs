// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Localized mails: the user's language (`locale` of `PATCH /users/me`, first set from `Accept-Language` at
//! registration) picks the template, English is the fallback, and operators override templates per language.
use crate::common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Registers `username` with an email address and `Accept-Language`; returns the session's access token.
async fn register(node: &TestNode, username: &str, accept_language: Option<&str>) -> String {
    let mut req = Request::post("/api/v1/auth/register").header(header::CONTENT_TYPE, "application/json");
    if let Some(l) = accept_language {
        req = req.header(header::ACCEPT_LANGUAGE, l);
    }
    let body = json!({ "username": username, "password": common::password(username), "email": format!("{username}@example.org"), "date_of_birth": common::ADULT_DATE_OF_BIRTH });
    let resp = node.router.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let (_, confirmed) = node.enroll_totp(j["preauth_token"].as_str().unwrap()).await;
    confirmed["session"]["access_token"].as_str().unwrap().to_string()
}

fn last_mail(node: &TestNode) -> (String, String, String) {
    node.state.mailer.outbox.lock().unwrap().last().unwrap().clone()
}

/// Confirms the address with the token of the last mail.
async fn verify(node: &TestNode) {
    let token = last_mail(node).2.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    let (s, _) = node.req(Method::POST, "/api/v1/auth/verify-email", None, Some(json!({ "token": token }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

async fn forgot(node: &TestNode, account: &str) -> (String, String, String) {
    // A pending reset link would be kept (no new mail): every call here starts without one.
    sqlx::query("DELETE FROM password_resets").execute(&node.state.db).await.unwrap();
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/forgot-password", None, Some(json!({ "account": account }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    last_mail(node)
}

#[tokio::test]
async fn the_registration_language_and_the_locale_setting_choose_the_mail_language() {
    let node = test_node("t.local").await;
    let carol = register(&node, "carol", Some("de-DE,de;q=0.9,en;q=0.8")).await;
    let (to, subject, body) = last_mail(&node);
    assert_eq!(
        (to.as_str(), subject.as_str()),
        ("carol@example.org", "Test node t.local: Bestätige deine E-Mail-Adresse")
    );
    assert!(body.starts_with("Hallo carol,") && body.contains("/verify-email?token="), "{body}");
    verify(&node).await;
    let (_, me) = node.get_auth("/api/v1/users/me", &carol).await;
    assert_eq!(me["locale"], "de-de", "{me}");
    assert!(forgot(&node, "carol").await.1.ends_with("Setze dein Passwort zurück"));

    // The client sends its language when it changes; English is the fallback for languages without texts.
    let (s, me) = node.patch("/api/v1/users/me", &carol, json!({ "locale": "en" })).await;
    assert_eq!((s, me["locale"].as_str()), (StatusCode::OK, Some("en")), "{me}");
    assert!(forgot(&node, "carol").await.1.ends_with("Reset your password"));
    let (_, me) = node.patch("/api/v1/users/me", &carol, json!({ "locale": "fr-CA" })).await;
    assert_eq!(me["locale"], "fr-ca");
    assert!(forgot(&node, "carol").await.1.ends_with("Reset your password"));
    for bad in ["klingon!", "x", "de-", &"a".repeat(40)] {
        let (s, j) = node.patch("/api/v1/users/me", &carol, json!({ "locale": bad })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.locale")), "{bad}: {j}");
    }
    let (_, me) = node.patch("/api/v1/users/me", &carol, json!({ "locale": "" })).await;
    assert!(me["locale"].is_null(), "an empty value clears it: {me}");

    // Without Accept-Language (or with one the node cannot use) nothing is stored: English.
    let dave = register(&node, "dave", Some("*")).await;
    assert!(last_mail(&node).1.ends_with("Confirm your email address"));
    let (_, me) = node.get_auth("/api/v1/users/me", &dave).await;
    assert!(me["locale"].is_null(), "{me}");
}

#[tokio::test]
async fn operators_override_templates_per_language() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("de")).unwrap();
    std::fs::write(
        dir.path().join("de/password_reset.txt"),
        "Subject: Passwort vergessen?\n\nServus {name}, hier entlang: {link}\nDein Team von {node}\n",
    )
    .unwrap();
    let path = dir.path().to_string_lossy().to_string();
    let node = test_node_with("t.local", move |c| c.mail_templates_dir = Some(path)).await;
    register(&node, "erik", Some("de")).await;
    verify(&node).await;
    let (_, subject, body) = forgot(&node, "erik").await;
    assert_eq!(subject, "Test node t.local: Passwort vergessen?");
    assert!(
        body.starts_with("Servus erik, hier entlang: http") && body.ends_with("Dein Team von Test node t.local"),
        "{body}"
    );
    // The other templates keep the built-in texts.
    register(&node, "fritz", Some("de")).await;
    assert!(last_mail(&node).1.ends_with("Bestätige deine E-Mail-Adresse"));
}

#[test]
fn check_config_validates_the_template_directory() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = common::dev_config("t.local", "/tmp", "sqlite::memory:");
    c.mail_templates_dir = Some(dir.path().join("missing").to_string_lossy().into());
    let err = c.validate().unwrap_err().to_string();
    assert!(err.contains("TAVRN_MAIL_TEMPLATES_DIR") && err.contains("not a directory"), "{err}");
    std::fs::create_dir_all(dir.path().join("en")).unwrap();
    std::fs::write(dir.path().join("en/verify_email.txt"), "Subject: Hi\n\n{token}\n").unwrap();
    c.mail_templates_dir = Some(dir.path().to_string_lossy().into());
    let err = c.validate().unwrap_err().to_string();
    assert!(err.contains("verify_email.txt") && err.contains("unknown variable {token}"), "{err}");
    std::fs::write(dir.path().join("en/verify_email.txt"), "Subject: Hi\n\n{link}\n").unwrap();
    assert!(c.validate().is_ok());
}

#[tokio::test]
async fn app_token_expiry_mails_reach_owners_with_a_confirmed_address_once_per_step() {
    use tavrn_node::applications::notify_expiring_tokens;
    let node = test_node("t.local").await;
    let gina = register(&node, "gina", Some("de")).await;
    verify(&node).await;
    // An address nobody confirmed gets no notices.
    let hans = register(&node, "hans", None).await;
    let mut apps = Vec::new();
    for (owner, name) in [(&gina, "Wetterbot"), (&hans, "Other")] {
        let (s, app) = node.post("/api/v1/applications", owner, json!({ "name": name })).await;
        assert_eq!(s, StatusCode::CREATED, "{app}");
        let id = app["id"].as_str().unwrap().to_string();
        let (s, t) = node.post(&format!("/api/v1/applications/{id}/tokens"), owner, json!({ "name": "main" })).await;
        assert_eq!(s, StatusCode::CREATED, "{t}");
        apps.push(id);
    }
    let mails = |node: &TestNode| node.state.mailer.outbox.lock().unwrap().clone();
    let before = mails(&node).len();
    let now = chrono::Utc::now();
    assert_eq!(notify_expiring_tokens(&node.state, now).await.unwrap(), 0);
    assert_eq!(mails(&node).len(), before, "nothing expires soon");

    let week = now + chrono::Duration::days(359);
    assert_eq!(notify_expiring_tokens(&node.state, week).await.unwrap(), 2);
    let sent = mails(&node);
    assert_eq!(sent.len(), before + 1, "only the confirmed address");
    let (to, subject, body) = sent.last().unwrap().clone();
    assert_eq!(
        (to.as_str(), subject.as_str()),
        ("gina@example.org", "Test node t.local: Ein App-Token läuft in 7 Tagen ab")
    );
    assert!(body.contains("Wetterbot") && body.contains("/settings/applications") && body.contains(" UTC"), "{body}");
    assert_eq!(notify_expiring_tokens(&node.state, week).await.unwrap(), 0);
    assert_eq!(mails(&node).len(), before + 1, "once per token and step");

    let day = now + chrono::Duration::days(364) + chrono::Duration::hours(12);
    assert_eq!(notify_expiring_tokens(&node.state, day).await.unwrap(), 2);
    let sent = mails(&node);
    assert_eq!(sent.len(), before + 2);
    assert!(sent.last().unwrap().1.ends_with("Ein App-Token läuft morgen ab"), "{:?}", sent.last());
    assert_eq!(notify_expiring_tokens(&node.state, day).await.unwrap(), 0);
    assert_eq!(mails(&node).len(), before + 2);
}
