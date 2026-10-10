// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Single sign-on via OpenID Connect (APPLICATIONS.md §8, mandatory test list of §11 step 6) against the
//! fake provider of `common::oidc`.

use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    TestNode,
    oidc::{FakeIdp, Login, Misbehavior, Outcome, configure, flow, pkce, until_callback},
    test_node_with,
};
use serde_json::{Value, json};
use tavrn_node::config::{Config, EmailMode, OidcGroupSync};

async fn sso_node(idp: &FakeIdp) -> TestNode {
    sso_node_with(idp, |_| {}).await
}

async fn sso_node_with(idp: &FakeIdp, tweak: impl FnOnce(&mut Config)) -> TestNode {
    let idp = idp.clone();
    test_node_with("sso.test", move |c| {
        configure(c, &idp);
        tweak(c);
    })
    .await
}

fn token(session: &Value) -> &str {
    session["access_token"].as_str().unwrap()
}

#[tokio::test]
async fn first_login_provisions_an_account_without_second_factor() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    // The login page learns about SSO from /node; the capability is announced.
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["sso"], json!({ "label": null, "only": false }));
    assert!(info["capabilities"].as_array().unwrap().contains(&json!("sso.oidc")));

    let mut login = Login::new("sub-alice", "Alice.Smith@corp.example");
    login.email = Some("alice@corp.example".into());
    login.email_verified = true;
    idp.set_login(login.clone());
    let session = flow(&node, "login", None).await.ok();
    assert_eq!(session["status"], "ok", "a full session, no second factor (§8.4): {session}");
    assert_eq!(session["user"]["username"], "alice.smith");
    assert_eq!(session["user"]["display_name"], "Alice.Smith@corp.example (IdP)");
    assert_eq!(session["user"]["email_verified"], true);
    assert_eq!(session["user"]["has_password"], false);
    assert_eq!(session["user"]["has_identity_key"], false, "the client sets up the recovery key next");
    assert!(idp.inner.lock().unwrap().last_basic_ok, "client_secret_basic with form-encoded credentials");
    let params = idp.inner.lock().unwrap().last_auth_params.clone();
    assert_eq!(params["scope"], "openid profile email groups");
    assert_eq!(params["redirect_uri"], "http://sso.test:8080/api/v1/auth/oidc/callback");

    let (s, me) = node.get_auth("/api/v1/users/me", token(&session)).await;
    assert_eq!(s, StatusCode::OK, "{me}");
    let (s, ident) = node.get_auth("/api/v1/auth/oidc/identity", token(&session)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ident["issuer"], idp.issuer.as_str());

    // The second login lands in the same account; the display name follows the provider.
    login.name = "Alice S.".into();
    idp.set_login(login);
    let again = flow(&node, "login", None).await.ok();
    assert_eq!(again["user"]["id"], session["user"]["id"]);
    assert_eq!(again["user"]["display_name"], "Alice S.");

    // Session cap (§8.6): the session ends after TAVRN_OIDC_SESSION_DAYS whatever the refreshes.
    let row: (String, String, i64) =
        sqlx::query_as("SELECT expires_at, max_expires_at, sso FROM sessions WHERE device_id = $1")
            .bind(again["device_id"].as_str().unwrap())
            .fetch_one(&node.state.db)
            .await
            .unwrap();
    let max = chrono::DateTime::parse_from_rfc3339(&row.1).unwrap();
    let days = (max.timestamp() - chrono::Utc::now().timestamp()) as f64 / 86400.0;
    assert!((6.9..=7.01).contains(&days), "{days}");
    assert_eq!(row.0, row.1, "refresh token expiry capped as well");
    assert_eq!(row.2, 1);
    let (s, refreshed) = node
        .req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": again["refresh_token"] })))
        .await;
    assert_eq!(s, StatusCode::OK, "{refreshed}");

    // SSO-only accounts have no password (§8.3).
    let (s, j) = node
        .post(
            "/api/v1/users/me/password",
            token(&again),
            json!({ "current_password": "x", "new_password": "new-password-123" }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("sso.password_unavailable")));
    let (s, j) = node.delete("/api/v1/auth/oidc/identity", token(&again)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("sso.last_login_method")));

    // Logout of an SSO session offers the provider's logout URL.
    let (s, out) = node.post("/api/v1/auth/logout", token(&again), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let url = reqwest::Url::parse(out["end_session_url"].as_str().unwrap()).unwrap();
    assert_eq!(url.path(), "/logout");
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q["client_id"], common::oidc::CLIENT_ID);
    assert_eq!(q["post_logout_redirect_uri"], "https://sso.test/login");

    // The audit log names the issuer, never a token.
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'sso.provision' AND meta LIKE $1")
        .bind(format!("%{}%", idp.issuer))
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn id_token_checks_refuse_every_tampering() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    idp.set_login(Login::new("sub-x", "xavier"));
    let cases = [
        Misbehavior { iss: Some("http://evil.example".into()), ..Default::default() },
        Misbehavior { aud: Some(json!("another-client")), ..Default::default() },
        Misbehavior { aud: Some(json!([common::oidc::CLIENT_ID, "other"])), ..Default::default() },
        Misbehavior { azp: Some("another-client".into()), ..Default::default() },
        Misbehavior { exp_offset: Some(-120), ..Default::default() },
        Misbehavior { nonce: Some("not-the-nonce".into()), ..Default::default() },
        Misbehavior { alg_none: true, ..Default::default() },
        Misbehavior { hs256: true, ..Default::default() },
        Misbehavior { groups_in_userinfo_only: true, userinfo_sub: Some("sub-other".into()), ..Default::default() },
    ];
    for m in cases {
        idp.misbehave(m.clone());
        assert_eq!(flow(&node, "login", None).await.callback_error(), "sso.token_invalid", "{m:?}");
    }
    // Provider errors arrive at the client as sso.idp_error with the (sanitized) OAuth error.
    idp.misbehave(Misbehavior { authorize_error: Some("access_denied".into()), ..Default::default() });
    match flow(&node, "login", None).await {
        Outcome::CallbackError(e, detail) => {
            assert_eq!((e.as_str(), detail.as_deref()), ("sso.idp_error", Some("access_denied")))
        }
        other => panic!("{other:?}"),
    }
    idp.misbehave(Misbehavior { token_error: Some("invalid_grant".into()), ..Default::default() });
    assert_eq!(flow(&node, "login", None).await.callback_error(), "sso.idp_error");
    // Nothing was provisioned by any of these attempts.
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = 'xavier'").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(n, 0);
    // A well-behaved provider works again.
    idp.misbehave(Misbehavior::default());
    flow(&node, "login", None).await.ok();
}

#[tokio::test]
async fn state_and_codes_are_single_use_and_bound_to_the_browser() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    idp.set_login(Login::new("sub-s", "sam"));
    let (verifier, challenge) = pkce();
    // Capture the provider's redirect to replay it.
    let body = json!({ "purpose": "login", "code_challenge": challenge, "client_state": common::oidc::CLIENT_STATE });
    let (_, start) = node.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(body)).await;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let resp = client.get(start["authorization_url"].as_str().unwrap()).send().await.unwrap();
    let location = reqwest::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    let callback = format!("/api/v1/auth/oidc/callback?{}", location.query().unwrap());
    let first = node.get(&callback).await;
    let target = reqwest::Url::parse(first.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(first.headers()["cache-control"], "no-store");
    let q: std::collections::HashMap<_, _> = target.query_pairs().into_owned().collect();
    assert_eq!(target.origin().ascii_serialization(), "https://sso.test", "always the node's own web origin");
    // Reused state.
    let second = node.get(&callback).await;
    let again = reqwest::Url::parse(second.headers()["location"].to_str().unwrap()).unwrap();
    assert!(again.query().unwrap().contains("error=sso.state_invalid"), "{again}");
    assert!(!again.query().unwrap().contains("state="), "an unknown state has no client state");
    // Unknown state.
    let unknown = node.get("/api/v1/auth/oidc/callback?code=x&state=forged").await;
    assert!(unknown.headers()["location"].to_str().unwrap().contains("error=sso.state_invalid"));
    // Wrong verifier spends the code.
    let (other_verifier, _) = pkce();
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/oidc/token",
            None,
            Some(json!({ "code": q["code"], "code_verifier": other_verifier })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("sso.code_invalid")));
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/oidc/token",
            None,
            Some(json!({ "code": q["code"], "code_verifier": verifier })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("sso.code_invalid")), "single use");

    // A code exchanged twice: only the first succeeds.
    let (verifier, challenge) = pkce();
    let q = until_callback(&node, "login", None, &challenge).await.unwrap();
    let body = json!({ "code": q["code"], "code_verifier": verifier });
    let (s, _) = node.req(Method::POST, "/api/v1/auth/oidc/token", None, Some(body.clone())).await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = node.req(Method::POST, "/api/v1/auth/oidc/token", None, Some(body)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("sso.code_invalid")));

    // Request validation of start.
    let bad = json!({ "purpose": "login", "code_challenge": "short", "client_state": common::oidc::CLIENT_STATE });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(bad)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.code_challenge")));
    let bad = json!({ "purpose": "login", "code_challenge": pkce().1, "client_state": "x" });
    let (s, _) = node.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // link and reauth need a session.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/oidc/start",
            None,
            Some(json!({ "purpose": "link", "code_challenge": pkce().1, "client_state": common::oidc::CLIENT_STATE })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.required")));
}

#[tokio::test]
async fn unknown_kid_triggers_one_jwks_refetch() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    idp.set_login(Login::new("sub-k", "kim"));
    flow(&node, "login", None).await.ok();
    let fetches = idp.jwks_fetches();
    // Key rotation at the provider: the cached JWKS lacks the new kid, one refetch finds it.
    idp.rotate_key("k2");
    flow(&node, "login", None).await.ok();
    assert_eq!(idp.jwks_fetches(), fetches + 1);
    flow(&node, "login", None).await.ok();
    assert_eq!(idp.jwks_fetches(), fetches + 1, "the refreshed set is cached");
    // A kid that never appears: one refetch, then refused.
    idp.sign_with_unpublished_key();
    assert_eq!(flow(&node, "login", None).await.callback_error(), "sso.token_invalid");
    assert_eq!(idp.jwks_fetches(), fetches + 2);
}

#[tokio::test]
async fn usernames_collide_safely_and_nothing_links_by_email() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| c.admin_users = "root".into()).await;
    let alice = node.register("alice").await;
    sqlx::query(
        "UPDATE users SET email = 'alice@corp.example', email_verified_at = '2026-01-01T00:00:00Z' WHERE id = $1",
    )
    .bind(&alice.user_id)
    .execute(&node.state.db)
    .await
    .unwrap();
    // Same username and the same verified email at the provider: still a new account.
    let mut login = Login::new("sub-mallory", "alice");
    login.email = Some("alice@corp.example".into());
    login.email_verified = true;
    idp.set_login(login);
    let s = flow(&node, "login", None).await.ok();
    assert_eq!(s["user"]["username"], "alice-2");
    assert_ne!(s["user"]["id"], alice.user_id.as_str());
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM external_identities WHERE user_id = $1")
        .bind(&alice.user_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "the password account was not linked");
    idp.set_login(Login::new("sub-alice-3", "alice"));
    assert_eq!(flow(&node, "login", None).await.ok()["user"]["username"], "alice-3");
    // The break-glass names of TAVRN_ADMIN_USERS are never handed to a provider account.
    idp.set_login(Login::new("sub-root", "root"));
    let r = flow(&node, "login", None).await.ok();
    assert_eq!(r["user"]["username"], "root-2");
    assert_eq!(r["user"]["is_node_admin"], false);
}

#[tokio::test]
async fn unverified_email_is_refused_when_the_node_requires_email() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| {
        c.email = EmailMode::Required;
        c.smtp_url = Some("smtp://127.0.0.1:1".into());
    })
    .await;
    let mut login = Login::new("sub-e", "erin");
    login.email = Some("erin@corp.example".into());
    idp.set_login(login.clone());
    assert_eq!(
        flow(&node, "login", None).await.exchange_error(),
        (StatusCode::FORBIDDEN, "sso.email_unverified".into())
    );
    login.email_verified = true;
    idp.set_login(login);
    let s = flow(&node, "login", None).await.ok();
    assert_eq!(s["user"]["email"], "erin@corp.example");
}

#[tokio::test]
async fn auto_provision_off_refuses_unknown_identities() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| c.oidc_auto_provision = false).await;
    idp.set_login(Login::new("sub-n", "nina"));
    assert_eq!(
        flow(&node, "login", None).await.exchange_error(),
        (StatusCode::FORBIDDEN, "sso.not_provisioned".into())
    );
}

#[tokio::test]
async fn linking_needs_a_signed_in_account_and_is_unique() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    idp.set_login(Login::new("sub-bob", "robert"));
    // The exchange of a link flow needs the session that started it.
    let (verifier, challenge) = pkce();
    let q = until_callback(&node, "link", Some(&bob.token), &challenge).await.unwrap();
    let body = json!({ "code": q["code"], "code_verifier": verifier });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/oidc/token", Some(&carol.token), Some(body)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("sso.session_mismatch")));
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM external_identities").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(n, 0);

    let linked = flow(&node, "link", Some(&bob.token)).await.ok();
    assert_eq!(linked, json!({ "linked": true }));
    let (_, ident) = node.get_auth("/api/v1/auth/oidc/identity", &bob.token).await;
    assert_eq!(ident["issuer"], idp.issuer.as_str());
    // Now the SSO login ends in bob's account, without his second factor.
    let s = flow(&node, "login", None).await.ok();
    assert_eq!(s["user"]["id"], bob.user_id.as_str());
    assert_eq!(s["user"]["has_password"], true);
    // A second link of bob: already linked; the same identity for carol: linked elsewhere.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/oidc/start",
            Some(&bob.token),
            Some(json!({ "purpose": "link", "code_challenge": pkce().1, "client_state": common::oidc::CLIENT_STATE })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("sso.already_linked")));
    assert_eq!(
        flow(&node, "link", Some(&carol.token)).await.exchange_error(),
        (StatusCode::CONFLICT, "sso.identity_linked".into())
    );
    // Unlinking works for an account with password and second factor.
    let (s, _) = node.delete("/api/v1/auth/oidc/identity", &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, ident) = node.get_auth("/api/v1/auth/oidc/identity", &bob.token).await;
    assert_eq!(ident, Value::Null);
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action IN ('sso.link', 'sso.unlink')")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn identity_reset_of_sso_accounts_is_confirmed_by_a_fresh_login() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    idp.set_login(Login::new("sub-r", "rita"));
    let session = flow(&node, "login", None).await.ok();
    let t = token(&session).to_string();
    let key = tavrn_crypto::MasterSecret::generate().unwrap().identity_public_key();
    let key = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key);
    // The login's own reauth token (PROTOCOL.md §5c) is not used here: the reset needs a fresh proof.
    node.forget_reauth(&t);
    let (s, j) = node.post("/api/v1/users/me/identity/reset", &t, json!({ "identity_public_key": key })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")));
    assert_eq!(j["meta"]["methods"], json!(["sso"]));
    let (s, j) = node
        .post("/api/v1/users/me/identity/reset", &t, json!({ "identity_public_key": key, "reauth_token": "x.y.z" }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")));
    let reauth = flow(&node, "reauth", Some(&t)).await.ok();
    assert_eq!(reauth["expires_in"], 300);
    assert_eq!(idp.inner.lock().unwrap().last_auth_params["prompt"], "login", "a fresh authentication");
    let rt = reauth["reauth_token"].as_str().unwrap();
    let body = json!({ "identity_public_key": key, "reauth_token": rt });
    let (s, j) = node.post("/api/v1/users/me/identity/reset", &t, body.clone()).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    // The reauth token stays valid for its five minutes, but only for this session.
    let other = flow(&node, "login", None).await.ok();
    node.forget_reauth(token(&other));
    let (s, _) = node.post("/api/v1/users/me/identity/reset", token(&other), body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "bound to the session that re-authenticated");
    // Another identity at the provider cannot confirm rita's reset.
    idp.set_login(Login::new("sub-other", "other"));
    assert_eq!(
        flow(&node, "reauth", Some(&t)).await.exchange_error(),
        (StatusCode::FORBIDDEN, "sso.identity_mismatch".into())
    );
    // Unlinked accounts cannot start a reauth.
    let pw = node.register("paula").await;
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/oidc/start",
            Some(&pw.token),
            Some(
                json!({ "purpose": "reauth", "code_challenge": pkce().1, "client_state": common::oidc::CLIENT_STATE }),
            ),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("sso.not_linked")));
}

#[tokio::test]
async fn oidc_only_disables_password_logins_except_break_glass() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| {
        c.oidc_only = true;
        c.admin_users = "root".into();
    })
    .await;
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["sso"]["only"], true);
    // Break-glass: the operators register and sign in with password and second factor as usual.
    let root = node.register("root").await;
    let back = node.login("root").await;
    assert_eq!(back.user_id, root.user_id);
    // Everybody else: no registration, no password login, no passkey-only login.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "newbie", "date_of_birth": "1990-01-01", "password": "password-new-1234" })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.password_login_disabled")));
    let hash = tavrn_node::auth::hash_password(&common::password("ulla")).unwrap();
    let ulla = tavrn_node::store::users::create_local(
        &node.state.db,
        tavrn_node::store::users::NewLocalUser {
            username: "ulla",
            domain: "sso.test",
            display_name: "Ulla",
            password_hash: &hash,
            email: None,
            is_node_admin: false,
            date_of_birth: Some(common::ADULT_DATE_OF_BIRTH),
        },
    )
    .await
    .unwrap();
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "ulla", "date_of_birth": "1990-01-01", "password": common::password("ulla") })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.password_login_disabled")));
    // Ulla signs in through the provider once her identity is linked (by an operator here).
    tavrn_node::store::oidc::link(&node.state.db, &ulla.id, &idp.issuer, "sub-ulla").await.unwrap();
    idp.set_login(Login::new("sub-ulla", "ulla"));
    assert_eq!(flow(&node, "login", None).await.ok()["user"]["id"], ulla.id.as_str());
    idp.set_login(Login::new("sub-o", "otto"));
    flow(&node, "login", None).await.ok();
}

#[tokio::test]
async fn provider_problems_never_stop_the_node() {
    // Nothing listens on port 9: SSO answers 502, everything else works.
    let node = test_node_with("sso.test", |c| {
        c.oidc_issuer = Some("http://127.0.0.1:9".into());
        c.oidc_client_id = Some("x".into());
    })
    .await;
    let body = json!({ "purpose": "login", "code_challenge": pkce().1, "client_state": common::oidc::CLIENT_STATE });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(body.clone())).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("sso.idp_unreachable")));
    node.register("still").await;
    // Issuer pinning: a discovery document of another issuer is refused.
    let idp = FakeIdp::start().await;
    idp.misbehave(Misbehavior { discovery_issuer: Some("http://evil.example".into()), ..Default::default() });
    let node = sso_node(&idp).await;
    let (s, j) = node.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(body.clone())).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("sso.idp_unreachable")));
    // Without an issuer every SSO route is 404 sso.disabled.
    let plain = common::test_node("plain.test").await;
    let (s, j) = plain.req(Method::POST, "/api/v1/auth/oidc/start", None, Some(body)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("sso.disabled")));
    let (_, info) = plain.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["sso"], Value::Null);
    let r = plain.get("/api/v1/auth/oidc/callback?state=x").await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// A room with a hoisted role owned by `owner`; returns (room id, role id).
async fn room_with_role(node: &TestNode, owner: &str, name: &str) -> (String, String) {
    let room = node.create_room(owner, name).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, role) =
        node.post(&format!("/api/v1/rooms/{room_id}/roles"), owner, json!({ "name": "Devs", "hoist": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    (room_id, role["id"].as_str().unwrap().to_string())
}

async fn put_map(node: &TestNode, admin: &str, map: Value) -> (StatusCode, Value) {
    node.put("/api/v1/admin/sso/group-map", admin, json!({ "map": map })).await
}

async fn member_roles(node: &TestNode, room: &str, user: &str) -> Option<Vec<String>> {
    tavrn_node::store::rooms::member(&node.state.db, room, user).await.unwrap()?;
    Some(tavrn_node::store::rooms::member_role_ids(&node.state.db, room, user).await.unwrap())
}

#[tokio::test]
async fn group_sync_grants_and_revokes_only_its_own_rights() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| {
        c.oidc_group_sync = OidcGroupSync::Sync;
        c.admin_users = "dana".into();
    })
    .await;
    let admin = node.register("admin").await;
    let (room, devs) = room_with_role(&node, &admin.token, "Engineering").await;
    let (s, manual) =
        node.post(&format!("/api/v1/rooms/{room}/roles"), &admin.token, json!({ "name": "Manual" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let manual = manual["id"].as_str().unwrap().to_string();
    let (other_room, _) = room_with_role(&node, &admin.token, "Manual room").await;

    // Admin API: non-admins are refused, invalid maps are refused.
    let peter = node.register("peter").await;
    let (s, _) = put_map(&node, &peter.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = put_map(&node, &admin.token, json!({ "devs": { "rooms": [{ "room": "nope" }] } })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("sso.group_map_invalid")));
    let (s, doc) = put_map(
        &node,
        &admin.token,
        json!({
            "devs": { "rooms": [{ "room": room, "roles": [devs] }] },
            "staff": { "room_creation": 3 },
            "it-admins": { "node_admin": true },
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{doc}");
    assert_eq!((doc["fixed"].as_bool(), doc["sync"].as_str()), (Some(false), Some("sync")));

    let mut login = Login::new("sub-d", "dave");
    login.groups = vec!["devs".into(), "staff".into(), "it-admins".into()];
    idp.set_login(login.clone());
    let first = flow(&node, "login", None).await.ok();
    let dave = first["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(first["user"]["is_node_admin"], true);
    assert_eq!(member_roles(&node, &room, &dave).await, Some(vec![devs.clone()]));
    assert_eq!(tavrn_node::store::users::room_creation_grant(&node.state.db, &dave).await.unwrap(), Some(3));
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE room_id = $1 AND action IN ('member.join', 'member.roles') AND actor_id IS NULL AND meta LIKE '%\"source\":\"sso\"%'")
        .bind(&room)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 2);

    // Rights granted by hand: a manual role in the same room and a membership in another room.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room}/members/{dave}"), &admin.token, json!({ "roles": [devs, manual] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    tavrn_node::store::rooms::add_member(&node.state.db, &other_room, &dave, true).await.unwrap();

    // The groups are gone: sync revokes exactly what it granted.
    login.groups = vec![];
    idp.set_login(login.clone());
    let second = flow(&node, "login", None).await.ok();
    assert_eq!(second["user"]["is_node_admin"], false);
    assert_eq!(member_roles(&node, &room, &dave).await, None, "the SSO membership ended");
    assert!(member_roles(&node, &other_room, &dave).await.is_some(), "the manual membership stays");
    assert_eq!(tavrn_node::store::users::room_creation_grant(&node.state.db, &dave).await.unwrap(), None);

    // Joined by hand, role by SSO: losing the group removes only the role.
    login.groups = vec!["devs".into()];
    idp.set_login(login.clone());
    flow(&node, "login", None).await.ok();
    sqlx::query("DELETE FROM sso_grants WHERE user_id = $1 AND kind = 'room'")
        .bind(&dave)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, _) = node
        .patch(&format!("/api/v1/rooms/{room}/members/{dave}"), &admin.token, json!({ "roles": [devs, manual] }))
        .await;
    assert_eq!(s, StatusCode::OK);
    login.groups = vec![];
    idp.set_login(login.clone());
    flow(&node, "login", None).await.ok();
    assert_eq!(member_roles(&node, &room, &dave).await, Some(vec![manual.clone()]));

    // TAVRN_ADMIN_USERS always wins: a sync never clears their flag. (dana is admin by configuration.)
    let dana = node.register("dana").await;
    assert!(tavrn_node::store::users::by_id(&node.state.db, &dana.user_id).await.unwrap().unwrap().is_node_admin());
    tavrn_node::store::oidc::link(&node.state.db, &dana.user_id, &idp.issuer, "sub-dana").await.unwrap();
    tavrn_node::store::oidc::record_grant(&node.state.db, &dana.user_id, "node_admin", "", "", "it-admins")
        .await
        .unwrap();
    idp.set_login(Login::new("sub-dana", "dana"));
    let d = flow(&node, "login", None).await.ok();
    assert_eq!(d["user"]["is_node_admin"], true);
}

#[tokio::test]
async fn add_mode_never_revokes_and_bans_win_over_the_map() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    let admin = node.register("admin").await;
    let (room, devs) = room_with_role(&node, &admin.token, "Team").await;
    let (s, _) =
        put_map(&node, &admin.token, json!({ "devs": { "rooms": [{ "room": room, "roles": [devs] }] } })).await;
    assert_eq!(s, StatusCode::OK);
    let mut login = Login::new("sub-f", "frank");
    login.groups = vec!["devs".into()];
    idp.set_login(login.clone());
    let frank = flow(&node, "login", None).await.ok()["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(member_roles(&node, &room, &frank).await, Some(vec![devs.clone()]));
    login.groups = vec![];
    idp.set_login(login);
    flow(&node, "login", None).await.ok();
    assert_eq!(member_roles(&node, &room, &frank).await, Some(vec![devs.clone()]), "add mode keeps everything");

    // A banned user is not added again by the map.
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{room}/bans"), &admin.token, json!({ "subject": "gina@sso.test" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let mut gina = Login::new("sub-g", "gina");
    gina.groups = vec!["devs".into()];
    idp.set_login(gina);
    let g = flow(&node, "login", None).await.ok()["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(member_roles(&node, &room, &g).await, None);

    // Groups from UserInfo when the ID token has none.
    let mut hans = Login::new("sub-h", "hans");
    hans.groups = vec!["devs".into()];
    idp.set_login(hans);
    idp.misbehave(Misbehavior { groups_in_userinfo_only: true, ..Default::default() });
    let h = flow(&node, "login", None).await.ok()["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(member_roles(&node, &room, &h).await, Some(vec![devs]));
}

#[tokio::test]
async fn a_fixed_group_map_cannot_be_changed_in_the_admin_api() {
    let idp = FakeIdp::start().await;
    let node = sso_node_with(&idp, |c| c.oidc_group_map = Some(r#"{ "staff": { "room_creation": 2 } }"#.into())).await;
    let admin = node.register("admin").await;
    let (s, doc) = node.get_auth("/api/v1/admin/sso/group-map", &admin.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(doc["fixed"], true);
    assert_eq!(doc["map"]["staff"]["room_creation"], 2);
    let (s, j) = put_map(&node, &admin.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("sso.group_map_fixed")));
}

/// Linking adds a login method that skips the second factor, and unlinking removes one: both need a fresh proof
/// (a reauth token), not just a session.
#[tokio::test]
async fn linking_and_unlinking_need_a_reauth_token() {
    let idp = FakeIdp::start().await;
    let node = sso_node(&idp).await;
    let bob = node.register("bob").await;
    let stolen = node.login("bob").await;
    node.forget_reauth(&stolen.token);
    idp.set_login(Login::new("sub-mallory", "mallory"));
    assert_eq!(
        flow(&node, "link", Some(&stolen.token)).await.exchange_error(),
        (StatusCode::FORBIDDEN, "auth.reauth_required".into()),
        "a bare access token links nothing"
    );
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM external_identities").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(n, 0);
    // With the reauth token of a fresh login it works, and unlinking needs one too.
    idp.set_login(Login::new("sub-bob", "robert"));
    assert_eq!(flow(&node, "link", Some(&bob.token)).await.ok(), json!({ "linked": true }));
    let (s, j) = node.delete("/api/v1/auth/oidc/identity", &stolen.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")), "{j}");
    let (s, j) = node.delete("/api/v1/auth/oidc/identity", &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
}
