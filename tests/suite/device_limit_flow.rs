// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Clients refuse a keys document with more than 100 devices: an account never gets a 101st device, and the keys
//! document of an account that had more lists at most 100.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{password, test_node, totp_code};
use serde_json::{Value, json};
use tavrn_node::store;

const DOMAIN: &str = "t.local";

#[tokio::test]
async fn an_account_never_gets_more_devices_than_a_keys_document_holds() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    for i in 1..100 {
        store::users::create_device(&node.state.db, &alice.user_id, &format!("old {i}"), "test").await.unwrap();
    }
    let pre = node.login_preauth("alice", &password("alice")).await;
    let preauth = pre["preauth_token"].as_str().unwrap();
    let mut answer = Value::Null;
    for step in [30, 0, 60] {
        let code = totp_code(&alice.totp_secret, common::now_secs() + step);
        let body = json!({ "preauth_token": preauth, "totp_code": code });
        let (s, j) = node.req(Method::POST, "/api/v1/auth/second-factor/verify", None, Some(body)).await;
        answer = json!({ "status": s.as_u16(), "body": j });
        if j["code"] != "auth.second_factor_invalid" {
            break;
        }
    }
    assert_eq!(answer["status"], 403, "{answer}");
    assert_eq!(answer["body"]["code"], "auth.device_limit", "{answer}");
    assert_eq!(answer["body"]["meta"]["max_devices"], 100, "{answer}");
    assert_eq!(store::users::device_count(&node.state.db, &alice.user_id).await.unwrap(), 100);

    // With one device removed, a new login succeeds again.
    let (s, j) = node.get_auth("/api/v1/users/me/devices", &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let old = j.as_array().unwrap().iter().find(|d| d["name"] == "old 1").unwrap()["id"].as_str().unwrap().to_string();
    assert!(store::users::delete_device(&node.state.db, &alice.user_id, &old).await.unwrap());
    node.login("alice").await;
}

#[tokio::test]
async fn a_keys_document_lists_at_most_100_devices() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    sqlx::query("UPDATE users SET identity_pubkey = 'identity' WHERE id = $1")
        .bind(&alice.user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    // An account that got its devices before the node capped them.
    for i in 0..105 {
        let d = store::users::create_device(&node.state.db, &alice.user_id, &format!("d{i}"), "test").await.unwrap();
        sqlx::query(
            "UPDATE devices SET public_key = $1, identity_signature = 'sig', attested_identity_key = 'identity',
             created_at = $2 WHERE id = $3",
        )
        .bind(format!("key{i}"))
        .bind(format!("2026-01-01T00:{:02}:{:02}.000Z", i / 60, i % 60))
        .bind(&d.id)
        .execute(&node.state.db)
        .await
        .unwrap();
    }
    let (s, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(s, StatusCode::OK, "{keys}");
    let devices = keys["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 100);
    assert_eq!(devices[0]["device_public_key"], "key5", "the newest 100, oldest first");
    assert_eq!(devices[99]["device_public_key"], "key104");
}
