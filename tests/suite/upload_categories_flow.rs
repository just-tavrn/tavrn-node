// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Upload categories (PROTOCOL.md §7a): classification by content and extension, the
//! executable rule, role settings (highest role wins), channel overrides, DMs and encrypted uploads.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, test_node_with};
use serde_json::{Value, json};

const DOMAIN: &str = "t.local";

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
    everyone: String,
}

async fn setup_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Setup {
    let node = test_node_with(DOMAIN, |c| {
        c.upload_allowed_types = "*/*".into();
        tweak(c);
    })
    .await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        room["roles"][0]["allowed_upload_categories"],
        json!(["images", "audio", "video", "documents", "archives", "other"]),
        "default: every category"
    );
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    Setup { node, alice, bob, room_id, channel, everyone }
}

async fn up(
    node: &TestNode,
    token: &str,
    conversation: &str,
    name: &str,
    mime: &str,
    data: &[u8],
) -> (StatusCode, Value) {
    let (s, _, body) = node
        .raw(
            Method::POST,
            &format!("/api/v1/conversations/{conversation}/uploads"),
            token,
            &[("content-type", mime), ("tavrn-file-name", name)],
            data.to_vec(),
        )
        .await;
    (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn forbidden(r: &(StatusCode, Value)) -> Option<(&str, bool)> {
    (r.0 == StatusCode::FORBIDDEN && r.1["code"] == "upload.type_forbidden")
        .then(|| (r.1["meta"]["category"].as_str().unwrap(), r.1["meta"]["executable"].as_bool().unwrap()))
}

#[tokio::test]
async fn executables_are_refused_unless_the_node_allows_them() {
    let s = setup_with(|_| {}).await;
    let png = b"\x89PNG\r\n\x1a\nrest";
    assert_eq!(up(&s.node, &s.bob.token, &s.channel, "a.png", "image/png", png).await.0, StatusCode::CREATED);
    for (name, data) in [
        ("setup.exe", &b"MZ\x90\x00"[..]),
        ("fake.png", b"MZ\x90\x00"),
        ("run.sh", b"#!/bin/sh"),
        ("app.jar", b"PK\x03\x04"),
    ] {
        let r = up(&s.node, &s.bob.token, &s.channel, name, "application/octet-stream", data).await;
        assert_eq!(forbidden(&r), Some(("other", true)), "{name}: {:?}", r.1);
    }
    // Even the owner cannot upload them on a default node.
    let r = up(&s.node, &s.alice.token, &s.channel, "tool.exe", "application/octet-stream", b"MZ").await;
    assert_eq!(forbidden(&r), Some(("other", true)));

    let s = setup_with(|c| c.upload_allow_executables = true).await;
    let r = up(&s.node, &s.bob.token, &s.channel, "tool.exe", "application/octet-stream", b"MZ").await;
    assert_eq!(r.0, StatusCode::CREATED, "allowed by the node and `other` allowed: {}", r.1);
    // … and still only with `other`.
    let path = format!("/api/v1/rooms/{}/roles/{}", s.room_id, s.everyone);
    let (st, j) =
        s.node.patch(&path, &s.alice.token, json!({ "allowed_upload_categories": ["images", "archives"] })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["allowed_upload_categories"], json!(["images", "archives"]));
    let r = up(&s.node, &s.bob.token, &s.channel, "tool.exe", "application/octet-stream", b"MZ").await;
    assert_eq!(forbidden(&r), Some(("other", true)));
}

#[tokio::test]
async fn roles_and_overrides_decide_the_categories() {
    let s = setup_with(|_| {}).await;
    let everyone = format!("/api/v1/rooms/{}/roles/{}", s.room_id, s.everyone);
    let (st, j) = s.node.patch(&everyone, &s.alice.token, json!({ "allowed_upload_categories": ["images"] })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.node.patch(&everyone, &s.alice.token, json!({ "allowed_upload_categories": null })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("role.upload_categories_invalid")), "{j}");
    let (st, j) = s.node.patch(&everyone, &s.alice.token, json!({ "allowed_upload_categories": ["pictures"] })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("role.upload_categories_invalid")), "{j}");

    let pdf = b"%PDF-1.7 ...";
    let r = up(&s.node, &s.bob.token, &s.channel, "rules.pdf", "application/pdf", pdf).await;
    assert_eq!(forbidden(&r), Some(("documents", false)), "{:?}", r.1);
    assert_eq!(r.1["meta"]["allowed_categories"], json!(["images"]));
    let (_, policy) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/upload-policy", s.channel), &s.bob.token).await;
    assert_eq!(policy["allowed_categories"], json!(["images"]));
    assert_eq!((policy["can_attach"].as_bool(), policy["executables_allowed"].as_bool()), (Some(true), Some(false)));

    // A role with documents (unset roles inherit; the highest role with a value wins).
    let (_, docs) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Docs", "position": 1, "allowed_upload_categories": ["images", "documents"] }),
        )
        .await;
    let (_, plain) = s
        .node
        .post(&format!("/api/v1/rooms/{}/roles", s.room_id), &s.alice.token, json!({ "name": "Plain", "position": 5 }))
        .await;
    assert_eq!(plain["allowed_upload_categories"], Value::Null);
    s.node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, s.bob.user_id),
            &s.alice.token,
            json!({ "roles": [docs["id"], plain["id"]] }),
        )
        .await;
    assert_eq!(up(&s.node, &s.bob.token, &s.channel, "rules.pdf", "application/pdf", pdf).await.0, StatusCode::CREATED);
    let (_, strict) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Strict", "position": 9, "allowed_upload_categories": ["audio"] }),
        )
        .await;
    s.node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, s.bob.user_id),
            &s.alice.token,
            json!({ "roles": [docs["id"], strict["id"]] }),
        )
        .await;
    let r = up(&s.node, &s.bob.token, &s.channel, "rules.pdf", "application/pdf", pdf).await;
    assert_eq!(forbidden(&r), Some(("documents", false)), "the highest role with a value wins");

    // Channel override on top: allow documents for @everyone here, deny audio for the member.
    let (st, o) = s
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            &s.alice.token,
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "role", "subject_id": s.everyone,
                    "allow": "0", "deny": "0", "upload_allow": ["documents"], "upload_deny": [] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{o}");
    assert_eq!(o[0]["upload_allow"], json!(["documents"]), "{o}");
    assert_eq!(up(&s.node, &s.bob.token, &s.channel, "rules.pdf", "application/pdf", pdf).await.0, StatusCode::CREATED);
    let (st, o) = s
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            &s.alice.token,
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "member", "subject_id": s.bob.user_id,
                    "allow": "0", "deny": "0", "upload_allow": ["video"], "upload_deny": ["video"] }),
        )
        .await;
    assert_eq!((st, o["code"].as_str()), (StatusCode::BAD_REQUEST, Some("override.conflict")), "{o}");
    // A permission-only override keeps the upload masks.
    let (st, o) = s
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            &s.alice.token,
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "role", "subject_id": s.everyone,
                    "allow": "0", "deny": "16" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{o}");
    assert_eq!(o[0]["upload_allow"], json!(["documents"]), "{o}");
    // The owner is never limited (executables aside).
    let r = up(&s.node, &s.alice.token, &s.channel, "x.zip", "application/zip", b"PK\x03\x04").await;
    assert_eq!(r.0, StatusCode::CREATED, "{}", r.1);
}

#[tokio::test]
async fn encrypted_uploads_declare_their_category_and_dms_use_the_node_default() {
    let node = test_node_with(DOMAIN, |c| c.upload_dm_categories = "images,video".into()).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Secret").await;
    let channel = TestNode::text_channel(&room);
    let room_id = room["id"].as_str().unwrap();
    let everyone = room["roles"][0]["id"].as_str().unwrap();
    node.patch(
        &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
        &alice.token,
        json!({ "allowed_upload_categories": ["images"] }),
    )
    .await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let cipher = vec![1u8; 64];
    let upload = |category: Option<&'static str>, conv: String, token: String| {
        let node = &node;
        let cipher = cipher.clone();
        async move {
            let mut headers = vec![("content-type", "application/octet-stream")];
            if let Some(c) = category {
                headers.push(("tavrn-upload-category", c));
            }
            let (s, _, body) = node
                .raw(Method::POST, &format!("/api/v1/conversations/{conv}/uploads"), &token, &headers, cipher)
                .await;
            (s, serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null))
        }
    };
    assert_eq!(upload(Some("images"), channel.clone(), bob.token.clone()).await.0, StatusCode::CREATED);
    let r = upload(Some("documents"), channel.clone(), bob.token.clone()).await;
    assert_eq!(forbidden(&r), Some(("documents", false)), "{:?}", r.1);
    let r = upload(None, channel.clone(), bob.token.clone()).await;
    assert_eq!(forbidden(&r), Some(("other", false)), "undeclared counts as other");
    let r = upload(Some("executable"), channel.clone(), alice.token.clone()).await;
    assert_eq!(forbidden(&r), Some(("other", true)));
    let r = upload(Some("bogus"), channel.clone(), bob.token.clone()).await;
    assert_eq!((r.0, r.1["code"].as_str()), (StatusCode::BAD_REQUEST, Some("upload.category_invalid")));

    // DMs use TAVRN_UPLOAD_DM_CATEGORIES.
    let (st, dm) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["bob@t.local"] })).await;
    assert!(st.is_success(), "{dm}");
    let dm_id = dm["id"].as_str().unwrap().to_string();
    let (_, policy) = node.get_auth(&format!("/api/v1/conversations/{dm_id}/upload-policy"), &alice.token).await;
    assert_eq!(policy["allowed_categories"], json!(["images", "video"]), "{policy}");
    assert_eq!(upload(Some("video"), dm_id.clone(), alice.token.clone()).await.0, StatusCode::CREATED);
    let r = upload(Some("archives"), dm_id.clone(), alice.token.clone()).await;
    assert_eq!(forbidden(&r), Some(("archives", false)));
}
