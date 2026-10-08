// SPDX-License-Identifier: AGPL-3.0-only
//! Device signatures on plaintext messages (FEDERATION.md §10.3): the node checks place and format,
//! stores the signature with the covered fields unchanged and returns it; it never verifies it.
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_crypto::{Device, PlaintextFields, PlaintextSignature, sign_plaintext, verify_plaintext};

const DOMAIN: &str = "t.local";

async fn setup() -> (TestNode, Session, Session, String, String) {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    (node, alice, bob, room_id, channel_id)
}

/// The signed fields as a client rebuilds them from an envelope.
fn fields_of(envelope: &Value) -> PlaintextFields {
    let s = |v: &Value| v.as_str().map(str::to_string);
    PlaintextFields {
        conversation: format!("{DOMAIN}/{}", envelope["conversation_id"].as_str().unwrap()),
        author: envelope["author"].as_str().unwrap().into(),
        device_id: envelope["device_id"].as_str().unwrap().into(),
        reply_to: s(&envelope["reply_to_id"]),
        thread_id: s(&envelope["thread_id"]),
        mentions_everyone: envelope["mentions_everyone"].as_bool().unwrap(),
        mentions: envelope["mentions"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().into()).collect(),
        attachments: Vec::new(),
    }
}

#[tokio::test]
async fn signed_plaintext_roundtrip_through_the_node() {
    let (node, alice, bob, _room_id, channel_id) = setup().await;
    let device = Device::generate("alice@t.local", &alice.device_id).unwrap();
    let path = format!("/api/v1/conversations/{channel_id}/messages");
    let mut fields = PlaintextFields {
        conversation: format!("{DOMAIN}/{channel_id}"),
        author: "alice@t.local".into(),
        device_id: alice.device_id.clone(),
        reply_to: None,
        thread_id: None,
        mentions_everyone: false,
        mentions: vec!["bob@t.local".into()],
        attachments: Vec::new(),
    };
    // Key order and number formats differ from the node's serialization: JCS makes them irrelevant.
    let content: Value =
        serde_json::from_str(r#"{"body":"Signiert @bob","type":"text","x":{"b":1.0,"a":"€"}}"#).unwrap();
    let sig = sign_plaintext(&device, &fields, &content).unwrap().to_base64url();
    let (s, m) = node
        .post(&path, &alice.token, json!({ "content": content, "mentions": ["bob@t.local"], "signature": sig }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["signature"], sig.as_str());

    // Bob reads the envelope and verifies it against Alice's device key.
    let (_, list) = node.get_auth(&path, &bob.token).await;
    let stored = &list[0];
    assert_eq!(stored["signature"], sig.as_str());
    verify_plaintext(&fields_of(stored), &stored["content"], &sig, &device.public_key()).unwrap();
    // A node that changed the content or a covered field would be caught.
    let mut forged = stored["content"].clone();
    forged["body"] = json!("Forged");
    assert!(verify_plaintext(&fields_of(stored), &forged, &sig, &device.public_key()).is_err());

    // Reply with a signature: reply_to is covered too.
    fields.reply_to = Some(stored["id"].as_str().unwrap().into());
    fields.mentions = Vec::new();
    let reply = json!({ "type": "text", "body": "Reply" });
    let sig2 = sign_plaintext(&device, &fields, &reply).unwrap().to_base64url();
    let (s, r) = node
        .post(&path, &alice.token, json!({ "content": reply, "reply_to_id": stored["id"], "signature": sig2 }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    verify_plaintext(&fields_of(&r), &r["content"], &sig2, &device.public_key()).unwrap();

    // Edits are signed anew; an edit without a signature clears the old one.
    let id = stored["id"].as_str().unwrap();
    fields.reply_to = None;
    let edited = json!({ "type": "text", "body": "Edited" });
    let sig3 = sign_plaintext(&device, &fields, &edited).unwrap().to_base64url();
    let (s, e) =
        node.patch(&format!("{path}/{id}"), &alice.token, json!({ "content": edited, "signature": sig3 })).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(e["signature"], sig3.as_str());
    verify_plaintext(&fields_of(&e), &e["content"], &sig3, &device.public_key()).unwrap();
    let (s, e) = node
        .patch(&format!("{path}/{id}"), &alice.token, json!({ "content": { "type": "text", "body": "without" } }))
        .await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(e["signature"], Value::Null);

    // Unsigned messages (old clients, bots) stay possible and carry null.
    let (s, u) = node.send(&bob.token, &_room_id, &channel_id, "unsigned").await;
    assert_eq!(s, StatusCode::CREATED, "{u}");
    assert_eq!(u["signature"], Value::Null);
}

#[tokio::test]
async fn malformed_and_misplaced_signatures_are_rejected() {
    let (node, alice, _bob, _room_id, channel_id) = setup().await;
    let path = format!("/api/v1/conversations/{channel_id}/messages");
    let good = PlaintextSignature { nonce: [1; 16], signature: [2; 64] }.to_base64url();
    let text = json!({ "type": "text", "body": "hi" });
    // Empty, too short, too long, standard base64 alphabet instead of base64url.
    let plus = format!("+{}", &good[1..]);
    for bad in [json!(""), json!("abc"), json!(&good[..100]), json!(format!("{good}AA")), json!(plus)] {
        let (s, j) = node.post(&path, &alice.token, json!({ "content": text, "signature": bad })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert_eq!(j["code"], "message.signature_invalid");
    }
    let (s, j) = node.post(&path, &alice.token, json!({ "content": text, "signature": 42 })).await;
    assert!(s.is_client_error(), "{j}");
    // Mentions of a signed message must arrive normalized (the node never rewrites signed fields).
    let (s, j) = node
        .post(&path, &alice.token, json!({ "content": text, "mentions": ["Bob@t.local"], "signature": good }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.mention_invalid");

    // Encrypted conversations: the signature lives inside the ciphertext, the field is refused.
    let room = node.create_room(&alice.token, "Encrypted").await;
    let encrypted = TestNode::text_channel(&room);
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{encrypted}/messages"),
            &alice.token,
            json!({ "content": "Y2lwaGVydGV4dA", "epoch": 0, "signature": good }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.signature_invalid");
}

/// A forum post's first message is signed (tavrn-protocol #3, tavrn-node #7): the client picks the thread id, so
/// the signature covers `thread_id` like every reply; the node keeps the id and checks it.
#[tokio::test]
async fn forum_posts_carry_a_client_chosen_id_and_a_signed_first_message() {
    let (node, alice, bob, room_id, _) = setup().await;
    // Clients send their own id only to nodes announcing it (older nodes would ignore it and the signature break).
    let (_, info) = node.get_auth("/api/v1/node", &alice.token).await;
    assert!(info["capabilities"].as_array().unwrap().contains(&json!("threads.client_ids")), "{info}");
    let (s, forum) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "help", "kind": "forum", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{forum}");
    let forum_id = forum["id"].as_str().unwrap().to_string();
    let threads = format!("/api/v1/rooms/{room_id}/channels/{forum_id}/threads");
    let device = Device::generate("alice@t.local", &alice.device_id).unwrap();
    let id = tavrn_node::util::ulid();
    let fields = PlaintextFields {
        conversation: format!("{DOMAIN}/{forum_id}"),
        author: "alice@t.local".into(),
        device_id: alice.device_id.clone(),
        reply_to: None,
        thread_id: Some(id.clone()),
        mentions_everyone: false,
        mentions: Vec::new(),
        attachments: Vec::new(),
    };
    let content = json!({ "type": "text", "body": "How do I set this up?" });
    let sig = sign_plaintext(&device, &fields, &content).unwrap().to_base64url();
    let post = |id: &str| json!({ "id": id, "title": "Setup", "message": { "content": content, "signature": sig } });

    // Malformed ids: not a ULID, not canonical (the signature covers the exact string), a time far off the node's.
    let far = ulid::Ulid::from_parts(0, 1).to_string();
    for bad in ["nope".to_string(), id.to_lowercase(), far] {
        let (s, j) = node.post(&threads, &alice.token, post(&bad)).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("thread.id_invalid")), "{bad}: {j}");
    }

    let (s, thread) = node.post(&threads, &alice.token, post(&id)).await;
    assert_eq!(s, StatusCode::CREATED, "{thread}");
    assert_eq!(thread["id"], id.as_str());
    let first = &thread["first_message"];
    assert_eq!((first["thread_id"].as_str(), first["signature"].as_str()), (Some(id.as_str()), Some(sig.as_str())));
    // Bob verifies the first message like any other.
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{forum_id}/messages?thread={id}"), &bob.token).await;
    let stored = &list[0];
    verify_plaintext(&fields_of(stored), &stored["content"], &sig, &device.public_key()).unwrap();

    // The id is taken now, also in another channel; without an id the node picks one as before.
    let (s, j) = node.post(&threads, &alice.token, post(&id)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("thread.id_taken")), "{j}");
    let (s, j) = node
        .post(
            &threads,
            &alice.token,
            json!({ "title": "Plain", "message": { "content": { "type": "text", "body": "x" } } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert!(tavrn_node::util::is_ulid(j["id"].as_str().unwrap()) && j["id"] != id.as_str());
}
