// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Polls (protocol PROTOCOL.md §7g, permissions.md bit 39): plaintext polls checked by the node, the plaintext close
//! time (set on create, moved earlier only), vote records (one per member, the last device wins, checked against the
//! poll in plaintext conversations, ciphertext under the current epoch in encrypted ones), events, the close, the
//! permission bit and its fixup, limits, cascade on delete. Votes never count as unread.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use common::{
    Session, TestNode,
    e2ee::{DOMAIN, qualified},
    perms, test_node,
};
use serde_json::{Value, json};
use tavrn_node::{hub::Event, permissions as p, polls::poll_hash};
use tokio::sync::broadcast;

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

async fn next_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str, matches: impl Fn(&Value) -> bool) -> Value {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind && matches(&ev.data) {
            return ev.data.clone();
        }
    }
}

fn in_secs(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn poll() -> Value {
    json!({ "type": "poll", "kind": "choice", "question": "Lunch?", "options": [{ "id": "a", "label": "Pizza" }, { "id": "b", "label": "Salad" }, { "id": "c", "label": "Soup" }], "max_choices": 2, "results_visible": "always", "votes_visible": "public" })
}

fn vote(message_id: &str, poll: &Value, choices: &[&str]) -> Value {
    json!({ "type": "poll.vote", "choices": choices, "voted_at": in_secs(0), "ctx": { "poll": message_id, "poll_hash": poll_hash(poll).unwrap() } })
}

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

impl Setup {
    fn messages(&self) -> String {
        format!("/api/v1/conversations/{}/messages", self.channel)
    }

    fn vote_url(&self, message_id: &str) -> String {
        format!("{}/{message_id}/poll/vote", self.messages())
    }

    fn votes_url(&self, message_id: &str) -> String {
        format!("{}/{message_id}/poll/votes", self.messages())
    }

    async fn send_poll(&self, token: &str, closes_at: Option<String>) -> Value {
        let (s, m) =
            self.node.post(&self.messages(), token, json!({ "content": poll(), "poll_closes_at": closes_at })).await;
        assert_eq!(s, StatusCode::CREATED, "{m}");
        m
    }

    async fn join(&self, username: &str) -> Session {
        let s = self.node.register(username).await;
        let (_, invite) =
            self.node.post(&format!("/api/v1/rooms/{}/invites", self.room_id), &self.alice.token, json!({})).await;
        let (st, j) = self
            .node
            .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &s.token, json!({}))
            .await;
        assert_eq!(st, StatusCode::OK, "{j}");
        s
    }

    async fn give(&self, user_id: &str, name: &str, bits: &[u64]) {
        let (s, role) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/roles", self.room_id),
                &self.alice.token,
                json!({ "name": name, "permissions": perms(bits), "position": 1 }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{role}");
        let (s, j) = self
            .node
            .patch(
                &format!("/api/v1/rooms/{}/members/{user_id}", self.room_id),
                &self.alice.token,
                json!({ "roles": [role["id"]] }),
            )
            .await;
        assert!(s.is_success(), "{j}");
    }

    async fn unread(&self, token: &str) -> i64 {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), token).await;
        room["read_states"].as_array().unwrap().iter().find(|r| r["conversation_id"] == self.channel.as_str()).unwrap()
            ["unread_count"]
            .as_i64()
            .unwrap()
    }
}

async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let bob = node.register("bob").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    Setup { node, alice, bob, room_id, channel }
}

#[tokio::test]
async fn plaintext_polls_are_checked_and_votes_are_records_not_messages() {
    let t = setup().await;
    // The node announces the capability.
    let (_, node) = t.node.get_auth("/api/v1/node", &t.alice.token).await;
    assert!(node["capabilities"].as_array().unwrap().iter().any(|c| c == "polls.v1"), "{node}");

    // Shapes the node can see are checked; a vote is never a message.
    let mut broken = poll();
    broken["options"] = json!([{ "id": "a", "label": "Only" }]);
    let (s, j) = t.node.post(&t.messages(), &t.alice.token, json!({ "content": broken })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_invalid"), "{j}");
    let (s, j) = t.node.post(&t.messages(), &t.alice.token, json!({ "content": vote("x", &poll(), &["a"]) })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.type_reserved"), "{j}");
    let (s, j) =
        t.node.post(&t.messages(), &t.alice.token, json!({ "content": poll(), "poll_closes_at": in_secs(30) })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_closes_invalid"), "{j}");
    let (s, j) = t
        .node
        .post(&t.messages(), &t.alice.token, json!({ "content": poll(), "poll_closes_at": "2030-01-01T10:00:00" }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_closes_invalid"), "{j}");

    // A poll with a close time; the close time comes back in UTC.
    let closes = (chrono::Utc::now() + chrono::Duration::hours(2))
        .with_timezone(&chrono::FixedOffset::east_opt(3600).unwrap())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let m = t.send_poll(&t.alice.token, Some(closes.clone())).await;
    let mid = m["id"].as_str().unwrap().to_string();
    let stored = m["poll_closes_at"].as_str().unwrap();
    assert!(stored.ends_with('Z'), "{stored}");
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(stored).unwrap(),
        chrono::DateTime::parse_from_rfc3339(&closes).unwrap()
    );
    let (_, list) = t.node.get_auth(&t.messages(), &t.bob.token).await;
    assert_eq!(list[0]["poll_closes_at"], stored);
    let (_, text) = t.node.send(&t.alice.token, &t.room_id, &t.channel, "hello").await;
    assert_eq!(text["poll_closes_at"], Value::Null);
    let text_id = text["id"].as_str().unwrap().to_string();
    let unread = t.unread(&t.alice.token).await;
    let count = t.node.get_auth(&t.messages(), &t.alice.token).await.1.as_array().unwrap().len();

    // Bob votes: a record with his address and device, an event to the channel, no message, no unread.
    let mut rx = t.node.state.hub.subscribe();
    let (s, v) = t.node.put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["a"]) })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["user"].as_str(), v["message_id"].as_str()),
        (Some(format!("bob@{DOMAIN}").as_str()), Some(mid.as_str()))
    );
    assert_eq!(v["device_id"], t.bob.device_id.as_str());
    assert_eq!((v["epoch"].clone(), v["content"]["choices"].clone()), (Value::Null, json!(["a"])));
    let ev = next_event(&mut rx, "poll.vote", |d| d["message_id"] == mid.as_str()).await;
    assert_eq!((ev["conversation_id"].as_str(), ev["user"].as_str()), (Some(t.channel.as_str()), v["user"].as_str()));
    assert_eq!(t.unread(&t.alice.token).await, unread, "votes never count as unread");
    assert_eq!(t.node.get_auth(&t.messages(), &t.alice.token).await.1.as_array().unwrap().len(), count);
    // The account's data summary names the votes (LEGAL.md §3.1).
    let (_, data) = t.node.get_auth("/api/v1/users/me/data", &t.bob.token).await;
    let votes = data["categories"].as_array().unwrap().iter().find(|c| c["key"] == "poll_votes").cloned();
    assert_eq!(votes.map(|c| c["count"].clone()), Some(json!(1)), "{data}");

    // Changing the vote replaces the record (created_at stays), with an optional plaintext signature.
    let sig = tavrn_crypto::PlaintextSignature { nonce: [1; 16], signature: [2; 64] }.to_base64url();
    let (s, v2) = t
        .node
        .put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["b", "c"]), "signature": sig }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v2}");
    assert_eq!((v2["created_at"].clone(), v2["signature"].as_str()), (v["created_at"].clone(), Some(sig.as_str())));
    let (s, j) = t
        .node
        .put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["a"]), "signature": "abc" }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.signature_invalid"));
    let (_, alice_vote) =
        t.node.put(&t.vote_url(&mid), &t.alice.token, json!({ "content": vote(&mid, &poll(), &["c"]) })).await;
    let (s, votes) = t.node.get_auth(&t.votes_url(&mid), &t.bob.token).await;
    assert_eq!(s, StatusCode::OK, "{votes}");
    let items = votes["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "one record per member");
    assert_eq!((&items[0]["content"]["choices"], &items[1]), (&json!(["b", "c"]), &alice_vote));

    // Votes that do not fit the poll, and votes on messages that are no polls (by another member: refused attempts
    // count towards the rate limit too).
    let erin = t.join("erin").await;
    for (content, what) in [
        (vote(&mid, &poll(), &["a", "b", "c"]), "too many choices"),
        (vote(&mid, &poll(), &["z"]), "unknown option"),
        (vote(&text_id, &poll(), &["a"]), "ctx names another message"),
        (vote(&mid, &json!({ "type": "poll", "question": "other" }), &["a"]), "another poll's hash"),
        (json!({ "type": "text", "body": "a" }), "no vote"),
    ] {
        let (s, j) = t.node.put(&t.vote_url(&mid), &erin.token, json!({ "content": content })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "poll.vote_invalid"), "{what}: {j}");
    }
    let (s, j) =
        t.node.put(&t.vote_url(&text_id), &erin.token, json!({ "content": vote(&text_id, &poll(), &["a"]) })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "poll.not_a_poll"), "{j}");
    let (s, j) = t.node.put(&t.vote_url(&mid), &erin.token, json!({ "content": "Y2lwaGVy" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.encryption_mismatch"), "{j}");
    let mut big = vote(&mid, &poll(), &["a"]);
    big["padding"] = json!("x".repeat(4200));
    let (s, j) = t.node.put(&t.vote_url(&mid), &erin.token, json!({ "content": big })).await;
    assert_eq!((s, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, "poll.vote_too_large"), "{j}");
    let (s, j) = t
        .node
        .put(&t.vote_url("01J9ZK3G5M8Q2W4E6R8T0Y2V99"), &erin.token, json!({ "content": vote(&mid, &poll(), &["a"]) }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "message.not_found"), "{j}");

    // Polls cannot be edited, and no message becomes one by an edit.
    let (s, j) = t.node.patch(&format!("{}/{mid}", t.messages()), &t.alice.token, json!({ "content": poll() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_immutable"), "{j}");
    let (s, j) =
        t.node.patch(&format!("{}/{text_id}", t.messages()), &t.alice.token, json!({ "content": poll() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_immutable"), "{j}");
    let (s, j) = t.node.patch(&format!("{}/{text_id}", t.messages()), &t.alice.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.content_missing"), "{j}");

    // Retracting: an event, then nothing to retract.
    let mut rx = t.node.state.hub.subscribe();
    let (s, _) = t.node.delete(&t.vote_url(&mid), &t.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ev = next_event(&mut rx, "poll.vote.delete", |d| d["message_id"] == mid.as_str()).await;
    assert_eq!(
        (ev["user"].as_str(), ev["room_id"].as_str()),
        (Some(format!("alice@{DOMAIN}").as_str()), Some(t.room_id.as_str()))
    );
    let (s, j) = t.node.delete(&t.vote_url(&mid), &t.alice.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "poll.vote_not_found"));

    // Closing early: only earlier, only by the author (or manage_messages), never from null.
    let close = |at: String| json!({ "poll_closes_at": at });
    let url = format!("{}/{mid}", t.messages());
    let (s, j) = t.node.patch(&url, &t.alice.token, close(in_secs(5 * 3600))).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_closes_invalid"), "later: {j}");
    let (s, j) = t.node.patch(&url, &t.alice.token, close(in_secs(-600))).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_closes_invalid"), "past: {j}");
    let (s, j) = t.node.patch(&url, &t.bob.token, close(in_secs(0))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.not_author"), "{j}");
    let (s, j) = t.node.patch(&format!("{}/{text_id}", t.messages()), &t.alice.token, close(in_secs(0))).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.poll_closes_invalid"), "no close time: {j}");
    let mut rx = t.node.state.hub.subscribe();
    let (s, closed) = t.node.patch(&url, &t.alice.token, close(in_secs(-5))).await;
    assert_eq!(s, StatusCode::OK, "{closed}");
    assert_eq!(closed["edited_at"], Value::Null, "closing is no edit");
    let at = chrono::DateTime::parse_from_rfc3339(closed["poll_closes_at"].as_str().unwrap()).unwrap();
    assert!((chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds().abs() < 5, "stored as the node's now");
    let ev = next_event(&mut rx, "message.update", |d| d["id"] == mid.as_str()).await;
    assert_eq!(ev["poll_closes_at"], closed["poll_closes_at"]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (s, j) = t.node.put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["a"]) })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "poll.closed"), "{j}");
    let (s, j) = t.node.delete(&t.vote_url(&mid), &t.bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "poll.closed"), "{j}");
    let (s, j) = t.node.patch(&url, &t.alice.token, close(in_secs(0))).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "poll.closed"), "{j}");
    // The closed poll still lists its votes.
    assert_eq!(t.node.get_auth(&t.votes_url(&mid), &t.bob.token).await.1["items"].as_array().unwrap().len(), 1);

    // Votes go with their message.
    let (s, _) = t.node.delete(&url, &t.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM poll_votes WHERE message_id = $1")
        .bind(&mid)
        .fetch_one(&t.node.state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn create_polls_moderators_closing_timeouts_members_and_the_rate_limit() {
    let t = setup().await;
    let m = t.send_poll(&t.alice.token, Some(in_secs(3600))).await;
    let mid = m["id"].as_str().unwrap().to_string();
    let bobs = t.send_poll(&t.bob.token, Some(in_secs(3600))).await;

    // Without create_polls (a channel override): no plaintext polls, no close times; voting stays possible.
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", t.room_id),
            &t.alice.token,
            json!({ "target_type": "channel", "target_id": t.channel, "subject_type": "role", "subject_id": t.room_id_everyone().await, "allow": "0", "deny": perms(&[p::CREATE_POLLS]) }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = t.node.post(&t.messages(), &t.bob.token, json!({ "content": poll() })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.poll_forbidden"), "{j}");
    let (s, j) = t
        .node
        .post(
            &t.messages(),
            &t.bob.token,
            json!({ "content": { "type": "text", "body": "x" }, "poll_closes_at": in_secs(600) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.poll_forbidden"), "{j}");
    let (s, j) = t.node.post(&t.messages(), &t.bob.token, json!({ "content": { "type": "text", "body": "x" } })).await;
    assert_eq!(s, StatusCode::CREATED, "texts still work: {j}");
    let (s, j) = t.node.put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["a"]) })).await;
    assert_eq!(s, StatusCode::OK, "voting needs view_channel only: {j}");

    // A moderator (manage_messages) closes someone else's poll; the room's audit log names it.
    let carol = t.join("carol").await;
    t.give(&carol.user_id, "Mods", &[p::MANAGE_MESSAGES]).await;
    let (s, j) =
        t.node.patch(&format!("{}/{mid}", t.messages()), &carol.token, json!({ "poll_closes_at": in_secs(60) })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let audit: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'message.poll_close' AND target = $1")
            .bind(&mid)
            .fetch_one(&t.node.state.db)
            .await
            .unwrap();
    assert_eq!(audit, 1);

    // Members in timeout do not vote; non-members neither.
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/members/{}/timeout", t.room_id, t.bob.user_id),
            &t.alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = t.node.put(&t.vote_url(&mid), &t.bob.token, json!({ "content": vote(&mid, &poll(), &["b"]) })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.timed_out"), "{j}");
    let (s, j) = t
        .node
        .patch(
            &format!("{}/{}", t.messages(), bobs["id"].as_str().unwrap()),
            &t.bob.token,
            json!({ "poll_closes_at": in_secs(60) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.timed_out"), "closing is writing: {j}");
    let dave = t.node.register("dave").await;
    let (s, j) = t.node.put(&t.vote_url(&mid), &dave.token, json!({ "content": vote(&mid, &poll(), &["b"]) })).await;
    assert!(s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND, "{s} {j}");
    let (s, _) = t.node.get_auth(&t.votes_url(&mid), &dave.token).await;
    assert!(s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND, "{s}");

    // At most 10 vote changes per user and minute.
    let other = t.send_poll(&t.alice.token, None).await;
    let oid = other["id"].as_str().unwrap().to_string();
    for i in 0..10 {
        let choice = if i % 2 == 0 { "a" } else { "b" };
        let (s, j) =
            t.node.put(&t.vote_url(&oid), &carol.token, json!({ "content": vote(&oid, &poll(), &[choice]) })).await;
        assert_eq!(s, StatusCode::OK, "vote {i}: {j}");
    }
    let (s, _) = t.node.delete(&t.vote_url(&oid), &carol.token).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

impl Setup {
    async fn room_id_everyone(&self) -> String {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &self.alice.token).await;
        room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

#[tokio::test]
async fn encrypted_votes_are_ciphertext_under_the_current_epoch() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    node.add_user(&mut alice, &dm, "bob").await;
    node.accept_welcomes(&mut bob).await;
    let base = format!("/api/v1/conversations/{dm}/messages");
    let conv = qualified(&dm);
    let epoch = alice.client.current_epoch(&conv).unwrap();

    // The node cannot see the poll; it takes the close time (DM members hold create_polls).
    let content = alice.client.encrypt_content(&conv, &poll().to_string()).unwrap();
    let (s, m) = node
        .post(&base, alice.token(), json!({ "content": content, "epoch": epoch, "poll_closes_at": in_secs(3600) }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let mid = m["id"].as_str().unwrap().to_string();
    let url = format!("{base}/{mid}/poll/vote");

    let mut rx = node.state.hub.subscribe();
    let sealed = bob.client.encrypt_content(&conv, &vote(&mid, &poll(), &["a"]).to_string()).unwrap();
    let (s, v) = node.put(&url, bob.token(), json!({ "content": sealed, "epoch": epoch })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((v["content"].as_str(), v["epoch"].as_i64()), (Some(sealed.as_str()), Some(epoch as i64)));
    let ev = next_event(&mut rx, "poll.vote", |d| d["message_id"] == mid.as_str()).await;
    assert_eq!(ev["content"], v["content"]);
    let (_, votes) = node.get_auth(&format!("{base}/{mid}/poll/votes"), alice.token()).await;
    assert_eq!(votes["items"][0]["content"], json!(sealed));

    // §5.3 checks; plaintext and signatures are refused; the size limit.
    let (s, j) = node.put(&url, bob.token(), json!({ "content": vote(&mid, &poll(), &["a"]) })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.encryption_mismatch"), "{j}");
    let (s, j) = node.put(&url, bob.token(), json!({ "content": sealed, "epoch": epoch + 1 })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.epoch_mismatch"), "{j}");
    let (s, j) = node.put(&url, bob.token(), json!({ "content": "not base64url!", "epoch": epoch })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.ciphertext_invalid"), "{j}");
    let sig = tavrn_crypto::PlaintextSignature { nonce: [1; 16], signature: [2; 64] }.to_base64url();
    let (s, j) = node.put(&url, bob.token(), json!({ "content": sealed, "epoch": epoch, "signature": sig })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.signature_invalid"), "{j}");
    let big = bob
        .client
        .encrypt_content(&conv, &json!({ "type": "poll.vote", "pad": "x".repeat(4000) }).to_string())
        .unwrap();
    let (s, j) = node.put(&url, bob.token(), json!({ "content": big, "epoch": epoch })).await;
    assert_eq!((s, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, "poll.vote_too_large"), "{j}");

    // Non-members of the DM do not see it.
    let carol = node.register("carol").await;
    let (s, _) = node.get_auth(&format!("{base}/{mid}/poll/votes"), &carol.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_startup_fixup_grants_create_polls_to_everyone_who_could_write_once() {
    let t = setup().await;
    let everyone = t.room_id_everyone().await;
    let (s, writers) = t
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", t.room_id),
            &t.alice.token,
            json!({ "name": "Writers", "permissions": perms(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{writers}");
    let (s, readers) = t
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", t.room_id),
            &t.alice.token,
            json!({ "name": "Readers", "permissions": perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{readers}");
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", t.room_id),
            &t.alice.token,
            json!({ "target_type": "channel", "target_id": t.channel, "subject_type": "role", "subject_id": readers["id"], "allow": perms(&[p::SEND_MESSAGES]), "deny": "0" }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    // As on a node from before the bit: nobody holds it, the fixup has not run.
    sqlx::query("UPDATE roles SET permissions = permissions - $1 WHERE (permissions & $1) <> 0")
        .bind(p::CREATE_POLLS as i64)
        .execute(&t.node.state.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::CREATE_POLLS_MARKER)
        .execute(&t.node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&t.node.state.db).await.unwrap();
    assert!(report.create_polls_grants >= 3, "{report:?}");
    let role_bits = |id: String| {
        let db = t.node.state.db.clone();
        async move {
            let v: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap();
            v as u64
        }
    };
    assert!(p::has(role_bits(everyone).await, p::CREATE_POLLS), "@everyone could write");
    assert!(p::has(role_bits(writers["id"].as_str().unwrap().into()).await, p::CREATE_POLLS));
    assert!(!p::has(role_bits(readers["id"].as_str().unwrap().into()).await, p::CREATE_POLLS), "readers could not");
    let allow: i64 = sqlx::query_scalar("SELECT allow FROM permission_overrides WHERE subject_id = $1")
        .bind(readers["id"].as_str().unwrap())
        .fetch_one(&t.node.state.db)
        .await
        .unwrap();
    assert!(p::has(allow as u64, p::CREATE_POLLS), "the override that let them write");
    let report = tavrn_node::fixups::run(&t.node.state.db).await.unwrap();
    assert_eq!(report.create_polls_grants, 0, "runs once");
    // New rooms have it in @everyone's defaults.
    let room = t.node.plaintext_room(&t.bob.token, "Fresh").await;
    let fresh = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["permissions"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(p::has(fresh, p::CREATE_POLLS));
}
