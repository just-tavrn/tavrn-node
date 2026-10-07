// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Threads, forum and announcement channels (PROTOCOL.md §7e): permissions per channel kind, the thread routes,
//! paging and filters, follow and unread state, archive and lock, deletion with its cascade, forum tags,
//! threads in encrypted channels (ciphertext only), and app tokens.

use crate::common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    Session, TestNode, body_bytes,
    e2ee::{Dev, qualified},
    test_node,
};
use serde_json::{Value, json};
use tavrn_node::{hub::Event, permissions as p};
use tokio::sync::broadcast;
use tower::ServiceExt;

const D: &str = "t.local";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

fn text(body: &str) -> Value {
    json!({ "content": { "type": "text", "body": body } })
}

fn in_thread(body: &str, thread_id: &str) -> Value {
    json!({ "content": { "type": "text", "body": body }, "thread_id": thread_id })
}

/// A plaintext room of Alice's with Bob and Carol as members.
struct Room {
    node: TestNode,
    alice: Session,
    bob: Session,
    carol: Session,
    room_id: String,
    channel: String,
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn setup() -> Room {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    join(&node, &alice, &room_id, &bob).await;
    join(&node, &alice, &room_id, &carol).await;
    // Timestamps have millisecond resolution: keep "before" and "after the join" apart.
    tokio::time::sleep(Duration::from_millis(5)).await;
    Room { node, alice, bob, carol, room_id, channel }
}

impl Room {
    fn messages(&self, channel: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{channel}/messages", self.room_id)
    }
    fn threads(&self, channel: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{channel}/threads", self.room_id)
    }
    async fn send(&self, token: &str, channel: &str, body: Value) -> (StatusCode, Value) {
        self.node.post(&self.messages(channel), token, body).await
    }
    async fn send_ok(&self, token: &str, channel: &str, body: Value) -> Value {
        let (s, j) = self.send(token, channel, body).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        j
    }
    async fn create_thread(&self, token: &str, channel: &str, body: Value) -> (StatusCode, Value) {
        self.node.post(&self.threads(channel), token, body).await
    }
    async fn thread_ok(&self, token: &str, channel: &str, body: Value) -> Value {
        let (s, j) = self.create_thread(token, channel, body).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        j
    }
    async fn channel(&self, kind: &str, name: &str) -> String {
        let (s, j) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/channels", self.room_id),
                &self.alice.token,
                json!({ "kind": kind, "name": name, "encrypted": false }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        j["id"].as_str().unwrap().to_string()
    }
    async fn get_thread(&self, token: &str, id: &str) -> (StatusCode, Value) {
        self.node.get_auth(&format!("/api/v1/threads/{id}"), token).await
    }
    async fn list(&self, token: &str, channel: &str, query: &str) -> Value {
        let (s, j) = self.node.get_auth(&format!("{}?{query}", self.threads(channel)), token).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        j
    }
    /// A role with these permissions for `user_id`.
    async fn give_role(&self, user_id: &str, name: &str, perms: &[u64]) {
        let (s, role) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/roles", self.room_id),
                &self.alice.token,
                json!({ "name": name, "permissions": mask(perms) }),
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
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    /// Denies `bits` to `@everyone` in `channel`.
    async fn deny_everyone(&self, channel: &str, bits: &[u64]) {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &self.alice.token).await;
        let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": channel, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": mask(bits) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    async fn read_state(&self, token: &str, channel: &str) -> Value {
        let (s, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), token).await;
        assert_eq!(s, StatusCode::OK, "{room}");
        room["read_states"].as_array().unwrap().iter().find(|r| r["conversation_id"] == channel).unwrap().clone()
    }
}

async fn next_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str, matches: impl Fn(&Value) -> bool) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind && matches(&ev.data) {
            return ev.data.clone();
        }
    }
}

fn ids(list: &Value) -> Vec<String> {
    list["items"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap().to_string()).collect()
}

fn bodies(messages: &Value) -> Vec<String> {
    messages.as_array().unwrap().iter().map(|m| m["content"]["body"].as_str().unwrap_or("").to_string()).collect()
}

#[tokio::test]
async fn text_channel_thread_round_trip() {
    let r = setup().await;
    let mut rx = r.node.state.hub.subscribe();
    let root = r.send_ok(&r.alice.token, &r.channel, text("Release on Friday?")).await;
    let root_id = root["id"].as_str().unwrap();

    let thread = r
        .thread_ok(
            &r.bob.token,
            &r.channel,
            json!({ "title": "  Release plan ", "root_message_id": root_id, "message": text("Friday works") }),
        )
        .await;
    let thread_id = thread["id"].as_str().unwrap().to_string();
    assert_eq!(thread["title"], "Release plan", "{thread}");
    assert_eq!(thread["room_id"], r.room_id.as_str());
    assert_eq!(thread["channel_id"], r.channel.as_str());
    assert_eq!(thread["root_message_id"], root_id);
    assert_eq!(thread["root_deleted"], false);
    assert_eq!(thread["encrypted"], false);
    assert!(thread["title_epoch"].is_null());
    assert_eq!(thread["created_by"], format!("bob@{D}"));
    assert_eq!(thread["message_count"], 1);
    assert_eq!(thread["locked"], false);
    assert!(thread["archived_at"].is_null());
    assert_eq!(thread["me"]["following"], true);
    assert_eq!(thread["root_message"]["id"], root_id);
    assert_eq!(thread["participant_ids"], json!([r.bob.user_id]));
    let created = next_event(&mut rx, "thread.create", |d| d["thread"]["id"] == thread_id.as_str()).await;
    assert_eq!(created["room_id"], r.room_id.as_str());
    assert!(created["thread"].get("me").is_none_or(Value::is_null), "no per-user state in events: {created}");
    let first = next_event(&mut rx, "message.create", |d| d["thread_id"] == thread_id.as_str()).await;
    assert_eq!(first["content"]["body"], "Friday works");

    // Replies; the channel's list leaves thread messages out and shows the summary on the root.
    let reply = r.send_ok(&r.alice.token, &r.channel, in_thread("Then Friday", &thread_id)).await;
    assert_eq!(reply["thread_id"], thread_id.as_str());
    let update = next_event(&mut rx, "thread.update", |d| d["thread"]["id"] == thread_id.as_str()).await;
    assert_eq!(update["thread"]["message_count"], 2);
    assert_eq!(update["thread"]["last_message_id"], reply["id"]);
    r.send_ok(&r.carol.token, &r.channel, text("unrelated")).await;
    let (s, channel) = r.node.get_auth(&r.messages(&r.channel), &r.carol.token).await;
    assert_eq!(s, StatusCode::OK, "{channel}");
    assert_eq!(bodies(&channel), vec!["unrelated", "Release on Friday?"]);
    let listed_root = channel.as_array().unwrap().iter().find(|m| m["id"] == root_id).unwrap();
    assert_eq!(listed_root["thread"]["id"], thread_id.as_str(), "{listed_root}");
    assert_eq!(listed_root["thread"]["message_count"], 2);
    assert_eq!(listed_root["thread"]["participant_ids"], json!([r.alice.user_id, r.bob.user_id]));
    assert!(
        channel
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["content"]["body"] == "unrelated")
            .unwrap()
            .get("thread")
            .is_none()
    );
    let (s, page) = r.node.get_auth(&format!("{}?thread={thread_id}", r.messages(&r.channel)), &r.carol.token).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["Then Friday", "Friday works"]);
    let (s, page) = r
        .node
        .get_auth(
            &format!("{}?thread={thread_id}&around={}", r.messages(&r.channel), reply["id"].as_str().unwrap()),
            &r.carol.token,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["Then Friday", "Friday works"]);
    let (s, j) = r
        .node
        .get_auth(&format!("{}?thread={}", r.messages(&r.channel), tavrn_node::util::ulid()), &r.carol.token)
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "thread.not_found"));
    // `threads=all` (local search index sync): the channel with its threads.
    let (s, all) = r.node.get_auth(&format!("{}?threads=all", r.messages(&r.channel)), &r.carol.token).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_eq!(bodies(&all), vec!["unrelated", "Then Friday", "Friday works", "Release on Friday?"]);
    for bad in [format!("threads=some"), format!("threads=all&thread={thread_id}")] {
        let (s, j) = r.node.get_auth(&format!("{}?{bad}", r.messages(&r.channel)), &r.carol.token).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.filter_invalid"), "{bad}");
    }

    // One thread per root; thread messages are no roots; messages of other channels are no roots.
    let (s, j) =
        r.create_thread(&r.carol.token, &r.channel, json!({ "title": "again", "root_message_id": root_id })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "thread.exists"), "{j}");
    assert_eq!(j["meta"]["thread_id"], thread_id.as_str());
    let (s, j) =
        r.create_thread(&r.carol.token, &r.channel, json!({ "title": "nested", "root_message_id": reply["id"] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.root_invalid"));
    let other = r.channel("text", "other").await;
    let (s, j) = r.create_thread(&r.carol.token, &other, json!({ "title": "moved", "root_message_id": root_id })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.root_invalid"));
    // A thread id of another channel is unknown there.
    let (s, j) = r.send(&r.carol.token, &other, in_thread("wrong place", &thread_id)).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "thread.not_found"));
    // Titles: 1–100 characters.
    for title in [json!(""), json!("   "), json!("x".repeat(101)), json!(5)] {
        let (s, j) = r.create_thread(&r.carol.token, &r.channel, json!({ "title": title })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.title_invalid"), "{title}");
    }
    // Standalone threads need no root; text channels have no tags.
    let solo = r.thread_ok(&r.carol.token, &r.channel, json!({ "title": "Standalone" })).await;
    assert!(solo["root_message_id"].is_null());
    assert_eq!(solo["message_count"], 0);
    let (s, j) = r
        .create_thread(&r.carol.token, &r.channel, json!({ "title": "tagged", "tags": [tavrn_node::util::ulid()] }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.tags_invalid"));

    // GET by id; strangers and members without view_channel get 404/403.
    let (s, got) = r.get_thread(&r.carol.token, &thread_id).await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_eq!(got["message_count"], 2);
    assert_eq!(got["me"]["following"], false);
    let dave = r.node.register("dave").await;
    let (s, j) = r.get_thread(&dave.token, &thread_id).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"));
    let (s, j) = r.get_thread(&dave.token, &tavrn_node::util::ulid()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "thread.not_found"));
    r.deny_everyone(&r.channel, &[p::VIEW_CHANNEL]).await;
    let (s, j) = r.get_thread(&r.carol.token, &thread_id).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "thread.not_found"));

    // Edits keep the thread; slash-command style content (`action`) works in threads too.
    let me = r
        .send_ok(
            &r.alice.token,
            &r.channel,
            json!({ "content": { "type": "action", "body": "waves" }, "thread_id": thread_id }),
        )
        .await;
    assert_eq!(me["thread_id"], thread_id.as_str());
    let (s, edited) = r
        .node
        .patch(
            &format!("{}/{}", r.messages(&r.channel), me["id"].as_str().unwrap()),
            &r.alice.token,
            json!({ "content": { "type": "action", "body": "waves twice" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{edited}");
    assert_eq!(edited["thread_id"], thread_id.as_str());
}

#[tokio::test]
async fn permissions_per_channel_kind() {
    let r = setup().await;
    // Text channel without create_threads: no new threads, no replies; channel messages still work.
    let root = r.send_ok(&r.alice.token, &r.channel, text("root")).await;
    let thread = r.thread_ok(&r.alice.token, &r.channel, json!({ "title": "T", "root_message_id": root["id"] })).await;
    let thread_id = thread["id"].as_str().unwrap();
    r.deny_everyone(&r.channel, &[p::CREATE_THREADS]).await;
    let (s, j) = r.create_thread(&r.bob.token, &r.channel, json!({ "title": "no" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.create_forbidden"));
    let (s, j) = r.send(&r.bob.token, &r.channel, in_thread("no", thread_id)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.reply_forbidden"));
    r.send_ok(&r.bob.token, &r.channel, text("top level is fine")).await;
    // A read-only channel has no new threads either.
    let quiet = r.channel("text", "quiet").await;
    r.deny_everyone(&quiet, &[p::SEND_MESSAGES]).await;
    let (s, j) = r.create_thread(&r.bob.token, &quiet, json!({ "title": "no" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.send_forbidden"));

    // Forum: posts only; send_messages is enough, create_threads is not needed.
    let forum = r.channel("forum", "help").await;
    r.deny_everyone(&forum, &[p::CREATE_THREADS]).await;
    let (s, j) = r.send(&r.bob.token, &forum, text("loose")).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.thread_required"));
    let (s, j) = r.create_thread(&r.bob.token, &forum, json!({ "title": "Empty post" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.message_required"));
    let (s, j) = r
        .create_thread(
            &r.bob.token,
            &forum,
            json!({ "title": "Rooted", "root_message_id": root["id"], "message": text("x") }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.root_invalid"));
    let post =
        r.thread_ok(&r.bob.token, &forum, json!({ "title": "How do I…", "message": text("…set this up?") })).await;
    assert_eq!(post["message_count"], 1);
    assert_eq!(post["first_message"]["content"]["body"], "…set this up?");
    assert!(post["root_message"].is_null());
    r.send_ok(&r.carol.token, &forum, in_thread("Like this", post["id"].as_str().unwrap())).await;
    r.deny_everyone(&forum, &[p::SEND_MESSAGES]).await;
    let (s, j) = r.create_thread(&r.bob.token, &forum, json!({ "title": "Nope", "message": text("x") })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.send_forbidden"));

    // Announcement: only members with manage_messages post outside threads; everybody replies in threads.
    let news = r.channel("announcement", "news").await;
    let (s, j) = r.send(&r.bob.token, &news, text("me too")).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.announcement_forbidden"));
    let announcement = r.send_ok(&r.alice.token, &news, text("v1.0 is out")).await;
    let discussion = r
        .thread_ok(
            &r.bob.token,
            &news,
            json!({ "title": "v1.0", "root_message_id": announcement["id"], "message": text("Congrats") }),
        )
        .await;
    r.send_ok(&r.carol.token, &news, in_thread("Thanks", discussion["id"].as_str().unwrap())).await;
    r.give_role(&r.carol.user_id, "Herald", &[p::MANAGE_MESSAGES]).await;
    r.send_ok(&r.carol.token, &news, text("Carol announces")).await;
    let (s, j) = r
        .node
        .put(
            &format!(
                "/api/v1/rooms/{}/channels/{news}/messages/{}/reactions/%F0%9F%8E%89",
                r.room_id,
                announcement["id"].as_str().unwrap()
            ),
            &r.bob.token,
            json!({}),
        )
        .await;
    assert!(s.is_success(), "everybody reacts: {s} {j}");

    // Voice and files channels and the welcome channel have no threads; DMs have no threads either.
    let (_, room) = r.node.get_auth(&format!("/api/v1/rooms/{}", r.room_id), &r.alice.token).await;
    let voice = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = r.create_thread(&r.alice.token, &voice, json!({ "title": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.unsupported_channel"));
    let welcome = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = r.create_thread(&r.alice.token, &welcome, json!({ "title": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.unsupported_channel"));
}

#[tokio::test]
async fn listing_paging_filters_and_tags() {
    let r = setup().await;
    let forum = r.channel("forum", "ideas").await;
    let path = format!("/api/v1/rooms/{}/channels/{forum}", r.room_id);
    // Tags: at most 20, unique names, 1–32 characters; ids stay for kept entries.
    let (s, ch) = r
        .node
        .patch(&path, &r.alice.token, json!({ "tags": [{ "name": "Bug", "emoji": "🐛" }, { "name": "Feature" }, { "name": "Question", "emoji": ":pogchamp:" }] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{ch}");
    let tags = ch["tags"].as_array().unwrap().clone();
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0]["name"], "Bug");
    assert_eq!(tags[0]["emoji"], "🐛");
    assert!(tags[1]["emoji"].is_null());
    let (bug, feature, question) =
        (tags[0]["id"].as_str().unwrap(), tags[1]["id"].as_str().unwrap(), tags[2]["id"].as_str().unwrap());
    for bad in [
        json!([{ "name": "a" }, { "name": "A" }]),
        json!([{ "name": "" }]),
        json!([{ "name": "x".repeat(33) }]),
        json!([{ "name": "x", "emoji": "not an emoji at all" }]),
        json!((0..21).map(|i| json!({ "name": format!("t{i}") })).collect::<Vec<_>>()),
        json!([{ "id": tavrn_node::util::ulid(), "name": "unknown id" }]),
    ] {
        let (s, j) = r.node.patch(&path, &r.alice.token, json!({ "tags": bad })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "channel.tags_invalid"), "{bad}");
    }
    let (s, j) = r.node.patch(&path, &r.bob.token, json!({ "tags": [] })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "channel.manage_forbidden"));
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel),
            &r.alice.token,
            json!({ "tags": [{ "name": "x" }] }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "channel.tags_invalid"), "only forums have tags");

    // Posts with tags (at most 5, of this channel).
    let post = |title: &str, tags: Vec<&str>| json!({ "title": title, "tags": tags, "message": text(title) });
    let a = r.thread_ok(&r.bob.token, &forum, post("A", vec![bug])).await;
    tokio::time::sleep(Duration::from_millis(3)).await;
    let b = r.thread_ok(&r.bob.token, &forum, post("B", vec![feature, question])).await;
    tokio::time::sleep(Duration::from_millis(3)).await;
    let c = r.thread_ok(&r.carol.token, &forum, post("C", vec![bug])).await;
    assert_eq!(a["tags"], json!([bug]));
    let (s, j) = r.create_thread(&r.bob.token, &forum, post("bad", vec!["01J00000000000000000000000"])).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.tags_invalid"));
    let (s, j) = r
        .create_thread(
            &r.bob.token,
            &forum,
            json!({ "title": "x", "tags": [bug, bug, bug, bug, bug, bug], "message": text("x") }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.tags_invalid"));
    let (a, b, c) = (a["id"].as_str().unwrap(), b["id"].as_str().unwrap(), c["id"].as_str().unwrap());

    // Activity order: a reply moves A to the top; created order ignores it.
    tokio::time::sleep(Duration::from_millis(3)).await;
    r.send_ok(&r.carol.token, &forum, in_thread("bump", a)).await;
    assert_eq!(ids(&r.list(&r.carol.token, &forum, "").await), vec![a, c, b]);
    assert_eq!(ids(&r.list(&r.carol.token, &forum, "sort=created").await), vec![c, b, a]);
    assert_eq!(ids(&r.list(&r.carol.token, &forum, &format!("tag={bug}")).await), vec![a, c]);
    let listed = r.list(&r.carol.token, &forum, "").await;
    let first = &listed["items"][0];
    assert_eq!(first["first_message"]["content"]["body"], "A", "post cards carry the first message: {first}");
    assert_eq!(first["message_count"], 2);

    // Paging.
    let page1 = r.list(&r.carol.token, &forum, "limit=2").await;
    assert_eq!(ids(&page1), vec![a, c]);
    let next = page1["next"].as_str().unwrap();
    let page2 = r.list(&r.carol.token, &forum, &format!("limit=2&before={next}")).await;
    assert_eq!(ids(&page2), vec![b]);
    assert!(page2["next"].is_null());
    let page1 = r.list(&r.carol.token, &forum, "limit=2&sort=created").await;
    assert_eq!(ids(&page1), vec![c, b]);
    let page2 = r
        .list(&r.carol.token, &forum, &format!("limit=2&sort=created&before={}", page1["next"].as_str().unwrap()))
        .await;
    assert_eq!(ids(&page2), vec![a]);

    // Archived threads are left out by default.
    let (s, j) = r.node.patch(&format!("/api/v1/threads/{b}"), &r.bob.token, json!({ "archived": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["archived_at"].is_string());
    assert_eq!(ids(&r.list(&r.carol.token, &forum, "").await), vec![a, c]);
    assert_eq!(ids(&r.list(&r.carol.token, &forum, "archived=true").await), vec![b]);
    assert_eq!(ids(&r.list(&r.carol.token, &forum, "archived=all").await), vec![a, c, b]);
    for bad in ["archived=maybe", "sort=random", "tag=nope", "before=nope", "limit=500"] {
        let (s, j) = r.node.get_auth(&format!("{}?{bad}", r.threads(&forum)), &r.carol.token).await;
        if bad == "limit=500" {
            assert_eq!(s, StatusCode::OK, "limits are clamped: {j}");
        } else {
            assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        }
    }

    // Post tags: the creator edits them, others need manage_threads; removed channel tags disappear.
    let (s, j) = r.node.patch(&format!("/api/v1/threads/{a}"), &r.carol.token, json!({ "tags": [feature] })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.manage_forbidden"));
    let (s, j) = r.node.patch(&format!("/api/v1/threads/{a}"), &r.bob.token, json!({ "tags": [feature, bug] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["tags"], json!([feature, bug]));
    r.give_role(&r.carol.user_id, "Gardener", &[p::MANAGE_THREADS]).await;
    let (s, j) = r.node.patch(&format!("/api/v1/threads/{a}"), &r.carol.token, json!({ "tags": [bug] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _) = r.node.patch(&path, &r.alice.token, json!({ "tags": [{ "id": feature, "name": "Feature" }] })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, got) = r.get_thread(&r.carol.token, a).await;
    assert_eq!(got["tags"], json!([]), "the removed tag is dropped: {got}");
    let (_, got) = r.get_thread(&r.carol.token, b).await;
    assert_eq!(got["tags"], json!([feature]));
    let (_, audit) = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", r.room_id), &r.alice.token).await;
    let actions: Vec<&str> =
        audit["items"].as_array().or(audit.as_array()).unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
    assert!(actions.contains(&"channel.tags"), "{actions:?}");
    assert!(actions.contains(&"thread.update"), "{actions:?}");
}

#[tokio::test]
async fn follow_unread_and_read_markers() {
    let r = setup().await;
    let root = r.send_ok(&r.alice.token, &r.channel, text("root")).await;
    let thread = r.thread_ok(&r.alice.token, &r.channel, json!({ "title": "T", "root_message_id": root["id"] })).await;
    let thread_id = thread["id"].as_str().unwrap().to_string();
    // Bob follows by writing; Carol never follows.
    let bobs = r.send_ok(&r.bob.token, &r.channel, in_thread("hello", &thread_id)).await;
    for token in [&r.bob.token, &r.carol.token] {
        let last = r.read_state(token, &r.channel).await["last_message_id"].clone();
        let (s, j) = r
            .node
            .put(&format!("/api/v1/conversations/{}/read", r.channel), token, json!({ "last_read_message_id": last }))
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    tokio::time::sleep(Duration::from_millis(3)).await;
    let mut rx = r.node.state.hub.subscribe();
    let m1 = r.send_ok(&r.alice.token, &r.channel, in_thread("one", &thread_id)).await;
    r.send_ok(&r.alice.token, &r.channel, json!({ "content": { "type": "text", "body": "@bob two" }, "thread_id": thread_id, "mentions": [format!("bob@{D}")] })).await;

    let (_, t) = r.get_thread(&r.bob.token, &thread_id).await;
    assert_eq!(
        t["me"],
        json!({ "following": true, "last_read_message_id": bobs["id"], "unread_count": 2, "mention_count": 1 }),
        "{t}"
    );
    let bob_channel = r.read_state(&r.bob.token, &r.channel).await;
    assert_eq!(
        (bob_channel["unread_count"].as_i64(), bob_channel["mention_count"].as_i64()),
        (Some(2), Some(1)),
        "{bob_channel}"
    );
    let carol_channel = r.read_state(&r.carol.token, &r.channel).await;
    assert_eq!(carol_channel["unread_count"], 0, "thread messages count for followers only: {carol_channel}");
    assert_eq!(carol_channel["last_message_id"], root["id"], "the channel's newest message ignores threads");
    let (_, t) = r.get_thread(&r.carol.token, &thread_id).await;
    assert_eq!(t["me"]["unread_count"], 0);

    // The per-thread marker.
    let (s, state) = r
        .node
        .put(&format!("/api/v1/threads/{thread_id}/read"), &r.bob.token, json!({ "last_read_message_id": m1["id"] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{state}");
    assert_eq!(state["thread_id"], thread_id.as_str());
    assert_eq!(state["unread_count"], 1);
    assert_eq!(state["mention_count"], 1);
    let ev = next_event(&mut rx, "thread.read", |d| d["thread_id"] == thread_id.as_str()).await;
    assert_eq!(ev["last_read_message_id"], m1["id"]);
    // Never backwards; only messages of the thread.
    let (s, state) = r
        .node
        .put(&format!("/api/v1/threads/{thread_id}/read"), &r.bob.token, json!({ "last_read_message_id": bobs["id"] }))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(state["last_read_message_id"], m1["id"]);
    let (s, j) = r
        .node
        .put(&format!("/api/v1/threads/{thread_id}/read"), &r.bob.token, json!({ "last_read_message_id": root["id"] }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "message.not_found"));
    let (s, j) = r
        .node
        .put(&format!("/api/v1/threads/{thread_id}/read"), &r.bob.token, json!({ "last_read_message_id": "x" }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.id"));

    // Followed threads of the room.
    let (s, followed) = r.node.get_auth(&format!("/api/v1/rooms/{}/followed-threads", r.room_id), &r.bob.token).await;
    assert_eq!(s, StatusCode::OK, "{followed}");
    assert_eq!(followed["items"].as_array().unwrap().len(), 1);
    assert_eq!(followed["items"][0]["unread_count"], 1);
    let (_, followed) = r.node.get_auth(&format!("/api/v1/rooms/{}/followed-threads", r.room_id), &r.carol.token).await;
    assert_eq!(followed["items"], json!([]));

    // Unfollow: no counts; following again counts from then on.
    let (s, state) = r.node.delete(&format!("/api/v1/threads/{thread_id}/follow"), &r.bob.token).await;
    assert_eq!(s, StatusCode::OK, "{state}");
    assert_eq!((state["following"].as_bool(), state["unread_count"].as_i64()), (Some(false), Some(0)));
    assert_eq!(r.read_state(&r.bob.token, &r.channel).await["unread_count"], 0);
    let (s, state) = r.node.post(&format!("/api/v1/threads/{thread_id}/follow"), &r.carol.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{state}");
    assert_eq!(state["following"], true);
    assert_eq!(state["unread_count"], 0, "following starts with nothing unread");
    tokio::time::sleep(Duration::from_millis(3)).await;
    r.send_ok(&r.alice.token, &r.channel, in_thread("three", &thread_id)).await;
    assert_eq!(r.read_state(&r.carol.token, &r.channel).await["unread_count"], 1);
    // Muted channels count nothing, also in threads.
    let (s, j) = r
        .node
        .put(
            "/api/v1/users/me/notification-settings",
            &r.carol.token,
            json!({ "global": { "mode": "all" }, "channels": { r.channel.clone(): { "muted_until": "forever" } } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, t) = r.get_thread(&r.carol.token, &thread_id).await;
    assert_eq!(t["me"]["unread_count"], 0, "{t}");
}

#[tokio::test]
async fn archive_lock_and_auto_archive() {
    let r = setup().await;
    let thread = r.thread_ok(&r.bob.token, &r.channel, json!({ "title": "Bob's", "message": text("start") })).await;
    let id = thread["id"].as_str().unwrap().to_string();
    let path = format!("/api/v1/threads/{id}");
    // Others need manage_threads for every change.
    for body in [json!({ "title": "Carol's now" }), json!({ "archived": true }), json!({ "locked": true })] {
        let (s, j) = r.node.patch(&path, &r.carol.token, body).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.manage_forbidden"));
    }
    // The creator renames and archives; a new message reopens.
    let (s, j) = r.node.patch(&path, &r.bob.token, json!({ "title": "Renamed", "archived": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["title"], "Renamed");
    assert!(j["archived_at"].is_string());
    r.send_ok(&r.carol.token, &r.channel, in_thread("revive", &id)).await;
    let (_, j) = r.get_thread(&r.carol.token, &id).await;
    assert!(j["archived_at"].is_null(), "{j}");
    // A moderator locks: nobody without manage_threads writes, the creator included.
    r.give_role(&r.carol.user_id, "Moderator", &[p::MANAGE_THREADS]).await;
    let (s, j) = r.node.patch(&path, &r.carol.token, json!({ "locked": true, "archived": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["locked"], true);
    let (s, j) = r.send(&r.bob.token, &r.channel, in_thread("let me in", &id)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.locked"));
    r.send_ok(&r.carol.token, &r.channel, in_thread("mods may", &id)).await;
    let (_, j) = r.get_thread(&r.carol.token, &id).await;
    assert!(j["archived_at"].is_string(), "locked threads stay archived: {j}");

    // auto_archive_minutes: 60–43200, default 7 days.
    let channel_path = format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel);
    let (_, room) = r.node.get_auth(&format!("/api/v1/rooms/{}", r.room_id), &r.alice.token).await;
    let ch = room["channels"].as_array().unwrap().iter().find(|c| c["id"] == r.channel.as_str()).unwrap().clone();
    assert_eq!(ch["auto_archive_minutes"], 10080);
    for bad in [59, 43201] {
        let (s, j) = r.node.patch(&channel_path, &r.alice.token, json!({ "auto_archive_minutes": bad })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.range"));
    }
    let (s, j) = r.node.patch(&channel_path, &r.alice.token, json!({ "auto_archive_minutes": 60 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["auto_archive_minutes"], 60);

    // The housekeeping job archives threads idle for longer.
    let fresh = r.thread_ok(&r.bob.token, &r.channel, json!({ "title": "Fresh", "message": text("x") })).await;
    let idle = r.thread_ok(&r.bob.token, &r.channel, json!({ "title": "Idle", "message": text("x") })).await;
    sqlx::query("UPDATE threads SET last_message_at = $1 WHERE id = $2")
        .bind(tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::minutes(61)))
        .bind(idle["id"].as_str().unwrap())
        .execute(&r.node.state.db)
        .await
        .unwrap();
    let mut rx = r.node.state.hub.subscribe();
    let archived = tavrn_node::threads::auto_archive(&r.node.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(archived, 1);
    let ev = next_event(&mut rx, "thread.update", |d| d["thread"]["id"] == idle["id"]).await;
    assert!(ev["thread"]["archived_at"].is_string());
    let (_, j) = r.get_thread(&r.bob.token, fresh["id"].as_str().unwrap()).await;
    assert!(j["archived_at"].is_null());
}

async fn upload(r: &Room, token: &str, channel: &str, data: &[u8]) -> String {
    let req = Request::post(format!("/api/v1/rooms/{}/channels/{channel}/uploads", r.room_id))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "image/png")
        .header("tavrn-file-name", "a.png")
        .body(Body::from(data.to_vec()))
        .unwrap();
    let resp = r.node.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    j["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn deleting_threads_and_roots() {
    let r = setup().await;
    let root = r.send_ok(&r.alice.token, &r.channel, text("root")).await;
    let root_id = root["id"].as_str().unwrap().to_string();
    let thread = r.thread_ok(&r.bob.token, &r.channel, json!({ "title": "T", "root_message_id": root_id })).await;
    let id = thread["id"].as_str().unwrap().to_string();
    let blob = upload(&r, &r.carol.token, &r.channel, b"\x89PNGfake").await;
    let with_file = r
        .send_ok(
            &r.carol.token,
            &r.channel,
            json!({ "content": { "type": "text", "body": "file" }, "attachments": [blob], "thread_id": id }),
        )
        .await;
    r.send_ok(&r.bob.token, &r.channel, in_thread("mine", &id)).await;

    // Deleting a single thread message updates the counters.
    let own = r.send_ok(&r.bob.token, &r.channel, in_thread("oops", &id)).await;
    let (s, _) =
        r.node.delete(&format!("{}/{}", r.messages(&r.channel), own["id"].as_str().unwrap()), &r.bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, t) = r.get_thread(&r.bob.token, &id).await;
    assert_eq!(t["message_count"], 2, "{t}");

    // The creator may not delete Carol's messages with the thread; a moderator may.
    let (s, j) = r.node.delete(&format!("/api/v1/threads/{id}"), &r.bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "thread.delete_forbidden"));
    r.give_role(&r.carol.user_id, "Moderator", &[p::MANAGE_THREADS]).await;
    let mut rx = r.node.state.hub.subscribe();
    let (s, _) = r.node.delete(&format!("/api/v1/threads/{id}"), &r.carol.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ev = next_event(&mut rx, "thread.delete", |d| d["id"] == id.as_str()).await;
    assert_eq!(ev["channel_id"], r.channel.as_str());
    let (s, _) = r.get_thread(&r.alice.token, &id).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE thread_id = $1")
        .bind(&id)
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(gone, 0);
    assert!(r.node.state.storage.read(&blob).await.unwrap().is_none(), "the upload's file is deleted");
    let (s, _) = r
        .node
        .get_auth(&format!("{}/{}", r.messages(&r.channel), with_file["id"].as_str().unwrap()), &r.alice.token)
        .await;
    assert_ne!(s, StatusCode::OK);
    // The root stays, without a summary.
    let (_, channel) = r.node.get_auth(&r.messages(&r.channel), &r.alice.token).await;
    let listed = channel.as_array().unwrap().iter().find(|m| m["id"] == root_id.as_str()).unwrap();
    assert!(listed.get("thread").is_none_or(Value::is_null), "{listed}");
    let (_, audit) = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", r.room_id), &r.alice.token).await;
    let entry = audit["items"]
        .as_array()
        .or(audit.as_array())
        .unwrap()
        .iter()
        .find(|e| e["action"] == "thread.delete")
        .cloned()
        .unwrap();
    assert_eq!(entry["meta"]["deleted"], 2, "{entry}");

    // A creator deletes a thread holding only their own messages.
    let solo = r.thread_ok(&r.bob.token, &r.channel, json!({ "title": "Solo", "message": text("me") })).await;
    let (s, _) = r.node.delete(&format!("/api/v1/threads/{}", solo["id"].as_str().unwrap()), &r.bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Deleting the root keeps the thread.
    let root2 = r.send_ok(&r.alice.token, &r.channel, text("root 2")).await;
    let t2 = r
        .thread_ok(
            &r.carol.token,
            &r.channel,
            json!({ "title": "T2", "root_message_id": root2["id"], "message": text("reply") }),
        )
        .await;
    let (s, _) =
        r.node.delete(&format!("{}/{}", r.messages(&r.channel), root2["id"].as_str().unwrap()), &r.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, j) = r.get_thread(&r.carol.token, t2["id"].as_str().unwrap()).await;
    assert_eq!(j["root_deleted"], true, "{j}");
    assert!(j["root_message"].is_null());
    assert_eq!(j["message_count"], 1);

    // Purges recount the threads they touch.
    let t3 = r.thread_ok(&r.carol.token, &r.channel, json!({ "title": "T3", "message": text("c") })).await;
    r.send_ok(&r.bob.token, &r.channel, in_thread("b", t3["id"].as_str().unwrap())).await;
    tavrn_node::routes::messages::purge_with_blobs(
        &r.node.state,
        &tavrn_node::store::messages::PurgeFilter { author_id: Some(r.bob.user_id.clone()), ..Default::default() },
    )
    .await
    .unwrap();
    let (_, j) = r.get_thread(&r.carol.token, t3["id"].as_str().unwrap()).await;
    assert_eq!(j["message_count"], 1, "{j}");

    // Deleting the channel removes its threads.
    let other = r.channel("text", "doomed").await;
    let t4 = r.thread_ok(&r.alice.token, &other, json!({ "title": "x", "message": text("x") })).await;
    let (s, _) = r.node.delete(&format!("/api/v1/rooms/{}/channels/{other}", r.room_id), &r.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM threads WHERE id = $1")
        .bind(t4["id"].as_str().unwrap())
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Encrypted channels: the threads use the channel's MLS group, titles and messages are ciphertext.
#[tokio::test]
async fn encrypted_channel_threads_are_ciphertext() {
    let node = test_node(D).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let room = node.create_room(alice.token(), "Secret").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    assert_eq!(
        room["channels"].as_array().unwrap().iter().find(|c| c["id"] == channel.as_str()).unwrap()["encrypted"],
        true
    );
    join(&node, &alice.session, &room_id, &bob.session).await;
    node.create_group(&mut alice, &channel).await;
    node.add_user(&mut alice, &channel, "bob").await;
    node.accept_welcomes(&mut bob).await;
    let conv = qualified(&channel);
    let seal = |dev: &Dev, json: Value| {
        (dev.client.encrypt_content(&conv, &json.to_string()).unwrap(), dev.client.current_epoch(&conv).unwrap())
    };

    let (root_ct, epoch) = seal(&alice, json!({ "type": "text", "body": "the root" }));
    let (s, root) = node
        .post(
            &format!("/api/v1/conversations/{channel}/messages"),
            alice.token(),
            json!({ "content": root_ct, "epoch": epoch }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{root}");
    let threads = format!("/api/v1/rooms/{room_id}/channels/{channel}/threads");

    // Plaintext titles and messages are refused here.
    let (s, j) =
        node.post(&threads, bob.token(), json!({ "title": "visible title", "root_message_id": root["id"] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "thread.title_invalid"), "{j}");
    let (title_ct, title_epoch) = seal(&bob, json!({ "type": "thread.title", "body": "Secret plans" }));
    let (s, j) = node
        .post(
            &threads,
            bob.token(),
            json!({ "title": title_ct, "title_epoch": title_epoch + 5, "root_message_id": root["id"] }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.epoch_mismatch"), "{j}");
    let (msg_ct, msg_epoch) = seal(&bob, json!({ "type": "text", "body": "first secret reply" }));
    let (s, thread) = node
        .post(
            &threads,
            bob.token(),
            json!({ "title": title_ct, "title_epoch": title_epoch, "root_message_id": root["id"], "message": { "content": msg_ct, "epoch": msg_epoch } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{thread}");
    assert_eq!(thread["encrypted"], true);
    assert_eq!(thread["title_epoch"], title_epoch);
    assert_eq!(thread["title_author"], format!("bob@{D}"));
    assert_eq!(thread["title_device_id"], bob.session.device_id.as_str());
    let thread_id = thread["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/messages"),
            alice.token(),
            json!({ "content": { "type": "text", "body": "plain" }, "thread_id": thread_id }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.encryption_mismatch"));

    // Alice reads the title and the reply with the channel's group: no new group, no new keys.
    let opened = open(&alice, &conv, thread["title"].as_str().unwrap(), &format!("bob@{D}"), &bob.session.device_id);
    assert_eq!(opened["type"], "thread.title");
    assert_eq!(opened["body"], "Secret plans");
    let (s, page) =
        node.get_auth(&format!("/api/v1/conversations/{channel}/messages?thread={thread_id}"), alice.token()).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let first = &page[0];
    assert_eq!(first["encrypted"], true);
    assert_eq!(first["thread_id"], thread_id.as_str());
    let opened = open(&alice, &conv, first["content"].as_str().unwrap(), &format!("bob@{D}"), &bob.session.device_id);
    assert_eq!(opened["body"], "first secret reply");
    let groups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mls_groups").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(groups, 1, "threads use the channel's group");

    // A rename by Alice is her ciphertext under the current epoch.
    let (renamed_ct, renamed_epoch) = seal(&alice, json!({ "type": "thread.title", "body": "Renamed plans" }));
    node.post(&format!("/api/v1/rooms/{room_id}/roles"), alice.token(), json!({ "name": "x", "permissions": "0" }))
        .await;
    let (s, j) = node
        .patch(
            &format!("/api/v1/threads/{thread_id}"),
            alice.token(),
            json!({ "title": renamed_ct, "title_epoch": renamed_epoch }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "owners manage every thread: {j}");
    assert_eq!(j["title_author"], format!("alice@{D}"));

    // Nothing the node stores contains the plaintext.
    let titles: Vec<String> = sqlx::query_scalar("SELECT title FROM threads").fetch_all(&node.state.db).await.unwrap();
    let contents: Vec<String> =
        sqlx::query_scalar("SELECT content FROM messages").fetch_all(&node.state.db).await.unwrap();
    for stored in titles.iter().chain(&contents) {
        for secret in ["Secret plans", "Renamed plans", "first secret reply", "the root"] {
            assert!(!stored.contains(secret), "plaintext {secret:?} stored");
        }
    }
}

/// Decrypts content of `author`/`device` with the device's group state (test helper around the crypto core).
fn open(dev: &Dev, conv: &str, content: &str, author: &str, device: &str) -> Value {
    let plain = dev.client.decrypt_content(conv, author, device, content, None).expect("decrypts");
    serde_json::from_str(&plain).unwrap()
}

#[tokio::test]
async fn app_tokens_use_the_messages_scopes() {
    let r = setup().await;
    let thread =
        r.thread_ok(&r.alice.token, &r.channel, json!({ "title": "Bots welcome", "message": text("hi") })).await;
    let id = thread["id"].as_str().unwrap();
    let token = |scopes: Value, name: &'static str| {
        let r = &r;
        async move {
            let wanted = mask(&[p::SEND_MESSAGES, p::CREATE_THREADS, p::READ_HISTORY]);
            let (s, app) = r
                .node
                .post(
                    "/api/v1/applications",
                    &r.alice.token,
                    json!({ "name": name, "public": true, "requested_permissions": wanted }),
                )
                .await;
            assert_eq!(s, StatusCode::CREATED, "{app}");
            let app_id = app["id"].as_str().unwrap().to_string();
            let (s, t) = r
                .node
                .post(
                    &format!("/api/v1/applications/{app_id}/tokens"),
                    &r.alice.token,
                    json!({ "name": "main", "scopes": scopes }),
                )
                .await;
            assert_eq!(s, StatusCode::CREATED, "{t}");
            let (s, j) = r
                .node
                .post(&format!("/api/v1/rooms/{}/applications", r.room_id), &r.alice.token, json!({ "application": format!("{D}/{app_id}"), "permissions": mask(&[p::SEND_MESSAGES, p::CREATE_THREADS, p::READ_HISTORY]) }))
                .await;
            assert_eq!(s, StatusCode::CREATED, "{j}");
            t["secret"].as_str().unwrap().to_string()
        }
    };
    let reader = token(json!(["messages:read"]), "Reader").await;
    let writer = token(json!(["messages:read", "messages:write"]), "Writer").await;
    assert_eq!(ids(&r.list(&reader, &r.channel, "").await), vec![id]);
    let (s, _) = r.get_thread(&reader, id).await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = r.send(&reader, &r.channel, in_thread("no", id)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let (s, j) = r.create_thread(&reader, &r.channel, json!({ "title": "no" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let reply = r.send_ok(&writer, &r.channel, in_thread("Beep", id)).await;
    assert_eq!(reply["thread_id"], id);
    let own = r.thread_ok(&writer, &r.channel, json!({ "title": "Bot thread", "message": text("boop") })).await;
    let (s, j) = r
        .node
        .patch(&format!("/api/v1/threads/{}", own["id"].as_str().unwrap()), &writer, json!({ "archived": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.patch(&format!("/api/v1/threads/{id}"), &writer, json!({ "locked": true })).await;
    assert_eq!(
        (s, code(&j)),
        (StatusCode::FORBIDDEN, "thread.manage_forbidden"),
        "manage_threads needs the moderation scope"
    );
    let (s, _) = r
        .node
        .put(&format!("/api/v1/threads/{id}/read"), &writer, json!({ "last_read_message_id": reply["id"] }))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = r
        .node
        .put(&format!("/api/v1/threads/{id}/read"), &reader, json!({ "last_read_message_id": reply["id"] }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let (s, _) = r.node.get_auth(&format!("/api/v1/rooms/{}/followed-threads", r.room_id), &reader).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn manage_threads_is_restricted_and_granted_to_moderators_once() {
    let r = setup().await;
    // @everyone can never hold it.
    let (_, room) = r.node.get_auth(&format!("/api/v1/rooms/{}", r.room_id), &r.alice.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|x| x["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{everyone}", r.room_id),
            &r.alice.token,
            json!({ "permissions": mask(&[p::VIEW_CHANNEL, p::MANAGE_THREADS]) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "role.everyone_restricted"));
    // The startup fixup grants it to roles holding manage_messages, once.
    let (s, role) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", r.room_id),
            &r.alice.token,
            json!({ "name": "Mods", "permissions": mask(&[p::MANAGE_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::MANAGE_THREADS_MARKER)
        .execute(&r.node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&r.node.state.db).await.unwrap();
    assert!(report.manage_threads_roles >= 1, "{report:?}");
    let perms: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1")
        .bind(role["id"].as_str().unwrap())
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(perms as u64 & p::MANAGE_THREADS, p::MANAGE_THREADS);
    let report = tavrn_node::fixups::run(&r.node.state.db).await.unwrap();
    assert_eq!(report.manage_threads_roles, 0, "runs once");
}

/// Remote members get `notify` hints for thread messages as followers (every message) or when mentioned
/// directly; `@everyone` inside a thread reaches followers only.
#[tokio::test]
async fn notify_hints_for_remote_followers() {
    use common::federation::{A, two_nodes};
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let room = a.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    a.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "join_mode": "public" })).await;
    let bob = b.register("bob").await;
    let carol = b.register("carol").await;
    let bob_on_a = a.sign_in_from(&b, &bob).await;
    let carol_on_a = a.sign_in_from(&b, &carol).await;
    for s in [&bob_on_a, &carol_on_a] {
        let (st, j) = a.post(&format!("/api/v1/rooms/{room_id}/join"), &s.token, json!({})).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let threads = format!("/api/v1/rooms/{room_id}/channels/{channel}/threads");
    let messages = format!("/api/v1/rooms/{room_id}/channels/{channel}/messages");
    let (st, thread) = a.post(&threads, &bob_on_a.token, json!({ "title": "Bob's", "message": text("mine") })).await;
    assert_eq!(st, StatusCode::CREATED, "{thread}");
    let id = thread["id"].as_str().unwrap();
    a.deliver().await;
    let (st, j) = a
        .post(&messages, &alice.token, json!({ "content": { "type": "text", "body": "@everyone in a thread" }, "mentions_everyone": true, "thread_id": id }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(notified(&a).await, vec!["bob@b.test"], "followers only");
    let entry = a.outbox().await.into_iter().find(|e| e.kind == "notify").unwrap();
    let payload: Value = serde_json::from_str(&entry.body).unwrap();
    assert_eq!(payload["payload"]["conversation_id"], channel.as_str());
    assert_eq!(payload["payload"]["node"], A);
    assert!(!entry.body.contains("@everyone in a thread"), "hints carry no content");
    a.deliver().await;
    let (st, j) = a
        .post(
            &messages,
            &alice.token,
            json!({ "content": { "type": "text", "body": "carol?" }, "mentions": ["carol@b.test"], "thread_id": id }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(notified(&a).await, vec!["carol@b.test"], "direct mentions reach non-followers");
}

/// The recipients of the queued `notify` hints.
async fn notified(node: &common::federation::FedNode) -> Vec<String> {
    let mut to: Vec<String> = node
        .outbox()
        .await
        .into_iter()
        .filter(|e| e.kind == "notify")
        .map(|e| serde_json::from_str::<Value>(&e.body).unwrap()["to"].as_str().unwrap().to_string())
        .collect();
    to.sort();
    to
}
