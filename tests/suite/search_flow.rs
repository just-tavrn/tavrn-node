// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Node-side message search (PROTOCOL.md §7d) on SQLite and PostgreSQL: what is
//! indexed (plaintext channels only), what is found (prefixes, folded diacritics, filters, paging), who finds
//! it (channel permissions, the `read_history` cut, bots and their scopes, remote users), the limits and that
//! nothing a user types reaches the query syntax. Also the `around` page mode of `GET …/messages`.

use crate::common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, federation::two_nodes, perms, test_node_with};
use serde_json::{Value, json};
use tavrn_node::permissions as p;
use tower::ServiceExt;

const D: &str = "t.local";

struct Room {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

async fn setup_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Room {
    let node = test_node_with(D, tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    Room { node, alice, bob, room_id, channel }
}

async fn setup() -> Room {
    setup_with(|_| {}).await
}

impl Room {
    async fn send(&self, token: &str, channel: &str, body: &str) -> String {
        let (s, m) = self.node.send(token, &self.room_id, channel, body).await;
        assert_eq!(s, StatusCode::CREATED, "{m}");
        m["id"].as_str().unwrap().to_string()
    }

    async fn search_as(&self, token: &str, query: &str) -> (StatusCode, Value) {
        self.node.get_auth(&format!("/api/v1/rooms/{}/search?{query}", self.room_id), token).await
    }

    /// Bodies of the results (alice's view), in result order.
    async fn bodies(&self, query: &str) -> Vec<String> {
        bodies_of(&self.search_as(&self.alice.token, query).await)
    }

    async fn channel(&self, name: &str, encrypted: bool) -> String {
        let (s, c) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/channels", self.room_id),
                &self.alice.token,
                json!({ "name": name, "kind": "text", "encrypted": encrypted }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{c}");
        c["id"].as_str().unwrap().to_string()
    }

    async fn indexed(&self, channel: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM message_search WHERE conversation_id = $1")
            .bind(channel)
            .fetch_one(&self.node.state.db)
            .await
            .unwrap()
    }
}

fn bodies_of((status, json): &(StatusCode, Value)) -> Vec<String> {
    assert_eq!(*status, StatusCode::OK, "{json}");
    json["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["message"]["content"]["body"].as_str().unwrap().to_string())
        .collect()
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

#[tokio::test]
async fn finds_prefixes_highlights_and_says_what_was_searched() {
    let r = setup().await;
    r.send(&r.alice.token, &r.channel, "Der Müller backt Brot").await;
    r.send(&r.bob.token, &r.channel, "Hello World, hello **everyone**").await;
    r.send(&r.alice.token, &r.channel, "nothing to see").await;

    let (s, j) = r.search_as(&r.bob.token, "q=hel").await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["searched"], json!({ "kind": "node", "channels": 1 }));
    let hits = j["results"].as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["message"]["author"], "bob@t.local");
    assert_eq!(hits[0]["snippet"], "\u{1}Hello\u{2} World, \u{1}hello\u{2} **everyone**");
    assert_eq!(j["next_cursor"], Value::Null);

    // All words are required, case does not matter, diacritics fold, digits and letters only.
    assert_eq!(r.bodies("q=HELLO+wor").await, vec!["Hello World, hello **everyone**"]);
    assert!(r.bodies("q=hello+brot").await.is_empty());
    assert_eq!(r.bodies(&format!("q={}", enc("müller"))).await, vec!["Der Müller backt Brot"]);
    assert_eq!(r.bodies("q=muller").await, vec!["Der Müller backt Brot"]);
    assert_eq!(r.bodies(&format!("q={}", enc("MÜLL"))).await, vec!["Der Müller backt Brot"]);
    // Relevance order is accepted and returns the same set here.
    assert_eq!(r.bodies("q=hello&sort=relevance").await.len(), 1);
}

#[tokio::test]
async fn query_syntax_and_injection_are_plain_words() {
    let r = setup().await;
    r.send(&r.alice.token, &r.channel, "foo bar near the OR gate: a*b (x)").await;
    for q in [
        "\"foo\"",
        "foo\"",
        "(foo",
        "foo)",
        "foo*",
        "foo OR bar",
        "foo NEAR bar",
        "NEAR(foo bar)",
        "foo:bar",
        "foo & bar",
        "foo | !bar",
        "foo <-> bar",
        "'foo'",
        "foo'; DROP TABLE messages; --",
        "foo\\",
        "foo:*",
        "{foo}",
        "^foo",
        "foo -bar",
        "\u{0}foo",
    ] {
        let (s, j) = r.search_as(&r.alice.token, &format!("q={}", enc(q))).await;
        assert_eq!(s, StatusCode::OK, "{q}: {j}");
        let n = j["results"].as_array().unwrap().len();
        assert!(n <= 1, "{q}: {j}");
    }
    // Operators are just words: `OR` must be in the text, `NEAR` too.
    assert_eq!(r.bodies(&format!("q={}", enc("foo OR near"))).await.len(), 1);
    assert!(r.bodies(&format!("q={}", enc("foo OR zebra"))).await.is_empty(), "OR is a required word, not an operator");
    // Only punctuation: no words, no filter.
    for q in ["'", "\"", "()", "*", ":", "--", "   "] {
        let (s, j) = r.search_as(&r.alice.token, &format!("q={}", enc(q))).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("search.query_empty")), "{q}");
    }
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages").fetch_one(&r.node.state.db).await.unwrap();
    assert!(messages >= 1, "the table is still there");
}

#[tokio::test]
async fn limits_and_validation() {
    let r = setup().await;
    let code = |j: &Value| j["code"].as_str().unwrap_or("").to_string();
    let (s, j) = r.search_as(&r.alice.token, &format!("q={}", "a".repeat(257))).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "search.query_too_long".into()));
    assert_eq!(r.search_as(&r.alice.token, &format!("q={}", "a".repeat(256))).await.0, StatusCode::OK);
    let (s, j) = r.search_as(&r.alice.token, "").await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "search.query_empty".into()));
    for (query, want) in [
        ("q=x&has=link", "search.has_invalid"),
        ("q=x&sort=random", "search.sort_invalid"),
        ("q=x&after=yesterday", "search.date_invalid"),
        ("q=x&before=2026-02-30", "search.date_invalid"),
        ("q=x&author=nobody", "search.author_invalid"),
        ("q=x&cursor=abc", "search.cursor_invalid"),
        ("q=x&sort=relevance&cursor=o9999", "search.cursor_invalid"),
        ("q=x&channel=..%2F..", "validation.id"),
    ] {
        let (s, j) = r.search_as(&r.alice.token, query).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, want.to_string()), "{query}");
    }
    // Unknown room, not a member, no token.
    let (s, _) =
        r.node.get_auth(&format!("/api/v1/rooms/{}/search?q=x", tavrn_node::util::ulid()), &r.alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let carol = r.node.register("carol").await;
    let (s, j) = r.search_as(&carol.token, "q=x").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member".into()));
    assert_eq!(
        r.node.get(&format!("/api/v1/api/v1/rooms/{}/search?q=x", r.room_id)).await.status(),
        StatusCode::NOT_FOUND
    );
    let resp = r.node.get(&format!("/api/v1/rooms/{}/search?q=x", r.room_id)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // An unknown author matches nothing (no error that would tell who exists).
    r.send(&r.alice.token, &r.channel, "hello").await;
    assert!(r.bodies("q=hello&author=ghost%40t.local").await.is_empty());
}

#[tokio::test]
async fn encrypted_channels_are_never_indexed_and_the_switch_drops_rows() {
    let r = setup().await;
    let secret = r.channel("secret", true).await;
    // The encrypted channel takes no plaintext; the plaintext channel is indexed.
    r.send(&r.alice.token, &r.channel, "zebra crossing").await;
    assert_eq!(r.indexed(&r.channel).await, 1);
    assert_eq!(r.indexed(&secret).await, 0);
    let (_, j) = r.search_as(&r.alice.token, "q=zebra").await;
    assert_eq!(j["searched"]["channels"], 1, "only unencrypted channels are searched");

    // Switching to encrypted drops the rows; the old plaintext is not found any more.
    let path = format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel);
    let (s, j) = r.node.patch(&path, &r.alice.token, json!({ "encrypted": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(r.indexed(&r.channel).await, 0);
    let (_, j) = r.search_as(&r.alice.token, "q=zebra").await;
    assert_eq!((j["results"].as_array().unwrap().len(), j["searched"]["channels"].as_i64()), (0, Some(0)));

    // Back to plaintext: the plaintext messages are indexed again (in the background).
    let (s, _) = r.node.patch(&path, &r.alice.token, json!({ "encrypted": false })).await;
    assert_eq!(s, StatusCode::OK);
    for _ in 0..common::rounds(100) {
        if r.indexed(&r.channel).await == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(r.bodies("q=zebra").await, vec!["zebra crossing"]);
    // System messages (the encryption notices) are never indexed.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_search").fetch_one(&r.node.state.db).await.unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn edits_deletes_purges_and_channel_deletion_update_the_index() {
    let r = setup().await;
    let base = format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.channel);
    let id = r.send(&r.bob.token, &r.channel, "apple pie").await;
    assert_eq!(r.bodies("q=apple").await.len(), 1);
    let (s, j) = r
        .node
        .patch(&format!("{base}/{id}"), &r.bob.token, json!({ "content": { "type": "text", "body": "banana split" } }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(r.bodies("q=apple").await.is_empty(), "the old text is gone");
    assert_eq!(r.bodies("q=banana").await, vec!["banana split"]);
    let (s, _) = r.node.delete(&format!("{base}/{id}"), &r.bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(r.bodies("q=banana").await.is_empty());
    assert_eq!(r.indexed(&r.channel).await, 0);

    // Moderation purge (dry run, then with the confirmation token).
    r.send(&r.bob.token, &r.channel, "cherry one").await;
    r.send(&r.bob.token, &r.channel, "cherry two").await;
    let purge = format!("/api/v1/rooms/{}/moderation/purge", r.room_id);
    let (s, dry) = r.node.post(&purge, &r.alice.token, json!({ "author_id": r.bob.user_id })).await;
    assert_eq!(s, StatusCode::OK, "{dry}");
    let (s, done) = r
        .node
        .post(&purge, &r.alice.token, json!({ "author_id": r.bob.user_id, "confirm_token": dry["confirm_token"] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert!(r.bodies("q=cherry").await.is_empty());
    assert_eq!(r.indexed(&r.channel).await, 0);

    // Deleting the channel takes its rows along.
    let other = r.channel("other", false).await;
    r.send(&r.alice.token, &other, "durian").await;
    assert_eq!(r.indexed(&other).await, 1);
    let (s, _) = r.node.delete(&format!("/api/v1/rooms/{}/channels/{other}", r.room_id), &r.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(r.indexed(&other).await, 0);
}

#[tokio::test]
async fn results_follow_channel_permissions_and_the_history_cut() {
    let r = setup().await;
    let hidden = r.channel("staff", false).await;
    r.send(&r.alice.token, &r.channel, "public kiwi").await;
    r.send(&r.alice.token, &hidden, "secret kiwi").await;
    let room = r.node.get_auth(&format!("/api/v1/rooms/{}", r.room_id), &r.alice.token).await.1;
    let everyone = room["roles"].as_array().unwrap().iter().find(|x| x["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            &r.alice.token,
            json!({ "target_type": "channel", "target_id": hidden, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    // The owner sees both, bob only the public one (and the count says one channel).
    assert_eq!(r.bodies("q=kiwi").await.len(), 2);
    let res = r.search_as(&r.bob.token, "q=kiwi").await;
    assert_eq!(res.1["searched"]["channels"], 1);
    assert_eq!(bodies_of(&res), vec!["public kiwi"]);
    // Asking for the hidden channel explicitly finds nothing either.
    let res = r.search_as(&r.bob.token, &format!("q=kiwi&channel={hidden}")).await;
    assert_eq!((bodies_of(&res).len(), res.1["searched"]["channels"].as_i64()), (0, Some(0)));

    // Without `read_history` bob finds only what was written since his join.
    r.send(&r.alice.token, &r.channel, "old mango").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    sqlx::query("UPDATE room_members SET joined_at = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(tavrn_node::util::now())
        .bind(&r.room_id)
        .bind(&r.bob.user_id)
        .execute(&r.node.state.db)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    r.send(&r.alice.token, &r.channel, "new mango").await;
    assert_eq!(bodies_of(&r.search_as(&r.bob.token, "q=mango").await).len(), 2, "with read_history: everything");
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            &r.alice.token,
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member", "subject_id": r.bob.user_id, "allow": "0", "deny": perms(&[p::READ_HISTORY]) }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    assert_eq!(bodies_of(&r.search_as(&r.bob.token, "q=mango").await), vec!["new mango"]);
    assert_eq!(r.bodies("q=mango").await.len(), 2, "the owner is not cut");
}

#[tokio::test]
async fn filters_author_channel_dates_and_files() {
    let r = setup().await;
    let second = r.channel("second", false).await;
    r.send(&r.alice.token, &r.channel, "lemon by alice").await;
    r.send(&r.bob.token, &r.channel, "lemon by bob").await;
    r.send(&r.alice.token, &second, "lemon elsewhere").await;
    // An upload: the file name is searchable and `has=file` finds it.
    let req = Request::post(format!("/api/v1/rooms/{}/channels/{}/uploads", r.room_id, r.channel))
        .header(header::AUTHORIZATION, format!("Bearer {}", r.bob.token))
        .header(header::CONTENT_TYPE, "application/pdf")
        .header("tavrn-file-name", "invoice-2026.pdf")
        .body(Body::from(b"%PDF-1.4 fake".to_vec()))
        .unwrap();
    let resp = r.node.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let blob: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let (s, m) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.channel),
            &r.bob.token,
            json!({ "content": { "type": "text", "body": "lemon receipt" }, "attachments": [blob["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");

    assert_eq!(r.bodies("q=lemon").await.len(), 4);
    assert_eq!(r.bodies("q=lemon&author=BOB%40t.local").await, vec!["lemon receipt", "lemon by bob"]);
    assert_eq!(r.bodies(&format!("q=lemon&channel={second}")).await, vec!["lemon elsewhere"]);
    assert_eq!(r.bodies("q=lemon&has=file").await, vec!["lemon receipt"]);
    assert_eq!(r.bodies("q=invoice").await, vec!["lemon receipt"], "file names are searchable");
    let (_, j) = r.search_as(&r.alice.token, "q=invoice").await;
    assert_eq!(j["results"][0]["message"]["attachments"][0]["name"], "invoice-2026.pdf");
    assert!(j["results"][0]["snippet"].as_str().unwrap().contains("\u{1}invoice\u{2}"), "{j}");
    // Filters without words: all files, all of an author.
    assert_eq!(r.bodies("has=file").await, vec!["lemon receipt"]);
    assert_eq!(r.bodies("author=alice%40t.local").await.len(), 2);
    // Dates: everything is from today.
    let today = chrono::Utc::now().date_naive();
    let tomorrow = today + chrono::Duration::days(1);
    assert_eq!(r.bodies(&format!("q=lemon&after={today}")).await.len(), 4);
    assert!(r.bodies(&format!("q=lemon&after={tomorrow}")).await.is_empty());
    assert!(r.bodies(&format!("q=lemon&before={today}")).await.is_empty());
    assert_eq!(r.bodies(&format!("q=lemon&before={tomorrow}T00:00:00Z")).await.len(), 4);
}

#[tokio::test]
async fn cursor_paging_newest_and_relevance() {
    let r = setup().await;
    for i in 0..7 {
        r.send(&r.alice.token, &r.channel, &format!("page item {i}")).await;
    }
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let q = match &cursor {
            Some(c) => format!("q=item&limit=3&cursor={c}"),
            None => "q=item&limit=3".to_string(),
        };
        let (s, j) = r.search_as(&r.alice.token, &q).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        pages += 1;
        seen.extend(bodies_of(&(s, j.clone())));
        match j["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seen, (0..7).rev().map(|i| format!("page item {i}")).collect::<Vec<_>>(), "newest first, no gaps");

    let (_, j) = r.search_as(&r.alice.token, "q=item&limit=3&sort=relevance").await;
    assert_eq!(j["next_cursor"], "o3");
    let (_, j2) = r.search_as(&r.alice.token, "q=item&limit=3&sort=relevance&cursor=o6").await;
    assert_eq!((j2["results"].as_array().unwrap().len(), &j2["next_cursor"]), (1, &Value::Null));
    // At most 50 per page.
    let (_, j) = r.search_as(&r.alice.token, "q=item&limit=500").await;
    assert_eq!(j["results"].as_array().unwrap().len(), 7);
}

#[tokio::test]
async fn search_is_rate_limited_and_can_be_disabled() {
    let r = setup_with(|c| c.search_rate_per_minute = 3).await;
    for _ in 0..3 {
        assert_eq!(r.search_as(&r.bob.token, "q=x").await.0, StatusCode::OK);
    }
    let (s, j) = r.search_as(&r.bob.token, "q=x").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert_eq!(r.search_as(&r.alice.token, "q=x").await.0, StatusCode::OK, "per user");

    let off = setup_with(|c| c.search_enabled = false).await;
    off.send(&off.alice.token, &off.channel, "hidden text").await;
    let (s, j) = off.search_as(&off.alice.token, "q=hidden").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("search.disabled")));
    assert_eq!(off.indexed(&off.channel).await, 0, "nothing is indexed while disabled");
    let (_, info) = off.node.get_auth("/api/v1/node", &off.alice.token).await;
    assert!(!info["capabilities"].as_array().unwrap().iter().any(|c| c == "search.v1"), "{info}");
    let (_, info) = r.node.get_auth("/api/v1/node", &r.alice.token).await;
    assert!(info["capabilities"].as_array().unwrap().iter().any(|c| c == "search.v1"), "{info}");
}

#[tokio::test]
async fn backfill_indexes_existing_messages_once() {
    let r = setup().await;
    r.send(&r.alice.token, &r.channel, "legacy walnut").await;
    // A node that had the message before the search existed.
    sqlx::query("DELETE FROM message_search").execute(&r.node.state.db).await.unwrap();
    assert!(r.bodies("q=walnut").await.is_empty());
    assert_eq!(tavrn_node::search::backfill(&r.node.state).await.unwrap(), 1);
    assert_eq!(r.bodies("q=walnut").await, vec!["legacy walnut"]);
    assert_eq!(tavrn_node::search::backfill(&r.node.state).await.unwrap(), 0, "resumes after the stored cursor");
    // The startup DDL is idempotent (every start runs it again).
    let dialect = tavrn_node::search::Dialect::of(&r.node.state.config.database_url);
    tavrn_node::search::ensure_schema(&r.node.state.db, dialect).await.unwrap();
    r.send(&r.alice.token, &r.channel, "fresh walnut").await;
    assert_eq!(r.bodies("q=walnut").await, vec!["fresh walnut", "legacy walnut"]);
}

/// An installed bot of alice's with a token limited to `scopes`; returns the token.
async fn bot_token(r: &Room, name: &str, scopes: Value) -> String {
    let (s, app) = r.node.post("/api/v1/applications", &r.alice.token, json!({ "name": name, "public": true })).await;
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
        .post(
            &format!("/api/v1/rooms/{}/applications", r.room_id),
            &r.alice.token,
            json!({ "application": format!("{D}/{app_id}") }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    t["secret"].as_str().unwrap().to_string()
}

/// App tokens: the route needs `messages:read`, and "no bots" channels are never searched by bots.
#[tokio::test]
async fn bots_need_the_scope_and_respect_no_bots() {
    let r = setup().await;
    r.send(&r.alice.token, &r.channel, "bot visible fig").await;
    let quiet = r.channel("quiet", false).await;
    r.send(&r.alice.token, &quiet, "humans only fig").await;
    let reader = bot_token(&r, "Reader", json!(["messages:read"])).await;
    let writer = bot_token(&r, "Writer", json!(["messages:write"])).await;
    let res = r.search_as(&reader, "q=fig").await;
    assert_eq!(bodies_of(&res).len(), 2, "{:?}", res.1);
    let (s, j) = r.search_as(&writer, "q=fig").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("app.scope_missing")));
    let (s, j) = r
        .node
        .patch(&format!("/api/v1/rooms/{}/channels/{quiet}", r.room_id), &r.alice.token, json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let res = r.search_as(&reader, "q=fig").await;
    assert_eq!(bodies_of(&res), vec!["bot visible fig"]);
    assert_eq!(res.1["searched"]["channels"], 1);
}

#[tokio::test]
async fn remote_members_search_and_remote_strangers_do_not() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Meeting point").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let channel = TestNode::text_channel(&room);
    b.send(&carol.token, &room_id, &channel, "federated plum").await;

    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let path = format!("/api/v1/rooms/{room_id}/search?q=plum");
    let (s, j) = b.get_auth(&path, &remote.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.not_member")));
    let (s, _) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = b.get_auth(&path, &remote.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["results"][0]["message"]["author"], "carol@b.test");
    // A remote member's own messages are indexed like everyone's.
    b.send(&remote.token, &room_id, &channel, "plum from afar").await;
    let (_, j) = b.get_auth(&format!("{path}&author=alice%40a.test"), &carol.token).await;
    assert_eq!(j["results"][0]["message"]["content"]["body"], "plum from afar");
}

// ---------------------------------------------------------------- around (jump to a message)

#[tokio::test]
async fn around_opens_the_history_at_a_message() {
    let r = setup().await;
    let mut ids = Vec::new();
    for i in 0..30 {
        ids.push(r.send(&r.alice.token, &r.channel, &format!("m{i}")).await);
    }
    let path = format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.channel);
    let (s, j) = r.node.get_auth(&format!("{path}?around={}&limit=10", ids[10]), &r.bob.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let got: Vec<&str> = j.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    let want: Vec<&str> = ids[6..=15].iter().rev().map(String::as_str).collect();
    assert_eq!(got, want, "5 newer, the target, 4 older, newest first");
    // Near the end: fewer newer messages, more older ones.
    let (_, j) = r.node.get_auth(&format!("{path}?around={}&limit=10", ids[29]), &r.bob.token).await;
    assert_eq!(j.as_array().unwrap().len(), 10);
    assert_eq!(j[0]["id"], ids[29].as_str());
    // Lowercase ids work, the conversation route too.
    let (s, j) = r
        .node
        .get_auth(
            &format!("/api/v1/conversations/{}/messages?around={}&limit=4", r.channel, ids[0].to_lowercase()),
            &r.bob.token,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j.as_array().unwrap().last().unwrap()["id"], ids[0].as_str());

    let code = |j: &Value| j["code"].as_str().unwrap_or("").to_string();
    let (s, j) = r.node.get_auth(&format!("{path}?around={}&before={}", ids[3], ids[4]), &r.bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.cursor_conflict".into()));
    let (s, j) = r.node.get_auth(&format!("{path}?around=nope"), &r.bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.id".into()));
    let (s, j) = r.node.get_auth(&format!("{path}?around={}", tavrn_node::util::ulid()), &r.bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "message.not_found".into()));
    // A message of another channel is not found through this one.
    let other = r.channel("other", false).await;
    let foreign = r.send(&r.alice.token, &other, "elsewhere").await;
    let (s, _) = r.node.get_auth(&format!("{path}?around={foreign}"), &r.bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Without view_channel: forbidden as for any listing.
    let carol = r.node.register("carol").await;
    let (s, _) = r.node.get_auth(&format!("{path}?around={}", ids[1]), &carol.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
