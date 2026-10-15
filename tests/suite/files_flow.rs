// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Files channels (protocol/FILES.md): channel kind, folders, streamed uploads and
//! ranged downloads, names, moves, recursive deletes, the permission matrix, limits, realtime events and
//! housekeeping (orphans, retention never touches file entries).
use crate::common;

use axum::http::{HeaderMap, Method, StatusCode};
use common::{Session, TestNode, perms, test_node_with};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const DOMAIN: &str = "t.local";

struct Setup {
    node: TestNode,
    /// Room owner (and node admin: first account).
    alice: Session,
    /// Plain member.
    bob: Session,
    room_id: String,
    channel: String,
}

impl Setup {
    fn base(&self) -> String {
        format!("/api/v1/rooms/{}/channels/{}/files", self.room_id, self.channel)
    }

    async fn up(&self, token: &str, name: &str, parent: Option<&str>, mime: &str, data: &[u8]) -> (StatusCode, Value) {
        self.up_with(token, name, parent, mime, data, &[]).await
    }

    async fn up_with(
        &self,
        token: &str,
        name: &str,
        parent: Option<&str>,
        mime: &str,
        data: &[u8],
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let encoded = tavrn_node::files::sigv4::uri_encode(name, false);
        let mut headers = vec![("content-type", mime), ("tavrn-file-name", encoded.as_str())];
        if let Some(p) = parent {
            headers.push(("tavrn-parent", p));
        }
        headers.extend_from_slice(extra);
        let (s, _, body) =
            self.node.raw(Method::POST, &format!("{}/upload", self.base()), token, &headers, data.to_vec()).await;
        (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    async fn down(&self, token: &str, id: &str, range: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let headers: Vec<(&str, &str)> = range.map(|r| vec![("range", r)]).unwrap_or_default();
        let (s, h, b) =
            self.node.raw(Method::GET, &format!("{}/{id}/download", self.base()), token, &headers, Vec::new()).await;
        (s, h, b.to_vec())
    }

    async fn folder(&self, token: &str, parent: Option<&str>, name: &str) -> (StatusCode, Value) {
        self.node.post(&format!("{}/folders", self.base()), token, json!({ "parent_id": parent, "name": name })).await
    }

    async fn ls(&self, token: &str, query: &str) -> Value {
        let (s, j) = self.node.get_auth(&format!("{}?{query}", self.base()), token).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        j
    }

    async fn names(&self, token: &str, query: &str) -> Vec<String> {
        self.ls(token, query).await["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Sets a member override on the files channel.
    async fn member_override(&self, user: &Session, allow: u64, deny: u64) {
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": self.channel, "subject_type": "member",
                        "subject_id": user.user_id, "allow": allow.to_string(), "deny": deny.to_string() }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
}

async fn setup_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Setup {
    let node = test_node_with(DOMAIN, tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "files", "name": "Shared Files", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert!(s.is_success(), "{j}");
    Setup { node, alice, bob, room_id, channel: ch["id"].as_str().unwrap().to_string() }
}

async fn setup() -> Setup {
    setup_with(|_| {}).await
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn unencrypted_files_channels_stay_unencrypted_and_have_no_messages() {
    let s = setup().await;
    let (st, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
    assert_eq!(st, StatusCode::OK);
    let ch = room["channels"].as_array().unwrap().iter().find(|c| c["id"] == s.channel.as_str()).unwrap();
    assert_eq!((ch["kind"].as_str(), ch["encrypted"].as_bool()), (Some("files"), Some(false)));
    assert_eq!(ch["name"], "shared-files");

    let path = format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel);
    let (st, j) = s.node.patch(&path, &s.alice.token, json!({ "encrypted": true })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.encryption_fixed")), "{j}");
    let (st, j) = s.node.send(&s.alice.token, &s.room_id, &s.channel, "hello").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.no_text")), "{j}");
    // The usual channel settings keep working.
    let (st, j) = s.node.patch(&path, &s.alice.token, json!({ "name": "Archive", "topic": "Docs" })).await;
    assert_eq!((st, j["name"].as_str()), (StatusCode::OK, Some("archive")), "{j}");
    // The files routes answer only for files channels.
    let room = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await.1;
    let text = TestNode::text_channel(&room);
    let (st, j) = s.node.get_auth(&format!("/api/v1/rooms/{}/channels/{text}/files", s.room_id), &s.alice.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.not_files")), "{j}");
}

#[tokio::test]
async fn uploads_stream_into_encrypted_storage_and_download_with_ranges() {
    let s = setup().await;
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (st, f) = s.up(&s.bob.token, "data.dat", None, "application/octet-stream", &data).await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    assert_eq!((f["kind"].as_str(), f["size"].as_i64()), (Some("file"), Some(200_000)));
    assert_eq!(f["created_by"], s.bob.user_id.as_str());
    assert_eq!(f["parent_id"], Value::Null);
    let fid = id(&f);
    // At rest the file is the storage format, not the plaintext.
    let disk = std::fs::read(s.node.state.storage.path_of(&fid).unwrap()).unwrap();
    assert!(disk.starts_with(&tavrn_node::storage::MAGIC));

    let (st, h, body) = s.down(&s.alice.token, &fid, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, data);
    assert!(h["content-disposition"].to_str().unwrap().starts_with("attachment; filename=\"data.dat\""));
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["content-security-policy"], "default-src 'none'; sandbox");
    assert_eq!(h["accept-ranges"], "bytes");
    assert_eq!(h["content-type"], "application/octet-stream");

    for (range, start, end) in [
        ("bytes=0-9", 0, 9),
        ("bytes=65530-65545", 65530, 65545),
        ("bytes=199990-", 199_990, 199_999),
        ("bytes=-5", 199_995, 199_999),
        ("bytes=70000-200000", 70000, 199_999),
    ] {
        let (st, h, body) = s.down(&s.bob.token, &fid, Some(range)).await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(body, data[start..=end], "{range}");
        assert_eq!(h["content-range"], format!("bytes {start}-{end}/200000").as_str());
        assert_eq!(h["content-length"], (end - start + 1).to_string().as_str());
    }
    let (st, h, _) = s.down(&s.bob.token, &fid, Some("bytes=200000-")).await;
    assert_eq!(st, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(h["content-range"], "bytes */200000");
    // Multiple ranges are served whole.
    assert_eq!(s.down(&s.bob.token, &fid, Some("bytes=0-1,4-5")).await.0, StatusCode::OK);

    // Types: only safe ones are served as such; HTML and SVG never.
    let (_, png) = s.up(&s.bob.token, "pic.png", None, "image/png", b"\x89PNG\r\n\x1a\nrest").await;
    assert_eq!(png["mime"], "image/png");
    assert_eq!(s.down(&s.bob.token, &id(&png), None).await.1["content-type"], "image/png");
    let (_, html) = s.up(&s.bob.token, "page.html", None, "text/html", b"<script>alert(1)</script>").await;
    assert_eq!(s.down(&s.bob.token, &id(&html), None).await.1["content-type"], "application/octet-stream");
    let (_, svg) = s
        .up(&s.bob.token, "logo.png", None, "image/png", b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>")
        .await;
    assert_eq!(svg["mime"], "image/svg+xml", "content decides: SVG is a document");
    assert_eq!(s.down(&s.bob.token, &id(&svg), None).await.1["content-type"], "application/octet-stream");
    // An empty file is fine.
    let (st, empty) = s.up(&s.bob.token, "empty.txt", None, "text/plain", b"").await;
    assert_eq!(st, StatusCode::CREATED, "{empty}");
    let (st, _, body) = s.down(&s.bob.token, &id(&empty), None).await;
    assert_eq!((st, body.len()), (StatusCode::OK, 0));
    // Folders cannot be downloaded.
    let (_, folder) = s.folder(&s.bob.token, None, "Docs").await;
    let (st, _, _) = s.down(&s.bob.token, &id(&folder), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn names_are_validated_normalised_and_unique_per_folder() {
    let s = setup().await;
    for bad in ["../etc/passwd", "a/b", "..", ".", "back\\slash", "evil\u{202e}gpj.exe", "nul\u{1}"] {
        let (st, j) = s.folder(&s.bob.token, None, bad).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.name_invalid")), "{bad:?}: {j}");
        let (st, j) = s.up(&s.bob.token, bad, None, "text/plain", b"x").await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.name_invalid")), "{bad:?}: {j}");
    }
    let (st, j) = s.folder(&s.bob.token, None, &"x".repeat(256)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{j}");

    let (st, a) = s.up(&s.bob.token, "Report.txt", None, "text/plain", b"1").await;
    assert_eq!(st, StatusCode::CREATED, "{a}");
    let (st, j) = s.up(&s.bob.token, "report.TXT", None, "text/plain", b"2").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("files.name_taken")), "case-insensitive: {j}");
    let (st, j) = s.folder(&s.bob.token, None, "REPORT.txt").await;
    assert_eq!(st, StatusCode::CONFLICT, "folders and files share the names: {j}");
    let (st, j) =
        s.up_with(&s.bob.token, "report.txt", None, "text/plain", b"2", &[("tavrn-conflict", "rename")]).await;
    assert_eq!((st, j["name"].as_str()), (StatusCode::CREATED, Some("report (2).txt")), "{j}");
    // NFC: the decomposed and the composed form are the same name.
    let (st, _) = s.folder(&s.bob.token, None, "Caf\u{e9}").await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, j) = s.folder(&s.bob.token, None, "Cafe\u{301}").await;
    assert_eq!(st, StatusCode::CONFLICT, "{j}");
    // Same name in another folder is fine.
    let (_, docs) = s.folder(&s.bob.token, None, "docs").await;
    let (st, _) = s.up(&s.bob.token, "Report.txt", Some(&id(&docs)), "text/plain", b"3").await;
    assert_eq!(st, StatusCode::CREATED);
    // Unknown parents.
    let (st, j) = s.up(&s.bob.token, "x.txt", Some(&id(&a)), "text/plain", b"x").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.parent_not_folder")), "{j}");
    let (st, j) = s.folder(&s.bob.token, Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"), "y").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("files.parent_not_found")), "{j}");
}

#[tokio::test]
async fn folders_list_paginate_search_and_nest_up_to_32_levels() {
    let s = setup().await;
    let (_, docs) = s.folder(&s.bob.token, None, "Docs").await;
    let docs_id = id(&docs);
    let (_, sub) = s.folder(&s.bob.token, Some(&docs_id), "Sub").await;
    for name in ["b.txt", "A.txt", "c.txt"] {
        assert_eq!(s.up(&s.bob.token, name, Some(&docs_id), "text/plain", b"x").await.0, StatusCode::CREATED);
    }
    s.up(&s.bob.token, "top-report.txt", None, "text/plain", b"x").await;
    let listing = s.ls(&s.alice.token, &format!("parent={docs_id}")).await;
    let names: Vec<&str> = listing["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Sub", "A.txt", "b.txt", "c.txt"], "folders first, then by name (case-insensitive)");
    assert_eq!(listing["path"], json!([{ "id": docs_id, "name": "Docs" }]));
    assert_eq!(s.names(&s.alice.token, "").await, ["Docs", "top-report.txt"]);

    // Pagination with the cursor.
    let page = s.ls(&s.alice.token, &format!("parent={docs_id}&limit=2")).await;
    assert_eq!(page["entries"].as_array().unwrap().len(), 2);
    let next = page["next_after"].as_str().unwrap();
    let rest = s.names(&s.alice.token, &format!("parent={docs_id}&limit=2&after={next}")).await;
    assert_eq!(rest, ["b.txt", "c.txt"]);
    assert_eq!(
        s.ls(&s.alice.token, &format!("parent={docs_id}&limit=2&after={next}")).await["next_after"],
        Value::Null
    );
    // Search across the channel, case-insensitive; wildcards are literal.
    assert_eq!(s.names(&s.alice.token, "q=REPORT").await, ["top-report.txt"]);
    assert_eq!(s.names(&s.alice.token, "q=.txt&limit=10").await.len(), 4);
    assert!(s.names(&s.alice.token, "q=%25").await.is_empty());
    // One entry with its path.
    let (st, d) = s.node.get_auth(&format!("{}/{}", s.base(), id(&sub)), &s.bob.token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(d["path"].as_array().unwrap().len(), 2);

    // Depth: 32 levels of folders, not 33.
    let mut parent: Option<String> = None;
    for level in 1..=32 {
        let (st, f) = s.folder(&s.alice.token, parent.as_deref(), &format!("L{level}")).await;
        assert_eq!(st, StatusCode::CREATED, "level {level}: {f}");
        parent = Some(id(&f));
    }
    let (st, j) = s.folder(&s.alice.token, parent.as_deref(), "L33").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.too_deep")), "{j}");
    assert_eq!(s.up(&s.alice.token, "deep.txt", parent.as_deref(), "text/plain", b"x").await.0, StatusCode::CREATED);
    // Moving a folder with a subfolder under level 31 would exceed the limit.
    let (st, j) = s.node.patch(&format!("{}/{docs_id}", s.base()), &s.bob.token, json!({ "parent_id": parent })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.too_deep")), "{j}");
    // Limits of a listing.
    let (st, _) = s.node.get_auth(&format!("{}?after=nonsense", s.base()), &s.bob.token).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(s.ls(&s.bob.token, "limit=100000").await["entries"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn rename_and_move_refuse_cycles_and_collisions() {
    let s = setup().await;
    let (_, a) = s.folder(&s.bob.token, None, "A").await;
    let (_, b) = s.folder(&s.bob.token, Some(&id(&a)), "B").await;
    let (_, c) = s.folder(&s.bob.token, Some(&id(&b)), "C").await;
    let (_, f) = s.up(&s.bob.token, "f.txt", Some(&id(&c)), "text/plain", b"content").await;
    let path = |e: &Value| format!("{}/{}", s.base(), id(e));

    for target in [&a, &b, &c] {
        let (st, j) = s.node.patch(&path(&a), &s.bob.token, json!({ "parent_id": id(target) })).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.move_into_self")), "{j}");
    }
    let (st, j) = s.node.patch(&path(&f), &s.bob.token, json!({ "parent_id": id(&f) })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.parent_not_folder")), "{j}");
    // Move C (with its file) to the top level and rename it.
    let (st, j) = s.node.patch(&path(&c), &s.bob.token, json!({ "parent_id": null, "name": "C2" })).await;
    assert_eq!((st, j["name"].as_str(), &j["parent_id"]), (StatusCode::OK, Some("C2"), &Value::Null), "{j}");
    assert_eq!(s.names(&s.bob.token, "").await, ["A", "C2"]);
    // The file moved along and is still readable (metadata-only move).
    let (st, _, body) = s.down(&s.bob.token, &id(&f), None).await;
    assert_eq!((st, body.as_slice()), (StatusCode::OK, &b"content"[..]));
    // Collision on rename and on move.
    let (st, j) = s.node.patch(&path(&c), &s.bob.token, json!({ "name": "a" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("files.name_taken")), "{j}");
    s.folder(&s.bob.token, Some(&id(&a)), "C2").await;
    let (st, _) = s.node.patch(&path(&c), &s.bob.token, json!({ "parent_id": id(&a) })).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, j) = s.node.patch(&path(&f), &s.bob.token, json!({ "name": "../x" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.name_invalid")));
}

#[tokio::test]
async fn deletes_are_recursive_counted_audited_and_remove_the_bytes() {
    let s = setup().await;
    let (_, a) = s.folder(&s.bob.token, None, "A").await;
    let (_, b) = s.folder(&s.bob.token, Some(&id(&a)), "B").await;
    let (_, f1) = s.up(&s.bob.token, "1.txt", Some(&id(&a)), "text/plain", b"12345").await;
    let (_, f2) = s.up(&s.bob.token, "2.txt", Some(&id(&b)), "text/plain", b"123").await;
    let paths: Vec<_> = [&f1, &f2].iter().map(|f| s.node.state.storage.path_of(&id(f)).unwrap()).collect();
    assert!(paths.iter().all(|p| p.exists()));
    let (st, r) = s.node.delete(&format!("{}/{}", s.base(), id(&a)), &s.bob.token).await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r, json!({ "files": 2, "folders": 2, "bytes": 8 }));
    assert!(paths.iter().all(|p| !p.exists()), "stored files are gone");
    assert!(s.names(&s.bob.token, "").await.is_empty());
    assert_eq!(s.down(&s.bob.token, &id(&f1), None).await.0, StatusCode::NOT_FOUND);
    let (st, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), &s.alice.token).await;
    assert_eq!(st, StatusCode::OK, "{log}");
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "files.delete").expect("audit entry");
    assert_eq!(entry["meta"]["files"], 2);
    assert_eq!(entry["meta"]["name"], "A");
    let (st, _) = s.node.delete(&format!("{}/{}", s.base(), id(&a)), &s.bob.token).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn permission_matrix() {
    let s = setup().await;
    let carol = s.node.register("carol").await;
    let (_, invite) = s.node.post(&format!("/api/v1/rooms/{}/invites", s.room_id), &s.alice.token, json!({})).await;
    s.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    let stranger = s.node.register("stranger").await;

    let (_, alices) = s.up(&s.alice.token, "alice.txt", None, "text/plain", b"a").await;
    let (_, bobs) = s.up(&s.bob.token, "bob.txt", None, "text/plain", b"b").await;
    let (_, bob_folder) = s.folder(&s.bob.token, None, "bobs").await;
    s.up(&s.alice.token, "inside.txt", Some(&id(&bob_folder)), "text/plain", b"x").await;
    let entry = |e: &Value| format!("{}/{}", s.base(), id(e));

    // Not a member: nothing.
    let (st, _) = s.node.get_auth(&s.base(), &stranger.token).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(s.down(&stranger.token, &id(&alices), None).await.0, StatusCode::FORBIDDEN);

    // attach_files: own entries only.
    let (st, j) = s.node.patch(&entry(&alices), &s.bob.token, json!({ "name": "mine.txt" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.manage_forbidden")), "{j}");
    assert_eq!(s.node.delete(&entry(&alices), &s.bob.token).await.0, StatusCode::FORBIDDEN);
    let (st, _) = s.node.patch(&entry(&bobs), &s.bob.token, json!({ "name": "bob2.txt" })).await;
    assert_eq!(st, StatusCode::OK);
    // A folder of bob's that holds alice's file: deleting needs manage_files.
    let (st, j) = s.node.delete(&entry(&bob_folder), &s.bob.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.manage_forbidden")), "{j}");

    // Without attach_files: browse and download, nothing else.
    s.member_override(&carol, 0, p::ATTACH_FILES).await;
    assert_eq!(s.names(&carol.token, "").await.len(), 3);
    assert_eq!(s.down(&carol.token, &id(&alices), None).await.0, StatusCode::OK);
    let (st, j) = s.up(&carol.token, "c.txt", None, "text/plain", b"c").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.upload_forbidden")), "{j}");
    let (st, _) = s.folder(&carol.token, None, "c").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (_, info) = s.node.get_auth(&format!("{}/usage", s.base()), &carol.token).await;
    assert_eq!((info["can_upload"].as_bool(), info["can_manage"].as_bool()), (Some(false), Some(false)));

    // manage_files: everybody's entries.
    s.member_override(&carol, p::MANAGE_FILES, 0).await;
    let (st, _) = s.node.patch(&entry(&alices), &carol.token, json!({ "name": "renamed-by-carol.txt" })).await;
    assert_eq!(st, StatusCode::OK);
    let (st, r) = s.node.delete(&entry(&bob_folder), &carol.token).await;
    assert_eq!((st, r["files"].as_u64()), (StatusCode::OK, Some(1)), "{r}");
    let (_, info) = s.node.get_auth(&format!("{}/usage", s.base()), &carol.token).await;
    assert_eq!((info["can_manage"].as_bool(), info["can_configure"].as_bool()), (Some(true), Some(false)));

    // Without view_channel: nothing at all.
    s.member_override(&s.bob, 0, p::VIEW_CHANNEL).await;
    let (st, j) = s.node.get_auth(&s.base(), &s.bob.token).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(s.down(&s.bob.token, &id(&alices), None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(s.up(&s.bob.token, "x.txt", None, "text/plain", b"x").await.0, StatusCode::FORBIDDEN);

    // The backend needs manage_channels and manage_files.
    let (st, j) = s.node.get_auth(&format!("{}/backend", s.base()), &carol.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.backend_forbidden")), "{j}");
    let (st, j) = s.node.get_auth(&format!("{}/backend", s.base()), &s.alice.token).await;
    assert_eq!((st, j["kind"].as_str()), (StatusCode::OK, Some("internal")), "{j}");
    assert_eq!(perms(&[p::MANAGE_FILES]), (1u64 << 33).to_string());
}

#[tokio::test]
async fn limits_categories_and_entitlements() {
    let s = setup_with(|c| {
        c.upload_max_bytes = 1000;
        c.files_channels_max_bytes = 1500;
    })
    .await;
    let (st, j) = s.up(&s.bob.token, "big.dat", None, "application/octet-stream", &[0u8; 1001]).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("upload.too_large")), "{j}");
    assert_eq!(
        s.up(&s.bob.token, "a.dat", None, "application/octet-stream", &[1u8; 1000]).await.0,
        StatusCode::CREATED
    );
    let (st, j) = s.up(&s.bob.token, "b.dat", None, "application/octet-stream", &[2u8; 600]).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("files.quota_exceeded")), "{j}");
    assert_eq!(j["meta"]["used_bytes"], 1000);
    assert_eq!(s.up(&s.bob.token, "c.dat", None, "application/octet-stream", &[3u8; 500]).await.0, StatusCode::CREATED);
    let (_, info) = s.node.get_auth(&format!("{}/usage", s.base()), &s.bob.token).await;
    assert_eq!(
        (
            info["used_bytes"].as_i64(),
            info["limit_bytes"].as_i64(),
            info["files"].as_i64(),
            info["max_upload_bytes"].as_u64()
        ),
        (Some(1500), Some(1500), Some(2), Some(1000)),
        "{info}"
    );
    assert_eq!(info["backend"], "internal");
    // Nothing of a refused upload stays behind.
    assert_eq!(s.names(&s.bob.token, "").await, ["a.dat", "c.dat"]);

    // Upload categories and executables as for attachments.
    let s = setup().await;
    let everyone = {
        let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
        room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{everyone}", s.room_id),
            &s.alice.token,
            json!({ "allowed_upload_categories": ["images"] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.up(&s.bob.token, "rules.pdf", None, "application/pdf", b"%PDF-1.7").await;
    assert_eq!(
        (st, j["code"].as_str(), j["meta"]["category"].as_str()),
        (StatusCode::FORBIDDEN, Some("upload.type_forbidden"), Some("documents")),
        "{j}"
    );
    let (st, j) = s.up(&s.alice.token, "setup.exe", None, "application/octet-stream", b"MZ\x90\x00").await;
    assert_eq!((st, j["meta"]["executable"].as_bool()), (StatusCode::FORBIDDEN, Some(true)), "{j}");
    assert_eq!(s.up(&s.bob.token, "ok.png", None, "image/png", b"\x89PNG\r\n\x1a\n").await.0, StatusCode::CREATED);
    assert!(s.names(&s.bob.token, "").await.iter().all(|n| n == "ok.png"));
}

#[tokio::test]
async fn the_room_owners_entitlement_switches_files_channels() {
    let node = test_node_with(DOMAIN, |c| c.files_channels = tavrn_node::config::Switch::Off).await;
    let admin = node.register("admin").await;
    let owner = node.register("owner").await;
    let room = node.create_room(&owner.token, "R").await;
    let room_id = room["id"].as_str().unwrap();
    let channels = format!("/api/v1/rooms/{room_id}/channels");
    let create = |name: &'static str| {
        node.post(&channels, &owner.token, json!({ "kind": "files", "name": name, "encrypted": false }))
    };
    let (st, j) = create("a").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.disabled")), "{j}");
    let (st, grant) = node
        .post(
            "/api/v1/admin/entitlements/grants",
            &admin.token,
            json!({ "subject": format!("room:{room_id}"), "overrides": { "files_channels.enabled": 1 } }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{grant}");
    let (st, ch) = create("b").await;
    assert_eq!(st, StatusCode::CREATED, "{ch}");
    let base = format!("/api/v1/rooms/{room_id}/channels/{}/files", ch["id"].as_str().unwrap());
    let (st, f) = node.post(&format!("{base}/folders"), &owner.token, json!({ "name": "kept" })).await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    // The grant ends: no uploads or folders, browsing stays.
    node.delete(&format!("/api/v1/admin/entitlements/grants/{}", grant["id"].as_str().unwrap()), &admin.token).await;
    let (st, _, body) = node
        .raw(
            Method::POST,
            &format!("{base}/upload"),
            &owner.token,
            &[("tavrn-file-name", "x.txt"), ("content-type", "text/plain")],
            b"x".to_vec(),
        )
        .await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.disabled")), "{j}");
    let (st, j) = node.post(&format!("{base}/folders"), &owner.token, json!({ "name": "new" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.disabled")));
    let (st, list) = node.get_auth(&base, &owner.token).await;
    assert_eq!((st, list["entries"].as_array().unwrap().len()), (StatusCode::OK, 1));
    let (_, info) = node.get_auth(&format!("{base}/usage"), &owner.token).await;
    assert_eq!((info["enabled"].as_bool(), info["can_upload"].as_bool()), (Some(false), Some(false)));
}

#[tokio::test]
async fn changes_are_announced_to_the_room() {
    let s = setup().await;
    let mut rx = s.node.state.hub.subscribe();
    let (_, folder) = s.folder(&s.bob.token, None, "Live").await;
    s.up(&s.bob.token, "x.txt", Some(&id(&folder)), "text/plain", b"x").await;
    let mut seen = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if ev.kind == "files.update" {
            seen.push(ev.data.clone());
        }
    }
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0], json!({ "room_id": s.room_id, "channel_id": s.channel, "parent_id": null }));
    assert_eq!(seen[1]["parent_id"], id(&folder).as_str());
}

#[tokio::test]
async fn deleting_the_channel_or_the_room_removes_the_stored_files() {
    let s = setup().await;
    let (_, f) = s.up(&s.bob.token, "x.txt", None, "text/plain", b"x").await;
    let path = s.node.state.storage.path_of(&id(&f)).unwrap();
    assert!(path.exists());
    let (st, _) = s.node.delete(&format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel), &s.alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(!path.exists());

    let s = setup().await;
    let (_, f) = s.up(&s.bob.token, "y.txt", None, "text/plain", b"y").await;
    let path = s.node.state.storage.path_of(&id(&f)).unwrap();
    let (st, j) = s.node.delete(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
    assert!(st.is_success(), "{j}");
    assert!(!path.exists());
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_entries").fetch_one(&s.node.state.db).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn housekeeping_keeps_file_entries_out_of_retention_and_sweeps_orphans() {
    let s = setup_with(|c| c.attachment_retention_days = 1).await;
    let (_, f) = s.up(&s.bob.token, "keep.txt", None, "text/plain", b"keep me").await;
    let (_, lost) = s.up(&s.bob.token, "lost.txt", None, "text/plain", b"lost").await;
    let db = &s.node.state.db;
    sqlx::query("UPDATE file_entries SET created_at = '2020-01-01T00:00:00.000Z'").execute(db).await.unwrap();
    // Retention: file entries are not attachments.
    let report = tavrn_node::housekeeping::expire_attachments(
        &s.node.state,
        chrono::Utc::now() + chrono::Duration::days(30),
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(report.expired, 0);
    let (st, _, body) = s.down(&s.bob.token, &id(&f), None).await;
    assert_eq!((st, body.as_slice()), (StatusCode::OK, &b"keep me"[..]));

    // Orphans: an entry whose stored file is gone, a stored file without an entry; real entries survive.
    std::fs::remove_file(s.node.state.storage.path_of(&id(&lost)).unwrap()).unwrap();
    let stray = tavrn_node::util::ulid();
    s.node.state.storage.write(&stray, b"stray").await.unwrap();
    let later = chrono::Utc::now() + chrono::Duration::days(2);
    let r = tavrn_node::housekeeping::sweep_orphans(&s.node.state, later).await.unwrap();
    assert_eq!(r.file_entries, 1, "{r:?}");
    assert!(r.files >= 1, "{r:?}");
    assert_eq!(s.names(&s.bob.token, "").await, ["keep.txt"]);
    assert!(s.node.state.storage.path_of(&id(&f)).unwrap().exists());
    assert_eq!(s.down(&s.bob.token, &id(&f), None).await.2, b"keep me");
    assert!(s.node.state.storage.read(&stray).await.unwrap().is_none());
}

// ---------------------------------------------------------------- renames, quotas and aborted uploads

#[tokio::test]
async fn a_rename_is_classified_like_an_upload() {
    let s = setup().await;
    let script = b"@echo off\r\nstart calc.exe\r\n";
    // The node refuses the script under its real name and accepts the same bytes as text.
    let (st, j) = s.up(&s.bob.token, "run.bat", None, "text/plain", script).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("upload.type_forbidden")), "{j}");
    let (st, j) = s.up(&s.bob.token, "run.txt", None, "text/plain", script).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let entry = id(&j);
    // Renaming it to an executable name is refused like the upload.
    let (st, j) = s.node.patch(&format!("{}/{entry}", s.base()), &s.bob.token, json!({ "name": "run.bat" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("upload.type_forbidden")), "{j}");
    assert_eq!(j["meta"]["executable"], true);
    let (st, h, _) = s.down(&s.bob.token, &entry, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(h["content-disposition"].to_str().unwrap().contains("run.txt"));
    // A harmless new name passes.
    let (st, j) = s.node.patch(&format!("{}/{entry}", s.base()), &s.bob.token, json!({ "name": "run.md" })).await;
    assert_eq!((st, j["name"].as_str()), (StatusCode::OK, Some("run.md")), "{j}");

    // Role-restricted categories: a member who may upload documents only cannot rename into an archive.
    let everyone = {
        let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
        room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{everyone}", s.room_id),
            &s.alice.token,
            json!({ "allowed_upload_categories": ["documents"] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.node.patch(&format!("{}/{entry}", s.base()), &s.bob.token, json!({ "name": "run.zip" })).await;
    assert_eq!(
        (st, j["code"].as_str(), j["meta"]["category"].as_str()),
        (StatusCode::FORBIDDEN, Some("upload.type_forbidden"), Some("archives")),
        "{j}"
    );
    // Moving without a new name is no rename.
    let (_, folder) = s.folder(&s.bob.token, None, "Docs").await;
    let (st, j) =
        s.node.patch(&format!("{}/{entry}", s.base()), &s.bob.token, json!({ "parent_id": id(&folder) })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
}
