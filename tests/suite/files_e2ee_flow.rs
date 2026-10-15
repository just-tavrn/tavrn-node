// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end encrypted files channels (protocol/FILES.md §8): encryption by default and fixed afterwards,
//! the MLS group, entry records, opaque storage (no name or type in any row or path), client-chosen ids,
//! ciphertext ranges, renames as new records, thumbnails, the "mine" listing for deleting without keys, the
//! records route and the history window.
use crate::common;

use axum::http::{HeaderMap, Method, StatusCode};
use common::{
    TestNode,
    e2ee::{Dev, qualified},
    perms, test_node,
};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const DOMAIN: &str = "t.local";
const SECRET_NAME: &str = "Quarterly-secret-plan.pdf";

struct E {
    node: TestNode,
    alice: Dev,
    bob: Dev,
    room_id: String,
    channel: String,
}

/// A fresh client-chosen entry id.
fn new_id() -> String {
    tavrn_node::util::ulid()
}

impl E {
    fn base(&self) -> String {
        format!("/api/v1/rooms/{}/channels/{}/files", self.room_id, self.channel)
    }

    /// An entry record (content format 1) of `dev` under its current epoch.
    fn record(&self, dev: &Dev, entry: &str, kind: &str, name: &str) -> (String, i64) {
        let q = qualified(&self.channel);
        let json = json!({ "type": "files.entry", "v": 1, "entry": entry, "kind": kind, "name": name,
                           "mime": "application/pdf", "size": 3, "key": "k" });
        (dev.client.encrypt_content(&q, &json.to_string()).unwrap(), dev.client.current_epoch(&q).unwrap() as i64)
    }

    async fn folder(&self, dev: &Dev, parent: Option<&str>, name: &str) -> (StatusCode, Value) {
        let id = new_id();
        let (record, epoch) = self.record(dev, &id, "folder", name);
        self.node
            .post(
                &format!("{}/folders", self.base()),
                dev.token(),
                json!({ "parent_id": parent, "id": id, "record": record, "record_epoch": epoch }),
            )
            .await
    }

    async fn upload_with(&self, dev: &Dev, headers: &[(&str, &str)], body: &[u8]) -> (StatusCode, Value) {
        let (s, _, b) =
            self.node.raw(Method::POST, &format!("{}/upload", self.base()), dev.token(), headers, body.to_vec()).await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// Uploads `body` as the ciphertext of a new file with a valid record.
    async fn upload(&self, dev: &Dev, parent: Option<&str>, body: &[u8]) -> (StatusCode, Value) {
        let id = new_id();
        let (record, epoch) = self.record(dev, &id, "file", SECRET_NAME);
        let epoch = epoch.to_string();
        let mut h = vec![
            ("tavrn-entry-id", id.as_str()),
            ("tavrn-record", record.as_str()),
            ("tavrn-record-epoch", epoch.as_str()),
            ("tavrn-upload-category", "documents"),
            ("content-type", "application/pdf"),
        ];
        if let Some(p) = parent {
            h.push(("tavrn-parent", p));
        }
        self.upload_with(dev, &h, body).await
    }

    async fn down(&self, token: &str, id: &str, range: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let headers: Vec<(&str, &str)> = range.map(|r| vec![("range", r)]).unwrap_or_default();
        let (s, h, b) =
            self.node.raw(Method::GET, &format!("{}/{id}/download", self.base()), token, &headers, Vec::new()).await;
        (s, h, b.to_vec())
    }

    async fn ls(&self, token: &str, query: &str) -> Value {
        let (s, j) = self.node.get_auth(&format!("{}?{query}", self.base()), token).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        j
    }

    async fn member_override(&self, user_id: &str, allow: u64, deny: u64) {
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                self.alice.token(),
                json!({ "target_type": "channel", "target_id": self.channel, "subject_type": "member",
                        "subject_id": user_id, "allow": allow.to_string(), "deny": deny.to_string() }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
}

async fn join(node: &TestNode, owner: &str, room_id: &str, token: &str) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

/// Alice owns a room with an encrypted files channel whose group holds Alice's and Bob's devices.
async fn setup() -> E {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let room = node.create_room(alice.token(), "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    join(&node, alice.token(), &room_id, bob.token()).await;
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), alice.token(), json!({ "kind": "files", "name": "Vault" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    assert_eq!(ch["encrypted"], true, "files channels are encrypted by default: {ch}");
    assert_eq!(ch["history_for_new_members"], "all", "files channels share their history by default: {ch}");
    let channel = ch["id"].as_str().unwrap().to_string();
    node.create_group(&mut alice, &channel).await;
    node.add_user(&mut alice, &channel, "bob").await;
    assert_eq!(node.accept_welcomes(&mut bob).await, 1);
    E { node, alice, bob, room_id, channel }
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn files_channels_are_encrypted_by_default_and_fixed_after_creation() {
    let s = setup().await;
    let channels = format!("/api/v1/rooms/{}/channels", s.room_id);
    let (st, plain) =
        s.node.post(&channels, s.alice.token(), json!({ "kind": "files", "name": "open", "encrypted": false })).await;
    assert_eq!((st, plain["encrypted"].as_bool()), (StatusCode::CREATED, Some(false)), "{plain}");
    let (st, enc) =
        s.node.post(&channels, s.alice.token(), json!({ "kind": "files", "name": "closed", "encrypted": true })).await;
    assert_eq!((st, enc["encrypted"].as_bool()), (StatusCode::CREATED, Some(true)), "{enc}");

    for (ch, value) in [(&s.channel, false), (&id(&plain), true)] {
        let (st, j) = s.node.patch(&format!("{channels}/{ch}"), s.alice.token(), json!({ "encrypted": value })).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.encryption_fixed")), "{j}");
    }
    // The same value is no change; the other settings keep working.
    let (st, j) = s
        .node
        .patch(&format!("{channels}/{}", s.channel), s.alice.token(), json!({ "encrypted": true, "topic": "Docs" }))
        .await;
    assert_eq!((st, j["topic"].as_str(), j["encrypted"].as_bool()), (StatusCode::OK, Some("Docs"), Some(true)), "{j}");
    // The history policy of files channels is all or nothing.
    let (st, j) = s
        .node
        .patch(&format!("{channels}/{}", s.channel), s.alice.token(), json!({ "history_for_new_members": "days:30" }))
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.history_policy_invalid")), "{j}");
    let (st, j) = s
        .node
        .patch(
            &format!("{channels}/{}", s.channel),
            s.alice.token(),
            json!({ "history_for_new_members": "since_join" }),
        )
        .await;
    assert_eq!((st, j["history_for_new_members"].as_str()), (StatusCode::OK, Some("since_join")), "{j}");
    assert_eq!(plain["history_for_new_members"], "all", "{plain}");
    // Text channels still switch.
    let room = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), s.alice.token()).await.1;
    let text = TestNode::text_channel(&room);
    let (st, j) = s.node.patch(&format!("{channels}/{text}"), s.alice.token(), json!({ "encrypted": false })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    // Still no messages.
    let (st, j) = s.node.send(s.alice.token(), &s.room_id, &s.channel, "hi").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.no_text")), "{j}");
    // The node announces the capability.
    let (_, wk) = s.node.get_auth("/.well-known/tavrn", s.alice.token()).await;
    assert!(wk["capabilities"].as_array().unwrap().iter().any(|c| c == "files.e2ee"), "{wk}");
}

#[tokio::test]
async fn the_group_of_a_files_channel_is_created_by_uploaders() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let room = node.create_room(alice.token(), "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    join(&node, alice.token(), &room_id, bob.token()).await;
    let (_, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), alice.token(), json!({ "kind": "files", "name": "f" }))
        .await;
    let channel = id(&ch);
    let (_, overrides) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            alice.token(),
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member",
                    "subject_id": bob.session.user_id, "allow": "0", "deny": perms(&[p::ATTACH_FILES]) }),
        )
        .await;
    assert!(overrides.is_array(), "{overrides}");
    let gi = bob.client.create_group(&qualified(&channel)).unwrap();
    let (st, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/mls/group"),
            bob.token(),
            json!({ "group_info": common::e2ee::b64(&gi) }),
        )
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.upload_forbidden")), "{j}");
    // Without send_messages but with attach_files the group can be created.
    let (_, _) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            alice.token(),
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member",
                    "subject_id": bob.session.user_id, "allow": "0", "deny": perms(&[p::SEND_MESSAGES]) }),
        )
        .await;
    let (st, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/mls/group"),
            bob.token(),
            json!({ "group_info": common::e2ee::b64(&gi) }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn entries_carry_records_and_the_node_stores_no_names() {
    let s = setup().await;
    let (st, folder) = s.folder(&s.alice, None, "Board secrets").await;
    assert_eq!(st, StatusCode::CREATED, "{folder}");
    assert_eq!((folder["name"].as_str(), folder["mime"].as_str()), (Some(""), Some("")), "{folder}");
    assert_eq!(folder["record_author"], format!("alice@{DOMAIN}"));
    assert_eq!(folder["record_device_id"], s.alice.session.device_id.as_str());
    assert_eq!(folder["record_epoch"], 1);
    let fid = id(&folder);

    let data = b"\x01ciphertext bytes that the node cannot read".to_vec();
    let (st, file) = s.upload(&s.bob, Some(&fid), &data).await;
    assert_eq!(st, StatusCode::CREATED, "{file}");
    assert_eq!((file["name"].as_str(), file["mime"].as_str()), (Some(""), Some("")), "{file}");
    assert_eq!((file["size"].as_i64(), file["parent_id"].as_str()), (Some(data.len() as i64), Some(fid.as_str())));
    assert_eq!(file["record_author"], format!("bob@{DOMAIN}"));
    assert!(file["record"].as_str().unwrap().len() > 100);
    let list = s.ls(s.alice.token(), &format!("parent={fid}")).await;
    assert_eq!(list["entries"][0]["record"], file["record"]);
    assert_eq!(list["path"][0]["id"], fid.as_str());

    // Nothing readable in any row, file name or the API: the name exists only inside the records.
    let rows: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT id, name, name_key, mime FROM file_entries").fetch_all(&s.node.state.db).await.unwrap();
    assert_eq!(rows.len(), 2);
    for (rid, name, key, mime) in &rows {
        assert_eq!((name.as_str(), mime.as_str()), ("", ""), "{rid}");
        assert_eq!(key, rid, "the unique name key is the id");
    }
    let dump: Vec<(String,)> = sqlx::query_as(
        "SELECT COALESCE(name, '') || COALESCE(mime, '') || COALESCE(sha256, '') || COALESCE(record, '') FROM file_entries",
    )
    .fetch_all(&s.node.state.db)
    .await
    .unwrap();
    // Whole plaintext values, not fragments: a three-letter fragment like "pdf" turns up in base64 ciphertext by
    // chance (one in a few hundred runs), a folder name or a MIME type does not.
    for (row,) in dump {
        assert!(!row.contains("Board secrets") && !row.contains(SECRET_NAME) && !row.contains("application/pdf"), "{row}");
    }
    // The node picks the storage id: client-chosen ids never name a stored file.
    let sid: String = sqlx::query_scalar("SELECT storage_id FROM file_entries WHERE id = $1")
        .bind(id(&file))
        .fetch_one(&s.node.state.db)
        .await
        .unwrap();
    assert_ne!(sid, id(&file));
    assert!(s.node.state.storage.path_of(&sid).unwrap().exists());
    assert!(!s.node.state.storage.path_of(&id(&file)).unwrap().exists());
    assert!(!list.to_string().contains("secret") && !list.to_string().contains("application/pdf"), "{list}");
}

#[tokio::test]
async fn encrypted_routes_refuse_plaintext_names_and_bad_records() {
    let s = setup().await;
    let base = s.base();
    let (st, j) = s.node.post(&format!("{base}/folders"), s.alice.token(), json!({ "name": "x" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.encrypted")), "{j}");
    let fid = new_id();
    let (record, epoch) = s.record(&s.alice, &fid, "folder", "x");
    let cases = [
        (json!({ "id": fid, "record": "not-base64!", "record_epoch": epoch }), "files.record_invalid"),
        (json!({ "id": fid, "record": "AQAA", "record_epoch": epoch }), "files.record_invalid"),
        (json!({ "id": fid, "record": record, "record_epoch": epoch + 1 }), "message.epoch_mismatch"),
        (json!({ "id": "nope", "record": record, "record_epoch": epoch }), "files.id_invalid"),
        (
            json!({ "id": ulid::Ulid::from_parts(1_000_000, 1).to_string(), "record": record, "record_epoch": epoch }),
            "files.id_invalid",
        ),
        (json!({ "record": record, "record_epoch": epoch }), "files.id_invalid"),
        (json!({ "id": fid, "record_epoch": epoch }), "files.record_invalid"),
    ];
    for (body, code) in cases {
        let (st, j) = s.node.post(&format!("{base}/folders"), s.alice.token(), body.clone()).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}: {j}");
    }
    let (st, j) = s
        .node
        .post(
            &format!("{base}/folders"),
            s.alice.token(),
            json!({ "id": fid, "record": record, "record_epoch": epoch }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (st, j) = s
        .node
        .post(
            &format!("{base}/folders"),
            s.alice.token(),
            json!({ "id": fid, "record": record, "record_epoch": epoch }),
        )
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("files.id_taken")), "{j}");

    // Uploads: a plaintext name or conflict mode is refused, the category must be declared.
    let uid = new_id();
    let (record, epoch) = s.record(&s.alice, &uid, "file", "a.pdf");
    let epoch = epoch.to_string();
    let good = [
        ("tavrn-entry-id", uid.as_str()),
        ("tavrn-record", record.as_str()),
        ("tavrn-record-epoch", epoch.as_str()),
        ("tavrn-upload-category", "documents"),
    ];
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut h = good.to_vec();
        h.extend_from_slice(extra);
        h
    };
    for (headers, code) in [
        (with(&[("tavrn-file-name", "a.pdf")]), "files.encrypted"),
        (with(&[("tavrn-conflict", "rename")]), "files.encrypted"),
        ([&good[..3], &[("tavrn-upload-category", "pictures")]].concat(), "upload.category_invalid"),
        (with(&[("tavrn-upload-category", "pictures")]).into_iter().skip(1).collect(), "files.id_invalid"),
    ] {
        let (st, j) = s.upload_with(&s.alice, &headers, b"x").await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{headers:?}: {j}");
    }
    // Categories are checked against the declaration (cooperative enforcement).
    let denied = tavrn_node::uploads::DOCUMENTS;
    let (st, j) = s
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            s.alice.token(),
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "member",
                    "subject_id": s.bob.session.user_id, "allow": "0", "deny": "0",
                    "upload_deny": tavrn_node::uploads::names(denied) }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.upload(&s.bob, None, b"doc").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("upload.type_forbidden")), "{j}");
    // Search is the clients' job.
    let (st, j) = s.node.get_auth(&format!("{base}?q=plan"), s.alice.token()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.search_unavailable")), "{j}");
}

#[tokio::test]
async fn downloads_serve_the_ciphertext_with_ranges() {
    let s = setup().await;
    let data: Vec<u8> = (0..150_000u32).map(|i| (i % 249) as u8).collect();
    let (st, f) = s.upload(&s.alice, None, &data).await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    let fid = id(&f);
    let (st, h, body) = s.down(s.bob.token(), &fid, None).await;
    assert_eq!((st, body.len()), (StatusCode::OK, data.len()));
    assert_eq!(body, data);
    assert_eq!(h["content-type"], "application/octet-stream");
    assert!(h["content-disposition"].to_str().unwrap().contains(&format!("filename=\"{fid}\"")), "{h:?}");
    let (st, h, part) = s.down(s.bob.token(), &fid, Some("bytes=1048-2095")).await;
    assert_eq!((st, part.as_slice()), (StatusCode::PARTIAL_CONTENT, &data[1048..=2095]));
    assert_eq!(h["content-range"], format!("bytes 1048-2095/{}", data.len()).as_str());
    // Quota and usage count the ciphertext.
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), s.bob.token()).await;
    assert_eq!((usage["used_bytes"].as_i64(), usage["encrypted"].as_bool()), (Some(150_000), Some(true)), "{usage}");
}

#[tokio::test]
async fn renames_write_new_records_and_moves_keep_them() {
    let mut s = setup().await;
    let (_, folder) = s.folder(&s.alice, None, "A").await;
    let (_, f) = s.upload(&s.alice, None, b"abc").await;
    let fid = id(&f);
    let path = format!("{}/{fid}", s.base());
    let (st, j) = s.node.patch(&path, s.alice.token(), json!({ "name": "plain.txt" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.encrypted")), "{j}");
    // Bob may not rename Alice's file without manage_files.
    s.member_override(&s.bob.session.user_id.clone(), 0, p::MANAGE_FILES).await;
    let (record, epoch) = s.record(&s.bob, &fid, "file", "bob.txt");
    let (st, j) = s.node.patch(&path, s.bob.token(), json!({ "record": record, "record_epoch": epoch })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.manage_forbidden")), "{j}");
    // A self update moves the group on: the rename is written under the new epoch.
    let q = qualified(&s.channel);
    let out = s.alice.client.self_update(&q).unwrap();
    let (st, j) = s.node.post_commit(s.alice.token(), &s.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    s.alice.client.merge_pending_commit(&q).unwrap();
    let (record, epoch) = s.record(&s.alice, &fid, "file", "renamed.txt");
    assert_eq!(epoch, 2);
    let (st, j) = s.node.patch(&path, s.alice.token(), json!({ "record": record, "record_epoch": epoch })).await;
    assert_eq!(
        (st, j["record_epoch"].as_i64(), j["record"].as_str()),
        (StatusCode::OK, Some(2), Some(record.as_str()))
    );
    // A move keeps the record.
    let (st, j) = s.node.patch(&path, s.alice.token(), json!({ "parent_id": id(&folder) })).await;
    assert_eq!(
        (st, j["record"].as_str(), j["parent_id"].as_str()),
        (StatusCode::OK, Some(record.as_str()), Some(id(&folder).as_str()))
    );
}

#[tokio::test]
async fn thumbnails_are_kept_next_to_their_entry() {
    let s = setup().await;
    let (_, f) = s.upload(&s.alice, None, b"photo ciphertext").await;
    let fid = id(&f);
    let thumb = format!("{}/{fid}/thumbnail", s.base());
    let (st, j) = s.node.get_auth(&thumb, s.bob.token()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("files.no_thumbnail")), "{j}");
    let (st, _, b) = s.node.raw(Method::PUT, &thumb, s.bob.token(), &[], b"bob's".to_vec()).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&b));
    let (st, _, b) = s.node.raw(Method::PUT, &thumb, s.alice.token(), &[], vec![7u8; 1024 * 1024 + 1]).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&b));
    let (st, _, _) = s.node.raw(Method::PUT, &thumb, s.alice.token(), &[], vec![9u8; 4000]).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, h, body) = s.node.raw(Method::GET, &thumb, s.bob.token(), &[], Vec::new()).await;
    assert_eq!((st, body.len()), (StatusCode::OK, 4000));
    assert_eq!(h["content-type"], "application/octet-stream");
    let (_, list) = s.node.get_auth(&s.base(), s.bob.token()).await;
    assert_eq!(list["entries"][0]["thumbnail_size"], 4000);
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), s.bob.token()).await;
    assert_eq!(usage["used_bytes"].as_i64(), Some(16 + 4000), "thumbnails count: {usage}");
    // The orphan sweep knows thumbnails; a delete removes them.
    let r = tavrn_node::housekeeping::sweep_orphans(&s.node.state, chrono::Utc::now() + chrono::Duration::days(2))
        .await
        .unwrap();
    assert_eq!((r.files, r.file_entries), (0, 0), "{r:?}");
    let (_, again) = s.node.raw(Method::GET, &thumb, s.bob.token(), &[], Vec::new()).await.into_parts_status();
    assert_eq!(again, StatusCode::OK);
    let stored: String = sqlx::query_scalar("SELECT thumbnail_id FROM file_entries WHERE id = $1")
        .bind(&fid)
        .fetch_one(&s.node.state.db)
        .await
        .unwrap();
    let (st, j) = s.node.delete(&format!("{}/{fid}", s.base()), s.alice.token()).await;
    assert_eq!((st, j["bytes"].as_u64()), (StatusCode::OK, Some(16 + 4000)), "{j}");
    assert!(!s.node.state.storage.path_of(&stored).unwrap().exists());

    // Unencrypted channels have no thumbnails and no records route.
    let (_, plain) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", s.room_id),
            s.alice.token(),
            json!({ "kind": "files", "name": "open", "encrypted": false }),
        )
        .await;
    let base = format!("/api/v1/rooms/{}/channels/{}/files", s.room_id, id(&plain));
    let (st, j) = s.node.get_auth(&format!("{base}/records"), s.alice.token()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.not_encrypted")), "{j}");
}

trait StatusOnly {
    fn into_parts_status(self) -> ((), StatusCode);
}
impl StatusOnly for (StatusCode, HeaderMap, axum::body::Bytes) {
    fn into_parts_status(self) -> ((), StatusCode) {
        ((), self.0)
    }
}

#[tokio::test]
async fn own_entries_are_listed_and_deleted_without_keys() {
    let s = setup().await;
    let (_, af) = s.upload(&s.alice, None, b"alice").await;
    let (_, folder) = s.folder(&s.bob, None, "Bob's").await;
    let (_, b1) = s.upload(&s.bob, Some(&id(&folder)), b"bob one").await;
    let (_, b2) = s.upload(&s.bob, None, b"bob two!").await;
    let (st, mine) = s.node.get_auth(&format!("{}/mine?limit=2", s.base()), s.bob.token()).await;
    assert_eq!(st, StatusCode::OK, "{mine}");
    assert_eq!(
        (mine["files"].as_i64(), mine["folders"].as_i64(), mine["bytes"].as_i64()),
        (Some(2), Some(1), Some(15))
    );
    let ids: Vec<&str> = mine["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [id(&folder), id(&b1)], "oldest first");
    assert!(mine["entries"][0]["record"].is_null(), "no records in mine: {mine}");
    let after = mine["next_after"].as_str().unwrap();
    let (_, rest) = s.node.get_auth(&format!("{}/mine?after={after}", s.base()), s.bob.token()).await;
    assert_eq!(rest["entries"][0]["id"], id(&b2).as_str());
    assert!(rest["next_after"].is_null());
    // A member without any key material deletes by ownership; others' entries stay protected.
    let (st, _) = s.node.delete(&format!("{}/{}", s.base(), id(&b2)), s.bob.token()).await;
    assert_eq!(st, StatusCode::OK);
    let (st, j) = s.node.delete(&format!("{}/{}", s.base(), id(&af)), s.bob.token()).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{j}");
    let (st, j) = s.node.delete(&format!("{}/{}", s.base(), id(&folder)), s.bob.token()).await;
    assert_eq!((st, j["files"].as_u64(), j["folders"].as_u64()), (StatusCode::OK, Some(1), Some(1)), "{j}");
    let (_, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), s.alice.token()).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "files.delete").unwrap();
    assert_eq!(entry["meta"]["name"], "", "no names in the audit log of encrypted channels: {entry}");
}

#[tokio::test]
async fn records_outside_the_history_window_are_not_served() {
    let mut s = setup().await;
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel),
            s.alice.token(),
            json!({ "history_for_new_members": "since_join" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (_, old) = s.upload(&s.alice, None, b"old").await;
    let carol = s.node.crypto_user("carol").await;
    join(&s.node, s.alice.token(), &s.room_id, carol.token()).await;
    // The old record was written when Alice joined, before Carol did.
    let alice_joined: String = sqlx::query_scalar("SELECT joined_at FROM room_members WHERE user_id = $1")
        .bind(&s.alice.session.user_id)
        .fetch_one(&s.node.state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE file_entries SET record_at = $1 WHERE id = $2")
        .bind(&alice_joined)
        .bind(id(&old))
        .execute(&s.node.state.db)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (_, new) = s.upload(&s.alice, None, b"new").await;

    let list = s.ls(carol.token(), "").await;
    let by_id = |l: &Value, i: &str| l["entries"].as_array().unwrap().iter().find(|e| e["id"] == i).unwrap().clone();
    let o = by_id(&list, &id(&old));
    assert!(o["record"].is_null() && o["record_epoch"].is_null() && o["record_author"].is_null(), "{o}");
    assert!(by_id(&list, &id(&new))["record"].is_string());
    let (_, one) = s.node.get_auth(&format!("{}/{}", s.base(), id(&old)), carol.token()).await;
    assert!(one["entry"]["record"].is_null(), "{one}");
    let (st, recs) = s.node.get_auth(&format!("{}/records", s.base()), carol.token()).await;
    assert_eq!(st, StatusCode::OK, "{recs}");
    let ids: Vec<&str> = recs["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [id(&new)]);
    // The ciphertext stays downloadable (useless without the record).
    assert_eq!(s.down(carol.token(), &id(&old), None).await.0, StatusCode::OK);
    // Alice (member since the start) sees both; the policy `all` opens the window for Carol.
    let (_, recs) = s.node.get_auth(&format!("{}/records", s.base()), s.alice.token()).await;
    assert_eq!(recs["entries"].as_array().unwrap().len(), 2);
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel),
            s.alice.token(),
            json!({ "history_for_new_members": "all" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert!(by_id(&s.ls(carol.token(), "").await, &id(&old))["record"].is_string());

    // Filters and paging of the records route.
    let q = qualified(&s.channel);
    let out = s.alice.client.self_update(&q).unwrap();
    s.node.post_commit(s.alice.token(), &s.channel, &out).await;
    s.alice.client.merge_pending_commit(&q).unwrap();
    let (_, third) = s.upload(&s.alice, None, b"third").await;
    let (_, recs) = s.node.get_auth(&format!("{}/records?epoch=2", s.base()), carol.token()).await;
    assert_eq!(recs["entries"].as_array().unwrap().len(), 1);
    assert_eq!(recs["entries"][0]["id"], id(&third).as_str());
    let since = new["created_at"].as_str().unwrap();
    let (_, recs) = s
        .node
        .get_auth(&format!("{}/records?since={}&limit=1", s.base(), urlencoding_lite(since)), carol.token())
        .await;
    assert_eq!(recs["entries"][0]["id"], id(&new).as_str(), "{recs}");
    let after = recs["next_after"].as_str().unwrap();
    let (_, recs) = s.node.get_auth(&format!("{}/records?after={after}", s.base()), carol.token()).await;
    assert_eq!(recs["entries"][0]["id"], id(&third).as_str(), "{recs}");
    let (st, j) = s.node.get_auth(&format!("{}/records?since=yesterday", s.base()), carol.token()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{j}");
}

fn urlencoding_lite(s: &str) -> String {
    s.replace(':', "%3A").replace('+', "%2B")
}

#[tokio::test]
async fn new_members_wait_for_keys_when_records_are_in_their_window() {
    let s = setup().await;
    s.upload(&s.alice, None, b"before carol").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let mut carol = s.node.crypto_user("carol").await;
    join(&s.node, s.alice.token(), &s.room_id, carol.token()).await;
    let (st, gi) = s.node.get_auth(&format!("/api/v1/conversations/{}/mls/group-info", s.channel), carol.token()).await;
    assert_eq!(st, StatusCode::OK, "{gi}");
    let out =
        carol.client.join_by_external_commit(&qualified(&s.channel), &common::e2ee::unb64(&gi["group_info"])).unwrap();
    let (st, j) = s.node.post_commit(carol.token(), &s.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (_, pending) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", s.channel), s.alice.token()).await;
    assert_eq!(pending["items"][0]["user"], format!("carol@{DOMAIN}"), "{pending}");
}

/// Carol joins the room, Alice uploads `after_join` (or nothing), then Carol's device joins the files channel's group
/// under `since_join`: the members waiting for keys.
async fn since_join_pending(upload_after_join: bool) -> Value {
    let s = setup().await;
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel),
            s.alice.token(),
            json!({ "history_for_new_members": "since_join" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    s.upload(&s.alice, None, b"before carol").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let mut carol = s.node.crypto_user("carol").await;
    join(&s.node, s.alice.token(), &s.room_id, carol.token()).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    if upload_after_join {
        s.upload(&s.alice, None, b"since carol joined").await;
    }
    let (st, gi) = s.node.get_auth(&format!("/api/v1/conversations/{}/mls/group-info", s.channel), carol.token()).await;
    assert_eq!(st, StatusCode::OK, "{gi}");
    let out =
        carol.client.join_by_external_commit(&qualified(&s.channel), &common::e2ee::unb64(&gi["group_info"])).unwrap();
    let (st, j) = s.node.post_commit(carol.token(), &s.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (_, pending) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", s.channel), s.alice.token()).await;
    pending
}

#[tokio::test]
async fn under_since_join_records_since_the_join_make_a_member_wait() {
    // Records from before the join never count.
    let pending = since_join_pending(false).await;
    assert_eq!(pending["items"], json!([]), "{pending}");
    // A record written after Carol's room join, before her device entered the group, does.
    let pending = since_join_pending(true).await;
    assert_eq!(pending["items"][0]["user"], format!("carol@{DOMAIN}"), "{pending}");
}

#[tokio::test]
async fn usage_names_the_store_only_for_managers() {
    let s = setup().await;
    let (_, mine) = s.node.get_auth(&format!("{}/usage", s.base()), s.alice.token()).await;
    assert_eq!((mine["backend_host"].as_str(), mine["backend_prefix"].as_str()), (Some(""), Some("")), "{mine}");
    let (_, bobs) = s.node.get_auth(&format!("{}/usage", s.base()), s.bob.token()).await;
    assert!(bobs["backend_host"].is_null(), "{bobs}");
}

/// Bob resets his security key and his new device rejoins the files channel's group (ENCRYPTION.md §7b).
async fn reset_and_rejoin(s: &E, upload_after_reset: bool) -> Value {
    s.upload(&s.alice, None, b"before the reset").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let fresh = tavrn_crypto::MasterSecret::generate().unwrap();
    let (st, j) = s
        .node
        .post(
            "/api/v1/users/me/identity/reset",
            s.bob.token(),
            json!({ "identity_public_key": common::e2ee::b64(&fresh.identity_public_key()), "password": common::password("bob") }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let session = s.node.login("bob").await;
    let mut bob = s.node.attest(session, fresh, 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    if upload_after_reset {
        s.upload(&s.alice, None, b"after the reset").await;
    }
    let (st, gi) = s.node.get_auth(&format!("/api/v1/conversations/{}/mls/group-info", s.channel), bob.token()).await;
    assert_eq!(st, StatusCode::OK, "{gi}");
    let out =
        bob.client.join_by_external_commit(&qualified(&s.channel), &common::e2ee::unb64(&gi["group_info"])).unwrap();
    let (st, j) = s.node.post_commit(bob.token(), &s.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (_, pending) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", s.channel), s.alice.token()).await;
    pending
}

#[tokio::test]
async fn after_a_key_reset_only_records_since_the_reset_make_a_member_wait() {
    // Records from before the reset never count: nothing to wait for.
    let s = setup().await;
    let pending = reset_and_rejoin(&s, false).await;
    assert_eq!(pending["items"].as_array().unwrap().len(), 0, "{pending}");

    // A record written since the reset makes Bob's new device wait, with the reset window.
    let s = setup().await;
    let pending = reset_and_rejoin(&s, true).await;
    let item = &pending["items"][0];
    assert_eq!(item["user"], format!("bob@{DOMAIN}"), "{pending}");
    assert!(item["key_reset_at"].is_string() && item["min_epoch"].is_i64(), "{item}");
}

/// After a key reset the records route, the listing and single entries serve only records written since the reset,
/// whatever the policy (ENCRYPTION.md §7b "History after a key reset", FILES.md §8.7).
#[tokio::test]
async fn after_a_key_reset_records_from_before_it_are_not_served() {
    let s = setup().await;
    let (_, before) = s.upload(&s.alice, None, b"before").await;
    // Bob reset (policy `all`): his new device joins and must not get the old record.
    reset_and_rejoin(&s, true).await;
    let bob = s.node.login("bob").await;
    let (st, recs) = s.node.get_auth(&format!("{}/records", s.base()), &bob.token).await;
    assert_eq!(st, StatusCode::OK, "{recs}");
    let ids: Vec<&str> = recs["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(!ids.is_empty(), "the record written after the reset is served: {recs}");
    assert!(!ids.contains(&id(&before).as_str()), "no record from before the reset: {recs}");
    let list = s.ls(&bob.token, "").await;
    let old = list["entries"].as_array().unwrap().iter().find(|e| e["id"] == id(&before).as_str()).unwrap().clone();
    assert!(old["record"].is_null(), "{old}");
    let (_, one) = s.node.get_auth(&format!("{}/{}", s.base(), id(&before)), &bob.token).await;
    assert!(one["entry"]["record"].is_null(), "{one}");
    // Alice (no reset) keeps every record.
    let (_, recs) = s.node.get_auth(&format!("{}/records", s.base()), s.alice.token()).await;
    assert!(recs["entries"].as_array().unwrap().iter().any(|e| e["id"] == id(&before).as_str()), "{recs}");
}
