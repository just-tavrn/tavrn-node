// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! External stores of files channels (protocol/FILES.md §5): WebDAV and S3-compatible
//! storage against in-process mock servers, the encryption toggle, secrets that never leave the node, the
//! switching rule and the SSRF refusals.
use crate::common;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use common::{Session, TestNode, test_node_with};
use serde_json::{Value, json};
use tavrn_node::config::Switch;

const DOMAIN: &str = "t.local";

// ---------------------------------------------------------------- Mock stores

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    WebDav,
    S3,
}

#[derive(Default)]
struct Store {
    objects: HashMap<String, Vec<u8>>,
    collections: HashSet<String>,
    /// Requests whose authentication failed.
    refused: u32,
    /// S3 requests whose signature was verified.
    verified: u32,
    /// Answer every DELETE with 503 (an unreachable or broken store).
    fail_deletes: bool,
}

#[derive(Clone)]
struct Mock {
    flavor: Flavor,
    store: Arc<Mutex<Store>>,
}

const DAV_USER: &str = "dav";
const DAV_PASS: &str = "dav-secret-pw";
const S3_ACCESS: &str = "AKIDEXAMPLE";
const S3_SECRET: &str = "s3-secret-key-123";

fn ranged(data: &[u8], headers: &HeaderMap) -> Response {
    let len = data.len();
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok()).and_then(|r| r.strip_prefix("bytes="));
    if let Some((a, b)) = range.and_then(|r| r.split_once('-')) {
        let start: usize = a.parse().unwrap();
        let end: usize = if b.is_empty() { len - 1 } else { b.parse::<usize>().unwrap().min(len - 1) };
        let mut resp = data[start..=end].to_vec().into_response();
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        resp.headers_mut().insert(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}").parse().unwrap());
        return resp;
    }
    data.to_vec().into_response()
}

fn authorized(m: &Mock, method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    match m.flavor {
        Flavor::WebDav => {
            let expected =
                format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{DAV_USER}:{DAV_PASS}")));
            headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(expected.as_str())
        }
        Flavor::S3 => {
            let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let (date, sha) = (get("x-amz-date"), get("x-amz-content-sha256"));
            let url = reqwest::Url::parse(&format!("http://{}{}", get("host"), uri)).unwrap();
            let signed = vec![
                ("host".to_string(), get("host")),
                ("x-amz-content-sha256".to_string(), sha.clone()),
                ("x-amz-date".to_string(), date.clone()),
            ];
            let signer = tavrn_node::files::sigv4::Signer {
                access_key: S3_ACCESS,
                secret_key: S3_SECRET,
                region: "eu-test-1",
                service: "s3",
            };
            let ok = sha == "UNSIGNED-PAYLOAD"
                && get("authorization") == signer.authorization(method.as_str(), &url, &signed, &sha, &date);
            if ok {
                m.store.lock().unwrap().verified += 1;
            }
            ok
        }
    }
}

async fn handle(State(m): State<Mock>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&m, &method, &uri, &headers) {
        m.store.lock().unwrap().refused += 1;
        return StatusCode::FORBIDDEN.into_response();
    }
    let path = uri.path().to_string();
    let mut st = m.store.lock().unwrap();
    match method.as_str() {
        "PROPFIND" => {
            (StatusCode::MULTI_STATUS, "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"/>").into_response()
        }
        "MKCOL" => {
            if st.collections.insert(path) {
                StatusCode::CREATED.into_response()
            } else {
                StatusCode::METHOD_NOT_ALLOWED.into_response()
            }
        }
        "HEAD" if m.flavor == Flavor::S3 && path == "/files" => StatusCode::OK.into_response(),
        "PUT" => {
            if m.flavor == Flavor::WebDav {
                let parent = &path[..path.rfind('/').unwrap() + 1];
                if parent != "/dav/" && !st.collections.contains(parent) {
                    return StatusCode::CONFLICT.into_response();
                }
            }
            let declared: usize = headers[header::CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
            assert_eq!(declared, body.len(), "Content-Length matches the streamed body");
            st.objects.insert(path, body.to_vec());
            StatusCode::CREATED.into_response()
        }
        "GET" => match st.objects.get(&path) {
            Some(data) => ranged(data, &headers),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        "DELETE" if st.fail_deletes => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        "DELETE" => match st.objects.remove(&path) {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn mock(flavor: Flavor) -> (Mock, u16) {
    let m = Mock { flavor, store: Arc::default() };
    let app = Router::new().fallback(handle).with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (m, port)
}

// ---------------------------------------------------------------- Setup

struct Setup {
    node: TestNode,
    alice: Session,
    room_id: String,
    channel: String,
}

impl Setup {
    fn base(&self) -> String {
        format!("/api/v1/rooms/{}/channels/{}/files", self.room_id, self.channel)
    }

    async fn up(&self, name: &str, data: &[u8]) -> (StatusCode, Value) {
        let len = data.len().to_string();
        let (s, _, body) = self
            .node
            .raw(
                Method::POST,
                &format!("{}/upload", self.base()),
                &self.alice.token,
                &[("tavrn-file-name", name), ("content-type", "application/octet-stream"), ("content-length", &len)],
                data.to_vec(),
            )
            .await;
        (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    async fn down(&self, id: &str, range: Option<&str>) -> (StatusCode, Vec<u8>) {
        let headers: Vec<(&str, &str)> = range.map(|r| vec![("range", r)]).unwrap_or_default();
        let (s, _, b) = self
            .node
            .raw(Method::GET, &format!("{}/{id}/download", self.base()), &self.alice.token, &headers, Vec::new())
            .await;
        (s, b.to_vec())
    }

    async fn backend(&self, body: Value) -> (StatusCode, Value) {
        self.node.put(&format!("{}/backend", self.base()), &self.alice.token, body).await
    }

    async fn test(&self, body: Option<Value>) -> (StatusCode, Value) {
        self.node.req(Method::POST, &format!("{}/backend/test", self.base()), Some(&self.alice.token), body).await
    }
}

async fn setup(external: Switch, private: Switch) -> Setup {
    setup_with(|c| {
        c.files_external = external;
        c.files_external_private = private;
    })
    .await
}

/// A node configured by `tweak`, Alice's room and an unencrypted files channel in it.
async fn setup_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Setup {
    let node = test_node_with(DOMAIN, tweak).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "R").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "files", "name": "f", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    Setup { node, alice, room_id, channel: ch["id"].as_str().unwrap().to_string() }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..common::rounds(100) {
        if check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    unreachable!("condition not reached");
}

// ---------------------------------------------------------------- Tests

#[tokio::test]
async fn external_stores_are_off_by_default_and_refuse_private_targets() {
    let s = setup(Switch::Off, Switch::Off).await;
    let (st, j) = s.backend(json!({ "kind": "webdav", "url": "https://dav.example.com/" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.external_disabled")), "{j}");
    let (st, j) = s.backend(json!({ "kind": "internal" })).await;
    assert_eq!(
        (st, j["kind"].as_str(), j["external_allowed"].as_bool()),
        (StatusCode::OK, Some("internal"), Some(false)),
        "{j}"
    );

    let s = setup(Switch::On, Switch::Off).await;
    let cases = [
        (json!({ "kind": "webdav", "url": "http://dav.example.com/" }), "files.backend_https_required"),
        (json!({ "kind": "webdav", "url": "https://127.0.0.1:9/" }), "files.backend_address_forbidden"),
        (json!({ "kind": "webdav", "url": "https://[::1]/" }), "files.backend_address_forbidden"),
        (json!({ "kind": "webdav", "url": "https://169.254.169.254/latest/" }), "files.backend_address_forbidden"),
        (json!({ "kind": "webdav", "url": "https://localhost:9/" }), "files.backend_address_forbidden"),
        (json!({ "kind": "webdav", "url": "https://user:pw@dav.example.com/" }), "files.backend_invalid"),
        (
            json!({ "kind": "s3", "url": "https://localhost:9", "bucket": "files", "access_key": "a", "secret_key": "b" }),
            "files.backend_address_forbidden",
        ),
        (
            json!({ "kind": "s3", "url": "https://10.0.0.1", "bucket": "files", "access_key": "a", "secret_key": "b" }),
            "files.backend_address_forbidden",
        ),
        (
            json!({ "kind": "s3", "url": "https://s3.example.com", "bucket": "Bad_Bucket", "access_key": "a", "secret_key": "b" }),
            "files.backend_invalid",
        ),
        (json!({ "kind": "ftp", "url": "https://x.example.com" }), "validation.enum"),
    ];
    for (body, code) in cases {
        let (st, j) = s.backend(body.clone()).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "PUT {body}: {j}");
        let (st, j) = s.test(Some(body.clone())).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "test {body}: {j}");
    }
    let (_, info) = s.node.get_auth(&format!("{}/backend", s.base()), &s.alice.token).await;
    assert_eq!(info["kind"], "internal", "nothing was stored");
}

#[tokio::test]
async fn webdav_store_streams_files_and_keeps_its_secret() {
    let (m, port) = mock(Flavor::WebDav).await;
    let s = setup(Switch::On, Switch::On).await;
    let url = format!("http://127.0.0.1:{port}/dav/");
    let (st, info) =
        s.backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "password": DAV_PASS })).await;
    assert_eq!(st, StatusCode::OK, "{info}");
    assert_eq!((info["kind"].as_str(), info["password_set"].as_bool()), (Some("webdav"), Some(true)));
    assert_eq!(info["prefix"], format!("tavrn/{}/", s.channel).as_str());
    assert!(!info.to_string().contains(DAV_PASS), "the password is never returned: {info}");
    assert!(m.store.lock().unwrap().collections.contains(&format!("/dav/tavrn/{}/", s.channel)), "prefix created");
    let (st, j) = s.test(None).await;
    assert_eq!((st, j["ok"].as_bool()), (StatusCode::OK, Some(true)), "{j}");
    // Stored encrypted with secrets.key, never in the audit log.
    let raw: String =
        sqlx::query_scalar("SELECT config FROM file_channel_backends").fetch_one(&s.node.state.db).await.unwrap();
    assert!(!raw.contains(DAV_PASS) && !raw.contains("127.0.0.1"), "configuration is encrypted at rest");
    let (_, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), &s.alice.token).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "files.backend").expect("audit entry").clone();
    assert!(!entry.to_string().contains(DAV_PASS), "{entry}");
    assert_eq!(entry["meta"]["kind"], "webdav");

    // A plain upload lands as is under prefix + entry id.
    let data = sample(150_000);
    let (st, f) = s.up("big.dat", &data).await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    let fid = f["id"].as_str().unwrap().to_string();
    let key = format!("/dav/tavrn/{}/{fid}", s.channel);
    assert_eq!(m.store.lock().unwrap().objects.get(&key), Some(&data), "readable outside tavrn");
    assert!(s.node.state.storage.path_of(&fid).map(|p| !p.exists()).unwrap(), "nothing stored on the node");
    assert_eq!(s.down(&fid, None).await, (StatusCode::OK, data.clone()));
    let (st, part) = s.down(&fid, Some("bytes=70000-70009")).await;
    assert_eq!((st, part.as_slice()), (StatusCode::PARTIAL_CONTENT, &data[70000..70010]));
    // Rename: metadata only.
    let (st, _) = s.node.patch(&format!("{}/{fid}", s.base()), &s.alice.token, json!({ "name": "renamed.dat" })).await;
    assert_eq!(st, StatusCode::OK);
    assert!(m.store.lock().unwrap().objects.contains_key(&key));
    // Without Content-Length an external upload is refused.
    let (st, _, body) = s
        .node
        .raw(
            Method::POST,
            &format!("{}/upload", s.base()),
            &s.alice.token,
            &[("tavrn-file-name", "x.dat")],
            b"xyz".to_vec(),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&body));

    // Encryption on (credentials kept by leaving the password empty): new files are sealed on the store.
    let (st, info) = s
        .backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "password": "", "encrypt_files": true }))
        .await;
    assert_eq!((st, info["encrypt_files"].as_bool()), (StatusCode::OK, Some(true)), "{info}");
    let (st, g) = s.up("sealed.dat", &data).await;
    assert_eq!(st, StatusCode::CREATED, "{g}");
    let gid = g["id"].as_str().unwrap().to_string();
    let gkey = format!("/dav/tavrn/{}/{gid}", s.channel);
    let stored = m.store.lock().unwrap().objects.get(&gkey).cloned().unwrap();
    assert!(stored.starts_with(&tavrn_node::storage::MAGIC), "wrapped with the storage format");
    assert_eq!(stored.len() as u64, tavrn_node::storage::encrypted_len(data.len() as u64));
    assert!(!stored.windows(64).any(|w| w == &data[1000..1064]), "no plaintext on the store");
    assert_eq!(s.down(&gid, None).await, (StatusCode::OK, data.clone()));
    for (range, a, b) in [
        ("bytes=65530-65545", 65530, 65545),
        ("bytes=0-0", 0, 0),
        ("bytes=149990-", 149_990, 149_999),
        ("bytes=131000-140000", 131_000, 140_000),
    ] {
        let (st, part) = s.down(&gid, Some(range)).await;
        assert_eq!((st, part.as_slice()), (StatusCode::PARTIAL_CONTENT, &data[a..=b]), "{range}");
    }
    // The plain file stays readable after the toggle.
    assert_eq!(s.down(&fid, None).await.1, data);

    // Switching the store while files exist is refused; credentials alone may change.
    let (st, j) = s
        .backend(json!({ "kind": "webdav", "url": format!("http://127.0.0.1:{port}/other/"), "username": DAV_USER }))
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("files.backend_not_empty")), "{j}");
    let (st, j) = s.backend(json!({ "kind": "internal" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("files.backend_not_empty")), "{j}");

    // Deleting removes the objects (in the background) and the file key.
    let (st, r) = s.node.delete(&format!("{}/{gid}", s.base()), &s.alice.token).await;
    assert_eq!((st, r["files"].as_u64()), (StatusCode::OK, Some(1)));
    let store = m.store.clone();
    eventually(|| !store.lock().unwrap().objects.contains_key(&gkey)).await;
    assert!(s.node.state.storage.external_key(&gid).await.is_err());
    s.node.delete(&format!("{}/{fid}", s.base()), &s.alice.token).await;
    eventually(|| !store.lock().unwrap().objects.contains_key(&key)).await;
    // Empty again: switching back to internal works.
    let (st, j) = s.backend(json!({ "kind": "internal" })).await;
    assert_eq!((st, j["kind"].as_str()), (StatusCode::OK, Some("internal")), "{j}");
    assert_eq!(m.store.lock().unwrap().refused, 0);

    // Wrong credentials: the test reports the store's answer.
    let (st, j) =
        s.test(Some(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "password": "wrong" }))).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("files.backend_failed")), "{j}");
}

#[tokio::test]
async fn s3_store_signs_every_request() {
    let (m, port) = mock(Flavor::S3).await;
    let s = setup(Switch::On, Switch::On).await;
    let config = json!({
        "kind": "s3", "url": format!("http://127.0.0.1:{port}"), "bucket": "files", "region": "eu-test-1",
        "access_key": S3_ACCESS, "secret_key": S3_SECRET, "prefix": "share", "encrypt_files": true,
    });
    let (st, j) = s.test(Some(config.clone())).await;
    assert_eq!((st, j["ok"].as_bool()), (StatusCode::OK, Some(true)), "{j}");
    let (st, info) = s.backend(config.clone()).await;
    assert_eq!(st, StatusCode::OK, "{info}");
    assert_eq!((info["secret_key_set"].as_bool(), info["prefix"].as_str()), (Some(true), Some("share/")));
    assert!(!info.to_string().contains(S3_SECRET));

    let data = sample(70_000);
    let (st, f) = s.up("clip.dat", &data).await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    let fid = f["id"].as_str().unwrap().to_string();
    let stored = m
        .store
        .lock()
        .unwrap()
        .objects
        .get(&format!("/files/share/{fid}"))
        .cloned()
        .expect("object under bucket/prefix/id");
    assert!(stored.starts_with(&tavrn_node::storage::MAGIC));
    assert_eq!(s.down(&fid, None).await, (StatusCode::OK, data.clone()));
    let (st, part) = s.down(&fid, Some("bytes=65536-65600")).await;
    assert_eq!((st, part.as_slice()), (StatusCode::PARTIAL_CONTENT, &data[65536..=65600]));
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!(
        (usage["backend"].as_str(), usage["encrypt_files"].as_bool(), usage["used_bytes"].as_i64()),
        (Some("s3"), Some(true), Some(70_000))
    );
    s.node.delete(&format!("{}/{fid}", s.base()), &s.alice.token).await;
    let store = m.store.clone();
    eventually(|| store.lock().unwrap().objects.is_empty()).await;
    let (refused, verified) = {
        let st = m.store.lock().unwrap();
        (st.refused, st.verified)
    };
    assert_eq!(refused, 0, "every request carried a valid signature");
    assert!(verified >= 6, "{verified}");

    // A wrong secret is refused by the store.
    let mut wrong = config.clone();
    wrong["secret_key"] = json!("not-the-secret");
    let (st, j) = s.test(Some(wrong)).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("files.backend_failed")), "{j}");
    // An unreachable store.
    let mut gone = config;
    gone["url"] = json!("http://127.0.0.1:9");
    let (st, j) = s.test(Some(gone)).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("files.backend_unreachable")), "{j}");
}

// ---------------------------------------------------------------- Encrypted channels and deletion

/// An external WebDAV store for `channel` of `room_id` (Alice manages it).
async fn webdav_for(node: &TestNode, token: &str, room_id: &str, channel: &str, port: u16) -> Value {
    let (st, info) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/files/backend"),
            token,
            json!({ "kind": "webdav", "url": format!("http://127.0.0.1:{port}/dav/"), "username": DAV_USER, "password": DAV_PASS }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{info}");
    info
}

async fn plain_upload(node: &TestNode, token: &str, base: &str, name: &str, data: &[u8]) -> String {
    let len = data.len().to_string();
    let (st, _, body) = node
        .raw(
            Method::POST,
            &format!("{base}/upload"),
            token,
            &[("tavrn-file-name", name), ("content-length", &len)],
            data.to_vec(),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string()
}

fn objects_under(m: &Mock, channel: &str) -> usize {
    let prefix = format!("/dav/tavrn/{channel}/");
    m.store.lock().unwrap().objects.keys().filter(|k| k.starts_with(&prefix)).count()
}

#[tokio::test]
async fn encrypted_channels_keep_the_ciphertext_on_the_store() {
    use common::e2ee::qualified;
    let (m, port) = mock(Flavor::WebDav).await;
    let node = test_node_with(DOMAIN, |c| {
        c.files_external = Switch::On;
        c.files_external_private = Switch::On;
    })
    .await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "R").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (_, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), alice.token(), json!({ "kind": "files", "name": "v" }))
        .await;
    let channel = ch["id"].as_str().unwrap().to_string();
    node.create_group(&mut alice, &channel).await;
    let base = format!("/api/v1/rooms/{room_id}/channels/{channel}/files");
    let (st, j) = node
        .put(
            &format!("{base}/backend"),
            alice.token(),
            json!({ "kind": "webdav", "url": format!("http://127.0.0.1:{port}/dav/"), "username": DAV_USER,
                    "password": DAV_PASS, "encrypt_files": true }),
        )
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.backend_invalid")), "{j}");
    webdav_for(&node, alice.token(), &room_id, &channel, port).await;

    let id = tavrn_node::util::ulid();
    let q = qualified(&channel);
    let record = alice
        .client
        .encrypt_content(
            &q,
            &json!({ "type": "files.entry", "v": 1, "entry": id, "kind": "file", "name": "n" }).to_string(),
        )
        .unwrap();
    let epoch = alice.client.current_epoch(&q).unwrap().to_string();
    let data = sample(90_000);
    let len = data.len().to_string();
    let (st, _, body) = node
        .raw(
            Method::POST,
            &format!("{base}/upload"),
            alice.token(),
            &[
                ("tavrn-entry-id", &id),
                ("tavrn-record", &record),
                ("tavrn-record-epoch", &epoch),
                ("tavrn-upload-category", "other"),
                ("content-length", &len),
            ],
            data.clone(),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let key = format!("/dav/tavrn/{channel}/{id}");
    assert_eq!(m.store.lock().unwrap().objects.get(&key), Some(&data), "the client's ciphertext as it is");
    let (st, _, part) = node
        .raw(Method::GET, &format!("{base}/{id}/download"), alice.token(), &[("range", "bytes=100-199")], Vec::new())
        .await;
    assert_eq!((st, &part[..]), (StatusCode::PARTIAL_CONTENT, &data[100..200]));

    // The channel goes, and its objects go with it even when keeping is asked for: they are unreadable anyway.
    let (st, _) =
        node.delete(&format!("/api/v1/rooms/{room_id}/channels/{channel}?keep_external=true"), alice.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let store = m.store.clone();
    eventually(|| !store.lock().unwrap().objects.contains_key(&key)).await;
}

#[tokio::test]
async fn deleting_channels_and_rooms_cleans_the_external_store() {
    let (m, port) = mock(Flavor::WebDav).await;
    let s = setup(Switch::On, Switch::On).await;
    let db = &s.node.state.db;
    let channels = format!("/api/v1/rooms/{}/channels", s.room_id);
    let new_channel = |name: &'static str| {
        let (node, token, channels) = (&s.node, s.alice.token.clone(), channels.clone());
        async move {
            let (st, ch) =
                node.post(&channels, &token, json!({ "kind": "files", "name": name, "encrypted": false })).await;
            assert_eq!(st, StatusCode::CREATED, "{ch}");
            ch["id"].as_str().unwrap().to_string()
        }
    };

    // Kept on request: entries and configuration go, the objects stay; the audit log says so.
    let kept = new_channel("kept").await;
    webdav_for(&s.node, &s.alice.token, &s.room_id, &kept, port).await;
    let kbase = format!("{channels}/{kept}/files");
    plain_upload(&s.node, &s.alice.token, &kbase, "a.txt", b"a").await;
    plain_upload(&s.node, &s.alice.token, &kbase, "b.txt", b"b").await;
    let (_, usage) = s.node.get_auth(&format!("{kbase}/usage"), &s.alice.token).await;
    assert_eq!(usage["backend_host"], "127.0.0.1", "{usage}");
    assert_eq!(usage["backend_prefix"], format!("tavrn/{kept}/").as_str(), "{usage}");
    let (st, _) = s.node.delete(&format!("{channels}/{kept}?keep_external=true"), &s.alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(objects_under(&m, &kept), 2, "kept on the store");
    let (_, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), &s.alice.token).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "channel.delete").unwrap().clone();
    assert_eq!(
        (entry["meta"]["keep_external"].as_bool(), entry["meta"]["kept_objects"].as_u64()),
        (Some(true), Some(2)),
        "{entry}"
    );

    // A store that fails: the objects wait in the queue, housekeeping retries them later.
    let flaky = new_channel("flaky").await;
    webdav_for(&s.node, &s.alice.token, &s.room_id, &flaky, port).await;
    let fbase = format!("{channels}/{flaky}/files");
    plain_upload(&s.node, &s.alice.token, &fbase, "c.txt", b"c").await;
    m.store.lock().unwrap().fail_deletes = true;
    let (st, _) = s.node.delete(&format!("{channels}/{flaky}"), &s.alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let queued = || async {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_pending_deletes").fetch_one(db).await.unwrap();
        n
    };
    for _ in 0..common::rounds(100) {
        let attempts: Option<i64> =
            sqlx::query_scalar("SELECT MAX(attempts) FROM file_pending_deletes").fetch_one(db).await.unwrap();
        if attempts.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(queued().await, 1);
    assert_eq!(objects_under(&m, &flaky), 1);
    let raw: String = sqlx::query_scalar("SELECT config FROM file_pending_deletes").fetch_one(db).await.unwrap();
    assert!(!raw.contains(DAV_PASS) && !raw.contains("127.0.0.1"), "the queue keeps the configuration sealed");
    let now = chrono::Utc::now();
    let r = tavrn_node::housekeeping::retry_external_deletes(&s.node.state, now + chrono::Duration::hours(2))
        .await
        .unwrap();
    assert_eq!((r.deleted, r.failed), (0, 1), "{r:?}");
    m.store.lock().unwrap().fail_deletes = false;
    // Not due yet right after a failure.
    let r = tavrn_node::housekeeping::retry_external_deletes(&s.node.state, now + chrono::Duration::hours(2))
        .await
        .unwrap();
    assert_eq!(r.deleted, 0, "{r:?}");
    let r = tavrn_node::housekeeping::retry_external_deletes(&s.node.state, now + chrono::Duration::hours(5))
        .await
        .unwrap();
    assert_eq!(r.deleted, 1, "{r:?}");
    assert_eq!((queued().await, objects_under(&m, &flaky)), (0, 0));
    // Objects whose store never comes back are given up after 7 days.
    let lost = new_channel("lost").await;
    webdav_for(&s.node, &s.alice.token, &s.room_id, &lost, port).await;
    plain_upload(&s.node, &s.alice.token, &format!("{channels}/{lost}/files"), "d.txt", b"d").await;
    m.store.lock().unwrap().fail_deletes = true;
    s.node.delete(&format!("{channels}/{lost}"), &s.alice.token).await;
    let r =
        tavrn_node::housekeeping::retry_external_deletes(&s.node.state, now + chrono::Duration::days(8)).await.unwrap();
    assert_eq!(r.given_up, 1, "{r:?}");
    assert_eq!(queued().await, 0);
    m.store.lock().unwrap().fail_deletes = false;

    // Deleting the room removes the objects of its external channels (the default).
    let last = new_channel("last").await;
    webdav_for(&s.node, &s.alice.token, &s.room_id, &last, port).await;
    plain_upload(&s.node, &s.alice.token, &format!("{channels}/{last}/files"), "e.txt", b"e").await;
    let (st, j) = s.node.delete(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
    assert!(st.is_success(), "{j}");
    let store = m.store.clone();
    let prefix = format!("/dav/tavrn/{last}/");
    eventually(|| !store.lock().unwrap().objects.keys().any(|k| k.starts_with(&prefix))).await;
    assert_eq!(objects_under(&m, &kept), 2, "the kept objects are not touched later");
}

/// Authorization audit (2026-10-09): "empty secrets use the stored ones" only for the same server and account.
/// Otherwise anybody allowed to configure the backend could test it against a host of their choice and receive the
/// stored password there.
#[tokio::test]
async fn authz_stored_secrets_never_go_to_another_server() {
    let (_, port) = mock(Flavor::WebDav).await;
    let (other, other_port) = mock(Flavor::WebDav).await;
    let s = setup(Switch::On, Switch::On).await;
    let url = format!("http://127.0.0.1:{port}/dav/");
    let (st, info) =
        s.backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "password": DAV_PASS })).await;
    assert_eq!(st, StatusCode::OK, "{info}");
    let elsewhere = format!("http://127.0.0.1:{other_port}/dav/");
    let (_, j) =
        s.test(Some(json!({ "kind": "webdav", "url": elsewhere, "username": DAV_USER, "password": "" }))).await;
    assert_ne!(j["ok"].as_bool(), Some(true), "the stored password authenticated at another server: {j}");
    let (_, j) = s.backend(json!({ "kind": "webdav", "url": elsewhere, "username": DAV_USER, "password": "" })).await;
    assert_ne!(j["kind"].as_str(), Some("webdav"), "moved with the stored password: {j}");
    assert!(other.store.lock().unwrap().collections.is_empty(), "nothing was created with the stored password");
}

// ---------------------------------------------------------------- Node policy: external stores only

/// A node on external stores only (`TAVRN_FILES_INTERNAL=off`, tavrn-node#45).
async fn external_only(quota: u64) -> Setup {
    setup_with(|c| {
        c.files_internal = Switch::Off;
        c.files_external = Switch::On;
        c.files_external_private = Switch::On;
        c.files_channels_max_bytes = quota;
    })
    .await
}

/// `TAVRN_FILES_INTERNAL=off` (FILES.md §5): a new files channel has no store (`backend: "none"`) and takes no
/// uploads and no folders until an external store is set; the node's own storage cannot be chosen; the policy is
/// published in `GET /node` and the discovery document.
#[tokio::test]
async fn without_internal_storage_files_channels_need_an_external_store() {
    let (m, port) = mock(Flavor::WebDav).await;
    let s = external_only(0).await;

    // The policy for clients, before the first upload.
    let (st, node) = s.node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!((st, node["files_internal"].as_bool()), (StatusCode::OK, Some(false)), "{node}");
    let (_, doc) = s.node.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert_eq!(doc["policies"]["files_internal"], false, "{doc}");

    // The channel exists without a store.
    let (st, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!(st, StatusCode::OK, "{usage}");
    assert_eq!(
        (usage["backend"].as_str(), usage["can_upload"].as_bool(), usage["enabled"].as_bool()),
        (Some("none"), Some(false), Some(true)),
        "{usage}"
    );
    let (_, info) = s.node.get_auth(&format!("{}/backend", s.base()), &s.alice.token).await;
    assert_eq!(
        (info["kind"].as_str(), info["internal_allowed"].as_bool(), info["external_allowed"].as_bool()),
        (Some("none"), Some(false), Some(true)),
        "{info}"
    );

    // Every way onto the node's storage is refused.
    let refused = |(st, j): (StatusCode, Value), what: &str| {
        assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.internal_disabled")), "{what}: {j}");
    };
    refused(s.up("a.txt", b"hello").await, "upload");
    refused(
        s.node.post(&format!("{}/folders", s.base()), &s.alice.token, json!({ "name": "Docs" })).await,
        "new folder",
    );
    refused(s.backend(json!({ "kind": "internal" })).await, "PUT backend internal");
    refused(s.test(Some(json!({ "kind": "internal" }))).await, "test internal");
    refused(s.test(None).await, "test of the stored (no) store");
    let (_, list) = s.node.get_auth(&s.base(), &s.alice.token).await;
    assert_eq!(list["entries"].as_array().map(Vec::len), Some(0), "nothing was stored: {list}");

    // An external store: uploads and folders work, the store holds the bytes.
    webdav_for(&s.node, &s.alice.token, &s.room_id, &s.channel, port).await;
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!((usage["backend"].as_str(), usage["can_upload"].as_bool()), (Some("webdav"), Some(true)), "{usage}");
    let (st, folder) = s.node.post(&format!("{}/folders", s.base()), &s.alice.token, json!({ "name": "Docs" })).await;
    assert_eq!(st, StatusCode::CREATED, "{folder}");
    let data = sample(150_000);
    let (st, f) = s.up("big.dat", &data).await;
    assert_eq!(st, StatusCode::CREATED, "unlimited without TAVRN_FILES_CHANNELS_MAX_BYTES: {f}");
    let fid = f["id"].as_str().unwrap().to_string();
    assert_eq!(objects_under(&m, &s.channel), 1);
    assert_eq!(s.down(&fid, None).await, (StatusCode::OK, data));

    // Emptied again, the channel still cannot move to the node's storage.
    s.node.delete(&format!("{}/{fid}", s.base()), &s.alice.token).await;
    let store = m.clone();
    let channel = s.channel.clone();
    eventually(|| objects_under(&store, &channel) == 0).await;
    refused(s.backend(json!({ "kind": "internal" })).await, "PUT backend internal after the store");

    // A node with its own storage (the default) says so.
    let d = setup(Switch::Off, Switch::Off).await;
    let (_, node) = d.node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(node["files_internal"], true, "{node}");
    let (_, doc) = d.node.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert_eq!(doc["policies"]["files_internal"], true);
    let (_, usage) = d.node.get_auth(&format!("{}/usage", d.base()), &d.alice.token).await;
    assert_eq!(usage["backend"], "internal", "{usage}");
    let (_, info) = d.node.get_auth(&format!("{}/backend", d.base()), &d.alice.token).await;
    assert_eq!((info["kind"].as_str(), info["internal_allowed"].as_bool()), (Some("internal"), Some(true)));
}

/// The node quota (`files_channels.max_bytes`) limits only the node's own storage, never an external store
/// (tavrn-node#58); an external store has its own optional limit in the backend settings (`max_bytes`, FILES.md §5),
/// enforced on the bytes the node relays and shown as the channel's limit.
#[tokio::test]
async fn the_node_quota_never_limits_external_stores_the_channel_limit_does() {
    let (_m, port) = mock(Flavor::WebDav).await;
    let s = external_only(100_000).await;
    let info = webdav_for(&s.node, &s.alice.token, &s.room_id, &s.channel, port).await;
    assert_eq!(info["max_bytes"], 0, "no limit unless set: {info}");
    let (st, j) = s.up("big.dat", &sample(150_000)).await;
    assert_eq!(st, StatusCode::CREATED, "the node quota of 100 000 bytes does not apply: {j}");
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!((usage["limit_bytes"].as_i64(), usage["used_bytes"].as_i64()), (Some(0), Some(150_000)), "{usage}");

    // The room's managers limit the store: shown in usage and GET backend, enforced on uploads.
    let url = format!("http://127.0.0.1:{port}/dav/");
    let (st, info) = s
        .backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "password": "", "max_bytes": 200_000 }))
        .await;
    assert_eq!(
        (st, info["max_bytes"].as_i64(), info["password_set"].as_bool()),
        (StatusCode::OK, Some(200_000), Some(true)),
        "{info}"
    );
    let (_, got) = s.node.get_auth(&format!("{}/backend", s.base()), &s.alice.token).await;
    assert_eq!(got["max_bytes"], 200_000);
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!(usage["limit_bytes"], 200_000, "{usage}");
    let (st, j) = s.up("more.dat", &sample(100_000)).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("files.quota_exceeded")), "{j}");
    assert_eq!(
        (j["meta"]["limit_bytes"].as_i64(), j["meta"]["used_bytes"].as_i64()),
        (Some(200_000), Some(150_000)),
        "{j}"
    );
    let (st, j) = s.up("fits.dat", &sample(40_000)).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");

    // Out of range is refused; 0 lifts the limit again.
    let (st, j) =
        s.backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "max_bytes": 1u64 << 51 })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.backend_invalid")), "{j}");
    let (st, info) = s.backend(json!({ "kind": "webdav", "url": url, "username": DAV_USER, "max_bytes": 0 })).await;
    assert_eq!((st, info["max_bytes"].as_i64()), (StatusCode::OK, Some(0)), "{info}");
    let (st, j) = s.up("again.dat", &sample(100_000)).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
}

/// The node's own storage keeps the node quota; a per-channel limit is only for external stores.
#[tokio::test]
async fn the_node_quota_limits_the_node_storage_and_max_bytes_is_for_external_stores_only() {
    let s = setup_with(|c| c.files_channels_max_bytes = 100_000).await;
    let (st, j) = s.up("big.dat", &sample(150_000)).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("files.quota_exceeded")), "{j}");
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!(usage["limit_bytes"], 100_000, "{usage}");
    let (st, j) = s.backend(json!({ "kind": "internal", "max_bytes": 5000 })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("files.backend_invalid")), "{j}");
    let (st, info) = s.backend(json!({ "kind": "internal" })).await;
    assert_eq!((st, info["max_bytes"].as_i64()), (StatusCode::OK, Some(0)), "{info}");
}

/// A node switched to `TAVRN_FILES_INTERNAL=off` keeps the files its channels hold already: they are listed,
/// downloaded, renamed and deleted as before, but the channel takes no new uploads until it moved to an external
/// store (possible once it is empty, FILES.md §5).
#[tokio::test]
async fn switching_internal_storage_off_keeps_the_existing_files() {
    let mut s = setup(Switch::On, Switch::On).await;
    let (st, f) = s.up("old.txt", b"kept on the node").await;
    assert_eq!(st, StatusCode::CREATED, "{f}");
    let fid = f["id"].as_str().unwrap().to_string();

    let off = tavrn_node::config::Config { files_internal: Switch::Off, ..(*s.node.state.config).clone() };
    s.node.state.config = Arc::new(off);
    s.node.router = tavrn_node::app::router(s.node.state.clone());

    assert_eq!(s.down(&fid, None).await, (StatusCode::OK, b"kept on the node".to_vec()));
    let (st, j) = s.node.patch(&format!("{}/{fid}", s.base()), &s.alice.token, json!({ "name": "renamed.txt" })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.up("new.txt", b"x").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("files.internal_disabled")), "{j}");
    let (_, usage) = s.node.get_auth(&format!("{}/usage", s.base()), &s.alice.token).await;
    assert_eq!((usage["backend"].as_str(), usage["files"].as_i64()), (Some("none"), Some(1)), "{usage}");
    let (st, _) = s.node.delete(&format!("{}/{fid}", s.base()), &s.alice.token).await;
    assert_eq!(st, StatusCode::OK);
}
