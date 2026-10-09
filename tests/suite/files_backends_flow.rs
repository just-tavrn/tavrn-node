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
    let node = test_node_with(DOMAIN, |c| {
        c.files_external = external;
        c.files_external_private = private;
    })
    .await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "R").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "files", "name": "f" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    Setup { node, alice, room_id, channel: ch["id"].as_str().unwrap().to_string() }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
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
