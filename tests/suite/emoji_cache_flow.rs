// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cached copies of other nodes' emojis and clips: readers load `<:name:ID@host>` through the node
//! they talk to (`?host=`), which fetches the bytes once (public addresses only, size cap, content checks), keeps
//! them after the origin deleted them, answers `If-None-Match`, and evicts or purges copies.
use crate::common;

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use common::{
    TestNode, body_bytes,
    federation::{B, two_nodes},
    test_node_with,
};
use serde_json::Value;
use tavrn_node::federation::client::{ClientOptions, FederationClient, Lookup};
use tower::ServiceExt;

const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49,
    0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x64, 0xf8, 0xcf, 0x50, 0x0f, 0x00, 0x03, 0x86, 0x01, 0x80, 0x5a, 0x34, 0x7d,
    0x6b, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];
const ID: &str = "01J9ZK8Q4V6X3M2N1P0R5S7T8W";

async fn get_with(router: &Router, path: &str, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = router.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let (status, h) = (resp.status(), resp.headers().clone());
    (status, h, body_bytes(resp).await.to_vec())
}

fn code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body).ok().and_then(|v| v["code"].as_str().map(String::from))
}

async fn cached_rows(node: &TestNode) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM remote_emoji_cache").fetch_one(&node.state.db).await.unwrap()
}

#[tokio::test]
async fn foreign_emojis_and_clips_are_served_from_a_cached_copy_that_outlives_the_origin() {
    let (a, b) = two_nodes().await;
    let alice = b.register("alice").await;
    let (s, _, e) = b
        .raw(
            Method::POST,
            "/api/v1/users/me/emojis",
            &alice.token,
            &[("content-type", "image/png"), ("tavrn-emoji-name", "pog")],
            PNG_1X1.to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let emoji: Value = serde_json::from_slice(&e).unwrap();
    let id = emoji["id"].as_str().unwrap();
    let headers = [("content-type", "audio/ogg"), ("tavrn-sound-name", "Fanfare"), ("tavrn-sound-duration-ms", "500")];
    let (s, _, snd) = b.raw(Method::POST, "/api/v1/users/me/sounds", &alice.token, &headers, vec![5u8; 300]).await;
    assert_eq!(s, StatusCode::CREATED);
    let sound: Value = serde_json::from_slice(&snd).unwrap();
    let sid = sound["id"].as_str().unwrap();

    // a.test fetches the copy once; the reader never talks to b.test.
    let path = format!("/api/v1/emojis/{id}/image?host={B}");
    let (s, h, first) = get_with(&a.router, &path, &[]).await;
    assert_eq!(s, StatusCode::OK, "{:?}", code(&first));
    assert_eq!(h[header::CONTENT_TYPE], "image/webp");
    assert_eq!(h[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
    assert_eq!(h["x-content-type-options"], "nosniff");
    let etag = h[header::ETAG].to_str().unwrap().to_string();
    assert_eq!(etag, format!("\"{id}@{B}\""));
    let (s, _, _) = get_with(&a.router, &path, &[("if-none-match", &etag)]).await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    let (s, _, still) = get_with(&a.router, &format!("{path}&still=1"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!still.is_empty());
    let (s, h, audio) = get_with(&a.router, &format!("/api/v1/sounds/{sid}/audio?host={B}"), &[]).await;
    assert_eq!((s, h[header::CONTENT_TYPE].to_str().unwrap()), (StatusCode::OK, "audio/ogg"));
    assert_eq!(audio, vec![5u8; 300]);
    assert_eq!(cached_rows(&a).await, 3);
    // `?host=` naming the node itself is the local route.
    let (s, _, _) = get_with(&b.router, &format!("/api/v1/emojis/{id}/image?host={B}"), &[]).await;
    assert_eq!(s, StatusCode::OK);

    // The origin deletes them: messages that used them stay readable on a.test.
    b.delete(&format!("/api/v1/users/me/emojis/{id}"), &alice.token).await;
    b.delete(&format!("/api/v1/users/me/sounds/{sid}"), &alice.token).await;
    let (s, _, _) = get_with(&b.router, &format!("/api/v1/emojis/{id}/image"), &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, again) = get_with(&a.router, &path, &[]).await;
    assert_eq!((s, again), (StatusCode::OK, first));
    let (s, _, _) = get_with(&a.router, &format!("/api/v1/sounds/{sid}/audio?host={B}"), &[]).await;
    assert_eq!(s, StatusCode::OK);

    // Never cached and gone at the origin: 404 (clients show the placeholder).
    let (s, _, body) = get_with(&a.router, &format!("/api/v1/emojis/{ID}/image?host={B}"), &[]).await;
    assert_eq!((s, code(&body).as_deref()), (StatusCode::NOT_FOUND, Some("media.remote_not_found")));

    // Admins purge a copy (audited); unused copies are evicted after the configured days.
    let admin = a.register("admin").await;
    let user = a.register("user").await;
    let (s, _) = a.delete(&format!("/api/v1/admin/media-cache/{B}/{id}"), &user.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = a.delete(&format!("/api/v1/admin/media-cache/{B}/{id}"), &admin.token).await;
    assert_eq!((s, j["deleted"].as_u64()), (StatusCode::OK, Some(2)), "{j}");
    let (_, log) = a.get_auth("/api/v1/admin/audit-log", &admin.token).await;
    assert!(log.to_string().contains("media_cache.purge"), "{log}");
    let (s, _, _) = get_with(&a.router, &path, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "purged and gone at the origin");
    assert_eq!(cached_rows(&a).await, 1);
    let soon = chrono::Utc::now() + chrono::Duration::days(364);
    assert_eq!(tavrn_node::emoji_cache::evict_unused(&a.state, soon).await.unwrap(), 0);
    let later = chrono::Utc::now() + chrono::Duration::days(366);
    assert_eq!(tavrn_node::emoji_cache::evict_unused(&a.state, later).await.unwrap(), 1);
    assert_eq!(cached_rows(&a).await, 0);
}

/// A fake origin: the response per path, and how often it was asked.
fn fake_origin(hits: Arc<AtomicUsize>) -> Router {
    let count = move || {
        hits.fetch_add(1, Ordering::SeqCst);
    };
    let c1 = count.clone();
    let c2 = count;
    Router::new()
        .route(
            "/api/v1/emojis/{id}/image",
            get(move |axum::extract::Path(id): axum::extract::Path<String>| {
                c1();
                async move {
                    match id.as_str() {
                        // HTML posing as an image.
                        "01J9ZK8Q4V6X3M2N1P0R5S7T81" => {
                            ([(header::CONTENT_TYPE, "text/html")], b"<script>x</script>".to_vec()).into_response()
                        }
                        // SVG with an image type.
                        "01J9ZK8Q4V6X3M2N1P0R5S7T82" => {
                            ([(header::CONTENT_TYPE, "image/png")], b"<svg onload=alert(1)>".to_vec()).into_response()
                        }
                        // Too large.
                        "01J9ZK8Q4V6X3M2N1P0R5S7T83" => {
                            ([(header::CONTENT_TYPE, "image/png")], vec![0u8; 300 * 1024]).into_response()
                        }
                        _ => ([(header::CONTENT_TYPE, "image/png")], PNG_1X1.to_vec()).into_response(),
                    }
                }
            }),
        )
        .route(
            "/api/v1/sounds/{id}/audio",
            get(move || {
                c2();
                async { ([(header::CONTENT_TYPE, "application/octet-stream")], vec![1u8; 10]).into_response() }
            }),
        )
}

async fn serve(router: Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    port
}

#[tokio::test]
async fn the_cache_refuses_wrong_types_oversized_bodies_and_bad_hosts() {
    let hits = Arc::new(AtomicUsize::new(0));
    let port = serve(fake_origin(hits.clone())).await;
    let node = test_node_with("t.local", |c| {
        c.federation_allow_private = true;
        c.federation_dev_peers = format!("fake.test=http://127.0.0.1:{port}");
    })
    .await;
    let r = &node.router;
    for (id, why) in [
        ("01J9ZK8Q4V6X3M2N1P0R5S7T81", "wrong content type"),
        ("01J9ZK8Q4V6X3M2N1P0R5S7T82", "not an image"),
        ("01J9ZK8Q4V6X3M2N1P0R5S7T83", "too large"),
    ] {
        let (s, _, body) = get_with(r, &format!("/api/v1/emojis/{id}/image?host=fake.test"), &[]).await;
        assert_eq!((s, code(&body).as_deref()), (StatusCode::BAD_GATEWAY, Some("media.remote_unavailable")), "{why}");
    }
    let (s, _, _) = get_with(r, &format!("/api/v1/sounds/{ID}/audio?host=fake.test"), &[]).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "clips must be audio/*");
    assert_eq!(cached_rows(&node).await, 0);
    // A good one is cached: the second request does not reach the origin.
    let (s, _, _) = get_with(r, &format!("/api/v1/emojis/{ID}/image?host=fake.test"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    let before = hits.load(Ordering::SeqCst);
    let (s, _, _) = get_with(r, &format!("/api/v1/emojis/{ID}/image?host=fake.test"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), before, "cache hit");

    // Hosts that are not node domains never leave the node.
    for host in ["127.0.0.1", "localhost", "evil.test%2Fx", "[::1]", "a@b.test", "t.local:1/x"] {
        let (s, _, body) = get_with(r, &format!("/api/v1/emojis/{ID}/image?host={host}"), &[]).await;
        assert_eq!((s, code(&body).as_deref()), (StatusCode::BAD_REQUEST, Some("media.host_invalid")), "{host}");
    }
}

/// Resolves every name to a private address.
struct Private;

impl Lookup for Private {
    fn lookup(&self, _host: String) -> futures::future::BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async { Ok(vec![IpAddr::from([10, 0, 0, 7])]) })
    }
}

#[tokio::test]
async fn origins_resolving_to_private_addresses_are_refused() {
    let hits = Arc::new(AtomicUsize::new(0));
    let port = serve(fake_origin(hits.clone())).await;
    let node =
        test_node_with("t.local", |c| c.federation_dev_peers = format!("inner.test=http://inner.test:{port}")).await;
    let mut state = node.state.clone();
    let options = ClientOptions { lookup: Arc::new(Private), ..Default::default() };
    state.federation = Arc::new(FederationClient::with_options(&state.config, options).unwrap());
    let router = tavrn_node::app::router(state);
    for host in ["inner.test", "intranet.example"] {
        let (s, _, body) = get_with(&router, &format!("/api/v1/emojis/{ID}/image?host={host}"), &[]).await;
        assert_eq!((s, code(&body).as_deref()), (StatusCode::BAD_GATEWAY, Some("media.remote_unavailable")), "{host}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// The cache is bounded: per origin host and in total the least recently used copies go, and fetches (misses) are
/// limited per client address while cached copies are still served.
#[tokio::test]
async fn the_cache_is_capped_per_host_and_in_total_and_misses_are_limited() {
    let hits = Arc::new(AtomicUsize::new(0));
    let port = serve(fake_origin(hits.clone())).await;
    let node = test_node_with("t.local", |c| {
        c.federation_allow_private = true;
        c.federation_dev_peers = format!("fake.test=http://127.0.0.1:{port},other.test=http://127.0.0.1:{port}");
        // Every clip of the fake origin has 10 bytes.
        c.media_cache_max_bytes_per_host = 30;
        c.media_cache_max_bytes = 50;
    })
    .await;
    let r = &node.router;
    let size = |host: &'static str| {
        let db = node.state.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COALESCE(SUM(size), 0) FROM remote_emoji_cache WHERE origin_host = $1")
                .bind(host)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    let mut last = String::new();
    for _ in 0..10 {
        last = tavrn_node::util::ulid();
        let (s, _, _) = get_with(r, &format!("/api/v1/sounds/{last}/audio?host=fake.test"), &[]).await;
        assert_eq!(s, StatusCode::OK);
    }
    assert_eq!(size("fake.test").await, 30, "one host stops at its cap");
    let (s, _, _) = get_with(r, &format!("/api/v1/sounds/{last}/audio?host=fake.test"), &[]).await;
    assert_eq!(s, StatusCode::OK, "the newest copy stays");
    assert_eq!(hits.load(Ordering::SeqCst), 10, "served from the cache");
    for _ in 0..3 {
        let id = tavrn_node::util::ulid();
        assert_eq!(get_with(r, &format!("/api/v1/sounds/{id}/audio?host=other.test"), &[]).await.0, StatusCode::OK);
    }
    tavrn_node::emoji_cache::enforce_total_cap(&node.state).await.unwrap();
    assert!(size("fake.test").await + size("other.test").await <= 50, "the total cap holds");
    assert_eq!(size("other.test").await, 30, "the least recently used copies went first");

    // Misses over the per-address budget: 429; cached copies are still served.
    while node.state.media_miss_limiter.check("miss:unknown").is_ok() {}
    let (s, _, body) = get_with(r, &format!("/api/v1/sounds/{}/audio?host=fake.test", tavrn_node::util::ulid()), &[]).await;
    assert_eq!((s, code(&body).as_deref()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
    let (s, _, _) = get_with(r, &format!("/api/v1/sounds/{last}/audio?host=fake.test"), &[]).await;
    assert_eq!(s, StatusCode::OK);
}
