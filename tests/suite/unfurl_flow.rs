// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! `GET /api/v1/unfurl`: authentication, the node switch, the URL and address checks
//! and a successful preview through the route (the SSRF cases in detail are unit tests of `unfurl.rs`).
use crate::common;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    http::{Method, StatusCode, header},
    routing::get,
};
use common::{test_node, test_node_with};
use futures::future::BoxFuture;
use tavrn_node::{federation::client::Lookup, unfurl::Unfurler};

struct FakeDns(HashMap<String, Vec<IpAddr>>);

impl Lookup for FakeDns {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        let r = self.0.get(&host).cloned().ok_or_else(|| std::io::Error::other("NXDOMAIN"));
        Box::pin(async move { r })
    }
}

fn q(url: &str) -> String {
    format!("/api/v1/unfurl?url={}", url.replace(':', "%3A").replace('/', "%2F").replace('?', "%3F"))
}

#[tokio::test]
async fn unfurl_needs_a_session_and_refuses_private_targets() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, _) = node.req(Method::GET, &q("https://example.com/"), None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    for (url, code) in [
        ("ftp://example.com/", "unfurl.url_invalid"),
        ("http://user:pw@example.com/", "unfurl.url_invalid"),
        ("http://127.0.0.1/", "unfurl.address_forbidden"),
        ("http://10.0.0.8/", "unfurl.address_forbidden"),
        ("http://169.254.169.254/latest/meta-data/", "unfurl.address_forbidden"),
        ("http://[::1]/", "unfurl.address_forbidden"),
        ("http://[fd00::1]/", "unfurl.address_forbidden"),
        ("http://localhost/", "unfurl.address_forbidden"),
    ] {
        let (s, j) = node.get_auth(&q(url), &alice.token).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{url}: {j}");
        assert_eq!(j["code"], code, "{url}");
    }
    let (_, info) = node.get_auth("/api/v1/node", &alice.token).await;
    assert!(info["capabilities"].as_array().unwrap().iter().any(|c| c == "unfurl"), "{info}");
}

#[tokio::test]
async fn unfurl_can_be_switched_off() {
    let node = test_node_with("t.local", |c| c.unfurl = tavrn_node::unfurl::UnfurlSetting::Off).await;
    let alice = node.register("alice").await;
    let (s, j) = node.get_auth(&q("https://example.com/"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(j["code"], "unfurl.disabled");
    let (_, info) = node.get_auth("/api/v1/node", &alice.token).await;
    assert!(!info["capabilities"].as_array().unwrap().iter().any(|c| c == "unfurl"));
}

#[tokio::test]
async fn a_page_is_previewed_through_the_route() {
    let page = r#"<html><head><meta property="og:title" content="Hello"><meta name="description" content="World"></head></html>"#;
    let site = Router::new()
        .route("/page", get(move || async move { ([(header::CONTENT_TYPE, "text/html")], page) }))
        .route("/file.zip", get(|| async { ([(header::CONTENT_TYPE, "application/zip")], "PK") }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, site).await.unwrap() });

    let mut node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let dns = FakeDns(HashMap::from([("site.test".to_string(), vec!["127.0.0.1".parse().unwrap()])]));
    node.state.unfurl = Some(Arc::new(Unfurler::new(
        "t.local",
        Arc::new(dns),
        HashSet::from(["site.test".to_string()]),
        Duration::from_secs(3),
        1000,
    )));
    node.router = tavrn_node::app::router(node.state.clone());
    let url = format!("http://site.test:{port}/page");
    let (s, j) = node.get_auth(&q(&url), &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["url"], url);
    assert_eq!(j["title"], "Hello");
    assert_eq!(j["description"], "World");
    assert_eq!(j["site"], "site.test");
    assert!(j.get("image_data_url").is_none());
    let (s, j) = node.get_auth(&q(&format!("http://site.test:{port}/file.zip")), &alice.token).await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{j}");
    assert_eq!(j["code"], "unfurl.not_html");
}
