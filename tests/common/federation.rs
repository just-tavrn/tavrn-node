// SPDX-License-Identifier: AGPL-3.0-only
//! Two in-process nodes on real loopback ports that talk through the real federation client
//! (FEDERATION.md §13): `a.test` and `b.test`, `--dev`, `TAVRN_FEDERATION_ALLOW_PRIVATE=true` and
//! `TAVRN_FEDERATION_DEV_PEERS` pointing at each other.

use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Mutex,
};

use axum::http::StatusCode;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use tavrn_node::{app::router, config::Config, federation::outbox, keys::NodeKey};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

use super::{Session, TestNode};

pub const A: &str = "a.test";
pub const B: &str = "b.test";
pub const C: &str = "c.test";

/// A test node served on a fixed loopback port; it can be stopped and started again.
pub struct FedNode {
    pub node: TestNode,
    pub port: u16,
    server: Mutex<Option<(oneshot::Sender<()>, JoinHandle<()>)>>,
}

impl Deref for FedNode {
    type Target = TestNode;
    fn deref(&self) -> &TestNode {
        &self.node
    }
}

impl DerefMut for FedNode {
    fn deref_mut(&mut self) -> &mut TestNode {
        &mut self.node
    }
}

/// Binds `127.0.0.1:port` (0 = any) with `SO_REUSEADDR`, so a stopped node can take its port again.
fn bind(port: u16) -> TcpListener {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    socket.listen(1024).unwrap()
}

impl FedNode {
    pub fn domain(&self) -> &str {
        &self.node.state.config.domain
    }

    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/api/v1/ws", self.port)
    }

    fn serve(&self, listener: TcpListener) {
        let router = self.node.router.clone();
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        *self.server.lock().unwrap() = Some((tx, handle));
    }

    /// Stops listening and closes all connections (the node is "down").
    pub async fn stop(&self) {
        let server = self.server.lock().unwrap().take();
        if let Some((tx, handle)) = server {
            let _ = tx.send(());
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        }
    }

    /// Serves again on the same port.
    pub async fn start(&self) {
        self.stop().await;
        self.serve(bind(self.port));
    }

    /// "Restarts" the node with other signing keys (rotation: the newest `kid` signs). The database
    /// stays the same.
    pub async fn restart_with_keys(&mut self, keys: Vec<NodeKey>) {
        self.stop().await;
        let mut keys = keys;
        keys.sort_by(|a, b| a.kid.cmp(&b.kid));
        self.node.state.keys = std::sync::Arc::new(keys);
        self.node.router = router(self.node.state.clone());
        self.serve(bind(self.port));
    }

    /// Signs arbitrary claims with this node's current signing key.
    pub fn sign<T: Serialize>(&self, claims: &T) -> String {
        let key = self.node.state.signing_key();
        tavrn_node::jwt::sign(&key.signing, &key.kid, claims).unwrap()
    }

    /// Requests a federation token for `target` with a session of this node.
    pub async fn federation_token(&self, session: &Session, target: &str) -> String {
        let (status, json) = self.post("/api/v1/federation/token", &session.token, json!({ "target": target })).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["target"], target);
        assert_eq!(json["expires_in"], 600);
        json["token"].as_str().unwrap().into()
    }

    /// `POST /auth/federated` on this node.
    pub async fn federated_login(&self, token: &str) -> (StatusCode, Value) {
        self.req(
            axum::http::Method::POST,
            "/api/v1/auth/federated",
            None,
            Some(json!({ "token": token, "device_name": "Firefox" })),
        )
        .await
    }

    /// Federation token from `home` for this node, then the federated login; asserts success.
    pub async fn sign_in_from(&self, home: &FedNode, session: &Session) -> RemoteSession {
        let token = home.federation_token(session, self.domain()).await;
        let (status, json) = self.federated_login(&token).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        RemoteSession {
            token: json["access_token"].as_str().unwrap().into(),
            refresh: json["refresh_token"].as_str().unwrap().into(),
            device_id: json["device_id"].as_str().unwrap().into(),
            response: json,
        }
    }

    /// A bot of `home` signs in here with its app token; returns the access token of the federated session.
    pub async fn sign_in_from_bot(&self, home: &FedNode, app_token: &str) -> String {
        let (status, json) = home.post("/api/v1/federation/token", app_token, json!({ "target": self.domain() })).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = self.federated_login(json["token"].as_str().unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        json["access_token"].as_str().unwrap().into()
    }

    /// Runs one outbox round with the real clock.
    pub async fn deliver(&self) -> outbox::DeliveryReport {
        outbox::deliver_due(&self.node.state, Utc::now()).await.unwrap()
    }

    /// Runs one outbox round at `now + secs`.
    pub async fn deliver_at(&self, secs: i64) -> outbox::DeliveryReport {
        outbox::deliver_due(&self.node.state, Utc::now() + chrono::Duration::seconds(secs)).await.unwrap()
    }

    pub async fn outbox(&self) -> Vec<tavrn_node::store::federation::OutboxRow> {
        tavrn_node::store::federation::outbox_entries(&self.node.state.db).await.unwrap()
    }
}

/// A federated session on a target node.
pub struct RemoteSession {
    pub token: String,
    pub refresh: String,
    /// The home device id.
    pub device_id: String,
    pub response: Value,
}

pub async fn two_nodes() -> (FedNode, FedNode) {
    two_nodes_with(|_| {}, |_| {}).await
}

/// Two federating nodes; the tweaks run after the federation settings are filled in.
pub async fn two_nodes_with<'a>(
    tweak_a: impl FnOnce(&mut Config) + 'a,
    tweak_b: impl FnOnce(&mut Config) + 'a,
) -> (FedNode, FedNode) {
    let mut tweaks: Vec<Tweak<'a>> = vec![Box::new(tweak_a), Box::new(tweak_b)];
    let mut nodes = federated(&[A, B], &mut tweaks).await;
    let b = nodes.pop().unwrap();
    let a = nodes.pop().unwrap();
    (a, b)
}

/// Three federating nodes `a.test`, `b.test`, `c.test`.
pub async fn three_nodes() -> (FedNode, FedNode, FedNode) {
    three_nodes_with(|_| {}, |_| {}, |_| {}).await
}

pub async fn three_nodes_with<'a>(
    tweak_a: impl FnOnce(&mut Config) + 'a,
    tweak_b: impl FnOnce(&mut Config) + 'a,
    tweak_c: impl FnOnce(&mut Config) + 'a,
) -> (FedNode, FedNode, FedNode) {
    let mut tweaks: Vec<Tweak<'a>> = vec![Box::new(tweak_a), Box::new(tweak_b), Box::new(tweak_c)];
    let mut nodes = federated(&[A, B, C], &mut tweaks).await;
    let c = nodes.pop().unwrap();
    let b = nodes.pop().unwrap();
    let a = nodes.pop().unwrap();
    (a, b, c)
}

/// Nodes for `domains` that know each other as development peers.
type Tweak<'a> = Box<dyn FnOnce(&mut Config) + 'a>;

async fn federated(domains: &[&str], tweaks: &mut Vec<Tweak<'_>>) -> Vec<FedNode> {
    let listeners: Vec<TcpListener> = domains.iter().map(|_| bind(0)).collect();
    let ports: Vec<u16> = listeners.iter().map(|l| l.local_addr().unwrap().port()).collect();
    let peers =
        domains.iter().zip(&ports).map(|(d, p)| format!("{d}=http://127.0.0.1:{p}")).collect::<Vec<_>>().join(",");
    let mut nodes = Vec::new();
    for ((domain, port), tweak) in domains.iter().zip(&ports).zip(tweaks.drain(..)) {
        let node = super::test_node_with(domain, |c| {
            c.federation_allow_private = true;
            c.federation_dev_peers = peers.clone();
            tweak(c);
        })
        .await;
        nodes.push(FedNode { node, port: *port, server: Mutex::new(None) });
    }
    for (node, listener) in nodes.iter().zip(listeners) {
        node.serve(listener);
    }
    nodes
}

/// What the identity domain's website of a delegating node answers on `/.well-known/tavrn`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SiteMode {
    /// Forwards the request to the node (the reverse-proxy rule of the operator docs).
    Proxy,
    /// Serves the node's document with another `domain`.
    WrongDomain,
    /// Serves the node's document with its endpoints moved to `127.0.0.1:<port>` (the node moved hosts).
    MovedTo(u16),
}

/// The website of the identity domain `a.test`: only `/.well-known/tavrn`, everything else is 404. It
/// counts the requests for other paths, so a test sees that no API request went to the website.
pub struct Site {
    pub port: u16,
    pub mode: std::sync::Arc<Mutex<SiteMode>>,
    pub other_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// `a.test` delegating to its own host: identity domain `a.test` (served by a separate website listener,
/// the development peer mapping of `a.test`), node A at `TAVRN_PUBLIC_URL=http://127.0.0.1:<port>`; and
/// a normal node `b.test`.
pub async fn delegated_pair() -> (FedNode, FedNode, Site) {
    delegated_pair_with(|_| {}).await
}

/// [`delegated_pair`] with a tweak of B's configuration.
pub async fn delegated_pair_with(tweak_b: impl FnOnce(&mut Config)) -> (FedNode, FedNode, Site) {
    use axum::{body::Body, extract::Request, response::IntoResponse};
    use tower::ServiceExt;

    let site_listener = bind(0);
    let (la, lb) = (bind(0), bind(0));
    let (site_port, pa, pb) =
        (site_listener.local_addr().unwrap().port(), la.local_addr().unwrap().port(), lb.local_addr().unwrap().port());
    let peers = format!("{A}=http://127.0.0.1:{site_port},{B}=http://127.0.0.1:{pb}");
    let a = super::test_node_with(A, |c| {
        c.federation_allow_private = true;
        c.federation_dev_peers = peers.clone();
        c.public_url = Some(format!("http://127.0.0.1:{pa}"));
    })
    .await;
    let b = super::test_node_with(B, |c| {
        c.federation_allow_private = true;
        c.federation_dev_peers = peers.clone();
        tweak_b(c);
    })
    .await;
    let a = FedNode { node: a, port: pa, server: Mutex::new(None) };
    let b = FedNode { node: b, port: pb, server: Mutex::new(None) };
    a.serve(la);
    b.serve(lb);

    let mode = std::sync::Arc::new(Mutex::new(SiteMode::Proxy));
    let other = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let node_router = a.node.router.clone();
    let (m, o) = (mode.clone(), other.clone());
    let app = axum::Router::new().fallback(move |req: Request| {
        let (node_router, m, o) = (node_router.clone(), m.clone(), o.clone());
        async move {
            if req.uri().path() != "/.well-known/tavrn" {
                o.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return StatusCode::NOT_FOUND.into_response();
            }
            let forwarded = Request::get("/.well-known/tavrn").body(Body::empty()).unwrap();
            let resp = node_router.oneshot(forwarded).await.unwrap();
            if *m.lock().unwrap() == SiteMode::Proxy {
                return resp.into_response();
            }
            let bytes = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
            let mut doc: Value = serde_json::from_slice(&bytes).unwrap();
            let mode = *m.lock().unwrap();
            match mode {
                SiteMode::MovedTo(port) => {
                    doc["api"] = json!(format!("http://127.0.0.1:{port}/api/v1"));
                    doc["ws"] = json!(format!("ws://127.0.0.1:{port}/api/v1/ws"));
                }
                _ => doc["domain"] = json!("evil.test"),
            }
            axum::Json(doc).into_response()
        }
    });
    tokio::spawn(async move { axum::serve(site_listener, app).await.unwrap() });
    (a, b, Site { port: site_port, mode, other_requests: other })
}
