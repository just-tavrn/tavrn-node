// SPDX-License-Identifier: AGPL-3.0-only
//! Helpers for federation tests of rooms, keys, MLS, friends and DMs across nodes (FEDERATION.md
//! §3–§6): users with identity and attested devices whose addresses carry their node's domain, MLS
//! operations on any node with any session, and WebSocket listeners.

use std::time::Duration;

use axum::http::StatusCode;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_crypto::{Client, CommitOutput, Device, MasterSecret};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

use super::{
    Session, TestNode,
    e2ee::{b64, unb64},
    federation::FedNode,
};

/// A user of a node with identity key and one attested device.
pub struct FedDev {
    pub session: Session,
    pub master: MasterSecret,
    pub client: Client,
    /// `username@home domain`
    pub address: String,
}

impl FedDev {
    pub fn token(&self) -> &str {
        &self.session.token
    }
    pub fn identity(&self) -> String {
        self.client.device().identity()
    }
}

/// Qualified conversation id `<node>/<id>` (MLS group id).
pub fn q(node: &str, conversation_id: &str) -> String {
    format!("{node}/{conversation_id}")
}

impl FedNode {
    /// New account on this node with identity key, attested device and `kps` KeyPackages.
    pub async fn crypto_user(&self, username: &str, kps: usize) -> FedDev {
        let s = self.register(username).await;
        let master = MasterSecret::generate().unwrap();
        self.put_identity(&s, &master).await;
        self.attest_fed(s, master, kps).await
    }

    /// Attests the device of `s` (address with this node's domain) and uploads KeyPackages.
    pub async fn attest_fed(&self, s: Session, master: MasterSecret, kps: usize) -> FedDev {
        let address = format!("{}@{}", s.username, self.domain());
        let device = Device::generate(&address, &s.device_id).unwrap();
        let att = device.attest(&master).unwrap();
        let (st, j) = self
            .put(
                &format!("/api/v1/users/me/devices/{}/key", s.device_id),
                &s.token,
                json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) }),
            )
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
        let dev = FedDev { session: s, master, client: Client::new(device), address };
        if kps > 0 {
            let packages: Vec<String> = (0..kps).map(|_| b64(&dev.client.create_key_package().unwrap())).collect();
            let (st, j) = self
                .post(
                    &format!("/api/v1/users/me/devices/{}/key-packages", dev.session.device_id),
                    dev.token(),
                    json!({ "key_packages": packages }),
                )
                .await;
            assert_eq!(st, StatusCode::CREATED, "{j}");
        }
        dev
    }

    /// Number of stored KeyPackages of a device of this node.
    pub async fn kp_count(&self, device_id: &str) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT CAST(COUNT(*) AS BIGINT) FROM key_packages WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(&self.state.db)
            .await
            .unwrap()
    }
}

impl TestNode {
    /// Creates the MLS group of a conversation hosted on `node` with the device as only member.
    pub async fn mls_group(&self, node: &str, token: &str, client: &mut Client, conversation_id: &str) {
        let gi = client.create_group(&q(node, conversation_id)).unwrap();
        let (st, j) = self
            .post(
                &format!("/api/v1/conversations/{conversation_id}/mls/group"),
                token,
                json!({ "group_info": b64(&gi) }),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
    }

    /// Claims KeyPackages of `address` through this node: `(status, body)`.
    pub async fn claim_raw(&self, token: &str, address: &str) -> (StatusCode, Value) {
        self.post(&format!("/api/v1/users/{address}/key-packages/claim"), token, json!({})).await
    }

    /// Claims KeyPackages of `address` through this node and returns them.
    pub async fn claim_kps(&self, token: &str, address: &str) -> Vec<Vec<u8>> {
        let (st, j) = self.claim_raw(token, address).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        j["key_packages"].as_array().unwrap().iter().map(|k| unb64(&k["key_package"])).collect()
    }

    pub async fn commit(&self, token: &str, conversation_id: &str, out: &CommitOutput) -> (StatusCode, Value) {
        self.post(
            &format!("/api/v1/conversations/{conversation_id}/mls/commits"),
            token,
            json!({
                "epoch": out.epoch,
                "commit": b64(&out.commit),
                "group_info": b64(&out.group_info),
                "welcome": out.welcome.as_ref().map(|w| b64(w)),
            }),
        )
        .await
    }

    /// Adds the devices of `address` (claimed through this node), commits and merges.
    pub async fn add_to_group(
        &self,
        node: &str,
        token: &str,
        client: &mut Client,
        conversation_id: &str,
        address: &str,
    ) {
        let kps = self.claim_kps(token, address).await;
        assert!(!kps.is_empty(), "{address} has KeyPackages");
        let out = client.add_members(&q(node, conversation_id), &kps).unwrap();
        let (st, j) = self.commit(token, conversation_id, &out).await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
        client.merge_pending_commit(&q(node, conversation_id)).unwrap();
    }

    /// Joins every pending Welcome of the session's device; returns their number.
    pub async fn join_welcomes(&self, node: &str, token: &str, client: &mut Client) -> usize {
        let (st, j) = self.get_auth("/api/v1/mls/welcomes", token).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        let items = j["items"].as_array().unwrap().clone();
        for w in &items {
            let (conv, _) = client.join_by_welcome(&unb64(&w["welcome"])).unwrap();
            assert_eq!(conv, q(node, w["conversation_id"].as_str().unwrap()));
            let (st, _) = self.delete(&format!("/api/v1/mls/welcomes/{}", w["id"].as_str().unwrap()), token).await;
            assert_eq!(st, StatusCode::NO_CONTENT);
        }
        items.len()
    }

    /// Processes the handshake log from the client's current epoch.
    pub async fn catch_up_on(&self, node: &str, token: &str, client: &mut Client, conversation_id: &str) {
        let conv = q(node, conversation_id);
        let since = client.current_epoch(&conv).unwrap();
        let (st, j) = self
            .get_auth(&format!("/api/v1/conversations/{conversation_id}/mls/messages?since_epoch={since}"), token)
            .await;
        assert_eq!(st, StatusCode::OK, "{j}");
        for item in j["items"].as_array().unwrap() {
            client.process_handshake(&conv, &unb64(&item["commit"])).unwrap();
        }
    }

    /// Sends an encrypted text message to a conversation hosted on `node`.
    pub async fn send_secret(
        &self,
        node: &str,
        token: &str,
        client: &Client,
        conversation_id: &str,
        body: &str,
    ) -> (StatusCode, Value) {
        let conv = q(node, conversation_id);
        let content = client.encrypt_content(&conv, &json!({ "type": "text", "body": body }).to_string()).unwrap();
        let epoch = client.current_epoch(&conv).unwrap();
        self.post(
            &format!("/api/v1/conversations/{conversation_id}/messages"),
            token,
            json!({ "content": content, "epoch": epoch }),
        )
        .await
    }

    /// Reads the newest message of a conversation and decrypts it with `client`; returns the body.
    pub async fn read_secret(&self, node: &str, token: &str, client: &Client, conversation_id: &str) -> String {
        let (st, list) = self.get_auth(&format!("/api/v1/conversations/{conversation_id}/messages"), token).await;
        assert_eq!(st, StatusCode::OK, "{list}");
        let m = &list[0];
        let plain = client
            .decrypt_content(
                &q(node, conversation_id),
                m["author"].as_str().unwrap(),
                m["device_id"].as_str().unwrap(),
                m["content"].as_str().unwrap(),
                None,
            )
            .unwrap();
        let v: Value = serde_json::from_str(&plain).unwrap();
        v["body"].as_str().unwrap().to_string()
    }
}

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Opens a WebSocket on `node` with `token` and waits for `ready`.
pub async fn ws(node: &FedNode, token: &str) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(node.ws_url()).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    let ready = super::within(Duration::from_secs(5), "the WebSocket's ready", ws.next()).await.unwrap().unwrap();
    assert!(ready.to_text().unwrap().contains("\"ready\""), "{ready:?}");
    ws
}

/// Waits (at most 5 s, scaled by `TAVRN_TEST_TIMEOUT_FACTOR`) for the next event of `kind` and returns its data.
pub async fn event(ws: &mut Ws, kind: &str) -> Value {
    let deadline = super::deadline(Duration::from_secs(5));
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .unwrap_or_else(|_| panic!("no {kind} event within {:?}", super::timeout(Duration::from_secs(5))))
            .unwrap()
            .unwrap();
        let Ok(text) = msg.to_text() else { continue };
        let Ok(v) = serde_json::from_str::<Value>(text) else { continue };
        if v["op"] == "event" && v["type"] == kind {
            return v["data"].clone();
        }
    }
}

/// `true` if no event of `kind` arrives within `ms` milliseconds.
pub async fn no_event(ws: &mut Ws, kind: &str, ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return true,
            Ok(Some(Ok(msg))) => {
                if let Ok(text) = msg.to_text()
                    && let Ok(v) = serde_json::from_str::<Value>(text)
                    && v["op"] == "event"
                    && v["type"] == kind
                {
                    return false;
                }
            }
            Ok(_) => return true,
        }
    }
}
