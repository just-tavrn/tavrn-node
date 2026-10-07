// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A Valkey outage while several instances run (docs/SCALING.md): needs `TAVRN_TEST_CACHE_URL` and drops every
//! connection of that Valkey, so it holds the test Valkey exclusively (`cluster::valkey_exclusive`) and does not
//! disturb the scenarios of `cluster_flow.rs`.
use crate::common;

use std::time::Duration;

use axum::http::Method;
use common::cluster::{self, Instance, domain, instances};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMessage;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(inst: &Instance, token: &str) -> Socket {
    let mut ws = tokio_tungstenite::connect_async(inst.ws_url()).await.unwrap().0;
    ws.send(WsMessage::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    assert_eq!(next(&mut ws, 5000).await.unwrap()["op"], "ready");
    ws
}

async fn next(ws: &mut Socket, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["op"] != "ping" {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

async fn wait_event(ws: &mut Socket, kind: &str, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis() as u64;
        let frame = next(ws, left.max(1)).await?;
        if (kind == "resync" && frame["op"] == "resync") || frame["type"] == kind {
            return Some(frame);
        }
    }
}

#[tokio::test]
async fn a_valkey_outage_is_survived_with_a_resync() {
    let Some((cache, _valkey)) = cluster::valkey_exclusive("a_valkey_outage_is_survived_with_a_resync").await else {
        return;
    };
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let room = a.node.plaintext_room(&alice.token, "Raid").await;
    let (room_id, channel) = (room["id"].as_str().unwrap().to_string(), common::TestNode::text_channel(&room));
    let mut ws = connect(a, &alice.token).await;
    // Valkey drops every connection (as in a restart): the subscriptions break and are renewed.
    let url = std::env::var("TAVRN_TEST_CACHE_URL").unwrap();
    let mut admin = redis::Client::open(url.as_str()).unwrap().get_multiplexed_async_connection().await.unwrap();
    let _: i64 = redis::cmd("CLIENT").arg("KILL").arg("TYPE").arg("pubsub").query_async(&mut admin).await.unwrap();
    let _: i64 = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("normal")
        .arg("SKIPME")
        .arg("yes")
        .query_async(&mut admin)
        .await
        .unwrap();
    assert_eq!(wait_event(&mut ws, "resync", 10_000).await.unwrap(), json!({ "op": "resync" }));
    // Commands reconnect by themselves; events flow again.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        b.node.send(&alice.token, &room_id, &channel, "after the outage").await;
        if let Some(ev) = wait_event(&mut ws, "message.create", 1000).await {
            assert_eq!(ev["data"]["content"]["body"], "after the outage");
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "events do not flow again");
    }
    let (_, ready) = b.node.req(Method::GET, "/readyz", None, None).await;
    assert_eq!(ready["cache"], true, "{ready}");
}
