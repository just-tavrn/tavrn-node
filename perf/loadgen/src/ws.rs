// SPDX-License-Identifier: AGPL-3.0-only
//! WebSocket clients (`/api/v1/ws`, PROTOCOL.md §6): hello/ready, answering pings, counting events.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{sync::watch, task::JoinHandle};
use tokio_tungstenite::tungstenite::Message;

use crate::stats::lock;

/// Counters shared by all connections.
#[derive(Default)]
pub struct WsStats {
    /// Connections that reached `ready`.
    pub connected: AtomicU64,
    /// Connection attempts that failed (handshake, hello, timeout).
    pub failed: AtomicU64,
    /// Connections closed by the node (or broken) before the run ended.
    pub dropped: AtomicU64,
    /// `message.create` events received over all connections.
    pub message_events: AtomicU64,
    /// `resync` frames (the node's broadcast buffer overflowed for a slow client).
    pub resyncs: AtomicU64,
}

impl WsStats {
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }
}

/// Receive time of each `message.create` (by message id) on one observing connection.
#[derive(Default)]
pub struct Observer {
    pub received: Mutex<HashMap<String, Instant>>,
}

/// `ws://` URL of the node's WebSocket endpoint.
pub fn ws_url(http_base: &str) -> String {
    format!("{}/api/v1/ws", http_base.replacen("http", "ws", 1))
}

/// Message id of a `message.create` event frame, if it is one.
pub fn message_create_id(frame: &str) -> Option<String> {
    let v: Value = serde_json::from_str(frame).ok()?;
    if v["op"] == "event" && v["type"] == "message.create" { v["data"]["id"].as_str().map(String::from) } else { None }
}

/// Connects, sends `hello` and waits for `ready`; then a background task answers pings and counts
/// events until `stop` turns true.
pub async fn connect(
    url: &str,
    token: &str,
    stats: Arc<WsStats>,
    observer: Option<Arc<Observer>>,
    mut stop: watch::Receiver<bool>,
) -> Result<JoinHandle<()>> {
    let attempt = async {
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
        ws.send(Message::text(json!({ "op": "hello", "token": token, "capabilities": [] }).to_string())).await?;
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.contains("\"op\":\"ready\"") => return Ok(ws),
                Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(other)) => bail!("unexpected frame before ready: {other:?}"),
                Some(Err(e)) => return Err(e.into()),
                None => bail!("closed before ready"),
            }
        }
    };
    let ws = match tokio::time::timeout(Duration::from_secs(20), attempt).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        Err(_) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("timeout waiting for ready"));
        }
    };
    stats.connected.fetch_add(1, Ordering::Relaxed);
    Ok(tokio::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        loop {
            tokio::select! {
                _ = stop.changed() => {
                    let _ = sink.close().await;
                    return;
                }
                frame = stream.next() => match frame {
                    Some(Ok(Message::Text(text))) => {
                        if text.contains("\"op\":\"ping\"") {
                            if sink.send(Message::text(r#"{"op":"pong"}"#)).await.is_err() {
                                break;
                            }
                        } else if text.contains("\"type\":\"message.create\"") {
                            stats.message_events.fetch_add(1, Ordering::Relaxed);
                            if let Some(obs) = &observer && let Some(id) = message_create_id(&text) {
                                lock(&obs.received).insert(id, Instant::now());
                            }
                        } else if text.contains("\"op\":\"resync\"") {
                            stats.resyncs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
        }
        if !*stop.borrow() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(ws_url("http://127.0.0.1:8183"), "ws://127.0.0.1:8183/api/v1/ws");
        assert_eq!(ws_url("https://node.example"), "wss://node.example/api/v1/ws");
    }

    #[test]
    fn message_ids_from_event_frames() {
        let frame = r#"{"op":"event","id":"E1","type":"message.create","data":{"id":"M1","content":{}}}"#;
        assert_eq!(message_create_id(frame).as_deref(), Some("M1"));
        assert_eq!(message_create_id(r#"{"op":"event","type":"typing","data":{"id":"x"}}"#), None);
        assert_eq!(message_create_id("not json"), None);
    }
}
