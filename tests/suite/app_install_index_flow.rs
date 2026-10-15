// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The install index of a bot (APPLICATIONS.md §4.5) is shared by every node: one node gets only its own share of it,
//! so it cannot silence the genuine installations of the others.
use crate::common;

use axum::http::StatusCode;
use common::test_node;
use serde_json::json;
use tavrn_node::{installations, store, util};

const D: &str = common::e2ee::DOMAIN;

#[tokio::test]
async fn one_node_cannot_fill_a_bots_install_index() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let (s, app) = node.post("/api/v1/applications", &alice.token, json!({ "name": "Indexed", "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let bot_id = app["bot"]["id"].as_str().unwrap().to_string();
    let bot = store::users::by_id(&node.state.db, &bot_id).await.unwrap().unwrap();
    let install = |room_name: String, by: &str| installations::Incoming::Install {
        room_id: util::ulid(),
        room_name,
        installed_by: by.into(),
    };
    let share = installations::MAX_INDEX_ENTRIES_PER_NODE;
    for i in 0..share {
        let r =
            installations::handle_for_bot(&node.state, "evil.test", &bot, install(format!("fake {i}"), "m@evil.test"))
                .await
                .unwrap();
        assert_eq!(r, "handled");
    }
    let r = installations::handle_for_bot(&node.state, "evil.test", &bot, install("one more".into(), "m@evil.test"))
        .await
        .unwrap();
    assert_eq!(r, "ignored", "the node used up its share");
    let r =
        installations::handle_for_bot(&node.state, "good.test", &bot, install("Real room".into(), "carol@good.test"))
            .await
            .unwrap();
    assert_eq!(r, "handled", "another node's genuine installation is indexed");
    let n = store::installations::index_count(&node.state.db, app["id"].as_str().unwrap()).await.unwrap();
    assert_eq!(n, share + 1);
}
