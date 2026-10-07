// SPDX-License-Identifier: AGPL-3.0-only
//! Helpers for end-to-end encryption tests: the native `tavrn_crypto` crate plays the client.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tavrn_crypto::{Client, Device, MasterSecret, util};

use super::{Session, TestNode};

pub const DOMAIN: &str = "t.local";

pub fn b64(bytes: &[u8]) -> String {
    util::b64url_encode(bytes)
}

pub fn unb64(s: &Value) -> Vec<u8> {
    util::b64url_decode(s.as_str().expect("base64url string")).expect("base64url")
}

pub fn address(s: &Session) -> String {
    format!("{}@{DOMAIN}", s.username)
}

/// Qualified conversation id (MLS group id).
pub fn qualified(conversation_id: &str) -> String {
    format!("{DOMAIN}/{conversation_id}")
}

/// One device of a user with its MLS client and the account's master secret.
pub struct Dev {
    pub session: Session,
    pub master: MasterSecret,
    pub client: Client,
}

impl Dev {
    pub fn token(&self) -> &str {
        &self.session.token
    }
    pub fn identity(&self) -> String {
        self.client.device().identity()
    }
}

impl TestNode {
    /// Uploads the identity key (first device only).
    pub async fn put_identity(&self, s: &Session, master: &MasterSecret) {
        let (st, j) = self
            .put(
                "/api/v1/users/me/identity",
                &s.token,
                json!({ "identity_public_key": b64(&master.identity_public_key()) }),
            )
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    }

    /// Generates, attests and uploads the device key of `s` plus `kps` KeyPackages.
    pub async fn attest(&self, s: Session, master: MasterSecret, kps: usize) -> Dev {
        let device = Device::generate(&address(&s), &s.device_id).unwrap();
        let att = device.attest(&master).unwrap();
        let (st, j) = self
            .put(
                &format!("/api/v1/users/me/devices/{}/key", s.device_id),
                &s.token,
                json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) }),
            )
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
        let dev = Dev { session: s, master, client: Client::new(device) };
        if kps > 0 {
            self.upload_kps(&dev, kps).await;
        }
        dev
    }

    pub async fn upload_kps(&self, dev: &Dev, n: usize) -> (StatusCode, Value) {
        let kps: Vec<String> = (0..n).map(|_| b64(&dev.client.create_key_package().unwrap())).collect();
        let r = self
            .post(
                &format!("/api/v1/users/me/devices/{}/key-packages", dev.session.device_id),
                dev.token(),
                json!({ "key_packages": kps }),
            )
            .await;
        assert_eq!(r.0, StatusCode::CREATED, "{}", r.1);
        r
    }

    /// New account with identity key and one attested device.
    pub async fn crypto_user(&self, username: &str) -> Dev {
        let s = self.register(username).await;
        let master = MasterSecret::generate().unwrap();
        self.put_identity(&s, &master).await;
        self.attest(s, master, 3).await
    }

    /// Second device of the same account (login + attestation with the same master secret).
    pub async fn second_device(&self, first: &Dev) -> Dev {
        let s = self.login(&first.session.username).await;
        let master = MasterSecret::from_bytes(*first.master.to_bytes());
        self.attest(s, master, 3).await
    }

    pub async fn befriend(&self, a: &Session, b: &Session) {
        let (st, j) = self.post("/api/v1/users/me/friends/requests", &a.token, json!({ "user": b.username })).await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
        let (st, j) = self.post("/api/v1/users/me/friends/requests", &b.token, json!({ "user": a.username })).await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
        assert_eq!(j["status"], "accepted", "{j}");
    }

    pub async fn create_dm(&self, a: &Session, b: &Session) -> String {
        let (st, j) = self
            .post(
                "/api/v1/conversations",
                &a.token,
                json!({ "kind": "dm", "members": [format!("{}@{DOMAIN}", b.username)] }),
            )
            .await;
        assert!(st == StatusCode::CREATED || st == StatusCode::OK, "{j}");
        j["id"].as_str().unwrap().to_string()
    }

    /// Creates the MLS group of a conversation with `dev` as the only member.
    pub async fn create_group(&self, dev: &mut Dev, conversation_id: &str) {
        let gi = dev.client.create_group(&qualified(conversation_id)).unwrap();
        let (st, j) = self
            .post(
                &format!("/api/v1/conversations/{conversation_id}/mls/group"),
                dev.token(),
                json!({ "group_info": b64(&gi) }),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
    }

    /// Claims the KeyPackages of `username`'s devices.
    pub async fn claim(&self, token: &str, username: &str) -> Vec<Vec<u8>> {
        let (st, j) = self.post(&format!("/api/v1/users/{username}/key-packages/claim"), token, json!({})).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        j["key_packages"].as_array().unwrap().iter().map(|k| unb64(&k["key_package"])).collect()
    }

    /// Posts a commit output; returns status and body without merging.
    pub async fn post_commit(
        &self,
        token: &str,
        conversation_id: &str,
        out: &tavrn_crypto::CommitOutput,
    ) -> (StatusCode, Value) {
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

    /// Adds all devices of `username` (claim + commit + merge). Returns the Welcome.
    pub async fn add_user(&self, dev: &mut Dev, conversation_id: &str, username: &str) -> Vec<u8> {
        let kps = self.claim(dev.token(), username).await;
        assert!(!kps.is_empty(), "{username} has KeyPackages");
        let out = dev.client.add_members(&qualified(conversation_id), &kps).unwrap();
        let (st, j) = self.post_commit(dev.token(), conversation_id, &out).await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
        dev.client.merge_pending_commit(&qualified(conversation_id)).unwrap();
        out.welcome.unwrap()
    }

    /// Fetches the device's pending Welcomes and joins with each.
    pub async fn accept_welcomes(&self, dev: &mut Dev) -> usize {
        let (st, j) = self.get_auth("/api/v1/mls/welcomes", dev.token()).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        let items = j["items"].as_array().unwrap().clone();
        for w in &items {
            let (conv, _) = dev.client.join_by_welcome(&unb64(&w["welcome"])).unwrap();
            assert_eq!(conv, qualified(w["conversation_id"].as_str().unwrap()));
            let (st, _) =
                self.delete(&format!("/api/v1/mls/welcomes/{}", w["id"].as_str().unwrap()), dev.token()).await;
            assert_eq!(st, StatusCode::NO_CONTENT);
        }
        items.len()
    }

    /// Processes the handshake log from the device's current epoch.
    pub async fn catch_up(&self, dev: &mut Dev, conversation_id: &str) {
        let conv = qualified(conversation_id);
        let since = dev.client.current_epoch(&conv).unwrap();
        let (st, j) = self
            .get_auth(&format!("/api/v1/conversations/{conversation_id}/mls/messages?since_epoch={since}"), dev.token())
            .await;
        assert_eq!(st, StatusCode::OK, "{j}");
        for item in j["items"].as_array().unwrap() {
            dev.client.process_handshake(&conv, &unb64(&item["commit"])).unwrap();
        }
    }

    /// Sends an encrypted text message to a conversation route.
    pub async fn send_encrypted(&self, dev: &Dev, conversation_id: &str, body: &str) -> (StatusCode, Value) {
        let conv = qualified(conversation_id);
        let content = dev.client.encrypt_content(&conv, &json!({ "type": "text", "body": body }).to_string()).unwrap();
        let epoch = dev.client.current_epoch(&conv).unwrap();
        self.post(
            &format!("/api/v1/conversations/{conversation_id}/messages"),
            dev.token(),
            json!({ "content": content, "epoch": epoch }),
        )
        .await
    }
}
