// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]
//! Test helpers: in-memory nodes. With `TAVRN_TEST_DATABASE_URL` (PostgreSQL) every test node gets its own
//! fresh database, dropped with the node (`databases`), otherwise SQLite in-memory.

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Method, Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tavrn_node::{
    app::{AppState, router},
    config::Config,
};
use tower::ServiceExt;

pub mod cluster;
pub mod crossnode;
pub mod databases;
pub mod e2ee;
pub mod federation;
pub mod logs;
pub mod oidc;
pub mod webauthn;

pub struct TestNode {
    pub router: Router,
    pub state: AppState,
    /// TOTP secret and unused recovery codes per username (filled by `register`).
    pub factors: std::sync::Mutex<std::collections::HashMap<String, Factors>>,
    /// Reauth token of each login's access token (`AuthResponse.reauth_token`): `req` sends it as `Tavrn-Reauth`, as
    /// a client does right after signing in (PROTOCOL.md §5c). Tokens from a refresh have none.
    pub reauth: std::sync::Mutex<std::collections::HashMap<String, String>>,
    _tmp: tempfile::TempDir,
    /// The node's PostgreSQL database, dropped with the node (after everything else).
    _db: Option<databases::TestDatabase>,
}

/// TOTP secret and unused recovery codes of a test user.
pub type Factors = (Vec<u8>, Vec<String>);

pub struct Session {
    pub token: String,
    pub refresh: String,
    pub user_id: String,
    pub username: String,
    pub device_id: String,
    /// Raw TOTP secret enrolled by `register`.
    pub totp_secret: Vec<u8>,
    /// The ten recovery codes shown at enrollment.
    pub recovery_codes: Vec<String>,
}

/// Date of birth the helpers register with (an adult, PROTOCOL.md §5e).
pub const ADULT_DATE_OF_BIRTH: &str = "1990-01-01";

/// Password the helpers use for `username`.
pub fn password(username: &str) -> String {
    format!("password-{username}-123")
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// TOTP code (SHA-1, 6 digits, 30 s) of `secret` at `time`, as an authenticator app computes it.
pub fn totp_code(secret: &[u8], time: u64) -> String {
    totp_rs::Builder::new().with_secret(secret.to_vec()).build().unwrap().generate(time).to_string()
}

/// Decodes the base32 secret returned by `/auth/totp/enroll`.
pub fn totp_secret(base32: &str) -> Vec<u8> {
    totp_rs::Secret::try_from_base32(base32).unwrap().as_bytes().to_vec()
}

/// The database of a test node: a fresh PostgreSQL database with `TAVRN_TEST_DATABASE_URL` (dropped with the
/// returned guard, see [`databases`]), else SQLite in memory.
async fn test_database_url() -> (String, Option<databases::TestDatabase>) {
    let Ok(base) = std::env::var("TAVRN_TEST_DATABASE_URL") else { return ("sqlite::memory:".into(), None) };
    let (url, database) = databases::create(&base).await;
    (url, Some(database))
}

pub fn dev_config(domain: &str, data_dir: &str, database_url: &str) -> Config {
    Config {
        dev: true,
        domain: domain.into(),
        name: format!("Test node {domain}"),
        database_url: database_url.into(),
        data_dir: data_dir.into(),
        // Browsers (and the software authenticator) allow plain http only for localhost.
        webauthn_origin: Some(format!("https://{domain}")),
        ..Config::defaults_for(true)
    }
}

pub async fn test_node(domain: &str) -> TestNode {
    test_node_with(domain, |_| {}).await
}

pub async fn test_node_with(domain: &str, tweak: impl FnOnce(&mut Config)) -> TestNode {
    let tmp = tempfile::tempdir().unwrap();
    let (url, db) = test_database_url().await;
    let mut config = dev_config(domain, &tmp.path().to_string_lossy(), &url);
    tweak(&mut config);
    config.validate().unwrap();
    let state = AppState::init(config).await.unwrap();
    TestNode {
        router: router(state.clone()),
        state,
        factors: Default::default(),
        reauth: Default::default(),
        _tmp: tmp,
        _db: db,
    }
}

impl TestNode {
    pub async fn get(&self, path: &str) -> Response<Body> {
        self.router.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap()
    }

    /// Any request with an optional token and JSON body; returns status and JSON (or null for an empty body).
    pub async fn req(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (status, json) = self.req_inner(method, path, token, body).await;
        self.remember_reauth(&json);
        (status, json)
    }

    /// Remembers the reauth token of a session response (login, registration, SSO).
    pub fn remember_reauth(&self, json: &Value) {
        for session in [json, &json["session"]] {
            if let (Some(access), Some(reauth)) = (session["access_token"].as_str(), session["reauth_token"].as_str()) {
                self.reauth.lock().unwrap().insert(access.to_string(), reauth.to_string());
            }
        }
    }

    /// Forgets the reauth token of `token` (the next sensitive request needs a fresh one).
    pub fn forget_reauth(&self, token: &str) {
        self.reauth.lock().unwrap().remove(token);
    }

    async fn req_inner(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
            if let Some(r) = self.reauth.lock().unwrap().get(t) {
                builder = builder.header("tavrn-reauth", r.as_str());
            }
        }
        let request = match body {
            Some(b) => {
                builder.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())).unwrap()
            }
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()))
        };
        (status, json)
    }

    /// Request with a raw body and extra headers; returns status, headers and raw body.
    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        token: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, axum::http::HeaderMap, Bytes) {
        let mut builder =
            Request::builder().method(method).uri(path).header(header::AUTHORIZATION, format!("Bearer {token}"));
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = self.router.clone().oneshot(builder.body(Body::from(body)).unwrap()).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        (status, headers, body_bytes(resp).await)
    }

    /// GET with a token, returning the raw response (headers, binary bodies).
    pub async fn get_with(&self, path: &str, token: &str) -> Response<Body> {
        let request =
            Request::get(path).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap();
        self.router.clone().oneshot(request).await.unwrap()
    }

    pub async fn post(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.req(Method::POST, path, Some(token), Some(body)).await
    }
    pub async fn patch(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.req(Method::PATCH, path, Some(token), Some(body)).await
    }
    pub async fn put(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.req(Method::PUT, path, Some(token), Some(body)).await
    }
    pub async fn get_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.req(Method::GET, path, Some(token), None).await
    }
    pub async fn delete(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.req(Method::DELETE, path, Some(token), None).await
    }

    /// Registers `username` (an adult), enrolls TOTP with the pre-auth token and returns the full session.
    pub async fn register(&self, username: &str) -> Session {
        self.register_born(username, ADULT_DATE_OF_BIRTH).await
    }

    /// Registers `username` with the date of birth `date_of_birth` (`YYYY-MM-DD`), enrolls TOTP and returns the
    /// full session.
    pub async fn register_born(&self, username: &str, date_of_birth: &str) -> Session {
        let preauth = self.register_preauth_born(username, date_of_birth).await;
        let (secret, confirmed) = self.enroll_totp(&preauth).await;
        let session = &confirmed["session"];
        let codes: Vec<String> =
            confirmed["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        self.factors.lock().unwrap().insert(username.into(), (secret.clone(), codes.clone()));
        Session {
            token: session["access_token"].as_str().unwrap().into(),
            refresh: session["refresh_token"].as_str().unwrap().into(),
            user_id: session["user"]["id"].as_str().unwrap().into(),
            username: username.into(),
            device_id: session["device_id"].as_str().unwrap().into(),
            totp_secret: secret,
            recovery_codes: codes,
        }
    }

    /// Registers `username` without enrolling a factor; returns the pre-auth token (stage `enroll`).
    pub async fn register_preauth(&self, username: &str) -> String {
        self.register_preauth_born(username, ADULT_DATE_OF_BIRTH).await
    }

    /// [`TestNode::register_preauth`] with the date of birth `date_of_birth`.
    pub async fn register_preauth_born(&self, username: &str, date_of_birth: &str) -> String {
        let body = json!({ "username": username, "password": password(username), "device_name": "test", "date_of_birth": date_of_birth });
        let (status, json) = self.req(Method::POST, "/api/v1/auth/register", None, Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "registration of {username}: {json}");
        assert_eq!(json["status"], "enrollment_required", "{json}");
        assert!(json.get("access_token").is_none(), "no session before the second factor: {json}");
        json["preauth_token"].as_str().unwrap().into()
    }

    /// Enrolls and confirms TOTP with `bearer` (pre-auth token or session); returns the raw secret
    /// and the confirm response (`recovery_codes`, `session`).
    pub async fn enroll_totp(&self, bearer: &str) -> (Vec<u8>, Value) {
        let (status, enroll) = self.post("/api/v1/auth/totp/enroll", bearer, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{enroll}");
        let secret = totp_secret(enroll["secret"].as_str().unwrap());
        let (status, confirmed) =
            self.post("/api/v1/auth/totp/confirm", bearer, json!({ "code": totp_code(&secret, now_secs()) })).await;
        assert_eq!(status, StatusCode::OK, "{confirmed}");
        (secret, confirmed)
    }

    /// Password step of the login; returns the response (status and pre-auth token).
    pub async fn login_preauth(&self, username: &str, password: &str) -> Value {
        let (status, json) = self
            .req(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({ "username": username, "password": password, "device_name": "second" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "Login {username}: {json}");
        json
    }

    /// Second factor step with the user's TOTP secret. A code is accepted once per 30-second step,
    /// so after the current and the next step were used the helper falls back to a recovery code.
    pub async fn verify_second_factor(&self, username: &str, preauth: &str) -> Value {
        let (secret, _) = self.factors.lock().unwrap().get(username).cloned().expect("the user's factors");
        let now = now_secs();
        for time in [now, now + 30] {
            let body = json!({ "preauth_token": preauth, "totp_code": totp_code(&secret, time) });
            let (status, json) = self.req(Method::POST, "/api/v1/auth/second-factor/verify", None, Some(body)).await;
            if status == StatusCode::OK {
                return json;
            }
            assert_eq!(json["code"], "auth.second_factor_invalid", "{json}");
        }
        let code = self.factors.lock().unwrap().get_mut(username).unwrap().1.pop().expect("recovery code");
        let body = json!({ "preauth_token": preauth, "recovery_code": code });
        let (status, json) = self.req(Method::POST, "/api/v1/auth/second-factor/verify", None, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        json
    }

    /// Full login (password and TOTP) of a user created with `register`, as a new device.
    pub async fn login(&self, username: &str) -> Session {
        let pre = self.login_preauth(username, &password(username)).await;
        assert_eq!(pre["status"], "second_factor_required", "{pre}");
        let json = self.verify_second_factor(username, pre["preauth_token"].as_str().unwrap()).await;
        let (secret, codes) = self.factors.lock().unwrap().get(username).cloned().unwrap();
        Session {
            token: json["access_token"].as_str().unwrap().into(),
            refresh: json["refresh_token"].as_str().unwrap().into(),
            user_id: json["user"]["id"].as_str().unwrap().into(),
            username: username.into(),
            device_id: json["device_id"].as_str().unwrap().into(),
            totp_secret: secret,
            recovery_codes: codes,
        }
    }

    pub async fn create_room(&self, token: &str, name: &str) -> Value {
        let (status, json) = self.post("/api/v1/rooms", token, json!({ "name": name })).await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        json
    }

    /// A room whose default text channel is unencrypted, for tests of plaintext features (formats,
    /// limits, moderation). Since phase 2 new channels are end-to-end encrypted by default; the
    /// flag is flipped directly in the database so that no system message is created.
    pub async fn plaintext_room(&self, token: &str, name: &str) -> Value {
        let mut room = self.create_room(token, name).await;
        let channel = Self::text_channel(&room);
        sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
            .bind(&channel)
            .execute(&self.state.db)
            .await
            .unwrap();
        for c in room["channels"].as_array_mut().unwrap() {
            if c["id"] == channel.as_str() {
                c["encrypted"] = json!(false);
            }
        }
        room
    }

    /// Text channel id of the room (the "general" channel created with it).
    pub fn text_channel(room: &Value) -> String {
        room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "text").unwrap()["id"]
            .as_str()
            .unwrap()
            .into()
    }

    pub async fn send(&self, token: &str, room_id: &str, channel_id: &str, body: &str) -> (StatusCode, Value) {
        self.post(
            &format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"),
            token,
            json!({ "content": { "type": "text", "body": body } }),
        )
        .await
    }
}

pub async fn body_bytes(resp: Response<Body>) -> Bytes {
    resp.into_body().collect().await.unwrap().to_bytes()
}

pub async fn body_json(resp: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

pub fn perms(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}
