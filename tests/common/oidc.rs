// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::panic)]
//! A fake OpenID provider for the SSO tests (APPLICATIONS.md §11 step 6): a real HTTP server on
//! `127.0.0.1:<random port>` (the node talks to it over the network, `--dev` allows the `http://` issuer)
//! with discovery, an authorization endpoint that approves at once, a PKCE-checking token endpoint, JWKS and
//! UserInfo. ID tokens are RS256 (openssl keys, signed with jsonwebtoken's RustCrypto signer); every
//! misbehavior the node must refuse can be switched on per test.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, crypto::rust_crypto::DEFAULT_PROVIDER};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CLIENT_ID: &str = "tavrn-test";
pub const CLIENT_SECRET: &str = "test-secret: with spaces & symbols";

pub struct Key {
    pub kid: String,
    der: Vec<u8>,
    pub jwk: Value,
}

impl Key {
    pub fn generate(kid: &str) -> Self {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let jwk = json!({ "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()), "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()) });
        Self { kid: kid.into(), der: rsa.private_key_to_der().unwrap(), jwk }
    }
}

/// Who signs in next and how the provider misbehaves.
#[derive(Clone, Debug)]
pub struct Login {
    pub sub: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub groups: Vec<String>,
}

impl Login {
    pub fn new(sub: &str, username: &str) -> Self {
        Self {
            sub: sub.into(),
            username: username.into(),
            name: format!("{username} (IdP)"),
            email: None,
            email_verified: false,
            groups: vec![],
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Misbehavior {
    pub iss: Option<String>,
    pub aud: Option<Value>,
    pub azp: Option<String>,
    pub exp_offset: Option<i64>,
    pub nonce: Option<String>,
    pub alg_none: bool,
    pub hs256: bool,
    /// Discovery announces this issuer instead of its own.
    pub discovery_issuer: Option<String>,
    /// The token endpoint answers `400 { error }`.
    pub token_error: Option<String>,
    /// The authorization endpoint answers `?error=…`.
    pub authorize_error: Option<String>,
    /// Groups only in UserInfo, not in the ID token.
    pub groups_in_userinfo_only: bool,
    /// UserInfo answers another `sub`.
    pub userinfo_sub: Option<String>,
}

struct Issued {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    login: Login,
}

pub struct Inner {
    pub issuer: String,
    /// Keys published in the JWKS.
    pub published: Vec<Key>,
    /// Kid of the key that signs.
    pub signing_kid: String,
    pub next: Login,
    pub misbehave: Misbehavior,
    codes: HashMap<String, Issued>,
    access: HashMap<String, Login>,
    pub jwks_fetches: usize,
    pub discovery_fetches: usize,
    pub token_requests: usize,
    /// The node's last token request: did it authenticate with HTTP Basic?
    pub last_basic_ok: bool,
    pub last_auth_params: HashMap<String, String>,
}

#[derive(Clone)]
pub struct FakeIdp {
    pub inner: Arc<Mutex<Inner>>,
    pub issuer: String,
}

impl FakeIdp {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let key = Key::generate("k1");
        let inner = Arc::new(Mutex::new(Inner {
            issuer: issuer.clone(),
            signing_kid: key.kid.clone(),
            published: vec![key],
            next: Login::new("sub-default", "default"),
            misbehave: Misbehavior::default(),
            codes: HashMap::new(),
            access: HashMap::new(),
            jwks_fetches: 0,
            discovery_fetches: 0,
            token_requests: 0,
            last_basic_ok: false,
            last_auth_params: HashMap::new(),
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/jwks", get(jwks))
            .route("/userinfo", get(userinfo))
            .with_state(inner.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { inner, issuer }
    }

    pub fn set_login(&self, login: Login) {
        self.inner.lock().unwrap().next = login;
    }

    pub fn misbehave(&self, m: Misbehavior) {
        self.inner.lock().unwrap().misbehave = m;
    }

    /// Rotates to a new signing key that is published at once (the node's cached JWKS does not know it).
    pub fn rotate_key(&self, kid: &str) {
        let mut i = self.inner.lock().unwrap();
        i.published.push(Key::generate(kid));
        i.signing_kid = kid.into();
    }

    /// Signs with a key that is never published.
    pub fn sign_with_unpublished_key(&self) {
        let mut i = self.inner.lock().unwrap();
        i.signing_kid = "ghost".into();
    }

    pub fn jwks_fetches(&self) -> usize {
        self.inner.lock().unwrap().jwks_fetches
    }
}

async fn discovery(State(s): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let mut i = s.lock().unwrap();
    i.discovery_fetches += 1;
    let base = i.issuer.clone();
    Json(json!({
        "issuer": i.misbehave.discovery_issuer.clone().unwrap_or(base.clone()),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "jwks_uri": format!("{base}/jwks"),
        "end_session_endpoint": format!("{base}/logout"),
        "id_token_signing_alg_values_supported": ["RS256", "HS256", "none"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

async fn authorize(State(s): State<Arc<Mutex<Inner>>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let mut i = s.lock().unwrap();
    i.last_auth_params = q.clone();
    let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    if let Some(error) = i.misbehave.authorize_error.clone() {
        return Redirect::to(&format!("{redirect}?error={error}&state={state}")).into_response();
    }
    assert_eq!(q.get("client_id").map(String::as_str), Some(CLIENT_ID));
    assert_eq!(q.get("code_challenge_method").map(String::as_str), Some("S256"));
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    let code = tavrn_node::util::random_token(16);
    let issued = Issued {
        nonce: q.get("nonce").cloned().unwrap_or_default(),
        challenge: q.get("code_challenge").cloned().unwrap_or_default(),
        redirect_uri: redirect.clone(),
        login: i.next.clone(),
    };
    i.codes.insert(code.clone(), issued);
    Redirect::to(&format!("{redirect}?code={code}&state={state}")).into_response()
}

fn b64url_sha256(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

fn form_decode(s: &str) -> String {
    reqwest::Url::parse(&format!("http://x/?x={s}"))
        .ok()
        .and_then(|u| u.query_pairs().next().map(|(_, v)| v.into_owned()))
        .unwrap_or_default()
}

async fn token(
    State(s): State<Arc<Mutex<Inner>>>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let mut i = s.lock().unwrap();
    i.token_requests += 1;
    let bad = |e: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response();
    // Client authentication (HTTP Basic, both parts form-encoded, RFC 6749 §2.3.1).
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok());
    let ok = match basic {
        Some(pair) => pair
            .split_once(':')
            .is_some_and(|(id, secret)| form_decode(id) == CLIENT_ID && form_decode(secret) == CLIENT_SECRET),
        None => false,
    };
    i.last_basic_ok = ok;
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_client" }))).into_response();
    }
    if let Some(e) = i.misbehave.token_error.clone() {
        return bad(&e);
    }
    let Some(issued) = f.get("code").and_then(|c| i.codes.remove(c)) else { return bad("invalid_grant") };
    if f.get("grant_type").map(String::as_str) != Some("authorization_code")
        || f.get("redirect_uri") != Some(&issued.redirect_uri)
        || f.get("code_verifier").map(|v| b64url_sha256(v)) != Some(issued.challenge.clone())
    {
        return bad("invalid_grant");
    }
    let now = chrono::Utc::now().timestamp();
    let m = i.misbehave.clone();
    let login = issued.login.clone();
    let mut claims = json!({
        "iss": m.iss.clone().unwrap_or(i.issuer.clone()),
        "aud": m.aud.clone().unwrap_or(json!(CLIENT_ID)),
        "sub": login.sub,
        "exp": now + m.exp_offset.unwrap_or(300),
        "iat": now,
        "auth_time": now,
        "nonce": m.nonce.clone().unwrap_or(issued.nonce.clone()),
        "preferred_username": login.username,
        "name": login.name,
        "email_verified": login.email_verified,
    });
    if let Some(email) = &login.email {
        claims["email"] = json!(email);
    }
    if let Some(azp) = &m.azp {
        claims["azp"] = json!(azp);
    }
    if !m.groups_in_userinfo_only {
        claims["groups"] = json!(login.groups);
    }
    let id_token = if m.alg_none {
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({ "alg": "none", "kid": i.signing_kid }).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    } else if m.hs256 {
        // Algorithm confusion: HMAC keyed with the public modulus.
        let key = &i.published[0];
        let secret = URL_SAFE_NO_PAD.decode(key.jwk["n"].as_str().unwrap()).unwrap();
        sign(&json!({ "alg": "HS256", "kid": key.kid }), &claims, Algorithm::HS256, &EncodingKey::from_secret(&secret))
    } else {
        let kid = i.signing_kid.clone();
        let der = match i.published.iter().find(|k| k.kid == kid) {
            Some(k) => k.der.clone(),
            None => Key::generate(&kid).der,
        };
        sign(
            &json!({ "alg": "RS256", "kid": kid, "typ": "JWT" }),
            &claims,
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&der),
        )
    };
    let access = tavrn_node::util::random_token(16);
    i.access.insert(access.clone(), login);
    Json(json!({ "access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": id_token }))
        .into_response()
}

fn sign(header: &Value, claims: &Value, alg: Algorithm, key: &EncodingKey) -> String {
    let input =
        format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let signer = (DEFAULT_PROVIDER.signer_factory)(&alg, key).unwrap();
    let sig: Vec<u8> = signer.try_sign(input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

async fn jwks(State(s): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let mut i = s.lock().unwrap();
    i.jwks_fetches += 1;
    Json(json!({ "keys": i.published.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>() }))
}

async fn userinfo(State(s): State<Arc<Mutex<Inner>>>, headers: HeaderMap) -> Response {
    let i = s.lock().unwrap();
    let token =
        headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let Some(login) = token.and_then(|t| i.access.get(t)) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    Json(json!({
        "sub": i.misbehave.userinfo_sub.clone().unwrap_or(login.sub.clone()),
        "preferred_username": login.username,
        "groups": login.groups,
    }))
    .into_response()
}

// ---------------------------------------------------------------- the browser's side of a flow

/// What a simulated browser got at the end of a flow.
#[derive(Debug)]
pub enum Outcome {
    /// The callback redirected with `error` (and `idp_error`).
    CallbackError(String, Option<String>),
    /// The exchange answered.
    Exchange(StatusCode, Value),
}

impl Outcome {
    pub fn ok(self) -> Value {
        match self {
            Self::Exchange(StatusCode::OK, v) => v,
            other => panic!("SSO flow failed: {other:?}"),
        }
    }

    pub fn callback_error(self) -> String {
        match self {
            Self::CallbackError(e, _) => e,
            other => panic!("expected a callback error: {other:?}"),
        }
    }

    pub fn exchange_error(self) -> (StatusCode, String) {
        match self {
            Self::Exchange(s, v) if s != StatusCode::OK => (s, v["code"].as_str().unwrap_or("").to_string()),
            other => panic!("expected an exchange error: {other:?}"),
        }
    }
}

pub fn pkce() -> (String, String) {
    let verifier = tavrn_node::util::random_token(48);
    let challenge = b64url_sha256(&verifier);
    (verifier, challenge)
}

pub const CLIENT_STATE: &str = "client-state-0123456789";

/// The steps up to the callback: start, provider, callback. Returns the redirect's query.
pub async fn until_callback(
    node: &super::TestNode,
    purpose: &str,
    token: Option<&str>,
    challenge: &str,
) -> Result<HashMap<String, String>, (StatusCode, Value)> {
    let body = json!({ "purpose": purpose, "code_challenge": challenge, "client_state": CLIENT_STATE, "device_name": "SSO-Test" });
    let (status, start) = node.req(axum::http::Method::POST, "/api/v1/auth/oidc/start", token, Some(body)).await;
    if status != StatusCode::OK {
        return Err((status, start));
    }
    let url = start["authorization_url"].as_str().unwrap();
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let resp = client.get(url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER, "provider redirects");
    let location = resp.headers()[header::LOCATION.as_str()].to_str().unwrap().to_string();
    let callback = reqwest::Url::parse(&location).unwrap();
    assert_eq!(callback.path(), "/api/v1/auth/oidc/callback");
    let response = node.get(&format!("/api/v1/auth/oidc/callback?{}", callback.query().unwrap_or(""))).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = response.headers()[header::LOCATION].to_str().unwrap().to_string();
    let target = reqwest::Url::parse(&target).unwrap();
    assert_eq!(target.path(), "/sso/callback", "{target}");
    Ok(target.query_pairs().into_owned().collect())
}

/// A whole flow as a browser runs it; `token` = the session for `link`/`reauth` (also sent at the exchange). A
/// login that provisioned an account completes its date of birth right away, as the client's dialog does
/// (PROTOCOL.md §5e; [`exchange`] leaves it out).
pub async fn flow(node: &super::TestNode, purpose: &str, token: Option<&str>) -> Outcome {
    let outcome = exchange(node, purpose, token).await;
    if let Outcome::Exchange(StatusCode::OK, session) = &outcome
        && let Some(access) = session["access_token"].as_str()
    {
        let body = json!({ "date_of_birth": super::ADULT_DATE_OF_BIRTH });
        let (status, json) = node.put("/api/v1/users/me/date-of-birth", access, body).await;
        assert!(status == StatusCode::OK || json["code"] == "age.date_of_birth_set", "{json}");
    }
    outcome
}

/// [`flow`] without completing the date of birth of a provisioned account.
pub async fn exchange(node: &super::TestNode, purpose: &str, token: Option<&str>) -> Outcome {
    let (verifier, challenge) = pkce();
    let query = match until_callback(node, purpose, token, &challenge).await {
        Ok(q) => q,
        Err((status, body)) => return Outcome::Exchange(status, body),
    };
    if let Some(error) = query.get("error") {
        return Outcome::CallbackError(error.clone(), query.get("idp_error").cloned());
    }
    assert_eq!(query.get("state").map(String::as_str), Some(CLIENT_STATE));
    let body = json!({ "code": query["code"], "code_verifier": verifier });
    let (status, json) = node.req(axum::http::Method::POST, "/api/v1/auth/oidc/token", token, Some(body)).await;
    Outcome::Exchange(status, json)
}

/// Configures a test node for the fake provider.
pub fn configure(c: &mut tavrn_node::config::Config, idp: &FakeIdp) {
    c.oidc_issuer = Some(idp.issuer.clone());
    c.oidc_client_id = Some(CLIENT_ID.into());
    c.oidc_client_secret = Some(CLIENT_SECRET.into());
}
