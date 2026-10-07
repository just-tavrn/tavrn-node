// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn helpers: `webauthn-authenticator-rs`' software passkey plays browser and authenticator.
//!
//! `SoftPasskey` is not a resident-key authenticator: it signs only for credentials named in
//! `allowCredentials` and returns no user handle. For the discoverable (passkey-only) login the
//! helper therefore names the credential itself and attaches the user handle afterwards, exactly
//! what a browser returns for a resident credential (the user handle is not signed).

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{
    prelude::{CreationChallengeResponse, RequestChallengeResponse, Url, WebauthnAuthenticator},
    softpasskey::SoftPasskey,
};

use super::TestNode;

/// Origin of the test node's relying party (`TAVRN_WEBAUTHN_ORIGIN` of the test config).
pub const ORIGIN: &str = "https://t.local";

pub struct Authenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
    origin: Url,
}

impl Authenticator {
    /// A software passkey that reports user verification (PIN/biometrics) as performed.
    pub fn new() -> Self {
        Self::with_origin(ORIGIN)
    }

    /// The same, but the "browser" runs on another origin (phishing site).
    pub fn with_origin(origin: &str) -> Self {
        Self { inner: WebauthnAuthenticator::new(SoftPasskey::new(true)), origin: Url::parse(origin).unwrap() }
    }

    /// `navigator.credentials.create()` with the node's `options`; returns the credential JSON.
    pub fn register(&mut self, options: &Value) -> Value {
        let options: CreationChallengeResponse = serde_json::from_value(options.clone()).unwrap();
        serde_json::to_value(self.inner.do_registration(self.origin.clone(), options).unwrap()).unwrap()
    }

    /// `navigator.credentials.get()` with the node's `options`; returns the assertion JSON.
    pub fn authenticate(&mut self, options: &Value) -> Value {
        let options: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
        serde_json::to_value(self.inner.do_authentication(self.origin.clone(), options).unwrap()).unwrap()
    }

    /// Assertion for a discoverable login: the authenticator picks `credential_id` and returns
    /// `user_handle`. `user_verification = false` produces an assertion without the UV flag.
    pub fn authenticate_discoverable(
        &mut self,
        options: &Value,
        credential_id: &str,
        user_handle: Option<&[u8]>,
        user_verification: bool,
    ) -> Value {
        let mut options = options.clone();
        options["publicKey"]["allowCredentials"] = json!([{ "type": "public-key", "id": credential_id }]);
        if !user_verification {
            options["publicKey"]["userVerification"] = json!("discouraged");
        }
        let mut assertion = self.authenticate(&options);
        if let Some(handle) = user_handle {
            assertion["response"]["userHandle"] = json!(tavrn_crypto::util::b64url_encode(handle));
        }
        assertion
    }
}

/// WebAuthn user handle of a user id (the ULID's 16 bytes).
pub fn user_handle(user_id: &str) -> Vec<u8> {
    ulid::Ulid::from_string(user_id).unwrap().to_bytes().to_vec()
}

impl TestNode {
    /// Registers a passkey with `bearer` (session or pre-auth token); returns the finish response.
    pub async fn add_passkey(&self, bearer: &str, auth: &mut Authenticator, name: &str) -> Value {
        let (status, finish) = self.try_add_passkey(bearer, auth, name, |_| {}).await;
        assert_eq!(status, StatusCode::OK, "{finish}");
        finish
    }

    /// Like `add_passkey`, but returns status and body; `tweak` may modify the credential JSON.
    pub async fn try_add_passkey(
        &self,
        bearer: &str,
        auth: &mut Authenticator,
        name: &str,
        tweak: impl FnOnce(&mut Value),
    ) -> (StatusCode, Value) {
        let (status, start) = self.post("/api/v1/auth/webauthn/register/start", bearer, json!({})).await;
        if status != StatusCode::OK {
            return (status, start);
        }
        let mut credential = auth.register(&start["options"]);
        tweak(&mut credential);
        self.post(
            "/api/v1/auth/webauthn/register/finish",
            bearer,
            json!({ "challenge_id": start["challenge_id"], "name": name, "response": credential }),
        )
        .await
    }

    /// Second factor step with a passkey; returns status and body of `login/finish`.
    pub async fn passkey_second_factor(&self, preauth: &str, auth: &mut Authenticator) -> (StatusCode, Value) {
        let (status, start) = self
            .req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({ "preauth_token": preauth })))
            .await;
        assert_eq!(status, StatusCode::OK, "{start}");
        let assertion = auth.authenticate(&start["options"]);
        self.req(
            Method::POST,
            "/api/v1/auth/webauthn/login/finish",
            None,
            Some(json!({ "challenge_id": start["challenge_id"], "response": assertion, "preauth_token": preauth })),
        )
        .await
    }
}
