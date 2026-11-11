// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn helpers: `webauthn-authenticator-rs`' software passkey plays browser and authenticator.
//!
//! `SoftPasskey` is not a resident-key authenticator: it signs only for credentials named in
//! `allowCredentials` and returns no user handle. For the discoverable (passkey-only) login the
//! helper therefore names the credential itself and attaches the user handle afterwards, exactly
//! what a browser returns for a resident credential (the user handle is not signed).
//!
//! The helper calls the authenticator directly with the caller's origin, as a browser or Android's Credential
//! Manager does after its own relying party checks: so the same key also plays an app whose origin is opaque
//! (`android:apk-key-hash:…`, PROTOCOL.md §5a.4), which a browser emulation would refuse before the node sees it.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{
    AuthenticatorBackend,
    prelude::{CreationChallengeResponse, RequestChallengeResponse, Url},
    softpasskey::SoftPasskey,
};

use super::TestNode;

/// Origin of the test node's relying party (`TAVRN_WEBAUTHN_ORIGIN` of the test config).
pub const ORIGIN: &str = "https://t.local";

/// The origin of an Android app (PROTOCOL.md §5a.4) for the tests: `android:apk-key-hash:` and a (fake) SHA-256 in
/// base64url, 32 zero bytes.
pub const APP_ORIGIN: &str = "android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Timeout the "browser" grants the authenticator (the node asks for more; browsers cap it too).
const TIMEOUT_MS: u32 = 60_000;

pub struct Authenticator {
    inner: SoftPasskey,
    origin: Url,
}

impl Authenticator {
    /// A software passkey that reports user verification (PIN/biometrics) as performed.
    pub fn new() -> Self {
        Self::with_origin(ORIGIN)
    }

    /// The same, but the "browser" runs on another origin (phishing site).
    pub fn with_origin(origin: &str) -> Self {
        Self { inner: SoftPasskey::new(true), origin: Url::parse(origin).unwrap() }
    }

    /// The same key, used from now on under `origin` (a passkey made in the app, then used in the browser).
    pub fn use_origin(&mut self, origin: &str) {
        self.origin = Url::parse(origin).unwrap();
    }

    /// `navigator.credentials.create()` with the node's `options`; returns the credential JSON.
    pub fn register(&mut self, options: &Value) -> Value {
        let options: CreationChallengeResponse = serde_json::from_value(options.clone()).unwrap();
        let credential = self.inner.perform_register(self.origin.clone(), options.public_key, TIMEOUT_MS).unwrap();
        serde_json::to_value(credential).unwrap()
    }

    /// `navigator.credentials.get()` with the node's `options`; returns the assertion JSON.
    pub fn authenticate(&mut self, options: &Value) -> Value {
        let options: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
        let assertion = self.inner.perform_auth(self.origin.clone(), options.public_key, TIMEOUT_MS).unwrap();
        serde_json::to_value(assertion).unwrap()
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

/// A synced passkey (backup eligible and backed up) with a known private key that signs assertions by hand: it plays
/// the authenticator of a credential an older node stored, whose `Passkey` JSON a test inserts directly.
pub struct FixedKey {
    signer: FixedSigner,
    pub cred_id: Vec<u8>,
    counter: u32,
}

enum FixedSigner {
    /// ES256 (COSE -7).
    P256(p256::ecdsa::SigningKey),
    /// RS256 (COSE -257, RSASSA-PKCS1-v1_5 with SHA-256), e.g. Windows Hello.
    Rsa(openssl::pkey::PKey<openssl::pkey::Private>),
}

impl FixedKey {
    /// An ES256 key from its private scalar.
    pub fn p256(scalar: [u8; 32], cred_id: &[u8]) -> Self {
        let secret = p256::SecretKey::from_slice(&scalar).unwrap();
        Self::with(FixedSigner::P256(p256::ecdsa::SigningKey::from(secret)), cred_id)
    }

    /// An RS256 key from its PKCS#8 DER (base64).
    pub fn rsa(pkcs8_base64: &str, cred_id: &[u8]) -> Self {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD.decode(pkcs8_base64).unwrap();
        Self::with(FixedSigner::Rsa(openssl::pkey::PKey::private_key_from_pkcs8(&der).unwrap()), cred_id)
    }

    fn with(signer: FixedSigner, cred_id: &[u8]) -> Self {
        Self { signer, cred_id: cred_id.to_vec(), counter: 0 }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match &self.signer {
            FixedSigner::P256(key) => {
                use p256::ecdsa::{Signature, signature::Signer};
                let signature: Signature = key.sign(data);
                signature.to_der().as_bytes().to_vec()
            }
            FixedSigner::Rsa(key) => {
                let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key).unwrap();
                signer.update(data).unwrap();
                signer.sign_to_vec().unwrap()
            }
        }
    }

    /// `navigator.credentials.get()` with the node's `options` on [`ORIGIN`]: user presence and verification, the
    /// next signature counter, and `user_handle` for a discoverable login.
    pub fn authenticate(&mut self, options: &Value, user_handle: Option<&[u8]>) -> Value {
        use sha2::{Digest, Sha256};
        let b64 = tavrn_crypto::util::b64url_encode;
        let pk = &options["publicKey"];
        self.counter += 1;
        let mut auth_data = Sha256::digest(pk["rpId"].as_str().unwrap().as_bytes()).to_vec();
        auth_data.push(0x01 | 0x04 | 0x08 | 0x10); // UP, UV, BE, BS
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get", "challenge": pk["challenge"], "origin": ORIGIN, "crossOrigin": false,
        }))
        .unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self.sign(&signed);
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data), "clientDataJSON": b64(&client_data),
                "signature": b64(&signature), "userHandle": user_handle.map(b64),
            },
            "clientExtensionResults": {},
        })
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
