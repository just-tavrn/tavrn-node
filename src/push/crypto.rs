// SPDX-License-Identifier: AGPL-3.0-only
//! The cryptography of web push: the node's VAPID key (RFC 8292) and the payload encryption of RFC 8291
//! (`aes128gcm`, RFC 8188 with a single record).
//!
//! The VAPID key is a P-256 key pair in `<data_dir>/keys/vapid.key` (PKCS#8 PEM, mode 0600), created at the first
//! start and never rotated: browsers bind their subscriptions to its public key, so a new key invalidates every
//! subscription (users enable push again; nothing else is lost).

use std::path::Path;

use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use p256::{
    PublicKey, SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use sha2::Sha256;

/// File name of the VAPID key in `<data_dir>/keys/`.
pub const VAPID_KEY_FILE: &str = "vapid.key";
/// Record size announced in the `aes128gcm` header (one record carries the whole payload).
const RECORD_SIZE: u32 = 4096;
/// Largest plaintext that fits one record (record size − 16 bytes tag − 1 delimiter byte).
pub const MAX_PLAINTEXT: usize = RECORD_SIZE as usize - 17;
/// Lifetime of a VAPID token (RFC 8292 §2: at most 24 hours).
pub const VAPID_TTL_SECS: i64 = 12 * 3600;

/// The node's VAPID key.
#[derive(Clone)]
pub struct VapidKey {
    signing: SigningKey,
    /// Base64url of the uncompressed public point (65 bytes): `applicationServerKey` of the browsers.
    public: String,
}

impl std::fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKey").field("public", &self.public).finish_non_exhaustive()
    }
}

impl VapidKey {
    pub fn generate() -> Self {
        Self::from_secret(SecretKey::random(&mut rand::rngs::OsRng))
    }

    fn from_secret(secret: SecretKey) -> Self {
        let public = URL_SAFE_NO_PAD.encode(secret.public_key().to_encoded_point(false).as_bytes());
        Self { signing: SigningKey::from(secret), public }
    }

    /// Loads `<dir>/vapid.key` or creates it (mode 0600). A file that is not a P-256 PKCS#8 key is an error, never
    /// replaced.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(VAPID_KEY_FILE);
        if !path.exists() {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create key directory {}", dir.display()))?;
            let key = Self::generate();
            let pem = SecretKey::from(&key.signing).to_pkcs8_pem(LineEnding::LF).map_err(|e| anyhow!("PEM: {e}"))?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(pem.as_bytes()).with_context(|| format!("cannot write {}", path.display()))?;
                    file.sync_all().with_context(|| format!("cannot write {}", path.display()))?;
                    tracing::info!(path = %path.display(), "new VAPID key for web push generated");
                    return Ok(key);
                }
                // Another instance created it in the meantime: read that one.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("cannot create {}", path.display())),
            }
        }
        let pem = zeroize::Zeroizing::new(
            std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?,
        );
        let secret = SecretKey::from_pkcs8_pem(&pem)
            .map_err(|e| anyhow!("{} is not a P-256 PKCS#8 key: {e}", path.display()))?;
        Ok(Self::from_secret(secret))
    }

    pub fn public_key(&self) -> &str {
        &self.public
    }

    /// The `Authorization` header value of RFC 8292 for a push service origin (`https://host[:port]`).
    pub fn authorization(&self, audience: &str, contact: &str, now_secs: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({ "aud": audience, "exp": now_secs + VAPID_TTL_SECS, "sub": contact });
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let input = format!("{header}.{claims}");
        let signature: Signature = self.signing.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        format!("vapid t={token}, k={}", self.public)
    }
}

/// Why a subscription's keys were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    P256dh,
    Auth,
}

/// Checks the browser's keys of a subscription: `p256dh` a base64url uncompressed P-256 point on the curve,
/// `auth` base64url of 16 bytes.
pub fn check_keys(p256dh: &str, auth: &str) -> Result<(), KeyError> {
    let point = URL_SAFE_NO_PAD.decode(p256dh.trim_end_matches('=')).map_err(|_| KeyError::P256dh)?;
    if point.len() != 65 || point[0] != 4 || PublicKey::from_sec1_bytes(&point).is_err() {
        return Err(KeyError::P256dh);
    }
    let auth = URL_SAFE_NO_PAD.decode(auth.trim_end_matches('=')).map_err(|_| KeyError::Auth)?;
    if auth.len() != 16 {
        return Err(KeyError::Auth);
    }
    Ok(())
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).map_err(|_| anyhow!("HKDF length"))?;
    Ok(out)
}

/// Content key and nonce of RFC 8291 §3.4 and RFC 8188 §2.2.
fn derive(
    ecdh_secret: &[u8],
    auth: &[u8],
    salt: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf_expand(auth, ecdh_secret, &key_info, 32)?;
    let cek = hkdf_expand(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16)?;
    let nonce = hkdf_expand(salt, &ikm, b"Content-Encoding: nonce\0", 12)?;
    Ok((cek, nonce))
}

/// Encrypts `plaintext` for a subscription (`p256dh`, `auth` as base64url) with a fresh sender key and salt.
/// Returns the request body (`Content-Encoding: aes128gcm`).
pub fn encrypt(p256dh: &str, auth: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let as_secret = SecretKey::random(&mut rand::rngs::OsRng);
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    encrypt_with(p256dh, auth, plaintext, &as_secret, &salt)
}

fn encrypt_with(
    p256dh: &str,
    auth: &str,
    plaintext: &[u8],
    as_secret: &SecretKey,
    salt: &[u8; 16],
) -> anyhow::Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(anyhow!("push payload too large ({} bytes)", plaintext.len()));
    }
    let ua_public_bytes = URL_SAFE_NO_PAD.decode(p256dh.trim_end_matches('=')).context("p256dh")?;
    let auth = URL_SAFE_NO_PAD.decode(auth.trim_end_matches('=')).context("auth")?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes).map_err(|_| anyhow!("p256dh is not a P-256 point"))?;
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());
    let (cek, nonce) = derive(shared.raw_secret_bytes(), &auth, salt, &ua_public_bytes, as_public.as_bytes())?;
    // One record: the plaintext and the delimiter 0x02 of the last record, no padding.
    let mut record = plaintext.to_vec();
    record.push(2);
    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|_| anyhow!("key length"))?;
    let sealed = cipher
        .encrypt(nonce.as_slice().try_into().map_err(|_| anyhow!("nonce length"))?, Payload { msg: &record, aad: b"" })
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + sealed.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.as_bytes().len() as u8);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&sealed);
    Ok(body)
}

/// The browser's side: decrypts a single-record `aes128gcm` body with the subscription's private key and `auth`
/// secret. Used by the tests (a fake push service checks what the node sent); a node never decrypts pushes.
pub fn decrypt(ua_secret: &SecretKey, auth: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
    if body.len() < 21 {
        return Err(anyhow!("body too short"));
    }
    let salt = &body[..16];
    let id_len = body[20] as usize;
    let key_end = 21 + id_len;
    let as_public_bytes = body.get(21..key_end).ok_or_else(|| anyhow!("key id missing"))?;
    let as_public = PublicKey::from_sec1_bytes(as_public_bytes).map_err(|_| anyhow!("key id is not a P-256 point"))?;
    let ua_public = ua_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());
    let (cek, nonce) = derive(shared.raw_secret_bytes(), auth, salt, ua_public.as_bytes(), as_public_bytes)?;
    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|_| anyhow!("key length"))?;
    let mut record = cipher
        .decrypt(
            nonce.as_slice().try_into().map_err(|_| anyhow!("nonce length"))?,
            Payload { msg: &body[key_end..], aad: b"" },
        )
        .map_err(|_| anyhow!("decryption failed"))?;
    // Strip the padding and the delimiter of the last record.
    while record.last() == Some(&0) {
        record.pop();
    }
    if record.pop() != Some(2) {
        return Err(anyhow!("not a last record"));
    }
    Ok(record)
}

/// Verifies a VAPID `Authorization` header (`vapid t=<jwt>, k=<key>`) against the expected public key and
/// audience; returns the claims. For the tests' fake push service.
pub fn verify_authorization(header: &str, public_key: &str, audience: &str) -> anyhow::Result<serde_json::Value> {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    let rest = header.strip_prefix("vapid ").ok_or_else(|| anyhow!("not a vapid header"))?;
    let mut token = None;
    let mut key = None;
    for part in rest.split(',').map(str::trim) {
        if let Some(t) = part.strip_prefix("t=") {
            token = Some(t);
        } else if let Some(k) = part.strip_prefix("k=") {
            key = Some(k);
        }
    }
    let (token, key) = (token.ok_or_else(|| anyhow!("t missing"))?, key.ok_or_else(|| anyhow!("k missing"))?);
    if key != public_key {
        return Err(anyhow!("another key"));
    }
    let (input, signature) = token.rsplit_once('.').ok_or_else(|| anyhow!("not a JWT"))?;
    let point = URL_SAFE_NO_PAD.decode(key)?;
    let verifying = VerifyingKey::from_sec1_bytes(&point).map_err(|_| anyhow!("bad key"))?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature)?).map_err(|_| anyhow!("bad signature"))?;
    verifying.verify(input.as_bytes(), &signature).map_err(|_| anyhow!("signature invalid"))?;
    let claims_b64 = input.split('.').nth(1).ok_or_else(|| anyhow!("no claims"))?;
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64)?)?;
    if claims["aud"] != audience {
        return Err(anyhow!("wrong audience {}", claims["aud"]));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn b64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    /// RFC 8291 Appendix A.
    #[test]
    fn rfc8291_example() {
        let as_secret = SecretKey::from_slice(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(as_secret.public_key().to_encoded_point(false).as_bytes()),
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
        );
        let ua_secret = SecretKey::from_slice(&b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")).unwrap();
        let ua_public = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        let auth = "BTBZMqHH6r4Tts7J_aSIgg";
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let body =
            encrypt_with(ua_public, auth, b"When I grow up, I want to be a watermelon", &as_secret, &salt).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
        assert_eq!(decrypt(&ua_secret, &b64(auth), &body).unwrap(), b"When I grow up, I want to be a watermelon");
    }

    #[test]
    fn roundtrip_with_fresh_keys_and_limits() {
        let ua = SecretKey::random(&mut rand::rngs::OsRng);
        let ua_public = URL_SAFE_NO_PAD.encode(ua.public_key().to_encoded_point(false).as_bytes());
        let auth = [7u8; 16];
        let auth_b64 = URL_SAFE_NO_PAD.encode(auth);
        check_keys(&ua_public, &auth_b64).unwrap();
        let a = encrypt(&ua_public, &auth_b64, b"{\"v\":1}").unwrap();
        let b = encrypt(&ua_public, &auth_b64, b"{\"v\":1}").unwrap();
        assert_ne!(a, b, "fresh salt and sender key per push");
        assert_eq!(decrypt(&ua, &auth, &a).unwrap(), b"{\"v\":1}");
        assert!(decrypt(&ua, &[8u8; 16], &a).is_err(), "another auth secret fails");
        assert!(encrypt(&ua_public, &auth_b64, &vec![b'x'; MAX_PLAINTEXT]).is_ok());
        assert!(encrypt(&ua_public, &auth_b64, &vec![b'x'; MAX_PLAINTEXT + 1]).is_err());
        assert_eq!(check_keys("AAAA", &auth_b64), Err(KeyError::P256dh));
        let mut off_curve = vec![4u8];
        off_curve.extend_from_slice(&[1u8; 64]);
        assert_eq!(check_keys(&URL_SAFE_NO_PAD.encode(&off_curve), &auth_b64), Err(KeyError::P256dh));
        assert_eq!(check_keys(&ua_public, "c2hvcnQ"), Err(KeyError::Auth));
    }

    #[test]
    fn vapid_key_file_and_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let key = VapidKey::load_or_create(dir.path()).unwrap();
        let again = VapidKey::load_or_create(dir.path()).unwrap();
        assert_eq!(key.public_key(), again.public_key(), "the key is kept");
        assert_eq!(b64(key.public_key()).len(), 65);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(VAPID_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let header = key.authorization("https://push.example.net", "mailto:ops@example.org", 1_000);
        let claims = verify_authorization(&header, key.public_key(), "https://push.example.net").unwrap();
        assert_eq!(claims["exp"], 1_000 + VAPID_TTL_SECS);
        assert_eq!(claims["sub"], "mailto:ops@example.org");
        assert!(verify_authorization(&header, key.public_key(), "https://other.example").is_err());
        assert!(verify_authorization(&header, VapidKey::generate().public_key(), "https://push.example.net").is_err());
        std::fs::write(dir.path().join(VAPID_KEY_FILE), "garbage").unwrap();
        assert!(VapidKey::load_or_create(dir.path()).is_err(), "a broken key file is never replaced");
    }
}
