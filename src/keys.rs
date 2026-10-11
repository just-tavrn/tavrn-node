// SPDX-License-Identifier: AGPL-3.0-only
//! Signing keys of the node (Ed25519). Generated at the first start and stored as
//! `<data_dir>/keys/node-<kid>.pem`. All existing keys are published in `.well-known`;
//! the newest one signs.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding},
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct NodeKey {
    pub kid: String,
    pub signing: SigningKey,
}

/// Public representation as a JWK-like object for `.well-known`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct PublicKeyInfo {
    pub kid: String,
    pub alg: String,
    pub crv: String,
    /// Base64url (without padding) of the 32-byte public key.
    pub x: String,
}

impl NodeKey {
    pub fn generate(kid: impl Into<String>) -> Self {
        // What SigningKey::generate does, from the system CSPRNG (ed25519-dalek 2 takes a rand_core 0.6 RNG).
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        crate::util::fill_random(secret.as_mut());
        Self { kid: kid.into(), signing: SigningKey::from_bytes(&secret) }
    }

    pub fn verifying(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            kid: self.kid.clone(),
            alg: "EdDSA".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(self.verifying().as_bytes()),
        }
    }

    fn path(dir: &Path, kid: &str) -> PathBuf {
        dir.join(format!("node-{kid}.pem"))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create key directory {}", dir.display()))?;
        let pem = self.signing.to_pkcs8_pem(LineEnding::LF).map_err(|e| anyhow!("PEM encoding: {e}"))?;
        let path = Self::path(dir, &self.kid);
        std::fs::write(&path, pem.as_bytes()).with_context(|| format!("cannot write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Loads all `node-*.pem` from the directory, sorted by `kid` ascending (newest last).
    pub fn load_all(dir: &Path) -> anyhow::Result<Vec<Self>> {
        let mut keys = Vec::new();
        if !dir.exists() {
            return Ok(keys);
        }
        for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(kid) = name.strip_prefix("node-").and_then(|n| n.strip_suffix(".pem")) else { continue };
            let pem = std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let signing = SigningKey::from_pkcs8_pem(&pem)
                .map_err(|e| anyhow!("{} is not a valid Ed25519 PKCS#8 key: {e}", path.display()))?;
            keys.push(Self { kid: kid.to_string(), signing });
        }
        keys.sort_by(|a, b| a.kid.cmp(&b.kid));
        Ok(keys)
    }

    /// Loads the existing keys or generates a new one at the first start.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Vec<Self>> {
        let keys = Self::load_all(dir)?;
        if !keys.is_empty() {
            return Ok(keys);
        }
        let kid = current_kid();
        let key = Self::generate(&kid);
        key.save(dir)?;
        tracing::info!(kid, dir = %dir.display(), "new node signing key generated");
        Ok(vec![key])
    }
}

/// File name of the node's secret for data at rest (in `<data_dir>/keys/`).
pub const SECRET_KEY_FILE: &str = "secrets.key";

/// Loads the node's 32-byte secret for data at rest (TOTP secrets) from `<dir>/secrets.key`, or
/// creates it at the first start (mode 0600). Unlike the signing keys it is never rotated: losing
/// it makes every stored TOTP secret undecryptable, so it is backed up together with the keys.
pub fn load_or_create_secret(dir: &Path) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    let path = dir.join(SECRET_KEY_FILE);
    if !path.exists()
        && let Some(secret) = create_key_file(&path)?
    {
        tracing::info!(path = %path.display(), "new node secret generated");
        return Ok(secret);
    }
    read_key_file(&path)
}

/// Creates a key file with 32 random bytes (mode 0600, the directory if needed). `None` if another
/// process created it in the meantime (then read that one).
pub fn create_key_file(path: &Path) -> anyhow::Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create key directory {}", dir.display()))?;
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    crate::util::fill_random(secret.as_mut());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(secret.as_slice()).with_context(|| format!("cannot write {}", path.display()))?;
            file.sync_all().with_context(|| format!("cannot write {}", path.display()))?;
            Ok(Some(secret))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot create {}", path.display())),
    }
}

/// Reads a 32-byte key file; a file of another length is a clear error, never replaced.
pub fn read_key_file(path: &Path) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    let bytes =
        zeroize::Zeroizing::new(std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?);
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{} is corrupt (expected 32 bytes, found {})", path.display(), bytes.len()))?;
    Ok(zeroize::Zeroizing::new(secret))
}

/// `kid` from the current date plus a random suffix, e.g. `20261004-3f9a1c` (FEDERATION.md §1.2): a node that
/// restores a backup without its key directory and generates a new key on the same day never repeats a `kid` its
/// peers know with another key (which they would treat as a key conflict). Sorting by `kid` still sorts by date.
fn current_kid() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Days since epoch → date without an external crate (algorithm by Howard Hinnant).
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let mut suffix = [0u8; 3];
    crate::util::fill_random(&mut suffix);
    format!("{y:04}{m:02}{d:02}-{}", suffix.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn generated_key_signs_and_verifies() {
        let k = NodeKey::generate("test");
        let sig = k.signing.sign(b"hello");
        k.verifying().verify(b"hello", &sig).unwrap();
        assert!(k.verifying().verify(b"hello!", &sig).is_err());
    }

    #[test]
    fn public_info_is_base64url_of_32_bytes() {
        let info = NodeKey::generate("k1").public_info();
        assert_eq!(info.alg, "EdDSA");
        assert_eq!(URL_SAFE_NO_PAD.decode(info.x).unwrap().len(), 32);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let k = NodeKey::generate("20260101");
        k.save(dir.path()).unwrap();
        let loaded = NodeKey::load_all(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kid, "20260101");
        assert_eq!(loaded[0].verifying(), k.verifying());
    }

    #[test]
    fn load_or_create_creates_once_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let first = NodeKey::load_or_create(dir.path()).unwrap();
        let second = NodeKey::load_or_create(dir.path()).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].verifying(), second[0].verifying());
    }

    #[test]
    fn keys_are_sorted_by_kid() {
        let dir = tempfile::tempdir().unwrap();
        NodeKey::generate("20260202").save(dir.path()).unwrap();
        NodeKey::generate("20260101").save(dir.path()).unwrap();
        let kids: Vec<_> = NodeKey::load_all(dir.path()).unwrap().into_iter().map(|k| k.kid).collect();
        assert_eq!(kids, vec!["20260101", "20260202"]);
    }

    #[test]
    fn corrupt_pem_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("node-x.pem"), "broken").unwrap();
        let err = NodeKey::load_all(dir.path()).unwrap_err().to_string();
        assert!(err.contains("node-x.pem"), "{err}");
    }

    #[test]
    fn secret_file_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let first = load_or_create_secret(&keys).unwrap();
        let second = load_or_create_secret(&keys).unwrap();
        assert_eq!(*first, *second, "reused at the second start");
        assert_ne!(*first, [0u8; 32]);
        let other = load_or_create_secret(tempfile::tempdir().unwrap().path()).unwrap();
        assert_ne!(*first, *other, "random per node");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(keys.join(SECRET_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The signing key loader ignores the file.
        assert!(NodeKey::load_all(&keys).unwrap().is_empty());
        // A truncated file is a clear error, not a new secret.
        std::fs::write(keys.join(SECRET_KEY_FILE), [1u8; 5]).unwrap();
        let err = load_or_create_secret(&keys).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn current_kid_is_a_date_with_a_random_suffix() {
        let kid = current_kid();
        assert_eq!(kid.len(), 15, "{kid}");
        assert!(kid.starts_with("20") && kid.as_bytes()[8] == b'-', "{kid}");
        assert!(kid[9..].chars().all(|c| c.is_ascii_hexdigit()), "{kid}");
        assert_ne!(current_kid(), current_kid(), "two keys of the same day differ");
    }
}
