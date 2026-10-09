// SPDX-License-Identifier: AGPL-3.0-only
//! Files channels (`protocol/FILES.md`): a folder tree per channel of kind `files`
//! instead of a chat. End-to-end encrypted channels (§8) keep only ciphertext and entry records the node cannot
//! read; unencrypted ones use the node's storage encryption at rest. Either kind can keep its bytes on an
//! external WebDAV/S3 store per channel ([`remote`]).
//!
//! This module holds what the routes share: name rules, the encrypted backend configuration, the API types
//! and the stream adapters (size limit and hash, sealing for external stores, ranges).

pub mod remote;
pub mod sigv4;

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use axum::body::Bytes;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Stream, StreamExt};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::{app::AppState, error::ApiError, validate::bad};

/// Longest entry name in characters.
pub const MAX_NAME: usize = 255;
/// Deepest folder nesting (a file in the 32nd folder level is the deepest entry).
pub const MAX_DEPTH: usize = 32;
/// Entries (files and folders) per channel; bounds every recursive walk.
pub const MAX_ENTRIES_PER_CHANNEL: i64 = 100_000;
/// Default and largest page of a listing.
pub const LIST_DEFAULT: i64 = 100;
pub const LIST_MAX: i64 = 200;
/// Bytes of an upload read before it is classified (content sniffing needs ~37 KiB for disk images).
pub const SNIFF_BYTES: usize = 64 * 1024;

/// A boxed byte stream as the routes pass them around.
pub type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Bidirectional controls that can disguise an extension (`invoice\u{202e}txt.exe`).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{061c}')
}

/// Validates and normalises an entry name: NFC, trimmed, 1–255 characters, no `/` or `\`, no control or
/// bidirectional control characters, not `.` or `..`.
pub fn entry_name(raw: &str) -> Result<String, ApiError> {
    let name: String = raw.nfc().collect();
    let name = name.trim();
    let invalid = |detail: &str| bad("files.name_invalid", detail.to_string());
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(invalid("Names have 1 to 255 characters"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(invalid("Names cannot contain / or \\"));
    }
    if name.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(invalid("Names cannot contain control characters"));
    }
    if name == "." || name == ".." {
        return Err(invalid("This name is reserved"));
    }
    Ok(name.to_string())
}

/// The case-insensitive key of a name (unique per folder).
pub fn name_key(name: &str) -> String {
    name.to_lowercase().nfc().collect()
}

/// A search term as a `LIKE` pattern on `name_key` (with `\` as the escape character).
pub fn search_pattern(q: &str) -> Result<String, ApiError> {
    let key = name_key(q.trim());
    if key.is_empty() || key.chars().count() > 100 || key.chars().any(char::is_control) {
        return Err(bad("files.search_invalid", "Search terms have 1 to 100 characters"));
    }
    let escaped: String =
        key.chars().flat_map(|c| if matches!(c, '%' | '_' | '\\') { vec!['\\', c] } else { vec![c] }).collect();
    Ok(format!("%{escaped}%"))
}

/// `name (n).ext` for the n-th alternative of a taken name.
pub fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 16 => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// Types served as they are (the client may show them inline); everything else is `application/octet-stream`
/// on download. SVG is never inline.
pub fn served_mime(mime: &str) -> &str {
    let m = mime.split(';').next().unwrap_or("").trim();
    let safe = (m.starts_with("image/") && m != "image/svg+xml")
        || m.starts_with("audio/")
        || m.starts_with("video/")
        || m == "application/pdf"
        || m == "text/plain";
    if safe && m.len() <= 100 && m.bytes().all(|b| b.is_ascii_graphic()) { m } else { "application/octet-stream" }
}

/// The stored type of an upload: the declared one if it is a plain `type/subtype`, else a guess from the name.
pub fn upload_mime(declared: Option<&str>, name: &str, head: &[u8]) -> String {
    let declared = declared.unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let plausible = declared.len() <= 100
        && declared.split_once('/').is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && declared.bytes().all(|c| c.is_ascii_alphanumeric() || b"/.+-_".contains(&c))
        });
    let mime = if plausible && declared != "application/octet-stream" {
        declared
    } else {
        mime_guess::from_path(name).first_raw().unwrap_or("application/octet-stream").to_string()
    };
    if crate::uploads::is_svg(head, name, &mime) { "image/svg+xml".to_string() } else { mime }
}

// ---------------------------------------------------------------- Backend configuration at rest

/// Key for backend configurations: `HKDF-SHA256(IKM = secrets.key, info = "tavrn files backend v1")`.
fn config_key(state: &AppState) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, state.secret_key.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    if hk.expand(b"tavrn files backend v1", out.as_mut()).is_err() {
        out.fill(0);
    }
    out
}

/// `base64url(nonce || AES-256-GCM(json))`, bound to the channel id.
pub fn seal_config(state: &AppState, channel_id: &str, config: &remote::RemoteConfig) -> Result<String, ApiError> {
    let json = Zeroizing::new(serde_json::to_vec(config).map_err(|e| ApiError::Internal(e.into()))?);
    let mut nonce = [0u8; 12];
    crate::util::fill_random(&mut nonce);
    let ct = Aes256Gcm::new((&*config_key(state)).into())
        .encrypt((&nonce).into(), Payload { msg: &json, aad: channel_id.as_bytes() })
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("backend configuration could not be encrypted")))?;
    Ok(URL_SAFE_NO_PAD.encode([nonce.as_slice(), &ct].concat()))
}

pub fn open_config(state: &AppState, channel_id: &str, sealed: &str) -> Result<remote::RemoteConfig, ApiError> {
    let fail = || {
        ApiError::Internal(anyhow::anyhow!(
            "backend configuration of {channel_id} cannot be decrypted (secrets.key replaced or lost?)"
        ))
    };
    let raw = URL_SAFE_NO_PAD.decode(sealed).map_err(|_| fail())?;
    if raw.len() < 12 + 16 {
        return Err(fail());
    }
    let plain = Zeroizing::new(
        Aes256Gcm::new((&*config_key(state)).into())
            .decrypt(raw[..12].try_into().map_err(|_| fail())?, Payload { msg: &raw[12..], aad: channel_id.as_bytes() })
            .map_err(|_| fail())?,
    );
    serde_json::from_slice(&plain).map_err(|_| fail())
}

// ---------------------------------------------------------------- API types

/// A folder or file of a files channel.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FileEntry {
    pub id: String,
    pub channel_id: String,
    /// The folder it is in; `null` at the top level.
    pub parent_id: Option<String>,
    /// `folder` or `file`.
    pub kind: String,
    pub name: String,
    /// Content type (files; empty for folders).
    pub mime: String,
    /// Size in bytes (files; 0 for folders).
    pub size: i64,
    /// SHA-256 of the content, base64url (files).
    pub sha256: String,
    /// User id of the uploader or creator (`null` after the account was deleted).
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Encrypted channels: the entry record (content format 1 with name, type and file key, FILES.md §8.4);
    /// `null` in unencrypted channels and when it was written before the requester's history window (§8.7).
    pub record: Option<String>,
    pub record_epoch: Option<i64>,
    /// Address of the user whose device wrote the record.
    pub record_author: Option<String>,
    pub record_device_id: Option<String>,
    /// When the record was written.
    pub record_at: Option<String>,
    /// Size of the stored thumbnail (encrypted channels; 0 = none).
    pub thumbnail_size: i64,
}

// ---------------------------------------------------------------- Stream adapters

/// Size and hash of a stream that passed through [`metered`].
#[derive(Default)]
pub struct Meter {
    pub len: u64,
    pub exceeded: bool,
    hasher: Sha256,
}

impl Meter {
    /// The SHA-256 so far (base64url).
    pub fn sha256(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.hasher.clone().finalize())
    }
}

/// Counts and hashes a stream; more than `limit` bytes end it with an error (and `exceeded`).
pub fn metered(stream: ByteStream, limit: u64) -> (ByteStream, Arc<Mutex<Meter>>) {
    let meter = Arc::new(Mutex::new(Meter::default()));
    let m = meter.clone();
    let out = stream.map(move |item| {
        let bytes = item?;
        let mut g = m.lock().map_err(|_| std::io::Error::other("meter poisoned"))?;
        g.len += bytes.len() as u64;
        if g.len > limit {
            g.exceeded = true;
            return Err(std::io::Error::other("upload exceeds the size limit"));
        }
        g.hasher.update(&bytes);
        Ok(bytes)
    });
    (Box::pin(out), meter)
}

/// Encrypts a plaintext stream into the storage format (external stores with `encrypt_files`).
pub fn sealed(stream: ByteStream, key: Zeroizing<[u8; 32]>) -> ByteStream {
    let sealer = crate::storage::ChunkSealer::new(&key);
    let state = (stream, Some(sealer));
    Box::pin(futures::stream::unfold(state, |(mut stream, sealer)| async move {
        let mut sealer = sealer?;
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => match sealer.push(&chunk) {
                    Ok(out) if out.is_empty() => continue,
                    Ok(out) => return Some((Ok(Bytes::from(out)), (stream, Some(sealer)))),
                    Err(e) => return Some((Err(std::io::Error::other(e)), (stream, None))),
                },
                Some(Err(e)) => return Some((Err(e), (stream, None))),
                None => {
                    let item = sealer.finish().map(Bytes::from).map_err(std::io::Error::other);
                    return Some((item, (stream, None)));
                }
            }
        }
    }))
}

/// Decrypts a stream of sealed chunks (see [`crate::storage::ChunkOpener`]).
pub fn opened(stream: ByteStream, opener: crate::storage::ChunkOpener) -> ByteStream {
    let state = (stream, Some(opener));
    Box::pin(futures::stream::unfold(state, |(mut stream, opener)| async move {
        let mut opener = opener?;
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => match opener.push(&chunk) {
                    Ok(out) if out.is_empty() => continue,
                    Ok(out) => return Some((Ok(Bytes::from(out)), (stream, Some(opener)))),
                    Err(e) => return Some((Err(std::io::Error::other(e)), (stream, None))),
                },
                Some(Err(e)) => return Some((Err(e), (stream, None))),
                None => {
                    return match opener.finish() {
                        Ok(()) => None,
                        Err(e) => Some((Err(std::io::Error::other(e)), (stream, None))),
                    };
                }
            }
        }
    }))
}

/// Drops the first `skip` bytes and ends after `take` bytes (HTTP ranges).
pub fn sliced(stream: ByteStream, skip: u64, take: u64) -> ByteStream {
    let state = (stream, skip, take);
    Box::pin(futures::stream::unfold(state, |(mut stream, mut skip, mut take)| async move {
        while take > 0 {
            match stream.next().await? {
                Ok(mut chunk) => {
                    if skip >= chunk.len() as u64 {
                        skip -= chunk.len() as u64;
                        continue;
                    }
                    let _ = chunk.split_to(skip as usize);
                    skip = 0;
                    if chunk.len() as u64 > take {
                        chunk.truncate(take as usize);
                    }
                    take -= chunk.len() as u64;
                    if chunk.is_empty() {
                        continue;
                    }
                    return Some((Ok(chunk), (stream, skip, take)));
                }
                Err(e) => return Some((Err(e), (stream, 0, 0))),
            }
        }
        None
    }))
}

/// Reads up to `max` bytes from the front of a stream; returns them and the rest of the stream.
pub async fn read_head(mut stream: ByteStream, max: usize) -> std::io::Result<(Bytes, ByteStream)> {
    let mut head = Vec::new();
    while head.len() < max {
        match stream.next().await {
            Some(chunk) => head.extend_from_slice(&chunk?),
            None => break,
        }
    }
    let head = Bytes::from(head);
    let first: ByteStream =
        Box::pin(futures::stream::iter(if head.is_empty() { vec![] } else { vec![Ok(head.clone())] }));
    Ok((head, Box::pin(first.chain(stream))))
}

/// Longest entry record in bytes (FILES.md §8.4).
pub const MAX_RECORD_BYTES: usize = 8 * 1024;
/// Shortest entry record: version, epoch, nonce, tag and signature (ENCRYPTION.md §5.3).
pub const MIN_RECORD_BYTES: usize = 1 + 8 + 12 + 16 + 64;
/// Largest thumbnail ciphertext.
pub const MAX_THUMBNAIL_BYTES: usize = 1024 * 1024;
/// Client-chosen entry ids must be within this many milliseconds of the node's clock.
pub const ID_SKEW_MS: u64 = 24 * 3600 * 1000;

/// A client-chosen entry id (encrypted channels): a ULID whose time is within a day of `now_ms`.
pub fn client_id(id: Option<&str>, now_ms: u64) -> Result<String, ApiError> {
    let invalid = || bad("files.id_invalid", "id must be a fresh ULID (its time within a day of the node's clock)");
    let id = id.map(str::trim).filter(|i| crate::util::is_ulid(i)).ok_or_else(invalid)?;
    let ts = ulid::Ulid::from_string(id).map_err(|_| invalid())?.timestamp_ms();
    if ts.abs_diff(now_ms) > ID_SKEW_MS {
        return Err(invalid());
    }
    Ok(id.to_string())
}

/// Shape of an entry record (base64url content format 1, 121 bytes to 8 KiB); epochs are checked by the caller.
pub fn record_shape(record: Option<&str>) -> Result<&str, ApiError> {
    let invalid = || bad("files.record_invalid", "record must be encrypted content (format 1) of at most 8 KiB");
    let record = record.filter(|r| !r.is_empty() && r.len() <= MAX_RECORD_BYTES * 4 / 3 + 4).ok_or_else(invalid)?;
    let bytes = tavrn_crypto::util::b64url_decode(record).map_err(|_| invalid())?;
    if bytes.len() < MIN_RECORD_BYTES || bytes.len() > MAX_RECORD_BYTES || tavrn_crypto::content_header(record).is_err()
    {
        return Err(invalid());
    }
    Ok(record)
}

/// Parses a single-range `Range` header against a length: `Some(Ok((start, end)))` (inclusive),
/// `Some(Err(()))` when unsatisfiable, `None` when absent or not a single byte range (served whole).
pub fn parse_range(header: Option<&str>, len: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = header?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let range = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || len == 0 {
            return Some(Err(()));
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end: u64 = if b.is_empty() { len.saturating_sub(1) } else { b.parse().ok()? };
        if start >= len || end < start {
            return Some(Err(()));
        }
        (start, end.min(len - 1))
    };
    Some(Ok(range))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn names_are_validated_and_normalised() {
        assert_eq!(entry_name("  Bericht.pdf ").unwrap(), "Bericht.pdf");
        // NFD "e" + combining acute becomes the composed "é".
        assert_eq!(entry_name("Cafe\u{301}").unwrap(), "Caf\u{e9}");
        assert_eq!(name_key("Caf\u{c9}.TXT"), "caf\u{e9}.txt");
        for bad in
            ["", "   ", "a/b", "..", ".", "a\\b", "a\u{0}b", "line\nbreak", "invoice\u{202e}txt.exe", "x\u{2066}y"]
        {
            assert_eq!(entry_name(bad).unwrap_err().code(), "files.name_invalid", "{bad:?}");
        }
        assert!(entry_name(&"a".repeat(255)).is_ok());
        assert!(entry_name(&"a".repeat(256)).is_err());
        assert!(entry_name("..hidden").is_ok());
        assert!(entry_name("ünïcødé 名前.txt").is_ok());
    }

    #[test]
    fn search_patterns_escape_wildcards() {
        assert_eq!(search_pattern("Rep").unwrap(), "%rep%");
        assert_eq!(search_pattern("50%_a\\").unwrap(), "%50\\%\\_a\\\\%");
        assert!(search_pattern("  ").is_err());
        assert!(search_pattern(&"x".repeat(101)).is_err());
    }

    #[test]
    fn numbered_names_keep_the_extension() {
        assert_eq!(numbered("photo.jpg", 2), "photo (2).jpg");
        assert_eq!(numbered("README", 3), "README (3)");
        assert_eq!(numbered(".bashrc", 2), ".bashrc (2)");
    }

    #[test]
    fn only_safe_types_are_served_as_such() {
        assert_eq!(served_mime("image/png"), "image/png");
        assert_eq!(served_mime("video/mp4; codecs=x"), "video/mp4");
        assert_eq!(served_mime("image/svg+xml"), "application/octet-stream");
        assert_eq!(served_mime("text/html"), "application/octet-stream");
        assert_eq!(served_mime("application/javascript"), "application/octet-stream");
        assert_eq!(upload_mime(Some("image/png"), "x.png", b""), "image/png");
        assert_eq!(upload_mime(None, "notes.pdf", b""), "application/pdf");
        assert_eq!(upload_mime(Some("application/octet-stream"), "a.mp3", b""), "audio/mpeg");
        assert_eq!(upload_mime(Some("image/png"), "x.png", b"<svg xmlns='x'/>"), "image/svg+xml");
        assert_eq!(upload_mime(Some("text/html\r\nX: y"), "x.bin", b""), "application/octet-stream");
    }

    #[test]
    fn client_ids_and_record_shapes_are_checked() {
        let now = 1_760_000_000_000u64;
        let fresh = ulid::Ulid::from_parts(now - 1000, 7).to_string();
        assert_eq!(client_id(Some(&fresh), now).unwrap(), fresh);
        for bad in [None, Some(""), Some("nope"), Some("01J9ZK3G5M8Q2W4E6R8T0Y2Vä1")] {
            assert_eq!(client_id(bad, now).unwrap_err().code(), "files.id_invalid", "{bad:?}");
        }
        let old = ulid::Ulid::from_parts(now - ID_SKEW_MS - 1, 7).to_string();
        let future = ulid::Ulid::from_parts(now + ID_SKEW_MS + 1, 7).to_string();
        assert!(client_id(Some(&old), now).is_err() && client_id(Some(&future), now).is_err());

        let mut raw = vec![1u8];
        raw.extend_from_slice(&3u64.to_be_bytes());
        raw.extend_from_slice(&[0u8; 12 + 16 + 64]);
        let ok = URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(record_shape(Some(&ok)).unwrap(), ok);
        let short = URL_SAFE_NO_PAD.encode(&raw[..100]);
        let mut v2 = raw.clone();
        v2[0] = 2;
        let big = URL_SAFE_NO_PAD.encode([raw.clone(), vec![0u8; MAX_RECORD_BYTES]].concat());
        for bad in [None, Some(""), Some("AQAA"), Some(short.as_str()), Some("not base64!"), Some(big.as_str())] {
            assert_eq!(record_shape(bad).unwrap_err().code(), "files.record_invalid", "{bad:?}");
        }
        assert!(record_shape(Some(&URL_SAFE_NO_PAD.encode(&v2))).is_err(), "unknown version");
    }

    #[test]
    fn ranges_are_parsed() {
        assert_eq!(parse_range(Some("bytes=0-9"), 100), Some(Ok((0, 9))));
        assert_eq!(parse_range(Some("bytes=90-"), 100), Some(Ok((90, 99))));
        assert_eq!(parse_range(Some("bytes=-10"), 100), Some(Ok((90, 99))));
        assert_eq!(parse_range(Some("bytes=50-500"), 100), Some(Ok((50, 99))));
        assert_eq!(parse_range(Some("bytes=100-"), 100), Some(Err(())));
        assert_eq!(parse_range(Some("bytes=9-3"), 100), Some(Err(())));
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), None);
        assert_eq!(parse_range(Some("items=0-1"), 100), None);
        assert_eq!(parse_range(None, 100), None);
    }

    fn stream_of(parts: &[&[u8]]) -> ByteStream {
        let v: Vec<std::io::Result<Bytes>> = parts.iter().map(|p| Ok(Bytes::copy_from_slice(p))).collect();
        Box::pin(futures::stream::iter(v))
    }

    async fn collect(s: ByteStream) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut s = s;
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c?);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn streams_are_metered_sliced_sealed_and_opened() {
        let (s, meter) = metered(stream_of(&[b"hello ", b"world"]), 11);
        assert_eq!(collect(s).await.unwrap(), b"hello world");
        assert_eq!(meter.lock().unwrap().len, 11);
        assert_eq!(meter.lock().unwrap().sha256(), URL_SAFE_NO_PAD.encode(Sha256::digest(b"hello world")));
        let (s, meter) = metered(stream_of(&[b"hello ", b"world"]), 10);
        assert!(collect(s).await.is_err());
        assert!(meter.lock().unwrap().exceeded);

        assert_eq!(collect(sliced(stream_of(&[b"0123", b"4567", b"89"]), 3, 5)).await.unwrap(), b"34567");
        assert_eq!(collect(sliced(stream_of(&[b"0123"]), 0, 10)).await.unwrap(), b"0123");

        let (head, rest) = read_head(stream_of(&[b"ab", b"cd", b"ef"]), 3).await.unwrap();
        assert_eq!(&head[..], b"abcd");
        assert_eq!(collect(rest).await.unwrap(), b"abcdef");

        let key = Zeroizing::new([5u8; 32]);
        let plain: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let parts: Vec<&[u8]> = plain.chunks(7000).collect();
        let sealed_bytes = collect(sealed(stream_of(&parts), key.clone())).await.unwrap();
        assert_eq!(sealed_bytes, crate::storage::encrypt_bytes(&key, &plain).await.unwrap());
        let opener = crate::storage::ChunkOpener::new(&key, plain.len() as u64, 0, true);
        let sealed_parts: Vec<&[u8]> = sealed_bytes.chunks(3333).collect();
        assert_eq!(collect(opened(stream_of(&sealed_parts), opener)).await.unwrap(), plain);
        let opener = crate::storage::ChunkOpener::new(&key, plain.len() as u64, 0, true);
        assert!(collect(opened(stream_of(&[&sealed_bytes[..1000]]), opener)).await.is_err(), "truncated");
    }
}
