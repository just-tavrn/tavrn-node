// SPDX-License-Identifier: AGPL-3.0-only
//! Blob storage on the file system: `<data_dir>/blobs/<id[0..2]>/<id>`. File names from input are never used
//! for paths (only the ULID), so path traversal is impossible.
//!
//! **Encryption at rest.** Every file is stored encrypted so that the storage directory (later
//! an S3 bucket) can be copied, backed up or moved without exposing content: per file a random 32-byte key,
//! AES-256-GCM over the content in chunks of 64 KiB (format below), the file key wrapped with the node's
//! *storage key* (`<data_dir>/keys/storage.key`, AES-256-GCM, AAD = storage id) and kept in the `blob_keys`
//! row of the file. This is not end-to-end encryption: the node holds the keys by design and decrypts while
//! streaming a download. Attachments of encrypted conversations are already ciphertext; they are wrapped a
//! second time like everything else (one uniform path, no special case).
//!
//! File format version 1: the 8-byte magic [`MAGIC`], then the chunks. Chunk `i` is
//! `AES-256-GCM(file key, nonce = 0x000000 || u64be(i) || last, plaintext[i * 64 KiB ..][..64 KiB])` including
//! the 16-byte tag; `last` is 1 on the final chunk (truncation and reordering fail authentication). The key is
//! unique per file, so a counter nonce is safe. An empty file is one empty final chunk.
//!
//! A file counts as encrypted only if it starts with the magic **and** has a `blob_keys` row; everything else
//! is plaintext (files from before encryption existed, or written with `TAVRN_STORAGE_ENCRYPTION=off`).
//! [`BlobStorage::encrypt_plaintext`] encrypts those in place (housekeeping, idempotent and resumable). Sizes
//! and SHA-256 hashes in the API always describe the plaintext.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, anyhow, bail};
use axum::body::Bytes;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::Stream;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{config::Config, db::Pool, store::blobs as keys_store};

/// File name of the storage key in `<data_dir>/keys/`.
pub const STORAGE_KEY_FILE: &str = "storage.key";
/// The next storage key while a rotation runs (`tavrn-node rotate-storage-key`); renamed to
/// [`STORAGE_KEY_FILE`] when every file key is re-wrapped.
pub const NEXT_STORAGE_KEY_FILE: &str = "storage.key.next";
/// First bytes of an encrypted file (format version 1).
pub const MAGIC: [u8; 8] = *b"TVRNBLB\x01";
/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
/// `blob_keys.enc_version` of the format above.
pub const ENC_VERSION: i64 = 1;
/// Throughput of the in-place encryption of existing files (bytes per second).
pub const MIGRATION_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

// ---------------------------------------------------------------- Storage key

/// A storage key (wraps the per-file keys) and its fingerprint.
pub struct StorageKey {
    key: Zeroizing<[u8; 32]>,
    id: String,
}

/// A file key wrapped with a storage key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub wrapped: Vec<u8>,
    pub nonce: [u8; 12],
}

impl StorageKey {
    pub fn from_bytes(key: Zeroizing<[u8; 32]>) -> Self {
        let digest = Sha256::new().chain_update(b"tavrn storage key id\0").chain_update(key.as_slice()).finalize();
        let id = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Self { key, id }
    }

    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        crate::util::fill_random(key.as_mut());
        Self::from_bytes(key)
    }

    /// Fingerprint (16 hex digits) stored with every wrapped key; it reveals nothing about the key.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new((&*self.key).into())
    }

    /// Wraps a file key, bound to its storage id (a wrapped key copied to another row does not unwrap).
    pub fn wrap(&self, storage_id: &str, file_key: &[u8; 32]) -> anyhow::Result<WrappedKey> {
        let mut nonce = [0u8; 12];
        crate::util::fill_random(&mut nonce);
        let wrapped = self
            .cipher()
            .encrypt((&nonce).into(), Payload { msg: file_key, aad: storage_id.as_bytes() })
            .map_err(|_| anyhow!("file key could not be wrapped"))?;
        Ok(WrappedKey { wrapped, nonce })
    }

    pub fn unwrap(&self, storage_id: &str, wrapped: &[u8], nonce: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let nonce: &Nonce<_> = nonce.try_into().map_err(|_| anyhow!("wrap nonce of {storage_id} is damaged"))?;
        let plain = Zeroizing::new(
            self.cipher()
                .decrypt(nonce, Payload { msg: wrapped, aad: storage_id.as_bytes() })
                .map_err(|_| anyhow!("the file key of {storage_id} does not unwrap with storage key {}", self.id))?,
        );
        let key: [u8; 32] =
            plain.as_slice().try_into().map_err(|_| anyhow!("the file key of {storage_id} has the wrong length"))?;
        Ok(Zeroizing::new(key))
    }
}

/// The storage keys of the node: `current` wraps new files; `others` (the next key of an interrupted
/// rotation) only unwrap.
pub struct Keyring {
    pub current: StorageKey,
    pub others: Vec<StorageKey>,
}

impl Keyring {
    pub fn single(key: StorageKey) -> Self {
        Self { current: key, others: Vec::new() }
    }

    pub fn by_id(&self, id: &str) -> Option<&StorageKey> {
        std::iter::once(&self.current).chain(&self.others).find(|k| k.id == id)
    }
}

/// Loads the storage key from `<key_dir>/storage.key` or creates it at the first start (0600). Refuses to
/// start if the file is missing while encrypted files exist, or if it matches none of them (wrong file
/// restored): a new key would make every file unreadable and mix keys.
pub async fn load_keyring(key_dir: &Path, db: &Pool) -> anyhow::Result<Keyring> {
    let path = key_dir.join(STORAGE_KEY_FILE);
    let in_use = keys_store::blob_key_ids(db).await?;
    let total: i64 = in_use.iter().map(|(_, n)| n).sum();
    let current = if path.exists() {
        StorageKey::from_bytes(crate::keys::read_key_file(&path)?)
    } else {
        if total > 0 {
            bail!(
                "{} is missing, but {total} stored files are encrypted with it. Restore the key file from your \
                 backup; without it these files cannot be read.",
                path.display()
            );
        }
        match crate::keys::create_key_file(&path)? {
            Some(key) => {
                tracing::info!(path = %path.display(), "new storage key created (back it up with the other keys)");
                StorageKey::from_bytes(key)
            }
            None => StorageKey::from_bytes(crate::keys::read_key_file(&path)?),
        }
    };
    let mut ring = Keyring::single(current);
    let next = key_dir.join(NEXT_STORAGE_KEY_FILE);
    if next.exists() {
        tracing::warn!(path = %next.display(), "an interrupted storage key rotation was found; run `tavrn-node rotate-storage-key` again to finish it");
        ring.others.push(StorageKey::from_bytes(crate::keys::read_key_file(&next)?));
    }
    let unknown: i64 = in_use.iter().filter(|(id, _)| ring.by_id(id).is_none()).map(|(_, n)| n).sum();
    if unknown > 0 && unknown == total {
        bail!(
            "{} matches none of the {total} encrypted files (wrong key file?). Restore the right key from your \
             backup.",
            path.display()
        );
    }
    if unknown > 0 {
        tracing::error!(
            files = unknown,
            "stored files are wrapped with a storage key this node does not have; they cannot be read"
        );
    }
    Ok(ring)
}

/// Report of [`rotate_storage_key`].
#[derive(Debug, PartialEq, Eq)]
pub struct RotationReport {
    pub old_key_id: String,
    pub new_key_id: String,
    pub rewrapped: u64,
    /// Rows wrapped with neither key (unreadable before and after).
    pub unknown: u64,
}

/// Rows re-wrapped per query.
const ROTATION_BATCH: i64 = 500;

/// Key rotation (`tavrn-node rotate-storage-key`, run with the node stopped): creates the next storage key
/// (`storage.key.next`), re-wraps every file key with it (the files themselves are not touched) and replaces
/// `storage.key` with it. Resumable: an interrupted run leaves both files and continues where it stopped.
pub async fn rotate_storage_key(key_dir: &Path, db: &Pool) -> anyhow::Result<RotationReport> {
    let path = key_dir.join(STORAGE_KEY_FILE);
    let next_path = key_dir.join(NEXT_STORAGE_KEY_FILE);
    let ring = load_keyring(key_dir, db).await?;
    let old = &ring.current;
    let next = match ring.others.first() {
        Some(next) => StorageKey::from_bytes(Zeroizing::new(*next.key)),
        None => match crate::keys::create_key_file(&next_path)? {
            Some(key) => StorageKey::from_bytes(key),
            None => StorageKey::from_bytes(crate::keys::read_key_file(&next_path)?),
        },
    };
    if next.id == old.id {
        bail!("{} equals the current storage key; delete it and run the rotation again", next_path.display());
    }
    let mut rewrapped = 0;
    loop {
        let rows = keys_store::blob_keys_wrapped_by(db, &old.id, ROTATION_BATCH).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let (wrapped, nonce) = decode_wrap(&row)?;
            let file_key = old.unwrap(&row.storage_id, &wrapped, &nonce)?;
            let new = next.wrap(&row.storage_id, &file_key)?;
            if keys_store::rewrap_blob_key(db, &row.storage_id, &old.id, &encode_wrap(&new, &next.id, row.enc_version))
                .await?
            {
                rewrapped += 1;
            }
        }
    }
    let unknown: i64 = keys_store::blob_key_ids(db)
        .await?
        .into_iter()
        .filter(|(id, _)| *id != next.id && *id != old.id)
        .map(|(_, n)| n)
        .sum();
    std::fs::rename(&next_path, &path)
        .with_context(|| format!("{} could not replace {}", next_path.display(), path.display()))?;
    Ok(RotationReport {
        old_key_id: old.id.clone(),
        new_key_id: next.id.clone(),
        rewrapped,
        unknown: unknown.max(0) as u64,
    })
}

fn decode_wrap(row: &keys_store::BlobKeyRow) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let wrapped = URL_SAFE_NO_PAD
        .decode(&row.wrapped_key)
        .map_err(|_| anyhow!("wrapped key of {} is damaged", row.storage_id))?;
    let nonce =
        URL_SAFE_NO_PAD.decode(&row.wrap_nonce).map_err(|_| anyhow!("wrap nonce of {} is damaged", row.storage_id))?;
    Ok((wrapped, nonce))
}

fn encode_wrap(w: &WrappedKey, key_id: &str, enc_version: i64) -> keys_store::NewBlobKey {
    keys_store::NewBlobKey {
        wrapped_key: URL_SAFE_NO_PAD.encode(&w.wrapped),
        wrap_nonce: URL_SAFE_NO_PAD.encode(w.nonce),
        key_id: key_id.to_string(),
        enc_version,
    }
}

// ---------------------------------------------------------------- File format

fn chunk_nonce(index: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&index.to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// Chunks and plaintext length of an encrypted file of `file_len` bytes; `None` if the length is impossible.
pub fn encrypted_layout(file_len: u64) -> Option<(u64, u64)> {
    let body = file_len.checked_sub(MAGIC.len() as u64)?;
    if body < TAG as u64 {
        return None;
    }
    let full = (CHUNK + TAG) as u64;
    let chunks = body.div_ceil(full);
    let last = body - (chunks - 1) * full;
    if last < TAG as u64 {
        return None;
    }
    Some((chunks, body - chunks * TAG as u64))
}

/// Number of chunks of a plaintext of `len` bytes (at least one).
fn chunk_count(len: u64) -> u64 {
    len.div_ceil(CHUNK as u64).max(1)
}

/// Reads until `buf` is full or the end of the input; returns the bytes read.
async fn read_full<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Encrypts `len` bytes from `input` into `out` (magic and chunks).
async fn encrypt_stream<R, W>(file_key: &[u8; 32], len: u64, input: &mut R, out: &mut W) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let cipher = Aes256Gcm::new(file_key.into());
    out.write_all(&MAGIC).await?;
    let chunks = chunk_count(len);
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = len;
    for index in 0..chunks {
        let want = remaining.min(CHUNK as u64) as usize;
        let n = read_full(input, &mut buf[..want]).await?;
        if n != want {
            bail!("the file changed while it was encrypted");
        }
        remaining -= n as u64;
        let last = index + 1 == chunks;
        let ct = cipher
            .encrypt((&chunk_nonce(index, last)).into(), &buf[..n])
            .map_err(|_| anyhow!("chunk could not be encrypted"))?;
        out.write_all(&ct).await?;
    }
    Ok(())
}

/// Encrypts a whole plaintext in memory (format version 1).
pub async fn encrypt_bytes(file_key: &[u8; 32], plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(plain.len() + MAGIC.len() + TAG * chunk_count(plain.len() as u64) as usize);
    let mut input = plain;
    encrypt_stream(file_key, plain.len() as u64, &mut input, &mut out).await?;
    Ok(out)
}

/// Size of the encrypted form (magic and chunks) of a plaintext of `len` bytes.
pub fn encrypted_len(len: u64) -> u64 {
    MAGIC.len() as u64 + len + TAG as u64 * chunk_count(len)
}

/// Incremental encryption into the format above when the length is not known in advance (streamed uploads
/// of files channels): at most one chunk of plaintext is held back, because only the end
/// of the input tells whether a full chunk is the last one. The output equals [`encrypt_bytes`].
pub struct ChunkSealer {
    cipher: Aes256Gcm,
    index: u64,
    pending: Vec<u8>,
    header: bool,
}

impl ChunkSealer {
    pub fn new(file_key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(file_key.into()),
            index: 0,
            pending: Vec::with_capacity(CHUNK * 2),
            header: false,
        }
    }

    fn seal(&mut self, plain: &[u8], last: bool, out: &mut Vec<u8>) -> anyhow::Result<()> {
        Self::seal_with(&self.cipher, &mut self.index, plain, last, out)
    }

    /// Seals one chunk; an associated function so that `push` can seal straight out of `pending` (no copy).
    fn seal_with(
        cipher: &Aes256Gcm,
        index: &mut u64,
        plain: &[u8],
        last: bool,
        out: &mut Vec<u8>,
    ) -> anyhow::Result<()> {
        let ct = cipher
            .encrypt((&chunk_nonce(*index, last)).into(), plain)
            .map_err(|_| anyhow!("chunk could not be encrypted"))?;
        *index += 1;
        out.extend_from_slice(&ct);
        Ok(())
    }

    /// Takes plaintext; returns the ciphertext of every chunk that is certainly not the last one (and the
    /// magic before the first output).
    pub fn push(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if !self.header {
            out.extend_from_slice(&MAGIC);
            self.header = true;
        }
        self.pending.extend_from_slice(data);
        let mut start = 0;
        while self.pending.len() - start > CHUNK {
            Self::seal_with(&self.cipher, &mut self.index, &self.pending[start..start + CHUNK], false, &mut out)?;
            start += CHUNK;
        }
        self.pending.drain(..start);
        Ok(out)
    }

    /// Seals the rest as the final chunk (an empty input is one empty final chunk).
    pub fn finish(mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if !self.header {
            out.extend_from_slice(&MAGIC);
        }
        let rest = std::mem::take(&mut self.pending);
        self.seal(&rest, true, &mut out)?;
        Ok(out)
    }
}

/// Incremental decryption of the format above (downloads from an external store). The plaintext length of
/// the whole file is known (the entry's size), so every chunk's sealed size and whether it is the last one
/// follow from its index. Starts at chunk `first_chunk` (ranges); `with_magic`: the input begins with the
/// magic (only when starting at chunk 0).
pub struct ChunkOpener {
    cipher: Aes256Gcm,
    index: u64,
    chunks: u64,
    plain_len: u64,
    pending: Vec<u8>,
    magic_left: usize,
}

impl ChunkOpener {
    pub fn new(file_key: &[u8; 32], plain_len: u64, first_chunk: u64, with_magic: bool) -> Self {
        Self {
            cipher: Aes256Gcm::new(file_key.into()),
            index: first_chunk,
            chunks: chunk_count(plain_len),
            plain_len,
            pending: Vec::with_capacity((CHUNK + TAG) * 2),
            magic_left: if with_magic { MAGIC.len() } else { 0 },
        }
    }

    /// The sealed size of chunk `index`.
    fn sealed_size(&self, index: u64) -> usize {
        if index + 1 == self.chunks { (self.plain_len - index * CHUNK as u64) as usize + TAG } else { CHUNK + TAG }
    }

    /// Takes ciphertext; returns the plaintext of every complete chunk.
    pub fn push(&mut self, mut data: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.magic_left > 0 {
            let n = self.magic_left.min(data.len());
            let at = MAGIC.len() - self.magic_left;
            if data[..n] != MAGIC[at..at + n] {
                bail!("stored file has no valid header");
            }
            self.magic_left -= n;
            data = &data[n..];
        }
        self.pending.extend_from_slice(data);
        let mut out = Vec::new();
        let mut start = 0;
        while self.index < self.chunks {
            let size = self.sealed_size(self.index);
            if self.pending.len() - start < size {
                break;
            }
            let last = self.index + 1 == self.chunks;
            let plain = self
                .cipher
                .decrypt((&chunk_nonce(self.index, last)).into(), &self.pending[start..start + size])
                .map_err(|_| anyhow!("stored file failed authentication (damaged or tampered)"))?;
            out.extend_from_slice(&plain);
            self.index += 1;
            start += size;
        }
        self.pending.drain(..start);
        if self.index == self.chunks && !self.pending.is_empty() {
            bail!("stored file is longer than expected");
        }
        Ok(out)
    }

    /// The input ended: fails when it stopped inside a chunk.
    pub fn finish(self) -> anyhow::Result<()> {
        if self.magic_left > 0 || !self.pending.is_empty() {
            bail!("stored file is truncated");
        }
        Ok(())
    }

    /// Every chunk was opened (a whole file was read).
    pub fn complete(&self) -> bool {
        self.index == self.chunks
    }
}

/// Byte range of the sealed chunks that hold plaintext bytes `start..=end` of a file of `plain_len` bytes:
/// `(first chunk, sealed start offset, sealed end offset inclusive)`.
pub fn sealed_range(plain_len: u64, start: u64, end: u64) -> (u64, u64, u64) {
    let first = start / CHUNK as u64;
    let last = (end / CHUNK as u64).min(chunk_count(plain_len) - 1);
    let full = (CHUNK + TAG) as u64;
    let begin = if first == 0 { 0 } else { MAGIC.len() as u64 + first * full };
    let finish = if last + 1 == chunk_count(plain_len) {
        encrypted_len(plain_len) - 1
    } else {
        MAGIC.len() as u64 + (last + 1) * full - 1
    };
    (first, begin, finish)
}

// ---------------------------------------------------------------- Reading

enum Source {
    Plain { file: tokio::fs::File },
    Encrypted { file: tokio::fs::File, cipher: Box<Aes256Gcm>, index: u64, chunks: u64, remaining: u64 },
}

/// An opened file: its plaintext length and the plaintext as a stream (decrypted chunk by chunk).
pub struct BlobReader {
    /// Plaintext length in bytes.
    pub len: u64,
    /// The file is stored encrypted.
    pub encrypted: bool,
    source: Source,
}

impl BlobReader {
    /// Plaintext chunks; a chunk that fails authentication ends the stream with an error.
    pub fn into_stream(self) -> impl Stream<Item = std::io::Result<Bytes>> + Send + 'static {
        futures::stream::try_unfold(self.source, |mut source| async move {
            match &mut source {
                Source::Plain { file } => {
                    let mut buf = vec![0u8; CHUNK];
                    let n = read_full(file, &mut buf).await?;
                    if n == 0 {
                        return Ok(None);
                    }
                    buf.truncate(n);
                    Ok(Some((Bytes::from(buf), source)))
                }
                Source::Encrypted { file, cipher, index, chunks, remaining } => {
                    if *index == *chunks {
                        return Ok(None);
                    }
                    let last = *index + 1 == *chunks;
                    let size = if last { *remaining } else { (CHUNK + TAG) as u64 } as usize;
                    let mut buf = vec![0u8; size];
                    file.read_exact(&mut buf).await?;
                    *remaining -= size as u64;
                    let plain = cipher.decrypt((&chunk_nonce(*index, last)).into(), buf.as_slice()).map_err(|_| {
                        std::io::Error::other("stored file failed authentication (damaged or tampered)")
                    })?;
                    *index += 1;
                    Ok(Some((Bytes::from(plain), source)))
                }
            }
        })
    }

    /// The whole plaintext (avatars, emojis, sounds: small files).
    pub async fn read_all(self) -> anyhow::Result<Vec<u8>> {
        use futures::TryStreamExt;
        let mut out = Vec::with_capacity(self.len.min(64 * 1024 * 1024) as usize);
        let mut stream = std::pin::pin!(self.into_stream());
        while let Some(chunk) = stream.try_next().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- Storage

/// Report of [`BlobStorage::encrypt_plaintext`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EncryptReport {
    /// Files encrypted in this run and their plaintext bytes.
    pub encrypted: u64,
    pub bytes: u64,
    /// Plaintext files left for a later run (`max_files` reached).
    pub remaining: u64,
    pub failed: u64,
}

#[derive(Clone)]
pub struct BlobStorage {
    root: PathBuf,
    db: Pool,
    keys: Arc<Keyring>,
    /// New files are written encrypted (`TAVRN_STORAGE_ENCRYPTION=on`).
    encrypt: bool,
    /// One in-place encryption run at a time.
    migrating: Arc<tokio::sync::Mutex<()>>,
    /// The last run found no plaintext file (housekeeping skips further runs).
    clean: Arc<AtomicBool>,
}

impl BlobStorage {
    pub fn new(data_dir: &str, db: Pool, keys: Keyring, encrypt: bool) -> Self {
        Self {
            root: Path::new(data_dir).join("blobs"),
            db,
            keys: Arc::new(keys),
            encrypt,
            migrating: Arc::new(tokio::sync::Mutex::new(())),
            clean: Arc::new(AtomicBool::new(!encrypt)),
        }
    }

    /// Storage of the node: loads (or creates) the storage key, warns if encryption is off.
    pub async fn open(config: &Config, db: Pool) -> anyhow::Result<Self> {
        let keys = load_keyring(&Path::new(&config.data_dir).join("keys"), &db).await?;
        let encrypt = config.storage_encryption.enabled();
        if !encrypt {
            tracing::warn!(
                "TAVRN_STORAGE_ENCRYPTION=off: new files are stored UNENCRYPTED (debugging only); encrypted files stay readable"
            );
        }
        Ok(Self::new(&config.data_dir, db, keys, encrypt))
    }

    /// New files are encrypted.
    pub fn encrypts(&self) -> bool {
        self.encrypt
    }

    /// The fingerprint of the current storage key.
    pub fn key_id(&self) -> &str {
        self.keys.current.id()
    }

    fn path(&self, id: &str) -> PathBuf {
        debug_assert!(crate::util::is_ulid(id));
        self.root.join(&id[..2]).join(id)
    }

    /// The path of a stored file (tests check what lies on disk).
    pub fn path_of(&self, id: &str) -> Option<PathBuf> {
        crate::util::is_ulid(id).then(|| self.path(id))
    }

    /// Writes `data` under `<id>.part` (encrypted unless switched off) and returns the key row to store.
    async fn write_part(
        &self,
        id: &str,
        tmp: &Path,
        len: u64,
        input: &mut (impl AsyncRead + Unpin),
    ) -> anyhow::Result<Option<keys_store::NewBlobKey>> {
        let mut f = tokio::fs::File::create(tmp).await.with_context(|| format!("{} not writable", tmp.display()))?;
        let row = if self.encrypt {
            let mut file_key = Zeroizing::new([0u8; 32]);
            crate::util::fill_random(file_key.as_mut());
            let wrapped = self.keys.current.wrap(id, &file_key)?;
            let mut out = tokio::io::BufWriter::with_capacity(CHUNK + TAG, &mut f);
            encrypt_stream(&file_key, len, input, &mut out).await?;
            out.flush().await?;
            Some(encode_wrap(&wrapped, self.keys.current.id(), ENC_VERSION))
        } else {
            tokio::io::copy(input, &mut f).await?;
            None
        };
        f.sync_all().await?;
        Ok(row)
    }

    pub async fn write(&self, id: &str, data: &[u8]) -> anyhow::Result<()> {
        let path = self.path(id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("cannot create blob directory {}", parent.display()))?;
        }
        let tmp = path.with_extension("part");
        let mut input = data;
        let row = match self.write_part(id, &tmp, data.len() as u64, &mut input).await {
            Ok(row) => row,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
        };
        // The key row goes first: a reader that sees the new file always finds its key.
        if let Some(row) = &row
            && let Err(e) = keys_store::put_blob_key(&self.db, id, row).await
        {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            if row.is_some() {
                let _ = keys_store::delete_blob_key(&self.db, id).await;
            }
            return Err(e.into());
        }
        Ok(())
    }

    /// Writes a stream of unknown length (files channels): encrypted chunk by chunk with
    /// at most two chunks in memory, then the key row and the rename as in [`BlobStorage::write`]. Returns
    /// the plaintext length. A failing stream (size limit, aborted upload) leaves nothing behind.
    pub async fn write_stream<S>(&self, id: &str, mut stream: S) -> anyhow::Result<u64>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Unpin,
    {
        use futures::StreamExt;
        let path = self.path(id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("blob directory {} cannot be created", parent.display()))?;
        }
        let tmp = path.with_extension("part");
        let result: anyhow::Result<(u64, Option<keys_store::NewBlobKey>)> = async {
            let f = tokio::fs::File::create(&tmp).await.with_context(|| format!("{} not writable", tmp.display()))?;
            let mut out = tokio::io::BufWriter::with_capacity(CHUNK + TAG, f);
            let mut len = 0u64;
            let row = if self.encrypt {
                let mut file_key = Zeroizing::new([0u8; 32]);
                crate::util::fill_random(file_key.as_mut());
                let wrapped = self.keys.current.wrap(id, &file_key)?;
                let mut sealer = ChunkSealer::new(&file_key);
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    len += chunk.len() as u64;
                    out.write_all(&sealer.push(&chunk)?).await?;
                }
                out.write_all(&sealer.finish()?).await?;
                Some(encode_wrap(&wrapped, self.keys.current.id(), ENC_VERSION))
            } else {
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    len += chunk.len() as u64;
                    out.write_all(&chunk).await?;
                }
                None
            };
            out.flush().await?;
            out.into_inner().sync_all().await?;
            Ok((len, row))
        }
        .await;
        let (len, row) = match result {
            Ok(r) => r,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
        };
        if let Some(row) = &row
            && let Err(e) = keys_store::put_blob_key(&self.db, id, row).await
        {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            if row.is_some() {
                let _ = keys_store::delete_blob_key(&self.db, id).await;
            }
            return Err(e.into());
        }
        Ok(len)
    }

    /// Opens a stored file positioned at plaintext byte `offset` (HTTP ranges): the reader starts at the
    /// chunk that holds `offset`; the returned number of leading plaintext bytes must still be skipped.
    /// `None` if the file does not exist.
    pub async fn open_reader_at(&self, id: &str, offset: u64) -> anyhow::Result<Option<(BlobReader, u64)>> {
        let Some(mut reader) = self.open_reader(id).await? else { return Ok(None) };
        if offset == 0 {
            return Ok(Some((reader, 0)));
        }
        let offset = offset.min(reader.len);
        let skip = match &mut reader.source {
            Source::Plain { file } => {
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                0
            }
            Source::Encrypted { file, index, chunks, remaining, .. } => {
                let first = (offset / CHUNK as u64).min(chunks.saturating_sub(1));
                let pos = first * (CHUNK + TAG) as u64;
                file.seek(std::io::SeekFrom::Start(MAGIC.len() as u64 + pos)).await?;
                *index = first;
                *remaining -= pos;
                offset - first * CHUNK as u64
            }
        };
        Ok(Some((reader, skip)))
    }

    /// A new random file key for an object stored elsewhere under `id` (external stores of files
    /// channels), wrapped with the storage key and kept in `blob_keys` like the node's own files.
    pub async fn new_external_key(&self, id: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let mut file_key = Zeroizing::new([0u8; 32]);
        crate::util::fill_random(file_key.as_mut());
        let wrapped = self.keys.current.wrap(id, &file_key)?;
        keys_store::put_blob_key(&self.db, id, &encode_wrap(&wrapped, self.keys.current.id(), ENC_VERSION)).await?;
        Ok(file_key)
    }

    /// The file key of an object stored elsewhere under `id` (see [`BlobStorage::new_external_key`]).
    pub async fn external_key(&self, id: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let row = keys_store::blob_key(&self.db, id).await?.ok_or_else(|| anyhow!("no file key for {id}"))?;
        if row.enc_version != ENC_VERSION {
            bail!("object {id} has the unknown format {}", row.enc_version);
        }
        let key = self
            .keys
            .by_id(&row.key_id)
            .ok_or_else(|| anyhow!("object {id} is wrapped with an unknown storage key {}", row.key_id))?;
        let (wrapped, nonce) = decode_wrap(&row)?;
        key.unwrap(id, &wrapped, &nonce)
    }

    /// Deletes only the file key of an object stored elsewhere.
    pub async fn delete_key(&self, id: &str) {
        if let Err(e) = keys_store::delete_blob_key(&self.db, id).await {
            tracing::warn!(id, error = %e, "blob key could not be deleted");
        }
    }

    /// Opens a stored file for reading; `None` if it does not exist. Fails if its key cannot be unwrapped
    /// (unknown or wrong storage key).
    pub async fn open_reader(&self, id: &str) -> anyhow::Result<Option<BlobReader>> {
        let mut file = match tokio::fs::File::open(self.path(id)).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file_len = file.metadata().await?.len();
        let mut head = [0u8; MAGIC.len()];
        let n = read_full(&mut file, &mut head).await?;
        if n == MAGIC.len()
            && head == MAGIC
            && let Some(row) = keys_store::blob_key(&self.db, id).await?
        {
            if row.enc_version != ENC_VERSION {
                bail!("stored file {id} has the unknown format {}", row.enc_version);
            }
            let key = self.keys.by_id(&row.key_id).ok_or_else(|| {
                anyhow!(
                    "stored file {id} is wrapped with an unknown storage key {} (restore keys/storage.key)",
                    row.key_id
                )
            })?;
            let (wrapped, nonce) = decode_wrap(&row)?;
            let file_key = key.unwrap(id, &wrapped, &nonce)?;
            let (chunks, len) =
                encrypted_layout(file_len).ok_or_else(|| anyhow!("stored file {id} is damaged (impossible length)"))?;
            let cipher = Box::new(Aes256Gcm::new((&*file_key).into()));
            return Ok(Some(BlobReader {
                len,
                encrypted: true,
                source: Source::Encrypted { file, cipher, index: 0, chunks, remaining: file_len - MAGIC.len() as u64 },
            }));
        }
        file.seek(std::io::SeekFrom::Start(0)).await?;
        Ok(Some(BlobReader { len: file_len, encrypted: false, source: Source::Plain { file } }))
    }

    /// The whole plaintext of a stored file.
    pub async fn read(&self, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self.open_reader(id).await? {
            Some(reader) => Ok(Some(reader.read_all().await?)),
            None => Ok(None),
        }
    }

    /// Files directly in the blob directories last modified before `cutoff`: `(file name, path)`. The
    /// name is a storage id, or `<id>.part` for an interrupted write.
    pub async fn files_before(&self, cutoff: std::time::SystemTime) -> anyhow::Result<Vec<(String, PathBuf)>> {
        let mut out = Vec::new();
        let mut dirs = match tokio::fs::read_dir(&self.root).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(dir) = dirs.next_entry().await? {
            if !dir.file_type().await?.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(dir.path()).await?;
            while let Some(f) = files.next_entry().await? {
                let meta = f.metadata().await?;
                if meta.is_file() && meta.modified().is_ok_and(|m| m < cutoff) {
                    out.push((f.file_name().to_string_lossy().into_owned(), f.path()));
                }
            }
        }
        Ok(out)
    }

    /// Deletes a file found by [`BlobStorage::files_before`] (only paths inside the blob directory) and its key.
    pub async fn delete_path(&self, path: &Path) {
        if !path.starts_with(&self.root) {
            return;
        }
        if let Err(e) = tokio::fs::remove_file(path).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), error = %e, "could not delete blob file");
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()).filter(|n| crate::util::is_ulid(n))
            && let Err(e) = keys_store::delete_blob_key(&self.db, name).await
        {
            tracing::warn!(id = name, error = %e, "blob key could not be deleted");
        }
    }

    /// Deletes a file and its key (deleting the key alone already makes the content unreadable).
    pub async fn delete(&self, id: &str) {
        if let Err(e) = keys_store::delete_blob_key(&self.db, id).await {
            tracing::warn!(id, error = %e, "blob key could not be deleted");
        }
        if let Err(e) = tokio::fs::remove_file(self.path(id)).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(id, error = %e, "could not delete blob file");
        }
    }

    /// The last [`BlobStorage::encrypt_plaintext`] run found nothing left to encrypt.
    pub fn plaintext_clean(&self) -> bool {
        self.clean.load(Ordering::Relaxed)
    }

    /// Is the stored file `id` plaintext (no magic, or no key row)?
    async fn is_plaintext(&self, id: &str, path: &Path) -> anyhow::Result<bool> {
        let mut head = [0u8; MAGIC.len()];
        let n = match tokio::fs::File::open(path).await {
            Ok(mut f) => read_full(&mut f, &mut head).await?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(n < MAGIC.len() || head != MAGIC || keys_store::blob_key(&self.db, id).await?.is_none())
    }

    /// Encrypts one plaintext file in place: ciphertext to `<id>.part`, key row, rename over the original.
    /// Returns the plaintext bytes (0 if there was nothing to do).
    async fn encrypt_in_place(&self, id: &str) -> anyhow::Result<u64> {
        let path = self.path(id);
        if !self.is_plaintext(id, &path).await? {
            return Ok(0);
        }
        let mut src = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let len = src.metadata().await?.len();
        let tmp = path.with_extension("part");
        let row = match self.write_part(id, &tmp, len, &mut src).await {
            Ok(Some(row)) => row,
            Ok(None) => bail!("encryption is switched off"),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
        };
        keys_store::put_blob_key(&self.db, id, &row).await?;
        // Deleted meanwhile: do not bring it back.
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            let _ = tokio::fs::remove_file(&tmp).await;
            let _ = keys_store::delete_blob_key(&self.db, id).await;
            return Ok(0);
        }
        tokio::fs::rename(&tmp, &path).await?;
        Ok(len)
    }

    /// Encrypts plaintext files in place: files written before encryption at rest existed or
    /// while it was off. Idempotent and resumable (every run looks at what lies on disk), at most `max_files`
    /// per run, paced to `bytes_per_sec`, progress in the log. Does nothing while encryption is off.
    pub async fn encrypt_plaintext(&self, max_files: u64, bytes_per_sec: u64) -> anyhow::Result<EncryptReport> {
        let mut report = EncryptReport::default();
        if !self.encrypt {
            return Ok(report);
        }
        let Ok(_guard) = self.migrating.try_lock() else { return Ok(report) };
        let far_future = std::time::SystemTime::now() + Duration::from_secs(86_400 * 365);
        let files = self.files_before(far_future).await?;
        for (name, path) in files.iter().filter(|(n, _)| crate::util::is_ulid(n)) {
            match self.is_plaintext(name, path).await {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(id = %name, error = %e, "stored file could not be checked");
                    continue;
                }
            }
            if report.encrypted >= max_files {
                report.remaining += 1;
                continue;
            }
            match self.encrypt_in_place(name).await {
                Ok(0) => {}
                Ok(bytes) => {
                    report.encrypted += 1;
                    report.bytes += bytes;
                    if report.encrypted.is_multiple_of(100) {
                        tracing::info!(files = report.encrypted, bytes = report.bytes, "encrypting stored files …");
                    }
                    let pause = Duration::from_secs_f64(bytes as f64 / bytes_per_sec.max(1) as f64);
                    tokio::time::sleep(pause.max(Duration::from_millis(1))).await;
                }
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(id = %name, error = %e, "stored file could not be encrypted (retried later)");
                }
            }
        }
        self.clean.store(report.remaining == 0 && report.failed == 0, Ordering::Relaxed);
        Ok(report)
    }
}

/// `image/*,application/pdf` → does `image/png` match? Compared without parameters, case-insensitive.
pub fn mime_allowed(allowed: &[String], mime: &str) -> bool {
    let mime = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if mime.is_empty() || !mime.contains('/') {
        return false;
    }
    allowed.iter().any(|pattern| {
        let p = pattern.trim().to_ascii_lowercase();
        p == "*/*" || p == mime || p.strip_suffix("/*").is_some_and(|prefix| mime.starts_with(&format!("{prefix}/")))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    async fn storage(dir: &Path, encrypt: bool) -> (BlobStorage, Pool) {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        let keys = load_keyring(&dir.join("keys"), &db).await.unwrap();
        (BlobStorage::new(&dir.to_string_lossy(), db.clone(), keys, encrypt), db)
    }

    #[tokio::test]
    async fn write_read_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = storage(dir.path(), true).await;
        let id = crate::util::ulid();
        s.write(&id, b"hello").await.unwrap();
        assert_eq!(s.read(&id).await.unwrap().unwrap(), b"hello");
        s.delete(&id).await;
        assert!(s.read(&id).await.unwrap().is_none());
        s.delete(&id).await; // a second delete is not an error
    }

    #[tokio::test]
    async fn file_on_disk_is_not_the_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        let id = crate::util::ulid();
        let plain = b"secret attachment content, repeated ".repeat(10);
        s.write(&id, &plain).await.unwrap();
        let disk = std::fs::read(s.path_of(&id).unwrap()).unwrap();
        assert!(disk.starts_with(&MAGIC));
        assert!(!disk.windows(16).any(|w| plain.windows(16).any(|p| p == w)), "no plaintext on disk");
        assert_eq!(disk.len(), MAGIC.len() + plain.len() + TAG);
        let row = keys_store::blob_key(&db, &id).await.unwrap().unwrap();
        assert_eq!(row.key_id, s.key_id());
        assert_eq!(row.enc_version, ENC_VERSION);
        let reader = s.open_reader(&id).await.unwrap().unwrap();
        assert!(reader.encrypted);
        assert_eq!(reader.len, plain.len() as u64);
    }

    #[tokio::test]
    async fn chunked_roundtrip_for_every_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = storage(dir.path(), true).await;
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 17] {
            let id = crate::util::ulid();
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            s.write(&id, &data).await.unwrap();
            let file_len = std::fs::metadata(s.path_of(&id).unwrap()).unwrap().len();
            assert_eq!(encrypted_layout(file_len).map(|(_, plain)| plain), Some(len as u64), "{len}");
            assert_eq!(s.read(&id).await.unwrap().unwrap(), data, "{len}");
        }
    }

    #[test]
    fn layout_rejects_impossible_lengths() {
        assert_eq!(encrypted_layout(0), None);
        assert_eq!(encrypted_layout(8 + 15), None);
        assert_eq!(encrypted_layout(8 + 16), Some((1, 0)));
        assert_eq!(encrypted_layout((8 + CHUNK + TAG + 5) as u64), None, "a last chunk shorter than a tag");
        assert_eq!(encrypted_layout((8 + CHUNK + TAG + TAG + 1) as u64), Some((2, CHUNK as u64 + 1)));
    }

    #[tokio::test]
    async fn tampering_truncation_and_reordering_fail() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = storage(dir.path(), true).await;
        let id = crate::util::ulid();
        let data = vec![7u8; 2 * CHUNK + 100];
        s.write(&id, &data).await.unwrap();
        let path = s.path_of(&id).unwrap();
        let good = std::fs::read(&path).unwrap();
        // A flipped bit.
        let mut bad = good.clone();
        bad[100] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        assert!(s.read(&id).await.is_err());
        // Truncated after the first chunk (no final chunk).
        std::fs::write(&path, &good[..MAGIC.len() + CHUNK + TAG]).unwrap();
        assert!(s.read(&id).await.is_err());
        // Chunks swapped.
        let c = CHUNK + TAG;
        let mut swapped = good[..8].to_vec();
        swapped.extend_from_slice(&good[8 + c..8 + 2 * c]);
        swapped.extend_from_slice(&good[8..8 + c]);
        swapped.extend_from_slice(&good[8 + 2 * c..]);
        std::fs::write(&path, &swapped).unwrap();
        assert!(s.read(&id).await.is_err());
        std::fs::write(&path, &good).unwrap();
        assert_eq!(s.read(&id).await.unwrap().unwrap(), data);
    }

    #[tokio::test]
    async fn a_key_row_copied_to_another_file_does_not_unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        let (a, b) = (crate::util::ulid(), crate::util::ulid());
        s.write(&a, b"aaa").await.unwrap();
        s.write(&b, b"bbb").await.unwrap();
        let row_a = keys_store::blob_key(&db, &a).await.unwrap().unwrap();
        let copy = keys_store::NewBlobKey {
            wrapped_key: row_a.wrapped_key,
            wrap_nonce: row_a.wrap_nonce,
            key_id: row_a.key_id,
            enc_version: row_a.enc_version,
        };
        keys_store::put_blob_key(&db, &b, &copy).await.unwrap();
        assert!(s.read(&b).await.is_err(), "the AAD binds the wrapped key to its storage id");
    }

    #[tokio::test]
    async fn wrong_storage_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        let id = crate::util::ulid();
        s.write(&id, b"secret").await.unwrap();
        // Another storage key cannot unwrap the file key.
        let other =
            BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), Keyring::single(StorageKey::generate()), true);
        let err = other.read(&id).await.unwrap_err().to_string();
        assert!(err.contains("unknown storage key"), "{err}");
        // A wrong key file under the right fingerprint fails the authentication.
        let row = keys_store::blob_key(&db, &id).await.unwrap().unwrap();
        let mut forged = StorageKey::generate();
        forged.id = row.key_id.clone();
        let other = BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), Keyring::single(forged), true);
        assert!(other.read(&id).await.unwrap_err().to_string().contains("does not unwrap"));
        // The node refuses to start with a replaced or missing key file.
        let keys = dir.path().join("keys");
        let original = std::fs::read(keys.join(STORAGE_KEY_FILE)).unwrap();
        std::fs::write(keys.join(STORAGE_KEY_FILE), [9u8; 32]).unwrap();
        let err = load_keyring(&keys, &db).await.err().unwrap().to_string();
        assert!(err.contains("matches none"), "{err}");
        std::fs::remove_file(keys.join(STORAGE_KEY_FILE)).unwrap();
        let err = load_keyring(&keys, &db).await.err().unwrap().to_string();
        assert!(err.contains("is missing"), "{err}");
        assert!(!keys.join(STORAGE_KEY_FILE).exists(), "no new key replaces the lost one");
        std::fs::write(keys.join(STORAGE_KEY_FILE), &original).unwrap();
        assert!(load_keyring(&keys, &db).await.is_ok());
    }

    #[tokio::test]
    async fn storage_key_file_is_created_once_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        let keys = dir.path().join("keys");
        let first = load_keyring(&keys, &db).await.unwrap();
        let second = load_keyring(&keys, &db).await.unwrap();
        assert_eq!(first.current.id(), second.current.id());
        assert_eq!(std::fs::read(keys.join(STORAGE_KEY_FILE)).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(keys.join(STORAGE_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Signing keys and the secrets key are separate files.
        assert!(crate::keys::NodeKey::load_all(&keys).unwrap().is_empty());
    }

    #[tokio::test]
    async fn off_mode_writes_plaintext_and_still_reads_encrypted_files() {
        let dir = tempfile::tempdir().unwrap();
        let (on, db) = storage(dir.path(), true).await;
        let enc = crate::util::ulid();
        on.write(&enc, b"encrypted before").await.unwrap();
        let keys = load_keyring(&dir.path().join("keys"), &db).await.unwrap();
        let off = BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), keys, false);
        let plain = crate::util::ulid();
        off.write(&plain, b"plain now").await.unwrap();
        assert_eq!(std::fs::read(off.path_of(&plain).unwrap()).unwrap(), b"plain now");
        assert!(keys_store::blob_key(&db, &plain).await.unwrap().is_none());
        assert_eq!(off.read(&enc).await.unwrap().unwrap(), b"encrypted before");
        assert_eq!(off.read(&plain).await.unwrap().unwrap(), b"plain now");
        // Off mode never migrates.
        assert_eq!(off.encrypt_plaintext(u64::MAX, u64::MAX).await.unwrap(), EncryptReport::default());
    }

    #[tokio::test]
    async fn existing_plaintext_files_are_encrypted_in_place_resumably() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        // Plaintext files as an older node left them, one of them starting with the magic but without a key.
        let mut ids = Vec::new();
        for i in 0..5u8 {
            let id = crate::util::ulid();
            let path = s.path_of(&id).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let content =
                if i == 0 { [MAGIC.as_slice(), b"looks encrypted"].concat() } else { vec![i; 1000 * i as usize] };
            std::fs::write(&path, &content).unwrap();
            ids.push((id, content));
        }
        let fresh = crate::util::ulid();
        s.write(&fresh, b"already encrypted").await.unwrap();
        // Readable before the migration.
        for (id, content) in &ids {
            assert_eq!(&s.read(id).await.unwrap().unwrap(), content);
        }
        // Two per run: resumable.
        let first = s.encrypt_plaintext(2, u64::MAX).await.unwrap();
        assert_eq!((first.encrypted, first.remaining, first.failed), (2, 3, 0));
        assert!(!s.plaintext_clean());
        let second = s.encrypt_plaintext(u64::MAX, u64::MAX).await.unwrap();
        assert_eq!((second.encrypted, second.remaining, second.failed), (3, 0, 0));
        assert!(s.plaintext_clean());
        // Idempotent.
        assert_eq!(s.encrypt_plaintext(u64::MAX, u64::MAX).await.unwrap().encrypted, 0);
        for (id, content) in &ids {
            let disk = std::fs::read(s.path_of(id).unwrap()).unwrap();
            assert!(disk.starts_with(&MAGIC) && disk != *content, "encrypted on disk");
            assert!(keys_store::blob_key(&db, id).await.unwrap().is_some());
            assert_eq!(&s.read(id).await.unwrap().unwrap(), content, "same plaintext afterwards");
        }
        assert_eq!(s.read(&fresh).await.unwrap().unwrap(), b"already encrypted");
        // Deleting removes the key row with the file.
        s.delete(&ids[1].0).await;
        assert!(keys_store::blob_key(&db, &ids[1].0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rotation_rewraps_keys_without_touching_files() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        let keys = dir.path().join("keys");
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let id = crate::util::ulid();
            s.write(&id, &[i; 100]).await.unwrap();
            ids.push(id);
        }
        let before: Vec<Vec<u8>> = ids.iter().map(|id| std::fs::read(s.path_of(id).unwrap()).unwrap()).collect();
        let old_id = s.key_id().to_string();
        let report = rotate_storage_key(&keys, &db).await.unwrap();
        assert_eq!(report.old_key_id, old_id);
        assert_ne!(report.new_key_id, old_id);
        assert_eq!((report.rewrapped, report.unknown), (3, 0));
        assert!(!keys.join(NEXT_STORAGE_KEY_FILE).exists());
        let after: Vec<Vec<u8>> = ids.iter().map(|id| std::fs::read(s.path_of(id).unwrap()).unwrap()).collect();
        assert_eq!(before, after, "files are not re-encrypted");
        // The old key no longer opens anything; a node started with the new key reads everything.
        assert!(s.read(&ids[0]).await.is_err());
        let ring = load_keyring(&keys, &db).await.unwrap();
        assert_eq!(ring.current.id(), report.new_key_id);
        let rotated = BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), ring, true);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(rotated.read(id).await.unwrap().unwrap(), vec![i as u8; 100]);
        }
    }

    #[tokio::test]
    async fn an_interrupted_rotation_is_readable_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = storage(dir.path(), true).await;
        let keys = dir.path().join("keys");
        let (a, b) = (crate::util::ulid(), crate::util::ulid());
        s.write(&a, b"aaa").await.unwrap();
        s.write(&b, b"bbb").await.unwrap();
        // Simulate a run that re-wrapped only `a`.
        let next =
            StorageKey::from_bytes(crate::keys::create_key_file(&keys.join(NEXT_STORAGE_KEY_FILE)).unwrap().unwrap());
        let row = keys_store::blob_key(&db, &a).await.unwrap().unwrap();
        let (w, n) = decode_wrap(&row).unwrap();
        let file_key = s.keys.current.unwrap(&a, &w, &n).unwrap();
        let new = encode_wrap(&next.wrap(&a, &file_key).unwrap(), next.id(), ENC_VERSION);
        assert!(keys_store::rewrap_blob_key(&db, &a, s.key_id(), &new).await.unwrap());
        // A node started now holds both keys and reads both files.
        let ring = load_keyring(&keys, &db).await.unwrap();
        let mid = BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), ring, true);
        assert_eq!(mid.read(&a).await.unwrap().unwrap(), b"aaa");
        assert_eq!(mid.read(&b).await.unwrap().unwrap(), b"bbb");
        // The next run finishes with the same next key.
        let report = rotate_storage_key(&keys, &db).await.unwrap();
        assert_eq!((report.new_key_id.as_str(), report.rewrapped), (next.id(), 1));
        let done =
            BlobStorage::new(&dir.path().to_string_lossy(), db.clone(), load_keyring(&keys, &db).await.unwrap(), true);
        assert_eq!(done.read(&a).await.unwrap().unwrap(), b"aaa");
        assert_eq!(done.read(&b).await.unwrap().unwrap(), b"bbb");
    }

    #[test]
    fn mime_patterns() {
        let allowed: Vec<String> = ["image/*", "application/pdf"].iter().map(|s| s.to_string()).collect();
        assert!(mime_allowed(&allowed, "image/png"));
        assert!(mime_allowed(&allowed, "IMAGE/JPEG; charset=x"));
        assert!(mime_allowed(&allowed, "application/pdf"));
        assert!(!mime_allowed(&allowed, "application/x-sh"));
        assert!(!mime_allowed(&allowed, "text/html"));
        assert!(!mime_allowed(&allowed, "not-a-mime"));
        assert!(mime_allowed(&["*/*".to_string()], "anything/else"));
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    const LENGTHS: [usize; 8] = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 7, 3 * CHUNK + 5];

    #[tokio::test]
    async fn the_sealer_produces_the_storage_format() {
        let key = [7u8; 32];
        for len in LENGTHS {
            let plain = sample(len);
            let expected = encrypt_bytes(&key, &plain).await.unwrap();
            for piece in [1usize, 1000, CHUNK, CHUNK + 3, 1 << 20] {
                let mut sealer = ChunkSealer::new(&key);
                let mut out = Vec::new();
                for part in plain.chunks(piece) {
                    out.extend(sealer.push(part).unwrap());
                }
                out.extend(sealer.finish().unwrap());
                assert_eq!(out, expected, "len {len}, piece {piece}");
                assert_eq!(out.len() as u64, encrypted_len(len as u64), "len {len}");
            }
        }
    }

    #[tokio::test]
    async fn the_opener_decrypts_whole_files_and_ranges() {
        let key = [9u8; 32];
        for len in LENGTHS {
            let plain = sample(len);
            let sealed = encrypt_bytes(&key, &plain).await.unwrap();
            let mut opener = ChunkOpener::new(&key, len as u64, 0, true);
            let mut out = Vec::new();
            for part in sealed.chunks(4097) {
                out.extend(opener.push(part).unwrap());
            }
            assert!(opener.complete());
            opener.finish().unwrap();
            assert_eq!(out, plain, "len {len}");
            if len == 0 {
                continue;
            }
            for (start, end) in
                [(0, len - 1), (len / 2, len - 1), (len - 1, len - 1), (len / 3, (len / 3 + 10).min(len - 1))]
            {
                let (first, a, b) = sealed_range(len as u64, start as u64, end as u64);
                let mut opener = ChunkOpener::new(&key, len as u64, first, a == 0);
                let mut out = opener.push(&sealed[a as usize..=b as usize]).unwrap();
                opener.finish().unwrap();
                let skip = start - first as usize * CHUNK;
                out.drain(..skip);
                out.truncate(end - start + 1);
                assert_eq!(out, plain[start..=end], "len {len} range {start}-{end}");
            }
        }
        // Tampering, truncation and a wrong key fail.
        let sealed = encrypt_bytes(&key, &sample(CHUNK + 10)).await.unwrap();
        let mut bad = sealed.clone();
        bad[20] ^= 1;
        assert!(ChunkOpener::new(&key, (CHUNK + 10) as u64, 0, true).push(&bad).is_err());
        let mut opener = ChunkOpener::new(&key, (CHUNK + 10) as u64, 0, true);
        opener.push(&sealed[..sealed.len() - 3]).unwrap();
        assert!(opener.finish().is_err());
        assert!(ChunkOpener::new(&[1u8; 32], (CHUNK + 10) as u64, 0, true).push(&sealed).is_err());
    }

    #[tokio::test]
    async fn streams_are_written_and_read_from_an_offset() {
        for encrypt in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (s, _) = storage(dir.path(), encrypt).await;
            for len in LENGTHS {
                let id = crate::util::ulid();
                let plain = sample(len);
                let parts: Vec<std::io::Result<Bytes>> =
                    plain.chunks(5000).map(|c| Ok(Bytes::copy_from_slice(c))).collect();
                assert_eq!(s.write_stream(&id, futures::stream::iter(parts)).await.unwrap(), len as u64);
                assert_eq!(s.read(&id).await.unwrap().unwrap(), plain, "encrypt {encrypt} len {len}");
                for offset in [0, 1, CHUNK, CHUNK + 5, len.saturating_sub(1)] {
                    if offset >= len {
                        continue;
                    }
                    let (reader, skip) = s.open_reader_at(&id, offset as u64).await.unwrap().unwrap();
                    let mut all = reader.read_all().await.unwrap();
                    all.drain(..skip as usize);
                    assert_eq!(all, plain[offset..], "encrypt {encrypt} len {len} offset {offset}");
                }
            }
            // A failing stream leaves no file behind.
            let id = crate::util::ulid();
            let parts: Vec<std::io::Result<Bytes>> =
                vec![Ok(Bytes::from_static(b"abc")), Err(std::io::Error::other("too large"))];
            assert!(s.write_stream(&id, futures::stream::iter(parts)).await.is_err());
            assert!(s.read(&id).await.unwrap().is_none());
            assert!(!s.path_of(&id).unwrap().with_extension("part").exists());
        }
    }

    #[tokio::test]
    async fn external_keys_are_wrapped_and_found_again() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = storage(dir.path(), true).await;
        let id = crate::util::ulid();
        let key = s.new_external_key(&id).await.unwrap();
        assert_eq!(*s.external_key(&id).await.unwrap(), *key);
        s.delete_key(&id).await;
        assert!(s.external_key(&id).await.is_err());
    }
}
