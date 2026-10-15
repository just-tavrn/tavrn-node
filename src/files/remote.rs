// SPDX-License-Identifier: AGPL-3.0-only
//! External stores of files channels (protocol/FILES.md §5): WebDAV and S3-compatible
//! object storage, spoken by the node over reqwest. Uploads and downloads are streamed through (bounded
//! memory); the object key is the channel's prefix plus the entry id, so renames and moves never touch the
//! store.
//!
//! SSRF rules as for link previews: only `https` (plain `http` only with `TAVRN_FILES_EXTERNAL_PRIVATE=on`),
//! no credentials in the URL, IP literals and every DNS answer must be public addresses unless the private
//! switch is on (the vetting resolver is the one reqwest connects with, no second lookup), redirects are never
//! followed.

use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
    time::Duration,
};

use reqwest::{Method, StatusCode, Url, header};
use serde::{Deserialize, Serialize};

use super::sigv4::{self, Signer};
use crate::federation::client::{AddressForbidden, SystemLookup, VettingResolver, forbidden_ip};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// No byte for this long ends a transfer (large files may take long in total).
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest URL, prefix, bucket and region accepted.
const MAX_URL: usize = 1024;
const MAX_PREFIX: usize = 200;

/// Kind of a channel's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Internal,
    Webdav,
    S3,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Webdav => "webdav",
            Self::S3 => "s3",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "internal" => Some(Self::Internal),
            "webdav" => Some(Self::Webdav),
            "s3" => Some(Self::S3),
            _ => None,
        }
    }
}

/// Configuration of an external store as it is kept (encrypted) in `file_channel_backends.config`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// WebDAV: the base collection; S3: the endpoint (path-style addressing).
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub bucket: String,
    /// Key prefix (`a/b/`), ends with `/` unless empty.
    #[serde(default)]
    pub prefix: String,
    /// The channel's limit on this store in bytes, set by its managers (`0` = unlimited, FILES.md §5). The node quota
    /// `files_channels.max_bytes` never applies to external stores.
    #[serde(default)]
    pub max_bytes: u64,
}

/// Largest per-channel limit of an external store (1 PiB, like the entitlement keys).
pub const MAX_STORE_BYTES: u64 = 1 << 50;

/// Why an external store refused or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// The configuration is invalid (field name).
    Invalid(&'static str),
    /// `http` without the private switch.
    HttpsRequired,
    /// The host is or resolves to a non-public address.
    AddressForbidden,
    /// The store answered with an unexpected status.
    Status(u16),
    /// Network error or timeout.
    Unreachable,
}

impl RemoteError {
    pub fn into_api(self) -> crate::error::ApiError {
        use crate::error::ApiError;
        match self {
            Self::Invalid(field) => {
                crate::validate::bad("files.backend_invalid", format!("{field} is missing or invalid"))
            }
            Self::HttpsRequired => crate::validate::bad("files.backend_https_required", "The store must use https"),
            Self::AddressForbidden => crate::validate::bad(
                "files.backend_address_forbidden",
                "The store's address is not public (private, loopback or link-local addresses are not allowed)",
            ),
            Self::Status(status) => ApiError::BadGateway {
                code: "files.backend_failed",
                detail: format!("The external store answered with status {status}"),
            },
            Self::Unreachable => ApiError::BadGateway {
                code: "files.backend_unreachable",
                detail: "The external store is not reachable".into(),
            },
        }
    }
}

/// One HTTP client per private switch (vetting resolver, no redirects, no proxy). Fails closed: when the client
/// cannot be built, no request goes out (a default client would connect without the vetting resolver).
fn client(allow_private: bool) -> Result<&'static reqwest::Client, RemoteError> {
    static PUBLIC: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    static PRIVATE: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    let cell = if allow_private { &PRIVATE } else { &PUBLIC };
    cell.get_or_init(|| {
        let resolver = VettingResolver::new(Arc::new(SystemLookup), allow_private, HashSet::new());
        reqwest::Client::builder()
            .user_agent(format!("tavrn-node/{} (files)", crate::app::SOFTWARE_VERSION))
            .dns_resolver(Arc::new(resolver))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .no_proxy()
            .build()
            .inspect_err(|e| tracing::error!(error = %e, "HTTP client for external file stores cannot be built"))
            .ok()
    })
    .as_ref()
    .ok_or(RemoteError::Unreachable)
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX
        && prefix.split('/').filter(|s| !s.is_empty()).all(|seg| {
            seg != "."
                && seg != ".."
                && seg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
        && !prefix.starts_with('/')
        && !prefix.contains("//")
}

/// Normalises a prefix (`a/b` → `a/b/`).
pub fn normalize_prefix(prefix: &str) -> String {
    let p = prefix.trim().trim_matches('/');
    if p.is_empty() { String::new() } else { format!("{p}/") }
}

/// Checks a URL's shape without contacting it: scheme, credentials, host, IP literal.
pub fn check_url(raw: &str, allow_private: bool) -> Result<Url, RemoteError> {
    if raw.is_empty() || raw.len() > MAX_URL {
        return Err(RemoteError::Invalid("url"));
    }
    let url = Url::parse(raw.trim()).map_err(|_| RemoteError::Invalid("url"))?;
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        "http" => return Err(RemoteError::HttpsRequired),
        _ => return Err(RemoteError::Invalid("url")),
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() || url.query().is_some() {
        return Err(RemoteError::Invalid("url"));
    }
    let host = url.host_str().filter(|h| !h.is_empty()).ok_or(RemoteError::Invalid("url"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && forbidden_ip(ip)
        && !allow_private
    {
        return Err(RemoteError::AddressForbidden);
    }
    Ok(url)
}

/// Validates a configuration for `kind` and returns it normalised.
pub fn validate(kind: Kind, mut c: RemoteConfig, allow_private: bool) -> Result<RemoteConfig, RemoteError> {
    check_url(&c.url, allow_private)?;
    c.url = c.url.trim().to_string();
    c.prefix = normalize_prefix(&c.prefix);
    if !valid_prefix(&c.prefix) {
        return Err(RemoteError::Invalid("prefix"));
    }
    if c.max_bytes > MAX_STORE_BYTES {
        return Err(RemoteError::Invalid("max_bytes"));
    }
    let short = |s: &str, max: usize| s.len() <= max && !s.chars().any(char::is_control);
    match kind {
        Kind::Internal => return Err(RemoteError::Invalid("kind")),
        Kind::Webdav => {
            if !short(&c.username, 256) || !short(&c.password, 1024) || c.username.contains(':') {
                return Err(RemoteError::Invalid("username"));
            }
            if !c.url.ends_with('/') {
                c.url.push('/');
            }
            c.access_key.clear();
            c.secret_key.clear();
            c.region.clear();
            c.bucket.clear();
        }
        Kind::S3 => {
            let bucket_ok = (3..=63).contains(&c.bucket.len())
                && c.bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'));
            if !bucket_ok {
                return Err(RemoteError::Invalid("bucket"));
            }
            if c.access_key.is_empty() || !short(&c.access_key, 256) {
                return Err(RemoteError::Invalid("access_key"));
            }
            if c.secret_key.is_empty() || !short(&c.secret_key, 1024) {
                return Err(RemoteError::Invalid("secret_key"));
            }
            if c.region.is_empty() {
                c.region = "us-east-1".into();
            }
            if c.region.len() > 32 || !c.region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(RemoteError::Invalid("region"));
            }
            c.url = c.url.trim_end_matches('/').to_string();
            c.username.clear();
            c.password.clear();
        }
    }
    Ok(c)
}

/// The location part of a configuration: changing it moves the store (allowed only for an empty channel).
pub fn location(kind: Kind, c: &RemoteConfig) -> String {
    match kind {
        Kind::Internal => String::new(),
        Kind::Webdav => format!("{}|{}", c.url, c.prefix),
        Kind::S3 => format!("{}|{}|{}", c.url, c.bucket, c.prefix),
    }
}

/// A configured external store.
pub struct RemoteStore {
    kind: Kind,
    config: RemoteConfig,
    allow_private: bool,
}

impl RemoteStore {
    pub fn new(kind: Kind, config: RemoteConfig, allow_private: bool) -> Self {
        Self { kind, config, allow_private }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The store's configuration (with the channel's limit).
    pub fn config(&self) -> &RemoteConfig {
        &self.config
    }

    /// The URL of an object (key without prefix) or, for `""`, of the prefix collection.
    fn object_url(&self, key: &str) -> Result<Url, RemoteError> {
        let c = &self.config;
        let raw = match self.kind {
            Kind::Webdav => format!("{}{}{}", c.url, c.prefix, key),
            Kind::S3 => format!("{}/{}/{}{}", c.url, c.bucket, c.prefix, key),
            Kind::Internal => return Err(RemoteError::Invalid("kind")),
        };
        Url::parse(&raw).map_err(|_| RemoteError::Invalid("url"))
    }

    /// The SSRF checks before every request: shape, then DNS (the resolver repeats it when connecting).
    async fn check_target(&self, url: &Url) -> Result<(), RemoteError> {
        check_url(url.as_str(), self.allow_private)?;
        let host = url.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }
        let resolver = VettingResolver::new(Arc::new(SystemLookup), self.allow_private, HashSet::new());
        match resolver.vetted(host).await {
            Ok(_) => Ok(()),
            Err(e) if e.is::<AddressForbidden>() => Err(RemoteError::AddressForbidden),
            Err(_) => Err(RemoteError::Unreachable),
        }
    }

    /// Builds a request with the store's authentication.
    fn request(
        &self,
        method: Method,
        url: Url,
        extra: &[(&str, String)],
    ) -> Result<reqwest::RequestBuilder, RemoteError> {
        let http = client(self.allow_private)?;
        let mut req = http.request(method.clone(), url.clone());
        for (k, v) in extra {
            req = req.header(*k, v);
        }
        match self.kind {
            Kind::Webdav => {
                if !self.config.username.is_empty() || !self.config.password.is_empty() {
                    req = req.basic_auth(&self.config.username, Some(&self.config.password));
                }
                Ok(req)
            }
            Kind::S3 => {
                let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
                let headers = vec![
                    ("host".to_string(), sigv4::host_header(&url)),
                    ("x-amz-content-sha256".to_string(), sigv4::UNSIGNED_PAYLOAD.to_string()),
                    ("x-amz-date".to_string(), amz_date.clone()),
                ];
                let signer = Signer {
                    access_key: &self.config.access_key,
                    secret_key: &self.config.secret_key,
                    region: &self.config.region,
                    service: "s3",
                };
                let auth = signer.authorization(method.as_str(), &url, &headers, sigv4::UNSIGNED_PAYLOAD, &amz_date);
                Ok(req
                    .header("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD)
                    .header("x-amz-date", amz_date)
                    .header(header::AUTHORIZATION, auth))
            }
            Kind::Internal => Ok(req),
        }
    }

    async fn send(&self, req: Result<reqwest::RequestBuilder, RemoteError>) -> Result<reqwest::Response, RemoteError> {
        req?.send().await.map_err(|e| {
            // The vetting resolver refused an address while connecting (DNS changed since the check).
            let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
            while let Some(s) = source {
                if s.downcast_ref::<AddressForbidden>().is_some() {
                    return RemoteError::AddressForbidden;
                }
                source = s.source();
            }
            RemoteError::Unreachable
        })
    }

    /// Creates the prefix collections on a WebDAV store (S3 has no directories). Existing ones are fine.
    pub async fn prepare(&self) -> Result<(), RemoteError> {
        if self.kind != Kind::Webdav {
            // S3 has no directories; the endpoint's addresses are still vetted before the configuration is kept.
            let url = Url::parse(&self.config.url).map_err(|_| RemoteError::Invalid("url"))?;
            return self.check_target(&url).await;
        }
        let mut path = String::new();
        for seg in self.config.prefix.split('/').filter(|s| !s.is_empty()) {
            path.push_str(seg);
            path.push('/');
            let url = Url::parse(&format!("{}{path}", self.config.url)).map_err(|_| RemoteError::Invalid("url"))?;
            self.check_target(&url).await?;
            let method = Method::from_bytes(b"MKCOL").unwrap_or(Method::PUT);
            let resp = self.send(self.request(method, url, &[])).await?;
            // 201 created, 405 already there (some servers answer 301 for an existing collection).
            if !(resp.status().is_success() || matches!(resp.status().as_u16(), 301 | 405)) {
                return Err(RemoteError::Status(resp.status().as_u16()));
            }
        }
        Ok(())
    }

    /// Uploads an object of exactly `len` bytes from a stream.
    pub async fn put(&self, key: &str, body: reqwest::Body, len: u64) -> Result<(), RemoteError> {
        let url = self.object_url(key)?;
        self.check_target(&url).await?;
        let req = self
            .request(Method::PUT, url, &[(header::CONTENT_LENGTH.as_str(), len.to_string())])
            .map(|r| r.header(header::CONTENT_TYPE, "application/octet-stream").body(body));
        let resp = self.send(req).await?;
        if resp.status().is_success() { Ok(()) } else { Err(RemoteError::Status(resp.status().as_u16())) }
    }

    /// Downloads an object, optionally bytes `start..=end` of it. The response is 200 or 206.
    pub async fn get(&self, key: &str, range: Option<(u64, u64)>) -> Result<reqwest::Response, RemoteError> {
        let url = self.object_url(key)?;
        self.check_target(&url).await?;
        let extra: Vec<(&str, String)> =
            range.map(|(a, b)| vec![(header::RANGE.as_str(), format!("bytes={a}-{b}"))]).unwrap_or_default();
        let resp = self.send(self.request(Method::GET, url, &extra)).await?;
        match resp.status() {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
            s => Err(RemoteError::Status(s.as_u16())),
        }
    }

    /// Deletes an object (a missing one counts as deleted).
    pub async fn delete(&self, key: &str) -> Result<(), RemoteError> {
        let url = self.object_url(key)?;
        self.check_target(&url).await?;
        let resp = self.send(self.request(Method::DELETE, url, &[])).await?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(RemoteError::Status(resp.status().as_u16()))
        }
    }

    /// Connectivity check: the store answers (WebDAV `PROPFIND`, S3 `HEAD` of the bucket), the prefix exists,
    /// and a small probe object can be written, read and deleted.
    pub async fn test(&self) -> Result<(), RemoteError> {
        let base = match self.kind {
            Kind::Webdav => Url::parse(&self.config.url).map_err(|_| RemoteError::Invalid("url"))?,
            Kind::S3 => Url::parse(&format!("{}/{}", self.config.url, self.config.bucket))
                .map_err(|_| RemoteError::Invalid("url"))?,
            Kind::Internal => return Ok(()),
        };
        self.check_target(&base).await?;
        let resp = match self.kind {
            Kind::Webdav => {
                let method = Method::from_bytes(b"PROPFIND").unwrap_or(Method::GET);
                self.send(self.request(method, base, &[("depth", "0".to_string())])).await?
            }
            _ => self.send(self.request(Method::HEAD, base, &[])).await?,
        };
        if !resp.status().is_success() {
            return Err(RemoteError::Status(resp.status().as_u16()));
        }
        self.prepare().await?;
        let probe = format!(".tavrn-probe-{}", crate::util::ulid());
        let data = b"tavrn connectivity probe".to_vec();
        self.put(&probe, reqwest::Body::from(data.clone()), data.len() as u64).await?;
        let read = self.get(&probe, None).await?.bytes().await.map_err(|_| RemoteError::Unreachable);
        let deleted = self.delete(&probe).await;
        if read? != data {
            return Err(RemoteError::Status(500));
        }
        deleted
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn cfg(url: &str) -> RemoteConfig {
        RemoteConfig {
            url: url.into(),
            access_key: "AK".into(),
            secret_key: "SK".into(),
            bucket: "files".into(),
            ..Default::default()
        }
    }

    #[test]
    fn urls_must_be_public_https() {
        assert!(check_url("https://dav.example.com/remote/", false).is_ok());
        assert_eq!(check_url("http://dav.example.com/", false).unwrap_err(), RemoteError::HttpsRequired);
        assert!(check_url("http://dav.example.com/", true).is_ok());
        for bad in [
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://[::1]/",
            "https://169.254.169.254/",
            "https://[::ffff:192.168.0.1]/",
        ] {
            assert_eq!(check_url(bad, false).unwrap_err(), RemoteError::AddressForbidden, "{bad}");
            assert!(check_url(bad, true).is_ok(), "{bad} with the private switch");
        }
        for bad in ["ftp://x.example/", "https://user:pw@x.example/", "https://x.example/?a=1", "not a url", ""] {
            assert!(matches!(check_url(bad, true), Err(RemoteError::Invalid(_))), "{bad}");
        }
    }

    #[test]
    fn configurations_are_validated_and_normalised() {
        let c =
            validate(Kind::S3, RemoteConfig { prefix: "/a/b".into(), ..cfg("https://s3.example/") }, false).unwrap();
        assert_eq!((c.url.as_str(), c.prefix.as_str(), c.region.as_str()), ("https://s3.example", "a/b/", "us-east-1"));
        assert_eq!(
            validate(Kind::S3, RemoteConfig { bucket: "A".into(), ..cfg("https://s3.example") }, false),
            Err(RemoteError::Invalid("bucket"))
        );
        assert_eq!(
            validate(Kind::S3, RemoteConfig { secret_key: String::new(), ..cfg("https://s3.example") }, false),
            Err(RemoteError::Invalid("secret_key"))
        );
        assert_eq!(
            validate(Kind::S3, RemoteConfig { prefix: "a/../b".into(), ..cfg("https://s3.example") }, false),
            Err(RemoteError::Invalid("prefix"))
        );
        assert_eq!(
            validate(Kind::S3, RemoteConfig { prefix: "a b".into(), ..cfg("https://s3.example") }, false),
            Err(RemoteError::Invalid("prefix"))
        );
        let w = validate(
            Kind::Webdav,
            RemoteConfig { username: "u".into(), password: "p".into(), ..cfg("https://dav.example/files") },
            false,
        )
        .unwrap();
        assert_eq!(w.url, "https://dav.example/files/");
        assert!(w.secret_key.is_empty() && w.bucket.is_empty(), "fields of the other kind are dropped");
        assert_eq!(
            validate(Kind::Webdav, RemoteConfig { username: "a:b".into(), ..cfg("https://dav.example/") }, false),
            Err(RemoteError::Invalid("username"))
        );
        assert_ne!(location(Kind::S3, &c), location(Kind::S3, &RemoteConfig { bucket: "other".into(), ..c.clone() }));
        assert_eq!(location(Kind::S3, &c), location(Kind::S3, &RemoteConfig { secret_key: "new".into(), ..c.clone() }));
        assert_eq!(
            location(Kind::S3, &c),
            location(Kind::S3, &RemoteConfig { max_bytes: 10, ..c.clone() }),
            "the limit is no move of the store"
        );
        assert_eq!(
            validate(Kind::S3, RemoteConfig { max_bytes: MAX_STORE_BYTES + 1, ..cfg("https://s3.example") }, false),
            Err(RemoteError::Invalid("max_bytes"))
        );
        assert_eq!(
            validate(Kind::S3, RemoteConfig { max_bytes: MAX_STORE_BYTES, ..cfg("https://s3.example") }, false)
                .unwrap()
                .max_bytes,
            MAX_STORE_BYTES
        );
    }

    #[tokio::test]
    async fn names_resolving_to_private_addresses_are_refused() {
        let store =
            RemoteStore::new(Kind::Webdav, validate(Kind::Webdav, cfg("https://localhost:1/"), false).unwrap(), false);
        assert_eq!(store.test().await.unwrap_err(), RemoteError::AddressForbidden);
        assert_eq!(store.delete("x").await.unwrap_err(), RemoteError::AddressForbidden);
    }
}
