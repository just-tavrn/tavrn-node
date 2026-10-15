// SPDX-License-Identifier: AGPL-3.0-only
//! Sender-generated link previews (protocol/PROTOCOL.md §7 `preview`).
//!
//! The sender's client asks its own home node to unfurl one URL while composing; the result goes into the
//! message content (encrypted with it in E2EE conversations), so readers never fetch anything and the node
//! never unfurls on its own. Every fetch is SSRF-safe:
//!
//! - only `http`/`https`, no credentials in the URL, ports 80, 443, 8080 and 8443 only;
//! - IP literals and every DNS answer must be public unicast addresses ([`forbidden_ip`]); reqwest connects
//!   only to the addresses the vetting resolver returned (no second lookup, no DNS rebinding window);
//! - redirects are followed by hand (at most [`MAX_REDIRECTS`]) and each hop is checked again;
//! - 5 seconds for everything, at most 1 MiB of `text/html` is read, the image at most 5 MiB;
//! - the image is converted by the media pipeline (ffmpeg without network protocols) to a WebP of at most
//!   400 px and 40 KiB and returned inline as a data URL; SVG and everything else unknown is dropped.
//!
//! Results are cached in memory for an hour (failures for five minutes) in a bounded LRU; requests are
//! rate-limited per user and the number of concurrent fetches is bounded.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use base64::Engine;
use reqwest::{Url, header};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use utoipa::ToSchema;

use crate::{
    auth::RateLimiter,
    config::Config,
    error::ApiError,
    federation::client::{Lookup, SystemLookup, VettingResolver, forbidden_ip},
    media::{MediaKind, Pipeline},
};

/// `TAVRN_UNFURL`: `on` (default) or `off` (the route answers 404 `unfurl.disabled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnfurlSetting {
    On,
    Off,
}

pub const MAX_REDIRECTS: usize = 3;
pub const MAX_HTML_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_URL_LEN: usize = 2048;
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const ALLOWED_PORTS: &[u16] = &[80, 443, 8080, 8443];
const CACHE_ENTRIES: usize = 512;
const CACHE_TTL: Duration = Duration::from_secs(3600);
const FAILURE_TTL: Duration = Duration::from_secs(300);
const CONCURRENT_FETCHES: usize = 16;
const MAX_TITLE: usize = 200;
const MAX_DESCRIPTION: usize = 300;
const MAX_SITE: usize = 100;

/// A link preview as the sender's client puts it into the message content.
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct UnfurlResponse {
    /// The requested URL (normalized).
    pub url: String,
    /// `og:title`, `twitter:title` or `<title>`; empty if the page has none.
    pub title: String,
    /// `og:description`, `twitter:description` or `<meta name="description">`; may be empty.
    pub description: String,
    /// `og:site_name` or the host name.
    pub site: String,
    /// `data:image/webp;base64,…` (at most 400 px, 40 KiB), if the page names a usable image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_data_url: Option<String>,
}

/// Why an unfurl failed; cheap to clone so failures can be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Not an http(s) URL, credentials, a port outside the allowed ones, too long.
    Invalid,
    /// The host is or resolves to a non-public address.
    Forbidden,
    /// The answer is not HTML.
    NotHtml,
    /// Unreachable, non-2xx status, too many redirects.
    Fetch,
    Timeout,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "unfurl.url_invalid",
            Self::Forbidden => "unfurl.address_forbidden",
            Self::NotHtml => "unfurl.not_html",
            Self::Fetch => "unfurl.fetch_failed",
            Self::Timeout => "unfurl.timeout",
        }
    }

    fn into_api(self) -> ApiError {
        match self {
            Self::Invalid => ApiError::BadRequest {
                code: self.code(),
                detail: "Only public http(s) URLs on ports 80, 443, 8080 or 8443 can be previewed".into(),
            },
            Self::Forbidden => ApiError::BadRequest {
                code: self.code(),
                detail: "The address is not public and cannot be previewed".into(),
            },
            Self::NotHtml => ApiError::UnsupportedMedia { code: self.code(), detail: "The page is not HTML".into() },
            Self::Fetch => ApiError::BadGateway { code: self.code(), detail: "The page could not be loaded".into() },
            Self::Timeout => ApiError::BadGateway { code: self.code(), detail: "The page took too long".into() },
        }
    }
}

/// The fields read from a page's `<head>`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PageMeta {
    pub title: String,
    pub description: String,
    pub site: String,
    /// Absolute http(s) URL of `og:image` / `twitter:image`.
    pub image: Option<Url>,
}

struct CacheEntry {
    stored: Instant,
    used: u64,
    ttl: Duration,
    value: Result<UnfurlResponse, Failure>,
}

/// The unfurl client: HTTP client with the vetting resolver, cache, rate limit and concurrency bound.
pub struct Unfurler {
    http: reqwest::Client,
    resolver: VettingResolver,
    /// Hosts that skip the address and port checks (tests only; empty in production).
    exempt: Arc<HashSet<String>>,
    total: Duration,
    cache: Mutex<(HashMap<String, CacheEntry>, u64)>,
    limiter: RateLimiter,
    slots: Semaphore,
}

impl Unfurler {
    /// The production client (system DNS, nothing exempt); `None` when `TAVRN_UNFURL=off`.
    pub fn from_config(config: &Config) -> Option<Self> {
        (config.unfurl == UnfurlSetting::On).then(|| {
            let per_minute = if config.dev { 1000 } else { 30 };
            Self::new(&config.domain, Arc::new(SystemLookup), HashSet::new(), TOTAL_TIMEOUT, per_minute)
        })
    }

    /// A client with its own DNS lookup, exempt hosts and timeout (tests).
    pub fn new(
        domain: &str,
        lookup: Arc<dyn Lookup>,
        exempt: HashSet<String>,
        total: Duration,
        per_minute: u32,
    ) -> Self {
        let resolver = VettingResolver::new(lookup, false, exempt.clone());
        let http = reqwest::Client::builder()
            .user_agent(format!(
                "Mozilla/5.0 (compatible; tavrn-unfurl/{}; +https://{domain})",
                crate::app::SOFTWARE_VERSION
            ))
            .dns_resolver(Arc::new(resolver.clone()))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(total)
            .timeout(total)
            .no_proxy()
            .build()
            .unwrap_or_default();
        Self {
            http,
            resolver,
            exempt: Arc::new(exempt),
            total,
            cache: Mutex::new((HashMap::new(), 0)),
            limiter: RateLimiter::new(per_minute, Duration::from_secs(60)),
            slots: Semaphore::new(CONCURRENT_FETCHES),
        }
    }

    /// Unfurls `raw` for `user_id`: rate limit, cache, fetch, image conversion with `media`.
    pub async fn unfurl(&self, user_id: &str, raw: &str, media: &Pipeline) -> Result<UnfurlResponse, ApiError> {
        let url = parse_url(raw).map_err(Failure::into_api)?;
        self.limiter.check_all(&[format!("unfurl:{user_id}")])?;
        let key = url.to_string();
        if let Some(hit) = self.cached(&key) {
            return hit.map_err(Failure::into_api);
        }
        let _slot = tokio::time::timeout(Duration::from_secs(2), self.slots.acquire()).await.ok().and_then(Result::ok);
        let Some(_slot) = _slot else {
            return Err(ApiError::Unavailable { code: "unfurl.busy", detail: "Too many previews at once".into() });
        };
        let result = self.fetch(&url, media).await;
        if result != Err(Failure::Invalid) {
            self.store(key, result.clone());
        }
        result.map_err(Failure::into_api)
    }

    fn cached(&self, key: &str) -> Option<Result<UnfurlResponse, Failure>> {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let (map, tick) = &mut *guard;
        *tick += 1;
        let now = Instant::now();
        let entry = map.get_mut(key)?;
        if now.duration_since(entry.stored) >= entry.ttl {
            map.remove(key);
            return None;
        }
        entry.used = *tick;
        Some(entry.value.clone())
    }

    fn store(&self, key: String, value: Result<UnfurlResponse, Failure>) {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let (map, tick) = &mut *guard;
        *tick += 1;
        if map.len() >= CACHE_ENTRIES && !map.contains_key(&key) {
            // Least recently used out (a linear scan over a small, fixed-size map).
            if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| k.clone()) {
                map.remove(&oldest);
            }
        }
        let ttl = if value.is_ok() { CACHE_TTL } else { FAILURE_TTL };
        map.insert(key, CacheEntry { stored: Instant::now(), used: *tick, ttl, value });
    }

    /// Number of cached entries (tests).
    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).0.len()
    }

    /// Page and image within the total time budget; the image is optional (dropped when it fails or time
    /// runs out).
    pub async fn fetch(&self, url: &Url, media: &Pipeline) -> Result<UnfurlResponse, Failure> {
        let deadline = Instant::now() + self.total;
        let (body, final_url) =
            tokio::time::timeout(self.total, self.get(url, Want::Html)).await.map_err(|_| Failure::Timeout)??;
        let meta = parse_html(&String::from_utf8_lossy(&body), &final_url);
        let site = if meta.site.is_empty() { site_of(&final_url) } else { meta.site };
        let mut image_data_url = None;
        if let Some(image) = meta.image {
            let left = deadline.saturating_duration_since(Instant::now());
            let job = async {
                let (bytes, _) = self.get(&image, Want::Image).await.ok()?;
                let processed = media.process(MediaKind::Preview, bytes.into()).await.ok()?;
                (processed.still.len() <= MediaKind::Preview.max_output_bytes()).then(|| {
                    format!(
                        "data:{};base64,{}",
                        processed.still_mime,
                        base64::engine::general_purpose::STANDARD.encode(&processed.still)
                    )
                })
            };
            image_data_url = tokio::time::timeout(left, job).await.ok().flatten();
        }
        Ok(UnfurlResponse {
            url: url.to_string(),
            title: meta.title,
            description: meta.description,
            site,
            image_data_url,
        })
    }

    /// GET with hand-followed redirects; every hop is checked before it is contacted.
    async fn get(&self, start: &Url, want: Want) -> Result<(Vec<u8>, Url), Failure> {
        let mut url = start.clone();
        for hop in 0..=MAX_REDIRECTS {
            self.check_target(&url).await?;
            let response = self
                .http
                .get(url.clone())
                .header(header::ACCEPT, want.accept())
                .send()
                .await
                .map_err(|e| if e.is_timeout() { Failure::Timeout } else { Failure::Fetch })?;
            let status = response.status();
            if status.is_redirection() {
                if hop == MAX_REDIRECTS {
                    return Err(Failure::Fetch);
                }
                let location =
                    response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or(Failure::Fetch)?;
                url = url.join(location).map_err(|_| Failure::Fetch)?;
                continue;
            }
            if !status.is_success() {
                return Err(Failure::Fetch);
            }
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
                .unwrap_or_default();
            if !want.accepts(&content_type) {
                return Err(Failure::NotHtml);
            }
            if want == Want::Image && response.content_length().is_some_and(|n| n > want.max_bytes() as u64) {
                return Err(Failure::Fetch);
            }
            let body = read_capped(response, want.max_bytes(), want == Want::Html).await?;
            return Ok((body, url));
        }
        Err(Failure::Fetch)
    }

    /// Scheme, credentials and port ([`parse_url`] rules), then the addresses: an IP literal must be
    /// public; a name must resolve to public addresses only (the resolver repeats this when connecting).
    async fn check_target(&self, url: &Url) -> Result<(), Failure> {
        let host = check_shape(url)?;
        let literal = ip_literal(&host);
        if literal.is_some_and(forbidden_ip) {
            return Err(Failure::Forbidden);
        }
        let exempt = literal.is_none() && self.exempt.contains(&host);
        if !exempt && !ALLOWED_PORTS.contains(&url.port_or_known_default().unwrap_or(0)) {
            return Err(Failure::Invalid);
        }
        if literal.is_some() {
            return Ok(());
        }
        match self.resolver.precheck(&host).await {
            crate::federation::client::Precheck::Allowed => Ok(()),
            crate::federation::client::Precheck::Forbidden => Err(Failure::Forbidden),
            crate::federation::client::Precheck::Unresolved => Err(Failure::Fetch),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Html,
    Image,
}

impl Want {
    fn accept(self) -> &'static str {
        match self {
            Self::Html => "text/html,application/xhtml+xml;q=0.9",
            Self::Image => "image/webp,image/png,image/jpeg,image/gif;q=0.8",
        }
    }

    fn accepts(self, content_type: &str) -> bool {
        match self {
            Self::Html => matches!(content_type, "text/html" | "application/xhtml+xml"),
            // The media pipeline sniffs the bytes; SVG and other unknown formats are refused there.
            Self::Image => content_type.starts_with("image/"),
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::Html => MAX_HTML_BYTES,
            Self::Image => MAX_IMAGE_BYTES,
        }
    }
}

/// Reads at most `max` bytes. HTML is cut there (the `<head>` comes first); a larger image is refused.
async fn read_capped(mut response: reqwest::Response, max: usize, truncate: bool) -> Result<Vec<u8>, Failure> {
    let mut body = Vec::new();
    while let Some(chunk) =
        response.chunk().await.map_err(|e| if e.is_timeout() { Failure::Timeout } else { Failure::Fetch })?
    {
        let room = max - body.len();
        if chunk.len() > room {
            if !truncate {
                return Err(Failure::Fetch);
            }
            body.extend_from_slice(&chunk[..room]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parses and normalizes a requested URL: http(s), a host, no credentials, at most [`MAX_URL_LEN`]
/// characters; the fragment is dropped.
pub fn parse_url(raw: &str) -> Result<Url, Failure> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_URL_LEN {
        return Err(Failure::Invalid);
    }
    let mut url = Url::parse(raw).map_err(|_| Failure::Invalid)?;
    check_shape(&url)?;
    url.set_fragment(None);
    Ok(url)
}

/// The host of an http(s) URL without credentials (lowercase, IPv6 without brackets).
fn check_shape(url: &Url) -> Result<String, Failure> {
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return Err(Failure::Invalid);
    }
    let host = url.host_str().filter(|h| !h.is_empty()).ok_or(Failure::Invalid)?;
    Ok(host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase())
}

fn ip_literal(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

fn site_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    clean(host.strip_prefix("www.").unwrap_or(host), MAX_SITE)
}

// ---------------------------------------------------------------- HTML

/// Reads OpenGraph, Twitter card, `<title>` and `<meta name="description">` from the `<head>` (or the
/// first part of the document when there is no `</head>`). Linear in the input; no DOM is built.
pub fn parse_html(html: &str, base: &Url) -> PageMeta {
    let lower = html.to_ascii_lowercase();
    let end = lower.find("</head").or_else(|| lower.find("<body")).unwrap_or(lower.len());
    let (head, head_lower) = (&html[..end], &lower[..end]);
    let mut found: HashMap<&'static str, String> = HashMap::new();
    const KEYS: &[&str] = &[
        "og:title",
        "twitter:title",
        "og:description",
        "twitter:description",
        "description",
        "og:site_name",
        "og:image",
        "og:image:url",
        "og:image:secure_url",
        "twitter:image",
        "twitter:image:src",
    ];
    let mut from = 0;
    while let Some(pos) = head_lower[from..].find("<meta") {
        let start = from + pos + 5;
        let Some(close) = head_lower[start..].find('>') else { break };
        let attrs = parse_attributes(&head[start..start + close]);
        from = start + close + 1;
        let key = attrs.get("property").or_else(|| attrs.get("name")).map(|k| k.trim().to_ascii_lowercase());
        let (Some(key), Some(content)) = (key, attrs.get("content")) else { continue };
        if let Some(k) = KEYS.iter().find(|k| **k == key) {
            found.entry(k).or_insert_with(|| decode_entities(content));
        }
    }
    let title_tag = head_lower.find("<title").and_then(|t| {
        let open = t + head_lower[t..].find('>')? + 1;
        let close = open + head_lower[open..].find("</title")?;
        Some(decode_entities(&head[open..close]))
    });
    let pick = |keys: &[&str]| keys.iter().find_map(|k| found.get(k).filter(|v| !v.trim().is_empty()).cloned());
    let image = pick(&["og:image:secure_url", "og:image", "og:image:url", "twitter:image", "twitter:image:src"])
        .and_then(|src| base.join(src.trim()).ok())
        .filter(|u| matches!(u.scheme(), "http" | "https"));
    PageMeta {
        title: clean(&pick(&["og:title", "twitter:title"]).or(title_tag).unwrap_or_default(), MAX_TITLE),
        description: clean(
            &pick(&["og:description", "twitter:description", "description"]).unwrap_or_default(),
            MAX_DESCRIPTION,
        ),
        site: clean(&pick(&["og:site_name"]).unwrap_or_default(), MAX_SITE),
        image,
    }
}

/// Attributes of one tag (`name=value`, quoted with `"` or `'` or unquoted), names lowercase.
fn parse_attributes(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && out.len() < 32 {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'/' {
            i += 1;
        }
        let name = s[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let value = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let v = &s[start..i];
                i += 1;
                v
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                &s[start..i]
            };
            if !name.is_empty() {
                out.entry(name).or_insert_with(|| value.to_string());
            }
        } else if name.is_empty() {
            i += 1;
        }
    }
    out
}

/// The common named entities and numeric references; anything else stays as written.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        // Byte search: the window may end inside a multi-byte character, `;` never does.
        let Some(semi) = rest.as_bytes()[..rest.len().min(12)].iter().position(|&b| b == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            e if e.starts_with("#x") || e.starts_with("#X") => {
                u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32)
            }
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whitespace collapsed, control and bidi override characters removed, at most `max` characters
/// (an ellipsis marks a cut).
fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}') {
            continue;
        }
        if space {
            out.push(' ');
            count += 1;
            space = false;
        }
        if count >= max {
            out.pop();
            out.push('…');
            return out;
        }
        out.push(c);
        count += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use futures::future::BoxFuture;

    /// Test DNS: fixed answers per name.
    struct FakeDns(HashMap<String, Vec<IpAddr>>);

    impl Lookup for FakeDns {
        fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
            let r = self.0.get(&host).cloned().ok_or_else(|| std::io::Error::other("NXDOMAIN"));
            Box::pin(async move { r })
        }
    }

    const PAGE: &str = r#"<!doctype html><html><head>
        <title>Fallback &amp; title</title>
        <meta property="og:title" content="Cats &amp; Dogs">
        <meta name=description content='A page about &quot;pets&quot;'>
        <meta property="og:site_name" content="Pet Site">
        <meta property="og:image" content="/img.png">
        </head><body><meta property="og:title" content="ignored"></body></html>"#;

    /// A 1×1 PNG (still images pass without ffmpeg when small).
    const PIXEL: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
        0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0x64, 0xF8, 0xCF, 0x50, 0x0F, 0x00, 0x03, 0x86, 0x01, 0x80,
        0x5A, 0x34, 0x7D, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    /// A local test site; `public.test` and `other.test` map to it and are exempt from the address check
    /// (it listens on 127.0.0.1), `private.test` resolves to 10.0.0.1 and `mixed.test` to a public and a
    /// private address.
    async fn site() -> (Unfurler, u16, Pipeline, tempfile::TempDir) {
        let port_holder = std::sync::Arc::new(std::sync::OnceLock::<u16>::new());
        let p = port_holder.clone();
        let app = Router::new()
            .route("/page", get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE) }))
            .route("/img.png", get(|| async { ([(header::CONTENT_TYPE, "image/png")], PIXEL) }))
            .route("/json", get(|| async { ([(header::CONTENT_TYPE, "application/json")], "{}") }))
            .route(
                "/big",
                get(|| async {
                    let mut body = String::from("<html><head><meta property=\"og:title\" content=\"Big\">");
                    body.push_str(&"x".repeat(2 * MAX_HTML_BYTES));
                    body.push_str("<title>after the cap</title></head></html>");
                    ([(header::CONTENT_TYPE, "text/html")], body)
                }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    ([(header::CONTENT_TYPE, "text/html")], PAGE)
                }),
            )
            .route(
                "/to-loopback",
                get(move || async move { redirect(format!("http://127.0.0.1:{}/page", p.get().unwrap())) }),
            )
            .route("/to-private", get(|| async { redirect("http://private.test/page".into()) }))
            .route("/to-v6", get(|| async { redirect("http://[::1]/page".into()) }))
            .route("/to-other", get(|| async { redirect("/page".into()) }))
            .route("/loop", get(|| async { redirect("/loop".into()) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        port_holder.set(port).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let dns = FakeDns(HashMap::from([
            ("public.test".to_string(), vec![local]),
            ("other.test".to_string(), vec![local]),
            ("private.test".to_string(), vec!["10.0.0.1".parse().unwrap()]),
            // A routable address next to a private one (documentation ranges would not do: they are refused too).
            ("mixed.test".to_string(), vec!["93.184.216.34".parse().unwrap(), "192.168.1.1".parse().unwrap()]),
        ]));
        let exempt = HashSet::from(["public.test".to_string(), "other.test".to_string()]);
        let unfurler = Unfurler::new("node.test", Arc::new(dns), exempt, Duration::from_millis(1500), 1000);
        let dir = tempfile::tempdir().unwrap();
        let config =
            Config { media_ffmpeg: "off".into(), data_dir: dir.path().to_string_lossy().into(), ..Config::default() };
        (unfurler, port, Pipeline::new(&config), dir)
    }

    fn redirect(to: String) -> impl IntoResponse {
        let mut h = HeaderMap::new();
        h.insert(header::LOCATION, to.parse().unwrap());
        (StatusCode::FOUND, h)
    }

    async fn fetch(u: &Unfurler, p: &Pipeline, url: &str) -> Result<UnfurlResponse, Failure> {
        u.fetch(&parse_url(url).unwrap(), p).await
    }

    #[tokio::test]
    async fn a_public_page_is_unfurled_with_its_image() {
        let (u, port, p, _d) = site().await;
        let r = fetch(&u, &p, &format!("http://public.test:{port}/page#frag")).await.unwrap();
        assert_eq!(r.url, format!("http://public.test:{port}/page"), "the fragment is dropped");
        assert_eq!(r.title, "Cats & Dogs");
        assert_eq!(r.description, "A page about \"pets\"");
        assert_eq!(r.site, "Pet Site");
        let image = r.image_data_url.unwrap();
        assert!(image.starts_with("data:image/png;base64,"), "{image}");
        // A relative redirect on the same exempt host is followed.
        let r = fetch(&u, &p, &format!("http://public.test:{port}/to-other")).await.unwrap();
        assert_eq!(r.title, "Cats & Dogs");
    }

    #[tokio::test]
    async fn private_targets_are_refused() {
        let (u, port, p, _d) = site().await;
        for url in [
            "http://127.0.0.1/".to_string(),
            format!("http://127.0.0.1:{port}/page"),
            "http://10.1.2.3/".into(),
            "http://169.254.169.254/latest/meta-data/".into(),
            "http://[::1]/".into(),
            "http://[fc00::1]/".into(),
            "http://[fd12:3456::1]/".into(),
            "http://[fe80::1]/".into(),
            "http://[::ffff:127.0.0.1]/".into(),
            "http://0x7f.1/".into(),
            "http://2130706433/".into(),
            "http://private.test/page".into(),
            "http://mixed.test/".into(),
        ] {
            assert_eq!(fetch(&u, &p, &url).await.unwrap_err(), Failure::Forbidden, "{url}");
        }
    }

    #[tokio::test]
    async fn redirects_to_private_targets_are_refused() {
        let (u, port, p, _d) = site().await;
        for path in ["to-loopback", "to-private", "to-v6"] {
            let url = format!("http://public.test:{port}/{path}");
            assert_eq!(fetch(&u, &p, &url).await.unwrap_err(), Failure::Forbidden, "{path}");
        }
        assert_eq!(fetch(&u, &p, &format!("http://public.test:{port}/loop")).await.unwrap_err(), Failure::Fetch);
    }

    #[tokio::test]
    async fn non_html_oversized_and_slow_answers() {
        let (u, port, p, _d) = site().await;
        let base = format!("http://public.test:{port}");
        assert_eq!(fetch(&u, &p, &format!("{base}/json")).await.unwrap_err(), Failure::NotHtml);
        // Only the first MiB is read: the title after it is never seen.
        let big = fetch(&u, &p, &format!("{base}/big")).await.unwrap();
        assert_eq!(big.title, "Big");
        assert_eq!(fetch(&u, &p, &format!("{base}/slow")).await.unwrap_err(), Failure::Timeout);
        assert_eq!(fetch(&u, &p, "http://nxdomain.test/").await.unwrap_err(), Failure::Fetch);
    }

    #[test]
    fn urls_are_checked_before_anything_is_fetched() {
        for bad in [
            "",
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://user:pw@example.com/",
            "http://user@example.com/",
            "not a url",
            &format!("https://example.com/{}", "a".repeat(MAX_URL_LEN)),
        ] {
            assert_eq!(parse_url(bad).unwrap_err(), Failure::Invalid, "{bad}");
        }
        assert_eq!(parse_url(" https://Example.COM/a?b=1#c ").unwrap().as_str(), "https://example.com/a?b=1");
    }

    #[tokio::test]
    async fn ports_outside_the_allowed_ones_are_refused() {
        let (u, _, p, _d) = site().await;
        assert_eq!(fetch(&u, &p, "http://mixed.test:22/").await.unwrap_err(), Failure::Invalid);
        assert_eq!(fetch(&u, &p, "https://93.184.216.34:6379/").await.unwrap_err(), Failure::Invalid);
    }

    #[tokio::test]
    async fn results_are_cached_and_requests_rate_limited() {
        let (_, port, p, _d) = site().await;
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let dns = FakeDns(HashMap::from([("public.test".to_string(), vec![local])]));
        let u = Unfurler::new(
            "node.test",
            Arc::new(dns),
            HashSet::from(["public.test".to_string()]),
            Duration::from_secs(2),
            3,
        );
        let url = format!("http://public.test:{port}/page");
        u.unfurl("u1", &url, &p).await.unwrap();
        assert_eq!(u.cache_len(), 1);
        u.unfurl("u1", &url, &p).await.unwrap();
        // Invalid URLs are refused before the limiter counts them, so the third valid one still passes.
        assert_eq!(u.unfurl("u1", "ftp://x/", &p).await.unwrap_err().code(), "unfurl.url_invalid");
        u.unfurl("u1", &url, &p).await.unwrap();
        assert!(matches!(u.unfurl("u1", &url, &p).await.unwrap_err(), ApiError::RateLimited { .. }));
        assert!(u.unfurl("u2", &url, &p).await.is_ok(), "the limit is per user");
    }

    #[test]
    fn html_metadata_is_parsed() {
        let base = Url::parse("https://example.com/a/b").unwrap();
        let m = parse_html(PAGE, &base);
        assert_eq!(m.title, "Cats & Dogs");
        assert_eq!(m.image.unwrap().as_str(), "https://example.com/img.png");
        // <title> as the fallback, twitter cards, entities, whitespace and control characters.
        let m = parse_html(
            "<HEAD><TITLE>\n  Hello\u{202E}  &#x41;&#66;\u{7}\n</TITLE><meta name='twitter:image' content='//cdn.example/x.jpg'></HEAD>",
            &base,
        );
        assert_eq!(m.title, "Hello AB");
        assert_eq!(m.image.unwrap().as_str(), "https://cdn.example/x.jpg");
        // Non-http images and missing heads.
        let m = parse_html("<meta property=og:image content=\"javascript:alert(1)\"><p>text", &base);
        assert!(m.image.is_none());
        assert_eq!(m.title, "");
        // Long values are cut.
        let long = format!("<meta property=og:title content=\"{}\">", "a".repeat(1000));
        assert_eq!(parse_html(&long, &base).title.chars().count(), MAX_TITLE);
        // Unterminated tags and stray ampersands do not panic.
        assert_eq!(parse_html("<meta property=\"og:title\" content=\"x &", &base).title, "");
        assert_eq!(decode_entities("a & b &unknown; &#xZZ; &#128512;"), "a & b &unknown; &#xZZ; 😀");
        assert_eq!(decode_entities("&ab€€€€€;x"), "&ab€€€€€;x", "multi-byte characters inside the window");
        assert_eq!(decode_entities("€&"), "€&");
    }

    #[test]
    fn site_falls_back_to_the_host() {
        assert_eq!(site_of(&Url::parse("https://www.example.com/x").unwrap()), "example.com");
    }
}
