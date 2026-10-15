// SPDX-License-Identifier: AGPL-3.0-only
//! Serves the embedded web client (`web/dist`, included at build time).
//! Unknown paths outside the API serve `index.html` (single-page app routing). Files are served from the embedded
//! bytes without a copy, compressed when the client accepts it (a `.br`/`.gz` copy made at build time, else gzip made
//! once on the first request), and with an `ETag` (`304` on revalidation, which `index.html` needs: `no-cache`).

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist"]
#[exclude = ".gitkeep"]
pub struct WebAssets;

// 'wasm-unsafe-eval': allows compiling the crypto core (@tavrn/crypto, WebAssembly); it does not allow eval().
// connect-src 'self' https: wss: lets the client talk to every node (FEDERATION.md §8).
// frame-src: the click-to-play embeds of the web client (tavrn-web, src/lib/embeds.ts), exactly these hosts.
// challenges.cloudflare.com (Turnstile script and frame): only when the node has a captcha configured.
// object-src 'none': no plugins; everything else falls back to default-src 'self'.
const EMBED_FRAMES: &str = "https://www.youtube-nocookie.com https://player.twitch.tv https://clips.twitch.tv https://player.vimeo.com https://open.spotify.com";
const TURNSTILE: &str = "https://challenges.cloudflare.com https://*.challenges.cloudflare.com";

/// The CSP of the web client's HTML pages. `dev`: development peers speak plain HTTP (`TAVRN_FEDERATION_DEV_PEERS`);
/// `captcha`: the Turnstile hosts are allowed.
pub fn csp(dev: bool, captcha: bool) -> String {
    let turnstile = if captcha { format!(" {TURNSTILE}") } else { String::new() };
    let (img, connect) = if dev { (" http:", " http: ws:") } else { ("", "") };
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'{turnstile}; style-src 'self' 'unsafe-inline'; \
         font-src 'self'; img-src 'self' data: blob: https:{img}; media-src 'self' blob:; \
         connect-src 'self' https: wss:{connect}; worker-src 'self' blob:; object-src 'none'; \
         frame-src{turnstile} {EMBED_FRAMES}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
}

pub fn is_available() -> bool {
    WebAssets::get("index.html").is_some()
}

/// Smallest file worth compressing.
const MIN_COMPRESS: usize = 1024;

/// Compressed copies of the embedded files, made on the first request that accepts them (gzip). The embedded
/// files are fixed for the life of the process, so the map only grows to the size of the bundle.
static GZIPPED: LazyLock<Mutex<HashMap<String, Bytes>>> = LazyLock::new(Mutex::default);

/// Types that compress well (scripts, styles, WebAssembly, markup, JSON, SVG); fonts and images already are.
fn compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/javascript"
                | "application/json"
                | "application/wasm"
                | "application/manifest+json"
                | "image/svg+xml"
                | "application/xml"
        )
}

/// Does `Accept-Encoding` allow `coding` (named with a q-value above 0, or `*`)?
fn accepts(headers: &HeaderMap, coding: &str) -> bool {
    headers.get_all(header::ACCEPT_ENCODING).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(
        |item| {
            let mut parts = item.split(';');
            let name = parts.next().unwrap_or("").trim();
            let zero = parts
                .any(|p| p.trim().strip_prefix("q=").is_some_and(|q| q.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)));
            (name.eq_ignore_ascii_case(coding) || name == "*") && !zero
        },
    )
}

/// Does `If-None-Match` name `etag` (or `*`)?
fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == etag || t == "*")
}

/// The gzip copy of an embedded file, compressed once (off the async workers) and then shared.
async fn gzipped(path: &str, data: Bytes) -> Option<Bytes> {
    if let Some(hit) = GZIPPED.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
        return Some(hit.clone());
    }
    let packed = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::with_capacity(data.len() / 3), flate2::Compression::best());
        encoder.write_all(&data).and_then(|()| encoder.finish()).ok()
    })
    .await
    .ok()
    .flatten()?;
    let packed = Bytes::from(packed);
    GZIPPED.lock().unwrap_or_else(|e| e.into_inner()).insert(path.to_string(), packed.clone());
    Some(packed)
}

/// One embedded file as a response: borrowed bytes (no copy per request in release builds), a precompressed or
/// gzip copy when the client accepts it, an `ETag` from the file's hash with `304` for a matching `If-None-Match`.
async fn respond(
    path: &str,
    (data, sha256): (Cow<'static, [u8]>, [u8; 32]),
    request: &HeaderMap,
    cacheable: bool,
    csp: Option<&str>,
) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let hash = URL_SAFE_NO_PAD.encode(&sha256[..18]);
    let bytes = match data {
        Cow::Borrowed(b) => Bytes::from_static(b),
        Cow::Owned(v) => Bytes::from(v),
    };
    let compress = compressible(mime.essence_str()) && bytes.len() >= MIN_COMPRESS;
    // A copy compressed at build time (`<path>.br`, `<path>.gz`), else gzip made here.
    let mut encoded: Option<(&'static str, Bytes)> = None;
    if compress {
        for (coding, ext) in [("br", "br"), ("gzip", "gz")] {
            if accepts(request, coding)
                && let Some(pre) = WebAssets::get(&format!("{path}.{ext}"))
            {
                let pre = match pre.data {
                    Cow::Borrowed(b) => Bytes::from_static(b),
                    Cow::Owned(v) => Bytes::from(v),
                };
                encoded = Some((coding, pre));
                break;
            }
        }
        if encoded.is_none()
            && accepts(request, "gzip")
            && let Some(gz) = gzipped(path, bytes.clone()).await
        {
            encoded = Some(("gzip", gz));
        }
    }
    let etag = match &encoded {
        Some((coding, _)) => format!("\"{hash}-{coding}\""),
        None => format!("\"{hash}\""),
    };
    let fresh = not_modified(request, &etag);
    let mut resp = match (&encoded, fresh) {
        (_, true) => {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::NOT_MODIFIED;
            r
        }
        (Some((_, body)), false) => Response::new(Body::from(body.clone())),
        (None, false) => Response::new(Body::from(bytes)),
    };
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if cacheable { "public, max-age=31536000, immutable" } else { "no-cache" }),
    );
    if let Ok(v) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, v);
    }
    if compress {
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    if let Some((coding, _)) = &encoded {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    if let Some(value) = csp.and_then(|c| HeaderValue::from_str(c).ok()) {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    resp
}

async fn serve(path: &str, request: &HeaderMap, cacheable: bool, dev: bool, captcha: bool) -> Option<Response> {
    let file = WebAssets::get(path)?;
    let csp = path.ends_with(".html").then(|| csp(dev, captcha));
    let hash = file.metadata.sha256_hash();
    Some(respond(path, (file.data, hash), request, cacheable, csp.as_deref()).await)
}

pub async fn handler(State(state): State<crate::app::AppState>, uri: Uri, request: HeaderMap) -> Response {
    let dev = state.config.dev;
    let captcha = state.config.captcha_provider != crate::config::CaptchaProvider::None;
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path.starts_with(".well-known/") {
        return crate::routes::not_found().await.into_response();
    }
    // Hashed build artifacts live under assets/ and may be cached for a long time.
    if !path.is_empty()
        && let Some(resp) = serve(path, &request, path.starts_with("assets/"), dev, captcha).await
    {
        return resp;
    }
    match serve("index.html", &request, false, dev, captcha).await {
        Some(resp) => resp,
        None => (
            StatusCode::NOT_FOUND,
            "Web client not embedded (web/dist missing at build time). The API runs under /api/v1.",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use http_body_util::BodyExt;

    fn file(data: &'static [u8]) -> (Cow<'static, [u8]>, [u8; 32]) {
        (Cow::Borrowed(data), <sha2::Sha256 as sha2::Digest>::digest(data).into())
    }

    fn with(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    async fn body(resp: Response) -> Vec<u8> {
        resp.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    static SCRIPT: LazyLock<Vec<u8>> =
        LazyLock::new(|| "export const greeting = 'hello tavern';\n".repeat(200).into_bytes());

    #[tokio::test]
    async fn scripts_are_gzipped_when_accepted_and_revalidated_by_etag() {
        let script: &'static [u8] = SCRIPT.as_slice();
        let path = "assets/test-gzip.js";
        let plain = respond(path, file(script), &HeaderMap::new(), true, None).await;
        assert_eq!(plain.status(), StatusCode::OK);
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(plain.headers()[header::VARY], "accept-encoding");
        let plain_tag = plain.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(body(plain).await, script);

        let gz =
            respond(path, file(script), &with(&[(header::ACCEPT_ENCODING, "br;q=0, gzip, deflate")]), true, None).await;
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(gz.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        let gz_tag = gz.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_ne!(gz_tag, plain_tag, "each encoding has its own tag");
        let packed = body(gz).await;
        assert!(packed.len() < script.len() / 4, "{} of {}", packed.len(), script.len());
        let mut unpacked = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(packed.as_slice()), &mut unpacked).unwrap();
        assert_eq!(unpacked, script);

        // Refused codings and small files stay plain.
        let refused = respond(path, file(script), &with(&[(header::ACCEPT_ENCODING, "gzip;q=0")]), true, None).await;
        assert!(refused.headers().get(header::CONTENT_ENCODING).is_none());
        let small =
            respond("assets/small.js", file(b"x()"), &with(&[(header::ACCEPT_ENCODING, "gzip")]), true, None).await;
        assert!(small.headers().get(header::CONTENT_ENCODING).is_none());
        let font =
            respond("assets/f.woff2", file(script), &with(&[(header::ACCEPT_ENCODING, "gzip")]), true, None).await;
        assert!(font.headers().get(header::CONTENT_ENCODING).is_none(), "fonts are compressed already");

        // Revalidation: the tag of the variant answers 304 without a body, with the same headers.
        let again = respond(
            path,
            file(script),
            &with(&[(header::ACCEPT_ENCODING, "gzip"), (header::IF_NONE_MATCH, &format!("W/\"x\", {gz_tag}"))]),
            true,
            None,
        )
        .await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(again.headers()[header::ETAG], gz_tag.as_str());
        assert!(body(again).await.is_empty());
        let stale = respond(path, file(script), &with(&[(header::IF_NONE_MATCH, &gz_tag)]), true, None).await;
        assert_eq!(stale.status(), StatusCode::OK, "another variant's tag does not match");
    }

    #[tokio::test]
    async fn index_html_keeps_no_cache_and_its_csp_with_an_etag() {
        let page: &'static [u8] = b"<!doctype html><html><body>tavrn</body></html>";
        let policy = csp(false, false);
        let resp = respond("index.html", file(page), &HeaderMap::new(), false, Some(&policy)).await;
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(resp.headers()[header::CONTENT_SECURITY_POLICY], policy.as_str());
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/html");
        let tag = resp.headers()[header::ETAG].to_str().unwrap().to_string();
        let resp =
            respond("index.html", file(page), &with(&[(header::IF_NONE_MATCH, &tag)]), false, Some(&policy)).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(resp.headers()[header::CONTENT_SECURITY_POLICY], policy.as_str());
    }

    fn directive(csp: &str, name: &str) -> String {
        csp.split(';').map(str::trim).find(|d| d.starts_with(name)).unwrap_or_default().to_string()
    }

    #[test]
    fn csp_allows_webassembly_but_not_eval() {
        let script_src = directive(&csp(false, false), "script-src");
        assert!(script_src.contains("'wasm-unsafe-eval'"));
        assert!(!script_src.contains("'unsafe-eval'"));
        assert!(!script_src.contains("'unsafe-inline'"));
    }

    #[test]
    fn csp_allows_other_nodes_and_plain_http_only_in_dev() {
        assert!(directive(&csp(false, false), "connect-src").contains("https: wss:"));
        assert!(!directive(&csp(false, false), "connect-src").contains("http:"));
        assert!(directive(&csp(true, false), "connect-src").contains("http: ws:"));
        for dev in [false, true] {
            assert!(csp(dev, false).contains("frame-ancestors 'none'"));
            assert!(csp(dev, true).contains("object-src 'none'"));
        }
    }

    #[test]
    fn csp_frames_only_the_embed_providers_and_the_captcha_when_configured() {
        for dev in [false, true] {
            let frames = directive(&csp(dev, false), "frame-src");
            let hosts: Vec<&str> = frames.split_whitespace().skip(1).collect();
            assert_eq!(
                hosts,
                [
                    "https://www.youtube-nocookie.com",
                    "https://player.twitch.tv",
                    "https://clips.twitch.tv",
                    "https://player.vimeo.com",
                    "https://open.spotify.com",
                ]
            );
            let with = directive(&csp(dev, true), "frame-src");
            assert!(
                with.starts_with("frame-src https://challenges.cloudflare.com https://*.challenges.cloudflare.com ")
            );
        }
        assert!(!csp(false, false).contains("cloudflare"), "no captcha, no captcha hosts");
        assert!(directive(&csp(false, true), "script-src").contains("https://challenges.cloudflare.com"));
    }

    #[test]
    fn csp_names_no_font_or_style_hosts() {
        for (dev, captcha) in [(false, false), (true, true)] {
            let c = csp(dev, captcha);
            assert!(!c.contains("fonts.googleapis.com") && !c.contains("fonts.gstatic.com"), "{c}");
            assert_eq!(directive(&c, "font-src"), "font-src 'self'");
        }
    }
}
