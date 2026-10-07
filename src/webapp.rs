// SPDX-License-Identifier: AGPL-3.0-only
//! Serves the embedded web client (`web/dist`, included at build time).
//! Unknown paths outside the API serve `index.html` (single-page app routing).

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist"]
#[exclude = ".gitkeep"]
pub struct WebAssets;

// challenges.cloudflare.com: Turnstile captcha (script and iframe), only in effect if the operator enables it.
// 'wasm-unsafe-eval': allows compiling the crypto core (@tavrn/crypto, WebAssembly); it does not allow eval().
// connect-src 'self' https: wss: lets the client talk to every node (FEDERATION.md §8).
// frame-src: the click-to-play embeds of the web client (tavrn-web, src/lib/embeds.ts), exactly these hosts.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' https://challenges.cloudflare.com https://*.challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https:; media-src 'self' blob:; connect-src 'self' https: wss:; worker-src 'self' blob:; frame-src https://challenges.cloudflare.com https://*.challenges.cloudflare.com https://www.youtube-nocookie.com https://player.twitch.tv https://clips.twitch.tv https://player.vimeo.com https://open.spotify.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
// Development (`--dev`): development peers speak plain HTTP (`TAVRN_FEDERATION_DEV_PEERS`).
const CSP_DEV: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' https://challenges.cloudflare.com https://*.challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https: http:; media-src 'self' blob:; connect-src 'self' https: wss: http: ws:; worker-src 'self' blob:; frame-src https://challenges.cloudflare.com https://*.challenges.cloudflare.com https://www.youtube-nocookie.com https://player.twitch.tv https://clips.twitch.tv https://player.vimeo.com https://open.spotify.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// The CSP of the web client's HTML pages.
pub fn csp(dev: bool) -> &'static str {
    if dev { CSP_DEV } else { CSP }
}

pub fn is_available() -> bool {
    WebAssets::get("index.html").is_some()
}

fn serve(path: &str, cacheable: bool, dev: bool) -> Option<Response> {
    let file = WebAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = Response::new(Body::from(file.data.into_owned()));
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if cacheable { "public, max-age=31536000, immutable" } else { "no-cache" }),
    );
    if path.ends_with(".html") {
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp(dev)));
    }
    Some(resp)
}

pub async fn handler(State(state): State<crate::app::AppState>, uri: Uri) -> Response {
    let dev = state.config.dev;
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path.starts_with(".well-known/") {
        return crate::routes::not_found().await.into_response();
    }
    // Hashed build artifacts live under assets/ and may be cached for a long time.
    if !path.is_empty()
        && let Some(resp) = serve(path, path.starts_with("assets/"), dev)
    {
        return resp;
    }
    match serve("index.html", false, dev) {
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
    #[test]
    fn csp_allows_webassembly_but_not_eval() {
        let script_src = super::CSP.split(';').find(|d| d.trim().starts_with("script-src")).unwrap_or_default();
        assert!(script_src.contains("'wasm-unsafe-eval'"));
        assert!(!script_src.contains("'unsafe-eval'"));
        assert!(!script_src.contains("'unsafe-inline'"));
    }

    #[test]
    fn csp_allows_other_nodes_and_plain_http_only_in_dev() {
        let connect =
            |csp: &str| csp.split(';').find(|d| d.trim().starts_with("connect-src")).unwrap_or_default().to_string();
        assert!(connect(super::csp(false)).contains("https: wss:"));
        assert!(!connect(super::csp(false)).contains("http:"));
        assert!(connect(super::csp(true)).contains("http: ws:"));
        for dev in [false, true] {
            assert!(super::csp(dev).contains("frame-ancestors 'none'"));
        }
    }

    #[test]
    fn csp_frames_only_the_embed_providers_and_the_captcha() {
        for dev in [false, true] {
            let frames = super::csp(dev).split(';').find(|d| d.trim().starts_with("frame-src")).unwrap_or_default();
            let hosts: Vec<&str> = frames.split_whitespace().skip(1).collect();
            assert_eq!(
                hosts,
                [
                    "https://challenges.cloudflare.com",
                    "https://*.challenges.cloudflare.com",
                    "https://www.youtube-nocookie.com",
                    "https://player.twitch.tv",
                    "https://clips.twitch.tv",
                    "https://player.vimeo.com",
                    "https://open.spotify.com",
                ]
            );
        }
    }
}
