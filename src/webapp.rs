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

fn serve(path: &str, cacheable: bool, dev: bool, captcha: bool) -> Option<Response> {
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
    if path.ends_with(".html")
        && let Ok(value) = HeaderValue::from_str(&csp(dev, captcha))
    {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    Some(resp)
}

pub async fn handler(State(state): State<crate::app::AppState>, uri: Uri) -> Response {
    let dev = state.config.dev;
    let captcha = state.config.captcha_provider != crate::config::CaptchaProvider::None;
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path.starts_with(".well-known/") {
        return crate::routes::not_found().await.into_response();
    }
    // Hashed build artifacts live under assets/ and may be cached for a long time.
    if !path.is_empty()
        && let Some(resp) = serve(path, path.starts_with("assets/"), dev, captcha)
    {
        return resp;
    }
    match serve("index.html", false, dev, captcha) {
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
    use super::csp;

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
