// SPDX-License-Identifier: AGPL-3.0-only
//! GIF search via Giphy or Tenor. The API key stays on the node; clients only ask the node.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{config::GifProvider, error::ApiError};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Gif {
    pub id: String,
    pub title: String,
    /// Full animation (GIF or MP4)
    pub url: String,
    /// Small preview
    pub preview_url: String,
    pub width: i64,
    pub height: i64,
}

#[derive(Clone)]
pub struct GifClient {
    provider: GifProvider,
    key: String,
    http: reqwest::Client,
    base: String,
}

impl GifClient {
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        if config.gif_provider == GifProvider::None {
            return None;
        }
        let base = match config.gif_provider {
            GifProvider::Giphy => "https://api.giphy.com",
            GifProvider::Tenor => "https://tenor.googleapis.com",
            GifProvider::None => unreachable!(),
        };
        Some(Self::new(config.gif_provider, config.gif_api_key.clone().unwrap_or_default(), base))
    }

    pub fn new(provider: GifProvider, key: String, base: &str) -> Self {
        Self {
            provider,
            key,
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().unwrap_or_default(),
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub fn provider(&self) -> GifProvider {
        self.provider
    }

    /// Allowed hosts for GIF URLs in messages (clients only load from these).
    pub fn allowed_hosts(&self) -> &'static [&'static str] {
        match self.provider {
            GifProvider::Giphy => &[
                "media.giphy.com",
                "media0.giphy.com",
                "media1.giphy.com",
                "media2.giphy.com",
                "media3.giphy.com",
                "media4.giphy.com",
                "i.giphy.com",
            ],
            GifProvider::Tenor => &["media.tenor.com", "c.tenor.com", "media1.tenor.com"],
            GifProvider::None => &[],
        }
    }

    pub async fn search(&self, query: Option<&str>, limit: u32) -> Result<Vec<Gif>, ApiError> {
        let limit = limit.clamp(1, 50).to_string();
        let unavailable = |e: reqwest::Error| {
            // Without the URL: it carries the node's API key and the user's search term.
            tracing::warn!(error = %e.without_url(), "GIF provider unreachable");
            ApiError::Unavailable { code: "gif.unavailable", detail: "GIF service unreachable".into() }
        };
        match self.provider {
            GifProvider::Giphy => {
                let (path, mut params) = match query {
                    Some(q) => ("/v1/gifs/search", vec![("q", q.to_string())]),
                    None => ("/v1/gifs/trending", vec![]),
                };
                params.push(("api_key", self.key.clone()));
                params.push(("limit", limit));
                params.push(("rating", "pg-13".into()));
                let resp =
                    self.http.get(format!("{}{path}", self.base)).query(&params).send().await.map_err(unavailable)?;
                let body: GiphyResponse = resp
                    .json()
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("unreadable Giphy response: {e}")))?;
                Ok(body
                    .data
                    .into_iter()
                    .filter_map(|g| {
                        let full = g.images.original?;
                        let preview = g.images.fixed_height_small.or(g.images.fixed_height)?;
                        Some(Gif {
                            id: g.id,
                            title: g.title.unwrap_or_default(),
                            url: full.url,
                            preview_url: preview.url,
                            width: full.width.parse().unwrap_or(0),
                            height: full.height.parse().unwrap_or(0),
                        })
                    })
                    .collect())
            }
            GifProvider::Tenor => {
                let (path, mut params) = match query {
                    Some(q) => ("/v2/search", vec![("q", q.to_string())]),
                    None => ("/v2/featured", vec![]),
                };
                params.push(("key", self.key.clone()));
                params.push(("limit", limit));
                params.push(("media_filter", "gif,tinygif".into()));
                params.push(("contentfilter", "medium".into()));
                let resp =
                    self.http.get(format!("{}{path}", self.base)).query(&params).send().await.map_err(unavailable)?;
                let body: TenorResponse = resp
                    .json()
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("unreadable Tenor response: {e}")))?;
                Ok(body
                    .results
                    .into_iter()
                    .filter_map(|g| {
                        let full = g.media_formats.gif?;
                        let preview = g.media_formats.tinygif.unwrap_or_else(|| full.clone());
                        let (w, h) = full
                            .dims
                            .map(|d| (d.first().copied().unwrap_or(0), d.get(1).copied().unwrap_or(0)))
                            .unwrap_or((0, 0));
                        Some(Gif {
                            id: g.id,
                            title: g.content_description.unwrap_or_default(),
                            url: full.url,
                            preview_url: preview.url,
                            width: w,
                            height: h,
                        })
                    })
                    .collect())
            }
            GifProvider::None => Ok(Vec::new()),
        }
    }
}

#[derive(Deserialize)]
struct GiphyResponse {
    data: Vec<GiphyGif>,
}
#[derive(Deserialize)]
struct GiphyGif {
    id: String,
    title: Option<String>,
    images: GiphyImages,
}
#[derive(Deserialize)]
struct GiphyImages {
    original: Option<GiphyImage>,
    fixed_height: Option<GiphyImage>,
    fixed_height_small: Option<GiphyImage>,
}
#[derive(Deserialize)]
struct GiphyImage {
    url: String,
    #[serde(default)]
    width: String,
    #[serde(default)]
    height: String,
}
#[derive(Deserialize)]
struct TenorResponse {
    results: Vec<TenorGif>,
}
#[derive(Deserialize)]
struct TenorGif {
    id: String,
    content_description: Option<String>,
    media_formats: TenorFormats,
}
#[derive(Deserialize)]
struct TenorFormats {
    gif: Option<TenorMedia>,
    tinygif: Option<TenorMedia>,
}
#[derive(Deserialize, Clone)]
struct TenorMedia {
    url: String,
    dims: Option<Vec<i64>>,
}

/// Checks a GIF URL from a message: https and a host of the configured provider.
pub fn valid_gif_url(url: &str, allowed_hosts: &[&str]) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
    !host.is_empty() && allowed_hosts.contains(&host.as_str()) && url.len() <= 2048
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use axum::{Json, Router, extract::Query, routing::get};

    #[tokio::test]
    async fn giphy_and_tenor_are_normalized() {
        #[derive(Deserialize)]
        struct Q {
            q: Option<String>,
            api_key: Option<String>,
            key: Option<String>,
        }
        let app = Router::new()
            .route("/v1/gifs/search", get(|Query(q): Query<Q>| async move {
                assert_eq!(q.api_key.as_deref(), Some("k"));
                Json(serde_json::json!({ "data": [{ "id": "g1", "title": q.q, "images": { "original": { "url": "https://media.giphy.com/g1.gif", "width": "480", "height": "270" }, "fixed_height_small": { "url": "https://media.giphy.com/g1s.gif" } } }] }))
            }))
            .route("/v2/search", get(|Query(q): Query<Q>| async move {
                assert_eq!(q.key.as_deref(), Some("k"));
                Json(serde_json::json!({ "results": [{ "id": "t1", "content_description": "cat", "media_formats": { "gif": { "url": "https://media.tenor.com/t1.gif", "dims": [320, 240] }, "tinygif": { "url": "https://media.tenor.com/t1s.gif" } } }] }))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{addr}");
        let giphy = GifClient::new(GifProvider::Giphy, "k".into(), &base);
        let r = giphy.search(Some("dog"), 10).await.unwrap();
        assert_eq!(
            r,
            vec![Gif {
                id: "g1".into(),
                title: "dog".into(),
                url: "https://media.giphy.com/g1.gif".into(),
                preview_url: "https://media.giphy.com/g1s.gif".into(),
                width: 480,
                height: 270
            }]
        );
        let tenor = GifClient::new(GifProvider::Tenor, "k".into(), &base);
        let r = tenor.search(Some("cat"), 10).await.unwrap();
        assert_eq!(r[0].title, "cat");
        assert_eq!((r[0].width, r[0].height), (320, 240));
        assert_eq!(r[0].preview_url, "https://media.tenor.com/t1s.gif");
        let down = GifClient::new(GifProvider::Giphy, "k".into(), "http://127.0.0.1:1");
        assert_eq!(down.search(Some("x"), 5).await.unwrap_err().code(), "gif.unavailable");
    }

    #[test]
    fn gif_url_validation() {
        let hosts = &["media.giphy.com"];
        assert!(valid_gif_url("https://media.giphy.com/x.gif", hosts));
        assert!(!valid_gif_url("http://media.giphy.com/x.gif", hosts));
        assert!(!valid_gif_url("https://evil.example/x.gif", hosts));
        assert!(!valid_gif_url("https://media.giphy.com.evil.example/x.gif", hosts));
    }
}
