// SPDX-License-Identifier: AGPL-3.0-only
//! Markdown → sanitized HTML for the legal pages. The admin's Markdown is rendered once when
//! a document is published. Nothing the author writes reaches the page as markup: raw HTML blocks and inline HTML
//! become escaped text, images become their alt text (no third-party requests from a legal page), and links keep
//! only `http(s):`, `mailto:`, same-site paths and fragments (anything else, e.g. `javascript:`, points to `#`).

use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, TagEnd, html};

/// Largest Markdown source of one document (bytes).
pub const MAX_MARKDOWN_BYTES: usize = 200 * 1024;

/// `true` for link targets a legal page may carry.
pub fn safe_url(url: &str) -> bool {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:") {
        return !u.chars().any(|c| c.is_control() || c.is_whitespace());
    }
    // Same-site paths and fragments; `//host` would be protocol-relative.
    (u.starts_with('/') && !u.starts_with("//")) || u.starts_with('#')
}

/// Renders `markdown` to HTML without any author-controlled markup.
pub fn render(markdown: &str) -> String {
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut in_image = 0usize;
    let events = Parser::new_ext(markdown, options).filter_map(|event| match event {
        Event::Html(s) | Event::InlineHtml(s) => Some(Event::Text(s)),
        Event::Start(Tag::Image { .. }) => {
            in_image += 1;
            None
        }
        Event::End(TagEnd::Image) => {
            in_image = in_image.saturating_sub(1);
            None
        }
        Event::Start(Tag::Link { link_type, dest_url, title, id }) => {
            let dest_url = if safe_url(&dest_url) { dest_url } else { CowStr::Borrowed("#") };
            Some(Event::Start(Tag::Link { link_type, dest_url, title, id }))
        }
        other => Some(other),
    });
    let mut out = String::with_capacity(markdown.len() * 3 / 2);
    html::push_html(&mut out, events);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_usual_markdown() {
        let html = render("# Impressum\n\n**Max** Muster\n\n- a\n- b\n\n| A | B |\n|---|---|\n| 1 | 2 |\n");
        assert!(html.contains("<h1>Impressum</h1>"), "{html}");
        assert!(html.contains("<strong>Max</strong>"));
        assert!(html.contains("<li>a</li>"));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn raw_html_and_scripts_are_escaped() {
        for md in [
            "<script>alert(1)</script>",
            "hi <img src=x onerror=alert(1)> there",
            "<iframe src=\"https://evil.example\"></iframe>",
            "<a href=\"javascript:alert(1)\">x</a>",
        ] {
            let html = render(md);
            assert!(!html.contains("<script"), "{html}");
            assert!(!html.contains("<img"), "{html}");
            assert!(!html.contains("<iframe"), "{html}");
            assert!(!html.contains("<a href=\"javascript"), "{html}");
            assert!(html.contains("&lt;"), "escaped: {html}");
        }
    }

    #[test]
    fn unsafe_links_and_images_are_neutralized() {
        let html = render(
            "[click](javascript:alert(1)) [data](data:text/html,x) [ok](https://a.example/x) [mail](mailto:a@b.example) [rel](/legal/terms) [proto](//evil.example)",
        );
        assert!(!html.contains("javascript:"), "{html}");
        assert!(!html.contains("data:text"), "{html}");
        assert!(html.contains("href=\"https://a.example/x\""));
        assert!(html.contains("href=\"mailto:a@b.example\""));
        assert!(html.contains("href=\"/legal/terms\""));
        assert!(!html.contains("//evil.example"), "{html}");
        let html = render("![tracker](https://tracker.example/p.gif)");
        assert!(!html.contains("<img"), "{html}");
        assert!(html.contains("tracker"), "alt text stays: {html}");
        let html = render("<https://ok.example>");
        assert!(html.contains("href=\"https://ok.example\""), "{html}");
    }

    #[test]
    fn safe_url_rules() {
        assert!(safe_url("https://a.example"));
        assert!(safe_url("HTTP://A.example"));
        assert!(safe_url("#top"));
        assert!(!safe_url("JaVaScRiPt:alert(1)"));
        assert!(!safe_url("vbscript:x"));
        assert!(!safe_url("//evil.example"));
        assert!(!safe_url("https://a.example/\u{0}x"));
        assert!(!safe_url("relative/path"));
    }
}
