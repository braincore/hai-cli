use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

/// Fetch limited amount of HTML to extract OpenGraph tags.
const FETCH_OG_TAGS_MAX_BYTES: usize = 2 * 1024 * 1024;
const FETCH_OG_TAGS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OgTag {
    key: String,
    value: String,
}

/// Fetches `url` and returns OpenGraph `<meta>` tags in the order that they
/// appear in the HTML.
pub async fn fetch_og_tags(url: &str) -> Result<Vec<OgTag>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("Invalid url: {}", e))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Only http and https urls are supported".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_OG_TAGS_TIMEOUT)
        .user_agent(concat!("hai-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("Failed to build http client: {}", e))?;
    let resp = client
        .get(parsed)
        .header("accept", "text/html,application/xhtml+xml")
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Request failed with status {}", resp.status()));
    }

    // Read the body up to the fetch size limit.
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Failed to read body: {}", e))?;
        let remaining = FETCH_OG_TAGS_MAX_BYTES - body.len();
        if chunk.len() >= remaining {
            body.extend_from_slice(&chunk[..remaining]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let html = String::from_utf8_lossy(&body);
    Ok(parse_og_tags(&html))
}

/// Extracts `og:*` meta tags in order of appearance. Accepts both the
/// correct `property` attribute and the commonly misused `name`.
pub fn parse_og_tags(html: &str) -> Vec<OgTag> {
    let doc = dom_query::Document::from(html);
    let mut tags = Vec::new();
    for meta in doc.select("meta").nodes() {
        let Some(key) = meta
            .attr("property")
            .filter(|k| k.trim().starts_with("og:"))
            .or_else(|| meta.attr("name").filter(|k| k.trim().starts_with("og:")))
        else {
            continue;
        };
        let Some(value) = meta.attr("content") else {
            continue;
        };
        tags.push(OgTag {
            key: key.trim().to_string(),
            value: value.to_string(),
        });
    }
    tags
}

#[cfg(test)]
mod fetch_og_tags_tests {
    use super::parse_og_tags;

    #[test]
    fn parses_og_tags_in_order() {
        let html = r#"<html><head>
            <meta property="og:title" content="Hello">
            <meta name="description" content="ignored">
            <meta name="og:type" content="article">
            <meta property="og:image" content="https://x/1.png">
            <meta property="og:image" content="https://x/2.png">
            <meta property="twitter:card" content="ignored">
            </head><body></body></html>"#;
        let tags: Vec<(String, String)> = parse_og_tags(html)
            .into_iter()
            .map(|t| (t.key, t.value))
            .collect();
        assert_eq!(
            tags,
            vec![
                ("og:title".into(), "Hello".into()),
                ("og:type".into(), "article".into()),
                ("og:image".into(), "https://x/1.png".into()),
                ("og:image".into(), "https://x/2.png".into()),
            ]
        );
    }
}
