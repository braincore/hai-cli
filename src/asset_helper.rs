use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub fn get_invalid_asset_name_re() -> &'static Regex {
    static ASSET_NAME_RE: OnceLock<Regex> = OnceLock::new();
    ASSET_NAME_RE.get_or_init(|| {
        Regex::new(r##"(?://{1,})|[\[@+!#\$%^&\*<>,?\\|}{~:;\[\]\s"'=`]"##).unwrap()
    })
}

/// Constructs the publicly accessible URL for an asset.
pub fn get_public_asset_url(asset_name: &str) -> Option<String> {
    let (username, asset_path) = if asset_name.starts_with("/")
        && let Some(pos) = asset_name[1..].find('/')
    {
        asset_name.split_at(pos + 1)
    } else {
        return None;
    };
    let username = &username[1..];
    Some(format!("https://{username}.hai.dog{asset_path}"))
}

pub fn best_guess_temp_file_extension(
    asset_name: &str,
    asset_content_type: Option<&str>,
    initial_content: &[u8],
) -> String {
    let ext_from_name = Path::new(asset_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_string());
    let ext_from_content_type = asset_content_type
        .as_ref()
        .and_then(|ct| mime_guess::get_mime_extensions_str(ct))
        // Pick the shortest so that "md" is prioritized over "markdown"
        .and_then(|exts| exts.iter().min_by_key(|s| s.len()).copied())
        .map(|s| s.to_string());
    // If there's an asset_content_type that doesn't produce a extension via
    // mime-guess, then we don't want to assume it's markdown.
    let ext_from_markdown = if asset_content_type.is_none() && initial_content.starts_with(b"# ") {
        Some("md".to_string())
    } else {
        None
    };
    // Combine all options, in order of priority
    ext_from_name
        .or(ext_from_content_type)
        .or(ext_from_markdown)
        .map(|ext| format!(".{}", ext))
        .unwrap_or_default()
}

pub fn best_guess_content_type(
    asset_name: &str,
    asset_content_type: Option<&str>,
    initial_content: &[u8],
) -> String {
    let content_type_from_asset_name = Path::new(asset_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| mime_guess::from_ext(ext).first_raw());
    let content_type_from_asset_content_type = asset_content_type;
    let content_type_from_initial_content =
        if asset_content_type.is_none() && initial_content.starts_with(b"# ") {
            Some("text/markdown")
        } else {
            None
        };
    content_type_from_asset_content_type
        .or(content_type_from_asset_name)
        .or(content_type_from_initial_content)
        .unwrap_or(mime_guess::mime::APPLICATION_OCTET_STREAM.as_ref())
        .to_string()
}

// --

#[cfg(test)]
mod tests {
    #[test]
    fn test_best_guess_temp_file_extension() {
        use super::best_guess_temp_file_extension;

        // Extension from name
        let ext = best_guess_temp_file_extension("foo.md", None, b"# heading");
        assert_eq!(ext, ".md");

        // Extension from content type
        let ext = best_guess_temp_file_extension("foo", Some("text/markdown"), b"# heading");
        assert_eq!(ext, ".md");

        // Extension from markdown content
        let ext = best_guess_temp_file_extension("foo", None, b"# heading");
        assert_eq!(ext, ".md");

        // No extension
        let ext = best_guess_temp_file_extension("foo", None, b"plain text");
        assert_eq!(ext, "");

        // Content type with no known extension
        let ext =
            best_guess_temp_file_extension("foo", Some("application/x-unknown"), b"# heading");
        assert_eq!(ext, "");

        // Name and content type: prefers name
        let ext = best_guess_temp_file_extension("foo.txt", Some("text/markdown"), b"# heading");
        assert_eq!(ext, ".txt");

        // Name and markdown: prefers name
        let ext = best_guess_temp_file_extension("foo.txt", None, b"# heading");
        assert_eq!(ext, ".txt");
    }
}
