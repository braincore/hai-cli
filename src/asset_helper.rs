use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub fn get_invalid_asset_name_re() -> &'static Regex {
    static ASSET_NAME_RE: OnceLock<Regex> = OnceLock::new();
    ASSET_NAME_RE.get_or_init(|| {
        Regex::new(r##"(?://{1,})|[\[@+!#\$%^&\*<>,?\\|}{~:;\[\]\s"'=`]"##).unwrap()
    })
}

/// Checks for whitespace, control chars, and symbols.
/// Does not check for confusable homoglyphs.
pub fn is_likely_valid_asset_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.contains(char::is_whitespace) {
        return false;
    }
    if name.chars().any(|c| c.is_control()) {
        return false;
    }

    // For /s/ paths, skip the user segment and only validate the rest
    let to_validate = if let Some(after_s) = name.strip_prefix("/s/") {
        // Find the end of the user segment
        match after_s.split_once('/') {
            Some((_, rest)) => rest,
            None => "", // Just "/s/<users>" with no relpath - nothing more to validate
        }
    } else {
        name
    };

    if !to_validate.is_empty() && get_invalid_asset_name_re().is_match(to_validate) {
        return false;
    }
    true
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

pub async fn resolve_attachment_asset_name(asset_name: &str, api_client: &HaiClient) -> String {
    if !asset_name.contains(':') {
        // Non-attachment asset name, nothing further to resolve
        return asset_name.to_string();
    }

    if asset_name.starts_with(':') {
        // An asset attachment already in API format, so just return it
        return asset_name.to_string();
    }

    use crate::api::types::asset::AssetGetArg;

    // Split into the chain of names: the first is a real asset name, and each
    // subsequent segment is an attachment relative to the prior asset.
    //
    // For API-format compatibility, each set of priors need to be converted
    // into an entry ID:
    //
    // grandparent-asset-name:parent-attachment-name:child-attachment-name
    // - query grandparent-asset
    // - query (grandparent-entry-id:parent-attachment-name)
    // - query (parent-attachment-entry-id:child-attachment-name)
    let (mut current_name, rest) = asset_name
        .split_once(':')
        .map(|(n, r)| (n.to_string(), r))
        .expect("unexpected missing :");
    let (segments, last_relname) = match rest.rsplit_once(':') {
        Some((before_last, last)) => (before_last.split(':').collect::<Vec<&str>>(), last),
        None => (vec![], rest),
    };

    for relname in &segments {
        // Fetch the current asset to obtain its entry_id.
        let entry_id = match api_client
            .asset_get(AssetGetArg {
                name: current_name.to_string(),
            })
            .await
        {
            Ok(entry) => entry.entry.entry_id,
            Err(e) => {
                eprintln!(
                    "error: failed to fetch asset '{}' to get entry_id: {}",
                    current_name, e
                );
                // Bail out
                return asset_name.to_string();
            }
        };
        // Build next level
        current_name = format!(":{}/{}", entry_id, relname);
    }

    // Final query to get the entry_id of the last segment
    match api_client
        .asset_get(AssetGetArg {
            name: current_name.to_string(),
        })
        .await
    {
        Ok(res) => {
            if last_relname.is_empty() {
                format!(":{}", res.entry.entry_id)
            } else {
                format!(":{}/{}", res.entry.entry_id, last_relname)
            }
        }
        Err(e) => {
            eprintln!(
                "error: failed to fetch asset '{}' to get entry_id: {}",
                current_name, e
            );
            // Bail out
            return asset_name.to_string();
        }
    }
}

/// If an asset-key begins with `//`, it is converted to the current logged-in
/// user's public asset prefix: /<username>/<path>
pub fn expand_pub_asset_name(asset_name: &str, account: &Option<crate::db::Account>) -> String {
    if asset_name.starts_with("//") {
        if let Some(account) = account {
            format!("/{}{}", account.username, &asset_name[1..])
        } else {
            asset_name.to_string()
        }
    } else {
        asset_name.to_string()
    }
}

/// If an asset-key begins with `/s/+`..., the current logged-in user's username
/// is added: `/s/<username>+...`.
pub fn expand_shared_pool_asset_name(
    asset_name: &str,
    account: &Option<crate::db::Account>,
) -> String {
    if asset_name.starts_with("/s/+") {
        if let Some(account) = account {
            format!("/s/{}+{}", account.username, &asset_name[4..])
        } else {
            asset_name.to_string()
        }
    } else {
        asset_name.to_string()
    }
}

/// Expands `//` and `/s/+` prefixes in asset names.
pub fn expand_asset_name(asset_name: &str, account: &Option<crate::db::Account>) -> String {
    expand_shared_pool_asset_name(&expand_pub_asset_name(asset_name, account), account)
}

// --

use crate::api::client::HaiClient;
use crate::api::types::asset::{
    AssetEntry, AssetEntryListArg, AssetEntryListNextArg, EntryListOrder,
};

/// Lists all asset entries under the given prefix, cursoring through all pages.
/// Returns the collected entries with no printing or session side effects.
pub async fn list_all_asset_entries(
    api_client: &HaiClient,
    prefix: &str,
) -> Result<Vec<AssetEntry>, ()> {
    let mut entries = Vec::new();

    let mut res = api_client
        .asset_entry_list(AssetEntryListArg {
            prefix: Some(prefix.to_string()),
            limit: 200,
            order: EntryListOrder::Asc,
        })
        .await
        .map_err(|_| ())?;

    loop {
        entries.extend_from_slice(&res.entries);

        if !res.has_more {
            break;
        }

        res = api_client
            .asset_entry_list_next(AssetEntryListNextArg {
                cursor: res.cursor,
                limit: 200,
            })
            .await
            .map_err(|_| ())?;
    }

    Ok(entries)
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
