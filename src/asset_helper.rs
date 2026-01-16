use regex::Regex;
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
