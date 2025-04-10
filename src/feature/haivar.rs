/// Helpers for the half-baked $var substitution feature.
///
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

fn get_haivar_re() -> &'static Regex {
    static HAIVAR_RE: OnceLock<Regex> = OnceLock::new();
    HAIVAR_RE.get_or_init(|| Regex::new(r"\$([a-zA-Z][a-zA-Z0-9_]*)").unwrap())
}

/// Finds all instances of $var in string and replaces them with mapping.
pub fn replace_haivars(s: &str, haivars: &HashMap<String, String>) -> String {
    let haivar_re = get_haivar_re();
    let result = haivar_re.replace_all(s, |caps: &regex::Captures| {
        let key = &caps[1];
        haivars.get(key).cloned().unwrap_or_else(|| {
            eprintln!("error: undefined variable: {}", &caps[0]);
            caps[0].to_string()
        })
    });
    result.to_string()
}
