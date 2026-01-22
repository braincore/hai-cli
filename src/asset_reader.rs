use futures::future::join_all;
use glob::Pattern;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, Semaphore};

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset::{
    AssetEntry, AssetGetArg, AssetGetError, AssetGetResult, AssetMetadataInfo,
};
use crate::asset_cache::{AssetBlobCache, DownloadAssetError};
use crate::feature::asset_keyring::AssetKeyring;

// --

pub enum GetAssetError {
    BadName,
    DataFetchFailed,
}

/// If returns None, responsible for printing error msg.
pub async fn get_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<(Vec<u8>, AssetEntry), GetAssetError> {
    let asset_get_res = get_asset_entry(api_client, asset_name, bad_name_ok).await?;
    if let Some(data_url) = asset_get_res.entry.asset.url.as_ref()
        && let Some(hash) = asset_get_res.entry.asset.hash.as_ref()
    {
        let data_contents = match asset_blob_cache.get_or_download(data_url, hash).await {
            Ok(contents) => contents,
            Err(_) => {
                return Err(GetAssetError::DataFetchFailed);
            }
        };
        Ok((data_contents, asset_get_res.entry))
    } else {
        Err(GetAssetError::BadName)
    }
}

pub async fn get_asset_entry(
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<AssetGetResult, GetAssetError> {
    match api_client
        .asset_get(AssetGetArg {
            name: asset_name.to_string(),
        })
        .await
    {
        Ok(res) => Ok(res),
        Err(e) => {
            if matches!(e, RequestError::Route(AssetGetError::BadName)) {
                if bad_name_ok {
                    return Err(GetAssetError::BadName);
                }
            } else {
                eprintln!("error: {}", e);
            }
            match e {
                RequestError::BadRequest(_)
                | RequestError::Http(_)
                | RequestError::Unexpected(_) => Err(GetAssetError::DataFetchFailed),
                RequestError::Route(e) => match e {
                    AssetGetError::BadName => Err(GetAssetError::BadName),
                    _ => Err(GetAssetError::DataFetchFailed),
                },
            }
        }
    }
}

// --

/// If returns None, responsible for printing error msg.
pub async fn get_asset_and_metadata(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>, AssetEntry), GetAssetError> {
    let asset_get_res = get_asset_entry(api_client, asset_name, bad_name_ok).await?;
    let data_contents = if let Some(data_url) = asset_get_res.entry.asset.url.as_ref()
        && let Some(hash) = asset_get_res.entry.asset.hash.as_ref()
    {
        match asset_blob_cache.get_or_download(data_url, hash).await {
            Ok(contents) => contents,
            Err(_) => {
                eprintln!("error: failed to fetch asset data");
                return Err(GetAssetError::DataFetchFailed);
            }
        }
    } else {
        return Err(GetAssetError::BadName);
    };
    let metadata_contents = if let Some(AssetMetadataInfo {
        url: Some(metadata_url),
        hash: Some(metadata_hash),
        ..
    }) = asset_get_res.entry.metadata.as_ref()
    {
        Some(
            match asset_blob_cache
                .get_or_download(metadata_url, metadata_hash)
                .await
            {
                Ok(contents) => contents,
                Err(_) => {
                    eprintln!("error: failed to fetch asset metadata");
                    return Err(GetAssetError::DataFetchFailed);
                }
            },
        )
    } else {
        None
    };
    Ok((data_contents, metadata_contents, asset_get_res.entry))
}

// --

/// If returns None, responsible for printing error msg.
pub async fn get_only_asset_metadata(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<(Option<Vec<u8>>, AssetEntry), GetAssetError> {
    let asset_get_res = get_asset_entry(api_client, asset_name, bad_name_ok).await?;
    if asset_get_res.entry.asset.url.is_none() {
        return Err(GetAssetError::BadName);
    }
    let metadata_contents = if let Some(AssetMetadataInfo {
        url: Some(metadata_url),
        hash: Some(metadata_hash),
        ..
    }) = asset_get_res.entry.metadata.as_ref()
    {
        Some(
            match asset_blob_cache
                .get_or_download(metadata_url, metadata_hash)
                .await
            {
                Ok(contents) => contents,
                Err(_) => {
                    eprintln!("error: failed to fetch asset metadata");
                    return Err(GetAssetError::DataFetchFailed);
                }
            },
        )
    } else {
        None
    };
    Ok((metadata_contents, asset_get_res.entry))
}

// --

pub async fn get_asset_raw(data_url: &str) -> Option<Vec<u8>> {
    let asset_get_resp = match reqwest::get(data_url).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("error: {}", e);
            return None;
        }
    };
    if !asset_get_resp.status().is_success() {
        eprintln!("error: failed to fetch asset: {}", asset_get_resp.status());
        return None;
    }
    match asset_get_resp.bytes().await {
        Ok(contents) => Some(contents.to_vec()),
        Err(e) => {
            eprintln!("error: asset is non-text: {}", e);
            None
        }
    }
}

// --

/// Checks if an asset path contains glob characters
pub fn is_glob_pattern(path: &str) -> bool {
    path.contains('*') || path.contains('?') || path.contains('[')
}

/// Extracts the prefix for API query and the full pattern for client-side filtering.
/// e.g., "a/b/*.jpg" -> (prefix: "a/b/", pattern: "a/b/*.jpg")
pub fn parse_glob_pattern(pattern: &str) -> (String, Pattern) {
    // Find the first glob character
    let first_glob_idx = pattern
        .find(|c| c == '*' || c == '?' || c == '[')
        .unwrap_or(pattern.len());

    // Prefix is everything up to and including the last '/' before the glob
    let prefix = if let Some(last_slash) = pattern[..first_glob_idx].rfind('/') {
        pattern[..=last_slash].to_string()
    } else {
        String::new()
    };

    let compiled_pattern = Pattern::new(pattern).expect("Invalid glob pattern");

    (prefix, compiled_pattern)
}

/// Expands a glob pattern by querying the API and filtering results.
async fn expand_glob(
    api_client: &HaiClient,
    glob_pattern: &str,
) -> Result<Vec<AssetEntry>, String> {
    use crate::api::types::asset::{AssetEntryListArg, AssetEntryListError, AssetEntryListNextArg};

    let (prefix, pattern) = parse_glob_pattern(glob_pattern);

    let mut matching_assets = Vec::new();

    // Initial API call
    let mut asset_list_res = api_client
        .asset_entry_list(AssetEntryListArg {
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix)
            },
            limit: 200,
        })
        .await
        .map_err(|e| {
            if matches!(e, RequestError::Route(AssetEntryListError::Empty)) {
                format!("no assets match glob pattern: {}", glob_pattern)
            } else {
                format!("cannot list assets for glob {}: {}", glob_pattern, e)
            }
        })?;

    // Collect all matching entries
    loop {
        for entry in &asset_list_res.entries {
            if pattern.matches(&entry.name) {
                matching_assets.push(entry.clone());
            }
        }

        if !asset_list_res.has_more {
            break;
        }

        asset_list_res = api_client
            .asset_entry_list_next(AssetEntryListNextArg {
                cursor: asset_list_res.cursor,
                limit: 200,
            })
            .await
            .map_err(|e| format!("cannot list assets for glob {}: {}", glob_pattern, e))?;
    }

    if matching_assets.is_empty() {
        return Err(format!("no assets match glob pattern: {}", glob_pattern));
    }

    // Sort for consistent ordering
    matching_assets.sort_by(|a, b| human_sort::compare(&a.name, &b.name));

    Ok(matching_assets)
}

pub type AssetTempFileMap = HashMap<String, Result<tempfile::NamedTempFile, GetAssetError>>;

/// Prepares assets from a list of asset names/globs as temporary files.
///
/// This function:
/// 1. Expands any glob patterns in the input list
/// 2. Downloads all matching assets to temporary files in parallel
/// 3. Returns a map of asset names to their temporary files
///
/// # Arguments
/// * `api_client` - The API client for fetching assets
/// * `asset_names_or_globs` - A slice of asset names or glob patterns (without @ prefix)
/// * `max_concurrent_downloads` - Maximum number of concurrent downloads
/// * `skip_download` - Optional set of asset names to create as empty files instead of downloading
///
/// # Returns
/// A tuple containing:
/// - A map of asset names to their (NamedTempFile, PathBuf) tuples
/// - A map of glob patterns to their expanded asset names (for callers that need this info)
pub async fn prepare_assets_from_names_as_temp_files(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
    skip_download: Option<&HashSet<String>>,
) -> Result<(AssetTempFileMap, HashMap<String, Vec<String>>), String> {
    let empty_set = HashSet::new();
    let skip_download = skip_download.unwrap_or(&empty_set);

    let mut asset_final_map = HashMap::new();

    // Track expanded globs for caller reference
    let mut expanded_globs: HashMap<String, Vec<String>> = HashMap::new();

    // Collect unique assets to process
    let mut seen_assets: HashSet<String> = HashSet::new();
    let mut assets_to_download: Vec<AssetEntry> = Vec::new();
    let mut asset_fetch_failures = Vec::new();

    for asset_ref in asset_names_or_globs {
        if is_glob_pattern(asset_ref) {
            // Skip if we've already expanded this glob
            if expanded_globs.contains_key(asset_ref) {
                continue;
            }

            // Expand the glob
            let matched_asset_entries = expand_glob(api_client, asset_ref).await?;

            // Queue each matched asset for download
            for matched_asset_entry in &matched_asset_entries {
                if !seen_assets.contains(&matched_asset_entry.name) {
                    seen_assets.insert(matched_asset_entry.name.clone());
                    // Glob-matched assets are always inputs, so they need download
                    assets_to_download.push(matched_asset_entry.clone());
                }
            }

            expanded_globs.insert(
                asset_ref.clone(),
                matched_asset_entries
                    .iter()
                    .map(|entry| entry.name.clone())
                    .collect::<Vec<_>>(),
            );
        } else {
            // Regular asset (non-glob)
            if !seen_assets.contains(asset_ref) {
                seen_assets.insert(asset_ref.clone());
                if skip_download.contains(asset_ref) {
                    asset_final_map.insert(
                        asset_ref.clone(),
                        create_empty_temp_file(asset_ref, None, None)
                            .map_err(|_e| GetAssetError::DataFetchFailed),
                    );
                } else {
                    match get_asset_entry(api_client, asset_ref, false).await {
                        Ok(get_res) => assets_to_download.push(get_res.entry),
                        Err(e) => {
                            asset_fetch_failures.push((asset_ref.clone(), e));
                        }
                    };
                }
            }
        }
    }

    // Download/create files in parallel
    let sync_res = crate::asset_sync::sync_entries(
        asset_blob_cache,
        asset_keyring,
        api_client,
        crate::asset_sync::AssetSyncSource::AssetEntry(assets_to_download),
        None,
        Some(max_concurrent_downloads),
        false,
    )
    .await;
    let asset_map = match sync_res {
        Ok(sync_res) => {
            let mut asset_map: HashMap<String, Result<NamedTempFile, GetAssetError>> =
                HashMap::new();
            for (source, asset_temp_file, _) in sync_res {
                if let Some(asset_temp_file) = asset_temp_file {
                    asset_map.insert(source.asset_name.clone(), Ok(asset_temp_file));
                } else {
                    asset_map.insert(
                        source.asset_name.clone(),
                        Err(GetAssetError::DataFetchFailed),
                    );
                }
            }
            asset_map
        }
        Err(_) => {
            return Err("failed to sync assets".to_string());
        }
    };
    for (asset_ref, res) in asset_map {
        asset_final_map.insert(asset_ref, res);
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }
    Ok((asset_final_map, expanded_globs))
}

/// Prepares @assets in shell commands and handles redirections.
///
/// This function:
/// 1. Identifies all @asset references in the command (including glob patterns)
/// 2. Expands glob patterns (e.g., @data/*.jpg) to matching assets
/// 3. Downloads input assets to temporary files on the local machine (in parallel)
/// 4. Creates appropriate temporary files for output assets
/// 5. Handles append operations (>>) by downloading existing assets first
/// 6. Rewrites the shell command to use the local file paths
///
/// Returns:
/// * A tuple containing:
///   - The modified command with @assets replaced by file paths
///   - A map of asset names to their temporary files and paths
///   - A set of asset names that are used as outputs (via > or >>)
pub async fn prepare_assets_from_cmd_as_temp_files(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    cmd: &str,
    max_concurrent_downloads: usize,
) -> Result<(String, AssetTempFileMap, HashSet<String>), String> {
    let asset_regex = Regex::new(r"@([^\s]+)").expect("Invalid regex");
    let append_regex = Regex::new(r">>\s*@([^\s]+)").expect("Invalid regex");
    let output_regex = Regex::new(r"(?:>|>>)\s*@([^\s]+)").expect("Invalid regex");

    let mut append_assets = HashSet::new();
    let mut output_assets = HashSet::new();

    // Original @asset reference (including @) and the replacement info.
    // (full_match, asset_path, is_glob)
    let mut replacements: Vec<(String, String, bool)> = Vec::new();

    // First identify output assets and append assets
    for cap in output_regex.captures_iter(cmd) {
        let output_asset = cap[1].to_string();
        if is_glob_pattern(&output_asset) {
            return Err(format!(
                "Glob patterns are not allowed in output redirections: @{}",
                output_asset
            ));
        }
        output_assets.insert(output_asset);
    }

    for cap in append_regex.captures_iter(cmd) {
        let append_asset = cap[1].to_string();
        if is_glob_pattern(&append_asset) {
            return Err(format!(
                "Glob patterns are not allowed in append redirections: @{}",
                append_asset
            ));
        }
        append_assets.insert(append_asset);
    }

    // Identify input assets (may overlap with output assets) separately since
    // they must be downloaded.
    let input_assets: HashSet<String> = {
        let output_redirection_regex = Regex::new(r">>?\s*@[^\s]+").expect("Invalid regex");
        let cmd_without_outputs = output_redirection_regex.replace_all(cmd, "");

        asset_regex
            .captures_iter(&cmd_without_outputs)
            .map(|cap| cap[1].to_string())
            .collect()
    };

    // Collect all asset references from the command
    let mut asset_refs: Vec<String> = Vec::new();
    let mut seen_refs: HashSet<String> = HashSet::new();

    for cap in asset_regex.captures_iter(cmd) {
        let full_match = cap[0].to_string();
        let asset_path = cap[1].to_string();
        let is_glob = is_glob_pattern(&asset_path);

        if !seen_refs.contains(&asset_path) {
            seen_refs.insert(asset_path.clone());
            asset_refs.push(asset_path.clone());
        }

        replacements.push((full_match, asset_path, is_glob));
    }

    // Output-only assets that need temp files created (but not downloaded)
    let output_only_assets: HashSet<String> = output_assets
        .iter()
        .filter(|asset| !input_assets.contains(*asset) && !append_assets.contains(*asset))
        .cloned()
        .collect();

    // Use the new function to prepare all assets
    let (asset_map, expanded_globs) = prepare_assets_from_names_as_temp_files(
        asset_blob_cache,
        asset_keyring,
        api_client,
        &asset_refs,
        max_concurrent_downloads,
        Some(&output_only_assets),
    )
    .await?;

    // Build final replacements with actual paths
    let mut final_replacements: Vec<(String, String)> = Vec::new();

    for (full_match, asset_path, is_glob) in replacements {
        if is_glob {
            // Get the expanded assets for this glob
            if let Some(matched_assets) = expanded_globs.get(&asset_path) {
                let expanded_paths: Vec<String> = matched_assets
                    .iter()
                    .filter_map(|matched_asset| {
                        asset_map.get(matched_asset).and_then(|res| {
                            res.as_ref()
                                .ok()
                                .map(|tempfile| tempfile.path().to_string_lossy().to_string())
                        })
                    })
                    .collect();
                let replacement = expanded_paths.join(" ");
                final_replacements.push((full_match, replacement));
            }
        } else {
            // Regular asset
            if let Some(Ok(tempfile)) = asset_map.get(&asset_path) {
                final_replacements
                    .push((full_match, tempfile.path().to_string_lossy().to_string()));
            }
        }
    }

    // Perform replacements of @asset with temp files from longest first to
    // avoid collisions with assets whose names are subsets of one another.
    final_replacements.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
    let mut modified_cmd = cmd.to_string();
    for (pattern, replacement) in final_replacements {
        modified_cmd = modified_cmd.replace(&pattern, &replacement);
    }
    Ok((modified_cmd, asset_map, output_assets))
}

/// Create an empty temporary file for output assets
pub fn create_empty_temp_file(
    asset_name: &str,
    rev_id: Option<&str>,
    suffix: Option<&str>,
) -> Result<tempfile::NamedTempFile, DownloadAssetError> {
    // Extract the file stem (name without extension) from the asset path
    let path = Path::new(asset_name);
    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("asset");

    // Remove non-alphanumeric characters from file stem
    let clean_stem: String = file_stem.chars().filter(|c| c.is_alphanumeric()).collect();
    let clean_stem = if clean_stem.is_empty() {
        "asset"
    } else {
        &clean_stem
    };

    // Get the extension
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str().map(|s| format!(".{}", s)))
        .unwrap_or_default();

    // Build the prefix: asset_<filename>_
    let prefix = format!("asset_{}_", clean_stem);

    // Build the suffix: _<rev_id><extension>
    let mut full_suffix = String::new();
    if let Some(rev_id) = rev_id {
        full_suffix.push('_');
        full_suffix.push_str(rev_id);
    }
    full_suffix.push_str(&extension);
    if let Some(suffix) = suffix {
        full_suffix.push_str(suffix);
    }

    let temp_file = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(&full_suffix)
        .tempfile()
        .map_err(|e| {
            eprintln!("error: Failed to create temporary file: {}", e);
            DownloadAssetError::DataFetchFailed
        })?;

    Ok(temp_file)
}

// --

#[derive(Debug, Clone)]
pub struct AssetFetchResult {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

pub type AssetExtendedFetchMap = HashMap<String, Result<AssetFetchResult, GetAssetError>>;

/// Fetches assets and their metadata from a list of asset names/globs, keeping contents in memory.
///
/// This function:
/// 1. Expands any glob patterns in the input list
/// 2. Downloads all matching assets and their metadata in parallel
/// 3. Returns a map of asset names to their contents and metadata as Vec<u8>
///
/// # Arguments
/// * `api_client` - The API client for fetching assets
/// * `asset_names_or_globs` - A slice of asset names or glob patterns (without @ prefix)
/// * `max_concurrent_downloads` - Maximum number of concurrent downloads
/// * `download_metadata` - Whether to download asset metadata along with the data
///
/// # Returns
/// A tuple containing:
/// - A map of asset names to their data and optional metadata
/// - A map of glob patterns to their expanded asset names (for callers that need this info)
pub async fn fetch_assets_from_names_in_memory_extended(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
    download_metadata: bool,
) -> Result<(AssetExtendedFetchMap, HashMap<String, Vec<String>>), String> {
    // Track expanded globs for caller reference
    let mut expanded_globs: HashMap<String, Vec<String>> = HashMap::new();

    // Collect unique assets to process
    let mut seen_assets: HashSet<String> = HashSet::new();
    let mut assets_to_fetch: Vec<AssetEntry> = Vec::new();

    let mut asset_fetch_failures = Vec::new();

    for asset_ref in asset_names_or_globs {
        if is_glob_pattern(asset_ref) {
            // Skip if we've already expanded this glob
            if expanded_globs.contains_key(asset_ref) {
                continue;
            }

            // Expand the glob
            let matched_asset_entries = expand_glob(api_client, asset_ref).await?;

            // Queue each matched asset for download
            for matched_asset_entry in &matched_asset_entries {
                if !seen_assets.contains(&matched_asset_entry.name) {
                    seen_assets.insert(matched_asset_entry.name.clone());
                    assets_to_fetch.push(matched_asset_entry.clone());
                }
            }

            expanded_globs.insert(
                asset_ref.clone(),
                matched_asset_entries
                    .iter()
                    .map(|entry| entry.name.clone())
                    .collect::<Vec<_>>(),
            );
        } else {
            // Regular asset (non-glob)
            if !seen_assets.contains(asset_ref) {
                seen_assets.insert(asset_ref.clone());
                match get_asset_entry(api_client, asset_ref, false).await {
                    Ok(get_res) => assets_to_fetch.push(get_res.entry),
                    Err(e) => {
                        asset_fetch_failures.push((asset_ref.clone(), e));
                    }
                };
            }
        }
    }

    // Download assets and metadata in parallel
    let asset_map = download_assets_extended_parallel_in_memory(
        asset_blob_cache.clone(),
        &assets_to_fetch,
        max_concurrent_downloads,
        download_metadata,
    )
    .await?;

    let mut asset_final_map: AssetExtendedFetchMap = HashMap::new();
    for (asset_ref, download_res) in asset_map {
        asset_final_map.insert(
            asset_ref,
            download_res
                .map(|r| AssetFetchResult {
                    data: r.data,
                    metadata: r.metadata,
                })
                .map_err(|_e| GetAssetError::DataFetchFailed),
        );
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }

    Ok((asset_final_map, expanded_globs))
}

#[derive(Debug, Clone)]
pub struct AssetDownloadResult {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

pub type AssetExtendedDownloadMap =
    HashMap<String, Result<AssetDownloadResult, DownloadAssetError>>;

// Internal enum to track what kind of download completed
enum DownloadKind {
    Data(String),     // asset name
    Metadata(String), // asset name
}

async fn download_assets_extended_parallel_in_memory(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_entries: &[AssetEntry],
    max_concurrent_downloads: usize,
    download_metadata: bool,
) -> Result<AssetExtendedDownloadMap, String> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));

    let mut handles = Vec::new();

    for asset_entry in asset_entries {
        // Spawn data download
        if let Some(data_url) = asset_entry.asset.url.as_ref()
            && let Some(hash) = asset_entry.asset.hash.as_ref()
        {
            let sem_clone = Arc::clone(&semaphore);
            let name = asset_entry.name.clone();
            let data_url_clone = data_url.clone();
            let hash_clone = hash.clone();
            let cache_clone = asset_blob_cache.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                (
                    DownloadKind::Data(name),
                    cache_clone
                        .get_or_download(&data_url_clone, &hash_clone)
                        .await,
                )
            });
            handles.push(handle);
        }

        // Spawn metadata download if it exists
        if download_metadata
            && let Some(AssetMetadataInfo {
                url: Some(metadata_url),
                hash: Some(metadata_hash),
                ..
            }) = asset_entry.metadata.as_ref()
        {
            let sem_clone = Arc::clone(&semaphore);
            let name = asset_entry.name.clone();
            let metadata_url_clone = metadata_url.clone();
            let metadata_hash_clone = metadata_hash.clone();
            let cache_clone = asset_blob_cache.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                (
                    DownloadKind::Metadata(name),
                    cache_clone
                        .get_or_download(&metadata_url_clone, &metadata_hash_clone)
                        .await,
                )
            });
            handles.push(handle);
        }
    }

    let results = join_all(handles).await;

    // Intermediate storage: name -> (Option<data_result>, Option<metadata_result>)
    let mut intermediate: HashMap<
        String,
        (
            Option<Result<Vec<u8>, DownloadAssetError>>,
            Option<Result<Vec<u8>, DownloadAssetError>>,
        ),
    > = HashMap::new();

    // Initialize entries for all assets that have data URLs
    for asset_entry in asset_entries {
        if asset_entry.asset.url.is_some() && asset_entry.asset.hash.is_some() {
            intermediate.insert(asset_entry.name.clone(), (None, None));
        }
    }

    // Collect results
    for result in results {
        match result {
            Ok((kind, download_result)) => match kind {
                DownloadKind::Data(name) => {
                    if let Some(entry) = intermediate.get_mut(&name) {
                        entry.0 = Some(download_result);
                    }
                }
                DownloadKind::Metadata(name) => {
                    if let Some(entry) = intermediate.get_mut(&name) {
                        entry.1 = Some(download_result);
                    }
                }
            },
            Err(e) => {
                return Err(format!("Download task panicked: {}", e));
            }
        }
    }

    // Build final map
    let mut asset_map: AssetExtendedDownloadMap = HashMap::new();

    for (name, (data_opt, metadata_opt)) in intermediate {
        let result = match data_opt {
            Some(Ok(data)) => {
                // Data succeeded, check metadata
                match metadata_opt {
                    Some(Ok(metadata)) => Ok(AssetDownloadResult {
                        data,
                        metadata: Some(metadata),
                    }),
                    Some(Err(e)) => Err(e), // Metadata download failed
                    None => Ok(AssetDownloadResult {
                        data,
                        metadata: None, // No metadata for this asset
                    }),
                }
            }
            Some(Err(e)) => Err(e), // Data download failed
            None => {
                // This shouldn't happen if we initialized correctly
                continue;
            }
        };

        asset_map.insert(name, result);
    }

    Ok(asset_map)
}
