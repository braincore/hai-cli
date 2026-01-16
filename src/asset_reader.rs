use futures::future::join_all;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset::{
    AssetEntry, AssetGetArg, AssetGetError, AssetGetResult, AssetMetadataInfo,
};
use crate::asset_cache::{AssetBlobCache, DownloadAssetError};
use glob::Pattern;

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

pub type AssetTempFileMap =
    HashMap<String, Result<(tempfile::NamedTempFile, PathBuf), GetAssetError>>;
pub type AssetTempFileDownloadMap =
    HashMap<String, Result<(tempfile::NamedTempFile, PathBuf), DownloadAssetError>>;

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
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
    skip_download: Option<&HashSet<String>>,
) -> Result<(AssetTempFileMap, HashMap<String, Vec<String>>), String> {
    let empty_set = HashSet::new();
    let skip_download = skip_download.unwrap_or(&empty_set);

    // Track expanded globs for caller reference
    let mut expanded_globs: HashMap<String, Vec<String>> = HashMap::new();

    // Collect unique assets to process
    let mut seen_assets: HashSet<String> = HashSet::new();
    let mut assets_to_process: Vec<(AssetEntry, bool)> = Vec::new(); // (asset_name, needs_download)
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
                    let needs_download = !skip_download.contains(&matched_asset_entry.name);
                    assets_to_process.push((matched_asset_entry.clone(), needs_download));
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
                let needs_download = !skip_download.contains(asset_ref);
                //assets_to_process.push((asset_ref.clone(), needs_download));
                match get_asset_entry(api_client, asset_ref, false).await {
                    Ok(get_res) => assets_to_process.push((get_res.entry, needs_download)),
                    Err(e) => {
                        asset_fetch_failures.push((asset_ref.clone(), e));
                    }
                };
            }
        }
    }

    // Download/create files in parallel
    let asset_map = download_assets_parallel(assets_to_process, max_concurrent_downloads).await?;
    let mut asset_final_map = HashMap::new();
    for (asset_ref, download_res) in asset_map {
        asset_final_map.insert(
            asset_ref,
            download_res.map_err(|_e| GetAssetError::DataFetchFailed),
        );
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }
    Ok((asset_final_map, expanded_globs))
}

/// Downloads or creates temp files for a list of assets in parallel.
async fn download_assets_parallel(
    assets_to_process: Vec<(AssetEntry, bool)>, // (asset_name, needs_download)
    max_concurrent_downloads: usize,
) -> Result<AssetTempFileDownloadMap, String> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));

    let mut handles = Vec::new();

    for (asset_entry, needs_download) in assets_to_process {
        let sem_clone = Arc::clone(&semaphore);

        if let Some(data_url) = asset_entry.asset.url.as_ref() {
            let asset_entry_name = asset_entry.name.clone();
            let data_url_clone = data_url.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                let result = if needs_download {
                    download_asset_to_temp(&asset_entry_name, &data_url_clone).await
                } else {
                    create_empty_temp_file(&asset_entry.name, None)
                };

                (asset_entry.name, result)
            });

            handles.push(handle);
        }
    }

    // Wait for all downloads to complete
    let results = join_all(handles).await;

    // Process results and build asset_map
    let mut asset_map: AssetTempFileDownloadMap = HashMap::new();

    for result in results {
        match result {
            Ok((key, value)) => {
                asset_map.insert(key, value);
            }
            Err(e) => {
                return Err(format!("Download task panicked: {}", e));
            }
        }
    }

    Ok(asset_map)
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

    // Determine which assets should skip download (output-only assets with >)
    let skip_download: HashSet<String> = output_assets
        .iter()
        .filter(|asset| !append_assets.contains(*asset))
        .cloned()
        .collect();

    // Use the new function to prepare all assets
    let (asset_map, expanded_globs) = prepare_assets_from_names_as_temp_files(
        api_client,
        &asset_refs,
        max_concurrent_downloads,
        Some(&skip_download),
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
                                .map(|(_, path)| path.to_string_lossy().to_string())
                        })
                    })
                    .collect();
                let replacement = expanded_paths.join(" ");
                final_replacements.push((full_match, replacement));
            }
        } else {
            // Regular asset
            if let Some(Ok((_, path))) = asset_map.get(&asset_path) {
                final_replacements.push((full_match, path.to_string_lossy().to_string()));
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

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

/// Download an asset to a temporary file
///
/// NOTE: The NamedTempFile is returned. When it eventually goes out of scope,
/// the temporary file will be removed.
async fn download_asset_to_temp(
    asset_name: &str,
    url: &str,
) -> Result<(tempfile::NamedTempFile, PathBuf), DownloadAssetError> {
    let (temp_file, temp_file_path) = create_empty_temp_file(asset_name, None)?;

    let asset_get_resp = match reqwest::get(url).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("error: {}", e);
            return Err(DownloadAssetError::DataFetchFailed);
        }
    };

    if !asset_get_resp.status().is_success() {
        eprintln!("error: failed to fetch asset: {}", asset_get_resp.status());
        return Err(DownloadAssetError::DataFetchFailed);
    }

    // Stream write to file
    let mut file = tokio::fs::File::from_std(temp_file.reopen().map_err(|e| {
        eprintln!("error: failed to reopen temp file: {}", e);
        DownloadAssetError::DataFetchFailed
    })?);

    let mut stream = asset_get_resp.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            eprintln!("error: failed to read chunk: {}", e);
            DownloadAssetError::DataFetchFailed
        })?;
        file.write_all(&chunk).await.map_err(|e| {
            eprintln!("error: failed to write chunk: {}", e);
            DownloadAssetError::DataFetchFailed
        })?;
    }

    file.flush().await.map_err(|e| {
        eprintln!("error: failed to flush file: {}", e);
        DownloadAssetError::DataFetchFailed
    })?;

    Ok((temp_file, temp_file_path))
}

/// Create an empty temporary file for output assets
pub fn create_empty_temp_file(
    asset_name: &str,
    rev_id: Option<&str>,
) -> Result<(tempfile::NamedTempFile, PathBuf), DownloadAssetError> {
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
    let mut suffix = String::new();
    if let Some(rev_id) = rev_id {
        suffix.push('_');
        suffix.push_str(rev_id);
    }
    suffix.push_str(&extension);

    let temp_file = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(&suffix)
        .tempfile()
        .map_err(|e| {
            eprintln!("error: Failed to create temporary file: {}", e);
            DownloadAssetError::DataFetchFailed
        })?;

    // Get the path to the temporary file
    let temp_file_path = temp_file.path().to_path_buf();

    Ok((temp_file, temp_file_path))
}
pub type AssetFetchMap = HashMap<String, Result<Vec<u8>, GetAssetError>>;
pub type AssetDownloadMap = HashMap<String, Result<Vec<u8>, DownloadAssetError>>;

/// Fetches assets from a list of asset names/globs, keeping contents in memory.
///
/// This function:
/// 1. Expands any glob patterns in the input list
/// 2. Downloads all matching assets in parallel
/// 3. Returns a map of asset names to their contents as Vec<u8>
///
/// # Arguments
/// * `api_client` - The API client for fetching assets
/// * `asset_names_or_globs` - A slice of asset names or glob patterns (without @ prefix)
/// * `max_concurrent_downloads` - Maximum number of concurrent downloads
/// * `skip_download` - Optional set of asset names to create as empty Vec<u8> instead of downloading
///
/// # Returns
/// A tuple containing:
/// - A map of asset names to their contents as Vec<u8>
/// - A map of glob patterns to their expanded asset names (for callers that need this info)
pub async fn fetch_assets_from_names_in_memory(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
) -> Result<(AssetFetchMap, HashMap<String, Vec<String>>), String> {
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

    // Download assets in parallel
    let asset_map = download_assets_parallel_in_memory(
        asset_blob_cache.clone(),
        &assets_to_fetch,
        max_concurrent_downloads,
    )
    .await?;
    let mut asset_final_map = HashMap::new();
    for (asset_ref, download_res) in asset_map {
        asset_final_map.insert(
            asset_ref,
            download_res.map_err(|_e| GetAssetError::DataFetchFailed),
        );
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }

    Ok((asset_final_map, expanded_globs))
}

/// Downloads assets in parallel, keeping contents in memory.
async fn download_assets_parallel_in_memory(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_entries: &[AssetEntry],
    max_concurrent_downloads: usize,
) -> Result<AssetDownloadMap, String> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));

    let mut handles = Vec::new();

    for asset_entry in asset_entries {
        let sem_clone = Arc::clone(&semaphore);

        if let Some(data_url) = asset_entry.asset.url.as_ref()
            && let Some(hash) = asset_entry.asset.hash.as_ref()
        {
            let asset_entry_clone = asset_entry.clone();
            let data_url_clone = data_url.clone();
            let hash_clone = hash.clone();
            let asset_blob_cache_clone = asset_blob_cache.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                (
                    asset_entry_clone.name,
                    asset_blob_cache_clone
                        .get_or_download(&data_url_clone, &hash_clone)
                        .await,
                )
            });

            handles.push(handle);
        }
    }

    // Wait for all downloads to complete
    let results = join_all(handles).await;

    // Process results and build asset_map
    let mut asset_map: AssetDownloadMap = HashMap::new();

    for result in results {
        match result {
            Ok((key, value)) => {
                asset_map.insert(key, value);
            }
            Err(e) => {
                return Err(format!("Download task panicked: {}", e));
            }
        }
    }

    Ok(asset_map)
}
