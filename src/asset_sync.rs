use futures::future::join_all;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::fs::create_dir_all;
use tokio::sync::{Mutex, Semaphore};

use crate::api::{
    self,
    client::HaiClient,
    types::asset::{
        AssetEntry, AssetEntryIterArg, AssetEntryIterError, AssetEntryIterNextArg, AssetEntryOp,
        AssetInfo, AssetMetadataInfo, AssetRevision,
    },
};
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader;
use crate::config;
use crate::crypt;
use crate::feature::{
    asset_crypt::{self, KeyRecipient},
    asset_keyring::AssetKeyring,
};

/// Current limitations:
/// - No cursor resumption
pub async fn sync_prefix(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    prefix: &str,
    target_path: &str,
    max_concurrent_downloads: Option<usize>,
    debug: bool,
) -> Result<(), ()> {
    //
    // Create target path if it doesn't exist.
    //
    let path = std::path::Path::new(target_path);
    if path.exists() {
        if !path.is_dir() {
            eprintln!(
                "error: target path '{}' exists but is not a directory",
                target_path
            );
            return Err(());
        }
    } else {
        // Path doesn't exist, create the directory
        match create_dir_all(path).await {
            Ok(_) => {
                if debug {
                    let _ =
                        config::write_to_debug_log(format!("Created directory: {}\n", target_path));
                }
            }
            Err(e) => {
                eprintln!("error: failed to create directory '{}': {}", target_path, e);
                return Err(());
            }
        }
    }

    // Determine the folder prefix for saved assets
    let folder_prefix = get_folder_prefix(prefix);

    //
    // Collect all entries
    //

    let mut entries: Vec<AssetEntry> = vec![];
    let mut asset_iter_res = match api_client
        .asset_entry_iter(AssetEntryIterArg {
            prefix: Some(prefix.into()),
            limit: 200,
        })
        .await
    {
        Ok(res) => res,
        Err(e) => {
            match e {
                api::client::RequestError::Route(AssetEntryIterError::Empty) => {
                    eprintln!("[empty]");
                }
                _ => {
                    eprintln!("error: {}", e);
                }
            }
            return Err(());
        }
    };
    loop {
        entries.extend_from_slice(&asset_iter_res.entries);
        if !asset_iter_res.has_more {
            break;
        }
        asset_iter_res = match api_client
            .asset_entry_iter_next(AssetEntryIterNextArg {
                cursor: asset_iter_res.cursor,
                limit: 200,
            })
            .await
        {
            Ok(res) => res,
            Err(e) => {
                eprintln!("error: {}", e);
                return Err(());
            }
        };
    }

    println!("Syncing {} entries...", entries.len());

    let _ = sync_entries(
        asset_blob_cache,
        asset_keyring,
        api_client,
        recipient,
        AssetSyncSource::AssetEntry(entries.clone()),
        Some((&folder_prefix, target_path)),
        max_concurrent_downloads,
        debug,
    )
    .await;
    Ok(())
}

/// When catching up to latest changes in the sync index, fast-forwarding lets
/// us discard all already-obsolete entries given that newer versions of them
/// are already present in the result set.
fn fast_forward_entries(entries: Vec<AssetEntry>) -> Vec<AssetEntry> {
    // Use a HashMap to track the last index for each name
    let mut last_indices = std::collections::HashMap::new();

    // Find the last index for each name
    for (index, entry) in entries.iter().enumerate() {
        last_indices.insert(entry.name.clone(), index);
    }

    // Build a new vector keeping only the entries at the last indices
    entries
        .into_iter()
        .enumerate()
        .filter(|(index, entry)| last_indices.get(&entry.name) == Some(index))
        .map(|(_, entry)| entry)
        .collect()
}

/// Extracts the folder prefix from a given prefix string.
///
/// Examples:
/// - "folderA/folderB/abc" -> "folderA/folderB/"
/// - "folderA/folderB/" -> "folderA/folderB/"
/// - "folderA/folderB" -> "folderA/"
/// - "/folderA/folderB/abc" -> "/folderA/folderB/"
fn get_folder_prefix(prefix: &str) -> String {
    // If the prefix already ends with a slash, it's already a folder prefix
    if prefix.ends_with('/') {
        return prefix.to_string();
    }

    // Find the last slash in the prefix
    match prefix.rfind('/') {
        Some(pos) => {
            // Include the slash in the result, but make sure we don't add an extra one
            let folder_prefix = &prefix[..=pos];
            folder_prefix.to_string()
        }
        None => {
            // No slash found, return empty string (root)
            String::new()
        }
    }
}

// --

/// Helper function to get file hash either from xattrs or calculating it.
///
/// Defaults to xattrs if present and the mtime matches since it doesn't
/// require expensive hashing. However, this makes it potentially unreliable.
async fn get_file_hash(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    let fs_metadata = std::fs::metadata(file_path)?;
    if let Ok(fs_modified_time) = fs_metadata.modified() {
        let mtime_ts = fs_modified_time
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let xattr_mtime_ts =
            if let Some(xattr_mtime_bytes) = xattr_get(file_path, "user.hai.hash_mtime") {
                if let Ok(xattr_mtime_str) = std::str::from_utf8(&xattr_mtime_bytes) {
                    xattr_mtime_str.parse::<u64>().ok()
                } else {
                    None
                }
            } else {
                None
            };
        if Some(mtime_ts) == xattr_mtime_ts {
            if let Some(xattr_hash_bytes) = xattr_get(file_path, "user.hai.hash")
                && let Ok(xattr_hash_hex_str) = std::str::from_utf8(&xattr_hash_bytes)
            {
                match hex::decode(xattr_hash_hex_str) {
                    Ok(binary_data) => {
                        // Validate that it's the correct length for SHA-256 (32 bytes)
                        if binary_data.len() == 32 {
                            return Ok(binary_data);
                        } else {
                            println!(
                                "Warning: Hash has unexpected length: {} bytes",
                                binary_data.len()
                            );
                        }
                    }
                    Err(e) => {
                        println!("Error decoding hex string: {}", e);
                    }
                }
            }
        }
    }
    calculate_file_hash(file_path).await
}

/// Helper function to calculate SHA-256 hash of a file
async fn calculate_file_hash(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    // Use tokio's spawn_blocking to run synchronous file I/O in a separate thread
    let path = file_path.to_string();
    let hash = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, std::io::Error> {
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();

        // Read the file in chunks to avoid loading it all into memory
        let mut buffer = [0; 1024 * 1024]; // 1MB buffer
        loop {
            let bytes_read = std::io::Read::read(&mut file, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(result.to_vec())
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))??;

    Ok(hash)
}

// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    // Check if the hex string has valid length
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string must have an even number of characters".to_string());
    }

    // Convert hex to bytes
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex character: {}", e))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

// --

#[cfg(not(target_os = "windows"))]
fn xattr_get(file_path: &str, key: &str) -> Option<Vec<u8>> {
    xattr::get(file_path, format!("user.hai.{}", key)).unwrap_or_default()
}

/// On windows, we mimic xattrs using NTFS's ADS feature. The handling differs
/// because we can't read a key-at-a-time so instead we read the entire blob.
#[cfg(target_os = "windows")]
fn xattr_get(file_path: &str, key: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let ads_path = format!("{}:hai", file_path);

    // Try to open the ADS
    let mut file = std::fs::File::open(&ads_path).ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;

    let json: serde_json::Value = serde_json::from_str(&contents).ok()?;

    match json.get(key) {
        Some(val) => {
            // Only support string values
            if let Some(s) = val.as_str() {
                Some(s.as_bytes().to_vec())
            } else {
                None
            }
        }
        None => None,
    }
}

// --

#[cfg(not(target_os = "windows"))]
fn xattr_set(file_path: &str, key: &str, value: &str) -> Result<(), ()> {
    xattr::set(file_path, format!("user.hai.{}", key), value.as_bytes()).map_err(|_| ())
}

#[cfg(target_os = "windows")]
fn xattr_set(file_path: &str, key: &str, value: &str) -> Result<(), ()> {
    use serde_json::{Map, Value};
    use std::io::{Read, Seek, SeekFrom, Write};

    let ads_path = format!("{}:hai", file_path);

    // Try to open the ADS for reading and writing, create if it doesn't exist
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&ads_path)
        .map_err(|_| ())?;

    // Read the existing JSON, or start with an empty object
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok();
    let mut json: Map<String, Value> = if contents.trim().is_empty() {
        Map::new()
    } else {
        serde_json::from_str(&contents).unwrap_or_else(|_| Map::new())
    };

    json.insert(key.to_string(), Value::String(value.to_string()));
    let new_contents = serde_json::to_string(&json).map_err(|_| ())?;

    // Truncate and write the new JSON
    file.set_len(0).map_err(|_| ())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    file.write_all(new_contents.as_bytes()).map_err(|_| ())?;

    Ok(())
}

// --

struct AssetEntryDownloadTask {
    source: AssetSourceMinimal,
    final_path: Option<String>,
}

pub enum AssetSyncSource {
    AssetEntry(Vec<AssetEntry>),
    AssetRevision((String, Vec<AssetRevision>)), // (asset_name, revisions)
}

pub struct AssetSourceMinimal {
    pub asset: AssetInfo,
    pub asset_name: String,
    pub op: AssetEntryOp,
    pub metadata: Option<AssetMetadataInfo>,
    pub iter_info: Option<(String, i64)>, // (entry_id, seq_id)
}

/// Syncs sources (asset-entries or revisions) to local system.
///
/// It's a bit bloated because it's designed to handle syncing down revisions
/// of a single asset as well as syncing down all changes to a folder.
///
/// Features:
/// - Uses asset blob cache to avoid re-downloading blobs
/// - If `persist` set, checks if destination already up-to-date. If so, does
///   not re-download.
/// - If `persist` set, supports deletion operations.
/// - Downloads in parallel.
///
/// # Returns
///
/// Only returns temp files if `persist` is None. When temp files go out of
/// scope, they will be automatically removed.
pub async fn sync_entries(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    sync_source: AssetSyncSource,
    persist: Option<(&str, &str)>, // (folder_prefix, target_path)
    max_concurrent_downloads: Option<usize>,
    debug: bool,
) -> Result<
    Vec<(
        AssetSourceMinimal,
        Option<tempfile::NamedTempFile>,
        Option<tempfile::NamedTempFile>,
    )>,
    (),
> {
    let max_concurrent_downloads = max_concurrent_downloads.unwrap_or(10);
    let sources = match sync_source {
        AssetSyncSource::AssetEntry(entries) => {
            let ff_entries = fast_forward_entries(entries);
            ff_entries
                .into_iter()
                .map(|entry| AssetSourceMinimal {
                    asset: entry.asset,
                    asset_name: entry.name,
                    op: entry.op,
                    metadata: entry.metadata,
                    iter_info: Some((entry.entry_id, entry.seq_id)),
                })
                .collect::<Vec<AssetSourceMinimal>>()
        }
        AssetSyncSource::AssetRevision((asset_name, revisions)) => revisions
            .into_iter()
            .map(|rev| AssetSourceMinimal {
                asset: rev.asset,
                asset_name: asset_name.clone(),
                op: rev.op,
                metadata: rev.metadata,
                iter_info: None,
            })
            .collect::<Vec<AssetSourceMinimal>>(),
    };

    let mut entries_to_delete = vec![];
    let mut entries_with_dl_tasks = vec![];

    for source in sources {
        if matches!(source.op, AssetEntryOp::Delete) {
            entries_to_delete.push(source);
            continue;
        }

        let final_path = if let Some((folder_prefix, target_path)) = persist {
            // Trim the folder prefix from the entry name
            let relative_path = match source.asset_name.strip_prefix(folder_prefix) {
                Some(path) => path,
                None => &source.asset_name, // If for some reason it doesn't have the prefix
            };

            // Construct the full target path for the data asset
            Some(format!("{}/{}", target_path, relative_path))
        } else {
            None
        };

        entries_with_dl_tasks.push(AssetEntryDownloadTask { source, final_path });
    }

    // Create a semaphore with max_concurrent_downloads
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));
    let mut handles = Vec::new();

    for dl_task in entries_with_dl_tasks {
        let asset_blob_cache_clone = asset_blob_cache.clone();
        let asset_keyring_clone = asset_keyring.clone();
        let api_client_clone = api_client.clone();
        let recipient_clone = recipient.clone();
        let sem_clone = Arc::clone(&semaphore);

        // Create a future that acquires a semaphore before downloading to
        // cap the number of simultaneous downloads.
        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();

            let asset_blob_cache = asset_blob_cache_clone.clone();
            let asset_keyring = asset_keyring_clone;
            let api_client = api_client_clone;
            let recipient = recipient_clone;

            let source = dl_task.source;
            let final_path = dl_task.final_path;
            let metadata_final_path = final_path.as_ref().map(|p| format!("{}.metadata", p));

            if matches!(source.op, AssetEntryOp::Delete)
                && let Some(asset_final_path) = final_path.as_deref()
            {
                // Handle deletion when persisting
                if debug {
                    let _ = config::write_to_debug_log(format!("Deleting: {}\n", asset_final_path));
                }
                let _ = tokio::fs::remove_file(asset_final_path).await;
                if let Some(metadata_final_path) = metadata_final_path.as_deref() {
                    if debug {
                        let _ = config::write_to_debug_log(format!(
                            "Deleting: {}\n",
                            metadata_final_path
                        ));
                    }
                    let _ = tokio::fs::remove_file(metadata_final_path).await;
                }
                return Ok((source, None, None));
            }

            let metadata_already_uptodate = if let Some(metadata_final_path) = &metadata_final_path
                && let Some(metadata) = source.metadata.as_ref()
                && let Some(metadata_hash) = metadata.hash.as_deref()
            {
                match get_file_hash(metadata_final_path).await {
                    Ok(existing_hash) => {
                        if let Ok(expected_hash) = hex_to_bytes(metadata_hash)
                            && existing_hash == expected_hash
                        {
                            if debug {
                                let _ = config::write_to_debug_log(format!(
                                    "sync: metadata for {} already up to date at '{}'\n",
                                    source.asset_name, metadata_final_path
                                ));
                            }
                            true
                        } else {
                            false
                        }
                    }
                    Err(_) => {
                        // Ignore error and proceed with recreating it
                        false
                    }
                }
            } else {
                false
            };
            let metadata_existing_contents = if metadata_already_uptodate {
                Some(
                    tokio::fs::read(metadata_final_path.as_ref().unwrap())
                        .await
                        .expect("failed to read existing metadata file"),
                )
            } else {
                None
            };

            let (metadata_contents_temp_file, metadata_contents) =
                if let Some(metadata_existing_contents) = metadata_existing_contents {
                    (None, Some(metadata_existing_contents))
                } else if let Some(metadata) = source.metadata.as_ref()
                    && let Some(metadata_url) = metadata.url.as_deref()
                    && let Some(metadata_hash) = metadata.hash.as_deref()
                {
                    let metadata_contents_temp_file = asset_reader::create_empty_temp_file(
                        &source.asset_name,
                        Some(&metadata.rev_id),
                        Some(".metadata"),
                    )
                    .expect("failed to create temp data file");
                    let metadata_contents_temp_file = match asset_blob_cache
                        .get_or_download_to_tempfile(
                            &metadata_url,
                            metadata_hash,
                            metadata_contents_temp_file,
                        )
                        .await
                    {
                        Ok(temp_file) => temp_file,
                        Err(e) => {
                            eprintln!(
                                "error: failed to download metadata for '{}': {}",
                                source.asset_name, e
                            );
                            return Err(e);
                        }
                    };
                    let metadata_contents_temp_path =
                        metadata_contents_temp_file.path().to_path_buf();
                    match tokio::fs::read(&metadata_contents_temp_path).await {
                        Ok(metadata_contents) => {
                            (Some(metadata_contents_temp_file), Some(metadata_contents))
                        }
                        Err(e) => {
                            eprintln!(
                                "error: failed to read metadata temp file for '{}': {}",
                                source.asset_name, e
                            );
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                };

            let asset_already_uptodate = if let Some(final_path) = &final_path
                && let Some(asset_hash) = source.asset.hash.as_deref()
            {
                match get_file_hash(final_path).await {
                    Ok(existing_hash) => {
                        if let Ok(expected_hash) = hex_to_bytes(asset_hash)
                            && existing_hash == expected_hash
                        {
                            let _ = config::write_to_debug_log(format!(
                                "sync: asset data for {} already up to date at '{}'\n",
                                source.asset_name, final_path
                            ));
                            true
                        } else {
                            false
                        }
                    }
                    Err(_) => {
                        // Ignore error and proceed with recreating it
                        false
                    }
                }
            } else {
                false
            };

            let data_contents_temp_file = if asset_already_uptodate {
                None
            } else if let Some(data_url) = source.asset.url.as_deref()
                && let Some(data_hash) = source.asset.hash.as_deref()
            {
                let data_contents_temp_file = asset_reader::create_empty_temp_file(
                    &source.asset_name,
                    Some(&source.asset.rev_id),
                    None,
                )
                .expect("failed to create temp data file");
                let data_contents_temp_file = match asset_blob_cache
                    .get_or_download_to_tempfile(&data_url, data_hash, data_contents_temp_file)
                    .await
                {
                    Ok(temp_file) => temp_file,
                    Err(e) => {
                        eprintln!("error: failed to download '{}': {}", source.asset_name, e);
                        return Err(e);
                    }
                };
                Some(data_contents_temp_file)
            } else {
                None
            };

            let (decrypted_data_contents_temp_file, decrypted_hash) =
                if let Some(data_contents_temp_file) = data_contents_temp_file.as_ref()
                    && let Some(metadata_contents) = metadata_contents.as_deref()
                    && let Some(rec_key_info) = asset_crypt::parse_metadata_for_encryption_info(
                        &metadata_contents,
                        recipient.as_ref(),
                    )
                {
                    let in_path = data_contents_temp_file.path();
                    let decrypted_asset_contents_temp_file =
                        asset_reader::create_empty_temp_file(&source.asset_name, None, None)
                            .expect("failed to create temp data file");
                    let decrypted_asset_contents_temp_path =
                        decrypted_asset_contents_temp_file.path();

                    match asset_crypt::get_symmetric_key_ez(
                        asset_blob_cache,
                        asset_keyring,
                        &api_client,
                        &rec_key_info,
                    )
                    .await
                    {
                        Ok(sym_info) => {
                            crypt::decrypt_file(
                                in_path,
                                decrypted_asset_contents_temp_path,
                                &sym_info.aes_key,
                            )
                            .unwrap();
                            let decrypted_hash = calculate_file_hash(
                                &decrypted_asset_contents_temp_path.to_string_lossy(),
                            )
                            .await
                            .ok();
                            (Some(decrypted_asset_contents_temp_file), decrypted_hash)
                        }
                        Err(_) => {
                            let _ = config::write_to_debug_log(format!(
                                "sync: failed to get decryption key for {}\n",
                                source.asset_name
                            ));
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                };

            let data_contents_temp_file =
                if let Some(decrypted_file) = decrypted_data_contents_temp_file {
                    Some(decrypted_file)
                } else {
                    data_contents_temp_file
                };

            if data_contents_temp_file.is_some() {
                let data_contents_path = data_contents_temp_file
                    .as_ref()
                    .unwrap()
                    .path()
                    .to_str()
                    .unwrap();
                asset_file_set_xattrs(&data_contents_path, &source);
                asset_data_file_set_xattrs(&data_contents_path, &source, decrypted_hash.as_deref());
            }

            if metadata_contents_temp_file.is_some() {
                let metadata_contents_path = metadata_contents_temp_file
                    .as_ref()
                    .unwrap()
                    .path()
                    .to_str()
                    .unwrap();
                asset_file_set_xattrs(&metadata_contents_path, &source);
                asset_metadata_file_set_xattrs(&metadata_contents_path, &source);
            }

            let data_contents_temp_file = if let Some(asset_final_path) = final_path.clone()
                && let Some(data_contents_temp_file) = data_contents_temp_file
            {
                let target_data_file = std::path::Path::new(&asset_final_path);
                if let Some(parent) = target_data_file.parent()
                    && !parent.exists()
                {
                    match std::fs::create_dir_all(parent) {
                        Ok(_) => {}
                        Err(_) => {
                            // Try to continue
                        }
                    }
                }
                data_contents_temp_file
                    .persist(&asset_final_path)
                    .expect("failed to persist data file");
                None
            } else {
                data_contents_temp_file
            };

            let metadata_contents_temp_file = if let Some(metadata_final_path) = metadata_final_path
                && let Some(metadata_contents_temp_file) = metadata_contents_temp_file
            {
                let target_metadata_file = std::path::Path::new(&metadata_final_path);
                if let Some(parent) = target_metadata_file.parent()
                    && !parent.exists()
                {
                    match std::fs::create_dir_all(parent) {
                        Ok(_) => {}
                        Err(_) => {
                            // Try to continue
                        }
                    }
                }
                metadata_contents_temp_file
                    .persist(&metadata_final_path)
                    .expect("failed to persist metadata file");
                None
            } else {
                metadata_contents_temp_file
            };

            Ok((source, data_contents_temp_file, metadata_contents_temp_file))
        });

        handles.push(handle);
    }

    // Wait for all downloads to complete
    let mut result = vec![];
    for handle in join_all(handles).await {
        // Unwrap the JoinHandle result to get the inner result
        if let Ok(handle_result) = handle {
            if let Ok((source, data_temp_file_opt, metadata_temp_file_opt)) = handle_result {
                result.push((source, data_temp_file_opt, metadata_temp_file_opt));
            }
        } else {
            // Handle the case where the task panicked
            eprintln!("A download task panicked");
        }
    }

    Ok(result)
}

/// Sets universal xattrs for an asset file.
///
/// All assets files (data or metadata) get:
/// - user.hai.entry_id
/// - user.hai.seq_id
fn asset_file_set_xattrs(path: &str, source: &AssetSourceMinimal) {
    if let Some((entry_id, seq_id)) = source.iter_info.as_ref() {
        if xattr_set(&path, "user.hai.entry_id", &entry_id).is_err() {
            eprintln!("failed to set entry_id xattr");
        }
        if xattr_set(&path, "user.hai.seq_id", &seq_id.to_string()).is_err() {
            eprintln!("failed to set seq_id xattr");
        }
    }
}

/// Sets xattrs for asset data files (not metadata).
///
/// All data asset files get:
/// - user.hai.rev_id
/// - user.hai.hash_mtime (local file mtime when hash attached)
/// - user.hai.hash
/// - user.hai.decrypted
///   - set to "true" if content was decrypted based on metadata.encrypted
/// - user.hai.content_type
fn asset_data_file_set_xattrs(
    path: &str,
    source: &AssetSourceMinimal,
    decrypted_hash: Option<&[u8]>,
) {
    if xattr_set(&path, "user.hai.rev_id", &source.asset.rev_id).is_err() {
        eprintln!("failed to set rev_id xattr");
    }
    if let Some(hash) = source.asset.hash.as_ref() {
        //
        // Write the file hash and the mtime of the file into
        // xattrs to make change detection easier.
        //
        let metadata = std::fs::metadata(&path).expect("failed to read file metadata");
        if let Ok(modified_time) = metadata.modified() {
            let mtime_ts = modified_time
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            if xattr_set(&path, "user.hai.hash_mtime", &mtime_ts.to_string()).is_err() {
                eprintln!("failed to set hash_mtime xattr");
            }
        }

        if xattr_set(&path, "user.hai.hash", hash).is_err() {
            eprintln!("failed to set hash xattr");
        }

        if let Some(decrypted_hash) = decrypted_hash {
            let decrypted_hash_hex = hex::encode(decrypted_hash);
            if xattr_set(&path, "user.hai.decrypted_hash", &decrypted_hash_hex).is_err() {
                eprintln!("failed to set decrypted_hash xattr");
            }
        }
    }
    if let Some(AssetMetadataInfo {
        content_encrypted,
        content_type,
        ..
    }) = source.metadata.as_ref()
    {
        if let Some(_content_encrypted) = content_encrypted {
            if xattr_set(&path, "user.hai.decrypted", "true").is_err() {
                eprintln!("failed to set decrypted xattr");
            }
        }
        if let Some(content_type) = content_type {
            if xattr_set(&path, "user.hai.content_type", content_type).is_err() {
                eprintln!("failed to set content_type xattr");
            }
        }
    }
}

/// Sets xattrs for asset metadata files.
///
/// All metadata asset files get:
/// - user.hai.is_metadata
/// - user.hai.rev_id
/// - user.hai.hash_mtime (local file mtime when hash attached)
/// - user.hai.hash
fn asset_metadata_file_set_xattrs(path: &str, source: &AssetSourceMinimal) {
    if let Some(AssetMetadataInfo {
        rev_id,
        hash: Some(hash),
        ..
    }) = source.metadata.as_ref()
    {
        if xattr_set(&path, "user.hai.is_metadata", "true").is_err() {
            eprintln!("failed to set is_metadata xattr");
        }
        if xattr_set(&path, "user.hai.rev_id", &rev_id).is_err() {
            eprintln!("failed to set rev_id xattr");
        }
        //
        // Write the file hash and the mtime of the file into
        // xattrs to make change detection easier.
        //
        let metadata = std::fs::metadata(&path).expect("failed to read file metadata");
        if let Ok(modified_time) = metadata.modified() {
            let mtime_ts = modified_time
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            if xattr_set(&path, "user.hai.hash_mtime", &mtime_ts.to_string()).is_err() {
                eprintln!("failed to set hash_mtime xattr");
            }
        }

        if xattr_set(&path, "user.hai.hash", &hash).is_err() {
            eprintln!("failed to set hash xattr");
        }
    }
}
