use futures::future::join_all;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs::{File, create_dir_all};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore};

use crate::api::{
    self,
    client::HaiClient,
    types::asset::{
        AssetCreatedBy, AssetEntry, AssetEntryIterArg, AssetEntryIterError, AssetEntryIterNextArg,
        AssetEntryOp, AssetMetadataInfo, AssetRevision,
    },
};
use crate::config;

struct DownloadTask {
    entry_name: String,
    url: String,
    task_type: DownloadTaskType,
}

enum DownloadTaskType {
    Data,
    Metadata,
}

/// Current limitations:
/// - No cursor resumption
/// - Does not sync asset metadata
pub async fn sync_prefix(
    api_client: &HaiClient,
    prefix: &str,
    target_path: &str,
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

    sync_entries(entries.clone(), &folder_prefix, target_path, debug).await
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

async fn sync_entries(
    entries: Vec<AssetEntry>,
    folder_prefix: &str,
    target_path: &str,
    debug: bool,
) -> Result<(), ()> {
    let ff_entries = fast_forward_entries(entries);

    // Prepare download tasks
    let mut entry_with_tasks = vec![];

    for entry in ff_entries {
        // Trim the folder prefix from the entry name
        let relative_path = match entry.name.strip_prefix(folder_prefix) {
            Some(path) => path,
            None => &entry.name, // If for some reason it doesn't have the prefix
        };

        // Construct the full target path for the data asset
        let target_data_file_path = format!("{}/{}", target_path, relative_path);

        if matches!(entry.op, AssetEntryOp::Delete) {
            entry_with_tasks.push((entry, target_data_file_path, None));
            continue;
        }

        let expected_data_hash = entry.asset.hash.clone().unwrap_or("".to_string());

        // Check if file already exists and has the correct hash
        let target_data_file = std::path::Path::new(&target_data_file_path);
        let download_data = if target_data_file.exists() && !expected_data_hash.is_empty() {
            match get_file_hash(&target_data_file_path).await {
                Ok(data_file_hash) => {
                    // Convert the expected hash from hex to bytes
                    match hex_to_bytes(&expected_data_hash) {
                        Ok(decoded_data_hash) => {
                            if data_file_hash == decoded_data_hash {
                                if debug {
                                    let _ = config::write_to_debug_log(format!(
                                        "Skipping (hash match): {}\n",
                                        target_data_file_path
                                    ));
                                }
                                false
                            } else {
                                if debug {
                                    let _ = config::write_to_debug_log(format!(
                                        "Hash mismatch, re-downloading: {}\n",
                                        target_data_file_path
                                    ));
                                }
                                true
                            }
                        }
                        Err(e) => {
                            if debug {
                                let _ = config::write_to_debug_log(format!(
                                    "warning: failed to decode hash for '{}': {}\n",
                                    entry.name, e
                                ));
                            }
                            true
                        }
                    }
                }
                Err(e) => {
                    if debug {
                        let _ = config::write_to_debug_log(format!(
                            "warning: failed to calculate hash for existing file '{}': {}\n",
                            entry.name, e
                        ));
                    }
                    true
                }
            }
        } else {
            true
        };

        let target_metadata_file_path = format!("{}/{}.metadata", target_path, relative_path);
        let target_metadata_file = std::path::Path::new(&target_metadata_file_path);

        let expected_metadata_hash = entry
            .metadata
            .as_ref()
            .and_then(|md| md.hash.clone())
            .unwrap_or("".to_string());

        let download_metadata =
            if target_metadata_file.exists() && !expected_metadata_hash.is_empty() {
                match get_file_hash(&target_metadata_file_path).await {
                    Ok(metadata_file_hash) => {
                        // Convert the expected hash from hex to bytes
                        match hex_to_bytes(&expected_metadata_hash) {
                            Ok(decoded_metadata_hash) => {
                                if metadata_file_hash == decoded_metadata_hash {
                                    if debug {
                                        let _ = config::write_to_debug_log(format!(
                                            "Skipping (hash match): {}\n",
                                            target_metadata_file_path
                                        ));
                                    }
                                    false
                                } else {
                                    if debug {
                                        let _ = config::write_to_debug_log(format!(
                                            "Hash mismatch, re-downloading: {}\n",
                                            target_metadata_file_path
                                        ));
                                    }
                                    true
                                }
                            }
                            Err(e) => {
                                if debug {
                                    let _ = config::write_to_debug_log(format!(
                                        "warning: failed to decode hash for '{}' metadata: {}\n",
                                        entry.name, e
                                    ));
                                }
                                true
                            }
                        }
                    }
                    Err(e) => {
                        if debug {
                            let _ = config::write_to_debug_log(format!(
                                "warning: failed to calculate hash for existing file '{}': {}\n",
                                entry.name, e
                            ));
                        }
                        true
                    }
                }
            } else {
                true
            };

        if !download_data && !download_metadata {
            // Skip this entry if no download is needed
            if debug {
                let _ = config::write_to_debug_log(format!(
                    "Skipping (no download needed): {}\n",
                    target_data_file_path
                ));
            }
            continue;
        }

        // Ensure the parent directory exists
        let target_data_file = std::path::Path::new(&target_data_file_path);
        if let Some(parent) = target_data_file.parent()
            && !parent.exists()
        {
            match std::fs::create_dir_all(parent) {
                Ok(_) => {
                    if debug {
                        let _ = config::write_to_debug_log(format!(
                            "Created directory: {}\n",
                            parent.display()
                        ));
                    }
                }
                Err(e) => {
                    eprintln!(
                        "error: failed to create directory '{}': {}",
                        parent.display(),
                        e
                    );
                    continue; // Skip this file but continue with others
                }
            }
        }

        if download_data && let Some(data_url) = entry.asset.url.as_ref() {
            let data_download_task = Some(DownloadTask {
                entry_name: entry.name.clone(),
                url: data_url.clone(),
                task_type: DownloadTaskType::Data,
            });
            entry_with_tasks.push((entry.clone(), target_data_file_path, data_download_task));
        }
        if download_metadata
            && let Some(metadata_info) = entry.metadata.as_ref()
            && let Some(metadata_url) = metadata_info.url.as_ref()
        {
            let metadata_download_task = Some(DownloadTask {
                entry_name: entry.name.clone(),
                url: metadata_url.clone(),
                task_type: DownloadTaskType::Metadata,
            });
            entry_with_tasks.push((entry, target_metadata_file_path, metadata_download_task));
        }
    }

    let max_concurrent_downloads = 10;

    println!(
        "Starting {} downloads with max {} concurrent...",
        entry_with_tasks.len(),
        max_concurrent_downloads
    );
    if debug {
        let _ = config::write_to_debug_log(format!(
            "Starting {} downloads with max {} concurrent...\n",
            entry_with_tasks.len(),
            max_concurrent_downloads
        ));
    }

    // Create a semaphore with max_concurrent_downloads
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));
    let mut handles = Vec::new();

    for (entry, target_path, task) in entry_with_tasks {
        if let Some(task) = task {
            let entry_clone = entry.clone();
            let entry_name = task.entry_name.clone();
            let url = task.url.clone();
            let target_path_clone = target_path.clone();
            let sem_clone = Arc::clone(&semaphore);
            let type_str = match task.task_type {
                DownloadTaskType::Data => "data",
                DownloadTaskType::Metadata => "metadata",
            };

            // Create a future that acquires a semaphore before downloading to
            // cap the number of simultaneous downloads.
            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                println!(
                    "Downloading: {} ({}) -> {}",
                    entry_name, type_str, target_path_clone
                );
                if debug {
                    let _ = config::write_to_debug_log(format!(
                        "Downloading: {} ({}) -> {}\n",
                        entry_name, type_str, target_path_clone
                    ));
                }
                let result = download_file(&url, &target_path_clone).await;
                if result.is_ok() {
                    if xattr_set(
                        &target_path_clone,
                        "user.hai.entry_id",
                        &entry_clone.entry_id,
                    )
                    .is_err()
                    {
                        eprintln!("failed to set entry_id xattr");
                    }
                    if xattr_set(
                        &target_path_clone,
                        "user.hai.seq_id",
                        &entry_clone.seq_id.to_string(),
                    )
                    .is_err()
                    {
                        eprintln!("failed to set seq_id xattr");
                    }
                    if matches!(task.task_type, DownloadTaskType::Data) {
                        if xattr_set(
                            &target_path_clone,
                            "user.hai.rev_id",
                            &entry_clone.asset.rev_id,
                        )
                        .is_err()
                        {
                            eprintln!("failed to set rev_id xattr");
                        }
                        if let Some(hash) = entry_clone.asset.hash.as_ref() {
                            //
                            // Write the file hash and the mtime of the file into
                            // xattrs to make change detection easier.
                            //
                            let metadata = std::fs::metadata(&target_path_clone)
                                .expect("failed to read file metadata");
                            if let Ok(modified_time) = metadata.modified() {
                                let mtime_ts = modified_time
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_secs();
                                if xattr_set(
                                    &target_path_clone,
                                    "user.hai.hash_mtime",
                                    &mtime_ts.to_string(),
                                )
                                .is_err()
                                {
                                    eprintln!("failed to set hash_mtime xattr");
                                }
                            }

                            if xattr_set(&target_path_clone, "user.hai.hash", hash).is_err() {
                                eprintln!("failed to set hash xattr");
                            }
                        }
                    } else if matches!(task.task_type, DownloadTaskType::Metadata)
                        && let Some(AssetMetadataInfo {
                            hash: Some(hash),
                            rev_id,
                            ..
                        }) = entry_clone.metadata
                    {
                        if xattr_set(&target_path_clone, "user.hai.is_metadata", "true").is_err() {
                            eprintln!("failed to set is_metadata xattr");
                        }
                        if xattr_set(&target_path_clone, "user.hai.rev_id", &rev_id).is_err() {
                            eprintln!("failed to set rev_id xattr");
                        }
                        //
                        // Write the file hash and the mtime of the file into
                        // xattrs to make change detection easier.
                        //
                        let metadata = std::fs::metadata(&target_path_clone)
                            .expect("failed to read file metadata");
                        if let Ok(modified_time) = metadata.modified() {
                            let mtime_ts = modified_time
                                .duration_since(std::time::UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_secs();
                            if xattr_set(
                                &target_path_clone,
                                "user.hai.hash_mtime",
                                &mtime_ts.to_string(),
                            )
                            .is_err()
                            {
                                eprintln!("failed to set hash_mtime xattr");
                            }
                        }

                        if xattr_set(&target_path_clone, "user.hai.hash", &hash).is_err() {
                            eprintln!("failed to set hash xattr");
                        }
                    }
                }
                (entry_name, target_path_clone, result)
            });

            handles.push(handle);
        } else if matches!(entry.op, AssetEntryOp::Delete) {
            let entry_name = entry.name.clone();
            let target_path_clone = target_path.clone();
            let handle = tokio::spawn(async move {
                if debug {
                    let _ =
                        config::write_to_debug_log(format!("Deleting: {}\n", target_path_clone));
                }
                let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
                    tokio::fs::remove_file(&target_path_clone)
                        .await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                (entry_name, target_path_clone, result)
            });

            handles.push(handle);
        }
    }

    #[allow(clippy::type_complexity)]
    // (entry name, target path, result)
    let mut results: Vec<(
        String,
        String,
        Result<(), Box<dyn std::error::Error + Send + Sync>>,
    )> = Vec::new();

    // Wait for all downloads to complete
    for handle in join_all(handles).await {
        // Unwrap the JoinHandle result to get the inner result
        if let Ok(result) = handle {
            results.push(result);
        } else {
            // Handle the case where the task panicked
            eprintln!("A download task panicked");
        }
    }

    // Process results in order
    for result in results {
        match result.2 {
            Ok(_) => {
                if debug {
                    let _ = config::write_to_debug_log(format!("Saved: {}\n", result.1));
                }
            }
            Err(e) => eprintln!("error: failed to download '{}': {}", result.0, e),
        }
    }

    Ok(())
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

/// Helper function to download a file directly to disk to minimize mem usage.
pub async fn download_file(
    url: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(format!("Failed to download: HTTP status {}", response.status()).into());
    }
    let mut file = File::create(path).await?;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
    }
    Ok(())
}

// --

async fn get_file_hash(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    let metadata = std::fs::metadata(file_path).expect("failed to read file metadata");
    if let Ok(modified_time) = metadata.modified() {
        let mtime_ts = modified_time
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
            // If the filesystem doesn't show any modifications since the file
            // was tagged, use the hash set in xattrs.
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
    //use std::fs::{File, OpenOptions};
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

pub async fn download_revision_to_temp(
    asset_name: &str,
    revision: &AssetRevision,
    seen_revisions_map_mutex: Arc<Mutex<HashMap<String, std::path::PathBuf>>>,
) -> (
    Option<String>,
    Option<(tempfile::NamedTempFile, std::path::PathBuf)>,
) {
    let mut msgs: Vec<String> = vec![];
    let mut temp_file = None;
    if let Some(data_url) = revision.asset.url.as_ref() {
        let seen_revisions_map = seen_revisions_map_mutex.lock().await;
        if let Some(existing_data_temp_file_path) = seen_revisions_map.get(&revision.asset.rev_id) {
            msgs.push(format!(
                "Data of '{}' copied to '{}'",
                asset_name,
                existing_data_temp_file_path.display()
            ));
        } else {
            // Drop lock before longer download operation
            drop(seen_revisions_map);
            match crate::asset_editor::create_empty_temp_file(
                asset_name,
                Some(&revision.asset.rev_id),
            ) {
                Ok((data_temp_file, data_temp_file_path)) => {
                    match crate::asset_sync::download_file(
                        data_url,
                        &data_temp_file_path.to_string_lossy(),
                    )
                    .await
                    {
                        Ok(_) => {
                            msgs.push(format!(
                                "Revision '{}' copied to '{}'",
                                revision.asset.rev_id,
                                data_temp_file_path.display()
                            ));
                            if let AssetCreatedBy::User(user) = &revision.asset.created_by {
                                msgs.push(format!("    By: {}", user.username));
                            }
                            let action = match revision.op {
                                AssetEntryOp::Add => "add",
                                AssetEntryOp::Push => "push",
                                AssetEntryOp::Delete => "delete",
                                AssetEntryOp::Edit => "edit",
                                AssetEntryOp::Fork => "fork",
                                AssetEntryOp::Metadata => "metadata",
                                AssetEntryOp::Other => "other",
                            };
                            msgs.push(format!("    Op: {}", action));

                            temp_file = Some((data_temp_file, data_temp_file_path.clone()));
                            let mut seen_revisions_map = seen_revisions_map_mutex.lock().await;
                            seen_revisions_map
                                .insert(revision.asset.rev_id.clone(), data_temp_file_path);
                            drop(seen_revisions_map);
                        }
                        Err(_e) => {
                            eprintln!("error: failed to download: {}", _e);
                        }
                    }
                }
                Err(_) => {
                    eprintln!("error: failed to fetch: {}", asset_name);
                }
            }
        }
    }
    (
        if !msgs.is_empty() {
            Some(msgs.join("\n"))
        } else {
            None
        },
        temp_file,
    )
}
