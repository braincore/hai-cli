use futures::future::join_all;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::fs::{create_dir_all, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use crate::api::{
    self,
    client::HaiClient,
    types::asset::{
        AssetEntry, AssetEntryIterArg, AssetEntryIterError, AssetEntryIterNextArg, AssetEntryOp,
    },
};
use crate::config;

// Structure to hold download task information
struct DownloadTask {
    entry_name: String,
    data_url: String,
}

// FIXME: Support metadata (Sync it down as .metadata?)
// FIXME: Support arbitrary cursor
// FIXME: Add xattr (start with seq_id & rev_id & asset_name?)

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
        let relative_path = match entry.name.strip_prefix(&folder_prefix) {
            Some(path) => path,
            None => &entry.name, // If for some reason it doesn't have the prefix
        };

        // Construct the full target path
        let target_file_path = format!("{}/{}", target_path, relative_path);

        if matches!(entry.op, AssetEntryOp::Delete) {
            entry_with_tasks.push((entry, target_file_path, None));
            continue;
        }

        let expected_hash = entry.asset.hash.clone().unwrap_or("".to_string());

        // Check if file already exists and has the correct hash
        let target_file = std::path::Path::new(&target_file_path);
        if target_file.exists() && !expected_hash.is_empty() {
            match get_file_hash(&target_file_path).await {
                Ok(file_hash) => {
                    // Convert the expected hash from hex to bytes
                    match hex_to_bytes(&expected_hash) {
                        Ok(decoded_hash) => {
                            if file_hash == decoded_hash {
                                if debug {
                                    let _ = config::write_to_debug_log(format!(
                                        "Skipping (hash match): {}\n",
                                        target_file_path
                                    ));
                                }
                                continue; // Skip download
                            } else {
                                if debug {
                                    let _ = config::write_to_debug_log(format!(
                                        "Hash mismatch, re-downloading: {}\n",
                                        target_file_path
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            if debug {
                                let _ = config::write_to_debug_log(format!(
                                    "warning: failed to decode hash for '{}': {}\n",
                                    entry.name, e
                                ));
                            }
                            // Continue with download
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
                    // Continue with download
                }
            }
        }

        // Ensure the parent directory exists
        let target_file = std::path::Path::new(&target_file_path);
        if let Some(parent) = target_file.parent() {
            if !parent.exists() {
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
        }

        // Download the file directly to disk
        println!("Downloading: {} -> {}", entry.name, target_file_path);
        if debug {
            let _ = config::write_to_debug_log(format!(
                "Downloading: {} -> {}\n",
                entry.name, target_file_path
            ));
        }

        if let Some(data_url) = entry.asset.url.as_ref() {
            let download_task = Some(DownloadTask {
                entry_name: entry.name.clone(),
                data_url: data_url.clone(),
            });
            entry_with_tasks.push((entry, target_file_path, download_task));
        }
    }

    let max_concurrent_downloads = 5;

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
            let data_url = task.data_url.clone();
            let target_path_clone = target_path.clone();
            let sem_clone = Arc::clone(&semaphore);

            // Create a future that acquires a semaphore before downloading to
            // cap the number of simultaneous downloads.
            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                println!("Downloading: {} -> {}", entry_name, target_path_clone);
                if debug {
                    let _ = config::write_to_debug_log(format!(
                        "Downloading: {} -> {}\n",
                        entry_name, target_path_clone
                    ));
                }
                let result = download_file(&data_url, &target_path_clone).await;
                if result.is_ok() {
                    if xattr::set(
                        target_path_clone.clone(),
                        "user.hai.entry_id",
                        entry_clone.entry_id.as_bytes(),
                    )
                    .is_err()
                    {
                        eprintln!("failed to set entry_id xattr");
                    }
                    if xattr::set(
                        target_path_clone.clone(),
                        "user.hai.rev_id",
                        entry_clone.asset.rev_id.as_bytes(),
                    )
                    .is_err()
                    {
                        eprintln!("failed to set rev_id xattr");
                    }
                    if xattr::set(
                        target_path_clone.clone(),
                        "user.hai.seq_id",
                        entry_clone.seq_id.to_string().as_bytes(),
                    )
                    .is_err()
                    {
                        eprintln!("failed to set seq_id xattr");
                    }
                    if let Some(hash) = entry_clone.asset.hash.as_ref() {
                        //
                        // Write the file hash and the mtime of the file into
                        // xattrs to make change detection easier.
                        //
                        let metadata = std::fs::metadata(target_path_clone.clone())
                            .expect("failed to read file metadata");
                        if let Ok(modified_time) = metadata.modified() {
                            let mtime_ts = modified_time
                                .duration_since(std::time::UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_secs();
                            if xattr::set(
                                target_path_clone.clone(),
                                "user.hai.hash_mtime",
                                mtime_ts.to_string().as_bytes(),
                            )
                            .is_err()
                            {
                                eprintln!("failed to set hash_mtime xattr");
                            }
                        }

                        if xattr::set(target_path_clone.clone(), "user.hai.hash", hash.as_bytes())
                            .is_err()
                        {
                            eprintln!("failed to set hash xattr");
                        }
                    }
                }
                // The permit is automatically released when _permit goes out of scope
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
async fn download_file(
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
            if let Ok(Some(xattr_mtime_bytes)) = xattr::get(file_path, "user.hai.hash_mtime") {
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
            if let Ok(Some(xattr_hash_bytes)) = xattr::get(file_path, "user.hai.hash") {
                if let Ok(xattr_hash_hex_str) = std::str::from_utf8(&xattr_hash_bytes) {
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
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))??;

    Ok(hash)
}

// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    // Check if the hex string has valid length
    if hex.len() % 2 != 0 {
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
