use futures::future::join_all;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
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

const HAISYNC_FILENAME: &str = ".haisync";
const METADATA_EXTENSION: &str = ".metadata";

/// Represents the `.haisync` file that tracks sync state for a folder.
///
/// This file is placed at the root of a synced folder.
/// - The remote prefix this folder is synced against
/// - The cursor for resuming incremental sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaiSyncState {
    /// The remote asset prefix this folder syncs with (e.g. "projects/myapp/")
    pub remote_prefix: String,
    /// The cursor for resuming incremental sync. This is an opaque string
    /// provided by the API after listing entries.
    /// `None` means no sync has been performed yet (fresh state).
    pub cursor: Option<String>,
}

impl HaiSyncState {
    /// Read a `.haisync` file from the given directory.
    pub fn read_from_dir(dir: &Path) -> Result<Self, String> {
        let path = dir.join(HAISYNC_FILENAME);
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
    }

    /// Write this state to a `.haisync` file in the given directory.
    pub fn write_to_dir(&self, dir: &Path) -> Result<(), String> {
        let path = dir.join(HAISYNC_FILENAME);
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize haisync state: {}", e))?;
        std::fs::write(&path, contents)
            .map_err(|e| format!("Failed to write {}: {}", path.display(), e))
    }
}

/// Scans the immediate children and all descendants of `dir` for any
/// `.haisync` files.
///
/// This is used to prevent syncing a folder that contains nested sync roots.
/// Returns `Some(path)` with the first `.haisync` found, or `None` if clean.
///
/// Note: This deliberately skips `dir_path` itself; only children are considered.
pub fn find_haisync_in_children(dir_path: &Path) -> Option<std::path::PathBuf> {
    let walker = WalkBuilder::new(dir_path)
        .follow_links(true)
        .hidden(false)
        .git_ignore(false)
        .max_depth(None)
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // Skip any .haisync that is directly in the source directory itself
        // since that's valid.
        if let Some(parent) = path.parent()
            && parent == dir_path
        {
            continue;
        }

        if path
            .file_name()
            .map(|n| n == HAISYNC_FILENAME)
            .unwrap_or(false)
        {
            return Some(path.to_path_buf());
        }
    }

    None
}

/// Result of resolving the `.haisync` location for a sync operation.
pub struct HaiSyncResolution {
    /// The directory containing the `.haisync` file.
    pub sync_root: std::path::PathBuf,

    /// The parsed state from the `.haisync` file.
    pub state: HaiSyncState,

    /// `true` if the `.haisync` was found in an ancestor directory
    /// (i.e., not directly in the requested target folder).
    pub is_ancestor: bool,
}

/// Looks for a `.haisync` file starting at `target_dir` and walking up to ancestors.
///
/// Returns:
/// - `Ok(Some(resolution))` if a `.haisync` was found (in target or an ancestor)
/// - `Ok(None)` if no `.haisync` exists anywhere in the ancestor chain
/// - `Err(...)` on I/O or parse errors
pub fn resolve_haisync(target_dir: &Path) -> Result<Option<HaiSyncResolution>, String> {
    let target_dir = target_dir
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize '{}': {}", target_dir.display(), e))?;

    let mut current = Some(target_dir.as_path());
    let mut is_first = true;

    while let Some(dir) = current {
        let haisync_path = dir.join(HAISYNC_FILENAME);
        if haisync_path.is_file() {
            let state = HaiSyncState::read_from_dir(dir)?;
            return Ok(Some(HaiSyncResolution {
                sync_root: dir.to_path_buf(),
                state,
                is_ancestor: !is_first,
            }));
        }
        is_first = false;
        // On some platforms, parent() never returns None (only empty string)
        current = dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && *p != dir);
    }

    Ok(None)
}

pub async fn sync_down(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    prefix: Option<&str>,
    target_path: &str,
    max_concurrent_downloads: Option<usize>,
    debug: bool,
) -> Result<(), String> {
    //
    // Resolve .haisync state
    //
    let target_dir = std::path::Path::new(target_path);

    // Check for .haisync in child directories (error if found)
    if target_dir.exists() {
        if let Some(child_haisync) = find_haisync_in_children(target_dir) {
            return Err(format!(
                "error: found nested .haisync at '{}'. Cannot sync a folder that contains nested sync roots.",
                child_haisync.display()
            ));
        }
    }

    // Resolve existing .haisync from target or ancestors
    let resolution = if target_dir.exists() {
        match resolve_haisync(target_dir) {
            Ok(Some(resolution)) => {
                // Validate prefix if one was provided
                if let Some(prefix) = prefix {
                    if resolution.state.remote_prefix != prefix {
                        if resolution.is_ancestor {
                            if debug {
                                let _ = config::write_to_debug_log(format!(
                                    "sync: using ancestor .haisync at '{}' with prefix '{}'\n",
                                    resolution.sync_root.display(),
                                    resolution.state.remote_prefix
                                ));
                            }
                            resolution
                        } else {
                            return Err(format!(
                                "error: .haisync in '{}' has remote_prefix '{}' but sync was requested with prefix '{}'. \
                                 Remove the .haisync file to re-initialize.",
                                resolution.sync_root.display(),
                                resolution.state.remote_prefix,
                                prefix
                            ));
                        }
                    } else {
                        if debug {
                            let _ = config::write_to_debug_log(format!(
                                "sync: resuming with .haisync at '{}' (cursor: {:?})\n",
                                resolution.sync_root.display(),
                                resolution.state.cursor
                            ));
                        }
                        resolution
                    }
                } else {
                    // No prefix provided — use whatever is in .haisync
                    if debug {
                        let _ = config::write_to_debug_log(format!(
                            "sync: using .haisync at '{}' with prefix '{}' (cursor: {:?})\n",
                            resolution.sync_root.display(),
                            resolution.state.remote_prefix,
                            resolution.state.cursor
                        ));
                    }
                    resolution
                }
            }
            Ok(None) => {
                // No .haisync found
                if let Some(prefix) = prefix {
                    // Fresh sync with provided prefix
                    let state = HaiSyncState {
                        remote_prefix: prefix.to_string(),
                        cursor: None,
                    };
                    HaiSyncResolution {
                        sync_root: target_dir.to_path_buf(),
                        state,
                        is_ancestor: false,
                    }
                } else {
                    return Err(format!(
                        "error: no .haisync file found in '{}' or its ancestors. \
                         A remote prefix must be specified for the initial sync.",
                        target_path
                    ));
                }
            }
            Err(e) => {
                return Err(format!("error: failed to resolve .haisync: {}", e));
            }
        }
    } else {
        // Target doesn't exist yet
        if let Some(prefix) = prefix {
            let state = HaiSyncState {
                remote_prefix: prefix.to_string(),
                cursor: None,
            };
            HaiSyncResolution {
                sync_root: target_dir.to_path_buf(),
                state,
                is_ancestor: false,
            }
        } else {
            return Err(format!(
                "error: target path '{}' does not exist and no remote prefix was specified. \
                 A remote prefix must be specified for the initial sync.",
                target_path
            ));
        }
    };

    let (sync_root, mut haisync_state, is_ancestor) = (
        resolution.sync_root,
        resolution.state,
        resolution.is_ancestor,
    );

    // When using an ancestor .haisync, the actual target_path and prefix come
    // from the ancestor's state.
    let (effective_prefix, effective_target_path) = if is_ancestor {
        (
            haisync_state.remote_prefix.clone(),
            sync_root.to_string_lossy().to_string(),
        )
    } else {
        (haisync_state.remote_prefix.clone(), target_path.to_string())
    };

    //
    // Create target path if it doesn't exist.
    //
    let path = std::path::Path::new(&effective_target_path);
    if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "error: target path '{}' exists but is not a directory",
                effective_target_path
            ));
        }
    } else {
        match create_dir_all(path).await {
            Ok(_) => {
                if debug {
                    let _ = config::write_to_debug_log(format!(
                        "Created directory: {}\n",
                        effective_target_path
                    ));
                }
            }
            Err(e) => {
                return Err(format!(
                    "error: failed to create directory '{}': {}",
                    effective_target_path, e
                ));
            }
        }
    }

    // Determine the folder prefix for saved assets
    let folder_prefix = get_folder_prefix(&effective_prefix);

    //
    // Collect all entries — either resume from cursor or start fresh
    //
    let mut entries: Vec<AssetEntry> = vec![];
    let mut latest_cursor: Option<String>;

    if let Some(cursor) = haisync_state.cursor.clone() {
        // Resume from existing cursor
        if debug {
            let _ = config::write_to_debug_log(format!("sync: resuming from cursor\n"));
        }

        let mut iter_res = api_client
            .asset_entry_iter_next(AssetEntryIterNextArg { cursor, limit: 200 })
            .await
            .map_err(|e| format!("error: {}", e))?;

        loop {
            entries.extend_from_slice(&iter_res.entries);
            latest_cursor = Some(iter_res.cursor.clone());
            if !iter_res.has_more {
                break;
            }
            iter_res = api_client
                .asset_entry_iter_next(AssetEntryIterNextArg {
                    cursor: iter_res.cursor,
                    limit: 200,
                })
                .await
                .map_err(|e| format!("error: {}", e))?;
        }
    } else {
        // Fresh sync — start from the beginning
        let mut asset_iter_res = match api_client
            .asset_entry_iter(AssetEntryIterArg {
                prefix: Some(effective_prefix.clone()),
                limit: 200,
            })
            .await
        {
            Ok(res) => res,
            Err(e) => {
                // Even on empty, write .haisync so future calls know the prefix
                // (but we have no cursor to save)
                let fresh_state = HaiSyncState {
                    remote_prefix: effective_prefix.clone(),
                    cursor: None,
                };
                if let Err(write_err) = fresh_state.write_to_dir(&sync_root) {
                    eprintln!("warning: failed to write .haisync: {}", write_err);
                }

                return match e {
                    api::client::RequestError::Route(AssetEntryIterError::Empty) => {
                        println!("[empty]");
                        Ok(())
                    }
                    _ => Err(format!("error: {}", e)),
                };
            }
        };

        loop {
            entries.extend_from_slice(&asset_iter_res.entries);
            latest_cursor = Some(asset_iter_res.cursor.clone());
            if !asset_iter_res.has_more {
                break;
            }
            asset_iter_res = api_client
                .asset_entry_iter_next(AssetEntryIterNextArg {
                    cursor: asset_iter_res.cursor,
                    limit: 200,
                })
                .await
                .map_err(|e| format!("error: {}", e))?;
        }
    }

    if entries.is_empty() && latest_cursor.is_some() {
        println!("Already up to date.");
        if let Some(cursor) = latest_cursor {
            haisync_state.cursor = Some(cursor);
            if let Err(e) = haisync_state.write_to_dir(&sync_root) {
                eprintln!("warning: failed to write .haisync: {}", e);
            }
        }
        return Ok(());
    }

    // Filter out any .haisync entries from the server
    entries.retain(|entry| {
        !entry.name.ends_with(HAISYNC_FILENAME)
            && !entry.name.contains(&format!("/{}", HAISYNC_FILENAME))
    });

    println!("Syncing {} entries...", entries.len());

    let _ = sync_down_entries(
        asset_blob_cache,
        asset_keyring,
        api_client,
        recipient,
        AssetSyncSource::AssetEntry(entries.clone()),
        Some((&folder_prefix, &effective_target_path)),
        max_concurrent_downloads,
        debug,
    )
    .await;

    //
    // Write updated .haisync after successful sync
    //
    if let Some(cursor) = latest_cursor {
        haisync_state.cursor = Some(cursor);
    }
    if let Err(e) = haisync_state.write_to_dir(&sync_root) {
        eprintln!("warning: failed to write .haisync: {}", e);
    } else if debug {
        let _ = config::write_to_debug_log(format!(
            "sync: wrote .haisync to '{}'\n",
            sync_root.display()
        ));
    }

    Ok(())
}

enum LocalAssetFileChangeStatus {
    Unchanged(String), // local file hash
    /// Caller's responsibility to reassign xattr and decide if changed.
    XattrLost(String), // local file hash
    DataChanged(String), // local file hash
    /// Caller's responsibility to determine if it's deleted or moved.
    Missing,
}

/// Decide based on hash info available in xattrs whether a file has been
/// changed.
///
/// Race considerations: xattrs are read before file contents.
async fn is_local_asset_file_changed_using_xattr(
    file_path: &str,
) -> Result<LocalAssetFileChangeStatus, String> {
    // Extract stored hash from xattr
    let maybe_encrypted_hash_xattr =
        xattr_get(file_path, "user.hai.hash").and_then(|bytes| String::from_utf8(bytes).ok());
    let decrypted_hash_xattr = xattr_get(file_path, "user.hai.decrypted_hash")
        .and_then(|bytes| String::from_utf8(bytes).ok());

    // Calculate actual file hash to compare to
    let actual_file_hash = match calculate_file_hash(file_path).await {
        Ok(hash) => hash,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalAssetFileChangeStatus::Missing);
        }
        Err(e) => {
            return Err(format!("Failed to calculate hash: {}", e));
        }
    };
    let actual_file_hash_hex = hex::encode(&actual_file_hash);

    let hash_xattr = match decrypted_hash_xattr.or(maybe_encrypted_hash_xattr) {
        Some(hash) => hash,
        None => return Ok(LocalAssetFileChangeStatus::XattrLost(actual_file_hash_hex)),
    };

    // Compare hashes
    if actual_file_hash_hex.eq_ignore_ascii_case(&hash_xattr) {
        Ok(LocalAssetFileChangeStatus::Unchanged(actual_file_hash_hex))
    } else {
        Ok(LocalAssetFileChangeStatus::DataChanged(
            actual_file_hash_hex,
        ))
    }
}

enum LocalAssetFileSyncDownPolicy {
    // Caller should sync data file & xattrs
    Sync,
    // Caller should only sync xattrs
    SyncOnlyXattrs,
    // Caller needs to do nothing
    AlreadySynced,
    NoSyncDueToLocalChanges,
}

async fn decide_local_asset_file_sync_down_policy(
    file_path: &str,
    source: &AssetSourceMinimal,
) -> Result<LocalAssetFileSyncDownPolicy, String> {
    let change_status = match is_local_asset_file_changed_using_xattr(file_path).await {
        Ok(status) => status,
        Err(e) => {
            eprintln!(
                "Warning: Failed to check local file status for '{}': {}",
                file_path, e
            );
            return Err(e);
        }
    };
    if let Some(source_hash) = source.asset.hash.as_ref() {
        return Ok(match change_status {
            LocalAssetFileChangeStatus::Unchanged(file_hash) => {
                // File unchanged, so we can accept changes from remote
                if &file_hash == source_hash {
                    LocalAssetFileSyncDownPolicy::SyncOnlyXattrs
                } else {
                    LocalAssetFileSyncDownPolicy::Sync
                }
            }
            LocalAssetFileChangeStatus::XattrLost(file_hash) => {
                if &file_hash == source_hash {
                    // Local file matches remote despite lack of xattrx -> sync
                    LocalAssetFileSyncDownPolicy::Sync
                } else {
                    LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges
                }
            }
            LocalAssetFileChangeStatus::DataChanged(file_hash) => {
                if &file_hash == source_hash {
                    // Local file matches remote -> sync
                    LocalAssetFileSyncDownPolicy::Sync
                } else {
                    LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges
                }
            }
            LocalAssetFileChangeStatus::Missing => LocalAssetFileSyncDownPolicy::Sync,
        });
    } else {
        // Remote is a deletion (could assert source.op is DELETE)
        return Ok(match change_status {
            LocalAssetFileChangeStatus::Unchanged(_file_hash) => {
                // File unchanged, so we can accept the deletion from remote
                LocalAssetFileSyncDownPolicy::Sync
            }
            LocalAssetFileChangeStatus::XattrLost(_file_hash) => {
                LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges
            }
            LocalAssetFileChangeStatus::DataChanged(_file_hash) => {
                LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges
            }
            LocalAssetFileChangeStatus::Missing => {
                // Already deleted locally
                LocalAssetFileSyncDownPolicy::AlreadySynced
            }
        });
    }
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
pub async fn sync_down_entries(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    sync_source: AssetSyncSource,
    persist: Option<(&str, &str)>, // (folder_prefix, target_path)
    max_concurrent_downloads: Option<usize>,
    debug: bool,
) -> Vec<(
    AssetSourceMinimal,
    Option<tempfile::NamedTempFile>,
    Option<tempfile::NamedTempFile>,
)> {
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

    //
    // Construct download tasks
    //

    let mut entries_with_dl_tasks = vec![];

    for source in sources {
        if source.asset_name == HAISYNC_FILENAME
            || source
                .asset_name
                .ends_with(&format!("/{}", HAISYNC_FILENAME))
        {
            // Assume any .haisync files on the server are a mistake so don't
            // sync them down.
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

            // Handle deletion when persisting
            if matches!(source.op, AssetEntryOp::Delete)
                && let Some(asset_final_path) = final_path.as_deref()
            {
                let sync_down_policy = match decide_local_asset_file_sync_down_policy(
                    asset_final_path,
                    &source,
                )
                .await
                {
                    Ok(policy) => policy,
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to decide sync down policy for '{}': {}. Skipping deletion.",
                            asset_final_path, e
                        );
                        return Err(e);
                    }
                };
                match sync_down_policy {
                    LocalAssetFileSyncDownPolicy::Sync
                    | LocalAssetFileSyncDownPolicy::SyncOnlyXattrs => {
                        // SyncOnlyXattrs is unexpected for deletion
                        if debug {
                            let _ = config::write_to_debug_log(format!(
                                "Deleting: {}\n",
                                asset_final_path
                            ));
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
                    LocalAssetFileSyncDownPolicy::AlreadySynced => {
                        // Already deleted locally, nothing to do
                        return Ok((source, None, None));
                    }
                    LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges => {
                        eprintln!(
                            "Warning: Detected local changes to '{}'. Skipping deletion from remote.",
                            asset_final_path
                        );
                        return Ok((source, None, None));
                    }
                }
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
                        Some(METADATA_EXTENSION),
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
                            return Err(e.to_string());
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

            let asset_sync_down_policy = if let Some(final_path) = &final_path {
                match decide_local_asset_file_sync_down_policy(final_path, &source).await {
                    Ok(policy) => policy,
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to decide sync down policy for '{}': {}. Skipping deletion.",
                            final_path, e
                        );
                        return Err(e.to_string());
                    }
                }
            } else {
                LocalAssetFileSyncDownPolicy::Sync
            };

            if matches!(
                asset_sync_down_policy,
                LocalAssetFileSyncDownPolicy::NoSyncDueToLocalChanges
            ) {
                eprintln!(
                    "Warning: Detected local changes to '{}'. Skipping sync from remote.",
                    final_path.as_deref().unwrap_or("<unknown>")
                );
                return Ok((source, None, None));
            } else if matches!(
                asset_sync_down_policy,
                LocalAssetFileSyncDownPolicy::AlreadySynced
            ) {
                return Ok((source, None, None));
            }

            let data_contents_temp_file =
                if !matches!(asset_sync_down_policy, LocalAssetFileSyncDownPolicy::Sync) {
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
                            return Err(e.to_string());
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
        match handle {
            Ok(inner_result) => match inner_result {
                Ok((source, data_temp_file_opt, metadata_temp_file_opt)) => {
                    result.push((source, data_temp_file_opt, metadata_temp_file_opt));
                }
                Err(e) => {
                    eprintln!("A download task failed: {}", e);
                }
            },
            Err(e) => {
                // Handle the case where the task panicked
                eprintln!("A download task panicked: {}", e);
            }
        }
    }

    result
}

/// Sets universal xattrs for an asset file.
///
/// All assets files (data or metadata) get:
/// - user.hai.entry_id
/// - user.hai.seq_id
/// - user.hai.asset_name
fn asset_file_set_xattrs(path: &str, source: &AssetSourceMinimal) {
    if let Some((entry_id, seq_id)) = source.iter_info.as_ref() {
        if xattr_set(&path, "user.hai.entry_id", &entry_id).is_err() {
            eprintln!("failed to set entry_id xattr");
        }
        if xattr_set(&path, "user.hai.seq_id", &seq_id.to_string()).is_err() {
            eprintln!("failed to set seq_id xattr");
        }
        if xattr_set(&path, "user.hai.asset_name", &source.asset_name).is_err() {
            eprintln!("failed to set asset_name xattr");
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

// --

//
// Asset Sync Up
//

use crate::api::types::asset::{AssetMetadataPutArg, PutConflictPolicy};
use crate::asset_async_writer::{WorkerAssetMsg, WorkerAssetUpdate};

/// Result of a single file sync-up operation
pub struct SyncUpResult {
    #[allow(dead_code)]
    pub file_path: String,
    #[allow(dead_code)]
    pub asset_name: String,
    pub action: SyncUpAction,
    pub success: bool,
    #[allow(dead_code)]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SyncUpAction {
    Created,
    Updated,
    Moved,
    Skipped,    // Hash unchanged
    SkippedNew, // New file but sync_new_files=false
}

impl std::fmt::Display for SyncUpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncUpAction::Created => write!(f, "Created"),
            SyncUpAction::Updated => write!(f, "Updated"),
            SyncUpAction::Moved => write!(f, "Moved"),
            SyncUpAction::Skipped => write!(f, "Skipped (unchanged)"),
            SyncUpAction::SkippedNew => write!(f, "Skipped (new file)"),
        }
    }
}

/// Options for sync-up operation
pub struct SyncUpOptions {
    pub sync_new_files: bool,
    pub max_concurrent_uploads: usize,
    pub debug: bool,
}

impl Default for SyncUpOptions {
    fn default() -> Self {
        Self {
            sync_new_files: false,
            max_concurrent_uploads: 10,
            debug: false,
        }
    }
}

/// Syncs local changes up to the remote API server.
///
/// # Arguments
/// * `asset_blob_cache` - Asset blob cache
/// * `asset_keyring` - Asset keyring for encryption
/// * `api_client` - The API client
/// * `username` - Optional username for encryption
/// * `update_asset_tx` - Channel to send asset updates
/// * `source_path` - Local directory path to sync from
/// * `target_prefix` - Remote asset prefix (folder path)
/// * `options` - Sync options
///
/// # Returns
/// Vector of results for each file processed
pub async fn sync_up(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<WorkerAssetMsg>,
    source_path: &str,
    target_prefix: Option<&str>,
    options: SyncUpOptions,
) -> Result<Vec<SyncUpResult>, String> {
    let source_dir = Path::new(source_path);

    if !source_dir.exists() {
        return Err(format!(
            "Source path '{}' does not exist",
            source_dir.display()
        ));
    }

    if !source_dir.is_dir() {
        return Err(format!(
            "Source path '{}' is not a directory",
            source_dir.display()
        ));
    }

    //
    // Check for .haisync in child directories (error if found in a child, not
    // source itself)
    //
    if let Some(child_haisync) = find_haisync_in_children(source_dir) {
        return Err(format!(
            "Found nested .haisync at '{}'. Cannot sync a folder that contains nested sync roots.",
            child_haisync.display()
        ));
    }

    //
    // Resolve .haisync from source or ancestors
    //
    let (effective_source, effective_prefix) = match resolve_haisync(source_dir) {
        Ok(Some(resolution)) => {
            if let Some(prefix) = target_prefix {
                if resolution.state.remote_prefix != prefix {
                    if resolution.is_ancestor {
                        // Ancestor has a different prefix — use the ancestor's sync root
                        if options.debug {
                            let _ = config::write_to_debug_log(format!(
                                "sync_up: using ancestor .haisync at '{}' with prefix '{}'\n",
                                resolution.sync_root.display(),
                                resolution.state.remote_prefix
                            ));
                        }
                        (
                            resolution.sync_root.to_string_lossy().to_string(),
                            resolution.state.remote_prefix,
                        )
                    } else {
                        return Err(format!(
                            ".haisync in '{}' has remote_prefix '{}' but sync was requested with prefix '{}'. \
                             Remove the .haisync file to re-initialize.",
                            resolution.sync_root.display(),
                            resolution.state.remote_prefix,
                            prefix
                        ));
                    }
                } else {
                    // Prefix matches
                    if options.debug {
                        let _ = config::write_to_debug_log(format!(
                            "sync_up: using .haisync at '{}' with prefix '{}'\n",
                            resolution.sync_root.display(),
                            resolution.state.remote_prefix
                        ));
                    }
                    if resolution.is_ancestor {
                        (
                            resolution.sync_root.to_string_lossy().to_string(),
                            resolution.state.remote_prefix,
                        )
                    } else {
                        (source_path.to_string(), resolution.state.remote_prefix)
                    }
                }
            } else {
                // No prefix provided — use whatever is in .haisync
                if options.debug {
                    let _ = config::write_to_debug_log(format!(
                        "sync_up: using .haisync at '{}' with prefix '{}'\n",
                        resolution.sync_root.display(),
                        resolution.state.remote_prefix
                    ));
                }
                if resolution.is_ancestor {
                    (
                        resolution.sync_root.to_string_lossy().to_string(),
                        resolution.state.remote_prefix,
                    )
                } else {
                    (source_path.to_string(), resolution.state.remote_prefix)
                }
            }
        }
        Ok(None) => {
            // No .haisync found
            if let Some(prefix) = target_prefix {
                (source_path.to_string(), prefix.to_string())
            } else {
                return Err(format!(
                    "No .haisync file found in '{}' or its ancestors. \
                     A remote prefix must be specified for sync-up.",
                    source_path
                ));
            }
        }
        Err(e) => {
            return Err(format!("Failed to resolve .haisync: {}", e));
        }
    };

    let has_trailing_slash = effective_source.ends_with('/');
    let source_path = Path::new(&effective_source);
    let strip_base = source_path.to_path_buf();

    // The base path we strip from, and optionally a prefix to add back
    let dir_prefix = if has_trailing_slash {
        String::new()
    } else {
        let dir_name = source_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        format!("{}/", dir_name)
    };

    // Normalize target_prefix to ensure it ends with '/' if non-empty
    let target_prefix = if !effective_prefix.is_empty() && !effective_prefix.ends_with('/') {
        format!("{}/", effective_prefix)
    } else {
        effective_prefix
    };

    // Collect all files to potentially sync
    let mut file_pairs: Vec<(String, String, bool)> = Vec::new(); // (file_path, asset_name, is_metadata)

    let walker = WalkBuilder::new(source_path)
        .follow_links(true)
        .hidden(false)
        // NOTE: Only uses .gitignore if .git exists
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if name == HAISYNC_FILENAME {
                return false; // Never sync .haisync
            }
            !name.starts_with('.') || name == ".gitignore" || name == ".ignore"
        })
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        let file_path = path.to_string_lossy().to_string();

        // Get relative path from source_path
        let relative_path = match path.strip_prefix(&strip_base) {
            Ok(rel) => rel.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // Determine if this is a metadata file
        let is_metadata = relative_path.ends_with(METADATA_EXTENSION);

        // Construct asset name (with dir_prefix for rsync-like behavior)
        let asset_name = if is_metadata {
            let base_name = relative_path.strip_suffix(METADATA_EXTENSION).unwrap();
            format!("{}{}{}", target_prefix, dir_prefix, base_name)
        } else {
            format!("{}{}{}", target_prefix, dir_prefix, relative_path)
        };

        file_pairs.push((file_path, asset_name, is_metadata));
    }

    if options.debug {
        let _ = config::write_to_debug_log(format!(
            "sync_up: found {} files to process\n",
            file_pairs.len()
        ));
    }

    // Process files with concurrency control
    let semaphore = Arc::new(Semaphore::new(options.max_concurrent_uploads));
    let mut handles = Vec::new();

    for (file_path, asset_name, is_metadata) in file_pairs {
        let asset_blob_cache_clone = asset_blob_cache.clone();
        let asset_keyring_clone = asset_keyring.clone();
        let api_client_clone = api_client.clone();
        let username_clone = username.to_string().clone();
        let update_asset_tx_clone = update_asset_tx.clone();
        let sem_clone = Arc::clone(&semaphore);
        let debug = options.debug;
        let sync_new_files = options.sync_new_files;

        // Check if the file was previously synced under a different asset name (i.e., moved locally)
        let previous_asset_name = xattr_get(&file_path, "user.hai.asset_name")
            .and_then(|bytes| String::from_utf8(bytes).ok());

        let is_move = match &previous_asset_name {
            Some(old_name) => old_name != &asset_name,
            None => false,
        };

        if is_move && !is_metadata {
            let old_asset_name = previous_asset_name.unwrap();

            if debug {
                let _ = config::write_to_debug_log(format!(
                    "sync_up: detected move '{}' -> '{}'\n",
                    old_asset_name, asset_name
                ));
            }

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                sync_up_move(
                    asset_blob_cache_clone,
                    asset_keyring_clone,
                    &api_client_clone,
                    &username_clone,
                    update_asset_tx_clone,
                    &file_path,
                    &old_asset_name,
                    &asset_name,
                    debug,
                )
                .await
            });

            handles.push(handle);
        } else if is_metadata {
            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                vec![
                    sync_up_metadata_file(
                        &api_client_clone,
                        &file_path,
                        &asset_name,
                        sync_new_files,
                        debug,
                    )
                    .await,
                ]
            });

            handles.push(handle);
        } else {
            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                vec![
                    sync_up_data_file(
                        asset_blob_cache_clone,
                        asset_keyring_clone,
                        &api_client_clone,
                        &username_clone,
                        update_asset_tx_clone,
                        &file_path,
                        &asset_name,
                        sync_new_files,
                        debug,
                    )
                    .await,
                ]
            });

            handles.push(handle);
        }
    }

    // Collect results
    let mut results = Vec::new();
    for handle in join_all(handles).await {
        match handle {
            Ok(result) => results.extend(result),
            Err(e) => {
                eprintln!("A sync task panicked: {}", e);
            }
        }
    }

    // Print summary
    let created = results
        .iter()
        .filter(|r| matches!(r.action, SyncUpAction::Created) && r.success)
        .count();
    let updated = results
        .iter()
        .filter(|r| matches!(r.action, SyncUpAction::Updated) && r.success)
        .count();
    let moved = results
        .iter()
        .filter(|r| matches!(r.action, SyncUpAction::Moved) && r.success)
        .count();
    let skipped = results
        .iter()
        .filter(|r| matches!(r.action, SyncUpAction::Skipped))
        .count();
    let skipped_new = results
        .iter()
        .filter(|r| matches!(r.action, SyncUpAction::SkippedNew))
        .count();
    let failed = results.iter().filter(|r| !r.success).count();

    println!(
        "Sync up complete: {} created, {} updated, {} moved, {} unchanged, {} skipped (new), {} failed",
        created, updated, moved, skipped, skipped_new, failed
    );

    Ok(results)
}

/// Syncs a single data file up to the remote server.
///
/// TODO:
/// - Clear xattrs if anything unexpected (or missing)
/// - Atomic xattr updates (modifying bit?)
async fn sync_up_data_file(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<WorkerAssetMsg>,
    file_path: &str,
    asset_name: &str,
    sync_new_files: bool,
    debug: bool,
) -> SyncUpResult {
    // Check if this file was originally synced down (has xattrs)
    let existing_rev_id =
        xattr_get(file_path, "user.hai.rev_id").and_then(|bytes| String::from_utf8(bytes).ok());
    let existing_entry_id =
        xattr_get(file_path, "user.hai.entry_id").and_then(|bytes| String::from_utf8(bytes).ok());
    let existing_hash =
        xattr_get(file_path, "user.hai.hash").and_then(|bytes| String::from_utf8(bytes).ok());
    // Check for decrypted_hash first (indicates file was decrypted during sync-down)
    let existing_decrypted_hash = xattr_get(file_path, "user.hai.decrypted_hash")
        .and_then(|bytes| String::from_utf8(bytes).ok());

    let is_previously_synced = existing_rev_id.is_some();

    // If not previously synced and we're not syncing new files, skip
    if !is_previously_synced && !sync_new_files {
        if debug {
            let _ = config::write_to_debug_log(format!(
                "sync_up: skipping new file '{}' (sync_new_files=false)\n",
                file_path
            ));
        }
        return SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: SyncUpAction::SkippedNew,
            success: true,
            error: None,
        };
    }

    // Calculate current file hash
    let current_hash = match calculate_file_hash(file_path).await {
        Ok(hash) => hex::encode(hash),
        Err(e) => {
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Failed to calculate hash: {}", e)),
            };
        }
    };

    // Compare with existing hash to determine if changed
    // Use decrypted_hash if available (for files that were encrypted on server)
    let hash_to_compare = existing_decrypted_hash.as_ref().or(existing_hash.as_ref());

    if let Some(existing) = hash_to_compare {
        if current_hash.eq_ignore_ascii_case(existing) {
            if debug {
                let _ = config::write_to_debug_log(format!(
                    "sync_up: skipping unchanged file '{}'\n",
                    file_path
                ));
            }
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: true,
                error: None,
            };
        }
    }

    // Read file contents
    let file_contents = match tokio::fs::read(file_path).await {
        Ok(contents) => contents,
        Err(e) => {
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Failed to read file: {}", e)),
            };
        }
    };

    let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
        asset_blob_cache.clone(),
        asset_keyring.clone(),
        api_client.clone(),
        Some(&KeyRecipient::User(username.to_string())),
        &asset_name,
        false,
    )
    .await
    {
        Ok(akm_info) => akm_info,
        Err(e) => {
            match e {
                asset_crypt::AkmSelectionError::Abort(msg) => {
                    eprintln!("error: {}", msg);
                }
            }
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Decryption key error")),
            };
        }
    };

    // Build asset_entry_ref if we have both entry_id and rev_id (for replace/fork)
    let asset_entry_ref = match (&existing_entry_id, &existing_rev_id) {
        (Some(entry_id), Some(rev_id)) => Some((entry_id.clone(), rev_id.clone())),
        _ => None,
    };

    let is_update = asset_entry_ref.is_some();
    if debug {
        if is_update {
            let _ = config::write_to_debug_log(format!(
                "sync_up: updating '{}' -> '{}' (entry_id: {:?}, rev_id: {:?})\n",
                file_path, asset_name, existing_entry_id, existing_rev_id
            ));
        } else {
            let _ = config::write_to_debug_log(format!(
                "sync_up: creating '{}' -> '{}'\n",
                file_path, asset_name
            ));
        }
    }

    // Send update through the async writer channel
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    let send_result = update_asset_tx
        .send(WorkerAssetMsg::Update(WorkerAssetUpdate {
            asset_name: asset_name.to_string(),
            asset_entry_ref,
            new_contents: file_contents,
            is_push: false,
            api_client: api_client.clone(),
            one_shot: true,
            akm_info,
            reply_channel: Some(reply_tx),
        }))
        .await;

    if let Err(e) = send_result {
        return SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: if is_update {
                SyncUpAction::Updated
            } else {
                SyncUpAction::Created
            },
            success: false,
            error: Some(format!("Failed to send update: {}", e)),
        };
    }

    // Wait for reply
    match reply_rx.await {
        Ok(Ok(asset_entry)) => {
            // Update xattrs with new entry info
            let _ = xattr_set(file_path, "user.hai.rev_id", &asset_entry.asset.rev_id);
            let _ = xattr_set(file_path, "user.hai.entry_id", &asset_entry.entry_id);
            if let Some(hash) = &asset_entry.asset.hash {
                update_hash_xattrs(file_path, hash);
            }
            let _ = xattr_set(
                file_path,
                "user.hai.seq_id",
                &asset_entry.seq_id.to_string(),
            );

            SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: if is_update {
                    SyncUpAction::Updated
                } else {
                    SyncUpAction::Created
                },
                success: true,
                error: None,
            }
        }
        Ok(Err(e)) => SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: if is_update {
                SyncUpAction::Updated
            } else {
                SyncUpAction::Created
            },
            success: false,
            error: Some(format!("Asset save error: {:?}", e)),
        },
        Err(e) => SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: if is_update {
                SyncUpAction::Updated
            } else {
                SyncUpAction::Created
            },
            success: false,
            error: Some(format!("Reply channel error: {}", e)),
        },
    }
}

/// Syncs a single metadata file up to the remote server.
async fn sync_up_metadata_file(
    api_client: &HaiClient,
    file_path: &str,
    asset_name: &str,
    sync_new_files: bool,
    debug: bool,
) -> SyncUpResult {
    // Check if this metadata file was originally synced down
    let is_metadata = xattr_get(file_path, "user.hai.is_metadata")
        .map(|bytes| String::from_utf8(bytes).ok())
        .flatten()
        .map(|s| s == "true")
        .unwrap_or(false);
    let existing_hash =
        xattr_get(file_path, "user.hai.hash").and_then(|bytes| String::from_utf8(bytes).ok());

    let is_previously_synced = is_metadata && existing_hash.is_some();

    // If not previously synced and we're not syncing new files, skip
    if !is_previously_synced && !sync_new_files {
        if debug {
            let _ = config::write_to_debug_log(format!(
                "sync_up: skipping new metadata file '{}' (sync_new_files=false)\n",
                file_path
            ));
        }
        return SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: SyncUpAction::SkippedNew,
            success: true,
            error: None,
        };
    }

    // Calculate current file hash
    let current_hash = match calculate_file_hash(file_path).await {
        Ok(hash) => hex::encode(hash),
        Err(e) => {
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Failed to calculate hash: {}", e)),
            };
        }
    };

    // Compare with existing hash
    if let Some(existing) = &existing_hash {
        if current_hash.eq_ignore_ascii_case(existing) {
            if debug {
                let _ = config::write_to_debug_log(format!(
                    "sync_up: skipping unchanged metadata file '{}'\n",
                    file_path
                ));
            }
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: true,
                error: None,
            };
        }
    }

    // Read file contents
    let file_contents = match tokio::fs::read(file_path).await {
        Ok(contents) => contents,
        Err(e) => {
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Failed to read file: {}", e)),
            };
        }
    };

    if debug {
        let _ = config::write_to_debug_log(format!(
            "sync_up: uploading metadata '{}' -> '{}'\n",
            file_path, asset_name
        ));
    }

    let metadata_contents = match serde_json::from_slice(&file_contents) {
        Ok(json) => json,
        Err(e) => {
            return SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action: SyncUpAction::Skipped,
                success: false,
                error: Some(format!("Failed to parse metadata JSON: {}", e)),
            };
        }
    };

    // Metadata always uses put with override
    match api_client
        .asset_metadata_put(AssetMetadataPutArg {
            name: asset_name.to_string(),
            data: metadata_contents,
            conflict_policy: PutConflictPolicy::Override,
        })
        .await
    {
        Ok(result) => {
            // Update xattrs
            let _ = xattr_set(file_path, "user.hai.is_metadata", "true");
            if let Some(md) = result.entry.metadata {
                if let Some(hash) = md.hash {
                    update_hash_xattrs(file_path, &hash);
                }
                let _ = xattr_set(file_path, "user.hai.rev_id", &md.rev_id);
            }

            let action = if is_previously_synced {
                SyncUpAction::Updated
            } else {
                SyncUpAction::Created
            };

            SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: asset_name.to_string(),
                action,
                success: true,
                error: None,
            }
        }
        Err(e) => SyncUpResult {
            file_path: file_path.to_string(),
            asset_name: asset_name.to_string(),
            action: if is_previously_synced {
                SyncUpAction::Updated
            } else {
                SyncUpAction::Created
            },
            success: false,
            error: Some(format!("API error: {}", e)),
        },
    }
}

/// Updates hash-related xattrs after successful upload
fn update_hash_xattrs(file_path: &str, hash: &str) {
    let _ = xattr_set(file_path, "user.hai.hash", hash);

    // Update mtime
    if let Ok(metadata) = std::fs::metadata(file_path) {
        if let Ok(modified_time) = metadata.modified() {
            let mtime_ts = modified_time
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            let _ = xattr_set(file_path, "user.hai.hash_mtime", &mtime_ts.to_string());
        }
    }
}

/// Syncs a moved file up to the remote server.
///
/// Detects that a file was moved locally (via xattr asset_name mismatch),
/// performs the remote move, and then optionally syncs content if it also changed.
async fn sync_up_move(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<WorkerAssetMsg>,
    file_path: &str,
    old_asset_name: &str,
    new_asset_name: &str,
    debug: bool,
) -> Vec<SyncUpResult> {
    if debug {
        let _ = config::write_to_debug_log(format!(
            "sync_up_move: moving '{}' -> '{}' (file: '{}')\n",
            old_asset_name, new_asset_name, file_path
        ));
    }

    use crate::api::types::asset::AssetMoveArg;

    // Perform the remote move
    let move_result = api_client
        .asset_move(AssetMoveArg {
            source_name: old_asset_name.to_string(),
            target_name: new_asset_name.to_string(),
        })
        .await;

    match move_result {
        Ok(result) => {
            // Update xattrs with new move result
            let _ = xattr_set(file_path, "user.hai.asset_name", new_asset_name);
            let _ = xattr_set(file_path, "user.hai.rev_id", &result.entry.asset.rev_id);
            let _ = xattr_set(file_path, "user.hai.entry_id", &result.entry.entry_id);
            let _ = xattr_set(
                file_path,
                "user.hai.seq_id",
                &result.entry.seq_id.to_string(),
            );
            if let Some(hash) = &result.entry.asset.hash {
                update_hash_xattrs(file_path, hash);
            }

            let mut results = vec![SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: new_asset_name.to_string(),
                action: SyncUpAction::Moved,
                success: true,
                error: None,
            }];

            // Now check if the content also changed since last sync
            let existing_hash = xattr_get(file_path, "user.hai.hash")
                .and_then(|bytes| String::from_utf8(bytes).ok());
            let existing_decrypted_hash = xattr_get(file_path, "user.hai.decrypted_hash")
                .and_then(|bytes| String::from_utf8(bytes).ok());
            let hash_to_compare = existing_decrypted_hash.as_ref().or(existing_hash.as_ref());

            let current_hash = match calculate_file_hash(file_path).await {
                Ok(hash) => Some(hex::encode(hash)),
                Err(_) => None,
            };

            let content_changed = match (&current_hash, hash_to_compare) {
                (Some(current), Some(existing)) => !current.eq_ignore_ascii_case(existing),
                _ => true,
            };

            if content_changed {
                if debug {
                    let _ = config::write_to_debug_log(format!(
                        "sync_up_move: content also changed for '{}', syncing data\n",
                        file_path
                    ));
                }

                let data_result = sync_up_data_file(
                    asset_blob_cache,
                    asset_keyring,
                    api_client,
                    username,
                    update_asset_tx,
                    file_path,
                    new_asset_name,
                    false,
                    debug,
                )
                .await;

                results.push(data_result);
            }

            results
        }
        Err(e) => {
            eprintln!(
                "Failed to move asset '{}' -> '{}': {}",
                old_asset_name, new_asset_name, e
            );

            vec![SyncUpResult {
                file_path: file_path.to_string(),
                asset_name: new_asset_name.to_string(),
                action: SyncUpAction::Moved,
                success: false,
                error: Some(format!("Failed to move asset: {}", e)),
            }]
        }
    }
}

#[allow(dead_code)]
/// Inner function to sync specific file/asset pairs.
/// Useful when you already know which files need to be synced.
pub async fn sync_up_pairs(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<WorkerAssetMsg>,
    pairs: Vec<(String, String)>, // (file_path, asset_name)
    options: SyncUpOptions,
) -> Result<Vec<SyncUpResult>, String> {
    let semaphore = Arc::new(Semaphore::new(options.max_concurrent_uploads));
    let mut handles = Vec::new();

    for (file_path, asset_name) in pairs {
        let asset_blob_cache_clone = asset_blob_cache.clone();
        let asset_keyring_clone = asset_keyring.clone();
        let api_client_clone = api_client.clone();
        let username_clone = username.to_string();
        let update_asset_tx_clone = update_asset_tx.clone();
        let sem_clone = Arc::clone(&semaphore);
        let debug = options.debug;
        let sync_new_files = options.sync_new_files;

        // Determine if this is a metadata file based on file path
        let is_metadata = file_path.ends_with(METADATA_EXTENSION);

        let handle = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();

            if is_metadata {
                sync_up_metadata_file(
                    &api_client_clone,
                    &file_path,
                    &asset_name,
                    sync_new_files,
                    debug,
                )
                .await
            } else {
                sync_up_data_file(
                    asset_blob_cache_clone,
                    asset_keyring_clone,
                    &api_client_clone,
                    &username_clone,
                    update_asset_tx_clone,
                    &file_path,
                    &asset_name,
                    sync_new_files,
                    debug,
                )
                .await
            }
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in join_all(handles).await {
        match handle {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("A sync task panicked: {}", e);
            }
        }
    }

    Ok(results)
}
