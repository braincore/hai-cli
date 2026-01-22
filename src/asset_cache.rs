use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::config::write_to_debug_log;

pub struct AssetBlobCache {
    cache_dir: PathBuf,
    in_flight: Arc<Mutex<HashSet<String>>>, // tracks hashes being downloaded
    disable_cache: bool,
    max_cache_size_bytes: Option<u64>, // None = unlimited
    debug: bool,
}

impl AssetBlobCache {
    /// Create a new AssetBlobCache
    ///
    /// # Arguments
    /// * `cache_dir` - The directory to use for caching assets.
    /// * `debug` - If true, logs cache hits & misses.
    pub fn new(cache_dir: PathBuf, debug: bool) -> Self {
        Self {
            cache_dir,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            disable_cache: false,
            max_cache_size_bytes: None,
            debug,
        }
    }

    /// Disable caching. When disabled, assets will always be downloaded fresh.
    pub fn with_cache_disabled(mut self, disable: bool) -> Self {
        self.disable_cache = disable;
        self
    }

    /// Set maximum cache size in bytes. When exceeded, LRU eviction kicks in.
    pub fn with_max_size(mut self, max_bytes: u64) -> Self {
        self.max_cache_size_bytes = Some(max_bytes);
        self
    }

    /// Get or download an asset, returning the data as a Vec<u8>
    ///
    /// # Arguments
    /// * `url` - The URL of the asset to download
    /// * `hash` - The SHA256 hash of the asset
    pub async fn get_or_download(
        &self,
        url: &str,
        hash: &str,
    ) -> Result<Vec<u8>, DownloadAssetError> {
        // Fast path: cache disabled, just download
        if self.disable_cache {
            return download_and_verify(url, hash).await;
        }

        loop {
            // Fast path: check cache without lock
            if let Some(data) = self
                .try_read_cache(hash)
                .await
                .map_err(|_e| DownloadAssetError::FsFailed)?
            {
                if self.debug {
                    let _ = write_to_debug_log(format!("cache hit for hash {}", hash));
                }
                return Ok(data);
            }
            if self.debug {
                let _ = write_to_debug_log(format!("cache miss for hash {}", hash));
            }

            // Slow path: ensure only one download per hash
            let mut in_flight = self.in_flight.lock().await;

            // Check again in case another task just finished
            if let Some(data) = self
                .try_read_cache(hash)
                .await
                .map_err(|_e| DownloadAssetError::FsFailed)?
            {
                return Ok(data);
            }

            // Not in cache, download.
            if in_flight.insert(hash.to_string()) {
                drop(in_flight); // Release lock during download

                let result = async {
                    let data = download_asset(url).await?;
                    if !verify_sha256_in_memory(hash, &data) {
                        return Err(DownloadAssetError::HashMismatch);
                    }
                    self.write_cache(hash, &data)
                        .await
                        .map_err(|_e| DownloadAssetError::FsFailed)?;

                    // Evict if needed (do this after write completes)
                    if let Err(e) = self.evict_if_needed().await {
                        eprintln!("warning: cache eviction failed: {:?}", e);
                    }

                    Ok(data)
                }
                .await;

                // Remove from in-flight
                self.in_flight.lock().await.remove(hash);

                return result;
            }

            // Another task is downloading, wait and retry
            drop(in_flight);
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Loop will retry
        }
    }

    /// Get or download an asset to a file path (e.g., from tempfile)
    ///
    /// If cached, copies from cache to the destination path.
    /// If not cached, downloads to destination and adds to cache.
    ///
    /// # Arguments
    /// * `url` - The URL of the asset to download
    /// * `hash` - The SHA256 hash of the asset
    /// * `dest_path` - The destination file path (e.g., from NamedTempFile::path())
    pub async fn get_or_download_to_path(
        &self,
        url: &str,
        hash: &str,
        dest_path: &Path,
    ) -> Result<(), DownloadAssetError> {
        // Fast path: cache disabled, just download directly
        if self.disable_cache {
            return download_and_verify_to_path(url, hash, dest_path).await;
        }

        loop {
            // Fast path: check cache without lock
            let cache_path = self.cache_dir.join(hash);
            if self.is_in_cache(hash).await {
                if self.debug {
                    let _ = write_to_debug_log(format!("cache hit for hash {}", hash));
                }
                // Copy from cache to destination
                let dest = dest_path.to_path_buf();
                let cache = cache_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::copy(&cache, &dest)?;
                    // Touch the cache file to mark as recently accessed
                    filetime::set_file_mtime(&cache, filetime::FileTime::now()).ok();
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| DownloadAssetError::FsFailed)?
                .map_err(|_| DownloadAssetError::FsFailed)?;

                return Ok(());
            }

            if self.debug {
                let _ = write_to_debug_log(format!("cache miss for hash {}", hash));
            }

            // Slow path: ensure only one download per hash
            let mut in_flight = self.in_flight.lock().await;

            // Check again in case another task just finished
            if self.is_in_cache(hash).await {
                drop(in_flight);
                continue; // Retry from the top to copy from cache
            }

            // Not in cache, download.
            if in_flight.insert(hash.to_string()) {
                drop(in_flight); // Release lock during download

                let result = async {
                    // Download directly to destination (hashes while streaming)
                    download_and_verify_to_path(url, hash, dest_path).await?;

                    // Copy to cache (streaming copy)
                    let dest = dest_path.to_path_buf();
                    let cache = cache_path.clone();
                    tokio::task::spawn_blocking(move || std::fs::copy(&dest, &cache))
                        .await
                        .map_err(|_| DownloadAssetError::FsFailed)?
                        .map_err(|_| DownloadAssetError::FsFailed)?;

                    // Evict if needed
                    if let Err(e) = self.evict_if_needed().await {
                        eprintln!("warning: cache eviction failed: {:?}", e);
                    }

                    Ok(())
                }
                .await;

                // Remove from in-flight
                self.in_flight.lock().await.remove(hash);

                return result;
            }

            // Another task is downloading, wait and retry
            drop(in_flight);
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Loop will retry
        }
    }

    /// Get or download an asset to a NamedTempFile
    ///
    /// Takes ownership of the temp file, writes to it, and returns it.
    ///
    /// # Arguments
    /// * `url` - The URL of the asset to download
    /// * `hash` - The SHA256 hash of the asset
    /// * `temp_file` - The NamedTempFile to write to
    pub async fn get_or_download_to_tempfile(
        &self,
        url: &str,
        hash: &str,
        temp_file: tempfile::NamedTempFile,
    ) -> Result<tempfile::NamedTempFile, DownloadAssetError> {
        // Fast path: cache disabled, just download
        if self.disable_cache {
            download_and_verify_to_path(url, hash, temp_file.path()).await?;
            return Ok(temp_file);
        }

        loop {
            // Fast path: check cache without lock
            let cache_path = self.cache_dir.join(hash);
            if self.is_in_cache(hash).await {
                if self.debug {
                    let _ = write_to_debug_log(format!("cache hit for hash {}", hash));
                }
                // Copy from cache to temp file
                let dest = temp_file.path().to_path_buf();
                let cache = cache_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::copy(&cache, &dest)?;
                    filetime::set_file_mtime(&cache, filetime::FileTime::now()).ok();
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| DownloadAssetError::FsFailed)?
                .map_err(|_| DownloadAssetError::FsFailed)?;

                return Ok(temp_file);
            }

            if self.debug {
                let _ = write_to_debug_log(format!("cache miss for hash {}", hash));
            }

            // Slow path: ensure only one download per hash
            let mut in_flight = self.in_flight.lock().await;

            // Check again in case another task just finished
            if self.is_in_cache(hash).await {
                drop(in_flight);
                continue; // Retry from the top to copy from cache
            }

            // Not in cache, download.
            if in_flight.insert(hash.to_string()) {
                drop(in_flight); // Release lock during download

                let result = async {
                    // Download directly to temp file (hashes while streaming)
                    download_and_verify_to_path(url, hash, temp_file.path()).await?;

                    // Copy to cache (streaming copy)
                    let source = temp_file.path().to_path_buf();
                    let cache = cache_path.clone();
                    tokio::task::spawn_blocking(move || std::fs::copy(&source, &cache))
                        .await
                        .map_err(|_| DownloadAssetError::FsFailed)?
                        .map_err(|_| DownloadAssetError::FsFailed)?;

                    // Evict if needed
                    if let Err(e) = self.evict_if_needed().await {
                        eprintln!("warning: cache eviction failed: {:?}", e);
                    }

                    Ok(temp_file)
                }
                .await;

                // Remove from in-flight
                self.in_flight.lock().await.remove(hash);

                return result;
            }

            // Another task is downloading, wait and retry
            drop(in_flight);
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Loop will retry
        }
    }

    async fn is_in_cache(&self, hash: &str) -> bool {
        let path = self.cache_dir.join(hash);
        let hash_clone = hash.to_string();

        tokio::task::spawn_blocking(move || {
            if !path.exists() {
                return false;
            }
            // Verify the cached file isn't corrupted
            match std::fs::read(&path) {
                Ok(data) => verify_sha256_in_memory(&hash_clone, &data),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn try_read_cache(&self, hash: &str) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.cache_dir.join(hash);
        let hash_clone = hash.to_string();
        tokio::task::spawn_blocking(move || {
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            if !verify_sha256_in_memory(&hash_clone, &data) {
                // Verify file isn't corrupted
                std::fs::remove_file(&path).ok();
                return Ok(None);
            }
            // Touch the file to mark as recently accessed
            filetime::set_file_mtime(&path, filetime::FileTime::now()).ok();
            Ok(Some(data))
        })
        .await?
    }

    /// Store contents in the cache with the hash key.
    ///
    /// # Arguments
    /// * `hash` - The SHA256 hash of the contents
    /// * `data` - The data to cache
    ///
    /// # Returns
    /// A result indicating success or failure
    pub async fn write_cache(&self, hash: &str, data: &[u8]) -> std::io::Result<()> {
        let path = self.cache_dir.join(hash);
        let data = data.to_vec();
        let hash_clone = hash.to_string();

        tokio::task::spawn_blocking(move || {
            // Atomic write: write to temp file with unique name, then rename
            let random_suffix: u32 = rand::random();
            let temp_filename = format!("{}.{:08x}.tmp", hash_clone, random_suffix);
            let temp_path = path.with_file_name(temp_filename);

            std::fs::write(&temp_path, &data)?;
            std::fs::rename(&temp_path, &path)?; // Atomic on POSIX
            Ok(())
        })
        .await?
    }

    async fn evict_if_needed(&self) -> std::io::Result<()> {
        const MAX_FILES: usize = 100;

        let max_size = match self.max_cache_size_bytes {
            Some(size) => size,
            None => return Ok(()), // No limit set
        };

        let cache_dir = self.cache_dir.clone();
        let debug = self.debug;

        tokio::task::spawn_blocking(move || {
            // Collect all cache files with their metadata
            let entries = std::fs::read_dir(&cache_dir)?;
            let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();

            for entry in entries {
                let entry = entry?;
                let path = entry.path();

                // Skip temp files and directories
                if path.extension().and_then(|s| s.to_str()) == Some("tmp") {
                    continue;
                }
                if !path.is_file() {
                    continue;
                }

                let metadata = entry.metadata()?;
                let size = metadata.len();
                let mtime = metadata.modified()?;

                files.push((path, size, mtime));
            }

            // Calculate total size and count
            let total_size: u64 = files.iter().map(|(_, size, _)| size).sum();
            let file_count = files.len();

            // Check if we're under both limits
            if total_size <= max_size && file_count <= MAX_FILES {
                return Ok(()); // Under both limits, nothing to do
            }

            // Sort by mtime (oldest first)
            files.sort_by_key(|(_, _, mtime)| *mtime);

            // Evict oldest files until under BOTH limits
            let mut current_size = total_size;
            let mut current_count = file_count;
            let mut evicted_count = 0;

            for (path, size, _) in files {
                // Stop if we're under both limits
                if current_size <= max_size && current_count <= MAX_FILES {
                    break;
                }

                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!("warning: failed to evict cache file {:?}: {}", path, e);
                } else {
                    current_size -= size;
                    current_count -= 1;
                    evicted_count += 1;
                }
            }

            if debug && evicted_count > 0 {
                let _ = crate::config::write_to_debug_log(format!(
                    "info: evicted {} cache files (limits: {} files, {} bytes)\n",
                    evicted_count, MAX_FILES, max_size
                ));
            }

            Ok(())
        })
        .await?
    }
}

// --

async fn download_and_verify(url: &str, hash: &str) -> Result<Vec<u8>, DownloadAssetError> {
    let data = download_asset(url).await?;
    if !verify_sha256_in_memory(hash, &data) {
        eprintln!("error: hash mismatch for {}", url);
        return Err(DownloadAssetError::HashMismatch);
    }
    Ok(data)
}

/// Downloads in chunks to a specified file path, verifying hash after
/// download.
///
/// NOTE: Safe to use with large assets.
pub async fn download_and_verify_to_path(
    url: &str,
    hash: &str,
    dest_path: &Path,
) -> Result<(), DownloadAssetError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|_| DownloadAssetError::DataFetchFailed)?;

    if !resp.status().is_success() {
        return Err(DownloadAssetError::DataFetchFailed);
    }

    let mut file = tokio::fs::File::create(dest_path)
        .await
        .map_err(|_| DownloadAssetError::FsFailed)?;

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|_| DownloadAssetError::DataFetchFailed)?
    {
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| DownloadAssetError::FsFailed)?;
    }

    file.flush()
        .await
        .map_err(|_| DownloadAssetError::FsFailed)?;

    let computed = format!("{:x}", hasher.finalize());
    if computed != hash {
        let _ = tokio::fs::remove_file(dest_path).await;
        return Err(DownloadAssetError::HashMismatch);
    }

    Ok(())
}

// --

pub enum DownloadAssetError {
    DataFetchFailed,
    FsFailed,
    HashMismatch,
}

impl ::std::fmt::Display for DownloadAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadAssetError::DataFetchFailed => write!(f, "Failed to fetch asset data"),
            DownloadAssetError::FsFailed => write!(f, "Filesystem operation failed"),
            DownloadAssetError::HashMismatch => write!(f, "Asset hash mismatch"),
        }
    }
}

impl ::std::fmt::Debug for DownloadAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadAssetError::DataFetchFailed => write!(f, "DownloadAssetError::DataFetchFailed"),
            DownloadAssetError::FsFailed => write!(f, "DownloadAssetError::FsFailed"),
            DownloadAssetError::HashMismatch => write!(f, "DownloadAssetError::HashMismatch"),
        }
    }
}

/// Downloads an asset to memory.
pub async fn download_asset(url: &str) -> Result<Vec<u8>, DownloadAssetError> {
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
    match asset_get_resp.bytes().await {
        Ok(contents) => Ok(contents.to_vec()),
        Err(e) => {
            eprintln!("error: failed to fetch asset: {}", e);
            Err(DownloadAssetError::DataFetchFailed)
        }
    }
}

/// WARNING: Since it's all in memory, don't use it for large data.
fn verify_sha256_in_memory(hash: &str, contents: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    let computed_hash = format!("{:x}", hasher.finalize());
    computed_hash == hash
}

/// WARNING: Since it's all in memory, don't use it for large data.
pub fn compute_sha256_in_memory(contents: &[u8]) -> (String, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    let hash = hasher.finalize();
    (format!("{:x}", hash), hash.to_vec())
}

#[allow(dead_code)]
pub async fn verify_sha256_from_file(hash: &str, path: &Path) -> Result<bool, std::io::Error> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = format!("{:x}", hasher.finalize());
    Ok(computed_hash == hash)
}

#[allow(dead_code)]
pub async fn compute_sha256_from_file(path: &Path) -> Result<(String, Vec<u8>), std::io::Error> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok((format!("{:x}", hash), hash.to_vec()))
}
