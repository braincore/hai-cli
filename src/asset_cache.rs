use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use sha2::{Digest, Sha256};

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
            return self.download_and_verify(url, hash).await;
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
                    if !verify_sha256(hash, &data) {
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

    async fn download_and_verify(
        &self,
        url: &str,
        hash: &str,
    ) -> Result<Vec<u8>, DownloadAssetError> {
        let data = download_asset(url).await?;
        if !verify_sha256(hash, &data) {
            eprintln!("error: hash mismatch for {}", url);
            return Err(DownloadAssetError::HashMismatch);
        }
        Ok(data)
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
            if !verify_sha256(&hash_clone, &data) {
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
                eprintln!(
                    "info: evicted {} cache files (limits: {} files, {} bytes)",
                    evicted_count, MAX_FILES, max_size
                );
            }

            Ok(())
        })
        .await?
    }
}

pub enum DownloadAssetError {
    DataFetchFailed,
    FsFailed,
    HashMismatch,
}

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

fn verify_sha256(hash: &str, contents: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    let computed_hash = format!("{:x}", hasher.finalize());
    computed_hash == hash
}

pub fn compute_sha256(contents: &[u8]) -> (String, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    let hash = hasher.finalize();
    (format!("{:x}", hash), hash.to_vec())
}
