use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::asset_reader;

/// Returns true if `hash` is a well-formed SHA-256 hex digest.
///
/// It's important to validate the hash since it's used to construct a path
/// inside the cache directory. Without this check, an attacker can maliciously
/// provide a hash that escapes the cache directory.
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub struct AssetBlobCache {
    cache_dir: PathBuf,
    /// Tracks {hashes} being downloaded
    in_flight: Arc<Mutex<HashSet<String>>>,
    /// Serialize evictions since underlying alg doesn't support concurrency.
    evict_lock: Arc<Mutex<()>>,
    disable_cache: bool,
    max_cache_size_bytes: Option<u64>, // None = unlimited
}

impl AssetBlobCache {
    /// Create a new AssetBlobCache.
    ///
    /// # Arguments
    /// * `cache_dir` - The directory to use for caching assets.
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            evict_lock: Arc::new(Mutex::new(())),
            disable_cache: false,
            max_cache_size_bytes: None,
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

    /// Get or download an asset.
    ///
    /// Download and validation is done in memory.
    ///
    /// # Arguments
    /// * `url` - The URL of the asset to download
    /// * `hash` - The SHA256 hash of the asset
    pub async fn get_or_download(
        &self,
        url: &str,
        hash: &str,
    ) -> Result<Vec<u8>, DownloadAssetError> {
        if !is_valid_hash(hash) {
            return Err(DownloadAssetError::HashMismatch);
        }

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
                tracing::debug!(%hash, "cache hit");
                return Ok(data);
            }

            tracing::debug!(%hash, "cache miss");

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
        if !is_valid_hash(hash) {
            return Err(DownloadAssetError::HashMismatch);
        }

        // Fast path: cache disabled, just download directly
        if self.disable_cache {
            return download_and_verify_to_path(url, hash, dest_path).await;
        }

        loop {
            // Fast path: check cache without lock
            let cache_path = self.cache_dir.join(hash);
            if self.is_in_cache(hash).await {
                tracing::debug!(%hash, "cache hit");
                // Copy from cache to destination
                let dest = dest_path.to_path_buf();
                let cache = cache_path.clone();
                let copied = tokio::task::spawn_blocking(move || {
                    std::fs::copy(&cache, &dest)?;
                    // Touch the cache file to mark as recently accessed
                    filetime::set_file_mtime(&cache, filetime::FileTime::now()).ok();
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| DownloadAssetError::FsFailed)?;

                match copied {
                    Ok(()) => return Ok(()),
                    // TOCTOU: eviction removed the entry between the check and
                    // the copy. That is a cache miss, not a failure.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!(%hash, "cache entry vanished after check; retrying");
                        continue;
                    }
                    Err(_) => return Err(DownloadAssetError::FsFailed),
                }
            }

            tracing::debug!(%hash, "cache miss");

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
        if !is_valid_hash(hash) {
            return Err(DownloadAssetError::HashMismatch);
        }

        // Fast path: cache disabled, just download
        if self.disable_cache {
            download_and_verify_to_path(url, hash, temp_file.path()).await?;
            return Ok(temp_file);
        }

        loop {
            // Fast path: check cache without lock
            let cache_path = self.cache_dir.join(hash);
            if self.is_in_cache(hash).await {
                tracing::debug!(%hash, "cache hit");
                // Copy from cache to temp file
                let dest = temp_file.path().to_path_buf();
                let cache = cache_path.clone();
                let copied = tokio::task::spawn_blocking(move || {
                    std::fs::copy(&cache, &dest)?;
                    filetime::set_file_mtime(&cache, filetime::FileTime::now()).ok();
                    Ok::<_, std::io::Error>(())
                })
                .await
                .map_err(|_| DownloadAssetError::FsFailed)?;

                match copied {
                    Ok(()) => return Ok(temp_file),
                    // TOCTOU: eviction removed the entry between the check and
                    // the copy. That is a cache miss, not a failure.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!(%hash, "cache entry vanished after check; retrying");
                        continue;
                    }
                    Err(_) => return Err(DownloadAssetError::FsFailed),
                }
            }

            tracing::debug!(%hash, "cache miss");

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
        let hash = hash.to_string();

        tokio::task::spawn_blocking(move || verify_sha256_of_file(&hash, &path).unwrap_or(false))
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
        if !is_valid_hash(hash) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid cache hash",
            ));
        }
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
        use std::io::ErrorKind;
        use std::time::SystemTime;

        const MAX_FILES: usize = 100;

        let max_size = match self.max_cache_size_bytes {
            Some(size) => size,
            None => return Ok(()),
        };

        // Only one pass at a time. If another is already running it will
        // observe whatever we just wrote, so skipping is always safe.
        let _guard = match self.evict_lock.try_lock() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };

        let cache_dir = self.cache_dir.clone();

        tokio::task::spawn_blocking(move || {
            let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();

            for entry in std::fs::read_dir(&cache_dir)? {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let path = entry.path();

                if path.extension().and_then(|s| s.to_str()) == Some("tmp") {
                    continue;
                }

                // Single stat, and the file is allowed to vanish underneath us.
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                if !metadata.is_file() {
                    continue;
                }

                let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                files.push((path, metadata.len(), mtime));
            }

            let mut current_size: u64 = files.iter().map(|(_, s, _)| *s).sum();
            let mut current_count = files.len();

            if current_size <= max_size && current_count <= MAX_FILES {
                return Ok(());
            }

            files.sort_by_key(|(_, _, mtime)| *mtime);

            let mut evicted = 0usize;
            for (path, size, _) in files {
                if current_size <= max_size && current_count <= MAX_FILES {
                    break;
                }
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        current_size = current_size.saturating_sub(size);
                        current_count -= 1;
                        evicted += 1;
                    }
                    // Someone beat us to it: the space really is freed.
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        current_size = current_size.saturating_sub(size);
                        current_count -= 1;
                    }
                    Err(e) => {
                        tracing::warn!(?path, error = %e, "failed to evict cache file");
                    }
                }
            }

            if evicted > 0 {
                tracing::info!(
                    evicted,
                    max_files = MAX_FILES,
                    max_bytes = max_size,
                    "evicted cache files"
                );
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
    let resp = match reqwest::get(url).await {
        Ok(resp) => resp,
        Err(_) => {
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::Unexpected,
            ));
        }
    };

    if !resp.status().is_success() {
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::RateLimited,
            ));
        } else {
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::Unexpected,
            ));
        }
    }

    let mut file = tokio::fs::File::create(dest_path)
        .await
        .map_err(|_| DownloadAssetError::FsFailed)?;

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.try_next().await.map_err(|_| {
        DownloadAssetError::DataFetchFailed(asset_reader::DataFetchFailure::Unexpected)
    })? {
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
    FsFailed,
    HashMismatch,
    DataFetchFailed(asset_reader::DataFetchFailure),
}

impl ::std::fmt::Display for DownloadAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadAssetError::FsFailed => write!(f, "Filesystem operation failed"),
            DownloadAssetError::HashMismatch => write!(f, "Asset hash mismatch"),
            DownloadAssetError::DataFetchFailed(failure) => {
                write!(f, "Failed to fetch asset data: {}", failure)
            }
        }
    }
}

impl ::std::fmt::Debug for DownloadAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadAssetError::FsFailed => write!(f, "DownloadAssetError::FsFailed"),
            DownloadAssetError::HashMismatch => write!(f, "DownloadAssetError::HashMismatch"),
            DownloadAssetError::DataFetchFailed(failure) => {
                write!(f, "DownloadAssetError::DataFetchFailed({})", failure)
            }
        }
    }
}

/// Downloads an asset to memory.
pub async fn download_asset(url: &str) -> Result<Vec<u8>, DownloadAssetError> {
    let asset_get_resp = match reqwest::get(url).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("error: {}", e);
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::Unexpected,
            ));
        }
    };
    if !asset_get_resp.status().is_success() {
        eprintln!("error: failed to fetch asset: {}", asset_get_resp.status());
        if asset_get_resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::RateLimited,
            ));
        } else {
            return Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::Unexpected,
            ));
        }
    }
    match asset_get_resp.bytes().await {
        Ok(contents) => Ok(contents.to_vec()),
        Err(e) => {
            eprintln!("error: failed to fetch asset: {}", e);
            Err(DownloadAssetError::DataFetchFailed(
                asset_reader::DataFetchFailure::Unexpected,
            ))
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

/// Streams `path` through SHA-256 and compares against `hash`.
/// Peak memory is one buffer, regardless of file size.
fn verify_sha256_of_file(hash: &str, path: &Path) -> std::io::Result<bool> {
    let (hash_str, _hash_bytes) = compute_sha256_of_file(path)?;
    Ok(hash_str == hash)
}

pub fn compute_sha256_of_file(path: &Path) -> std::io::Result<(String, Vec<u8>)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];

    loop {
        let bytes_read = file.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok((format!("{:x}", hash), hash.to_vec()))
}
