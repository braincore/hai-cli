use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::asset_reader;

pub struct AssetBlobCache {
    cache_dir: PathBuf,
    /// Per-hash single-flight locks for in-progress downloads.
    locks: Arc<KeyedLocks>,
    /// Serialize evictions since underlying alg doesn't support concurrency.
    evict_lock: Arc<Mutex<()>>,
    disable_cache: bool,
    max_cache_size_bytes: Option<u64>, // None = unlimited
    /// HACK: Memory-leak cache (no eviction) for a few rare cases (signature
    /// verification key). Will refactor in the future likely to a separate
    /// cache.
    entry_cache: Arc<Mutex<HashMap<String, crate::api::types::asset::AssetEntry>>>,
}

impl AssetBlobCache {
    /// Create a new AssetBlobCache.
    ///
    /// # Arguments
    /// * `cache_dir` - The directory to use for caching assets.
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            locks: Arc::new(KeyedLocks::default()),
            evict_lock: Arc::new(Mutex::new(())),
            disable_cache: false,
            max_cache_size_bytes: None,
            entry_cache: Arc::new(Mutex::new(HashMap::new())),
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

        // 1. Optimistic cache hit: no locks
        if let Some(data) = self
            .try_read_cache(hash)
            .await
            .map_err(|_e| DownloadAssetError::FsFailed)?
        {
            tracing::debug!(%hash, "cache hit");
            return Ok(data);
        }

        tracing::debug!(%hash, "cache miss");

        // 2. Acquire lock to populate cache for this hash
        let _g = self.locks.lock(hash).await;

        // 3. Now that lock is acquired, re-check if hash was added already.
        if let Some(data) = self
            .try_read_cache(hash)
            .await
            .map_err(|_e| DownloadAssetError::FsFailed)?
        {
            return Ok(data);
        }

        // 4. Hash locked: do the download and caching
        let data = download_asset(url).await?;
        if !verify_sha256_in_memory(hash, &data) {
            return Err(DownloadAssetError::HashMismatch);
        }
        if let Err(e) = self.write_cache(hash, &data).await {
            tracing::warn!(%hash, error = ?e, "cache insert failed; serving download anyway");
        }
        let _ = self.evict_if_needed().await;
        Ok(data)
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

        // 1. Optimistic cache hit: no locks
        if self.copy_from_cache(hash, dest_path).await? {
            tracing::debug!(%hash, "cache hit");
            return Ok(());
        }

        tracing::debug!(%hash, "cache miss");

        // 2. Acquire lock to populate cache for this hash
        let _g = self.locks.lock(hash).await;

        // 3. Now that lock is acquired, re-check if hash was added already.
        if self.copy_from_cache(hash, dest_path).await? {
            return Ok(());
        }

        // 4. Hash locked: do the download and caching
        download_and_verify_to_path(url, hash, dest_path).await?;
        if let Err(e) = self.insert_into_cache(hash, dest_path).await {
            tracing::warn!(%hash, error = ?e, "cache insert failed; serving download anyway");
        }
        let _ = self.evict_if_needed().await;
        Ok(())
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

        // 1. Optimistic cache hit: no locks
        if self.copy_from_cache(hash, temp_file.path()).await? {
            tracing::debug!(%hash, "cache hit");
            return Ok(temp_file);
        }

        tracing::debug!(%hash, "cache miss");

        // 2. Acquire lock to populate cache for this hash
        let _g = self.locks.lock(hash).await;

        // 3. Now that lock is acquired, re-check if hash was added already.
        if self.copy_from_cache(hash, temp_file.path()).await? {
            return Ok(temp_file);
        }

        // 4. Hash locked: do the download and caching
        download_and_verify_to_path(url, hash, temp_file.path()).await?;
        if let Err(e) = self.insert_into_cache(hash, temp_file.path()).await {
            tracing::warn!(%hash, error = ?e, "cache insert failed; serving download anyway");
        }
        let _ = self.evict_if_needed().await;
        Ok(temp_file)
    }

    /// Copy a cached entry to `dest`, touching its mtime on success.
    ///
    /// Returns `Ok(true)` on a hit, `Ok(false)` on a miss (including the
    /// TOCTOU case where eviction removed the entry after we checked), and
    /// `Err` only on a genuine filesystem failure.
    async fn copy_from_cache(&self, hash: &str, dest: &Path) -> Result<bool, DownloadAssetError> {
        if !self.is_in_cache(hash).await {
            return Ok(false);
        }
        let cache = self.cache_dir.join(hash);
        let dest = dest.to_path_buf();
        let copied = tokio::task::spawn_blocking(move || {
            std::fs::copy(&cache, &dest)?;
            // Touch the cache file to mark as recently accessed.
            filetime::set_file_mtime(&cache, filetime::FileTime::now()).ok();
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| DownloadAssetError::FsFailed)?;

        match copied {
            Ok(()) => Ok(true),
            // TOCTOU: eviction removed the entry between the check and the
            // copy. That is a cache miss, not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(%hash, "cache entry vanished after check; treating as miss");
                Ok(false)
            }
            Err(_) => Err(DownloadAssetError::FsFailed),
        }
    }

    /// Streaming-copy the already-verified file at `src` into the cache.
    async fn insert_into_cache(&self, hash: &str, src: &Path) -> std::io::Result<()> {
        let cache = self.cache_dir.join(hash);
        let src = src.to_path_buf();
        tokio::task::spawn_blocking(move || std::fs::copy(&src, &cache).map(|_| ()))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "cache copy task panicked")
            })?
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

    pub async fn insert_entry_cache(&self, entry: crate::api::types::asset::AssetEntry) {
        self.entry_cache
            .lock()
            .await
            .insert(entry.name.clone(), entry);
    }

    pub async fn get_entry_cache(
        &self,
        name: &str,
    ) -> Option<crate::api::types::asset::AssetEntry> {
        self.entry_cache.lock().await.get(name).cloned()
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

// --

/// Per-key single-flight coordination.
///
/// Each key maps to an async mutex. Acquiring the key returns a guard that,
/// when dropped (including via task cancellation), releases the lock and
/// reclaims the map entry if nobody else is waiting on it.
#[derive(Default)]
struct KeyedLocks(StdMutex<HashMap<String, Arc<Mutex<()>>>>);

impl KeyedLocks {
    /// # Returns
    ///
    /// A guard that when dropped releases the key.
    async fn lock(self: &Arc<Self>, key: &str) -> KeyGuard {
        let m = {
            let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let guard = m.clone().lock_owned().await;
        KeyGuard {
            locks: self.clone(),
            key: key.to_owned(),
            _guard: guard,
        }
    }
}

struct KeyGuard {
    locks: Arc<KeyedLocks>,
    key: String,
    _guard: OwnedMutexGuard<()>,
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        tracing::debug!("trying to drop KeyGuard for key {}", self.key);
        let mut map = self.locks.0.lock().unwrap_or_else(|e| e.into_inner());
        // If count is 2 (OwnedMutexGuard + map), then nobody else is waiting
        // and it's safe to reclaim.
        if map
            .get(&self.key)
            .is_some_and(|m| Arc::strong_count(m) <= 2)
        {
            tracing::debug!("drop key {}!", self.key);
            map.remove(&self.key);
        }
    }
}

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
