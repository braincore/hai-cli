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
    AssetEntry, AssetGetArg, AssetGetError, AssetGetResult, AssetKind, AssetMetadataInfo,
    AssetRevision, AssetRevisionGetArg, AssetRevisionGetError, EntryRef,
};
use crate::asset_cache::{AssetBlobCache, DownloadAssetError};
use crate::feature::access::{self, AccessRequest, Perm};
use crate::feature::asset_crypt::AkmSelectionError;
use crate::feature::{
    asset_crypt::{self, KeyRecipient},
    asset_keyring::AssetKeyring,
};
use crate::io::Io;
use crate::{asset_helper, crypt};

// --

#[derive(Debug)]
pub enum GetAssetError {
    BadName,
    DataFetchFailed(DataFetchFailure),
    /// Caller's permissions / access rights are insufficient.
    /// Prioritized over `BadName` to avoid leaking existence.
    AccessDenied,
}

impl std::error::Error for GetAssetError {}

impl std::fmt::Display for GetAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetAssetError::BadName => write!(f, "bad-name"),
            GetAssetError::AccessDenied => write!(f, "access-denied"),
            GetAssetError::DataFetchFailed(failure) => write!(f, "data-fetch-failed: {}", failure),
        }
    }
}

#[derive(Debug)]
pub enum DataFetchFailure {
    Unexpected,
    Retryable,
    RateLimited,
}

impl std::error::Error for DataFetchFailure {}

impl std::fmt::Display for DataFetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataFetchFailure::Unexpected => write!(f, "unexpected"),
            DataFetchFailure::Retryable => write!(f, "retryable"),
            DataFetchFailure::RateLimited => write!(f, "rate-limited"),
        }
    }
}

// --

//
// Access checks
//

/// Outcome of a permission check against `perms`.
enum AccessCheck {
    Allowed,
    Denied,
    /// The check couldn't complete (e.g. network). Kept distinct from denial
    /// so that a timeout isn't reported as "access denied".
    Failed(DataFetchFailure),
}

impl AccessCheck {
    fn into_get_asset_result(self) -> Result<(), GetAssetError> {
        match self {
            AccessCheck::Allowed => Ok(()),
            AccessCheck::Denied => Err(GetAssetError::AccessDenied),
            AccessCheck::Failed(f) => Err(GetAssetError::DataFetchFailed(f)),
        }
    }
}

fn access_resolve_err_to_check(e: RequestError<AssetGetError>) -> AccessCheck {
    match e {
        // Do not propagate route errors because it can confirm existence of
        // assets.
        RequestError::Route(_) => AccessCheck::Denied,
        RequestError::RateLimit(_) => AccessCheck::Failed(DataFetchFailure::RateLimited),
        RequestError::Http(_) => AccessCheck::Failed(DataFetchFailure::Retryable),
        RequestError::BadRequest(_) | RequestError::Unexpected(_) => {
            AccessCheck::Failed(DataFetchFailure::Unexpected)
        }
    }
}

/// Checks access to `asset_name`.
///
/// Supports resolving attachment anchors and writes to new assets.
async fn check_name_access(
    api_client: &HaiClient,
    access: Option<&[&Perm]>,
    asset_name: &str,
    write: bool,
) -> AccessCheck {
    let Some(access) = access else {
        return AccessCheck::Allowed;
    };
    match access::access_perm_for_asset_access_request(api_client, asset_name, access, write).await
    {
        Ok(true) => AccessCheck::Allowed,
        Ok(false) => AccessCheck::Denied,
        Err((_, e)) => access_resolve_err_to_check(e),
    }
}

/// Checks access for an already-fetched entry by name and entry_id.
///
/// Since the entry is already fetched, an additional fetch is only necessary
/// if the entry is an attachment whose anchor must be resolved.
async fn check_entry_access(
    api_client: &HaiClient,
    access: Option<&[&Perm]>,
    entry: &AssetEntry,
    write: bool,
) -> AccessCheck {
    let Some(access) = access else {
        return AccessCheck::Allowed;
    };
    let (by_name, by_id) = if write {
        (
            AccessRequest::WriteByName { name: &entry.name },
            AccessRequest::WriteByEntryId {
                entry_id: &entry.entry_id,
            },
        )
    } else {
        (
            AccessRequest::ReadByName { name: &entry.name },
            AccessRequest::ReadByEntryId {
                entry_id: &entry.entry_id,
            },
        )
    };
    if access::check_access(access, &by_name).is_ok()
        || access::check_access(access, &by_id).is_ok()
    {
        return AccessCheck::Allowed;
    }
    if !asset_helper::is_attachment(&entry.name) {
        return AccessCheck::Denied;
    }
    check_name_access(api_client, Some(access), &entry.name, write).await
}

async fn check_list_access(
    api_client: &HaiClient,
    access: Option<&[&Perm]>,
    prefix: &str,
) -> AccessCheck {
    let Some(access) = access else {
        return AccessCheck::Allowed;
    };
    match access::access_perm_for_asset_list_prefix_request(api_client, prefix, access).await {
        Ok(true) => AccessCheck::Allowed,
        Ok(false) => AccessCheck::Denied,
        Err((_, e)) => access_resolve_err_to_check(e),
    }
}

/// Fetches an entry and, if `access` is set, enforces read or write access.
///
/// Careful to report `AccessDenied` rather than `BadName` to mask existence
/// when applicable.
pub async fn get_asset_entry_checked(
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
    access: Option<&[&Perm]>,
    write: bool,
) -> Result<AssetGetResult, GetAssetError> {
    match get_asset_entry(api_client, asset_name, bad_name_ok).await {
        Ok(res) => {
            check_entry_access(api_client, access, &res.entry, write)
                .await
                .into_get_asset_result()?;
            Ok(res)
        }
        Err(GetAssetError::BadName) => {
            check_name_access(api_client, access, asset_name, write)
                .await
                .into_get_asset_result()?;
            Err(GetAssetError::BadName)
        }
        Err(e) => Err(e),
    }
}

// --

pub async fn asset_blob_cache_get_asset_contents(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    data_url: &str,
    hash: &str,
) -> Result<Vec<u8>, GetAssetError> {
    match asset_blob_cache
        .get_or_download_limited(data_url, hash, api_client.limiter())
        .await
    {
        Ok(contents) => Ok(contents),
        Err(err) => match err {
            DownloadAssetError::DataFetchFailed(failure) => {
                return Err(GetAssetError::DataFetchFailed(failure));
            }
            DownloadAssetError::FsFailed | DownloadAssetError::HashMismatch => {
                return Err(GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected));
            }
        },
    }
}

/// If `access` is None, no access checks are performed.
pub async fn get_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
    access: Option<&[&Perm]>,
) -> Result<(Vec<u8>, AssetEntry), GetAssetError> {
    let asset_entry = get_asset_entry_checked(api_client, asset_name, bad_name_ok, access, false)
        .await?
        .entry;
    if let Some(data_url) = asset_entry.asset.url.as_ref()
        && let Some(hash) = asset_entry.asset.hash.as_ref()
    {
        let data_contents =
            asset_blob_cache_get_asset_contents(asset_blob_cache, api_client, data_url, hash)
                .await?;
        Ok((data_contents, asset_entry))
    } else {
        Err(GetAssetError::BadName)
    }
}

/// If `access` is None, no access checks are performed.
pub async fn get_asset_using_cache(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
    access: Option<&[&Perm]>,
) -> Result<(Vec<u8>, AssetEntry), GetAssetError> {
    let asset_entry = match asset_blob_cache.get_entry_cache(asset_name).await {
        Some(entry) => {
            // Just because an entry is in the cache doesn't mean the caller
            // has access to it. Re-check access.
            check_entry_access(api_client, access, &entry, false)
                .await
                .into_get_asset_result()?;
            entry.clone()
        }
        None => {
            let asset_entry =
                get_asset_entry_checked(api_client, asset_name, bad_name_ok, access, false)
                    .await?
                    .entry;
            asset_blob_cache
                .insert_entry_cache(asset_entry.clone())
                .await;
            asset_entry
        }
    };
    if let Some(data_url) = asset_entry.asset.url.as_ref()
        && let Some(hash) = asset_entry.asset.hash.as_ref()
    {
        let data_contents =
            asset_blob_cache_get_asset_contents(asset_blob_cache, api_client, data_url, hash)
                .await?;
        Ok((data_contents, asset_entry))
    } else {
        Err(GetAssetError::BadName)
    }
}

/// WARNING: Does not check access, see `get_asset_entry_checked`.
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
            }
            match e {
                RequestError::BadRequest(_)
                | RequestError::Http(_)
                | RequestError::Unexpected(_) => {
                    Err(GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected))
                }
                RequestError::RateLimit(_) => Err(GetAssetError::DataFetchFailed(
                    DataFetchFailure::RateLimited,
                )),
                RequestError::Route(e) => match e {
                    AssetGetError::BadName => Err(GetAssetError::BadName),
                    _ => Err(GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected)),
                },
            }
        }
    }
}

// --

/// If `access` is None, no access checks are performed.
pub async fn get_asset_and_metadata(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
    access: Option<&[&Perm]>,
) -> Result<(Vec<u8>, Option<Vec<u8>>, AssetEntry), GetAssetError> {
    let asset_get_res =
        get_asset_entry_checked(api_client, asset_name, bad_name_ok, access, false).await?;
    let data_contents = if let Some(data_url) = asset_get_res.entry.asset.url.as_ref()
        && let Some(hash) = asset_get_res.entry.asset.hash.as_ref()
    {
        asset_blob_cache_get_asset_contents(asset_blob_cache.clone(), api_client, data_url, hash)
            .await?
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
            asset_blob_cache_get_asset_contents(
                asset_blob_cache,
                api_client,
                metadata_url,
                metadata_hash,
            )
            .await?,
        )
    } else {
        None
    };
    Ok((data_contents, metadata_contents, asset_get_res.entry))
}

pub enum GetDecryptedAssetError {
    GetAsset(GetAssetError),
    Akm(AkmSelectionError),
}

impl std::fmt::Display for GetDecryptedAssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetDecryptedAssetError::GetAsset(e) => write!(f, "get-asset-error: {}", e),
            GetDecryptedAssetError::Akm(e) => write!(f, "akm-selection-error: {}", e),
        }
    }
}

pub async fn get_decrypted_asset_and_metadata(
    io: &Io,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
    asset_name: &str,
    access: Option<&[&Perm]>,
) -> Result<(Vec<u8>, AssetEntry), GetDecryptedAssetError> {
    match get_asset_and_metadata(
        asset_blob_cache.clone(),
        &api_client,
        &asset_name,
        false,
        access,
    )
    .await
    {
        Ok((asset_contents, md_contents, asset_entry)) => {
            let akm_info = match asset_crypt::extract_akm_from_metadata(
                io,
                asset_blob_cache.clone(),
                asset_keyring.clone(),
                api_client.clone(),
                username.map(|u| KeyRecipient::User(u.to_string())).as_ref(),
                md_contents.as_deref(),
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    return Err(GetDecryptedAssetError::Akm(e));
                }
            };
            if let Some(akm_info) = &akm_info {
                let enc_content = crypt::EncryptedContent::from_bytes(&asset_contents).unwrap();
                Ok((
                    crypt::decrypt_content(
                        &enc_content,
                        &akm_info.unlocked_akm.sym_key_info.aes_key,
                    )
                    .unwrap(),
                    asset_entry,
                ))
            } else {
                Ok((asset_contents.to_vec(), asset_entry))
            }
        }
        Err(e) => Err(GetDecryptedAssetError::GetAsset(e)),
    }
}

pub enum GetRevisionError {
    BadEntryRef,
    BadRevId,
    /// For clarity (wrt AccessDenied): This is an API rejection.
    NoPermission,
    /// Access rights of the session are insufficient. Checked pre-API request.
    AccessDenied,
    Deleted,
    DataFetchFailed(DataFetchFailure),
}

/// Fetches the asset data and metadata for a specific revision.
///
/// # Arguments
/// * `asset_blob_cache` - Cache for downloading asset blobs
/// * `api_client` - API client for fetching asset revision info
/// * `asset_name` - Name of the asset to fetch
/// * `rev_id` - Optional revision ID to fetch; if None, fetches latest revision
/// * `only_fetch_metadata_if_necessary` - If true, only fetches metadata if
///   the asset is encrypted.
/// * `access` - If None, no access checks are performed.
///
/// # Returns
/// `Ok((data_contents, metadata_contents, revision))` on success, where
/// `data_contents` and `metadata_contents` are optional byte vectors
/// containing the asset data and metadata respectively, and `revision` is the
/// fetched `AssetRevision`.
///
/// `data_contents` is None when the entry contains no data (e.g. Folder).
pub async fn get_asset_and_metadata_revision(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    rev_id: Option<&str>,
    only_fetch_metadata_if_necessary: bool,
    access: Option<&[&Perm]>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, AssetRevision), GetRevisionError> {
    let revision = get_asset_revision(api_client, asset_name, rev_id, access).await?;

    let data_contents = if let Some(data_url) = revision.asset.url.as_ref()
        && let Some(hash) = revision.asset.hash.as_ref()
    {
        match asset_blob_cache
            .get_or_download_limited(data_url, hash, api_client.limiter())
            .await
        {
            Ok(contents) => Some(contents),
            Err(err) => match err {
                DownloadAssetError::DataFetchFailed(failure) => {
                    return Err(GetRevisionError::DataFetchFailed(failure));
                }
                DownloadAssetError::FsFailed | DownloadAssetError::HashMismatch => {
                    return Err(GetRevisionError::DataFetchFailed(
                        DataFetchFailure::Unexpected,
                    ));
                }
            },
        }
    } else {
        None
    };
    let metadata_contents = if let Some(AssetMetadataInfo {
        url: Some(metadata_url),
        hash: Some(metadata_hash),
        content_encrypted,
        ..
    }) = revision.metadata.as_ref()
    {
        if content_encrypted.is_some() || !only_fetch_metadata_if_necessary {
            Some(
                match asset_blob_cache
                    .get_or_download_limited(metadata_url, metadata_hash, api_client.limiter())
                    .await
                {
                    Ok(contents) => contents,
                    Err(err) => match err {
                        DownloadAssetError::DataFetchFailed(failure) => {
                            return Err(GetRevisionError::DataFetchFailed(failure));
                        }
                        DownloadAssetError::FsFailed | DownloadAssetError::HashMismatch => {
                            return Err(GetRevisionError::DataFetchFailed(
                                DataFetchFailure::Unexpected,
                            ));
                        }
                    },
                },
            )
        } else {
            None
        }
    } else {
        None
    };
    Ok((data_contents, metadata_contents, revision))
}

/// Fetches only the revision entry (no asset data or metadata contents are
/// downloaded).
///
/// Returns `GetRevisionError::Deleted` if the revision is a deletion.
///
/// If `access` is set, access is checked before the revision is requested.
pub async fn get_asset_revision(
    api_client: &HaiClient,
    asset_name: &str,
    rev_id: Option<&str>,
    access: Option<&[&Perm]>,
) -> Result<AssetRevision, GetRevisionError> {
    match check_name_access(api_client, access, asset_name, false).await {
        AccessCheck::Allowed => {}
        AccessCheck::Denied => return Err(GetRevisionError::AccessDenied),
        AccessCheck::Failed(f) => return Err(GetRevisionError::DataFetchFailed(f)),
    }
    let revision_get_res = match api_client
        .asset_revision_get(AssetRevisionGetArg {
            entry_ref: EntryRef::Name(asset_name.to_string()),
            rev_id: rev_id.map(|s| s.to_string()),
        })
        .await
    {
        Ok(res) => Ok(res),
        Err(e) => match e {
            RequestError::BadRequest(_) => Err(GetRevisionError::DataFetchFailed(
                DataFetchFailure::Unexpected,
            )),
            RequestError::Http(_) => Err(GetRevisionError::DataFetchFailed(
                DataFetchFailure::Retryable,
            )),
            RequestError::RateLimit(_) => Err(GetRevisionError::DataFetchFailed(
                DataFetchFailure::RateLimited,
            )),
            RequestError::Unexpected(_) => Err(GetRevisionError::DataFetchFailed(
                DataFetchFailure::Retryable,
            )),
            RequestError::Route(e) => match e {
                AssetRevisionGetError::BadEntryRef => Err(GetRevisionError::BadEntryRef),
                AssetRevisionGetError::NoPermission => Err(GetRevisionError::NoPermission),
                AssetRevisionGetError::BadRevId => Err(GetRevisionError::BadRevId),
                _ => Err(GetRevisionError::DataFetchFailed(
                    DataFetchFailure::Unexpected,
                )),
            },
        },
    }?;

    if matches!(
        revision_get_res.revision.op,
        crate::api::types::asset::AssetEntryOp::Delete
    ) {
        return Err(GetRevisionError::Deleted);
    }
    Ok(revision_get_res.revision)
}

// --

/// If `access` is None, no access checks are performed.
pub async fn get_only_asset_metadata(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
    access: Option<&[&Perm]>,
) -> Result<(Option<Vec<u8>>, AssetEntry), GetAssetError> {
    let asset_get_res =
        get_asset_entry_checked(api_client, asset_name, bad_name_ok, access, false).await?;
    if asset_get_res.entry.asset.url.is_none()
        && asset_get_res.entry.asset.kind != AssetKind::Folder
    {
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
                .get_or_download_limited(metadata_url, metadata_hash, api_client.limiter())
                .await
            {
                Ok(contents) => contents,
                Err(err) => match err {
                    DownloadAssetError::DataFetchFailed(failure) => {
                        return Err(GetAssetError::DataFetchFailed(failure));
                    }
                    DownloadAssetError::FsFailed | DownloadAssetError::HashMismatch => {
                        return Err(GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected));
                    }
                },
            },
        )
    } else {
        None
    };
    Ok((metadata_contents, asset_get_res.entry))
}

// --

#[derive(Debug)]
pub enum DownloadError {
    Request(reqwest::Error),
    BadStatus(reqwest::StatusCode),
    Body(reqwest::Error),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadError::Request(e) => write!(f, "request failed: {}", e),
            DownloadError::BadStatus(s) => write!(f, "bad status: {}", s),
            DownloadError::Body(e) => write!(f, "failed to read body: {}", e),
        }
    }
}

impl std::error::Error for DownloadError {}

/// Downloads content from a URL using a new reqwest client.
///
/// Emphasizing the lack of client re-use so that the caller knows it's not
/// ideal (connection pool, dns cache, tls, ...).
pub async fn download_with_new_client(url: &str) -> Result<Vec<u8>, DownloadError> {
    let resp = reqwest::get(url).await.map_err(DownloadError::Request)?;

    if !resp.status().is_success() {
        return Err(DownloadError::BadStatus(resp.status()));
    }

    let bytes = resp.bytes().await.map_err(DownloadError::Body)?;
    Ok(bytes.to_vec())
}

/// Preferred method for downloading content.
#[allow(dead_code)]
pub async fn download_with_existing_client(
    client: &reqwest::Client,
    url: &str,
) -> Result<Vec<u8>, DownloadError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(DownloadError::Request)?;

    if !resp.status().is_success() {
        return Err(DownloadError::BadStatus(resp.status()));
    }

    let bytes = resp.bytes().await.map_err(DownloadError::Body)?;
    Ok(bytes.to_vec())
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
    use crate::api::types::asset::{
        AssetEntryListArg, AssetEntryListError, AssetEntryListNextArg, EntryListOrder,
    };

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
            order: EntryListOrder::Asc,
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

    // Sort for consistent ordering
    matching_assets.sort_by(|a, b| numeric_sort::cmp(&a.name, &b.name));

    Ok(matching_assets)
}

// --

/// Result of expanding a glob while checking access.
enum CheckedGlob {
    /// No prefix access rights to expand the glob.
    Denied,
    Failed(DataFetchFailure),
    Expanded {
        /// Matches that passed the access check (sorted).
        allowed: Vec<AssetEntry>,
        /// Matches that failed the access check. Safe to reveal by name since
        /// the caller is allowed to list them.
        denied: Vec<String>,
        /// Matches whose access check could not complete.
        failed: Vec<(String, DataFetchFailure)>,
    },
}

/// Like `expand_glob`, but if `access` is set, requires list access to the
/// glob's prefix and checks each match for read (or write) access.
///
/// NOTE: The entire glob must be accessible according to the provided `access`
/// rights. If only a portion of the glob is satisfied by an `access` right, an
/// `access-denied` error is returned.
async fn expand_glob_checked(
    api_client: &HaiClient,
    glob_pattern: &str,
    access: Option<&[&Perm]>,
    write: bool,
) -> Result<CheckedGlob, String> {
    let (prefix, _) = parse_glob_pattern(glob_pattern);
    match check_list_access(api_client, access, &prefix).await {
        AccessCheck::Allowed => {}
        AccessCheck::Denied => return Ok(CheckedGlob::Denied),
        AccessCheck::Failed(f) => return Ok(CheckedGlob::Failed(f)),
    }
    let entries = expand_glob(api_client, glob_pattern).await?;
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    let mut failed = Vec::new();
    for entry in entries {
        match check_entry_access(api_client, access, &entry, write).await {
            AccessCheck::Allowed => allowed.push(entry),
            AccessCheck::Denied => denied.push(entry.name),
            AccessCheck::Failed(f) => failed.push((entry.name, f)),
        }
    }
    Ok(CheckedGlob::Expanded {
        allowed,
        denied,
        failed,
    })
}

// --

pub enum FolderPolicy {
    #[allow(dead_code)]
    Exclude,
    #[allow(dead_code)]
    ExcludeButRecurse,
    IncludeOnly,
    IncludeAndRecurse,
}

/// Fetches asset entries for a list of asset names or glob patterns.
///
/// * `access` - If `None`, no permission checks are performed. If `Some`, each
///   glob's prefix must be listable and every resolved entry (including
///   recursed folder contents) must grant read access, or write access if
///   `write`. Any denial is returned as an error.
pub async fn get_asset_entries_from_globs(
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    folder_policy: FolderPolicy,
    access: Option<&[&Perm]>,
    write: bool,
) -> Result<Vec<AssetEntry>, String> {
    let mut resolved_entries: Vec<AssetEntry> = Vec::new();
    let mut seen_globs: HashSet<String> = HashSet::new();
    let mut seen_asset_names: HashSet<String> = HashSet::new();

    let mut frontier = asset_names_or_globs.to_vec();

    while let Some(asset_ref) = frontier.pop() {
        if is_glob_pattern(&asset_ref) {
            // Skip if we've already expanded this glob
            if seen_globs.contains(&asset_ref) {
                continue;
            }
            seen_globs.insert(asset_ref.clone());

            let asset_entries =
                match expand_glob_checked(api_client, &asset_ref, access, write).await? {
                    CheckedGlob::Denied => {
                        return Err(format!("access denied: {}", asset_ref));
                    }
                    CheckedGlob::Failed(f) => {
                        return Err(format!("cannot check access for {}: {}", asset_ref, f));
                    }
                    CheckedGlob::Expanded {
                        allowed,
                        denied,
                        failed,
                    } => {
                        if let Some(name) = denied.first() {
                            return Err(format!("access denied: {}", name));
                        }
                        if let Some((name, f)) = failed.first() {
                            return Err(format!("cannot check access for {}: {}", name, f));
                        }
                        allowed
                    }
                };

            for entry in asset_entries {
                if seen_asset_names.contains(&entry.name) {
                    continue;
                }
                seen_asset_names.insert(entry.name.clone());
                if entry.asset.kind == AssetKind::Folder {
                    match folder_policy {
                        FolderPolicy::Exclude => {}
                        FolderPolicy::ExcludeButRecurse => {
                            frontier.push(format!("{}/*", entry.name));
                        }
                        FolderPolicy::IncludeOnly => resolved_entries.push(entry),
                        FolderPolicy::IncludeAndRecurse => {
                            frontier.push(format!("{}/*", entry.name));
                            resolved_entries.push(entry);
                        }
                    }
                } else {
                    resolved_entries.push(entry);
                }
            }
        } else {
            // Regular asset (non-glob)
            if !seen_asset_names.contains(&asset_ref) {
                match get_asset_entry_checked(api_client, &asset_ref, false, access, write).await {
                    Ok(get_res) => {
                        seen_asset_names.insert(asset_ref.clone());
                        if get_res.entry.asset.kind == AssetKind::Folder {
                            match folder_policy {
                                FolderPolicy::Exclude => {}
                                FolderPolicy::ExcludeButRecurse => {
                                    frontier.push(format!("{}/*", get_res.entry.name));
                                }
                                FolderPolicy::IncludeOnly => {
                                    resolved_entries.push(get_res.entry);
                                }
                                FolderPolicy::IncludeAndRecurse => {
                                    frontier.push(format!("{}/*", get_res.entry.name));
                                    resolved_entries.push(get_res.entry);
                                }
                            }
                        } else {
                            resolved_entries.push(get_res.entry);
                        }
                    }
                    Err(GetAssetError::AccessDenied) => {
                        return Err(format!("access denied: {}", asset_ref));
                    }
                    Err(e) => {
                        return Err(e.to_string());
                    }
                };
            }
        }
    }
    Ok(resolved_entries)
}

// --

pub type AssetTempFileMap = HashMap<String, Result<tempfile::NamedTempFile, GetAssetError>>;

pub struct PreparedTempAssets {
    /// Asset name -> temp file creation result
    pub asset_map: AssetTempFileMap,
    /// Glob pattern -> expanded asset names. Excludes access-denied matches.
    pub expanded_globs: HashMap<String, Vec<String>>,
    /// Asset names (or glob patterns, if the glob's prefix couldn't be listed)
    /// that failed the access check.
    pub access_denied: Vec<String>,
}

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
/// * `access` - If `None`, no permission checks are performed. If `Some`,
///   downloaded assets require read access, `skip_download` assets (outputs)
///   require write access, and globs require list access to their prefix.
pub async fn prepare_assets_from_names_as_temp_files(
    io: &Io,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
    skip_download: Option<&HashSet<String>>,
    access: Option<&[&Perm]>,
) -> Result<PreparedTempAssets, String> {
    let empty_set = HashSet::new();
    let skip_download = skip_download.unwrap_or(&empty_set);

    let mut asset_final_map = HashMap::new();

    // Track expanded globs for caller reference
    let mut expanded_globs: HashMap<String, Vec<String>> = HashMap::new();

    // Collect unique assets to process
    let mut seen_assets: HashSet<String> = HashSet::new();
    let mut assets_to_download: Vec<AssetEntry> = Vec::new();
    let mut asset_fetch_failures = Vec::new();
    let mut access_denied = Vec::new();

    for asset_ref in asset_names_or_globs {
        if is_glob_pattern(asset_ref) {
            // Skip if we've already expanded this glob
            if expanded_globs.contains_key(asset_ref) {
                continue;
            }

            match expand_glob_checked(api_client, asset_ref, access, false).await? {
                CheckedGlob::Denied => access_denied.push(asset_ref.clone()),
                CheckedGlob::Failed(f) => asset_fetch_failures
                    .push((asset_ref.clone(), GetAssetError::DataFetchFailed(f))),
                CheckedGlob::Expanded {
                    allowed,
                    denied,
                    failed,
                } => {
                    if allowed.is_empty() && denied.is_empty() && failed.is_empty() {
                        // If glob doesn't match anything, use the shell approach and
                        // treat the blob as the literal asset name.
                        asset_fetch_failures.push((asset_ref.clone(), GetAssetError::BadName));
                        continue;
                    }
                    for name in denied {
                        if seen_assets.insert(name.clone()) {
                            access_denied.push(name);
                        }
                    }
                    for (name, f) in failed {
                        if seen_assets.insert(name.clone()) {
                            asset_fetch_failures.push((name, GetAssetError::DataFetchFailed(f)));
                        }
                    }
                    expanded_globs.insert(
                        asset_ref.clone(),
                        allowed.iter().map(|entry| entry.name.clone()).collect(),
                    );
                    for entry in allowed {
                        if seen_assets.insert(entry.name.clone()) {
                            // Glob-matched assets are always inputs, so they need download
                            assets_to_download.push(entry);
                        }
                    }
                }
            }
        } else if seen_assets.insert(asset_ref.clone()) {
            // Regular asset (non-glob)
            if skip_download.contains(asset_ref) {
                // Output-only: must be writable. It may not exist yet.
                match check_name_access(api_client, access, asset_ref, true).await {
                    AccessCheck::Allowed => {
                        asset_final_map.insert(
                            asset_ref.clone(),
                            create_empty_temp_file(asset_ref, None, None).map_err(|dl_err| {
                                match dl_err {
                                    DownloadAssetError::FsFailed
                                    | DownloadAssetError::HashMismatch => {
                                        GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected)
                                    }
                                    DownloadAssetError::DataFetchFailed(failure) => {
                                        GetAssetError::DataFetchFailed(failure)
                                    }
                                }
                            }),
                        );
                    }
                    AccessCheck::Denied => access_denied.push(asset_ref.clone()),
                    AccessCheck::Failed(f) => asset_fetch_failures
                        .push((asset_ref.clone(), GetAssetError::DataFetchFailed(f))),
                }
            } else {
                match get_asset_entry_checked(api_client, asset_ref, false, access, false).await {
                    Ok(get_res) => assets_to_download.push(get_res.entry),
                    Err(GetAssetError::AccessDenied) => access_denied.push(asset_ref.clone()),
                    Err(e) => asset_fetch_failures.push((asset_ref.clone(), e)),
                }
            }
        }
    }

    // Download/create files in parallel
    let sync_res = crate::asset_sync::sync_down_entries(
        io,
        asset_blob_cache,
        asset_keyring,
        api_client,
        recipient,
        crate::asset_sync::AssetSyncSource::AssetEntry(assets_to_download),
        None,
        Some(max_concurrent_downloads),
        false,
    )
    .await;
    let mut asset_map: HashMap<String, Result<NamedTempFile, GetAssetError>> = HashMap::new();
    for (source, asset_temp_file, _) in sync_res {
        if let Some(asset_temp_file) = asset_temp_file {
            asset_map.insert(source.asset_name.clone(), Ok(asset_temp_file));
        } else {
            asset_map.insert(
                source.asset_name.clone(),
                // FIXME: This isn't necessarily just an unexpected error.
                Err(GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected)),
            );
        }
    }
    for (asset_ref, res) in asset_map {
        asset_final_map.insert(asset_ref, res);
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }
    Ok(PreparedTempAssets {
        asset_map: asset_final_map,
        expanded_globs,
        access_denied,
    })
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
/// 7. If `access` is set, returns an error listing every ref that fails an
///    access check (outputs/appends need write, inputs need read, globs need
///    list). Nothing is downloaded-and-run partially.
///
/// NOTE: Care is taken to detect asset-names that have added trailing
/// characters. For example, a semicolon that indicates the end of a shell cmd.
///
/// Returns:
/// * A tuple containing:
///   - The modified command with @assets replaced by file paths
///   - A map of asset names to their temporary files and paths
///   - A set of asset names that are used as outputs (via > or >>)
pub async fn prepare_assets_from_cmd_as_temp_files(
    io: &Io,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    account: &Option<crate::db::Account>,
    api_client: &HaiClient,
    recipient: Option<KeyRecipient>,
    cmd: &str,
    max_concurrent_downloads: usize,
    access: Option<&[&Perm]>,
) -> Result<(String, AssetTempFileMap, HashSet<String>), String> {
    let asset_regex = Regex::new(r"@@([^\s]+)").expect("Invalid regex");
    let append_regex = Regex::new(r">>\s*@@([^\s]+)").expect("Invalid regex");
    let output_regex = Regex::new(r"(?:>|>>)\s*@@([^\s]+)").expect("Invalid regex");

    let mut append_assets = HashSet::new();
    let mut output_assets = HashSet::new();

    // Original @asset reference (including @) and the replacement info.
    // (full_match, asset_path, is_glob)
    let mut replacements: Vec<(String, String, bool)> = Vec::new();

    // First identify output assets and append assets
    for cap in output_regex.captures_iter(cmd) {
        let expanded = asset_helper::expand_asset_name(&cap[1], account);
        let Some(asset_name) = asset_helper::trim_to_likely_valid_asset_name(&expanded, true, true)
        else {
            continue;
        };
        let output_asset = asset_helper::expand_asset_name(asset_name, account);
        if is_glob_pattern(&output_asset) {
            return Err(format!(
                "Glob patterns are not allowed in output redirections: @{}",
                output_asset
            ));
        }
        output_assets.insert(output_asset);
    }

    for cap in append_regex.captures_iter(cmd) {
        let expanded = asset_helper::expand_asset_name(&cap[1], account);
        let Some(asset_name) = asset_helper::trim_to_likely_valid_asset_name(&expanded, true, true)
        else {
            continue;
        };
        let append_asset = asset_helper::expand_asset_name(asset_name, account);
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
        let output_redirection_regex = Regex::new(r">>?\s*@@[^\s]+").expect("Invalid regex");
        let cmd_without_outputs = output_redirection_regex.replace_all(cmd, "");

        asset_regex
            .captures_iter(&cmd_without_outputs)
            .filter_map(|cap| {
                let expanded = asset_helper::expand_asset_name(&cap[1], account);
                let asset_name =
                    asset_helper::trim_to_likely_valid_asset_name(&expanded, true, true)?;
                Some(asset_helper::expand_asset_name(asset_name, account))
            })
            .collect()
    };

    // Collect all asset references from the command
    let mut asset_refs: Vec<String> = Vec::new();
    let mut seen_refs: HashSet<String> = HashSet::new();

    for cap in asset_regex.captures_iter(cmd) {
        let full_match = cap[0].to_string();
        let expanded = asset_helper::expand_asset_name(&cap[1], account);
        let Some(asset_path) = asset_helper::trim_to_likely_valid_asset_name(&expanded, true, true)
        else {
            continue;
        };
        let is_glob = is_glob_pattern(&asset_path);

        if !seen_refs.contains(asset_path) {
            seen_refs.insert(asset_path.to_string());
            asset_refs.push(asset_path.to_string());
        }

        replacements.push((full_match, asset_path.to_string(), is_glob));
    }

    // Output-only assets that need temp files created (but not downloaded)
    let output_only_assets: HashSet<String> = output_assets
        .iter()
        .filter(|asset| !input_assets.contains(*asset) && !append_assets.contains(*asset))
        .cloned()
        .collect();

    // Check write access for outputs.
    let mut access_denied: Vec<String> = Vec::new();
    for output_asset in output_assets
        .iter()
        .filter(|asset| !output_only_assets.contains(*asset))
    {
        match check_name_access(api_client, access, output_asset, true).await {
            AccessCheck::Allowed => {}
            AccessCheck::Denied => access_denied.push(output_asset.clone()),
            AccessCheck::Failed(f) => {
                return Err(format!("cannot check access for {}: {}", output_asset, f));
            }
        }
    }

    let PreparedTempAssets {
        asset_map,
        expanded_globs,
        access_denied: prepare_access_denied,
    } = prepare_assets_from_names_as_temp_files(
        io,
        asset_blob_cache,
        asset_keyring,
        api_client,
        recipient,
        &asset_refs,
        max_concurrent_downloads,
        Some(&output_only_assets),
        access,
    )
    .await?;

    // Don't run command at all if any asset ref failed access check.
    for name in prepare_access_denied {
        if !access_denied.contains(&name) {
            access_denied.push(name);
        }
    }
    if !access_denied.is_empty() {
        access_denied.sort();
        return Err(format!("access denied: {}", access_denied.join(", ")));
    }

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
        .map_err(|_e| DownloadAssetError::FsFailed)?;

    Ok(temp_file)
}

// --

#[derive(Debug, Clone)]
pub struct AssetFetchResult {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
    pub asset_entry: AssetEntry,
}

pub type AssetExtendedFetchMap = HashMap<String, Result<AssetFetchResult, GetAssetError>>;

#[derive(Debug)]
pub struct AssetFetchGroupResult {
    /// Asset name -> contents/metadata fetch result
    pub fetched: AssetExtendedFetchMap,
    /// Glob pattern -> expanded asset names. Excludes access-denied matches.
    #[allow(dead_code)]
    pub expanded_globs: HashMap<String, Vec<String>>,
    /// Assets skipped due to content restrictions (redactions).
    pub skipped_content_restrictions: Vec<String>,
    /// Assets skipped because they're folders.
    pub skipped_folders: Vec<String>,
    /// Asset names (or glob patterns, if the glob's prefix couldn't be listed)
    /// that failed the access check.
    pub access_denied: Vec<String>,
}

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
/// * `access` - If `None`, no permission checks are performed. If `Some`, every
///   asset must grant read access and every glob's prefix must be listable.
///   Permission is checked before redaction/folder status so neither leaks.
pub async fn fetch_assets_from_names_in_memory_extended(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_names_or_globs: &[String],
    max_concurrent_downloads: usize,
    download_metadata: bool,
    access: Option<&[&Perm]>,
) -> Result<AssetFetchGroupResult, String> {
    // Track expanded globs for caller reference
    let mut expanded_globs: HashMap<String, Vec<String>> = HashMap::new();

    // Collect unique assets to process
    let mut seen_assets: HashSet<String> = HashSet::new();
    // (asset ref, entry)
    let mut assets_to_fetch: Vec<(String, AssetEntry)> = Vec::new();
    let mut skipped_content_restrictions = Vec::new();
    let mut skipped_folders = Vec::new();
    let mut access_denied = Vec::new();

    let mut asset_fetch_failures = Vec::new();
    for asset_ref in asset_names_or_globs {
        if is_glob_pattern(asset_ref) {
            // Skip if we've already expanded this glob
            if expanded_globs.contains_key(asset_ref) {
                continue;
            }

            match expand_glob_checked(api_client, asset_ref, access, false).await? {
                CheckedGlob::Denied => access_denied.push(asset_ref.clone()),
                CheckedGlob::Failed(f) => asset_fetch_failures
                    .push((asset_ref.clone(), GetAssetError::DataFetchFailed(f))),
                CheckedGlob::Expanded {
                    allowed,
                    denied,
                    failed,
                } => {
                    if allowed.is_empty() && denied.is_empty() && failed.is_empty() {
                        // If glob doesn't match anything, use the shell approach and
                        // treat the blob as the literal asset name.
                        asset_fetch_failures.push((asset_ref.clone(), GetAssetError::BadName));
                        continue;
                    }
                    for name in denied {
                        if seen_assets.insert(name.clone()) {
                            access_denied.push(name);
                        }
                    }
                    for (name, f) in failed {
                        if seen_assets.insert(name.clone()) {
                            asset_fetch_failures.push((name, GetAssetError::DataFetchFailed(f)));
                        }
                    }
                    expanded_globs.insert(
                        asset_ref.clone(),
                        allowed.iter().map(|entry| entry.name.clone()).collect(),
                    );
                    for entry in allowed {
                        // Mark seen even when skipped so overlapping globs
                        // don't report the same asset twice.
                        if !seen_assets.insert(entry.name.clone()) {
                            continue;
                        }
                        if entry.redactions.is_some() {
                            skipped_content_restrictions.push(entry.name);
                        } else if matches!(entry.asset.kind, AssetKind::Folder) {
                            skipped_folders.push(entry.name);
                        } else {
                            assets_to_fetch.push((entry.name.clone(), entry));
                        }
                    }
                }
            }
        } else if seen_assets.insert(asset_ref.clone()) {
            // Regular asset (non-glob)
            match get_asset_entry_checked(api_client, asset_ref, false, access, false).await {
                Ok(get_res) => {
                    if get_res.entry.redactions.is_some() {
                        skipped_content_restrictions.push(get_res.entry.name.clone());
                    } else if matches!(get_res.entry.asset.kind, AssetKind::Folder) {
                        skipped_folders.push(get_res.entry.name.clone());
                    } else {
                        assets_to_fetch.push((asset_ref.clone(), get_res.entry));
                    }
                }
                Err(GetAssetError::AccessDenied) => access_denied.push(asset_ref.clone()),
                Err(e) => asset_fetch_failures.push((asset_ref.clone(), e)),
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
                    asset_entry: r.asset_entry,
                })
                .map_err(|dl_err| match dl_err {
                    DownloadAssetError::FsFailed => {
                        GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected)
                    }
                    DownloadAssetError::HashMismatch => {
                        GetAssetError::DataFetchFailed(DataFetchFailure::Unexpected)
                    }
                    DownloadAssetError::DataFetchFailed(failure) => {
                        GetAssetError::DataFetchFailed(failure)
                    }
                }),
        );
    }
    for (asset_ref, e) in asset_fetch_failures {
        asset_final_map.insert(asset_ref, Err(e));
    }

    Ok(AssetFetchGroupResult {
        fetched: asset_final_map,
        expanded_globs,
        skipped_content_restrictions,
        skipped_folders,
        access_denied,
    })
}

#[derive(Debug, Clone)]
pub struct AssetDownloadResult {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
    pub asset_entry: AssetEntry,
}

pub type AssetExtendedDownloadMap =
    HashMap<String, Result<AssetDownloadResult, DownloadAssetError>>;

#[derive(Debug)]
/// Internal enum to track what kind of download completed
enum DownloadKind {
    Data(String),     // asset entry_id
    Metadata(String), // asset entry_id
}

/// Internal accumulator for a single asset's in-flight results
struct PendingAsset {
    asset_entry: AssetEntry,
    data: Option<Result<Vec<u8>, DownloadAssetError>>,
    metadata: Option<Result<Vec<u8>, DownloadAssetError>>,
}

async fn download_assets_extended_parallel_in_memory(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_entries: &[(String, AssetEntry)],
    max_concurrent_downloads: usize,
    download_metadata: bool,
) -> Result<AssetExtendedDownloadMap, String> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));

    let mut handles = Vec::new();

    for (asset_ref, asset_entry) in asset_entries {
        // Spawn data download
        if let Some(data_url) = asset_entry.asset.url.as_ref()
            && let Some(hash) = asset_entry.asset.hash.as_ref()
        {
            let sem_clone = Arc::clone(&semaphore);
            let asset_ref_clone = asset_ref.clone();
            let entry_id = asset_entry.entry_id.clone();
            let data_url_clone = data_url.clone();
            let hash_clone = hash.clone();
            let cache_clone = asset_blob_cache.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                (
                    asset_ref_clone,
                    DownloadKind::Data(entry_id),
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
            let asset_ref_clone = asset_ref.clone();
            let entry_id = asset_entry.entry_id.clone();
            let metadata_url_clone = metadata_url.clone();
            let metadata_hash_clone = metadata_hash.clone();
            let cache_clone = asset_blob_cache.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                (
                    asset_ref_clone,
                    DownloadKind::Metadata(entry_id),
                    cache_clone
                        .get_or_download(&metadata_url_clone, &metadata_hash_clone)
                        .await,
                )
            });
            handles.push(handle);
        }
    }

    let results = join_all(handles).await;

    // Intermediate storage: name -> pending results + the originating asset entry
    let mut intermediate: HashMap<String, PendingAsset> = HashMap::new();

    // Initialize entries for all assets that have data URLs
    for (asset_ref, asset_entry) in asset_entries {
        if asset_entry.asset.url.is_some() && asset_entry.asset.hash.is_some() {
            intermediate.insert(
                asset_ref.clone(),
                PendingAsset {
                    asset_entry: asset_entry.clone(),
                    data: None,
                    metadata: None,
                },
            );
        }
    }

    // Collect results
    for result in results {
        match result {
            Ok((asset_ref, kind, download_result)) => match kind {
                DownloadKind::Data(_entry_id) => {
                    if let Some(entry) = intermediate.get_mut(&asset_ref) {
                        entry.data = Some(download_result);
                    }
                }
                DownloadKind::Metadata(_entry_id) => {
                    if let Some(entry) = intermediate.get_mut(&asset_ref) {
                        entry.metadata = Some(download_result);
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

    for (
        asset_ref,
        PendingAsset {
            asset_entry,
            data,
            metadata,
        },
    ) in intermediate
    {
        let result = match data {
            Some(Ok(data)) => {
                // Data succeeded, check metadata
                match metadata {
                    Some(Ok(metadata)) => Ok(AssetDownloadResult {
                        data,
                        metadata: Some(metadata),
                        asset_entry,
                    }),
                    Some(Err(e)) => Err(e), // Metadata download failed
                    None => Ok(AssetDownloadResult {
                        data,
                        metadata: None, // No metadata for this asset
                        asset_entry,
                    }),
                }
            }
            Some(Err(e)) => Err(e), // Data download failed
            None => {
                // This shouldn't happen if we initialized correctly
                continue;
            }
        };

        asset_map.insert(asset_ref, result);
    }

    Ok(asset_map)
}
