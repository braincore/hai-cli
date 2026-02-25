use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset::{
    AssetEntry, AssetEntryOp, AssetMetadataInfo, AssetPushArg, AssetPushError, AssetPutArg,
    AssetPutError, AssetReplaceArg, AssetReplaceError, PutConflictPolicy, ReplaceConflictPolicy,
};
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader;
use crate::feature::asset_crypt;

#[derive(Debug)]
pub enum WorkerAssetMsg {
    Init(WorkerAssetInit),
    Update(WorkerAssetUpdate),
    Done(String), // asset_name
    Flush(tokio::sync::oneshot::Sender<()>),
}

#[derive(Debug)]
pub struct WorkerAssetInit {
    pub asset_name: String,
    pub asset_entry_ref: (String, String), // (entry_id, rev_id)
    pub new_contents: Vec<u8>,
}

#[derive(Debug)]
pub struct WorkerAssetUpdate {
    pub asset_name: String,
    pub asset_entry_ref: Option<(String, String)>, // (entry_id, rev_id)
    pub new_contents: Vec<u8>,
    pub is_push: bool,
    pub api_client: HaiClient,
    pub one_shot: bool,
    pub akm_info: Option<crate::feature::asset_crypt::AssetKeyMaterial>,
    pub reply_channel: Option<tokio::sync::oneshot::Sender<Result<AssetEntry, AssetSaveError>>>,
}

#[derive(Debug)]
pub enum AssetSaveError {
    Put(RequestError<AssetPutError>),
    Replace(RequestError<AssetReplaceError>),
    Push(RequestError<AssetPushError>),
}

pub async fn worker_update_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    mut rx: tokio::sync::mpsc::Receiver<WorkerAssetMsg>,
    _db: Arc<Mutex<rusqlite::Connection>>,
    debug: bool,
) {
    // asset_name -> (entry_id, asset_rev_id, UNENCRYPTED_content_sha256_hash)
    let mut asset_bottom_map: HashMap<String, (String, String, Vec<u8>)> = HashMap::new();
    // Track errors because the editor sometimes swallows the errors so instead
    // we print them once the user has exited.
    // asset_name -> vec[errors]
    let mut asset_errors: HashMap<String, Vec<String>> = HashMap::new();
    while let Some(msg) = rx.recv().await {
        match msg {
            WorkerAssetMsg::Init(WorkerAssetInit {
                asset_name,
                asset_entry_ref,
                new_contents,
            }) => {
                let new_hash = Sha256::digest(&new_contents).to_vec();
                asset_bottom_map
                    .insert(asset_name, (asset_entry_ref.0, asset_entry_ref.1, new_hash));
            }
            WorkerAssetMsg::Update(WorkerAssetUpdate {
                asset_name,
                asset_entry_ref,
                new_contents,
                is_push,
                api_client,
                one_shot,
                akm_info,
                reply_channel,
            }) => {
                // Treat asset as markdown if it has .md extension or does not
                // have an extension
                let is_markdown = {
                    let path = std::path::Path::new(&asset_name);
                    match path.extension() {
                        None => true,
                        Some(ext) => ext.to_string_lossy().to_lowercase() == "md", // .md extension
                    }
                };
                let mut md_title = None;
                if is_markdown
                    && let Ok(content_str) = std::str::from_utf8(&new_contents)
                    && let Some(first_line) = content_str.lines().next()
                    && let Some(title_candidate) = first_line.strip_prefix("# ")
                {
                    let title = title_candidate.trim().to_string();
                    if !title.is_empty() {
                        md_title = Some(serde_json::Value::String(title));
                    }
                }

                let (new_hash_str, new_hash) =
                    crate::asset_cache::compute_sha256_in_memory(&new_contents);
                // Check if the hash matches the last known hash
                if let Some((_, _, last_hash)) = asset_bottom_map.get(&asset_name)
                    && &new_hash == last_hash
                {
                    if debug {
                        let _ = crate::config::write_to_debug_log(format!(
                            "worker-update-asset: skipped update for '{}' (hash unchanged)\n",
                            asset_name
                        ));
                    }
                    continue;
                }
                let (new_hash_str, new_contents) = if let Some(akm_info) = akm_info.as_ref() {
                    let enc_content = crate::feature::asset_crypt::encrypt_asset_with_aes_key(
                        &akm_info.sym_key_info.aes_key,
                        &new_contents,
                    );
                    (
                        crate::asset_cache::compute_sha256_in_memory(&enc_content).0,
                        enc_content,
                    )
                } else {
                    (new_hash_str, new_contents)
                };
                // NOTE: If encryption used, add encrypted version to blob cache
                let _ = asset_blob_cache
                    .write_cache(&new_hash_str, &new_contents)
                    .await;

                let new_entry = if is_push {
                    match api_client
                        .asset_push(AssetPushArg {
                            name: asset_name.clone(),
                            data: new_contents,
                        })
                        .await
                    {
                        Ok(res) => {
                            if debug {
                                let _ = crate::config::write_to_debug_log(format!(
                                    "asset-push-result: {:?}\n",
                                    res
                                ));
                            }
                            if res
                                .entry
                                .metadata
                                .as_ref()
                                .map(|md| md.content_encrypted.is_none())
                                .unwrap_or(true)
                                && let Some(akm_info) = akm_info.as_ref()
                            {
                                // If this is the first time putting the
                                // asset and it's encrypted, store the
                                // encryption metadata.
                                if let Err(e) = asset_crypt::put_asset_encryption_metadata(
                                    &api_client,
                                    &asset_name,
                                    &akm_info,
                                )
                                .await
                                {
                                    eprintln!(
                                        "error: failed to put asset encryption metadata: {}",
                                        e
                                    );
                                }
                            }
                            Ok(res.entry)
                        }
                        Err(e) => {
                            let error_msg = format!("error: failed to push asset: {}", e);
                            eprintln!("{}", error_msg);
                            asset_errors
                                .entry(asset_name.clone())
                                .or_default()
                                .push(error_msg);
                            Err(AssetSaveError::Push(e))
                        }
                    }
                } else {
                    let bottom = asset_bottom_map
                        .get(&asset_name)
                        .cloned()
                        .or(asset_entry_ref.map(|(id, rev)| (id, rev, vec![])));
                    let new_entry = if let Some((entry_id, rev_id, ..)) = bottom {
                        match api_client
                            .asset_replace(AssetReplaceArg {
                                entry_id,
                                rev_id: Some(rev_id),
                                data: new_contents,
                                conflict_policy: ReplaceConflictPolicy::Fork,
                            })
                            .await
                        {
                            Ok(res) => {
                                if debug {
                                    let _ = crate::config::write_to_debug_log(format!(
                                        "asset-replace-result: {:?}\n",
                                        res
                                    ));
                                }
                                if matches!(res.entry.op.clone(), AssetEntryOp::Fork) {
                                    // Since this isn't an error, it doesn't
                                    // need to printed immediately to the
                                    // terminal which tends to bork the UI of
                                    // terminal-based editors (e.g. vim).
                                    let error_msg = format!(
                                        "notice: asset '{}' was forked to '{}'",
                                        asset_name, res.entry.name
                                    );
                                    asset_errors
                                        .entry(asset_name.clone())
                                        .or_default()
                                        .push(error_msg);
                                }

                                if !one_shot {
                                    // Update the asset_bottom_map with new leaf node
                                    asset_bottom_map.insert(
                                        asset_name.clone(),
                                        (
                                            res.entry.entry_id.clone(),
                                            res.entry.asset.rev_id.clone(),
                                            new_hash,
                                        ),
                                    );
                                }
                                Ok(res.entry)
                            }
                            Err(e) => {
                                let error_msg = format!("error: failed to replace asset: {}", e);
                                eprintln!("{}", error_msg);
                                asset_errors
                                    .entry(asset_name.clone())
                                    .or_default()
                                    .push(error_msg);
                                Err(AssetSaveError::Replace(e))
                            }
                        }
                    } else {
                        match api_client
                            .asset_put(AssetPutArg {
                                name: asset_name.clone(),
                                data: new_contents,
                                conflict_policy: PutConflictPolicy::Override,
                            })
                            .await
                        {
                            Ok(res) => {
                                if debug {
                                    let _ = crate::config::write_to_debug_log(format!(
                                        "asset-put-result: {:?}\n",
                                        res
                                    ));
                                }
                                if res
                                    .entry
                                    .metadata
                                    .as_ref()
                                    .map(|md| md.content_encrypted.is_none())
                                    .unwrap_or(true)
                                    && let Some(akm_info) = akm_info.as_ref()
                                {
                                    // If this is the first time putting the
                                    // asset and it's encrypted, store the
                                    // encryption metadata.
                                    if let Err(e) = asset_crypt::put_asset_encryption_metadata(
                                        &api_client,
                                        &asset_name,
                                        &akm_info,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "error: failed to put asset encryption metadata: {}",
                                            e
                                        );
                                    }
                                }
                                Ok(res.entry)
                            }
                            Err(e) => {
                                let error_msg = format!("error: failed to put asset: {}", e);
                                eprintln!("{}", error_msg);
                                asset_errors
                                    .entry(asset_name.clone())
                                    .or_default()
                                    .push(error_msg);
                                Err(AssetSaveError::Put(e))
                            }
                        }
                    };
                    if is_markdown
                        && let Ok(asset_entry) =
                            asset_metadata_set_key(&api_client, &asset_name, "title", md_title)
                                .await
                        && !one_shot
                        && let Some((_, _, existing_hash)) = asset_bottom_map.get(&asset_name)
                    {
                        // Metadata updates change the revision
                        // ID which we need to update to avoid
                        // forking.
                        asset_bottom_map.insert(
                            asset_name.clone(),
                            (
                                asset_entry.entry_id,
                                asset_entry.asset.rev_id,
                                existing_hash.clone(),
                            ),
                        );
                    }
                    new_entry
                };
                if let Some(reply_channel) = reply_channel {
                    let _ = reply_channel.send(new_entry);
                }
            }
            WorkerAssetMsg::Done(asset_name) => {
                if debug {
                    let _ = crate::config::write_to_debug_log(format!(
                        "worker-update-asset: done: {}\n",
                        asset_name
                    ));
                }
                asset_bottom_map.remove(&asset_name);
                let errors = asset_errors.remove(&asset_name);
                if let Some(errors) = errors
                    && !errors.is_empty()
                {
                    eprintln!("errors while in editor:");
                    for error_msg in errors {
                        eprintln!("{}", error_msg);
                    }
                }
            }
            WorkerAssetMsg::Flush(response_tx) => {
                // All previous messages have been processed by the time we get here
                let _ = response_tx.send(());
            }
        }
    }
}

pub async fn flush_asset_updates(update_asset_tx: &tokio::sync::mpsc::Sender<WorkerAssetMsg>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _ = update_asset_tx.send(WorkerAssetMsg::Flush(tx)).await;
    let _ = rx.await; // Wait for flush to complete
}

// --

/// Sets the metadata field `key` to `value` for the asset.
///
/// This function is necessary because the API only supports setting the entire
/// metadata object at once, rather than individual fields.
///
/// On error, prints reason.
pub async fn asset_metadata_set_key(
    api_client: &HaiClient,
    asset_name: &str,
    key: &str,
    value: Option<serde_json::Value>,
) -> Result<AssetEntry, ()> {
    use crate::api::types::asset::AssetGetArg;
    match api_client
        .asset_get(AssetGetArg {
            name: asset_name.to_string(),
        })
        .await
    {
        Ok(res) => {
            let mut md_json = if let Some(AssetMetadataInfo {
                url: Some(metadata_url),
                ..
            }) = res.entry.metadata.as_ref()
            {
                if let Some(contents_bin) = asset_reader::get_asset_raw(metadata_url).await {
                    let contents = String::from_utf8_lossy(&contents_bin);
                    serde_json::from_str::<serde_json::Value>(&contents)
                        .expect("failed to parse metadata")
                } else {
                    return Err(());
                }
            } else {
                serde_json::json!({})
            };
            // Check if the current value is the same as the target value
            let needs_update = if let Some(map) = md_json.as_object() {
                match (&value, map.get(key)) {
                    (Some(target_value), Some(current_value)) => target_value != current_value,
                    (None, None) => false,
                    _ => true,
                }
            } else {
                // If metadata is not a map, we'll need to update
                value.is_some()
            };
            if !needs_update {
                return Ok(res.entry);
            }
            if let Some(map) = md_json.as_object_mut() {
                if let Some(value) = value {
                    map.insert(key.to_string(), value);
                } else {
                    map.remove(key);
                }
            } else {
                eprintln!("unexpected: metadata is not a map");
                return Err(());
            }
            let md_contents =
                serde_json::to_string(&md_json).expect("failed to serialize metadata");
            use crate::api::types::asset::{AssetMetadataPutArg, PutConflictPolicy};
            // NOTE/FUTURE: Better to switch to reject conflict-policy and
            // refetch the metadata on rejection.
            match api_client
                .asset_metadata_put(AssetMetadataPutArg {
                    name: asset_name.to_owned(),
                    data: md_contents,
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await
            {
                Ok(res) => Ok(res.entry),
                Err(e) => {
                    eprintln!("error: {}", e);
                    Err(())
                }
            }
        }
        Err(e) => {
            eprintln!("error: {}", e);
            Err(())
        }
    }
}

/// Merges source and target metadata objects.
///
/// - If there's no source_md, returns target_md.
/// - If there's no target_md, returns source_md (excluding the "encrypted" key).
/// - If both exist, combines target_md with source_md, where:
///   - The "encrypted" key from source_md is always ignored.
///   - target_md keys take priority in case of conflicts.
///
/// Returns the merged metadata, or None if both inputs are None.
pub fn metadata_merge(
    source_md: Option<serde_json::Value>,
    target_md: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (source_md, target_md) {
        // No source, just use target
        (None, target) => target,

        // No target, use source but remove "encrypted" key
        (Some(mut source), None) => {
            if let Some(map) = source.as_object_mut() {
                map.remove("encrypted");
            }
            Some(source)
        }

        // Both exist, merge them with target taking priority
        (Some(source), Some(mut target)) => {
            if let (Some(source_map), Some(target_map)) =
                (source.as_object(), target.as_object_mut())
            {
                for (key, value) in source_map {
                    // Skip "encrypted" key from source
                    if key == "encrypted" {
                        continue;
                    }
                    // Only insert if target doesn't already have this key
                    if !target_map.contains_key(key) {
                        target_map.insert(key.clone(), value.clone());
                    }
                }
            }
            Some(target)
        }
    }
}
