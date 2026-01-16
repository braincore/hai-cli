use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::HaiClient;
use crate::api::types::asset::{
    AssetEntryOp, AssetPushArg, AssetPutArg, AssetReplaceArg, PutConflictPolicy,
    ReplaceConflictPolicy,
};
use crate::asset_cache::AssetBlobCache;
use crate::asset_editor::asset_metadata_set_key;

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
}

use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub async fn worker_update_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    mut rx: tokio::sync::mpsc::Receiver<WorkerAssetMsg>,
    _db: Arc<Mutex<rusqlite::Connection>>,
    debug: bool,
) {
    // asset_name -> (entry_id, asset_rev_id, content_sha256_hash)
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

                let (new_hash_str, new_hash) = crate::asset_cache::compute_sha256(&new_contents);
                let _ = asset_blob_cache
                    .write_cache(&new_hash_str, &new_contents)
                    .await;
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
                if is_push {
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
                        }
                        Err(e) => {
                            let error_msg = format!("error: failed to push asset: {}", e);
                            eprintln!("{}", error_msg);
                            asset_errors
                                .entry(asset_name.clone())
                                .or_default()
                                .push(error_msg);
                        }
                    }
                } else {
                    let bottom = asset_bottom_map
                        .get(&asset_name)
                        .cloned()
                        .or(asset_entry_ref.map(|(id, rev)| (id, rev, vec![])));
                    if let Some((entry_id, rev_id, ..)) = bottom {
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
                                if matches!(res.entry.op, AssetEntryOp::Fork) {
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
                                        (res.entry.entry_id, res.entry.asset.rev_id, new_hash),
                                    );
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("error: failed to replace asset: {}", e);
                                eprintln!("{}", error_msg);
                                asset_errors
                                    .entry(asset_name.clone())
                                    .or_default()
                                    .push(error_msg);
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
                            }
                            Err(e) => {
                                let error_msg = format!("error: failed to put asset: {}", e);
                                eprintln!("{}", error_msg);
                                asset_errors
                                    .entry(asset_name.clone())
                                    .or_default()
                                    .push(error_msg);
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
