use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::io::Write;
use std::process::Command as SyncCommand;
use std::{fs, io};
use tempfile::NamedTempFile;
use tokio::sync::mpsc::Sender;

#[allow(clippy::too_many_arguments)]
/// Function to edit with an editor and watch for changes to trigger a callback
pub async fn edit_with_editor_api(
    api_client: &HaiClient,
    shell: &str,
    editor: &str,
    initial_content: &[u8],
    asset_name: &str,
    asset_entry_ref: Option<(String, String)>, // (entry_id, rev_id)
    is_push: bool,
    tx: Sender<WorkerAssetMsg>,
    debug: bool,
) -> io::Result<String> {
    // Create a temporary file with the initial content
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(initial_content)?;
    let file_path = temp_file.path().to_owned();

    let tx_to_send_done = tx.clone();

    // Create a thread-safe notify watcher
    let api_client_cloned = api_client.clone();
    let asset_name_cloned = asset_name.to_string();
    let asset_entry_ref_cloned = asset_entry_ref
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .clone();
    let file_path_cloned = file_path.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            let api_client = api_client_cloned.clone();
            let asset_name = asset_name_cloned.clone();
            let asset_entry_ref = asset_entry_ref_cloned.clone();
            let file_path = file_path_cloned.clone();
            match res {
                Ok(event) => {
                    if debug {
                        let _ = crate::config::write_to_debug_log(format!(
                            "asset-watcher: {}: {:?}: {:?}\n",
                            asset_name, asset_entry_ref, event
                        ));
                    }
                    if let notify::EventKind::Modify(notify::event::ModifyKind::Data(_)) =
                        event.kind
                    {
                        if let Ok(new_contents) = fs::read(&file_path) {
                            // Send an async message to the worker thread when the file changes
                            let msg = WorkerAssetMsg::Update(WorkerAssetUpdate {
                                asset_name,
                                asset_entry_ref,
                                new_contents,
                                is_push,
                                api_client,
                                one_shot: false,
                            });
                            let _ = tx.blocking_send(msg);
                        }
                    }
                }
                Err(e) => eprintln!("Watch error: {:?}", e),
            }
        },
        notify::Config::default(),
    )
    .expect("error: failed to create watcher");

    // Watch the temp file for changes
    watcher
        .watch(&file_path, RecursiveMode::NonRecursive)
        .expect("error: failed to watch for file changes");

    // Execute editor
    let status = SyncCommand::new(shell)
        .arg("-c")
        .arg(format!("{} {}", editor, file_path.to_string_lossy()))
        .status()
        .expect("failed to launch editor");

    // Stop watching once the editor exits
    drop(watcher);

    // Send an async message to the worker thread that the edits are done so it
    // can clean its state.
    let msg = WorkerAssetMsg::Done(asset_name.to_string());
    let _ = tx_to_send_done.send(msg).await;

    if !status.success() {
        eprintln!("error: editor did not exit successfully");
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Editor failed",
        ));
    }

    // Check the final modified contents
    let edited_content = fs::read_to_string(file_path)?;

    Ok(edited_content)
}

// --

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::HaiClient;
use crate::api::types::asset::{
    AssetEntry, AssetEntryOp, AssetPushArg, AssetPutArg, AssetReplaceArg, PutConflictPolicy,
    ReplaceConflictPolicy,
};

#[derive(Debug)]
pub enum WorkerAssetMsg {
    Update(WorkerAssetUpdate),
    Done(String), // asset_name
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

use std::collections::HashMap;

pub async fn worker_update_asset(
    mut rx: tokio::sync::mpsc::Receiver<WorkerAssetMsg>,
    _db: Arc<Mutex<rusqlite::Connection>>,
    debug: bool,
) {
    // asset_name -> (entry_id, asset_rev_id)
    let mut asset_bottom_map: HashMap<String, (String, String)> = HashMap::new();
    // Track errors because the editor sometimes swallows the errors so instead
    // we print them once the user has exited.
    // asset_name -> vec[errors]
    let mut asset_errors: HashMap<String, Vec<String>> = HashMap::new();
    while let Some(msg) = rx.recv().await {
        match msg {
            WorkerAssetMsg::Update(WorkerAssetUpdate {
                asset_name,
                asset_entry_ref,
                new_contents,
                is_push,
                api_client,
                one_shot,
            }) => {
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
                        .or(asset_entry_ref);
                    if let Some((entry_id, rev_id)) = bottom {
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
                                    // Update the asset_bottom_map with the new entry_id and rev_id
                                    asset_bottom_map.insert(
                                        asset_name.clone(),
                                        (res.entry.entry_id, res.entry.asset.rev_id),
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
                if let Some(errors) = errors {
                    if !errors.is_empty() {
                        eprintln!("errors while in editor:");
                        for error_msg in errors {
                            eprintln!("{}", error_msg);
                        }
                    }
                }
            }
        }
    }
}

pub enum GetAssetError {
    BadName,
    DataFetchFailed,
    NotText,
}

/// If returns None, responsible for printing error msg.
pub async fn get_asset(
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<(Vec<u8>, AssetEntry), GetAssetError> {
    use crate::api::types::asset::AssetGetArg;
    let asset_get_res = match api_client
        .asset_get(AssetGetArg {
            name: asset_name.to_string(),
        })
        .await
    {
        Ok(res) => res,
        Err(e) => {
            if bad_name_ok
                && matches!(
                    e,
                    crate::api::client::RequestError::Route(
                        crate::api::types::asset::AssetGetError::BadName
                    )
                )
            {
                return Err(GetAssetError::BadName);
            } else {
                eprintln!("error: {}", e);
            }
            return Err(GetAssetError::BadName);
        }
    };
    let asset_get_resp = match reqwest::get(asset_get_res.data_url).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("error: {}", e);
            return Err(GetAssetError::DataFetchFailed);
        }
    };
    if !asset_get_resp.status().is_success() {
        eprintln!("error: failed to fetch asset: {}", asset_get_resp.status());
        return Err(GetAssetError::DataFetchFailed);
    }
    match asset_get_resp.bytes().await {
        Ok(contents) => Ok((contents.to_vec(), asset_get_res.entry)),
        Err(e) => {
            eprintln!("error: failed to fetch asset: {}", e);
            Err(GetAssetError::DataFetchFailed)
        }
    }
}

/// If returns None, responsible for printing error msg.
pub async fn get_asset_as_text(
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<String, GetAssetError> {
    let asset_content = get_asset(api_client, asset_name, bad_name_ok).await;
    asset_content
        .and_then(|(bytes, _)| String::from_utf8(bytes).map_err(|_e| GetAssetError::NotText))
}

pub async fn get_asset_raw(data_url: &str) -> Option<Vec<u8>> {
    let asset_get_resp = match reqwest::get(data_url).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("error: {}", e);
            return None;
        }
    };
    if !asset_get_resp.status().is_success() {
        eprintln!("error: failed to fetch asset: {}", asset_get_resp.status());
        return None;
    }
    match asset_get_resp.bytes().await {
        Ok(contents) => Some(contents.to_vec()),
        Err(e) => {
            eprintln!("error: asset is non-text: {}", e);
            None
        }
    }
}

// --

use regex::Regex;
use std::sync::OnceLock;

pub fn get_invalid_asset_name_re() -> &'static Regex {
    static ASSET_NAME_RE: OnceLock<Regex> = OnceLock::new();
    ASSET_NAME_RE.get_or_init(|| {
        Regex::new(r##"(?://{1,})|[\[@+!#\$%^&\*<>,?\\|}{~:;\[\]\s"'=`]"##).unwrap()
    })
}
