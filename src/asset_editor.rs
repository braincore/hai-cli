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
    asset_content_type: Option<String>,
    is_push: bool,
    tx: Sender<WorkerAssetMsg>,
    debug: bool,
) -> io::Result<Vec<u8>> {
    // Create a temporary file with an extension to assist editors that use the
    // extension for syntax highlighting (e.g. vim)
    let ext =
        best_guess_temp_file_extension(asset_name, asset_content_type.as_deref(), initial_content);
    let mut temp_file = NamedTempFile::with_suffix(&ext)?;
    temp_file.write_all(initial_content)?;
    let file_path = temp_file.path().to_owned();

    let tx_main = tx.clone();

    if let Some(asset_entry_ref) = asset_entry_ref.as_ref() {
        let init_msg = WorkerAssetMsg::Init(WorkerAssetInit {
            asset_name: asset_name.to_string(),
            asset_entry_ref: asset_entry_ref.clone(),
            new_contents: initial_content.to_vec(),
        });
        let _ = tx_main.send(init_msg).await;
    }

    // Create a thread-safe notify watcher
    let api_client_cloned = api_client.clone();
    let asset_name_cloned = asset_name.to_string();
    let asset_entry_ref_cloned = asset_entry_ref
        .as_ref()
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
        notify::Config::default().with_compare_contents(true),
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
    // Sometimes the watcher hasn't even finished reporting events (noticed on
    // macOS with fsevent) so we do a final check for changed contents below.
    drop(watcher);

    // Check the final modified contents
    // Worker is responsible for no-oping if contents unchanged
    let final_contents = fs::read(file_path)?;
    let final_update_msg = WorkerAssetMsg::Update(WorkerAssetUpdate {
        asset_name: asset_name.to_string(),
        asset_entry_ref,
        new_contents: final_contents.clone(),
        is_push,
        api_client: api_client.clone(),
        one_shot: false,
    });
    let _ = tx_main.send(final_update_msg).await;

    // Send an async message to the worker thread that the edits are done so it
    // can clean its state.
    let done_msg = WorkerAssetMsg::Done(asset_name.to_string());
    let _ = tx_main.send(done_msg).await;

    if !status.success() {
        eprintln!("error: editor did not exit successfully");
        return Err(std::io::Error::other("Editor failed"));
    }

    Ok(final_contents)
}

fn best_guess_temp_file_extension(
    asset_name: &str,
    asset_content_type: Option<&str>,
    initial_content: &[u8],
) -> String {
    let ext_from_name = Path::new(asset_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_string());
    let ext_from_content_type = asset_content_type
        .as_ref()
        .and_then(|ct| mime_guess::get_mime_extensions_str(ct))
        // Pick the shortest so that "md" is prioritized over "markdown"
        .and_then(|exts| exts.iter().min_by_key(|s| s.len()).copied())
        .map(|s| s.to_string());
    // If there's an asset_content_type that doesn't produce a extension via
    // mime-guess, then we don't want to assume it's markdown.
    let ext_from_markdown = if asset_content_type.is_none() && initial_content.starts_with(b"# ") {
        Some("md".to_string())
    } else {
        None
    };
    // Combine all options, in order of priority
    ext_from_name
        .or(ext_from_content_type)
        .or(ext_from_markdown)
        .map(|ext| format!(".{}", ext))
        .unwrap_or_default()
}

// --

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset::{
    AssetEntry, AssetEntryOp, AssetGetError, AssetMetadataInfo, AssetPushArg, AssetPutArg,
    AssetReplaceArg, PutConflictPolicy, ReplaceConflictPolicy,
};

#[derive(Debug)]
pub enum WorkerAssetMsg {
    Init(WorkerAssetInit),
    Update(WorkerAssetUpdate),
    Done(String), // asset_name
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
                if is_markdown {
                    if let Ok(content_str) = std::str::from_utf8(&new_contents) {
                        if let Some(first_line) = content_str.lines().next() {
                            if let Some(title_candidate) = first_line.strip_prefix("# ") {
                                let title = title_candidate.trim().to_string();
                                if !title.is_empty() {
                                    md_title = Some(serde_json::Value::String(title));
                                }
                            }
                        }
                    }
                }

                let new_hash = Sha256::digest(&new_contents).to_vec();
                // Check if the hash matches the last known hash
                if let Some((_, _, last_hash)) = asset_bottom_map.get(&asset_name) {
                    if &new_hash == last_hash {
                        if debug {
                            let _ = crate::config::write_to_debug_log(format!(
                                "worker-update-asset: skipped update for '{}' (hash unchanged)\n",
                                asset_name
                            ));
                        }
                        continue;
                    }
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
                    if is_markdown {
                        if let Ok(asset_entry) =
                            asset_metadata_set_key(&api_client, &asset_name, "title", md_title)
                                .await
                        {
                            if !one_shot {
                                if let Some((_, _, existing_hash)) =
                                    asset_bottom_map.get(&asset_name)
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

// --

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
    let asset_get_res = get_asset_entry(api_client, asset_name, bad_name_ok).await?;
    if let Some(data_url) = asset_get_res.entry.asset.url.as_ref() {
        let data_contents = download_asset(data_url).await?;
        Ok((data_contents, asset_get_res.entry))
    } else {
        Err(GetAssetError::BadName)
    }
}

use crate::api::types::asset::{AssetGetArg, AssetGetResult};

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
            } else {
                eprintln!("error: {}", e);
            }
            match e {
                RequestError::BadRequest(_)
                | RequestError::Http(_)
                | RequestError::Unexpected(_) => Err(GetAssetError::DataFetchFailed),
                RequestError::Route(e) => match e {
                    AssetGetError::BadName => Err(GetAssetError::BadName),
                    _ => Err(GetAssetError::DataFetchFailed),
                },
            }
        }
    }
}

pub async fn download_asset(url: &str) -> Result<Vec<u8>, GetAssetError> {
    let asset_get_resp = match reqwest::get(url).await {
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
        Ok(contents) => Ok(contents.to_vec()),
        Err(e) => {
            eprintln!("error: failed to fetch asset: {}", e);
            Err(GetAssetError::DataFetchFailed)
        }
    }
}

// --

/// If returns None, responsible for printing error msg.
pub async fn get_asset_and_metadata(
    api_client: &HaiClient,
    asset_name: &str,
    bad_name_ok: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>, AssetEntry), GetAssetError> {
    let asset_get_res = get_asset_entry(api_client, asset_name, bad_name_ok).await?;
    let data_contents = if let Some(data_url) = asset_get_res.entry.asset.url.as_ref() {
        download_asset(data_url).await?
    } else {
        return Err(GetAssetError::BadName);
    };
    let metadata_contents = if let Some(AssetMetadataInfo {
        url: Some(metadata_url),
        ..
    }) = asset_get_res.entry.metadata.as_ref()
    {
        Some(download_asset(metadata_url).await?)
    } else {
        None
    };
    Ok((data_contents, metadata_contents, asset_get_res.entry))
}

// --

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

// --

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
                if let Some(contents_bin) = get_asset_raw(metadata_url).await {
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

// --

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Prepares @assets in shell commands and handles redirections.
///
/// This function:
/// 1. Identifies all @asset references in the command
/// 2. Downloads input assets to temporary files on the local machine
/// 3. Creates appropriate temporary files for output assets
/// 4. Handles append operations (>>) by downloading existing assets first
/// 5. Rewrites the shell command to use the local file paths
///
/// # Returns
/// * A tuple containing:
///   - The modified command with @assets replaced by file paths
///   - A map of asset names to their temporary files and paths
///   - A set of asset names that are used as outputs (via > or >>)
///
/// # Examples
///
/// ```
/// // Original: !!cat @input > @output
/// // Modified: !!cat /tmp/asset_123.txt > /tmp/asset_456.txt
/// let (modified_cmd, asset_map, output_assets) = prepare_assets(&client, "!!cat @input > @output").await?;
/// // output_assets contains "output"
/// ```
pub async fn prepare_assets(
    api_client: &HaiClient,
    cmd: &str,
) -> Result<
    (
        String,
        HashMap<String, (tempfile::NamedTempFile, PathBuf)>,
        HashSet<String>,
    ),
    String,
> {
    let asset_regex = Regex::new(r"@([^\s]+)").expect("Invalid regex");

    let append_regex = Regex::new(r">>\s*@([^\s]+)").expect("Invalid regex");
    let output_regex = Regex::new(r"(?:>|>>)\s*@([^\s]+)").expect("Invalid regex");

    let mut append_assets = HashSet::new();
    let mut output_assets = HashSet::new();

    let mut asset_map = HashMap::new();

    // Original @asset name and the temp file path it will be replaced by.
    let mut replacements = Vec::new();

    // First identify output assets and append assets
    for cap in output_regex.captures_iter(cmd) {
        let output_asset = cap[1].to_string();
        output_assets.insert(output_asset);
    }

    for cap in append_regex.captures_iter(cmd) {
        let append_asset = cap[1].to_string();
        append_assets.insert(append_asset);
    }

    // Process all assets
    for cap in asset_regex.captures_iter(cmd) {
        let full_match = cap[0].to_string();
        let asset_path = cap[1].to_string();

        // Skip if we've already processed this asset
        if asset_map.contains_key(&asset_path) {
            continue;
        }

        // For append assets (>>), we need to download them first
        // For output assets with (>), we can just create an empty file
        // For input assets, download them
        let (temp_file, temp_file_path) =
            if output_assets.contains(&asset_path) && !append_assets.contains(&asset_path) {
                // Simple output with > (overwrite), just create empty file
                create_empty_temp_file(&asset_path, None)?
            } else {
                // Either an input asset or an append asset (>>), download it
                download_asset_to_temp(api_client, &asset_path).await?
            };

        replacements.push((full_match, temp_file_path.to_string_lossy().to_string()));

        // Store the mapping
        asset_map.insert(asset_path.clone(), (temp_file, temp_file_path));
    }

    // Perform replacements of @asset with temp files from longest first to
    // avoid collisions with assets whose names are subsets of one another.
    replacements.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
    let mut modified_cmd = cmd.to_string();
    for (pattern, replacement) in replacements {
        modified_cmd = modified_cmd.replace(&pattern, &replacement);
    }

    Ok((modified_cmd, asset_map, output_assets))
}

/// Download an asset to a temporary file
///
/// NOTE: The NamedTempFile is returned. When it eventually goes out of scope,
/// the temporary file will be removed.
async fn download_asset_to_temp(
    api_client: &HaiClient,
    asset_name: &str,
) -> Result<(tempfile::NamedTempFile, PathBuf), String> {
    let (temp_file, temp_file_path) = create_empty_temp_file(asset_name, None)?;
    let (asset_contents, _) = match get_asset(api_client, asset_name, false).await {
        Ok(contents) => contents,
        Err(e) => {
            return Err(match e {
                GetAssetError::BadName => format!("bad name: {}", asset_name),
                GetAssetError::DataFetchFailed => format!("fetch failed: {}", asset_name),
                _ => format!("unexpected error: {}", asset_name),
            });
        }
    };
    match fs::write(&temp_file_path, asset_contents) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: failed to save: {}", e);
        }
    }
    Ok((temp_file, temp_file_path))
}

/// Create an empty temporary file for output assets
pub fn create_empty_temp_file(
    asset_name: &str,
    rev_id: Option<&str>,
) -> Result<(tempfile::NamedTempFile, PathBuf), String> {
    // Create a temporary file copying the extension
    let extension = Path::new(asset_name)
        .extension()
        .and_then(|ext| ext.to_str().map(|s| format!(".{}", s)))
        .unwrap_or_default();
    let mut prefix = "asset_".to_string();
    if let Some(rev_id) = rev_id {
        prefix.push_str(rev_id);
        prefix.push('_');
    }
    let temp_file = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(&extension)
        .tempfile()
        .map_err(|e| format!("Failed to create temporary file: {}", e))?;

    // Get the path to the temporary file
    let temp_file_path = temp_file.path().to_path_buf();

    Ok((temp_file, temp_file_path))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_best_guess_temp_file_extension() {
        use super::best_guess_temp_file_extension;

        // Extension from name
        let ext = best_guess_temp_file_extension("foo.md", None, b"# heading");
        assert_eq!(ext, ".md");

        // Extension from content type
        let ext = best_guess_temp_file_extension("foo", Some("text/markdown"), b"# heading");
        assert_eq!(ext, ".md");

        // Extension from markdown content
        let ext = best_guess_temp_file_extension("foo", None, b"# heading");
        assert_eq!(ext, ".md");

        // No extension
        let ext = best_guess_temp_file_extension("foo", None, b"plain text");
        assert_eq!(ext, "");

        // Content type with no known extension
        let ext =
            best_guess_temp_file_extension("foo", Some("application/x-unknown"), b"# heading");
        assert_eq!(ext, "");

        // Name and content type: prefers name
        let ext = best_guess_temp_file_extension("foo.txt", Some("text/markdown"), b"# heading");
        assert_eq!(ext, ".txt");

        // Name and markdown: prefers name
        let ext = best_guess_temp_file_extension("foo.txt", None, b"# heading");
        assert_eq!(ext, ".txt");
    }
}
