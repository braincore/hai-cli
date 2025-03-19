use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::io::Write;
use std::process::Command as SyncCommand;
use std::{fs, io};
use tempfile::NamedTempFile;
use tokio::sync::mpsc::Sender;

/// Function to edit with an editor and watch for changes to trigger a callback
pub fn edit_with_editor_api(
    api_client: &HaiClient,
    shell: &str,
    editor: &str,
    initial_content: &[u8],
    asset_name: &str,
    push: bool,
    tx: Sender<(String, Vec<u8>, bool, HaiClient)>,
) -> io::Result<String> {
    // Create a temporary file with the initial content
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(initial_content)?;
    let file_path = temp_file.path().to_owned();

    // Create a thread-safe notify watcher
    let api_client_cloned = api_client.clone();
    let asset_name_cloned = asset_name.to_string();
    let file_path_cloned = file_path.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            let api_client = api_client_cloned.clone();
            let asset_name = asset_name_cloned.clone();
            let file_path = file_path_cloned.clone();
            match res {
                Ok(event) => {
                    if let notify::EventKind::Modify(_) = event.kind {
                        if let Ok(new_contents) = fs::read(&file_path) {
                            // Send an async message to the worker thread when the file changes
                            let _ = tx.blocking_send((asset_name, new_contents, push, api_client));
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
use crate::api::types::asset::{AssetPushArg, AssetPutArg, PutConflictPolicy};

pub async fn worker_update_asset(
    mut rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>, bool, HaiClient)>,
    _db: Arc<Mutex<rusqlite::Connection>>,
) {
    while let Some((asset_name, new_value, push, api_client)) = rx.recv().await {
        if push {
            match api_client
                .asset_push(AssetPushArg {
                    name: asset_name,
                    data: new_value,
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to push asset: {}", e);
                }
            }
        } else {
            match api_client
                .asset_put(AssetPutArg {
                    name: asset_name,
                    data: new_value,
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to put asset: {}", e);
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
) -> Result<Vec<u8>, GetAssetError> {
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
        Ok(contents) => Ok(contents.to_vec()),
        Err(e) => {
            eprintln!("error: failed to fetch asset: {}", e);
            return Err(GetAssetError::DataFetchFailed);
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
    asset_content.and_then(|bytes| String::from_utf8(bytes).map_err(|_e| GetAssetError::NotText))
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
            return None;
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
