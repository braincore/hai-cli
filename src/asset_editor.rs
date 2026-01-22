use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::io::Write;
use std::path::Path;
use std::process::Command as SyncCommand;
use std::{fs, io};
use tempfile::NamedTempFile;
use tokio::sync::mpsc::Sender;

use crate::api::client::HaiClient;
use crate::asset_async_writer::{WorkerAssetInit, WorkerAssetMsg, WorkerAssetUpdate};

#[allow(clippy::too_many_arguments)]
/// Function to sync asset changes while editing asset with external editor.
///
/// A filewatcher is used to detect changes to the asset file and trigger
/// a callback to write the changes to the asset backend.
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
    akm_info: Option<crate::feature::asset_crypt::AssetKeyMaterial>,
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
    let akm_info_cloned = akm_info.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            let api_client = api_client_cloned.clone();
            let asset_name = asset_name_cloned.clone();
            let asset_entry_ref = asset_entry_ref_cloned.clone();
            let file_path = file_path_cloned.clone();
            let akm_info = akm_info_cloned.clone();
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
                        && let Ok(new_contents) = fs::read(&file_path)
                    {
                        // Send an async message to the worker thread when the file changes
                        let msg = WorkerAssetMsg::Update(WorkerAssetUpdate {
                            asset_name,
                            asset_entry_ref,
                            new_contents,
                            is_push,
                            api_client,
                            one_shot: false,
                            akm_info,
                        });
                        let _ = tx.blocking_send(msg);
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
        akm_info,
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
