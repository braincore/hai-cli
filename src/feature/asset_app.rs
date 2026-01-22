use std::sync::Arc;

use crate::api::client::HaiClient;
use crate::asset_cache::AssetBlobCache;
use crate::asset_helper;
use crate::cmd_processor::{ProcessCmdResult, expand_pub_asset_name};
use crate::session::SessionState;

pub async fn launch_browser(
    session: &mut SessionState,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    is_task_mode_step: bool,
    prog_asset_name: &str,
    target_asset_name: &str,
) -> ProcessCmdResult {
    let prog_asset_name = expand_pub_asset_name(prog_asset_name, &session.account);
    let target_asset_name = expand_pub_asset_name(target_asset_name, &session.account);

    let asset_prog_url =
        if let Some(asset_prog_url) = asset_helper::get_public_asset_url(&prog_asset_name) {
            asset_prog_url
        } else {
            // Prog-asset is private -> use temporary presigned url
            use crate::api::types::asset::AssetGetArg;
            match api_client
                .asset_get(AssetGetArg {
                    name: prog_asset_name.clone(),
                })
                .await
            {
                Ok(res) => {
                    if res
                        .entry
                        .metadata
                        .as_ref()
                        .map_or(false, |md| md.content_encrypted.is_some())
                    {
                        eprintln!(
                            "error: asset '{}' is encrypted; cannot launch in browser",
                            prog_asset_name
                        );
                        return ProcessCmdResult::Loop;
                    } else if let Some(data_url) = res.entry.asset.url {
                        data_url
                    } else {
                        eprintln!(
                            "error: asset '{}' does not have a link; cannot launch in browser",
                            prog_asset_name
                        );
                        return ProcessCmdResult::Loop;
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            }
        };

    if let Ok((ws_addr, clients, cancel_token, auth_token)) =
        crate::feature::gateway::launch_gateway(asset_blob_cache.clone(), api_client.clone()).await
    {
        let sep = if asset_prog_url.contains('?') {
            '&'
        } else {
            '?'
        };
        let suffix = format!(
            "_input={}#_ws=ws://{}&_token={}",
            target_asset_name, ws_addr, auth_token
        );
        let final_url = format!("{}{}{}", asset_prog_url, sep, suffix);
        println!("Opening asset-as-editor in browser: {}", final_url);
        if let Err(e) = open::that_detached(final_url) {
            eprintln!("error: failed to open asset-as-editor in browser: {}", e);
        }
        session
            .gateways
            .push((is_task_mode_step, ws_addr, clients, cancel_token));
    }
    ProcessCmdResult::Loop
}
