use std::sync::Arc;

use crate::api::client::HaiClient;
use crate::asset_cache::AssetBlobCache;
use crate::asset_helper;
use crate::cmd_processor::expand_pub_asset_name;
use crate::session::SessionState;

pub async fn launch_browser(
    session: &mut SessionState,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<crate::asset_async_writer::WorkerAssetMsg>,
    is_task_mode_step: bool,
    prog_asset_name: &str,
    target_asset_name: Option<&str>,
    debug: bool,
) {
    let prog_asset_name = expand_pub_asset_name(prog_asset_name, &session.account);
    let target_asset_name = target_asset_name.map(|n| expand_pub_asset_name(n, &session.account));

    if let Ok((ws_addr, clients, cancel_token, auth_token)) =
        crate::feature::gateway::launch_gateway(
            asset_blob_cache.clone(),
            session.asset_keyring.clone(),
            api_client.clone(),
            username,
            update_asset_tx.clone(),
        )
        .await
    {
        let localhost_addr = format!("localhost:{}", ws_addr.port());
        let (asset_prog_url, asset_prog_from_localhost) =
            if let Some(asset_prog_url) = asset_helper::get_public_asset_url(&prog_asset_name) {
                if debug {
                    (
                        format!("http://{}{}", localhost_addr, prog_asset_name),
                        true,
                    )
                } else {
                    (asset_prog_url, false)
                }
            } else {
                // Prog-asset is private -> use proxy through the gateaway
                use crate::api::types::asset::AssetGetArg;
                match api_client
                    .asset_get(AssetGetArg {
                        name: prog_asset_name.clone(),
                    })
                    .await
                {
                    Ok(res) => {
                        // NOTE: Both the encrypted and unencrypted code paths
                        // use the same gateway proxy URL. They are kept
                        // separate to make it clear that the encrypted path
                        // has no other option but to proxy whereas the
                        // unencrypted path could use the temporary public URL.
                        if res
                            .entry
                            .metadata
                            .as_ref()
                            .map_or(false, |md| md.content_encrypted.is_some())
                        {
                            (
                                format!("http://{}/~/{}", localhost_addr, prog_asset_name),
                                true,
                            )
                        } else if let Some(_data_url) = res.entry.asset.url {
                            (
                                format!("http://{}/~/{}", localhost_addr, prog_asset_name),
                                true,
                            )
                        } else {
                            eprintln!(
                                "error: asset '{}' does not have a link; cannot launch in browser",
                                prog_asset_name
                            );
                            return;
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        return;
                    }
                }
            };

        let gateway_localhost_addr = format!("localhost:{}", ws_addr.port());

        let mut fragment_params: Vec<(&str, &str)> = Vec::new();
        if let Some(ref target) = target_asset_name {
            fragment_params.push(("asset", target));
        }
        if !asset_prog_from_localhost {
            fragment_params.push(("token", &auth_token));
            fragment_params.push(("s", &gateway_localhost_addr));
        }

        let final_url = if fragment_params.is_empty() {
            asset_prog_url.to_string()
        } else {
            let fragment = fragment_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            format!("{}#{}", asset_prog_url, fragment)
        };
        println!("Opening asset-as-editor in browser: {}", final_url);
        if let Err(e) = open::that_detached(final_url) {
            eprintln!("error: failed to open asset-as-editor in browser: {}", e);
        }
        session
            .gateways
            .push((is_task_mode_step, ws_addr, clients, cancel_token));
    }
}
