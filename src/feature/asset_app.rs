use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::HaiClient;
use crate::asset_cache::AssetBlobCache;
use crate::asset_helper;
use crate::cmd_processor::expand_pub_asset_name;
use crate::feature::gateway;
use crate::repl_remote::ReplRemote;
use crate::session::SessionState;

pub async fn start_app_and_launch_browser(
    session: &mut SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<crate::asset_async_writer::WorkerAssetMsg>,
    is_task_mode_step: bool,
    prog_asset_name: &str,
    target_asset_name: Option<&str>,
    skip_browser_launch: bool,
    reuse_existing_gateway: bool,
    debug: bool,
) -> Option<(String, SocketAddr, SocketAddr)> {
    let prog_asset_name = expand_pub_asset_name(prog_asset_name, &session.account);
    let target_asset_name = target_asset_name.map(|n| expand_pub_asset_name(n, &session.account));

    if reuse_existing_gateway {
        if let Some(gateway_info) = session
            .gateways
            .iter()
            .find(|g| g.service_name == prog_asset_name && (!is_task_mode_step || g.is_task_step))
        {
            let final_url = get_asset_app_url(
                &gateway_info.addr,
                &prog_asset_name,
                target_asset_name.as_deref(),
                &gateway_info.auth_token,
                debug,
            );
            println!("Reusing existing gateway. Asset app URL: {}", final_url);
            if !skip_browser_launch {
                println!("Opening asset app in browser");
                if let Err(e) = open::that_detached(&final_url) {
                    eprintln!("error: failed to open asset app in browser: {}", e);
                }
            }
            return Some((final_url, gateway_info.addr, gateway_info.perm_addr));
        }
    }

    if let Some((final_url, addr, perm_addr, clients, cancel_token, auth_token)) = start_app(
        ReplRemote::from_session(session),
        db,
        asset_blob_cache,
        session.asset_keyring.clone(),
        api_client,
        username,
        update_asset_tx,
        &prog_asset_name,
        target_asset_name.as_deref(),
        debug,
    )
    .await
    {
        if skip_browser_launch {
            println!("Asset app URL: {}", final_url);
        } else {
            println!("Opening asset app in browser: {}", final_url);
            if let Err(e) = open::that_detached(&final_url) {
                eprintln!("error: failed to open asset app in browser: {}", e);
            }
        }
        session.gateways.push(crate::session::GatewayInfo {
            service_name: prog_asset_name.to_string(),
            is_task_step: is_task_mode_step,
            addr,
            perm_addr,
            clients,
            cancel_token,
            auth_token,
        });
        Some((final_url, addr, perm_addr))
    } else {
        None
    }
}

pub async fn start_app(
    repl_remote: ReplRemote,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<crate::asset_async_writer::WorkerAssetMsg>,
    prog_asset_name: &str,
    target_asset_name: Option<&str>,
    debug: bool,
) -> Option<(
    String,
    SocketAddr,
    SocketAddr,
    gateway::Clients,
    tokio_util::sync::CancellationToken,
    String,
)> {
    if let Ok((addr, perm_addr, clients, cancel_token, auth_token)) =
        crate::feature::gateway::launch_gateway(
            repl_remote,
            db.clone(),
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            api_client.clone(),
            username,
            update_asset_tx.clone(),
            None,
            &prog_asset_name,
        )
        .await
    {
        let final_url = get_asset_app_url(
            &addr,
            prog_asset_name,
            target_asset_name,
            &auth_token,
            debug,
        );
        Some((
            final_url,
            addr,
            perm_addr,
            clients,
            cancel_token,
            auth_token,
        ))
    } else {
        None
    }
}

pub fn get_asset_app_url(
    ws_addr: &SocketAddr,
    prog_asset_name: &str,
    target_asset_name: Option<&str>,
    auth_token: &str,
    debug: bool,
) -> String {
    let (asset_app_url, localhost_serves_asset_app) =
        get_asset_app_info(ws_addr, prog_asset_name, debug);

    let gateway_localhost_addr = format!("localhost:{}", ws_addr.port());

    let mut fragment_params: Vec<(&str, &str)> = Vec::new();
    let encoded_target;
    if let Some(ref target) = target_asset_name {
        encoded_target = urlencoding::encode(target);
        fragment_params.push(("asset", &encoded_target));
    }
    if !localhost_serves_asset_app {
        fragment_params.push(("token", &auth_token));
        fragment_params.push(("s", &gateway_localhost_addr));
    }

    if fragment_params.is_empty() {
        asset_app_url.to_string()
    } else {
        let fragment = fragment_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}#{}", asset_app_url, fragment)
    }
}

pub fn get_asset_app_info(
    ws_addr: &SocketAddr,
    prog_asset_name: &str,
    debug: bool,
) -> (String, bool) {
    let localhost_addr = format!("localhost:{}", ws_addr.port());
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
        // Prog-asset is private -> use proxy through the gateway
        (
            format!("http://{}/~/{}", localhost_addr, prog_asset_name),
            true,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenWithHandler {
    AssetApp { asset_name: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenWithEntry {
    pub handler: OpenWithHandler,
}

pub fn get_open_with_entries(md: &serde_json::Value) -> Option<Vec<OpenWithEntry>> {
    let open_with_entries = md.get("open_with")?;
    let arr = open_with_entries.as_array()?;

    let entries: Vec<OpenWithEntry> = arr
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Currently, best match is simply the first entry.
pub fn get_best_match_open_with_entry(md: &serde_json::Value) -> Option<OpenWithEntry> {
    if let Some(open_with_entries) = get_open_with_entries(md) {
        open_with_entries.into_iter().next()
    } else {
        None
    }
}
