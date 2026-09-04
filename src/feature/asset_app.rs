use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::HaiClient;
use crate::asset_cache::AssetBlobCache;
use crate::asset_helper;
use crate::feature::gateway;
use crate::io::{Io, Out};
use crate::repl_remote::ReplRemote;
use crate::session::SessionState;
use crate::{errorln, outln};

pub async fn start_app_and_launch_browser(
    io: &Io,
    config_path_override: Option<&str>,
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
    // When set, a local filesystem path to a vite project. `npm run dev` is
    // launched there and GET requests under `prog_asset_name` are proxied to
    // the vite dev server.
    dev_mode: Option<&str>,
) -> Option<(String, SocketAddr, SocketAddr)> {
    let prog_asset_name = asset_helper::expand_pub_asset_name(prog_asset_name, &session.account);
    let target_asset_name =
        target_asset_name.map(|n| asset_helper::expand_pub_asset_name(n, &session.account));

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
            outln!(io, "Reusing existing gateway. Asset app URL: {}", final_url);
            if !skip_browser_launch {
                outln!(io, "Opening asset app in browser");
                if let Err(e) = open::that_detached(&final_url) {
                    errorln!(io, "failed to open asset app in browser: {}", e);
                }
            }
            return Some((final_url, gateway_info.addr, gateway_info.perm_addr));
        }
    }

    if let Some((final_url, addr, perm_addr, clients, cancel_token, auth_token)) = start_app(
        io,
        config_path_override,
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
        dev_mode,
    )
    .await
    {
        if skip_browser_launch {
            outln!(io, "Asset app URL: {}", final_url);
        } else {
            outln!(io, "Opening asset app in browser: {}", final_url);
            if let Err(e) = open::that_detached(&final_url) {
                errorln!(io, "failed to open asset app in browser: {}", e);
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

/// Launches a gateway server (websocket + http) to serve the asset app.
///
/// # Arguments
/// - `local_dev_path`: If set, a local filesystem path to a vite project.
///   `npm run dev` is launched there and GET requests under `prog_asset_name`
///   are proxied to the vite dev server.
pub async fn start_app(
    io: &Io,
    config_path_override: Option<&str>,
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
    local_dev_path: Option<&str>,
) -> Option<(
    String,
    SocketAddr,
    SocketAddr,
    gateway::Clients,
    tokio_util::sync::CancellationToken,
    String,
)> {
    // If local_dev_path set, launches a vite dev server (`npm run dev`) in the
    // provided project directory on a free port.
    let vite_proxy = if let Some(vite_project_path) = local_dev_path {
        match launch_vite_dev_server(&io.out, vite_project_path, prog_asset_name).await {
            Some(vite_proxy) => Some(vite_proxy),
            None => {
                errorln!(io, "failed to launch vite dev server");
                return None;
            }
        }
    } else {
        None
    };

    if let Ok((addr, perm_addr, clients, cancel_token, auth_token)) =
        crate::feature::gateway::launch_gateway(
            io,
            config_path_override,
            repl_remote,
            db.clone(),
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            api_client.clone(),
            username,
            update_asset_tx.clone(),
            None,
            &prog_asset_name,
            vite_proxy,
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

/// Launches a vite dev server via `npm run dev` in `vite_project_path`.
///
/// A free port is chosen automatically and passed to vite. Returns the host
/// (e.g. "127.0.0.1:5173") once the server is accepting connections, or `None`
/// if it fails to start.
///
/// The spawned process is detached: it inherits stdio and is not tracked for
/// shutdown.
async fn launch_vite_dev_server(
    out: &Out,
    vite_project_path: &str,
    asset_app_prefix: &str,
) -> Option<gateway::ViteProxy> {
    // Pick a free port by binding to :0 and immediately releasing it. There's
    // a small race window before vite binds, but --strictPort ensures we fail
    // loudly rather than silently drifting to another port.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        drop(listener);
        port
    };

    let vite_host = format!("127.0.0.1:{}", port);

    outln!(
        out,
        "Launching vite dev server (`npm run dev`) in {} on http://{}",
        vite_project_path,
        vite_host
    );

    // Assumption: generally, canonicalization of the asset prefix is done via
    // a redirect by the gateway during asset lookup. Vite doesn't do this
    // redirection, so keep it as consistent as possible, add a trailing slash.
    let asset_app_prefix = if asset_app_prefix.ends_with('/') {
        asset_app_prefix.to_string()
    } else {
        format!("{}/", asset_app_prefix)
    };

    let spawn_result = tokio::process::Command::new("npm")
        .arg("run")
        .arg("dev")
        .arg("--")
        .arg("--base")
        .arg(asset_app_prefix.clone())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--strictPort")
        .current_dir(vite_project_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();

    let _child = match spawn_result {
        Ok(child) => child,
        Err(e) => {
            errorln!(out, "failed to spawn `npm run dev`: {}", e);
            return None;
        }
    };
    // Intentionally detach the child: dropping the handle without waiting lets
    // it keep running for the duration of the dev session.
    // FIXME: Remove memory leak by returning proxy process and adding it to
    // `session.gateways`.
    std::mem::forget(_child);

    // Wait for vite to start accepting connections (up to ~30s).
    for _ in 0..150 {
        if tokio::net::TcpStream::connect(&vite_host).await.is_ok() {
            return Some(gateway::ViteProxy {
                host: vite_host,
                asset_prefix: asset_app_prefix.to_string(),
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    errorln!(out, "timed out waiting for vite dev server to start");
    None
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
        encoded_target = urlencoding::encode(target)
            .replace("%2F", "/")
            .replace("%2B", "+");
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
