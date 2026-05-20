use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};
use tokio_util::sync::CancellationToken;

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset;
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader::GetRevisionError;
use crate::{
    asset_async_writer, asset_reader,
    feature::asset_crypt::{self, KeyRecipient},
};

pub const DEV_MODE: &str = "DEV_MODE";

pub type ClientId = u64;
pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<std::collections::HashMap<ClientId, Client>>>;

pub type Perms = Arc<Mutex<Vec<Perm>>>;

// Map of perm_request_id -> (csrf_token, expiry time, requested_perms)
pub type PermRequestMap = Arc<Mutex<HashMap<String, (String, std::time::Instant, Vec<Perm>)>>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetPerm {
    read: bool,
    write: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetPrefixPerm {
    create: bool,
    list: bool,
}

/// A key detail about `Perm` is that it's a coarse permission scheme for what
/// requests will be forwarded from the gateway to the API. Just because an op
/// has permission in the gateway doesn't mean it will be allowed by the API.
///
/// For example, there's a permission for public assets that's read/write.
/// But, unless the asset is the current user's public asset, it won't be
/// writable. The API will reject the request and the error will be sent back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum Perm {
    AssetName {
        name: String,
        perm: AssetPerm,
    },
    AssetEntryId {
        entry_id: String,
        perm: AssetPerm,
    },
    /// prefix: Require that it ends with "/"
    AssetPrefix {
        prefix: String,
        perm: AssetPerm,
        prefix_perm: AssetPrefixPerm,
    },
    PublicAsset,
    SharedAssetName {
        name: String,
        perm: AssetPerm,
    },
    SharedAssetPrefix {
        prefix: String,
        perm: AssetPerm,
        prefix_perm: AssetPrefixPerm,
    },
    LlmPrompt,
}

impl Perm {
    /// Check if this single permission grants the requested access
    fn grants(&self, request: &AccessRequest<'_>) -> bool {
        match (self, request) {
            // Exact name match for read
            (Perm::AssetName { name, perm }, AccessRequest::ReadByName { name: req_name }) => {
                name == *req_name && perm.read
            }

            // Exact name match for write
            (Perm::AssetName { name, perm }, AccessRequest::WriteByName { name: req_name }) => {
                name == *req_name && perm.write
            }

            // Entry ID match for read
            (
                Perm::AssetEntryId { entry_id, perm },
                AccessRequest::ReadByEntryId { entry_id: req_id },
            ) => entry_id == *req_id && perm.read,

            // Prefix match for read by name
            (Perm::AssetPrefix { prefix, perm, .. }, AccessRequest::ReadByName { name }) => {
                name.starts_with(prefix) && perm.read
            }

            // Prefix match for write by name
            (Perm::AssetPrefix { prefix, perm, .. }, AccessRequest::WriteByName { name }) => {
                name.starts_with(prefix) && perm.write
            }

            // Prefix permissions for list
            (
                Perm::AssetPrefix {
                    prefix,
                    prefix_perm,
                    ..
                },
                AccessRequest::ListPrefix { prefix: req_prefix },
            ) => req_prefix.starts_with(prefix) && prefix_perm.list,

            // Public paths
            (Perm::PublicAsset, AccessRequest::ReadByName { name: req_name }) => {
                is_public_path(req_name)
            }

            // --- Shared asset name: match the suffix after /s/<participants>/ ---
            (
                Perm::SharedAssetName { name, perm },
                AccessRequest::ReadByName { name: req_name },
            ) => shared_path_suffix(req_name).map_or(false, |suffix| suffix == name && perm.read),
            (
                Perm::SharedAssetName { name, perm },
                AccessRequest::WriteByName { name: req_name },
            ) => shared_path_suffix(req_name).map_or(false, |suffix| suffix == name && perm.write),

            // --- Shared asset prefix: match the suffix after /s/<participants>/ ---
            (Perm::SharedAssetPrefix { prefix, perm, .. }, AccessRequest::ReadByName { name }) => {
                shared_path_suffix(name)
                    .map_or(false, |suffix| suffix.starts_with(prefix) && perm.read)
            }
            (Perm::SharedAssetPrefix { prefix, perm, .. }, AccessRequest::WriteByName { name }) => {
                shared_path_suffix(name)
                    .map_or(false, |suffix| suffix.starts_with(prefix) && perm.write)
            }
            (
                Perm::SharedAssetPrefix {
                    prefix,
                    prefix_perm,
                    ..
                },
                AccessRequest::ListPrefix { prefix: req_prefix },
            ) => shared_path_suffix(req_prefix).map_or(false, |suffix| {
                suffix.starts_with(prefix) && prefix_perm.list
            }),

            // LlmPrompt
            (Perm::LlmPrompt, AccessRequest::LlmPrompt) => true,

            // No match
            _ => false,
        }
    }

    // Helper if permission requires keyring access
    fn requires_keyring(&self) -> bool {
        matches!(
            self,
            Perm::AssetName { .. }
                | Perm::AssetEntryId { .. }
                | Perm::AssetPrefix { .. }
                | Perm::SharedAssetName { .. }
                | Perm::SharedAssetPrefix { .. }
        )
    }
}

/// Extract the path portion after `/s/<participants>/` from a shared path.
/// Returns Some(suffix) if the path matches `/s/<participants>/...`, None otherwise.
fn shared_path_suffix(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/s/")?;
    // Find the first '/' after the participants segment
    let slash_idx = rest.find('/')?;
    let suffix = &rest[slash_idx + 1..];
    Some(suffix)
}

fn is_public_path(path: &str) -> bool {
    path.starts_with("/") && !path.starts_with("/s/")
}

/// Check if any permission in the list grants the requested access
pub fn check_access(perms: &[Perm], request: &AccessRequest<'_>) -> Result<(), PermCheckError> {
    if perms.iter().any(|p| p.grants(request)) {
        Ok(())
    } else {
        Err(PermCheckError::Unauthorized)
    }
}

/// Async version that takes the Arc<Mutex<...>> directly
pub async fn check_access_async(
    perms: &Perms,
    request: &AccessRequest<'_>,
) -> Result<(), PermCheckError> {
    let perms = perms.lock().await;
    check_access(&perms, request)
}

/// What kind of access is being requested
#[derive(Debug, Clone)]
pub enum AccessRequest<'a> {
    /// Read a specific asset by name
    ReadByName { name: &'a str },
    /// Write a specific asset by name
    WriteByName { name: &'a str },
    /// Read a specific asset by entry_id
    ReadByEntryId { entry_id: &'a str },
    /// List assets under a prefix
    ListPrefix { prefix: &'a str },
    /// Prompt LLM
    LlmPrompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermCheckError {
    Unauthorized,
}

// -- Minimal HTTP parsing/response helpers --

struct HttpRequest {
    method: String,
    path: String,
    query_params: std::collections::HashMap<String, String>,
    headers: std::collections::HashMap<String, String>,
    subdomain: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
    async fn parse(
        stream: &mut BufReader<&mut tokio::net::TcpStream>,
        base_domain: &str,
    ) -> Option<Self> {
        let mut request_line = String::new();
        if stream.read_line(&mut request_line).await.ok()? == 0 {
            return None;
        }

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let method = parts[0].to_string();
        let full_path = parts[1];

        // Parse path and query params
        let (path, query_params) = Self::parse_path_and_query(full_path);

        let mut headers = std::collections::HashMap::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.ok()? == 0 {
                break;
            }
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Parse subdomain from Host header
        let subdomain = Self::parse_subdomain(headers.get("host").map(|s| s.as_str()), base_domain);

        // Read body if Content-Length is present
        let body = if let Some(content_length) = headers.get("content-length") {
            if let Ok(len) = content_length.parse::<usize>() {
                // Limit body size to prevent memory exhaustion (e.g., 64MB)
                const MAX_BODY_SIZE: usize = 64 * 1024 * 1024;
                if len > MAX_BODY_SIZE {
                    return None;
                }

                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await.ok()?;
                body
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Some(HttpRequest {
            method,
            path,
            query_params,
            headers,
            subdomain,
            body,
        })
    }

    fn parse_subdomain(host_header: Option<&str>, base_domain: &str) -> Option<String> {
        let host = host_header?;

        // Strip port if present (e.g., "foo.example.com:8080" -> "foo.example.com")
        let host = host.split(':').next().unwrap_or(host);

        // Check if host ends with base_domain
        if !host.ends_with(base_domain) {
            return None;
        }

        // Handle exact match (no subdomain)
        if host == base_domain {
            return None;
        }

        // Extract subdomain: "foo.bar.example.com" with base "example.com" -> "foo.bar"
        let prefix_len = host.len() - base_domain.len();
        if prefix_len == 0 {
            return None;
        }

        let prefix = &host[..prefix_len];

        // Must end with '.' to be a valid subdomain
        let subdomain = prefix.strip_suffix('.')?;

        if subdomain.is_empty() {
            return None;
        }

        Some(subdomain.to_string())
    }

    fn parse_path_and_query(
        full_path: &str,
    ) -> (String, std::collections::HashMap<String, String>) {
        let mut query_params = std::collections::HashMap::new();

        let (path, query_string) = match full_path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q)),
            None => (full_path.to_string(), None),
        };

        if let Some(qs) = query_string {
            for pair in qs.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, value) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                // Basic percent-decoding for common cases
                let key = Self::percent_decode(key);
                let value = Self::percent_decode(value);
                query_params.insert(key, value);
            }
        }

        (path, query_params)
    }

    fn percent_decode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.bytes().peekable();

        while let Some(b) = chars.next() {
            match b {
                b'%' => {
                    let hex: String = chars.by_ref().take(2).map(|c| c as char).collect();
                    if hex.len() == 2 {
                        if let Ok(decoded) = u8::from_str_radix(&hex, 16) {
                            result.push(decoded as char);
                            continue;
                        }
                    }
                    result.push('%');
                    result.push_str(&hex);
                }
                b'+' => result.push(' '),
                _ => result.push(b as char),
            }
        }
        result
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.headers.get("cookie").and_then(|cookies| {
            cookies.split(';').map(|s| s.trim()).find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k.trim() == name {
                    Some(v.trim())
                } else {
                    None
                }
            })
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    fn bearer_token(&self) -> Option<&str> {
        self.headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
    }

    fn query_param(&self, key: &str) -> Option<&str> {
        self.query_params.get(key).map(|s| s.as_str())
    }

    /// Returns the query string (without leading `?`), or `None` if empty
    fn query_string(&self) -> Option<String> {
        if self.query_params.is_empty() {
            None
        } else {
            let qs = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            Some(qs)
        }
    }

    #[allow(dead_code)]
    fn subdomain(&self) -> Option<&str> {
        self.subdomain.as_deref()
    }
}

struct HttpResponse {
    status: u16,
    status_text: &'static str,
    content_type: String,
    body: Vec<u8>,
    set_cookie: Option<String>,
    additional_headers: Vec<(String, String)>,
}

impl HttpResponse {
    fn ok(body: Vec<u8>, content_type: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK",
            content_type: content_type.to_string(),
            body,
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn no_content() -> Self {
        Self {
            status: 204,
            status_text: "No Content",
            content_type: "text/plain".into(),
            body: Vec::new(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn redirect_temp(location: &str) -> Self {
        Self {
            status: 302,
            status_text: "Found",
            content_type: "text/plain".into(),
            body: Vec::new(),
            set_cookie: None,
            additional_headers: vec![("Location".to_string(), location.to_string())],
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            status_text: "Not Found",
            content_type: "text/plain".into(),
            body: b"Not Found".to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: 401,
            status_text: "Unauthorized",
            content_type: "text/plain".into(),
            body: b"Unauthorized".to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn forbidden() -> Self {
        Self {
            status: 403,
            status_text: "Forbidden",
            content_type: "text/plain".into(),
            body: b"Forbidden".to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn bad_request(msg: &str) -> Self {
        Self {
            status: 400,
            status_text: "Bad Request",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn internal_error(msg: &str) -> Self {
        Self {
            status: 500,
            status_text: "Internal Server Error",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn teapot(msg: &str) -> Self {
        Self {
            status: 418,
            status_text: "I'm a teapot",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }

    fn with_cookie(mut self, cookie: String) -> Self {
        self.set_cookie = Some(cookie);
        self
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.additional_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    fn auth_cookie(token: &str) -> String {
        // `Secure` is not set because this is used over localhost
        format!("hai_token={}; Path=/; HttpOnly; SameSite=Strict", token)
    }

    async fn write_to(self, stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
        let cookie_header = match &self.set_cookie {
            Some(cookie) => format!("Set-Cookie: {}\r\n", cookie),
            None => String::new(),
        };

        let additional_headers: String = self
            .additional_headers
            .iter()
            .map(|(name, value)| format!("{}: {}\r\n", name, value))
            .collect();

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}{}Connection: close\r\n\r\n",
            self.status,
            self.status_text,
            self.content_type,
            self.body.len(),
            cookie_header,
            additional_headers,
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&self.body).await?;
        stream.flush().await?;
        Ok(())
    }

    fn json_status(status: u16, body: &str) -> Self {
        Self {
            status,
            status_text: match status {
                401 => "Unauthorized",
                _ => "Error",
            },
            content_type: "application/json".to_string(),
            body: body.as_bytes().to_vec(),
            set_cookie: None,
            additional_headers: Vec::new(),
        }
    }
}

/// Launches a gateway server (websocket + http).
///
/// # Arguments
///
/// * `asset_blob_cache` - A cache for asset blobs.
/// * `asset_keyring` - A keyring for asset encryption keys.
/// * `api_client` - The API client to use for requests.
/// * `username` - The username of the user launching the gateway.
/// * `update_asset_tx` - A channel for sending asset update messages.
/// * `auth_token` - Set the auth token explicitly rather than randomly
///   generating one.
pub async fn launch_gateway(
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    auth_token: Option<&str>,
    service_name: &str,
) -> std::io::Result<(SocketAddr, SocketAddr, Clients, CancellationToken, String)> {
    // Generate a random authentication token
    let token = auth_token.map_or_else(
        || {
            (0..32)
                .map(|_| {
                    let idx = rand::rng().random_range(0..62);
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    chars[idx] as char
                })
                .collect()
        },
        |t| t.to_string(),
    );

    // Main gateway listener
    let mut port = 1339;
    let listener = loop {
        let addr = format!("127.0.0.1:{}", port);
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(_) => port += 1,
        }
    };
    let local_addr = listener.local_addr()?;

    // Permissions server on separate port (different origin!)
    let mut perm_port = port + 100; // e.g., 1439
    let perm_listener = loop {
        let addr = format!("127.0.0.1:{}", perm_port);
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(_) => perm_port += 1,
        }
    };
    let perm_addr = perm_listener.local_addr()?;

    println!(
        "Gateway listening on http://{} (HTTP + WebSocket)",
        local_addr
    );
    println!("Token: {}", token);
    println!("Permissions server on http://{}", perm_addr);

    let clients: Clients = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let clients_clone = clients.clone();

    let default_perms = vec![
        Perm::PublicAsset,
        Perm::AssetName {
            name: service_name.to_string(),
            perm: {
                AssetPerm {
                    read: true,
                    write: true,
                }
            },
        },
        Perm::AssetPrefix {
            prefix: format!("{}/", service_name),
            perm: AssetPerm {
                read: true,
                write: true,
            },
            prefix_perm: AssetPrefixPerm {
                create: true,
                list: true,
            },
        },
    ];

    let perms_nolock = if let Some(username) = username {
        let mut loaded_perms =
            crate::db::load_gateway_perms(&*db.lock().await, username, service_name);
        for default_perm in default_perms {
            if !loaded_perms.contains(&default_perm) {
                loaded_perms.push(default_perm.clone());
            }
        }
        loaded_perms
    } else {
        default_perms
    };
    let perms: Perms = Arc::new(Mutex::new(perms_nolock));

    let perms_clone = perms.clone();
    let perms_clone2 = perms.clone();

    let cancel_token = CancellationToken::new();
    let cancel_child1 = cancel_token.child_token();
    let cancel_child2 = cancel_token.child_token();

    let perm_request_map: PermRequestMap = Arc::new(Mutex::new(HashMap::new()));
    let perm_request_map_clone = perm_request_map.clone();

    let token_clone = token.clone();
    let asset_keyring_clone = asset_keyring.clone();
    let asset_blob_cache_cloned = asset_blob_cache.clone();
    let api_client_clone = api_client.clone();
    let username_owned = username.map(|s| s.to_string());
    let service_name_clone = service_name.to_string();
    let next_client_id = Arc::new(std::sync::atomic::AtomicU64::new(1));

    let cookie_set = Arc::new(AtomicBool::new(false));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_child1.cancelled() => {
                    let mut clients_guard = clients_clone.lock().await;
                    for (_id, client) in clients_guard.drain() {
                        drop(client);
                    }
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("Accept error: {:?}", e);
                            continue;
                        }
                    };

                    let _ = stream.set_nodelay(true);

                    let token_clone_inner = token_clone.clone();
                    let api_client_clone_inner = api_client_clone.clone();
                    let asset_blob_cache_inner = asset_blob_cache_cloned.clone();
                    let asset_keyring_inner = asset_keyring_clone.clone();
                    let clients_inner = clients_clone.clone();
                    let perms_inner = perms_clone.clone();
                    let perm_request_map_inner = perm_request_map_clone.clone();
                    let username_inner = username_owned.clone();
                    let service_name_inner = service_name_clone.clone();
                    let update_asset_tx_inner = update_asset_tx.clone();
                    let next_client_id_inner = next_client_id.clone();
                    let cookie_set_inner = cookie_set.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            peer_addr,
                            perm_addr,
                            token_clone_inner,
                            asset_blob_cache_inner,
                            asset_keyring_inner,
                            api_client_clone_inner,
                            clients_inner,
                            perms_inner,
                            perm_request_map_inner,
                            username_inner,
                            &service_name_inner,
                            update_asset_tx_inner,
                            next_client_id_inner,
                            cookie_set_inner,
                        ).await {
                            eprintln!("Connection error from {}: {:?}", peer_addr, e);
                        }
                    });
                }
            }
        }
    });

    let db_clone = db.clone();
    let asset_keyring_clone = asset_keyring.clone();
    let asset_blob_cache_cloned = asset_blob_cache.clone();
    let api_client_clone = api_client.clone();
    let clients_clone = clients.clone();
    let perm_request_map_clone = perm_request_map.clone();

    let username_clone = username.map(|u| u.to_string()).clone();
    let service_name_clone = service_name.to_string();

    // Permissions server task
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_child2.cancelled() => break,
                accept_result = perm_listener.accept() => {
                    let (stream, _peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("Perm server accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let db_inner = db_clone.clone();
                    let api_client_clone_inner = api_client_clone.clone();
                    let asset_blob_cache_inner = asset_blob_cache_cloned.clone();
                    let asset_keyring_inner = asset_keyring_clone.clone();
                    let clients_inner = clients_clone.clone();
                    let perms_inner = perms_clone2.clone();
                    let perm_request_map_inner = perm_request_map_clone.clone();
                    let username_inner = username_clone.clone();
                    let service_name_inner = service_name_clone.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_perm_http_connection(
                            db_inner,
                            asset_blob_cache_inner,
                            asset_keyring_inner,
                            &api_client_clone_inner,
                            clients_inner,
                            stream,
                            perms_inner,
                            perm_request_map_inner,
                            username_inner.as_deref(),
                            &service_name_inner,
                        ).await {
                            eprintln!("Perm connection error: {:?}", e);
                        }
                    });
                }
            }
        }
    });

    Ok((local_addr, perm_addr, clients, cancel_token, token))
}

// Handles both HTTP and WebSocket connections, dispatching to the appropriate
// handler based on the initial request.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    perm_addr: SocketAddr,
    token: String,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    clients: Clients,
    perms: Perms,
    perm_request_map: PermRequestMap,
    username: Option<String>,
    #[allow(unused_variables)] service_name: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    cookie_set: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek at the first bytes to read the HTTP request line and headers
    // without consuming them permanently
    let mut peek_buf = vec![0u8; 4096];

    // Use peek to look at data without consuming it
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    let peek_str = String::from_utf8_lossy(&peek_buf[..n]);

    // Check if this is a WebSocket upgrade request
    let is_websocket = peek_str.contains("Upgrade: websocket")
        || peek_str.contains("Upgrade: Websocket")
        || peek_str.contains("upgrade: websocket");

    if is_websocket {
        // Handle as WebSocket - tokio-tungstenite will read the upgrade request
        handle_websocket_connection(
            stream,
            &perm_addr,
            token,
            api_client,
            asset_blob_cache,
            asset_keyring,
            clients,
            perms,
            perm_request_map,
            username,
            update_asset_tx,
            next_client_id,
            cookie_set,
            &peek_str,
        )
        .await
    } else {
        // Handle as HTTP - we need to actually read and parse the request
        handle_http_connection(
            stream,
            &peer_addr,
            token,
            api_client,
            asset_blob_cache,
            asset_keyring,
            perms,
            username,
            update_asset_tx,
            cookie_set,
        )
        .await
    }
}

/// Extracts cookie value from raw HTTP headers (for peeked data)
fn extract_cookie_from_raw(raw_headers: &str, cookie_name: &str) -> Option<String> {
    for line in raw_headers.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("cookie:") {
            let cookie_str = line.splitn(2, ':').nth(1)?.trim();
            for pair in cookie_str.split(';') {
                let pair = pair.trim();
                if let Some((k, v)) = pair.split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

async fn handle_websocket_connection(
    stream: tokio::net::TcpStream,
    perm_addr: &SocketAddr,
    token: String,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    clients: Clients,
    perms: Perms,
    perm_request_map: PermRequestMap,
    username: Option<String>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    cookie_set: Arc<AtomicBool>,
    peeked_request: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check auth from cookie first (if cookie was already set)
    let cookie_token = extract_cookie_from_raw(peeked_request, "hai_token");
    let cookie_auth_valid = cookie_token.as_ref().map(|t| t == &token).unwrap_or(false);

    // If cookie is set and valid, we're authenticated via cookie
    // Otherwise, we'll require the auth message below
    let pre_authenticated =
        cookie_set.load(std::sync::atomic::Ordering::SeqCst) && cookie_auth_valid;

    let mut ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            // Handeshake error
            eprintln!("WebSocket handshake error: {:?}", e);
            return Ok(());
        }
    };

    if !pre_authenticated {
        //
        // If not pre-authenticated via cookie, first message must be an auth message
        //
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws_stream.next()).await {
            Ok(Some(Ok(Message::Text(msg)))) => {
                let auth_msg: ClientMessageAuthRequest = match serde_json::from_str(&msg) {
                    Ok(m) => m,
                    Err(_e) => {
                        let _ = ws_stream
                            .send(Message::Text(Utf8Bytes::from(
                                &serde_json::to_string(&ClientMessageAuthResponse::BadRequest)
                                    .unwrap(),
                            )))
                            .await;
                        let _ = ws_stream.close(None).await;
                        return Ok(());
                    }
                };
                if auth_msg.token != Some(token) {
                    let _ = ws_stream
                        .send(Message::Text(Utf8Bytes::from(
                            &serde_json::to_string(&ClientMessageAuthResponse::BadToken).unwrap(),
                        )))
                        .await;
                    let _ = ws_stream.close(None).await;
                    return Ok(());
                }
            }
            _ => {
                let _ = ws_stream
                    .send(Message::Text(Utf8Bytes::from(
                        &serde_json::to_string(&ClientMessageAuthResponse::BadRequest).unwrap(),
                    )))
                    .await;
                let _ = ws_stream.close(None).await;
                return Ok(());
            }
        }
    }

    // Client is authenticated, create channel and add to clients list
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let client_id = next_client_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    clients.lock().await.insert(client_id, tx);

    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    // Send acknowledgment that auth succeeded
    let _ = ws_sink
        .send(Message::Text(Utf8Bytes::from(
            &serde_json::to_string(&ClientMessageAuthResponse::Ok {
                version: env!("CARGO_PKG_VERSION").into(),
            })
            .unwrap(),
        )))
        .await;

    // Ping interval to keep connection alive
    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Periodic ping to keep connection alive
            _ = ping_interval.tick() => {
                if ws_sink.send(Message::Ping(Bytes::from_static(b"ping"))).await.is_err() {
                    break;
                }
            }
            // Messages from the server to send to this client
            Some(msg) = rx.recv() => {
                if ws_sink.send(msg).await.is_err() {
                    break;
                }
            }
            // Messages from the client
            msg_option = ws_stream.next() => {
                match msg_option {
                    Some(Ok(Message::Text(msg))) => {
                        handle_client_message(
                            perm_addr,
                            asset_blob_cache.clone(),
                            asset_keyring.clone(),
                            &api_client,
                            perms.clone(),
                            perm_request_map.clone(),
                            username.as_deref(),
                            update_asset_tx.clone(),
                            &mut ws_sink,
                            &msg).await;
                    }
                    Some(Ok(Message::Binary(_data))) => {
                        // No-op binary data for now as it's unexpected
                    }
                    Some(Ok(Message::Close(_))) => {
                        // Client closed connection gracefully
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Pong received, connection is alive
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        // Don't log ResetWithoutClosingHandshake as error - it's common
                        match &e {
                            tokio_tungstenite::tungstenite::Error::Protocol(
                                tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
                            ) => {
                                // Client connection reset
                            }
                            _ => {
                                // Client websocket error
                            }
                        }
                        break;
                    }
                    None => {
                        // Stream ended
                        break;
                    }
                }
            }
        }
    }

    // Remove client from list on disconnect
    clients.lock().await.remove(&client_id);

    Ok(())
}

async fn handle_http_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: &std::net::SocketAddr,
    token: String,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    perms: Perms,
    username: Option<String>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    cookie_set: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf_reader = BufReader::new(&mut stream);

    // Parse the HTTP request
    let request = match HttpRequest::parse(&mut buf_reader, "localhost").await {
        Some(req) => req,
        None => return Ok(()),
    };

    // Handle the HTTP request
    let response = handle_http_request(
        &request,
        &peer_addr,
        &token,
        asset_blob_cache,
        asset_keyring,
        &api_client,
        perms,
        username,
        update_asset_tx,
        cookie_set,
    )
    .await;

    response.write_to(&mut stream).await?;

    Ok(())
}

// -- HTTP request handler --

async fn handle_http_request(
    request: &HttpRequest,
    #[allow(unused_variables)] peer_addr: &std::net::SocketAddr,
    expected_token: &str,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perms: Perms,
    username: Option<String>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    cookie_set: Arc<AtomicBool>,
) -> HttpResponse {
    // Check if origin is allowed for CORS
    let origin = request.header("Origin");
    let allowed_origin = origin.and_then(|o| {
        if is_allowed_origin(o) {
            Some(o.to_string())
        } else {
            None
        }
    });

    // Handle OPTIONS preflight request
    if request.method.as_str() == "OPTIONS" {
        return build_cors_preflight_response(allowed_origin.as_deref());
    }

    // Check token from multiple sources: cookie, bearer token, query param
    let cookie_token = request.cookie("hai_token");
    let bearer_token = request.bearer_token();
    let query_token = request.query_param("token");

    // Parse optional query params
    let rev_id: Option<String> = request.query_param("rev_id").map(|s| s.to_string());
    let metadata_ref: bool = request
        .query_param("metadata")
        .map(|v| v == "1")
        .unwrap_or(false);
    let is_push: bool = request
        .query_param("push")
        .map(|v| v == "1")
        .unwrap_or(false);

    let should_set_cookie = !cookie_set.load(std::sync::atomic::Ordering::SeqCst);

    let authenticated = if let Some(ct) = cookie_token {
        ct == expected_token
    } else if let Some(bt) = bearer_token {
        bt == expected_token
    } else if let Some(qt) = query_token {
        qt == expected_token
    } else {
        false
    };

    if !authenticated && !should_set_cookie {
        return HttpResponse::unauthorized();
    }

    if should_set_cookie {
        cookie_set.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // /~/ is the prefix for a user's private asset pool.
    let path = {
        let p = request.path.trim_start_matches("/~/");
        let mut end = p.len();
        if let Some(i) = p.find('?') {
            end = std::cmp::min(end, i);
        }
        if let Some(i) = p.find('#') {
            end = std::cmp::min(end, i);
        }
        &p[..end]
    };

    // URL decode the path
    let asset_name = match urlencoding::decode(path) {
        Ok(decoded_path) => match decoded_path.split_once('@') {
            Some((_asset_name, asset_app_name)) => asset_app_name.to_string(),
            None => decoded_path.to_string(),
        },
        Err(_) => return HttpResponse::bad_request("Invalid URL encoding"),
    };

    let mut response = match request.method.as_str() {
        "GET" => {
            if is_push {
                return HttpResponse::bad_request("push parameter is not valid for GET requests");
            }
            handle_get(
                &request,
                &asset_name,
                rev_id.as_deref(),
                metadata_ref,
                asset_blob_cache,
                asset_keyring,
                api_client,
                perms,
                username,
            )
            .await
        }
        "PUT" => {
            if metadata_ref {
                if is_push {
                    return HttpResponse::bad_request(
                        "push parameter is not valid when metadata=1",
                    );
                }
                handle_put_metadata(
                    &asset_name,
                    &request.body,
                    asset_blob_cache,
                    asset_keyring,
                    api_client.clone(),
                    perms,
                    username,
                )
                .await
            } else {
                handle_put(
                    &asset_name,
                    &request.body,
                    is_push,
                    asset_blob_cache,
                    asset_keyring,
                    api_client.clone(),
                    perms,
                    username,
                    update_asset_tx,
                )
                .await
            }
        }
        _ => HttpResponse::bad_request("Only GET, PUT, and OPTIONS supported"),
    };

    // Add CORS headers to actual response if origin is allowed
    if let Some(ref origin) = allowed_origin {
        response = response
            .with_header("Access-Control-Allow-Origin", origin)
            .with_header("Access-Control-Allow-Credentials", "true");
    }

    if should_set_cookie {
        response = response.with_cookie(HttpResponse::auth_cookie(expected_token));
    }

    response
}

/// Check if the origin is allowed for CORS
fn is_allowed_origin(origin: &str) -> bool {
    if origin == "https://hai.dog" {
        return true;
    }

    // Check for *.hai.dog subdomains
    if let Some(rest) = origin.strip_prefix("https://") {
        if let Some(subdomain) = rest.strip_suffix(".hai.dog") {
            // Ensure it's a valid subdomain (not empty, no slashes)
            return !subdomain.is_empty() && !subdomain.contains('/');
        }
    }

    false
}

/// Build CORS preflight response
fn build_cors_preflight_response(allowed_origin: Option<&str>) -> HttpResponse {
    match allowed_origin {
        Some(origin) => HttpResponse::no_content()
            .with_header("Access-Control-Allow-Origin", origin)
            .with_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
            .with_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization",
            )
            .with_header("Access-Control-Allow-Credentials", "true")
            .with_header("Access-Control-Max-Age", "86400"),
        None => HttpResponse::forbidden(),
    }
}

async fn handle_get(
    request: &HttpRequest,
    asset_name: &str,
    rev_id: Option<&str>,
    return_metadata: bool,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perms: Perms,
    username: Option<String>,
) -> HttpResponse {
    // Check permission at the start
    if let Err(PermCheckError::Unauthorized) =
        check_access_async(&perms, &AccessRequest::ReadByName { name: asset_name }).await
    {
        return HttpResponse::forbidden();
    }

    let default_filenames = &["index", "index.html", "README", "README.md"];

    let (data_contents, md_contents, asset_revision, resolved_name) = {
        let is_directory_request = asset_name.is_empty() || asset_name.ends_with('/');

        if is_directory_request {
            // Skip exact lookup, go straight to default files
            let base_name = asset_name.trim_end_matches('/');

            let mut found = None;
            for filename in default_filenames {
                let fallback_name = if base_name.is_empty() {
                    filename.to_string()
                } else {
                    format!("{}/{}", base_name, filename)
                };

                match asset_reader::get_asset_and_metadata_revision(
                    asset_blob_cache.clone(),
                    api_client,
                    &fallback_name,
                    rev_id,
                    !return_metadata,
                )
                .await
                {
                    Ok((data, md, rev)) => {
                        found = Some((data, md, rev, fallback_name));
                        break;
                    }
                    Err(_) => continue,
                }
            }

            match found {
                Some(res) => res,
                None => return HttpResponse::not_found(),
            }
        } else {
            // Try exact asset first
            match asset_reader::get_asset_and_metadata_revision(
                asset_blob_cache.clone(),
                api_client,
                asset_name,
                rev_id,
                !return_metadata,
            )
            .await
            {
                Ok((data, md, rev)) => (data, md, rev, asset_name.to_string()),
                Err(
                    GetRevisionError::BadEntryRef
                    | GetRevisionError::BadRevId
                    | GetRevisionError::Deleted,
                ) if rev_id.is_none() => {
                    // Exact asset not found, try default files
                    let mut found = None;
                    for filename in default_filenames {
                        let fallback_name = format!("{}/{}", asset_name, filename);

                        match asset_reader::get_asset_and_metadata_revision(
                            asset_blob_cache.clone(),
                            api_client,
                            &fallback_name,
                            None,
                            !return_metadata,
                        )
                        .await
                        {
                            Ok((data, md, rev)) => {
                                found = Some((data, md, rev, fallback_name));
                                break;
                            }
                            Err(_) => continue,
                        }
                    }

                    match found {
                        Some(_res) => {
                            // Found a default file, redirect to trailing slash
                            if request.path.find('@').is_some() {
                                return HttpResponse::redirect_temp(&format!(
                                    "{}/{}",
                                    request.path,
                                    request
                                        .query_string()
                                        .map(|qs| format!("?{}", qs))
                                        .unwrap_or_default(),
                                ));
                            } else {
                                return HttpResponse::redirect_temp(&format!("{}/", asset_name));
                            }
                        }
                        None => return HttpResponse::not_found(),
                    }
                }
                Err(GetRevisionError::BadEntryRef) => return HttpResponse::not_found(),
                Err(GetRevisionError::BadRevId) => return HttpResponse::not_found(),
                Err(GetRevisionError::Deleted) => return HttpResponse::not_found(),
                Err(GetRevisionError::DataFetchFailed) => {
                    return HttpResponse::bad_request("Invalid URL encoding");
                }
            }
        }
    };

    let (decrypted_contents, content_type) = if return_metadata {
        if let Some(md_contents) = md_contents {
            (md_contents, "application/json".to_string())
        } else {
            return HttpResponse::not_found();
        }
    } else {
        match asset_crypt::maybe_decrypt_asset_contents(
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            api_client,
            username.map(|s| KeyRecipient::User(s.to_string())).as_ref(),
            &data_contents,
            md_contents.as_deref(),
        )
        .await
        {
            Ok(decrypted_asset_contents) => {
                let asset_content_type = asset_revision
                    .metadata
                    .and_then(|md| md.content_type.clone());
                let content_type = crate::asset_helper::best_guess_content_type(
                    &resolved_name,
                    asset_content_type.as_deref(),
                    &decrypted_asset_contents,
                );
                (decrypted_asset_contents, content_type)
            }
            Err(e) => {
                eprintln!("error: failed to decrypt: {}", e);
                return HttpResponse::internal_error("Failed to decrypt asset");
            }
        }
    };

    HttpResponse::ok(decrypted_contents, &content_type)
}

async fn handle_put(
    asset_name: &str,
    body: &[u8],
    is_push: bool,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    perms: Perms,
    username: Option<String>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
) -> HttpResponse {
    if let Err(PermCheckError::Unauthorized) =
        check_access_async(&perms, &AccessRequest::WriteByName { name: asset_name }).await
    {
        return HttpResponse::forbidden();
    }
    // Choose encryption key material for this asset
    let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
        asset_blob_cache.clone(),
        asset_keyring.clone(),
        api_client.clone(),
        username
            .as_ref()
            .map(|s| KeyRecipient::User(s.to_string()))
            .as_ref(),
        asset_name,
        false,
    )
    .await
    {
        Ok(akm_info) => akm_info,
        Err(e) => {
            match e {
                asset_crypt::AkmSelectionError::Abort(msg) => {
                    eprintln!("error: {}", msg);
                }
            }
            return HttpResponse::bad_request("Decryption key error");
        }
    };

    // Send update to the async writer worker
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    if let Err(e) = update_asset_tx
        .send(asset_async_writer::WorkerAssetMsg::Update(
            asset_async_writer::WorkerAssetUpdate {
                asset_name: asset_name.to_string(),
                asset_entry_ref: None,
                new_contents: body.to_vec(),
                is_push,
                api_client: api_client.clone(),
                one_shot: true,
                akm_info,
                reply_channel: Some(reply_tx),
            },
        ))
        .await
    {
        eprintln!("error: failed to send to update worker: {}", e);
        return HttpResponse::internal_error("Failed to process update");
    }

    // Wait for the response
    match reply_rx.await {
        Ok(Ok(new_entry)) => match serde_json::to_vec(&new_entry) {
            Ok(json_bytes) => HttpResponse::ok(json_bytes, "application/json"),
            Err(_) => HttpResponse::internal_error("Failed to serialize response"),
        },
        Ok(Err(e)) => {
            eprintln!("error: failed to update asset: {:?}", e);
            match e {
                asset_async_writer::AssetSaveError::Put(RequestError::Route(
                    asset::AssetPutError::NoPermission,
                ))
                | asset_async_writer::AssetSaveError::Replace(RequestError::Route(
                    asset::AssetReplaceError::NoPermission,
                ))
                | asset_async_writer::AssetSaveError::Push(RequestError::Route(
                    asset::AssetPushError::NoPermission,
                )) => {
                    return HttpResponse::unauthorized();
                }
                asset_async_writer::AssetSaveError::Put(RequestError::BadRequest(msg))
                | asset_async_writer::AssetSaveError::Replace(RequestError::BadRequest(msg))
                | asset_async_writer::AssetSaveError::Push(RequestError::BadRequest(msg)) => {
                    return HttpResponse::bad_request(&format!("Unexpected error: {}", msg));
                }
                asset_async_writer::AssetSaveError::Put(RequestError::Http(http_err))
                | asset_async_writer::AssetSaveError::Replace(RequestError::Http(http_err))
                | asset_async_writer::AssetSaveError::Push(RequestError::Http(http_err)) => {
                    return HttpResponse::internal_error(&format!("HTTP error: {}", http_err));
                }
                asset_async_writer::AssetSaveError::Put(RequestError::Unexpected(msg))
                | asset_async_writer::AssetSaveError::Replace(RequestError::Unexpected(msg))
                | asset_async_writer::AssetSaveError::Push(RequestError::Unexpected(msg)) => {
                    return HttpResponse::internal_error(&format!("Unexpected error: {}", msg));
                }
                asset_async_writer::AssetSaveError::Put(RequestError::Route(route_err)) => {
                    return HttpResponse::teapot(
                        &serde_json::to_string(&route_err)
                            .expect("unexpected failure to serialize"),
                    );
                }
                asset_async_writer::AssetSaveError::Replace(RequestError::Route(route_err)) => {
                    return HttpResponse::teapot(
                        &serde_json::to_string(&route_err)
                            .expect("unexpected failure to serialize"),
                    );
                }
                asset_async_writer::AssetSaveError::Push(RequestError::Route(route_err)) => {
                    return HttpResponse::teapot(
                        &serde_json::to_string(&route_err)
                            .expect("unexpected failure to serialize"),
                    );
                }
            }
        }
        Err(_) => HttpResponse::internal_error("Update worker did not respond"),
    }
}

async fn handle_put_metadata(
    asset_name: &str,
    body: &[u8],
    _asset_blob_cache: Arc<AssetBlobCache>,
    _asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    perms: Perms,
    _username: Option<String>,
) -> HttpResponse {
    if let Err(PermCheckError::Unauthorized) =
        check_access_async(&perms, &AccessRequest::WriteByName { name: asset_name }).await
    {
        return HttpResponse::forbidden();
    }
    match api_client
        .asset_metadata_put(asset::AssetMetadataPutArg {
            name: asset_name.to_string(),
            data: String::from_utf8_lossy(body).to_string(),
            conflict_policy: asset::PutConflictPolicy::Override,
        })
        .await
    {
        Ok(res) => match serde_json::to_vec(&res) {
            Ok(json_bytes) => HttpResponse::ok(json_bytes, "application/json"),
            Err(_) => HttpResponse::internal_error("Failed to serialize response"),
        },
        Err(e) => {
            eprintln!("error: metadata put failed: {}", e);
            match e {
                RequestError::BadRequest(msg) => {
                    return HttpResponse::bad_request(&format!("Unexpected error: {}", msg));
                }
                RequestError::Http(http_err) => {
                    return HttpResponse::internal_error(&format!("HTTP error: {}", http_err));
                }
                RequestError::Route(route_err) => match route_err {
                    asset::AssetMetadataPutError::NoPermission => {
                        return HttpResponse::unauthorized();
                    }
                    e => {
                        return HttpResponse::teapot(
                            &serde_json::to_string(&e).expect("unexpected failure to serialize"),
                        );
                    }
                },
                RequestError::Unexpected(msg) => {
                    return HttpResponse::internal_error(&format!("Unexpected error: {}", msg));
                }
            }
        }
    }
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageAuthRequest {
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ClientMessageAuthResponse {
    Ok { version: String },
    BadToken,
    BadRequest,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: MessageContent,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum MessageContent {
    Text { text: String },
    ImageUrl { image_url: ImageData },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ImageData {
    pub url: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplPromptArg {
    messages: Vec<ChatMessage>,
    model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplPromptResultDelta {
    Delta {
        delta: String,
    },
    /// Redundant (inverse) with message-frame `more`
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplPromptError {
    ExecutionFailed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplPermGetResult {
    perms: Vec<Perm>,
    keyring_need_unlock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplPermRequestArg {
    perms: Vec<Perm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplPermRequestResult {
    existing_perms: Vec<Perm>,
    requested_perms: Vec<Perm>,
    keyring_need_unlock: bool,
    request_id: String,
    url: String,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageRequest {
    /// Always echo-ed back in the ClientMessageResponse so that client can
    /// correlate responses to requests.
    mid: u64,
    route: String,
    arg: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ClientMessageResponse<T, U> {
    Ok {
        mid: u64,
        result: T,
        /// If set, client should keep `mid` response handler alive to handle
        /// subsequent messages related to it. Only set if `more` is true to
        /// reduce overhead.
        #[serde(default)]
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        more: bool,
    },
    RouteError {
        mid: u64,
        error: U,
    },
    BadRequestError {
        error: String,
    },
    AuthorizationError {
        mid: u64,
        error: String,
    },
    HttpError {
        mid: u64,
        error: String,
    },
    UnexpectedError {
        mid: u64,
        error: String,
    },
}

// --

//
// Helper functions for sending responses
//

async fn send_error_response<E: Serialize>(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    mid: u64,
    error: RequestError<E>,
) {
    let resp_err: ClientMessageResponse<(), E> = match error {
        RequestError::Http(http_err) => ClientMessageResponse::HttpError {
            mid: mid,
            error: http_err.to_string(),
        },
        RequestError::Route(route_err) => ClientMessageResponse::RouteError {
            mid: mid,
            error: route_err,
        },
        RequestError::BadRequest(msg) => ClientMessageResponse::BadRequestError { error: msg },
        RequestError::Unexpected(msg) => ClientMessageResponse::UnexpectedError {
            mid: mid,
            error: msg,
        },
    };
    let json_string = serde_json::to_string(&resp_err).expect("Failed to re-serialize response");
    let _ = ws_sink
        .send(Message::Text(Utf8Bytes::from(&json_string)))
        .await;
}

async fn send_response<T: Serialize, E: Serialize>(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    mid: u64,
    result: Result<T, RequestError<E>>,
    more: bool,
) -> bool {
    match result {
        Ok(res) => {
            let resp_ok: ClientMessageResponse<T, E> = ClientMessageResponse::Ok {
                mid: mid,
                result: res,
                more,
            };
            let json_string =
                serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
            true
        }
        Err(e) => {
            send_error_response(ws_sink, mid, e).await;
            false
        }
    }
}

async fn send_bad_request_error(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    error: &str,
) {
    let resp_err = ClientMessageResponse::<(), String>::BadRequestError {
        error: error.to_string(),
    };
    let json_string = serde_json::to_string(&resp_err).expect("Failed to re-serialize response");
    let _ = ws_sink
        .send(Message::Text(Utf8Bytes::from(&json_string)))
        .await;
}

async fn send_bad_authorization_error(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    mid: u64,
    error: &str,
) {
    let resp_err = ClientMessageResponse::<(), String>::AuthorizationError {
        mid,
        error: error.to_string(),
    };
    let json_string = serde_json::to_string(&resp_err).expect("Failed to re-serialize response");
    let _ = ws_sink
        .send(Message::Text(Utf8Bytes::from(&json_string)))
        .await;
}

// --

async fn handle_client_message(
    perm_addr: &SocketAddr,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perms: Perms,
    perm_request_map: PermRequestMap,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    msg: &str,
) {
    // Deserialize the incoming message
    let client_msg: ClientMessageRequest = match serde_json::from_str(msg) {
        Ok(m) => m,
        Err(_e) => {
            send_bad_request_error(ws_sink, "Invalid message format").await;
            return;
        }
    };

    let ClientMessageRequest { mid, route, arg } = client_msg;

    match route.as_str() {
        "repl/prompt" => {
            if let Err(PermCheckError::Unauthorized) =
                check_access_async(&perms, &AccessRequest::LlmPrompt).await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let repl_arg: ReplPromptArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };

            let (exe, mut args) = crate::feature::self_invocation();
            if let Some(model) = repl_arg.model {
                args.push("-m".to_string());
                args.push(model);
            }
            args.push("bye".to_string());

            let len = repl_arg.messages.len();
            for (i, msg) in repl_arg.messages.iter().enumerate() {
                let content = match &msg.content {
                    MessageContent::Text { text } => match msg.role {
                        ChatRole::User => {
                            if i == len - 1 {
                                text.clone()
                            } else {
                                format!("/prep {}", text)
                            }
                        }
                        ChatRole::Assistant => format!("/assistant {}", text),
                    },
                    MessageContent::ImageUrl { .. } => {
                        // TODO: handle images (need /load-image-b64)
                        continue;
                    }
                };
                args.push(content);
            }

            let mut child = match tokio::process::Command::new(&exe)
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(e) => {
                    send_response::<ReplPromptResultDelta, ReplPromptError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplPromptError::ExecutionFailed {
                            message: e.to_string(),
                        })),
                        false,
                    )
                    .await;
                    return;
                }
            };

            let stdout = child.stdout.take().expect("stdout was piped");
            let stderr = child.stderr.take().expect("stderr was piped");

            let mut stdout_reader = BufReader::new(stdout);
            let mut stderr_reader = BufReader::new(stderr);
            let mut stdout_buf = vec![0u8; 4096];
            let mut stderr_buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    result = stdout_reader.read(&mut stdout_buf) => {
                        match result {
                            Ok(0) => break,
                            Ok(n) => {
                                let chunk = String::from_utf8_lossy(&stdout_buf[..n]).to_string();
                                let resp: ClientMessageResponse<ReplPromptResultDelta, ReplPromptError> =
                                    ClientMessageResponse::Ok {
                                        mid,
                                        result: ReplPromptResultDelta::Delta { delta: chunk },
                                        more: true,
                                    };
                                let json_string =
                                    serde_json::to_string(&resp).expect("Failed to serialize chunk");
                                if ws_sink
                                    .send(Message::Text(Utf8Bytes::from(&json_string)))
                                    .await
                                    .is_err()
                                {
                                    let _ = child.kill().await;
                                    return;
                                }
                            },
                            Err(e) => {
                                send_response::<ReplPromptResultDelta, ReplPromptError>(
                                    ws_sink,
                                    mid,
                                    Err(RequestError::Route(ReplPromptError::ExecutionFailed {
                                        message: e.to_string(),
                                    })),
                                    false,
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    result = stderr_reader.read(&mut stderr_buf) => {
                        match result {
                            Ok(0) => {},
                            Ok(n) => {
                                let chunk = String::from_utf8_lossy(&stderr_buf[..n]).to_string();
                                let resp: ClientMessageResponse<ReplPromptResultDelta, ReplPromptError> =
                                    ClientMessageResponse::Ok {
                                        mid,
                                        result: ReplPromptResultDelta::Delta { delta: chunk },
                                        more: false,
                                    };
                                let json_string =
                                    serde_json::to_string(&resp).expect("Failed to serialize chunk");
                                if ws_sink
                                    .send(Message::Text(Utf8Bytes::from(&json_string)))
                                    .await
                                    .is_err()
                                {
                                    let _ = child.kill().await;
                                    return;
                                }
                            },
                            Err(e) => {
                                send_response::<ReplPromptResultDelta, ReplPromptError>(
                                    ws_sink,
                                    mid,
                                    Err(RequestError::Route(ReplPromptError::ExecutionFailed {
                                        message: e.to_string(),
                                    })),
                                    false,
                                )
                                .await;
                                return;
                            }
                        }
                    }
                }
            }

            let status = child.wait().await;
            let success = status.map(|s| s.success()).unwrap_or(false);

            if success {
                let resp: ClientMessageResponse<ReplPromptResultDelta, ReplPromptError> =
                    ClientMessageResponse::Ok {
                        mid,
                        result: ReplPromptResultDelta::Done,
                        more: false,
                    };
                let json_string = serde_json::to_string(&resp).expect("Failed to serialize done");
                let _ = ws_sink
                    .send(Message::Text(Utf8Bytes::from(&json_string)))
                    .await;
            } else {
                send_response::<ReplPromptResultDelta, ReplPromptError>(
                    ws_sink,
                    mid,
                    Err(RequestError::Route(ReplPromptError::ExecutionFailed {
                        message: "Process exited with non-zero status".to_string(),
                    })),
                    false,
                )
                .await;
            }
        }
        "repl/whoami" => {
            let json_string = format!(
                r#"{{".tag":"ok","mid":{},"result":{{"username":{}}}}}"#,
                mid,
                serde_json::to_string(&username).unwrap_or("null".to_string())
            );
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
        }
        "repl/perm/get" => {
            let perms_guard = perms.lock().await;

            // Check if any existing permissions require keyring access.
            let perm_requires_keyring: bool =
                perms_guard.iter().any(|perm| perm.requires_keyring());
            // Perm requires it and a user has a keyring key.
            let unlocked_keyring_required =
                if perm_requires_keyring && let Some(username) = username {
                    asset_crypt::get_encryption_key(
                        asset_blob_cache.clone(),
                        api_client,
                        &KeyRecipient::User(username.to_string()),
                        None,
                    )
                    .await
                    .ok()
                    .flatten()
                } else {
                    None
                };

            let keyring_need_unlock =
                if let Some(unlocked_keyring_required) = unlocked_keyring_required {
                    if asset_keyring
                        .lock()
                        .await
                        .can_unlock_decrypt_key(
                            asset_blob_cache.clone(),
                            api_client,
                            &unlocked_keyring_required.recipient_key_id_parts(),
                        )
                        .await
                    {
                        false
                    } else {
                        true
                    }
                } else {
                    false
                };

            let perm_get_result = ReplPermGetResult {
                perms: perms_guard.clone(),
                keyring_need_unlock,
            };
            let resp: ClientMessageResponse<ReplPermGetResult, ()> = ClientMessageResponse::Ok {
                mid,
                result: perm_get_result,
                more: false,
            };
            let json_string = serde_json::to_string(&resp).expect("Failed to serialize response");
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
        }
        "repl/perm/request" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let perm_req_arg: ReplPermRequestArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };

            // Generate request_id
            let request_id: String = (0..10)
                .map(|_| {
                    let idx = rand::rng().random_range(0..62);
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    chars[idx] as char
                })
                .collect();

            // Generate CSRF token
            let csrf_token: String = (0..32)
                .map(|_| {
                    let idx = rand::rng().random_range(0..62);
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    chars[idx] as char
                })
                .collect();

            // Store with 5-minute expiry
            {
                let mut perm_requests = perm_request_map.lock().await;
                // Prevent memory leak: clear expired tokens
                let now = std::time::Instant::now();
                perm_requests.retain(|_, (_, expiry, _)| now < *expiry);
                perm_requests.insert(
                    request_id.clone(),
                    (
                        csrf_token.clone(),
                        now + std::time::Duration::from_secs(300),
                        perm_req_arg.perms.clone(),
                    ),
                );
            }

            let perm_requires_keyring: bool = perm_req_arg
                .perms
                .iter()
                .any(|perm| perm.requires_keyring());
            // Perm requires it and a user has a keyring key.
            let unlocked_keyring_required =
                if perm_requires_keyring && let Some(username) = username {
                    asset_crypt::get_encryption_key(
                        asset_blob_cache.clone(),
                        api_client,
                        &KeyRecipient::User(username.to_string()),
                        None,
                    )
                    .await
                    .ok()
                    .flatten()
                } else {
                    None
                };

            let keyring_need_unlock =
                if let Some(unlocked_keyring_required) = unlocked_keyring_required {
                    if asset_keyring
                        .lock()
                        .await
                        .can_unlock_decrypt_key(
                            asset_blob_cache.clone(),
                            api_client,
                            &unlocked_keyring_required.recipient_key_id_parts(),
                        )
                        .await
                    {
                        false
                    } else {
                        true
                    }
                } else {
                    false
                };

            let perms_guard = perms.lock().await;
            let new_requested_perms = perm_req_arg
                .perms
                .iter()
                .filter(|req_perm| !perms_guard.contains(req_perm))
                .collect::<Vec<_>>();

            let perm_req_result = ReplPermRequestResult {
                existing_perms: perms_guard.clone(),
                requested_perms: new_requested_perms.iter().map(|p| (*p).clone()).collect(),
                keyring_need_unlock,
                request_id: request_id.clone(),
                url: format!("http://{}/request/{}", perm_addr, request_id),
            };
            let resp: ClientMessageResponse<ReplPermRequestResult, ()> =
                ClientMessageResponse::Ok {
                    mid,
                    result: perm_req_result,
                    more: false,
                };
            let json_string = serde_json::to_string(&resp).expect("Failed to serialize response");
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
        }
        "asset/get" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let asset_arg: asset::AssetGetArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::ReadByName {
                    name: &asset_arg.name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_get(asset_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetGetResult,
                        asset::AssetGetError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/entry/list" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let list_arg: asset::AssetEntryListArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::ListPrefix {
                    prefix: list_arg.prefix.as_deref().unwrap_or(""),
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_entry_list(list_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetEntryListResult,
                        asset::AssetEntryListError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/entry/list/next" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let list_arg: asset::AssetEntryListNextArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            // NOTE: No additional permission check. Assumption is that the
            // caller was authorized for the first entry/list call.
            match api_client.asset_entry_list_next(list_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetEntryListResult,
                        asset::AssetEntryListNextError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/entry/search" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let search_arg: asset::AssetEntrySearchArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::ListPrefix {
                    prefix: search_arg.asset_pool_path.as_deref().unwrap_or(""),
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_entry_search(search_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetEntrySearchResult,
                        asset::AssetEntrySearchError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/move" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let move_arg: asset::AssetMoveArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::ReadByName {
                    name: &move_arg.source_name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &move_arg.target_name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_move(move_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetMoveResult,
                        asset::AssetMoveError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/remove" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let remove_arg: asset::AssetRemoveArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &remove_arg.name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_remove(remove_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetRemoveResult,
                        asset::AssetRemoveError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/revision/iter" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let rev_iter_arg: asset::AssetRevisionIterArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            match &rev_iter_arg.entry_ref {
                asset::EntryRef::Name(name) => {
                    if let Err(PermCheckError::Unauthorized) =
                        check_access_async(&perms, &AccessRequest::ReadByName { name }).await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                asset::EntryRef::EntryId(entry_id) => {
                    if let Err(PermCheckError::Unauthorized) = check_access_async(
                        &perms,
                        &AccessRequest::ReadByEntryId { entry_id: entry_id },
                    )
                    .await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                _ => {
                    send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                    return;
                }
            }
            match api_client.asset_revision_iter(rev_iter_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetRevisionIterResult,
                        asset::AssetRevisionIterError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/revision/iter/next" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let rev_iter_next_arg: asset::AssetRevisionIterNextArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            // NOTE: No additional permission check. Assumption is that the
            // caller was authorized for the first revision/iter call.
            match api_client.asset_revision_iter_next(rev_iter_next_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetRevisionIterResult,
                        asset::AssetRevisionIterNextError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/revision/get" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let rev_get_arg: asset::AssetRevisionGetArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            match &rev_get_arg.entry_ref {
                asset::EntryRef::Name(name) => {
                    if let Err(PermCheckError::Unauthorized) =
                        check_access_async(&perms, &AccessRequest::ReadByName { name }).await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                asset::EntryRef::EntryId(entry_id) => {
                    if let Err(PermCheckError::Unauthorized) = check_access_async(
                        &perms,
                        &AccessRequest::ReadByEntryId { entry_id: entry_id },
                    )
                    .await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                _ => {
                    send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                    return;
                }
            }
            match api_client.asset_revision_get(rev_get_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetRevisionGetResult,
                        asset::AssetRevisionGetError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/pool/create_shared" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let create_shared_arg: asset::AssetPoolCreateSharedArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            match api_client.asset_pool_create_shared(create_shared_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetPoolCreateSharedResult,
                        asset::AssetPoolCreateSharedError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/pool/list" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            match api_client.asset_pool_list(()).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<asset::AssetPoolListResult, ()> =
                        ClientMessageResponse::Ok {
                            mid: mid.clone(),
                            result: res,
                            more: false,
                        };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/folder/collapse" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let collapse_arg: asset::AssetPoolFolderCollapseArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &collapse_arg.prefix,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_folder_collapse(collapse_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<(), asset::AssetPoolFolderCollapseError> =
                        ClientMessageResponse::Ok {
                            mid: mid.clone(),
                            result: res,
                            more: false,
                        };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/folder/expand" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let expand_arg: asset::AssetPoolFolderExpandArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &expand_arg.prefix,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_folder_expand(expand_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<(), asset::AssetPoolFolderExpandError> =
                        ClientMessageResponse::Ok {
                            mid: mid.clone(),
                            result: res,
                            more: false,
                        };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/folder/list" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let list_arg: asset::AssetPoolFolderListArg =
                match serde_json::from_str(&arg.to_string()) {
                    Ok(arg) => arg,
                    Err(_e) => {
                        send_bad_request_error(
                            ws_sink,
                            &format!("Invalid argument for {}", route.as_str()),
                        )
                        .await;
                        return;
                    }
                };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &&AccessRequest::ListPrefix {
                    prefix: &list_arg.clone().prefix.unwrap_or("".to_string()),
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            match api_client.asset_folder_list(list_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetPoolFolderListResult,
                        asset::AssetPoolFolderListError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: res,
                        more: false,
                    };
                    let json_string =
                        serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
                    let _ = ws_sink
                        .send(Message::Text(Utf8Bytes::from(&json_string)))
                        .await;
                }
                Err(e) => {
                    send_error_response(ws_sink, mid, e).await;
                }
            }
        }
        "asset/put" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let asset_arg: asset::AssetPutArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &asset_arg.name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                asset_blob_cache.clone(),
                asset_keyring.clone(),
                api_client.clone(),
                username
                    .as_ref()
                    .map(|s| KeyRecipient::User(s.to_string()))
                    .as_ref(),
                &asset_arg.name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            eprintln!("error: {}", msg);
                        }
                    }
                    send_bad_request_error(ws_sink, "Decryption key error").await;
                    None
                }
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let _ = update_asset_tx
                .send(asset_async_writer::WorkerAssetMsg::Update(
                    asset_async_writer::WorkerAssetUpdate {
                        asset_name: asset_arg.name.clone(),
                        asset_entry_ref: None,
                        new_contents: asset_arg.data.clone(),
                        is_push: false,
                        api_client: api_client.clone(),
                        one_shot: true,
                        akm_info: akm_info.clone(),
                        reply_channel: Some(reply_tx),
                    },
                ))
                .await;
            if let Ok(Ok(new_entry)) = reply_rx.await {
                send_response::<asset::AssetEntry, asset::AssetPutError>(
                    ws_sink,
                    mid,
                    Ok(new_entry),
                    false,
                )
                .await;
                return;
            } else {
                send_bad_request_error(ws_sink, "Failed to update asset").await;
            }
        }
        "asset/put_text" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let asset_arg: asset::AssetPutTextArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(
                        ws_sink,
                        &format!("Invalid argument for {}", route.as_str()),
                    )
                    .await;
                    return;
                }
            };
            if let Err(PermCheckError::Unauthorized) = check_access_async(
                &perms,
                &AccessRequest::WriteByName {
                    name: &asset_arg.name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                asset_blob_cache.clone(),
                asset_keyring.clone(),
                api_client.clone(),
                username
                    .as_ref()
                    .map(|s| KeyRecipient::User(s.to_string()))
                    .as_ref(),
                &asset_arg.name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            eprintln!("error: {}", msg);
                        }
                    }
                    send_bad_request_error(ws_sink, "Decryption key error").await;
                    None
                }
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let _ = update_asset_tx
                .send(asset_async_writer::WorkerAssetMsg::Update(
                    asset_async_writer::WorkerAssetUpdate {
                        asset_name: asset_arg.name.clone(),
                        asset_entry_ref: None,
                        new_contents: asset_arg.data.into_bytes(),
                        is_push: false,
                        api_client: api_client.clone(),
                        one_shot: true,
                        akm_info: akm_info.clone(),
                        reply_channel: Some(reply_tx),
                    },
                ))
                .await;
            if let Ok(Ok(new_entry)) = reply_rx.await {
                send_response::<asset::AssetEntry, asset::AssetPutError>(
                    ws_sink,
                    mid,
                    Ok(new_entry),
                    false,
                )
                .await;
                return;
            } else {
                send_bad_request_error(ws_sink, "Failed to update asset").await;
            }
        }
        _other => {
            send_bad_request_error(ws_sink, "Unknown route").await;
        }
    }
}

// -- Permissions server

async fn handle_perm_http_connection(
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    clients: Clients,
    mut stream: tokio::net::TcpStream,
    perms: Perms,
    perm_request_map: PermRequestMap,
    username: Option<&str>,
    service_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf_reader = BufReader::new(&mut stream);

    let request = match HttpRequest::parse(&mut buf_reader, "localhost").await {
        Some(req) => req,
        None => return Ok(()),
    };

    let response = match request.method.as_str() {
        "GET" => {
            if request.path.starts_with("/request/") {
                let request_id = &request.path["/request/".len()..];
                let perm_request_map_unlocked = perm_request_map.lock().await;
                if let Some((csrf_token, _expiry, requested_perms)) =
                    perm_request_map_unlocked.get(request_id).cloned()
                {
                    drop(perm_request_map_unlocked);

                    // Build existing permissions section
                    let existing_perms = perms.lock().await;
                    let existing_section = if existing_perms.is_empty() {
                        r#"<div class="existing"><div class="section-label">Existing permissions</div><div class="existing-empty">None granted yet.</div></div>"#.to_string()
                    } else {
                        let mut items = String::new();
                        for perm in existing_perms.iter() {
                            let (icon, label, detail) = format_perm_toggle(perm);
                            items.push_str(&format!(
                                r#"<div class="existing-item"><span class="perm-icon">{icon}</span><div><div class="perm-label">{label}</div><div class="perm-detail">{detail}</div></div></div>"#,
                            ));
                        }
                        format!(
                            r#"<div class="existing"><div class="section-label">Existing permissions</div>{items}</div>"#,
                        )
                    };

                    let mut perm_toggles = String::new();
                    for (i, perm) in requested_perms.iter().enumerate() {
                        if existing_perms.contains(perm) {
                            continue;
                        }
                        let (icon, label, detail) = format_perm_toggle(perm);
                        let data_json = serde_json::to_string(perm).unwrap_or_default();
                        let data_attr = html_escape(&data_json);
                        perm_toggles.push_str(&format!(
                            r#"<label class="perm" for="p{i}">
<div class="perm-info"><span class="perm-icon">{icon}</span><div><div class="perm-label">{label}</div><div class="perm-detail">{detail}</div></div></div>
<div class="toggle"><input type="checkbox" id="p{i}" name="perm_{i}" data-perm="{data_attr}" checked><span class="track"><span class="knob"></span></span></div>
</label>"#,
                        ));
                    }

                    drop(existing_perms);

                    // Determine if keyring unlock is needed
                    let perm_requires_keyring: bool =
                        requested_perms.iter().any(|perm| perm.requires_keyring());

                    let unlocked_keyring_required =
                        if perm_requires_keyring && let Some(username) = username {
                            asset_crypt::get_encryption_key(
                                asset_blob_cache.clone(),
                                api_client,
                                &KeyRecipient::User(username.to_string()),
                                None,
                            )
                            .await
                            .ok()
                            .flatten()
                        } else {
                            None
                        };

                    let keyring_need_unlock =
                        if let Some(ref unlocked_keyring_required) = unlocked_keyring_required {
                            if asset_keyring
                                .lock()
                                .await
                                .can_unlock_decrypt_key(
                                    asset_blob_cache.clone(),
                                    api_client,
                                    &unlocked_keyring_required.recipient_key_id_parts(),
                                )
                                .await
                            {
                                false
                            } else {
                                true
                            }
                        } else {
                            false
                        };

                    // Build keyring section
                    let keyring_section = if keyring_need_unlock {
                        r#"<div class="keyring-section">
    <div class="section-label">Keyring unlock required</div>
    <div class="keyring-info"><p>Some requested permissions require access to encrypted data. Enter your keyring password to unlock.</p></div>
    <div class="keyring-error" id="keyring-error" style="display:none;"><span class="error-icon">✕</span><span id="keyring-error-msg"></span></div>
    <div class="keyring-input-wrap">
        <label class="keyring-label" for="keyring_password">🔒 Keyring password</label>
        <input type="password" id="keyring_password" class="keyring-input" placeholder="Enter your keyring password" autocomplete="off">
    </div>
</div>"#.to_string()
                    } else {
                        String::new()
                    };

                    let keyring_need_unlock_js = if keyring_need_unlock { "true" } else { "false" };

                    HttpResponse::ok(
                        format!(
                            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Permissions — {service_name_escaped}</title>
<style>
:root {{ --bg: #1a1a1e; --surface: #26262b; --surface2: #2f2f35; --border: #38383f; --text: #e4e4e8; --text2: #9a9aa0; --accent: #6c8cff; --accent-hover: #5a7af0; --green: #3dd68c; --green-bg: #2a3a30; --red: #ff6b6b; --red-bg: #3a2a2a; --red-border: #5a3333; --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 24px 16px; min-height: 100vh; }}
.container {{ max-width: 460px; margin: 0 auto; }}
.header {{ margin-bottom: 36px; }}
.header h1 {{ font-size: 18px; font-weight: 600; margin-bottom: 4px; }}
.header .app-name {{ color: var(--accent); }}
.header p {{ font-size: 13px; color: var(--text2); }}
.section-label {{ font-size: 16px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text2); margin-bottom: 8px; }}
.perm {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 6px; cursor: pointer; transition: background 0.15s; }}
.perm:hover {{ background: var(--surface2); }}
.perm-info {{ display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }}
.perm-icon {{ font-size: 18px; flex-shrink: 0; width: 28px; text-align: center; }}
.perm-label {{ font-size: 13px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.perm-detail {{ font-size: 11px; color: var(--text2); font-family: var(--mono); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.perm-detail code {{ background: var(--surface2); padding: 1px 5px; border-radius: 4px; font-size: 11px; font-family: var(--mono); }}
.toggle {{ position: relative; flex-shrink: 0; }}
.toggle input {{ position: absolute; opacity: 0; pointer-events: none; }}
.track {{ display: block; width: 44px; height: 26px; background: #48484f; border-radius: 13px; position: relative; transition: background 0.2s; }}
.knob {{ position: absolute; top: 3px; left: 3px; width: 20px; height: 20px; background: #fff; border-radius: 50%; transition: transform 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }}
.toggle input:checked + .track {{ background: var(--green); }}
.toggle input:checked + .track .knob {{ transform: translateX(18px); }}
.btn {{ display: block; width: 100%; padding: 13px; background: var(--accent); color: #fff; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.15s; margin-top: 32px; }}
.btn:hover {{ background: var(--accent-hover); }}
.btn:active {{ transform: scale(0.98); }}
.existing {{ margin-bottom: 36px; }}
.existing-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 6px; opacity: 0.65; }}
.existing-empty {{ font-size: 13px; color: var(--text2); padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; }}
.remember {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-top: 16px; cursor: pointer; transition: background 0.15s; }}
.remember:hover {{ background: var(--surface2); }}
.remember-info {{ display: flex; flex-direction: column; gap: 2px; flex: 1; min-width: 0; }}
.remember-label {{ font-size: 13px; font-weight: 500; }}
.remember-detail {{ font-size: 11px; color: var(--text2); }}
.keyring-section {{ margin-bottom: 36px; }}
.keyring-info p {{ font-size: 13px; color: var(--text2); margin-bottom: 12px; }}
.keyring-input-wrap {{ position: relative; }}
.keyring-label {{ display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; color: var(--text2); }}
.keyring-input {{ display: block; width: 100%; padding: 12px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; color: var(--text); font-size: 14px; font-family: var(--mono); outline: none; transition: border-color 0.15s; }}
.keyring-input:focus {{ border-color: var(--accent); }}
.keyring-input.has-error {{ border-color: var(--red); }}
.keyring-error {{ display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: var(--red-bg); border: 1px solid var(--red-border); border-radius: 10px; margin-bottom: 10px; font-size: 13px; color: var(--red); }}
.error-icon {{ font-size: 14px; font-weight: 700; flex-shrink: 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1><span class="app-name">{service_name_escaped}</span> is requesting permissions</h1>
        <p>Toggle off anything you don't want to grant.</p>
    </div>
    {existing_section}
    <form id="f">
        <input type="hidden" name="csrf_token" value="{csrf_token_escaped}">
        {keyring_section}
        <div class="requested">
            <div class="section-label">Requested</div>
            {perm_toggles}
        </div>
        <label class="remember" for="remember">
            <div class="remember-info">
                <div class="remember-label">Long-term access</div>
                <div class="remember-detail">Remember these permissions for future sessions</div>
            </div>
            <div class="toggle">
                <input type="checkbox" id="remember" checked>
                <span class="track"><span class="knob"></span></span>
            </div>
        </label>
        <button class="btn" type="submit">Grant selected</button>
    </form>
</div>
<script>
const KEYRING_NEEDED = {keyring_need_unlock_js};

function showKeyringError(msg) {{
    const errEl = document.getElementById('keyring-error');
    const errMsg = document.getElementById('keyring-error-msg');
    const pwInput = document.getElementById('keyring_password');
    if (errEl && errMsg && pwInput) {{
        errMsg.textContent = msg;
        errEl.style.display = 'flex';
        pwInput.classList.add('has-error');
        pwInput.focus();
        pwInput.select();
    }}
}}

function clearKeyringError() {{
    const errEl = document.getElementById('keyring-error');
    const pwInput = document.getElementById('keyring_password');
    if (errEl) errEl.style.display = 'none';
    if (pwInput) pwInput.classList.remove('has-error');
}}

if (KEYRING_NEEDED) {{
    document.getElementById('keyring_password').addEventListener('input', clearKeyringError);
}}

document.getElementById('f').onsubmit = e => {{
    e.preventDefault();
    const btn = e.target.querySelector('button');

    let keyring_password = null;
    if (KEYRING_NEEDED) {{
        const pwInput = document.getElementById('keyring_password');
        keyring_password = pwInput.value;
        if (!keyring_password) {{
            showKeyringError('Please enter your keyring password.');
            return;
        }}
    }}

    btn.disabled = true;
    btn.textContent = 'Granting\u2026';
    clearKeyringError();

    const grant = [];
    document.querySelectorAll('input[type=checkbox][data-perm]').forEach(c => {{
        if (c.checked) grant.push(JSON.parse(c.dataset.perm));
    }});
    const remember = document.getElementById('remember').checked;
    const body = {{
        csrf_token: document.querySelector('input[name=csrf_token]').value,
        request_id: "{request_id_escaped}",
        grant,
        remember
    }};
    if (keyring_password !== null) {{
        body.keyring_password = keyring_password;
    }}
    fetch('/submit', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
    }}).then(r => {{
        if (r.ok) return r.text().then(t => {{ document.open(); document.write(t); document.close(); }});
        if (r.status === 401) {{
            return r.json().then(j => {{
                btn.disabled = false;
                btn.textContent = 'Grant selected';
                showKeyringError(j.message || 'Incorrect keyring password. Please try again.');
            }}).catch(() => {{
                btn.disabled = false;
                btn.textContent = 'Grant selected';
                showKeyringError('Incorrect keyring password. Please try again.');
            }});
        }}
        btn.disabled = false;
        btn.textContent = 'Grant selected';
        alert('Failed (' + r.status + ')');
    }}).catch(() => {{
        btn.disabled = false;
        btn.textContent = 'Grant selected';
        alert('Network error');
    }});
}};
</script>
</body>
</html>"#,
                            service_name_escaped = html_escape(service_name),
                            csrf_token_escaped = html_escape(&csrf_token),
                            perm_toggles = perm_toggles,
                            request_id_escaped = html_escape(request_id),
                            existing_section = existing_section,
                            keyring_section = keyring_section,
                            keyring_need_unlock_js = keyring_need_unlock_js,
                        )
                        .into(),
                        "text/html",
                    )
                } else {
                    HttpResponse::not_found()
                }
            } else {
                HttpResponse::not_found()
            }
        }
        "POST" => {
            if request.path == "/submit" {
                if let Ok(perm_req) = serde_json::from_slice::<PermRequestSubmit>(&request.body) {
                    let mut perm_request_map_unlocked = perm_request_map.lock().await;
                    if let Some((csrf_token, expiry, perms_requested)) =
                        perm_request_map_unlocked.get(&perm_req.request_id).cloned()
                    {
                        let now = std::time::Instant::now();
                        if perm_req.csrf_token == csrf_token && now < expiry {
                            // Check if any granted perms require keyring
                            let any_granted_requires_keyring =
                                perm_req.grant.iter().any(|perm| perm.requires_keyring());

                            let unlocked_keyring_required =
                                if any_granted_requires_keyring && let Some(username) = username {
                                    asset_crypt::get_encryption_key(
                                        asset_blob_cache.clone(),
                                        api_client,
                                        &KeyRecipient::User(username.to_string()),
                                        None,
                                    )
                                    .await
                                    .ok()
                                    .flatten()
                                } else {
                                    None
                                };

                            let keyring_need_unlock = if let Some(ref unlocked_keyring_required) =
                                unlocked_keyring_required
                            {
                                !asset_keyring
                                    .lock()
                                    .await
                                    .can_unlock_decrypt_key(
                                        asset_blob_cache.clone(),
                                        api_client,
                                        &unlocked_keyring_required.recipient_key_id_parts(),
                                    )
                                    .await
                            } else {
                                false
                            };

                            // If keyring unlock is needed, validate the password
                            if keyring_need_unlock {
                                let password = perm_req.keyring_password.as_deref().unwrap_or("");
                                if password.is_empty() {
                                    drop(perm_request_map_unlocked);
                                    let resp = HttpResponse::json_status(
                                        401,
                                        r#"{"message":"Keyring password is required to grant these permissions."}"#,
                                    );
                                    resp.write_to(&mut stream).await?;
                                    return Ok(());
                                }

                                let rec_key_id_parts = unlocked_keyring_required
                                    .as_ref()
                                    .unwrap()
                                    .recipient_key_id_parts();

                                let unlock_success = asset_keyring
                                    .lock()
                                    .await
                                    .unlock_decrypt_key(
                                        asset_blob_cache.clone(),
                                        api_client,
                                        &rec_key_id_parts,
                                        password,
                                    )
                                    .await
                                    .is_ok();

                                if !unlock_success {
                                    // Password incorrect
                                    drop(perm_request_map_unlocked);
                                    let resp = HttpResponse::json_status(
                                        401,
                                        r#"{"message":"Incorrect keyring password. Please try again."}"#,
                                    );
                                    resp.write_to(&mut stream).await?;
                                    return Ok(());
                                }
                            }

                            // Keyring is unlocked (or wasn't needed)
                            perm_request_map_unlocked.remove(&perm_req.request_id);
                            drop(perm_request_map_unlocked);

                            let mut perms_unlocked = perms.lock().await;
                            let mut newly_granted = Vec::new();
                            for granted_perm in perm_req.grant.iter() {
                                if perms_unlocked.contains(granted_perm) {
                                    continue;
                                }
                                if perms_requested.contains(granted_perm) {
                                    perms_unlocked.push(granted_perm.clone());
                                    newly_granted.push(granted_perm.clone());
                                }
                            }

                            if let Some(username) = username
                                && perm_req.remember
                                && !newly_granted.is_empty()
                            {
                                let _ = crate::db::merge_gateway_perms(
                                    &mut *db.lock().await,
                                    username,
                                    service_name,
                                    &newly_granted,
                                );
                            }

                            let remember_active = perm_req.remember;

                            let mut all_rows = String::new();
                            for perm in perms_unlocked.iter() {
                                let is_new = newly_granted.contains(perm);
                                let (icon, label, detail) = format_perm_toggle(perm);
                                let new_badge = if is_new {
                                    r#" <span class="badge">new</span>"#
                                } else {
                                    ""
                                };
                                all_rows.push_str(&format!(
                                    r#"<div class="perm-row{}"><span class="perm-icon">{icon}</span><div><div class="perm-label">{label}{new_badge}</div><div class="perm-detail">{detail}</div></div></div>"#,
                                    if is_new { " new-row" } else { "" },
                                ));
                            }
                            drop(perms_unlocked);

                            if !newly_granted.is_empty() {
                                let clients_unlocked = clients.lock().await;
                                for (_client_id, tx) in clients_unlocked.iter() {
                                    let json_string = format!(
                                        r#"{{".tag":"ok","mid":{},"route":"client/perm/updated","arg":null}}"#,
                                        -1,
                                    );
                                    let _ = tx.send(Message::Text(Utf8Bytes::from(&json_string)));
                                }
                            }

                            if all_rows.is_empty() {
                                all_rows = r#"<div class="perm-row"><div class="perm-label" style="color:var(--text2);">No permissions granted.</div></div>"#.to_string();
                            }

                            let granted_count = newly_granted.len();
                            let subtitle = if granted_count == 0 {
                                "No new permissions were granted.".to_string()
                            } else {
                                let persist_note = if remember_active {
                                    " These will be remembered for future sessions."
                                } else {
                                    " These apply to this session only."
                                };
                                format!(
                                    "{} permission{} granted.{}",
                                    granted_count,
                                    if granted_count == 1 { "" } else { "s" },
                                    persist_note,
                                )
                            };

                            HttpResponse::ok(
                                format!(
                                    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Permissions Granted</title>
<style>
:root {{ --bg: #1a1a1e; --surface: #26262b; --surface2: #2f2f35; --border: #38383f; --text: #e4e4e8; --text2: #9a9aa0; --green: #3dd68c; --green-dim: #2a3a30; --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 24px 16px; min-height: 100vh; }}
.container {{ max-width: 460px; margin: 0 auto; }}
.done-icon {{ font-size: 36px; margin-bottom: 12px; }}
.header h1 {{ font-size: 18px; font-weight: 600; margin-bottom: 4px; }}
.header p {{ font-size: 13px; color: var(--text2); margin-bottom: 20px; }}
.section-label {{ font-size: 16px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text2); margin-bottom: 8px; }}
.perm-row {{ display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 6px; }}
.new-row {{ border-color: var(--green); background: var(--green-dim); }}
.perm-icon {{ font-size: 18px; flex-shrink: 0; width: 28px; text-align: center; }}
.perm-label {{ font-size: 13px; font-weight: 500; }}
.perm-detail {{ font-size: 11px; color: var(--text2); font-family: var(--mono); margin-top: 2px; }}
.perm-detail code {{ background: var(--surface2); padding: 1px 5px; border-radius: 4px; font-size: 11px; font-family: var(--mono); }}
.badge {{ display: inline-block; font-size: 10px; font-weight: 600; background: var(--green); color: #1a1a1e; padding: 1px 6px; border-radius: 4px; margin-left: 6px; vertical-align: middle; text-transform: uppercase; letter-spacing: 0.03em; }}
.close-msg {{ margin-top: 20px; text-align: center; font-size: 12px; color: var(--text2); }}
.persist-note {{ display: flex; align-items: center; gap: 8px; margin-top: 14px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; font-size: 12px; color: var(--text2); }}
.persist-note .pi {{ font-size: 16px; flex-shrink: 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="done-icon">✓</div>
        <h1>Done</h1>
        <p>{subtitle}</p>
    </div>
    <div class="section-label">All granted permissions</div>
    {all_rows}
    {persist_section}
    <p class="close-msg">You can close this tab.</p>
</div>
</body>
</html>"#,
                                    subtitle = html_escape(&subtitle),
                                    all_rows = all_rows,
                                    persist_section = if remember_active && granted_count > 0 {
                                        r#"<div class="persist-note"><span class="pi">💾</span>Long-term access enabled — permissions saved for future sessions.</div>"#
                                    } else if granted_count > 0 {
                                        r#"<div class="persist-note"><span class="pi">⏳</span>Session only — permissions will reset when the app restarts.</div>"#
                                    } else {
                                        ""
                                    },
                                )
                                .into(),
                                "text/html",
                            )
                        } else {
                            HttpResponse::forbidden()
                        }
                    } else {
                        HttpResponse::forbidden()
                    }
                } else {
                    HttpResponse::bad_request("Invalid JSON")
                }
            } else {
                HttpResponse::not_found()
            }
        }
        _ => HttpResponse::bad_request("Only GET and POST supported"),
    };

    response.write_to(&mut stream).await?;

    Ok(())
}

fn format_perm_toggle(
    perm: &Perm,
) -> (
    // icon
    &'static str,
    // label
    String,
    // description (html)
    String,
) {
    match perm {
        Perm::AssetName { name, perm: ap } => {
            let flags = perm_flags(ap.read, ap.write, false, false);
            (
                "📄",
                format!("Asset by name"),
                format!("<code>{}</code> — {}", html_escape(name), flags),
            )
        }
        Perm::AssetEntryId { entry_id, perm: ap } => {
            let flags = perm_flags(ap.read, ap.write, false, false);
            (
                "📄",
                format!("Asset by ID"),
                format!("<code>{}</code> — {}", html_escape(entry_id), flags),
            )
        }
        Perm::AssetPrefix {
            prefix,
            perm: ap,
            prefix_perm,
        } if prefix == "" => {
            let flags = perm_flags(ap.read, ap.write, prefix_perm.create, prefix_perm.list);
            ("📁", format!("All private assets"), format!("{}", flags))
        }
        Perm::AssetPrefix {
            prefix,
            perm: ap,
            prefix_perm,
        } => {
            let flags = perm_flags(ap.read, ap.write, prefix_perm.create, prefix_perm.list);
            (
                "📁",
                format!("Asset prefix"),
                format!("<code>{}</code> — {}", html_escape(prefix), flags),
            )
        }
        Perm::PublicAsset => (
            "📄",
            format!("Public assets"),
            format!("<code>/*</code> not including <code>/s/*</code>"),
        ),
        Perm::SharedAssetName { name, perm: ap } => {
            let flags = perm_flags(ap.read, ap.write, false, false);
            (
                "📄",
                format!("Shared asset by name"),
                format!("<code>/s/*/{}</code> — {}", html_escape(name), flags),
            )
        }
        Perm::SharedAssetPrefix {
            prefix,
            perm: ap,
            prefix_perm,
        } => {
            let flags = perm_flags(ap.read, ap.write, prefix_perm.create, prefix_perm.list);
            (
                "📁",
                format!("Shared asset prefix"),
                format!("<code>/s/*/{}</code> — {}", html_escape(prefix), flags),
            )
        }
        Perm::LlmPrompt => (
            "💬",
            format!("LLM Prompting"),
            "Converse without tools or system-level permissions".to_string(),
        ),
    }
}

fn perm_flags(read: bool, write: bool, create: bool, list: bool) -> String {
    let mut flags = Vec::new();
    if read {
        flags.push("read");
    }
    if write {
        flags.push("write");
    }
    if create {
        flags.push("create");
    }
    if list {
        flags.push("list");
    }
    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(", ")
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermRequestSubmit {
    request_id: String,
    csrf_token: String,
    grant: Vec<Perm>,
    remember: bool,
    keyring_password: Option<String>,
}
