use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server;
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};
use tokio_util::sync::CancellationToken;

use crate::api::client::{HaiClient, RequestError};
use crate::api::types::asset;
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader::{DataFetchFailure, GetRevisionError};
use crate::feature::asset_crypt::{EncryptKeyInfo, VerifyingKeyInfo};
use crate::feature::{kernel, opengraph};
use crate::session::{self, CmdInputReply};
use crate::{
    asset_async_writer, asset_helper, asset_reader,
    feature::asset_crypt::{self, KeyRecipient},
};
use crate::{
    errorln, infoln,
    io::{Io, Out},
};

// --

//
// Cookie helpers
//

pub const HAI_TOKEN_COOKIE_NAME: &str = "hai_token";

/// Encodes a name into a cookie-name-safe string.
///
/// Necessary b/c cookie names must be US-ASCII and missing special chars like
/// front slash.
///
/// Useful for encoding asset names in cookie names.
fn encode_cookie_name(name: &str) -> String {
    URL_SAFE_NO_PAD.encode(name.as_bytes())
}

fn encode_cookie_name_suffix(asset_app_name: &str, username: Option<&str>) -> String {
    match username {
        Some(username) => encode_cookie_name(&format!("{}_{}", username, asset_app_name)),
        None => encode_cookie_name(asset_app_name),
    }
}

/// Use this for generating auth cookies!
///
/// IMPORTANT: All `localhost:*` sites share the same cookies. So, it's
/// critical that all cookies are HTTP_ONLY and that they're namespaced at the
/// cookie-name level to avoid collisions (worse, assumption of another app's
/// permissions).
fn auth_cookie_name(service_name: &str, username: Option<&str>, port: u16) -> String {
    format!(
        "{}_{}_{}",
        HAI_TOKEN_COOKIE_NAME,
        encode_cookie_name_suffix(service_name, username),
        port
    )
}

// --

pub type ClientId = u64;
pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<std::collections::HashMap<ClientId, Client>>>;

pub type PermCtxs = Arc<Mutex<Vec<PermCtx>>>;

// --

//
// Perm-gate types
//

/// A pending permission request created by gateway's `repl/perm/request`.
/// The request is referenced by the perm-gate's `perm_gate/request/submit`.
#[derive(Debug, Clone)]
pub struct PendingPermRequest {
    pub expiry: std::time::Instant,
    pub perms: Vec<Perm>,
    pub choosers: Vec<Chooser>,
}

/// Map of perm_request_id -> pending request
pub type PermRequestMap = Arc<Mutex<HashMap<String, PendingPermRequest>>>;

/// TTL for pending permission requests.
const PERM_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Asset-apps can request to open another asset-app using the gateway route
/// `/repl/open_with`. We store these pending requests in the following struct
/// (keyed by token) and check the request when the user's browser accesses the
/// perm-gate's `/open`. This prevents other web apps from opening asset-apps.
#[derive(Debug, Clone)]
pub struct PendingAssetAppOpen {
    pub asset_app: String,
    pub asset: Option<String>,
    pub expiry: std::time::Instant,
}

// Map of asset_app_open_token -> pending open
pub type AssetAppOpenTokenMap = Arc<Mutex<HashMap<String, PendingAssetAppOpen>>>;

const ASSET_APP_OPEN_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const MAX_ASSET_APP_OPEN_TOKENS: usize = 1000;

/// Hard-coded service name of the perm-gate asset-app.
pub const PERM_GATE_SERVICE_NAME: &str = "/hai/app/perm-gate";
const PERM_GATE_ASSET_PREFIX: &str = "/hai/app/perm-gate/";

/// Single-file build of the perm-gate for running it fully locally.
const PERM_GATE_EMBEDDED_HTML: &[u8] = include_bytes!("perm_gate_embedded.html");

// --

/// Where the perm-gate asset-app is served from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermGateSource {
    /// Served from `/hai/app/perm-gate/` in the asset store.
    AssetStore,
    /// Served from the single-file build embedded in the binary.
    Embedded,
}

impl PermGateSource {
    /// Set `HAI_PERM_GATE_SOURCE=embedded` to use the embedded build.
    /// Defaults to the asset store.
    pub fn from_env() -> Self {
        match std::env::var("HAI_PERM_GATE_SOURCE").as_deref() {
            Ok("embedded") => PermGateSource::Embedded,
            _ => PermGateSource::AssetStore,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PermGateSource::AssetStore => "asset-store",
            PermGateSource::Embedded => "embedded",
        }
    }
}

/// State of the asset-app gateway that a perm-gate gateway administers.
pub struct PermGateCtx {
    pub repl_remote: crate::repl_remote::ReplRemote,
    pub target_service_name: String,
    pub target_perm_ctxs: PermCtxs,
    pub target_perm_request_map: PermRequestMap,
    pub target_clients: Clients,
    pub source: PermGateSource,
}

/// IMPORTANT: The mode is determined solely by how the gateway was launched.
pub enum GatewayMode {
    /// Regular asset-app gateway.
    App,
    /// Perm-gate gateway: serves only the perm-gate asset-app, exposes
    /// `/open` and the `perm-gate/*` websocket routes.
    PermGate(PermGateCtx),
}

// --

//
// Asset-app Permissions
//

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetPerm {
    pub read: bool,
    pub write: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetPrefixPerm {
    pub create: bool,
    pub list: bool,
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
    /// NOTE: This isn't intended to be used long-term. It's a temporary
    /// measure since the hai kernel has no capability for restricting
    /// permissions.
    Everything,
}

impl Perm {
    /// Check if this single permission grants the requested access
    fn grants(&self, request: &AccessRequest<'_>) -> bool {
        match (self, request) {
            // The Everything permission grants all access
            (Perm::Everything, _) => true,

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

            // Entry ID match for write
            (
                Perm::AssetEntryId { entry_id, perm },
                AccessRequest::WriteByEntryId { entry_id: req_id },
            ) => entry_id == *req_id && perm.write,

            // Prefix match for read by name
            (Perm::AssetPrefix { prefix, perm, .. }, AccessRequest::ReadByName { name }) => {
                name.starts_with(prefix)
                    && perm.read
                    && !name.starts_with(".keys/")
                    && !name.starts_with("vault/")
                    && !name.starts_with(".sys/hai.toml")
            }

            // Prefix match for write by name
            (Perm::AssetPrefix { prefix, perm, .. }, AccessRequest::WriteByName { name }) => {
                name.starts_with(prefix)
                    && perm.write
                    && !name.starts_with(".keys/")
                    && !name.starts_with("vault/")
                    && !name.starts_with(".sys/hai.toml")
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
                asset_helper::is_in_public_asset_pool(req_name)
            }
            (Perm::PublicAsset, AccessRequest::WriteByName { name: req_name }) => {
                // Allow an attempt to write to a public path knowing that the
                // API will reject it unless the owner has given explicit
                // permission otherwise.
                asset_helper::is_in_public_asset_pool(req_name)
            }

            // --- Shared asset name: match the suffix after /s/<participants>/ ---
            (
                Perm::SharedAssetName { name, perm },
                AccessRequest::ReadByName { name: req_name },
            ) => asset_helper::get_shared_asset_relpath(req_name)
                .map_or(false, |suffix| suffix == name && perm.read),
            (
                Perm::SharedAssetName { name, perm },
                AccessRequest::WriteByName { name: req_name },
            ) => asset_helper::get_shared_asset_relpath(req_name)
                .map_or(false, |suffix| suffix == name && perm.write),

            // --- Shared asset prefix: match the suffix after /s/<participants>/ ---
            (Perm::SharedAssetPrefix { prefix, perm, .. }, AccessRequest::ReadByName { name }) => {
                asset_helper::get_shared_asset_relpath(name)
                    .map_or(false, |suffix| suffix.starts_with(prefix) && perm.read)
            }
            (Perm::SharedAssetPrefix { prefix, perm, .. }, AccessRequest::WriteByName { name }) => {
                asset_helper::get_shared_asset_relpath(name)
                    .map_or(false, |suffix| suffix.starts_with(prefix) && perm.write)
            }
            (
                Perm::SharedAssetPrefix {
                    prefix,
                    prefix_perm,
                    ..
                },
                AccessRequest::ListPrefix { prefix: req_prefix },
            ) => asset_helper::get_shared_asset_relpath(req_prefix).map_or(false, |suffix| {
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
                | Perm::Everything
        )
    }
}

/// Check if any permission in the list grants the requested access
pub fn check_access(
    perm_ctxs: &[PermCtx],
    request: &AccessRequest<'_>,
) -> Result<(), PermCheckError> {
    if perm_ctxs.iter().any(|p| p.perm.grants(request)) {
        Ok(())
    } else {
        Err(PermCheckError::Unauthorized)
    }
}

/// Async version that takes the Arc<Mutex<...>> directly
pub async fn check_access_async(
    perm_ctxs: &PermCtxs,
    request: &AccessRequest<'_>,
) -> Result<(), PermCheckError> {
    let perm_ctxs = perm_ctxs.lock().await;
    check_access(&perm_ctxs, request)
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
    /// Write a specific asset by entry_id
    WriteByEntryId { entry_id: &'a str },
    /// List assets under a prefix
    ListPrefix { prefix: &'a str },
    /// Prompt LLM
    LlmPrompt,
    /// Everything
    Everything,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermCheckError {
    Unauthorized,
}

// --

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermCtx {
    perm: Perm,
    lifetime: PermLifetime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum PermLifetime {
    Default,
    UntilRevoked,
    ThisSession,
}

// --

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum Chooser {
    Asset {
        by_entry_id: bool,
        max_count: Option<u32>,
        perm: AssetPerm,
        /// UI hint for the perm-gate's picker. Not enforced by the gateway.
        filter: ChooserAssetFilter,
    },
    /// If `by_entry_id`, the folder is granted via `Perm::AssetEntryId` (just
    /// like a blob) and `prefix_perm` is unused. Otherwise, it's granted via
    /// `Perm::AssetPrefix`.
    AssetFolder {
        by_entry_id: bool,
        perm: AssetPerm,
        prefix_perm: AssetPrefixPerm,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ChooserAssetFilter {
    All,
    Images,
}

// --

//
// Kernel types and handles
//

pub type KernelId = String;

pub struct KernelHandle {
    pub child: tokio::process::Child,
    #[allow(dead_code)]
    pub port: u16,
    #[allow(dead_code)]
    pub token: String,
    #[allow(dead_code)]
    pub created_at: std::time::Instant,
    pub tags: Vec<String>,
}

pub type KernelMap = Arc<Mutex<HashMap<KernelId, KernelHandle>>>;

// --

//
// HTTP Request Parsing
//

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

// --

//
// HTTP Response Helpers
//

/// URL is prettier if / and + are not percent-encoded. They're common in asset
/// names in fragments.
fn encode_asset_fragment(asset_name: &str) -> String {
    urlencoding::encode(asset_name)
        .to_string()
        .replace("%2F", "/")
        .replace("%2B", "+")
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

    fn too_many_requests() -> Self {
        Self {
            status: 429,
            status_text: "Too Many Requests",
            content_type: "text/plain".into(),
            body: b"Rate limit exceeded. Try again in 60 seconds.".to_vec(),
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

    fn payload_too_large(msg: &str) -> Self {
        Self {
            status: 413,
            status_text: "Payload Too Large",
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

    fn auth_cookie(
        username: Option<&str>,
        service_name: &str,
        local_addr: &SocketAddr,
        token: &str,
    ) -> String {
        // `Secure` is not set because this is used over localhost
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict",
            auth_cookie_name(service_name, username, local_addr.port()),
            token
        )
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
}

// --

pub struct ViteProxy {
    pub host: String,
    pub asset_prefix: String,
}

pub const GATEWAY_BASE_PORT: u16 = 1339;

/// Launches a gateway server.
///
/// The gateway server is a bit more complex than a single server. Two separate
/// listeners are launched on differenrt ports each capable of responding to
/// HTTP and websocket requests independently. The first listener serves as the
/// primary gateway serving the asset-app. The second listener serves as a
/// permission-gate and handles requests specifically for changing an app's
/// permissions.
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
/// * `vite_proxy` - When set, where GET requests whose asset path begins with
///   `asset_prefix` are proxied to instead of being served from the asset API.
///   Vite websocket requests are also proxied.
pub async fn launch_gateway(
    io: &Io,
    config_path_override: Option<&str>,
    repl_remote: crate::repl_remote::ReplRemote,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    auth_token: Option<&str>,
    service_name: &str,
    vite_proxy: Option<ViteProxy>,
) -> std::io::Result<(SocketAddr, SocketAddr, Clients, CancellationToken, String)> {
    // Set process-wide API limiter to limit gateway traffic (HTTP & websocket
    // routes) to the API. Otherwise, asset-apps have a tendency to overwhelm
    // the API with requests and trigger 429s which they don't handle
    // gracefully.
    let api_client = api_client.with_limiter(crate::api::limiter::gateway_limiter());

    // Generate a random authentication token
    let token = auth_token.map_or_else(generate_token, |t| t.to_string());

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

    infoln!(
        io,
        "Gateway listening on http://localhost:{} (HTTP + WebSocket)",
        local_addr.port()
    );
    infoln!(io, "Token: {}", token);
    let perm_gate_source = PermGateSource::from_env();
    infoln!(
        io,
        "Perm-gate on http://localhost:{} (source: {})",
        perm_addr.port(),
        perm_gate_source.as_str()
    );

    let clients: Clients = Arc::new(Mutex::new(std::collections::HashMap::new()));

    let maybe_slash = if service_name.ends_with("/") { "" } else { "/" };
    let app_folder_prefix = if service_name.starts_with("/") {
        format!(".app{}{}", service_name, maybe_slash)
    } else {
        format!(".app/p/{}{}", service_name, maybe_slash)
    };

    let default_perms = vec![
        // Default access to all public assets.
        PermCtx {
            perm: Perm::PublicAsset,
            lifetime: PermLifetime::Default,
        },
        // Default access to the asset-app for cases where the app is a single
        // asset rather than a folder.
        PermCtx {
            perm: Perm::AssetName {
                name: service_name.to_string(),
                perm: {
                    AssetPerm {
                        read: true,
                        write: true,
                    }
                },
            },
            lifetime: PermLifetime::Default,
        },
        // Default access to the asset-app's folder. NOTE: The asset-app may be
        // in a location without write access. The gateway allows the write
        // attempt which the API may reject.
        PermCtx {
            perm: Perm::AssetPrefix {
                prefix: format!("{}{}", service_name, maybe_slash),
                perm: AssetPerm {
                    read: true,
                    write: true,
                },
                prefix_perm: AssetPrefixPerm {
                    create: true,
                    list: true,
                },
            },
            lifetime: PermLifetime::Default,
        },
        // Default r/w access to an app folder in private assets so that all
        // apps have a baseline place to store configs.
        PermCtx {
            perm: Perm::AssetPrefix {
                prefix: app_folder_prefix,
                perm: AssetPerm {
                    read: true,
                    write: true,
                },
                prefix_perm: AssetPrefixPerm {
                    create: true,
                    list: true,
                },
            },
            lifetime: PermLifetime::Default,
        },
    ];

    let perms_nolock = if let Some(username) = username {
        let mut loaded_perms =
            crate::db::load_gateway_perms(&*db.lock().await, username, service_name)
                .into_iter()
                .map(|perm| PermCtx {
                    perm,
                    lifetime: PermLifetime::UntilRevoked,
                })
                .collect::<Vec<_>>();
        for default_perm in default_perms {
            if loaded_perms
                .iter()
                .filter(|p| p.perm == default_perm.perm)
                .count()
                == 0
            {
                loaded_perms.push(default_perm.clone());
            }
        }
        loaded_perms
    } else {
        default_perms
    };
    let perm_ctxs: PermCtxs = Arc::new(Mutex::new(perms_nolock));

    let cancel_token = CancellationToken::new();

    let perm_request_map: PermRequestMap = Arc::new(Mutex::new(HashMap::new()));
    let asset_app_open_tokens: AssetAppOpenTokenMap = Arc::new(Mutex::new(HashMap::new()));
    let username_owned = username.map(|s| s.to_string());
    let config_path_override_owned = config_path_override.map(|s| s.to_string());

    // Primary gateway: serves the asset-app.
    spawn_accept_loop(
        listener,
        cancel_token.child_token(),
        ListenerCtx {
            io: io.clone(),
            config_path_override: config_path_override_owned.clone(),
            db: db.clone(),
            local_addr,
            perm_gate_addr: perm_addr,
            token: token.clone(),
            asset_blob_cache: asset_blob_cache.clone(),
            asset_keyring: asset_keyring.clone(),
            api_client: api_client.clone(),
            clients: clients.clone(),
            perm_ctxs: perm_ctxs.clone(),
            perm_request_map: perm_request_map.clone(),
            kernel_map: Arc::new(Mutex::new(HashMap::new())),
            username: username_owned.clone(),
            service_name: service_name.to_string(),
            update_asset_tx: update_asset_tx.clone(),
            next_client_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            cookie_set: Arc::new(AtomicBool::new(false)),
            vite_proxy: Arc::new(vite_proxy),
            mode: Arc::new(GatewayMode::App),
            asset_app_open_tokens: asset_app_open_tokens.clone(),
        },
    );

    // The perm-gate: a second gateway on a separate origin (port) that serves
    // the perm-gate asset-app. It's distinct from the primary gateway in two
    // ways: 1. It has extra privileges to manage the asset-app's perms; 2. It
    // serves the `perm-gate` asset-app.
    spawn_accept_loop(
        perm_listener,
        cancel_token.child_token(),
        ListenerCtx {
            io: io.clone(),
            config_path_override: config_path_override_owned,
            db: db.clone(),
            local_addr: perm_addr,
            perm_gate_addr: perm_addr,
            token: generate_token(),
            asset_blob_cache: asset_blob_cache.clone(),
            asset_keyring: asset_keyring.clone(),
            api_client: api_client.clone(),
            clients: Arc::new(Mutex::new(HashMap::new())),
            perm_ctxs: Arc::new(Mutex::new(perm_gate_default_perms())),
            // The perm-gate cannot request perms for itself
            perm_request_map: Arc::new(Mutex::new(HashMap::new())),
            kernel_map: Arc::new(Mutex::new(HashMap::new())),
            username: username_owned,
            service_name: PERM_GATE_SERVICE_NAME.to_string(),
            update_asset_tx: update_asset_tx.clone(),
            next_client_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            cookie_set: Arc::new(AtomicBool::new(false)),
            vite_proxy: Arc::new(None),
            mode: Arc::new(GatewayMode::PermGate(PermGateCtx {
                repl_remote,
                target_service_name: service_name.to_string(),
                target_perm_ctxs: perm_ctxs.clone(),
                target_perm_request_map: perm_request_map.clone(),
                target_clients: clients.clone(),
                source: perm_gate_source,
            })),
            asset_app_open_tokens: asset_app_open_tokens.clone(),
        },
    );

    Ok((local_addr, perm_addr, clients, cancel_token, token))
}

#[derive(Clone)]
struct ListenerCtx {
    io: Io,
    config_path_override: Option<String>,
    db: Arc<Mutex<rusqlite::Connection>>,
    local_addr: SocketAddr,
    perm_gate_addr: SocketAddr,
    token: String,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    clients: Clients,
    perm_ctxs: PermCtxs,
    perm_request_map: PermRequestMap,
    kernel_map: KernelMap,
    username: Option<String>,
    service_name: String,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    cookie_set: Arc<AtomicBool>,
    vite_proxy: Arc<Option<ViteProxy>>,
    mode: Arc<GatewayMode>,
    asset_app_open_tokens: AssetAppOpenTokenMap,
}

fn spawn_accept_loop(listener: TcpListener, cancel: CancellationToken, ctx: ListenerCtx) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    ctx.clients.lock().await.clear();
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            errorln!(ctx.io, "Accept error: {:?}", e);
                            continue;
                        }
                    };
                    // All connections are going through loopback so it's
                    // likely unnecessary to disable Nagle's alg (buffering
                    // when TCP ack is delayed), but do it anyway.
                    let _ = stream.set_nodelay(true);
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            &ctx.io,
                            ctx.config_path_override.as_deref(),
                            ctx.db.clone(),
                            stream,
                            ctx.local_addr,
                            ctx.perm_gate_addr,
                            &ctx.token,
                            ctx.asset_blob_cache.clone(),
                            ctx.asset_keyring.clone(),
                            ctx.api_client.clone(),
                            ctx.clients.clone(),
                            ctx.perm_ctxs.clone(),
                            ctx.perm_request_map.clone(),
                            ctx.kernel_map.clone(),
                            ctx.username.as_deref(),
                            &ctx.service_name,
                            ctx.update_asset_tx.clone(),
                            ctx.next_client_id.clone(),
                            ctx.cookie_set.clone(),
                            ctx.vite_proxy.clone(),
                            ctx.mode.clone(),
                            ctx.asset_app_open_tokens.clone(),
                        ).await {
                            errorln!(ctx.io, "Connection error from {}: {:?}", peer_addr, e);
                        }
                    });
                }
            }
        }
    });
}

// Handles both HTTP and WebSocket connections, dispatching to the appropriate
// handler based on the initial request.
async fn handle_connection(
    io: &Io,
    config_path_override: Option<&str>,
    db: Arc<Mutex<rusqlite::Connection>>,
    stream: tokio::net::TcpStream,
    local_addr: SocketAddr,
    perm_addr: SocketAddr,
    token: &str,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    clients: Clients,
    perm_ctxs: PermCtxs,
    perm_request_map: PermRequestMap,
    kernel_map: KernelMap,
    username: Option<&str>,
    service_name: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    cookie_set: Arc<AtomicBool>,
    vite_proxy: Arc<Option<ViteProxy>>,
    mode: Arc<GatewayMode>,
    asset_app_open_tokens: AssetAppOpenTokenMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek at the first bytes (do not consume) to read the HTTP request line
    // and headers without consuming them permanently
    let mut peek_buf = vec![0u8; 4096];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    let peek_str = String::from_utf8_lossy(&peek_buf[..n]);

    // Check if this is a WebSocket upgrade request. Crude method, verified
    // works with with wscat & chrome, but may need a proper parser eventually.
    let is_websocket = peek_str.contains("Upgrade: websocket")
        || peek_str.contains("Upgrade: Websocket")
        || peek_str.contains("upgrade: websocket");

    if is_websocket {
        // Check if this is a Vite HMR connection that should be proxied
        let is_vite_hmr = vite_proxy.is_some()
            && (peek_str.contains("Sec-WebSocket-Protocol: vite-hmr")
                || peek_str.contains("sec-websocket-protocol: vite-hmr"));
        if is_vite_hmr {
            return handle_vite_websocket_proxy(&io.out, stream, &vite_proxy).await;
        }
        // Handle as WebSocket
        handle_websocket_connection(
            io,
            config_path_override,
            db,
            stream,
            &local_addr,
            &perm_addr,
            token,
            api_client,
            asset_blob_cache,
            asset_keyring,
            clients,
            perm_ctxs,
            perm_request_map,
            kernel_map,
            username,
            service_name,
            update_asset_tx,
            next_client_id,
            cookie_set,
            &mode,
            &asset_app_open_tokens,
        )
        .await
    } else {
        // Handle as HTTP
        handle_http_connection(
            io,
            stream,
            &local_addr,
            token,
            api_client,
            asset_blob_cache,
            asset_keyring,
            perm_ctxs,
            username,
            service_name,
            update_asset_tx,
            cookie_set,
            vite_proxy,
            &mode,
            &asset_app_open_tokens,
        )
        .await
    }
}

async fn handle_vite_websocket_proxy(
    out: &Out,
    mut client_stream: tokio::net::TcpStream,
    vite_proxy: &Arc<Option<ViteProxy>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let vite_host = match vite_proxy.as_ref() {
        Some(proxy) => proxy.host.clone(),
        None => return Ok(()),
    };

    if out.is_terminal() {
        infoln!(
            out,
            "Proxying WebSocket connection to Vite dev server at {}",
            vite_host
        );
    }
    tracing::info!(
        "Proxying WebSocket connection to Vite dev server at {}",
        vite_host
    );

    // Connect to Vite dev server
    let mut vite_stream = tokio::net::TcpStream::connect(vite_host).await?;

    // Just pump bytes in both directions.
    // The upgrade request is still in client_stream's buffer (we peeked,
    // didn't consume), so it flows through to Vite naturally, and Vite's 101
    // response flows back.
    tokio::io::copy_bidirectional(&mut client_stream, &mut vite_stream).await?;

    Ok(())
}

async fn handle_websocket_connection(
    io: &Io,
    config_path_override: Option<&str>,
    db: Arc<Mutex<rusqlite::Connection>>,
    stream: tokio::net::TcpStream,
    local_addr: &SocketAddr,
    perm_addr: &SocketAddr,
    token: &str,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    clients: Clients,
    perm_ctxs: PermCtxs,
    perm_request_map: PermRequestMap,
    kernel_map: KernelMap,
    username: Option<&str>,
    service_name: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    cookie_set: Arc<AtomicBool>,
    mode: &GatewayMode,
    asset_app_open_tokens: &AssetAppOpenTokenMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cookie_name = auth_cookie_name(service_name, username, local_addr.port());

    let mut cookie_auth_valid = false;

    let callback = |req: &server::Request,
                    resp: server::Response|
     -> Result<server::Response, server::ErrorResponse> {
        let origin = req
            .headers()
            .get(http::header::ORIGIN)
            .and_then(|v| v.to_str().ok());
        match origin {
            Some(o) if is_allowed_origin(local_addr, o) => {
                // Allow connections from the same origin (localhost)
            }
            None => {
                // Make it easier for non-browser clients to connect
            }
            _ => {
                let mut err = server::ErrorResponse::new(Some("Forbidden origin".into()));
                *err.status_mut() = http::StatusCode::FORBIDDEN;
                return Err(err);
            }
        }

        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok());
        match host {
            Some(h) if is_allowed_host(local_addr, h) => {
                // Allow connections to the correct host
            }
            _ => {
                let mut err = server::ErrorResponse::new(Some("Forbidden host".into()));
                *err.status_mut() = http::StatusCode::FORBIDDEN;
                return Err(err);
            }
        }

        // Check valid cookie
        cookie_auth_valid = req
            .headers()
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(';'))
            .filter_map(|kv| kv.trim().split_once('='))
            .any(|(k, v)| k == cookie_name && v == token);

        Ok(resp)
    };

    let mut ws_stream = match accept_hdr_async(stream, callback).await {
        Ok(ws) => ws,
        Err(e) => {
            if io.is_terminal() {
                errorln!(io, "WebSocket handshake error: {:?}", e);
            }
            tracing::debug!("WebSocket handshake error: {:?}", e);
            return Ok(());
        }
    };

    let pre_authenticated =
        cookie_set.load(std::sync::atomic::Ordering::SeqCst) && cookie_auth_valid;

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
                if auth_msg.token != Some(token.to_string()) {
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
                            io,
                            config_path_override,
                            db.clone(),
                            perm_addr,
                            asset_blob_cache.clone(),
                            asset_keyring.clone(),
                            &api_client,
                            perm_ctxs.clone(),
                            perm_request_map.clone(),
                            kernel_map.clone(),
                            username.as_deref(),
                            update_asset_tx.clone(),
                            mode,
                            asset_app_open_tokens,
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

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMessageAuthRequest {
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ClientMessageAuthResponse {
    Ok { version: String },
    BadToken,
    BadRequest,
}

// --

async fn handle_http_connection(
    io: &Io,
    mut stream: tokio::net::TcpStream,
    local_addr: &std::net::SocketAddr,
    token: &str,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    perm_ctxs: PermCtxs,
    username: Option<&str>,
    service_name: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    cookie_set: Arc<AtomicBool>,
    vite_proxy: Arc<Option<ViteProxy>>,
    mode: &GatewayMode,
    asset_app_open_tokens: &AssetAppOpenTokenMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf_reader = BufReader::new(&mut stream);

    // Parse the HTTP request
    let request = match HttpRequest::parse(&mut buf_reader, "localhost").await {
        Some(req) => req,
        None => return Ok(()),
    };

    // Handle the HTTP request
    let response = handle_http_request(
        io,
        &request,
        &local_addr,
        &token,
        asset_blob_cache,
        asset_keyring,
        &api_client,
        perm_ctxs,
        username,
        service_name,
        update_asset_tx,
        cookie_set,
        vite_proxy,
        mode,
        asset_app_open_tokens,
    )
    .await;

    response.write_to(&mut stream).await?;

    Ok(())
}

// -- HTTP request handler --

async fn handle_http_request(
    io: &Io,
    request: &HttpRequest,
    local_addr: &SocketAddr,
    expected_token: &str,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perm_ctxs: PermCtxs,
    username: Option<&str>,
    service_name: &str,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    cookie_set: Arc<AtomicBool>,
    vite_proxy: Arc<Option<ViteProxy>>,
    mode: &GatewayMode,
    asset_app_open_tokens: &AssetAppOpenTokenMap,
) -> HttpResponse {
    // Check if origin is allowed for CORS
    let origin = request.header("Origin");

    let allowed_origin = origin.and_then(|o| {
        if is_allowed_origin(local_addr, o) {
            Some(o.to_string())
        } else {
            None
        }
    });

    // Handle OPTIONS preflight request
    if request.method.as_str() == "OPTIONS" {
        return build_cors_preflight_response(allowed_origin.as_deref());
    }

    if let Some(origin) = origin
        && !is_allowed_origin(local_addr, origin)
    {
        return HttpResponse::forbidden();
    }

    let host = request.header("Host");
    if let Some(host) = host
        && !is_allowed_host(local_addr, host)
    {
        return HttpResponse::forbidden();
    }

    // Perm-gate: `/open` is navigated to from other asset-apps, so it's
    // authorized by its own open-token rather than the gateway auth token.
    if let GatewayMode::PermGate(pg_ctx) = mode
        && request.path == "/open"
    {
        return with_perm_gate_security_headers(
            handle_perm_gate_open(request, pg_ctx, asset_app_open_tokens).await,
        );
    }

    // Check token from multiple sources: cookie, bearer token, query param
    let cookie_token = request.cookie(&auth_cookie_name(service_name, username, local_addr.port()));
    let bearer_token = request.bearer_token();
    let query_token = request.query_param("token");

    // Parse optional query params
    let rev_id: Option<String> = request.query_param("rev_id").map(|s| s.to_string());
    let conflict_policy: Option<String> = request
        .query_param("conflict_policy")
        .map(|s| s.to_string());
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
        let p = request.path.strip_prefix("/~/").unwrap_or(&request.path);
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
            // Vite proxy: no support for data-first format because @ is used
            // in some dependency names (e.g. @vite, @react-refresh)
            Some((_asset_name, asset_app_name)) if vite_proxy.is_none() => {
                asset_app_name.to_string()
            }
            Some(_) | None => {
                // Support entry_id and attachment look ups by ignoring any
                // path construct before the `:`. This is so that relative
                // paths in the browser using the `:` syntax can be used for
                // look ups.
                match decoded_path.find(':') {
                    Some(idx) => decoded_path[idx..].to_string(),
                    None => decoded_path.to_string(),
                }
            }
        },
        Err(_) => return HttpResponse::bad_request("Invalid URL encoding"),
    };

    let mut response = if let GatewayMode::PermGate(pg_ctx) = mode {
        with_perm_gate_security_headers(
            handle_perm_gate_http(
                io,
                request,
                pg_ctx,
                service_name,
                asset_blob_cache,
                asset_keyring,
                api_client,
                perm_ctxs,
                username,
            )
            .await,
        )
    } else {
        match request.method.as_str() {
            "GET" => {
                if is_push {
                    return HttpResponse::bad_request(
                        "push parameter is not valid for GET requests",
                    );
                }
                handle_get(
                    io,
                    &request,
                    service_name,
                    &asset_name,
                    rev_id.as_deref(),
                    metadata_ref,
                    asset_blob_cache,
                    asset_keyring,
                    api_client,
                    perm_ctxs,
                    username,
                    vite_proxy,
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
                        &io.out,
                        &asset_name,
                        &request.body,
                        asset_blob_cache,
                        asset_keyring,
                        api_client.clone(),
                        perm_ctxs,
                        username,
                    )
                    .await
                } else {
                    handle_put(
                        io,
                        &asset_name,
                        rev_id.as_deref(),
                        conflict_policy.as_deref(),
                        &request.body,
                        is_push,
                        asset_blob_cache,
                        asset_keyring,
                        api_client.clone(),
                        perm_ctxs,
                        username,
                        update_asset_tx,
                    )
                    .await
                }
            }
            _ => HttpResponse::bad_request("Only GET, PUT, and OPTIONS supported"),
        }
    };

    // Add CORS headers to actual response if origin is allowed
    if let Some(ref origin) = allowed_origin {
        response = response
            .with_header("Access-Control-Allow-Origin", origin)
            .with_header("Access-Control-Allow-Credentials", "true");
    }

    if should_set_cookie {
        response = response
            .with_cookie(HttpResponse::auth_cookie(
                username,
                service_name,
                local_addr,
                expected_token,
            ))
            .with_header("Clear-Site-Data", "\"storage\"");
    }

    response
}

/// Check if the origin is allowed for CORS
fn is_allowed_origin(local_addr: &SocketAddr, origin: &str) -> bool {
    origin == format!("http://localhost:{}", local_addr.port())
}

fn is_allowed_host(local_addr: &SocketAddr, host: &str) -> bool {
    host == format!("localhost:{}", local_addr.port())
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
    io: &Io,
    request: &HttpRequest,
    service_name: &str,
    asset_name: &str,
    rev_id: Option<&str>,
    return_metadata: bool,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perm_ctxs: PermCtxs,
    username: Option<&str>,
    vite_proxy: Arc<Option<ViteProxy>>,
) -> HttpResponse {
    // In dev-mode, proxy GET requests whose asset path matches the configured
    // prefix to the vite dev server rather than serving them from the asset
    // store.
    //
    // Additionally, always proxy vite's internal HMR / dev-client endpoints
    // (e.g. `/@vite/client`, `/@react-refresh`) regardless of the prefix,
    // since these are requested at fixed absolute paths by vite-injected
    // client code and won't share the app's asset prefix.
    if let Some(vite_proxy) = vite_proxy.as_ref() {
        if asset_name.starts_with(&vite_proxy.asset_prefix) {
            return proxy_get_to_vite_dev_server(&io.out, &vite_proxy.host, request).await;
        }
    }

    match asset_app_has_gateway_perm_for_asset_access_request(
        &api_client,
        asset_name,
        &perm_ctxs,
        false,
    )
    .await
    {
        Ok(has_perm) => {
            if !has_perm {
                return HttpResponse::forbidden();
            }
        }
        Err((_asset_name, e)) => {
            return asset_get_request_error_to_http_response(e);
        }
    }

    // IMPORTANT SECURITY DETAIL
    // Reject service workers because they can register a hook that lets them
    // persist beyond one asset-app and potentially exploit another asset-app
    // that re-uses the same gateway port.
    //
    // The service worker can even reject a `Clear-Site-Data: storage` header
    // from the gateway which means it can avoid its own removal.
    //
    // This approach was taken because web workers are still desirable and
    // should not be affected by this.
    if request.header("Service-Worker") == Some("script") {
        return HttpResponse::forbidden();
    }

    let is_attachment = crate::asset_helper::is_attachment(asset_name);
    let default_filenames = &["index", "index.html", "README", "README.md"];

    let (data_contents, md_contents, asset_revision, resolved_name) = {
        let is_directory_request = asset_name.is_empty() || asset_name.ends_with('/');

        if is_directory_request && !is_attachment {
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
            .and_then(|(data, md, rev)| {
                if matches!(rev.asset.kind, crate::api::types::asset::AssetKind::Folder)
                    && !return_metadata
                {
                    Err(GetRevisionError::BadEntryRef)
                } else {
                    Ok((data, md, rev))
                }
            }) {
                Ok((data, md, rev)) => (data, md, rev, asset_name.to_string()),
                Err(
                    GetRevisionError::BadEntryRef
                    | GetRevisionError::BadRevId
                    | GetRevisionError::Deleted,
                ) if rev_id.is_none() && !is_attachment => {
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
                Err(GetRevisionError::NoPermission) => return HttpResponse::forbidden(),
                Err(GetRevisionError::Deleted) => return HttpResponse::not_found(),
                Err(GetRevisionError::DataFetchFailed(DataFetchFailure::Unexpected)) => {
                    return HttpResponse::internal_error("Unexpected data fetch failure.");
                }
                Err(GetRevisionError::DataFetchFailed(DataFetchFailure::Retryable)) => {
                    return HttpResponse::internal_error(
                        "Temporary data fetch failure, please retry again.",
                    );
                }
                Err(GetRevisionError::DataFetchFailed(DataFetchFailure::RateLimited)) => {
                    return HttpResponse::too_many_requests();
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
    } else if let Some(data_contents) = data_contents {
        match asset_crypt::maybe_decrypt_asset_contents(
            io,
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
                tracing::error!("error: failed to decrypt: {}", e);
                return HttpResponse::internal_error("Failed to decrypt asset");
            }
        }
    } else {
        return HttpResponse::no_content();
    };

    let resp = HttpResponse::ok(decrypted_contents, &content_type);

    // IMPORTANT SECURITY NOTE
    // A worrisome attack vector is the user clicking on a link to another app.
    // If that potentially malicious app is served by the same gateway (link
    // was provided as a relative link) and assuming cookie authentication, a
    // malicious app would be able to utilize all of the granted permissions.
    // This is extremely bad.
    //
    // To prevent this, all content served that's unrelated to the asset-app
    // (does not share the asset prefix) that the gateway was created for, has
    // `sandbox` set so that scripts cannot be run. As added protection, we
    // default disposition to attachment and tell the browser to not guess the
    // content type.
    let app_prefix = service_name.trim_end_matches('/');
    let is_app_asset = asset_name == app_prefix
        || asset_name
            .strip_prefix(app_prefix)
            .is_some_and(|rest| rest.starts_with('/'));
    if is_app_asset {
        resp
    } else {
        let resp = resp
            .with_header("Content-Security-Policy", "sandbox")
            .with_header("X-Content-Type-Options", "nosniff");
        if is_inline_safe(&content_type) {
            resp
        } else {
            resp.with_header("Content-Disposition", "attachment")
        }
    }
}

fn is_inline_safe(content_type: &str) -> bool {
    let base = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    matches!(
        base.as_str(),
        "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/avif"
            | "image/bmp"
            | "video/mp4"
            | "video/webm"
            | "video/ogg"
            | "audio/mpeg"
            | "audio/ogg"
            | "audio/wav"
            | "audio/webm"
            | "audio/flac"
            | "audio/aac"
            | "audio/mp4"
    )
}

/// Proxies an internal `asset/get` response back to the app request that
/// made the overarching request.
fn asset_get_request_error_to_http_response(
    req_err: RequestError<asset::AssetGetError>,
) -> HttpResponse {
    match req_err {
        RequestError::Route(get_err) => match get_err {
            asset::AssetGetError::BadName => HttpResponse::not_found(),
            asset::AssetGetError::NoPermission => HttpResponse::forbidden(),
            _ => HttpResponse::internal_error(&format!("{}", get_err)),
        },
        // An internal bad-request isn't the fault of the app request so report
        // it as an internal error.
        RequestError::BadRequest(bad_req) => HttpResponse::internal_error(&bad_req),
        RequestError::RateLimit(_body) => HttpResponse::too_many_requests(),
        RequestError::Http(http_err) => HttpResponse::internal_error(&format!("{}", http_err)),
        RequestError::Unexpected(err) => HttpResponse::internal_error(&err),
    }
}

// --

/// Proxies a GET request to the vite dev server (dev-mode only).
///
/// The full request path (including query string) is forwarded to
/// `http://<vite_host><path>?<query>`. The response body, status, and
/// content-type are relayed back to the caller.
async fn proxy_get_to_vite_dev_server(
    out: &Out,
    vite_host: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let query = request
        .query_string()
        .map(|qs| format!("?{}", qs))
        .unwrap_or_default();
    let url = format!("http://{}{}{}", vite_host, request.path, query);

    let client = reqwest::Client::new();
    let mut req = client.get(&url);

    // Forward a few relevant headers so vite/HMR behaves as expected.
    for header_name in ["accept", "accept-encoding", "user-agent", "if-none-match"] {
        if let Some(value) = request.header(header_name) {
            req = req.header(header_name, value);
        }
    }

    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            if out.is_terminal() {
                errorln!(out, "dev-mode proxy request failed: {}", e);
            }
            tracing::debug!("dev-mode proxy request failed: {}", e);
            return HttpResponse::internal_error("Dev-mode proxy request failed");
        }
    };

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let body = match resp.bytes().await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            if out.is_terminal() {
                errorln!(out, "failed to read dev-mode proxy response: {}", e);
            }
            tracing::debug!("failed to read dev-mode proxy response: {}", e);
            return HttpResponse::internal_error("Failed to read dev-mode proxy response");
        }
    };

    HttpResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("OK"),
        content_type,
        body,
        set_cookie: None,
        additional_headers: Vec::new(),
    }
}

async fn handle_put(
    io: &Io,
    asset_name: &str,
    rev_id: Option<&str>,
    conflict_policy: Option<&str>,
    body: &[u8],
    is_push: bool,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    perm_ctxs: PermCtxs,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
) -> HttpResponse {
    let asset_entry_ref = if let Some(rev_id) = rev_id {
        if !asset_helper::is_entry_id(asset_name) {
            // If replacing asset only if rev_id matches, require reference by
            // entry_id. The multi-colon check is to ensure it's not an attachment.
            return HttpResponse::bad_request(
                "If `rev_id` set, `asset_name` must be an `entry_id`.",
            );
        } else {
            // API doesn't use `:` notation for `entry_id` fields
            Some((asset_name[1..].to_string(), rev_id.to_string()))
        }
    } else {
        None
    };
    let (put_conflict_policy, replace_conflict_policy) = if let Some(conflict_policy) =
        conflict_policy
    {
        if rev_id.is_some() {
            match conflict_policy {
                "reject" => (None, Some(asset::ReplaceConflictPolicy::Reject)),
                "fork" => (None, Some(asset::ReplaceConflictPolicy::Fork)),
                _ => {
                    return HttpResponse::bad_request(
                        "If `rev_id` set, `conflict_policy` must be `reject` or `fork`.",
                    );
                }
            }
        } else {
            match conflict_policy {
                "override" => (Some(asset::PutConflictPolicy::Override), None),
                "reject" => (Some(asset::PutConflictPolicy::Reject), None),
                _ => {
                    return HttpResponse::bad_request(
                        "If `rev_id` is not set, `conflict_policy` must be `override` or `reject`.",
                    );
                }
            }
        }
    } else {
        (
            Some(asset::PutConflictPolicy::Override),
            Some(asset::ReplaceConflictPolicy::Reject),
        )
    };

    match asset_app_has_gateway_perm_for_asset_access_request(
        &api_client,
        asset_name,
        &perm_ctxs,
        true,
    )
    .await
    {
        Ok(has_perm) => {
            if !has_perm {
                return HttpResponse::forbidden();
            }
        }
        Err((_asset_name, e)) => {
            return asset_get_request_error_to_http_response(e);
        }
    }

    // Choose encryption key material for this asset
    let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
        io,
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
                    if io.is_terminal() {
                        errorln!(io, "{}", msg);
                    }
                    tracing::debug!("{}", msg);
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
                asset_entry_ref,
                new_contents: body.to_vec(),
                is_push,
                put_conflict_policy,
                replace_conflict_policy,
                api_client: api_client.clone(),
                one_shot: true,
                akm_info,
                reply_channel: Some(reply_tx),
            },
        ))
        .await
    {
        if io.is_terminal() {
            errorln!(io, "failed to send to update worker: {}", e);
        }
        tracing::debug!("failed to send to update worker: {}", e);
        return HttpResponse::internal_error("Failed to process update");
    }

    // Wait for the response
    match reply_rx.await {
        Ok(Ok(new_entry)) => match serde_json::to_vec(&serde_json::json!({ "entry": new_entry })) {
            Ok(json_bytes) => HttpResponse::ok(json_bytes, "application/json"),
            Err(_) => HttpResponse::internal_error("Failed to serialize response"),
        },
        Ok(Err(e)) => {
            if io.is_terminal() {
                errorln!(io, "failed to update asset: {:?}", e);
            }
            tracing::debug!("failed to update asset: {:?}", e);
            match e {
                asset_async_writer::AssetSaveError::Put(RequestError::BadRequest(msg))
                | asset_async_writer::AssetSaveError::Replace(RequestError::BadRequest(msg))
                | asset_async_writer::AssetSaveError::Push(RequestError::BadRequest(msg)) => {
                    return HttpResponse::bad_request(&format!("Unexpected error: {}", msg));
                }
                asset_async_writer::AssetSaveError::Put(RequestError::RateLimit(_msg))
                | asset_async_writer::AssetSaveError::Replace(RequestError::RateLimit(_msg))
                | asset_async_writer::AssetSaveError::Push(RequestError::RateLimit(_msg)) => {
                    return HttpResponse::too_many_requests();
                }
                asset_async_writer::AssetSaveError::Put(RequestError::Http(http_err))
                | asset_async_writer::AssetSaveError::Replace(RequestError::Http(http_err))
                | asset_async_writer::AssetSaveError::Push(RequestError::Http(http_err)) => {
                    if http_err.status() == Some(reqwest::StatusCode::PAYLOAD_TOO_LARGE) {
                        return HttpResponse::payload_too_large(&http_err.to_string());
                    } else {
                        return HttpResponse::internal_error(&format!("HTTP error: {}", http_err));
                    }
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
    out: &Out,
    asset_name: &str,
    body: &[u8],
    _asset_blob_cache: Arc<AssetBlobCache>,
    _asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    perm_ctxs: PermCtxs,
    _username: Option<&str>,
) -> HttpResponse {
    match asset_app_has_gateway_perm_for_asset_access_request(
        &api_client,
        asset_name,
        &perm_ctxs,
        true,
    )
    .await
    {
        Ok(has_perm) => {
            if !has_perm {
                return HttpResponse::forbidden();
            }
        }
        Err((_asset_name, e)) => {
            return asset_get_request_error_to_http_response(e);
        }
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
            if out.is_terminal() {
                errorln!(out, "metadata put failed: {}", e);
            }
            tracing::debug!("metadata put failed: {}", e);
            match e {
                RequestError::BadRequest(msg) => {
                    return HttpResponse::bad_request(&format!("Unexpected error: {}", msg));
                }
                RequestError::RateLimit(_) => {
                    return HttpResponse::too_many_requests();
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

/// Checks permission to access an asset across multiple dimensions.
///
/// 1. entry_id
/// 2. asset_name
/// 3. resolving attachment to asset_name / entry_id
///
/// # Returns
///
/// True if user has the necessary permission.
pub async fn asset_app_has_gateway_perm_for_asset_access_request(
    api_client: &HaiClient,
    asset_name: &str,
    perm_ctxs: &PermCtxs,
    write: bool,
) -> Result<bool, (String, RequestError<asset::AssetGetError>)> {
    // Quick exit: Try to check access by the `asset_name` given to see if we
    // can avoid any extra queries.
    if asset_helper::is_entry_id(asset_name) {
        let access_req = if write {
            AccessRequest::WriteByEntryId {
                entry_id: asset_name,
            }
        } else {
            AccessRequest::ReadByEntryId {
                entry_id: asset_name,
            }
        };
        if check_access_async(&perm_ctxs, &access_req).await.is_ok() {
            return Ok(true);
        }
    } else {
        let access_req = if write {
            AccessRequest::WriteByName { name: asset_name }
        } else {
            AccessRequest::ReadByName { name: asset_name }
        };
        if check_access_async(&perm_ctxs, &access_req).await.is_ok() {
            return Ok(true);
        }
    }

    // If the quick exit didn't work, we need to resolve the full perm-granting
    // entry (attachment anchor, if applicable) and try both the name and
    // entry_id. NOTE: Could be optimized to use fewer queries on average.
    let perm_granting_asset_entry =
        asset_helper::resolve_perm_granting_asset_entry(api_client, asset_name).await?;
    let access_req_by_name = if write {
        AccessRequest::WriteByName {
            name: &perm_granting_asset_entry.name,
        }
    } else {
        AccessRequest::ReadByName {
            name: &perm_granting_asset_entry.name,
        }
    };
    if check_access_async(&perm_ctxs, &access_req_by_name)
        .await
        .is_ok()
    {
        return Ok(true);
    }
    let access_req_by_entry_id = if write {
        AccessRequest::WriteByEntryId {
            entry_id: &perm_granting_asset_entry.entry_id,
        }
    } else {
        AccessRequest::ReadByEntryId {
            entry_id: &perm_granting_asset_entry.entry_id,
        }
    };
    if check_access_async(&perm_ctxs, &access_req_by_entry_id)
        .await
        .is_ok()
    {
        return Ok(true);
    }
    Ok(false)
}

/// Checks permission to list a prefix across multiple dimensions.
///
/// 1. List prefix access is superset of asset_prefix.
/// 2. Read access to perm-granting asset (attachment anchor).
///
/// # Returns
///
/// True if user has the necessary permission.
pub async fn asset_app_has_gateway_perm_for_asset_list_prefix_request(
    api_client: &HaiClient,
    asset_prefix: &str,
    perm_ctxs: &PermCtxs,
) -> Result<bool, (String, RequestError<asset::AssetGetError>)> {
    // Quick exit: Try to check access by the `asset_prefix` given to see if we
    // can avoid any extra queries.
    let access_req = AccessRequest::ListPrefix {
        prefix: asset_prefix,
    };
    if check_access_async(&perm_ctxs, &access_req).await.is_ok() {
        return Ok(true);
    }

    if asset_helper::is_attachment(asset_prefix) {
        // If it's an attachment, get the perm-granting asset and check if we
        // have read permissions to it.
        let perm_granting_asset_entry =
            asset_helper::resolve_perm_granting_asset_entry(api_client, asset_prefix).await?;
        let access_req_by_name = AccessRequest::ReadByName {
            name: &perm_granting_asset_entry.name,
        };
        if check_access_async(&perm_ctxs, &access_req_by_name)
            .await
            .is_ok()
        {
            return Ok(true);
        }
        let access_req_by_entry_id = AccessRequest::ReadByEntryId {
            entry_id: &perm_granting_asset_entry.entry_id,
        };
        if check_access_async(&perm_ctxs, &access_req_by_entry_id)
            .await
            .is_ok()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplKernelSpawnArg {
    tags: Option<Vec<String>>,
    model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplKernelSpawnResult {
    kernel_id: String,
    port: u16,
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplKernelSpawnError {
    SpawnFailed { message: String },
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplKernelTeardownArg {
    kernel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplKernelTeardownResult {
    /// True if a kernel with that ID existed and was killed. Otherwise, false.
    ok: bool,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplKernelListResult {
    kernels: Vec<KernelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KernelInfo {
    kernel_id: String,
    tags: Vec<String>,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplStarredResult {
    starred: Vec<StarredItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum StarredItem {
    Task { task: String, shortcut: String },
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplShareArg {
    asset_name: String,
    recipient: String,
    write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplShareError {
    BadName,
    KeyNotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplUnshareArg {
    asset_name: String,
    recipient: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplUnshareError {
    BadName,
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

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplPermRequestArg {
    perms: Vec<Perm>,
    #[serde(default)]
    choosers: Vec<Chooser>,
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
pub struct ReplOpenWithArg {
    asset_app: String,
    asset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplOpenWithResult {
    url: String,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchOgTagsArg {
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchOgTagsResult {
    tags: Vec<opengraph::OgTag>,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplCryptSignArg {
    message: String, // b64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplCryptSignResult {
    signer_key_id: String, // u:<username>:<key_id>
    signature: String,     // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplCryptSignError {
    BadMessage,
    BadKey,
    KeyLocked,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplCryptVerifyArg {
    message: String,       // b64
    signer_key_id: String, // u:<username>:<key_id>
    signature: String,     // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplCryptVerifyResult {
    is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum ReplCryptVerifyError {
    BadMessage,
    BadKey,
    BadSignature,
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
    GatewayError {
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
        RequestError::RateLimit(msg) => ClientMessageResponse::GatewayError {
            mid: mid,
            error: msg,
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

async fn send_bad_gateway_error(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    mid: u64,
    error: &str,
) {
    let resp_err = ClientMessageResponse::<(), String>::GatewayError {
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
    io: &Io,
    config_path_override: Option<&str>,
    db: Arc<Mutex<rusqlite::Connection>>,
    perm_addr: &SocketAddr,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perm_ctxs: PermCtxs,
    perm_request_map: PermRequestMap,
    kernel_map: KernelMap,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    mode: &GatewayMode,
    asset_app_open_tokens: &AssetAppOpenTokenMap,
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

    if route.starts_with("perm_gate/") {
        match mode {
            GatewayMode::PermGate(pg) => {
                handle_perm_gate_message(
                    db,
                    asset_blob_cache,
                    asset_keyring,
                    api_client,
                    username,
                    pg,
                    ws_sink,
                    mid,
                    &route,
                    &arg,
                )
                .await;
            }
            GatewayMode::App => {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
            }
        }
        return;
    }

    match route.as_str() {
        "repl/kernel/spawn" => {
            if let Err(PermCheckError::Unauthorized) =
                check_access_async(&perm_ctxs, &AccessRequest::Everything).await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let spawn_arg: ReplKernelSpawnArg = match serde_json::from_str(&arg.to_string()) {
                Ok(a) => a,
                Err(_) => {
                    send_bad_request_error(ws_sink, &format!("Invalid argument for {route}")).await;
                    return;
                }
            };

            let (exe, mut args, using_cargo) = crate::feature::self_invocation();
            if let Some(model) = spawn_arg.model {
                args.push("-m".into());
                args.push(model);
            }
            args.push("--kernel".into());

            let mut child = match tokio::process::Command::new(&exe)
                .args(&args)
                .stdin(std::process::Stdio::null())
                // Stdout must be piped to read kernel's ready message
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true) // For clean up on exit
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    send_response::<ReplKernelSpawnResult, ReplKernelSpawnError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplKernelSpawnError::SpawnFailed {
                            message: e.to_string(),
                        })),
                        false,
                    )
                    .await;
                    return;
                }
            };

            // Give more leeway for cargo since the binary might need to be
            // re-built.
            let timeout = if using_cargo {
                std::time::Duration::from_secs(30)
            } else {
                std::time::Duration::from_secs(10)
            };

            // Waiting for kernel is necessary to ensure it's ready to accept a
            // connection, and also to get the port it's bound to and token for
            // authentication.
            match kernel::wait_for_kernel_ready(&mut child, timeout).await {
                Ok(ready) => {
                    let kernel_id = generate_kernel_id();
                    kernel_map.lock().await.insert(
                        kernel_id.clone(),
                        KernelHandle {
                            child,
                            port: ready.port,
                            token: ready.token.clone(),
                            created_at: std::time::Instant::now(),
                            tags: spawn_arg.tags.unwrap_or_default(),
                        },
                    );
                    let result = ReplKernelSpawnResult {
                        kernel_id,
                        port: ready.port,
                        token: ready.token.clone(),
                    };
                    send_response::<ReplKernelSpawnResult, ReplKernelSpawnError>(
                        ws_sink,
                        mid,
                        Ok(result),
                        false,
                    )
                    .await;
                }
                Err(e) => {
                    // Something went wrong. Fully kill the child process in
                    // case it's still alive.
                    let _ = child.kill().await; // SIGKILL
                    let _ = child.wait().await; // Zombie reaper
                    send_response::<ReplKernelSpawnResult, ReplKernelSpawnError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplKernelSpawnError::SpawnFailed {
                            message: e,
                        })),
                        false,
                    )
                    .await;
                    return;
                }
            }
        }
        "repl/kernel/teardown" => {
            if let Err(PermCheckError::Unauthorized) =
                check_access_async(&perm_ctxs, &AccessRequest::Everything).await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let arg: ReplKernelTeardownArg = match serde_json::from_str(&arg.to_string()) {
                Ok(a) => a,
                Err(_) => {
                    send_bad_request_error(ws_sink, "Invalid argument").await;
                    return;
                }
            };
            let handle = kernel_map.lock().await.remove(&arg.kernel_id);
            match handle {
                Some(mut h) => {
                    let _ = h.child.kill().await; // SIGKILL
                    let _ = h.child.wait().await; // Zombie reaper
                    send_response::<ReplKernelTeardownResult, ()>(
                        ws_sink,
                        mid,
                        Ok(ReplKernelTeardownResult { ok: true }),
                        false,
                    )
                    .await;
                }
                None => {
                    send_response::<ReplKernelTeardownResult, ()>(
                        ws_sink,
                        mid,
                        Ok(ReplKernelTeardownResult { ok: false }),
                        false,
                    )
                    .await;
                }
            }
        }
        "repl/kernel/list" => {
            if let Err(PermCheckError::Unauthorized) =
                check_access_async(&perm_ctxs, &AccessRequest::Everything).await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            let kernels = kernel_map
                .lock()
                .await
                .iter()
                .map(|(kernel_id, handle)| KernelInfo {
                    kernel_id: kernel_id.clone(),
                    tags: handle.tags.clone(),
                })
                .collect();
            send_response::<ReplKernelListResult, ()>(
                ws_sink,
                mid,
                Ok(ReplKernelListResult { kernels }),
                false,
            )
            .await;
        }
        "repl/starred" => {
            let starred = match crate::feature::config_sync::get_merged_config(
                config_path_override,
                db.clone(),
                username,
            )
            .await
            {
                Ok(cfg) => cfg
                    .starred_task
                    .iter()
                    .map(|starred_task| StarredItem::Task {
                        task: starred_task.task.clone(),
                        shortcut: starred_task.shortcut.clone(),
                    })
                    .collect(),
                Err(e) => {
                    if io.is_terminal() {
                        errorln!(io, "failed to read config: {}", e);
                    }
                    tracing::debug!("failed to read config: {}", e);
                    vec![]
                }
            };
            send_response::<ReplStarredResult, ()>(
                ws_sink,
                mid,
                Ok(ReplStarredResult { starred }),
                false,
            )
            .await;
        }
        "repl/share" => {
            let Some(username) = username else {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            };

            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let share_arg: ReplShareArg = match serde_json::from_str(&arg.to_string()) {
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

            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &share_arg.asset_name,
                &perm_ctxs,
                true,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
            }

            let mut grant_tasks = vec![share_arg.asset_name.clone()];

            while let Some(asset_name) = grant_tasks.pop() {
                let (md_contents, asset_entry) = match asset_reader::get_only_asset_metadata(
                    asset_blob_cache.clone(),
                    &api_client,
                    &asset_name,
                    false,
                )
                .await
                {
                    Ok(res) => res,
                    Err(asset_reader::GetAssetError::BadName) => {
                        send_error_response(
                            ws_sink,
                            mid,
                            RequestError::Route(ReplShareError::BadName),
                        )
                        .await;
                        return;
                    }
                    Err(e) => {
                        send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                        return;
                    }
                };
                if let Some(md_contents) = md_contents.as_ref() {
                    match asset_crypt::akm_grant(
                        &io,
                        asset_blob_cache.clone(),
                        asset_keyring.clone(),
                        &api_client,
                        &username,
                        &KeyRecipient::User(share_arg.recipient.clone()),
                        &md_contents,
                    )
                    .await
                    {
                        Ok(Some(updated_md)) => {
                            use crate::api::types::asset::{
                                AssetMetadataPutArg, PutConflictPolicy,
                            };
                            match api_client
                                .asset_metadata_put(AssetMetadataPutArg {
                                    name: asset_name.to_string(),
                                    data: updated_md,
                                    conflict_policy: PutConflictPolicy::Override,
                                })
                                .await
                            {
                                Ok(_put_res) => {}
                                Err(e) => {
                                    send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                                    return;
                                }
                            };
                        }
                        Ok(None) => {
                            // No update needed
                        }
                        Err(asset_crypt::AkmGrantError::KeyNotFound) => {
                            send_error_response(
                                ws_sink,
                                mid,
                                RequestError::Route(ReplShareError::KeyNotFound),
                            )
                            .await;
                            return;
                        }
                        Err(asset_crypt::AkmGrantError::FetchFailed) => {
                            send_bad_gateway_error(ws_sink, mid, "Failed to grant asset key").await;
                            return;
                        }
                        Err(asset_crypt::AkmGrantError::MetadataUpdateFailed) => {
                            send_bad_gateway_error(ws_sink, mid, "Metadata failed to update").await;
                            return;
                        }
                    };
                }
                let asset_entry_anchor_id = format!(":{}:", asset_entry.entry_id);
                match asset_helper::list_all_asset_entries(&api_client, &asset_entry_anchor_id)
                    .await
                {
                    Ok(entries) => {
                        for entry in entries {
                            grant_tasks.push(entry.name.clone());
                        }
                    }
                    Err(_) => {
                        send_bad_gateway_error(
                            ws_sink,
                            mid,
                            "Failed to list attachments, share is incomplete",
                        )
                        .await;
                        return;
                    }
                }
            }
            use crate::api::types::asset::{
                AceEffectSet, AssetAcePrincipal, AssetEntryAclSetArg, EntryRef,
            };
            match api_client
                .asset_entry_acl_set(AssetEntryAclSetArg {
                    entry_ref: EntryRef::Name(share_arg.asset_name.to_owned()),
                    principal: AssetAcePrincipal::User(share_arg.recipient.clone()),
                    read_data: Some(AceEffectSet::Allow),
                    read_revisions: Some(AceEffectSet::Allow),
                    write_data: if share_arg.write {
                        Some(AceEffectSet::Allow)
                    } else {
                        None
                    },
                    push_data: if share_arg.write {
                        Some(AceEffectSet::Allow)
                    } else {
                        None
                    },
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                    return;
                }
            }
            send_response::<(), ReplShareError>(ws_sink, mid, Ok(()), false).await;
        }
        "repl/unshare" => {
            let Some(username) = username else {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            };

            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let unshare_arg: ReplUnshareArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(e) => {
                    send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                    return;
                }
            };

            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &unshare_arg.asset_name,
                &perm_ctxs,
                true,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
            }

            let mut revoke_tasks = vec![unshare_arg.asset_name.clone()];

            while let Some(asset_name) = revoke_tasks.pop() {
                let (md_contents, asset_entry) = match asset_reader::get_only_asset_metadata(
                    asset_blob_cache.clone(),
                    &api_client,
                    &asset_name,
                    false,
                )
                .await
                {
                    Ok(res) => res,
                    Err(asset_reader::GetAssetError::BadName) => {
                        send_error_response(
                            ws_sink,
                            mid,
                            RequestError::Route(ReplUnshareError::BadName),
                        )
                        .await;
                        return;
                    }
                    Err(e) => {
                        send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                        return;
                    }
                };
                if let Some(md_contents) = md_contents.as_ref() {
                    match asset_crypt::akm_revoke(
                        &io,
                        asset_blob_cache.clone(),
                        asset_keyring.clone(),
                        &api_client,
                        &username,
                        &KeyRecipient::User(unshare_arg.recipient.clone()),
                        &md_contents,
                    )
                    .await
                    {
                        Ok(Some(updated_md)) => {
                            use crate::api::types::asset::{
                                AssetMetadataPutArg, PutConflictPolicy,
                            };
                            match api_client
                                .asset_metadata_put(AssetMetadataPutArg {
                                    name: asset_name.to_string(),
                                    data: updated_md,
                                    conflict_policy: PutConflictPolicy::Override,
                                })
                                .await
                            {
                                Ok(_put_res) => {}
                                Err(e) => {
                                    send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                                    return;
                                }
                            };
                        }
                        Ok(None) => {
                            // No update needed
                        }
                        Err(asset_crypt::AkmRevokeError::FetchFailed) => {
                            send_bad_gateway_error(ws_sink, mid, "Failed to revoke asset key")
                                .await;
                            return;
                        }
                        Err(asset_crypt::AkmRevokeError::MetadataUpdateFailed) => {
                            send_bad_gateway_error(ws_sink, mid, "Metadata failed to update").await;
                            return;
                        }
                    };
                }
                let asset_entry_anchor_id = format!(":{}:", asset_entry.entry_id);
                match asset_helper::list_all_asset_entries(&api_client, &asset_entry_anchor_id)
                    .await
                {
                    Ok(entries) => {
                        for entry in entries {
                            revoke_tasks.push(entry.name.clone());
                        }
                    }
                    Err(_) => {
                        send_bad_gateway_error(
                            ws_sink,
                            mid,
                            "Failed to list attachments, share is incomplete",
                        )
                        .await;
                        return;
                    }
                }
            }
            use crate::api::types::asset::{
                AceEffectSet, AssetAcePrincipal, AssetEntryAclSetArg, EntryRef,
            };
            match api_client
                .asset_entry_acl_set(AssetEntryAclSetArg {
                    entry_ref: EntryRef::Name(unshare_arg.asset_name.to_owned()),
                    principal: AssetAcePrincipal::User(unshare_arg.recipient.clone()),
                    read_data: Some(AceEffectSet::Inherit),
                    read_revisions: Some(AceEffectSet::Inherit),
                    write_data: Some(AceEffectSet::Inherit),
                    push_data: Some(AceEffectSet::Inherit),
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    send_bad_gateway_error(ws_sink, mid, &e.to_string()).await;
                    return;
                }
            }
            send_response::<(), ReplShareError>(ws_sink, mid, Ok(()), false).await;
        }
        "repl/prompt" => {
            if let Err(PermCheckError::Unauthorized) =
                check_access_async(&perm_ctxs, &AccessRequest::LlmPrompt).await
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

            let (exe, mut args, _using_cargo) = crate::feature::self_invocation();
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
            let perm_ctxs_guard = perm_ctxs.lock().await;

            // Check if any existing permissions require keyring access.
            let perm_requires_keyring: bool = perm_ctxs_guard
                .iter()
                .any(|perm| perm.perm.requires_keyring());

            let keyring_need_unlock = perm_requires_keyring
                && does_keyring_need_unlock(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client,
                    username,
                )
                .await
                .is_some();

            let perm_get_result = ReplPermGetResult {
                perms: perm_ctxs_guard.iter().map(|p| p.perm.clone()).collect(),
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
            if matches!(mode, GatewayMode::PermGate(_)) {
                send_bad_request_error(ws_sink, "Route not available to the perm-gate").await;
                return;
            }
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

            // Unguessable, one-shot, time-limited. Binds the perm-gate's
            // approval to this specific request.
            let request_id = generate_token();
            {
                let mut perm_requests = perm_request_map.lock().await;
                // Prevent memory leak: clear expired requests
                let now = std::time::Instant::now();
                perm_requests.retain(|_, req| now < req.expiry);
                perm_requests.insert(
                    request_id.clone(),
                    PendingPermRequest {
                        expiry: now + PERM_REQUEST_TTL,
                        perms: perm_req_arg.perms.clone(),
                        choosers: perm_req_arg.choosers.clone(),
                    },
                );
            }

            // Every chooser yields asset/prefix perms which require the keyring.
            let perm_requires_keyring: bool = !perm_req_arg.choosers.is_empty()
                || perm_req_arg
                    .perms
                    .iter()
                    .any(|perm| perm.requires_keyring());

            let keyring_need_unlock = perm_requires_keyring
                && does_keyring_need_unlock(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client,
                    username,
                )
                .await
                .is_some();

            let perm_ctxs_guard = perm_ctxs.lock().await;
            let new_requested_perms = perm_req_arg
                .perms
                .iter()
                .filter(|req_perm| !perm_ctxs_guard.iter().any(|p| &p.perm == *req_perm))
                .cloned()
                .collect::<Vec<_>>();

            let perm_req_result = ReplPermRequestResult {
                existing_perms: perm_ctxs_guard.iter().map(|p| p.perm.clone()).collect(),
                requested_perms: new_requested_perms,
                keyring_need_unlock,
                request_id: request_id.clone(),
                url: perm_gate_request_url(perm_addr, &request_id),
            };
            drop(perm_ctxs_guard);
            send_response::<ReplPermRequestResult, ()>(ws_sink, mid, Ok(perm_req_result), false)
                .await;
        }
        "repl/open_with" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let open_with_arg: ReplOpenWithArg = match serde_json::from_str(&arg.to_string()) {
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
            // The asset-app name is interpolated into a REPL command.
            if !is_valid_open_with_asset_app(&open_with_arg.asset_app) {
                send_bad_request_error(ws_sink, "Invalid asset_app").await;
                return;
            }

            // Issue (or refresh) a token bound to exactly this target. Reused
            // for identical targets so apps that render many links don't grow
            // the map unboundedly.
            let open_token = {
                let mut tokens = asset_app_open_tokens.lock().await;
                let now = std::time::Instant::now();
                tokens.retain(|_, o| now < o.expiry);
                let existing = tokens.iter_mut().find(|(_, o)| {
                    o.asset_app == open_with_arg.asset_app && o.asset == open_with_arg.asset
                });
                if let Some((token, pending_open)) = existing {
                    pending_open.expiry = now + ASSET_APP_OPEN_TOKEN_TTL;
                    Some(token.clone())
                } else if tokens.len() >= MAX_ASSET_APP_OPEN_TOKENS {
                    None
                } else {
                    let token = generate_token();
                    tokens.insert(
                        token.clone(),
                        PendingAssetAppOpen {
                            asset_app: open_with_arg.asset_app.clone(),
                            asset: open_with_arg.asset.clone(),
                            expiry: now + ASSET_APP_OPEN_TOKEN_TTL,
                        },
                    );
                    Some(token)
                }
            };
            let Some(open_token) = open_token else {
                send_bad_gateway_error(ws_sink, mid, "Too many outstanding open_with links").await;
                return;
            };

            let result = ReplOpenWithResult {
                url: format!(
                    "http://localhost:{}/open?token={}",
                    perm_addr.port(),
                    open_token
                ),
            };
            send_response::<ReplOpenWithResult, ()>(ws_sink, mid, Ok(result), false).await;
        }
        "repl/fetch_og_tags" => {
            let fetch_arg: FetchOgTagsArg = match serde_json::from_value(arg.clone()) {
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
            match opengraph::fetch_og_tags(&fetch_arg.url).await {
                Ok(tags) => {
                    send_response::<FetchOgTagsResult, ()>(
                        ws_sink,
                        mid,
                        Ok(FetchOgTagsResult { tags }),
                        false,
                    )
                    .await;
                }
                Err(e) => {
                    send_bad_gateway_error(ws_sink, mid, &e).await;
                }
            }
        }
        "repl/crypt/sign" => {
            let Some(username) = username else {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            };

            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let crypt_sign_arg: ReplCryptSignArg = match serde_json::from_str(&arg.to_string()) {
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

            let message_bytes = match URL_SAFE_NO_PAD.decode(&crypt_sign_arg.message) {
                Ok(bytes) => bytes,
                Err(_e) => {
                    send_response::<ReplCryptSignResult, ReplCryptSignError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplCryptSignError::BadMessage)),
                        false,
                    )
                    .await;
                    return;
                }
            };
            let sign_result = match asset_crypt::sign_message_using_ed25519_key(
                io,
                asset_blob_cache,
                asset_keyring,
                api_client,
                username,
                &message_bytes,
            )
            .await
            {
                Ok((signing_key_id, signature)) => ReplCryptSignResult {
                    signer_key_id: format!("u:{}:{}", username, signing_key_id),
                    signature: hex::encode(signature),
                },
                Err(sign_err) => {
                    let e = match sign_err {
                        asset_crypt::SignMessageError::InvalidKey
                        | asset_crypt::SignMessageError::KeyNotFound => {
                            RequestError::Route(ReplCryptSignError::BadKey)
                        }
                        asset_crypt::SignMessageError::BadPassword => {
                            RequestError::Route(ReplCryptSignError::KeyLocked)
                        }
                        asset_crypt::SignMessageError::FetchFailed => {
                            send_bad_gateway_error(
                                ws_sink,
                                mid,
                                "Bad gateway: fetch failed (transient)",
                            )
                            .await;
                            return;
                        }
                    };
                    send_response::<ReplCryptSignResult, ReplCryptSignError>(
                        ws_sink,
                        mid,
                        Err(e),
                        false,
                    )
                    .await;
                    return;
                }
            };

            let resp: ClientMessageResponse<ReplCryptSignResult, ()> = ClientMessageResponse::Ok {
                mid,
                result: sign_result,
                more: false,
            };
            let json_string = serde_json::to_string(&resp).expect("Failed to serialize response");
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
        }
        "repl/crypt/verify" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let crypt_verify_arg: ReplCryptVerifyArg = match serde_json::from_str(&arg.to_string())
            {
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

            let message_bytes = match URL_SAFE_NO_PAD.decode(&crypt_verify_arg.message) {
                Ok(bytes) => bytes,
                Err(_e) => {
                    send_response::<ReplCryptVerifyResult, ReplCryptVerifyError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplCryptVerifyError::BadMessage)),
                        false,
                    )
                    .await;
                    return;
                }
            };
            let signature_bytes = match hex::decode(&crypt_verify_arg.signature) {
                Ok(bytes) => {
                    let bytes: [u8; 64] = match bytes.try_into() {
                        Ok(arr) => arr,
                        Err(_e) => {
                            send_response::<ReplCryptVerifyResult, ReplCryptVerifyError>(
                                ws_sink,
                                mid,
                                Err(RequestError::Route(ReplCryptVerifyError::BadSignature)),
                                false,
                            )
                            .await;
                            return;
                        }
                    };
                    bytes
                }
                Err(_e) => {
                    send_response::<ReplCryptVerifyResult, ReplCryptVerifyError>(
                        ws_sink,
                        mid,
                        Err(RequestError::Route(ReplCryptVerifyError::BadSignature)),
                        false,
                    )
                    .await;
                    return;
                }
            };
            let verify_result = match asset_crypt::verify_signature_using_ed25519_key(
                asset_blob_cache,
                api_client,
                &crypt_verify_arg.signer_key_id,
                &message_bytes,
                &signature_bytes,
            )
            .await
            {
                Ok(is_valid) => ReplCryptVerifyResult { is_valid },
                Err(verify_err) => {
                    let e = match verify_err {
                        asset_crypt::VerifySignatureError::InvalidKey
                        | asset_crypt::VerifySignatureError::KeyNotFound => {
                            RequestError::Route(ReplCryptVerifyError::BadKey)
                        }
                        asset_crypt::VerifySignatureError::FetchFailed => {
                            send_bad_gateway_error(
                                ws_sink,
                                mid,
                                "Bad gateway: fetch failed (transient)",
                            )
                            .await;
                            return;
                        }
                    };
                    send_response::<ReplCryptVerifyResult, ReplCryptVerifyError>(
                        ws_sink,
                        mid,
                        Err(e),
                        false,
                    )
                    .await;
                    return;
                }
            };

            let resp: ClientMessageResponse<ReplCryptVerifyResult, ()> =
                ClientMessageResponse::Ok {
                    mid,
                    result: verify_result,
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
            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &asset_arg.name,
                &perm_ctxs,
                false,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
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
            match asset_app_has_gateway_perm_for_asset_list_prefix_request(
                &api_client,
                list_arg.prefix.as_deref().unwrap_or(""),
                &perm_ctxs,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
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
            match asset_app_has_gateway_perm_for_asset_list_prefix_request(
                &api_client,
                search_arg.asset_pool_path.as_deref().unwrap_or(""),
                &perm_ctxs,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
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
            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &move_arg.source_name,
                &perm_ctxs,
                false,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
            }
            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &move_arg.target_name,
                &perm_ctxs,
                true,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
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
            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &remove_arg.name,
                &perm_ctxs,
                true,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
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

            let asset_name_for_perm_check = match &rev_iter_arg.entry_ref {
                asset::EntryRef::Name(name) => name.clone(),
                asset::EntryRef::EntryId(entry_id) => format!(":{}", entry_id.to_string()),
                _ => {
                    send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                    return;
                }
            };

            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &asset_name_for_perm_check,
                &perm_ctxs,
                false,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
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
                        check_access_async(&perm_ctxs, &AccessRequest::ReadByName { name }).await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                asset::EntryRef::EntryId(entry_id) => {
                    if let Err(PermCheckError::Unauthorized) = check_access_async(
                        &perm_ctxs,
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
        "asset/revision/redact" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let redact_get_arg: asset::AssetRevisionRedactArg =
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
            let asset_name_for_perm_check = format!(":{}", redact_get_arg.entry_id);
            match asset_app_has_gateway_perm_for_asset_access_request(
                &api_client,
                &asset_name_for_perm_check,
                &perm_ctxs,
                true,
            )
            .await
            {
                Ok(has_perm) => {
                    if !has_perm {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                Err((_asset_name, e)) => {
                    send_error_response(ws_sink, mid, e).await;
                    return;
                }
            }
            match api_client.asset_revision_redact(redact_get_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetRevisionRedactResult,
                        asset::AssetRevisionRedactError,
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
        "asset/folder/create" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let folder_create_arg: asset::AssetFolderCreateArg =
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
                &perm_ctxs,
                &AccessRequest::WriteByName {
                    name: &folder_create_arg.name,
                },
            )
            .await
            {
                send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                return;
            }
            // Determine AKM before creating the folder so that we don't use
            // its existence as evidence of the AKM choice.
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                io,
                asset_blob_cache.clone(),
                asset_keyring.clone(),
                api_client.clone(),
                username
                    .as_ref()
                    .map(|s| KeyRecipient::User(s.to_string()))
                    .as_ref(),
                &folder_create_arg.name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            if io.is_terminal() {
                                errorln!(io, "{}", msg);
                            }
                            tracing::debug!("{}", msg);
                        }
                    }
                    send_bad_request_error(ws_sink, "Decryption key error").await;
                    return;
                }
            };
            match api_client.asset_folder_create(folder_create_arg).await {
                Ok(folder_create_res) => {
                    if folder_create_res
                        .entry
                        .metadata
                        .as_ref()
                        .map(|md| md.content_encrypted.is_none())
                        .unwrap_or(true)
                        && let Some(akm_info) = akm_info.as_ref()
                    {
                        // If this is the first time putting the asset and it's
                        // encrypted, store the encryption metadata.
                        if let Err(e) = asset_crypt::put_asset_encryption_metadata(
                            &api_client,
                            &folder_create_res.entry.name,
                            &akm_info,
                        )
                        .await
                        {
                            send_bad_gateway_error(ws_sink, mid, &e).await;
                            if io.is_terminal() {
                                errorln!(io, "failed to put asset encryption metadata: {}", e);
                            }
                            tracing::debug!("failed to put asset encryption metadata: {}", e);
                            return;
                        }
                    }

                    let resp_ok: ClientMessageResponse<
                        asset::AssetFolderCreateResult,
                        asset::AssetFolderCreateError,
                    > = ClientMessageResponse::Ok {
                        mid: mid.clone(),
                        result: folder_create_res,
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
                &perm_ctxs,
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
                &perm_ctxs,
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
                &perm_ctxs,
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
                &perm_ctxs,
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
                io,
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
                            if io.is_terminal() {
                                errorln!(io, "{}", msg);
                            }
                            tracing::debug!("{}", msg);
                        }
                    }
                    send_bad_request_error(ws_sink, "Decryption key error").await;
                    return;
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
                        put_conflict_policy: Some(asset_arg.conflict_policy),
                        replace_conflict_policy: None,
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
                &perm_ctxs,
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
                io,
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
                            if io.is_terminal() {
                                errorln!(io, "{}", msg);
                            }
                            tracing::debug!("{}", msg);
                        }
                    }
                    send_bad_request_error(ws_sink, "Decryption key error").await;
                    return;
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
                        put_conflict_policy: Some(asset_arg.conflict_policy),
                        replace_conflict_policy: None,
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
        "asset/entry/acl/set" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let acl_arg: asset::AssetEntryAclSetArg = match serde_json::from_str(&arg.to_string()) {
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
            match acl_arg.entry_ref {
                asset::EntryRef::Name(ref name) => {
                    if let Err(PermCheckError::Unauthorized) =
                        check_access_async(&perm_ctxs, &AccessRequest::WriteByName { name }).await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                asset::EntryRef::EntryId(ref entry_id) => {
                    if let Err(PermCheckError::Unauthorized) = check_access_async(
                        &perm_ctxs,
                        &AccessRequest::WriteByEntryId { entry_id: entry_id },
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
            match api_client.asset_entry_acl_set(acl_arg).await {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetEntryAclSetResult,
                        asset::AssetEntryAclSetError,
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
        "asset/entry/acl/get_effective" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let acl_get_effective_arg: asset::AssetEntryAclGetEffectiveArg =
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
            match acl_get_effective_arg.entry_ref {
                asset::EntryRef::Name(ref name) => {
                    if let Err(PermCheckError::Unauthorized) =
                        check_access_async(&perm_ctxs, &AccessRequest::ReadByName { name }).await
                    {
                        send_bad_authorization_error(ws_sink, mid, "Unauthorized").await;
                        return;
                    }
                }
                asset::EntryRef::EntryId(ref entry_id) => {
                    if let Err(PermCheckError::Unauthorized) = check_access_async(
                        &perm_ctxs,
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
            match api_client
                .asset_entry_acl_get_effective(acl_get_effective_arg)
                .await
            {
                Ok(res) => {
                    let resp_ok: ClientMessageResponse<
                        asset::AssetEntryAclGetEffectiveResult,
                        asset::AssetEntryAclGetEffectiveError,
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
        _other => {
            send_bad_request_error(ws_sink, "Unknown route").await;
        }
    }
}

// --

//
// Perm-gate
//

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    Message,
>;

fn parse_arg<T: DeserializeOwned>(arg: &serde_json::Value) -> Option<T> {
    // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
    serde_json::from_str(&arg.to_string()).ok()
}

// --

/// Read-only access to the whole asset tree (minus the usual `.keys/`,
/// `vault/`, `.sys/hai.toml` exclusions), plus `Everything`.
///
/// NOTE: `Everything` is redundant with (and broader than) the read-only perm.
/// It's a stopgap for kernel access until a dedicated kernel perm exists, at
/// which point `Everything` should be dropped.
fn perm_gate_default_perms() -> Vec<PermCtx> {
    vec![
        PermCtx {
            perm: Perm::AssetPrefix {
                prefix: String::new(),
                perm: AssetPerm {
                    read: true,
                    write: false,
                },
                prefix_perm: AssetPrefixPerm {
                    create: false,
                    list: true,
                },
            },
            lifetime: PermLifetime::Default,
        },
        PermCtx {
            perm: Perm::Everything,
            lifetime: PermLifetime::Default,
        },
    ]
}

fn perm_gate_request_url(perm_gate_addr: &SocketAddr, request_id: &str) -> String {
    format!(
        "http://localhost:{}{}#request_id={}",
        perm_gate_addr.port(),
        PERM_GATE_ASSET_PREFIX,
        request_id
    )
}

fn with_perm_gate_security_headers(resp: HttpResponse) -> HttpResponse {
    resp
        // Clickjacking: a requesting app must not be able to frame the
        // perm-gate and trick the user into clicking "Grant".
        .with_header("Content-Security-Policy", "frame-ancestors 'none'")
        .with_header("X-Frame-Options", "DENY")
        // Sever the opener so the requesting app keeps no window handle.
        .with_header("Cross-Origin-Opener-Policy", "same-origin")
        .with_header("Referrer-Policy", "no-referrer")
}

fn is_valid_open_with_asset_app(asset_app: &str) -> bool {
    !asset_app.is_empty()
        && !asset_app
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

async fn notify_perm_updated(clients: &Clients, new_perms: &[Perm]) {
    let json = serde_json::json!({
        ".tag": "ok",
        "mid": -1,
        "route": "client/perm/updated",
        "arg": {
            "new_perms": new_perms,
        },
    })
    .to_string();
    for tx in clients.lock().await.values() {
        let _ = tx.send(Message::Text(Utf8Bytes::from(json.clone())));
    }
}

async fn get_pending_perm_request(
    perm_request_map: &PermRequestMap,
    request_id: &str,
) -> Option<PendingPermRequest> {
    let map = perm_request_map.lock().await;
    map.get(request_id)
        .filter(|req| std::time::Instant::now() < req.expiry)
        .cloned()
}

/// Serves the perm-gate asset-app.
///
/// Only GETs under `/hai/app/perm-gate/` are served. Everything else is 404.
async fn handle_perm_gate_http(
    io: &Io,
    request: &HttpRequest,
    pg_ctx: &PermGateCtx,
    service_name: &str,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    perm_ctxs: PermCtxs,
    username: Option<&str>,
) -> HttpResponse {
    if request.method != "GET" {
        return HttpResponse::bad_request("Only GET supported");
    }
    let decoded = match urlencoding::decode(&request.path) {
        Ok(p) => p.into_owned(),
        Err(_) => return HttpResponse::bad_request("Invalid URL encoding"),
    };
    // Foward to slash version
    if decoded == PERM_GATE_SERVICE_NAME {
        return HttpResponse::redirect_temp(PERM_GATE_ASSET_PREFIX);
    }
    // If not the perm-gate asset-app -> 404 error.
    let Some(rest) = decoded.strip_prefix(PERM_GATE_ASSET_PREFIX) else {
        return HttpResponse::not_found();
    };
    // Reject all non-standard notation (including our own) in the asset-app
    // path.
    if rest.contains(':') || rest.contains('@') || rest.split('/').any(|seg| seg == "..") {
        return HttpResponse::not_found();
    }
    match pg_ctx.source {
        PermGateSource::Embedded => {
            if rest.is_empty() || rest == "index.html" {
                HttpResponse::ok(PERM_GATE_EMBEDDED_HTML.to_vec(), "text/html; charset=utf-8")
            } else {
                HttpResponse::not_found()
            }
        }
        PermGateSource::AssetStore => {
            handle_get(
                io,
                request,
                service_name,
                &decoded,
                None,
                false,
                asset_blob_cache,
                asset_keyring,
                api_client,
                perm_ctxs,
                username,
                Arc::new(None),
            )
            .await
        }
    }
}

/// Dedicated perm-gate handler for `/open?token=<token>`
///
/// The purpose of this handler is to allow asset-app A to open asset-app B
/// with a clean separation of permissions (no inheritance) which requires
/// launching a completely separate gateway.
///
/// The token originates from the standard gateway's `repl/open_with` route.
/// The token ensures that web apps cannot launch arbitrary asset-apps.
async fn handle_perm_gate_open(
    request: &HttpRequest,
    pg_ctx: &PermGateCtx,
    asset_app_open_tokens: &AssetAppOpenTokenMap,
) -> HttpResponse {
    let sec_fetch_mode = request.header("Sec-Fetch-Mode").unwrap_or_default();
    if request.header("Origin").is_some()
        || (sec_fetch_mode != "navigate" && !sec_fetch_mode.is_empty())
    {
        // Only top-level navigations. Prevents JS fetch() from following the
        // redirect.
        return HttpResponse::unauthorized();
    }
    let Some(token) = request.query_param("token") else {
        return HttpResponse::bad_request("Missing 'token' query parameter");
    };
    let pending_open = {
        let tokens = asset_app_open_tokens.lock().await;
        tokens
            .get(token)
            .filter(|o| std::time::Instant::now() < o.expiry)
            .cloned()
    };
    let Some(pending_open) = pending_open else {
        return HttpResponse::forbidden();
    };

    let repl_remote = pg_ctx.repl_remote.clone();
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel(1);
    repl_remote
        .push_cmd(crate::session::CmdInput {
            input: format!("/asset-app.no_open {}", pending_open.asset_app),
            source: session::CmdSource::Internal { print_cmd: false },
            reply_channel: Some(reply_tx),
        })
        .await;
    repl_remote.signal_break();
    match reply_rx.recv().await {
        Some(CmdInputReply::Gateway(Some((url, _addr, _perm_addr)))) => {
            match pending_open.asset.as_deref() {
                Some(asset_name) => {
                    let sep = if url.contains('#') { '&' } else { '#' };
                    HttpResponse::redirect_temp(&format!(
                        "{}{}asset={}",
                        url,
                        sep,
                        encode_asset_fragment(asset_name)
                    ))
                }
                None => HttpResponse::redirect_temp(&url),
            }
        }
        Some(CmdInputReply::Gateway(None)) => {
            HttpResponse::internal_error("Failed to start asset app")
        }
        None => HttpResponse::internal_error("Failed to get response from REPL"),
    }
}

// --

//
// Perm-gate websocket routes
//

//
// route: perm_gate/request/get
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestGetArg {
    request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestGetResult {
    service_name: String,
    existing_perm_ctxs: Vec<PermCtx>,
    /// Requested perms not already granted.
    requested_perms: Vec<Perm>,
    choosers: Vec<Chooser>,
    keyring_need_unlock: bool,
    expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum PermGateRequestGetError {
    NotFound,
}

//
// route: perm_gate/request/submit
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestSubmitArg {
    request_id: String,
    grant: Vec<PermCtx>,
    #[serde(default)]
    grant_chooser: Vec<Vec<PermCtx>>,
    #[serde(default)]
    keyring_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestSubmitResult {
    new_perm_ctxs: Vec<PermCtx>,
    all_perm_ctxs: Vec<PermCtx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum PermGateRequestSubmitError {
    NotFound,
    BadLifetime,
    KeyringPasswordRequired,
    KeyringPasswordIncorrect,
}

//
// route: perm_gate/request/deny
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestDenyArg {
    request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGateRequestDenyResult {
    /// True if the request existed (and was removed).
    ok: bool,
}

//
// route: perm_gate/perm/list
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGatePermListResult {
    service_name: String,
    all_perm_ctxs: Vec<PermCtx>,
    keyring_need_unlock: bool,
}

//
// route: perm_gate/perm/revoke
//

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGatePermRevokeArg {
    perms: Vec<Perm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermGatePermRevokeResult {
    revoked: Vec<Perm>,
    all_perm_ctxs: Vec<PermCtx>,
}

async fn handle_perm_gate_message(
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
    pg_ctx: &PermGateCtx,
    ws_sink: &mut WsSink,
    mid: u64,
    route: &str,
    arg: &serde_json::Value,
) {
    match route {
        "perm_gate/request/get" => {
            let Some(arg) = parse_arg::<PermGateRequestGetArg>(arg) else {
                send_bad_request_error(ws_sink, &format!("Invalid argument for {route}")).await;
                return;
            };
            let Some(pending) =
                get_pending_perm_request(&pg_ctx.target_perm_request_map, &arg.request_id).await
            else {
                send_response::<PermGateRequestGetResult, _>(
                    ws_sink,
                    mid,
                    Err(RequestError::Route(PermGateRequestGetError::NotFound)),
                    false,
                )
                .await;
                return;
            };

            let existing_perm_ctxs = pg_ctx.target_perm_ctxs.lock().await.clone();
            let keyring_need_unlock = (!pending.choosers.is_empty()
                || pending.perms.iter().any(|p| p.requires_keyring())
                || existing_perm_ctxs
                    .iter()
                    .any(|perm_ctx| perm_ctx.perm.requires_keyring()))
                && does_keyring_need_unlock(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client,
                    username,
                )
                .await
                .is_some();
            let requested_perms = pending
                .perms
                .iter()
                .filter(|p| {
                    !existing_perm_ctxs
                        .iter()
                        .any(|perm_ctx| perm_ctx.perm == **p)
                })
                .cloned()
                .collect();
            let result = PermGateRequestGetResult {
                service_name: pg_ctx.target_service_name.clone(),
                existing_perm_ctxs: existing_perm_ctxs,
                requested_perms,
                choosers: pending.choosers.clone(),
                keyring_need_unlock,
                expires_in_secs: pending
                    .expiry
                    .saturating_duration_since(std::time::Instant::now())
                    .as_secs(),
            };
            send_response::<_, PermGateRequestGetError>(ws_sink, mid, Ok(result), false).await;
        }
        "perm_gate/request/submit" => {
            let Some(arg) = parse_arg::<PermGateRequestSubmitArg>(arg) else {
                send_bad_request_error(ws_sink, &format!("Invalid argument for {route}")).await;
                return;
            };
            fn submit_err(
                e: PermGateRequestSubmitError,
            ) -> Result<PermGateRequestSubmitResult, RequestError<PermGateRequestSubmitError>>
            {
                Err(RequestError::Route(e))
            }
            let Some(pending) =
                get_pending_perm_request(&pg_ctx.target_perm_request_map, &arg.request_id).await
            else {
                send_response(
                    ws_sink,
                    mid,
                    submit_err(PermGateRequestSubmitError::NotFound),
                    false,
                )
                .await;
                return;
            };

            // Check for bad lifetime (default)
            if arg
                .grant
                .iter()
                .chain(arg.grant_chooser.iter().flatten())
                .any(|perm_ctx| perm_ctx.lifetime == PermLifetime::Default)
            {
                send_response(
                    ws_sink,
                    mid,
                    submit_err(PermGateRequestSubmitError::BadLifetime),
                    false,
                )
                .await;
                return;
            }

            let any_granted_requires_keyring = arg
                .grant
                .iter()
                .chain(arg.grant_chooser.iter().flatten())
                .any(|perm_ctx| perm_ctx.perm.requires_keyring());
            let existing_requires_keyring = pg_ctx
                .target_perm_ctxs
                .lock()
                .await
                .iter()
                .any(|perm_ctx| perm_ctx.perm.requires_keyring());
            let keyring_need_unlock = if !any_granted_requires_keyring && !existing_requires_keyring
            {
                None
            } else {
                does_keyring_need_unlock(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client,
                    username,
                )
                .await
            };

            let keyring_unlocked =
                if let Some((enc_key_info, verifying_key_info)) = keyring_need_unlock {
                    let password = arg.keyring_password.as_deref().unwrap_or("");
                    if password.is_empty() {
                        send_response(
                            ws_sink,
                            mid,
                            submit_err(PermGateRequestSubmitError::KeyringPasswordRequired),
                            false,
                        )
                        .await;
                        return;
                    }
                    let decrypt_unlocked = asset_keyring
                        .lock()
                        .await
                        .unlock_decrypt_key(
                            asset_blob_cache.clone(),
                            api_client,
                            &enc_key_info.recipient_key_id_parts(),
                            password,
                        )
                        .await
                        .is_ok();
                    // NOTE: Unexpected for decryption key & signing key to differ.
                    let signing_unlocked = decrypt_unlocked
                        && asset_keyring
                            .lock()
                            .await
                            .unlock_signing_key(
                                asset_blob_cache.clone(),
                                api_client,
                                &verifying_key_info.recipient_key_id_parts(),
                                password,
                            )
                            .await
                            .is_ok();
                    if !signing_unlocked {
                        send_response(
                            ws_sink,
                            mid,
                            submit_err(PermGateRequestSubmitError::KeyringPasswordIncorrect),
                            false,
                        )
                        .await;
                        return;
                    }
                    true
                } else {
                    false
                };

            // Consume the request to prevent re-use (double submission)
            if pg_ctx
                .target_perm_request_map
                .lock()
                .await
                .remove(&arg.request_id)
                .is_none()
            {
                send_response(
                    ws_sink,
                    mid,
                    submit_err(PermGateRequestSubmitError::NotFound),
                    false,
                )
                .await;
                return;
            }

            let mut perm_ctxs_guard = pg_ctx.target_perm_ctxs.lock().await;
            let mut new_perm_ctxs: Vec<PermCtx> = Vec::new();
            let mut new_until_revoked_perms = Vec::new();
            let mut add_grant = |granted_perm_ctx: PermCtx| {
                if perm_ctxs_guard
                    .iter()
                    .any(|perm_ctx| perm_ctx.perm == granted_perm_ctx.perm)
                    || new_perm_ctxs
                        .iter()
                        .any(|perm_ctx| perm_ctx.perm == granted_perm_ctx.perm)
                {
                    return;
                }
                perm_ctxs_guard.push(granted_perm_ctx.clone());
                if granted_perm_ctx.lifetime == PermLifetime::UntilRevoked {
                    new_until_revoked_perms.push(granted_perm_ctx.perm.clone());
                }
                new_perm_ctxs.push(granted_perm_ctx);
            };

            // Explicitly requested perms: only perms that were actually
            // requested can be granted.
            for granted_perm_ctx in arg.grant {
                if pending.perms.contains(&granted_perm_ctx.perm) {
                    add_grant(granted_perm_ctx);
                }
            }

            // Chooser grants: `grant_chooser[i]` holds the user's picks for
            // `pending.choosers[i]`. If a pick is incompatible with its
            // chooser, it's igored (as are out-of-range indices).
            for (chooser_idx, chooser_grants) in arg.grant_chooser.into_iter().enumerate() {
                let Some(chooser) = pending.choosers.get(chooser_idx) else {
                    continue;
                };
                let max_count = match chooser {
                    Chooser::Asset { max_count, .. } => max_count.map(|c| c as usize),
                    Chooser::AssetFolder { .. } => None,
                };
                let mut accepted = 0usize;
                for granted_perm_ctx in chooser_grants {
                    if max_count.is_some_and(|max| accepted >= max) {
                        break;
                    }
                    let Some(perm) = chooser_grant_to_perm(chooser, &granted_perm_ctx.perm) else {
                        continue;
                    };
                    accepted += 1;
                    add_grant(PermCtx {
                        perm,
                        lifetime: granted_perm_ctx.lifetime,
                    });
                }
            }

            let all_perm_ctxs = perm_ctxs_guard.clone();
            drop(perm_ctxs_guard);

            if let Some(username) = username
                && !new_until_revoked_perms.is_empty()
            {
                let _ = crate::db::merge_gateway_perms(
                    &mut *db.lock().await,
                    username,
                    &pg_ctx.target_service_name,
                    &new_until_revoked_perms,
                );
            }

            if !new_perm_ctxs.is_empty() || keyring_unlocked {
                notify_perm_updated(
                    &pg_ctx.target_clients,
                    &new_perm_ctxs
                        .iter()
                        .map(|perm_ctx| perm_ctx.perm.clone())
                        .collect::<Vec<_>>(),
                )
                .await;
            }

            send_response::<_, PermGateRequestSubmitError>(
                ws_sink,
                mid,
                Ok(PermGateRequestSubmitResult {
                    new_perm_ctxs,
                    all_perm_ctxs,
                }),
                false,
            )
            .await;
        }
        "perm_gate/request/deny" => {
            let Some(arg) = parse_arg::<PermGateRequestDenyArg>(arg) else {
                send_bad_request_error(ws_sink, &format!("Invalid argument for {route}")).await;
                return;
            };
            let ok = pg_ctx
                .target_perm_request_map
                .lock()
                .await
                .remove(&arg.request_id)
                .is_some();
            send_response::<_, ()>(ws_sink, mid, Ok(PermGateRequestDenyResult { ok }), false).await;
        }
        "perm_gate/perm/list" => {
            let perm_ctxs = pg_ctx.target_perm_ctxs.lock().await.clone();
            let keyring_need_unlock = perm_ctxs
                .iter()
                .any(|perm_ctx| perm_ctx.perm.requires_keyring())
                && does_keyring_need_unlock(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client,
                    username,
                )
                .await
                .is_some();
            send_response::<_, ()>(
                ws_sink,
                mid,
                Ok(PermGatePermListResult {
                    service_name: pg_ctx.target_service_name.clone(),
                    all_perm_ctxs: perm_ctxs,
                    keyring_need_unlock,
                }),
                false,
            )
            .await;
        }
        "perm_gate/perm/revoke" => {
            let Some(arg) = parse_arg::<PermGatePermRevokeArg>(arg) else {
                send_bad_request_error(ws_sink, &format!("Invalid argument for {route}")).await;
                return;
            };
            let mut revoked = Vec::new();
            let mut perm_ctxs_guard = pg_ctx.target_perm_ctxs.lock().await;
            perm_ctxs_guard.retain(|perm_ctx| {
                if arg.perms.contains(&perm_ctx.perm) {
                    revoked.push(perm_ctx.perm.clone());
                    false
                } else {
                    true
                }
            });
            let all_perm_ctxs = perm_ctxs_guard.clone();
            drop(perm_ctxs_guard);

            // Revoking also forgets.
            if let Some(username) = username {
                let mut conn = db.lock().await;
                let remembered =
                    crate::db::load_gateway_perms(&conn, username, &pg_ctx.target_service_name);
                let remaining: Vec<Perm> = remembered
                    .iter()
                    .filter(|p| !arg.perms.contains(p))
                    .cloned()
                    .collect();
                if remaining.len() != remembered.len() {
                    let _ = crate::db::clear_gateway_perms(
                        &conn,
                        username,
                        &pg_ctx.target_service_name,
                    );
                    if !remaining.is_empty() {
                        let _ = crate::db::merge_gateway_perms(
                            &mut conn,
                            username,
                            &pg_ctx.target_service_name,
                            &remaining,
                        );
                    }
                }
            }

            if !revoked.is_empty() {
                notify_perm_updated(&pg_ctx.target_clients, &[]).await;
            }

            send_response::<_, ()>(
                ws_sink,
                mid,
                Ok(PermGatePermRevokeResult {
                    revoked,
                    all_perm_ctxs,
                }),
                false,
            )
            .await;
        }
        _ => send_bad_request_error(ws_sink, "Unknown route").await,
    }
}

// --

/// If keyring needs unlocking, returns key-info for encryption and signing
/// keys.
///
/// WARNING: Does not properly handle or report the unexpected case where only
/// one of the encryption or signing keys exists as this is not a supported
/// scenario currently.
async fn does_keyring_need_unlock(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
) -> Option<(EncryptKeyInfo, VerifyingKeyInfo)> {
    let unlocked_keyring_required = if let Some(username) = username {
        (
            asset_crypt::get_encryption_key(
                asset_blob_cache.clone(),
                api_client,
                &KeyRecipient::User(username.to_string()),
                None,
            )
            .await
            .ok()
            .flatten(),
            asset_crypt::get_verifying_key(
                asset_blob_cache.clone(),
                api_client,
                &KeyRecipient::User(username.to_string()),
                None,
            )
            .await
            .ok()
            .flatten(),
        )
    } else {
        (None, None)
    };

    if let (Some(unlocked_enc_keyring_required), Some(unlocked_sign_keyring_required)) =
        unlocked_keyring_required
    {
        let mut kr = asset_keyring.lock().await;
        let can_unlock_enc = kr
            .can_unlock_decrypt_key(
                asset_blob_cache.clone(),
                api_client,
                &unlocked_enc_keyring_required.recipient_key_id_parts(),
            )
            .await;
        let can_unlock_sign = kr
            .can_unlock_signing_key(
                asset_blob_cache.clone(),
                api_client,
                &unlocked_sign_keyring_required.recipient_key_id_parts(),
            )
            .await;
        if can_unlock_enc && can_unlock_sign {
            None
        } else {
            Some((
                unlocked_enc_keyring_required,
                unlocked_sign_keyring_required,
            ))
        }
    } else {
        None
    }
}

// --

// --

//
// Chooser grant validation
//

/// True if `granted` does not exceed `requested`.
fn asset_perm_within(granted: &AssetPerm, requested: &AssetPerm) -> bool {
    (!granted.read || requested.read) && (!granted.write || requested.write)
}

/// True if `granted` does not exceed `requested`.
fn asset_prefix_perm_within(granted: &AssetPrefixPerm, requested: &AssetPrefixPerm) -> bool {
    (!granted.create || requested.create) && (!granted.list || requested.list)
}

/// Assets that a chooser must never hand out, mirroring the exclusions that
/// `Perm::AssetPrefix` applies.
fn is_protected_asset_name(name: &str) -> bool {
    name.starts_with(".keys/") || name.starts_with("vault/") || name.starts_with(".sys/hai.toml")
}

/// Validates and normalizes an entry-id grant against the requested perm.
fn chooser_entry_id_grant(entry_id: &str, perm: &AssetPerm, requested: &AssetPerm) -> Option<Perm> {
    // Canonical form does not use leading `:`
    let entry_id = entry_id.strip_prefix(':').unwrap_or(entry_id);
    if entry_id.is_empty()
        || entry_id.contains(':')
        || (!perm.read && !perm.write)
        || !asset_perm_within(perm, requested)
    {
        return None;
    }
    Some(Perm::AssetEntryId {
        entry_id: entry_id.to_string(),
        perm: perm.clone(),
    })
}

/// Checks whether a perm granted via the perm-gate for `chooser` is compatible
/// with what the chooser requested.
///
/// Returns the (normalized) perm to grant, or `None` if the grant must be
/// ignored.
///
/// NOTE: `ChooserAssetFilter` is intentionally not enforced. It's a UI hint
/// for the perm-gate's picker.
fn chooser_grant_to_perm(chooser: &Chooser, granted: &Perm) -> Option<Perm> {
    match (chooser, granted) {
        (
            Chooser::Asset {
                by_entry_id: false,
                perm: requested,
                ..
            },
            Perm::AssetName { name, perm },
        ) => {
            if name.is_empty()
                || name.starts_with(':')
                || name.ends_with('/')
                || is_protected_asset_name(name)
                || (!perm.read && !perm.write)
                || !asset_perm_within(perm, requested)
            {
                return None;
            }
            Some(granted.clone())
        }
        // Assets and folders chosen by entry_id are both granted as
        // `AssetEntryId`. WARN: Giving access to a folder via entry_id may
        // have some untested limitations.
        (
            Chooser::Asset {
                by_entry_id: true,
                perm: requested,
                ..
            }
            | Chooser::AssetFolder {
                by_entry_id: true,
                perm: requested,
                ..
            },
            Perm::AssetEntryId { entry_id, perm },
        ) => chooser_entry_id_grant(entry_id, perm, requested),
        (
            Chooser::AssetFolder {
                by_entry_id: false,
                perm: requested,
                prefix_perm: requested_prefix_perm,
            },
            Perm::AssetPrefix {
                prefix,
                perm,
                prefix_perm,
            },
        ) => {
            // Reject whole-pool prefixes ("" = all private assets, "/" = all
            // public assets).
            if !prefix.ends_with('/')
                || prefix == "/"
                || prefix.starts_with(':')
                || is_protected_asset_name(prefix)
                || !asset_perm_within(perm, requested)
                || !asset_prefix_perm_within(prefix_perm, requested_prefix_perm)
            {
                return None;
            }
            Some(granted.clone())
        }
        _ => None,
    }
}

// --

fn generate_random_string(length: usize) -> String {
    (0..length)
        .map(|_| {
            let idx = rand::rng().random_range(0..62);
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[idx] as char
        })
        .collect()
}

fn generate_kernel_id() -> String {
    generate_random_string(12)
}

pub fn generate_token() -> String {
    generate_random_string(32)
}
