use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};
use tokio_util::sync::CancellationToken;

use crate::api::client::HaiClient;
use crate::api::types::asset;
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader::GetAssetError;
use crate::{
    asset_async_writer, asset_reader,
    feature::asset_crypt::{self, KeyRecipient},
};

pub type ClientId = u64;
pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<std::collections::HashMap<ClientId, Client>>>;

// -- Minimal HTTP parsing/response helpers --

struct HttpRequest {
    method: String,
    path: String,
    query_params: std::collections::HashMap<String, String>,
    headers: std::collections::HashMap<String, String>,
    subdomain: Option<String>,
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
        let subdomain = Self::parse_subdomain(headers.get("host"), base_domain);

        Some(HttpRequest {
            method,
            path,
            query_params,
            headers,
            subdomain,
        })
    }

    fn parse_subdomain(host_header: Option<&String>, base_domain: &str) -> Option<String> {
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

    fn bearer_token(&self) -> Option<&str> {
        self.headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
    }

    fn query_param(&self, key: &str) -> Option<&str> {
        self.query_params.get(key).map(|s| s.as_str())
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
}

impl HttpResponse {
    fn ok(body: Vec<u8>, content_type: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK",
            content_type: content_type.to_string(),
            body,
            set_cookie: None,
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            status_text: "Not Found",
            content_type: "text/plain".into(),
            body: b"Not Found".to_vec(),
            set_cookie: None,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: 401,
            status_text: "Unauthorized",
            content_type: "text/plain".into(),
            body: b"Unauthorized".to_vec(),
            set_cookie: None,
        }
    }

    fn bad_request(msg: &str) -> Self {
        Self {
            status: 400,
            status_text: "Bad Request",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
            set_cookie: None,
        }
    }

    fn internal_error(msg: &str) -> Self {
        Self {
            status: 500,
            status_text: "Internal Server Error",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
            set_cookie: None,
        }
    }

    fn with_cookie(mut self, cookie: String) -> Self {
        self.set_cookie = Some(cookie);
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

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
            self.status,
            self.status_text,
            self.content_type,
            self.body.len(),
            cookie_header,
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&self.body).await?;
        stream.flush().await?;
        Ok(())
    }
}

pub async fn launch_gateway(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: HaiClient,
    username: Option<&str>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
) -> std::io::Result<(SocketAddr, Clients, CancellationToken, String)> {
    // Generate a random authentication token
    let token: String = (0..32)
        .map(|_| {
            let idx = rand::rng().random_range(0..62);
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[idx] as char
        })
        .collect();

    let mut port = 1339;
    let listener = loop {
        let addr = format!("127.0.0.1:{}", port);
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(_) => port += 1,
        }
    };
    let local_addr = listener.local_addr()?;
    println!(
        "Gateway listening on http://{} (HTTP + WebSocket) auth token: {}",
        local_addr, token
    );

    let clients: Clients = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let clients_clone = clients.clone();
    let cancel_token = CancellationToken::new();
    let cancel_token_child = cancel_token.child_token();
    let token_clone = token.clone();
    let api_client_clone = api_client.clone();
    let asset_keyring_clone = asset_keyring.clone();
    let asset_blob_cache_cloned = asset_blob_cache.clone();
    let username_owned = username.map(|s| s.to_string());
    let next_client_id = Arc::new(std::sync::atomic::AtomicU64::new(1));

    let cookie_set = Arc::new(AtomicBool::new(false));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token_child.cancelled() => {
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
                    let username_inner = username_owned.clone();
                    let update_asset_tx_inner = update_asset_tx.clone();
                    let next_client_id_inner = next_client_id.clone();
                    let cookie_set_inner = cookie_set.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            peer_addr,
                            token_clone_inner,
                            api_client_clone_inner,
                            asset_blob_cache_inner,
                            asset_keyring_inner,
                            clients_inner,
                            username_inner,
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

    Ok((local_addr, clients, cancel_token, token))
}

// Handles both HTTP and WebSocket connections, dispatching to the appropriate
// handler based on the initial request.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    token: String,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    clients: Clients,
    username: Option<String>,
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
            &peer_addr,
            token,
            api_client,
            asset_blob_cache,
            asset_keyring,
            clients,
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
            username,
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
    #[allow(unused_variables)] peer_addr: &SocketAddr,
    token: String,
    api_client: HaiClient,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    clients: Clients,
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
                            &serde_json::to_string(&ClientMessageAuthResponse::BadRequest).unwrap(),
                        )))
                        .await;
                    let _ = ws_stream.close(None).await;
                    return Ok(());
                }
            };
            if auth_msg.token != Some(token) && !pre_authenticated {
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
                            asset_blob_cache.clone(),
                            asset_keyring.clone(),
                            &api_client, username.as_deref(),
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
    username: Option<String>,
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
        username,
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
    username: Option<String>,
    cookie_set: Arc<AtomicBool>,
) -> HttpResponse {
    // Check token from multiple sources: cookie, bearer token, query param
    let cookie_token = request.cookie("hai_token");
    let bearer_token = request.bearer_token();
    let query_token = request.query_param("token");

    let should_set_cookie = !cookie_set.load(std::sync::atomic::Ordering::SeqCst);

    let authenticated = if let Some(ct) = cookie_token {
        // Cookie present - validate it
        ct == expected_token
    } else if let Some(bt) = bearer_token {
        // Bearer token - validate, set cookie if first request
        bt == expected_token
    } else if let Some(qt) = query_token {
        // Query param token - validate, set cookie if first request
        qt == expected_token
    } else {
        false
    };

    if !authenticated && !should_set_cookie {
        return HttpResponse::unauthorized();
    }

    // Mark cookie as set (for future requests)
    if should_set_cookie {
        cookie_set.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // Only handle GET for now
    if request.method != "GET" {
        return HttpResponse::bad_request("Only GET supported");
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
        Ok(decoded_path) => {
            // Support <asset_name>@<asset_app_name> format
            match decoded_path.split_once('@') {
                Some((_asset_name, asset_app_name)) => asset_app_name.to_string(),
                None => decoded_path.to_string(),
            }
        }
        Err(_) => return HttpResponse::bad_request("Invalid URL encoding"),
    };

    let (data_contents, md_contents, asset_entry) = match asset_reader::get_asset_and_metadata(
        asset_blob_cache.clone(),
        &api_client,
        &asset_name,
        false,
    )
    .await
    {
        Ok(res) => res,
        Err(GetAssetError::BadName) => return HttpResponse::not_found(),
        Err(GetAssetError::DataFetchFailed) => {
            return HttpResponse::bad_request("Invalid URL encoding");
        }
    };
    let decrypted_asset_contents = match asset_crypt::maybe_decrypt_asset_contents(
        asset_blob_cache.clone(),
        asset_keyring.clone(),
        &api_client,
        username.map(|s| KeyRecipient::User(s.to_string())).as_ref(),
        &data_contents,
        md_contents.as_deref(),
    )
    .await
    {
        Ok(res) => res,
        Err(e) => {
            eprintln!("error: failed to decrypt: {}", e);
            return HttpResponse::internal_error("Failed to decrypt asset");
        }
    };

    let asset_content_type = asset_entry.metadata.and_then(|md| md.content_type.clone());
    let content_type = crate::asset_helper::best_guess_content_type(
        &asset_name,
        asset_content_type.as_deref(),
        &decrypted_asset_contents,
    );

    let mut response = HttpResponse::ok(decrypted_asset_contents, &content_type);

    // Set cookie on first authenticated request
    if should_set_cookie {
        response = response.with_cookie(HttpResponse::auth_cookie(expected_token));
    }

    response
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageAuthRequest {
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessageAuthResponse {
    Ok { version: String },
    BadToken,
    BadRequest,
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageRequest {
    route: String,
    arg: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessageResponse<T, U> {
    Ok { result: T, payload_count: u32 },
    RouteError { error: U },
    BadRequestError { error: String },
    HttpError { error: String },
    UnexpectedError { error: String },
}

// --

// Helper functions for sending responses

async fn send_error_response<E: Serialize>(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    error: crate::api::client::RequestError<E>,
) {
    let resp_err: ClientMessageResponse<(), E> = match error {
        crate::api::client::RequestError::Http(http_err) => ClientMessageResponse::HttpError {
            error: http_err.to_string(),
        },
        crate::api::client::RequestError::Route(route_err) => {
            ClientMessageResponse::RouteError { error: route_err }
        }
        crate::api::client::RequestError::BadRequest(msg) => {
            ClientMessageResponse::BadRequestError { error: msg }
        }
        crate::api::client::RequestError::Unexpected(msg) => {
            ClientMessageResponse::UnexpectedError { error: msg }
        }
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
    result: Result<T, crate::api::client::RequestError<E>>,
    payload_count: u32,
) -> bool {
    match result {
        Ok(res) => {
            let resp_ok: ClientMessageResponse<T, E> = ClientMessageResponse::Ok {
                result: res,
                payload_count,
            };
            let json_string =
                serde_json::to_string(&resp_ok).expect("Failed to re-serialize response");
            let _ = ws_sink
                .send(Message::Text(Utf8Bytes::from(&json_string)))
                .await;
            true
        }
        Err(e) => {
            send_error_response(ws_sink, e).await;
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

async fn send_http_error<E: Serialize>(
    ws_sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >,
    error: &str,
) {
    let resp_err = ClientMessageResponse::<(), E>::HttpError {
        error: error.to_string(),
    };
    let json_string = serde_json::to_string(&resp_err).expect("Failed to re-serialize response");
    let _ = ws_sink
        .send(Message::Text(Utf8Bytes::from(&json_string)))
        .await;
}

// --

async fn handle_client_message(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
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

    let ClientMessageRequest { route, arg } = client_msg;

    match route.as_str() {
        "asset/get" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let asset_arg: asset::AssetGetArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(ws_sink, "Invalid argument for asset/get").await;
                    return;
                }
            };

            let (data_contents, md_contents, _asset_entry) =
                match asset_reader::get_asset_and_metadata(
                    asset_blob_cache.clone(),
                    &api_client,
                    &asset_arg.name,
                    false,
                )
                .await
                {
                    Ok(res) => res,
                    Err(_) => {
                        send_http_error::<asset::AssetGetError>(ws_sink, "Data fetch failed").await;
                        return;
                    }
                };
            let decrypted_asset_contents = match asset_crypt::maybe_decrypt_asset_contents(
                asset_blob_cache.clone(),
                asset_keyring.clone(),
                &api_client,
                username.map(|s| KeyRecipient::User(s.to_string())).as_ref(),
                &data_contents,
                md_contents.as_deref(),
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: failed to decrypt: {}", e);
                    return;
                }
            };
            match api_client.asset_get(asset_arg).await {
                Ok(res) => {
                    if let Some(_data_url) = res.entry.asset.url.as_ref()
                        && let Some(_hash) = res.entry.asset.hash.as_ref()
                    {
                        let resp_ok: ClientMessageResponse<
                            asset::AssetGetResult,
                            asset::AssetGetError,
                        > = ClientMessageResponse::Ok {
                            result: res,
                            payload_count: 1,
                        };
                        let json_string = serde_json::to_string(&resp_ok)
                            .expect("Failed to re-serialize response");
                        let _ = ws_sink
                            .send(Message::Text(Utf8Bytes::from(&json_string)))
                            .await;
                        let _ = ws_sink
                            .send(Message::Binary(Bytes::from(decrypted_asset_contents)))
                            .await;
                    } else {
                        // Asset with no contents
                        send_response::<_, asset::AssetGetError>(ws_sink, Ok(res), 0).await;
                    }
                }
                Err(e) => {
                    send_error_response(ws_sink, e).await;
                }
            }
        }
        "asset/put" => {
            // NOTE: Cannot use `serde_json::from_value` here b/c of custom deserialization
            let asset_arg: asset::AssetPutArg = match serde_json::from_str(&arg.to_string()) {
                Ok(arg) => arg,
                Err(_e) => {
                    send_bad_request_error(ws_sink, "Invalid argument for asset/put").await;
                    return;
                }
            };
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
            if let Ok(Some(new_entry)) = reply_rx.await {
                send_response::<asset::AssetEntry, asset::AssetPutError>(ws_sink, Ok(new_entry), 0)
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
                    send_bad_request_error(ws_sink, "Invalid argument for asset/put_text").await;
                    return;
                }
            };

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
            if let Ok(Some(new_entry)) = reply_rx.await {
                send_response::<asset::AssetEntry, asset::AssetPutError>(ws_sink, Ok(new_entry), 0)
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
