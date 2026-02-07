use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
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
use crate::{asset_async_writer, asset_reader, feature::asset_crypt};

pub type ClientId = u64;
pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<std::collections::HashMap<ClientId, Client>>>;

// -- Minimal HTTP parsing/response helpers --

struct HttpRequest {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, String>,
}

impl HttpRequest {
    async fn parse(stream: &mut BufReader<&mut tokio::net::TcpStream>) -> Option<Self> {
        let mut request_line = String::new();
        if stream.read_line(&mut request_line).await.ok()? == 0 {
            return None;
        }

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();

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

        Some(HttpRequest {
            method,
            path,
            headers,
        })
    }

    fn bearer_token(&self) -> Option<&str> {
        self.headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
    }
}

struct HttpResponse {
    status: u16,
    status_text: &'static str,
    content_type: String,
    body: Vec<u8>,
}

impl HttpResponse {
    fn ok(body: Vec<u8>, content_type: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK",
            content_type: content_type.to_string(),
            body,
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            status_text: "Not Found",
            content_type: "text/plain".into(),
            body: b"Not Found".to_vec(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: 401,
            status_text: "Unauthorized",
            content_type: "text/plain".into(),
            body: b"Unauthorized".to_vec(),
        }
    }

    fn bad_request(msg: &str) -> Self {
        Self {
            status: 400,
            status_text: "Bad Request",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
        }
    }

    fn internal_error(msg: &str) -> Self {
        Self {
            status: 500,
            status_text: "Internal Server Error",
            content_type: "text/plain".into(),
            body: msg.as_bytes().to_vec(),
        }
    }

    async fn write_to(self, stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.status_text,
            self.content_type,
            self.body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&self.body).await?;
        stream.flush().await?;
        Ok(())
    }
}

// -- Check if request is WebSocket upgrade --

fn is_websocket_upgrade(headers: &std::collections::HashMap<String, String>) -> bool {
    headers
        .get("upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
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
        "WebSocket gateway listening on ws://{} auth token: {}",
        local_addr, token
    );

    // Spawn the server loop as a background task
    let clients: Clients = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let clients_clone = clients.clone();
    let cancel_token = CancellationToken::new();
    let cancel_token_child = cancel_token.child_token();
    let token_clone = token.clone();
    let api_client_clone = api_client.clone();
    let asset_keyring_clone = asset_keyring.clone();

    let asset_blob_cache_cloned = asset_blob_cache.clone();

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
                    let (mut stream, _peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("Accept error: {:?}", e);
                            continue;
                        }
                    };

                    let _ = stream.set_nodelay(true);

                    let token_clone_inner = token_clone.clone();
                    let api_client_clone_inner = api_client_clone.clone();
                    let asset_blob_cache_cloned_cloned = asset_blob_cache_cloned.clone();
                    let asset_keyring_clone_inner = asset_keyring_clone.clone();

                    tokio::spawn(async move {
                        // Peek at the request to determine if it's WebSocket or HTTP
                        let mut buf_reader = BufReader::new(&mut stream);

                        // Parse the HTTP request first
                        let request = match HttpRequest::parse(&mut buf_reader).await {
                            Some(req) => req,
                            None => return,
                        };

                        if is_websocket_upgrade(&request.headers) {
                            // It's a WebSocket upgrade - reconstruct the request and hand off
                            // We need to create a new stream since we consumed part of it
                            // For simplicity, we'll reject and ask client to reconnect cleanly
                            // OR we can use the already-parsed info

                            // Actually, for WebSocket we need the raw stream, so let's handle this differently
                            // We'll drop the buf_reader and use the stream directly
                            drop(buf_reader);

                            // Unfortunately we already consumed the HTTP upgrade request
                            // The cleanest approach is to handle WS separately or use hyper
                            // For quick-and-dirty: just close and let client retry on a different path

                            // Alternative: reconstruct and use tokio-tungstenite's server_accept
                            // For now, let's just handle HTTP and keep WS on a separate check

                            // HACK: For this quick version, we'll just return an error
                            // In production, you'd want to handle this properly
                            let _ = HttpResponse::bad_request("WebSocket upgrade not supported on this path, use raw connection")
                                .write_to(&mut stream)
                                .await;
                            return;
                        }

                        // It's a regular HTTP request
                        let response = handle_http_request(
                            &request,
                            &token_clone_inner,
                            asset_blob_cache_cloned_cloned.clone(),
                            asset_keyring_clone_inner.clone(),
                            &api_client_clone_inner,
                        ).await;

                        let _ = response.write_to(&mut stream).await;
                    });
                }
            }
        }
    });

    // Spawn a separate WebSocket-only listener (quick fix for the peek issue)
    let ws_port = port + 1000; // Use a different port for WS
    let ws_listener = TcpListener::bind(format!("127.0.0.1:{}", ws_port)).await?;
    let ws_addr = ws_listener.local_addr()?;
    println!("WebSocket-only listener on ws://{}", ws_addr);

    let clients_clone_ws = clients.clone();
    let cancel_token_child_ws = cancel_token.child_token();
    let token_clone_ws = token.clone();
    let username_clone_ws = username.map(|s| s.to_string());
    let asset_blob_cache_ws = asset_blob_cache.clone();
    let api_client_ws = api_client.clone();
    let update_asset_tx_ws = update_asset_tx.clone();
    let asset_keyring_ws = asset_keyring.clone();
    let next_client_id_ws = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000)); // Different range

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token_child_ws.cancelled() => {
                    break;
                }
                accept_result = ws_listener.accept() => {
                    let (stream, _peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("WebSocket accept error: {:?}", e);
                            continue;
                        }
                    };

                    let _ = stream.set_nodelay(true);

                    let mut ws_stream = match accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            eprintln!("WebSocket handshake error: {:?}", e);
                            continue;
                        }
                    };

                    let clients_clone_inner = clients_clone_ws.clone();
                    let token_clone_inner = token_clone_ws.clone();
                    let api_client_cloned = api_client_ws.clone();
                    let username_clone_inner = username_clone_ws.clone();
                    let update_asset_tx_cloned = update_asset_tx_ws.clone();
                    let client_id = next_client_id_ws.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let asset_blob_cache_cloned = asset_blob_cache_ws.clone();
                    let asset_keyring_cloned = asset_keyring_ws.clone();

                    tokio::spawn(async move {
                        // WebSocket authentication and handling (same as before)
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ws_stream.next()
                        ).await {
                            Ok(Some(Ok(Message::Text(msg)))) => {
                                let auth_msg: ClientMessageAuthRequest = match serde_json::from_str(&msg) {
                                    Ok(m) => m,
                                    Err(_e) => {
                                        let _ = ws_stream
                                            .send(Message::Text(Utf8Bytes::from(&serde_json::to_string(&ClientMessageAuthResponse::BadRequest).unwrap())))
                                            .await;
                                        let _ = ws_stream.close(None).await;
                                        return;
                                    }
                                };
                                if auth_msg.token != token_clone_inner {
                                    let _ = ws_stream
                                        .send(Message::Text(Utf8Bytes::from(&serde_json::to_string(&ClientMessageAuthResponse::BadToken).unwrap())))
                                        .await;
                                    let _ = ws_stream.close(None).await;
                                    return;
                                }
                            }
                            _ => {
                                let _ = ws_stream
                                    .send(Message::Text(Utf8Bytes::from(&serde_json::to_string(&ClientMessageAuthResponse::BadRequest).unwrap())))
                                    .await;
                                let _ = ws_stream.close(None).await;
                                return;
                            }
                        }

                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                        clients_clone_inner.lock().await.insert(client_id, tx);

                        let (mut ws_sink, mut ws_stream) = ws_stream.split();

                        let _ = ws_sink
                            .send(Message::Text(Utf8Bytes::from(&serde_json::to_string(&ClientMessageAuthResponse::Ok {
                                version: env!("CARGO_PKG_VERSION").into(),
                            }).unwrap())))
                            .await;

                        let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
                        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                        loop {
                            tokio::select! {
                                _ = ping_interval.tick() => {
                                    if ws_sink.send(Message::Ping(Bytes::from_static(b"ping"))).await.is_err() {
                                        break;
                                    }
                                }
                                Some(msg) = rx.recv() => {
                                    if ws_sink.send(msg).await.is_err() {
                                        break;
                                    }
                                }
                                msg_option = ws_stream.next() => {
                                    match msg_option {
                                        Some(Ok(Message::Text(msg))) => {
                                            handle_client_message(
                                                asset_blob_cache_cloned.clone(),
                                                asset_keyring_cloned.clone(),
                                                &api_client_cloned,
                                                username_clone_inner.as_deref(),
                                                update_asset_tx_cloned.clone(),
                                                &mut ws_sink,
                                                &msg
                                            ).await;
                                        }
                                        Some(Ok(Message::Binary(_data))) => {}
                                        Some(Ok(Message::Close(_))) => break,
                                        Some(Ok(Message::Ping(data))) => {
                                            let _ = ws_sink.send(Message::Pong(data)).await;
                                        }
                                        Some(Ok(Message::Pong(_))) => {}
                                        Some(Ok(_)) => {}
                                        Some(Err(_)) => break,
                                        None => break,
                                    }
                                }
                            }
                        }

                        clients_clone_inner.lock().await.remove(&client_id);
                    });
                }
            }
        }
    });

    Ok((local_addr, clients, cancel_token, token))
}

// -- HTTP request handler --

async fn handle_http_request(
    request: &HttpRequest,
    expected_token: &str,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<crate::feature::asset_keyring::AssetKeyring>>,
    api_client: &HaiClient,
) -> HttpResponse {
    // Check authorization
    // FIXME: Bring back... maybe initial one doesn't need auth?
    /*match request.bearer_token() {
        Some(token) if token == expected_token => {}
        Some(_) => return HttpResponse::unauthorized(),
        None => return HttpResponse::unauthorized(),
    }*/

    // Only handle GET for now
    if request.method != "GET" {
        return HttpResponse::bad_request("Only GET supported");
    }

    // Parse the path (strip leading slash)
    //let path = request.path.trim_start_matches('/');
    //let asset_name = request.path;

    let path = {
        let p = request.path.trim_start_matches("/~/");
        let mut end = p.len();
        if let Some(i) = p.find('?') { end = std::cmp::min(end, i); }
        if let Some(i) = p.find('#') { end = std::cmp::min(end, i); }
        &p[..end]
    };

    // URL decode the path
    let asset_name = match urlencoding::decode(path) {
        Ok(p) => p.into_owned(),
        Err(_) => return HttpResponse::bad_request("Invalid URL encoding"),
    };

    // TODO: Use decoded_path to proxy to cloud storage and fetch the file
    // Example: let file_contents = fetch_from_cloud_storage(&decoded_path).await;
    // For now, just return the path as a placeholder
    println!("HI HI HI: requested asset: {} {}", path, asset_name);

    //let source_asset_name = resolve_asset_name(source_asset_name, session);

    // Special case if target is `.`
    /*let target_file_path = if target_file_path == "." {
        match source_asset_name.rsplit('/').next() {
            Some(filename) => filename.to_string(),
            None => source_asset_name.clone(), // If no slashes
        }
    } else {
        target_file_path.to_owned()
    };
    let target_file_path = match shellexpand::full(&target_file_path) {
        Ok(s) => s.into_owned(),
        Err(e) => {
            eprintln!("error: undefined path variable: {}", e.var_name);
            return ProcessCmdResult::Loop;
        }
    };*/
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
    let content_type = crate::asset_helper::best_guess_temp_file_extension(&asset_name, asset_content_type.as_deref(), &decrypted_asset_contents);

    // Placeholder response
    HttpResponse::ok(
        //format!("Would fetch: {}", decoded_path).into_bytes(),
        decrypted_asset_contents,
        &content_type,
    )
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageAuthRequest {
    token: String,
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
            let akm_info = if let Some(username) = username {
                match asset_crypt::choose_akm_for_asset_by_name(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client.clone(),
                    &username,
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
                }
            } else {
                None
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

            let akm_info = if let Some(username) = username {
                match asset_crypt::choose_akm_for_asset_by_name(
                    asset_blob_cache.clone(),
                    asset_keyring.clone(),
                    api_client.clone(),
                    &username,
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
                }
            } else {
                None
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
