use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};
use tokio_util::sync::CancellationToken;

use crate::api::client::HaiClient;
use crate::api::types::asset;

pub type ClientId = u64;
pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<std::collections::HashMap<ClientId, Client>>>;

pub async fn launch_gateway(
    api_client: HaiClient,
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

    // Client ID counter
    let next_client_id = Arc::new(std::sync::atomic::AtomicU64::new(0));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token_child.cancelled() => {
                    let mut clients_guard = clients_clone.lock().unwrap();
                    for (_id, client) in clients_guard.drain() {
                        drop(client);
                    }
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, _peer_addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("WebSocket accept error: {:?}", e);
                            continue;
                        }
                    };

                    // Set TCP keepalive to detect dead connections
                    let _ = stream.set_nodelay(true);

                    let mut ws_stream = match accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            // Handeshake error
                            eprintln!("WebSocket handshake error: {:?}", e);
                            continue;
                        }
                    };

                    let clients_clone_inner = clients_clone.clone();
                    let token_clone_inner = token_clone.clone();
                    let api_client_cloned = api_client.clone();
                    let client_id = next_client_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    tokio::spawn(async move {
                        // Wait for the first message which should contain the auth token
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

                        // Client is authenticated, create channel and add to clients list
                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                        clients_clone_inner.lock().unwrap().insert(client_id, tx);

                        let (mut ws_sink, mut ws_stream) = ws_stream.split();

                        // Send acknowledgment that auth succeeded
                        let _ = ws_sink
                            .send(Message::Text(Utf8Bytes::from(&serde_json::to_string(&ClientMessageAuthResponse::Ok).unwrap())))
                            .await;

                        // Ping interval to keep connection alive
                        let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
                        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                        // Handle bidirectional communication
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
                                            handle_client_message(&api_client_cloned, &mut ws_sink, &msg).await;
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
                        clients_clone_inner.lock().unwrap().remove(&client_id);
                    });
                }
            }
        }
    });

    Ok((local_addr, clients, cancel_token, token))
}

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMessageAuthRequest {
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessageAuthResponse {
    Ok,
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
    api_client: &HaiClient,
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

            match api_client.asset_get(asset_arg).await {
                Ok(res) => {
                    if let Some(data_url) = res.entry.asset.url.as_ref() {
                        match crate::asset_editor::download_asset(data_url).await {
                            Ok(contents) => {
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
                                let _ = ws_sink.send(Message::Binary(Bytes::from(contents))).await;
                            }
                            Err(crate::asset_editor::DownloadAssetError::DataFetchFailed) => {
                                send_http_error::<asset::AssetGetError>(
                                    ws_sink,
                                    "Data fetch failed",
                                )
                                .await;
                            }
                        }
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

            send_response(ws_sink, api_client.asset_put(asset_arg).await, 0).await;
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

            send_response(ws_sink, api_client.asset_put_text(asset_arg).await, 0).await;
        }
        _other => {
            send_bad_request_error(ws_sink, "Unknown route").await;
        }
    }
}
