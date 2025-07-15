use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response},
};

use crate::db;

#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum Message {
    Push(PushMessage),
}

#[derive(Debug, Deserialize)]
pub struct PushMessage {
    pub queue_name: Option<String>,
    pub cmds: Vec<String>,
}

pub async fn listen(address: &str, whitelisted_origin: Option<String>) {
    let listener = TcpListener::bind(address).await.unwrap();
    println!("WebSocket server listening on ws://{}", address);

    let db = Arc::new(Mutex::new(db::open_db().expect("Failed to open database")));

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _) = match accept_result {
                    Ok(pair) => pair,
                    Err(e) => {
                        println!("Accept error: {e}");
                        continue;
                    }
                };
                let db = db.clone();
                let whitelisted_origin = whitelisted_origin.clone();
                tokio::spawn(async move {
                    let ws_stream = accept_hdr_async(stream, |req: &Request, response: Response| {
                        // Check the Origin header to prevent unwanted connections.
                        // FUTURE: Add an authorization check.
                        let req_origin = req.headers().get("origin").and_then(|h| h.to_str().ok());
                        println!("incoming: origin header: {:?}", req_origin);
                        if req_origin.is_none() || req_origin == whitelisted_origin.as_deref() {
                            Ok(response)
                        } else {
                            // Reject the connection
                            eprintln!("reject: bad host header: {:?}", req_origin);
                            Err(tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(Some("Forbidden: Invalid Host".into())))
                        }
                    })
                    .await;

                    let ws_stream = match ws_stream {
                        Ok(ws) => ws,
                        Err(e) => {
                            println!("rejected: {e}");
                            return;
                        }
                    };

                    let peer_addr = ws_stream.get_ref().peer_addr();

                    println!("established connection: {:?}", peer_addr);

                    let (mut write, mut read) = ws_stream.split();

                    while let Some(msg) = read.next().await {
                        let msg = match msg {
                            Ok(m) => m,
                            Err(e) => {
                                let _ = write
                                    .send(format!("error reading message: {e}").into())
                                    .await;
                                break;
                            }
                        };

                        if msg.is_text() {
                            let text = msg.into_text().unwrap();
                            match serde_json::from_str::<Message>(&text) {
                                Ok(message) => {
                                    println!("received message: {:?}", message);

                                    match &message {
                                        Message::Push(PushMessage { queue_name, cmds }) => {
                                            db::listen_queue_push(
                                                &*db.lock().await,
                                                &queue_name.as_ref().unwrap_or(&"".to_string()),
                                                &cmds,
                                            )
                                            .expect("Failed to push to queue");
                                        }
                                    }

                                    // Echo back a confirmation
                                    let reply = format!("Received: {:?}", message);
                                    let _ = write.send(reply.into()).await;
                                }
                                Err(e) => {
                                    let err_msg = format!("deserialization error: {e}");
                                    eprintln!("{err_msg}");
                                    let _ = write.send(err_msg.into()).await;
                                }
                            }
                        }
                    }
                    println!("closed connection: {:?}", peer_addr);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received, shutting down WebSocket server.");
                break;
            }
        }
    }
}
