use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_util::sync::CancellationToken;

use crate::io::Io;

pub async fn execute_html_tool(
    io: &Io,
    session: &mut crate::session::SessionState,
    is_task_mode_step: bool,
    input: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let html = extract_html_from_fn_arg(input)?;
    let new_browser = session.html_output.is_none();
    if new_browser {
        let (temp_file, temp_file_path) = create_empty_temp_file()
            .map_err(|e| format!("error: failed to create temporary output file: {}", e))?;
        let (addr, clients, cancel_token) = html_output_server(temp_file_path).await?;
        session.html_output = Some((temp_file, is_task_mode_step, addr, clients, cancel_token));
    }

    let (temp_file_path, addr) = {
        let (temp_file, _, addr, _, _) =
            session.html_output.as_mut().expect("html_output set above");
        // Hot-reload script is injected when the HTML is served, not in the
        // file itself (see `inject_hot_reload`).
        temp_file.as_file_mut().set_len(0)?;
        temp_file.as_file_mut().seek(SeekFrom::Start(0))?;
        temp_file.write_all(html.as_bytes())?;
        temp_file.flush()?;
        (temp_file.path().to_string_lossy().to_string(), *addr)
    };

    if new_browser {
        // `addr` is 127.0.0.1 (not localhost) to isolate it from asset-apps
        let url = format!("http://{}/", addr);
        // Opened only after the first write so the initial load isn't empty.
        if let Err(e) = io.open_url(&url) {
            if let Some((.., cancel_token)) = session.html_output.take() {
                cancel_token.cancel();
            }
            return Err(format!("error: failed to open browser: {}", e).into());
        }
    } else if let Some((_, _, _, clients, _)) = session.html_output.as_mut() {
        notify_clients(clients, "reload");
    }

    Ok(temp_file_path)
}

/// Create an empty temporary file for HTML output.
fn create_empty_temp_file() -> Result<(tempfile::NamedTempFile, PathBuf), String> {
    let temp_file = tempfile::Builder::new()
        .prefix("hai_")
        .suffix(".html")
        .tempfile()
        .map_err(|e| format!("Failed to create temporary file: {}", e))?;

    // Get the path to the temporary file
    let temp_file_path = temp_file.path().to_path_buf();

    Ok((temp_file, temp_file_path))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct HtmlToolFnArg {
    input: String,
}

pub fn extract_html_from_fn_arg(arg: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str::<HtmlToolFnArg>(arg)?.input)
}

pub type Client = UnboundedSender<Message>;
pub type Clients = Arc<Mutex<Vec<Client>>>;

/// Serves the HTML output file and its hot-reload websocket on one port:
///
/// - `GET /` returns the current contents of `html_path`.
/// - A websocket upgrade (any path) registers a hot-reload client.
pub async fn html_output_server(
    html_path: PathBuf,
) -> std::io::Result<(SocketAddr, Clients, CancellationToken)> {
    let mut port = 1339;
    let listener = loop {
        let addr = format!("127.0.0.1:{}", port);
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(_) => port += 1,
        }
    };
    let local_addr = listener.local_addr()?;

    // Spawn the server loop as a background task
    let clients: Clients = Arc::new(Mutex::new(Vec::new()));
    let clients_clone = clients.clone();
    let cancel_token = CancellationToken::new();
    let cancel_token_child = cancel_token.child_token();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token_child.cancelled() => {
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, _) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::error!("html output server accept error: {:?}", e);
                            continue;
                        }
                    };
                    let clients = clients_clone.clone();
                    let html_path = html_path.clone();
                    let cancel = cancel_token_child.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => {}
                            _ = handle_conn(stream, &html_path, clients) => {}
                        }
                    });
                }
            }
        }
    });

    Ok((local_addr, clients, cancel_token))
}

async fn handle_conn(stream: TcpStream, html_path: &Path, clients: Clients) {
    let Some((head_len, head)) = peek_request_head(&stream).await else {
        return;
    };
    if is_websocket_upgrade(&head) {
        let mut ws = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                tracing::error!("WebSocket handshake error: {:?}", e);
                return;
            }
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        clients.lock().unwrap().push(tx);
        while let Some(msg) = rx.recv().await {
            if ws.send(msg).await.is_err() {
                break;
            }
        }
    } else {
        serve_html(stream, head_len, &head, html_path).await;
    }
}

/// Peeks (without consuming, so the websocket handshake can still read it)
/// the request head through the blank line. Returns its byte length and text.
async fn peek_request_head(stream: &TcpStream) -> Option<(usize, String)> {
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_n = 0;
    loop {
        let n = tokio::time::timeout_at(deadline, stream.peek(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        if let Some(end) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let len = end + 4;
            return Some((len, String::from_utf8_lossy(&buf[..len]).into_owned()));
        }
        if n == buf.len() || tokio::time::Instant::now() >= deadline {
            return None;
        }
        if n == last_n {
            // peek returns immediately while unread data is buffered; avoid
            // spinning while the rest of the head arrives.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        last_n = n;
    }
}

fn is_websocket_upgrade(head: &str) -> bool {
    head.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("upgrade")
                && value.to_ascii_lowercase().contains("websocket")
        })
    })
}

async fn serve_html(mut stream: TcpStream, head_len: usize, head: &str, html_path: &Path) {
    // Finish consuming request head
    let mut discard = vec![0u8; head_len];
    if stream.read_exact(&mut discard).await.is_err() {
        return;
    }
    let mut parts = head.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let page = if method == "GET" && (path == "/" || path.starts_with("/?")) {
        tokio::fs::read(html_path).await.ok()
    } else {
        None
    };
    let (status, content_type, body) = match page {
        Some(body) => (
            "200 OK",
            "text/html; charset=utf-8",
            inject_hot_reload(body),
        ),
        None => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.shutdown().await;
}

/// Reloads the page on any message from the server's websocket.
const HOT_RELOAD_SCRIPT: &str = r#"<script>(function(){var ws=new WebSocket("ws://"+location.host+"/");ws.onmessage=function(){location.reload();};})();</script>"#;

/// Inserts the hot-reload script into the HTML.
fn inject_hot_reload(html: Vec<u8>) -> Vec<u8> {
    let pos = find_ascii_ci(&html, b"</head").unwrap_or_else(|| {
        let start = html
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        if html[start..].len() >= 9 && html[start..start + 9].eq_ignore_ascii_case(b"<!doctype") {
            html[start..]
                .iter()
                .position(|&b| b == b'>')
                .map_or(0, |i| start + i + 1)
        } else {
            0
        }
    });
    let mut out = Vec::with_capacity(html.len() + HOT_RELOAD_SCRIPT.len());
    out.extend_from_slice(&html[..pos]);
    out.extend_from_slice(HOT_RELOAD_SCRIPT.as_bytes());
    out.extend_from_slice(&html[pos..]);
    out
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn notify_clients(clients: &Arc<Mutex<Vec<Client>>>, msg: &str) {
    let mut to_remove = vec![];
    let mut clients_guard = clients.lock().unwrap();
    for (i, client) in clients_guard.iter().enumerate() {
        if client.send(Message::Text(Utf8Bytes::from(msg))).is_err() {
            to_remove.push(i);
        }
    }
    // Remove any clients that have disconnected
    for i in to_remove.into_iter().rev() {
        clients_guard.remove(i);
    }
}
