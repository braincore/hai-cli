use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_util::sync::CancellationToken;

pub async fn execute_html_tool(
    session: &mut crate::session::SessionState,
    is_task_mode_step: bool,
    input: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let html_body = extract_html_from_fn_arg(input)?;
    let (new_browser, temp_file_path) = if let Some((temp_file, ..)) = &session.html_output {
        // If the session already has an HTML output, we will not create a new browser
        (false, temp_file.path().to_string_lossy().to_string())
    } else {
        let (hot_reload_addr, clients, cancel_token) = hot_reload_websocket_server().await?;
        let temp_file_path = match create_empty_temp_file() {
            Ok((temp_file, temp_file_path)) => {
                start_browser(temp_file_path.to_str().unwrap())
                    .map_err(|e| format!("error: failed to open browser: {}", e))?;
                session.html_output = Some((
                    temp_file,
                    is_task_mode_step,
                    hot_reload_addr.clone(),
                    clients,
                    cancel_token,
                ));
                temp_file_path.clone()
            }
            Err(e) => {
                return Err(format!("error: failed to create temporary output file: {}", e).into());
            }
        };
        (true, temp_file_path.to_string_lossy().to_string())
    };

    if let Some((temp_file, _, hot_reload_addr, _, _)) = session.html_output.as_mut() {
        let hot_reload_ws_url = format!("ws://{}/", hot_reload_addr);
        let wrapped_output = format!(
            r#"<html>
<head>
    <title>hai</title>
    <script>
        (function() {{
            var ws = new WebSocket("{hot_reload_ws_url}");
            ws.onmessage = function(event) {{
                // Reload the page when any message is received
                location.reload();
            }};
        }})();
    </script>
</head>
{}
</html>"#,
            html_body
        );

        // Truncate the file to 5 bytes
        temp_file.as_file_mut().set_len(5)?;

        // Seek to start and read back
        temp_file.as_file_mut().seek(SeekFrom::Start(0))?;

        temp_file.write_all(wrapped_output.as_bytes())?;
        temp_file.flush()?;
    }

    if !new_browser {
        if let Some((_, _, _, clients, _)) = session.html_output.as_mut() {
            notify_clients(&clients, "reload");
        }
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

fn start_browser(temp_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Windows: Necessary for browser to open a file that's already open for
    // writing by this process. Also, requires `shellexecute-on-windows`
    // feature for `open` crate.
    Ok(open::that_detached(temp_file_path)?)
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

pub async fn hot_reload_websocket_server()
-> std::io::Result<(SocketAddr, Clients, CancellationToken)> {
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
                    // Optionally: clean up, close connections, etc.
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, _) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("WebSocket accept error: {:?}", e);
                            continue;
                        }
                    };
                    let ws_stream = match accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            eprintln!("WebSocket handshake error: {:?}", e);
                            continue;
                        }
                    };
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
                    clients_clone.lock().unwrap().push(tx);

                    let mut ws_sink = ws_stream;
                    tokio::spawn(async move {
                        // FUTURE: Consider adding another cancellation token
                        // for this forwarding task.
                        while let Some(msg) = rx.recv().await {
                            let _ = ws_sink.send(msg).await;
                        }
                    });
                }
            }
        }
    });

    Ok((local_addr, clients, cancel_token))
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
