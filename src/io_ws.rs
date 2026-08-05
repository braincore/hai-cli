use serde::{Deserialize, Serialize};

/// Server -> client.
#[derive(Serialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ServerMsg {
    Out {
        text: String,
    },
    Err {
        text: String,
    },
    Alert {
        level: String,
        text: String,
    },
    Display {
        mime: String,
        data: String,
    },
    Code {
        text: String,
        lang: Option<String>,
        bg: Option<(u8, u8, u8)>,
    },
    /// Prompt the client for input (a `Query`).
    Query {
        id: u64,
        message: String,
        kind: String,
        secret: bool,
    },
    /// Kernel is ready for the next REPL cell.
    ReplPrompt {
        id: u64,
    },
}

/// Client -> server.
#[derive(Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Answer to a `Query` or `ReplPrompt`. `text: None` means
    /// cancelled/eof.
    Answer { id: u64, text: Option<String> },
    /// Client-initiated eval (notebook-style push).
    Eval { input: String },
}

use crate::io::{Answer, Level, Query};

pub enum WsCmd {
    // From WsOutput. Fire-and-forget.
    Out(String),
    Err(String),
    Alert {
        level: Level,
        text: String,
    },
    Display {
        mime: String,
        data: String,
    },
    Code {
        text: String,
        lang: Option<String>,
        bg: Option<(u8, u8, u8)>,
    },

    // From WsInput. Blocking: actor holds `reply` until the client answers.
    Query {
        q: Query,
        reply: std::sync::mpsc::Sender<Answer>,
    },
    ReplLine {
        reply: std::sync::mpsc::Sender<Answer>,
    },
}

use crate::io::{OutOfBandStream, Output, TerminalCapability};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone)]
pub struct WsOutput {
    cmd: UnboundedSender<WsCmd>,
}

impl WsOutput {
    pub fn new(cmd: UnboundedSender<WsCmd>) -> Self {
        WsOutput { cmd }
    }
    fn send(&self, cmd: WsCmd) {
        // If the actor is gone, silently drop; the kernel keeps running.
        let _ = self.cmd.send(cmd);
    }
}

impl Output for WsOutput {
    fn push_out(&mut self, s: &str) {
        self.send(WsCmd::Out(s.to_string()));
    }
    fn push_err(&mut self, s: &str) {
        self.send(WsCmd::Err(s.to_string()));
    }
    // push_flush: no-op. Nothing is buffered on this side; the actor owns
    // buffering, and a WebSocket frame is sent whole.

    fn push_alert(&mut self, level: Level, msg: &str) {
        self.send(WsCmd::Alert {
            level,
            text: msg.to_string(),
        });
    }

    fn push_display(&mut self, mime: &str, data: &str) {
        self.send(WsCmd::Display {
            mime: mime.to_string(),
            data: data.to_string(),
        });
    }

    // The whole point of the web backend: send the UN-rendered source and
    // let the browser highlight. So we override push_code_bg (not push_code)
    // to carry lang + bg over the wire.
    fn push_code_bg(&mut self, text: &str, lang: Option<&str>, bg: Option<(u8, u8, u8)>) {
        self.send(WsCmd::Code {
            text: text.to_string(),
            lang: lang.map(str::to_string),
            bg,
        });
    }

    // push_out_of_band: this backend IS blind to the caller's raw stdout
    // writes (the caller printed to a local terminal, not our socket), so we
    // SHOULD emit, per the trait contract.
    fn push_out_of_band(&mut self, s: &str, stream: OutOfBandStream) {
        match stream {
            OutOfBandStream::Out => self.send(WsCmd::Out(s.to_string())),
            OutOfBandStream::Err => self.send(WsCmd::Err(s.to_string())),
        }
    }

    // push_terminal_transient: default false. Not a cursor terminal.

    fn terminal_capability(&self) -> TerminalCapability {
        TerminalCapability::None
    }
}

use crate::io::Input;

pub struct WsInput {
    cmd: UnboundedSender<WsCmd>,
}

impl WsInput {
    pub fn new(cmd: UnboundedSender<WsCmd>) -> Self {
        WsInput { cmd }
    }
}

impl Input for WsInput {
    fn ask(&mut self, q: &Query) -> Answer {
        let (reply, rx) = std::sync::mpsc::channel();
        if self
            .cmd
            .send(WsCmd::Query {
                q: q.clone(),
                reply,
            })
            .is_err()
        {
            return Answer::Eof;
        }
        rx.recv().unwrap_or(Answer::Eof)
    }

    fn next_repl(&mut self) -> Answer {
        let (reply, rx) = std::sync::mpsc::channel();
        if self.cmd.send(WsCmd::ReplLine { reply }).is_err() {
            return Answer::Eof;
        }
        rx.recv().unwrap_or(Answer::Eof)
    }

    fn drives_repl(&self) -> bool {
        true
    }
}

// --

use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, VecDeque};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, UnboundedReceiver};

/// A blocking input request the actor is holding open.
pub struct Pending {
    reply: std::sync::mpsc::Sender<Answer>,
    // What to (re)send to a client. None => this is a ReplLine.
    query: Option<Query>,
}

pub struct WsActor {
    listener: TcpListener,
    //pub addr: String,
    //pub origin: Option<String>,
    pub token: String,
    pub cmd_rx: UnboundedReceiver<WsCmd>,

    // The live connection's write half, as a channel to its writer task.
    pub conn_tx: Option<UnboundedSender<String>>,
    // Inbound messages from the live connection.
    pub conn_rx: Option<UnboundedReceiver<String>>,

    // Output produced while nobody was connected (or full scrollback).
    // Replayed on connect.
    pub buffer: VecDeque<String>,

    // In-flight blocking input requests, keyed by id.
    pub pending: HashMap<u64, Pending>,
    pub next_id: u64,

    // Client-pushed evals waiting to satisfy the next `next_repl`.
    pub eval_queue: VecDeque<String>,
    // If next_repl is parked with no eval ready, its id lives in pending;
    // remember it so a pushed Eval can satisfy it directly.
    pub repl_waiter: Option<u64>,

    /// For idle self-exit. `None` while a client is connected.
    idle_since: Option<tokio::time::Instant>,
    /// Whether any client has EVER connected. Distinguishes "never used,
    /// abandoned spawn" from "used, then disconnected".
    ever_connected: bool,
}

impl WsActor {
    pub fn new(
        listener: TcpListener,
        //addr: String,
        token: String,
        cmd_rx: UnboundedReceiver<WsCmd>,
    ) -> Self {
        Self {
            //addr,
            listener,
            token,
            cmd_rx,
            conn_tx: None,
            conn_rx: None,
            buffer: VecDeque::new(),
            pending: HashMap::new(),
            next_id: 0,
            eval_queue: VecDeque::new(),
            repl_waiter: None,
            idle_since: None,
            ever_connected: false,
        }
    }

    /*
    pub async fn run(mut self) {
        let listener = TcpListener::bind(&self.addr).await.expect("bind failed");
        println!("kernel listening on ws://{}", self.addr);

        loop {
            // Only accept when nobody's connected (single-session kernel).
            let can_accept = self.conn_tx.is_none();

            tokio::select! {
                // 1. Commands from the sync backends.
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.on_cmd(cmd),
                        None => break, // all backends dropped; kernel done
                    }
                }

                // 2. A new client wants in.
                accept = listener.accept(), if can_accept => {
                    if let Ok((stream, _)) = accept {
                        self.on_connect(stream).await;
                    }
                }

                // 3. A message from the current client.
                Some(text) = recv_opt(&mut self.conn_rx), if self.conn_rx.is_some() => {
                    self.on_client_msg(text);
                }

                // 3b. Detect disconnect: recv_opt yields None.
                else => {
                    if self.conn_rx.is_some() {
                        self.on_disconnect();
                    }
                }
            }
        }
    }
    */
    pub async fn run(mut self) {
        // Idle-exit policy.
        const BOOT_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
        const DISCONNECT_GRACE: std::time::Duration = std::time::Duration::from_secs(300);

        loop {
            let can_accept = self.conn_tx.is_none();

            // Compute the idle deadline for this iteration, if idle.
            let idle_deadline = self.idle_since.map(|since| {
                let grace = if self.ever_connected {
                    DISCONNECT_GRACE
                } else {
                    BOOT_GRACE
                };
                since + grace
            });

            tokio::select! {
                // 1. Commands from the sync backends.
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.on_cmd(cmd),
                        None => break, // all backends dropped; kernel done
                    }
                }

                // 2. A new client wants in. Auth happens inside on_connect.
                accept = self.listener.accept(), if can_accept => {
                    if let Ok((stream, _)) = accept {
                        self.on_connect(stream).await;
                    }
                }

                // 3. A message from the current client.
                Some(text) = recv_opt(&mut self.conn_rx), if self.conn_rx.is_some() => {
                    self.on_client_msg(text);
                }

                // 4. Idle timeout: nobody connected for too long -> exit.
                _ = sleep_until_opt(idle_deadline), if idle_deadline.is_some() => {
                    eprintln!("kernel: idle timeout, exiting");
                    break;
                }

                // 5. Disconnect detection.
                else => {
                    if self.conn_rx.is_some() {
                        self.on_disconnect();
                    }
                }
            }
        }
    }
}

// Helper so `select!` can await an Option<Receiver> uniformly.
async fn recv_opt(r: &mut Option<UnboundedReceiver<String>>) -> Option<String> {
    match r {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Sleep until an optional deadline; pend forever if None.
async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

impl WsActor {
    fn on_cmd(&mut self, cmd: WsCmd) {
        match cmd {
            WsCmd::Out(text) => self.emit(ServerMsg::Out { text }),
            WsCmd::Err(text) => self.emit(ServerMsg::Err { text }),
            WsCmd::Alert { level, text } => self.emit(ServerMsg::Alert {
                level: level.label().to_string(),
                text,
            }),
            WsCmd::Display { mime, data } => self.emit(ServerMsg::Display { mime, data }),
            WsCmd::Code { text, lang, bg } => self.emit(ServerMsg::Code { text, lang, bg }),

            WsCmd::Query { q, reply } => {
                let id = self.alloc_id();
                let msg = ServerMsg::Query {
                    id,
                    message: q.message.clone(),
                    kind: match q.kind {
                        crate::io::QueryKind::Line => "line".into(),
                        crate::io::QueryKind::Confirm => "confirm".into(),
                    },
                    secret: q.secret,
                };
                self.pending.insert(
                    id,
                    Pending {
                        reply,
                        query: Some(q),
                    },
                );
                self.emit(msg); // if disconnected, this buffers; resent on connect
            }

            WsCmd::ReplLine { reply } => {
                // If a client already pushed an eval, satisfy immediately.
                if let Some(code) = self.eval_queue.pop_front() {
                    let _ = reply.send(Answer::Text(code));
                    return;
                }
                let id = self.alloc_id();
                self.pending.insert(id, Pending { reply, query: None });
                self.repl_waiter = Some(id);
                self.emit(ServerMsg::ReplPrompt { id });
            }
        }
    }

    fn emit(&mut self, msg: ServerMsg) {
        let json = serde_json::to_string(&msg).unwrap();
        match &self.conn_tx {
            Some(tx) if tx.send(json.clone()).is_ok() => {}
            // No client, or send failed: buffer for replay on (re)connect.
            _ => self.buffer.push_back(json),
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl WsActor {
    fn on_client_msg(&mut self, text: String) {
        let msg: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("bad client msg: {e}");
                return;
            }
        };
        match msg {
            ClientMsg::Answer { id, text } => {
                if let Some(p) = self.pending.remove(&id) {
                    if self.repl_waiter == Some(id) {
                        self.repl_waiter = None;
                    }
                    let answer = match text {
                        Some(t) => Answer::Text(t),
                        None => Answer::Cancelled,
                    };
                    let _ = p.reply.send(answer);
                }
            }
            ClientMsg::Eval { input } => {
                // Satisfy a parked next_repl if there is one; else queue it.
                if let Some(id) = self.repl_waiter.take() {
                    if let Some(p) = self.pending.remove(&id) {
                        let _ = p.reply.send(Answer::Text(input));
                        return;
                    }
                }
                self.eval_queue.push_back(input);
            }
        }
    }
}

use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

impl WsActor {
    async fn on_connect(&mut self, stream: tokio::net::TcpStream) {
        let _ = stream.set_nodelay(true);

        let ws = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("kernel: handshake error: {e:?}");
                return;
            }
        };

        // Authenticate BEFORE wiring the socket into conn_tx/conn_rx.
        let ws = match authenticate(ws, &self.token).await {
            Ok(ws) => ws,
            Err(()) => return, // rejected + closed inside authenticate
        };

        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<String>();

        tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                if write.send(Message::Text(m.into())).await.is_err() {
                    break;
                }
            }
            let _ = write.close().await;
        });
        tokio::spawn(async move {
            while let Some(Ok(m)) = read.next().await {
                if m.is_text() {
                    if in_tx.send(m.into_text().unwrap().to_string()).is_err() {
                        break;
                    }
                } else if m.is_close() {
                    break;
                }
            }
        });

        self.conn_tx = Some(out_tx);
        self.conn_rx = Some(in_rx);

        // Reset since we have a client
        self.idle_since = None; // connected -> not idle
        self.ever_connected = true;

        // Replay buffered output + re-send pending prompts (as before).
        self.replay_backlog();
        self.resend_pending();
    }

    fn on_disconnect(&mut self) {
        self.conn_tx = None;
        self.conn_rx = None;
        self.idle_since = Some(tokio::time::Instant::now()); // start idle clock
        // Deliberately keep `pending` — reconnect resends them.
    }
}

impl WsActor {
    /// Flush everything buffered while disconnected to the now-live client.
    /// Called from on_connect, AFTER conn_tx is set.
    fn replay_backlog(&mut self) {
        let backlog: Vec<String> = self.buffer.drain(..).collect();
        for json in backlog {
            self.emit_now(&json);
        }
    }

    /// Send a pre-serialized frame directly to the live client, bypassing the
    /// buffer. Only valid when conn_tx is Some (i.e. from within on_connect
    /// or while connected).
    fn emit_now(&self, json: &str) {
        if let Some(tx) = &self.conn_tx {
            let _ = tx.send(json.to_string());
        }
    }
}

impl WsActor {
    /// Re-send all outstanding input requests to the reconnected client, so
    /// prompts issued before a disconnect don't get lost. Called from
    /// on_connect, AFTER conn_tx is set and AFTER replay_backlog.
    fn resend_pending(&mut self) {
        // Collect first to avoid borrowing self.pending while calling emit_now
        // (which borrows self). Cheap: pending is small (usually 0 or 1).
        let frames: Vec<String> = self
            .pending
            .iter()
            .map(|(id, p)| self.pending_frame(*id, p))
            .collect();

        for json in frames {
            self.emit_now(&json);
        }
    }

    /// Build the wire frame for a pending request (a Query or a ReplPrompt).
    fn pending_frame(&self, id: u64, p: &Pending) -> String {
        let msg = match &p.query {
            Some(q) => ServerMsg::Query {
                id,
                message: q.message.clone(),
                kind: match q.kind {
                    crate::io::QueryKind::Line => "line".to_string(),
                    crate::io::QueryKind::Confirm => "confirm".to_string(),
                },
                secret: q.secret,
            },
            None => ServerMsg::ReplPrompt { id },
        };
        serde_json::to_string(&msg).expect("serialize pending frame")
    }
}

/*
impl WsActor {
    async fn on_connect(&mut self, stream: tokio::net::TcpStream) {
        // (origin check via accept_hdr_async omitted for brevity — same as
        //  your existing handshake code)
        let ws = match tokio_tungstenite::accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("handshake failed: {e}");
                return;
            }
        };
        let (mut write, mut read) = ws.split();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<String>();

        // Writer task: drains out_rx to the socket.
        tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                if write.send(WsMessage::Text(m.into())).await.is_err() {
                    break;
                }
            }
            let _ = write.close().await;
        });
        // Reader task: forwards socket text into in_tx.
        tokio::spawn(async move {
            while let Some(Ok(m)) = read.next().await {
                if m.is_text() {
                    if in_tx.send(m.into_text().unwrap().to_string()).is_err() {
                        break;
                    }
                } else if m.is_close() {
                    break;
                }
            }
        });

        self.conn_tx = Some(out_tx);
        self.conn_rx = Some(in_rx);

        // 1. Replay everything the client missed while disconnected.
        let backlog: Vec<String> = self.buffer.drain(..).collect();
        for json in backlog {
            self.emit_now(&json);
        }

        // 2. Re-send any pending input requests, so a half-answered prompt
        //    survives a reconnect instead of aborting.
        let resend: Vec<(u64, Option<Query>)> = self
            .pending
            .iter()
            .map(|(id, p)| (*id, p.query.clone()))
            .collect();
        for (id, q) in resend {
            let msg = match q {
                Some(q) => ServerMsg::Query {
                    id,
                    message: q.message,
                    kind: match q.kind {
                        crate::io::QueryKind::Line => "line".into(),
                        crate::io::QueryKind::Confirm => "confirm".into(),
                    },
                    secret: q.secret,
                },
                None => ServerMsg::ReplPrompt { id },
            };
            let json = serde_json::to_string(&msg).unwrap();
            self.emit_now(&json);
        }
    }

    fn emit_now(&self, json: &str) {
        if let Some(tx) = &self.conn_tx {
            let _ = tx.send(json.to_string());
        }
    }

    fn on_disconnect(&mut self) {
        // DO NOT fail pending requests. Wait for next client.
        // Output will buffer.
        println!("client disconnected; kernel still running");
        self.conn_tx = None;
        self.conn_rx = None;
    }
}
*/

//use futures_util::{SinkExt, StreamExt};
use crate::feature::gateway::{ClientMessageAuthRequest, ClientMessageAuthResponse};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Utf8Bytes;

/// Authenticate a freshly-accepted websocket against the kernel token.
///
/// The first client message must be a `ClientMessageAuthRequest` carrying the
/// matching token, within 10s. On success, returns the stream (unconsumed
/// past the auth frame) so the caller can split it and begin serving. On any
/// failure, sends the appropriate `ClientMessageAuthResponse`, closes the
/// socket, and returns `Err(())`.
///
/// Mirrors the gateway's token handshake so the web client has ONE auth
/// implementation regardless of which server it's talking to.
async fn authenticate(
    mut ws_stream: WebSocketStream<tokio::net::TcpStream>,
    token: &str,
) -> Result<WebSocketStream<tokio::net::TcpStream>, ()> {
    // Helper: send a response, close, and give up.
    async fn reject(
        mut ws: WebSocketStream<tokio::net::TcpStream>,
        resp: ClientMessageAuthResponse,
    ) {
        let _ = ws
            .send(Message::Text(Utf8Bytes::from(
                &serde_json::to_string(&resp).unwrap(),
            )))
            .await;
        let _ = ws.close(None).await;
    }

    // First frame must arrive within the grace window.
    match tokio::time::timeout(std::time::Duration::from_secs(10), ws_stream.next()).await {
        Ok(Some(Ok(Message::Text(msg)))) => {
            // Parse the auth request.
            let auth_msg: ClientMessageAuthRequest = match serde_json::from_str(&msg) {
                Ok(m) => m,
                Err(_e) => {
                    reject(ws_stream, ClientMessageAuthResponse::BadRequest).await;
                    return Err(());
                }
            };

            // Check the token.
            if auth_msg.token.as_deref() != Some(token) {
                reject(ws_stream, ClientMessageAuthResponse::BadToken).await;
                return Err(());
            }

            // Success: acknowledge, then hand the stream back.
            let _ = ws_stream
                .send(Message::Text(Utf8Bytes::from(
                    &serde_json::to_string(&ClientMessageAuthResponse::Ok {
                        version: env!("CARGO_PKG_VERSION").into(),
                    })
                    .unwrap(),
                )))
                .await;
            Ok(ws_stream)
        }

        // Timeout, stream ended, protocol error, or a non-text first frame:
        // all treated as a malformed handshake.
        _ => {
            reject(ws_stream, ClientMessageAuthResponse::BadRequest).await;
            Err(())
        }
    }
}
