use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::cmd_registry;
use crate::ctrlc_handler::CtrlcHandler;
use crate::io::{Input, Output, SectionId, SectionKind, TerminalCapability};

// --

//
// Implements io::Input and io::Output for WebSocket backend.
//
// The general architecture is that the kernel owns a WsActor and WebSocket i/o
// handlers (WsInput and WsOutput) as siblings. The WsActor and WebSocket i/o
// communicate via a bidirectional channel.
//
// The WebSocket i/o handlers are simply wrappers around the channel to the
// actor. The actor owns the WebSocket connection and sending/receiving
// messages. It also manages auth, buffering, and sending/resending even when
// clients are disconnected.
//

#[derive(Clone)]
pub struct WsOutput {
    cmd_tx: UnboundedSender<WsCmd>,
}

impl WsOutput {
    pub fn new(cmd_tx: UnboundedSender<WsCmd>) -> Self {
        WsOutput { cmd_tx }
    }
    fn send(&self, cmd: WsCmd) {
        let _ = self.cmd_tx.send(cmd);
    }
}

/// Unmodified:
/// - `push_flush`: No-op since nothing is buffered unless required by the
///   actor.
/// - `push_terminal_transient`: False since not a cursor terminal.
impl Output for WsOutput {
    fn push_out(&mut self, s: &str) {
        self.send(WsCmd::Out(s.to_string()));
    }
    fn push_err(&mut self, s: &str) {
        self.send(WsCmd::Err(s.to_string()));
    }

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

    fn push_code_bg(&mut self, text: &str, lang: Option<&str>, bg: Option<(u8, u8, u8)>) {
        self.send(WsCmd::Code {
            text: text.to_string(),
            lang: lang.map(str::to_string),
            bg,
        });
    }

    fn push_section_begin(&mut self, id: SectionId, kind: SectionKind) {
        self.send(WsCmd::SectionBegin { id, kind });
    }

    fn push_section_end(&mut self, id: SectionId) {
        self.send(WsCmd::SectionEnd { id });
    }

    fn terminal_capability(&self) -> TerminalCapability {
        TerminalCapability::None
    }

    fn is_section_aware(&self) -> bool {
        true
    }
}

pub struct WsInput {
    cmd_tx: UnboundedSender<WsCmd>,
}

impl WsInput {
    pub fn new(cmd_tx: UnboundedSender<WsCmd>) -> Self {
        WsInput { cmd_tx }
    }
}

impl Input for WsInput {
    /// Request response to query from the client.
    ///
    /// Blocks until the client answers.
    ///
    /// # Returns
    ///
    /// `Answer::Eof` if client disconnected.
    fn ask(&mut self, q: &Query) -> Answer {
        let (reply, rx) = std::sync::mpsc::channel();
        if self
            .cmd_tx
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

    /// Request the next REPL input line from the client.
    ///
    /// Blocks until the client answers.
    ///
    /// # Returns
    ///
    /// `Answer::Eof` if client disconnected.
    fn next_repl(
        &mut self,
        index: u32,
        model: String,
        use_hai_router: crate::session::HaiRouterState,
        input_tokens: u32,
        task_mode: Option<String>,
        tool_mode: Option<String>,
        incognito: bool,
        agentic: bool,
    ) -> Answer {
        let (reply, rx) = std::sync::mpsc::channel();
        let use_hai_router = match use_hai_router {
            crate::session::HaiRouterState::On => HaiRouterState::On,
            crate::session::HaiRouterState::OffForModel => HaiRouterState::OffForModel,
            crate::session::HaiRouterState::Off => HaiRouterState::Off,
        };
        if self
            .cmd_tx
            .send(WsCmd::ReplLine {
                reply,
                index,
                model,
                use_hai_router,
                input_tokens,
                task_mode,
                tool_mode,
                incognito,
                agentic,
            })
            .is_err()
        {
            return Answer::Eof;
        }
        rx.recv().unwrap_or(Answer::Eof)
    }

    fn drives_repl(&self) -> bool {
        true
    }

    fn update_config(
        &self,
        cmd_registry: &cmd_registry::Registry,
        account: &Option<crate::db::Account>,
        starred_shortcuts: &Vec<String>,
        is_first_user_input: bool,
    ) {
        if self
            .cmd_tx
            .send(WsCmd::UpdateConfig {
                cmd_registry: cmd_registry.clone(),
                account: account.clone(),
                starred_shortcuts: starred_shortcuts.clone(),
                is_first_user_input,
            })
            .is_err()
        {
            tracing::debug!("kernel: failed to send UpdateConfig to actor");
        }
    }
}

// --

/// Server -> client.
#[derive(Clone, Serialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ServerMsg {
    Out {
        text: String,
    },
    Err {
        text: String,
    },
    Alert {
        level: crate::io::Level,
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

    SectionBegin {
        id: SectionId,
        kind: SectionKind,
    },
    SectionEnd {
        id: SectionId,
    },

    /// Query/ask the client for input
    Query {
        query_id: u64,
        message: String,
        kind: crate::io::QueryKind,
        secret: bool,
    },
    /// Kernel is waiting for the next REPL input
    ReplPrompt {
        index: u32,
        model: String,
        use_hai_router: HaiRouterState,
        input_tokens: u32,
        task_mode: Option<String>,
        tool_mode: Option<String>,
        incognito: bool,
        agentic: bool,
    },

    //
    // Request/response messages. These carry a `mid` (message id) that
    // correlates a response back to the client request that triggered it.
    //
    /// Response to a `ClientMsg::CmdRegistryList` request.
    CmdRegistryList {
        mid: u64,
        cmds: Vec<CmdEntry>,
    },
    /// Response to a `ClientMsg::CmdRegistryComplete` request.
    CmdRegistryComplete {
        mid: u64,
        suggestions: Vec<Suggestion>,
    },
}

#[derive(Clone, Serialize)]
pub struct CmdEntry {
    pub canonical: String,
    pub aliases: Vec<String>,
    pub description: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Suggestion {
    pub value: String,
    pub display_override: Option<String>,
    pub description: Option<String>,
    pub span: Span,
    pub append_whitespace: bool,
}

impl Suggestion {
    fn from_reedline_suggestion(s: &reedline::Suggestion) -> Self {
        Self {
            value: s.value.clone(),
            display_override: s.display_override.clone(),
            description: s.description.clone(),
            span: Span {
                start: s.span.start as u32,
                end: s.span.end as u32,
            },
            append_whitespace: s.append_whitespace,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Serialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum HaiRouterState {
    On,
    OffForModel,
    Off,
}

// --

/// Client -> server.
#[derive(Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Answer to a `Query`
    Answer {
        query_id: u64,
        text: Option<String>,
    },

    /// Equivalent of client submitting a REPL read line.
    Eval {
        input: String,
    },

    /// Request the list of registered commands.
    /// Server will echo back `mid` in response.
    CmdRegistryList {
        mid: u64,
    },

    /// Request tab/auto-complete results.
    /// Server will echo back `mid` in response.
    CmdRegistryComplete {
        mid: u64,
        line: String,
    },

    Interrupt,
}

// --

use crate::io::{Answer, Level, Query};

/// Commands sent from the kernel to the actor.
pub enum WsCmd {
    // WsOutput commands
    // Straightforward mapping
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
    SectionBegin {
        id: SectionId,
        kind: SectionKind,
    },
    SectionEnd {
        id: SectionId,
    },

    // WsInput commands:
    // These are blocking for the actor. Actor waits on `reply` until the
    // client answers.
    Query {
        reply: std::sync::mpsc::Sender<Answer>,
        q: Query,
    },
    ReplLine {
        reply: std::sync::mpsc::Sender<Answer>,
        index: u32,
        model: String,
        use_hai_router: HaiRouterState,
        input_tokens: u32,
        task_mode: Option<String>,
        tool_mode: Option<String>,
        incognito: bool,
        agentic: bool,
    },

    /// Update the state of the actor.
    UpdateConfig {
        cmd_registry: cmd_registry::Registry,
        account: Option<crate::db::Account>,
        starred_shortcuts: Vec<String>,
        is_first_user_input: bool,
    },
}

// --

/// A blocking input request the actor is holding open.
pub struct PendingClientInput {
    reply: std::sync::mpsc::Sender<Answer>,
    server_msg: ServerMsg,
}

pub struct WsActor {
    ctrlc_handler: CtrlcHandler,

    listener: TcpListener,

    pub token: String,

    /// Commands from the kernel
    pub cmd_rx: UnboundedReceiver<WsCmd>,

    /// Send to the client
    pub conn_tx: Option<UnboundedSender<String>>,

    /// Receive from the client
    pub conn_rx: Option<UnboundedReceiver<String>>,

    /// Output buffered while no client was connected. Used to replay on
    /// connect.
    pub conn_tx_buffer: VecDeque<String>,

    /// Pending input requests that have been sent to the client.
    pending_client_queries: HashMap<u64, PendingClientInput>,
    pending_client_repl: Option<PendingClientInput>,

    /// Currently open sections, outermost first.
    ///
    /// Used to force-close all sections before the next prompt.
    section_stack: Vec<(SectionId, SectionKind)>,

    /// For generating sequential IDs to assign to pending input requests.
    pub next_id: u64,

    /// A queue of evals pushed by the client that are waiting to be consumed
    /// by `next_repl` calls.
    pub eval_queue: VecDeque<String>,

    /// For idle self-exit. `None` while a client is connected.
    idle_since: Option<tokio::time::Instant>,

    /// Whether any client has EVER connected. Distinguishes "never used,
    /// abandoned spawn" from "used, then disconnected".
    ever_connected: bool,

    /// Registry of commands available in REPL.
    cmd_registry: cmd_registry::Registry,

    account: Option<crate::db::Account>,

    starred_shortcuts: Vec<String>,

    /// Whether the user has sent a message yet.
    is_first_user_input: bool,
}

impl WsActor {
    pub fn new(
        ctrlc_handler: CtrlcHandler,
        listener: TcpListener,
        token: String,
        cmd_rx: UnboundedReceiver<WsCmd>,
        cmd_registry: cmd_registry::Registry,
    ) -> Self {
        Self {
            ctrlc_handler,
            listener,
            token,
            cmd_rx,
            conn_tx: None,
            conn_rx: None,
            conn_tx_buffer: VecDeque::new(),
            pending_client_queries: HashMap::new(),
            pending_client_repl: None,
            section_stack: Vec::new(),
            next_id: 0,
            eval_queue: VecDeque::new(),
            idle_since: None,
            ever_connected: false,
            cmd_registry,
            account: None,
            starred_shortcuts: vec![],
            is_first_user_input: false,
        }
    }

    pub async fn run(mut self) {
        // Idle-exit grace periods
        const BOOT_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
        const DISCONNECT_GRACE: std::time::Duration = std::time::Duration::from_secs(300);

        loop {
            let can_accept = self.conn_tx.is_none();

            let idle_deadline = self.idle_since.map(|since| {
                let grace = if self.ever_connected {
                    DISCONNECT_GRACE
                } else {
                    BOOT_GRACE
                };
                since + grace
            });

            // Multi-select
            tokio::select! {
                // Command from the kernel via io (WsOutput/WsInput)
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.on_cmd(cmd),
                        None => break, // all backends dropped; kernel done
                    }
                }

                // New client + auth
                accept = self.listener.accept(), if can_accept => {
                    if let Ok((stream, _)) = accept {
                        self.on_connect(stream).await;
                    }
                }

                // Message from client, or client disconnected
                maybe_text = recv_opt(&mut self.conn_rx), if self.conn_rx.is_some() => {
                    match maybe_text {
                        Some(text) => self.on_client_msg(text),
                        None => {
                            tracing::debug!("kernel: client disconnected");
                            self.on_disconnect();
                        }
                    }
                }

                // Timeout -> exit
                _ = sleep_until_deadline(idle_deadline), if idle_deadline.is_some() => {
                    tracing::debug!("kernel: idle timeout, exiting");
                    break;
                }

                // Don't think this can happen
                else => break,
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

/// If `deadline` is None, await forever. Otherwise, await until the deadline.
async fn sleep_until_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

// --

//
// WsActor implementation for sending i/o commands from the kernel to the
// client.
//
// The output commands map ~one-to-one with ServerMsg variants.
// The input commands are a bit more complex and buffer requests until the
// client answers (even if disconnected temporarily).
//

impl WsActor {
    fn on_cmd(&mut self, cmd: WsCmd) {
        match cmd {
            WsCmd::Out(text) => self.emit_or_buffer(ServerMsg::Out { text }),
            WsCmd::Err(text) => self.emit_or_buffer(ServerMsg::Err { text }),
            WsCmd::Alert { level, text } => self.emit_or_buffer(ServerMsg::Alert { level, text }),
            WsCmd::Display { mime, data } => self.emit_or_buffer(ServerMsg::Display { mime, data }),
            WsCmd::Code { text, lang, bg } => {
                self.emit_or_buffer(ServerMsg::Code { text, lang, bg })
            }
            WsCmd::SectionBegin { id, kind } => self.on_section_begin(id, kind),
            WsCmd::SectionEnd { id } => self.on_section_end(id),
            WsCmd::Query { q, reply } => {
                let query_id = self.alloc_query_id();
                let server_msg = ServerMsg::Query {
                    query_id,
                    message: q.message.clone(),
                    kind: q.kind,
                    secret: q.secret,
                };
                self.pending_client_queries.insert(
                    query_id,
                    PendingClientInput {
                        reply,
                        server_msg: server_msg.clone(),
                    },
                );
                // We rely on `pending_client_queries` to resend the query if
                // the client disconnects (rather than the buffer).
                self.emit_or_drop(server_msg);
            }
            WsCmd::ReplLine {
                reply,
                index,
                model,
                use_hai_router,
                input_tokens,
                task_mode,
                tool_mode,
                incognito,
                agentic,
            } => {
                // Should not be necessary, but as a backstop, if there are any
                // sections open, close them. This takes advantage of the fact
                // that all sections must be closed before the next prompt.
                self.close_all_sections();

                // If a client already pushed an eval, return it.
                if let Some(code) = self.eval_queue.pop_front() {
                    let _ = reply.send(Answer::Text(code));
                    return;
                }
                let server_msg = ServerMsg::ReplPrompt {
                    index,
                    model,
                    use_hai_router,
                    input_tokens,
                    task_mode,
                    tool_mode,
                    incognito,
                    agentic,
                };
                self.pending_client_repl = Some(PendingClientInput {
                    reply,
                    server_msg: server_msg.clone(),
                });
                // We rely on `pending_client_repl` to resend the query if the
                // client disconnects (rather than the buffer).
                self.emit_or_drop(server_msg);
            }
            WsCmd::UpdateConfig {
                cmd_registry,
                account,
                starred_shortcuts,
                is_first_user_input,
            } => {
                self.cmd_registry = cmd_registry;
                self.account = account;
                self.starred_shortcuts = starred_shortcuts;
                self.is_first_user_input = is_first_user_input;
            }
        }
    }

    /// Emit a message to the client, or buffer it if no client is connected.
    fn emit_or_buffer(&mut self, msg: ServerMsg) {
        let json = serde_json::to_string(&msg).unwrap();
        match &self.conn_tx {
            Some(tx) if tx.send(json.clone()).is_ok() => {}
            // No client, or send failed: buffer for replay on (re)connect.
            _ => self.conn_tx_buffer.push_back(json),
        }
    }

    /// Emit a message to the client, drop it if no client is connected.
    fn emit_or_drop(&mut self, msg: ServerMsg) {
        let json = serde_json::to_string(&msg).unwrap();
        if let Some(tx) = &self.conn_tx {
            let _ = tx.send(json);
        }
    }

    fn alloc_query_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

// --

//
// WsActor section bookkeeping.
//
// Keeps track of the stack of sections.
//

impl WsActor {
    fn on_section_begin(&mut self, id: SectionId, kind: SectionKind) {
        self.section_stack.push((id, kind.clone()));
        self.emit_or_buffer(ServerMsg::SectionBegin { id, kind });
    }

    fn on_section_end(&mut self, id: SectionId) {
        let Some(pos) = self.section_stack.iter().rposition(|s| s.0 == id) else {
            tracing::error!("kernel: section_end for unknown/closed section {id}, ignoring");
            return;
        };
        if pos != self.section_stack.len() - 1 {
            tracing::error!("kernel: section_end for non-innermost section {id}");
        }
        while self.section_stack.len() > pos {
            let (id, _) = self.section_stack.pop().expect("stack len checked");
            self.emit_or_buffer(ServerMsg::SectionEnd { id });
        }
    }

    /// Force-close every open section. Called before next prompt.
    fn close_all_sections(&mut self) {
        while let Some((id, _)) = self.section_stack.pop() {
            self.emit_or_buffer(ServerMsg::SectionEnd { id });
        }
    }
}

// --

//
// WsActor implementation for receiving i/o commands from the client to the
// kernel.
//

impl WsActor {
    fn on_client_msg(&mut self, text: String) {
        tracing::debug!("kernel: client msg: {text}");
        let msg: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("bad client msg: {e}");
                return;
            }
        };
        match msg {
            ClientMsg::Answer { query_id, text } => {
                tracing::debug!("kernel: client msg: answer: {query_id} {text:?}");
                if let Some(p) = self.pending_client_queries.remove(&query_id) {
                    let answer = match text {
                        Some(t) => Answer::Text(t),
                        None => Answer::Cancelled,
                    };
                    tracing::debug!(
                        "kernel: client msg: answer: {answer:?} sending to pending query"
                    );
                    let _ = p.reply.send(answer);
                }
            }
            ClientMsg::Eval { input } => {
                tracing::debug!("kernel: client msg: eval: {input}");
                if let Some(p) = self.pending_client_repl.take() {
                    tracing::debug!("kernel: client msg: eval: pending found");
                    // Server is actively waiting for input so consume it
                    // immediately.
                    let _ = p.reply.send(Answer::Text(input));
                    return;
                } else {
                    tracing::debug!("kernel: client msg: eval: not pending, pushing to eval_queue");
                    // If server isn't actively waiting for input, just queue
                    // it up.
                    self.eval_queue.push_back(input);
                }
            }
            ClientMsg::CmdRegistryList { mid } => {
                tracing::debug!("kernel: client msg: cmd_registry_list: mid={mid}");
                self.on_cmd_registry_list(mid);
            }

            ClientMsg::CmdRegistryComplete { mid, line } => {
                tracing::debug!("kernel: client msg: cmd_registry_complete: mid={mid} line={line}");
                self.on_cmd_registry_complete(mid, line);
            }

            ClientMsg::Interrupt => {
                tracing::debug!("kernel: client msg: interrupt");
                self.ctrlc_handler.trigger();
            }
        }
    }

    fn on_cmd_registry_list(&mut self, mid: u64) {
        let cmds = self
            .cmd_registry
            .cmds()
            .iter()
            .map(|cmd_spec| CmdEntry {
                canonical: cmd_spec.canonical(),
                aliases: cmd_spec.aliases_with_sigil(),
                description: Some(cmd_spec.doc.summary.to_string()),
            })
            .collect();
        self.emit_or_drop(ServerMsg::CmdRegistryList { mid, cmds });
    }

    fn on_cmd_registry_complete(&mut self, mid: u64, line: String) {
        let api_client = crate::session::mk_api_client_from_account(self.account.as_ref());
        let suggestions = crate::feature::cmd_completer::complete(
            &self.cmd_registry,
            &api_client,
            &self.account,
            &self.starred_shortcuts,
            self.is_first_user_input,
            &line,
            line.len(),
        )
        .iter()
        .map(Suggestion::from_reedline_suggestion)
        .collect();
        self.emit_or_drop(ServerMsg::CmdRegistryComplete { mid, suggestions });
    }
}

// --

//
// WsActor implementation for managing client connections, authentication, and
// replay.
//

use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

impl WsActor {
    async fn on_connect(&mut self, stream: tokio::net::TcpStream) {
        let _ = stream.set_nodelay(true);

        let ws = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                tracing::debug!("kernel: handshake error: {e:?}");
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

        // Catch client up (send output backlog and resend input requests)
        self.send_backlog_to_client();
        self.resend_pending_client_input();
    }

    fn on_disconnect(&mut self) {
        self.conn_tx = None;
        self.conn_rx = None;
        // Start idle clock
        self.idle_since = Some(tokio::time::Instant::now());
    }

    /// Send a serialized frame directly to the live client, bypassing the
    /// buffer. If client isn't connected, it's dropped.
    fn emit_now(&self, json: &str) {
        if let Some(tx) = &self.conn_tx {
            let _ = tx.send(json.to_string());
        }
    }

    /// Flush everything buffered while disconnected to the now-live client.
    /// Called from on_connect, AFTER conn_tx is set.
    fn send_backlog_to_client(&mut self) {
        let backlog: Vec<String> = self.conn_tx_buffer.drain(..).collect();
        for json in backlog {
            self.emit_now(&json);
        }
    }

    /// Re-send all outstanding input requests to the reconnected client, so
    /// prompts issued before a disconnect don't get lost.
    fn resend_pending_client_input(&mut self) {
        // Send query requests
        let frames: Vec<String> = self
            .pending_client_queries
            .iter()
            .map(|(_id, p)| {
                serde_json::to_string(&p.server_msg).expect("unexpected serialization error")
            })
            .collect();

        for json in frames {
            self.emit_now(&json);
        }

        // Send repl prompt request
        if let Some(p) = &self.pending_client_repl {
            let server_msg_json =
                serde_json::to_string(&p.server_msg).expect("unexpected serialization error");
            self.emit_now(&server_msg_json);
        }
    }
}

// --

use crate::feature::gateway::{ClientMessageAuthRequest, ClientMessageAuthResponse};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Utf8Bytes;

/// Authenticate a freshly-accepted websocket against the kernel token.
///
/// Logic borrowed from websocket gateway authentication.
///
/// The first message from the client must be a `ClientMessageAuthRequest`
/// and sent within a grace period (see code).
async fn authenticate(
    mut ws_stream: WebSocketStream<tokio::net::TcpStream>,
    token: &str,
) -> Result<WebSocketStream<tokio::net::TcpStream>, ()> {
    // Helper function for client rejections
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

    const MESSAGE_GRACE_PERIOD: u64 = 10;

    //
    // Follows same flow as gateway websocket server auth to check token.
    //

    match tokio::time::timeout(
        std::time::Duration::from_secs(MESSAGE_GRACE_PERIOD),
        ws_stream.next(),
    )
    .await
    {
        Ok(Some(Ok(Message::Text(msg)))) => {
            let auth_msg: ClientMessageAuthRequest = match serde_json::from_str(&msg) {
                Ok(m) => m,
                Err(_e) => {
                    reject(ws_stream, ClientMessageAuthResponse::BadRequest).await;
                    return Err(());
                }
            };
            if auth_msg.token.as_deref() != Some(token) {
                reject(ws_stream, ClientMessageAuthResponse::BadToken).await;
                return Err(());
            }
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
        _ => {
            // All protocol-level errors treated as bad request
            reject(ws_stream, ClientMessageAuthResponse::BadRequest).await;
            Err(())
        }
    }
}
