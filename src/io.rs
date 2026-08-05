use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use two_face::re_exports::syntect::easy::HighlightLines;
use two_face::re_exports::syntect::parsing::SyntaxSet;

// --

// Notes:
//
// # Muted state is orthogonal to recording state
//
// - Muting prevents any output from being sent to the backend.
// - Whether muted or not, recording controls whether output is saved to a
//   transcript for later use.
//
// # Terminal vs. non-terminal backends
//
// - Terminal backends (stdio, web) can render styling and/or cursor movement.
// - Non-terminal backends (file, pipe) cannot, and must treat all output as
//   plain text.
//

// --

//
// Macros to mimic println!/eprintln! (uses write!/writeln! approach of taking
// the handle as the first arg).
//

#[macro_export]
macro_rules! out {
    ($out:expr, $($arg:tt)*) => {
        $out.out(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! outln {
    ($out:expr) => {
        $out.out("\n")
    };
    ($out:expr, $($arg:tt)*) => {
        $out.out(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! err {
    ($out:expr, $($arg:tt)*) => {
        $out.err(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! errln {
    ($out:expr) => {
        $out.err("\n")
    };
    ($out:expr, $($arg:tt)*) => {
        $out.err(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

/// Flush any buffered output. Mirrors `std::io::Write::flush`.
#[macro_export]
macro_rules! flush {
    ($out:expr) => {
        $out.flush()
    };
}

/// Write to stdout without a trailing newline, then flush. The
/// `print!`-that-needs-flushing case (e.g. interactive prompts).
#[macro_export]
macro_rules! out_flush {
    ($out:expr, $($arg:tt)*) => {
        $out.out_flush(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

/// Write to stderr without a trailing newline, then flush.
#[macro_export]
macro_rules! err_flush {
    ($out:expr, $($arg:tt)*) => {
        $out.err_flush(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

//
// <out>_as: (Show-one-thing, record-another)
//
// Both arms are single expressions so if you need interpolation, use
// `format!`. Example:
//
//     outln_as!(io, format!("✓ {}", name.green()), name);
//

/// Print to stdout (no newline); record a possibly-different string.
#[macro_export]
macro_rules! out_as {
    ($out:expr, $shown:expr, $recorded:expr $(,)?) => {
        $out.out_as(
            &::std::format!("{}", $shown),
            &::std::format!("{}", $recorded),
        )
    };
}

/// Print to stdout with a trailing newline; record a possibly-different
/// string (also newline-terminated).
#[macro_export]
macro_rules! outln_as {
    ($out:expr, $shown:expr, $recorded:expr $(,)?) => {
        $out.out_as(
            &::std::format!("{}\n", $shown),
            &::std::format!("{}\n", $recorded),
        )
    };
}

/// Print to stderr (no newline); record a possibly-different string.
#[macro_export]
macro_rules! err_as {
    ($out:expr, $shown:expr, $recorded:expr $(,)?) => {
        $out.err_as(
            &::std::format!("{}", $shown),
            &::std::format!("{}", $recorded),
        )
    };
}

/// Print to stderr with a trailing newline; record a possibly-different
/// string (also newline-terminated).
#[macro_export]
macro_rules! errln_as {
    ($out:expr, $shown:expr, $recorded:expr $(,)?) => {
        $out.err_as(
            &::std::format!("{}\n", $shown),
            &::std::format!("{}\n", $recorded),
        )
    };
}

//
// Record-only macros.
//
// For text the caller presents itself (raw `print!`, cursor rewinds, syntax
// highlighting) but still wants in the transcript.
//

#[macro_export]
macro_rules! record_out {
    ($out:expr, $($arg:tt)*) => {
        $out.record_out(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! record_outln {
    ($out:expr) => {
        $out.record_out("\n")
    };
    ($out:expr, $($arg:tt)*) => {
        $out.record_out(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! record_err {
    ($out:expr, $($arg:tt)*) => {
        $out.record_err(&::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! record_errln {
    ($out:expr) => {
        $out.record_err("\n")
    };
    ($out:expr, $($arg:tt)*) => {
        $out.record_err(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

// --

#[derive(Clone)]
pub struct Io {
    pub out: Out,
    pub input: Arc<Mutex<dyn Input>>,
}

impl Io {
    /// Build from separate output + input backends.
    pub fn new<O, I>(out_backend: O, in_backend: I) -> Self
    where
        O: Output + 'static,
        I: Input + 'static,
    {
        Io {
            out: Out::new(out_backend),
            input: Arc::new(Mutex::new(in_backend)),
        }
    }

    /// CLI mode: stdout/stderr for output, stdin for input.
    pub fn stdio() -> Self {
        Io::new(StdioOutput::new(), StdinInput::new())
    }

    pub fn terminal_capability(&self) -> TerminalCapability {
        self.out.terminal_capability()
    }
    pub fn is_terminal(&self) -> bool {
        self.out.terminal_capability().can_style()
    }
    pub fn can_cursor(&self) -> bool {
        self.out.terminal_capability().can_cursor()
    }

    //
    // Input
    //

    /// Only applicable if the input backend drives the REPL.
    /// Stdio input does not (reedline does); web backends do.
    pub fn next_repl(
        &self,
        index: u32,
        model: String,
        use_hai_router: session::HaiRouterState,
        input_tokens: u32,
        task_mode: Option<String>,
        tool_mode: Option<String>,
        incognito: bool,
        agentic: bool,
    ) -> Answer {
        self.input.lock().unwrap().next_repl(
            index,
            model,
            use_hai_router,
            input_tokens,
            task_mode,
            tool_mode,
            incognito,
            agentic,
        )
    }

    /// True if the input backend drives the REPL, i.e. it produces REPL input.
    pub fn drives_repl(&self) -> bool {
        self.input.lock().unwrap().drives_repl()
    }

    /// Query the user for the answer to a question
    pub fn query(&self, q: &Query) -> Answer {
        let answer = self.input.lock().unwrap().ask(q);
        if q.record_message || q.record_answer {
            let mut s = String::new();
            if q.record_message {
                s.push_str(&q.message);
            }
            if q.record_answer {
                match &answer {
                    Answer::Text(t) => {
                        if !s.is_empty() {
                            s.push(' ');
                        }
                        s.push_str(t);
                    }
                    Answer::Cancelled => {
                        if !s.is_empty() {
                            s.push(' ');
                        }
                        s.push_str("<cancelled>");
                    }
                    Answer::Eof => {
                        if !s.is_empty() {
                            s.push(' ');
                        }
                        s.push_str("<eof>");
                    }
                }
            }
            record_outln!(self.out, "{}", s);
        }
        answer
    }

    //
    // Output: Convenience methods that forward to output backend.
    //

    pub fn out(&self, s: &str) {
        self.out.out(s)
    }
    pub fn err(&self, s: &str) {
        self.out.err(s)
    }
    pub fn flush(&self) {
        self.out.flush()
    }
    pub fn out_flush(&self, s: &str) {
        self.out.out_flush(s)
    }
    pub fn err_flush(&self, s: &str) {
        self.out.err_flush(s)
    }
    pub fn alert(&self, l: Level, s: &str) {
        self.out.alert(l, s)
    }
    pub fn display(&self, mime: &str, data: &str) {
        self.out.display(mime, data)
    }
    pub fn code(&self, text: &str, lang: Option<&str>) {
        self.out.code(text, lang)
    }
    pub fn code_bg(&self, text: &str, lang: Option<&str>, bg: Option<(u8, u8, u8)>) {
        self.out.code_bg(text, lang, bg)
    }

    pub fn code_reset(&self) {
        self.out.code_reset()
    }

    pub fn out_as(&self, shown: &str, recorded: &str) {
        self.out.out_as(shown, recorded);
    }

    pub fn err_as(&self, shown: &str, recorded: &str) {
        self.out.err_as(shown, recorded);
    }

    pub fn terminal_transient(&self, s: &str) -> bool {
        self.out.terminal_transient(s)
    }

    pub fn record_out(&self, s: &str) {
        self.out.record_out(s)
    }
    pub fn record_err(&self, s: &str) {
        self.out.record_err(s)
    }

    pub fn record_on(&self) -> bool {
        self.out.record_on()
    }
    pub fn record_off(&self) -> bool {
        self.out.record_off()
    }
    pub fn record_set(&self, enabled: bool) -> bool {
        self.out.record_set(enabled)
    }
    pub fn muted(&self) -> bool {
        self.out.muted()
    }
    pub fn mute(&self) -> bool {
        self.out.mute()
    }
    pub fn unmute(&self) -> bool {
        self.out.unmute()
    }
    pub fn mute_set(&self, muted: bool) -> bool {
        self.out.mute_set(muted)
    }
    pub fn transcript_with(&self, include_display: bool) -> String {
        self.out.transcript_with(include_display)
    }
    pub fn clear(&self) {
        self.out.clear()
    }
}

// --

pub trait Input: Send {
    /// Block until the user answers `prompt`, or the input source
    /// signals cancel/eof.
    fn ask(&mut self, query: &Query) -> Answer;

    /// Block until the client submits the next REPL cell/line.
    ///
    /// Only applicable if the input backend drives the REPL.
    /// Stdio input does not (reedline does); web backends do.
    fn next_repl(
        &mut self,
        _index: u32,
        _model: String,
        _use_hai_router: session::HaiRouterState,
        _input_tokens: u32,
        _task_mode: Option<String>,
        _tool_mode: Option<String>,
        _incognito: bool,
        _agentic: bool,
    ) -> Answer {
        self.ask(&Query::line("").with_record_message(false))
    }

    /// True if the input backend drives the REPL, i.e. it produces REPL input.
    /// False if the input backend is passive (e.g. stdio) where the caller
    /// has its own REPL loop (reedline).
    fn drives_repl(&self) -> bool {
        false
    }
}

/// A request for input. Backends decide how to present it.
#[derive(Clone, Debug)]
pub struct Query {
    pub message: String,
    pub kind: QueryKind,
    pub secret: bool,
    pub default: Option<String>,
    pub record_message: bool,
    pub record_answer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
pub enum QueryKind {
    /// Free-form input line
    Line,
    /// Yes/no
    Confirm,
}

#[derive(Clone, Debug)]
pub enum Answer {
    /// User provided input.
    Text(String),
    /// User cancelled this specific query (Ctrl-C, dismissed dialog).
    Cancelled,
    /// Input stream closed / EOF (Ctrl-D, socket gone). Terminal condition.
    Eof,
}

impl Answer {
    /// Converts the `Answer` into an `Option<String>`.
    ///
    /// Returns `Some(text)` for `Text`, and `None` for `Cancelled` or `Eof`.
    pub fn into_option(self) -> Option<String> {
        match self {
            Answer::Text(text) => Some(text),
            Answer::Cancelled | Answer::Eof => None,
        }
    }
}

impl From<Answer> for Option<String> {
    fn from(answer: Answer) -> Self {
        match answer {
            Answer::Text(text) => Some(text),
            Answer::Cancelled | Answer::Eof => None,
        }
    }
}

// --

/// The core trait. Implement this for each backend (stdio, captured, web, etc).
/// Methods are named `push_*` to avoid colliding with the `Out` wrapper's
/// `out`/`err` methods below.
pub trait Output: Send {
    fn push_out(&mut self, s: &str);
    fn push_err(&mut self, s: &str);

    /// Flush output
    ///
    /// This is a transport-level signal, not content, so it is never
    /// recorded into the transcript. Backends decide what it means:
    ///   - stdio: flush stdout/stderr.
    ///   - other: probably a no-op
    fn push_flush(&mut self) {}

    /// Leveled message. Backend owns label, color, routing, line termination.
    fn push_alert(&mut self, level: Level, msg: &str) {
        // Default: plain "label: msg" to the conventional stream.
        let line = format!("{} {}\n", level.label(), msg);
        if level.is_err_stream() {
            self.push_err(&line);
        } else {
            self.push_out(&line);
        }
    }

    /// Optional rich display (ipython-style MIME payloads).
    /// Default impl just ignores it; override in the web backend.
    fn push_display(&mut self, _mime: &str, _data: &str) {}

    /// A chunk of source code to render. The `text` is the *un-rendered*
    /// source; the backend decides the presentation (terminal escapes for
    /// stdio, HTML for web, ...). `lang` is a language/scope hint.
    ///
    /// Default impl treats it as plain text so backends that don't care
    /// about syntax highlighting (and the transcript) still work.
    fn push_code(&mut self, text: &str, _lang: Option<&str>) {
        self.push_out(text);
    }

    /// Like `push_code`, but with an optional RGB background color for the
    /// rendered output. Default impl ignores `bg` and defers to `push_code`
    /// so backends that don't do colored rendering still work.
    fn push_code_bg(&mut self, text: &str, lang: Option<&str>, _bg: Option<(u8, u8, u8)>) {
        self.push_code(text, lang);
    }

    /// Reset any incremental syntax-highlighting state. Call at document
    /// boundaries.
    fn push_code_reset(&mut self) {}

    /// Out-of-band output: text the caller has already output to the terminal
    /// that should be reported to other backends.
    ///
    /// This is only for exceptional cases!
    fn push_out_of_band(&mut self, s: &str, stream: OutOfBandStream) {
        if matches!(self.terminal_capability(), TerminalCapability::None) {
            // Since this is not a terminal, it's out-of-band and should
            // produce output.
            match stream {
                OutOfBandStream::Out => self.push_out(s),
                OutOfBandStream::Err => self.push_err(s),
            }
        } else {
            // If the backend is the terminal, don't emit anything.
        }
    }

    /// Ephemeral, terminal-only output.
    ///
    /// Primary use case is for text that will be written via cursor moves.
    ///
    /// - Emit ONLY if backend owns a cursor-capable screen, otherwise no-op.
    /// - Never recorded into the transcript.
    ///
    /// # Returns
    ///
    /// True if the text was emitted.
    fn push_terminal_transient(&mut self, _s: &str) -> bool {
        false
    }

    /// `TerminalCapability::None` if non-terminal.
    fn terminal_capability(&self) -> TerminalCapability {
        TerminalCapability::None
    }

    /// Whether the backend writes to a real screen the process's raw
    /// stdout also targets.
    fn is_terminal(&self) -> bool {
        self.terminal_capability().can_style()
    }
}

/// Which conventional stream an out-of-band chunk belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutOfBandStream {
    Out,
    Err,
}

/// A single recorded chunk of output, tagged by stream.
#[derive(Clone, Debug)]
pub enum Rec {
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
    Input {
        text: String,
        secret: bool,
    },
    /// A chunk of source code, carried in its *un-rendered* form so each
    /// backend can present it however it likes: terminal escapes for stdio,
    /// HTML for web, plaintext for the transcript.
    Code {
        text: String,
        lang: Option<String>,
        /// Optional RGB background color to apply while rendering (stdio
        /// backend only). Never affects the plaintext transcript.
        bg: Option<(u8, u8, u8)>,
    },
}

/// Shared recording state. Lives alongside the backend inside `Out`.
///
/// `log` is an append-only vec. A "start point" is just an index (a `Cursor`)
/// into that vec, so recording is cheap and you can have multiple concurrent
/// recordings from different start points.
struct Recorder {
    enabled: bool,
    log: Vec<Rec>,
    /// When false, all output to the *backend* is suppressed (a global
    /// mute). Recording into `log` is unaffected, so a muted session still
    /// produces a full transcript.
    muted: bool,
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder {
            enabled: false,
            log: Vec::new(),
            muted: false,
        }
    }
}

/// Async-safe, cheap-to-clone handle to an `Output` backend.
///
/// Locking is done per-call internally.
#[derive(Clone)]
pub struct Out {
    backend: Arc<Mutex<dyn Output>>,
    rec: Arc<Mutex<Recorder>>,
}

impl Out {
    /// Build from any backend.
    pub fn new<O: Output + 'static>(backend: O) -> Self {
        Out {
            backend: Arc::new(Mutex::new(backend)),
            rec: Arc::new(Mutex::new(Recorder::default())),
        }
    }

    /// Convenience constructor for CLI mode.
    pub fn stdio() -> Self {
        Out::new(StdioOutput::new())
    }

    /// Terminal capabilities of the backend. `TerminalCapability::None` while
    /// muted, since nothing we emit reaches a screen.
    pub fn terminal_capability(&self) -> TerminalCapability {
        if self.muted() {
            return TerminalCapability::None;
        }
        self.backend.lock().unwrap().terminal_capability()
    }

    /// Safe to emit styling escapes.
    pub fn is_terminal(&self) -> bool {
        self.terminal_capability().can_style()
    }

    /// Safe to move the cursor / rewrite lines / enter raw mode.
    pub fn can_cursor(&self) -> bool {
        self.terminal_capability().can_cursor()
    }

    //
    // Emit
    //

    pub fn out(&self, s: &str) {
        self.record(Rec::Out(s.to_string()));
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_out(s);
    }

    pub fn err(&self, s: &str) {
        self.record(Rec::Err(s.to_string()));
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_err(s);
    }

    /// Make any buffered output visible. See `Output::push_flush`.
    pub fn flush(&self) {
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_flush();
    }

    /// Write to stdout without a trailing newline, then flush.
    ///
    /// This is the `print!`-that-needs-flushing case (e.g. interactive
    /// prompts). Write + flush happen under a single lock so another
    /// thread can't interleave output between them.
    pub fn out_flush(&self, s: &str) {
        self.record(Rec::Out(s.to_string()));
        if self.muted() {
            return;
        }
        let mut b = self.backend.lock().unwrap();
        b.push_out(s);
        b.push_flush();
    }

    /// Write to stderr without a trailing newline, then flush.
    pub fn err_flush(&self, s: &str) {
        self.record(Rec::Err(s.to_string()));
        if self.muted() {
            return;
        }
        let mut b = self.backend.lock().unwrap();
        b.push_err(s);
        b.push_flush();
    }

    pub fn display(&self, mime: &str, data: &str) {
        self.record(Rec::Display {
            mime: mime.to_string(),
            data: data.to_string(),
        });
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_display(mime, data);
    }

    /// Emit a chunk of source code. The `text` is the *un-rendered* source;
    /// each backend renders it its own way (terminal escapes, HTML, ...).
    /// The transcript keeps the plaintext.
    pub fn code(&self, text: &str, lang: Option<&str>) {
        self.code_bg(text, lang, None)
    }

    /// Like `code`, but applies an RGB background color while rendering
    /// (stdio backend only). The transcript keeps plaintext, so `bg` never
    /// leaks into recorded output.
    pub fn code_bg(&self, text: &str, lang: Option<&str>, bg: Option<(u8, u8, u8)>) {
        self.record(Rec::Code {
            text: text.to_string(),
            lang: lang.map(|l| l.to_string()),
            bg,
        });
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_code_bg(text, lang, bg);
    }

    /// Start a new highlighting "document". Transport-level, not content,
    /// so it isn't recorded.
    pub fn code_reset(&self) {
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_code_reset();
    }

    //
    // Alerts: banners / notifications with semantic intent.
    // Exact presentation decided by backend.
    //

    pub fn alert(&self, level: Level, s: &str) {
        self.record(Rec::Alert {
            level,
            text: s.to_string(),
        });
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_alert(level, s);
    }

    /// Emit `shown` to the backend, but record `recorded` in the transcript.
    ///
    /// For when the on-screen form differs from the canonical log form:
    /// colored/animated/abbreviated on screen, plain/full in the transcript.
    pub fn out_as(&self, shown: &str, recorded: &str) {
        self.record(Rec::Out(recorded.to_string()));
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_out(shown);
    }

    pub fn err_as(&self, shown: &str, recorded: &str) {
        self.record(Rec::Err(recorded.to_string()));
        if self.muted() {
            return;
        }
        self.backend.lock().unwrap().push_err(shown);
    }

    /// Write directly to a cursor-capable terminal, bypassing the
    /// transcript and any backend that isn't a real screen.
    pub fn terminal_transient(&self, s: &str) -> bool {
        if self.muted() {
            return false;
        }
        self.backend.lock().unwrap().push_terminal_transient(s)
    }

    //
    // Recording
    //

    /// Record output into the transcript.
    ///
    /// Intended to be used for output the caller has already printed.
    ///
    /// Two steps:
    /// 1. The text is appended to the transcript (if recording flag set).
    /// 2. The text is sent to the backend via `push_out_of_band`, which emits
    ///    it only if the backend is a terminal. The stdio backend keeps the
    ///    default no-op to avoid double printing.
    pub fn record_out(&self, s: &str) {
        self.record(Rec::Out(s.to_string()));
        if self.muted() {
            return;
        }
        self.backend
            .lock()
            .unwrap()
            .push_out_of_band(s, OutOfBandStream::Out);
    }

    /// Like `record_out`, but tags the chunk as stderr.
    pub fn record_err(&self, s: &str) {
        self.record(Rec::Err(s.to_string()));
        if self.muted() {
            return;
        }
        self.backend
            .lock()
            .unwrap()
            .push_out_of_band(s, OutOfBandStream::Err);
    }

    /// Turn recording on. Returns previous state.
    pub fn record_on(&self) -> bool {
        let mut rec_lock = self.rec.lock().unwrap();
        let prev_state = rec_lock.enabled;
        rec_lock.enabled = true;
        prev_state
    }

    /// Turn recording off. Returns previous state.
    pub fn record_off(&self) -> bool {
        let mut rec_lock = self.rec.lock().unwrap();
        let prev_state = rec_lock.enabled;
        rec_lock.enabled = false;
        prev_state
    }

    /// Set recording state. Returns previous state.
    pub fn record_set(&self, enabled: bool) -> bool {
        let mut rec_lock = self.rec.lock().unwrap();
        let prev_state = rec_lock.enabled;
        rec_lock.enabled = enabled;
        prev_state
    }

    //
    // Muting
    //
    // A global on/off switch for visible output. When muted, nothing is
    // written to the backend, but recording into the transcript is
    // unaffected. All clones of this `Out` share the same mute state.
    //

    /// Whether visible output is currently suppressed.
    pub fn muted(&self) -> bool {
        self.rec.lock().unwrap().muted
    }

    /// Suppress all visible output. Returns previous mute state.
    pub fn mute(&self) -> bool {
        self.mute_set(true)
    }

    /// Resume visible output. Returns previous mute state.
    pub fn unmute(&self) -> bool {
        self.mute_set(false)
    }

    /// Set mute state directly. Returns previous mute state.
    pub fn mute_set(&self, muted: bool) -> bool {
        let mut rec_lock = self.rec.lock().unwrap();
        let prev_state = rec_lock.muted;
        rec_lock.muted = muted;
        prev_state
    }

    pub fn transcript_with(&self, include_display: bool) -> String {
        let g = self.rec.lock().unwrap();
        let mut s = String::new();
        for rec in &g.log {
            match rec {
                Rec::Out(t) | Rec::Err(t) => s.push_str(t),
                Rec::Alert { level, text } => {
                    s.push_str(level.label());
                    s.push(' ');
                    s.push_str(text);
                    s.push('\n');
                }
                Rec::Display { data, .. } if include_display => s.push_str(data),
                Rec::Display { .. } => {}
                Rec::Code { text, .. } => s.push_str(text),
                Rec::Input { text, .. } => {
                    s.push_str(text);
                    s.push('\n');
                    /*if *secret {
                        s.push_str("••••\n");
                    } else {
                        s.push_str(text);
                        s.push('\n');
                    }*/
                }
            }
        }
        s
    }

    /// Drop the entire log (and leave recording state as-is).
    pub fn clear(&self) {
        self.rec.lock().unwrap().log.clear();
    }

    pub fn record(&self, rec: Rec) {
        let mut g = self.rec.lock().unwrap();
        if g.enabled {
            g.log.push(rec);
        }
    }
}

//
// Levels for basic semantic intent
//

/// Semantic intent of a message. Presentation is decided by the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Level {
    Error,
    Warn,
    Success,
    Info,
    Note,
    Hint,
}

impl Level {
    /// The conventional label prefix ("warn:", "error:", ...).
    pub fn label(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Success => "ok",
            Level::Info => "info",
            Level::Note => "note",
            Level::Hint => "hint",
        }
    }

    /// Whether this level conventionally routes to stderr.
    pub fn is_err_stream(self) -> bool {
        matches!(self, Level::Error | Level::Warn)
    }
}

//
// Alert macros
// The `ln` suffix mirrors the raw writers (out!/outln!, err!/errln!) and keeps
// these clear of both the raw writers and other popular macros like log's
// error!/warn!/info!.
//

#[macro_export]
macro_rules! alert {
    ($out:expr, $level:expr, $($arg:tt)*) => {
        $out.alert($level, &::std::format!("{}", ::std::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! errorln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Error, $($arg)*)
    };
}

#[macro_export]
macro_rules! warnln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Warn, $($arg)*)
    };
}

#[macro_export]
macro_rules! successln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Success, $($arg)*)
    };
}

#[macro_export]
macro_rules! infoln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Info, $($arg)*)
    };
}

#[macro_export]
macro_rules! noteln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Note, $($arg)*)
    };
}

#[macro_export]
macro_rules! hintln {
    ($out:expr, $($arg:tt)*) => {
        $crate::alert!($out, $crate::Level::Hint, $($arg)*)
    };
}

//
// Backend: Std{out,err}
//

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// Writes straight to real stdout/stderr, styling alerts with ANSI color
/// when the target stream is a TTY (and NO_COLOR isn't set).
pub struct StdioOutput {
    color_out: bool,
    color_err: bool,
    terminal_capability: TerminalCapability,

    /// Highlight state for markdown which is treated as the mark up. It's kept
    /// alive across embedded code blocks so returning to markdown resumes the
    /// same context stack (open fences, lists, ...) instead of restarting as
    /// if at the top of a fresh document.
    doc_hl: Option<(String, HighlightLines<'static>)>,

    /// Highlight state for the current embedded code block. Rebuilt every
    /// time we (re-)enter a block language, so one block's unterminated
    /// string can't leak into the next.
    block_hl: Option<(String, HighlightLines<'static>)>,

    /// Language token of the previous `push_code_bg` call.
    last_lang: Option<String>,
}

fn is_doc_lang(token: &str) -> bool {
    matches!(token, "markdown" | "md" | "mdown" | "mkd")
}

fn new_highlighter(
    ps: &'static SyntaxSet,
    token: &str,
    doc: bool,
) -> Option<HighlightLines<'static>> {
    use two_face::theme::EmbeddedThemeName;
    let ts = crate::term_color::get_theme_set();
    let syntax = ps.find_syntax_by_token(token)?;
    let theme = if doc {
        // The markdown theme was chosen for these properties:
        // - Headers are bolded and highlighted (light blue)
        // - Bolded text is bolded but still white
        // - Ordered and unordered lists are highlighted (pink)
        ts.get(EmbeddedThemeName::ColdarkDark)
    } else {
        ts.get(EmbeddedThemeName::VisualStudioDarkPlus)
    };
    Some(HighlightLines::new(syntax, theme))
}

impl StdioOutput {
    pub fn new() -> Self {
        StdioOutput {
            color_out: color_enabled_for(Stream::Stdout),
            color_err: color_enabled_for(Stream::Stderr),
            terminal_capability: detect_terminal_capability(),
            doc_hl: None,
            block_hl: None,
            last_lang: None,
        }
    }

    /// Render `text` (a chunk of source in language `lang`) to terminal
    /// escapes. Returns `None` when we can't highlight (no color, no lang,
    /// or unknown lang) so the caller can fall back to plaintext.
    fn highlight_code(
        &mut self,
        text: &str,
        lang: Option<&str>,
        bg: Option<(u8, u8, u8)>,
    ) -> Option<String> {
        if !self.color_out {
            return None;
        }
        let color_capability = crate::term_color::terminal_color_capability()?;
        let lang = lang?;
        // jsx isn't supported by two_face, but tsx is.
        let lang_token = if lang == "jsx" { "tsx" } else { lang };

        let ps = crate::term_color::get_syntax_set();
        // Convert the RGB background (if any) into a syntect color once.
        let bg_color = bg.map(
            |(r, g, b)| two_face::re_exports::syntect::highlighting::Color { r, g, b, a: 255 },
        );

        let doc = is_doc_lang(lang_token);
        let continuing = self.last_lang.as_deref() == Some(lang_token);

        let highlighter: &mut HighlightLines<'static> = if doc {
            // Build once per session to allow for resumption
            if self.doc_hl.as_ref().map(|(l, _)| l.as_str()) != Some(lang_token) {
                self.doc_hl = Some((
                    lang_token.to_string(),
                    new_highlighter(ps, lang_token, true)?,
                ));
            }
            &mut self.doc_hl.as_mut()?.1
        } else {
            // Fresh state on every entry into a block language.
            if !continuing {
                self.block_hl = None;
                let hl = new_highlighter(ps, lang_token, false)?;
                self.block_hl = Some((lang_token.to_string(), hl));
            }
            &mut self.block_hl.as_mut()?.1
        };

        self.last_lang = Some(lang_token.to_string());

        let mut out = String::new();
        // Highlight line-by-line so syntect's per-line state advances
        // correctly, preserving the original text's newlines.
        let lines: Vec<&str> = text.split('\n').collect();
        for (i, line) in lines.iter().enumerate() {
            let line_with_ending = if i < lines.len() - 1 {
                format!("{}\n", line)
            } else {
                (*line).to_string()
            };
            let parts = highlighter.highlight_line(&line_with_ending, ps).ok()?;
            for (style, piece) in parts {
                out.push_str(&crate::term_color::as_terminal_escaped(
                    style,
                    piece,
                    &color_capability,
                    &bg_color,
                ));
            }
        }
        Some(out)
    }
}

impl Default for StdioOutput {
    fn default() -> Self {
        // For `colored` to colorize. Output is responsible for turning it on
        // and off per-stream. We just don't want `colored` to make the
        // decision for us.
        colored::control::set_override(true);
        Self::new()
    }
}

/// Resolve color policy for a single stream.
fn color_enabled_for(stream: Stream) -> bool {
    use std::io::IsTerminal;
    let env_var_color_policy = term_color::env_var_color_policy();
    match stream {
        Stream::Stdout => env_var_color_policy.unwrap_or(std::io::stdout().is_terminal()),
        Stream::Stderr => env_var_color_policy.unwrap_or(std::io::stderr().is_terminal()),
    }
}

impl Output for StdioOutput {
    fn push_out(&mut self, s: &str) {
        use std::io::Write;
        let mut o = std::io::stdout();
        let _ = o.write_all(s.as_bytes());
        // Auto-flush on a completed line so `outln!` behaves like
        // `println!`. Partial lines (via `out!`) stay buffered until an
        // explicit `flush!`/`out_flush!`.
        if s.ends_with('\n') {
            let _ = o.flush();
        }
    }

    fn push_err(&mut self, s: &str) {
        use std::io::Write;
        let mut e = std::io::stderr();
        let _ = e.write_all(s.as_bytes());
        // stderr is conventionally unbuffered, but flush completed lines
        // for consistency with stdout.
        if s.ends_with('\n') {
            let _ = e.flush();
        }
    }

    fn push_flush(&mut self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }

    fn push_alert(&mut self, level: Level, msg: &str) {
        use colored::Colorize;

        let to_err = level.is_err_stream();
        let color = if to_err {
            self.color_err
        } else {
            self.color_out
        };
        let label = format!(" {} ", level.label());

        let styled_label = if color {
            match level {
                Level::Error => label.white().on_red().bold().to_string(),
                Level::Warn => label.black().on_yellow().to_string(),
                Level::Success => label.black().on_green().to_string(),
                Level::Info => label.cyan().to_string(),
                Level::Note => label.dimmed().to_string(),
                Level::Hint => label.blue().to_string(),
            }
        } else {
            label.to_string()
        };

        // Backend owns label + line termination; call site passed only content.
        let line = format!("{} {}\n", styled_label, msg);

        if to_err {
            self.push_err(&line);
        } else {
            self.push_out(&line);
        }
    }

    fn push_code(&mut self, text: &str, lang: Option<&str>) {
        self.push_code_bg(text, lang, None);
    }

    fn push_code_bg(&mut self, text: &str, lang: Option<&str>, bg: Option<(u8, u8, u8)>) {
        match self.highlight_code(text, lang, bg) {
            Some(escaped) => self.push_out(&escaped),
            None => self.push_out(text),
        }
    }

    fn push_code_reset(&mut self) {
        self.doc_hl = None;
        self.block_hl = None;
        self.last_lang = None;
    }

    fn push_display(&mut self, mime: &str, data: &str) {
        match mime {
            "image/png" | "image/jpeg" | "image/webp" | "image/gif" => {
                if let Err(e) = render_image_to_term(data) {
                    // Fall back to stderr note rather than blowing up output.
                    self.push_err(&format!("warn: could not render image: {e}\n"));
                }
            }
            // Text-ish MIMEs: just print the payload.
            "text/plain" => self.push_out(data),
            // Unknown: skip, or print a placeholder.
            _ => self.push_err(&format!("note: unsupported display type {mime}\n")),
        }
    }

    fn push_terminal_transient(&mut self, s: &str) -> bool {
        if !self.terminal_capability.clone().can_cursor() {
            return false;
        }
        use std::io::Write;
        let mut o = std::io::stdout();
        let _ = o.write_all(s.as_bytes());
        // Transient text is almost always a partial line, so always flush.
        let _ = o.flush();
        true
    }

    fn terminal_capability(&self) -> TerminalCapability {
        self.terminal_capability.clone()
    }
}

// --

#[derive(Clone, Debug)]
pub enum TerminalCapability {
    /// No capability. For example, pipe, file, or web backend.
    None,
    /// Supports escape sequences for colors.
    Styled,
    /// Fully interactive terminal: cursor position, move cursor, rewrite
    /// lines, ...
    Interactive,
}

impl TerminalCapability {
    /// Safe to emit SGR/color escapes.
    pub fn can_style(self) -> bool {
        matches!(
            self,
            TerminalCapability::Styled | TerminalCapability::Interactive
        )
    }

    /// Safe to emit cursor motion, line clears, raw mode, alt screen.
    pub fn can_cursor(self) -> bool {
        matches!(self, TerminalCapability::Interactive)
    }
}

pub fn detect_terminal_capability() -> TerminalCapability {
    use std::io::IsTerminal;

    if !std::io::stdout().is_terminal() {
        // Redirected to a file/pipe
        return TerminalCapability::None;
    }

    // Screen is real, but do we own the cursor?
    let interactive = std::io::stdin().is_terminal()
        && !term_is_dumb()
        && std::env::var_os("CI").is_none()
        && std::env::var_os("HAI_NO_CURSOR").is_none();

    if interactive {
        TerminalCapability::Interactive
    } else {
        TerminalCapability::Styled
    }
}

fn term_is_dumb() -> bool {
    match std::env::var("TERM") {
        Ok(t) => t.is_empty() || t == "dumb",
        // No TERM on unix: assume dumb. On Windows, ConPTY handles ANSI
        // without TERM being set, so don't penalize it.
        Err(_) => cfg!(unix),
    }
}

// --

use crate::{session, term_color};
use base64::Engine;
use base64::engine::general_purpose;

fn render_image_to_term(encoded_image: &str) -> Result<(), Box<dyn std::error::Error>> {
    let use_pretty_images = std::env::var_os("HAI_NO_PRETTY_IMAGES").is_none();
    let image_height = std::env::var("HAI_IMAGE_HEIGHT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(20);

    let viuer_cfg = viuer::Config {
        height: Some(image_height),
        absolute_offset: false,
        use_iterm: use_pretty_images,
        use_kitty: use_pretty_images,
        use_sixel: use_pretty_images,
        truecolor: matches!(
            term_color::terminal_color_capability(),
            Some(term_color::ColorCapability::TrueColor)
        ),
        ..Default::default()
    };

    let image_bytes = general_purpose::STANDARD.decode(encoded_image)?;
    let dynamic_image = image::load_from_memory(&image_bytes)?;
    viuer::print(&dynamic_image, &viuer_cfg)?;
    Ok(())
}

// --

use std::io::Write;

use colored::Colorize;
use reedline::{
    Reedline, Signal, Vi, default_vi_insert_keybindings, default_vi_normal_keybindings,
};

use crate::line_editor;

//
// Input trait + request/response types
//

impl Query {
    pub fn line(message: impl Into<String>) -> Self {
        Query {
            message: message.into(),
            kind: QueryKind::Line,
            secret: false,
            default: None,
            record_message: true,
            record_answer: true,
        }
    }
    pub fn secret_line(message: impl Into<String>) -> Self {
        Query {
            message: message.into(),
            kind: QueryKind::Line,
            secret: true,
            default: None,
            record_message: true,
            record_answer: true,
        }
    }
    pub fn confirm(message: impl Into<String>) -> Self {
        Query {
            message: message.into(),
            kind: QueryKind::Confirm,
            secret: false,
            default: None,
            record_message: true,
            record_answer: true,
        }
    }
    pub fn with_secret(mut self, secret: bool) -> Self {
        self.secret = secret;
        self
    }

    pub fn with_record_message(mut self, record: bool) -> Self {
        self.record_message = record;
        self
    }

    pub fn with_record_answer(mut self, record: bool) -> Self {
        self.record_answer = record;
        self
    }
}

//
// Backend: stdin (reedline for lines, rpassword for secrets)
//

/// Reads from the real terminal. Owns the reedline/rpassword mechanics.
pub struct StdinInput {
    /// Reused across queries so history/edit-mode state persists within a
    /// session. reedline is created lazily on first non-secret query.
    reedline: Option<Reedline>,
}

impl StdinInput {
    pub fn new() -> Self {
        StdinInput { reedline: None }
    }

    fn line_editor(&mut self) -> &mut Reedline {
        self.reedline.get_or_insert_with(|| {
            Reedline::create()
                .use_bracketed_paste(true)
                .with_edit_mode(Box::new(Vi::new(
                    default_vi_insert_keybindings(),
                    default_vi_normal_keybindings(),
                )))
                .with_ansi_colors(true)
        })
    }

    fn ask_secret(&mut self, q: &Query) -> Answer {
        // Same banner you had before.
        print!("{} {} ", "  SECRET  ".black().on_white(), q.message);
        if std::io::stdout().flush().is_err() {
            return Answer::Eof;
        }
        match rpassword::prompt_password("") {
            Ok(s) => Answer::Text(s),
            // rpassword surfaces Ctrl-C / EOF as an Err; we can't easily
            // distinguish, so treat as Eof (terminal condition). If you want
            // Cancelled semantics for secrets, inspect e.kind() here.
            Err(_) => Answer::Eof,
        }
    }

    fn ask_line(&mut self, q: &Query) -> Answer {
        let qp = line_editor::QuestionPrompt::new(&q.message);
        match self.line_editor().read_line(&qp) {
            Ok(Signal::Success(answer)) => Answer::Text(answer),
            Ok(Signal::CtrlC) => Answer::Cancelled,
            Ok(Signal::CtrlD) => Answer::Eof,
            // Any other signal (resize, etc.) → treat as cancel of this query.
            Ok(_) => Answer::Cancelled,
            Err(_) => Answer::Eof,
        }
    }
}

impl Default for StdinInput {
    fn default() -> Self {
        Self::new()
    }
}

impl Input for StdinInput {
    fn ask(&mut self, q: &Query) -> Answer {
        if q.secret {
            self.ask_secret(q)
        } else {
            // Same handling for confirm and line queries
            self.ask_line(q)
        }
    }
}
