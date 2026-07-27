use std::sync::{Arc, Mutex};

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
// Show-one-thing / record-another.
//
// Both arms are single expressions (comma-separated), so if you need
// interpolation, wrap that arm in `format!` yourself:
//
//   outln_as!(io, format!("✓ {}", name.green()), name);
//   out_as!(io, spinner_frame, "downloading");
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

    //
    // Input
    //

    pub fn prompt(&self, p: &Prompt) -> Answer {
        let answer = self.input.lock().unwrap().prompt(p);
        if p.record_message || p.record_answer {
            let mut s = String::new();
            if p.record_message {
                s.push_str(&p.message);
            }
            if p.record_answer {
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

    pub fn out_as(&self, shown: &str, recorded: &str) {
        self.out.out_as(shown, recorded);
    }

    pub fn err_as(&self, shown: &str, recorded: &str) {
        self.out.err_as(shown, recorded);
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
    fn prompt(&mut self, prompt: &Prompt) -> Answer;
}

/// A request for input. Backends decide how to present it.
#[derive(Clone, Debug)]
pub struct Prompt {
    pub message: String,
    pub kind: PromptKind,
    pub secret: bool,
    pub default: Option<String>,
    pub record_message: bool,
    pub record_answer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    /// Free-form input line
    Line,
    /// Yes/no
    Confirm,
}

#[derive(Clone, Debug)]
pub enum Answer {
    /// User provided input.
    Text(String),
    /// User cancelled this specific prompt (Ctrl-C, dismissed dialog).
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

    /// Out-of-band output: text the caller has *already* output on its own
    /// (raw `print!`, cursor rewinds, syntax highlighting) that should be
    /// reported to other backends.
    ///
    /// Contract:
    ///   - If this backend owns the same surface the caller wrote to raw
    ///     (i.e. the terminal), it must NOT emit again.
    ///   - If this backend is blind to those raw writes (web, captured,
    ///     tee-to-file, ...), it SHOULD emit so the text reaches its surface.
    ///
    /// This is only for exceptional cases!
    fn push_out_of_band(&mut self, _s: &str, _stream: OutOfBandStream) {}
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
    Alert { level: Level, text: String },
    Display { mime: String, data: String },
    Input { text: String, secret: bool },
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

    //
    // Recording
    //

    /// Record output into the transcript for text the caller has *already*
    /// output itself (raw `print!`, cursor rewinds, syntax highlighting).
    ///
    /// Two steps:
    /// 1. The text is appended to the transcript (if recording flag set).
    /// 2. The text is sent to the backend via `push_out_of_band`, which emits
    ///    it only if the backend is blind to the caller's raw writes. The
    ///    stdio backend keeps the default no-op to avoid double printing.
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
    // A global on/off switch for *visible* output. When muted, nothing is
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

impl StdioOutput {
    pub fn new() -> Self {
        StdioOutput {
            color_out: color_enabled_for(Stream::Stdout),
            color_err: color_enabled_for(Stream::Stderr),
        }
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
/// Precedence: NO_COLOR (off) > FORCE_COLOR (on) > isatty().
fn color_enabled_for(stream: Stream) -> bool {
    use std::io::IsTerminal;

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("FORCE_COLOR").is_some() {
        return true;
    }
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
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
}

use crate::term_color;
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

impl Prompt {
    pub fn line(message: impl Into<String>) -> Self {
        Prompt {
            message: message.into(),
            kind: PromptKind::Line,
            secret: false,
            default: None,
            record_message: true,
            record_answer: true,
        }
    }
    pub fn secret_line(message: impl Into<String>) -> Self {
        Prompt {
            message: message.into(),
            kind: PromptKind::Line,
            secret: true,
            default: None,
            record_message: true,
            record_answer: true,
        }
    }
    pub fn confirm(message: impl Into<String>) -> Self {
        Prompt {
            message: message.into(),
            kind: PromptKind::Confirm,
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
    /// Reused across prompts so history/edit-mode state persists within a
    /// session. reedline is created lazily on first non-secret prompt.
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

    fn ask_secret(&mut self, p: &Prompt) -> Answer {
        // Same banner you had before.
        print!("{} {} ", "  SECRET  ".black().on_white(), p.message);
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

    fn ask_line(&mut self, p: &Prompt) -> Answer {
        let qp = line_editor::QuestionPrompt::new(&p.message);
        match self.line_editor().read_line(&qp) {
            Ok(Signal::Success(answer)) => Answer::Text(answer),
            Ok(Signal::CtrlC) => Answer::Cancelled,
            Ok(Signal::CtrlD) => Answer::Eof,
            // Any other signal (resize, etc.) → treat as cancel of this prompt.
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
    fn prompt(&mut self, p: &Prompt) -> Answer {
        if p.secret {
            self.ask_secret(p)
        } else {
            // Same handling for confirm and line prompts
            self.ask_line(p)
        }
    }
}
