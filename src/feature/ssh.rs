use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use russh::*;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::io::{Answer, Io, Query};

// --

/// RAII guard so raw mode is always disabled, even on early return/panic
struct RawModeGuard;

impl RawModeGuard {
    fn new() -> std::io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawModeGuard)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(unix)]
fn read_stdin_nonblocking(buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();

    // set O_NONBLOCK
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

    let result = stdin.lock().read(buf);

    // restore blocking
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };

    match result {
        Ok(n) => Ok(Some(n)),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn read_stdin_nonblocking(buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    use std::io::Read;
    use windows_sys::Win32::System::Console::{
        GetNumberOfConsoleInputEvents, GetStdHandle, STD_INPUT_HANDLE,
    };

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut count: u32 = 0;
    let ok = unsafe { GetNumberOfConsoleInputEvents(handle, &mut count) };
    if ok == 0 || count == 0 {
        return Ok(None); // nothing waiting
    }

    let n = std::io::stdin().lock().read(buf)?;
    Ok(Some(n))
}

//- -

//
// SSH client
//

pub struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Session {
    handle: client::Handle<Client>,
}

impl Session {
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        ssh_signing_key: Zeroizing<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect(config, (host, port), Client).await?;

        let ssh_private_key = PrivateKey::from_openssh(ssh_signing_key)?;

        let auth_res = session
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(
                    Arc::new(ssh_private_key),
                    session.best_supported_rsa_hash().await?.flatten(),
                ),
            )
            .await?;

        if !auth_res.success() {
            return Err("authentication failed".into());
        }

        Ok(Self { handle: session })
    }

    async fn sftp_session(&mut self) -> Result<SftpSession, Box<dyn std::error::Error>> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    pub async fn call(
        &mut self,
        command: &str,
    ) -> Result<(u32, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = 0u32;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // stderr
                        stderr.extend_from_slice(data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                }
                _ => {}
            }
        }

        Ok((exit_code, stdout, stderr))
    }

    /// Stream output to `io` as it arrives.
    pub async fn call_streaming(
        &mut self,
        io: &Io,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout_carry: Vec<u8> = Vec::new();
        let mut stderr_carry: Vec<u8> = Vec::new();
        let mut exit_code = 0u32;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    io.out_flush(&decode_utf8_chunk(&mut stdout_carry, data));
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        io.err_flush(&decode_utf8_chunk(&mut stderr_carry, data));
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                }
                _ => {}
            }
        }

        Ok(exit_code)
    }

    /// Interactive PTY session.
    ///
    /// If called through a local terminal, the terminal is put in raw mode and
    /// wired directly to the remote PTY.
    ///
    /// If `io` is driving the REPL (ie. websocket i/o), best effort is made to
    /// forward input and output through `io` (see `call_with_io`). `interrupt`
    /// is polled and forwarded to the remote as ^C.
    pub async fn call_interactive(
        &mut self,
        io: &Io,
        interrupt: &AtomicBool,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        if io.drives_repl() {
            self.call_with_io(io, interrupt, command).await
        } else {
            self.call_interactive_term(command).await
        }
    }

    /// PTY-backed exec where all I/O goes through `io`.
    ///
    /// NOTE: LLM-driven implementation.
    ///
    /// Output is forwarded to `io` line by line. When output goes quiet for
    /// `PROMPT_IDLE` while the remote is likely waiting for input (visible
    /// text on an unfinished line, or a line editor probing the cursor), it's
    /// treated as a prompt: it becomes an `io.query` and the answer is written
    /// to the remote stdin.
    ///
    /// Full-screen interactive programs (e.g. vim) aren't supported.
    async fn call_with_io(
        &mut self,
        io: &Io,
        interrupt: &AtomicBool,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;
        // Echo off: answers are shown (or hidden) by the client, not the PTY.
        channel
            .request_pty(false, "dumb", 120, 40, 0, 0, &[(Pty::ECHO, 0)])
            .await?;
        channel.exec(true, command).await?;

        let mut utf8_carry: Vec<u8> = Vec::new();
        let mut term = TermFilter::default();
        // Clean text after the last newline. Held back so that if it's a
        // prompt, it's shown once as the query message rather than twice.
        let mut partial = String::new();
        // Set when a line editor requests the cursor position: it's about to
        // read input even if its prompt has no visible text.
        let mut editor_waiting = false;
        // When output last went quiet + `PROMPT_IDLE`. Only reset by output,
        // so other select branches (e.g. interrupt polling) don't delay it.
        let mut idle_deadline = tokio::time::Instant::now() + PROMPT_IDLE;
        // Prompt of the outstanding query and whether it's secret.
        let mut asked: Option<(String, bool)> = None;
        // Line editors redraw the prompt with the answer after Enter. That
        // line is dropped since the client already shows both.
        let mut expected_redraw: Option<String> = None;
        let mut pending: Option<tokio::task::JoinHandle<Answer>> = None;
        let mut exit_code: Option<u32> = None;
        let mut interrupt_poll = tokio::time::interval(INTERRUPT_POLL);
        interrupt_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let prompt_ready = pending.is_none()
                && exit_code.is_none()
                && (editor_waiting || !partial.trim().is_empty());
            tokio::select! {
                msg = channel.wait() => {
                    let Some(msg) = msg else { break };
                    match msg {
                        ChannelMsg::Data { ref data }
                        | ChannelMsg::ExtendedData { ref data, .. } => {
                            idle_deadline = tokio::time::Instant::now() + PROMPT_IDLE;
                            let text = decode_utf8_chunk(&mut utf8_carry, data);
                            let (clean, dsr) = term.feed(&text);
                            // Answer cursor-position requests so line editors
                            // don't time out waiting for a terminal.
                            for _ in 0..dsr {
                                channel.data(DSR_REPLY).await?;
                            }
                            if dsr > 0 {
                                editor_waiting = true;
                            }
                            partial.push_str(&clean.replace("\r\n", "\n"));
                            if let Some(i) = partial.rfind('\n') {
                                let rest = partial.split_off(i + 1);
                                let mut lines = String::new();
                                for l in partial.split_inclusive('\n') {
                                    let body = l.strip_suffix('\n').unwrap_or(l);
                                    let body = after_last_cr(body);
                                    if let Some(r) = expected_redraw.take()
                                        && is_redraw(body, &r)
                                    {
                                        continue;
                                    }
                                    lines.push_str(body);
                                    lines.push('\n');
                                }
                                if !lines.is_empty() {
                                    io.out_flush(&lines);
                                }
                                partial = rest;
                            }
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            exit_code = Some(exit_status);
                            let _ = channel.eof().await;
                        }
                        _ => {}
                    }
                }

                // Output went quiet while the remote looks to be waiting for
                // input.
                _ = tokio::time::sleep_until(idle_deadline), if prompt_ready => {
                    editor_waiting = false;
                    let raw_prompt = std::mem::take(&mut partial);
                    let prompt = after_last_cr(&raw_prompt).trim().to_string();
                    let (message, secret) = classify_prompt(&prompt);
                    asked = Some((prompt, secret));
                    let q = if secret {
                        Query::secret_line(message)
                    } else {
                        Query::line(message)
                    };
                    let io2 = io.clone();
                    // `Input::ask` blocks the thread until the client answers.
                    pending = Some(tokio::task::spawn_blocking(move || io2.query(&q)));
                }

                ans = async { pending.as_mut().unwrap().await }, if pending.is_some() => {
                    pending = None;
                    let asked = asked.take();
                    match ans {
                        Ok(Answer::Text(t)) => {
                            // Echo is off, so a secret answer never appears
                            // in a redraw.
                            expected_redraw = asked.map(|(p, secret)| {
                                if secret { p } else { format!("{p}{t}") }
                            });
                            // `\r` is Enter for raw-mode line editors; in
                            // cooked mode the PTY (ICRNL) maps it to `\n`.
                            channel.data(format!("{t}\r").as_bytes()).await?;
                        }
                        // ^C through the PTY line discipline -> SIGINT
                        Ok(Answer::Cancelled) => channel.data(&b"\x03"[..]).await?,
                        // The client is gone, so no input will ever arrive.
                        // Close rather than leave the remote waiting forever.
                        Ok(Answer::Eof) | Err(_) => {
                            let _ = channel.close().await;
                            break;
                        }
                    }
                }

                _ = interrupt_poll.tick() => {
                    // ^C through the PTY line discipline -> SIGINT
                    if interrupt.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        channel.data(&b"\x03"[..]).await?;
                    }
                }
            }
        }

        if !partial.is_empty() {
            io.out_flush(&partial);
        }
        Ok(exit_code.unwrap_or(0))
    }

    /// Interactive PTY session with raw terminal mode
    async fn call_interactive_term(
        &mut self,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;

        let (w, h) = crossterm::terminal::size()?;

        channel
            .request_pty(
                false,
                &std::env::var("TERM").unwrap_or("xterm".into()),
                w as u32,
                h as u32,
                0,
                0,
                &[],
            )
            .await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdout = tokio::io::stdout();
        let mut stdin_closed = false;

        let _raw_term = RawModeGuard::new()?;

        loop {
            tokio::select! {
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            if !stdin_closed { channel.eof().await?; }
                            break;
                        }
                        _ => {}
                    }
                },

                _ = tokio::time::sleep(Duration::from_millis(5)), if !stdin_closed => {
                    let mut buf = [0u8; 1024];
                    match read_stdin_nonblocking(&mut buf)? {
                        Some(0) => {
                            stdin_closed = true;
                            channel.eof().await?;
                        }
                        Some(n) => {
                            channel.data(&buf[..n]).await?;
                        }
                        None => {} // nothing waiting, just loop
                    }
                },
            }
        }

        Ok(code)
    }

    /// Upload a file via SFTP
    pub async fn upload(
        &mut self,
        local_path: impl AsRef<Path>,
        remote_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let contents = tokio::fs::read(local_path).await?;

        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;

        remote_file.write_all(&contents).await?;
        remote_file.flush().await?;
        remote_file.shutdown().await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Download a file via SFTP
    pub async fn download(
        &mut self,
        remote_path: &str,
        local_path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp.open_with_flags(remote_path, OpenFlags::READ).await?;

        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents).await?;

        tokio::fs::write(local_path, &contents).await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Upload bytes directly via SFTP
    pub async fn upload_bytes(
        &mut self,
        data: &[u8],
        remote_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;

        remote_file.write_all(data).await?;
        remote_file.flush().await?;
        remote_file.shutdown().await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Download file as bytes via SFTP
    pub async fn download_bytes(
        &mut self,
        remote_path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp.open_with_flags(remote_path, OpenFlags::READ).await?;

        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents).await?;

        Ok(contents)
    }

    pub async fn close(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// How long output must be quiet on a partial line before it's treated as a
/// prompt by `Session::call_with_io`.
const PROMPT_IDLE: Duration = Duration::from_millis(300);

/// How often `Session::call_with_io` checks for a client interrupt.
const INTERRUPT_POLL: Duration = Duration::from_millis(50);

/// Reply to a cursor-position request (`ESC[6n`). There's no real screen, so
/// a fixed position is reported; line editors only need *a* reply to proceed.
const DSR_REPLY: &[u8] = b"\x1b[1;1R";

/// Minimal terminal emulation for `Session::call_with_io`.
///
/// NOTE: LLM-driven implementation.
///
/// Strips escape sequences (CSI, OSC, etc.) from remote PTY output and counts
/// Device Status Report requests (`ESC[6n`) which line editors (e.g.
/// crossterm/reedline) block on to learn the cursor position. Incomplete
/// sequences at a chunk boundary are carried to the next `feed`.
#[derive(Default)]
struct TermFilter {
    carry: String,
    /// True between a cursor save (`ESC 7` / `ESC[s`) and restore (`ESC 8` /
    /// `ESC[u`). Line editors use this to draw out-of-band text (e.g.
    /// reedline's right prompt) which shouldn't be part of the line.
    hidden: bool,
}

impl TermFilter {
    /// Returns (clean text, number of cursor-position requests seen).
    fn feed(&mut self, s: &str) -> (String, usize) {
        let mut input = std::mem::take(&mut self.carry);
        input.push_str(s);
        let chars: Vec<char> = input.chars().collect();
        let mut out = String::new();
        let mut dsr = 0;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c != '\x1b' {
                // Out-of-band text never spans lines, so a newline ends it even
                // if the restore never came. Otherwise all output would vanish.
                if c == '\n' {
                    self.hidden = false;
                }
                // Keep printable text plus newline/CR/tab; drop other controls.
                if !self.hidden && (!c.is_control() || matches!(c, '\n' | '\r' | '\t')) {
                    out.push(c);
                }
                i += 1;
                continue;
            }
            // Escape sequence
            let start = i;
            let Some(&next) = chars.get(i + 1) else {
                self.carry = chars[start..].iter().collect();
                break;
            };
            match next {
                '[' => {
                    // CSI: params/intermediates then a final byte in 0x40..=0x7E
                    let mut j = i + 2;
                    while j < chars.len() && !('\x40'..='\x7e').contains(&chars[j]) {
                        j += 1;
                    }
                    if j >= chars.len() {
                        self.carry = chars[start..].iter().collect();
                        break;
                    }
                    let params: String = chars[i + 2..j].iter().collect();
                    match (chars[j], params.as_str()) {
                        ('n', "6") => dsr += 1,
                        ('s', "") => self.hidden = true,
                        ('u', "") => self.hidden = false,
                        _ => {}
                    }
                    i = j + 1;
                }
                ']' | 'P' | '_' | '^' => {
                    // OSC/DCS/APC/PM: terminated by BEL or ST (ESC \)
                    let mut j = i + 2;
                    let mut end = None;
                    while j < chars.len() {
                        if chars[j] == '\x07' {
                            end = Some(j + 1);
                            break;
                        }
                        if chars[j] == '\x1b' {
                            if j + 1 >= chars.len() {
                                break;
                            }
                            if chars[j + 1] == '\\' {
                                end = Some(j + 2);
                                break;
                            }
                        }
                        j += 1;
                    }
                    match end {
                        Some(e) => i = e,
                        None => {
                            self.carry = chars[start..].iter().collect();
                            break;
                        }
                    }
                }
                // Two-char escapes (ESC 7, ESC 8, ESC =, ...)
                '7' => {
                    self.hidden = true;
                    i += 2;
                }
                '8' => {
                    self.hidden = false;
                    i += 2;
                }
                _ => i += 2,
            }
        }
        (out, dsr)
    }
}

/// Apply carriage-return overwrite semantics to a single line: only the text
/// after the last `\r` remains visible.
fn after_last_cr(line: &str) -> &str {
    match line.rfind('\r') {
        Some(i) => &line[i + 1..],
        None => line,
    }
}

/// Banner hai's own secret prompts print before reading with rpassword (see
/// `StdinInput::ask_secret`).
const HAI_SECRET_BANNER: &str = "SECRET";

/// Turn a remote prompt into a query message and whether it's secret.
///
/// A remote PTY doesn't tell us when the program disables echo, so secrecy
/// is inferred from the prompt text: hai's `SECRET` banner (which is stripped
/// since the client renders secrecy itself) or common password-ish keywords.
/// Keyword matching errs toward secrecy: a false positive only hides the
/// typed answer, while a false negative would display a secret.
fn classify_prompt(prompt: &str) -> (String, bool) {
    let prompt = prompt.trim();
    if let Some(rest) = prompt.strip_prefix(HAI_SECRET_BANNER) {
        return (rest.trim().to_string(), true);
    }
    let p = prompt.to_lowercase();
    let secret = [
        "password",
        "passphrase",
        "passcode",
        "pin:",
        "token",
        "secret",
    ]
    .iter()
    .any(|k| p.contains(k));
    (prompt.to_string(), secret)
}

/// Whether `line` is a line editor's redraw of `expected` (prompt + answer)
/// after Enter. Whitespace is ignored since editors may pad the prompt.
fn is_redraw(line: &str, expected: &str) -> bool {
    let strip = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let expected = strip(expected);
    !expected.is_empty() && strip(line) == expected
}

/// Decode bytes into a String without breaking multi-byte chars split across
/// chunks. Incomplete trailing bytes are kept in `carry` for the next call.
fn decode_utf8_chunk(carry: &mut Vec<u8>, data: &[u8]) -> String {
    carry.extend_from_slice(data);
    match std::str::from_utf8(carry) {
        Ok(s) => {
            let s = s.to_string();
            carry.clear();
            s
        }
        Err(e) if e.error_len().is_some() => {
            // Truly invalid bytes: decode lossily and reset.
            let s = String::from_utf8_lossy(carry).into_owned();
            carry.clear();
            s
        }
        Err(e) => {
            let valid = e.valid_up_to();
            let s = String::from_utf8_lossy(&carry[..valid]).into_owned();
            carry.drain(..valid);
            s
        }
    }
}
