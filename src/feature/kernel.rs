use serde::{Deserialize, Serialize};
use std::io::Write;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

use crate::db;
use crate::feature::gateway::{GATEWAY_BASE_PORT, generate_token};
use crate::io::Io;

// Base port for kernel websockets to begin searching for available ports.
pub const KERNEL_BASE_PORT: u16 = GATEWAY_BASE_PORT + 200;

/// This string is emitted by the kernel process on stdout when it is ready
/// to accept connections. This makes it less fragile for the parent to find
/// the kernel's readiness announcement amidst other stdout.
const KERNEL_READY_PREFIX: &str = "HAI_KERNEL_READY ";

/// This is the message emitted by a kernel process on stdout when it is ready.
/// It is emitted as JSON after the ready prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelReady {
    pub port: u16,
    pub token: String,
}

/// Use this on REPL start up to make it a kernel process.
///
/// This function is responsible for generating its own auth token and binding
/// to a port.
///
/// # Returns
/// - `Io`: A websocket I/O object for communicating with the kernel.
/// - `JoinHandle<()>`: A handle to the kernel actor task. `await` it for
///   clean up.
pub async fn run_kernel(
    account: Option<db::Account>,
) -> std::io::Result<(Io, tokio::task::JoinHandle<()>)> {
    // Find an open port
    let mut port = KERNEL_BASE_PORT;
    let listener = loop {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => break l,
            Err(_) => {
                port += 1;
                if port > KERNEL_BASE_PORT + 100 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "no free kernel port",
                    ));
                }
            }
        }
    };
    let port = listener.local_addr()?.port();

    // Generate an auth token that will be required to connect to the kernel.
    let token = generate_token();

    // Print "ready" message for parent.
    {
        let ready = serde_json::to_string(&KernelReady {
            port,
            token: token.clone(),
        })
        .expect("serialize readiness");
        // Guarantee readiness goes to stdout (avoid our io machinery).
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{KERNEL_READY_PREFIX}{ready}");
        let _ = out.flush();
    }

    use crate::cmd_registry;
    use crate::io_ws::{WsActor, WsInput, WsOutput};
    use tokio::sync::mpsc;

    // FUTURE: Obtain this from caller.
    let cmd_registry = cmd_registry::Registry::new();

    let api_client = crate::session::mk_api_client_from_account(account.as_ref());

    // Create actor for the io handler
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let actor = WsActor::new(listener, token, cmd_rx, cmd_registry, api_client, account);
    let actor_handle = tokio::spawn(actor.run());

    let io = Io::new(WsOutput::new(cmd_tx.clone()), WsInput::new(cmd_tx));

    Ok((io, actor_handle))
}

// --

//
// The below functions are for parent processes of kernels.
//

/// Read a kernel child process's stdout until it announces it's ready.
///
/// Rather than being used by the kernel process itself, this is used by the
/// parent process that spawns the kernel.
///
/// Consumes the child's stdout `BufReader` (we don't need stdout after this;
/// see the drain note below). Returns the port+token the child chose.
///
/// # Returns
///
/// On error, it's still the caller's responsibility to ensure the child is
/// fully dead.
pub async fn wait_for_kernel_ready(
    child: &mut tokio::process::Child,
    timeout: std::time::Duration,
) -> Result<KernelReady, String> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout was not piped".to_string())?;
    let mut lines = BufReader::new(stdout).lines();

    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        // Multi-select
        tokio::select! {
            // 1. A line of stdout
            line = lines.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if let Some(json) = line.strip_prefix(KERNEL_READY_PREFIX) {
                            let ready: KernelReady = serde_json::from_str(json)
                                .map_err(|e| format!("malformed readiness line: {e}"))?;
                            return Ok(ready);
                        }
                    }
                    // Unexpected: EOF on stdout before ready
                    Ok(None) => {
                        return Err(kernel_death_reason(child).await);
                    }
                    Err(e) => return Err(format!("error reading child stdout: {e}")),
                }
            }

            // 2. The kernel process died/exited.
            status = child.wait() => {
                let status = status.map_err(|e| format!("failed to wait on child: {e}"))?;
                return Err(format!("kernel exited before readiness: {status}"));
            }

            // 3. Timeout on kernel process boot.
            _ = tokio::time::sleep_until(deadline) => {
                return Err("kernel did not become ready within timeout".to_string());
            }
        }
    }
}

/// If unexpected stdout EOF, check exit status and make a best-effort error
/// message.
async fn kernel_death_reason(child: &mut tokio::process::Child) -> String {
    let status = child.wait().await;
    let mut stderr_text = String::new();
    if let Some(mut err) = child.stderr.take() {
        use tokio::io::AsyncReadExt;
        let _ = err.read_to_string(&mut stderr_text).await;
    }
    let stderr_text = stderr_text.trim();
    match status {
        Ok(s) if stderr_text.is_empty() => format!("kernel exited before ready: {s}"),
        Ok(s) => format!("kernel exited before ready: {s}: {stderr_text}"),
        Err(e) => format!("kernel died and wait failed: {e}"),
    }
}
