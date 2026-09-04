pub mod asset_app;
pub mod asset_crypt;
pub mod asset_keyring;
pub mod chat_store;
pub mod cmd_completer;
pub mod gateway;
pub mod haibot;
pub mod haivar;
pub mod html_tool;
pub mod kernel;
pub mod mcp;
pub mod queue_listen;

/// Returns the command and args needed to re-invoke this program.
///
/// - Re-invokes using `cargo run` if it was running under cargo.
/// - Re-invokes with the debug flag if it was present in the current
///   invocation.
///
/// # Returns
///
/// (command, args, using cargo?)
///
/// The `using cargo?` boolean is useful for adjusting usage in development
/// mode, e.g. longer timeout when waiting for invocation due to compilation
/// time.
fn self_invocation() -> (String, Vec<String>, bool) {
    // For dev: check if running under `cargo`, which sets the `CARGO` env var.
    if let Ok(cargo) = std::env::var("CARGO") {
        // Silence build output
        let mut args = vec!["run".to_string(), "-q".to_string()];

        // Preserve package name if in a workspace
        if let Ok(pkg) = std::env::var("CARGO_PKG_NAME") {
            args.push("-p".to_string());
            args.push(pkg);
        }

        // Everything after `--` is passed to our binary
        args.push("--".to_string());

        // Propagate the debug flag if present
        if let Some(flag) = debug_flag() {
            args.push(flag);
        }

        (cargo, args, true)
    } else {
        // Production/non-dev: use the current executable
        let exe = std::env::current_exe()
            .expect("Failed to determine current executable path")
            .to_string_lossy()
            .to_string();

        (exe, debug_flag().into_iter().collect(), false)
    }
}

/// Returns the `-d` / `--debug` flag if this process was invoked with it.
fn debug_flag() -> Option<String> {
    std::env::args().find(|a| a == "-d" || a == "--debug")
}
