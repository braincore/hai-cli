pub mod asset_app;
pub mod asset_crypt;
pub mod asset_keyring;
pub mod gateway;
pub mod haibot;
pub mod haivar;
pub mod html_tool;
pub mod mcp;
pub mod queue_listen;
pub mod save_chat;

/// Returns the command and args needed to re-invoke this program.
fn self_invocation() -> (String, Vec<String>) {
    // For dev: check if running under `cargo`` which sets `CARGO` env var.
    if let Ok(cargo) = std::env::var("CARGO") {
        // Silence build output
        let mut args = vec!["run".to_string(), "-q".to_string()];

        // Preserve package name if in a workspace
        if let Ok(pkg) = std::env::var("CARGO_PKG_NAME") {
            args.push("-p".to_string());
            args.push(pkg);
        }
        args.push("--".to_string());
        return (cargo, args);
    }

    // Production/non-dev: use the current executable
    let exe = std::env::current_exe()
        .expect("Failed to determine current executable path")
        .to_string_lossy()
        .to_string();

    (exe, vec![])
}
