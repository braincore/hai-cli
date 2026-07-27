use std::collections::HashMap;
use tokio::process::Command;

use rmcp::{
    ServiceExt,
    model::ListToolsResult,
    service::{RoleClient, RunningService},
    transport::{ConfigureCommandExt, TokioChildProcess},
};

use crate::{errorln, io::Out, outln};

pub type McpService = RunningService<RoleClient, ()>;

pub async fn init_mcp(out: &Out, cmd: &str) -> Option<(McpService, ListToolsResult)> {
    let cmd_parts = cmd.split_whitespace();

    let mut env = HashMap::new();
    let mut command = None;
    let mut args = Vec::new();

    for part in cmd_parts {
        if command.is_none() && part.contains('=') {
            let (k, v) = part.split_once('=').unwrap();
            env.insert(k.to_string(), v.to_string());
        } else if command.is_none() {
            command = Some(part.to_string());
        } else {
            args.push(part.to_string());
        }
    }

    let command = if let Some(command) = command {
        command
    } else {
        errorln!(out, "no command provided");
        return None;
    };

    let cmd = Command::new(&command).configure(|cmd| {
        cmd.args(&args);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.env("TERM", "dumb");
        cmd.env("NO_COLOR", "1");
        cmd.env("FORCE_COLOR", "0");
    });

    let transport = match TokioChildProcess::new(cmd) {
        Ok(transport) => transport,
        Err(e) => {
            errorln!(out, "failed to start process: {}", e);
            return None;
        }
    };

    let service = match ().serve(transport).await {
        Ok(service) => service,
        Err(e) => {
            errorln!(out, "failed to initialize MCP service: {}", e);
            return None;
        }
    };
    let server_info = service.peer_info();
    outln!(out, "Connected to server: {server_info:#?}");

    let tools = match service.list_tools(None).await {
        Ok(tools) => tools,
        Err(e) => {
            errorln!(out, "failed to list tools from MCP service: {}", e);
            return None;
        }
    };
    outln!(
        out,
        "Tools: {}",
        serde_json::to_string_pretty(&tools).expect("Failed to serialize tools")
    );

    Some((service, tools))
}
