use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::clipboard;

#[derive(Clone, Debug)]
pub enum Tool {
    CopyToClipboard,
    ExecPythonScript,
    ExecShellScript,
    ShellExec,
    ShellExecWithScript(String),
    HaiRepl,
}

/// Convert tool to repl command w/o prompt.
pub fn tool_to_cmd(tool: &Tool, require: bool) -> String {
    let tool_symbol = if require { "!" } else { "!?" };
    let tool_cmd = match tool {
        Tool::CopyToClipboard => "clip",
        Tool::ExecPythonScript => "py",
        Tool::ExecShellScript => "shscript",
        Tool::HaiRepl => "hai",
        Tool::ShellExec => "sh",
        Tool::ShellExecWithScript(cmd) => &format!("'{}'", cmd),
    };
    format!("{}{}", tool_symbol, tool_cmd)
}

#[derive(Clone, Debug)]
pub struct ToolPolicy {
    pub tool: Tool,
    /// Whether the AI is required to use this tool
    pub require: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ToolShellBasedArg {
    input: String,
}

pub async fn execute_shell_based_tool(
    tool: &Tool,
    arg: &str,
    shell: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let input = serde_json::from_str::<ToolShellBasedArg>(arg)?.input;
    Ok(match tool {
        Tool::CopyToClipboard => copy_to_clipboard(&input)?,
        Tool::ExecPythonScript => exec_python_script(&input).await?,
        Tool::ExecShellScript => exec_shell_script(shell, &input).await?,
        Tool::ShellExec => shell_exec(shell, &input).await?,
        Tool::ShellExecWithScript(cmd) => shell_exec_with_script(shell, cmd, &input).await?,
        _ => "fatal: not a shell-based tool".to_string(),
    })
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ToolHaiReplArg {
    cmds: Vec<String>,
}

pub fn execute_hai_repl_tool(
    tool: &Tool,
    arg: &str,
    cmd_queue: &mut VecDeque<((String, u32), String)>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cmds = serde_json::from_str::<ToolHaiReplArg>(arg)?.cmds;
    Ok(match tool {
        Tool::HaiRepl => {
            for (index, cmd) in cmds.iter().enumerate().rev() {
                cmd_queue.push_front((("hai-tool".to_string(), index as u32), cmd.clone()));
            }
            let output = format!("Pushed {} command(s) into queue", cmds.len());
            println!("{}", output);
            output
        }
        _ => "fatal: not a hai-repl tool".to_string(),
    })
}

// -- Shell-based tools

pub fn copy_to_clipboard(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    clipboard::copy_to_clipboard(text);
    println!("Copied to clipboard");
    Ok("Copied to clipboard".into())
}

/// `exec_python_script` is the execution of a python3 process that's fed a
/// script via stdin.
pub async fn exec_python_script(script: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Use the `.venv/bin/python` if found, otherwise fallback to "python3"
    let python_exec = find_python_in_venv();
    let mut child = Command::new(python_exec)
        .arg("-c")
        .arg(script)
        // Allow the script to read from the terminal's stdin
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    collect_and_print_command_output(&mut child).await
}

/// Searches for .venv/bin/python in the current and ancestor directories. It
/// returns the path to the Python executable if found, otherwise falls back
/// to the default "python3".
fn find_python_in_venv() -> String {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut dir = Some(current_dir.as_path());

    // Traverse from the current directory up to the root
    while let Some(current_dir) = dir {
        let venv_python_path = current_dir.join(".venv").join("bin").join("python");
        if venv_python_path.exists() {
            return venv_python_path.to_string_lossy().into_owned();
        }
        dir = current_dir.parent(); // Go up one directory
    }

    // Fallback to system Python
    "python3".to_string()
}

/// `shell_exec` is the execution of a program on the "command line".
/// No stdin is provided.
pub async fn shell_exec(shell: &str, cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    collect_and_print_command_output(&mut child).await
}

/// `exec_shell_script` is the execution of a shell that's fed a script via
/// stdin.
pub async fn exec_shell_script(
    shell: &str,
    script: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(script)
        // Allow the script to read from the terminal's stdin
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    collect_and_print_command_output(&mut child).await
}

/// `shell_exec_with_script` executes a specified program on the "command line"
/// and feeds a script via stdin.
pub async fn shell_exec_with_script(
    shell: &str,
    cmd: &str,
    script: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
    } else {
        return Err("Failed to open stdin".into());
    }
    collect_and_print_command_output(&mut child).await
}

pub async fn collect_and_print_command_output(
    child: &mut tokio::process::Child,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stdout = child.stdout.take().ok_or("Failed to open stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to open stderr")?;

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    let mut output_text = String::new();
    let mut stdout_done = false;
    let mut stderr_done = false;

    loop {
        tokio::select! {
            stdout_line = stdout_reader.next_line(), if !stdout_done => {
                match stdout_line {
                    Ok(Some(line)) => {
                        println!("{}", line);
                        output_text.push_str(&(line + "\n"));
                    }
                    Ok(None) => stdout_done = true,
                    Err(e) => return Err(e.into()),
                }
            }
            stderr_line = stderr_reader.next_line(), if !stderr_done => {
                match stderr_line {
                    Ok(Some(line)) => {
                        eprintln!("{}", line);
                        output_text.push_str(&(line + "\n"));
                    }
                    Ok(None) => stderr_done = true,
                    Err(e) => return Err(e.into()),
                }
            }
            else => break,
        }
        if stdout_done && stderr_done {
            break;
        }
    }

    match child.wait().await {
        Ok(status) => {
            if status.success() {
                Ok(output_text)
            } else {
                Ok(format!(
                    "{}Process exited with status: {}",
                    if output_text.len() > 0 {
                        format!("{}\n", output_text)
                    } else {
                        "".to_string()
                    },
                    status.code().unwrap_or(-256)
                ))
            }
        }
        Err(e) => Err(e.into()),
    }
}
