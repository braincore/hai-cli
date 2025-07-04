use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{clipboard, session};

#[derive(Clone, Debug)]
pub enum Tool {
    CopyToClipboard,
    ExecPythonScript,
    ExecPythonUvScript,
    ExecShellScript,
    Fn(FnTool),
    HaiRepl,
    ShellExec,
    /// (file_contents, extension)
    /// Extension is important because some programs make decisions based on
    /// the file's extension. For example, `uv run {file}` does not execute the
    /// `file`` unless it has a .py extension. It also lets us add syntax
    /// highlighting.
    ShellExecWithFile(String, Option<String>),
    ShellExecWithStdin(String),
}

#[derive(Clone, Debug)]
pub enum FnTool {
    FnPy,
    FnPyUv,
}

/// Convert tool to repl command w/o prompt.
pub fn tool_to_cmd(tool: &Tool, user_confirmation: bool, force_tool: bool) -> String {
    let tool_symbol = if user_confirmation { "!?" } else { "!" };
    let tool_cmd = match tool {
        Tool::CopyToClipboard => "clip",
        Tool::ExecPythonScript => "py",
        Tool::ExecPythonUvScript => "pyuv",
        Tool::ExecShellScript => "shscript",
        Tool::Fn(FnTool::FnPy) => "fn-py",
        Tool::Fn(FnTool::FnPyUv) => "fn-pyuv",
        Tool::HaiRepl => "hai",
        Tool::ShellExec => "sh",
        Tool::ShellExecWithFile(cmd, ext) => {
            if let Some(ext) = ext {
                &format!("{}.{}", cmd, ext)
            } else {
                &cmd.to_string()
            }
        }
        Tool::ShellExecWithStdin(cmd) => &format!("'{}'", cmd),
    };
    let force_tool_symbol = if force_tool { "" } else { "?" };
    format!("{}{}{}", tool_symbol, tool_cmd, force_tool_symbol)
}

/// The cmd-string for shell-exec-with-file supports {file.EXT} placeholders
/// where the extension is optional. This regex identifies this placeholder and
/// extract the optional extension.
pub fn get_file_placeholder_re() -> &'static Regex {
    static FILE_PLACEHOLDER_RE: OnceLock<Regex> = OnceLock::new();
    FILE_PLACEHOLDER_RE.get_or_init(|| Regex::new(r"\{file(?:\.([a-zA-Z0-9_.-]+))?\}").unwrap())
}

pub fn get_tool_syntax_highlighter_lang_token(tool: &Tool) -> Option<String> {
    match tool {
        Tool::CopyToClipboard => None,
        Tool::ExecPythonScript => Some("py".to_string()),
        Tool::ExecPythonUvScript => Some("py".to_string()),
        Tool::ExecShellScript => Some("bash".to_string()),
        Tool::Fn(FnTool::FnPy) => Some("py".to_string()),
        Tool::Fn(FnTool::FnPyUv) => Some("py".to_string()),
        Tool::HaiRepl => None,
        Tool::ShellExec => Some("bash".to_string()),
        // WARN: The work hasn't been done to ensure that syntax-highlighter
        // tokens match all file extensions correctly.
        Tool::ShellExecWithFile(_, ext) => ext.to_owned(),
        Tool::ShellExecWithStdin(_) => Some("bash".to_string()),
    }
}

#[derive(Clone, Debug)]
pub struct ToolPolicy {
    pub tool: Tool,
    /// Whether user confirmation is required to execute the tool
    pub user_confirmation: bool,
    /// Whether the AI is required to use this tool
    pub force_tool: bool,
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
        Tool::ExecPythonUvScript => exec_python_uv_script(&input).await?,
        Tool::ExecShellScript => exec_shell_script(shell, &input).await?,
        Tool::ShellExec => shell_exec(shell, &input).await?,
        Tool::ShellExecWithStdin(cmd) => shell_exec_with_stdin(shell, cmd, &input).await?,
        Tool::ShellExecWithFile(cmd, ext) => {
            shell_exec_with_file(shell, cmd, &input, ext.as_deref()).await?
        }
        _ => "fatal: not a shell-based tool".to_string(),
    })
}

pub async fn execute_ai_defined_tool(
    fn_tool: &FnTool,
    fn_def: &str,
    arg: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let script = format!(
        r#"{}

if __name__ == "__main__":
    import json
    arg = {}
    res = f(arg)
    print(json.dumps(res))
"#,
        fn_def, arg
    );
    if matches!(fn_tool, FnTool::FnPyUv) {
        exec_python_uv_script(&script).await
    } else {
        exec_python_script(&script).await
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ToolHaiReplArg {
    pub cmds: Vec<String>,
}

pub fn execute_hai_repl_tool(
    tool: &Tool,
    arg: &str,
    cmd_queue: &mut VecDeque<session::CmdInput>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cmds = serde_json::from_str::<ToolHaiReplArg>(arg)?.cmds;
    let cmd_count = cmds.len();
    Ok(match tool {
        Tool::HaiRepl => {
            for (index, cmd) in cmds.into_iter().enumerate().rev() {
                cmd_queue.push_front(session::CmdInput {
                    input: cmd.clone(),
                    source: session::CmdSource::HaiTool(index as u32),
                });
            }
            let output = format!("Pushed {} command(s) into queue", cmd_count);
            println!("{}", output);
            output
        }
        _ => "fatal: not a hai-repl tool".to_string(),
    })
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ToolAiDefineFnArg {
    input: String,
}

pub fn extract_ai_defined_fn_def(arg: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str::<ToolAiDefineFnArg>(arg)?.input)
}

// -- Shell-based tools

pub fn copy_to_clipboard(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    clipboard::copy_to_clipboard(text);
    println!("Copied to clipboard");
    Ok("Copied to clipboard".into())
}

/// Executes python3 with a script provided by the -c flag.
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

/// Executes python3 via `uv run`.
///
/// The advantage over `exec_python_script` is that it allows the script to
/// automatically install "script dependencies".
pub async fn exec_python_uv_script(script: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut temp_file = NamedTempFile::with_suffix(".py")?;
    temp_file.write_all(script.as_bytes())?;
    temp_file.flush()?;
    let mut child = Command::new("uv")
        .arg("--quiet") // Suppress uv's output (especially installation msgs)
        .arg("run")
        .arg(temp_file.path())
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

/// `shell_exec_with_file` executes a specified program on the "command line"
/// and replaces `{file}` in the command with a temporary file containing
/// the provided file contents.
pub async fn shell_exec_with_file(
    shell: &str,
    cmd: &str,
    file_contents: &str,
    ext: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut temp_file = if let Some(ext) = ext {
        NamedTempFile::with_suffix(format!(".{}", ext))?
    } else {
        NamedTempFile::new()?
    };
    temp_file.write_all(file_contents.as_bytes())?;
    temp_file.flush()?;
    let prepared_cmd = get_file_placeholder_re()
        .replace(cmd, &temp_file.path().to_string_lossy())
        .into_owned();
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(prepared_cmd)
        // Allow the script to read from the terminal's stdin
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    collect_and_print_command_output(&mut child).await
}

/// `shell_exec_with_stdin` executes a specified program on the "command line"
/// and feeds a script via stdin.
pub async fn shell_exec_with_stdin(
    shell: &str,
    cmd: &str,
    stdin: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin.write_all(stdin.as_bytes()).await?;
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
                    if !output_text.is_empty() {
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
