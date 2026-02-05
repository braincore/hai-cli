use crate::{
    config,
    tool::{FnTool, FnToolType, Tool},
};
use serde_json::{Value, json};

/// # Arguments
/// - schema_key_name: "parameters" for OpenAI; "input_schema" for Anthropic.
/// - shell: Allows AI to tailor the command especially since bash and
///   powershell are rather different.
pub fn get_tool_schema(tool: &Tool, schema_key_name: &str, shell: &str) -> Value {
    let tool_name = get_tool_name(tool);
    let system = config::get_machine_os_arch();
    match tool {
        Tool::CopyToClipboard => json!({
            "name": tool_name,
            "description": "Copies the input to the system clipboard at the user's request.",
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "The contents to be copied."
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::ExecPythonScript => json!({
            "name": tool_name,
            "description": format!("Execute a Python script. Everything the user wants should be printed to stdout.\nSystem = {}", system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "Python3-compatible script. The script should print important values to stdout.",
                    },

                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::ExecPythonUvScript => json!({
            "name": tool_name,
            "description": format!("Execute a Python script with support for installing script dependencies. Everything the user wants should be printed to stdout.\nSystem = {}", system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": r#"Python3-compatible script. The script should print important values to stdout.

If you use non-standard libraries, you must specify them with the following syntax at the beginning of input:

```python
# /// script
# requires-python = ">=3.12"  # Omit if unnecessary
# dependencies = [
#   "example-python-pkg-1",
#   "example-python-pkg-2>=version",  # Version spec if necessary
# ]
# ///
```
"#,
                    },

                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::Fn(FnTool {
            kind: FnToolType::FnPy,
            ..
        }) => json!({
            "name": tool_name,
            "description": "Define a Python function f(arg: Any) -> Any. It must be named `f`.",
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": r#"A Python function definition. IT MUST
BE NAMED `f`.

All dependencies including imports and other functions should be defined in
this function. The signature can be narrowed to something more specific than
`f(arg: Any) -> Any`. If so, use the correct Python type annotations.

The user will only see output to stdout. The return value can be used for
recursive functions, but otherwise, the user won't see it and it should be
omitted (None) by default."#
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::Fn(FnTool {
            kind: FnToolType::FnPyUv,
            ..
        }) => json!({
            "name": tool_name,
            "description": "Define a Python function f(arg: Any) -> Any. It must be named `f`.",
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": r#"A Python function definition. IT MUST
BE NAMED `f`.

The signature can be narrowed to something more specific than
`f(arg: Any) -> Any`. If so, use the correct Python type annotations.

The user will only see output to stdout. The return value can be used for
recursive functions, but otherwise, the user won't see it and it should be
omitted (None) by default.

All import statements should be within the function definition.

If you use non-standard libraries, you must specify them above the function
definition with the following syntax:

```python
# /// script
# requires-python = ">=3.12"  # Omit if unnecessary
# dependencies = [
#   "example-python-pkg-1",
#   "example-python-pkg-2>=version",  # Version spec if necessary
# ]
# ///

This is the only text allowed above the function definition.
```"#
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::Fn(FnTool {
            kind: FnToolType::FnSh,
            ..
        }) => json!({
            "name": tool_name,
            "description": "Define a shell script that implements the prompt.",
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": r#"A shell script. The input to the
script is available in a variable called `arg` so just use it. There's no
reason to prompt the user with read for the input.

The script should print important values to stdout."#
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::Html => json!({
            "name": tool_name,
            "description": format!("Generate HTML <body> tag (including embedded javascript/css) to implement the prompt.\nSystem = {}", system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "HTML <body></body> tag that will be injected. It can include embedded javascript and CSS.",
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        }),
        Tool::ShellScriptExec => json!({
            "name": tool_name,
            "description": format!("Execute a Shell script. Everything the user wants should be printed to stdout.\nShell = {}\nSystem = {}", shell, system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    "_continue": {
                        "type": "string",
                        "description": "Set this if the user's request requires you to interpret, analyze, or comment on the tool output; you will be able to respond after seeing the results before the user. Describe what you'll analyze."
                    },
                    "input": {
                        "type": "string",
                        "description": "Shell script. The script should print important values to stdout."
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
                "description": "If set, provide the `_continue` property before the `input` property in your response."
            },
        }),
        Tool::ShellExecWithFile(cmd, ext) => json!({
            "name": tool_name,
            "description": format!("Executes program: {}\n{{file}} is replaced with a temporary file\nShell = {}\nSystem = {}", cmd, shell, system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    // Prefixing with _ coaxes the AI to return the key first.
                    "_lang_tag": {
                        "type": "string",
                        "description": "The lang tag to be used in a markdown code block to syntax highlight the `input`. If not applicable, set to empty string.",
                    },
                    "input": {
                        "type": "string",
                        "description": format!("Executes program with this input passed as a temporary file {{file}} with ext={}. If it's a script, be aware that important values should be printed to stdout.", ext.as_ref().unwrap_or(&"none".to_string()))
                    },
                },
                "required":["_lang_tag", "input"],
                "additionalProperties": false,
                "description": "Provide the `_lang_tag` property before the `input` property in your response."
            },
        }),
        Tool::ShellExecWithStdin(cmd) => json!({
            "name": tool_name,
            "description": format!("Executes program: {}\nShell = {}\nSystem = {}", cmd, shell, system),
            schema_key_name: {
                "type": "object",
                "properties": {
                    // Prefixing with _ coaxes the AI to return the key first.
                    "_lang_tag": {
                        "type": "string",
                        "description": "The lang tag to be used in a markdown code block to syntax highlight the `input`. If not applicable, set to empty string.",
                    },
                    "input": {
                        "type": "string",
                        "description": "Executes program with this script passed via stdin. The script should print important values to stdout."
                    },
                },
                "required": ["_lang_tag", "input"],
                "additionalProperties": false,
                "description": "Provide the `_lang_tag` property before the `input` property in your response."
            },
        }),
        Tool::HaiRepl => json!({
            "name": tool_name,
            "description": r#"
Executes a series of hai-repl-commands.

Do not call this tool twice in one go, just use multiple elements in `cmds`.

Each hai-command can start with "/" or "!" (ask AI to use a tool). The behavior
without either prefix is for the message to be prompted to the AI. Some commands
can span multiple lines (e.g. /asset-new).

You can return 0 cmds or as many as you like. The AI will execute them in the
order they are given. Each successive command has access to the outputs of the
previous commands.

After every hai-command, the output whether it's a local program execution,
tool use, or AI response is available in the REPL-history that the next
hai-command can read and use.

If you don't have enough information to complete the prompt asked of you,
consider PROMPTING YOURSELF by including a `!hai <revised prompt>` in the list
of `cmds`.
"#,
            schema_key_name: {
                "type": "object",
                "properties": {
                    "cmds": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "description": r#"
Available Commands:

/prompt <prompt>      - Sends a message to the AI and gets a response
/ask-human <question> - Prompt the user with a question and add their answer to the conversation.

--

/cd <path>            - Change current working directory

--

/account              - See current and available accounts
/whois <username>     - Look up a user (try `ken`)

--

/load <glob path>     - Load files into the conversation (e.g., `/load src/**/*.py`)
                        Supports text files or PNG/JPG images
/load-url <url>       - Load the URL into the conversation
/exec <cmd>           - Executes a shell command and adds the output to this conversation.
                        The <cmd> can be treated as a bash shell command. One deviation
                        is the use of `@name` where a file would typically be specified.
                        `@name` will transparently be converted to the referenced asset
                        by `name` which avoids the need to `/asset-import` them to the
                        local filesystem. Shell output redirection (>) to `@name` will
                        be uploaded to the `@name` asset avoiding `/asset-export`.
/prep <msg>           - Add message to converation without prompting AI for response.
/prep(<accent>) <msg> - Adds message with accent color: danger, warn, info, success
/pin                  - Like /prep but the message is retained on /reset
/pin(<accent>) <msg>  - Add /pin with accent color: danger, warn, info, success
/clip                 - Copies the last message to your clipboard. Unlike !clip tool, AI is not prompted

--

Available Tools:
!sh <prompt>          - Ask AI to write shell script or pipeline that will be executed on your machine
!py <prompt>          - Ask AI to write Python script that will be executed on your machine
                        Searches for virtualenv in current dir & ancestors before falling back to python3
!pyuv <prompt>        - Ask AI to write Python script with inline dependencies auto-installed via uv
!html <prompt>        - Ask AI to write HTML/CSS/JS and open in system browser
!'<cmd>' <prompt>     - Ask AI to write script that will be piped to this cmd through stdin
                        e.g. !'uv run --python 3 --with geopy -' distance from san francisco to nyc
                        If `{file}` present in `<cmd>`, AI output written to temporary file
                        and substituted for `{file}` in the command
!hai <prompt>         - Ask AI to generate REPL commands to fulfill the prompt with the
                        full conversation as context. It's a way for an AI to recursively call
                        itself to construct a new set of commands based on new information in
                        the conversation.
!clip <prompt>        - Ask AI to copy a part of the conversation to your clipboard
! <prompt>            - Re-use previous tool with new prompt
!                     - Re-use previous tool and prompt

Function Tools:
!fn-py <prompt>       - Ask AI to write a Python function that can be invoked with `/f<index>`.
                        The function will take a single argument. The function will be given a name
                        `f<index>` where `index>` is a unique number which can be used to invoke it
                        as `/f<index>`.
!fn-pyuv <prompt>     - Similar to `!fn-py` but `uv` is used allowing for the function to use
                        additional library dependencies via a script dependency comment section.
!fn-sh <prompt>       - Ask AI to write a shell script that can be invoked with `/f<index>`.
                        The function will take a single argument. The function will be given a name
                        `f<index>` where `index>` is a unique number which can be used to invoke it
                        as `/f<index>`.
/f<index> <arg>       - Invoke a AI-defined reusable function with the given index.
                        For Python, `arg` must be a Python expression that can be evaluated.
                        For shell, `arg` must be a shell value or expression.

--

Standard Library Functions:
/std now              - Print current date and time
/std new-day-alert    - Make AI aware when a new day begins since the last interaction
/std which <prog>     - Checks if program is available.

--

Assets:

- Asset names that begin with `/<username>` are public assets that can be accessed by anyone.
- Asset names that begin with `//` are expanded to `/<username>/` automatically.

/asset-new <name><NEWLINE><body> - Create/replace a `doc` asset. This is a MULTI-line command.
                           - Use a newline after `name` to write arbitrary multi-line content to the asset.

/asset-list <prefix>    - List assets with the given (optional) prefix. Supports globs.
/asset-search <query>   - Search for assets semantically
/asset-load <name> [<name> ...]   - Load asset(s) into the conversation
/asset-view <name> [<name> ...]   - Print asset(s) contents and loads into the conversation
/asset-link <name>      - Prints link to asset (valid for 24hr) and loads into the conversation
/asset-revisions <name> <count> - Lists <count> number of revisions of an asset
/asset-listen <name> [<cursor>] - Blocks until a change to an asset. On a change, prints out
                                  information about the asset. If cursor is set, begins listening
                                  at that specific revision to ensure no changes are missed.
/asset-push <name><NEWLINE><body> - Push data into an asset. See pushed data w/ `/asset-revisions`
                            - Use a newline after `name` to push arbitrary multi-line content.
/asset-import <name> <path>   - Imports <path> from local machine into asset with <name>
/asset-export <name> <path>   - Exports asset with name to <path> on local machine
/asset-temp <name> [<count>]  - Exports asset & metadata to temp files.
                              - If count specified, that number of revisions is exported.
/asset-remove <name>    - Removes an asset
/asset-move <src> <dst> - Moves an asset from <src> to <dst>
/asset-copy <src> <dst> - Copies an asset from <src> to <dst>
/asset-md-get <name>    - Get the JSON-object metadata of an asset
/asset-md-set <name> <md>    - Set metadata for an asset. Must be a JSON object
/asset-md-set-key <name> <k> <v> - Set key to JSON value
/asset-md-del-key <name> <k> - Delete a key from an asset's metadata

--

/email <subject><NEWLINE><body> - Send an email to user.
                          - Use a newline after `subject` to specify a multi-line email body.

--

Tasks
/task <name/path>       - Enter task mode by loading task from repo (username/task-name) or file path
/task-search <query>    - Search for tasks in the repository
/task-view <name/path>  - View a task without loading it from repo or file path
/task-versions <name>   - List all versions of a task in the repo
/task-publish <path>    - Publish task to repo (requires /account-login)

Usage guideline for <NEWLINE>:

Example of /asset-new

```
/asset-new path/to/asset/abc
contents line 1
contents line 2
```


"#,
                        }
                    },
                },
                "required": ["cmds"],
                "additionalProperties": false,
            },
        }),
    }
}

pub fn get_tool_name(tool: &Tool) -> &str {
    match tool {
        Tool::HaiRepl => "hai_repl",
        Tool::CopyToClipboard => "copy_to_clipboard",
        Tool::ExecPythonScript => "exec_python_script",
        Tool::ExecPythonUvScript => "exec_python_uv_script",
        Tool::Fn(FnTool {
            kind: FnToolType::FnPy,
            ..
        }) => "fn_py",
        Tool::Fn(FnTool {
            kind: FnToolType::FnPyUv,
            ..
        }) => "fn_pyuv",
        Tool::Fn(FnTool {
            kind: FnToolType::FnSh,
            ..
        }) => "fn_sh",
        Tool::Html => "html",
        Tool::ShellExecWithFile(_, _) => "shell_exec_with_file",
        Tool::ShellExecWithStdin(_) => "shell_exec_with_stdin",
        Tool::ShellScriptExec => "shell_script_exec",
    }
}

/// WARN: Returns a best-effort Tool object from just the name of the tool as
/// specified in function-calling APIs. For certain tools, this returns a tool
/// of the correct type but with dummy internal data.
pub fn get_tool_from_name(name: &str) -> Option<Tool> {
    match name {
        "hai_repl" => Some(Tool::HaiRepl),
        "copy_to_clipboard" => Some(Tool::CopyToClipboard),
        "exec_python_script" => Some(Tool::ExecPythonScript),
        "exec_python_uv_script" => Some(Tool::ExecPythonUvScript),
        // Replaced by `shell_script_exec`
        "exec_shell_script" => Some(Tool::ShellScriptExec),
        "fn_py" => Some(Tool::Fn(FnTool {
            kind: FnToolType::FnPy,
            name: None,
        })),
        "fn_pyuv" => Some(Tool::Fn(FnTool {
            kind: FnToolType::FnPyUv,
            name: None,
        })),
        "fn_sh" => Some(Tool::Fn(FnTool {
            kind: FnToolType::FnSh,
            name: None,
        })),
        "html" => Some(Tool::Html),
        // Replaced by `shell_script_exec`
        "shell_exec" => Some(Tool::ShellScriptExec),
        "shell_exec_with_file" => Some(Tool::ShellExecWithFile("UNKNOWN".to_string(), None)),
        // This is deprecated, but included for compatibility with old saved
        // chats.
        "shell_exec_with_script" => Some(Tool::ShellExecWithStdin("UNKNOWN".to_string())),
        "shell_exec_with_stdin" => Some(Tool::ShellExecWithStdin("UNKNOWN".to_string())),
        "shell_script_exec" => Some(Tool::ShellScriptExec),

        _ => None,
    }
}

/// Must be kept in sync with tool:get_tool_sytax_highlighter_lang_token.
/// Useful when interpretting old AI chat history where the tool::Tool object
/// is no longer available but a string representation of the tool name is.
pub fn get_syntax_highlighter_token_from_tool_name(name: &str) -> Option<String> {
    match name {
        "hai_repl" => None,
        "copy_to_clipboard" => None,
        "exec_python_script" => Some("py".to_string()),
        "exec_python_uv_script" => Some("py".to_string()),
        // Replaced by `shell_script_exec`
        "exec_shell_script" => Some("bash".to_string()),
        "fn_py" => Some("py".to_string()),
        "fn_pyuv" => Some("py".to_string()),
        "fn_sh" => Some("sh".to_string()),
        "html" => Some("html".to_string()),
        // Replaced by `shell_script_exec`
        "shell_exec" => Some("bash".to_string()),
        "shell_exec_with_file" => None,
        // This is deprecated, but included for compatibility with old saved
        // chats.
        "shell_exec_with_script" => Some("bash".to_string()),
        "shell_exec_with_stdin" => Some("bash".to_string()),
        "shell_script_exec" => Some("bash".to_string()),
        _ => None,
    }
}
