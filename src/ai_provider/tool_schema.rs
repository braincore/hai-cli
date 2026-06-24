use crate::{
    config,
    tool::{FnTool, FnToolType, Tool},
};
use serde_json::{Value, json};

/// # Arguments
/// - schema_key_name: "parameters" for OpenAI; "input_schema" for Anthropic.
/// - shell: Allows AI to tailor the command especially since bash and
///   powershell are rather different.
pub fn get_tool_schema(tool: &Tool, schema_key_name: &str, shell: &str, agentic: bool) -> Value {
    let tool_name = get_tool_name(tool);
    let system = config::get_machine_os_arch();
    let mut schema = match tool {
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
                    "input": {
                        "type": "string",
                        "description": "Shell script. The script should print important values to stdout."
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
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
can span multiple lines (e.g. /asset-write).

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
                        .cache=BOOL    Cache the result for the next execution (default: false)
/ask-human <question> - Prompt the user with a question and add their answer to the conversation.
                        .secret=BOOL   Hide input from terminal (default: false)
                        .cache=BOOL    Cache the result for the next execution (default: false)

--

/cd <path>            - Change current working directory

--

/account              - See current and available accounts
/whois <username>     - Look up a user (try `ken`)

--

/file-read <glob>     - Load files into the conversation (e.g., `/load src/**/*.py`)
                        Supports text files or PNG/JPG images
                        .n=BOOL   Show line numbers (default: false) (handy when asking the LLM to produce patches or refer to specific lines)
/file-write <path> <multi-line body>
                      - Create/replace a file at `path`. This is a MULTI-line command.
                        Use a newline after `path` to write arbitrary multi-line content to the file.
/file-patch <path> <multi-line body>
    - Apply a search/replace patch to an existing file. This is a MULTI-line command.
      The body contains a search block and a replace block separated by a delimiter line.
      The search block must match full lines and EXACTLY ONE location in the asset.

      The delimiter is the LONGEST run of `=` characters appearing on its own line in the
      body, so it can be disambiguated from any legitimate `=` runs in your content.

      Format:
          /file-patch path/to/file
          <search text>
          =======
          <replace text>

      Tips:
          - When typing manually, a single `=` works as the delimiter (as long as your
            content has no `=` lines).
          - LLMs should default to 7 (`=======`), and use a longer run if the content
            itself contains lines of `=`.
          - Use /file-read or /file-cat to grab exact text for building the search block.
/file-cat <glob>      - Load file(s) into the conversation and print it
                        .n=BOOL   Show line numbers (default: false) (handy when asking the LLM to produce patches or refer to specific lines)
/http-get <url>       - Load the URL into the conversation
                        .n=BOOL   Show line numbers (default: false) (handy when asking the LLM to produce patches or refer to specific lines)
                        .raw=BOOL Return raw content rather than extracting markdown (default: false)
/exec <cmd>           - Executes a shell command and adds the output to this conversation.
                        The <cmd> can be treated as a bash shell command. One deviation
                        is the use of `@@name` where a file would typically be specified.
                        `@@name` will transparently be converted to the referenced asset
                        by `name` which avoids the need to `/asset-import` them to the
                        local filesystem. Shell output redirection (>) to `@@name` will
                        be uploaded to the `@@name` asset obviating `/asset-export`.
                        .cache=BOOL  Cache the result for the next execution (default: false)
                        .i=BOOL  Run the command in interactive mode (default: false) Inherit terminal stdin/stdout/stderr (required for vim, etc.)
/prep <msg>           - Add message to converation without prompting AI for response.
                        .{danger,warn,info,success}=BOOL   Accent color (default: none)
/prep <msg>           - Adds message with accent color: danger, warn, info, success
/pin                  - Like /prep but the message is retained on /reset
                        .{danger,warn,info,success}=BOOL   Accent color (default: none)
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
                        .cache=BOOL    Cache the result for the next execution (default: false)
!fn-pyuv <prompt>     - Similar to `!fn-py` but `uv` is used allowing for the function to use
                        additional library dependencies via a script dependency comment section.
                        .cache=BOOL    Cache the result for the next execution (default: false)
!fn-sh <prompt>       - Ask AI to write a shell script that can be invoked with `/f<index>`.
                        The function will take a single argument. The function will be given a name
                        `f<index>` where `index>` is a unique number which can be used to invoke it
                        as `/f<index>`.
                        .cache=BOOL    Cache the result for the next execution (default: false)
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

/asset <name> - Opens an asset in their configured editor for interactive editing by the user.
/asset-list <prefix>    - List assets with the given (optional) prefix. Supports globs.
/asset-search <query>   - Search for assets semantically
                          .path=STRING   Specify the asset-pool to search (default: none)
/asset-read <name> [<name> ...]   - Load asset(s) into the conversation
                                    .n=BOOL    Show line numbers (default: false) (handy when asking the LLM to produce patches or refer to specific lines)
/asset-write <name> <multi-line body>
                        - Create/replace an asset with `name`. This is a MULTI-line command.
                          Use a newline after `name` to write arbitrary multi-line content.
/asset-cat <name> [<name> ...]   - Load asset(s) into the conversation and print it
                                    .n=BOOL    Show line numbers (default: false) (handy when asking the LLM to produce patches or refer to specific lines)
/asset-patch <name> <multi-line body>
    - Apply a search/replace patch to an existing asset. This is a MULTI-line command.
    The body contains a search block and a replace block separated by a delimiter line.
    The search block must match full lines and EXACTLY ONE location in the asset.

    The delimiter is the LONGEST run of `=` characters appearing on its own line in the
    body, so it can be disambiguated from any legitimate `=` runs in your content.

    Format:
        /asset-patch path/to/file
        <search text>
        =======
        <replace text>

    Tips:
        - When typing manually, a single `=` works as the delimiter (as long as your
            content has no `=` lines).
        - LLMs should default to 7 (`=======`), and use a longer run if the content
            itself contains lines of `=`.
        - Use /asset-read or /asset-cat with .n=true to grab exact text and line context
        for building the search block.
/asset-link <name>      - Prints link to asset (valid for 24hr) and loads into the conversation
/asset-revisions <name> <count> - Lists <count> number of revisions of an asset
/asset-listen <name> [<cursor>] - Blocks until a change to an asset. On a change, prints out
                                  information about the asset. If cursor is set, begins listening
                                  at that specific revision to ensure no changes are missed.
/asset-push <name> <multi-line body> - Push data as a new asset revision.
                            - Use a newline after `name` to push arbitrary multi-line content.
                            - This is for pushing data like logs or messages that operate in an
                              append-only fashion. The content will be stored as a new revision
                              each time and the history can be viewed with `/asset-revisions`.
                              This is not for editing or replacing an asset.
/asset-import <name> <path>   - Imports local <path> into asset with <name>
/asset-export <name> <path>   - Exports asset with name to local <path>
/asset-temp <name> [<count>]  - Exports asset & metadata to temp files.
                              - If count specified, that number of revisions is exported.
/asset-revision-temp <name> [<rev_id>] - Exports revision of asset & metadata to a temporary file.
/asset-sync-up <path> <prefix>   - Sync local path to asset prefix. Trailing / in the path syncs the folder's contents (rsync semantics).
/asset-sync-down <prefix> <path> - Sync assets with prefix to local path. Trailing / in the prefix syncs the folder's contents (rsync semantics).
/asset-sync-diff <path> - Show what assets have changed locally since last sync-down.
/asset-remove <name>    - Removes an asset
/asset-move <src> <dst> - Moves an asset from <src> to <dst>
/asset-copy <src> <dst> - Copies an asset from <src> to <dst>
/asset-acl-get <name> - List ACL on an asset
/asset-acl-set <name> <principal> <ace>
                      - Change ACL on an asset
                        `principal` can be `everyone` or `user:<username>`
                        `ace` is formatted as `<effect>:<permission>`
                        effect: allow, deny, inherit
                        permission: read-data, read-revisions, push-data
/asset-md-get <name>    - Get the JSON-object metadata of an asset
/asset-md-set <name> <md>    - Set metadata for an asset. Must be a JSON object
/asset-md-set-key <name> <k> <v> - Set key to JSON value
/asset-md-del-key <name> <k> - Delete a key from an asset's metadata

--

/email <subject> <multi-line body> - Send an email to default address.
                          - Use a newline after `subject` to specify a multi-line email body.
/notif <title> <multi-line body> - Send a push notification to mobile app.
                          - Use a newline after `title` to specify a multi-line notification body.

--

Tasks
/task <name/path>       - Enter task mode by loading task from repo (username/task-name) or file path
                          .key=STRING   Namespace the cache (default: none)
                          .trust=BOOL   Do not prompt for user confirmations (default: false)
/task-search <query>    - Search for tasks in the repository
/task-cat <name/path>   - Print a task without loading it from repo or file path
/task-versions <name>   - List all versions of a task in the repo
/task-publish <path>    - Publish task to repo (requires /account-login)

--

MCPs (Experimental):

/mcp-add <name> [<env>] <cmd...> - Add Model Context Protocol server.
                                   Ex: `/mcp-add git V=1 uvx -q mcp-server-git`
                                   New command is created to invoke with:
                                   `/mcp_<name> <tool_name> <json_arg>`

Web search:

/web-search <query>             - Search the web for relevant information
    .n=NUMBER Number of results (default: 5)
    .pd=BOOL Results in past day
    .pw=BOOL Results in past 7 days
    .pm=BOOL Results in past month
    .py=BOOL Results in past year
    .range=STRING Results in a specific date range (Ex: "2023-01-01to2023-12-31")

    The output is too noisy for user consumption so you should
    recursively prompt yourself (/prompt subcommand) or follow up in
    agentic mode to analyze the results and give a final answer.

--

Usage guideline for command options:

/<cmd>.<opt> (defaults option to true)
/<cmd>.<opt>=true (explicitly set bool)
/<cmd>.<opt>="" (set string)
/<cmd>.<opt>=10 (set number)
/<cmd>.<opt1>.<opt2>="" (multi-option specification)

Usage guideline for <multi-line body>:

Example of /asset-write

```
/asset-write path/to/asset/abc
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
    };
    if agentic {
        schema[schema_key_name]["properties"]["_continue"] = json!({
            "type": "string",
            "description": "Agentic. Set this if the user's request requires you to follow up on, analyze, or comment on the tool output; you will be able to respond after seeing the results before returning control to the user. Describe what you're doing next and remind yourself what the stop condition is."
        });
        let continue_note = "If set, provide the `_continue` property before the `input` property in your response.";
        let new_description = schema[schema_key_name]
            .get("description")
            .and_then(|d| d.as_str())
            .map_or(continue_note.to_string(), |existing| {
                format!("{} {}", existing, continue_note)
            });

        schema[schema_key_name]["description"] = json!(new_description);
        if let Some(properties) = schema[schema_key_name]["properties"].as_object_mut() {
            // This is a really important for UI/UX. Some models (e.g., Claude)
            // tend to return keys in the order they are defined in the schema,
            // so we want to coax the AI to return the `_continue` key first if
            // it's present to improve the flow of the output: `_continue`
            // explanation before tool invocation instructions.
            reorder_with_key_first(properties, "_continue");
        }
    }
    schema
}

/// Reorder the keys in the map so that `first_key` comes first, if it exists.
///
/// This is to coax the AI to return that key first since some models tend to
/// return keys in the order they are defined in the schema.
fn reorder_with_key_first(map: &mut serde_json::Map<String, Value>, first_key: &str) {
    // Take ownership of the whole map, leaving an empty one
    let mut old_map = std::mem::take(map);

    // Insert _continue first (if it exists)
    if let Some(first_val) = old_map.remove(first_key) {
        map.insert(first_key.to_string(), first_val);
    }

    // Insert everything else
    for (k, v) in old_map {
        map.insert(k, v);
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
