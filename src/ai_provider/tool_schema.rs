use crate::{
    cmd_registry, config,
    tool::{FnTool, FnToolType, Tool},
};
use serde_json::{Value, json};

/// # Arguments
/// - schema_key_name: "parameters" for OpenAI; "input_schema" for Anthropic.
/// - shell: Allows AI to tailor the command especially since bash and
///   powershell are rather different.
pub fn get_tool_schema(
    cmd_registry: &cmd_registry::Registry,
    tool: &Tool,
    schema_key_name: &str,
    shell: &str,
    agentic: bool,
) -> Value {
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
        Tool::HaiRepl => {
            let hai_tool_cmd_registry_rendered =
                cmd_registry::render_llm(&cmd_registry, &cmd_registry::Filter::llm());
            json!({
                    "name": tool_name,
                    "description": r#"
Executes a series of hai-repl-commands.

Do not call this tool twice in one go, just use multiple elements in `cmds`.

Each hai-command can start with "/" or "!" (ask AI to use a tool). The behavior
without either prefix is for the message to be prompted to the AI. Some commands
can have multiple lines bodies (e.g. /asset-write).

You can return 0 cmds or as many as you like. The AI will execute them in the
order they are given.

The output of each command is added to the conversation history before the next
command is executed.

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
                                    "description": hai_tool_cmd_registry_rendered,
                                }
                            },
                        },
                        "required": ["cmds"],
                        "additionalProperties": false,
                    },
            })
        }
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
