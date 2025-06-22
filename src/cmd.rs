use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::tool;

#[derive(Clone, Debug)]
/// Represents all possible commands in the program's REPL
pub enum Cmd {
    /// No-op
    Noop,
    /// New conversation
    New,
    /// Reset conversation but retain /load-ed and /pin-ed data
    Reset,
    /// Quit the REPL
    Quit,
    /// Halp!
    Help(HelpCmd),
    /// Prompt the AI
    Prompt(PromptCmd),
    /// Change directory
    Cd(CdCmd),
    /// Switch AI model
    Ai(AiCmd),
    /// Set default AI model
    AiDefault(AiDefaultCmd),
    /// Set AI Provider API key
    SetKey(SetKeyCmd),
    /// Set masking on/off
    SetMaskSecrets(SetMaskSecretsCmd),
    /// Set hai-router on/off
    HaiRouter(HaiRouterCmd),
    /// Get/set AI model temperature
    Temperature(TemperatureCmd),
    /// Executes a shell command
    Exec(ExecCmd),
    /// Print all haivars
    PrintVars,
    /// Set a haivar variable
    SetVar(SetVarCmd),
    /// Load files into conversation
    Load(LoadCmd),
    /// Load URL into conversation
    LoadUrl(LoadUrlCmd),
    /// Add pinned message to conversation
    Pin(PinCmd),
    /// Add a message without triggering an AI response
    Prep(PrepCmd),
    /// Get/set system prompt
    SystemPrompt(SystemPromptCmd),
    /// Forgot messages in the conversation
    Forget(ForgetCmd),
    /// Keep messages in the conversation and forget the rest
    Keep(KeepCmd),
    /// Copy last message to clipboard
    Clip,
    /// Ask AI to use a tool
    Tool(ToolCmd),
    /// Enter tool mode
    ToolMode(ToolModeCmd),
    /// Exit tool mode
    ToolModeExit,
    /// Ask-human command to manually input data
    AskHuman(AskHumanCmd),
    /// Task-mode command for specific .haitask
    Task(TaskCmd),
    /// End current task-mode
    TaskEnd,
    /// Forget cached answers for ask-human in a specific .haitask
    TaskForget(TaskForgetCmd),
    /// Purge task from machine
    TaskPurge(TaskPurgeCmd),
    /// Download and cache task
    TaskFetch(TaskFetchCmd),
    /// Publishes a task to the repo
    TaskPublish(TaskPublishCmd),
    /// Include task cmds in conversation without entering task-mode
    TaskInclude(TaskIncludeCmd),
    /// Search for tasks in the repo
    TaskSearch(TaskSearchCmd),
    /// View the task config without running it
    TaskView(TaskViewCmd),
    /// List all versions of a task
    TaskVersions(TaskVersionsCmd),
    /// Edit an asset (create if does not exist)
    Asset(AssetCmd),
    /// Create a new asset
    AssetNew(AssetNewCmd),
    /// Edit an asset
    AssetEdit(AssetEditCmd),
    /// Push into an asset
    AssetPush(AssetPushCmd),
    /// List assets with matching prefix
    AssetList(AssetListCmd),
    /// Search assets semantically
    AssetSearch(AssetSearchCmd),
    /// Load an asset into the convo
    AssetLoad(AssetLoadCmd),
    /// View an asset
    AssetView(AssetViewCmd),
    /// Get link to an asset
    AssetLink(AssetLinkCmd),
    /// Remove an asset
    AssetRemove(AssetRemoveCmd),
    /// Show revisions of an asset
    AssetRevisions(AssetRevisionsCmd),
    /// Listen to changes to an asset
    AssetListen(AssetListenCmd),
    /// Follow changes to an asset
    /// NOTE: For debugging. Subject to removal.
    AssetFollow(AssetFollowCmd),
    /// Import an asset from the filesystem
    AssetImport(AssetImportCmd),
    /// Export an asset to the filesystem
    AssetExport(AssetExportCmd),
    /// Temporarily replicate asset onto local filesystem
    AssetTemp(AssetTempCmd),
    /// Syncs assets onto the local filesystem
    AssetSyncDown(AssetSyncDownCmd),
    /// Grant permission to an asset
    AssetAcl(AssetAclCmd),
    /// Get metadata for asset
    AssetMdGet(AssetMdGetCmd),
    /// Set metadata for asset
    AssetMdSet(AssetMdSetCmd),
    /// Set key in asset metadata
    AssetMdSetKey(AssetMdSetKeyCmd),
    /// Delete key in asset metadata
    AssetMdDelKey(AssetMdDelKeyCmd),
    /// Resume a chat
    ChatResume(ChatResumeCmd),
    /// Save a chat
    ChatSave(ChatSaveCmd),
    /// Send an email
    Email(EmailCmd),
    /// Execute AI-defined function
    FnExec(FnExecCmd),
    /// List all AI-defined functions
    Fns,
    /// Get current account (or if specified, switch to logged-in account)
    Account(AccountCmd),
    /// Make a new account
    AccountNew,
    /// Login to an account
    AccountLogin,
    /// Logout of account (remove local credentials)
    AccountLogout(AccountLogoutCmd),
    /// Balance of an account
    AccountBalance,
    /// Subscribe
    AccountSubscribe,
    /// Get whois info for a user
    Whois(WhoisCmd),
    /// See cost of models
    Cost,
    /// Dumps raw chat history (undocumented)
    Dump,
    /// Dumps session info (undocumented)
    DumpSession,
    /// Program info
    About,
}

//
// Structs for all named REPL commands
//

#[derive(Clone, Debug)]
pub struct HelpCmd {
    /// Whether to include help message in conversation history
    pub history: bool,
}

#[derive(Clone, Debug)]
pub struct PromptCmd {
    /// The prompt to message the AI
    pub prompt: String,
    /// Whether to cache the AI response to re-use next time
    pub cache: bool,
}

#[derive(Clone, Debug)]
pub struct CdCmd {
    /// Target directory to change to
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct AiCmd {
    /// AI model to switch to
    pub model: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AiDefaultCmd {
    /// AI model to set as default
    pub model: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SetKeyCmd {
    /// Provider name
    pub provider: String,

    /// API Key
    pub key: String,
}

#[derive(Clone, Debug)]
pub struct SetMaskSecretsCmd {
    pub on: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct HaiRouterCmd {
    pub on: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct TemperatureCmd {
    pub temperature: Option<f32>,
}

#[derive(Clone, Debug)]
pub struct ExecCmd {
    /// Shell command to execute
    pub command: String,
    /// Whether to cache the output to re-use next time
    pub cache: bool,
}

#[derive(Clone, Debug)]
pub struct SetVarCmd {
    /// Name of the variable
    pub key: String,
    /// Value to set
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct LoadCmd {
    /// Path or glob pattern to load files from
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct LoadUrlCmd {
    /// URL to load from
    pub url: String,
    /// Do not extract article and convert HTML to markdown
    pub raw: bool,
}

#[derive(Clone, Debug)]
pub struct PinCmd {
    /// Message to pin to the conversation
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct PrepCmd {
    /// Message to send without triggering AI response
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct SystemPromptCmd {
    /// The system prompt
    pub prompt: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ForgetCmd {
    /// Number of messages to forget
    pub n: u32,
}

#[derive(Clone, Debug)]
pub struct KeepCmd {
    /// Number of messages to keep from the bottom
    pub bottom: u32,
    /// Number of messages to keep from the top
    pub top: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ToolCmd {
    /// The tool to use
    pub tool: tool::Tool,
    /// Prompt to apply to tool
    pub prompt: String,
    /// Whether to require user confirmation
    pub user_confirmation: bool,
    /// Whether to require the use of the tool
    pub force_tool: bool,
    /// Whether to cache the AI response to re-use next time
    pub cache: bool,
}

#[derive(Clone, Debug)]
pub struct ToolModeCmd {
    /// The tool to use
    pub tool: tool::Tool,
    /// Whether to require user confirmation
    pub user_confirmation: bool,
    /// Whether to require the use of the tool
    pub force_tool: bool,
}

#[derive(Clone, Debug)]
pub struct AskHumanCmd {
    /// Question for the user to answer
    pub question: String,
    /// Whether to hide the answer in the UI
    pub secret: bool,
    /// Whether to cache the answer to re-use next time
    pub cache: bool,
}

// A note on how tasks are referenced:
// - task_fqn: The fully-qualified name of the task of the format
//     `[username]/[task name]`. The fqn is specified as the `name` in task
//     configs and is the name used in the global repository.
// - task_path: This is exclusively a filesystem path to a task config on the
//     local machine.
// - task_ref: A reference to task can be either an fqn or a local path. If the
//     ref begins with "/" it's treated as an absolute path. If it begins with
//     "./" it's treated as a path relative to the cwd. Otherwise, it is
//     interpreted as an fqn and is required to be `[username]/[task name]`.

#[derive(Clone, Debug)]
pub struct TaskCmd {
    /// Task fqn or local path (prefix with ./ or /)
    pub task_ref: String,
    /// If trusted, skip user confirmations on task initialization
    pub trust: bool,
}

#[derive(Clone, Debug)]
pub struct TaskForgetCmd {
    /// Task fqn or local path to forget cached answers for
    pub task_ref: String,
}

#[derive(Clone, Debug)]
pub struct TaskPurgeCmd {
    /// Task fqn to purge from machine
    pub task_fqn: String,
}

#[derive(Clone, Debug)]
pub struct TaskPublishCmd {
    /// Path to local haitask file
    pub task_path: String,
}

#[derive(Clone, Debug)]
pub struct TaskFetchCmd {
    /// Task fqn to download and cache
    pub task_fqn: String,
}

#[derive(Clone, Debug)]
pub struct TaskIncludeCmd {
    /// Task fqn or local path (prefix with ./ or /)
    pub task_ref: String,
}

#[derive(Clone, Debug)]
pub struct TaskSearchCmd {
    /// The search string to use
    pub q: String,
}

#[derive(Clone, Debug)]
pub struct TaskViewCmd {
    /// Task fqn or local path (prefix with ./ or /)
    pub task_ref: String,
}

#[derive(Clone, Debug)]
pub struct TaskVersionsCmd {
    /// Task fqn to list versions of
    pub task_fqn: String,
}

#[derive(Clone, Debug)]
pub struct AssetCmd {
    /// Name of the asset
    pub asset_name: String,

    /// Override of default editor
    pub editor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetNewCmd {
    /// Name of the asset (can include / for "foldering")
    pub asset_name: String,
    pub contents: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetEditCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetPushCmd {
    /// Name of the asset
    pub asset_name: String,
    pub contents: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetListCmd {
    /// All assets with this prefix will be listed
    /// Empty string is supported
    pub prefix: String,
}

#[derive(Clone, Debug)]
pub struct AssetSearchCmd {
    /// The search string to use
    pub q: String,
}

#[derive(Clone, Debug)]
pub struct AssetLoadCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetViewCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetRevisionsCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Number of revisions to show
    pub count: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct AssetFollowCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetListenCmd {
    /// Name of the asset
    pub asset_name: String,
    /// The cursor to listen on
    pub cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetLinkCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetRemoveCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetImportCmd {
    /// Name of the asset
    pub target_asset_name: String,
    /// Path to the file
    pub source_file_path: String,
}

#[derive(Clone, Debug)]
pub struct AssetExportCmd {
    /// Name of the asset
    pub source_asset_name: String,
    /// Path to the file
    pub target_file_path: String,
}

#[derive(Clone, Debug)]
pub struct AssetSyncDownCmd {
    /// Prefix of assets to sync down
    pub prefix: String,
    /// Path to sync down to
    pub target_path: String,
}

#[derive(Clone, Debug)]
pub struct AssetTempCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Number of revisions to output
    pub count: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum AssetAcePermission {
    ReadData,
    ReadRevisions,
    PushData,
}

#[derive(Clone, Debug)]
pub enum AssetAceType {
    Allow,
    Deny,
    Default,
}

#[derive(Clone, Debug)]
pub struct AssetAclCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Permission to grant
    pub ace_permission: AssetAcePermission,
    /// Permission to grant
    pub ace_type: AssetAceType,
}

#[derive(Clone, Debug)]
pub struct AssetMdGetCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetMdSetCmd {
    /// Name of the asset
    pub asset_name: String,

    /// Metadata (must be JSON-encoded object)
    pub metadata: String,
}

#[derive(Clone, Debug)]
pub struct AssetMdSetKeyCmd {
    /// Name of the asset
    pub asset_name: String,

    /// Top-level key of metadata to set
    pub key: String,

    /// A JSON-encoded value
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct AssetMdDelKeyCmd {
    /// Name of the asset
    pub asset_name: String,

    /// Top-level key of metadata to delete
    pub key: String,
}

#[derive(Clone, Debug)]
pub struct ChatResumeCmd {
    /// Name of the chat log asset
    /// If omitted, queries the local db for last chat
    pub chat_log_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ChatSaveCmd {
    /// Name of the asset to save the chat log to
    pub chat_log_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EmailCmd {
    /// Subject of the email
    pub subject: String,
    /// Body of the email
    pub body: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FnExecCmd {
    /// Name of the function
    pub fn_name: String,
    /// Argument to fn
    /// Syntax should be native to language of function definition
    pub arg: String,
}

#[derive(Clone, Debug)]
pub struct AccountCmd {
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountLogoutCmd {
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WhoisCmd {
    pub username: String,
}

fn get_cmd_re() -> &'static Regex {
    static CMD_RE: OnceLock<Regex> = OnceLock::new();
    CMD_RE.get_or_init(|| Regex::new(r"^([a-z!\?]?[a-z0-9-]*)( |\(|$)").unwrap())
}

fn get_tool_re() -> &'static Regex {
    static TOOL_RE: OnceLock<Regex> = OnceLock::new();
    TOOL_RE.get_or_init(|| Regex::new(r"^([a-z]+[a-z0-9-]*|'(?:\\'|[^'])*')?( |\?|\(|$)").unwrap())
}

fn get_ai_def_tool_re() -> &'static Regex {
    static TOOL_RE: OnceLock<Regex> = OnceLock::new();
    TOOL_RE.get_or_init(|| Regex::new(r"^f([0-9]*|'(?:\\'|[^'])*')?( |$)").unwrap())
}

/// Parses user/task input.
///
/// Errors are printed to the screen so the caller is not expected to.
///
/// In general, command-like strings that don't exactly match one of our
/// commands are treated as prompts rather than errors. This is to minimize
/// conflicts between prompts from the user (especially pasted code) and our
/// command list. For example, we don't want a "//comment" input to trigger an
/// error even though if you squint it looks like a cmd.
pub fn parse_user_input(
    input: &str,
    last_tool_cmd: Option<ToolCmd>,
    tool_mode: Option<ToolModeCmd>,
) -> Option<Cmd> {
    if input.trim().is_empty() {
        return Some(Cmd::Noop);
    }
    // EXPERIMENT: Add !!cmd as a short hand for exec. It's not ideal b/c it's
    // similar to the tool notations (! and !?). But, "/e " has proven to be
    // rather awkward to type. The "/" is tough to reach and the " " before the
    // command conflicts with muscle memory from other programs (ipython).
    let input = if let Some(shell_cmd) = input.strip_prefix("!!") {
        format!("/exec {}", shell_cmd)
    } else {
        input.to_string()
    };
    // NOTE: We intentionally preserve whitespace at the start of the input.
    // Why? Because a space at the start is the easiest way for a user to
    // indicate that their message is definitely not a command, but a prompt.
    if let Some(mut remaining) = input.strip_prefix('/') {
        // Try parsing as a command
        let input = input.trim_end();
        let cmd_re = get_cmd_re();
        let (mut remaining, cmd_name) = match cmd_re.captures(remaining) {
            Some(captures) => {
                if let Some(m) = captures.get(1) {
                    remaining = &input[m.end() + 1..];
                    (remaining, m.as_str())
                } else {
                    eprintln!("Warning: Did you intend to invoke a /command?");
                    return Some(Cmd::Prompt(PromptCmd {
                        prompt: input.into(),
                        cache: false,
                    }));
                }
            }
            None => {
                eprintln!("Warning: Did you intend to invoke a /command?");
                return Some(Cmd::Prompt(PromptCmd {
                    prompt: input.into(),
                    cache: false,
                }));
            }
        };
        let options_re = Regex::new(r"(\([^\)]*\))?( |$)").unwrap();
        let (remaining, options) = match options_re.captures(remaining) {
            Some(captures) => {
                if let Some(m) = captures.get(1) {
                    remaining = &remaining[m.end()..];
                    (remaining, parse_options(m.as_str()))
                } else {
                    (remaining, HashMap::new())
                }
            }
            None => (remaining, HashMap::new()),
        };
        parse_command(cmd_name, options.clone(), remaining, input)
    } else if let Some(mut remaining) = input.strip_prefix('!') {
        // Try parsing as a tool-command
        let input = input.trim_end();
        let user_confirmation = if remaining.starts_with("?") {
            remaining = &remaining[1..];
            true
        } else {
            false
        };
        // If the next char is blank, then we assume the user intends to use a
        // previous tool so we leave the tool_name empty.
        let (mut remaining, tool_name) = if remaining.is_empty() || remaining.starts_with(' ') {
            (remaining, "".to_string())
        } else {
            let tool_re = get_tool_re();
            match tool_re.captures(remaining) {
                Some(captures) => {
                    if let Some(m) = captures.get(1) {
                        remaining = &remaining[m.end()..];
                        (remaining, m.as_str().replace("\\'", "'"))
                    } else {
                        eprintln!("Warning: Did you intend to invoke a tool?");
                        return Some(Cmd::Prompt(PromptCmd {
                            prompt: input.into(),
                            cache: false,
                        }));
                    }
                }
                None => {
                    eprintln!("Warning: Did you intend to invoke a tool?");
                    return Some(Cmd::Prompt(PromptCmd {
                        prompt: input.into(),
                        cache: false,
                    }));
                }
            }
        };
        let force_tool = if remaining.starts_with("?") {
            remaining = &remaining[1..];
            false
        } else {
            true
        };
        let options_re = Regex::new(r"(\([^\)]*\))?( |$)").unwrap();
        let (remaining, options) = match options_re.captures(remaining) {
            Some(captures) => {
                if let Some(m) = captures.get(1) {
                    remaining = &remaining[m.end()..];
                    (remaining, parse_options(m.as_str()))
                } else {
                    (remaining, HashMap::new())
                }
            }
            None => (remaining, HashMap::new()),
        };
        parse_tool_command(
            tool_name.as_str(),
            user_confirmation,
            force_tool,
            last_tool_cmd,
            options.clone(),
            remaining,
            input,
        )
    } else if input.ends_with("\n\n") {
        let input = input.trim_end();
        println!("Info: Message is queued up and will be sent with your next message.");
        println!("It was not sent because it ended with two blank lines.");
        Some(Cmd::Prep(PrepCmd {
            message: input.into(),
        }))
    } else {
        let input = input.trim_end();
        if let Some(tool_mode) = tool_mode {
            Some(Cmd::Tool(ToolCmd {
                tool: tool_mode.tool,
                prompt: input.into(),
                user_confirmation: tool_mode.user_confirmation,
                force_tool: tool_mode.force_tool,
                cache: false,
            }))
        } else {
            Some(Cmd::Prompt(PromptCmd {
                prompt: input.into(),
                cache: false,
            }))
        }
    }
}

fn split_arg_and_optional_body(s: &str) -> (String, Option<String>) {
    s.split_once("\n")
        .map(|(l, r)| (l.to_string(), Some(r.to_string())))
        .unwrap_or((s.to_string(), None))
}

/// A single arg can't have spaces (see catchall variant)
fn parse_one_arg(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace()) {
        None
    } else {
        Some(trimmed.into())
    }
}

/// The one arg has space around it trimmed, but otherwise can contain
/// internal whitespace.
fn parse_one_arg_catchall(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.into())
    }
}

fn parse_two_arg(s: &str) -> Option<(String, String)> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        let args = trimmed.split_whitespace().collect::<Vec<&str>>();
        if args.len() != 2 {
            None
        } else {
            Some((args[0].into(), args[1].into()))
        }
    }
}

fn parse_two_arg_catchall(s: &str) -> Option<(String, String)> {
    let trimmed = s.trim();
    let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());

    let first = parts.next();
    let rest = parts.next();

    match (first, rest) {
        (Some(first), Some(rest)) => Some((first.to_string(), rest.to_string())),
        _ => None,
    }
}

fn parse_two_arg_one_optional_catchall(s: &str) -> Option<(String, Option<String>)> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());

    let first = parts.next();
    let rest = parts.next();

    match (first, rest) {
        (Some(first), rest) => Some((first.to_string(), rest.map(|s| s.to_string()))),
        _ => None,
    }
}

fn parse_three_arg_catchall(s: &str) -> Option<(String, String, String)> {
    let trimmed = s.trim();
    let mut parts = trimmed.splitn(3, |c: char| c.is_whitespace());

    let first = parts.next();
    let second = parts.next();
    let rest = parts.next();

    match (first, second, rest) {
        (Some(first), Some(second), Some(rest)) => {
            Some((first.to_string(), second.to_string(), rest.to_string()))
        }
        _ => None,
    }
}

/// If None is returned, it prints an error usage string.
fn parse_command(
    cmd_name: &str,
    options: HashMap<String, String>,
    remaining: &str,
    full_input: &str, // Only for the fallback case
) -> Option<Cmd> {
    let ai_def_tool_re = get_ai_def_tool_re();
    if let Some(captures) = ai_def_tool_re.captures(cmd_name) {
        if let Some(m) = captures.get(1) {
            let fn_name = format!("f{}", m.as_str());
            return Some(Cmd::FnExec(FnExecCmd {
                fn_name,
                arg: remaining.trim().to_string(),
            }));
        }
    }
    match cmd_name {
        "quit" | "q" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Quit)
        }
        "help" | "h" | "?" => {
            if !validate_options_and_print_err(cmd_name, &options, &["history"]) {
                return None;
            }
            let expected_types = HashMap::from([("history".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let history = options.get("history").map(|v| v == "true").unwrap_or(false);
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Help(HelpCmd { history }))
        }
        "new" | "n" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::New)
        }
        "reset" | "r" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Reset)
        }
        "clip" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Clip)
        }
        "printvars" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::PrintVars)
        }
        "dump" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Dump)
        }
        "dump-session" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::DumpSession)
        }
        "about" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::About)
        }
        "cd" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::Cd(CdCmd {
                path: parse_one_arg_catchall(remaining)?,
            }))
        }
        "ai" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::Ai(AiCmd {
                model: parse_one_arg(remaining),
            }))
        }
        "ai-default" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::AiDefault(AiDefaultCmd {
                model: parse_one_arg(remaining),
            }))
        }
        "set-key" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg(remaining) {
                Some((provider, key)) => Some(Cmd::SetKey(SetKeyCmd { provider, key })),
                None => {
                    eprintln!("Usage: /set-key <provider> <key>");
                    eprintln!("providers: openai, anthropic, deepseek, google");
                    None
                }
            }
        }
        "set-mask-secrets" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(arg) => {
                    if arg != "on" && arg != "off" {
                        eprintln!("Usage: /set-mask-secrets <on/off>");
                        None
                    } else {
                        Some(Cmd::SetMaskSecrets(SetMaskSecretsCmd {
                            on: Some(arg == "on"),
                        }))
                    }
                }
                None => Some(Cmd::SetMaskSecrets(SetMaskSecretsCmd { on: None })),
            }
        }
        "hai-router" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(arg) => {
                    if arg != "on" && arg != "off" {
                        eprintln!("Usage: /hai-router <on|off>");
                        None
                    } else {
                        Some(Cmd::HaiRouter(HaiRouterCmd {
                            on: Some(arg == "on"),
                        }))
                    }
                }
                None => Some(Cmd::HaiRouter(HaiRouterCmd { on: None })),
            }
        }
        "temperature" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(arg) => {
                    if arg == "none" {
                        None
                    } else {
                        match arg.parse::<f32>() {
                            Ok(value) => Some(Cmd::Temperature(TemperatureCmd {
                                temperature: Some(value),
                            })),
                            Err(_) => {
                                eprintln!("Error: Temperature must be a number or `none`.");
                                None
                            }
                        }
                    }
                }
                None => Some(Cmd::Temperature(TemperatureCmd { temperature: None })),
            }
        }
        "setvar" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((key, value)) => Some(Cmd::SetVar(SetVarCmd { key, value })),
                None => {
                    eprintln!("Usage: /setvar <key> <value...>");
                    None
                }
            }
        }
        "load" | "l" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(path) => Some(Cmd::Load(LoadCmd { path })),
                None => {
                    eprintln!("Usage: /load <glob path>");
                    None
                }
            }
        }
        "load-url" => {
            if !validate_options_and_print_err(cmd_name, &options, &["raw"]) {
                return None;
            }
            let expected_types = HashMap::from([("raw".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let raw = options.get("raw").map(|v| v == "true").unwrap_or(false);
            match parse_one_arg_catchall(remaining) {
                Some(url) => Some(Cmd::LoadUrl(LoadUrlCmd { url, raw })),
                None => {
                    eprintln!("Usage: /load-url(raw=false) <url>");
                    None
                }
            }
        }
        "prep" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(message) => Some(Cmd::Prep(PrepCmd { message })),
                None => {
                    eprintln!("Usage: /prep <message>");
                    None
                }
            }
        }
        "pin" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(message) => Some(Cmd::Pin(PinCmd { message })),
                None => {
                    eprintln!("Usage: /pin <message>");
                    None
                }
            }
        }
        "system-prompt" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::SystemPrompt(SystemPromptCmd {
                prompt: parse_one_arg_catchall(remaining),
            }))
        }
        "forget" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            let arg = parse_one_arg_catchall(remaining);
            let n = if let Some(n_str) = arg {
                match n_str.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("Usage: /forget <number>");
                        return None;
                    }
                }
            } else {
                1
            };
            Some(Cmd::Forget(ForgetCmd { n }))
        }
        "keep" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            let (top, bottom) = match parse_two_arg_one_optional_catchall(remaining) {
                Some((bottom_str, top_str)) => {
                    let bottom = match bottom_str.parse::<u32>() {
                        Ok(n) => n,
                        Err(_) => {
                            eprintln!("Usage: /keep <bottom> [<top>]");
                            return None;
                        }
                    };
                    let top = if let Some(top_str) = top_str {
                        match top_str.parse::<u32>() {
                            Ok(n) => Some(n),
                            Err(_) => {
                                eprintln!("Usage: /keep <bottom> [<top>]");
                                return None;
                            }
                        }
                    } else {
                        None
                    };
                    (top, bottom)
                }
                None => {
                    eprintln!("Usage: /keep <bottom> [<top>]");
                    return None;
                }
            };
            Some(Cmd::Keep(KeepCmd { bottom, top }))
        }
        "exec" | "e" => {
            if !validate_options_and_print_err(cmd_name, &options, &["cache"]) {
                return None;
            }
            let expected_types = HashMap::from([("cache".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let cache = options.get("cache").map(|v| v == "true").unwrap_or(false);
            match parse_one_arg_catchall(remaining) {
                Some(command) => Some(Cmd::Exec(ExecCmd { command, cache })),
                None => {
                    eprintln!("Usage: /exec(cache=false) <command>");
                    None
                }
            }
        }
        "ask-human" => {
            if !validate_options_and_print_err(cmd_name, &options, &["secret", "cache"]) {
                return None;
            }
            let expected_types = HashMap::from([
                ("secret".to_string(), OptionType::Bool),
                ("cache".to_string(), OptionType::Bool),
            ]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let secret = options.get("secret").map(|v| v == "true").unwrap_or(false);
            let cache = options.get("cache").map(|v| v == "true").unwrap_or(false);

            match parse_one_arg_catchall(remaining) {
                Some(question) => Some(Cmd::AskHuman(AskHumanCmd {
                    question,
                    secret,
                    cache,
                })),
                None => {
                    eprintln!("Usage: /ask-human(secret=false,cache=false) <question>");
                    None
                }
            }
        }
        "task" | "t" => {
            if !validate_options_and_print_err(cmd_name, &options, &["trust"]) {
                return None;
            }
            let expected_types = HashMap::from([("trust".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let trust = options.get("trust").map(|v| v == "true").unwrap_or(false);
            match parse_one_arg_catchall(remaining) {
                Some(task_ref) => Some(Cmd::Task(TaskCmd { task_ref, trust })),
                None => {
                    eprintln!("Usage: /task <task_ref>");
                    None
                }
            }
        }
        "task-end" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::TaskEnd)
        }
        "task-forget" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(task_ref) => Some(Cmd::TaskForget(TaskForgetCmd { task_ref })),
                None => {
                    eprintln!("Usage: /task-forget <task_ref>");
                    None
                }
            }
        }
        "task-purge" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(task_fqn) => Some(Cmd::TaskPurge(TaskPurgeCmd { task_fqn })),
                None => {
                    eprintln!("Usage: /task-purge <task_fqn>");
                    None
                }
            }
        }
        "task-publish" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(task_path) => Some(Cmd::TaskPublish(TaskPublishCmd { task_path })),
                None => {
                    eprintln!("Usage: /task-publish <task_path>");
                    None
                }
            }
        }
        "task-fetch" | "task-update" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(task_fqn) => Some(Cmd::TaskFetch(TaskFetchCmd { task_fqn })),
                None => {
                    eprintln!("Usage: /{} <task_fqn>", cmd_name);
                    None
                }
            }
        }
        "task-include" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(task_ref) => Some(Cmd::TaskInclude(TaskIncludeCmd { task_ref })),
                None => {
                    eprintln!("Usage: /task-include <task_ref>");
                    None
                }
            }
        }
        "task-search" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(q) => Some(Cmd::TaskSearch(TaskSearchCmd { q })),
                None => {
                    eprintln!("Usage: /task-search <query>");
                    None
                }
            }
        }
        "task-view" | "task-cat" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(task_ref) => Some(Cmd::TaskView(TaskViewCmd { task_ref })),
                None => {
                    eprintln!("Usage: /{} <task_ref>", cmd_name);
                    None
                }
            }
        }
        "task-versions" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(task_fqn) => Some(Cmd::TaskVersions(TaskVersionsCmd { task_fqn })),
                None => {
                    eprintln!("Usage: /{} <task_fqn>", cmd_name);
                    None
                }
            }
        }
        "asset" | "a" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_one_optional_catchall(remaining) {
                Some((asset_name, editor)) => Some(Cmd::Asset(AssetCmd { asset_name, editor })),
                None => {
                    eprintln!("Usage: /asset <name>");
                    None
                }
            }
        }
        "asset-new" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            let (cmd_arg, contents) = split_arg_and_optional_body(remaining);
            match parse_one_arg(&cmd_arg) {
                Some(asset_name) => Some(Cmd::AssetNew(AssetNewCmd {
                    asset_name,
                    contents,
                })),
                None => {
                    eprintln!("Usage: /asset-new <name> [⏎ <body>]");
                    None
                }
            }
        }
        "asset-edit" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetEdit(AssetEditCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-edit <name>");
                    None
                }
            }
        }
        "asset-push" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            let (cmd_arg, contents) = split_arg_and_optional_body(remaining);
            match parse_one_arg(&cmd_arg) {
                Some(asset_name) => Some(Cmd::AssetPush(AssetPushCmd {
                    asset_name,
                    contents,
                })),
                None => {
                    eprintln!("Usage: /asset-push <name> [⏎ <body>]");
                    None
                }
            }
        }
        "asset-list" | "ls" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(prefix) => Some(Cmd::AssetList(AssetListCmd { prefix })),
                None => Some(Cmd::AssetList(AssetListCmd {
                    prefix: "".to_string(),
                })),
            }
        }
        "asset-search" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg_catchall(remaining) {
                Some(q) => Some(Cmd::AssetSearch(AssetSearchCmd { q })),
                None => {
                    eprintln!("Usage: /asset-search <query>");
                    None
                }
            }
        }
        "asset-load" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetLoad(AssetLoadCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-load <name>");
                    None
                }
            }
        }
        "asset-view" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetView(AssetViewCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-view <name>");
                    None
                }
            }
        }
        "asset-revisions" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_one_optional_catchall(remaining) {
                Some((asset_name, count_str)) => {
                    let count = if let Some(count_str) = count_str {
                        match count_str.parse::<u32>() {
                            Ok(count) => Some(count),
                            Err(_) => {
                                eprintln!("Usage: /asset-revisions <name> [<count>]");
                                return None;
                            }
                        }
                    } else {
                        None
                    };
                    Some(Cmd::AssetRevisions(AssetRevisionsCmd { asset_name, count }))
                }
                None => {
                    eprintln!("Usage: /asset-revisions <name> [<count>]");
                    None
                }
            }
        }
        "asset-follow" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetFollow(AssetFollowCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-follow <name>");
                    None
                }
            }
        }
        "asset-listen" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_one_optional_catchall(remaining) {
                Some((asset_name, cursor)) => {
                    Some(Cmd::AssetListen(AssetListenCmd { asset_name, cursor }))
                }
                None => {
                    eprintln!("Usage: /asset-listen <name> [<cursor>]");
                    None
                }
            }
        }
        "asset-link" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetLink(AssetLinkCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-link <name>");
                    None
                }
            }
        }
        "asset-remove" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetRemove(AssetRemoveCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-remove <name>");
                    None
                }
            }
        }
        "asset-import" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((asset_name, file_path)) => Some(Cmd::AssetImport(AssetImportCmd {
                    target_asset_name: asset_name,
                    source_file_path: file_path,
                })),
                None => {
                    eprintln!("Usage: /asset-import <target_asset_name> <source_file_path>");
                    None
                }
            }
        }
        "asset-export" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((asset_name, file_path)) => Some(Cmd::AssetExport(AssetExportCmd {
                    source_asset_name: asset_name,
                    target_file_path: file_path,
                })),
                None => {
                    eprintln!("Usage: /asset-export <source_asset_name> <target_file_path>");
                    None
                }
            }
        }
        "asset-temp" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_one_optional_catchall(remaining) {
                Some((asset_name, count_str)) => {
                    let count = if let Some(count_str) = count_str {
                        match count_str.parse::<u32>() {
                            Ok(count) => Some(count),
                            Err(_) => {
                                eprintln!("Usage: /asset-temp <name> [<count>]");
                                return None;
                            }
                        }
                    } else {
                        None
                    };
                    Some(Cmd::AssetTemp(AssetTempCmd { asset_name, count }))
                }
                None => {
                    eprintln!("Usage: /asset-temp <asset_name> [<count>]");
                    None
                }
            }
        }
        "asset-sync-down" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((prefix, target_path)) => Some(Cmd::AssetSyncDown(AssetSyncDownCmd {
                    prefix,
                    target_path,
                })),
                None => {
                    eprintln!("Usage: /asset-sync-down <prefix> <target_path>");
                    None
                }
            }
        }
        "asset-acl" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((asset_name, acl_cmd)) => {
                    if let Some((ace_type, ace_perm)) = acl_cmd.split_once(":") {
                        let asset_ace_type = match ace_type {
                            "allow" => AssetAceType::Allow,
                            "deny" => AssetAceType::Deny,
                            "default" => AssetAceType::Default,
                            _ => {
                                eprintln!("error: unknown type: try allow, deny, default");
                                return None;
                            }
                        };
                        let asset_ace_perm = match ace_perm {
                            "read-data" => AssetAcePermission::ReadData,
                            "read-revisions" => AssetAcePermission::ReadRevisions,
                            "push-data" => AssetAcePermission::PushData,
                            _ => {
                                eprintln!("error: unknown permission");
                                return None;
                            }
                        };
                        Some(Cmd::AssetAcl(AssetAclCmd {
                            asset_name,
                            ace_permission: asset_ace_perm,
                            ace_type: asset_ace_type,
                        }))
                    } else {
                        eprintln!("error: bad format: try `allow:read-data`");
                        None
                    }
                }
                None => {
                    eprintln!("Usage: /asset-acl <asset_name> <allow|deny|default>:<acl>");
                    None
                }
            }
        }
        "asset-md-get" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(asset_name) => Some(Cmd::AssetMdGet(AssetMdGetCmd { asset_name })),
                None => {
                    eprintln!("Usage: /asset-md-get <name>");
                    None
                }
            }
        }
        "asset-md-set" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((asset_name, metadata)) => Some(Cmd::AssetMdSet(AssetMdSetCmd {
                    asset_name,
                    metadata,
                })),
                None => {
                    eprintln!("Usage: /asset-md-set <asset_name> <metadata>");
                    None
                }
            }
        }
        "asset-md-set-key" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_three_arg_catchall(remaining) {
                Some((asset_name, key, value)) => Some(Cmd::AssetMdSetKey(AssetMdSetKeyCmd {
                    asset_name,
                    key,
                    value,
                })),
                None => {
                    eprintln!("Usage: /asset-md-set-key <asset_name> <key> <value>");
                    None
                }
            }
        }
        "asset-md-del-key" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_two_arg_catchall(remaining) {
                Some((asset_name, key)) => {
                    Some(Cmd::AssetMdDelKey(AssetMdDelKeyCmd { asset_name, key }))
                }
                None => {
                    eprintln!("Usage: /asset-md-del-key <asset_name> <key>");
                    None
                }
            }
        }
        "chat-resume" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::ChatResume(ChatResumeCmd {
                chat_log_name: parse_one_arg_catchall(remaining),
            }))
        }
        "chat-save" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::ChatSave(ChatSaveCmd {
                chat_log_name: parse_one_arg(remaining),
            }))
        }
        "email" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            let (cmd_arg, body) = split_arg_and_optional_body(remaining);
            match parse_one_arg_catchall(&cmd_arg) {
                Some(subject) => Some(Cmd::Email(EmailCmd { subject, body })),
                None => {
                    eprintln!("Usage: /email <subject> [⏎ <body>]");
                    None
                }
            }
        }
        "fns" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Fns)
        }
        "account" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::Account(AccountCmd {
                username: parse_one_arg_catchall(remaining),
            }))
        }
        "account-new" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::AccountNew)
        }
        "account-login" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::AccountLogin)
        }
        "account-logout" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::AccountLogout(AccountLogoutCmd {
                username: parse_one_arg_catchall(remaining),
            }))
        }
        "account-balance" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::AccountBalance)
        }
        "account-subscribe" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::AccountSubscribe)
        }
        "whois" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            match parse_one_arg(remaining) {
                Some(username) => Some(Cmd::Whois(WhoisCmd { username })),
                None => {
                    eprintln!("Usage: /whois username");
                    None
                }
            }
        }
        "cost" => {
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            if parse_one_arg_catchall(remaining).is_some() {
                eprintln!("Usage: /{cmd_name} takes no arguments");
                return None;
            }
            Some(Cmd::Cost)
        }
        "prompt" => {
            if !validate_options_and_print_err(cmd_name, &options, &["cache"]) {
                return None;
            }
            let expected_types = HashMap::from([("cache".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let cache = options.get("cache").map(|v| v == "true").unwrap_or(false);
            match parse_one_arg_catchall(remaining) {
                Some(prompt) => Some(Cmd::Prompt(PromptCmd { prompt, cache })),
                None => {
                    eprintln!("Usage: /prompt(cache=false) <message>");
                    None
                }
            }
        }
        _ => {
            eprintln!("Warning: Did you intend to invoke a /command?");
            if !validate_options_and_print_err(cmd_name, &options, &[]) {
                return None;
            }
            Some(Cmd::Prompt(PromptCmd {
                prompt: full_input.to_owned(),
                cache: false,
            }))
        }
    }
}

/// If None is returned, it prints an error usage string.
fn parse_tool_command(
    tool_name: &str,
    user_confirmation: bool,
    force_tool: bool,
    last_tool_cmd: Option<ToolCmd>,
    options: HashMap<String, String>,
    remaining: &str,
    full_input: &str, // Only for the fallback case
) -> Option<Cmd> {
    match tool_name {
        "clip" => {
            match parse_one_arg_catchall(remaining) {
                Some(prompt) => {
                    Some(Cmd::Tool(ToolCmd {
                        tool: tool::Tool::CopyToClipboard,
                        // Include !clip as it nudges AI to use the tool
                        prompt: get_tool_prefixed_prompt(
                            &tool::Tool::CopyToClipboard,
                            user_confirmation,
                            &prompt,
                        ),
                        user_confirmation,
                        force_tool,
                        cache: false,
                    }))
                }
                None => {
                    eprintln!("Usage: !clip <prompt: what to clip>");
                    None
                }
            }
        }
        "py" => {
            match parse_one_arg_catchall(remaining) {
                Some(prompt) => {
                    Some(Cmd::Tool(ToolCmd {
                        tool: tool::Tool::ExecPythonScript,
                        // Include !py as it nudges AI to use the tool
                        prompt: get_tool_prefixed_prompt(
                            &tool::Tool::ExecPythonScript,
                            user_confirmation,
                            &prompt,
                        ),
                        user_confirmation,
                        force_tool,
                        cache: false,
                    }))
                }
                None => Some(Cmd::ToolMode(ToolModeCmd {
                    tool: tool::Tool::ExecPythonScript,
                    user_confirmation,
                    force_tool,
                })),
            }
        }
        "sh" => {
            match parse_one_arg_catchall(remaining) {
                Some(prompt) => {
                    Some(Cmd::Tool(ToolCmd {
                        tool: tool::Tool::ShellExec,
                        // Exclude !sh as it tends to make its way into the command itself
                        prompt: get_tool_prefixed_prompt(
                            &tool::Tool::ShellExec,
                            user_confirmation,
                            &prompt,
                        ),
                        user_confirmation,
                        force_tool,
                        cache: false,
                    }))
                }
                None => Some(Cmd::ToolMode(ToolModeCmd {
                    tool: tool::Tool::ShellExec,
                    user_confirmation,
                    force_tool,
                })),
            }
        }
        "shscript" => match parse_one_arg_catchall(remaining) {
            Some(prompt) => Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecShellScript,
                prompt: get_tool_prefixed_prompt(
                    &tool::Tool::ExecShellScript,
                    user_confirmation,
                    &prompt,
                ),
                user_confirmation,
                force_tool,
                cache: false,
            })),
            None => Some(Cmd::ToolMode(ToolModeCmd {
                tool: tool::Tool::ExecShellScript,
                user_confirmation,
                force_tool,
            })),
        },
        "hai" => match parse_one_arg_catchall(remaining) {
            Some(prompt) => Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::HaiRepl,
                prompt: get_tool_prefixed_prompt(&tool::Tool::HaiRepl, user_confirmation, &prompt),
                user_confirmation,
                force_tool,
                cache: false,
            })),
            None => Some(Cmd::ToolMode(ToolModeCmd {
                tool: tool::Tool::HaiRepl,
                user_confirmation,
                force_tool,
            })),
        },
        "fn-py" => {
            if !validate_options_and_print_err_for_tool(tool_name, &options, &["cache"]) {
                return None;
            }
            let expected_types = HashMap::from([("cache".to_string(), OptionType::Bool)]);
            if let Err(type_error) = validate_option_types(&options, &expected_types) {
                eprintln!("Error: {}", type_error);
                return None;
            }
            let cache = options.get("cache").map(|v| v == "true").unwrap_or(false);
            match parse_one_arg_catchall(remaining) {
                Some(prompt) => Some(Cmd::Tool(ToolCmd {
                    tool: tool::Tool::Fn,
                    prompt,
                    user_confirmation,
                    force_tool,
                    cache,
                })),
                None => {
                    eprintln!("Usage: !fn-py(cache=false) <prompt: function to implement>");
                    None
                }
            }
        }
        "exit" => Some(Cmd::ToolModeExit),
        "" => {
            // Tool (and possibly prompt) re-use
            if let Some(last_tool_cmd) = last_tool_cmd {
                match parse_one_arg_catchall(remaining) {
                    // Repeat tool with new prompt
                    Some(prompt) => Some(Cmd::Tool(ToolCmd {
                        tool: last_tool_cmd.tool.clone(),
                        prompt: get_tool_prefixed_prompt(
                            &last_tool_cmd.tool,
                            user_confirmation,
                            &prompt,
                        ),
                        user_confirmation,
                        force_tool,
                        cache: false,
                    })),
                    // Repeat tool and prompt
                    None => Some(Cmd::Tool(ToolCmd {
                        tool: last_tool_cmd.tool,
                        prompt: last_tool_cmd.prompt,
                        user_confirmation,
                        force_tool,
                        cache: false,
                    })),
                }
            } else {
                eprintln!("Error: No tool was previously used");
                None
            }
        }
        _ => {
            // Custom tool
            if tool_name.starts_with("'") {
                let shell_cmd = tool_name.trim_matches('\'').to_string();
                let file_placeholder_re = tool::get_file_placeholder_re();
                let tool = if let Some(caps) = file_placeholder_re.captures(&shell_cmd) {
                    let ext = caps.get(1).map(|m| m.as_str().to_string());
                    tool::Tool::ShellExecWithFile(shell_cmd.clone(), ext)
                } else {
                    tool::Tool::ShellExecWithStdin(shell_cmd.clone())
                };
                match parse_one_arg_catchall(remaining) {
                    Some(prompt) => Some(Cmd::Tool(ToolCmd {
                        tool: tool.clone(),
                        prompt: get_tool_prefixed_prompt(&tool, user_confirmation, &prompt),
                        user_confirmation,
                        force_tool,
                        cache: false,
                    })),
                    None => Some(Cmd::ToolMode(ToolModeCmd {
                        tool,
                        user_confirmation,
                        force_tool,
                    })),
                }
            } else {
                // Since the tool didn't match a known one, treat it as if the
                // user never intended to make a !tool call and send it to the
                // AI as a prompt.
                eprintln!("Warning: Did you intend to invoke a tool?");
                Some(Cmd::Prompt(PromptCmd {
                    prompt: full_input.to_owned(),
                    cache: false,
                }))
            }
        }
    }
}

/// Some tool calls are better handled by the AI when the tool-cmd is prefixed
/// to the prompt. For other tool calls (e.g. !sh), the tool-cmd confuses the
/// AI and causes mistakes (e.g. prefixing shell command with !).
fn get_tool_prefixed_prompt(tool: &tool::Tool, user_confirmation: bool, prompt: &String) -> String {
    let tool_call_type = if user_confirmation { "!?" } else { "!" };
    let tool_call = match tool {
        tool::Tool::CopyToClipboard => format!("{}clip ", tool_call_type),
        tool::Tool::ExecPythonScript => format!("{}py ", tool_call_type),
        tool::Tool::HaiRepl => format!("{}hai ", tool_call_type),
        tool::Tool::ShellExecWithFile(shell_cmd, _) | tool::Tool::ShellExecWithStdin(shell_cmd) => {
            format!("{}'{}' ", tool_call_type, shell_cmd)
        }
        _ => "".to_string(),
    };
    format!("{}{}", tool_call, prompt)
}

/// Parse command options: /cmd(key=value, ...)
///
/// - `options_input`: The portion of the input between the parentheses. Do not
///   include the `/cmd` nor what follows the command.
fn parse_options(options_input: &str) -> HashMap<String, String> {
    let mut options = HashMap::new();
    let content = options_input.trim();
    if content.starts_with('(') && content.ends_with(')') {
        let content = &content[1..content.len() - 1];
        for pair in content.split(',') {
            if let Some((key, value)) = pair.split_once('=') {
                options.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    options
}

/// Validates the options for a command.
///
/// - `options`: The parsed options from the command.
/// - `valid_keys`: A slice of valid keys for the command.
///
/// Returns:
/// - `Ok(())` if all options are valid.
/// - `Err(Vec<String>)` containing invalid keys if any invalid options are found.
fn validate_options(
    options: &HashMap<String, String>,
    valid_keys: &[&str],
) -> Result<(), Vec<String>> {
    let invalid_keys: Vec<String> = options
        .keys()
        .filter(|key| !valid_keys.contains(&key.as_str()))
        .cloned()
        .collect();

    if invalid_keys.is_empty() {
        Ok(())
    } else {
        Err(invalid_keys)
    }
}

fn validate_options_and_print_err(
    cmd: &str,
    options: &HashMap<String, String>,
    valid_keys: &[&str],
) -> bool {
    if let Err(invalid_keys) = validate_options(options, valid_keys) {
        let invalid_keys_pretty = invalid_keys.join(", ");
        eprintln!(
            "Error: Invalid option(s) for /{}: {}",
            cmd, invalid_keys_pretty
        );
        false
    } else {
        true
    }
}

fn validate_options_and_print_err_for_tool(
    tool_name: &str,
    options: &HashMap<String, String>,
    valid_keys: &[&str],
) -> bool {
    if let Err(invalid_keys) = validate_options(options, valid_keys) {
        let invalid_keys_pretty = invalid_keys.join(", ");
        eprintln!(
            "Error: Invalid option(s) for !{}: {}",
            tool_name, invalid_keys_pretty
        );
        false
    } else {
        true
    }
}

enum OptionType {
    Bool,
    #[allow(dead_code)]
    Number,
}

/// Validates the types for a set of options.
///
/// - `options`: The parsed options from the command.
/// - `expected_types`: A map specifying the expected type (`OptionType`) for each valid key.
///
/// Returns:
/// - `Ok(())` if all options have valid types.
/// - `Err(String)` containing an error message if a type mismatch is found.
fn validate_option_types(
    options: &HashMap<String, String>,
    expected_types: &HashMap<String, OptionType>,
) -> Result<(), String> {
    for (key, value) in options {
        if let Some(expected_type) = expected_types.get(key) {
            match expected_type {
                OptionType::Bool => {
                    if value != "true" && value != "false" {
                        return Err(format!(
                            "Invalid value for '{}': expected a boolean (true/false), got '{}'",
                            key, value
                        ));
                    }
                }
                OptionType::Number => {
                    if value.parse::<f64>().is_err() {
                        return Err(format!(
                            "Invalid value for '{}': expected a number, got '{}'",
                            key, value
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool;

    #[test]
    fn test_prefixed_whitespace() {
        // Test that a user can add a space before any input so that it's
        // treated as an AI prompt and never as a command. This eases issues
        // with pasting code that looks like a command.
        let input = " /load xyz";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Prompt(PromptCmd { prompt, .. })) => {
                assert_eq!(prompt, input);
            }
            _ => panic!("Failed to parse no args"),
        }
    }

    #[test]
    fn test_arguments() {
        // Test no arguments
        let input = "/ask-human agree?";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::AskHuman(AskHumanCmd {
                question,
                secret,
                cache,
            })) => {
                assert_eq!(question, "agree?");
                assert!(!secret);
                assert!(!cache);
            }
            _ => panic!("Failed to parse no args"),
        }

        // Test one argument
        let input = "/ask-human(secret=true) agree?";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::AskHuman(AskHumanCmd {
                question,
                secret,
                cache,
            })) => {
                assert_eq!(question, "agree?");
                assert!(secret);
                assert!(!cache);
            }
            _ => panic!("Failed to parse one args"),
        }

        // Test two arguments
        let input = "/ask-human(secret=true,cache=true) agree?";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::AskHuman(AskHumanCmd {
                question,
                secret,
                cache,
            })) => {
                assert_eq!(question, "agree?");
                assert!(secret);
                assert!(cache);
            }
            _ => panic!("Failed to parse two args"),
        }

        // Test two arguments separated by space
        let input = "/ask-human(secret=true, cache=true) agree?";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::AskHuman(AskHumanCmd {
                question,
                secret,
                cache,
            })) => {
                assert_eq!(question, "agree?");
                assert!(secret);
                assert!(cache);
            }
            _ => panic!("Failed to parse two args"),
        }
    }

    #[test]
    fn test_clip_tool_command() {
        let input = "!clip Copy this to clipboard";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::CopyToClipboard,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, input);
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to parse !clip command properly"),
        }
    }

    #[test]
    fn test_py_tool_command() {
        let input = "!py print('Hello, World!')";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, input);
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to parse !py command properly"),
        }
    }

    #[test]
    fn test_sh_tool_command() {
        let input = "!sh ls -lah";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExec,
                prompt,
                user_confirmation,
                ..
            })) => {
                // Does not include !sh b/c it confuses the AI
                assert_eq!(prompt, "ls -lah");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to parse !sh command properly"),
        }
    }

    #[test]
    fn test_shscript_tool_command() {
        let input = "!shscript echo 'Hello'";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecShellScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "echo 'Hello'");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to parse !shscript command properly"),
        }
    }

    #[test]
    fn test_invalid_tool_command() {
        let input = "!invalid_tool Something";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Prompt(PromptCmd { prompt, .. })) => {
                assert_eq!(prompt, input);
            }
            _ => panic!("Failed to parse no args"),
        }
    }

    #[test]
    fn test_optional_tool_command() {
        let input = "!?py print('Hello, World!')";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, input);
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !?py command properly"),
        }
    }

    #[test]
    fn test_custom_tool_command() {
        let input = "!?'psql' describe the user table";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql");
                assert_eq!(prompt, input);
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'psql' custom command properly"),
        }

        // custom tool with space
        let input = "!?'psql -hlocalhost' describe the user table";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql -hlocalhost");
                assert_eq!(prompt, input);
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'psql' custom command properly"),
        }

        // custom tool with double-quotes
        let input = "!?'psql -h \"localhost\"' describe the user table";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql -h \"localhost\"");
                assert_eq!(prompt, input);
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'psql' custom command properly"),
        }

        // custom tool with escaped single-quote
        let input = "!?'psql -h loc\\'alhost' describe the user table";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql -h loc'alhost");
                assert_eq!(prompt, "!?'psql -h loc'alhost' describe the user table");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'psql' custom command properly"),
        }

        // custom tool with file+ext placeholder
        let input = "!?'uv run {file.py}' distance sf to nyc";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithFile(cmd, ext),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "uv run {file.py}");
                assert_eq!(ext, Some("py".to_string()));
                assert_eq!(prompt, "!?'uv run {file.py}' distance sf to nyc");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'uv' custom command properly"),
        }

        // custom tool with file sans ext placeholder
        let input = "!?'uv run {file}' distance sf to nyc";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithFile(cmd, ext),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "uv run {file}");
                assert_eq!(ext, None);
                assert_eq!(prompt, "!?'uv run {file}' distance sf to nyc");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to parse !'uv' custom command properly"),
        }
    }

    #[test]
    fn test_tool_reuse_command() {
        let last_tool_cmd = ToolCmd {
            tool: tool::Tool::ExecPythonScript,
            prompt: "!py 1 + 2".to_string(),
            user_confirmation: true,
            force_tool: true,
            cache: false,
        };

        // Test tool re-use
        let input = "! 3 + 4";
        let cmd = parse_user_input(input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "!py 3 + 4");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }

        // Test tool re-use with !?
        let input = "!? 3 + 4";
        let cmd = parse_user_input(input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "!?py 3 + 4");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }

        // Test tool & prompt re-use
        let input = "!";
        let cmd = parse_user_input(input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "!py 1 + 2");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }

        // Test tool & prompt re-use with extraneous space and !?
        let input = "!? ";
        let cmd = parse_user_input(input, Some(last_tool_cmd), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                // The prompt is taken from the previous one so isn't changed to !?
                assert_eq!(prompt, "!py 1 + 2");
                // The actual require bit is changed correctly
                assert!(user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }

        //
        // Test custom tool
        //

        let last_tool_cmd = ToolCmd {
            tool: tool::Tool::ShellExecWithStdin("psql -hlocalhost".to_string()),
            prompt: "!'psql -hlocalhost' dump user table".to_string(),
            user_confirmation: true,
            force_tool: true,
            cache: false,
        };

        // Test tool re-use
        let input = "! dump task table";
        let cmd = parse_user_input(input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql -hlocalhost");
                assert_eq!(prompt, "!'psql -hlocalhost' dump task table");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }

        // Test tool & prompt re-use
        let input = "!";
        let cmd = parse_user_input(input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExecWithStdin(cmd),
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(cmd, "psql -hlocalhost");
                assert_eq!(prompt, "!'psql -hlocalhost' dump user table");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }
    }

    #[test]
    fn test_tool_mode() {
        let last_tool_cmd = ToolCmd {
            tool: tool::Tool::ShellExec,
            prompt: "list home dir".to_string(),
            user_confirmation: true,
            force_tool: true,
            cache: false,
        };

        //
        // Test entering tool mode
        //

        let cmd = parse_user_input("!py", None, None);
        match cmd {
            Some(Cmd::ToolMode(ToolModeCmd {
                tool: tool::Tool::ExecPythonScript,
                user_confirmation,
                ..
            })) => {
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to enter tool mode"),
        }

        //
        // Test tool mode
        //

        let tool_mode = ToolModeCmd {
            tool: tool::Tool::ExecPythonScript,
            user_confirmation: true,
            force_tool: true,
        };
        let input = "3 + 4";
        let cmd = parse_user_input(input, None, Some(tool_mode.clone()));
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "3 + 4");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to use tool mode"),
        }

        //
        // Test tool mode abides by last_tool_cmd
        //

        let cmd = parse_user_input(
            "! get system time",
            Some(last_tool_cmd),
            Some(tool_mode.clone()),
        );
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellExec,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "get system time");
                assert!(!user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }
    }

    #[test]
    fn test_tool_command_with_option() {
        let input = "!fn-py(cache=true) double a number";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::Fn,
                prompt,
                user_confirmation,
                force_tool,
                cache,
            })) => {
                assert_eq!(prompt, "double a number");
                assert!(!user_confirmation);
                assert!(force_tool);
                assert!(cache);
            }
            _ => panic!("Failed to parse !fn-py command properly"),
        }
    }

    #[test]
    fn test_tool_require() {
        let input = "!py area of circle w/ radius 3";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                force_tool,
                ..
            })) => {
                assert_eq!(prompt, "!py area of circle w/ radius 3");
                assert!(!user_confirmation);
                assert!(force_tool);
            }
            _ => panic!("Failed to parse !py command properly"),
        }

        let input = "!py? area of circle w/ radius 3";
        let cmd = parse_user_input(input, None, None);
        match cmd {
            Some(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                force_tool,
                ..
            })) => {
                assert_eq!(prompt, "!py area of circle w/ radius 3");
                assert!(!user_confirmation);
                assert!(!force_tool);
            }
            _ => panic!("Failed to parse !py command properly"),
        }
    }
}
