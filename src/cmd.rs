use regex::Regex;
use std::sync::OnceLock;

use crate::{cmd_parse, tool};

#[derive(Clone, Debug)]
/// Represents all possible commands in the program's REPL
pub enum Cmd {
    /// No-op
    Noop,
    /// New conversation
    New,
    /// Reset conversation but retains /pin /asset-read /file-read /http-get
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
    /// Agentic mode on/off
    Agentic(AgenticCmd),
    /// Get/set AI model temperature
    Temperature(TemperatureCmd),
    /// Executes a shell command
    Exec(ExecCmd),
    /// Print all haivars
    PrintVars,
    /// Set a haivar variable
    SetVar(SetVarCmd),
    /// Read files into conversation
    FileRead(FileReadCmd),
    /// Read file(s) into the conversation and print it
    FileCat(FileCatCmd),
    /// Write file
    FileWrite(FileWriteCmd),
    /// Patch a file by replacing an exact string
    FilePatch(FilePatchCmd),
    /// Load URL into conversation
    HttpGet(HttpGetCmd),
    /// Add pinned message to conversation
    Pin(PinCmd),
    /// Add a message without triggering an AI response
    Prep(PrepCmd),
    /// Add a message mocked as from the AI to the conversation
    Assistant(AssistantCmd),
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
    /// Download a task to a temp filefor editing
    TaskEdit(TaskEditCmd),
    /// Include task cmds in conversation without entering task-mode
    TaskInclude(TaskIncludeCmd),
    /// Search for tasks in the repo
    TaskSearch(TaskSearchCmd),
    /// View the task config without running it
    TaskCat(TaskCatCmd),
    /// List all versions of a task
    TaskVersions(TaskVersionsCmd),
    /// Create or edit an asset
    Asset(AssetCmd),
    /// Push into an asset
    AssetPush(AssetPushCmd),
    /// List assets with matching prefix
    AssetList(AssetListCmd),
    /// Search assets semantically
    AssetSearch(AssetSearchCmd),
    /// Read an asset into the convo
    AssetRead(AssetReadCmd),
    /// Write an asset
    AssetWrite(AssetWriteCmd),
    /// Read an asset into the convo and print it
    AssetCat(AssetCatCmd),
    /// Patch an asset by replacing an exact string
    AssetPatch(AssetPatchCmd),
    /// Get link to an asset
    AssetLink(AssetLinkCmd),
    /// Remove an asset
    AssetRemove(AssetRemoveCmd),
    /// Move an asset
    AssetMove(AssetMoveCmd),
    /// Copy an asset
    AssetCopy(AssetCopyCmd),
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
    /// Temporarily replicate asset revision onto local filesystem
    AssetRevisionTemp(AssetRevisionTempCmd),
    /// Syncs assets onto the local filesystem
    AssetSyncDown(AssetSyncDownCmd),
    /// Syncs assets up to the cloud
    AssetSyncUp(AssetSyncUpCmd),
    /// Print local changes to assets
    AssetSyncDiff(AssetSyncDiffCmd),
    /// Get ACL for an asset
    AssetAclGet(AssetAclGetCmd),
    /// Get effective ACL for an asset
    AssetAclGetEffective(AssetAclGetEffectiveCmd),
    /// Set ACL for an asset
    AssetAclSet(AssetAclSetCmd),
    /// Get metadata for asset
    AssetMdGet(AssetMdGetCmd),
    /// Set metadata for asset
    AssetMdSet(AssetMdSetCmd),
    /// Set key in asset metadata
    AssetMdSetKey(AssetMdSetKeyCmd),
    /// Delete key in asset metadata
    AssetMdDelKey(AssetMdDelKeyCmd),
    /// New asset folder
    AssetFolderNew(AssetFolderNewCmd),
    /// Collapse asset folder
    AssetFolderCollapse(AssetFolderCollapseCmd),
    /// Expand asset folder
    AssetFolderExpand(AssetFolderExpandCmd),
    /// List asset folder
    AssetFolderList(AssetFolderListCmd),
    /// Setup asset enc/dec & signing keys
    AssetCryptSetup,
    /// Unlock encryption key
    AssetCryptUnlock(AssetCryptUnlockCmd),
    /// Lock encryption key
    AssetCryptLock(AssetCryptLockCmd),
    /// Recover enc/dec & signing keys
    AssetCryptRecover(AssetCryptRecoverCmd),
    /// Launch an asset-based app in the browser
    AssetApp(AssetAppCmd),
    /// List permissions
    AssetAppPermsList(AssetAppPermsListCmd),
    /// Revoke permissions
    AssetAppPermsRevoke(AssetAppPermsRevokeCmd),
    /// Open an asset
    AssetOpen(AssetOpenCmd),
    /// Create a new asset-pool shared between users
    AssetPoolNew(AssetPoolNewCmd),
    /// List asset pools
    AssetPools,
    /// Start gateway server (Only for testing, so modestly hidden)
    Gateway(GatewayCmd),
    /// List chats and prompt for resumption
    Chats,
    /// Resume a chat
    ChatResume(ChatResumeCmd),
    /// Save a chat
    ChatSave(ChatSaveCmd),
    /// Send an email
    Email(EmailCmd),
    /// Send a notification
    Notif(NotifCmd),
    /// Execute AI-defined function
    FnExec(FnExecCmd),
    /// List all AI-defined functions
    Fns,
    /// Execute a standard library function
    Std(StdCmd),
    /// Add MCP server
    McpAdd(McpAddCmd),
    /// Call an MCP tool
    McpToolCall(McpToolCallCmd),
    /// Boot hai bot
    BotBoot(BotBootCmd),
    /// Get active hai bot info
    BotGetActive,
    /// Probe hai bot
    BotProbe,
    /// Setup hai bot
    BotSetup,
    /// Ssh into hai bot
    BotSsh,
    /// Shutdown hai bot
    BotShutdown,
    /// Get current account (or if specified, switch to logged-in account)
    Account(AccountCmd),
    /// Make a new account
    AccountNew,
    /// Login to an account
    AccountLogin(AccountLoginCmd),
    /// Logout of account (remove local credentials)
    AccountLogout(AccountLogoutCmd),
    /// Balance of an account
    AccountBalance,
    /// Subscribe
    AccountSubscribe,
    /// Setup inbox
    InboxSetup,
    /// Get whois info for a user
    Whois(WhoisCmd),
    /// See cost of models
    Cost,
    /// Web search
    WebSearch(WebSearchCmd),
    /// Pop a message from the listen queue
    QueuePop(QueuePopCmd),
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
    #[allow(dead_code)]
    /// DEPRECATED: Whether to include help message in conversation history
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
pub struct AgenticCmd {
    // Tuple of (agentic-mode, use-prompt-cache)
    pub on: Option<(bool, bool)>,
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
    /// Whether to run the command in interactive mode
    pub interactive: bool,
}

#[derive(Clone, Debug)]
pub struct SetVarCmd {
    /// Name of the variable
    pub key: String,
    /// Value to set
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct FileReadCmd {
    /// Path or glob pattern to load files from
    pub path: String,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
    /// If it's an image, whether to load the high-resolution version
    pub image_hq: bool,
}

#[derive(Clone, Debug)]
pub struct FileCatCmd {
    /// Path or glob pattern to load files from
    pub path: String,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
    /// If it's an image, whether to load the high-resolution version
    pub image_hq: bool,
}

#[derive(Clone, Debug)]
pub struct FileWriteCmd {
    /// Path to write file to
    pub path: String,
    /// Contents to write to the file
    pub contents: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilePatchCmd {
    /// Path to file to patch
    pub path: String,
    /// The exact string to replace in the asset
    pub search: String,
    /// The string to replace with
    pub replace: String,
}

#[derive(Clone, Debug)]
pub struct HttpGetCmd {
    /// URL to load from
    pub url: String,
    /// Do not extract article and convert HTML to markdown
    pub raw: bool,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
    /// If it's an image, whether to load the high-resolution version
    pub image_hq: bool,
}

#[derive(Clone, Debug)]
pub enum Accent {
    Danger,
    Warn,
    Info,
    Success,
}

#[derive(Clone, Debug)]
pub struct PinCmd {
    #[allow(dead_code)]
    /// Message to pin to the conversation
    pub message: String,
    /// Accent color for the pinned message
    pub accent: Option<Accent>,
}

#[derive(Clone, Debug)]
pub struct PrepCmd {
    #[allow(dead_code)]
    /// Message to send without triggering AI response
    pub message: String,
    /// Accent color for the prep message
    pub accent: Option<Accent>,
}

#[derive(Clone, Debug)]
pub struct AssistantCmd {
    /// Message to add as from the AI to the conversation
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
    /// Caching for a task is on a per-key basis.
    pub key: Option<String>,
    /// If trusted, skip user confirmations on task initialization
    pub trust: bool,
}

#[derive(Clone, Debug)]
pub struct TaskForgetCmd {
    /// Task fqn or local path to forget cached answers for
    pub task_ref: String,
    /// Forget cached answers for a specific key
    pub key: Option<String>,
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
pub struct TaskEditCmd {
    /// Task fqn to download to a temp file for editing
    pub task_fqn: String,
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
    /// Caching for a task is on a per-key basis.
    pub key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TaskSearchCmd {
    /// The search string to use
    pub q: String,
}

#[derive(Clone, Debug)]
pub struct TaskCatCmd {
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

    /// Whether to create the asset if it does not exist
    pub no_create: bool,
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
    /// Whether to sort by descending
    pub desc: bool,
    /// Display complete information in table format
    pub full: bool,
}

#[derive(Clone, Debug)]
pub struct AssetSearchCmd {
    /// The search string to use
    pub q: String,
    /// Optional asset-pool path to search within
    pub path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetReadCmd {
    /// Name of the asset
    pub asset_names: Vec<String>,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
    /// If it's an image, whether to load the high-resolution version
    pub image_hq: bool,
}

#[derive(Clone, Debug)]
pub struct AssetWriteCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Contents to write
    pub contents: Option<String>,
    /// Whether to encrypt the asset
    pub encrypt: bool,
}

#[derive(Clone, Debug)]
pub struct AssetCatCmd {
    /// Name of the asset
    pub asset_names: Vec<String>,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
    /// If it's an image, whether to load the high-resolution version
    pub image_hq: bool,
}

#[derive(Clone, Debug)]
pub struct AssetPatchCmd {
    /// Name of the asset
    pub asset_name: String,
    /// The exact string to replace in the asset
    pub search: String,
    /// The string to replace with
    pub replace: String,
}

#[derive(Clone, Debug)]
pub struct AssetRevisionsCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Number of revisions to show
    pub count: Option<u32>,
    /// Whether to include line numbers
    pub show_line_numbers: bool,
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
    /// Recursive removal of all assets under matched folders
    pub recursive: bool,
}

#[derive(Clone, Debug)]
pub struct AssetMoveCmd {
    pub source_asset_name: String,
    pub dest_asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetCopyCmd {
    pub source_asset_name: String,
    pub dest_asset_name: String,
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
pub struct AssetSyncUpCmd {
    /// Path of files to sync up as assets
    pub source_path: String,
    /// Prefix to sync up to
    pub target_prefix: String,
    /// Whether to sync new files
    pub sync_new_files: bool,
    /// Whether to do a dry run
    pub dry_run: bool,
}

#[derive(Clone, Debug)]
pub struct AssetSyncDiffCmd {
    /// Path to diff against
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct AssetTempCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Number of revisions to output
    pub count: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct AssetRevisionTempCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Revision ID to fetch
    pub rev_id: String,
}

#[derive(Clone, Debug)]
pub struct AssetAclGetCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetAclGetEffectiveCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub enum AssetAcePrincipal {
    Everyone,
    User(String),
}

#[derive(Clone, Debug)]
pub enum AssetAcePermission {
    ReadData,
    ReadRevisions,
    WriteData,
    PushData,
}

#[derive(Clone, Debug)]
pub enum AssetAceEffect {
    Allow,
    Deny,
    Inherit,
}

#[derive(Clone, Debug)]
pub struct AssetAclSetCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Principal
    pub ace_principal: AssetAcePrincipal,
    /// Permission to grant
    pub ace_permission: AssetAcePermission,
    /// Permission to grant
    pub ace_effect: AssetAceEffect,
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
pub struct AssetFolderNewCmd {
    /// Name of the folder asset
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct AssetFolderCollapseCmd {
    /// Folder prefix to collapse
    pub prefix: String,
}

#[derive(Clone, Debug)]
pub struct AssetFolderExpandCmd {
    /// Folder prefix to expand
    pub prefix: String,
}

#[derive(Clone, Debug)]
pub struct AssetFolderListCmd {
    /// Prefix of folders to list
    pub prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetCryptRecoverCmd {
    /// Key ID
    pub enc_key_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetCryptUnlockCmd {
    /// Key ID
    pub enc_key_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetCryptLockCmd {
    /// Key ID
    pub enc_key_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetAppCmd {
    /// Name of the asset
    pub asset_name: String,
    /// Do not open the app in the browser
    pub no_open: bool,
    /// Local path to a vite project. When set, `npm run dev` is launched there
    /// and GET requests under `asset_name` are proxied to the vite dev server.
    pub dev_mode: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AssetAppPermsListCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetAppPermsRevokeCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetOpenCmd {
    /// Name of the asset
    pub asset_name: String,
}

#[derive(Clone, Debug)]
pub struct AssetPoolNewCmd {
    /// List of usernames
    pub usernames: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GatewayCmd {
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ChatResumeCmd {
    /// Name of the chat log asset
    /// If omitted, queries the local db for last chat
    pub chat_log_name: Option<String>,
    /// Whether to create a new asset when re-saving
    pub fork: bool,
}

#[derive(Clone, Debug)]
pub struct ChatSaveCmd {
    /// Name of the asset to save the chat log to
    pub chat_log_name: Option<String>,
    /// If from a resumed chat, creates a new asset when re-saving
    pub fork: bool,
}

#[derive(Clone, Debug)]
pub struct EmailCmd {
    /// Subject of the email
    pub subject: String,
    /// Body of the email
    pub body: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NotifCmd {
    /// Title of the notification
    pub title: String,
    /// Body of the notification
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
pub enum StdCmd {
    Now,
    NewDayAlert,
    Which(String),
}

#[derive(Clone, Debug)]
pub struct McpAddCmd {
    pub name: String,
    pub cmd: String,
}

#[derive(Clone, Debug)]
pub struct McpToolCallCmd {
    pub name: String,
    pub tool_name: String,
    pub json_arg: String,
}

#[derive(Clone, Debug)]
pub struct BotBootCmd {
    pub hai_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountCmd {
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountLoginCmd {
    // hai account username
    pub username: Option<String>,
    // hai account password
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountLogoutCmd {
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WhoisCmd {
    pub username: String,
}

#[derive(Clone, Debug)]
pub struct WebSearchCmd {
    pub q: String,
    pub n: u32,
    pub pd: bool,
    pub pw: bool,
    pub pm: bool,
    pub py: bool,
    pub range: Option<String>,
}

#[derive(Clone, Debug)]
pub struct QueuePopCmd {
    pub queue_name: Option<String>,
}

pub fn get_cmds_with_markdown_body_re() -> &'static Regex {
    static CMDS_WITH_MARKDOWN_BODY_RE: OnceLock<Regex> = OnceLock::new();
    CMDS_WITH_MARKDOWN_BODY_RE.get_or_init(|| {
        Regex::new(r"^/(pin|prep|prompt|system-prompt)(\.[a-z0-9-_]+|\([a-z0-9-_]+\))?(\s|$)")
            .unwrap()
    })
}

/// Parses user/task input.
///
/// In general, command-like strings that don't exactly match one of our
/// commands are treated as prompts rather than errors. This is to minimize
/// conflicts between prompts from the user (especially pasted code) and our
/// command list. For example, we don't want a "//comment" input to trigger an
/// error even though if you squint it looks like a cmd.
pub fn parse_user_input(
    cmd_registry: &crate::cmd_registry::Registry,
    input: &str,
    last_tool_cmd: Option<ToolCmd>,
    tool_mode: Option<ToolModeCmd>,
) -> Result<Cmd, cmd_parse::ParseError> {
    if input.trim().is_empty() {
        return Ok(Cmd::Noop);
    }
    // NOTE: We intentionally preserve whitespace at the start of the input.
    // Why? Because a space at the start is the easiest way for a user to
    // indicate that their message is definitely not a command, but a prompt.

    // EXPERIMENT: Add $cmd as a short hand for exec. It's not ideal b/c it's
    // similar to the tool notations (! and !?). But, "/e " has proven to be
    // rather awkward to type. The "/" is tough to reach and the " " before the
    // command conflicts with muscle memory from other programs (ipython).
    let input = if let Some(shell_cmd) = input.strip_prefix("!!") {
        format!("/exec {}", shell_cmd)
    } else {
        input.to_string()
    };
    // EXPERIMENT: Add `$ <cmd>` as a short hand for `/exec`. Want to preserve
    // all `!` commmands (including `!!`) for tool use.
    let input = if let Some(shell_cmd) = input.strip_prefix("$ ") {
        format!("/exec {}", shell_cmd)
    } else {
        input.to_string()
    };

    // FUTURE: Ideally, these would be handled by the cmd_registry. Revisit
    // when refactoring to allow any command to be made into a tool.
    let (peeled_input, confirm, force) = peel_bang_modifiers(&input);

    // `!'<program>' <prompt>`: resolve the tool ourselves since it isn't in
    // the registry. Delegates tail to the generic parser.
    if let Some((shell_cmd, tail)) = split_custom_tool(&peeled_input) {
        let resolved = cmd_parse::parse_with_spec(crate::cmd_registry::CUSTOM_TOOL_SPEC, tail)?;
        return Ok(apply_tool_modifiers(
            build_custom_tool(resolved, shell_cmd)?,
            confirm,
            force,
        ));
    }

    match crate::cmd_parse::parse(cmd_registry, &peeled_input) {
        Ok(resolved_cmd_spec) => {
            match build(resolved_cmd_spec) {
                Ok(cmd) => {
                    Ok(apply_tool_modifiers(cmd, confirm, force))
                }
                Err(e) => Err(e),
            }
        }
        Err(ParseError::NotACommand) => {
            if peeled_input.ends_with("\n\n") {
                // NOTE: Caller should alert user why their message was
                // converted into a prep.
                let message = peeled_input.trim_end();
                Ok(Cmd::Prep(PrepCmd {
                    message: message.into(),
                    accent: None,
                }))
            } else if peeled_input.trim_end() == "!" {
                if let Some(last_tool_cmd) = last_tool_cmd {
                    let merged_user_confirmation = if confirm {
                        true
                    } else {
                        last_tool_cmd.user_confirmation
                    };
                    let merged_force_tool = if !force {
                        false
                    } else {
                        last_tool_cmd.force_tool
                    };
                    let tool_cmd = Cmd::Tool(ToolCmd {
                        tool: last_tool_cmd.tool,
                        prompt: last_tool_cmd.prompt.clone(),
                        user_confirmation: merged_user_confirmation,
                        force_tool: merged_force_tool,
                        cache: false,
                    });
                    Ok(tool_cmd)
                } else {
                    // NOTE: Caller should alert user why their tool shorthand
                    // was converted into a prompt.
                    Ok(Cmd::Prompt(PromptCmd {
                        prompt: input.into(),
                        cache: false,
                    }))
                }
            } else if let Some(remaining) = peeled_input.strip_prefix("! ") {
                if let Some(last_tool_cmd) = last_tool_cmd {
                    let merged_user_confirmation = if confirm {
                        true
                    } else {
                        last_tool_cmd.user_confirmation
                    };
                    let merged_force_tool = if !force {
                        false
                    } else {
                        last_tool_cmd.force_tool
                    };
                    let tool_cmd = Cmd::Tool(ToolCmd {
                        tool: last_tool_cmd.tool,
                        prompt: remaining.into(),
                        user_confirmation: merged_user_confirmation,
                        force_tool: merged_force_tool,
                        cache: false,
                    });
                    return Ok(apply_tool_modifiers(
                        tool_cmd,
                        merged_user_confirmation,
                        merged_force_tool,
                    ));
                } else {
                    // NOTE: Caller should alert user why their tool shorthand
                    // was converted into a prompt.
                    Ok(Cmd::Prompt(PromptCmd {
                        prompt: input.into(),
                        cache: false,
                    }))
                }
            } else if let Some(tool_mode) = tool_mode {
                let tool_cmd = Cmd::Tool(ToolCmd {
                    tool: tool_mode.tool,
                    prompt: input.into(),
                    user_confirmation: tool_mode.user_confirmation,
                    force_tool: tool_mode.force_tool,
                    cache: false,
                });
                return Ok(apply_tool_modifiers(
                    tool_cmd,
                    tool_mode.user_confirmation,
                    tool_mode.force_tool,
                ));
            } else {
                Ok(Cmd::Prompt(PromptCmd {
                    prompt: input.into(),
                    cache: false,
                }))
            }
        }
        Err(e) => Err(e),
    }
}

// --

/// The registry parser doesn't understand the `!?<tool>` and `!<tool>?`
/// modifiers. For example:
///
///   !?sh ...  -> user_confirmation = true
///   !sh? ...  -> force_tool = false
///
/// While ideally these would be moved to the parser, it's currently easier
/// just to keep track of these at this layer and pass an unmodified version to
/// the registry parser.
fn peel_bang_modifiers(input: &str) -> (String, bool, bool) {
    let (mut confirm, mut force) = (false, true);

    let Some(rest) = input.strip_prefix('!') else {
        return (input.to_string(), confirm, force);
    };
    let rest = match rest.strip_prefix('?') {
        Some(r) => {
            confirm = true;
            r
        }
        None => rest,
    };

    // End of the tool word: a quoted string, or a run of name chars.
    let end = match rest.chars().next() {
        Some(q @ ('\'' | '"')) => {
            let mut it = rest.char_indices().skip(1);
            loop {
                match it.next() {
                    Some((_, '\\')) => {
                        it.next();
                    }
                    Some((i, c)) if c == q => break i + c.len_utf8(),
                    Some(_) => {}
                    // Unterminated: hand it back untouched and let the old
                    // path report it.
                    None => return (input.to_string(), false, true),
                }
            }
        }
        _ => rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(rest.len()),
    };

    let tail = match rest[end..].strip_prefix('?') {
        Some(t) => {
            force = false;
            t
        }
        None => &rest[end..],
    };
    (format!("!{}{}", &rest[..end], tail), confirm, force)
}

/// Applies `user_confirmation` and `force_tool` to a `Cmd` since these flags
/// were determined by `peel_bang_modifiers` rather than by the registry
/// parser.
///
/// Also, adds the `!tool` prefix to the prompt for `Cmd::Tool` to assist the
/// LLM.
fn apply_tool_modifiers(cmd: Cmd, user_confirmation: bool, force_tool: bool) -> Cmd {
    match cmd {
        Cmd::Tool(c) => {
            // Conditionally add !tool to prompt + flags
            let prompt = get_tool_prefixed_prompt(&c.tool, user_confirmation, &c.prompt);
            Cmd::Tool(ToolCmd {
                prompt,
                user_confirmation,
                force_tool,
                ..c
            })
        }
        Cmd::ToolMode(c) => Cmd::ToolMode(ToolModeCmd {
            user_confirmation,
            force_tool,
            ..c
        }),
        other => other,
    }
}

// --

// Conversion of `ResolvedCmdSpec` into the `Cmd` the REPL executes.
//
// Everything here is a mechanical translation. Arity, enums, option types and
// bodies were already validated by the parser; the only failures raised here
// are semantic coercions (ACL strings, numbers in text slots).

use crate::cmd_parse::{Opts, ParseError, ResolvedCmdSpec};
use crate::cmd_registry::Sigil;

//
// Coercions
//

fn accent(opts: &Opts) -> Option<Accent> {
    opts.first_set(&["danger", "warn", "info", "success"])
        .map(|n| match n {
            "danger" => Accent::Danger,
            "warn" => Accent::Warn,
            "info" => Accent::Info,
            _ => Accent::Success,
        })
}

fn parse_principal(s: &str) -> Option<AssetAcePrincipal> {
    if s == "everyone" {
        return Some(AssetAcePrincipal::Everyone);
    }
    s.strip_prefix("user:")
        .filter(|u| !u.is_empty())
        .map(|u| AssetAcePrincipal::User(u.to_string()))
}

fn parse_ace(s: &str) -> Option<(AssetAceEffect, AssetAcePermission)> {
    let (effect, perm) = s.split_once(':')?;
    let effect = match effect {
        "allow" => AssetAceEffect::Allow,
        "deny" => AssetAceEffect::Deny,
        "inherit" => AssetAceEffect::Inherit,
        _ => return None,
    };
    let perm = match perm {
        "read-data" => AssetAcePermission::ReadData,
        "read-revisions" => AssetAcePermission::ReadRevisions,
        "write-data" => AssetAcePermission::WriteData,
        "push-data" => AssetAcePermission::PushData,
        _ => return None,
    };
    Some((effect, perm))
}

/// `/f1`, `/f_summarize`, ... — injected at runtime by the function-tool machinery.
fn is_fn_cmd(name: &str) -> bool {
    name.starts_with("f_")
        || (name.len() > 1
            && name.starts_with('f')
            && name[1..].chars().all(|c| c.is_ascii_digit()))
}

//
// !tool handler
//

/// Warning: Does not handle custom tools: ExecWithStdin or ExecWithFile
fn get_tool_from_resolved_cmd_spec(r: &ResolvedCmdSpec) -> Option<tool::Tool> {
    use tool::Tool;
    Some(match r.spec.name.as_ref() {
        "sh" => Tool::ShellScriptExec,
        "py" => Tool::ExecPythonScript,
        "pyuv" => Tool::ExecPythonUvScript,
        "html" => Tool::Html,
        "hai" => Tool::HaiRepl,
        "clip" => Tool::CopyToClipboard,
        "fn-py" => Tool::Fn(tool::FnTool {
            kind: tool::FnToolType::FnPy,
            name: r.opts.string("name"),
        }),
        "fn-pyuv" => Tool::Fn(tool::FnTool {
            kind: tool::FnToolType::FnPyUv,
            name: r.opts.string("name"),
        }),
        "fn-sh" => Tool::Fn(tool::FnTool {
            kind: tool::FnToolType::FnSh,
            name: r.opts.string("name"),
        }),
        _ => return None,
    })
}

/// `!<tool> [<prompt>]`. An empty prompt enters tool mode.
///
/// `user_confirmation` is left false: the `?` in `!?sh` is stripped by the
/// bespoke `!` grammar before `parse_with_spec`, so that layer owns the flag.
/// Use `set_user_confirmation` on the result.
fn build_tool(mut r: ResolvedCmdSpec) -> Result<Cmd, ParseError> {
    if r.spec.name == "exit" {
        return Ok(Cmd::ToolModeExit);
    }
    let Some(tool) = get_tool_from_resolved_cmd_spec(&r) else {
        debug_assert!(false, "no tool mapping for !{}", r.spec.name);
        return Err(ParseError::UnknownCmd {
            sigil: Sigil::Bang,
            name: r.spec.name.to_string(),
            suggestion: None,
        });
    };
    // Not every tool declares .cache; querying an undeclared option trips a
    // debug_assert in Opts.
    let cache = r.spec.find_opt("cache").is_some() && r.opts.bool("cache");
    let prompt = r.take(0);

    Ok(if prompt.trim().is_empty() {
        Cmd::ToolMode(ToolModeCmd {
            tool,
            user_confirmation: false,
            force_tool: true,
        })
    } else {
        Cmd::Tool(ToolCmd {
            tool,
            prompt,
            user_confirmation: false,
            force_tool: true,
            cache,
        })
    })
}

//
// Build cmd: ResolvedCmdSpec -> Cmd
//

pub fn build(mut r: ResolvedCmdSpec) -> Result<Cmd, ParseError> {
    if r.spec.sigil == Sigil::Bang {
        return build_tool(r);
    }
    let name = r.spec.name.as_ref();

    Ok(match name {
        //
        // Meta commands
        //
        "help" => Cmd::Help(HelpCmd {
            // DEPRECATED: output is always added to history.
            history: true,
        }),
        "quit" => Cmd::Quit,
        "new" => Cmd::New,
        "reset" => Cmd::Reset,

        //
        // LLM options
        //
        "set-key" => Cmd::SetKey(SetKeyCmd {
            provider: r.take(0),
            key: r.take(1),
        }),
        "ai" => Cmd::Ai(AiCmd {
            model: r.opt_take(0),
        }),
        "ai-default" => Cmd::AiDefault(AiDefaultCmd {
            model: r.opt_take(0),
        }),
        "agentic" => Cmd::Agentic(AgenticCmd {
            // (agentic-mode, use-prompt-cache)
            on: Some(match r.arg(0) {
                "on" => (true, true),
                "on-without-cache" => (true, false),
                _ => (false, false),
            }),
        }),
        "temperature" => Cmd::Temperature(TemperatureCmd {
            temperature: {
                let t = r.arg(0);
                if t.is_empty() || t.eq_ignore_ascii_case("none") {
                    None
                } else {
                    r.num::<f32>(0)?
                }
            },
        }),

        //
        // Account management
        //
        "account" => Cmd::Account(AccountCmd {
            username: r.opt_take(0),
        }),
        "account-new" => Cmd::AccountNew,
        "account-login" => Cmd::AccountLogin(AccountLoginCmd {
            username: None,
            password: None,
        }),
        "account-logout" => Cmd::AccountLogout(AccountLogoutCmd {
            username: r.opt_take(0),
        }),
        "account-balance" => Cmd::AccountBalance,
        "account-subscribe" => Cmd::AccountSubscribe,
        "whois" => Cmd::Whois(WhoisCmd {
            username: r.take(0),
        }),
        "hai-router" => Cmd::HaiRouter(HaiRouterCmd {
            // ArgKind::Enum already restricted this to on|off.
            on: Some(r.arg(0) == "on"),
        }),

        //
        // Files
        //
        "file-read" => Cmd::FileRead(FileReadCmd {
            path: r.take_rest(0).join(" "),
            show_line_numbers: r.opts.bool("n"),
            image_hq: r.opts.bool("hq"),
        }),
        "file-cat" => Cmd::FileCat(FileCatCmd {
            path: r.take_rest(0).join(" "),
            show_line_numbers: r.opts.bool("n"),
            image_hq: r.opts.bool("hq"),
        }),
        "file-write" => Cmd::FileWrite(FileWriteCmd {
            path: r.take(0),
            contents: r.body.take(),
        }),
        "file-patch" => {
            let (search, replace) = {
                let p = r.patch_or_err()?;
                (p.search.clone(), p.replace.clone())
            };
            Cmd::FilePatch(FilePatchCmd {
                path: r.take(0),
                search,
                replace,
            })
        }
        "cd" => Cmd::Cd(CdCmd { path: r.take(0) }),

        //
        // HTTP
        //
        "http-get" => Cmd::HttpGet(HttpGetCmd {
            url: r.take(0),
            raw: r.opts.bool("raw"),
            show_line_numbers: r.opts.bool("n"),
            image_hq: r.opts.bool("hq"),
        }),

        //
        // Exec
        //
        "exec" => Cmd::Exec(ExecCmd {
            command: r.take(0),
            cache: r.opts.bool("cache"),
            interactive: r.opts.bool("i"),
        }),

        //
        // Conversation management
        //
        "prep" => Cmd::Prep(PrepCmd {
            accent: accent(&r.opts),
            message: r.take(0),
        }),
        "pin" => Cmd::Pin(PinCmd {
            accent: accent(&r.opts),
            message: r.take(0),
        }),
        "system-prompt" => Cmd::SystemPrompt(SystemPromptCmd {
            prompt: r.opt_take(0),
        }),
        "clip" => Cmd::Clip,
        "forget" => Cmd::Forget(ForgetCmd {
            n: r.num(0)?.unwrap_or(1),
        }),
        "keep" => Cmd::Keep(KeepCmd {
            bottom: r
                .num(0)?
                .ok_or_else(|| r.bad_value(0, "expected a number"))?,
            top: r.num(1)?,
        }),

        //
        // Function tools
        //
        "fns" => Cmd::Fns,

        // Stdlib fns
        "std" => {
            let sub = r.sub.as_ref().expect("Sub arg is Required");
            Cmd::Std(match sub.spec.name.as_ref() {
                "now" => StdCmd::Now,
                "new-day-alert" => StdCmd::NewDayAlert,
                "which" => StdCmd::Which(sub.arg(0).to_string()),
                other => unreachable!("std subcommand {other} has no build arm"),
            })
        }

        //
        // Assets
        //
        "asset" => Cmd::Asset(AssetCmd {
            no_create: r.opts.bool("no_create"),
            asset_name: r.take(0),
            editor: r.opt_take(1),
        }),
        "asset-list" => Cmd::AssetList(AssetListCmd {
            desc: r.opts.bool("desc"),
            full: r.opts.bool("full"),
            prefix: r.take(0),
        }),
        "asset-search" => Cmd::AssetSearch(AssetSearchCmd {
            path: r.opts.string("path"),
            q: r.take(0),
        }),
        "asset-read" => Cmd::AssetRead(AssetReadCmd {
            show_line_numbers: r.opts.bool("n"),
            image_hq: r.opts.bool("hq"),
            asset_names: r.take_rest(0),
        }),
        "asset-write" => Cmd::AssetWrite(AssetWriteCmd {
            encrypt: r.opts.bool("encrypt"),
            asset_name: r.take(0),
            contents: r.body.take(),
        }),
        "asset-cat" => Cmd::AssetCat(AssetCatCmd {
            show_line_numbers: r.opts.bool("n"),
            image_hq: r.opts.bool("hq"),
            asset_names: r.take_rest(0),
        }),
        "asset-patch" => {
            let (search, replace) = {
                let p = r.patch_or_err()?;
                (p.search.clone(), p.replace.clone())
            };
            Cmd::AssetPatch(AssetPatchCmd {
                asset_name: r.take(0),
                search,
                replace,
            })
        }
        "asset-link" => Cmd::AssetLink(AssetLinkCmd {
            asset_name: r.take(0),
        }),
        "asset-revisions" => Cmd::AssetRevisions(AssetRevisionsCmd {
            show_line_numbers: r.opts.bool("n"),
            count: r.num(1)?,
            asset_name: r.take(0),
        }),
        "asset-listen" => Cmd::AssetListen(AssetListenCmd {
            asset_name: r.take(0),
            cursor: r.opt_take(1),
        }),
        "asset-follow" => Cmd::AssetFollow(AssetFollowCmd {
            asset_name: r.take(0),
        }),
        "asset-push" => Cmd::AssetPush(AssetPushCmd {
            asset_name: r.take(0),
            contents: r.body.take(),
        }),
        "asset-import" => Cmd::AssetImport(AssetImportCmd {
            target_asset_name: r.take(0),
            source_file_path: r.take(1),
        }),
        "asset-export" => Cmd::AssetExport(AssetExportCmd {
            source_asset_name: r.take(0),
            target_file_path: r.take(1),
        }),
        "asset-temp" => Cmd::AssetTemp(AssetTempCmd {
            count: r.num(1)?,
            asset_name: r.take(0),
        }),
        "asset-revision-temp" => Cmd::AssetRevisionTemp(AssetRevisionTempCmd {
            asset_name: r.take(0),
            rev_id: r.take(1),
        }),
        "asset-sync-up" => Cmd::AssetSyncUp(AssetSyncUpCmd {
            sync_new_files: r.opts.bool("new"),
            dry_run: r.opts.bool("dry"),
            source_path: r.take(0),
            target_prefix: r.take(1),
        }),
        "asset-sync-down" => Cmd::AssetSyncDown(AssetSyncDownCmd {
            prefix: r.take(0),
            target_path: r.take(1),
        }),
        "asset-sync-diff" => Cmd::AssetSyncDiff(AssetSyncDiffCmd { path: r.take(0) }),
        "asset-remove" => Cmd::AssetRemove(AssetRemoveCmd {
            asset_name: r.take(0),
            recursive: false,
        }),
        "asset-remove-recursive" => Cmd::AssetRemove(AssetRemoveCmd {
            asset_name: r.take(0),
            recursive: true,
        }),
        "asset-move" => Cmd::AssetMove(AssetMoveCmd {
            source_asset_name: r.take(0),
            dest_asset_name: r.take(1),
        }),
        "asset-copy" => Cmd::AssetCopy(AssetCopyCmd {
            source_asset_name: r.take(0),
            dest_asset_name: r.take(1),
        }),
        "asset-acl-get" => Cmd::AssetAclGet(AssetAclGetCmd {
            asset_name: r.take(0),
        }),
        "asset-acl-get-effective" => Cmd::AssetAclGetEffective(AssetAclGetEffectiveCmd {
            asset_name: r.take(0),
        }),
        "asset-acl-set" => {
            let principal = parse_principal(r.arg(1))
                .ok_or_else(|| r.bad_value(1, "expected `everyone` or `user:<username>`"))?;
            let (effect, permission) = parse_ace(r.arg(2)).ok_or_else(|| {
                r.bad_value(
                    2,
                    "expected <effect>:<permission>, e.g. allow:read-data \
                     (effect: allow|deny|inherit, permission: \
                     read-data|read-revisions|write-data|push-data)",
                )
            })?;
            Cmd::AssetAclSet(AssetAclSetCmd {
                asset_name: r.take(0),
                ace_principal: principal,
                ace_permission: permission,
                ace_effect: effect,
            })
        }
        "asset-md-get" => Cmd::AssetMdGet(AssetMdGetCmd {
            asset_name: r.take(0),
        }),
        "asset-md-set" => Cmd::AssetMdSet(AssetMdSetCmd {
            asset_name: r.take(0),
            metadata: r.take(1),
        }),
        "asset-md-set-key" => Cmd::AssetMdSetKey(AssetMdSetKeyCmd {
            asset_name: r.take(0),
            key: r.take(1),
            value: r.take(2),
        }),
        "asset-md-del-key" => Cmd::AssetMdDelKey(AssetMdDelKeyCmd {
            asset_name: r.take(0),
            key: r.take(1),
        }),
        "asset-folder-new" => Cmd::AssetFolderNew(AssetFolderNewCmd { name: r.take(0) }),
        "asset-folder-collapse" => {
            Cmd::AssetFolderCollapse(AssetFolderCollapseCmd { prefix: r.take(0) })
        }
        "asset-folder-expand" => Cmd::AssetFolderExpand(AssetFolderExpandCmd { prefix: r.take(0) }),
        "asset-folder-list" => Cmd::AssetFolderList(AssetFolderListCmd {
            prefix: r.opt_take(0),
        }),
        "asset-pools" => Cmd::AssetPools,
        "asset-pool-new" => Cmd::AssetPoolNew(AssetPoolNewCmd {
            usernames: r.take_rest(0),
        }),
        "asset-crypt-setup" => Cmd::AssetCryptSetup,
        "asset-crypt-lock" => Cmd::AssetCryptLock(AssetCryptLockCmd {
            enc_key_id: r.opt_take(0),
        }),
        "asset-crypt-unlock" => Cmd::AssetCryptUnlock(AssetCryptUnlockCmd {
            enc_key_id: r.opt_take(0),
        }),
        "asset-crypt-recover" => Cmd::AssetCryptRecover(AssetCryptRecoverCmd { enc_key_id: None }),
        "inbox-setup" => Cmd::InboxSetup,

        //
        // Asset apps
        //
        "asset-app" => Cmd::AssetApp(AssetAppCmd {
            no_open: r.opts.bool("no_open"),
            dev_mode: r.opts.string("dev_mode"),
            asset_name: r.take(0),
        }),
        "asset-app-perms-list" => Cmd::AssetAppPermsList(AssetAppPermsListCmd {
            asset_name: r.take(0),
        }),
        "asset-app-perms-revoke" => Cmd::AssetAppPermsRevoke(AssetAppPermsRevokeCmd {
            asset_name: r.take(0),
        }),
        "asset-open" => Cmd::AssetOpen(AssetOpenCmd {
            asset_name: r.take(0),
        }),

        //
        // Chats
        //
        "chats" => Cmd::Chats,
        "chat-save" => Cmd::ChatSave(ChatSaveCmd {
            fork: r.opts.bool("fork"),
            chat_log_name: r.opt_take(0),
        }),
        "chat-resume" => Cmd::ChatResume(ChatResumeCmd {
            fork: r.opts.bool("fork"),
            chat_log_name: r.opt_take(0),
        }),

        //
        // Tasks
        //
        "task" => Cmd::Task(TaskCmd {
            key: r.opts.string("key"),
            trust: r.opts.bool("trust"),
            task_ref: r.take(0),
        }),
        "task-search" => Cmd::TaskSearch(TaskSearchCmd { q: r.take(0) }),
        "task-cat" => Cmd::TaskCat(TaskCatCmd {
            task_ref: r.take(0),
        }),
        "task-versions" => Cmd::TaskVersions(TaskVersionsCmd {
            task_fqn: r.take(0),
        }),
        "task-end" => Cmd::TaskEnd,
        // `/task-update` is the user-facing name for a fetch of the latest version.
        "task-update" | "task-fetch" => Cmd::TaskFetch(TaskFetchCmd {
            task_fqn: r.take(0),
        }),
        "task-publish" => Cmd::TaskPublish(TaskPublishCmd {
            task_path: r.take(0),
        }),
        "task-edit" => Cmd::TaskEdit(TaskEditCmd {
            task_fqn: r.take(0),
        }),
        "task-forget" => Cmd::TaskForget(TaskForgetCmd {
            key: r.opts.string("key"),
            task_ref: r.take(0),
        }),
        "task-purge" => Cmd::TaskPurge(TaskPurgeCmd {
            task_fqn: r.take(0),
        }),
        "task-include" => Cmd::TaskInclude(TaskIncludeCmd {
            task_ref: r.take(0),
            key: None,
        }),

        // Prompting
        "prompt" => Cmd::Prompt(PromptCmd {
            cache: r.opts.bool("cache"),
            prompt: r.take(0),
        }),
        "ask-human" => Cmd::AskHuman(AskHumanCmd {
            secret: r.opts.bool("secret"),
            cache: r.opts.bool("cache"),
            question: r.take(0),
        }),

        //
        // MCP
        //
        "mcp-add" => {
            let name = r.take(0);
            let env = r.take(1);
            let cmd = r.take(2);
            Cmd::McpAdd(McpAddCmd {
                name,
                // McpAddCmd has no env field; the KEY=VALUE prefix rides along
                // on the command line, which is how the doc example reads.
                cmd: if env.is_empty() {
                    cmd
                } else {
                    format!("{env} {cmd}")
                },
            })
        }

        // Bot
        "bot-boot" => Cmd::BotBoot(BotBootCmd {
            hai_version: r.opt_take(0),
        }),
        "bot-get-active" => Cmd::BotGetActive,
        "bot-probe" => Cmd::BotProbe,
        "bot-setup" => Cmd::BotSetup,
        "bot-ssh" => Cmd::BotSsh,
        "bot-shutdown" => Cmd::BotShutdown,

        // Messaging
        "email" => Cmd::Email(EmailCmd {
            subject: r.take(0),
            body: r.body.take(),
        }),
        "notif" => Cmd::Notif(NotifCmd {
            title: r.take(0),
            body: r.body.take(),
        }),

        // Web search
        "web-search" => Cmd::WebSearch(WebSearchCmd {
            n: r.opts.u32("n").unwrap_or(5),
            pd: r.opts.bool("pd"),
            pw: r.opts.bool("pw"),
            pm: r.opts.bool("pm"),
            py: r.opts.bool("py"),
            range: r.opts.string("range"),
            q: r.take(0),
        }),

        // Utils
        "cost" => Cmd::Cost,
        "setvar" => Cmd::SetVar(SetVarCmd {
            key: r.take(0),
            value: r.take(1),
        }),
        "printvars" => Cmd::PrintVars,
        "set-mask-secrets" => Cmd::SetMaskSecrets(SetMaskSecretsCmd {
            on: match r.arg(0) {
                "" => None,
                s => Some(s == "on"),
            },
        }),
        "queue-pop" => Cmd::QueuePop(QueuePopCmd {
            queue_name: r.opt_take(0),
        }),
        "assistant" => Cmd::Assistant(AssistantCmd { message: r.take(0) }),
        "about" => Cmd::About,

        //
        // Debugging
        //
        "dump" => Cmd::Dump,
        "dump-session" => Cmd::DumpSession,
        "gateway" => Cmd::Gateway(GatewayCmd {
            auth_token: r.opt_take(0),
        }),

        //
        // Dynamic (runtime-injected)
        //
        n if is_fn_cmd(n) => Cmd::FnExec(FnExecCmd {
            fn_name: n.to_string(),
            arg: r.take(0),
        }),
        n if n.starts_with("mcp_") => Cmd::McpToolCall(McpToolCallCmd {
            name: n.to_string(),
            tool_name: r.take(0),
            json_arg: r.take(1),
        }),

        other => {
            // Loud in tests, graceful in release: a registry entry with no
            // build arm behaves like an unknown command rather than panicking
            // in the middle of someone's REPL session.
            debug_assert!(false, "no build arm for /{other}");
            return Err(ParseError::UnknownCmd {
                sigil: r.spec.sigil,
                name: other.to_string(),
                suggestion: None,
            });
        }
    })
}

// --

/// Splits `!'<program>' <tail>` into the program text and the remaining tail.
/// Returns `None` for anything that isn't the custom-tool form.
fn split_custom_tool(input: &str) -> Option<(String, &str)> {
    let rest = input.strip_prefix('!')?;
    let quote = match rest.chars().next()? {
        q @ ('\'' | '"') => q,
        _ => return None,
    };
    let mut cmd = String::new();
    let mut it = rest.char_indices().skip(1);
    loop {
        match it.next()? {
            // Only the quote char is escapable; a literal `\` stays a `\` so
            // shell commands aren't mangled.
            (_, '\\') => match it.next()? {
                (_, c) if c == quote => cmd.push(c),
                (_, c) => {
                    cmd.push('\\');
                    cmd.push(c);
                }
            },
            (i, c) if c == quote => return Some((cmd, &rest[i + c.len_utf8()..])),
            (_, c) => cmd.push(c),
        }
    }
}

/// Builds custom tool cmd from: `!'<program>' [<prompt>]`.
///
/// Switches between Tool::ShellExecWithFile and Tool::ShellExecWithStdin
/// based on whether the shell command contains a file placeholder.
///
/// Like regular tools, an empty prompt returns a ToolMode cmd.
fn build_custom_tool(mut r: ResolvedCmdSpec, shell_cmd: String) -> Result<Cmd, ParseError> {
    let tool = match tool::get_file_placeholder_re().captures(&shell_cmd) {
        Some(caps) => {
            let ext = caps.get(1).map(|m| m.as_str().to_string());
            tool::Tool::ShellExecWithFile(shell_cmd, ext)
        }
        None => tool::Tool::ShellExecWithStdin(shell_cmd),
    };
    let prompt = r.take(0);

    Ok(if prompt.trim().is_empty() {
        Cmd::ToolMode(ToolModeCmd {
            tool,
            user_confirmation: false,
            force_tool: true,
        })
    } else {
        Cmd::Tool(ToolCmd {
            tool,
            prompt,
            user_confirmation: false,
            force_tool: true,
            cache: false,
        })
    })
}

/// Parses a bare tool invocation: `!py`, `!?'psql -U postgres'`, `!sh?`
/// This differs from build_tool in that it's for config parsing, not the REPL.
///
/// - No trailing prompt
/// - No bare `!`
pub fn parse_tool_mode(
    cmd_registry: &crate::cmd_registry::Registry,
    input: &str,
) -> Result<ToolModeCmd, String> {
    let input = input.trim();
    if !input.starts_with('!') {
        return Err(format!("invalid tool {input:?}: must start with `!`"));
    }
    let (peeled, confirm, force) = peel_bang_modifiers(input);

    let cmd = if let Some((shell_cmd, tail)) = split_custom_tool(&peeled) {
        let r = cmd_parse::parse_with_spec(crate::cmd_registry::CUSTOM_TOOL_SPEC, tail)
            .map_err(|e| e.to_string())?;
        build_custom_tool(r, shell_cmd).map_err(|e| e.to_string())?
    } else {
        match cmd_parse::parse(cmd_registry, &peeled) {
            Ok(r) => build(r).map_err(|e| e.to_string())?,
            // `!`, `! foo`, `!!` — scan_name finds nothing to look up.
            Err(ParseError::NotACommand) => {
                return Err("no tool specified: expected `!<tool>`, e.g. `!py`".into());
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    match cmd {
        Cmd::ToolMode(c) => Ok(ToolModeCmd {
            user_confirmation: confirm,
            force_tool: force,
            ..c
        }),
        Cmd::Tool(_) => Err(format!(
            "{input:?} takes no prompt here — configure the tool only, e.g. `!py`"
        )),
        Cmd::ToolModeExit => Err("`!exit` ends tool mode; it can't be entered".into()),
        _ => Err(format!("{input:?} is not a tool")),
    }
}

// --

/// Some tool calls are better handled by the AI when the tool-cmd is prefixed
/// to the prompt. For other tool calls (e.g. !sh), the tool-cmd confuses the
/// AI and causes mistakes (e.g. prefixing shell command with !).
fn get_tool_prefixed_prompt(tool: &tool::Tool, user_confirmation: bool, prompt: &str) -> String {
    let tool_call_type = if user_confirmation { "!?" } else { "!" };
    let tool_call = match tool {
        tool::Tool::CopyToClipboard => format!("{}clip ", tool_call_type),
        tool::Tool::ShellScriptExec => "".to_string(),
        tool::Tool::ExecPythonScript => format!("{}py ", tool_call_type),
        // !py may be more understandable than !pyuv to the LLM--this is unscientific.
        tool::Tool::ExecPythonUvScript => format!("{}py ", tool_call_type),
        tool::Tool::HaiRepl => format!("{}hai ", tool_call_type),
        tool::Tool::Html => format!("{}html ", tool_call_type),
        tool::Tool::ShellExecWithFile(shell_cmd, _) | tool::Tool::ShellExecWithStdin(shell_cmd) => {
            format!("{}'{}' ", tool_call_type, shell_cmd)
        }
        _ => "".to_string(),
    };
    format!("{}{}", tool_call, prompt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_registry::Registry;
    use crate::tool;

    #[test]
    fn test_prefixed_whitespace() {
        // Test that a user can add a space before any input so that it's
        // treated as an AI prompt and never as a command. This eases issues
        // with pasting code that looks like a command.
        let input = " /load xyz";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Prompt(PromptCmd { prompt, .. })) => {
                assert_eq!(prompt, input);
            }
            _ => panic!("Failed to parse no args"),
        }
    }

    #[test]
    fn test_arguments() {
        // Test no arguments
        let input = "/ask-human agree?";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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
    fn test_arguments_new() {
        // Test one argument
        let input = "/ask-human.secret=true agree?";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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
        let input = "/ask-human.secret=true.cache=true agree?";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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

        // Test two arguments shorthand
        let input = "/ask-human.secret.cache agree?";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::AskHuman(AskHumanCmd {
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

        // Test string argument
        let input = "/task.key=\"test\".trust user/task";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Task(TaskCmd {
                task_ref,
                key,
                trust,
            })) => {
                assert_eq!(task_ref, "user/task");
                assert_eq!(key, Some("test".to_string()));
                assert!(trust);
            }
            _ => panic!("Failed to parse string arg"),
        }
    }

    #[test]
    fn test_clip_tool_command() {
        let input = "!clip Copy this to clipboard";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellScriptExec,
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
    fn test_invalid_tool_command() {
        let input = "!invalid_tool Something";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        matches!(cmd, Err(ParseError::UnknownCmd { sigil: Sigil::Bang, name, .. }) if name == "invalid_tool");
    }

    #[test]
    fn test_optional_tool_command() {
        let input = "!?py print('Hello, World!')";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
            user_confirmation: false,
            force_tool: true,
            cache: false,
        };

        // Test tool re-use
        let input = "! 3 + 4";
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
            user_confirmation: false,
            force_tool: true,
            cache: false,
        };

        // Test tool re-use
        let input = "! dump task table";
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, Some(last_tool_cmd.clone()), None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
            tool: tool::Tool::ShellScriptExec,
            prompt: "list home dir".to_string(),
            user_confirmation: true,
            force_tool: true,
            cache: false,
        };

        //
        // Test entering tool mode
        //

        let cmd = parse_user_input(&Registry::new(), "!py", None, None);
        match cmd {
            Ok(Cmd::ToolMode(ToolModeCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, Some(tool_mode.clone()));
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ExecPythonScript,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "!?py 3 + 4");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to use tool mode"),
        }

        //
        // Test tool mode abides by last_tool_cmd
        //

        let cmd = parse_user_input(
            &Registry::new(),
            "! get system time",
            Some(last_tool_cmd),
            Some(tool_mode.clone()),
        );
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool: tool::Tool::ShellScriptExec,
                prompt,
                user_confirmation,
                ..
            })) => {
                assert_eq!(prompt, "get system time");
                assert!(user_confirmation);
            }
            _ => panic!("Failed to re-use tool"),
        }
    }

    #[test]
    fn test_tool_command_with_option() {
        let input = "!fn-py(cache=true) double a number";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool:
                    tool::Tool::Fn(tool::FnTool {
                        kind: tool::FnToolType::FnPy,
                        name: None,
                    }),
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

        let input = "!fn-py.cache=true double a number";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool:
                    tool::Tool::Fn(tool::FnTool {
                        kind: tool::FnToolType::FnPy,
                        name: None,
                    }),
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

        let input = "!fn-py.cache double a number";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
                tool:
                    tool::Tool::Fn(tool::FnTool {
                        kind: tool::FnToolType::FnPy,
                        name: None,
                    }),
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Tool(ToolCmd {
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

    #[test]
    fn test_cmds_with_markdown_body_re() {
        assert!(get_cmds_with_markdown_body_re().is_match("/prep "));
        assert!(get_cmds_with_markdown_body_re().is_match("/prep.a"));
        assert!(get_cmds_with_markdown_body_re().is_match("/prep\n"));
        assert!(!get_cmds_with_markdown_body_re().is_match("/prepz"));
        assert!(!get_cmds_with_markdown_body_re().is_match("/prep["));
    }

    #[test]
    fn test_string_option() {
        // Test simple
        let input = "/task.key=\"A\".trust hai/test";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Task(TaskCmd {
                task_ref,
                key,
                trust,
                ..
            })) => {
                assert_eq!(task_ref, "hai/test");
                assert_eq!(key, Some("A".to_string()));
                assert!(trust);
            }
            _ => panic!("Failed to parse /task command properly"),
        }

        // Test comma in string
        let input = "/task.key=\"A,B\".trust hai/test";
        let cmd = parse_user_input(&Registry::new(), input, None, None);
        match cmd {
            Ok(Cmd::Task(TaskCmd {
                task_ref,
                key,
                trust,
                ..
            })) => {
                assert_eq!(task_ref, "hai/test");
                assert_eq!(key, Some("A,B".to_string()));
                assert!(trust);
            }
            _ => panic!("Failed to parse /task command properly"),
        }
    }
}
