use std::collections::{HashSet, VecDeque};
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    api::client::HaiClient,
    chat, cmd, config,
    db::{self, LogEntryRetentionPolicy},
};

pub enum ReplMode {
    Normal,
    /// Enter task-mode for task with given fqn
    Task(String),
}

pub const HAI_BYE_TASK_NAME: &str = "hai-bye";
pub const INIT_TASK_NAME: &str = "init";
pub const INTERNAL_TASK_NAME: &str = "_hai";

#[derive(Clone)]
pub enum HaiRouterState {
    On,
    OffForModel,
    Off,
}

#[derive(Debug)]
pub enum CmdSource {
    Init,
    HaiBye,
    Internal,
    HaiTool,
    // task_signature: (task_name, task_step_id)
    TaskStep(String, u32),
}

#[derive(Debug)]
pub struct CmdInfo {
    pub cmd: String,
    pub source: CmdSource,
}

pub struct SessionState {
    pub repl_mode: ReplMode,
    /// AI model in active use
    pub ai: config::AiModel,
    pub ai_temperature: Option<f32>,
    /// Running counter of tokens in convo (does not include loaded tokens)
    pub input_tokens: u32,
    /// Running counter of tokens loaded from files (this is retained on /reset)
    pub input_loaded_tokens: u32,
    /// Queue of cmds to run
    pub cmd_queue: VecDeque<CmdInfo>,
    /// History stores previous messages
    pub history: Vec<db::LogEntry>,
    /// The program to use to edit assets
    pub editor: String,
    /// The shell to use for the !sh tool.
    pub shell: String,
    /// These are outputs that should be masked due to sensitivity, which means
    /// they were acquired by user input with secret=true. These are not
    /// cleared even across conversations.
    pub masked_strings: HashSet<String>,
    pub mask_secrets: bool,
    /// Information about logged-in account
    pub account: Option<db::Account>,
    /// Whether the session is in incognito mode (history-less)
    pub incognito: bool,
    /// The last tool that was used (for ! shortcut)
    pub last_tool_cmd: Option<cmd::ToolCmd>,
    /// The tool activated in tool-mode
    pub tool_mode: Option<cmd::ToolModeCmd>,
    /// Whether to use hai-router for compatible AI models
    pub use_hai_router: HaiRouterState,
    /// (Temporary asset file, is task step?)
    pub temp_files: Vec<(tempfile::NamedTempFile, bool)>,
}

/// Recalculates token count based on history.
///
/// Useful when history has been pruned.
pub fn recalculate_input_tokens(session: &mut SessionState) {
    let mut input_tokens = 0;
    let mut input_loaded_tokens = 0;
    for log_entry in &session.history {
        if log_entry.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
            input_loaded_tokens += log_entry.tokens;
        } else {
            input_tokens += log_entry.tokens;
        }
    }
    session.input_tokens = input_tokens;
    session.input_loaded_tokens = input_loaded_tokens;
}

/// Convenience function to add "user text" into conversation history while
/// making the appropriate modifications to the session and token count.
///
/// # Returns
///
/// The number of tokens in `contents`.
pub fn session_history_add_user_text_entry(
    contents: &str,
    session: &mut SessionState,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    retention_policy: (bool, LogEntryRetentionPolicy),
) -> u32 {
    let asset_tokens = bpe_tokenizer.encode_with_special_tokens(contents);
    let token_count = asset_tokens.len() as u32;
    if matches!(
        retention_policy.1,
        LogEntryRetentionPolicy::ConversationLoad
    ) {
        session.input_loaded_tokens += token_count;
    } else {
        session.input_tokens += token_count;
    }
    session.history.push(db::LogEntry {
        uuid: Uuid::now_v7().to_string(),
        message: chat::Message {
            role: chat::MessageRole::User,
            content: vec![chat::MessageContent::Text {
                text: contents.to_string(),
            }],
            tool_calls: None,
            tool_call_id: None,
        },
        tokens: token_count,
        retention_policy,
    });
    token_count
}

/// Similar to `session_history_add_user_text_entry` but also adds an entry for
/// the user's input command.
pub fn session_history_add_user_cmd_and_reply_entries(
    cmd: &str,
    contents: &str,
    session: &mut SessionState,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    retention_policy: (bool, LogEntryRetentionPolicy),
) -> u32 {
    session_history_add_user_text_entry(cmd, session, bpe_tokenizer, retention_policy)
        + session_history_add_user_text_entry(contents, session, bpe_tokenizer, retention_policy)
}

/// Convenience function to add "user image" into conversation history while
/// making the appropriate modifications to the session and token count.
///
/// FIXME: Token count assumes provider is OpenAI (not necssarily) which will
/// downscale in low-detail mode to 85 tokens. No other provider does this and
/// this count will be inaccurate for them. Either fix token counting or apply
/// resize client-side.
///
/// # Returns
///
/// The number of tokens added.
pub fn session_history_add_user_image_entry(
    img_png_b64: &str,
    session: &mut SessionState,
    retention_policy: (bool, LogEntryRetentionPolicy),
) -> u32 {
    // OpenAI-specific for low-detail images
    let token_count = 85u32;
    if matches!(
        retention_policy.1,
        LogEntryRetentionPolicy::ConversationLoad
    ) {
        session.input_loaded_tokens += token_count;
    } else {
        session.input_tokens += token_count;
    }
    session.history.push(db::LogEntry {
        uuid: Uuid::now_v7().to_string(),
        message: chat::Message {
            role: chat::MessageRole::User,
            content: vec![chat::MessageContent::ImageUrl {
                image_url: chat::ImageData {
                    detail: "low".to_string(),
                    url: format!("data:image/png;base64,{}", &img_png_b64),
                },
            }],
            tool_calls: None,
            tool_call_id: None,
        },
        tokens: token_count,
        retention_policy,
    });
    token_count
}

// --

/// Attempts to activate the hai-router.
///
/// May not be possible due to the AI model. If so, it puts the hai-router into
/// a special state so that it will be activated if the model is switched to
/// one that is supported.
pub fn hai_router_try_activate(session: &mut SessionState) {
    session.use_hai_router = if config::is_ai_model_supported_by_hai_router(&session.ai) {
        HaiRouterState::On
    } else {
        HaiRouterState::OffForModel
    };
}

/// Uses `hai_router_try_activate` for special handling.
pub fn hai_router_set(session: &mut SessionState, on: bool) {
    if on {
        hai_router_try_activate(session);
    } else {
        session.use_hai_router = HaiRouterState::Off;
    }
}

// --

pub async fn account_login_setup_session(
    session: &mut SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
    user_id: &str,
    username: &str,
    token: &str,
) {
    db::login_account(&*db.lock().await, user_id, username, token)
        .expect("failed to write login info");
    session.account = Some(db::Account {
        user_id: user_id.to_string(),
        username: username.to_string(),
        token: token.to_string(),
    });
    match db::get_misc_entry(&*db.lock().await, username, "hai-router") {
        Ok(Some((hai_router_value, _))) => {
            hai_router_set(session, hai_router_value == "on");
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("failed to read db: {}", e);
        }
    }
}

pub async fn account_nobody_setup_session(
    session: &mut SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
) {
    if let Some(cur_account) = &session.account {
        db::switch_to_nobody_account(&*db.lock().await, &cur_account.username)
            .expect("failed to write login info");
        session.account = None;
        hai_router_set(session, false);
    }
}

// --

pub fn mk_api_client(session: Option<&SessionState>) -> HaiClient {
    let mut client = HaiClient::new(&get_api_base_url());
    if let Some(session) = session {
        if let Some(ref account) = session.account {
            client.set_token(&account.token);
        }
    }
    client
}

pub fn get_api_base_url() -> String {
    match env::var("HAI_BASE_URL") {
        Ok(value) => value,
        _ => "https://hai.superego.ai/1".to_string(),
    }
}

// --

/// Abridges history in three ways:
/// 1. Only includes User and Assistant messages.
/// 2. Truncates each message to the first 100 characters.
/// 3. Limits the total number of messages to 10.
pub fn get_abridged_history(history: &[db::LogEntry]) -> String {
    let mut result = String::new();
    let mut count = 0;

    for entry in history.iter().filter(|entry| {
        matches!(
            entry.message.role,
            chat::MessageRole::User | chat::MessageRole::Assistant
        )
    }) {
        if count >= 10 {
            break;
        }

        let message = &entry.message;

        let role_str = match message.role {
            chat::MessageRole::User => "User",
            chat::MessageRole::Assistant => "Assistant",
            // These roles are filtered out earlier
            _ => continue,
        };

        // Extract text content from the message
        let content_str = message
            .content
            .iter()
            .map(|content| match content {
                chat::MessageContent::Text { text } => text.clone(),
                chat::MessageContent::ImageUrl { .. } => "[Image]".to_string(),
            })
            .collect::<Vec<String>>()
            .join(" ");

        // Take the first 100 chars (or less if the message is shorter)
        let truncated_content = if content_str.len() > 100 {
            format!("{}...", &content_str[..100])
        } else {
            content_str
        };

        // Add delimiter if this isn't the first message
        if count > 0 {
            result.push_str("\n\n");
        }

        // Add the formatted message
        result.push_str(&format!("{}: {}", role_str, truncated_content));

        count += 1;
    }

    result
}
