use bstr::ByteSlice;
use chrono::{DateTime, Utc};
use colored::*;
use glob::glob;
use num_format::{Locale, ToFormattedString};
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::process::Command;
use tokio::sync::Mutex;
use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::api::client::RequestError;
use crate::session::{
    self, HaiRouterState, ReplMode, SessionState, hai_router_set, hai_router_try_activate,
    mk_api_client,
};
use crate::{
    api::{self, client::HaiClient},
    asset_async_writer,
    asset_cache::AssetBlobCache,
    asset_editor, asset_helper, asset_reader, asset_sync, chat, clipboard, cmd, cmd_registry,
    config, crypt, ctrlc_handler,
    db::{self, LogEntryRetentionPolicy},
    feature::{
        asset_crypt::{self, KeyRecipient},
        chat_store, haivar,
    },
    io::Io,
    io::Out,
    loader, term, term_color, tool,
};
use crate::{errorln, infoln, outln, outln_as, record_outln, successln, warnln};

pub struct ProcessCmdResult {
    pub next: ProcessCmdNext,
    pub discard_cmd_and_output: bool,
    pub retention_policy: LogEntryRetentionPolicy,
    pub history_entries: Vec<HistoryEntry>,
    /// New commands are added to the front of the cmd queue
    pub new_cmds: Vec<session::CmdInput>,
    pub new_temp_files: Vec<tempfile::NamedTempFile>,
    pub new_masked_strings: Vec<String>,
    pub purge_cmd_queue: bool,
    pub tool_mode_cmd: Option<Option<cmd::ToolModeCmd>>,
}

pub enum HistoryEntry {
    /// text
    UserText(String),
    /// (b64, hq, (w, h))
    UserImage(String, bool, (u32, u32)),
    /// (text, model)
    AssistantText(String, Option<config::AiModel>),
}

impl ProcessCmdResult {
    fn new(
        next: ProcessCmdNext,
        discard_cmd_and_output: bool,
        retention_policy: LogEntryRetentionPolicy,
        history_entries: Vec<HistoryEntry>,
        new_cmds: Vec<session::CmdInput>,
        new_temp_files: Vec<tempfile::NamedTempFile>,
        new_masked_strings: Vec<String>,
        purge_cmd_queue: bool,
        tool_mode_cmd: Option<Option<cmd::ToolModeCmd>>,
    ) -> Self {
        Self {
            next,
            discard_cmd_and_output,
            retention_policy,
            history_entries,
            new_cmds,
            new_temp_files,
            new_masked_strings,
            purge_cmd_queue,
            tool_mode_cmd,
        }
    }

    fn loop_next() -> Self {
        Self::new(
            ProcessCmdNext::Loop,
            false,
            LogEntryRetentionPolicy::None,
            vec![],
            vec![],
            vec![],
            vec![],
            false,
            None,
        )
    }

    fn break_next() -> Self {
        Self::new(
            ProcessCmdNext::Break,
            false,
            LogEntryRetentionPolicy::None,
            vec![],
            vec![],
            vec![],
            vec![],
            false,
            None,
        )
    }

    fn prompt_ai(prompt: String, cache: bool) -> Self {
        Self::new(
            ProcessCmdNext::PromptAi(prompt, cache),
            false,
            LogEntryRetentionPolicy::None,
            vec![],
            vec![],
            vec![],
            vec![],
            false,
            None,
        )
    }

    //
    // Builder methods
    //

    /// Mark the cmd and its output to be discarded.
    pub fn discard_cmd_and_output(mut self) -> Self {
        self.discard_cmd_and_output = true;
        self
    }

    /// Set the retention policy.
    pub fn with_retention_policy(mut self, policy: LogEntryRetentionPolicy) -> Self {
        self.retention_policy = policy;
        self
    }

    /// Replace the history entries.
    pub fn with_history_entries(mut self, history_entries: Vec<HistoryEntry>) -> Self {
        self.history_entries = history_entries;
        self
    }

    /// Replace the new commands (added to the front of the cmd queue).
    pub fn with_new_cmds(mut self, new_cmds: Vec<session::CmdInput>) -> Self {
        self.new_cmds = new_cmds;
        self
    }

    /// Replace the new temp files.
    pub fn with_new_temp_files(mut self, new_temp_files: Vec<tempfile::NamedTempFile>) -> Self {
        self.new_temp_files = new_temp_files;
        self
    }

    /// Replace new masked strings.
    pub fn with_new_masked_strings(mut self, new_masked_strings: Vec<String>) -> Self {
        self.new_masked_strings = new_masked_strings;
        self
    }

    pub fn with_purge_cmd_queue(mut self, purge_cmd_queue: bool) -> Self {
        self.purge_cmd_queue = purge_cmd_queue;
        self
    }

    pub fn with_tool_mode_cmd(mut self, tool_mode_cmd: Option<Option<cmd::ToolModeCmd>>) -> Self {
        self.tool_mode_cmd = tool_mode_cmd;
        self
    }
}

pub enum ProcessCmdNext {
    Loop,
    Break,
    /// (prompt, cache)
    PromptAi(String, bool),
}

const ASSET_ACCOUNT_REQ_MSG: &str =
    "You must be logged-in to use assets. Try /account-login or /account-new";

const BOT_ACCOUNT_REQ_MSG: &str = "You must be logged-in to use bots. Try /account-login";

#[allow(clippy::too_many_arguments)]
pub async fn process_cmd(
    io: &Io,
    config_path_override: &Option<String>,
    session: &mut SessionState,
    cfg: &mut config::Config,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    api_client: &HaiClient,
    cmd: &cmd::Cmd,
    cmd_input: &session::CmdInput,
    force_yes: bool,
    debug: bool,
) -> ProcessCmdResult {
    // Avoid using this except for caching
    let raw_user_input = cmd_input.input.as_str();

    let task_step_signature = cmd_input.source.get_task_step_signature();
    // Task steps only have a non-standard retention policy when they are
    // actioned as part of a process-wide task-mode.
    let is_task_mode_step =
        task_step_signature.is_some() && matches!(session.repl_mode, ReplMode::Task(..));
    let trusted = if let ReplMode::Task(_, _, trusted) = session.repl_mode {
        trusted && is_task_mode_step
    } else {
        false
    };

    // IMPORTANT: Because asset writes are committed asynchronously to make
    // the REPL more responsive, it's important to flush remaining writes
    // before processing follow up commands, otherwise, we lose read-after-
    // write consistency.
    asset_async_writer::flush_asset_updates(&update_asset_tx).await;

    match cmd.clone() {
        cmd::Cmd::Noop => ProcessCmdResult::loop_next().discard_cmd_and_output(),
        cmd::Cmd::Quit => {
            outln!(io, "さようなら！");
            // Don't want final message to be saved in history (the last
            // resort save in case conversation is resumed later)
            ProcessCmdResult::break_next().discard_cmd_and_output()
        }
        cmd::Cmd::Help(cmd::HelpCmd { history: _ }) => {
            let cmd_filter = cmd_registry::Filter::user();
            outln!(
                io,
                "{}\n\n- For quick answers, just ask the LLM.\n- `/forget` to unload help from conversation.\n- For more extensive help, use: `/task hai/help`",
                cmd_registry::render_help(&session.cmd_registry, &cmd_filter)
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Cd(cmd::CdCmd { path }) => {
            let path = if path.is_empty() { "~" } else { &path };
            let cd_target = shellexpand::full(path).unwrap().into_owned();
            if let Err(e) = env::set_current_dir(cd_target) {
                errorln!(io, "Failed to change directory: {}", e);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Ai(cmd::AiCmd { model }) => {
            if let Some(model_name) = model.as_deref() {
                if let Some(selected_ai_model) = config::ai_model_from_string(model_name) {
                    let ai_model_capability = config::get_ai_model_capability(&selected_ai_model);
                    if is_task_mode_step
                        && (matches!(session.use_hai_router, HaiRouterState::Off)
                            || !config::is_ai_model_supported_by_hai_router(&selected_ai_model))
                        && !config::check_api_key(&selected_ai_model, cfg)
                    {
                        warnln!(
                            io,
                            "Task may behave unexpectedly or fail without requested model",
                        );
                        return ProcessCmdResult::loop_next();
                    }
                    let mut ai_model_viable = true;
                    for msg in &session.history {
                        if !ai_model_capability.tool && msg.message.tool_call_id.is_some() {
                            errorln!(
                                io,
                                "Cannot switch because target model does not support tools. Clear conversation first: /new or /reset"
                            );
                            ai_model_viable = false;
                            break;
                        }
                        for content_part in &msg.message.content {
                            if ai_model_capability.image.is_none()
                                && matches!(content_part, chat::MessageContent::ImageUrl { .. })
                            {
                                errorln!(
                                    io,
                                    "Cannot switch because target model does not support images. Clear conversation first: /new or /reset"
                                );
                                ai_model_viable = false;
                                break;
                            }
                        }
                        if !ai_model_viable {
                            break;
                        }
                    }
                    if ai_model_viable {
                        if matches!(session.use_hai_router, HaiRouterState::On)
                            && !config::is_ai_model_supported_by_hai_router(&selected_ai_model)
                        {
                            warnln!(
                                io,
                                "Disabling hai-router because it does not support {}",
                                model_name
                            );
                            session.use_hai_router = HaiRouterState::OffForModel;
                        } else if matches!(session.use_hai_router, HaiRouterState::OffForModel)
                            && config::is_ai_model_supported_by_hai_router(&selected_ai_model)
                        {
                            infoln!(
                                io,
                                "Activating hai-router because {} is supported",
                                model_name
                            );
                            session.use_hai_router = HaiRouterState::On;
                        }
                        session.ai = selected_ai_model;
                    }
                } else {
                    errorln!(io, "Unknown model: {}", model_name);
                }
            }
            // For ollama, we print out the host information if it's set in the
            // user's config as it may be a source of confusion and errors.
            let host = if matches!(&session.ai, config::AiModel::Ollama(_)) {
                if let Some(ollama_base_url) = cfg
                    .ollama
                    .as_ref()
                    .and_then(|ollama| ollama.base_url.as_deref())
                {
                    format!(" ({})", ollama_base_url).to_owned()
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };
            outln!(
                io,
                "Using AI Model: {}{}",
                config::get_ai_model_display_name(&session.ai),
                host
            );
            if model.is_none() {
                let was_recording = io.record_off();
                outln!(io, "--");
                let need_openai_key = config::get_openai_api_key(cfg).is_none();
                let need_anthropic_key = config::get_anthropic_api_key(cfg).is_none();
                let need_deepseek_key = config::get_deepseek_api_key(cfg).is_none();
                let need_google_key = config::get_google_api_key(cfg).is_none();
                let need_xai_key = config::get_xai_api_key(cfg).is_none();
                let need_key = "  (NEED API KEY: /set-key OR /hai-router)";
                outln!(io, "Try these popular models:");
                outln!(
                    io,
                    "From OpenAI: gpt5, gpt5-mini, o4-mini, o3, openai/___{}",
                    if need_openai_key { need_key } else { "" }
                );
                outln!(
                    io,
                    "From Anthropic: sonnet, haiku, anthropic/___{}",
                    if need_anthropic_key { need_key } else { "" }
                );
                outln!(
                    io,
                    "From DeepSeek: deepseek, r1, deepseek/___{}",
                    if need_deepseek_key { need_key } else { "" }
                );
                outln!(
                    io,
                    "From Google: flash, google/___{}",
                    if need_google_key { need_key } else { "" }
                );
                outln!(
                    io,
                    "From xAI: grok-4, xai/___{}",
                    if need_xai_key { need_key } else { "" }
                );
                outln!(
                    io,
                    "Using Ollama: oss, gemma3, llama, llama-vision, ollama/___ (configure host in config)"
                );
                io.record_set(was_recording);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AiDefault(cmd::AiDefaultCmd { model }) => {
            if let Some(model_name) = model {
                config::insert_config_kv(
                    config_path_override,
                    None,
                    "default_ai_model",
                    &model_name,
                );
                cfg.reload(config_path_override)
                    .expect("Could not read config");
            }
            outln!(
                io,
                "Default AI Model: {}",
                cfg.default_ai_model.clone().unwrap_or("none".into())
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Clip => {
            if let Some(log_entry) = session.history.last() {
                if let Some(chat::MessageContent::Text { text }) = log_entry.message.content.last()
                {
                    clipboard::copy_to_clipboard(text);
                } else {
                    warnln!(io, "Entry type cannot be copied");
                }
            } else {
                warnln!(io, "No entry to copy");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::SetKey(cmd::SetKeyCmd { provider, key }) => {
            match provider.as_str() {
                "openai" | "anthropic" | "google" | "deepseek" | "xai" => {
                    config::insert_config_kv(
                        config_path_override,
                        Some(&provider),
                        "api_key",
                        &key,
                    );
                    cfg.reload(config_path_override)
                        .expect("Could not read config");
                }
                _ => {
                    errorln!(
                        io,
                        "unknown provider: {} (try openai, anthropic, google, deepseek, xai)",
                        provider
                    );
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::SetMaskSecrets(cmd::SetMaskSecretsCmd { on }) => {
            if let Some(on) = on {
                session.mask_secrets = on;
            } else {
                outln!(
                    io,
                    "Mask secrets: {}",
                    if session.mask_secrets { "on" } else { "off" }
                );
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::HaiRouter(cmd::HaiRouterCmd { on }) => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(
                    io,
                    "You must be logged-in to use hai-router. Try /account-login"
                );
                return ProcessCmdResult::loop_next();
            };
            if let Some(on) = on {
                hai_router_set(session, on);
                db::set_misc_entry(
                    &*db.lock().await,
                    &username,
                    "hai-router",
                    if matches!(session.use_hai_router, HaiRouterState::Off) {
                        "off"
                    } else {
                        "on"
                    },
                )
                .expect("failed to write to db");
            } else {
                outln!(
                    io,
                    "hai router: {}",
                    if matches!(session.use_hai_router, HaiRouterState::Off) {
                        "off"
                    } else if matches!(session.use_hai_router, HaiRouterState::OffForModel) {
                        "off (unsupported model)"
                    } else {
                        "on"
                    }
                );
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Agentic(cmd::AgenticCmd { on }) => {
            if let Some((on, use_prompt_cache)) = on {
                session.agentic = on;
                session.prompt_cache = use_prompt_cache;
            } else {
                outln!(
                    io,
                    "agentic mode: {}",
                    if session.agentic { "on" } else { "off" }
                );
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Temperature(cmd::TemperatureCmd { temperature }) => {
            if let Some(temperature) = temperature {
                session.ai_temperature = Some(temperature);
            } else if let Some(temperature) = session.ai_temperature {
                outln!(io, "AI Temperature: {}", temperature);
            } else {
                outln!(io, "AI Temperature: none (Using AI provider default)");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::New => {
            chat_store::save_chat_to_db(session, db).await;
            session.cmd_new().await;
            let was_recording = io.record_off();
            if let ReplMode::Task(ref task_fqn, ..) = session.repl_mode {
                outln!(io, "Task restarted: {}", task_fqn);
            } else {
                outln!(io, "New conversation begun");
            }
            io.record_set(was_recording);
            // Discard since /new doesn't make sense to add at the end of the
            // previous conversation nor at the start of the next.
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::Reset => {
            chat_store::save_chat_to_db(session, db).await;
            session.cmd_reset().await;
            let was_recording = io.record_off();
            if !session.history.is_empty() {
                if matches!(session.repl_mode, ReplMode::Task(..)) {
                    outln!(
                        io,
                        "Task restarted; /pin /asset-read /file-read /http-get retained"
                    );
                } else {
                    outln!(
                        io,
                        "New conversation begun with {} entries",
                        session.history.len()
                    );
                }
            } else {
                outln!(io, "Nothing was loaded or pinned. New conversation begun");
            }
            io.record_set(was_recording);
            // Discard since /reset doesn't make sense to add at the end of the
            // previous conversation nor at the start of the next.
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::PrintVars => {
            for (key, value) in &cfg.haivars {
                outln!(io, "{} = {}", key, value);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::ReprintHistory => {
            chat_store::reprint_conversation(io, &session.history).await;
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::Dump => {
            // Undocumented (for manual testing)
            let was_recording = io.record_off();
            for entry in &session.history {
                let role = entry.message.role.to_str();
                if entry.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
                    // Don't print entire files loaded as they flood the terminal.
                    if let chat::MessageContent::Text { text } = &entry.message.content[0] {
                        outln!(
                            io,
                            "{:<9}: {}",
                            role,
                            text.split_once("\n").unwrap_or((text, "")).0
                        );
                    } else if let chat::MessageContent::ImageUrl { image_url, .. } =
                        &entry.message.content[0]
                    {
                        outln!(io, "{:<9}: image: {}", role, &image_url.url[..10]);
                    }
                } else {
                    outln!(io, "{:<9}: {:?}", role, entry.message);
                }
            }
            io.record_set(was_recording);
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::DumpSession => {
            // Undocumented (for manual testing)
            let was_recording = io.record_off();
            outln!(io, "{:#?}", session);
            io.record_set(was_recording);
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::About => {
            outln!(
                io,
                r##"  _          ___
 | |         \_/
 | |___  ___  _
 |  _  |/ _ \/ |
 | | | | (_| | |
 \_| |_/\__,_|\|
"##
            );
            outln!(io, "hai (Hacker AI)");
            outln!(io, "Version: v{}", env!("CARGO_PKG_VERSION"));
            outln!(io);
            outln!(io, "Authored by Ken Elkabany @ken");
            outln!(io, "Send me an email: ken@elkabany.com");
            outln!(io);
            outln!(io, "Written to empower hackers everywhere");
            outln!(io, "- Wield the AI");
            outln!(io, "- Share knowledge");
            outln!(io, "- Emancipate data");
            outln!(io);
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::SetVar(cmd::SetVarCmd { key, value }) => {
            let key_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*$").unwrap();
            if key_regex.is_match(&key) {
                cfg.haivars.insert(key.to_owned(), value.to_owned());
            } else {
                errorln!(
                    io,
                    "Variable name '{}' is invalid: must start with a letter and only contain alphanumeric characters or underscores.",
                    key
                );
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Exec(cmd::ExecCmd {
            command,
            cache,
            interactive,
        }) => {
            let username = session
                .account
                .as_ref()
                .map(|account| account.username.clone());
            // Use an AtomicBool since it's lock-free and cannot
            // deadlock in the signal handler.
            let interrupted = Arc::new(AtomicBool::new(false));
            let shell_exec_handler_id = ctrlc_handler.add_handler({
                let interrupted = interrupted.clone();
                move || {
                    // Don't use `out` because of the risk of
                    // deadlock.
                    interrupted.store(true, Ordering::SeqCst);
                }
            });

            let (shell_exec_output, from_cache) =
                if let Some((ref task_fqn, ref task_key, step_index)) = task_step_signature {
                    let cached_output = if cache {
                        db::get_task_step_cache(
                            &*db.lock().await,
                            session
                                .account
                                .as_ref()
                                .map(|a| a.username.as_str())
                                .unwrap_or(""),
                            task_fqn,
                            task_key.as_deref(),
                            step_index,
                            raw_user_input,
                        )
                    } else {
                        None
                    };
                    if let Some(cached_output) = cached_output {
                        (Ok(cached_output), true)
                    } else {
                        // If we're initializing a task, it's critical that we ask the
                        // user for confirmation. Otherwise, a destructive command could
                        // be hidden in a task.
                        if !force_yes && !trusted {
                            outln!(io);
                            let answer = io
                                .query(&crate::io::Query::confirm("Execute above command? y/[n]:"))
                                .into_option()
                                .unwrap_or_default();
                            let answered_yes = answer.starts_with('y');
                            if !answered_yes {
                                outln!(io, "USER CANCELLED EXEC. TASK MAY MALFUNCTION.");
                                return ProcessCmdResult::loop_next();
                            }
                        }
                        (
                            shell_exec_with_asset_substitution(
                                io,
                                session,
                                asset_blob_cache.clone(),
                                update_asset_tx.clone(),
                                api_client,
                                username.as_deref(),
                                &command,
                                interactive,
                            )
                            .await,
                            false,
                        )
                    }
                } else {
                    (
                        shell_exec_with_asset_substitution(
                            io,
                            session,
                            asset_blob_cache.clone(),
                            update_asset_tx.clone(),
                            api_client,
                            username.as_deref(),
                            &command,
                            interactive,
                        )
                        .await,
                        false,
                    )
                };
            ctrlc_handler.remove_handler(shell_exec_handler_id);
            if interrupted.load(Ordering::SeqCst) {
                // ^C shows up in the terminal automatically, so just record
                // it.
                io.record_out("^C");
                outln!(io, "Shell Exec Interrupted");
            }
            let shell_exec_output = match shell_exec_output {
                Ok(output) => output,
                Err(e) => {
                    errorln!(io, "shell exec failed: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            if from_cache {
                if let Some((ref task_fqn, _, _)) = task_step_signature {
                    outln!(
                        io,
                        "[Retrieved from cache; `/task-forget {task_fqn}` to execute again]"
                    );
                }
                // Because it's from the cache, the value is not yet on the screen.
                outln!(io, "{}", shell_exec_output);
            } else if cache
                && let Some((ref task_fqn, ref task_key, step_index)) = task_step_signature
            {
                db::set_task_step_cache(
                    &*db.lock().await,
                    session
                        .account
                        .as_ref()
                        .map(|a| a.username.as_str())
                        .unwrap_or(""),
                    task_fqn,
                    task_key.as_deref(),
                    step_index,
                    raw_user_input,
                    &shell_exec_output,
                )
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AskHuman(cmd::AskHumanCmd {
            question,
            secret,
            cache,
        }) => {
            // Because there's cache handling, handle prompt records manually
            let prompt = crate::io::Query::line(question)
                .with_secret(secret)
                .with_record_message(false)
                .with_record_answer(false);
            let (answer, from_cache) = if cache {
                if let Some((ref task_fqn, ref task_key, step_index)) = task_step_signature {
                    db::get_task_step_cache(
                        &*db.lock().await,
                        session
                            .account
                            .as_ref()
                            .map(|a| a.username.as_str())
                            .unwrap_or(""),
                        task_fqn,
                        task_key.as_deref(),
                        step_index,
                        raw_user_input,
                    )
                    .map(|a| (Some(a), true))
                    .unwrap_or_else(|| (io.query(&prompt).into_option(), false))
                } else {
                    (io.query(&prompt).into_option(), false)
                }
            } else {
                (io.query(&prompt).into_option(), false)
            };
            let answer = if let Some(answer) = answer {
                answer
            } else {
                let purge_cmd_queue = if is_task_mode_step {
                    // If the user is initializing a task, but they ctrl+c the
                    // question, then abort the entire initialization. Assume
                    // they're uncomfortable with the task and don't want to
                    // proceed.
                    warnln!(io, "user cancelled input: task initialization aborted");
                    true
                } else {
                    false
                };
                return ProcessCmdResult::loop_next().with_purge_cmd_queue(purge_cmd_queue);
            };
            if from_cache {
                if let Some((ref task_fqn, _, _)) = task_step_signature {
                    let was_recording = io.record_off();
                    outln!(
                        io,
                        "[Retrieved from cache; `/task-forget {task_fqn}` to execute again]"
                    );
                    io.record_set(was_recording);
                }
                // Because it's from the cache, the value is not yet on the screen.
                if answer.is_empty() {
                    outln_as!(io, "*You left this blank*", "");
                } else if secret {
                    let mask: String = "*".repeat(answer.len());
                    outln_as!(io, mask, secret);
                } else {
                    outln!(io, "{}", answer);
                }
            } else if cache
                && let Some((ref task_fqn, ref task_key, step_index)) = task_step_signature
            {
                db::set_task_step_cache(
                    &*db.lock().await,
                    session
                        .account
                        .as_ref()
                        .map(|a| a.username.as_str())
                        .unwrap_or(""),
                    task_fqn,
                    task_key.as_deref(),
                    step_index,
                    raw_user_input,
                    &answer,
                )
            }
            let masked_string = if secret {
                // Since it was written as a secret, we assume it shouldn't be
                // printed on the screen.
                vec![answer.clone()]
            } else {
                vec![]
            };
            ProcessCmdResult::loop_next()
                .with_history_entries(vec![HistoryEntry::UserText(answer)])
                .with_new_masked_strings(masked_string)
        }
        cmd::Cmd::Prep(cmd::PrepCmd { .. }) | cmd::Cmd::Pin(cmd::PinCmd { .. }) => {
            let retention_policy = if matches!(cmd, cmd::Cmd::Pin(_)) {
                db::LogEntryRetentionPolicy::ConversationPin
            } else {
                db::LogEntryRetentionPolicy::None
            };
            // No UserText(message) is necessary since prep/pin input command
            // contains the full message.
            ProcessCmdResult::loop_next().with_retention_policy(retention_policy)
        }
        cmd::Cmd::Assistant(cmd::AssistantCmd { message }) => {
            let retention_policy = if matches!(cmd, cmd::Cmd::Pin(_)) {
                db::LogEntryRetentionPolicy::ConversationPin
            } else {
                db::LogEntryRetentionPolicy::None
            };
            ProcessCmdResult::loop_next()
                .discard_cmd_and_output()
                .with_retention_policy(retention_policy)
                .with_history_entries(vec![HistoryEntry::AssistantText(message, None)])
        }
        cmd::Cmd::SystemPrompt(cmd::SystemPromptCmd { prompt }) => {
            // NOTE: While it might be nice to have a cindexonfig option to set a
            // system-prompt, it would have a different behavior than currently
            // exists with /new, /reset, and /task-end for other message types.
            // To avoid this complexity, the recommendation is to define
            // system-prompts in tasks.
            if prompt.is_none() {
                if let Some(db::LogEntry {
                    message:
                        chat::Message {
                            role: chat::MessageRole::System,
                            content,
                            ..
                        },
                    ..
                }) = session.history.first()
                {
                    outln!(io, "The system prompt is:");
                    for msg in content {
                        if let chat::MessageContent::Text { text } = msg {
                            outln!(io, "{}", text);
                        }
                    }
                } else {
                    outln!(io, "There is no system prompt");
                }
                return ProcessCmdResult::loop_next();
            }
            // Remove existing system prompt (if exists)
            if let Some(db::LogEntry {
                message:
                    chat::Message {
                        role: chat::MessageRole::System,
                        ..
                    },
                tokens,
                ..
            }) = session.history.first()
            {
                session.input_tokens -= tokens;
                session.history.remove(0);
            }
            let prompt = prompt.as_ref().unwrap();
            let system_prompt_tokens = bpe_tokenizer.encode_with_special_tokens(prompt);
            let tokens = system_prompt_tokens.len() as u32;
            session.input_tokens += tokens;
            session.history.insert(
                0,
                db::LogEntry {
                    uuid: Uuid::now_v7().to_string(),
                    ts: chrono::Local::now(),
                    message: chat::Message {
                        role: chat::MessageRole::System,
                        content: vec![chat::MessageContent::Text {
                            text: prompt.to_owned(),
                        }],
                        tool_calls: None,
                        tool_call_id: None,
                    },
                    tokens,
                    // Treat like a /pin. /new clears it unless in task-mode.
                    retention_policy: (
                        is_task_mode_step,
                        db::LogEntryRetentionPolicy::ConversationPin,
                    ),
                    model: None,
                },
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Forget(cmd::ForgetCmd { mut n }) => {
            fn prepare_preview(preview: String, max_length: usize) -> String {
                let s = preview.replace("\n", " ");
                if s.chars().count() > max_length {
                    let truncated: String = s.trim().chars().take(max_length - 3).collect();
                    format!("{}...", truncated)
                } else {
                    s.to_string()
                }
            }
            while n > 0 && !session.history.is_empty() {
                if session.history.last().is_none() {
                    break;
                }
                let log_entry = match session.history.pop() {
                    Some(log_entry) => log_entry,
                    None => break,
                };
                let role_name = log_entry.message.role.to_str();
                let preview = log_entry.mk_preview_string();
                outln!(
                    io,
                    "Forgot {role_name} message: {}",
                    prepare_preview(preview, 80)
                );
                if matches!(log_entry.message.role, chat::MessageRole::User) {
                    n -= 1;
                }
            }
            session.recalculate_input_tokens();
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::Keep(cmd::KeepCmd { mut bottom, top }) => {
            fn prepare_preview(preview: String, max_length: usize) -> String {
                let s = preview.replace("\n", " ");
                if s.chars().count() > max_length {
                    let truncated: String = s.trim().chars().take(max_length - 3).collect();
                    format!("{}...", truncated)
                } else {
                    s.to_string()
                }
            }

            let mut kept_history = vec![];

            let mut top = top.unwrap_or(0) as i32;
            while !session.history.is_empty() {
                let log_entry = match session.history.first() {
                    Some(log_entry) => log_entry,
                    None => break,
                };
                if matches!(log_entry.message.role, chat::MessageRole::User) {
                    // Because the decrement happens only after user messages,
                    // it allows the system message and all assistance/tool
                    // messages that follow a user-message to be included.
                    top -= 1;
                    if top < 0 {
                        break;
                    }
                }
                let log_entry = session.history.remove(0);
                kept_history.push(log_entry.clone());
            }

            let mut kept_bottom_history = vec![];

            while bottom > 0 && !session.history.is_empty() {
                if session.history.last().is_none() {
                    break;
                }
                let log_entry = match session.history.pop() {
                    Some(log_entry) => log_entry,
                    None => break,
                };
                kept_bottom_history.push(log_entry.clone());
                if matches!(log_entry.message.role, chat::MessageRole::User) {
                    bottom -= 1;
                }
            }
            kept_bottom_history.reverse();
            kept_history.extend(kept_bottom_history);
            for log_entry in &kept_history {
                let role_name = log_entry.message.role.to_str();
                let preview = log_entry.mk_preview_string();
                outln!(
                    io,
                    "Keep {role_name} message: {}",
                    prepare_preview(preview, 80)
                );
            }
            session.history = kept_history;
            session.recalculate_input_tokens();

            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::FileRead(cmd::FileReadCmd {
            paths,
            show_line_numbers,
            image_hq,
        })
        | cmd::Cmd::FileCat(cmd::FileCatCmd {
            paths,
            show_line_numbers,
            image_hq,
        }) => {
            let mut history_entries = vec![];
            let mut newly_loaded_tokens = 0;
            for path in &paths {
                let raw_load_target = path;
                let load_target_deref =
                    haivar::replace_haivars(&io.out, &raw_load_target, &cfg.haivars);
                let load_target = match shellexpand::full(&load_target_deref) {
                    Ok(s) => s.into_owned(),
                    Err(e) => {
                        errorln!(io, "undefined path variable: {}", e.var_name);
                        continue;
                    }
                };
                // Iterate through paths and collect matching files
                let glob_res = glob(&load_target);
                if glob_res.is_err() {
                    errorln!(io, "bad glob: {:?}", glob_res.unwrap_err());
                    continue;
                }
                let glob_paths = glob_res.unwrap();
                let files: Result<Vec<_>, _> = glob_paths.collect();
                match files {
                    Ok(files) if files.is_empty() => {
                        errorln!(io, "no files matched: {}", load_target);
                        continue;
                    }
                    Ok(files) => {
                        for file_path in files {
                            let file_res = fs::File::open(&file_path);
                            if file_res.is_err() {
                                errorln!(
                                    io,
                                    "could not open file: {:?}: {:?}",
                                    file_path,
                                    file_res.unwrap_err()
                                );
                                continue;
                            }
                            let mut file = file_res.unwrap();
                            // Read the file contents into a buffer
                            let mut buffer = Vec::new();
                            if let Err(e) = file.read_to_end(&mut buffer) {
                                errorln!(io, "could not read file: {:?}: {:?}", file_path, e)
                            }
                            if let Ok(file_contents) = std::str::from_utf8(&buffer) {
                                let file_contents_with_delimeters = add_content_delimiters(
                                    "FILE",
                                    file_contents,
                                    &file_path.to_string_lossy(),
                                    None,
                                    show_line_numbers,
                                );
                                let token_count = bpe_tokenizer
                                    .encode_with_special_tokens(&file_contents_with_delimeters)
                                    .len() as u32;

                                let was_recording = io.record_off();
                                if matches!(cmd, cmd::Cmd::FileCat(_)) {
                                    outln!(io, "{}", file_contents);
                                } else {
                                    outln!(
                                        io,
                                        "Loaded: {} ({} tokens)",
                                        &file_path.to_string_lossy(),
                                        token_count.to_formatted_string(&Locale::en)
                                    );
                                }
                                io.record_set(was_recording);
                                history_entries
                                    .push(HistoryEntry::UserText(file_contents_with_delimeters));
                                newly_loaded_tokens += token_count;
                            } else {
                                let image_capability =
                                    config::get_ai_model_capability(&session.ai).image;
                                let use_thumbnail = image_capability
                                    .as_ref()
                                    .map(|cap| !image_hq && !cap.auto_resize)
                                    .unwrap_or(false);

                                // Not a text file, try opening as image
                                match loader::resolve_image_b64(
                                    &file_path.to_string_lossy().into_owned(),
                                    use_thumbnail,
                                )
                                .await
                                {
                                    Ok((img_png_b64, img_dim)) => {
                                        if image_capability.is_none() {
                                            errorln!(io, "model does not support images");
                                            return ProcessCmdResult::loop_next();
                                        }
                                        let token_count = session::calc_image_tokens(
                                            &session.ai,
                                            image_hq,
                                            img_dim,
                                        );
                                        newly_loaded_tokens += token_count;
                                        history_entries.push(HistoryEntry::UserImage(
                                            img_png_b64.clone(),
                                            image_hq,
                                            img_dim,
                                        ));
                                        let was_recording = io.record_off();
                                        if matches!(cmd, cmd::Cmd::FileCat(_)) {
                                            io.display("image/png", &img_png_b64);
                                        } else {
                                            outln!(
                                                io,
                                                "Loaded: {} ({} tokens)",
                                                &file_path.to_string_lossy(),
                                                token_count.to_formatted_string(&Locale::en)
                                            );
                                        }
                                        io.record_set(was_recording);
                                    }
                                    Err(e) => {
                                        errorln!(
                                            io,
                                            "failed to load as text or image: {:?}: {:?}",
                                            file_path,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => errorln!(io, "{:?}", e),
                }
            }
            if !matches!(cmd, cmd::Cmd::FileCat(_)) {
                let was_recording = io.record_off();
                outln!(
                    io,
                    "Total tokens loaded: {}",
                    newly_loaded_tokens.to_formatted_string(&Locale::en)
                );
                io.record_set(was_recording);
            }
            if history_entries.is_empty() {
                ProcessCmdResult::loop_next()
            } else {
                ProcessCmdResult::loop_next()
                    .with_retention_policy(LogEntryRetentionPolicy::ConversationLoad)
                    .with_history_entries(history_entries)
            }
        }
        cmd::Cmd::FileWrite(cmd::FileWriteCmd { path, contents }) => {
            let write_target_deref = haivar::replace_haivars(&io.out, &path, &cfg.haivars);
            let write_target = match shellexpand::full(&write_target_deref) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            match fs::write(&write_target, contents.clone().unwrap_or("".to_string())) {
                Ok(_) => {}
                Err(e) => {
                    errorln!(io, "could not write to file: {:?}: {:?}", write_target, e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::FilePatch(cmd::FilePatchCmd {
            path,
            search,
            replace,
        }) => {
            let patch_target_deref = haivar::replace_haivars(&io.out, &path, &cfg.haivars);
            let patch_target = match shellexpand::full(&patch_target_deref) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            match fs::File::open(&patch_target) {
                Ok(mut file) => {
                    // Read the file contents into a buffer
                    let mut buffer = Vec::new();
                    match file.read_to_end(&mut buffer) {
                        Ok(_) => match std::str::from_utf8(&buffer) {
                            Ok(file_contents) => {
                                match search_and_replace(&file_contents, &search, &replace, 10) {
                                    ReplaceResult::Success(new_contents) => {
                                        match fs::write(&patch_target, new_contents) {
                                            Ok(_) => {}
                                            Err(e) => {
                                                errorln!(
                                                    io,
                                                    "could not write to file: {:?}: {:?}",
                                                    patch_target,
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    ReplaceResult::NoMatch => {
                                        errorln!(io, "no matches found");
                                    }
                                    ReplaceResult::MultipleMatches(expanded_matches) => {
                                        let mut msg = format!(
                                            "search string isn't unique (found {} matches)",
                                            expanded_matches.len()
                                        );
                                        for expanded_match in expanded_matches {
                                            msg.push_str("<<<<<<< START EXPANDED MATCH\n");
                                            msg.push_str(&expanded_match);
                                            msg.push_str("\n>>>>>>> END EXPANDED MATCH\n");
                                        }
                                        errorln!(io, "{}", msg);
                                    }
                                }
                            }
                            Err(e) => {
                                errorln!(io, "file is not valid utf-8: {:?}: {}", patch_target, e);
                            }
                        },
                        Err(e) => {
                            errorln!(io, "could not read file: {:?}: {}", patch_target, e);
                        }
                    }
                }
                Err(e) => {
                    errorln!(io, "could not open file: {:?}: {}", patch_target, e);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::HttpGet(cmd::HttpGetCmd {
            url,
            raw,
            show_line_numbers,
            image_hq,
        }) => {
            let http_response = match reqwest::Client::new()
                .get(&url)
                .header("User-Agent", &format!("hai/{}", env!("CARGO_PKG_VERSION")))
                .send()
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    errorln!(io, "failed to load-url: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            let content_type = http_response
                .headers()
                .get("Content-Type")
                .and_then(|value| value.to_str().ok())
                .map(|s| s.to_string());
            let is_html_content_type = content_type
                .as_ref()
                .map(|ct| {
                    ct.trim_start()
                        .to_ascii_lowercase()
                        .starts_with("text/html")
                })
                .unwrap_or(false);
            let mut history_entries = vec![];
            match content_type.as_deref() {
                Some("image/jpeg") | Some("image/png") => {
                    let Some(image_capability) = config::get_ai_model_capability(&session.ai).image
                    else {
                        errorln!(io, "model does not support images");
                        return ProcessCmdResult::loop_next();
                    };
                    let img_bytes = if let Ok(img_bytes) = http_response.bytes().await {
                        img_bytes
                    } else {
                        errorln!(io, "failed to get image from url");
                        return ProcessCmdResult::loop_next();
                    };
                    let use_thumbnail = !image_hq && !image_capability.auto_resize;
                    let (img_png_b64, img_dim) = if let Ok(encode_res) =
                        loader::encode_image_bytes_to_png_base64(img_bytes, use_thumbnail)
                    {
                        encode_res
                    } else {
                        errorln!(io, "failed to encode image as png-base64");
                        return ProcessCmdResult::loop_next();
                    };

                    let token_count = session::calc_image_tokens(&session.ai, image_hq, img_dim);
                    history_entries.push(HistoryEntry::UserImage(
                        img_png_b64.clone(),
                        image_hq,
                        img_dim,
                    ));
                    let was_recording = io.record_off();
                    io.display("image/png", &img_png_b64);
                    outln!(
                        io,
                        "Loaded: {} ({} tokens)",
                        url,
                        token_count.to_formatted_string(&Locale::en)
                    );
                    io.record_set(was_recording);
                }
                _ => {
                    let url_body = match http_response.text().await {
                        Ok(body) => body,
                        Err(e) => {
                            errorln!(io, "failed to parse url: {}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    };

                    let (contents, format, title) = if !raw && is_html_content_type {
                        let cfg = dom_smoothie::Config {
                            max_elements_to_parse: 9000,
                            ..Default::default()
                        };
                        let mut readability = dom_smoothie::Readability::new(
                            url_body.clone(),
                            Some(url.as_str()),
                            Some(cfg),
                        )
                        .expect("failed to create readability obj");

                        match readability.parse() {
                            Ok(extracted_article) => {
                                let title = if !extracted_article.title.is_empty() {
                                    Some(
                                        htmd::convert(&extracted_article.title)
                                            .unwrap_or(extracted_article.title),
                                    )
                                } else {
                                    None
                                };
                                match htmd::convert(&extracted_article.content) {
                                    Ok(md) => (md, "markdown".to_string(), title),
                                    Err(_e) => (
                                        extracted_article.content.to_string(),
                                        "html-extracted".to_string(),
                                        title,
                                    ),
                                }
                            }
                            Err(_e) => (
                                url_body,
                                content_type.unwrap_or("html-failed-extract".to_string()),
                                None,
                            ),
                        }
                    } else {
                        (url_body, content_type.unwrap_or("raw".to_string()), None)
                    };

                    let url_contents_with_delimiters = format!(
                        "{}\n<<<<<< BEGIN_URL: {}{} >>>>>>\n{}\n<<<<<< END_URL: {} >>>>>>",
                        raw_user_input,
                        url,
                        if show_line_numbers {
                            " (with line numbers)"
                        } else {
                            ""
                        },
                        if show_line_numbers {
                            add_line_numbers(&contents)
                        } else {
                            contents
                        },
                        url,
                    );

                    let token_count = bpe_tokenizer
                        .encode_with_special_tokens(&url_contents_with_delimiters)
                        .len() as u32;

                    let was_recording = io.record_off();
                    outln!(
                        io,
                        "Loaded ({}): {} ({} tokens)",
                        format,
                        title.unwrap_or(url.clone()),
                        token_count.to_formatted_string(&Locale::en)
                    );
                    io.record_set(was_recording);

                    history_entries
                        .push(HistoryEntry::UserText(url_contents_with_delimiters.clone()));
                }
            }
            ProcessCmdResult::loop_next()
                .with_retention_policy(LogEntryRetentionPolicy::ConversationLoad)
                .with_history_entries(history_entries)
        }
        cmd::Cmd::Task(cmd::TaskCmd {
            task_ref,
            key,
            trust,
        }) => {
            if is_task_mode_step {
                errorln!(io, "cannot use /task within task steps: try /task-include");
                return ProcessCmdResult::loop_next();
            }
            let mut new_cmds = vec![];
            if matches!(session.repl_mode, ReplMode::Task(..)) {
                // If already in task mode, clear the existing session state and start fresh.
                new_cmds.extend(vec![
                    session::CmdInput {
                        input: "/task-end".to_string(),
                        source: session::CmdSource::Internal,
                        reply_channel: None,
                    },
                    session::CmdInput {
                        input: cmd_input.input.clone(),
                        source: session::CmdSource::Internal,
                        reply_channel: None,
                    },
                ]);
            } else if let Some((_, haitask)) = get_haitask_from_task_ref(
                io,
                &task_ref,
                session,
                "task",
                matches!(cmd_input.source, session::CmdSource::Internal),
            )
            .await
            {
                if let Some(dependencies) = haitask.dependencies.as_ref() {
                    let dependency_re = Regex::new(
                        r"^\s*([a-zA-Z0-9_\-]+)\s*(>=|<=|=|>|<)\s*([0-9A-Za-z\.\-\+]+)\s*$",
                    )
                    .unwrap();
                    for dependency in dependencies {
                        if let Some(caps) = dependency_re.captures(dependency) {
                            let task_dependency_name = &caps[1];
                            let comparison_op = &caps[2];
                            let task_dependency_version = &caps[3];
                            let task_dependency_semver = if let Ok(task_dependency_semver) =
                                semver::Version::parse(task_dependency_version)
                            {
                                task_dependency_semver
                            } else {
                                errorln!(io, "failed to parse semver: {}", task_dependency_version);
                                return ProcessCmdResult::loop_next();
                            };
                            let local_dependency_version = if task_dependency_name == "hai" {
                                semver::Version::parse(env!("CARGO_PKG_VERSION"))
                                    .expect("unexpected unparse-able version")
                            } else {
                                errorln!(io, "unknown dependency: {}", task_dependency_name);
                                return ProcessCmdResult::loop_next();
                            };

                            if comparison_op == ">=" {
                                if local_dependency_version < task_dependency_semver {
                                    errorln!(
                                        io,
                                        "task '{}' requires {} >= {}, but you have {}",
                                        haitask.name,
                                        task_dependency_name,
                                        task_dependency_version,
                                        local_dependency_version
                                    );
                                    return ProcessCmdResult::loop_next();
                                }
                            } else if comparison_op == "<=" {
                                if local_dependency_version > task_dependency_semver {
                                    errorln!(
                                        io,
                                        "task '{}' requires {} <= {}, but you have {}",
                                        haitask.name,
                                        task_dependency_name,
                                        task_dependency_version,
                                        local_dependency_version
                                    );
                                    return ProcessCmdResult::loop_next();
                                }
                            } else if comparison_op == "=" {
                                if local_dependency_version != task_dependency_semver {
                                    errorln!(
                                        io,
                                        "task '{}' requires {} = {}, but you have {}",
                                        haitask.name,
                                        task_dependency_name,
                                        task_dependency_version,
                                        local_dependency_version
                                    );
                                    return ProcessCmdResult::loop_next();
                                }
                            } else if comparison_op == ">" {
                                if local_dependency_version <= task_dependency_semver {
                                    errorln!(
                                        io,
                                        "task '{}' requires {} > {}, but you have {}",
                                        haitask.name,
                                        task_dependency_name,
                                        task_dependency_version,
                                        local_dependency_version
                                    );
                                    return ProcessCmdResult::loop_next();
                                }
                            } else if comparison_op == "<" {
                                if local_dependency_version >= task_dependency_semver {
                                    errorln!(
                                        io,
                                        "task '{}' requires {} < {}, but you have {}",
                                        haitask.name,
                                        task_dependency_name,
                                        task_dependency_version,
                                        local_dependency_version
                                    );
                                    return ProcessCmdResult::loop_next();
                                }
                            } else {
                                errorln!(io, "unknown comparison operator: {}", comparison_op);
                                return ProcessCmdResult::loop_next();
                            }
                        } else {
                            errorln!(io, "malformed dependency: {}", dependency);
                            return ProcessCmdResult::loop_next();
                        }
                    }
                }
                let window_title = format!(
                    "{}{}",
                    haitask.name,
                    if let Some(key) = key.as_deref() {
                        format!(" ({key})")
                    } else {
                        "".to_string()
                    }
                );
                term::window_title_set(&window_title);
                outln!(io);
                let was_recording = io.record_off();
                // Using println! instead of outln! here so that colored output
                // isn't sent to the backend.
                if io.is_terminal() {
                    println!(
                        "{} {}",
                        " TASK MODE ENABLED ".black().on_white(),
                        haitask.name
                    );
                } else {
                    outln!(io, "TASK MODE ENABLED: {}", haitask.name);
                }
                outln!(io, "  - /new -- restarts the task");
                outln!(
                    io,
                    "  - /reset -- restarts the task while retaining /pin /asset-read /file-read /http-get"
                );
                outln!(
                    io,
                    "  - /task-forget {} -- forgets cached/memorized answers",
                    task_ref
                );
                outln!(io, "  - /task-end -- Exit task mode (CTRL+D shortcut)");
                outln!(io);
                io.record_set(was_recording);
                for (index, step) in haitask.steps.into_iter().enumerate() {
                    new_cmds.push(session::CmdInput {
                        input: step.clone(),
                        source: session::CmdSource::TaskStep(
                            haitask.name.clone(),
                            key.clone(),
                            index as u32,
                        ),
                        reply_channel: None,
                    });
                }
                session.repl_mode = ReplMode::Task(haitask.name.clone(), key.clone(), trust);
            }
            ProcessCmdResult::loop_next().with_new_cmds(new_cmds)
        }
        cmd::Cmd::TaskInclude(cmd::TaskIncludeCmd { task_ref, key }) => {
            if let Some((_, haitask)) = get_haitask_from_task_ref(
                io,
                &task_ref,
                session,
                "task-include",
                matches!(cmd_input.source, session::CmdSource::Internal),
            )
            .await
            {
                let mut new_cmds = vec![];
                for (index, step) in haitask.steps.into_iter().enumerate() {
                    new_cmds.push(session::CmdInput {
                        input: step.clone(),
                        source: session::CmdSource::TaskStep(
                            haitask.name.clone(),
                            key.clone(),
                            index as u32,
                        ),
                        reply_channel: None,
                    });
                }
                ProcessCmdResult::loop_next().with_new_cmds(new_cmds)
            } else {
                ProcessCmdResult::loop_next()
            }
        }
        cmd::Cmd::TaskFetch(cmd::TaskFetchCmd { task_fqn }) => {
            if config::is_valid_task_fqn(&task_fqn).is_none() {
                errorln!(
                    io,
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::loop_next();
            };
            use api::types::task::TaskGetArg;
            match api_client
                .task_get(TaskGetArg {
                    task_fqn: task_fqn.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    outln!(io, "Fetched {}@{}", res.task_fqn, res.task_version);
                    if let Err(e) = config::parse_haitask_config(&res.config) {
                        errorln!(io, "failed to parse haitask config: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                    if let Err(e) = config::write_task_to_cache_path(&res.task_fqn, &res.config) {
                        errorln!(io, "failed to write haitask config: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                }
                Err(e) => {
                    errorln!(io, "error: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskEnd => {
            // Does not clear the conversation history because the user may
            // have accidentally entered task mode and we don't want to lose
            // their history when they exit. This makes accidentally using
            // /task instead of /task-include an inconvenience rather than
            // fatal.
            if session.cmd_task_end().await {
                infoln!(io, "task ended");
            } else {
                errorln!(io, "not in task mode");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskPublish(cmd::TaskPublishCmd { task_path }) => {
            let account = if let Some(ref account) = session.account {
                account
            } else {
                errorln!(
                    io,
                    "You must be logged-in to publish. Try /account-login or /account-new"
                );
                return ProcessCmdResult::loop_next();
            };
            let task_novar_path = haivar::replace_haivars(&io.out, &task_path, &cfg.haivars);
            let task_full_path = match shellexpand::full(&task_novar_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            let (haitask_contents, haitask) = match config::read_haitask(&task_full_path) {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to load task: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            if !haitask.name.starts_with(&(account.username.clone() + "/")) {
                errorln!(
                    io,
                    "task name must be prefixed with your account username: {}/",
                    account.username
                );
                return ProcessCmdResult::loop_next();
            }

            use api::types::task::TaskPutArg;
            match api_client
                .task_put(TaskPutArg {
                    task_fqn: haitask.name.clone(),
                    config: haitask_contents,
                })
                .await
            {
                Ok(_) => {
                    successln!(
                        io,
                        "{}@{} added to repository.",
                        haitask.name,
                        haitask.version
                    );
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskEdit(cmd::TaskEditCmd { task_fqn }) => {
            let account = if let Some(ref account) = session.account {
                account
            } else {
                errorln!(
                    io,
                    "You must be logged-in to edit a task. Try /account-login or /account-new"
                );
                return ProcessCmdResult::loop_next();
            };
            if config::is_valid_task_fqn(&task_fqn).is_none() {
                errorln!(
                    io,
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::loop_next();
            };

            let (username, task_name) = task_fqn
                .split_once('/')
                .expect("unexpected task fqn format");
            if username != account.username {
                errorln!(io, "you can only edit tasks under your own account");
                return ProcessCmdResult::loop_next();
            }

            let temp_file = match tempfile::Builder::new()
                .prefix(&format!("{}_{}_", account.username, task_name))
                .suffix(".toml")
                .tempfile()
            {
                Ok(temp_file) => temp_file,
                Err(e) => {
                    errorln!(io, "Failed to create temporary file: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            let temp_file_path = temp_file.path().to_string_lossy().into_owned();

            use api::types::task::TaskGetArg;
            match api_client
                .task_get(TaskGetArg {
                    task_fqn: task_fqn.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    fs::write(&temp_file_path, res.config).unwrap_or_else(|e| {
                        errorln!(io, "Failed to write to temporary file: {}", e);
                    });
                    outln!(
                        io,
                        "Task available for editing at: {}\nWhen finished, publish your changes with: /task-publish {}",
                        temp_file_path,
                        temp_file_path
                    );
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next().with_new_temp_files(vec![temp_file])
        }
        cmd::Cmd::TaskForget(cmd::TaskForgetCmd { task_ref, key }) => {
            let task_name = if config::is_valid_task_fqn(&task_ref).is_some() {
                task_ref.clone()
            } else if task_ref.starts_with(".")
                || task_ref.starts_with("/")
                || task_ref.starts_with("~")
            {
                let task_path = match shellexpand::full(&task_ref) {
                    Ok(s) => s.into_owned(),
                    Err(e) => {
                        errorln!(io, "undefined path variable: {}", e.var_name);
                        return ProcessCmdResult::loop_next();
                    }
                };
                match config::read_haitask(&task_path) {
                    Ok((_, task)) => task.name,
                    Err(e) => {
                        errorln!(io, "failed to read task: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                }
            } else {
                errorln!(io, "unknown task: {}", task_ref);
                return ProcessCmdResult::loop_next();
            };
            db::forget_task_step_cache(
                &*db.lock().await,
                session
                    .account
                    .as_ref()
                    .map(|account| account.username.as_str())
                    .unwrap_or(""),
                &task_name,
                key.as_deref(),
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskPurge(cmd::TaskPurgeCmd { task_fqn }) => {
            if config::is_valid_task_fqn(&task_fqn).is_none() {
                errorln!(
                    io,
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::loop_next();
            };
            db::purge_task_step_cache(&*db.lock().await, &task_fqn);
            match config::purge_cached_task(&task_fqn) {
                Ok(_) => {
                    successln!(io, "{} purged", task_fqn);
                }
                Err(e) => {
                    errorln!(io, "error: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskSearch(cmd::TaskSearchCmd { q }) => {
            fn prepare_description(description: Option<String>, max_length: usize) -> String {
                let s = description.unwrap_or("".to_string()).replace("\n", " ");
                if s.chars().count() > max_length {
                    let truncated: String = s.chars().take(max_length - 3).collect();
                    format!("{}...", truncated)
                } else {
                    s.to_string()
                }
            }

            use api::types::task::TaskSearchArg;
            match api_client
                .task_search(TaskSearchArg { q: q.to_owned() })
                .await
            {
                Ok(res) => {
                    let terminal_width = crossterm::terminal::size()
                        // If the terminal width is less than 80, just treat it as
                        // 80 so that we don't try too hard to shrink the contents.
                        .map(|size| size.0.max(80) as usize)
                        // If this isn't being run in a terminal, be more generous
                        // with the width.
                        .unwrap_or(120);
                    let mut semantic_lines = vec![];
                    for semantic_match in res.semantic_matches {
                        semantic_lines.push((
                            format!(
                                "{} ({}) ({} dls)",
                                semantic_match.task_fqn,
                                semantic_match.task_version,
                                abbreviate_number(semantic_match.downloads),
                            ),
                            semantic_match,
                        ));
                    }
                    let mut syntactic_lines = vec![];
                    for syntactic_match in res.syntactic_matches {
                        syntactic_lines.push((
                            format!(
                                "{} ({}) ({} dls)",
                                syntactic_match.task_fqn,
                                syntactic_match.task_version,
                                abbreviate_number(syntactic_match.downloads),
                            ),
                            syntactic_match,
                        ));
                    }

                    let max_name_width = semantic_lines
                        .iter()
                        .chain(syntactic_lines.iter())
                        .map(|(s, _)| s.len())
                        .max()
                        .unwrap_or(0);

                    // -6 is for the padding and "# "
                    let width_for_description = terminal_width - max_name_width - 6;

                    outln!(io, "=== Semantic Matches ===");
                    for (semantic_line, semantic_match) in semantic_lines {
                        outln!(
                            io,
                            "{:width$}    # {}",
                            semantic_line,
                            prepare_description(semantic_match.description, width_for_description),
                            width = max_name_width,
                        );
                    }
                    outln!(io, "");
                    outln!(io, "=== Syntactic Matches === ");
                    for (syntactic_line, syntactic_match) in syntactic_lines {
                        outln!(
                            io,
                            "{:width$}    # {}",
                            syntactic_line,
                            prepare_description(syntactic_match.description, width_for_description),
                            width = max_name_width,
                        );
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskCat(cmd::TaskCatCmd { task_ref }) => {
            if let Some((config, haitask)) = get_haitask_from_task_ref(
                io,
                &task_ref,
                session,
                "task-cat",
                matches!(cmd_input.source, session::CmdSource::Internal),
            )
            .await
            {
                outln!(
                    io,
                    "Web link: {}/task/{}@{}",
                    session::get_web_base_url(),
                    haitask.name,
                    haitask.version
                );
                term_color::print_with_syntax_highlighting(io, config.as_str(), "toml");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::TaskVersions(cmd::TaskVersionsCmd { task_fqn }) => {
            if config::is_valid_task_fqn(&task_fqn).is_none() {
                errorln!(
                    io,
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::loop_next();
            };
            use api::types::task::TaskListVersionsArg;
            match api_client
                .task_list_versions(TaskListVersionsArg {
                    task_fqn: task_fqn.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    for version in res.versions {
                        outln!(io, "{}", version);
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Asset(cmd::AssetCmd {
            asset_name,
            editor,
            no_create,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            if let Some(editor) = editor.as_deref()
                && let Some(prog_asset_name) = editor.strip_prefix("@")
            {
                crate::feature::asset_app::start_app_and_launch_browser(
                    &io,
                    session,
                    db.clone(),
                    asset_blob_cache.clone(),
                    &api_client,
                    Some(&username),
                    update_asset_tx.clone(),
                    is_task_mode_step,
                    prog_asset_name,
                    Some(&asset_name),
                    false,
                    true,
                    debug,
                    None,
                )
                .await;
                ProcessCmdResult::loop_next()
            } else {
                let (decrypted_asset_contents, asset_entry, akm_info) =
                    match asset_reader::get_asset_and_metadata(
                        asset_blob_cache.clone(),
                        &api_client,
                        &asset_name,
                        true,
                    )
                    .await
                    .map(|(ac, mc, ae)| (ac, mc, Some(ae)))
                    {
                        Ok((asset_contents, md_contents, asset_entry)) => {
                            let akm_info = match asset_crypt::extract_akm_from_metadata(
                                io,
                                asset_blob_cache.clone(),
                                session.asset_keyring.clone(),
                                api_client.clone(),
                                Some(&KeyRecipient::User(username.clone())),
                                md_contents.as_deref(),
                            )
                            .await
                            {
                                Ok(akm_info) => akm_info,
                                Err(e) => {
                                    match e {
                                        asset_crypt::AkmSelectionError::Abort(msg) => {
                                            errorln!(io, "{}", msg);
                                        }
                                    }
                                    return ProcessCmdResult::loop_next();
                                }
                            };
                            if let Some(akm_info) = &akm_info {
                                let enc_content =
                                    crypt::EncryptedContent::from_bytes(&asset_contents).unwrap();
                                (
                                    crypt::decrypt_content(
                                        &enc_content,
                                        &akm_info.unlocked_akm.sym_key_info.aes_key,
                                    )
                                    .unwrap(),
                                    asset_entry,
                                    Some(akm_info.clone()),
                                )
                            } else {
                                (asset_contents.to_vec(), asset_entry, None)
                            }
                        }
                        Err(asset_reader::GetAssetError::BadName) => {
                            if no_create {
                                errorln!(io, "asset does not exist: {}", asset_name);
                                return ProcessCmdResult::loop_next();
                            }
                            let akm_info = match asset_crypt::choose_akm_for_asset(
                                io,
                                asset_blob_cache.clone(),
                                session.asset_keyring.clone(),
                                api_client.clone(),
                                Some(&KeyRecipient::User(username.clone())),
                                &asset_crypt::extract_key_recipients_from_shared_asset_name(
                                    &asset_name,
                                    &username,
                                ),
                                None,
                                Some(asset_crypt::new_asset_akm_policy_by_asset_name(&asset_name)),
                            )
                            .await
                            {
                                Ok(akm_info) => akm_info,
                                Err(e) => {
                                    match e {
                                        asset_crypt::AkmSelectionError::Abort(msg) => {
                                            errorln!(io, "{}", msg);
                                        }
                                    }
                                    return ProcessCmdResult::loop_next();
                                }
                            };
                            (vec![], None, akm_info)
                        }
                        Err(e) => {
                            errorln!(io, "{}: failed to get: {}", asset_name, e);
                            return ProcessCmdResult::loop_next();
                        }
                    };

                let asset_entry_ref = asset_entry
                    .as_ref()
                    .map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
                let _ = asset_editor::edit_with_editor_api(
                    &api_client,
                    &session.shell,
                    &editor.clone().unwrap_or(session.editor.clone()),
                    &decrypted_asset_contents,
                    &asset_name,
                    asset_entry_ref,
                    asset_entry
                        .and_then(|entry| entry.metadata)
                        .and_then(|md| md.content_type),
                    false,
                    update_asset_tx,
                    akm_info,
                )
                .await;
                ProcessCmdResult::loop_next()
            }
        }
        cmd::Cmd::AssetPush(cmd::AssetPushCmd {
            asset_name,
            contents,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                api_client.clone(),
                Some(&KeyRecipient::User(username.clone())),
                &asset_name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            errorln!(io, "{}", msg);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };
            if let Some(contents) = contents {
                let _ = update_asset_tx
                    .send(asset_async_writer::WorkerAssetMsg::Update(
                        asset_async_writer::WorkerAssetUpdate {
                            asset_name,
                            asset_entry_ref: None,
                            new_contents: contents.clone().into_bytes(),
                            is_push: true,
                            api_client: api_client.clone(),
                            one_shot: true,
                            akm_info,
                            reply_channel: None,
                        },
                    ))
                    .await;
            } else {
                let _ = asset_editor::edit_with_editor_api(
                    &api_client,
                    &session.shell,
                    &session.editor,
                    &[],
                    &asset_name,
                    None,
                    None,
                    true,
                    update_asset_tx,
                    akm_info,
                )
                .await;
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetList(cmd::AssetListCmd { prefix, desc, full }) => {
            let prefix = resolve_asset_name(&io.out, &prefix, session).await;
            let (prefix, pattern) = if asset_reader::is_glob_pattern(&prefix) {
                let (prefix, pattern) = asset_reader::parse_glob_pattern(&prefix);
                (prefix, Some(pattern))
            } else {
                (prefix, None)
            };
            use crate::api::types::asset::{
                AssetEntryListArg, AssetEntryListError, AssetEntryListNextArg, AssetKind,
                EntryListOrder,
            };
            let mut asset_list_res = match api_client
                .asset_entry_list(AssetEntryListArg {
                    prefix: Some(prefix.clone()),
                    limit: 200,
                    order: if desc {
                        EntryListOrder::Desc
                    } else {
                        EntryListOrder::Asc
                    },
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    match e {
                        api::client::RequestError::Route(AssetEntryListError::Empty) => {
                            outln!(io, "[empty]");
                        }
                        _ => {
                            errorln!(io, "{}", e);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };

            // NOTE(UX win): If there is one entry that matches exactly the
            // prefix, it's likely that the user is trying to list the
            // contents of the folder. In this case, automatically list the
            // contents of the folder to save the user from having to re-type
            // the command with a trailing slash.
            if asset_list_res.entries.len() == 1
                && matches!(asset_list_res.entries[0].asset.kind, AssetKind::Folder)
                && asset_list_res.entries[0].name == prefix
            {
                let desc_option = if desc { ".desc" } else { "" };
                let full_option = if full { ".full" } else { "" };
                session
                    .cmd_queue
                    .lock()
                    .await
                    .push_front(session::CmdInput {
                        input: format!("/asset-list{}{} {}/", desc_option, full_option, prefix),
                        source: session::CmdSource::Internal,
                        reply_channel: None,
                    });
                return ProcessCmdResult::loop_next();
            }

            // Collect all entries (folders are embedded in the correct sort order).
            let mut entries = vec![];
            if asset_list_res.has_more {
                outln!(
                    io,
                    "[Listing assets in lexicographic (byte-order) due to size]"
                );
                loop {
                    entries.extend_from_slice(&asset_list_res.entries);
                    if !asset_list_res.has_more {
                        break;
                    }
                    asset_list_res = match api_client
                        .asset_entry_list_next(AssetEntryListNextArg {
                            cursor: asset_list_res.cursor,
                            limit: 200,
                        })
                        .await
                    {
                        Ok(res) => res,
                        Err(e) => {
                            errorln!(io, "{}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    };
                }
            } else {
                // If all entries are fetched in one-go, sort them.
                entries.extend_from_slice(&asset_list_res.entries);
                entries.sort_by(|a, b| numeric_sort::cmp(&a.name, &b.name));
                if desc {
                    entries.reverse();
                }
            }

            let digits = count_digits(entries.len() as u32);
            let mut new_quick_index_vars = vec![];
            let mut quick_index = 0;

            // First pass: collect the entries that match the pattern so we can
            // compute column widths for the full table.
            let matched: Vec<&AssetEntry> = entries
                .iter()
                .filter(|entry| pattern.as_ref().map_or(true, |p| p.matches(&entry.name)))
                .collect();

            if full {
                struct Row {
                    idx: String,
                    name: String,
                    id: String,
                    size: String,
                    ctype: String,
                    ts: String,
                    enc: String,
                    md: String,
                    acl: String,
                }

                // Column widths (measured in display width).
                let mut idx_w = "#".width();
                let mut name_w = "NAME".width();
                let mut id_w = "ID".width();
                let mut size_w = "SIZE".width();
                let mut type_w = "CON TYPE".width();
                let mut ts_w = "AGE".width();
                let mut enc_w = "ENC".width();
                let mut md_w = "MD".width();
                let mut acl_w = "ACL".width();

                let mut rows = vec![];

                for entry in &matched {
                    let is_folder = matches!(entry.asset.kind, AssetKind::Folder);

                    let idx = format!("{}", quick_index);

                    // Append glyphs to the name, like folders/push.
                    let push_symbol = if matches!(entry.asset.kind, AssetKind::Log) {
                        "📥"
                    } else {
                        ""
                    };
                    let name = if is_folder {
                        format!("{}📁", entry.name)
                    } else {
                        format!("{}{}", entry.name, push_symbol)
                    };

                    let id = entry.entry_id.to_string();

                    let size = if is_folder {
                        "-".to_string()
                    } else {
                        format_size(entry.total_size)
                    };

                    let ctype = entry
                        .metadata
                        .as_ref()
                        .and_then(|md| md.content_type.clone())
                        .unwrap_or_else(|| "-".to_string());

                    let ts = format_time_delta(&entry.asset.ts);

                    let enc = if entry
                        .metadata
                        .as_ref()
                        .map_or(false, |md| md.content_encrypted.is_some())
                    {
                        "🔒".to_string()
                    } else {
                        "".to_string()
                    };

                    let md = if entry.metadata.is_some() {
                        "✓".to_string()
                    } else {
                        "".to_string()
                    };

                    let acl = if !entry.asset.acl.is_empty() {
                        "✓".to_string()
                    } else {
                        "".to_string()
                    };

                    idx_w = idx_w.max(idx.width());
                    name_w = name_w.max(name.width());
                    id_w = id_w.max(id.width());
                    size_w = size_w.max(size.width());
                    type_w = type_w.max(ctype.width());
                    ts_w = ts_w.max(ts.width());
                    enc_w = enc_w.max(enc.width());
                    md_w = md_w.max(md.width());
                    acl_w = acl_w.max(acl.width());

                    rows.push(Row {
                        idx,
                        name,
                        id,
                        size,
                        ctype,
                        ts,
                        enc,
                        md,
                        acl,
                    });

                    new_quick_index_vars.push(entry.name.clone());
                    quick_index += 1;
                }

                // Helper closures for display-width-aware padding.
                let pad_right = |s: &str, w: usize| -> String {
                    let pad = w.saturating_sub(s.width());
                    format!("{}{}", s, " ".repeat(pad))
                };
                let pad_left = |s: &str, w: usize| -> String {
                    let pad = w.saturating_sub(s.width());
                    format!("{}{}", " ".repeat(pad), s)
                };

                let make_line = |idx: &str,
                                 name: &str,
                                 id: &str,
                                 size: &str,
                                 ctype: &str,
                                 ts: &str,
                                 enc: &str,
                                 md: &str,
                                 acl: &str|
                 -> String {
                    format!(
                        "{}  {}  {}  {}  {}  {}  {}  {}  {}",
                        pad_left(idx, idx_w),
                        pad_right(name, name_w),
                        pad_right(id, id_w),
                        pad_left(size, size_w),
                        pad_right(ctype, type_w),
                        pad_left(ts, ts_w),
                        pad_right(enc, enc_w),
                        pad_right(md, md_w),
                        pad_right(acl, acl_w),
                    )
                };

                // Header
                let header = make_line(
                    "#", "NAME", "ID", "SIZE", "CON TYPE", "AGE", "ENC", "MD", "ACL",
                );
                outln!(io, "{}", header);

                // Separator.
                let sep = make_line(
                    &"-".repeat(idx_w),
                    &"-".repeat(name_w),
                    &"-".repeat(id_w),
                    &"-".repeat(size_w),
                    &"-".repeat(type_w),
                    &"-".repeat(ts_w),
                    &"-".repeat(enc_w),
                    &"-".repeat(md_w),
                    &"-".repeat(acl_w),
                );
                outln!(io, "{}", sep);

                for row in &rows {
                    let line = make_line(
                        &row.idx, &row.name, &row.id, &row.size, &row.ctype, &row.ts, &row.enc,
                        &row.md, &row.acl,
                    );
                    outln!(io, "{}", line);
                }
            } else {
                // Existing behavior.
                for entry in &matched {
                    let line = if matches!(entry.asset.kind, AssetKind::Folder) {
                        printable_folder_line(&entry.name, Some((quick_index, digits)))
                    } else {
                        printable_asset_entry_line(entry, Some((quick_index, digits)))
                    };
                    outln!(io, "{}", line);
                    new_quick_index_vars.push(entry.name.clone());
                    quick_index += 1;
                }
            }

            session.quick_index_vars = new_quick_index_vars;
            if quick_index > 0 {
                let was_recording = io.record_off();
                outln!(io, "");
                outln!(
                    io,
                    "Tip: /a /asset can refer to assets by index using $0, $1, etc. AI is blind to indices."
                );
                io.record_set(was_recording);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetSearch(cmd::AssetSearchCmd { q, path }) => {
            let path = path
                .as_ref()
                .map(|p| asset_helper::expand_pub_asset_name(p, &session.account));
            use crate::api::types::asset::AssetEntrySearchArg;
            let asset_search_res = match api_client
                .asset_entry_search(AssetEntrySearchArg {
                    q: q.into(),
                    asset_pool_path: path.clone(),
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            let mut quick_index = 0;
            let mut new_quick_index_vars = vec![];
            let digits = count_digits(asset_search_res.semantic_matches.len() as u32);
            for entry in &asset_search_res.semantic_matches {
                let line = printable_asset_entry_line(entry, Some((quick_index, digits)));
                outln!(io, "{}", line);
                new_quick_index_vars.push(entry.name.clone());
                quick_index += 1;
            }
            session.quick_index_vars = new_quick_index_vars;
            if quick_index > 0 {
                let was_recording = io.record_off();
                outln!(io, "");
                outln!(
                    io,
                    "Tip: /a /asset can refer to assets by index using $0, $1, etc. AI is blind to indices."
                );
                io.record_set(was_recording);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetRead(cmd::AssetReadCmd {
            asset_names,
            show_line_numbers,
            image_hq,
        })
        | cmd::Cmd::AssetCat(cmd::AssetCatCmd {
            asset_names,
            show_line_numbers,
            image_hq,
        }) => {
            let asset_names = futures::future::join_all(
                asset_names
                    .iter()
                    .map(|name| resolve_asset_name(&io.out, name, session)),
            )
            .await;

            let mut history_entries = vec![];
            match asset_reader::fetch_assets_from_names_in_memory_extended(
                asset_blob_cache.clone(),
                api_client,
                &asset_names,
                4,
                true,
            )
            .await
            {
                Ok((asset_map, _, assets_skipped_content_restrictions, assets_skipped_folders)) => {
                    for asset_name in &assets_skipped_content_restrictions {
                        let err_msg = format!(
                            "error: asset '{}' skipped due to content restrictions.",
                            asset_name
                        );
                        errorln!(io, "{}", err_msg);
                    }
                    for asset_name in &assets_skipped_folders {
                        let err_msg = format!(
                            "error: asset '{}' skipped because it is a folder.",
                            asset_name
                        );
                        errorln!(io, "{}", err_msg);
                    }
                    for (asset_name, fetch_res) in &asset_map {
                        let (decrypted_asset_contents, asset_entry) = match fetch_res {
                            Ok(asset_reader::AssetFetchResult {
                                data: asset_contents,
                                metadata: Some(md_contents),
                                asset_entry,
                            }) => {
                                if let Some(rec_key_info) =
                                    asset_crypt::parse_metadata_for_encryption_info(
                                        &md_contents,
                                        session
                                            .account
                                            .as_ref()
                                            .map(|a| KeyRecipient::User(a.username.clone()))
                                            .as_ref(),
                                    )
                                {
                                    match asset_crypt::get_symmetric_key_ez(
                                        io,
                                        asset_blob_cache.clone(),
                                        session.asset_keyring.clone(),
                                        &api_client,
                                        &rec_key_info,
                                    )
                                    .await
                                    {
                                        Ok(sym_info) => {
                                            let enc_content =
                                                crypt::EncryptedContent::from_bytes(asset_contents)
                                                    .unwrap();
                                            (
                                                crypt::decrypt_content(
                                                    &enc_content,
                                                    &sym_info.aes_key,
                                                )
                                                .unwrap(),
                                                asset_entry,
                                            )
                                        }
                                        Err(e) => {
                                            errorln!(
                                                io,
                                                "{}: failed to get encryption key: {}",
                                                asset_name,
                                                e
                                            );
                                            return ProcessCmdResult::loop_next();
                                        }
                                    }
                                } else {
                                    (asset_contents.clone(), asset_entry)
                                }
                            }
                            Ok(asset_reader::AssetFetchResult {
                                data: asset_contents,
                                metadata: None,
                                asset_entry,
                            }) => (asset_contents.clone(), asset_entry),
                            Err(e) => {
                                match e {
                                    asset_reader::GetAssetError::BadName => {
                                        errorln!(io, "{}: asset not found", asset_name);
                                    }
                                    asset_reader::GetAssetError::DataFetchFailed(e) => {
                                        errorln!(io, "{}: fetch failed: {}", asset_name, e);
                                    }
                                };
                                return ProcessCmdResult::loop_next();
                            }
                        };

                        match String::from_utf8(decrypted_asset_contents.clone()) {
                            Ok(asset_contents_string) => {
                                let asset_contents_with_delimeters = add_content_delimiters(
                                    "ASSET",
                                    &asset_contents_string,
                                    &asset_name,
                                    Some(&format!("rev_id={}", asset_entry.asset.rev_id)),
                                    show_line_numbers,
                                );
                                let token_count = bpe_tokenizer
                                    .encode_with_special_tokens(&asset_contents_with_delimeters)
                                    .len() as u32;

                                let was_recording = io.record_off();
                                if matches!(cmd, cmd::Cmd::AssetRead(_)) {
                                    outln!(io, "Loaded: {} ({} tokens)", asset_name, token_count);
                                } else {
                                    outln!(
                                        io,
                                        "{}",
                                        if show_line_numbers {
                                            add_line_numbers(&asset_contents_string)
                                        } else {
                                            asset_contents_string.clone()
                                        }
                                    );
                                }
                                io.record_set(was_recording);
                                history_entries.push(HistoryEntry::UserText(
                                    asset_contents_with_delimeters.clone(),
                                ));
                            }
                            Err(_e) => {
                                // Not text, try opening as image
                                let image_capability =
                                    config::get_ai_model_capability(&session.ai).image;
                                let use_thumbnail = image_capability
                                    .as_ref()
                                    .map(|cap| !image_hq && !cap.auto_resize)
                                    .unwrap_or(false);

                                match loader::encode_image_bytes_to_png_base64(
                                    decrypted_asset_contents.into(),
                                    use_thumbnail,
                                ) {
                                    Ok((img_png_b64, img_dim)) => {
                                        if image_capability.is_none() {
                                            errorln!(io, "model does not support images");
                                            return ProcessCmdResult::loop_next();
                                        }
                                        let token_count = session::calc_image_tokens(
                                            &session.ai,
                                            image_hq,
                                            img_dim,
                                        );
                                        history_entries.push(HistoryEntry::UserImage(
                                            img_png_b64.clone(),
                                            image_hq,
                                            img_dim,
                                        ));
                                        let was_recording = io.record_off();
                                        if matches!(cmd, cmd::Cmd::AssetCat(_)) {
                                            io.display("image/png", &img_png_b64);
                                        } else {
                                            outln!(
                                                io,
                                                "Loaded: {} ({} tokens)",
                                                asset_name,
                                                token_count.to_formatted_string(&Locale::en)
                                            );
                                        }
                                        io.record_set(was_recording);
                                    }
                                    Err(e) => {
                                        errorln!(
                                            io,
                                            "failed to load as text or image: {:?}: {:?}",
                                            asset_name,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            }
            ProcessCmdResult::loop_next()
                .with_retention_policy(LogEntryRetentionPolicy::ConversationLoad)
                .with_history_entries(history_entries)
        }
        cmd::Cmd::AssetWrite(cmd::AssetWriteCmd {
            asset_name,
            contents,
            encrypt,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            if !asset_helper::is_likely_valid_asset_name(&asset_name, true) {
                // A client-side check is performed because interactive editors
                // like vim sometimes swallow the error message which means a
                // user won't be aware that their new asset didn't save.
                errorln!(io, "invalid name");
                return ProcessCmdResult::loop_next();
            } else if encrypt && asset_name.starts_with("/") {
                errorln!(io, "cannot create encrypted asset in the public pool");
                return ProcessCmdResult::loop_next();
            }
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                api_client.clone(),
                Some(&KeyRecipient::User(username.clone())),
                &asset_name,
                encrypt,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            errorln!(io, "{}", msg);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };
            // WARN: The conversation history is updated before the write is
            // complete.
            let _ = update_asset_tx
                .send(asset_async_writer::WorkerAssetMsg::Update(
                    asset_async_writer::WorkerAssetUpdate {
                        asset_name: asset_name.clone(),
                        asset_entry_ref: None,
                        new_contents: contents.clone().unwrap_or("".to_string()).into_bytes(),
                        is_push: false,
                        api_client: api_client.clone(),
                        one_shot: true,
                        akm_info: akm_info.clone(),
                        reply_channel: None,
                    },
                ))
                .await;
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetPatch(cmd::AssetPatchCmd {
            asset_name,
            search,
            replace,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            let (decrypted_asset_contents, asset_entry, akm_info) =
                match asset_reader::get_asset_and_metadata(
                    asset_blob_cache.clone(),
                    &api_client,
                    &asset_name,
                    true,
                )
                .await
                .map(|(ac, mc, ae)| (ac, mc, Some(ae)))
                {
                    Ok((asset_contents, md_contents, asset_entry)) => {
                        let akm_info = match asset_crypt::extract_akm_from_metadata(
                            io,
                            asset_blob_cache.clone(),
                            session.asset_keyring.clone(),
                            api_client.clone(),
                            Some(&KeyRecipient::User(username.clone())),
                            md_contents.as_deref(),
                        )
                        .await
                        {
                            Ok(akm_info) => akm_info,
                            Err(e) => {
                                match e {
                                    asset_crypt::AkmSelectionError::Abort(msg) => {
                                        errorln!(io, "{}", msg);
                                    }
                                }
                                return ProcessCmdResult::loop_next();
                            }
                        };
                        if let Some(akm_info) = &akm_info {
                            let enc_content =
                                crypt::EncryptedContent::from_bytes(&asset_contents).unwrap();
                            (
                                crypt::decrypt_content(
                                    &enc_content,
                                    &akm_info.unlocked_akm.sym_key_info.aes_key,
                                )
                                .unwrap(),
                                asset_entry,
                                Some(akm_info.clone()),
                            )
                        } else {
                            (asset_contents.to_vec(), asset_entry, None)
                        }
                    }
                    Err(asset_reader::GetAssetError::BadName) => {
                        errorln!(io, "asset does not exist: {}", asset_name);
                        return ProcessCmdResult::loop_next();
                    }
                    Err(e) => {
                        errorln!(io, "{}: failed to get: {}", asset_name, e);
                        return ProcessCmdResult::loop_next();
                    }
                };
            let decrypted_asset_contents_str = match String::from_utf8(decrypted_asset_contents) {
                Ok(s) => s,
                Err(e) => {
                    errorln!(io, "asset contents are not valid UTF-8: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            let asset_entry_ref = asset_entry
                .as_ref()
                .map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
            match search_and_replace(&decrypted_asset_contents_str, &search, &replace, 10) {
                ReplaceResult::Success(new_contents) => {
                    let _ = update_asset_tx
                        .send(asset_async_writer::WorkerAssetMsg::Update(
                            asset_async_writer::WorkerAssetUpdate {
                                asset_name: asset_name.clone(),
                                asset_entry_ref: asset_entry_ref,
                                new_contents: new_contents.into_bytes(),
                                is_push: false,
                                api_client: api_client.clone(),
                                one_shot: true,
                                akm_info: akm_info.clone(),
                                reply_channel: None,
                            },
                        ))
                        .await;
                    outln!(io, "ok");
                }
                ReplaceResult::NoMatch => {
                    errorln!(io, "no matches found");
                }
                ReplaceResult::MultipleMatches(expanded_matches) => {
                    let mut msg = format!(
                        "search string isn't unique (found {} matches)",
                        expanded_matches.len()
                    );
                    for expanded_match in expanded_matches {
                        msg.push_str("<<<<<<< START EXPANDED MATCH\n");
                        msg.push_str(&expanded_match);
                        msg.push_str("\n>>>>>>> END EXPANDED MATCH\n");
                    }
                    errorln!(io, "{}", msg);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetRevisions(cmd::AssetRevisionsCmd {
            asset_name,
            count,
            show_line_numbers,
        }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;

            let mut history_entries = vec![];

            use crate::api::types::asset::{
                AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
            };

            let mut remaining = count;
            let mut revision_cursor = match api_client
                .asset_revision_iter(AssetRevisionIterArg {
                    entry_ref: EntryRef::Name(asset_name.clone()),
                    limit: 1,
                    direction: RevisionIterDirection::Older,
                })
                .await
            {
                Ok(iter_res) => {
                    outln!(
                        io,
                        "Total Revisions (approximate): {}",
                        iter_res.approx_remaining
                    );
                    outln!(io);
                    for revision in iter_res.revisions {
                        if let Some(n) = remaining {
                            if n == 0 {
                                break;
                            }
                            remaining = Some(n - 1);
                        }
                        if let Some(history_entry) = print_revision(
                            io,
                            asset_blob_cache.clone(),
                            &api_client,
                            &asset_name,
                            show_line_numbers,
                            &revision,
                            session,
                        )
                        .await
                        {
                            history_entries.push(history_entry);
                        }
                    }
                    iter_res.next
                }
                Err(e) => {
                    errorln!(io, "failed to get revisions: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            if revision_cursor.is_none() {
                return ProcessCmdResult::loop_next().with_history_entries(history_entries);
            }
            loop {
                if let Some(n) = remaining {
                    if n == 0 {
                        break;
                    }
                    remaining = Some(n - 1);
                } else {
                    let was_recording = io.record_off();
                    outln!(io, "Press any key to continue... CTRL+C to stop");
                    io.record_set(was_recording);
                    let _ = crossterm::terminal::enable_raw_mode();
                    if let Ok(crossterm::event::Event::Key(key_event)) = crossterm::event::read() {
                        // Stop on Ctrl+C
                        if key_event.code == crossterm::event::KeyCode::Char('c')
                            && key_event
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)
                        {
                            let _ = crossterm::terminal::disable_raw_mode();
                            return ProcessCmdResult::loop_next()
                                .with_history_entries(history_entries);
                        }
                    }
                    let _ = crossterm::terminal::disable_raw_mode();
                }
                if let Some(next) = revision_cursor {
                    revision_cursor = match api_client
                        .asset_revision_iter_next(AssetRevisionIterNextArg {
                            cursor: next.cursor,
                            limit: 1,
                        })
                        .await
                    {
                        Ok(iter_next_res) => {
                            let was_recording = io.record_off();
                            outln!(
                                io,
                                "Remaining Revisions (approximate): {}",
                                iter_next_res.approx_remaining
                            );
                            outln!(io);
                            io.record_set(was_recording);
                            for revision in iter_next_res.revisions {
                                if let Some(history_entry) = print_revision(
                                    io,
                                    asset_blob_cache.clone(),
                                    &api_client,
                                    &asset_name,
                                    show_line_numbers,
                                    &revision,
                                    session,
                                )
                                .await
                                {
                                    history_entries.push(history_entry);
                                }
                            }
                            iter_next_res.next
                        }
                        Err(e) => {
                            errorln!(io, "failed to get revisions: {}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    };
                } else {
                    break;
                }
            }
            ProcessCmdResult::loop_next().with_history_entries(history_entries)
        }
        cmd::Cmd::AssetFollow(cmd::AssetFollowCmd { asset_name }) => {
            outln!(io, "WARN: /asset-follow is for debugging.");
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use crate::api::types::asset::{
                AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
            };
            let mut cursor = match api_client
                .asset_revision_iter(AssetRevisionIterArg {
                    entry_ref: EntryRef::Name(asset_name),
                    limit: 1,
                    direction: RevisionIterDirection::Newer,
                })
                .await
            {
                Ok(iter_res) => iter_res.next.expect("missing cursor").cursor,
                Err(e) => {
                    errorln!(io, "failed to get revisions: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::connect_async;
            use tokio_tungstenite::tungstenite::Message;

            let listen_url = format!(
                "{}/notify/listen",
                session::get_api_base_url().replace("http", "ws")
            );
            let (mut ws_stream, _) = match connect_async(listen_url).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to connect: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use crate::api::types::notify::{ListenAsset, NotifyListenArg};
            let arg = NotifyListenArg::Asset(ListenAsset {
                cursor: cursor.clone(),
            });
            ws_stream
                .send(Message::Text(serde_json::to_string(&arg).unwrap().into()))
                .await
                .unwrap();

            while let Some(msg) = {
                tokio::select! {
                    msg = ws_stream.next() => msg,
                    _ = tokio::signal::ctrl_c() => {
                        return ProcessCmdResult::loop_next();
                    }
                }
            } {
                outln!(io, "Received: {:?}", msg);
                match msg {
                    Ok(_msg) => {
                        // NOTE: `msg` isn't finalized so do not use contents.
                        cursor = match api_client
                            .asset_revision_iter_next(AssetRevisionIterNextArg {
                                cursor,
                                limit: 10,
                            })
                            .await
                        {
                            Ok(iter_res) => {
                                for revision in iter_res.revisions {
                                    if let Some(data_url) = revision.asset.url.as_ref()
                                        && let Ok(contents_bin) =
                                            asset_reader::download_with_new_client(data_url).await
                                    {
                                        let contents = String::from_utf8_lossy(&contents_bin);
                                        outln!(io, "{}", &contents);
                                    }
                                }
                                iter_res.next.expect("missing cursor").cursor
                            }
                            Err(e) => {
                                errorln!(io, "failed to get revisions: {}", e);
                                return ProcessCmdResult::loop_next();
                            }
                        };
                    }
                    Err(e) => {
                        errorln!(io, "websocket: {}", e);
                        break;
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetListen(cmd::AssetListenCmd { asset_name, cursor }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use crate::api::types::asset::{
                AssetCreatedBy, AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef,
                RevisionIterDirection,
            };
            let revision_start_cursor = if let Some(cursor) = cursor {
                cursor.clone()
            } else {
                match api_client
                    .asset_revision_iter(AssetRevisionIterArg {
                        entry_ref: EntryRef::Name(asset_name),
                        limit: 1,
                        direction: RevisionIterDirection::Newer,
                    })
                    .await
                {
                    Ok(iter_res) => iter_res.next.expect("missing cursor").cursor,
                    Err(e) => {
                        errorln!(io, "failed to get revisions: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                }
            };

            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::connect_async;
            use tokio_tungstenite::tungstenite::Message;

            let listen_url = format!(
                "{}/notify/listen",
                session::get_api_base_url().replace("http", "ws")
            );
            use crate::api::types::notify::{ListenAsset, NotifyListenArg};
            let arg = NotifyListenArg::Asset(ListenAsset {
                cursor: revision_start_cursor.clone(),
            });

            let mut attempt = 0;

            loop {
                let (mut ws_stream, _) = match connect_async(&listen_url).await {
                    Ok(res) => res,
                    Err(e) => {
                        errorln!(io, "failed to connect: {}", e);
                        attempt += 1;
                        let backoff_duration =
                            std::time::Duration::from_secs(2_u64.pow(attempt).min(60)); // Cap backoff
                        outln!(io, "retrying in {} seconds...", backoff_duration.as_secs());
                        // For ergonomics, support ctrl+c to stop reconnecting
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {
                                return ProcessCmdResult::loop_next();
                            }
                            _ = tokio::time::sleep(backoff_duration) => {
                            }
                        }
                        continue;
                    }
                };
                if attempt > 0 {
                    outln!(io, "connected");
                    attempt = 0;
                }
                ws_stream
                    .send(Message::Text(serde_json::to_string(&arg).unwrap().into()))
                    .await
                    .unwrap();

                if let Some(msg) = {
                    // For ergonomics, support ctrl+c to stop listening
                    tokio::select! {
                        msg = ws_stream.next() => msg,
                        _ = tokio::signal::ctrl_c() => {
                            return ProcessCmdResult::loop_next();
                        }
                    }
                } {
                    match msg {
                        Ok(_msg) => {
                            // NOTE: `msg` isn't finalized so do not use contents.
                            match api_client
                                .asset_revision_iter_next(AssetRevisionIterNextArg {
                                    cursor: revision_start_cursor.clone(),
                                    limit: 1,
                                })
                                .await
                            {
                                Ok(iter_res) => {
                                    if let Some(revision) = iter_res.revisions.first() {
                                        let mut output_lines = vec![];
                                        output_lines.push(format!(
                                            "data url: {}\n",
                                            revision
                                                .asset
                                                .url
                                                .as_ref()
                                                .unwrap_or(&"none".to_string())
                                        ));
                                        output_lines
                                            .push(format!("data size: {}\n", revision.asset.size));
                                        output_lines.push(format!(
                                            "data hash: {}\n",
                                            revision
                                                .asset
                                                .hash
                                                .as_ref()
                                                .unwrap_or(&"none".to_string())
                                        ));
                                        output_lines.push(format!("data op: {:?}\n", revision.op));
                                        if let AssetCreatedBy::User(ref created_by_user) =
                                            revision.asset.created_by
                                        {
                                            output_lines.push(format!(
                                                "by (user): {}\n",
                                                created_by_user.username
                                            ));
                                        }
                                        output_lines.push(format!(
                                            "data by: {:?}\n",
                                            revision.asset.created_by
                                        ));
                                        if let Some(md) = revision.metadata.as_ref() {
                                            output_lines.push(format!(
                                                "metadata url: {}\n",
                                                md.url.as_ref().unwrap_or(&"none".to_string())
                                            ));
                                            output_lines
                                                .push(format!("metadata size: {}\n", md.size));
                                            output_lines
                                                .push(format!("metadata hash: {:?}\n", md.hash));
                                        }
                                        output_lines.push(format!(
                                            "next cursor: {}\n",
                                            iter_res.next.expect("missing cursor").cursor
                                        ));
                                        let output = output_lines.join("");
                                        outln!(io, "{}", output);
                                    }
                                    break;
                                }
                                Err(e) => {
                                    errorln!(io, "failed to get revisions: {}", e);
                                    return ProcessCmdResult::loop_next();
                                }
                            };
                        }
                        Err(e) => {
                            // If the connection is reset, it's likely due to a timeout.
                            // In that case, ignore the error. If the server is not
                            // responding, we expect the reconnection attempt to fail
                            // and notify the user.
                            if !e
                                .to_string()
                                .contains("Connection reset without closing handshake")
                            {
                                errorln!(io, "websocket: {}", e);
                            }
                        }
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetLink(cmd::AssetLinkCmd { asset_name }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use crate::api::types::asset::AssetGetArg;
            let asset_data_url = match api_client
                .asset_get(AssetGetArg {
                    name: asset_name.clone(),
                })
                .await
            {
                Ok(res) => {
                    if res
                        .entry
                        .metadata
                        .as_ref()
                        .map_or(false, |md| md.content_encrypted.is_some())
                    {
                        errorln!(io, "encrypted assets cannot have links");
                        return ProcessCmdResult::loop_next();
                    } else if let Some(data_url) = res.entry.asset.url {
                        data_url
                    } else {
                        errorln!(io, "asset does not have link");
                        return ProcessCmdResult::loop_next();
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            outln!(io, "Expiring link (24 hours):");
            outln!(io, "{}", asset_data_url);
            if let Some(public_asset_url) = asset_helper::get_public_asset_url(&asset_name) {
                outln!(io);
                outln!(io, "Permalink:");
                outln!(io, "{}", public_asset_url);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetRemove(cmd::AssetRemoveCmd {
            asset_name,
            recursive,
        }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            if asset_name == "*" {
                errorln!(io, "cannot use wildcard at root");
                return ProcessCmdResult::loop_next();
            }
            use crate::api::types::asset::{AssetKind, AssetRemoveArg};
            let folder_policy = if recursive {
                asset_reader::FolderPolicy::IncludeAndRecurse
            } else {
                // Allows for removal of folder assets, but not their contents
                asset_reader::FolderPolicy::IncludeOnly
            };
            let asset_entries = match asset_reader::get_asset_entries_from_globs(
                &api_client,
                &[asset_name.clone()],
                folder_policy,
            )
            .await
            {
                Ok(asset_entries) => asset_entries,
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            if asset_entries.is_empty() {
                errorln!(io, "no match: {}", asset_name);
            } else if asset_entries.len() == 1
                && !recursive
                && !asset_reader::is_glob_pattern(&asset_name)
            {
                // If the user specified a single asset name without a glob
                // pattern, we can remove it directly.
                let asset_entry = &asset_entries[0];
                if asset_entry.asset.kind == AssetKind::Folder {
                    warnln!(
                        io,
                        "{}: removing folder-asset only; use /asset-remove-recursive to remove contents",
                        asset_entry.name
                    );
                }
                match api_client
                    .asset_remove(AssetRemoveArg {
                        name: asset_entry.name.clone(),
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        errorln!(io, "{}: {}", asset_entry.name, e);
                    }
                }
            } else {
                for asset_entry in &asset_entries {
                    if !recursive && asset_entry.asset.kind == AssetKind::Folder {
                        outln!(
                            io,
                            "{} [folder-asset only, use /asset-remove-recursive to remove contents]",
                            asset_entry.name
                        );
                    } else {
                        outln!(io, "{}", asset_entry.name);
                    }
                }
                // Some glob was used, so ask user for confirmation
                let q = "Are you sure you want to remove the following assets? (y/N)";
                let Some(answer) = io.query(&crate::io::Query::confirm(q)).into_option() else {
                    return ProcessCmdResult::loop_next();
                };
                let answer = answer.trim().to_lowercase();
                if answer != "y" && answer != "yes" {
                    record_outln!(io, "{} {}", q, answer);
                    errorln!(io, "cancelled");
                    return ProcessCmdResult::loop_next();
                }

                for asset_entry in asset_entries {
                    match api_client
                        .asset_remove(AssetRemoveArg {
                            name: asset_entry.name.clone(),
                        })
                        .await
                    {
                        Ok(_) => {
                            outln!(io, "{}", asset_entry.name);
                        }
                        Err(e) => {
                            errorln!(io, "{}: {}", asset_entry.name, e);
                        }
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetMove(cmd::AssetMoveCmd {
            source_asset_name,
            dest_asset_name,
        }) => {
            let _username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let source_asset_name =
                asset_helper::expand_pub_asset_name(&source_asset_name, &session.account);
            let dest_asset_name =
                asset_helper::expand_pub_asset_name(&dest_asset_name, &session.account);

            use crate::api::types::asset::AssetMoveArg;
            match api_client
                .asset_move(AssetMoveArg {
                    source_name: source_asset_name,
                    target_name: dest_asset_name,
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetCopy(cmd::AssetCopyCmd {
            source_asset_name,
            dest_asset_name,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let source_asset_name = resolve_asset_name(&io.out, &source_asset_name, session).await;
            let mut target_asset_name =
                resolve_asset_name(&io.out, &dest_asset_name, session).await;

            // If target ends with '/', append the filename from source
            if target_asset_name.ends_with('/') {
                let source_filename = source_asset_name
                    .rsplit('/')
                    .next()
                    .unwrap_or(&source_asset_name);
                target_asset_name.push_str(source_filename);
            }

            let mut copy_tasks = vec![(source_asset_name, target_asset_name)];

            while let Some((source_asset_name, target_asset_name)) = copy_tasks.pop() {
                let (data_contents, source_md_contents, source_asset_entry) =
                    match asset_reader::get_asset_and_metadata(
                        asset_blob_cache.clone(),
                        &api_client,
                        &source_asset_name,
                        false,
                    )
                    .await
                    {
                        Ok(res) => res,
                        Err(e) => {
                            errorln!(io, "{}: failed to get: {}", source_asset_name, e);
                            return ProcessCmdResult::loop_next();
                        }
                    };
                let decrypted_asset_contents = match asset_crypt::maybe_decrypt_asset_contents(
                    io,
                    asset_blob_cache.clone(),
                    session.asset_keyring.clone(),
                    &api_client,
                    Some(&KeyRecipient::User(username.clone())),
                    &data_contents,
                    source_md_contents.as_deref(),
                )
                .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        errorln!(io, "failed to decrypt: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                };

                let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                    io,
                    asset_blob_cache.clone(),
                    session.asset_keyring.clone(),
                    api_client.clone(),
                    Some(&KeyRecipient::User(username.clone())),
                    &target_asset_name,
                    false,
                )
                .await
                {
                    Ok(akm_info) => akm_info,
                    Err(e) => {
                        match e {
                            asset_crypt::AkmSelectionError::Abort(msg) => {
                                errorln!(io, "{}", msg);
                            }
                        }
                        return ProcessCmdResult::loop_next();
                    }
                };

                let _ = update_asset_tx
                    .send(asset_async_writer::WorkerAssetMsg::Update(
                        asset_async_writer::WorkerAssetUpdate {
                            asset_name: target_asset_name.clone(),
                            asset_entry_ref: None,
                            new_contents: decrypted_asset_contents.clone(),
                            is_push: false,
                            api_client: api_client.clone(),
                            one_shot: true,
                            akm_info: akm_info.clone(),
                            reply_channel: None,
                        },
                    ))
                    .await;

                // Wait until copied asset is committed along with metadata if
                // encryption applicable. That way the subsequent metadata fetch
                // will have the up-to-date info.
                asset_async_writer::flush_asset_updates(&update_asset_tx).await;

                let (target_md_contents, target_asset_entry) =
                    match asset_reader::get_only_asset_metadata(
                        asset_blob_cache.clone(),
                        &api_client,
                        &target_asset_name,
                        false,
                    )
                    .await
                    {
                        Ok(res) => res,
                        Err(e) => {
                            errorln!(io, "{}: failed to get: {}", target_asset_name, e);
                            return ProcessCmdResult::loop_next();
                        }
                    };

                let source_attachment_id = format!(":{}", source_asset_entry.entry_id);
                let target_attachment_id = format!(":{}", target_asset_entry.entry_id);

                let source_md = source_md_contents.as_ref().and_then(|md| {
                    let contents = String::from_utf8_lossy(md)
                        .replace(&source_attachment_id, &target_attachment_id);
                    serde_json::from_str::<serde_json::Value>(&contents).ok()
                });

                let target_md = target_md_contents.as_ref().and_then(|md| {
                    let contents = String::from_utf8_lossy(md);
                    serde_json::from_str::<serde_json::Value>(&contents).ok()
                });

                if source_md != target_md
                    && let Some(merged_md) =
                        asset_async_writer::metadata_merge(source_md, target_md)
                {
                    let md_contents =
                        serde_json::to_string(&merged_md).expect("failed to serialize metadata");

                    use crate::api::types::asset::{AssetMetadataPutArg, PutConflictPolicy};

                    match api_client
                        .asset_metadata_put(AssetMetadataPutArg {
                            name: target_asset_name.clone(),
                            data: md_contents,
                            conflict_policy: PutConflictPolicy::Override,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            errorln!(io, "{}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    }
                }

                match asset_helper::list_all_asset_entries(&api_client, &source_attachment_id).await
                {
                    Ok(entries) => {
                        for entry in entries {
                            copy_tasks.push((
                                entry.name.clone(),
                                entry
                                    .name
                                    .replace(&source_attachment_id, &target_attachment_id),
                            ));
                        }
                    }
                    Err(_) => {
                        errorln!(
                            io,
                            "failed to list attachments for asset: {}",
                            source_asset_name
                        );
                        errorln!(io, "copy is incomplete");
                    }
                }

                // Final write of body rewriting the attachment references
                let _ = update_asset_tx
                    .send(asset_async_writer::WorkerAssetMsg::Update(
                        asset_async_writer::WorkerAssetUpdate {
                            asset_name: target_asset_name.clone(),
                            asset_entry_ref: None,
                            new_contents: decrypted_asset_contents
                                .replace(&source_attachment_id, &target_attachment_id),
                            is_push: false,
                            api_client: api_client.clone(),
                            one_shot: true,
                            akm_info: akm_info.clone(),
                            reply_channel: None,
                        },
                    ))
                    .await;
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetImport(cmd::AssetImportCmd {
            target_asset_name,
            source_file_path,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let target_asset_name = resolve_asset_name(&io.out, &target_asset_name, &session).await;
            let source_file_path = match shellexpand::full(&source_file_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            let asset_contents = match fs::read(source_file_path) {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to read: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                api_client.clone(),
                Some(&KeyRecipient::User(username.clone())),
                &target_asset_name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            errorln!(io, "{}", msg);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };

            let _ = update_asset_tx
                .send(asset_async_writer::WorkerAssetMsg::Update(
                    asset_async_writer::WorkerAssetUpdate {
                        asset_name: target_asset_name.clone(),
                        asset_entry_ref: None,
                        new_contents: asset_contents,
                        is_push: false,
                        api_client: api_client.clone(),
                        one_shot: true,
                        akm_info: akm_info.clone(),
                        reply_channel: None,
                    },
                ))
                .await;

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetExport(cmd::AssetExportCmd {
            source_asset_name,
            target_file_path,
        }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let source_asset_name = resolve_asset_name(&io.out, &source_asset_name, session).await;
            // Special case if target is `.`
            let target_file_path = if target_file_path == "." {
                match source_asset_name.rsplit('/').next() {
                    Some(filename) => filename.to_string(),
                    None => source_asset_name.clone(), // If no slashes
                }
            } else {
                target_file_path.to_owned()
            };
            let target_file_path = match shellexpand::full(&target_file_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            let (data_contents, md_contents, _asset_entry) =
                match asset_reader::get_asset_and_metadata(
                    asset_blob_cache.clone(),
                    &api_client,
                    &source_asset_name,
                    false,
                )
                .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        errorln!(io, "{}: failed to get: {}", source_asset_name, e);
                        return ProcessCmdResult::loop_next();
                    }
                };
            let decrypted_asset_contents = match asset_crypt::maybe_decrypt_asset_contents(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                session
                    .account
                    .as_ref()
                    .map(|a| KeyRecipient::User(a.username.clone()))
                    .as_ref(),
                &data_contents,
                md_contents.as_deref(),
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to decrypt: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            match fs::write(&target_file_path, decrypted_asset_contents) {
                Ok(_) => {}
                Err(e) => {
                    errorln!(io, "failed to save: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetSyncDown(cmd::AssetSyncDownCmd {
            prefix,
            target_path,
        }) => {
            let prefix = if prefix == "-" {
                None
            } else {
                Some(asset_helper::expand_pub_asset_name(
                    &prefix,
                    &session.account,
                ))
            };
            let target_path = match shellexpand::full(&target_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            let _ = asset_sync::sync_down(
                &io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                session
                    .account
                    .as_ref()
                    .map(|a| KeyRecipient::User(a.username.clone())),
                prefix.as_deref(),
                &target_path,
                None,
                debug,
            )
            .await;
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetSyncUp(cmd::AssetSyncUpCmd {
            source_path,
            target_prefix,
            sync_new_files,
            dry_run,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let source_path = match shellexpand::full(&source_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            let target_prefix = if target_prefix == "-" {
                None
            } else {
                Some(asset_helper::expand_pub_asset_name(
                    &target_prefix,
                    &session.account,
                ))
            };
            match asset_sync::sync_up(
                &io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
                update_asset_tx,
                &source_path,
                target_prefix.as_deref(),
                asset_sync::SyncUpOptions {
                    sync_new_files,
                    max_concurrent_uploads: 10,
                    debug,
                    dry_run,
                },
            )
            .await
            {
                Ok(sync_results) => {
                    for res in &sync_results {
                        if matches!(res.action, asset_sync::SyncUpAction::Skipped) {
                            continue;
                        }
                        outln!(
                            io,
                            "sync: path={} -> name={}: action={}: {}",
                            res.file_path,
                            res.asset_name,
                            res.action,
                            if res.success {
                                "ok".to_string()
                            } else {
                                res.error.clone().unwrap_or_default()
                            },
                        )
                    }

                    // Print summary
                    let created = sync_results
                        .iter()
                        .filter(|r| {
                            matches!(r.action, asset_sync::SyncUpAction::Created) && r.success
                        })
                        .count();
                    let updated = sync_results
                        .iter()
                        .filter(|r| {
                            matches!(r.action, asset_sync::SyncUpAction::Updated) && r.success
                        })
                        .count();
                    let moved = sync_results
                        .iter()
                        .filter(|r| {
                            matches!(r.action, asset_sync::SyncUpAction::Moved) && r.success
                        })
                        .count();
                    let skipped = sync_results
                        .iter()
                        .filter(|r| matches!(r.action, asset_sync::SyncUpAction::Skipped))
                        .count();
                    let skipped_new = sync_results
                        .iter()
                        .filter(|r| matches!(r.action, asset_sync::SyncUpAction::SkippedNew))
                        .count();
                    let failed = sync_results.iter().filter(|r| !r.success).count();

                    outln!(
                        io,
                        "Sync up complete: {} created, {} updated, {} moved, {} unchanged, {} skipped (new), {} failed",
                        created,
                        updated,
                        moved,
                        skipped,
                        skipped_new,
                        failed
                    );
                }
                Err(e) => {
                    errorln!(io, "failed to sync up: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetSyncDiff(cmd::AssetSyncDiffCmd { path }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let path_style = detect_path_style(&path);
            let path = match shellexpand::full(&path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    errorln!(io, "undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::loop_next();
                }
            };
            match asset_sync::sync_up(
                &io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
                update_asset_tx,
                &path,
                None,
                asset_sync::SyncUpOptions {
                    sync_new_files: true,
                    max_concurrent_uploads: 1,
                    debug,
                    dry_run: true,
                },
            )
            .await
            {
                Ok(sync_results) => {
                    for result in &sync_results {
                        if !result.dry_run {
                            panic!("sync_up should be in dry_run mode for AssetSyncDiff");
                        }
                        if matches!(
                            result.action,
                            asset_sync::SyncUpAction::Skipped
                                | asset_sync::SyncUpAction::SkippedNew
                        ) {
                            continue;
                        }
                        outln!(
                            io,
                            "{:<10}: {}",
                            result.action,
                            simplify_path(&result.file_path, &path_style)
                        );
                    }
                }
                Err(e) => {
                    errorln!(io, "failed to sync diff: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetTemp(cmd::AssetTempCmd { asset_name, count }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;

            use crate::api::types::asset::{
                AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
            };

            let mut remaining = if let Some(count) = count {
                outln!(io, "(newest revisions first)");
                count
            } else {
                1
            };
            let iter_res = match api_client
                .asset_revision_iter(AssetRevisionIterArg {
                    entry_ref: EntryRef::Name(asset_name.clone()),
                    limit: std::cmp::min(10, remaining),
                    direction: RevisionIterDirection::Older,
                })
                .await
            {
                Ok(iter_res) => iter_res,
                Err(e) => {
                    errorln!(io, "failed to get revisions: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            remaining -= iter_res.revisions.len() as u32;
            let mut revision_cursor = iter_res.next.clone();

            let sync_res = asset_sync::sync_down_entries(
                &io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                session
                    .account
                    .as_ref()
                    .map(|a| KeyRecipient::User(a.username.clone())),
                asset_sync::AssetSyncSource::AssetRevision((
                    asset_name.clone(),
                    iter_res.revisions.clone(),
                )),
                None,
                None,
                true,
            )
            .await;
            let mut new_temp_files = vec![];
            for (source, data_temp_file, metadata_temp_file) in sync_res {
                if let Some(data_temp_file) = data_temp_file {
                    outln!(
                        io,
                        "Asset '{}' revision {} data copied to '{}'",
                        asset_name,
                        source.asset.rev_id,
                        data_temp_file.path().display()
                    );
                    new_temp_files.push(data_temp_file);
                }
                if let Some(metadata_temp_file) = metadata_temp_file
                    && let Some(metadata_info) = source.metadata.as_ref()
                {
                    outln!(
                        io,
                        "Asset '{}' revision {} metadata (revision {}) copied to '{}'",
                        asset_name,
                        source.asset.rev_id,
                        metadata_info.rev_id,
                        metadata_temp_file.path().display()
                    );
                    new_temp_files.push(metadata_temp_file);
                }
            }

            loop {
                if remaining == 0 {
                    break;
                }
                if let Some(next) = revision_cursor {
                    let iter_next_res = match api_client
                        .asset_revision_iter_next(AssetRevisionIterNextArg {
                            cursor: next.cursor,
                            limit: std::cmp::min(10, remaining),
                        })
                        .await
                    {
                        Ok(iter_next_res) => iter_next_res,
                        Err(e) => {
                            errorln!(io, "failed to get revisions: {}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    };
                    remaining -= iter_next_res.revisions.len() as u32;
                    revision_cursor = iter_next_res.next;

                    let sync_res = asset_sync::sync_down_entries(
                        &io,
                        asset_blob_cache.clone(),
                        session.asset_keyring.clone(),
                        &api_client,
                        session
                            .account
                            .as_ref()
                            .map(|a| KeyRecipient::User(a.username.clone())),
                        asset_sync::AssetSyncSource::AssetRevision((
                            asset_name.clone(),
                            iter_next_res.revisions.clone(),
                        )),
                        None,
                        None,
                        true,
                    )
                    .await;
                    for (source, data_temp_file, metadata_temp_file) in sync_res {
                        if let Some(data_temp_file) = data_temp_file {
                            outln!(
                                io,
                                "Asset '{}' revision {} data copied to '{}'",
                                asset_name,
                                source.asset.rev_id,
                                data_temp_file.path().display()
                            );
                            new_temp_files.push(data_temp_file);
                        }
                        if let Some(metadata_temp_file) = metadata_temp_file
                            && let Some(metadata_info) = source.metadata.as_ref()
                        {
                            outln!(
                                io,
                                "Asset '{}' revision {} metadata (revision {}) copied to '{}'",
                                asset_name,
                                source.asset.rev_id,
                                metadata_info.rev_id,
                                metadata_temp_file.path().display()
                            );
                            new_temp_files.push(metadata_temp_file);
                        }
                    }
                } else {
                    break;
                }
            }
            ProcessCmdResult::loop_next().with_new_temp_files(new_temp_files)
        }
        cmd::Cmd::AssetRevisionTemp(cmd::AssetRevisionTempCmd { asset_name, rev_id }) => {
            let _username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;

            use api::types::asset::{AssetRevisionGetArg, EntryRef};
            let revision_get_res = match api_client
                .asset_revision_get(AssetRevisionGetArg {
                    entry_ref: EntryRef::Name(asset_name.to_string()),
                    rev_id: Some(rev_id.clone()),
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to get asset revision: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let sync_res = asset_sync::sync_down_entries(
                &io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                session
                    .account
                    .as_ref()
                    .map(|a| KeyRecipient::User(a.username.clone())),
                asset_sync::AssetSyncSource::AssetRevision((
                    asset_name.clone(),
                    vec![revision_get_res.revision.clone()],
                )),
                None,
                None,
                true,
            )
            .await;

            let mut new_temp_files = vec![];
            for (source, data_temp_file, metadata_temp_file) in sync_res {
                if let Some(data_temp_file) = data_temp_file {
                    outln!(
                        io,
                        "Asset '{}' revision {} data copied to '{}'",
                        asset_name,
                        source.asset.rev_id,
                        data_temp_file.path().display()
                    );
                    new_temp_files.push(data_temp_file);
                }
                if let Some(metadata_temp_file) = metadata_temp_file
                    && let Some(metadata_info) = source.metadata.as_ref()
                {
                    outln!(
                        io,
                        "Asset '{}' revision {} metadata (revision {}) copied to '{}'",
                        asset_name,
                        source.asset.rev_id,
                        metadata_info.rev_id,
                        metadata_temp_file.path().display()
                    );
                    new_temp_files.push(metadata_temp_file);
                }
            }
            let revision_header = mk_revision_header(&revision_get_res.revision);
            outln!(io, "\n{}", revision_header);
            ProcessCmdResult::loop_next().with_new_temp_files(new_temp_files)
        }
        cmd::Cmd::AssetAclGet(cmd::AssetAclGetCmd { asset_name }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use api::types::asset::AssetGetArg;
            match api_client
                .asset_get(AssetGetArg {
                    name: asset_name.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    outln!(io, "{}", format_asset_acl(&res.entry.asset, None));
                }
                Err(err) => {
                    errorln!(io, "{}", err);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetAclGetEffective(cmd::AssetAclGetEffectiveCmd { asset_name }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use api::types::asset::{AssetEntryAclGetEffectiveArg, EntryRef};
            match api_client
                .asset_entry_acl_get_effective(AssetEntryAclGetEffectiveArg {
                    entry_ref: EntryRef::Name(asset_name.to_owned()),
                })
                .await
            {
                Ok(res) => {
                    let output = format!(
                        "read-data: {}\nread-revisions: {}\nwrite-data: {}\npush-data: {}",
                        if res.read_data { "true" } else { "false" },
                        if res.read_revisions { "true" } else { "false" },
                        if res.write_data { "true" } else { "false" },
                        if res.push_data { "true" } else { "false" },
                    );
                    outln!(io, "{}", output);
                }
                Err(err) => {
                    errorln!(io, "{}", err);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetAclSet(cmd::AssetAclSetCmd {
            asset_name,
            ace_principal,
            ace_permission,
            ace_effect,
        }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use api::types::asset::{
                AceEffectSet, AssetAcePrincipal, AssetEntryAclSetArg, EntryRef,
            };
            let api_ace_principal = match ace_principal {
                cmd::AssetAcePrincipal::User(ref username) => {
                    AssetAcePrincipal::User(username.clone())
                }
                cmd::AssetAcePrincipal::Everyone => AssetAcePrincipal::Everyone,
            };
            let api_ace_effect = match ace_effect {
                cmd::AssetAceEffect::Allow => AceEffectSet::Allow,
                cmd::AssetAceEffect::Deny => AceEffectSet::Deny,
                cmd::AssetAceEffect::Inherit => AceEffectSet::Inherit,
            };
            let _ = api_client
                .asset_entry_acl_set(AssetEntryAclSetArg {
                    entry_ref: EntryRef::Name(asset_name.to_owned()),
                    principal: api_ace_principal,
                    read_data: if matches!(ace_permission, cmd::AssetAcePermission::ReadData) {
                        Some(api_ace_effect.clone())
                    } else {
                        None
                    },
                    read_revisions: if matches!(
                        ace_permission,
                        cmd::AssetAcePermission::ReadRevisions
                    ) {
                        Some(api_ace_effect.clone())
                    } else {
                        None
                    },
                    write_data: if matches!(ace_permission, cmd::AssetAcePermission::WriteData) {
                        Some(api_ace_effect.clone())
                    } else {
                        None
                    },
                    push_data: if matches!(ace_permission, cmd::AssetAcePermission::PushData) {
                        Some(api_ace_effect.clone())
                    } else {
                        None
                    },
                })
                .await;
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetMdGet(cmd::AssetMdGetCmd { asset_name }) => {
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use crate::api::types::asset::{AssetGetArg, AssetMetadataInfo};
            match api_client.asset_get(AssetGetArg { name: asset_name }).await {
                Ok(res) => {
                    if let Some(AssetMetadataInfo {
                        url: Some(metadata_url),
                        ..
                    }) = res.entry.metadata.as_ref()
                    {
                        match asset_reader::download_with_new_client(metadata_url).await {
                            Ok(contents_bin) => {
                                let contents = String::from_utf8_lossy(&contents_bin);
                                let md_json = serde_json::from_str::<serde_json::Value>(&contents)
                                    .expect("failed to parse metadata");
                                let contents_pretty = serde_json::to_string_pretty(&md_json)
                                    .expect("failed to pretty-print md json");
                                outln!(io, "{}", &contents_pretty);
                            }
                            Err(e) => {
                                errorln!(io, "Failed to download metadata: {}", e);
                            }
                        }
                    } else {
                        outln!(io, "no metadata");
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetMdSet(cmd::AssetMdSetCmd {
            asset_name,
            metadata,
        }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            use crate::api::types::asset::{AssetMetadataPutArg, PutConflictPolicy};
            match api_client
                .asset_metadata_put(AssetMetadataPutArg {
                    name: asset_name,
                    data: metadata.clone(),
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "metadata put failed: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetMdSetKey(cmd::AssetMdSetKeyCmd {
            asset_name,
            key,
            value,
        }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            let value_json = match serde_json::from_str::<serde_json::Value>(&value) {
                Ok(value_json) => value_json,
                Err(e) => {
                    errorln!(io, "not a json value: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            match asset_async_writer::asset_metadata_set_key(
                &api_client,
                &asset_name,
                &key,
                Some(value_json),
            )
            .await
            {
                Ok(_) => {}
                Err(_) => {
                    errorln!(io, "metadata set key failed");
                    return ProcessCmdResult::loop_next();
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetMdDelKey(cmd::AssetMdDelKeyCmd { asset_name, key }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            match asset_async_writer::asset_metadata_set_key(&api_client, &asset_name, &key, None)
                .await
            {
                Ok(_) => {}
                Err(_) => {
                    errorln!(io, "metadata del key failed");
                    return ProcessCmdResult::loop_next();
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetFolderNew(cmd::AssetFolderNewCmd { name }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let asset_name = resolve_asset_name(&io.out, &name, session).await;

            use api::types::asset::AssetFolderCreateArg;
            // Determine AKM before creating the folder so that we don't use
            // its existence as evidence of the AKM choice.
            let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                api_client.clone(),
                Some(&KeyRecipient::User(username.to_string())),
                &asset_name,
                false,
            )
            .await
            {
                Ok(akm_info) => akm_info,
                Err(e) => {
                    match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            errorln!(io, "error: {}", msg);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };
            let folder_create_res = match api_client
                .asset_folder_create(AssetFolderCreateArg {
                    name: asset_name.clone(),
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "error: failed to create folder: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };
            if folder_create_res
                .entry
                .metadata
                .as_ref()
                .map(|md| md.content_encrypted.is_none())
                .unwrap_or(true)
                && let Some(akm_info) = akm_info.as_ref()
            {
                // If this is the first time putting the asset and it's
                // encrypted, store the encryption metadata.
                if let Err(e) = asset_crypt::put_asset_encryption_metadata(
                    &api_client,
                    &folder_create_res.entry.name,
                    &akm_info,
                )
                .await
                {
                    errorln!(io, "failed to put asset encryption metadata: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetFolderCollapse(cmd::AssetFolderCollapseCmd { prefix }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let prefix = asset_helper::expand_pub_asset_name(&prefix, &session.account);

            use api::types::asset::AssetPoolFolderCollapseArg;
            match api_client
                .asset_folder_collapse(AssetPoolFolderCollapseArg { prefix })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    errorln!(io, "failed to collapse folder: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetFolderExpand(cmd::AssetFolderExpandCmd { prefix }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let prefix = asset_helper::expand_pub_asset_name(&prefix, &session.account);

            use api::types::asset::AssetPoolFolderExpandArg;
            match api_client
                .asset_folder_expand(AssetPoolFolderExpandArg { prefix })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    errorln!(io, "failed to expand folder: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetFolderList(cmd::AssetFolderListCmd { prefix }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            let prefix = prefix
                .as_ref()
                .map(|prefix| asset_helper::expand_pub_asset_name(prefix, &session.account));

            use api::types::asset::AssetPoolFolderListArg;
            match api_client
                .asset_folder_list(AssetPoolFolderListArg { prefix })
                .await
            {
                Ok(res) => {
                    warnln!(io, "deprecated: find folders in /asset-list");
                    for folder in res.folders {
                        outln!(io, "{}", folder);
                    }
                }
                Err(e) => {
                    errorln!(io, "failed to list folders: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetCryptSetup => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            match crate::feature::asset_crypt::asset_crypt_setup(
                io,
                asset_blob_cache.clone(),
                api_client.clone(),
                &username,
            )
            .await
            {
                Ok((enc_key_id, sign_key_id, recovery_code)) => {
                    api_client
                        .asset_folder_create(api::types::asset::AssetFolderCreateArg {
                            name: "keys".to_string(),
                        })
                        .await
                        .map_err(|e| {
                            errorln!(io, "failed to create keys folder: {}", e);
                        })
                        .ok();
                    api_client
                        .asset_folder_create(api::types::asset::AssetFolderCreateArg {
                            name: format!("/{}/keys", username),
                        })
                        .await
                        .map_err(|e| {
                            errorln!(io, "failed to create public keys folder: {}", e);
                        })
                        .ok();
                    outln!(io);
                    outln!(
                        io,
                        "╔══════════════════════════════════════════════════════════════╗"
                    );
                    outln!(
                        io,
                        "║                   KEY SETUP COMPLETE                        ║"
                    );
                    outln!(
                        io,
                        "╠══════════════════════════════════════════════════════════════╣"
                    );
                    outln!(
                        io,
                        "║                 ⚠  WRITE THESE DOWN NOW  ⚠                   ║"
                    );
                    outln!(
                        io,
                        "╠══════════════════════════════════════════════════════════════╣"
                    );
                    outln!(io, "║ Encryption Key ID: {:<41} ║", enc_key_id);
                    outln!(io, "║ Signing Key ID:    {:<41} ║", sign_key_id);
                    let was_recording = io.record_off();
                    outln!(io, "║ Recovery Code:     {:<41} ║", recovery_code);
                    io.record_set(was_recording);
                    outln!(
                        io,
                        "╠══════════════════════════════════════════════════════════════╣"
                    );
                    outln!(
                        io,
                        "║  • Store all three values securely offline                   ║"
                    );
                    outln!(
                        io,
                        "║  • Recovery code is the ONLY way to recover your keys        ║"
                    );
                    outln!(
                        io,
                        "║    if you forget your password                               ║"
                    );
                    outln!(
                        io,
                        "║  • Anyone with the recovery code can decrypt your data       ║"
                    );
                    outln!(
                        io,
                        "╚══════════════════════════════════════════════════════════════╝"
                    );
                    outln!(io);
                    outln!(io, "New private assets will be encrypted.");
                }
                Err(crate::feature::asset_crypt::CryptSetupError::Abort) => {
                    errorln!(io, "aborting key setup");
                }
                Err(crate::feature::asset_crypt::CryptSetupError::InvalidPassword) => {
                    errorln!(io, "password cannot be empty");
                }
                Err(crate::feature::asset_crypt::CryptSetupError::PasswordMismatch) => {
                    errorln!(io, "passwords do not match");
                }
                Err(crate::feature::asset_crypt::CryptSetupError::ServerAbort(e)) => {
                    errorln!(io, "aborting key setup: {}", e);
                }
                Err(crate::feature::asset_crypt::CryptSetupError::Other(e)) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetCryptUnlock(cmd::AssetCryptUnlockCmd { enc_key_id }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            match asset_crypt::get_encryption_key(
                asset_blob_cache.clone(),
                &api_client,
                &asset_crypt::KeyRecipient::User(username),
                enc_key_id.as_deref(),
            )
            .await
            {
                Ok(Some(key)) => {
                    let mut asset_keyring_locked = session.asset_keyring.lock().await;
                    let rec_key_id_parts = asset_crypt::RecipientKeyIdParts {
                        recipient: key.recipient.clone(),
                        key_id: key.enc_key_id.clone(),
                        key_type: asset_crypt::KeyType::Encryption,
                    };
                    match asset_keyring_locked
                        .unlock_decrypt_key_with_prompt(
                            io,
                            asset_blob_cache.clone(),
                            &api_client,
                            &rec_key_id_parts,
                        )
                        .await
                    {
                        Ok(()) => {
                            outln!(io, "Key '{}' unlocked", key.enc_key_id);
                        }
                        Err(e) => {
                            errorln!(io, "failed to unlock key: {}", e);
                            return ProcessCmdResult::loop_next();
                        }
                    }
                }
                Ok(None) => {
                    errorln!(io, "encryption key not found");
                }
                Err(e) => {
                    errorln!(io, "failed to get encryption key: {}", e);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetCryptLock(cmd::AssetCryptLockCmd { enc_key_id }) => {
            let _username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let mut asset_keyring_locked = session.asset_keyring.lock().await;
            if let Some(enc_key_id) = enc_key_id {
                asset_keyring_locked.forget_decrypt_key(&enc_key_id);
            } else {
                asset_keyring_locked.forget_all();
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetCryptRecover(cmd::AssetCryptRecoverCmd { enc_key_id }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            // If no key ID provided, try to get it from the default key metadata
            let enc_key_id = match enc_key_id {
                Some(id) => id.to_string(),
                None => {
                    // Try to get key_id from keys/enc.key metadata
                    match asset_reader::get_asset_and_metadata(
                        asset_blob_cache.clone(),
                        &api_client,
                        &format!("/{username}/keys/enc.pub"),
                        true,
                    )
                    .await
                    {
                        Ok((_, Some(md_bytes), _)) => {
                            let md_str = String::from_utf8_lossy(&md_bytes).to_string();
                            if let Ok(md_json_parsed) =
                                serde_json::from_str::<serde_json::Value>(&md_str)
                            {
                                if let Some(s) =
                                    md_json_parsed.get("key_id").and_then(|v| v.as_str())
                                {
                                    s.to_string()
                                } else {
                                    errorln!(io, "fatal: metadata missing `key_id`");
                                    return ProcessCmdResult::loop_next();
                                }
                            } else {
                                errorln!(io, "fatal: failed to parse metadata");
                                return ProcessCmdResult::loop_next();
                            }
                        }
                        Ok((_, None, _)) => {
                            errorln!(io, "Key file has no metadata. Please specify --key-id");
                            return ProcessCmdResult::loop_next();
                        }
                        Err(e) => match e {
                            asset_reader::GetAssetError::BadName => {
                                errorln!(io, "No keys found");
                                return ProcessCmdResult::loop_next();
                            }
                            asset_reader::GetAssetError::DataFetchFailed(e) => {
                                errorln!(io, "fatal: failed to fetch key metadata: {}", e);
                                return ProcessCmdResult::loop_next();
                            }
                        },
                    }
                }
            };

            outln!(io, "Recovering keys for key ID: {}", enc_key_id);
            outln!(io);

            // Prompt for recovery code
            outln!(io, "⚠ Make sure no one can see your screen");
            let recovery_code_str = if let Some(code) = io
                .query(&crate::io::Query::line("Enter recovery code:"))
                .into_option()
            {
                // Remove any whitespace/dashes the user might have included
                code.trim().to_string()
            } else {
                errorln!(io, "aborted");
                return ProcessCmdResult::loop_next();
            };

            if recovery_code_str.is_empty() {
                errorln!(io, "recovery code cannot be empty");
                return ProcessCmdResult::loop_next();
            }

            // Prompt for new password
            let new_password = if let Some(password) = io
                .query(&crate::io::Query::secret_line(
                    "Enter new password to protect keys:",
                ))
                .into_option()
            {
                if password.is_empty() {
                    errorln!(io, "password cannot be empty");
                    return ProcessCmdResult::loop_next();
                }
                let password_verify = io
                    .query(&crate::io::Query::secret_line("Verify new password:"))
                    .into_option();
                if password_verify.as_deref() != Some(&password) {
                    errorln!(io, "passwords do not match");
                    return ProcessCmdResult::loop_next();
                }
                password.into_bytes()
            } else {
                errorln!(io, "password input cancelled");
                return ProcessCmdResult::loop_next();
            };

            outln!(io);
            outln!(io, "Attempting recovery...");

            let bundle = match asset_crypt::asset_crypt_recover(
                asset_blob_cache,
                api_client.clone(),
                &username,
                &enc_key_id,
                &recovery_code_str,
                &new_password,
            )
            .await
            {
                Ok(bundle) => bundle,
                Err(e) => {
                    errorln!(io, "key recovery failed: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let (recovered_enc_id, recovered_sign_id) = bundle.key_ids_hex();

            outln!(io);
            outln!(
                io,
                "╔══════════════════════════════════════════════════════════════╗"
            );
            outln!(
                io,
                "║                   KEY RECOVERY SUCCESSFUL                    ║"
            );
            outln!(
                io,
                "╠══════════════════════════════════════════════════════════════╣"
            );
            outln!(
                io,
                "║ Encryption Key ID: {:8}                                  ║",
                recovered_enc_id
            );
            outln!(
                io,
                "║ Signing Key ID:    {:8}                                  ║",
                recovered_sign_id
            );
            outln!(
                io,
                "╠══════════════════════════════════════════════════════════════╣"
            );
            outln!(
                io,
                "║ Your keys have been re-encrypted with your new password.     ║"
            );
            outln!(
                io,
                "║ Your recovery code remains valid for future recovery.        ║"
            );
            outln!(
                io,
                "╚══════════════════════════════════════════════════════════════╝"
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetApp(cmd::AssetAppCmd {
            asset_name,
            no_open,
            dev_mode,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                Some(account.username.clone())
            } else {
                None
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            let start_app_res = crate::feature::asset_app::start_app_and_launch_browser(
                &io,
                session,
                db.clone(),
                asset_blob_cache.clone(),
                &api_client,
                username.as_deref(),
                update_asset_tx.clone(),
                is_task_mode_step,
                &asset_name,
                None,
                no_open,
                true,
                debug,
                dev_mode.as_deref(),
            )
            .await;
            if let Some(reply_channel) = &cmd_input.reply_channel {
                let _ = reply_channel
                    .send(crate::session::CmdInputReply::Gateway(start_app_res))
                    .await;
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetAppPermsList(cmd::AssetAppPermsListCmd { asset_name }) => {
            let username = if let Some(account) = session.account.as_ref() {
                Some(account.username.clone())
            } else {
                None
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            if let Some(username) = username {
                let perms =
                    crate::db::load_gateway_perms(&*db.lock().await, &username, &asset_name);
                outln!(io, "Permissions for asset app '{}':", asset_name);
                if perms.is_empty() {
                    outln!(io, "  [no permissions]");
                } else {
                    for perm in perms {
                        outln!(io, "  {:?}", perm);
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetAppPermsRevoke(cmd::AssetAppPermsRevokeCmd { asset_name }) => {
            let username = if let Some(account) = session.account.as_ref() {
                Some(account.username.clone())
            } else {
                None
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;
            if let Some(username) = username {
                let _ = crate::db::clear_gateway_perms(&*db.lock().await, &username, &asset_name);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetOpen(cmd::AssetOpenCmd { asset_name }) => {
            let username = if let Some(account) = session.account.as_ref() {
                Some(account.username.clone())
            } else {
                None
            };
            let asset_name = resolve_asset_name(&io.out, &asset_name, session).await;

            let default_asset_app = match asset_reader::get_only_asset_metadata(
                asset_blob_cache.clone(),
                &api_client,
                &asset_name,
                false,
            )
            .await
            {
                Ok((md_contents, _asset_entry)) => md_contents.as_ref().and_then(|md| {
                    let contents: std::borrow::Cow<'_, str> = String::from_utf8_lossy(md);
                    let json: serde_json::Value = serde_json::from_str(&contents).ok()?;
                    let open_with_entry =
                        crate::feature::asset_app::get_best_match_open_with_entry(&json);
                    if let Some(crate::feature::asset_app::OpenWithEntry {
                        handler:
                            crate::feature::asset_app::OpenWithHandler::AssetApp {
                                asset_name: asset_app_name,
                            },
                        ..
                    }) = open_with_entry
                    {
                        Some(asset_app_name)
                    } else {
                        None
                    }
                }),
                Err(e) => match e {
                    asset_reader::GetAssetError::BadName => None,
                    asset_reader::GetAssetError::DataFetchFailed(e) => {
                        errorln!(io, "failed to fetch asset metadata: {}", e);
                        return ProcessCmdResult::loop_next();
                    }
                },
            };

            if let Some(default_asset_app) = default_asset_app {
                crate::feature::asset_app::start_app_and_launch_browser(
                    &io,
                    session,
                    db.clone(),
                    asset_blob_cache.clone(),
                    &api_client,
                    username.as_deref(),
                    update_asset_tx.clone(),
                    is_task_mode_step,
                    &default_asset_app,
                    Some(&asset_name),
                    false,
                    true,
                    debug,
                    None,
                )
                .await;
            } else {
                session
                    .cmd_queue
                    .lock()
                    .await
                    .push_front(session::CmdInput {
                        input: format!("/asset.no_create {}", asset_name),
                        source: session::CmdSource::Internal,
                        reply_channel: None,
                    });
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetPoolNew(cmd::AssetPoolNewCmd { usernames }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            use crate::api::types::asset::AssetPoolCreateSharedArg;
            match api_client
                .asset_pool_create_shared(AssetPoolCreateSharedArg {
                    usernames: usernames.clone(),
                })
                .await
            {
                Ok(res) => {
                    outln!(io, "Asset pool mounted at {}", res.mount_point);
                }
                Err(e) => {
                    errorln!(io, "failed to create asset pool: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Gateway(cmd::GatewayCmd { auth_token }) => {
            let _ = crate::feature::gateway::launch_gateway(
                io,
                crate::repl_remote::ReplRemote::from_session(session),
                db.clone(),
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                api_client.clone(),
                session
                    .account
                    .as_ref()
                    .map(|account| account.username.clone())
                    .as_deref(),
                update_asset_tx.clone(),
                auth_token.clone().as_deref(),
                crate::feature::gateway::DEV_GATEWAY,
                None,
            )
            .await;
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AssetPools => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            match api_client.asset_pool_list(()).await {
                Ok(res) => {
                    if res.pools.is_empty() {
                        outln!(io, "[no asset pools]");
                    } else {
                        for pool in res.pools {
                            if pool.mount_point.starts_with("/s/") {
                                outln!(io, "{}", pool.mount_point);
                            }
                        }
                    }
                }
                Err(_) => {
                    errorln!(io, "failed to list asset pools");
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Chats => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }

            use crate::api::types::asset::{
                AssetEntryListArg, AssetEntryListError, AssetEntryListNextArg, EntryListOrder,
            };
            let mut asset_list_res = match api_client
                .asset_entry_list(AssetEntryListArg {
                    prefix: Some("chat/".to_string()),
                    limit: 5,
                    order: EntryListOrder::Desc,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    match e {
                        api::client::RequestError::Route(AssetEntryListError::Empty) => {
                            outln!(io, "[empty]");
                        }
                        _ => {
                            errorln!(io, "{}", e);
                        }
                    }
                    return ProcessCmdResult::loop_next();
                }
            };

            if asset_list_res.entries.is_empty() {
                outln!(io, "[no saved chats]");
                return ProcessCmdResult::loop_next();
            }

            loop {
                for (index, entry) in asset_list_res.entries.iter().enumerate() {
                    if let Some(title) = entry.metadata.as_ref().and_then(|md| md.title.clone()) {
                        outln!(io, "{}. {} ({})", index, title, entry.name);
                    } else {
                        outln!(io, "{}. {}", index, entry.name);
                    }
                }
                outln!(io);
                if let Some(answer) = io
                    .query(&crate::io::Query::line(
                        "Chat to resume (Press Enter to load more; CTRL+C to stop):",
                    ))
                    .into_option()
                {
                    match answer.trim().parse::<usize>() {
                        Ok(i) if i < asset_list_res.entries.len() => {
                            let asset_name = &asset_list_res.entries[i].name;
                            session
                                .cmd_queue
                                .lock()
                                .await
                                .push_front(session::CmdInput {
                                    input: format!("/chat-resume {}", asset_name),
                                    source: session::CmdSource::Internal,
                                    reply_channel: None,
                                });
                            break;
                        }
                        _ => {
                            // continue looping to load more entries
                        }
                    }
                } else {
                    // CTRL+C pressed, cancel input
                    break;
                }

                if !asset_list_res.has_more {
                    break;
                }
                asset_list_res = match api_client
                    .asset_entry_list_next(AssetEntryListNextArg {
                        cursor: asset_list_res.cursor,
                        limit: 10,
                    })
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        errorln!(io, "{}", e);
                        return ProcessCmdResult::loop_next();
                    }
                };
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::ChatResume(cmd::ChatResumeCmd {
            chat_log_name,
            fork,
        }) => {
            chat_store::resume_chat_from_db_or_asset(
                &io,
                session,
                db,
                asset_blob_cache,
                &api_client,
                chat_log_name.as_deref(),
                fork,
            )
            .await;
            ProcessCmdResult::loop_next().discard_cmd_and_output()
        }
        cmd::Cmd::ChatSave(cmd::ChatSaveCmd {
            chat_log_name,
            fork,
        }) => {
            let username = if let Some(account) = session.account.as_ref() {
                account.username.clone()
            } else {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };
            let resolved_chat_log_name = if let Some(chat_log_name) = chat_log_name {
                Some(chat_log_name)
            } else if !fork && let Some(chat_log_name) = session.chat_log_asset_name.as_ref() {
                Some(chat_log_name.clone())
            } else {
                None
            };
            chat_store::save_chat_as_asset(
                &io,
                session,
                cfg,
                asset_blob_cache,
                update_asset_tx,
                ctrlc_handler,
                bpe_tokenizer,
                &api_client,
                &username,
                resolved_chat_log_name.as_deref(),
                debug,
            )
            .await;
            // Ensure the chat folder exists for better organization.
            // Not ideal that an attempt to create it is made each time even if
            // it's a no-op.
            api_client
                .asset_folder_create(api::types::asset::AssetFolderCreateArg {
                    name: "chat".to_string(),
                })
                .await
                .map_err(|e| {
                    errorln!(io, "failed to create chat folder: {}", e);
                })
                .ok();
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Email(cmd::EmailCmd { subject, body }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            use api::types::messaging::{EmailRecipientSendArg, EmailRecipientSendError};
            match api_client
                .messaging_email_recipient_send(EmailRecipientSendArg {
                    subject: subject.clone(),
                    email: None,
                    body: body.clone(),
                })
                .await
            {
                Ok(_) => {
                    outln!(io, "ok");
                }
                Err(e) => {
                    if let RequestError::Route(EmailRecipientSendError::NoDefaultRecipient) = e {
                        errorln!(io, "Use `/task hai/add-email` to add an email recipient");
                    } else {
                        errorln!(io, "failed to send email: {}", e);
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Notif(cmd::NotifCmd { title, body }) => {
            if session.account.is_none() {
                errorln!(io, "{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            }
            use api::types::messaging::{PushNotifSendArg, PushNotifSendError};
            match api_client
                .messaging_push_notif_send(PushNotifSendArg { title, body })
                .await
            {
                Ok(_) => {
                    outln!(io, "ok");
                }
                Err(e) => {
                    let err_msg = match e {
                        RequestError::Route(PushNotifSendError::NoActiveDevices) => {
                            "no registered device; please set up the mobile app".to_string()
                        }
                        _ => format!("failed to send notification: {}", e),
                    };
                    errorln!(io, "{}", err_msg);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Fns => {
            if session.ai_defined_fns.is_empty() {
                outln!(io, "No AI-defined functions available.");
            } else {
                outln!(io, "Available AI-defined functions:");
                outln!(io);
                for (fn_name, ai_defined_fn) in &session.ai_defined_fns {
                    outln!(io, "- /{}", fn_name);
                    outln!(io, "{}", ai_defined_fn.0.fn_def);
                    outln!(io);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Std(std_cmd) => {
            match std_cmd {
                cmd::StdCmd::Now => {
                    let now = chrono::Local::now();
                    let utc_now = chrono::Utc::now();
                    let local_tz = now.offset();
                    let output = format!(
                        "Local datetime ({}): {}\nUTC datetime: {}\n",
                        local_tz,
                        now.format("%Y-%m-%d %H:%M:%S"),
                        utc_now.format("%Y-%m-%d %H:%M:%S"),
                    );
                    outln!(io, "{}", output);
                }
                cmd::StdCmd::NewDayAlert => {
                    session.add_msg_on_new_day = true;
                }
                cmd::StdCmd::Which(prog) => {
                    session.add_msg_on_new_day = true;
                    match which::which(&prog) {
                        Ok(path) => {
                            outln!(io, "{}", path.display().to_string());
                        }
                        Err(which::Error::CannotFindBinaryPath) => {
                            errorln!(io, "'{}' not found", prog);
                        }
                        Err(e) => {
                            errorln!(io, "could not find {}: {}", prog, e);
                        }
                    };
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::FnExec(cmd::FnExecCmd { fn_name, arg }) => {
            let ai_defined_fn =
                if let Some((ai_defined_fn, _)) = session.ai_defined_fns.get(&fn_name) {
                    ai_defined_fn
                } else {
                    errorln!(io, "function '{}' is undefined", fn_name);
                    return ProcessCmdResult::loop_next();
                };

            let arg_with_default = if arg.is_empty()
                && matches!(
                    ai_defined_fn.fn_tool.kind,
                    tool::FnToolType::FnPy | tool::FnToolType::FnPyUv
                ) {
                "None".to_string()
            } else {
                arg.clone()
            };

            // Execute AI-defined tool/function
            match tool::execute_ai_defined_tool(
                &io.out,
                &ai_defined_fn.fn_tool,
                &ai_defined_fn.fn_def,
                &arg_with_default,
                Some(&session.get_shell_exec_env_vars()),
            )
            .await
            {
                Ok(_output) => {
                    // Output is ignored since it prints via io.out already
                    // which goes into the recorded transcript.
                }
                Err(e) => {
                    errorln!(io, "failed to execute tool: {}", e);
                }
            };
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::McpAdd(cmd::McpAddCmd { name, cmd }) => {
            let (mcp_service, mcp_tools) = match crate::feature::mcp::init_mcp(&io.out, &cmd).await
            {
                Some(res) => res,
                None => {
                    errorln!(io, "failed to initialize MCP service");
                    return ProcessCmdResult::loop_next();
                }
            };
            let full_name = format!("mcp_{}", name);
            session.add_mcp(&full_name, mcp_service, is_task_mode_step);

            let tools_str =
                serde_json::to_string_pretty(&mcp_tools).expect("Failed to serialize tools");

            outln!(
                io,
                "{}\n\nMCP service '{}' added. Call with: \n\n    /{} <mcp_tool> <json_arg>\n",
                tools_str,
                name,
                full_name
            );

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::McpToolCall(cmd::McpToolCallCmd {
            name,
            tool_name,
            json_arg,
        }) => {
            let (mcp_service, _) = if let Some(res) = session.mcps.get(&name) {
                res
            } else {
                errorln!(io, "no MCP service named '{}'", name);
                return ProcessCmdResult::loop_next();
            };

            let arg = match serde_json::from_str(&json_arg) {
                Ok(arg) => arg,
                Err(e) => {
                    errorln!(io, "failed to parse JSON argument: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use rmcp::model::CallToolRequestParams;

            let tool_call_res = match mcp_service
                .call_tool(CallToolRequestParams {
                    meta: None,
                    name: tool_name.clone().into(),
                    arguments: arg,
                    task: None,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to call MCP tool: {}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let tool_call_res_content = tool_call_res
                .content
                .iter()
                .filter_map(|c| match &c.raw {
                    rmcp::model::RawContent::Text(t) => Some(t.text.as_str()),
                    rmcp::model::RawContent::Image(_) => None,
                    rmcp::model::RawContent::Audio(_) => None,
                    rmcp::model::RawContent::Resource(_) => None,
                    rmcp::model::RawContent::ResourceLink(_) => None,
                })
                .collect::<Vec<_>>()
                .join("\n");

            outln!(io, "{}", tool_call_res_content);
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::BotBoot(cmd::BotBootCmd { hai_version }) => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            outln!(io, "Booting bot...");
            let (key_id, pub_key, _priv_key) = match asset_crypt::get_ed25519_for_ssh_key(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to unlock keyring: {:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use crate::api::types::bot::BootArg;
            let boot_res = match api_client
                .bot_boot(BootArg {
                    pub_key: pub_key.clone(),
                    pub_key_id: key_id.clone(),
                    hai_version,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            outln!(io);
            outln!(
                io,
                "╔══════════════════════════════════════════════════════════════╗"
            );
            outln!(
                io,
                "║                        BOT BOOTED                            ║"
            );
            outln!(
                io,
                "╠══════════════════════════════════════════════════════════════╣"
            );
            outln!(io, "║ Bot ID:          {:<43} ║", boot_res.bot.bot_id);
            outln!(io, "║ Hostname:        {:<43} ║", boot_res.bot.hostname);
            outln!(
                io,
                "║ Vanity Hostname: {:<43} ║",
                boot_res.bot.vanity_hostname.unwrap_or("[none]".to_string())
            );
            outln!(
                io,
                "╠══════════════════════════════════════════════════════════════╣"
            );
            outln!(
                io,
                "║                        NEXT STEP                             ║"
            );
            outln!(
                io,
                "║  Setting up bot...                                           ║"
            );
            outln!(
                io,
                "╚══════════════════════════════════════════════════════════════╝"
            );
            outln!(io);

            ProcessCmdResult::loop_next().with_new_cmds(vec![session::CmdInput {
                input: "/bot-probe".to_string(),
                source: session::CmdSource::Internal,
                reply_channel: None,
            }])
        }
        cmd::Cmd::BotGetActive => {
            let _username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let get_res = match api_client.bot_get_active(()).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            if let Some(bot) = get_res.bot {
                outln!(io, "Bot ID: {}", bot.bot_id);
                outln!(io, "Hostname: {}", bot.hostname);
                outln!(io, "Booted At: {}", bot.booted_at);
            } else {
                errorln!(io, "no active bots");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::BotProbe => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let get_res = match api_client.bot_get_active(()).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let hostname = if let Some(bot) = get_res.bot {
                outln!(io, "Bot ID: {}", bot.bot_id);
                outln!(io, "Hostname: {}", bot.hostname);
                outln!(io, "Booted At: {}", bot.booted_at);
                bot.hostname
            } else {
                errorln!(io, "no active bots");
                return ProcessCmdResult::loop_next();
            };

            let (_key_id, _pub_key, priv_key) = match asset_crypt::get_ed25519_for_ssh_key(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to unlock keyring: {:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use crate::feature::haibot;

            let mut client = match haibot::Session::connect(&hostname, 22, "hai", priv_key).await {
                Ok(client) => client,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let _ = client.call_streaming("~/.local/bin/hai -V").await;
            let _ = client.close().await;

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::BotSetup => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let get_res = match api_client.bot_get_active(()).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let hostname = if let Some(bot) = get_res.bot {
                outln!(io, "bot: id={}: ssh hai@{}", bot.bot_id, bot.hostname);
                bot.hostname
            } else {
                errorln!(io, "no active bots");
                return ProcessCmdResult::loop_next();
            };

            let (_key_id, _pub_key, priv_key) = match asset_crypt::get_ed25519_for_ssh_key(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to unlock keyring: {:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use crate::feature::haibot;

            let mut client = match haibot::Session::connect(&hostname, 22, "hai", priv_key).await {
                Ok(client) => client,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            outln!(io);
            outln!(
                io,
                "╔══════════════════════════════════════════════════════════════╗"
            );
            outln!(
                io,
                "║                      CONNECTED TO BOT                        ║"
            );
            outln!(
                io,
                "╠══════════════════════════════════════════════════════════════╣"
            );
            outln!(
                io,
                "║                     UPCOMING BOT SETUP                       ║"
            );
            outln!(
                io,
                "║                                                              ║"
            );
            outln!(
                io,
                "║  1. Copy your hai.toml config to your bot                    ║"
            );
            outln!(
                io,
                "║  2. Login to your hai account                                ║"
            );
            outln!(
                io,
                "║  3. Unlock your asset encryption key                         ║"
            );
            outln!(
                io,
                "╚══════════════════════════════════════════════════════════════╝"
            );
            outln!(io);

            let _ = client.call("mkdir -p /home/hai/.hai").await;
            outln!(io, "Copying hai.toml config...");
            let _ = client
                .upload(config::get_default_config_path(), "/home/hai/.hai/hai.toml")
                .await;
            outln!(io, "Logging into your hai account ({})...", username);
            let _ = client
                .call_interactive(&format!("~/.local/bin/hai login {}", username))
                .await;
            outln!(io, "Unlocking your asset encryption key...");
            let _ = client
                .call_interactive(&format!("~/.local/bin/hai bye /asset-crypt-unlock"))
                .await;
            if matches!(
                session.use_hai_router,
                session::HaiRouterState::On | session::HaiRouterState::OffForModel
            ) {
                outln!(io, "Turning on hai-router...");
                let _ = client
                    .call(&format!("~/.local/bin/hai bye '/hai-router on'"))
                    .await;
            }
            outln!(io, "Running haibot...");
            let _ = client
                .call_interactive(&format!("~/.local/bin/hai bot start -d"))
                .await;
            let _ = client.close().await;

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::BotSsh => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            let get_res = match api_client.bot_get_active(()).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let hostname = if let Some(bot) = get_res.bot {
                outln!(io, "bot: id={}: ssh hai@{}", bot.bot_id, bot.hostname);
                bot.hostname
            } else {
                errorln!(io, "no active bots");
                return ProcessCmdResult::loop_next();
            };

            let (_key_id, _pub_key, priv_key) = match asset_crypt::get_ed25519_for_ssh_key(
                io,
                asset_blob_cache.clone(),
                session.asset_keyring.clone(),
                &api_client,
                &username,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "failed to unlock keyring: {:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            use crate::feature::haibot;

            let mut client = match haibot::Session::connect(&hostname, 22, "hai", priv_key).await {
                Ok(client) => client,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            let _ = client.call_interactive("/usr/bin/bash").await;
            let _ = client.close().await;

            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::BotShutdown => {
            let _username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                errorln!(io, "{}", BOT_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::loop_next();
            };

            use crate::api::types::bot::ShutdownArg;

            let get_res = match api_client.bot_get_active(()).await {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "{:?}", e);
                    return ProcessCmdResult::loop_next();
                }
            };

            if let Some(bot) = get_res.bot {
                let _ = match api_client
                    .bot_shutdown(ShutdownArg { bot_id: bot.bot_id })
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        errorln!(io, "{:?}", e);
                        return ProcessCmdResult::loop_next();
                    }
                };
            } else {
                errorln!(io, "no active bots");
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Account(cmd::AccountCmd { username }) => {
            if let Some(username) = username {
                if username == "_" {
                    session::account_nobody_setup_session(session, db).await;
                } else {
                    let account = match db::switch_account(&*db.lock().await, &username) {
                        Ok(Some(account)) => account,
                        Ok(None) => {
                            errorln!(io, "{} credentials not found; try /account-login", username);
                            return ProcessCmdResult::loop_next();
                        }
                        Err(_) => {
                            errorln!(io, "failed to read db");
                            return ProcessCmdResult::loop_next();
                        }
                    };
                    outln!(io, "ハイ {}!", account.username);
                    session::account_login_setup_session(
                        &io.out,
                        session,
                        db,
                        &account.user_id,
                        &account.username,
                        &account.token,
                    )
                    .await;
                }
            } else {
                if let Some(account) = &session.account {
                    outln!(io, "ハイ {}!", account.username);
                } else {
                    outln!(
                        io,
                        "You have not logged into an account. Try /account-login"
                    );
                };
                match db::list_accounts(&*db.lock().await) {
                    Ok(usernames) => {
                        if !usernames.is_empty() {
                            let was_recording = io.record_off();
                            outln!(io);
                            outln!(io, "Available accounts (Try /account <username>):");
                            for username in usernames {
                                outln!(io, "- {}", username);
                            }
                            io.record_set(was_recording);
                        }
                    }
                    Err(_) => {
                        errorln!(io, "failed to read db");
                    }
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AccountNew => {
            let mut username;
            loop {
                username = match io.query(&crate::io::Query::line("Username?")).into_option() {
                    Some(username) => username,
                    None => return ProcessCmdResult::loop_next(),
                };
                if username.len() == 0 {
                    // Assume the user wants to cancel the account creation by
                    // pressing Enter without entering a username.
                    return ProcessCmdResult::loop_next();
                } else if username.len() >= 3 {
                    break;
                } else {
                    outln!(io, "Username must be at least 3 characters")
                }
            }
            let mut password;
            loop {
                password = match io
                    .query(&crate::io::Query::secret_line("Password?").with_record_answer(false))
                    .into_option()
                {
                    Some(password) => password,
                    None => return ProcessCmdResult::loop_next(),
                };
                if password.len() >= 8 {
                    break;
                } else {
                    outln!(io, "Password must be at least 8 characters")
                }
            }
            let email_answer = match io
                .query(&crate::io::Query::line(
                    "Email (optional: if you forget your password)?",
                ))
                .into_option()
            {
                Some(email_answer) => email_answer,
                None => return ProcessCmdResult::loop_next(),
            };
            let email = if email_answer.trim().is_empty() {
                None
            } else {
                Some(email_answer.trim().to_string())
            };
            outln!(
                io,
                "Read our terms of service: `/cat /hai/terms-of-service`"
            );

            let terms_answer = match io
                .query(&crate::io::Query::confirm(
                    "Accept terms of service? (Type 'yes')",
                ))
                .into_option()
            {
                Some(terms_answer) => terms_answer,
                None => return ProcessCmdResult::loop_next(),
            };
            if terms_answer != "y" && terms_answer != "yes" {
                errorln!(io, "Awkward...");
                return ProcessCmdResult::loop_next();
            }

            use api::types::account::AccountRegisterArg;
            let logged_out_api_client = mk_api_client(None);
            match logged_out_api_client
                .account_register(AccountRegisterArg {
                    username,
                    password,
                    email,
                })
                .await
            {
                Ok(res) => {
                    outln!(io, "ハイ {}!", res.username);
                    db::login_account(&*db.lock().await, &res.user_id, &res.username, &res.token)
                        .expect("failed to write login info");
                    session.account = Some(db::Account {
                        user_id: res.user_id,
                        username: res.username,
                        token: res.token,
                    });
                    outln!(io, "\nSetting up your inbox...");
                    let mut cmd_queue = session.cmd_queue.lock().await;
                    cmd_queue.push_front(session::CmdInput {
                        input: "/inbox-setup".to_string(),
                        source: session::CmdSource::Internal,
                        reply_channel: None,
                    });
                }
                Err(e) => {
                    errorln!(io, "error: {}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AccountLogin(cmd::AccountLoginCmd { username, password }) => {
            let username = if let Some(username) = username {
                username.to_owned()
            } else {
                match io.query(&crate::io::Query::line("Username?")).into_option() {
                    Some(username) => username,
                    None => return ProcessCmdResult::loop_next(),
                }
            };
            let password = if let Some(password) = password {
                password.to_owned()
            } else {
                match io
                    .query(&crate::io::Query::secret_line("Password?").with_record_answer(false))
                    .into_option()
                {
                    Some(password) => password,
                    None => return ProcessCmdResult::loop_next(),
                }
            };
            use api::types::account::AccountTokenFromLoginArg;
            let logged_out_api_client = mk_api_client(None);
            match logged_out_api_client
                .account_token_from_login(AccountTokenFromLoginArg { username, password })
                .await
            {
                Ok(res) => {
                    outln!(io, "ハイ {}!", res.username);
                    session::account_login_setup_session(
                        &io.out,
                        session,
                        db.clone(),
                        &res.user_id,
                        &res.username,
                        &res.token,
                    )
                    .await;
                    let new_api_client = mk_api_client(Some(session));
                    match new_api_client.account_get_balance(()).await {
                        Ok(balance_res) => {
                            if balance_res.remaining > 0 {
                                hai_router_try_activate(session);
                                db::set_misc_entry(
                                    &*db.lock().await,
                                    &res.username,
                                    "hai-router",
                                    "on",
                                )
                                .expect("failed to write to db");
                            }
                        }
                        Err(_) => {
                            errorln!(io, "could not fetch balance");
                        }
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AccountBalance => {
            match api_client.account_get_balance(()).await {
                Ok(res) => {
                    outln!(
                        io,
                        "Remaining balance: ${:.2}",
                        res.remaining as f64 / 100.0
                    );
                }
                Err(_) => {
                    errorln!(io, "could not fetch balance");
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::AccountSubscribe => {
            match &session.account {
                Some(account) => account,
                None => {
                    errorln!(
                        io,
                        "You must be logged-in to subscribe. Try /account-login or /account-new"
                    );
                    return ProcessCmdResult::loop_next();
                }
            };
            let subscribe_link = match api_client.account_get_subscribe_link(()).await {
                Ok(res) => res.subscribe_link,
                Err(_) => {
                    outln!(io, "You're already subscribed.");
                    outln!(
                        io,
                        "Need more credits? Email me at ken@elkabany.com for help (sorry for the manual process)"
                    );
                    return ProcessCmdResult::loop_next();
                }
            };
            outln!(io, "Subscribe to the hai basic plan ($6 USD / month):");
            outln!(
                io,
                "- $3 USD in AI credits that can be used across OpenAI, Anthropic, Google, Deepseek, xAI"
            );
            outln!(
                io,
                "  - Use `/ai <model>` without having to provide your own API keys"
            );
            outln!(io, "  - Unused credits expire after two months");
            outln!(io, "- 10 GB of asset storage and public link sharing");
            outln!(io, "- Send 1,000 emails per day with /email");
            outln!(
                io,
                "- An easy way to support the hai project and its ongoing experimentation"
            );
            outln!(io, "");
            outln!(io, "Subscribe with the Stripe link below:");
            outln!(io, "");
            outln!(io, "{}", subscribe_link);
            outln!(io, "");
            outln!(io, "- The business is \"Superego / Intertimes, Inc.\"");
            outln!(io, "  hai is a side project of the company");
            outln!(io, "");
            outln!(
                io,
                "After subscribing, run `/hai-router on`. The 🌐 icon means you're using credits instead of your personal API keys."
            );
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::InboxSetup => {
            match &session.account {
                Some(account) => account,
                None => {
                    errorln!(
                        io,
                        "You must be logged-in to setup your inbox. Try /account-login or /account-new"
                    );
                    return ProcessCmdResult::loop_next();
                }
            };
            ProcessCmdResult::loop_next().with_new_cmds(vec![
                session::CmdInput {
                    input: "/asset-push //inbox\n{}".to_string(),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                },
                session::CmdInput {
                    input: "/asset-acl-set //inbox everyone deny:read-data".to_string(),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                },
                session::CmdInput {
                    input: "/asset-acl-set //inbox everyone allow:push-data".to_string(),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                },
                session::CmdInput {
                    input: "/asset-md-set-key //inbox content_type \"application/json\""
                        .to_string(),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                },
            ])
        }
        cmd::Cmd::AccountLogout(cmd::AccountLogoutCmd { username }) => {
            if let Some(cur_account) = &session.account {
                let target_username = username.as_ref().unwrap_or(&cur_account.username);
                let _ = db::remove_account(&*db.lock().await, target_username);
                session::account_nobody_setup_session(session, db).await;
            } else {
                // no-op since not logged-in
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Whois(cmd::WhoisCmd { username }) => {
            use api::types::account::AccountWhoisArg;
            match api_client
                .account_whois(AccountWhoisArg {
                    username: username.clone(),
                })
                .await
            {
                Ok(res) => {
                    let mut whois_lines = vec![];

                    whois_lines.push(format!("Username: {}", res.username));

                    let naive_datetime =
                        chrono::NaiveDateTime::parse_from_str(&res.joined_on, "%Y-%m-%dT%H:%M:%SZ")
                            .expect("Failed to parse datetime");

                    let date_only = naive_datetime.format("%Y-%m-%d").to_string();
                    whois_lines.push(format!("Joined: {}", date_only));

                    if let Some(name) = res.name {
                        whois_lines.push(format!("Name: {}", name));
                    }
                    if let Some(bio) = res.bio {
                        whois_lines.push(format!("Bio: {}", bio));
                    }
                    whois_lines.push("".to_string());
                    whois_lines.push("Published Tasks:".to_string());

                    if res.tasks.is_empty() {
                        whois_lines.push("—".to_string());
                    } else {
                        for task in &res.tasks {
                            whois_lines.push(task.task_fqn.to_string());
                        }
                        whois_lines.push("".to_string());
                        whois_lines.push("Use `/task-cat <task_name>` to learn more".to_string());
                    }
                    let whois_output = whois_lines.join("\n");
                    outln!(io, "{}", whois_output);
                    if let Some(account) = &session.account
                        && account.username == username
                    {
                        outln!(io);
                        outln!(io, "To set a name or bio, run: `/task hai/account-update`");
                    }
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::WebSearch(cmd::WebSearchCmd {
            q,
            n,
            pd,
            pw,
            pm,
            py,
            range,
        }) => {
            use api::types::web::{BraveFreshness, BraveSearchArg};
            let freshness = if pd {
                Some(BraveFreshness::Pd)
            } else if pw {
                Some(BraveFreshness::Pw)
            } else if pm {
                Some(BraveFreshness::Pm)
            } else if py {
                Some(BraveFreshness::Py)
            } else if let Some(range) = range {
                Some(BraveFreshness::Custom(range.clone()))
            } else {
                None
            };
            match api_client
                .web_brave_search(BraveSearchArg {
                    q,
                    count: n,
                    freshness,
                })
                .await
            {
                Ok(res) => {
                    let mut output = String::new();
                    for (i, result) in res.grounding.generic.iter().enumerate() {
                        output.push_str(&format!("{}. {}\n", i + 1, result.title));
                        output.push_str(&format!("   {}\n", result.url));
                        for (j, snippet) in result.snippets.iter().enumerate() {
                            output.push_str(&format!("   {}. {}\n", j + 1, snippet));
                        }
                        output.push_str("\n");
                    }

                    outln!(io, "{}", output);
                }
                Err(e) => {
                    errorln!(io, "{}", e);
                }
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::Cost => {
            fn print_ai_model_prices(io: &Io, ai: &config::AiModel) {
                if let Some((input_cost_in_mills_per_million, output_cost_in_mills_per_million)) =
                    config::get_ai_model_cost(ai)
                {
                    outln!(
                        io,
                        "{:<24} {:<24} {}",
                        config::get_ai_model_display_name(ai),
                        config::mills_to_dollars(input_cost_in_mills_per_million),
                        config::mills_to_dollars(output_cost_in_mills_per_million)
                    )
                }
            }

            let mut agg_output_tokens = 0;
            let mut agg_input_tokens = 0;
            let mut cur_input_tokens = 0;
            for log in &session.history {
                if matches!(log.message.role, chat::MessageRole::Assistant) {
                    // AI was prompted, so compute cost
                    agg_output_tokens += log.tokens;
                    agg_input_tokens += cur_input_tokens;

                    // The AI output becomes part of the next input
                    cur_input_tokens += log.tokens;
                } else {
                    // AI wasn't prompted, so only increment input token count
                    cur_input_tokens += log.tokens;
                }
            }
            if let Some((input_cost_in_mills_per_million, output_cost_in_mills_per_million)) =
                config::get_ai_model_cost(&session.ai)
            {
                let agg_input_mills = ((input_cost_in_mills_per_million as f64)
                    * (agg_input_tokens as f64 / 1_000_000.0))
                    as u32;
                let agg_output_mills = ((output_cost_in_mills_per_million as f64)
                    * (agg_output_tokens as f64 / 1_000_000.0))
                    as u32;
                let agg_mills = agg_input_mills + agg_output_mills;
                let agg_output_cost = config::mills_to_dollars(agg_output_mills);
                let agg_input_cost = config::mills_to_dollars(agg_input_mills);
                let agg_cost = config::mills_to_dollars(agg_mills);

                outln!(
                    io,
                    "=== Cost is *approximate* based on active model ({}) and GPT-3 tokenization ===",
                    config::get_ai_model_display_name(&session.ai)
                );
                outln!(io);
                let cur_input_context_cost = config::mills_to_dollars(
                    ((input_cost_in_mills_per_million as f64)
                        * (cur_input_tokens as f64 / 1_000_000.0)) as u32,
                );
                outln!(
                    io,
                    "Your next prompt to the AI will have an input cost of: {} ({} tokens)",
                    cur_input_context_cost,
                    cur_input_tokens.to_formatted_string(&Locale::en)
                );
                outln!(io);
                outln!(io, "This conversation has so far cost: {}", agg_cost);
                outln!(
                    io,
                    "    input: {} ({} tokens)    output: {} ({} tokens)",
                    agg_input_cost,
                    agg_input_tokens.to_formatted_string(&Locale::en),
                    agg_output_cost,
                    agg_output_tokens.to_formatted_string(&Locale::en)
                );
            } else {
                outln!(
                    io,
                    "=== No price data for {} ===",
                    config::get_ai_model_display_name(&session.ai)
                );
                outln!(io, "This conversation has used this many tokens:");
                outln!(
                    io,
                    "    input: {} tokens      output: {} tokens",
                    agg_input_tokens.to_formatted_string(&Locale::en),
                    agg_output_tokens.to_formatted_string(&Locale::en)
                );
            }
            if !is_task_mode_step {
                // If a task is being initialized, don't include this extra
                // info since the task is probably just trying to make the user
                // aware of the cost of their first call with the current
                // model.
                let was_recording = io.record_off();
                outln!(io);
                outln!(io, "=== Popular model prices ===");
                outln!(
                    io,
                    "{:<24} {:<24} Per 1M output tokens",
                    "Model",
                    "Per 1M input tokens"
                );
                for ai in [
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt5(config::Gpt5Options {
                        reasoning_effort: None,
                        verbosity: None,
                    })),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt5Mini(config::Gpt5Options {
                        reasoning_effort: None,
                        verbosity: None,
                    })),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt5Nano(config::Gpt5Options {
                        reasoning_effort: None,
                        verbosity: None,
                    })),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt41),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt41Mini),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4o),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4oMini),
                    config::AiModel::OpenAi(config::OpenAiModel::O3),
                    config::AiModel::OpenAi(config::OpenAiModel::O4Mini),
                    config::AiModel::Google(config::GoogleModel::Gemini3Flash(
                        config::GeminiOptions {
                            thinking_level: None,
                        },
                    )),
                    config::AiModel::Google(config::GoogleModel::Gemini3Pro(
                        config::GeminiOptions {
                            thinking_level: None,
                        },
                    )),
                    config::AiModel::Anthropic(config::AnthropicModel::Sonnet45(false)),
                    config::AiModel::Anthropic(config::AnthropicModel::Opus45(false)),
                    config::AiModel::Anthropic(config::AnthropicModel::Haiku35),
                    config::AiModel::DeepSeek(config::DeepSeekModel::DeepSeekChat),
                    config::AiModel::DeepSeek(config::DeepSeekModel::DeepSeekReasoner),
                    config::AiModel::Xai(config::XaiModel::Grok4),
                ] {
                    print_ai_model_prices(io, &ai);
                }
                io.record_set(was_recording);
            }
            ProcessCmdResult::loop_next()
        }
        cmd::Cmd::QueuePop(cmd::QueuePopCmd { queue_name }) => {
            let cmds = db::listen_queue_pop(
                &mut *db.lock().await,
                queue_name.as_ref().unwrap_or(&"".to_string()),
            )
            .expect("failed to pop from queue");
            if let Some(cmds) = cmds {
                let mut new_cmds = vec![session::CmdInput {
                    input: "/new".to_string(),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                }];
                for (index, cmd) in cmds.iter().enumerate() {
                    new_cmds.push(session::CmdInput {
                        input: cmd.clone(),
                        source: session::CmdSource::ListenQueue(queue_name.clone(), index as u32),
                        reply_channel: None,
                    });
                }
                ProcessCmdResult::loop_next().with_new_cmds(new_cmds)
            } else {
                ProcessCmdResult::loop_next()
            }
        }
        cmd::Cmd::ToolMode(tool_mode_cmd) => {
            let was_recording = io.record_off();
            outln!(
                io,
                "Entering tool mode; All messages are treated as prompts for {}. Use `!exit` or CTRL+D when done",
                tool::tool_to_cmd(
                    &tool_mode_cmd.tool,
                    tool_mode_cmd.user_confirmation,
                    tool_mode_cmd.force_tool
                )
            );
            io.record_set(was_recording);
            ProcessCmdResult::loop_next().with_tool_mode_cmd(Some(Some(tool_mode_cmd)))
        }
        cmd::Cmd::ToolModeExit => ProcessCmdResult::loop_next().with_tool_mode_cmd(Some(None)),
        cmd::Cmd::Prompt(cmd::PromptCmd { prompt, cache })
        | cmd::Cmd::Tool(cmd::ToolCmd { prompt, cache, .. }) => {
            ProcessCmdResult::prompt_ai(prompt.to_owned(), cache)
        }
    }
}

// --

pub enum ReplaceResult {
    /// New content with replacement
    Success(String),
    /// No matches found
    NoMatch,
    /// Multiple matches found
    MultipleMatches(Vec<String>),
}

pub fn search_and_replace(
    content: &str,
    search: &str,
    replace: &str,
    context_lines: usize,
) -> ReplaceResult {
    if search.is_empty() {
        return ReplaceResult::NoMatch;
    }

    // Find all match positions where the match spans entire line(s):
    // - the match must start at the start of a line (col 0, including indentation)
    // - the match must end at the end of a line (at a newline or end of content)
    let matches: Vec<usize> = content
        .match_indices(search)
        .filter(|&(idx, _)| {
            // Check start: must be at start of content or right after a newline
            let starts_at_line = idx == 0 || content.as_bytes()[idx - 1] == b'\n';

            // Check end: must be at end of content or right before a newline
            let end = idx + search.len();
            let ends_at_line = end == content.len() || content.as_bytes()[end] == b'\n';

            starts_at_line && ends_at_line
        })
        .map(|(idx, _)| idx)
        .collect();

    match matches.len() {
        0 => ReplaceResult::NoMatch,
        1 => {
            let idx = matches[0];
            let mut new_content =
                String::with_capacity(content.len() - search.len() + replace.len());
            new_content.push_str(&content[..idx]);
            new_content.push_str(replace);
            new_content.push_str(&content[idx + search.len()..]);
            ReplaceResult::Success(new_content)
        }
        // More than one match found
        _ => {
            let lines: Vec<&str> = content.lines().collect();

            // Build byte offset -> line number mapping
            let mut line_starts: Vec<usize> = vec![0];
            for (i, line) in lines.iter().enumerate() {
                if i < lines.len() - 1 {
                    line_starts.push(line_starts.last().unwrap() + line.len() + 1);
                }
            }

            let contexts: Vec<String> = matches
                .iter()
                .map(|&byte_offset| {
                    let match_line = line_starts
                        .iter()
                        .position(|&start| start > byte_offset)
                        .map(|p| p - 1)
                        .unwrap_or(lines.len() - 1);

                    let start_line = match_line.saturating_sub(context_lines);
                    let end_line = (match_line + context_lines + 1).min(lines.len());

                    lines[start_line..end_line].join("\n")
                })
                .collect();

            ReplaceResult::MultipleMatches(contexts)
        }
    }
}

// --

#[allow(dead_code)]
fn detect_style_and_simplify_path(stylist: &str, path: &str) -> String {
    let style = detect_path_style(stylist);
    simplify_path(path, &style)
}

enum PathStyle {
    Relative, // user typed "src/ab" or "./src/ab" or "../ab"
    Tilde,    // user typed "~/src/ab"
    Absolute, // user typed "/Users/ken/src/ab"
}

fn detect_path_style(input: &str) -> PathStyle {
    if input.starts_with('~') {
        PathStyle::Tilde
    } else if input.starts_with('/') {
        PathStyle::Absolute
    } else {
        PathStyle::Relative
    }
}

fn simplify_path(abs_path: &str, style: &PathStyle) -> String {
    let p = std::path::Path::new(abs_path);

    match style {
        PathStyle::Relative => {
            if let Ok(cwd) = std::env::current_dir() {
                if let Ok(rel) = p.strip_prefix(&cwd) {
                    if rel.as_os_str().is_empty() {
                        return ".".to_string();
                    }
                    return rel.to_string_lossy().into_owned();
                }
            }
            // Not under cwd — leave it absolute rather than forcing it.
            abs_path.to_string()
        }
        PathStyle::Tilde => {
            if let Ok(home) = std::env::var("HOME") {
                if let Ok(rest) = p.strip_prefix(&home) {
                    if rest.as_os_str().is_empty() {
                        return "~".to_string();
                    }
                    return format!("~/{}", rest.to_string_lossy());
                }
            }
            abs_path.to_string()
        }
        PathStyle::Absolute => abs_path.to_string(),
    }
}

// --

pub async fn shell_exec_with_asset_substitution(
    io: &Io,
    session: &mut SessionState,
    asset_blob_cache: Arc<AssetBlobCache>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    cmd: &str,
    interactive: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let shell = &session.shell;
    let shell_exec_env_vars = &session.get_shell_exec_env_vars();
    // NOTE: Increasing concurrent downloads triggers 502 Gateway Timeouts.
    match asset_reader::prepare_assets_from_cmd_as_temp_files(
        &io,
        asset_blob_cache.clone(),
        session.asset_keyring.clone(),
        &session.account,
        api_client,
        username.map(|u| KeyRecipient::User(u.to_string())),
        cmd,
        4,
    )
    .await
    {
        Ok((updated_cmd, asset_map, output_assets)) => {
            for (asset_name, temp_res) in &asset_map {
                if let Err(e) = temp_res {
                    let err_msg = match e {
                        asset_reader::GetAssetError::BadName => {
                            format!("bad name: {}", asset_name)
                        }
                        asset_reader::GetAssetError::DataFetchFailed(e) => {
                            format!("fetch failed: {}: {}", asset_name, e)
                        }
                    };
                    return Err(err_msg.into());
                }
            }
            if username.is_none() && !output_assets.is_empty() {
                return Err(ASSET_ACCOUNT_REQ_MSG.into());
            }
            let res = if interactive {
                shell_exec_interactive(shell, &updated_cmd, Some(shell_exec_env_vars))
                    .await
                    .and_then(|_| Ok("".to_string()))
            } else {
                shell_exec(&io.out, shell, &updated_cmd, Some(shell_exec_env_vars)).await
            };
            for output_asset in output_assets {
                let username = username.unwrap(); // Checked before execution
                let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
                    io,
                    asset_blob_cache.clone(),
                    session.asset_keyring.clone(),
                    api_client.clone(),
                    Some(&KeyRecipient::User(username.to_string())),
                    &output_asset,
                    false,
                )
                .await
                {
                    Ok(akm_info) => akm_info,
                    Err(e) => match e {
                        asset_crypt::AkmSelectionError::Abort(msg) => {
                            return Err(msg.into());
                        }
                    },
                };
                let temp_file = match asset_map.get(&output_asset) {
                    Some(Ok(temp_file)) => temp_file,
                    Some(Err(e)) => {
                        let err_msg = match e {
                            asset_reader::GetAssetError::BadName => {
                                format!("bad name: {}", output_asset)
                            }
                            asset_reader::GetAssetError::DataFetchFailed(e) => {
                                format!("fetch failed: {}: {}", output_asset, e)
                            }
                        };
                        return Err(err_msg.into());
                    }
                    None => {
                        let err_msg = format!("missing output asset mapping: {}", output_asset);
                        return Err(err_msg.into());
                    }
                };
                let asset_contents = match fs::read(temp_file) {
                    Ok(res) => res,
                    Err(e) => {
                        let err_msg = format!("failed to read output file: {}", e);
                        return Err(err_msg.into());
                    }
                };
                let _ = update_asset_tx
                    .send(asset_async_writer::WorkerAssetMsg::Update(
                        asset_async_writer::WorkerAssetUpdate {
                            asset_name: output_asset,
                            asset_entry_ref: None,
                            new_contents: asset_contents,
                            is_push: false,
                            api_client: api_client.clone(),
                            one_shot: true,
                            akm_info: akm_info.clone(),
                            reply_channel: None,
                        },
                    ))
                    .await;
            }
            res
        }
        Err(e) => {
            let err_msg = format!("failed to prepare assets: {}", e);
            Err(err_msg.into())
        }
    }
}

// --

/// If None returned, it will have also printed an error message to stderr.
async fn get_haitask_from_task_ref(
    io: &Io,
    task_ref: &str,
    session: &mut SessionState,
    task_cmd: &str,
    fail_if_not_in_cache: bool,
) -> Option<(String, config::HaiTask)> {
    if let Some((_username, _task_name, task_fqn_versionless, version)) =
        config::is_valid_task_fqn(task_ref)
    {
        // NOTE: Version conflicts are handled by ignoring any cached task
        // that's the wrong version. The cache key is by task-fqn (without
        // version) so there can only be one cached task per fqn at a given
        // time.
        let task_cache_path = config::get_task_cache_path(&task_fqn_versionless);
        if task_cache_path.exists() {
            // Task in cache, so use it.
            let (config, haitask) =
                config::read_haitask(&task_cache_path.to_string_lossy()).unwrap();
            if let Some(version) = version {
                if version == haitask.version {
                    outln!(
                        io,
                        "Using version {} (`/task-update {}` to get any updates)",
                        haitask.version,
                        task_ref
                    );
                    return Some((config, haitask));
                } else {
                    outln!(
                        io,
                        "Cached version differs: {} != {} (refetching)",
                        version,
                        haitask.version
                    );
                }
            } else {
                outln!(
                    io,
                    "Using version {} (`/task-update {}` to get any updates)",
                    haitask.version,
                    task_ref
                );
                return Some((config, haitask));
            }
        }
        // Task missing from cache or was the wrong version
        if fail_if_not_in_cache {
            // To avoid an infinite loop of fetches that keep
            // retrying, fail if requested.
            errorln!(io, "failed to fetch task");
        } else {
            // Queue up a fetch task and then try again.
            session
                .cmd_queue
                .lock()
                .await
                .push_front(session::CmdInput {
                    input: format!("/{} {}", task_cmd, task_ref),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                });
            session
                .cmd_queue
                .lock()
                .await
                .push_front(session::CmdInput {
                    input: format!("/task-fetch {}", task_ref),
                    source: session::CmdSource::Internal,
                    reply_channel: None,
                });
        }
        None
    } else if task_ref.starts_with(".") || task_ref.starts_with("/") || task_ref.starts_with("~") {
        let task_path = match shellexpand::full(&task_ref) {
            Ok(s) => s.into_owned(),
            Err(e) => {
                errorln!(io, "undefined path variable: {}", e.var_name);
                return None;
            }
        };
        match config::read_haitask(&task_path) {
            Ok(read_res) => Some(read_res),
            Err(e) => {
                errorln!(io, "failed to load task: {}", e);
                None
            }
        }
    } else {
        errorln!(io, "unknown task: Try:");
        errorln!(io, "  1. Fully-qualified name (username/task-name)");
        errorln!(
            io,
            "  2. Path on your system using ./ for relative path and / for absolute path"
        );
        None
    }
}

// --

/// Written by AI
fn abbreviate_number(num: u64) -> String {
    let suffixes = ["", "k", "M", "B"];
    let mut value = num as f64;
    let mut index = 0;

    while value >= 1000.0 && index < suffixes.len() - 1 {
        value /= 1000.0;
        index += 1;
    }

    if value.fract() == 0.0 {
        format!("{}{}", value as u64, suffixes[index])
    } else {
        format!("{:.1}{}", value, suffixes[index])
    }
}

// --

use crate::api::types::asset::{AssetEntry, AssetEntryOp, AssetKind};

fn printable_asset_entry_line(entry: &AssetEntry, index: Option<(u32, u32)>) -> String {
    let index_str = index
        .map(|(i, digits)| format!("{:>width$}. ", i, width = digits as usize))
        .unwrap_or("".to_string());
    let push_symbol = if matches!(entry.asset.kind, AssetKind::Log) {
        "📥"
    } else {
        ""
    };
    let encrypted_symbol = if entry
        .metadata
        .as_ref()
        .map_or(false, |md| md.content_encrypted.is_some())
    {
        "🔒"
    } else {
        ""
    };
    let title = entry
        .metadata
        .as_ref()
        .and_then(|md| md.title.clone())
        .map(|md_title| format!(" [{}]", md_title))
        .unwrap_or("".to_string());
    let line = format!("{}{}{}{}", entry.name, encrypted_symbol, push_symbol, title);
    format!("{}{}", index_str, line)
}

fn printable_folder_line(folder: &str, index: Option<(u32, u32)>) -> String {
    let index_str = index
        .map(|(i, digits)| format!("{:>width$}. ", i, width = digits as usize))
        .unwrap_or_else(|| "".to_string());
    let line = format!("{}📁", folder);
    format!("{}{}", index_str, line)
}

fn count_digits(n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    ((n as f64).log10().floor() as u32) + 1
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Parse an RFC3339 / ISO8601 timestamp string and render a compact
/// "time ago" delta like "5m", "3d", "2mo", "1y".
fn format_time_delta(ts: &str) -> String {
    let parsed = DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc));

    let dt = match parsed {
        Ok(dt) => dt,
        Err(_) => return "-".to_string(),
    };

    let now = Utc::now();
    let secs = (now - dt).num_seconds();

    // Handle future timestamps gracefully.
    let (secs, suffix) = if secs < 0 {
        (-secs, "") // could add "+" for future if you want
    } else {
        (secs, "")
    };
    let _ = suffix;

    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else if secs < 86_400 * 30 {
        format!("{}d", secs / 86_400)
    } else if secs < 86_400 * 365 {
        format!("{}mo", secs / (86_400 * 30))
    } else {
        format!("{}y", secs / (86_400 * 365))
    }
}

// --

/// Executes the given command in the shell and returns the combined stdout and
/// stderr output as a string.
pub async fn shell_exec(
    out: &Out,
    shell: &str,
    cmd: &str,
    env_vars: Option<&HashMap<String, String>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut command = Command::new(shell);
    command
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(vars) = env_vars {
        command.envs(vars);
    }
    let mut child = command.spawn()?;
    tool::collect_and_output_command(out, &mut child).await
}

/// Executes the given command in the shell allowing it to inherit stdin,
/// stdio, and stderr for full interactivity.
pub async fn shell_exec_interactive(
    shell: &str,
    cmd: &str,
    env_vars: Option<&HashMap<String, String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(shell);
    command
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(vars) = env_vars {
        command.envs(vars);
    }
    let mut child = command.spawn()?;
    child.wait().await?;
    Ok(())
}

// --

/// Resolves asset names in a few ways:
///
/// 1. Expands public asset names (//) to explicitly include the username.
/// 2. Resolves quick variables ($) to their values in the session.
/// 3. Resolves the chain of parent asset names in attachment references
///    `grandparent_asset_name:parent_attachment_relname:attachment_relname`
///    to their entry_ids, one query per level of attachment depth.
///    - Passes through the attachment API format:
///      `:<entry_id>/<attachment_relname>`
pub async fn resolve_asset_name(out: &Out, asset_name: &str, session: &SessionState) -> String {
    let expanded = asset_helper::expand_asset_name(asset_name, &session.account);
    let resolved = resolve_quick_var(&expanded, session).unwrap_or(expanded);
    match asset_helper::resolve_attachment_asset_name(&resolved, &mk_api_client(Some(session)))
        .await
    {
        Ok(resolved_name) => resolved_name,
        Err((asset_name_failing, e)) => {
            errorln!(
                out,
                "failed to fetch asset name '{}' to get entry_id: {}",
                asset_name_failing,
                e
            );
            resolved
        }
    }
}

pub fn resolve_quick_var(asset_name: &str, session: &SessionState) -> Option<String> {
    if asset_name.starts_with('$') {
        let index = asset_name[1..].parse::<usize>().ok()?;
        session.quick_index_vars.get(index).cloned()
    } else {
        None
    }
}

// --

/// Adds line numbers for better diffing/patching by LLMs.
///
/// Line numbers are right-aligned based on the total number of lines to ensure
/// consistent formatting and separated by a vertical bar.
fn add_line_numbers(file_contents: &str) -> String {
    let lines: Vec<&str> = file_contents.lines().collect();
    let width = lines.len().to_string().len();

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:>width$} | {}", i + 1, line))
        .collect::<Vec<_>>()
        .join("\n")
}

// --

/// Adds delimiters around content to clearly indicate the source and
/// boundaries of the content to LLMs.
fn add_content_delimiters(
    source_type: &str,
    contents: &str,
    path: &str,
    more_info: Option<&str>,
    show_line_numbers: bool,
) -> String {
    format!(
        "<<<<<< BEGIN_{}: {}{}{} >>>>>>\n{}\n<<<<<< END_{}: {} >>>>>>",
        source_type.to_uppercase(),
        path,
        more_info
            .map(|s| format!(" ({})", s))
            .unwrap_or("".to_string()),
        if show_line_numbers {
            " (with line numbers)"
        } else {
            ""
        },
        if show_line_numbers {
            add_line_numbers(contents)
        } else {
            contents.to_string()
        },
        source_type.to_uppercase(),
        path,
    )
}

// --

fn mk_revision_header(revision: &crate::api::types::asset::AssetRevision) -> String {
    let mut output = vec![format!("Revision ID: {}", revision.asset.rev_id)];

    // Operation
    let op_str = match revision.op {
        AssetEntryOp::Add => "add",
        AssetEntryOp::Push => "push",
        AssetEntryOp::Delete => "delete",
        AssetEntryOp::Edit => "edit",
        AssetEntryOp::Fork => "fork",
        AssetEntryOp::Metadata => "metadata",
        AssetEntryOp::Move => "move",
        AssetEntryOp::Acl => "acl",
        AssetEntryOp::Other => "other",
    };
    output.push(format!("Operation: {}", op_str));

    // Asset info
    output.push("\nAsset info:".to_string());
    output.push(format!("  Rev ID:     {}", revision.asset.rev_id));
    output.push(format!("  Created By: {:?}", revision.asset.created_by));
    output.push(format!("  Size:       {} bytes", revision.asset.size));
    if let Some(hash) = &revision.asset.hash {
        output.push(format!("  Hash:       {}", hash));
    }

    output.push(format_asset_acl(&revision.asset, Some("  ACL:        ")));

    // Metadata info (if present)
    if let Some(metadata) = &revision.metadata {
        output.push("\nMetadata info:".to_string());
        output.push(format!("  Rev ID:     {}", metadata.rev_id));
        output.push(format!("  Created By: {:?}", metadata.created_by));
        output.push(format!("  Size:       {} bytes", metadata.size));
        if let Some(hash) = &metadata.hash {
            output.push(format!("  Hash:       {}", hash));
        }
        if let Some(title) = &metadata.title {
            output.push(format!("  Title:      {}", title));
        }
        if let Some(content_type) = &metadata.content_type {
            output.push(format!("  Content Type: {}", content_type));
        }
        if let Some(encrypted) = &metadata.content_encrypted {
            output.push(format!("  Encrypted:  {:?}", encrypted));
        }
    }
    output.join("\n")
}

async fn print_revision(
    io: &Io,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    asset_name: &str,
    show_line_numbers: bool,
    revision: &crate::api::types::asset::AssetRevision,
    session: &mut SessionState,
) -> Option<HistoryEntry> {
    let mut revision_header = mk_revision_header(revision);
    let md_contents = if let Some(crate::api::types::asset::AssetMetadataInfo {
        url: Some(metadata_url),
        ..
    }) = revision.metadata.as_ref()
    {
        match asset_reader::download_with_new_client(metadata_url).await {
            Ok(md_contents_bin) => {
                let md_contents = std::str::from_utf8(&md_contents_bin).expect("invalid metadata");
                let md_json: serde_json::Value = serde_json::from_str(md_contents)
                    .unwrap_or_else(|_| serde_json::json!(md_contents));
                let md_formatted = serde_json::to_string_pretty(&md_json).expect("json format");
                revision_header = format!("{}\n\nMetadata: {}", revision_header, md_formatted);
                Some(md_contents_bin)
            }
            Err(e) => {
                errorln!(io, "failed to fetch metadata: {}", e);
                return None;
            }
        }
    } else {
        None
    };
    outln!(io, "{}\n", revision_header);
    if let Some(data_url) = revision.asset.url.as_ref() {
        match asset_reader::download_with_new_client(data_url).await {
            Ok(contents_bin) => {
                let decrypted_asset_contents = if let Some(md_contents) = md_contents
                    && let Some(rec_key_info) = asset_crypt::parse_metadata_for_encryption_info(
                        &md_contents,
                        session
                            .account
                            .as_ref()
                            .map(|a| KeyRecipient::User(a.username.clone()))
                            .as_ref(),
                    ) {
                    match asset_crypt::get_symmetric_key_ez(
                        io,
                        asset_blob_cache.clone(),
                        session.asset_keyring.clone(),
                        &api_client,
                        &rec_key_info,
                    )
                    .await
                    {
                        Ok(sym_info) => {
                            let enc_content =
                                crypt::EncryptedContent::from_bytes(&contents_bin).unwrap();
                            crypt::decrypt_content(&enc_content, &sym_info.aes_key).unwrap()
                        }
                        Err(e) => {
                            errorln!(io, "failed to get encryption key: {}", e);
                            return None;
                        }
                    }
                } else {
                    contents_bin.clone()
                };
                match std::str::from_utf8(&decrypted_asset_contents) {
                    Ok(contents) => {
                        let was_recording = io.record_off();
                        if show_line_numbers {
                            outln!(io, "{}", add_line_numbers(contents));
                        } else {
                            outln!(io, "{}", contents);
                        }
                        outln!(io);
                        io.record_set(was_recording);
                        let contents_with_delimiters = add_content_delimiters(
                            "REVISION",
                            contents,
                            asset_name,
                            Some(&format!("rev_id={}", revision.asset.rev_id)),
                            show_line_numbers,
                        );
                        Some(HistoryEntry::UserText(contents_with_delimiters))
                    }
                    Err(_) => {
                        let was_recording = io.record_off();
                        let msg = format!("[binary data: {} bytes]", contents_bin.len());
                        outln!(io, "{}", msg);
                        outln!(io);
                        io.record_set(was_recording);
                        Some(HistoryEntry::UserText(msg.clone()))
                    }
                }
            }
            Err(e) => {
                errorln!(io, "failed to fetch asset data: {}", e);
                return None;
            }
        }
    } else {
        None
    }
}

fn format_asset_acl(asset: &crate::api::types::asset::AssetInfo, prefix: Option<&str>) -> String {
    let mut output_lines = Vec::new();
    asset.acl.iter().for_each(|ace| {
        let line = format!(
            "{}Principal: {}, read-data: {}, read-revisions: {}, write-data: {}, push-data: {}",
            prefix.unwrap_or(""),
            match ace.principal {
                api::types::asset::AssetAcePrincipal::User(ref username) =>
                    format!("User:{}", username.clone()),
                api::types::asset::AssetAcePrincipal::Everyone => "Everyone".to_string(),
                _ => return,
            },
            ace.read_data
                .as_ref()
                .map_or("Inherit".to_string(), |effect| format!("{:?}", effect)),
            ace.read_revisions
                .as_ref()
                .map_or("Inherit".to_string(), |effect| format!("{:?}", effect)),
            ace.write_data
                .as_ref()
                .map_or("Inherit".to_string(), |effect| format!("{:?}", effect)),
            ace.push_data
                .as_ref()
                .map_or("Inherit".to_string(), |effect| format!("{:?}", effect)),
        );
        output_lines.push(line);
    });
    output_lines.join("\n")
}
