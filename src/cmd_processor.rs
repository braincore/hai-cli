use colored::*;
use glob::glob;
use num_format::{Locale, ToFormattedString};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::api::client::RequestError;
use crate::session::{
    self, HaiRouterState, ReplMode, SessionState, hai_router_set, hai_router_try_activate,
    mk_api_client, session_history_add_user_cmd_and_reply_entries,
    session_history_add_user_image_entry, session_history_add_user_text_entry,
};
use crate::{
    api::{self, client::HaiClient},
    asset_editor, chat, clipboard, cmd, config, ctrlc_handler,
    db::{self, LogEntryRetentionPolicy},
    feature::{haivar, save_chat},
    loader, term, term_color, tool,
};

pub enum ProcessCmdResult {
    Loop,
    Break,
    PromptAi(String, bool),
}

#[allow(clippy::too_many_arguments)]
pub async fn process_cmd(
    config_path_override: &Option<String>,
    session: &mut SessionState,
    cfg: &mut config::Config,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_editor::WorkerAssetMsg>,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
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
    let trusted = if let ReplMode::Task(_, trusted) = session.repl_mode {
        trusted && is_task_mode_step
    } else {
        false
    };

    const ASSET_ACCOUNT_REQ_MSG: &str =
        "You must be logged-in to use assets. Try /account-login or /account-new";

    match cmd {
        cmd::Cmd::Noop => ProcessCmdResult::Loop,
        cmd::Cmd::Quit => {
            println!("さようなら！");
            ProcessCmdResult::Break
        }
        cmd::Cmd::Help(cmd::HelpCmd { history }) => {
            println!("{}", HELP_MSG);
            println!();
            println!("For interactive help: `/task hai/help`");
            if *history {
                session::session_history_add_user_text_entry(
                    HELP_MSG,
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Cd(cmd::CdCmd { path }) => {
            let path = if path.is_empty() { "~" } else { path };
            let cd_target = shellexpand::full(path).unwrap().into_owned();
            if let Err(e) = env::set_current_dir(cd_target) {
                eprintln!("Failed to change directory: {}", e);
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Ai(cmd::AiCmd { model }) => {
            if let Some(model_name) = model {
                if let Some(selected_ai_model) = config::ai_model_from_string(model_name) {
                    let ai_model_capability = config::get_ai_model_capability(&selected_ai_model);
                    if is_task_mode_step
                        && (matches!(session.use_hai_router, HaiRouterState::Off)
                            || !config::is_ai_model_supported_by_hai_router(&selected_ai_model))
                        && !config::check_api_key(&selected_ai_model, cfg)
                    {
                        eprintln!(
                            "{} task may behave unexpectedly or fail without requested model",
                            "warn:".black().on_yellow()
                        );
                        return ProcessCmdResult::Loop;
                    }
                    let mut ai_model_viable = true;
                    for msg in &session.history {
                        if !ai_model_capability.tool && msg.message.tool_call_id.is_some() {
                            eprintln!(
                                "error: cannot switch because target model does not support tools"
                            );
                            eprintln!("       clear conversation first: /new or /reset");
                            ai_model_viable = false;
                            break;
                        }
                        for content_part in &msg.message.content {
                            if !ai_model_capability.image
                                && matches!(content_part, chat::MessageContent::ImageUrl { .. })
                            {
                                eprintln!(
                                    "error: cannot switch because target model does not support images"
                                );
                                eprintln!("       clear conversation first: /new or /reset");
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
                            eprintln!(
                                "warning: disabling hai-router because it does not support {}",
                                model_name
                            );
                            session.use_hai_router = HaiRouterState::OffForModel;
                        } else if matches!(session.use_hai_router, HaiRouterState::OffForModel)
                            && config::is_ai_model_supported_by_hai_router(&selected_ai_model)
                        {
                            eprintln!(
                                "notice: activating hai-router because {} is supported",
                                model_name
                            );
                            session.use_hai_router = HaiRouterState::On;
                        }
                        session.ai = selected_ai_model;
                    }
                } else {
                    println!("Unknown model: {}", model_name);
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
            println!(
                "Using AI Model: {}{}",
                config::get_ai_model_display_name(&session.ai),
                host
            );
            if model.is_none() {
                println!("--");
                let need_openai_key = cfg
                    .openai
                    .as_ref()
                    .and_then(|c| c.api_key.as_ref())
                    .is_none();
                let need_anthropic_key = cfg
                    .anthropic
                    .as_ref()
                    .and_then(|c| c.api_key.as_ref())
                    .is_none();
                let need_deepseek_key = cfg
                    .deepseek
                    .as_ref()
                    .and_then(|c| c.api_key.as_ref())
                    .is_none();
                let need_google_key = cfg
                    .google
                    .as_ref()
                    .and_then(|c| c.api_key.as_ref())
                    .is_none();
                let need_key = "  (NEED API KEY: /set-key OR /hai-router)";
                println!("Try these popular models:");
                println!(
                    "From OpenAI: 4o, 4o-mini, o1, o1-mini, o3-mini, openai/___{}",
                    if need_openai_key { need_key } else { "" }
                );
                println!(
                    "From Anthropic: sonnet, haiku, anthropic/___{}",
                    if need_anthropic_key { need_key } else { "" }
                );
                println!(
                    "From DeepSeek: deepseek, r1, deepseek/___{}",
                    if need_deepseek_key { need_key } else { "" }
                );
                println!(
                    "From Google: flash, google/___{}",
                    if need_google_key { need_key } else { "" }
                );
                println!(
                    "Using Ollama: llama, llama-vision, ollama/___ (configure host in config)"
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AiDefault(cmd::AiDefaultCmd { model }) => {
            if let Some(model_name) = model {
                config::insert_config_kv(
                    config_path_override,
                    None,
                    &"default_ai_model".to_string(),
                    model_name,
                );
                cfg.reload(config_path_override)
                    .expect("Could not read config");
            }
            println!(
                "Default AI Model: {}",
                cfg.default_ai_model.clone().unwrap_or("none".into())
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Clip => {
            if let Some(log_entry) = session.history.last() {
                if let Some(chat::MessageContent::Text { text }) = log_entry.message.content.last()
                {
                    clipboard::copy_to_clipboard(text);
                } else {
                    println!("Entry type cannot be copied");
                }
            } else {
                println!("No entry to copy");
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::SetKey(cmd::SetKeyCmd { provider, key }) => {
            match provider.as_str() {
                "openai" | "anthropic" | "google" | "deepseek" => {
                    config::insert_config_kv(
                        config_path_override,
                        Some(provider),
                        &"api_key".to_string(),
                        key,
                    );
                    cfg.reload(config_path_override)
                        .expect("Could not read config");
                }
                _ => {
                    eprintln!(
                        "error: unknown provider: {} (try openai, anthropic, google, deepseek)",
                        provider
                    );
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::SetMaskSecrets(cmd::SetMaskSecretsCmd { on }) => {
            if let Some(on) = on {
                session.mask_secrets = *on;
            } else {
                println!(
                    "Mask secrets: {}",
                    if session.mask_secrets { "on" } else { "off" }
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::HaiRouter(cmd::HaiRouterCmd { on }) => {
            let username = if let Some(account) = &session.account {
                account.username.clone()
            } else {
                eprintln!("You must be logged-in to use hai-router. Try /account-login");
                return ProcessCmdResult::Loop;
            };
            if let Some(on) = on {
                hai_router_set(session, *on);
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
                println!(
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
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Temperature(cmd::TemperatureCmd { temperature }) => {
            if let Some(temperature) = temperature {
                session.ai_temperature = Some(*temperature);
            } else if let Some(temperature) = &session.ai_temperature {
                println!("AI Temperature: {}", temperature);
            } else {
                println!("AI Temperature: none (Using AI provider default)",);
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::New => {
            save_chat::save_chat_to_db(session, db).await;
            // In task-mode, we keep all task-mode initialization steps regardless
            // of standard retention policy.
            let task_mode = matches!(session.repl_mode, ReplMode::Task(..));
            session
                .history
                .retain(|log_entry| task_mode && log_entry.retention_policy.0);
            session.recalculate_input_tokens();
            session
                .temp_files
                .retain(|(_, is_task_step)| task_mode && *is_task_step);
            session
                .ai_defined_fns
                .retain(|_, (_, is_task_step)| task_mode && *is_task_step);
            if let ReplMode::Task(ref task_fqn, ..) = session.repl_mode {
                let task_restarted_header = format!("Task Restarted: {}", task_fqn);
                println!("{}", task_restarted_header.black().on_white());
            } else {
                println!("New conversation begun");
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Reset => {
            save_chat::save_chat_to_db(session, db).await;
            let task_mode = matches!(session.repl_mode, ReplMode::Task(..));
            session.history.retain(|log_entry| {
                (task_mode && log_entry.retention_policy.0)
                    || log_entry.retention_policy.1 != db::LogEntryRetentionPolicy::None
            });
            session.recalculate_input_tokens();
            session
                .temp_files
                .retain(|(_, is_task_step)| task_mode && *is_task_step);
            session
                .ai_defined_fns
                .retain(|_, (_, is_task_step)| task_mode && *is_task_step);
            if !session.history.is_empty() {
                if matches!(session.repl_mode, ReplMode::Task(..)) {
                    println!("Task restarted additional /pin(s) and /load(s) retained");
                } else {
                    println!(
                        "New conversation begun with {} entries",
                        session.history.len()
                    );
                }
            } else {
                println!("Nothing was loaded or pinned. New conversation begun");
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::PrintVars => {
            let mut printvars_lines = vec![];
            for (key, value) in &cfg.haivars {
                printvars_lines.push(format!("{} = {}", key, value));
            }
            let printvars_output = printvars_lines.join("\n");
            println!("{}", printvars_output);
            session_history_add_user_text_entry(
                &printvars_output,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Dump => {
            // Undocumented (for manual testing)
            for message in &session.history {
                if message.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
                    // Don't print entire files loaded as they flood the terminal.
                    if let chat::MessageContent::Text { text } = &message.message.content[0] {
                        println!("message: /load: {}", text.split_once("\n").unwrap().0);
                    } else if let chat::MessageContent::ImageUrl { image_url } =
                        &message.message.content[0]
                    {
                        println!("message: /load image: {}", &image_url.url[..10]);
                    }
                } else {
                    println!("message: {:?}", message);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::DumpSession => {
            println!("{:#?}", session);
            ProcessCmdResult::Loop
        }
        cmd::Cmd::About => {
            println!(
                r##"  _          ___
 | |         \_/
 | |___  ___  _
 |  _  |/ _ \/ |
 | | | | (_| | |
 \_| |_/\__,_|\|
"##
            );
            println!("hai (Hacker AI)");
            println!("Version: v{}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Authored by Ken Elkabany @ken");
            println!("Send me an email: ken@elkabany.com");
            println!();
            println!("Written to empower hackers everywhere");
            println!("- Wield the AI");
            println!("- Share knowledge");
            println!("- Emancipate data");
            println!();
            ProcessCmdResult::Loop
        }
        cmd::Cmd::SetVar(cmd::SetVarCmd { key, value }) => {
            let key_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*$").unwrap();
            if !key_regex.is_match(key) {
                println!(
                    "error: variable name '{}' is invalid: must start with a letter and only contain alphanumeric characters or underscores.",
                    key
                );
                return ProcessCmdResult::Loop;
            }
            cfg.haivars.insert(key.to_owned(), value.to_owned());
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Exec(cmd::ExecCmd { command, cache }) => {
            let shell_exec_handler_id = ctrlc_handler.add_handler(|| {
                println!("Shell Exec Interrupted");
            });
            let api_client = mk_api_client(Some(session));

            let (shell_exec_output, from_cache) = if let Some((ref task_fqn, step_index)) =
                task_step_signature
            {
                let cached_output = if *cache {
                    db::get_task_step_cache(
                        &*db.lock().await,
                        session
                            .account
                            .as_ref()
                            .map(|a| a.username.as_str())
                            .unwrap_or(""),
                        task_fqn,
                        step_index,
                        raw_user_input,
                    )
                } else {
                    None
                };
                if let Some(cached_output) = cached_output {
                    (cached_output, true)
                } else {
                    // If we're initializing a task, it's critical that we ask the
                    // user for confirmation. Otherwise, a destructive command could
                    // be hidden in a task.
                    if !force_yes && !trusted {
                        println!();
                        let answer = term::ask_question_default_empty(
                            "Execute above command? y/[n]:",
                            false,
                        );
                        let answered_yes = answer.starts_with('y');
                        if !answered_yes {
                            println!("USER CANCELLED EXEC. TASK MAY MALFUNCTION.");
                            return ProcessCmdResult::Loop;
                        }
                    }
                    (
                        shell_exec_with_asset_substitution(&api_client, &session.shell, command)
                            .await
                            .unwrap(),
                        false,
                    )
                }
            } else {
                (
                    shell_exec_with_asset_substitution(&api_client, &session.shell, command)
                        .await
                        .unwrap(),
                    false,
                )
            };
            println!();

            ctrlc_handler.remove_handler(shell_exec_handler_id);

            if from_cache {
                if let Some((ref task_fqn, _)) = task_step_signature {
                    println!("[Retrieved from cache; `/task-forget {task_fqn}` to execute again]");
                }
                // Because it's from the cache, the value is not yet on the screen.
                println!("{}", shell_exec_output);
            } else if *cache {
                if let Some((ref task_fqn, step_index)) = task_step_signature {
                    db::set_task_step_cache(
                        &*db.lock().await,
                        session
                            .account
                            .as_ref()
                            .map(|a| a.username.as_str())
                            .unwrap_or(""),
                        task_fqn,
                        step_index,
                        raw_user_input,
                        &shell_exec_output,
                    )
                }
            }
            session_history_add_user_cmd_and_reply_entries(
                command,
                &shell_exec_output,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AskHuman(cmd::AskHumanCmd {
            question,
            secret,
            cache,
        }) => {
            let (answer, from_cache) = if *cache {
                if let Some((ref task_fqn, step_index)) = task_step_signature {
                    db::get_task_step_cache(
                        &*db.lock().await,
                        session
                            .account
                            .as_ref()
                            .map(|a| a.username.as_str())
                            .unwrap_or(""),
                        task_fqn,
                        step_index,
                        raw_user_input,
                    )
                    .map(|a| (Some(a), true))
                    .unwrap_or_else(|| {
                        println!();
                        (term::ask_question(question, *secret), false)
                    })
                } else {
                    println!();
                    (term::ask_question(question, *secret), false)
                }
            } else {
                println!();
                (term::ask_question(question, *secret), false)
            };
            let answer = if let Some(answer) = answer {
                answer
            } else {
                if is_task_mode_step {
                    // If the user is initializing a task, but they ctrl+c the
                    // question, then abort the entire initialization. Assume
                    // they're uncomfortable with the task and don't want to
                    // proceed.
                    println!("user cancelled input: task initialization aborted");
                    session.cmd_queue.clear();
                }
                return ProcessCmdResult::Loop;
            };
            if from_cache {
                if let Some((ref task_fqn, _)) = task_step_signature {
                    println!("[Retrieved from cache; `/task-forget {task_fqn}` to execute again]");
                }
                // Because it's from the cache, the value is not yet on the screen.
                if answer.is_empty() {
                    println!("*You left this blank*");
                } else if *secret {
                    let mask: String = "*".repeat(answer.len());
                    println!("{}", mask);
                } else {
                    println!("{}", answer);
                }
            } else if *cache {
                if let Some((ref task_fqn, step_index)) = task_step_signature {
                    db::set_task_step_cache(
                        &*db.lock().await,
                        session
                            .account
                            .as_ref()
                            .map(|a| a.username.as_str())
                            .unwrap_or(""),
                        task_fqn,
                        step_index,
                        raw_user_input,
                        &answer,
                    )
                }
            }
            if *secret {
                // Since it was written as a secret, we assume it shouldn't be
                // printed on the screen.
                session.masked_strings.insert(answer.clone());
            }
            session_history_add_user_text_entry(
                question,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            session_history_add_user_text_entry(
                &answer,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Prep(cmd::PrepCmd { message }) | cmd::Cmd::Pin(cmd::PinCmd { message }) => {
            let retention_policy = if matches!(cmd, cmd::Cmd::Pin(_)) {
                db::LogEntryRetentionPolicy::ConversationPin
            } else {
                db::LogEntryRetentionPolicy::None
            };
            session_history_add_user_text_entry(
                message,
                session,
                bpe_tokenizer,
                (is_task_mode_step, retention_policy),
            );
            ProcessCmdResult::Loop
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
                    println!("The system prompt is:");
                    for msg in content {
                        if let chat::MessageContent::Text { text } = msg {
                            println!("{}", text);
                        }
                    }
                } else {
                    println!("There is no system prompt");
                }
                return ProcessCmdResult::Loop;
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
                },
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Forget(cmd::ForgetCmd { n }) => {
            let mut n = n.clone();
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
                println!(
                    "Forgot {role_name} message: {}",
                    prepare_preview(preview, 80)
                );
                if matches!(log_entry.message.role, chat::MessageRole::User) {
                    n -= 1;
                }
            }
            session.recalculate_input_tokens();
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Keep(cmd::KeepCmd { bottom, top }) => {
            let mut bottom = bottom.clone();
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
                println!("Keep {role_name} message: {}", prepare_preview(preview, 80));
            }
            session.history = kept_history;
            session.recalculate_input_tokens();

            ProcessCmdResult::Loop
        }
        cmd::Cmd::Load(cmd::LoadCmd { path }) => {
            //
            // The purpose of loading is for the user to be able to easily
            // inject files into the system context.
            //
            let raw_load_target = path;
            let load_target_deref = haivar::replace_haivars(raw_load_target, &cfg.haivars);
            let load_target = match shellexpand::full(&load_target_deref) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    eprintln!("error: undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::Loop;
                }
            };
            // Iterate through paths and collect matching files
            let paths_res = glob(&load_target);
            if paths_res.is_err() {
                eprintln!("error: bad glob: {:?}", paths_res.unwrap_err());
                return ProcessCmdResult::Loop;
            }
            let paths = paths_res.unwrap();
            let files: Result<Vec<_>, _> = paths.collect();
            let mut first_file = true;
            match files {
                Ok(files) => {
                    let mut newly_loaded_tokens = 0;
                    for file_path in files {
                        let file_res = fs::File::open(&file_path);
                        if file_res.is_err() {
                            eprintln!(
                                "error: could not open file: {:?}: {:?}",
                                file_path,
                                file_res.unwrap_err()
                            );
                            continue;
                        }
                        let mut file = file_res.unwrap();
                        // Read the file contents into a buffer
                        let mut buffer = Vec::new();
                        if let Err(e) = file.read_to_end(&mut buffer) {
                            eprintln!("error: could not read file: {:?}: {:?}", file_path, e)
                        }
                        if let Ok(file_contents) = std::str::from_utf8(&buffer) {
                            let mut file_contents_with_delimeters = format!(
                                "<<<<<< BEGIN_FILE: {} >>>>>>\n{}\n<<<<<< END_FILE: {} >>>>>>",
                                file_path.to_string_lossy(),
                                file_contents,
                                file_path.to_string_lossy()
                            );
                            if first_file {
                                // If this is the first file, inject the /load
                                // command. This way the AI knows how the loads
                                // were generated (glob or otherwise).
                                file_contents_with_delimeters = format!(
                                    "{}\n{}",
                                    raw_user_input, file_contents_with_delimeters
                                );
                                first_file = false;
                            }
                            let token_count = session_history_add_user_text_entry(
                                &file_contents_with_delimeters,
                                session,
                                bpe_tokenizer,
                                (is_task_mode_step, LogEntryRetentionPolicy::ConversationLoad),
                            );
                            println!(
                                "Loaded: {} ({} tokens)",
                                &file_path.to_string_lossy(),
                                token_count.to_formatted_string(&Locale::en)
                            );
                            newly_loaded_tokens += token_count;
                        } else {
                            // Not a text file, try opening as image
                            match loader::resolve_image_b64(
                                &file_path.to_string_lossy().into_owned(),
                            )
                            .await
                            {
                                Ok(img_png_b64) => {
                                    if !config::get_ai_model_capability(&session.ai).image {
                                        eprintln!("error: model does not support images");
                                        return ProcessCmdResult::Loop;
                                    }
                                    let token_count = session_history_add_user_image_entry(
                                        &img_png_b64,
                                        session,
                                        (
                                            is_task_mode_step,
                                            LogEntryRetentionPolicy::ConversationLoad,
                                        ),
                                    );
                                    newly_loaded_tokens += token_count;
                                    term::print_image_to_term(&img_png_b64).unwrap();
                                }
                                Err(e) => {
                                    eprintln!(
                                        "error: failed to load as text or image: {:?}: {:?}",
                                        file_path, e
                                    );
                                }
                            }
                        }
                    }
                    println!(
                        "Total tokens loaded: {}",
                        newly_loaded_tokens.to_formatted_string(&Locale::en)
                    );
                }
                Err(e) => println!("Error: {:?}", e),
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::LoadUrl(cmd::LoadUrlCmd { url, raw }) => {
            let http_response = match reqwest::Client::new()
                .get(url)
                .header("User-Agent", &format!("hai/{}", env!("CARGO_PKG_VERSION")))
                .send()
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    eprintln!("error: failed to load-url: {}", e);
                    return ProcessCmdResult::Loop;
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
            match content_type.as_deref() {
                Some("image/jpeg") | Some("image/png") => {
                    if !config::get_ai_model_capability(&session.ai).image {
                        eprintln!("error: model does not support images");
                        return ProcessCmdResult::Loop;
                    }
                    let img_bytes = if let Ok(img_bytes) = http_response.bytes().await {
                        img_bytes
                    } else {
                        eprintln!("error: failed to get image from url");
                        return ProcessCmdResult::Loop;
                    };
                    let img_png_b64 = if let Ok(img_png_b64) =
                        loader::encode_image_bytes_to_png_base64(img_bytes)
                    {
                        img_png_b64
                    } else {
                        eprintln!("error: failed to encode image as png-base64");
                        return ProcessCmdResult::Loop;
                    };
                    session_history_add_user_image_entry(
                        &img_png_b64,
                        session,
                        (is_task_mode_step, LogEntryRetentionPolicy::ConversationLoad),
                    );
                    term::print_image_to_term(&img_png_b64).unwrap();
                }
                _ => {
                    let url_body = match http_response.text().await {
                        Ok(body) => body,
                        Err(e) => {
                            eprintln!("failed to parse url: {}", e);
                            return ProcessCmdResult::Loop;
                        }
                    };

                    let (contents, format, title) = if !*raw && is_html_content_type {
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
                        "{}\n<<<<<< BEGIN_URL: {} >>>>>>\n{}\n<<<<<< END_URL: {} >>>>>>",
                        raw_user_input, url, contents, url,
                    );
                    let token_count = session_history_add_user_text_entry(
                        &url_contents_with_delimiters,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::ConversationLoad),
                    );
                    println!(
                        "Loaded ({}): {} ({} tokens)",
                        format,
                        title.unwrap_or(url.clone()),
                        token_count.to_formatted_string(&Locale::en)
                    );
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Task(cmd::TaskCmd { task_ref, trust }) => {
            if is_task_mode_step {
                eprintln!("error: cannot use /task within task steps: try /task-include");
                return ProcessCmdResult::Loop;
            }
            if matches!(session.repl_mode, ReplMode::Task(..)) {
                // If already in task mode, clear the existing session state and start fresh.
                session.cmd_queue.push_front(session::CmdInput {
                    // Use the original input in case args are used (e.g. trust=true)
                    input: cmd_input.input.clone(),
                    source: session::CmdSource::Internal,
                });
                session.cmd_queue.push_front(session::CmdInput {
                    input: "/task-end".to_string(),
                    source: session::CmdSource::Internal,
                });
            } else if let Some((_, haitask)) = get_haitask_from_task_ref(
                task_ref,
                session,
                "task",
                matches!(cmd_input.source, session::CmdSource::Internal),
            ) {
                term::window_title_set(&haitask.name);
                println!();
                println!(
                    "{} {}",
                    " TASK MODE ENABLED ".black().on_white(),
                    haitask.name
                );
                println!("  - /new -- restarts the task");
                println!(
                    "  - /reset -- restarts the task while retaining additional /pin and /load commands"
                );
                println!(
                    "  - /task-forget {} -- forgets cached/memorized answers",
                    task_ref
                );
                println!("  - /task-end -- Exit task mode (CTRL+D shortcut)");
                println!();
                for (index, step) in haitask.steps.iter().enumerate().rev() {
                    session.cmd_queue.push_front(session::CmdInput {
                        input: step.clone(),
                        source: session::CmdSource::TaskStep(haitask.name.clone(), index as u32),
                    });
                }
                session.repl_mode = ReplMode::Task(haitask.name.clone(), *trust);
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskInclude(cmd::TaskIncludeCmd { task_ref }) => {
            if let Some((_, haitask)) = get_haitask_from_task_ref(
                task_ref,
                session,
                "task-include",
                matches!(cmd_input.source, session::CmdSource::Internal),
            ) {
                for (index, step) in haitask.steps.iter().enumerate().rev() {
                    session.cmd_queue.push_front(session::CmdInput {
                        input: step.clone(),
                        source: session::CmdSource::TaskStep(haitask.name.clone(), index as u32),
                    });
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskFetch(cmd::TaskFetchCmd { task_fqn }) => {
            if config::is_valid_task_fqn(task_fqn).is_none() {
                eprintln!(
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::Loop;
            };
            let client = mk_api_client(Some(session));
            use api::types::task::TaskGetArg;
            match client
                .task_get(TaskGetArg {
                    task_fqn: task_fqn.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    println!("Fetched {}@{}", res.task_fqn, res.task_version);
                    if let Err(e) = config::parse_haitask_config(&res.config) {
                        eprintln!("failed to parse haitask config: {}", e);
                        return ProcessCmdResult::Loop;
                    }
                    if let Err(e) = config::write_task_to_cache_path(&res.task_fqn, &res.config) {
                        eprintln!("failed to write haitask config: {}", e);
                        return ProcessCmdResult::Loop;
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskEnd => {
            // Does not clear the conversation history because the user may
            // have accidentally entered task mode and we don't want to lose
            // their history when they exit. This makes accidentally using
            // /task instead of /task-include an inconvenience rather than
            // fatal.
            match session.repl_mode.clone() {
                ReplMode::Task(task_fqn, _) => {
                    session.repl_mode = ReplMode::Normal;
                    session.tool_mode = None;
                    // Support ending task prematurely while task steps are
                    // being executed by purging any remaining task steps from
                    // the queue.
                    session
                        .cmd_queue
                        .retain(|cmd_input| match &cmd_input.source {
                            session::CmdSource::TaskStep(step_task_fqn, _) => {
                                step_task_fqn != &task_fqn
                            }
                            _ => true,
                        });
                    term::window_title_reset();
                    println!("info: task ended");
                }
                _ => {
                    eprintln!("error: not in task mode");
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskPublish(cmd::TaskPublishCmd { task_path }) => {
            let account = if let Some(ref account) = session.account {
                account
            } else {
                eprintln!("You must be logged-in to publish. Try /account-login or /account-new");
                return ProcessCmdResult::Loop;
            };
            let task_novar_path = haivar::replace_haivars(task_path, &cfg.haivars);
            let task_full_path = match shellexpand::full(&task_novar_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    eprintln!("error: undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::Loop;
                }
            };
            let (haitask_contents, haitask) = match config::read_haitask(&task_full_path) {
                Ok(res) => res,
                Err(e) => {
                    eprint!("error: failed to load task: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            if !haitask.name.starts_with(&(account.username.clone() + "/")) {
                eprint!(
                    "error: task name must be prefixed with your account username: {}/",
                    account.username
                );
                return ProcessCmdResult::Loop;
            }

            use api::types::task::TaskPutArg;
            let client = mk_api_client(Some(session));
            match client
                .task_put(TaskPutArg {
                    task_fqn: haitask.name.clone(),
                    config: haitask_contents,
                })
                .await
            {
                Ok(_) => {
                    println!(
                        "Successfully added {}@{} to repository.",
                        haitask.name, haitask.version
                    );
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }

            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskForget(cmd::TaskForgetCmd { task_ref }) => {
            let task_name = if config::is_valid_task_fqn(task_ref).is_some() {
                task_ref.clone()
            } else if task_ref.starts_with(".")
                || task_ref.starts_with("/")
                || task_ref.starts_with("~")
            {
                let task_path = match shellexpand::full(&task_ref) {
                    Ok(s) => s.into_owned(),
                    Err(e) => {
                        eprintln!("error: undefined path variable: {}", e.var_name);
                        return ProcessCmdResult::Loop;
                    }
                };
                match config::read_haitask(&task_path) {
                    Ok((_, task)) => task.name,
                    Err(e) => {
                        eprint!("error: failed to read task: {}", e);
                        return ProcessCmdResult::Loop;
                    }
                }
            } else {
                eprint!("error: unknown task: {}", task_ref);
                return ProcessCmdResult::Loop;
            };
            db::purge_task_step_cache(&*db.lock().await, &task_name);
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskPurge(cmd::TaskPurgeCmd { task_fqn }) => {
            if config::is_valid_task_fqn(task_fqn).is_none() {
                eprintln!(
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::Loop;
            };
            db::purge_task_step_cache(&*db.lock().await, task_fqn);
            match config::purge_cached_task(task_fqn) {
                Ok(_) => {
                    println!("Sucessfully purged");
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskSearch(cmd::TaskSearchCmd { q }) => {
            let client = mk_api_client(Some(session));
            use api::types::task::TaskSearchArg;

            fn prepare_description(description: Option<String>, max_length: usize) -> String {
                let s = description.unwrap_or("".to_string()).replace("\n", " ");
                if s.chars().count() > max_length {
                    let truncated: String = s.chars().take(max_length - 3).collect();
                    format!("{}...", truncated)
                } else {
                    s.to_string()
                }
            }

            match client.task_search(TaskSearchArg { q: q.to_owned() }).await {
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

                    println!("=== Semantic Matches ===");
                    for (semantic_line, semantic_match) in semantic_lines {
                        println!(
                            "{:width$}    # {}",
                            semantic_line,
                            prepare_description(semantic_match.description, width_for_description),
                            width = max_name_width,
                        );
                    }
                    println!();
                    println!("=== Syntactic Matches === ");
                    for (syntactic_line, syntactic_match) in syntactic_lines {
                        println!(
                            "{:width$}    # {}",
                            syntactic_line,
                            prepare_description(syntactic_match.description, width_for_description),
                            width = max_name_width,
                        );
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskView(cmd::TaskViewCmd { task_ref }) => {
            if let Some((config, haitask)) = get_haitask_from_task_ref(
                task_ref,
                session,
                "task-view",
                matches!(cmd_input.source, session::CmdSource::Internal),
            ) {
                println!(
                    "Web link: {}/task/{}@{}",
                    session::get_web_base_url(),
                    haitask.name,
                    haitask.version
                );
                // FUTURE: Consider pretty printing config. For now, print the
                // raw config so that it's easier for people to copy + paste
                // for their own purposes.
                term_color::print_with_syntax_highlighting(config.as_str(), "toml");
                session_history_add_user_text_entry(
                    &config,
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskVersions(cmd::TaskVersionsCmd { task_fqn }) => {
            if config::is_valid_task_fqn(task_fqn).is_none() {
                eprintln!(
                    "invalid task fqn (fully-qualified name): format should be username/task-name"
                );
                return ProcessCmdResult::Loop;
            };
            let client = mk_api_client(Some(session));
            use api::types::task::TaskListVersionsArg;
            match client
                .task_list_versions(TaskListVersionsArg {
                    task_fqn: task_fqn.to_owned(),
                })
                .await
            {
                Ok(res) => {
                    for version in res.versions {
                        println!("{}", version);
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Asset(cmd::AssetCmd { asset_name, editor }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            let (asset_contents, asset_entry) =
                match asset_editor::get_asset(&api_client, &asset_name, true)
                    .await
                    .map(|(ac, ae)| (ac, Some(ae)))
                {
                    Ok(contents) => contents,
                    Err(asset_editor::GetAssetError::BadName) => (vec![], None),
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_entry_ref = asset_entry
                .as_ref()
                .map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
            let _ = asset_editor::edit_with_editor_api(
                &api_client,
                &session.shell,
                &editor.clone().unwrap_or(session.editor.clone()),
                &asset_contents,
                &asset_name,
                asset_entry_ref,
                asset_entry
                    .and_then(|entry| entry.metadata)
                    .and_then(|md| md.content_type),
                false,
                update_asset_tx,
                debug,
            )
            .await;
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetNew(cmd::AssetNewCmd {
            asset_name,
            contents,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            if asset_editor::get_invalid_asset_name_re().is_match(&asset_name) {
                // A client-side check is performed because interactive editors
                // like vim sometimes swallow the error message which means a
                // user won't be aware that their new asset didn't save.
                eprintln!("error: invalid name");
                return ProcessCmdResult::Loop;
            }
            let api_client = mk_api_client(Some(session));
            if let Some(contents) = contents {
                let _ = update_asset_tx
                    .send(asset_editor::WorkerAssetMsg::Update(
                        asset_editor::WorkerAssetUpdate {
                            asset_name,
                            asset_entry_ref: None,
                            new_contents: contents.clone().into_bytes(),
                            is_push: false,
                            api_client,
                            one_shot: true,
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
                    false,
                    update_asset_tx,
                    debug,
                )
                .await;
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetEdit(cmd::AssetEditCmd { asset_name }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            let (asset_contents, asset_entry) =
                match asset_editor::get_asset(&api_client, &asset_name, false)
                    .await
                    .map(|(ac, ae)| (ac, Some(ae)))
                {
                    Ok(asset_get_res) => asset_get_res,
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_entry_ref = asset_entry
                .as_ref()
                .map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
            let _ = asset_editor::edit_with_editor_api(
                &api_client,
                &session.shell,
                &session.editor,
                &asset_contents,
                &asset_name,
                asset_entry_ref,
                asset_entry
                    .and_then(|entry| entry.metadata)
                    .and_then(|md| md.content_type),
                false,
                update_asset_tx,
                debug,
            )
            .await;
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetPush(cmd::AssetPushCmd {
            asset_name,
            contents,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            if let Some(contents) = contents {
                let _ = update_asset_tx
                    .send(asset_editor::WorkerAssetMsg::Update(
                        asset_editor::WorkerAssetUpdate {
                            asset_name,
                            asset_entry_ref: None,
                            new_contents: contents.clone().into_bytes(),
                            is_push: true,
                            api_client,
                            one_shot: true,
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
                    debug,
                )
                .await;
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetList(cmd::AssetListCmd { prefix }) => {
            let prefix = expand_pub_asset_name(prefix, &session.account);
            use crate::api::types::asset::{
                AssetEntryIterArg, AssetEntryIterError, AssetEntryIterNextArg,
            };
            let api_client = mk_api_client(Some(session));
            let mut entries = vec![];
            let mut asset_iter_res = match api_client
                .asset_entry_iter(AssetEntryIterArg {
                    prefix: Some(prefix),
                    limit: 200,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    match e {
                        api::client::RequestError::Route(AssetEntryIterError::Empty) => {
                            eprintln!("[empty]");
                        }
                        _ => {
                            eprintln!("error: {}", e);
                        }
                    }
                    return ProcessCmdResult::Loop;
                }
            };

            let folders = asset_iter_res.collapsed_prefixes.clone();
            let mut printed_folders = HashSet::new();

            let mut asset_list_output = vec![];
            if asset_iter_res.has_more {
                println!("[Listing assets unsorted due to size]");
                let mut seen = HashSet::new();
                loop {
                    entries.extend_from_slice(&asset_iter_res.entries);
                    for entry in &asset_iter_res.entries {
                        if entry.op == AssetEntryOp::Delete {
                            continue;
                        }
                        if seen.contains(&entry.name) {
                            // In case an entry is modified during iteration
                            // (e.g. asset edited; metadata added)
                            continue;
                        }
                        seen.insert(entry.name.clone());
                        let line = if let Some(folder) = folders
                            .iter()
                            .find(|folder_prefix| entry.name.starts_with(*folder_prefix))
                        {
                            if !printed_folders.contains(folder) {
                                printed_folders.insert(folder);
                                Some(print_folder(folder))
                            } else {
                                None
                            }
                        } else {
                            Some(print_asset_entry(entry))
                        };
                        if let Some(line) = line {
                            asset_list_output.push(line);
                        }
                    }
                    if !asset_iter_res.has_more {
                        break;
                    }
                    asset_iter_res = match api_client
                        .asset_entry_iter_next(AssetEntryIterNextArg {
                            cursor: asset_iter_res.cursor,
                            limit: 200,
                        })
                        .await
                    {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("error: {}", e);
                            return ProcessCmdResult::Loop;
                        }
                    };
                }
            } else {
                // If all entries are fetched in one-go, sort them.
                entries.extend_from_slice(&asset_iter_res.entries);
                entries.sort_by(|a, b| human_sort::compare(&a.name, &b.name));
                for entry in &entries {
                    let line = if let Some(folder) = folders
                        .iter()
                        .find(|folder_prefix| entry.name.starts_with(*folder_prefix))
                    {
                        if !printed_folders.contains(folder) {
                            printed_folders.insert(folder);
                            Some(print_folder(folder))
                        } else {
                            None
                        }
                    } else {
                        Some(print_asset_entry(entry))
                    };
                    if let Some(line) = line {
                        asset_list_output.push(line);
                    }
                }
            }
            let asset_list_output = asset_list_output.join("\n");
            session_history_add_user_cmd_and_reply_entries(
                raw_user_input,
                &asset_list_output,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetSearch(cmd::AssetSearchCmd { q }) => {
            use crate::api::types::asset::AssetEntrySearchArg;
            let api_client = mk_api_client(Some(session));
            let asset_search_res = match api_client
                .asset_entry_search(AssetEntrySearchArg {
                    q: q.into(),
                    asset_pool_path: None,
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            let mut asset_search_output = vec![];
            for entry in &asset_search_res.semantic_matches {
                let line = print_asset_entry(entry);
                asset_search_output.push(line);
            }
            let asset_search_output = asset_search_output.join("\n");
            session_history_add_user_cmd_and_reply_entries(
                raw_user_input,
                &asset_search_output,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetLoad(cmd::AssetLoadCmd { asset_name })
        | cmd::Cmd::AssetView(cmd::AssetViewCmd { asset_name }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            let asset_contents =
                match asset_editor::get_asset_as_text(&api_client, &asset_name, false).await {
                    Ok(contents) => contents,
                    Err(asset_editor::GetAssetError::BadName) => {
                        let err_msg = format!("error: asset not found: {}", asset_name);
                        eprintln!("{}", err_msg);
                        session_history_add_user_cmd_and_reply_entries(
                            raw_user_input,
                            &err_msg,
                            session,
                            bpe_tokenizer,
                            (is_task_mode_step, LogEntryRetentionPolicy::None),
                        );
                        return ProcessCmdResult::Loop;
                    }
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_contents_with_delimeters = format!(
                "{}\n<<<<<< BEGIN_ASSET: {} >>>>>>\n{}\n<<<<<< END_ASSET: {} >>>>>>",
                raw_user_input, asset_name, asset_contents, asset_name,
            );

            let asset_token_count = session_history_add_user_text_entry(
                &asset_contents_with_delimeters,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::ConversationLoad),
            );
            if matches!(cmd, cmd::Cmd::AssetLoad(_)) {
                println!("Loaded: {} ({} tokens)", asset_name, asset_token_count);
            } else {
                println!("{}", asset_contents);
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetRevisions(cmd::AssetRevisionsCmd { asset_name, count }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));

            use crate::api::types::asset::{
                AssetCreatedBy, AssetEntryOp, AssetMetadataInfo, AssetRevision,
                AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
            };

            async fn print_revision(
                revision: &AssetRevision,
                session: &mut SessionState,
                bpe_tokenizer: &tiktoken_rs::CoreBPE,
                is_task_mode_step: bool,
            ) {
                println!("Revision ID: {}", revision.asset.rev_id);
                if let AssetCreatedBy::User(user) = &revision.asset.created_by {
                    println!("By: {}", user.username);
                }
                println!(
                    "Op: {}",
                    match revision.op {
                        AssetEntryOp::Add => {
                            "add"
                        }
                        AssetEntryOp::Push => {
                            "push"
                        }
                        AssetEntryOp::Delete => {
                            "delete"
                        }
                        AssetEntryOp::Edit => {
                            "edit"
                        }
                        AssetEntryOp::Fork => {
                            "fork"
                        }
                        AssetEntryOp::Metadata => {
                            "metadata"
                        }
                        AssetEntryOp::Other => {
                            "other"
                        }
                    }
                );
                if let Some(AssetMetadataInfo {
                    url: Some(metadata_url),
                    ..
                }) = revision.metadata.as_ref()
                {
                    if let Some(contents_bin) = asset_editor::get_asset_raw(metadata_url).await {
                        let contents = String::from_utf8_lossy(&contents_bin);
                        println!("Metadata: {}", &contents);
                        session_history_add_user_text_entry(
                            &contents,
                            session,
                            bpe_tokenizer,
                            (is_task_mode_step, LogEntryRetentionPolicy::None),
                        );
                    }
                }
                if let Some(data_url) = revision.asset.url.as_ref() {
                    if let Some(contents_bin) = asset_editor::get_asset_raw(data_url).await {
                        let contents = String::from_utf8_lossy(&contents_bin);
                        println!("{}", &contents);
                        session_history_add_user_text_entry(
                            &contents,
                            session,
                            bpe_tokenizer,
                            (is_task_mode_step, LogEntryRetentionPolicy::None),
                        );
                    }
                }
                println!();
            }
            let mut remaining = *count;
            let mut revision_cursor = match api_client
                .asset_revision_iter(AssetRevisionIterArg {
                    entry_ref: EntryRef::Name(asset_name),
                    limit: 1,
                    direction: RevisionIterDirection::Older,
                })
                .await
            {
                Ok(iter_res) => {
                    println!(
                        "Total Revisions (approximate): {}",
                        iter_res.approx_remaining
                    );
                    println!();
                    for revision in iter_res.revisions {
                        if let Some(n) = remaining {
                            if n == 0 {
                                break;
                            }
                            remaining = Some(n - 1);
                        }
                        print_revision(&revision, session, bpe_tokenizer, is_task_mode_step).await;
                    }
                    iter_res.next
                }
                Err(e) => {
                    eprintln!("error: failed to get revisions: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            if revision_cursor.is_none() {
                return ProcessCmdResult::Loop;
            }
            loop {
                if let Some(n) = remaining {
                    if n == 0 {
                        break;
                    }
                    remaining = Some(n - 1);
                } else {
                    println!("Press any key to continue... CTRL+C to stop");
                    let _ = crossterm::terminal::enable_raw_mode();
                    if let Ok(crossterm::event::Event::Key(key_event)) = crossterm::event::read() {
                        // Stop on Ctrl+C
                        if key_event.code == crossterm::event::KeyCode::Char('c')
                            && key_event
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)
                        {
                            let _ = crossterm::terminal::disable_raw_mode();
                            return ProcessCmdResult::Loop;
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
                            println!(
                                "Remaining Revisions (approximate): {}",
                                iter_next_res.approx_remaining
                            );
                            println!();
                            for revision in iter_next_res.revisions {
                                print_revision(
                                    &revision,
                                    session,
                                    bpe_tokenizer,
                                    is_task_mode_step,
                                )
                                .await;
                            }
                            iter_next_res.next
                        }
                        Err(e) => {
                            eprintln!("error: failed to get revisions: {}", e);
                            return ProcessCmdResult::Loop;
                        }
                    };
                } else {
                    break;
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetFollow(cmd::AssetFollowCmd { asset_name }) => {
            println!("WARN: /asset-follow is for debugging.");
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            use crate::api::types::asset::{
                AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
            };
            let api_client = mk_api_client(Some(session));
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
                    eprintln!("error: failed to get revisions: {}", e);
                    return ProcessCmdResult::Loop;
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
                    eprintln!("error: failed to connect: {}", e);
                    return ProcessCmdResult::Loop;
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
                        return ProcessCmdResult::Loop;
                    }
                }
            } {
                println!("Received: {:?}", msg);
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
                                    if let Some(data_url) = revision.asset.url.as_ref() {
                                        if let Some(contents_bin) =
                                            asset_editor::get_asset_raw(data_url).await
                                        {
                                            let contents = String::from_utf8_lossy(&contents_bin);
                                            println!("{}", &contents);
                                            session_history_add_user_text_entry(
                                                &contents,
                                                session,
                                                bpe_tokenizer,
                                                (is_task_mode_step, LogEntryRetentionPolicy::None),
                                            );
                                        }
                                    }
                                }
                                iter_res.next.expect("missing cursor").cursor
                            }
                            Err(e) => {
                                eprintln!("error: failed to get revisions: {}", e);
                                return ProcessCmdResult::Loop;
                            }
                        };
                    }
                    Err(e) => {
                        eprintln!("error: websocket: {}", e);
                        break;
                    }
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetListen(cmd::AssetListenCmd { asset_name, cursor }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            use crate::api::types::asset::{
                AssetCreatedBy, AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef,
                RevisionIterDirection,
            };
            let api_client = mk_api_client(Some(session));
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
                        eprintln!("error: failed to get revisions: {}", e);
                        return ProcessCmdResult::Loop;
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
                        eprintln!("error: failed to connect: {}", e);
                        attempt += 1;
                        let backoff_duration =
                            std::time::Duration::from_secs(2_u64.pow(attempt).min(60)); // Cap backoff
                        eprintln!("retrying in {} seconds...", backoff_duration.as_secs());
                        // For ergonomics, support ctrl+c to stop reconnecting
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {
                                return ProcessCmdResult::Loop;
                            }
                            _ = tokio::time::sleep(backoff_duration) => {
                            }
                        }
                        continue;
                    }
                };
                if attempt > 0 {
                    println!("connected");
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
                            return ProcessCmdResult::Loop;
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
                                        println!("{}", output);
                                        session_history_add_user_text_entry(
                                            &output,
                                            session,
                                            bpe_tokenizer,
                                            (is_task_mode_step, LogEntryRetentionPolicy::None),
                                        );
                                    }
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("error: failed to get revisions: {}", e);
                                    return ProcessCmdResult::Loop;
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
                                eprintln!("error: websocket: {}", e);
                            }
                        }
                    }
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetLink(cmd::AssetLinkCmd { asset_name }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            use crate::api::types::asset::AssetGetArg;
            let asset_data_url = match api_client.asset_get(AssetGetArg { name: asset_name }).await
            {
                Ok(res) => {
                    if let Some(data_url) = res.entry.asset.url {
                        data_url
                    } else {
                        eprintln!("error: asset does not have link");
                        return ProcessCmdResult::Loop;
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            println!("{}", asset_data_url);
            session_history_add_user_text_entry(
                &asset_data_url,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetRemove(cmd::AssetRemoveCmd { asset_name }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            use crate::api::types::asset::AssetRemoveArg;
            match api_client
                .asset_remove(AssetRemoveArg { name: asset_name })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            session_history_add_user_cmd_and_reply_entries(
                raw_user_input,
                "Removed",
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetImport(cmd::AssetImportCmd {
            target_asset_name,
            source_file_path,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let target_asset_name = expand_pub_asset_name(target_asset_name, &session.account);
            let source_file_path = match shellexpand::full(&source_file_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    eprintln!("error: undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::Loop;
                }
            };
            let asset_contents = match fs::read(source_file_path) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: failed to read: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            use crate::api::types::asset::{AssetPutArg, PutConflictPolicy};
            let api_client = mk_api_client(Some(session));
            match api_client
                .asset_put(AssetPutArg {
                    name: target_asset_name,
                    data: asset_contents,
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to put: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetExport(cmd::AssetExportCmd {
            source_asset_name,
            target_file_path,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let source_asset_name = expand_pub_asset_name(source_asset_name, &session.account);
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
                    eprintln!("error: undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::Loop;
                }
            };
            let api_client = mk_api_client(Some(session));
            let (asset_contents, _) =
                match asset_editor::get_asset(&api_client, &source_asset_name, false).await {
                    Ok(contents) => contents,
                    Err(_) => return ProcessCmdResult::Loop,
                };
            match fs::write(&target_file_path, asset_contents) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to save: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetSyncDown(cmd::AssetSyncDownCmd {
            prefix,
            target_path,
        }) => {
            let prefix = expand_pub_asset_name(prefix, &session.account);
            let target_path = match shellexpand::full(&target_path) {
                Ok(s) => s.into_owned(),
                Err(e) => {
                    eprintln!("error: undefined path variable: {}", e.var_name);
                    return ProcessCmdResult::Loop;
                }
            };
            let api_client = mk_api_client(Some(session));
            let _ = crate::asset_sync::sync_prefix(&api_client, &prefix, &target_path, debug).await;
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetTemp(cmd::AssetTempCmd { asset_name, count }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));

            if let Some(count) = count {
                use crate::api::types::asset::{
                    AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
                };

                let max_concurrent_downloads = 10;

                let mut remaining = *count;
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
                        eprintln!("error: failed to get revisions: {}", e);
                        return ProcessCmdResult::Loop;
                    }
                };

                let mut revision_cursor = iter_res.next.clone();

                let seen_revisions_map: Arc<Mutex<HashMap<String, std::path::PathBuf>>> =
                    Arc::new(Mutex::new(HashMap::new()));
                let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));
                let mut handles = Vec::new();

                for revision in iter_res.revisions {
                    if remaining == 0 {
                        break;
                    }
                    remaining -= 1;

                    let asset_name_clone = asset_name.clone();
                    let sem_clone = Arc::clone(&semaphore);
                    let seen_revisions_map_clone = seen_revisions_map.clone();

                    let handle = tokio::spawn(async move {
                        let _permit = sem_clone.acquire().await.unwrap();
                        crate::asset_sync::download_revision_to_temp(
                            &asset_name_clone,
                            &revision,
                            seen_revisions_map_clone,
                        )
                        .await
                    });
                    handles.push(handle);
                }

                println!("(newest revisions first)");
                let mut all_msgs = vec!["(newest revisions first)".to_string()];

                for handle in futures::future::join_all(handles).await {
                    // Unwrap the JoinHandle result to get the inner result
                    if let Ok(result) = handle {
                        if let Some(msg) = &result.0 {
                            println!("{}", msg);
                            all_msgs.push(msg.clone());
                        }
                        if let Some((temp_file, _temp_file_path)) = result.1 {
                            session.temp_files.push((temp_file, is_task_mode_step));
                        }
                    } else {
                        // Handle the case where the task panicked
                        eprintln!("A download task panicked");
                    }
                }

                loop {
                    if remaining == 0 {
                        break;
                    }
                    let mut handles = Vec::new();
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
                                eprintln!("error: failed to get revisions: {}", e);
                                return ProcessCmdResult::Loop;
                            }
                        };
                        revision_cursor = iter_next_res.next;

                        for revision in iter_next_res.revisions {
                            if remaining == 0 {
                                break;
                            }
                            remaining -= 1;
                            let asset_name_clone = asset_name.clone();
                            let sem_clone = Arc::clone(&semaphore);
                            let seen_revisions_map_clone = seen_revisions_map.clone();

                            let handle = tokio::spawn(async move {
                                let _permit = sem_clone.acquire().await.unwrap();
                                crate::asset_sync::download_revision_to_temp(
                                    &asset_name_clone,
                                    &revision,
                                    seen_revisions_map_clone,
                                )
                                .await
                            });
                            handles.push(handle);
                        }

                        for handle in futures::future::join_all(handles).await {
                            // Unwrap the JoinHandle result to get the inner result
                            if let Ok(result) = handle {
                                if let Some(msg) = &result.0 {
                                    println!("{}", msg);
                                    all_msgs.push(msg.clone());
                                }
                                if let Some((temp_file, _temp_file_path)) = result.1 {
                                    session.temp_files.push((temp_file, is_task_mode_step));
                                }
                            } else {
                                // Handle the case where the task panicked
                                eprintln!("A download task panicked");
                            }
                        }
                    } else {
                        break;
                    }
                }
                session_history_add_user_cmd_and_reply_entries(
                    raw_user_input,
                    &all_msgs.join("\n"),
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            } else {
                let (data_contents, metadata_contents, _asset_entry) =
                    match asset_editor::get_asset_and_metadata(&api_client, &asset_name, false)
                        .await
                    {
                        Ok(res) => res,
                        Err(_) => return ProcessCmdResult::Loop,
                    };

                let (data_temp_file, data_temp_file_path) =
                    match asset_editor::create_empty_temp_file(&asset_name, None) {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("error: failed to download: {}", e);
                            return ProcessCmdResult::Loop;
                        }
                    };
                match fs::write(&data_temp_file_path, data_contents) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("error: failed to save: {}", e);
                    }
                }
                session.temp_files.push((data_temp_file, is_task_mode_step));
                let mut msgs = vec![];
                let msg = format!(
                    "Asset '{}' copied to '{}'",
                    asset_name,
                    data_temp_file_path.display()
                );
                println!("{}", msg);
                msgs.push(msg);
                if let Some(metadata_contents) = metadata_contents {
                    let metadata_name = format!("{}.metadata", asset_name);
                    let (metadata_temp_file, metadata_temp_file_path) =
                        match asset_editor::create_empty_temp_file(&metadata_name, None) {
                            Ok(res) => res,
                            Err(e) => {
                                eprintln!("error: failed to download: {}", e);
                                return ProcessCmdResult::Loop;
                            }
                        };
                    match fs::write(&metadata_temp_file_path, metadata_contents) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("error: failed to save: {}", e);
                        }
                    }
                    session
                        .temp_files
                        .push((metadata_temp_file, is_task_mode_step));
                    let msg = format!(
                        "Metadata of '{}' copied to '{}'",
                        asset_name,
                        metadata_temp_file_path.display()
                    );
                    println!("{}", msg);
                    msgs.push(msg);
                }
                session_history_add_user_cmd_and_reply_entries(
                    raw_user_input,
                    &msgs.join("\n"),
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetAcl(cmd::AssetAclCmd {
            asset_name,
            ace_permission,
            ace_type,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            let api_ace_type = match ace_type {
                cmd::AssetAceType::Allow => AceType::Allow,
                cmd::AssetAceType::Deny => AceType::Deny,
                cmd::AssetAceType::Default => AceType::Default,
            };
            use api::types::asset::{AceType, AssetEntryAclSetArg, EntryRef};
            let _ = api_client
                .asset_entry_acl_set(AssetEntryAclSetArg {
                    entry_ref: EntryRef::Name(asset_name.to_owned()),
                    read_data: if matches!(ace_permission, cmd::AssetAcePermission::ReadData) {
                        Some(api_ace_type.clone())
                    } else {
                        None
                    },
                    read_revisions: if matches!(
                        ace_permission,
                        cmd::AssetAcePermission::ReadRevisions
                    ) {
                        Some(api_ace_type.clone())
                    } else {
                        None
                    },
                    push_data: if matches!(ace_permission, cmd::AssetAcePermission::PushData) {
                        Some(api_ace_type.clone())
                    } else {
                        None
                    },
                })
                .await;
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetMdGet(cmd::AssetMdGetCmd { asset_name }) => {
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            use crate::api::types::asset::{AssetGetArg, AssetMetadataInfo};
            match api_client.asset_get(AssetGetArg { name: asset_name }).await {
                Ok(res) => {
                    if let Some(AssetMetadataInfo {
                        url: Some(metadata_url),
                        ..
                    }) = res.entry.metadata.as_ref()
                    {
                        if let Some(contents_bin) = asset_editor::get_asset_raw(metadata_url).await
                        {
                            let contents = String::from_utf8_lossy(&contents_bin);
                            let md_json = serde_json::from_str::<serde_json::Value>(&contents)
                                .expect("failed to parse metadata");
                            let contents_pretty = serde_json::to_string_pretty(&md_json)
                                .expect("failed to pretty-print md json");
                            println!("{}", &contents_pretty);
                            session_history_add_user_cmd_and_reply_entries(
                                raw_user_input,
                                &contents_pretty,
                                session,
                                bpe_tokenizer,
                                (is_task_mode_step, LogEntryRetentionPolicy::None),
                            );
                        }
                    } else {
                        println!("no metadata");
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetMdSet(cmd::AssetMdSetCmd {
            asset_name,
            metadata,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
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
                    eprintln!("error: metadata put failed: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            session_history_add_user_text_entry(
                raw_user_input,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetMdSetKey(cmd::AssetMdSetKeyCmd {
            asset_name,
            key,
            value,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let value_json = match serde_json::from_str::<serde_json::Value>(value) {
                Ok(value_json) => value_json,
                Err(e) => {
                    eprintln!("error: not a json value: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            let api_client = mk_api_client(Some(session));
            if asset_editor::asset_metadata_set_key(&api_client, &asset_name, key, Some(value_json))
                .await
                .is_ok()
            {
                session_history_add_user_text_entry(
                    raw_user_input,
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetMdDelKey(cmd::AssetMdDelKeyCmd { asset_name, key }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let asset_name = expand_pub_asset_name(asset_name, &session.account);
            let api_client = mk_api_client(Some(session));
            if asset_editor::asset_metadata_set_key(&api_client, &asset_name, key, None)
                .await
                .is_ok()
            {
                session_history_add_user_text_entry(
                    raw_user_input,
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetFolderCollapse(cmd::AssetFolderCollapseCmd { prefix }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let prefix = expand_pub_asset_name(prefix, &session.account);

            use api::types::asset::AssetPoolFolderCollapseArg;
            let api_client = mk_api_client(Some(session));
            match api_client
                .asset_folder_collapse(AssetPoolFolderCollapseArg { prefix })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to collapse folder: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetFolderExpand(cmd::AssetFolderExpandCmd { prefix }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let prefix = expand_pub_asset_name(prefix, &session.account);

            use api::types::asset::AssetPoolFolderExpandArg;
            let api_client = mk_api_client(Some(session));
            match api_client
                .asset_folder_expand(AssetPoolFolderExpandArg { prefix })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: failed to expand folder: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AssetFolderList(cmd::AssetFolderListCmd { prefix }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let prefix = prefix
                .as_ref()
                .map(|prefix| expand_pub_asset_name(prefix, &session.account));

            use api::types::asset::AssetPoolFolderListArg;
            let api_client = mk_api_client(Some(session));
            match api_client
                .asset_folder_list(AssetPoolFolderListArg { prefix })
                .await
            {
                Ok(res) => {
                    for folder in res.folders {
                        println!("{}", folder);
                    }
                }
                Err(e) => {
                    eprintln!("error: failed to list folders: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::ChatResume(cmd::ChatResumeCmd { chat_log_name }) => {
            let chat_log_contents = if let Some(chat_log_name) = chat_log_name {
                if session.account.is_none() {
                    eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                    return ProcessCmdResult::Loop;
                }
                let api_client = mk_api_client(Some(session));
                match asset_editor::get_asset_as_text(&api_client, chat_log_name, false).await {
                    Ok(contents) => contents,
                    Err(_) => return ProcessCmdResult::Loop,
                }
            } else {
                let username = if let Some(account) = session.account.as_ref() {
                    account.username.clone()
                } else {
                    "".to_string()
                };
                if let Some(res) = db::get_misc_entry(&*db.lock().await, &username, "chat-last")
                    .expect("failed to write to db")
                {
                    res.0
                } else {
                    eprintln!("error: no chat saved");
                    return ProcessCmdResult::Loop;
                }
            };
            let history = match serde_json::from_str::<Vec<db::LogEntry>>(&chat_log_contents) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: chat log bad format: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            session.history = history;

            // Print out conversation to help user regain context
            for (i, log_entry) in session.history.iter().enumerate() {
                let role_name = match log_entry.message.role {
                    chat::MessageRole::Assistant => "assistant",
                    chat::MessageRole::User => "user",
                    chat::MessageRole::Tool => "tool",
                    chat::MessageRole::System => break,
                };

                if log_entry.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
                    session.input_loaded_tokens += log_entry.tokens;
                    if let chat::MessageContent::Text { text } = &log_entry.message.content[0] {
                        println!("{}[{}]: {}", role_name, i, text.split_once("\n").unwrap().0);
                        println!();
                    } else if let chat::MessageContent::ImageUrl { image_url } =
                        &log_entry.message.content[0]
                    {
                        println!("{}[{}]:", role_name, i);
                        match loader::resolve_image_b64(&image_url.url).await {
                            Ok(img_png_b64) => {
                                term::print_image_to_term(&img_png_b64).unwrap();
                                println!();
                            }
                            Err(e) => {
                                eprintln!("error: failed to load image: {}", e);
                            }
                        }
                    }
                } else {
                    let mut entry_body = String::new();
                    session.input_tokens += log_entry.tokens;
                    for part in &log_entry.message.content {
                        match part {
                            chat::MessageContent::Text { text } => {
                                entry_body.push_str(text);
                            }
                            chat::MessageContent::ImageUrl { .. } => entry_body.push_str("[image]"),
                        }
                        entry_body.push('\n');
                    }

                    let left_prompt = format!("{}[{}]:", role_name, i);
                    if matches!(log_entry.message.role, chat::MessageRole::Assistant) {
                        if let Some(tool_calls) = log_entry.message.tool_calls.as_ref() {
                            println!("{}", left_prompt.bright_green());
                            for tool_call in tool_calls {
                                let tool_name = tool_call.function.name.clone();
                                let mut json_obj_acc = crate::ai_provider::util::JsonObjectAccumulator::new(
                                    tool_call.id.clone(),
                                    tool_name.clone(),
                                    crate::ai_provider::tool_schema::get_syntax_highlighter_token_from_tool_name(&tool_name),
                                    HashSet::new(),
                                );
                                json_obj_acc.acc(&tool_call.function.arguments);
                                json_obj_acc.end();
                                println!();
                                println!();
                            }
                        } else {
                            println!("{}", left_prompt.bright_green());
                            let mut sh_printer =
                                crate::ai_provider::util::SyntaxHighlighterPrinter::new();
                            sh_printer.acc(&entry_body);
                            sh_printer.end();
                        }
                    } else {
                        print!("{} {}", left_prompt.bright_green(), entry_body);
                    }
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::ChatSave(cmd::ChatSaveCmd { chat_log_name }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let chat_log_asset_name = if let Some(chat_log_name) = chat_log_name {
                chat_log_name.to_owned()
            } else {
                let now = chrono::Local::now();
                format!("chat/{}", now.format("%Y-%m-%d-%H%M%S"))
            };

            let abridged_history = session::get_abridged_history(&session.history);
            let abridged_history_tokens =
                bpe_tokenizer.encode_with_special_tokens(&abridged_history);
            let chat_title = if abridged_history.len() > 100 {
                print!(
                    "Generating title ({} tokens)... ",
                    abridged_history_tokens
                        .len()
                        .to_formatted_string(&Locale::en)
                );
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                prompt_ai_simple(
                    &format!(
                        r#"Generate a short title for the included chat log.
Do not quote it.
Do not include anything besides the title.
Since the chat is already known as a conversation, do
not include words that imply its a conversation or
lesson (e.g. "understanding").\n\n{}"#,
                        abridged_history
                    ),
                    session,
                    cfg,
                    ctrlc_handler,
                    debug,
                )
                .await
            } else {
                None
            };
            println!("Saving to asset: {}", chat_log_asset_name);
            let serialized_log = serde_json::to_string_pretty(&session.history).unwrap();
            let api_client = mk_api_client(Some(session));
            use api::types::asset::{AssetPutTextArg, PutConflictPolicy};
            match api_client
                .asset_put_text(AssetPutTextArg {
                    name: chat_log_asset_name.clone(),
                    data: serialized_log,
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await
            {
                Ok(_) => {
                    if let Some(chat_title) = chat_title {
                        let _ = asset_editor::asset_metadata_set_key(
                            &api_client,
                            &chat_log_asset_name,
                            "title",
                            Some(serde_json::Value::String(chat_title)),
                        )
                        .await;
                    }
                }
                Err(e) => {
                    eprintln!("error: failed to save chat log: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Email(cmd::EmailCmd { subject, body }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let api_client = mk_api_client(Some(session));
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
                    session_history_add_user_text_entry(
                        raw_user_input,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::None),
                    );
                }
                Err(e) => {
                    eprintln!("error: failed to send email: {}", e);
                    if let RequestError::Route(EmailRecipientSendError::NoDefaultRecipient) = e {
                        eprintln!("Use `/task hai/add-email` to add an email recipient");
                    }
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Fns => {
            if session.ai_defined_fns.is_empty() {
                println!("No AI-defined functions available.");
            } else {
                println!("Available AI-defined functions:");
                println!();
                for (fn_name, ai_defined_fn) in &session.ai_defined_fns {
                    println!("- /{}", fn_name);
                    println!("{}", ai_defined_fn.0.fn_def);
                    println!()
                }
            }
            ProcessCmdResult::Loop
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
                    print!("{}", output);
                    session_history_add_user_cmd_and_reply_entries(
                        raw_user_input,
                        &output,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::None),
                    );
                }
                cmd::StdCmd::NewDayAlert => {
                    session.add_msg_on_new_day = true;
                    session_history_add_user_text_entry(
                        raw_user_input,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::None),
                    );
                }
                cmd::StdCmd::Which(prog) => {
                    session.add_msg_on_new_day = true;
                    let output = match which::which(prog) {
                        Ok(path) => path.display().to_string(),
                        Err(which::Error::CannotFindBinaryPath) => format!("'{}' not found", prog),
                        Err(e) => format!("error: could not find {}: {}", prog, e),
                    };
                    println!("{}", output);
                    session_history_add_user_cmd_and_reply_entries(
                        raw_user_input,
                        &output,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::None),
                    );
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::FnExec(cmd::FnExecCmd { fn_name, arg }) => {
            let ai_defined_fn =
                if let Some((ai_defined_fn, _)) = session.ai_defined_fns.get(fn_name) {
                    ai_defined_fn
                } else {
                    eprintln!("error: function '{}' is undefined", fn_name);
                    return ProcessCmdResult::Loop;
                };

            let arg_with_default = if arg.is_empty()
                && matches!(
                    ai_defined_fn.fn_tool,
                    tool::FnTool::FnPy | tool::FnTool::FnPyUv
                ) {
                "None".to_string()
            } else {
                arg.clone()
            };

            // Execute AI-defined tool/function
            let output = match tool::execute_ai_defined_tool(
                &ai_defined_fn.fn_tool,
                &ai_defined_fn.fn_def,
                &arg_with_default,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: failed to execute tool: {}", e);
                    e.to_string()
                }
            };

            // Save output to conversation history
            session_history_add_user_cmd_and_reply_entries(
                raw_user_input,
                &output,
                session,
                bpe_tokenizer,
                (is_task_mode_step, LogEntryRetentionPolicy::None),
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Account(cmd::AccountCmd { username }) => {
            if let Some(username) = username {
                if username == "_" {
                    session::account_nobody_setup_session(session, db).await;
                } else {
                    let account = match db::switch_account(&*db.lock().await, username) {
                        Ok(Some(account)) => account,
                        Ok(None) => {
                            eprintln!(
                                "error: {} credentials not found; try /account-login",
                                username
                            );
                            return ProcessCmdResult::Loop;
                        }
                        Err(_) => {
                            eprintln!("error: failed to read db");
                            return ProcessCmdResult::Loop;
                        }
                    };
                    println!("ハイ {}!", account.username);
                    session::account_login_setup_session(
                        session,
                        db,
                        &account.user_id,
                        &account.username,
                        &account.token,
                    )
                    .await;
                }
            } else {
                let output = if let Some(account) = &session.account {
                    println!("ハイ {}!", account.username);
                    account.username.clone()
                } else {
                    println!("You have not logged into an account. Try /account-login");
                    "You're not logged in".to_string()
                };
                session_history_add_user_cmd_and_reply_entries(
                    raw_user_input,
                    &output,
                    session,
                    bpe_tokenizer,
                    (is_task_mode_step, LogEntryRetentionPolicy::None),
                );
                match db::list_accounts(&*db.lock().await) {
                    Ok(usernames) => {
                        if !usernames.is_empty() {
                            println!();
                            println!("Available accounts (Try /account <username>):");
                            for username in usernames {
                                println!("- {}", username);
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("error: failed to read db");
                    }
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AccountNew => {
            let mut username;
            loop {
                username = match term::ask_question("Username?", false) {
                    Some(username) => username,
                    None => return ProcessCmdResult::Loop,
                };
                if username.len() >= 3 {
                    break;
                } else {
                    println!("Username must be at least 3 characters")
                }
            }
            let mut password;
            loop {
                password = match term::ask_question("Password?", true) {
                    Some(password) => password,
                    None => return ProcessCmdResult::Loop,
                };
                if password.len() >= 8 {
                    break;
                } else {
                    println!("Password must be at least 8 characters")
                }
            }
            let email_answer =
                match term::ask_question("Email (optional: if you forget your password)?", false) {
                    Some(email_answer) => email_answer,
                    None => return ProcessCmdResult::Loop,
                };
            let email = if email_answer.trim().is_empty() {
                None
            } else {
                Some(email_answer.trim().to_string())
            };
            println!("Read our terms of service: `/asset-view /hai/terms-of-service`");
            let terms_answer = term::ask_question_default_empty("Accept? (Type 'yes')", false);
            if terms_answer != "y" && terms_answer != "yes" {
                eprintln!("Awkward...");
                return ProcessCmdResult::Loop;
            }

            use api::types::account::AccountRegisterArg;
            let client = mk_api_client(None);
            match client
                .account_register(AccountRegisterArg {
                    username,
                    password,
                    email,
                })
                .await
            {
                Ok(res) => {
                    println!("ハイ {}!", res.username);
                    db::login_account(&*db.lock().await, &res.user_id, &res.username, &res.token)
                        .expect("failed to write login info");
                    session.account = Some(db::Account {
                        user_id: res.user_id,
                        username: res.username,
                        token: res.token,
                    });
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AccountLogin(cmd::AccountLoginCmd { username, password }) => {
            let username = if let Some(username) = username {
                username.to_owned()
            } else {
                match term::ask_question("Username?", false) {
                    Some(username) => username,
                    None => return ProcessCmdResult::Loop,
                }
            };
            let password = if let Some(password) = password {
                password.to_owned()
            } else {
                match term::ask_question("Password?", true) {
                    Some(password) => password,
                    None => return ProcessCmdResult::Loop,
                }
            };
            use api::types::account::AccountTokenFromLoginArg;
            let client = mk_api_client(None);
            match client
                .account_token_from_login(AccountTokenFromLoginArg { username, password })
                .await
            {
                Ok(res) => {
                    println!("ハイ {}!", res.username);
                    session::account_login_setup_session(
                        session,
                        db.clone(),
                        &res.user_id,
                        &res.username,
                        &res.token,
                    )
                    .await;
                    let client = mk_api_client(Some(session));
                    match client.account_get_balance(()).await {
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
                            eprintln!("error: could not fetch balance");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AccountBalance => {
            let client = mk_api_client(Some(session));
            match client.account_get_balance(()).await {
                Ok(res) => {
                    println!("Remaining balance: ${:.2}", res.remaining as f64 / 100.0);
                }
                Err(_) => {
                    eprintln!("error: could not fetch balance");
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AccountSubscribe => {
            match &session.account {
                Some(account) => account,
                None => {
                    eprintln!(
                        "You must be logged-in to subscribe. Try /account-login or /account-new"
                    );
                    return ProcessCmdResult::Loop;
                }
            };
            let client = mk_api_client(Some(session));
            let subscribe_link = match client.account_get_subscribe_link(()).await {
                Ok(res) => res.subscribe_link,
                Err(_) => {
                    println!("You're already subscribed.");
                    println!(
                        "Need more credits? Email me at ken@elkabany.com for help (sorry for the manual process)"
                    );
                    return ProcessCmdResult::Loop;
                }
            };
            println!("Subscribe to the hai basic plan ($6 USD / month):");
            println!(
                "- $3 USD in AI credits that can be used across OpenAI, Anthropic, Google, Deepseek"
            );
            println!("  - Use `/ai <model>` without having to provide your own API keys");
            println!("  - Unused credits expire after two months");
            println!("- 10 GB of asset storage and public link sharing");
            println!("- Send 1,000 emails per day with /email");
            println!("- An easy way to support the hai project and its ongoing experimentation");
            println!();
            println!("Subscribe with the Stripe link below:");
            println!();
            println!("{}", subscribe_link);
            println!();
            println!("- The business is \"Superego / Intertimes, Inc.\"");
            println!("  hai is a side project of the company");
            println!();
            println!(
                "After subscribing, run `/hai-router on`. The 🌐 icon means you're using credits instead of your personal API keys."
            );
            ProcessCmdResult::Loop
        }
        cmd::Cmd::AccountLogout(cmd::AccountLogoutCmd { username }) => {
            if let Some(cur_account) = &session.account {
                let target_username = username.as_ref().unwrap_or(&cur_account.username);
                let _ = db::remove_account(&*db.lock().await, target_username);
                session::account_nobody_setup_session(session, db).await;
            } else {
                // no-op since not logged-in
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Whois(cmd::WhoisCmd { username }) => {
            use api::types::account::AccountWhoisArg;
            let client = mk_api_client(Some(session));
            match client
                .account_whois(AccountWhoisArg {
                    username: username.into(),
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
                        whois_lines.push("Use `/task-view <task_name>` to learn more".to_string());
                    }
                    let whois_output = whois_lines.join("\n");
                    println!("{}", whois_output);
                    session_history_add_user_text_entry(
                        &whois_output,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::None),
                    );
                    if let Some(account) = &session.account {
                        if account.username == *username {
                            println!();
                            println!("To set a name or bio, run: `/task hai/account-update`");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Cost => {
            fn print_ai_model_prices(ai: &config::AiModel) {
                if let Some((input_cost_in_mills_per_million, output_cost_in_mills_per_million)) =
                    config::get_ai_model_cost(ai)
                {
                    println!(
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

                println!(
                    "=== Cost is *approximate* based on active model ({}) and GPT-3 tokenization ===",
                    config::get_ai_model_display_name(&session.ai)
                );
                println!();
                let cur_input_context_cost = config::mills_to_dollars(
                    ((input_cost_in_mills_per_million as f64)
                        * (cur_input_tokens as f64 / 1_000_000.0)) as u32,
                );
                println!(
                    "Your next prompt to the AI will have an input cost of: {} ({} tokens)",
                    cur_input_context_cost,
                    cur_input_tokens.to_formatted_string(&Locale::en)
                );
                println!();
                println!("This conversation has so far cost: {}", agg_cost);
                println!(
                    "    input: {} ({} tokens)    output: {} ({} tokens)",
                    agg_input_cost,
                    agg_input_tokens.to_formatted_string(&Locale::en),
                    agg_output_cost,
                    agg_output_tokens.to_formatted_string(&Locale::en)
                );
            } else {
                println!(
                    "=== No price data for {} ===",
                    config::get_ai_model_display_name(&session.ai)
                );
                println!("This conversation has used this many tokens:");
                println!(
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
                println!();
                println!("=== Popular model prices ===");
                println!(
                    "{:<24} {:<24} Per 1M output tokens",
                    "Model", "Per 1M input tokens"
                );
                for ai in [
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt41),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt41Mini),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4o),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4oMini),
                    config::AiModel::OpenAi(config::OpenAiModel::O3),
                    config::AiModel::OpenAi(config::OpenAiModel::O4Mini),
                    config::AiModel::Google(config::GoogleModel::Gemini25Flash),
                    config::AiModel::Google(config::GoogleModel::Gemini25Pro),
                    config::AiModel::Anthropic(config::AnthropicModel::Sonnet37(false)),
                    config::AiModel::Anthropic(config::AnthropicModel::Haiku35),
                    config::AiModel::DeepSeek(config::DeepSeekModel::DeepSeekChat),
                    config::AiModel::DeepSeek(config::DeepSeekModel::DeepSeekReasoner),
                ] {
                    print_ai_model_prices(&ai);
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::ToolMode(tool_mode_cmd) => {
            println!(
                "Entering tool mode; All messages are treated as prompts for {}. Use `!exit` when done",
                tool::tool_to_cmd(
                    &tool_mode_cmd.tool,
                    tool_mode_cmd.user_confirmation,
                    tool_mode_cmd.force_tool
                )
            );
            session.tool_mode = Some(tool_mode_cmd.clone());
            ProcessCmdResult::Loop
        }
        cmd::Cmd::ToolModeExit => {
            if session.tool_mode.is_some() {
                session.tool_mode = None;
            } else {
                eprintln!("warning: tool mode was not active");
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Prompt(cmd::PromptCmd { prompt, cache })
        | cmd::Cmd::Tool(cmd::ToolCmd { prompt, cache, .. }) => {
            ProcessCmdResult::PromptAi(prompt.to_owned(), *cache)
        }
    }
}

const HELP_MSG: &str = r##"Available Commands:

/? /h /help                  - Show this help menu
/q /quit                     - Bye (CTRL+D works too)
/n /new                      - New conversation
/r /reset                    - New conversation but retain /load-ed & /pin-ed data

--

/ai                          - Show the current AI model
/ai <model>                  - Switch AI model
                               Available models: 4o, 4o-mini, sonnet35, haiku35, llama32, llama32-vision, flash15
                               Prefix provider for any model: openai/*, anthropic/*, ollama/*, google/*
/ai-default                  - Show the default AI model on start up
/ai-default <model>          - Set the default AI model on start up
/temperature <t|none>        - Set the AI model temperature (0 for coding, higher for writing; depends on model)
/cd <path>                   - Change current working directory

--

/account [<username>]        - See current and available accounts
                               If username specified, switches to it. Use `_` to switch to no-user
/account-new                 - Make a new account
/account-login               - Login to your account
/account-logout [<username>] - Remove credentials of previously logged-in account
/account-balance             - Check credits remaining for hai-router
/account-subscribe           - Subscribe for hai-router & asset storage
/whois <username>            - Look up a user (try `ken`)
/hai-router <on|off>         - Turn on/off hai-router. Requires credits

--

/t /task <name|path>         - Enter task mode by loading task from repo (username/task-name) or file path
                               File path must start with `./`, `/`, or `~`
/task-search <query>         - Search for tasks in the repository
/task-view <name|path>       - View a task without loading it from repo or file path
/task-versions <name>        - List all versions of a task in the repository
/task-end                    - End task mode
/task-update <name>          - Update task to latest version
/task-publish <path>         - Publish task to repo (requires /account-login)
/task-forget <name>          - Forget all cached /ask-human answers
/task-purge <name>           - Remove task from your machine
/task-include <name|path>    - Include task commands in conversation without entering task mode

--

/l /load <glob path>         - Load files into the conversation (e.g., `/load src/**/*.py`)
                               Supports text files or PNG/JPG images
/load-url <url>              - Load url into the conversation
/e /exec <cmd>               - Executes a shell command and adds the output to this conversation
                               @asset can be used in place of file paths. These assets will be
                               transparently downloaded. If specified as a shell output redirect
                               (>), the output will be uploaded as an asset.
!!<cmd>                      - Alternative to `/exec` not to be confused with tools.
/prep                        - Queue a message to be sent with your next message (or, end with two blank lines)
/pin                         - Like /prep but the message is retained on /reset
/system-prompt               - Set a system prompt for the conversation
/clip                        - Copies the last message to your clipboard. Unlike !clip tool, AI is not prompted
/forget [<n>]                - Forget the last <n> messages in the conversation. Defaults to 1.
/keep <bottom> [<top>]       - Keep the last <bottom> messages in the conversation and forgets the rest.
                               If top is specified, keeps the first <top> messages as well.

--

Available Tools:
!clip <prompt>               - Ask AI to copy a part of the conversation to your clipboard
!py <prompt>                 - Ask AI to write Python script that will be executed on your machine
                               Searches for virtualenv in current dir & ancestors before falling back to python3
!sh <prompt>                 - Ask AI to write shell script or pipeline that will be executed on your machine
!hai <prompt>                - Ask AI to write and execute REPL command(s)
!'<cmd>' <prompt>            - Ask AI to write script that will be piped to this cmd through stdin
                               e.g. !'PG_PASSWORD=secret psql -h localhost -p 5432 -U postgres -d db' how many users?
                               e.g. !'uv run --python 3 --with geopy -' distance from san francisco to nyc
                               Vars from haivars & /setvar can be used: !'$psql' describe users table
! <prompt>                   - Re-use previous tool with new prompt
!                            - Re-use previous tool and prompt
!<tool>                      - Activates tool mode for the specified tool
                               In tool mode, all messages are treated as prompts for the tool.
                               Use !exit to exit tool mode

--

Standard Library Functions:
/std now                     - Displays the current date and time.
/std new-day-alert           - Make AI aware when a new day begins since the last interaction.
/std which <prog>            - Checks if program is available.

--

AI-Defined Reusable Functions (Experimental):
!fn-py <prompt>              - Ask AI to write a Python function to implement your prompt.
                               Function is given a name (`f<index>`) to invoke with: `/f<index> <arg>`
!fn-pyuv <prompt>            - Similar to `!fn-py` but `uv` is used allowing for the function to use
                               additional library dependencies via a script dependency comment section.
!fn-sh <prompt>              - Ask AI to write a shell script that can be invoked with `/f<index>`.
                               The function will take a single argument. The function will be given a name
                               `f<index>` where `index>` is a unique number which can be used to invoke it
                               as `/f<index>`.
/f<index> <arg>              - Invoke a AI-defined reusable function with the given index.
                               For Python, `arg` must be a Python expression that can be evaluated.
                               For shell, `arg` must be a shell value or expression.
/fns                         - List all available functions.

--

Assets (Experimental):

- Asset names that begin with `/<username>` are public assets that can be accessed by anyone.
- Asset names that begin with `//` are expanded to `/<username>/` automatically.

/a /asset <name> [<editor>]  - Open asset in editor (create if does not exist)
/asset-new <name>            - Create a new asset and open editor
/asset-edit <name>           - Open existing asset in editor
/ls /asset-list <prefix>     - List all assets with the given (optional) prefix
/asset-search <query>        - Search for assets semantically
/asset-load <name>           - Load asset into the conversation
/asset-view <name>           - Prints asset contents and loads it into the conversation
/asset-link <name>           - Prints link to asset (valid for 24hr) and loads it into the conversation
/asset-revisions <name> [<n>]- Lists revisions of an asset one at a time, waiting for user input
                               If `n` is set, displays `n` revisions without needing user input
/asset-listen <name> [<cursor>]  - Blocks until a change to an asset. On a change, prints out
                                   information about the asset. If cursor is set, begins listening
                                   at that specific revision to ensure no changes are missed.
/asset-acl <name> <ace>      - Changes ACL on an asset
                               `ace` is formatted as `type:permission`
                               type: allow, deny, default
                               permission: read-data, read-revisions, push-data
/asset-push <name>           - Push data into an asset. See pushed data w/ `/asset-revisions`
/asset-import <n> <p>        - Imports <path> into asset with <name>
/asset-export <n> <p>        - Exports asset with name to <path>
/asset-temp <name> [<count>] - Exports asset to a temporary file.
                               If `count` set, the latest `count` revisions are exported.
/asset-remove <name>         - Removes an asset
/asset-md-get <name>         - Get the metadata of an asset
/asset-md-set <name> <md>    - Set metadata for an asset. Must be a JSON object.
/asset-md-set-key <name> <k> <v> - Set key to JSON value.
/asset-md-del-key <name> <k> - Delete a key from an asset's metadata.
/asset-folder-collapse <path> - Collapse the specified folder when listing its parent, so it
                                appears as a single entry.
/asset-folder-expand <path>  - Expand a previously collapsed folder, showing its contents in the
                               parent listing.
/asset-folder-list [<path>]  - List all collapsed folders, optionally filtered by the given path
                               prefix.

/chat-save [<asset_name>]    - Save the conversation as an asset
                               If asset name omitted, name automatically generated
/chat-resume [<asset_name>]  - Replaces current chat with chat saved to asset via `/chat-save`
                               If asset name omitted, resumes last auto-saved chat"##;

// --

pub async fn shell_exec_with_asset_substitution(
    api_client: &HaiClient,
    shell: &str,
    cmd: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match asset_editor::prepare_assets(api_client, cmd).await {
        Ok((updated_cmd, asset_map, output_assets)) => {
            let res = shell_exec(shell, &updated_cmd).await;
            for output_asset in output_assets {
                let (temp_file, _temp_file_path) =
                    asset_map.get(&output_asset).expect("missing asset");
                let asset_contents = match fs::read(temp_file) {
                    Ok(res) => res,
                    Err(e) => {
                        let err_msg = format!("error: failed to read output file: {}", e);
                        eprintln!("{}", err_msg);
                        return Ok(err_msg);
                    }
                };
                use crate::api::types::asset::{AssetPutArg, PutConflictPolicy};
                match api_client
                    .asset_put(AssetPutArg {
                        name: output_asset,
                        data: asset_contents,
                        conflict_policy: PutConflictPolicy::Override,
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("error: failed to put: {}", e);
                    }
                }
            }
            res
        }
        Err(e) => {
            eprintln!("failed to prepare assets: {}", e);
            Ok(e)
        }
    }
}

// --

/// If None returned, it will have also printed an error message to stderr.
fn get_haitask_from_task_ref(
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
                    println!(
                        "Using version {} (`/task-update {}` to get any updates)",
                        haitask.version, task_ref
                    );
                    return Some((config, haitask));
                } else {
                    println!(
                        "Cached version differs: {} != {} (refetching)",
                        version, haitask.version
                    );
                }
            } else {
                println!(
                    "Using version {} (`/task-update {}` to get any updates)",
                    haitask.version, task_ref
                );
                return Some((config, haitask));
            }
        }
        // Task missing from cache or was the wrong version
        if fail_if_not_in_cache {
            // To avoid an infinite loop of fetches that keep
            // retrying, fail if requested.
            eprintln!("error: failed to fetch task");
        } else {
            // Queue up a fetch task and then try again.
            session.cmd_queue.push_front(session::CmdInput {
                input: format!("/{} {}", task_cmd, task_ref),
                source: session::CmdSource::Internal,
            });
            session.cmd_queue.push_front(session::CmdInput {
                input: format!("/task-fetch {}", task_ref),
                source: session::CmdSource::Internal,
            });
        }
        None
    } else if task_ref.starts_with(".") || task_ref.starts_with("/") || task_ref.starts_with("~") {
        let task_path = match shellexpand::full(&task_ref) {
            Ok(s) => s.into_owned(),
            Err(e) => {
                eprintln!("error: undefined path variable: {}", e.var_name);
                return None;
            }
        };
        match config::read_haitask(&task_path) {
            Ok(read_res) => Some(read_res),
            Err(e) => {
                eprint!("error: failed to load task: {}", e);
                None
            }
        }
    } else {
        eprintln!("error: unknown task: Try:");
        eprintln!("  1. Fully-qualified name (username/task-name)");
        eprintln!("  2. Path on your system using ./ for relative path and / for absolute path");
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

use crate::api::types::asset::{AssetEntry, AssetEntryOp};

fn print_asset_entry(entry: &AssetEntry) -> String {
    let symbol = if matches!(entry.op, AssetEntryOp::Push) {
        "📥"
    } else {
        ""
    };
    let title = entry
        .metadata
        .as_ref()
        .and_then(|md| md.title.clone())
        .map(|md_title| format!(" [{}]", md_title))
        .unwrap_or("".to_string());
    let line = format!("{}{}{}", entry.name, symbol, title);
    println!("{}", line);
    line
}

fn print_folder(folder: &str) -> String {
    let line = format!("{}📁", folder);
    println!("{}", line);
    line
}

// --

async fn prompt_ai_simple(
    prompt: &str,
    session: &mut SessionState,
    cfg: &config::Config,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    debug: bool,
) -> Option<String> {
    let msg_history = vec![chat::Message {
        role: chat::MessageRole::User,
        content: vec![chat::MessageContent::Text {
            text: prompt.to_string(),
        }],
        tool_call_id: None,
        tool_calls: None,
    }];
    let res = crate::prompt_ai(
        &msg_history,
        &None,
        &HashSet::new(),
        session,
        cfg,
        ctrlc_handler,
        debug,
    )
    .await;
    for chat_response in &res {
        if let chat::ChatCompletionResponse::Message { text } = chat_response {
            return Some(text.clone());
        }
    }
    None
}

// --

pub async fn shell_exec(shell: &str, cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    tool::collect_and_print_command_output(&mut child).await
}

// --

/// If an asset-key begins with `//`, it is converted to the current logged-in
/// user's public asset prefix: /<username>/<path>
pub fn expand_pub_asset_name(asset_name: &str, account: &Option<crate::db::Account>) -> String {
    if asset_name.starts_with("//") {
        if let Some(account) = account {
            format!("/{}{}", account.username, &asset_name[1..])
        } else {
            asset_name.to_string()
        }
    } else {
        asset_name.to_string()
    }
}
