use ai_provider::{anthropic, ollama, openai};
use api::types::asset::AssetCreatedBy;
use chat::ChatCompletionResponse;
use clap::{Parser, Subcommand};
use colored::*;
use db::LogEntryRetentionPolicy;
use glob::glob;
use line_editor::LineEditor;
use num_format::{Locale, ToFormattedString};
use reedline::{self, Signal};
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::ops::Deref;
use std::process::{self, Stdio};
use std::sync::{Arc, OnceLock};
use tokio::process::Command;
use tokio::sync::Mutex;
use uuid::Uuid;

mod ai_provider;
mod api;
mod asset_editor;
mod chat;
mod clipboard;
mod cmd;
mod config;
mod ctrlc_handler;
mod db;
mod line_editor;
mod loader;
mod term;
mod tool;

use api::client::HaiClient;

/// A CLI for interacting with LLMs in a hacker-centric way
#[derive(Parser)]
#[command(name = "hai")]
#[command(
    about = "A CLI for interacting with LLMs in a hacker-centric way",
    version = "0.1.0"
)]
struct Cli {
    /// Debug mode (logs to ~/.hai/debug.log)
    #[arg(short = 'd', long = "debug")]
    debug: bool, // Defaults to false

    /// Does not log conversation to history
    /// An incognito AI model can be set in your config
    #[arg(short = 'i', long = "incognito")]
    incognito: bool, // Defaults to false

    /// Use specific account ignoring the last active one
    #[arg(short = 'u', long = "username")]
    username: Option<String>,

    /// Use specific AI model
    #[arg(short = 'm', long = "model")]
    model: Option<String>,

    /// Non-default path to config file (defaults to ~/.hai/hai.toml)
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: Option<String>,

    /// Subcommands for the CLI
    #[command(subcommand)]
    subcommand: Option<CliSubcommand>,
}

#[derive(Subcommand)]
enum CliSubcommand {
    /// Set API keys
    SetKey {
        /// The AI provider (e.g., openai, anthropic, google, deepseek)
        provider: String,

        /// The API key to save
        key: String,
    },
    /// Enable task mode
    Task {
        /// The fully-qualified name of the task (username/task-name) or file path
        task_ref: String,
    },
    /// Run a set of commands/prompts and quit (alias: "bai").
    /// WARNING: Quote each command with single-quotes to avoid shell expansion.
    #[command(alias = "bai")]
    Bye {
        /// Prompts to run
        prompts: Vec<String>,

        /// Automatically confirm any prompts
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let config_path_override = args.config;
    if config_path_override.is_none() {
        config::create_config_dir_if_missing().expect("Could not create dir");
    }

    // Typically, reedline (line-editor) is intercepting signals. However, when
    // a tool subprocess is running, reedline isn't blocking, and therefore
    // this signal handler intercepts ctrl+c which no-ops for this process. The
    // child tool subprocess receives the SIGINT.
    let mut ctrlc_handler = ctrlc_handler::CtrlcHandler::new();
    if let Some(CliSubcommand::SetKey { provider, key }) = args.subcommand {
        match provider.as_str() {
            "openai" | "anthropic" | "google" | "deepseek" => {
                config::insert_config_kv(
                    &config_path_override,
                    Some(&provider),
                    &"api_key".to_string(),
                    &key,
                );
                process::exit(0);
            }
            _ => {
                eprintln!("error: unsupported provider: {}", provider);
                process::exit(1);
            }
        };
    } else {
        let (repl_mode, init_cmds, exit_when_done, force_yes) =
            if let Some(CliSubcommand::Bye { prompts, yes }) = args.subcommand {
                (ReplMode::Normal, prompts, true, yes)
            } else if let Some(CliSubcommand::Task { task_ref }) = args.subcommand {
                // When specified via the command-line, a relative file path may
                // not be prefixed with "./" which will then be incorrectly treated
                // as a task-fqn. To catch this, prefix "./" if the name has a dot
                // (due to a .toml extension) which an fqn cannot have.
                let fixed_task_ref = if !task_ref.starts_with("/")
                    && !task_ref.starts_with("./")
                    && !task_ref.starts_with("~")
                    && task_ref.contains(".")
                {
                    format!("./{}", task_ref)
                } else {
                    task_ref
                };
                (
                    ReplMode::Normal,
                    vec![format!("/task {}", fixed_task_ref)],
                    false,
                    false,
                )
            } else {
                (ReplMode::Normal, vec![], false, false)
            };
        repl(
            &config_path_override,
            args.debug,
            args.incognito,
            args.username,
            args.model,
            &mut ctrlc_handler,
            repl_mode,
            init_cmds,
            exit_when_done,
            force_yes,
        )
        .await?;
    }
    Ok(())
}

enum ReplMode {
    Normal,
    /// Enter task-mode for task with given fqn
    Task(String),
}

const HAI_BYE_TASK_NAME: &str = "hai-bye";
const INIT_TASK_NAME: &str = "init";
const INTERNAL_TASK_NAME: &str = "_hai";

struct SessionState {
    repl_mode: ReplMode,
    /// AI model in active use
    ai: config::AiModel,
    ai_temperature: Option<f32>,
    /// Running counter of tokens in convo (does not include loaded tokens)
    input_tokens: u32,
    /// Running counter of tokens loaded from files (this is retained on /reset)
    input_loaded_tokens: u32,
    /// Queue of ((task_name, task_step), cmd) - the first item is a "task_step_signature"
    cmd_queue: VecDeque<((String, u32), String)>,
    /// History stores previous messages
    history: Vec<db::LogEntry>,
    /// The program to use to edit assets
    editor: String,
    /// The shell to use for the !sh tool.
    shell: String,
    /// These are outputs that should be masked due to sensitivity, which means
    /// they were acquired by user input with secret=true. These are not
    /// cleared even across conversations.
    masked_strings: HashSet<String>,
    mask_secrets: bool,
    /// Information about logged-in account
    account: Option<db::Account>,
    /// The last tool that was used (for ! shortcut)
    last_tool_cmd: Option<cmd::ToolCmd>,
    /// The tool activated in tool-mode
    tool_mode: Option<cmd::ToolModeCmd>,
    /// Whether to use hai-router for compatible AI prompts
    use_hai_router: bool,
}

#[allow(clippy::too_many_arguments)]
async fn repl(
    config_path_override: &Option<String>,
    debug: bool,
    incognito: bool,
    force_account: Option<String>,
    force_ai_model: Option<String>,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    repl_mode: ReplMode,
    init_cmds: Vec<String>,
    exit_when_done: bool,
    force_yes: bool,
) -> Result<(), Box<dyn Error>> {
    let mut cfg = match config::get_config(config_path_override) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: failed to read config: {}", e);
            process::exit(1);
        }
    };
    let db = Arc::new(Mutex::new(db::open_db()?));

    // Use a channel to make asset updates async
    let (update_asset_tx, update_asset_rx) =
        tokio::sync::mpsc::channel::<asset_editor::WorkerAssetMsg>(100);
    tokio::spawn(asset_editor::worker_update_asset(
        update_asset_rx,
        db.clone(),
        debug,
    ));

    let autocomplete_repl_cmds: Vec<String> = [
        "/about",
        "/help",
        "/quit",
        "/ai",
        "/ai-default",
        "/temperature",
        "/cd",
        "/new",
        "/reset",
        "/task",
        "/task-end",
        "/task-update",
        "/task-publish",
        "/task-forget",
        "/task-purge",
        "/task-search",
        "/task-view",
        "/task-include",
        "/task-versions",
        "/load",
        "/load-url",
        "/exec",
        "/prep",
        "/pin",
        "/system-prompt",
        "/forget",
        "/clip",
        "/printvars",
        "/setvar",
        "/set-key",
        "/set-mask-secrets",
        "/asset",
        "/asset-new",
        "/asset-edit",
        "/asset-push",
        "/asset-list",
        "/asset-search",
        "/asset-load",
        "/asset-view",
        "/asset-revisions",
        "/asset-link",
        "/asset-import",
        "/asset-export",
        "/asset-acl",
        "/account",
        "/account-new",
        "/account-login",
        "/account-logout",
        "/account-balance",
        "/account-subscribe",
        "/chat-save",
        "/chat-load",
        "/whois",
        "/hai-router",
        "/cost",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let autocomplete_repl_ai_models: Vec<String> = [
        "4o",
        "4om",
        "gpt-4o",
        "gpt-4o-mini",
        "haiku35",
        "sonnet",
        "sonnet35",
        "sonnet37",
        "llama32",
        "llama32-vision",
        "flash",
        "flash20",
        "flash15",
        "deepseek",
        "v3",
        "r1",
        "openai/",
        "anthropic/",
        "google/",
        "ollama/",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let mut line_editor = LineEditor::new(incognito);
    let mut editor_prompt = line_editor::EditorPrompt::new();

    //
    // Spawn a task to load the tokenizer async b/c it would otherwise block
    // the REPL by ~100-300ms
    //
    let tokenizer = Arc::new(Mutex::new(None));
    let tokenizer_for_async_task = tokenizer.clone();
    tokio::spawn(async move {
        let loaded_tokenizer = tiktoken_rs::r50k_base().unwrap();
        // Because token counting is a rough approximation in the UI and isn't
        // standardized between different LLMs, we use GPT-3.5's r50k because
        // its smaller vocabulary means it loads 100ms faster on an M1 Max.
        let mut tokenizer_locked = tokenizer_for_async_task.lock().await;
        *tokenizer_locked = Some(loaded_tokenizer);
    });

    let mut default_ai_model = choose_init_ai_model(&cfg);
    if incognito {
        if let Some(ref ai_model_unmatched_str) = cfg.default_incognito_ai_model {
            if let Some(ai_model) = config::ai_model_from_string(ai_model_unmatched_str) {
                default_ai_model = ai_model;
            } else {
                eprintln!("error: unknown incognito model {}", ai_model_unmatched_str);
            }
        }
    }
    if let Some(force_ai_model) = force_ai_model {
        if let Some(ai_model) = config::ai_model_from_string(&force_ai_model) {
            default_ai_model = ai_model;
        } else {
            eprintln!("error: unknown model {}", force_ai_model);
            process::exit(1);
        }
    }
    let default_editor = cfg.default_editor.clone().unwrap_or("vim".into());
    let default_shell = cfg.default_shell.clone().unwrap_or("bash".into());

    let account = if let Some(force_account) = force_account {
        match db::get_account_by_username(&*db.lock().await, &force_account)? {
            Some(account) => Some(account),
            None => {
                eprintln!(
                    "error: `{}` is unavailable (try /account-login)",
                    force_account
                );
                process::exit(1);
            }
        }
    } else {
        db::get_active_account(&*db.lock().await)?
    };

    let multiple_accounts = db::list_accounts(&*db.lock().await)?.len() > 1;

    let mut session = SessionState {
        repl_mode,
        ai: default_ai_model,
        ai_temperature: if cfg.default_ai_temperature_to_absolute_zero {
            Some(0.)
        } else {
            None
        },
        input_tokens: 0,
        input_loaded_tokens: 0,
        cmd_queue: VecDeque::new(),
        history: vec![],
        editor: default_editor,
        shell: default_shell,
        masked_strings: HashSet::new(),
        mask_secrets: false,
        account: account.clone(),
        last_tool_cmd: None,
        tool_mode: None,
        use_hai_router: false,
    };

    if let Some(account) = &account {
        account_login_setup_session(
            &mut session,
            db.clone(),
            &account.user_id,
            &account.username,
            &account.token,
        )
        .await;
    }

    if !session.use_hai_router {
        // Prints error if API key not available
        check_api_key(&session.ai, &cfg);
    }

    for (step_index, init_cmd) in init_cmds.into_iter().enumerate() {
        let task_name = if exit_when_done {
            HAI_BYE_TASK_NAME.to_string()
        } else {
            INIT_TASK_NAME.to_string()
        };
        session
            .cmd_queue
            .push_back(((task_name, step_index as u32), init_cmd));
    }

    //
    // REPL Loop
    //
    if !exit_when_done {
        let newer_client_version = if cfg.check_for_updates {
            is_client_update_available(db.clone()).await
        } else {
            None
        };

        let update_available_str = newer_client_version
            .as_ref()
            .map(|version| format!(" -- Update available ({})", version))
            .unwrap_or_default();

        println!(
            "hai! ({}){}",
            env!("CARGO_PKG_VERSION"),
            update_available_str
        );
        if let Some(version) = newer_client_version {
            println!("  - changelog: `/asset-view /hai/changelog`");
            let os_arch = get_machine_os_arch();
            let ext = if os_arch.starts_with("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            let asset_name = format!("hai-cli-{}-{}.{}", version, get_machine_os_arch(), ext);
            println!("  - download: `/asset-export /hai/client/{} .`", asset_name);
            if let Ok(exe_path) = env::current_exe() {
                println!("  - install: unpack and copy to {:?}", exe_path);
            }
        }
        println!(
            "Type a prompt and press Enter. Use Alt+Enter or Option+Enter for multi-line prompts."
        );
        match env::var("TERM_PROGRAM") {
            Ok(value) if value == "Apple_Terminal" => {
                // This is required, otherwise Option+Enter does not register.
                println!("For Apple's Terminal, turn on Edit->Use Option as Meta Key.");
            }
            _ => {}
        }
        println!("/help for more commands.");
    };
    loop {
        line_editor.set_line_completer(
            debug,
            autocomplete_repl_cmds.clone(),
            autocomplete_repl_ai_models.clone(),
            mk_api_client(Some(&session)),
        );
        //
        // Set editor prompt info for display purposes
        //
        editor_prompt.set_index(session.history.len().try_into().unwrap());
        editor_prompt.set_ai_model_name(config::get_ai_model_display_name(&session.ai).to_string());
        editor_prompt.set_using_hai_router(session.use_hai_router);
        editor_prompt.set_input_tokens(session.input_tokens + session.input_loaded_tokens);
        if let ReplMode::Task(task_fqn) = &session.repl_mode {
            editor_prompt.set_task_mode(Some(task_fqn.to_owned()));
        } else {
            editor_prompt.set_task_mode(None);
        }
        editor_prompt.set_tool_mode(
            session
                .tool_mode
                .clone()
                .map(|tool_mode_cmd| tool::tool_to_cmd(&tool_mode_cmd.tool, tool_mode_cmd.require)),
        );

        editor_prompt.set_incognito(incognito);
        editor_prompt.set_is_dev(env::var("HAI_BASE_URL").is_ok());
        if multiple_accounts {
            // Show username if they have multiple accounts to help mitigate
            // account-confusion mistakes.
            editor_prompt.set_username(
                session
                    .account
                    .as_ref()
                    .map(|account| account.username.clone()),
            );
        }

        //
        // REPL Read
        // - Either reads from a queue of waiting cmds, from user input, or
        //   one-shot commandline.
        //
        let (user_input, task_step_signature) = if let Some((task_step_signature, cmd)) =
            session.cmd_queue.pop_front()
        {
            if task_step_signature.1 > 0 {
                println!();
            }
            if task_step_signature.0 != INTERNAL_TASK_NAME {
                // If it's an "internal" command, do not print to screen.
                let step_badge = format!("{}[{}]:", task_step_signature.0, session.history.len());
                println!("{} {}", step_badge.black().on_white(), cmd);
            }
            (cmd, Some(task_step_signature))
        } else if matches!(session.repl_mode, ReplMode::Normal)
            || matches!(session.repl_mode, ReplMode::Task(_))
        {
            line_editor.pre_readline();
            let sig = line_editor.reedline.read_line(&editor_prompt);
            line_editor.post_readline();
            match sig {
                // Maintain prefix whitespace as that's how a user can
                // easily make an input guarantee to not match a command.
                // Maintain suffix whitespace as that's how a user can switch
                // a /prompt into a /prep.
                Ok(Signal::Success(buffer)) => (buffer, None),
                Ok(Signal::CtrlC) => {
                    continue;
                }
                Ok(Signal::CtrlD) => {
                    println!("バイバイ！");
                    break;
                }
                unk => {
                    println!("Event: {:?}", unk);
                    continue;
                }
            }
        } else if exit_when_done && session.cmd_queue.is_empty() {
            // All commands executed
            process::exit(0);
        } else {
            eprintln!("error: unexpected repl-mode, please report");
            process::exit(1);
        };

        // Task steps only have a non-standard retention policy when they are
        // actioned as part of a process-wide task-mode.
        let is_task_mode_step =
            matches!(session.repl_mode, ReplMode::Task(_)) && task_step_signature.is_some();
        let task_step_requires_user_confirmation =
            if let Some(task_step_signature) = task_step_signature.as_ref() {
                task_step_signature.0 != HAI_BYE_TASK_NAME
            } else {
                false
            };

        let last_tool_cmd = session.last_tool_cmd.clone();
        let tool_mode = session.tool_mode.clone();
        // Expectation is that if `parse_user_input` returns None, it will have
        // also printed an error msg to the user so it's okay to ignore the
        // input here.
        let maybe_cmd = cmd::parse_user_input(&user_input, last_tool_cmd, tool_mode);
        let mut cmd = if let Some(cmd) = maybe_cmd {
            cmd
        } else {
            continue;
        };
        if exit_when_done && session.cmd_queue.is_empty() {
            if let cmd::Cmd::Noop = cmd {
                process::exit(0);
            }
        }

        // Block further progress until tokenizer has been loaded. Rarely
        // should it take this long. NOTE: It's important that this is placed
        // after the user's input. Though, in task-mode where user input is
        // skipped, this does block more-or-less immediately.
        {
            let tokenizer_locked = tokenizer.lock().await;
            if tokenizer_locked.is_none() {
                drop(tokenizer_locked);
                while tokenizer.lock().await.is_none() {
                    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
                }
            }
        }
        let tokenizer_locked = tokenizer.lock().await;
        let bpe_tokenizer = tokenizer_locked.as_ref().unwrap();

        //
        // REPL Eval/Print Commands
        //
        cmd = preprocess_cmd(cmd, &cfg.haivars);
        let (prompt, cache) = match process_cmd(
            config_path_override,
            &mut session,
            &mut cfg,
            db.clone(),
            update_asset_tx.clone(),
            ctrlc_handler,
            bpe_tokenizer,
            &cmd,
            &user_input,
            &task_step_signature,
            force_yes,
            debug,
        )
        .await
        {
            ProcessCmdResult::Break => break,
            ProcessCmdResult::Loop => {
                if exit_when_done && session.cmd_queue.is_empty() {
                    process::exit(0);
                };
                continue;
            }
            ProcessCmdResult::PromptAi(prompt, cache) => (prompt, cache),
        };

        //
        // Preflight checks
        //

        // Check model supports tools (if necessary)
        if let cmd::Cmd::Tool(_) = cmd {
            if !config::get_ai_model_capability(&session.ai).tool {
                eprintln!("error: model does not support tools");
                continue;
            }
        }

        // Check api-key for ai provider is set (prints error msg to stderr)
        if !session.use_hai_router && !check_api_key(&session.ai, &cfg) {
            continue;
        }

        //
        // REPL Eval/Print Prompt for AI
        //

        let tool_policy = if let cmd::Cmd::Tool(tool_cmd) = &cmd {
            session.last_tool_cmd = Some(tool_cmd.clone());
            Some(tool::ToolPolicy {
                tool: tool_cmd.tool.clone(),
                require: tool_cmd.require,
            })
        } else {
            None
        };

        //
        // Parse prompt for images
        // - Prints errors to stderr
        //

        let msg_content = chat::prompt_to_chat_message_content(&session.ai, &prompt).await;

        //
        // Append user-input to message history
        //
        let mut tokens = 0;
        for msg in &msg_content {
            tokens += match msg {
                chat::MessageContent::ImageUrl { .. } => {
                    85 // OpenAI-specific for low-detail images
                }
                chat::MessageContent::Text { text } => {
                    bpe_tokenizer.encode_with_special_tokens(text).len() as u32
                }
            }
        }
        session.input_tokens += tokens;
        session.history.push(db::LogEntry {
            uuid: Uuid::now_v7().to_string(),
            message: chat::Message {
                role: chat::MessageRole::User,
                content: msg_content,
                tool_calls: None,
                tool_call_id: None,
                tokens,
            },
            retention_policy: (is_task_mode_step, db::LogEntryRetentionPolicy::None),
        });

        println!();
        println!("{}", "↓↓↓".white().on_black());
        println!();

        let masked_strings = if session.mask_secrets {
            session.masked_strings.clone()
        } else {
            HashSet::<String>::new()
        };

        //
        // Prompt AI
        //

        // Send full history to AI
        let msg_history: Vec<chat::Message> = session
            .history
            .clone()
            .into_iter()
            .map(|log_entry| log_entry.message)
            .collect();

        let (ai_responses, from_cache) =
            if let Some((ref task_fqn, step_index)) = task_step_signature {
                let ai_responses_from_cache = if cache {
                    // An error deserializing is likely due to a change
                    // in format due to a version update. Assume that
                    // the cache value will be updated to a compatible
                    // schema once the user enters a new value.
                    db::get_task_step_cache(&*db.lock().await, task_fqn, step_index, &prompt)
                        .and_then(|cached_serialized_output| {
                            serde_json::from_str::<Vec<chat::ChatCompletionResponse>>(
                                &cached_serialized_output,
                            )
                            .ok()
                        })
                } else {
                    None
                };
                if let Some(ai_responses_from_cache) = ai_responses_from_cache {
                    (ai_responses_from_cache, true)
                } else {
                    if task_step_requires_user_confirmation && !force_yes {
                        // If we're initializing a task, it's critical that we ask the
                        // user for confirmation. Otherwise, a destructive command could
                        // be hidden in a task.
                        let answer =
                            term::ask_question_default_empty("Prompt AI the above? y/[n]:", false);
                        let answered_yes = answer.starts_with('y');
                        if !answered_yes {
                            println!("USER CANCELLED PROMPT. TASK MAY MALFUNCTION.");
                            continue;
                        }
                        println!();
                    }
                    (
                        prompt_ai(
                            &msg_history,
                            &tool_policy,
                            &masked_strings,
                            &mut session,
                            &cfg,
                            ctrlc_handler,
                            debug,
                        )
                        .await,
                        false,
                    )
                }
            } else {
                (
                    prompt_ai(
                        &msg_history,
                        &tool_policy,
                        &masked_strings,
                        &mut session,
                        &cfg,
                        ctrlc_handler,
                        debug,
                    )
                    .await,
                    false,
                )
            };

        if from_cache {
            if let Some((ref task_fqn, _)) = task_step_signature {
                println!("[Retrieved from cache; `/task-forget {task_fqn}` to prompt again]");
            }
            // Because it's from the cache, the response is not yet on the screen.
            for ai_response in &ai_responses {
                match ai_response {
                    chat::ChatCompletionResponse::Message { ref text } => {
                        println!("{}", text);
                    }
                    chat::ChatCompletionResponse::Tool { ref arg, .. } => {
                        println!("{}", arg);
                    }
                };
            }
        } else if cache {
            if let Some((task_name, step_index)) = &task_step_signature {
                db::set_task_step_cache(
                    &*db.lock().await,
                    task_name,
                    *step_index,
                    &prompt,
                    &serde_json::to_string(&ai_responses).unwrap(),
                )
            }
        }

        for ai_response in &ai_responses {
            //
            // Bookkeeping
            //

            // Increment `input_tokens` b/c the AI output will be part of the next input
            let tokens = match ai_response {
                chat::ChatCompletionResponse::Message { ref text } => {
                    bpe_tokenizer.encode_with_special_tokens(text).len() as u32
                }
                chat::ChatCompletionResponse::Tool { ref arg, .. } => {
                    bpe_tokenizer.encode_with_special_tokens(arg).len() as u32
                }
            };
            session.input_tokens += tokens;

            // Append AI's response to history
            match ai_response {
                chat::ChatCompletionResponse::Message { ref text } => {
                    session.history.push(db::LogEntry {
                        uuid: Uuid::now_v7().to_string(),
                        message: chat::Message {
                            role: chat::MessageRole::Assistant,
                            content: vec![chat::MessageContent::Text { text: text.clone() }],
                            tool_calls: None,
                            tool_call_id: None,
                            tokens,
                        },
                        retention_policy: (is_task_mode_step, db::LogEntryRetentionPolicy::None),
                    });
                }
                chat::ChatCompletionResponse::Tool {
                    ref tool_id,
                    ref tool_name,
                    ref arg,
                } => {
                    session.history.push(db::LogEntry {
                        uuid: Uuid::now_v7().to_string(),
                        message: chat::Message {
                            role: chat::MessageRole::Assistant,
                            // FIXME: This `content` is redundant with the tool
                            // call. Remove it? Set it to empty or null?
                            content: vec![chat::MessageContent::Text { text: arg.clone() }],
                            tool_calls: Some(vec![chat::ToolCall {
                                id: tool_id.clone(),
                                type_: "function".to_string(),
                                function: chat::Function {
                                    name: tool_name.to_owned(),
                                    arguments: arg.clone(),
                                },
                            }]),
                            tool_call_id: None,
                            tokens,
                        },
                        retention_policy: (is_task_mode_step, db::LogEntryRetentionPolicy::None),
                    });
                }
            }
        }

        //
        // Execute optional tool
        //
        for ai_response in &ai_responses {
            if let chat::ChatCompletionResponse::Tool {
                tool_id,
                tool_name,
                arg,
            } = &ai_response
            {
                println!();
                println!("{}", "⚙ ⚙ ⚙".white().on_black());
                println!();

                // The combined policy is a byproduct of pecularities in
                // Anthropic's API. Once a tool is used once in a conversation,
                // it can be used again by the AI and there's no way to disable
                // it. The tool cannot be removed from tool-schemas either once
                // it has appeared in the message history. This means that
                // tool_policy could be None, but the AI will still respond
                // with tool use. The "combined" policy accommodates the logic
                // for these over-zealous recommendations.
                let tool_policy_combined = tool_policy.clone().or_else(|| {
                    ai_provider::tool_schema::get_tool_from_name(tool_name).map(|tool| {
                        tool::ToolPolicy {
                            tool,
                            require: false,
                        }
                    })
                });

                // The negation of the policy to require the AI to use a tool
                // doubles as a way to require user confirmation.
                let tool_policy_needs_user_confirmation = tool_policy_combined
                    .clone()
                    .map(|tp| !tp.require)
                    .unwrap_or(false);
                // We have the user confirm all the commands in the hai-repl
                // tool at once rather than prompt for every command.
                let tool_type_needs_user_confirmation = if let Some(ref tp) = tool_policy_combined {
                    matches!(tp.tool, tool::Tool::HaiRepl)
                } else {
                    false
                };

                let user_confirmed_tool_execute = if !force_yes
                    && (cfg.tool_confirm
                        || tool_policy_needs_user_confirmation
                        || tool_type_needs_user_confirmation
                        || task_step_requires_user_confirmation)
                {
                    let answer = term::ask_question_default_empty("Execute? y/[n]:", false);
                    let answered_yes = answer.starts_with('y');
                    if !answered_yes {
                        let error_text = format!("USER CANCELLED TOOL: Execute? {}", answer);
                        let tokens =
                            bpe_tokenizer.encode_with_special_tokens(&error_text).len() as u32;
                        session.input_tokens += tokens;
                        session.history.push(db::LogEntry {
                            uuid: Uuid::now_v7().to_string(),
                            message: chat::Message {
                                role: chat::MessageRole::Tool,
                                content: vec![chat::MessageContent::Text { text: error_text }],
                                tool_calls: None,
                                tool_call_id: Some(tool_id.clone()),
                                tokens,
                            },
                            retention_policy: (
                                is_task_mode_step,
                                db::LogEntryRetentionPolicy::None,
                            ),
                        });
                    }
                    answered_yes
                } else {
                    true
                };

                if user_confirmed_tool_execute {
                    if let Some(ref tp) = tool_policy_combined {
                        let tool_exec_handler_id = ctrlc_handler.add_handler(|| {
                            println!("Tool Interrupted");
                        });
                        let output_text = if matches!(tp.tool, tool::Tool::HaiRepl) {
                            match tool::execute_hai_repl_tool(&tp.tool, arg, &mut session.cmd_queue)
                            {
                                Ok(output_text) => output_text,
                                Err(e) => {
                                    let err_text = format!("error executing hai-repl tool: {}", e);
                                    println!("{}", err_text);
                                    err_text
                                }
                            }
                        } else {
                            match tool::execute_shell_based_tool(&tp.tool, arg, &session.shell)
                                .await
                            {
                                Ok(output_text) => output_text,
                                Err(e) => {
                                    let err_text = format!("error executing tool: {}", e);
                                    println!("{}", err_text);
                                    err_text
                                }
                            }
                        };
                        ctrlc_handler.remove_handler(tool_exec_handler_id);
                        // Increment tokens because the tool output will be part of
                        // the next message's input.
                        let tokens =
                            bpe_tokenizer.encode_with_special_tokens(&output_text).len() as u32;
                        session.input_tokens += tokens;
                        session.history.push(db::LogEntry {
                            uuid: Uuid::now_v7().to_string(),
                            message: chat::Message {
                                role: chat::MessageRole::Tool,
                                content: vec![chat::MessageContent::Text { text: output_text }],
                                tool_calls: None,
                                tool_call_id: Some(tool_id.clone()),
                                tokens,
                            },
                            retention_policy: (
                                is_task_mode_step,
                                db::LogEntryRetentionPolicy::None,
                            ),
                        });
                    }
                }
            }
        }

        if exit_when_done && session.cmd_queue.is_empty() {
            process::exit(0);
        };

        println!();
        println!("{}", "---".white().on_black());
        println!();
    }

    Ok(())
}

// --

/// Replace haivars in specific parts of specific commands.
///
/// For now, this only replaces haivars in shell-exec-with-script tool in both
/// the shell-cmd and prompt, which includes the shell-cmd redundantly.
fn preprocess_cmd(cmd: cmd::Cmd, haivars: &HashMap<String, String>) -> cmd::Cmd {
    if let cmd::Cmd::Tool(cmd::ToolCmd {
        tool: tool::Tool::ShellExecWithScript(shell_cmd),
        prompt,
        require,
        cache,
    }) = &cmd
    {
        cmd::Cmd::Tool(cmd::ToolCmd {
            // Replace variables in the custom command itself for tool
            // execution.
            tool: tool::Tool::ShellExecWithScript(replace_haivars(shell_cmd, haivars)),
            // Replace vars in the recorded input because the unexpanded
            // vars are sometimes too opaque for the AI to understand.
            prompt: replace_haivars(prompt, haivars),
            require: *require,
            cache: *cache,
        })
    } else {
        cmd.clone()
    }
}

// --

enum ProcessCmdResult {
    Loop,
    Break,
    PromptAi(String, bool),
}

#[allow(clippy::too_many_arguments)]
async fn process_cmd(
    config_path_override: &Option<String>,
    session: &mut SessionState,
    cfg: &mut config::Config,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_editor::WorkerAssetMsg>,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    cmd: &cmd::Cmd,
    raw_user_input: &str, // Avoid using this except for caching
    task_step_signature: &Option<(String, u32)>,
    force_yes: bool,
    debug: bool,
) -> ProcessCmdResult {
    // Task steps only have a non-standard retention policy when they are
    // actioned as part of a process-wide task-mode.
    let is_task_mode_step =
        matches!(session.repl_mode, ReplMode::Task(_)) && task_step_signature.is_some();
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
                session_history_add_user_text_entry(
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
                if let Some(ai_model) = config::ai_model_from_string(model_name) {
                    let selected_ai_model = ai_model;
                    let ai_model_capability = config::get_ai_model_capability(&selected_ai_model);
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
                        if session.use_hai_router
                            && !config::is_ai_model_supported_by_hai_router(&selected_ai_model)
                        {
                            eprintln!(
                                "warning: disabling hai-router because it does not support {}",
                                model_name
                            );
                            session.use_hai_router = false;
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
            let account = if let Some(account) = &session.account {
                account
            } else {
                eprintln!("You must be logged-in to use hai-router. Try /account-login");
                return ProcessCmdResult::Loop;
            };
            if let Some(on) = on {
                session.use_hai_router = *on;
                db::set_misc_entry(
                    &*db.lock().await,
                    &account.username,
                    "hai-router",
                    if session.use_hai_router { "on" } else { "off" },
                )
                .expect("failed to write to db");
            } else {
                println!(
                    "hai router: {}",
                    if session.use_hai_router { "on" } else { "off" }
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
            // In task-mode, we keep all task-mode initialization steps regardless
            // of standard retention policy.
            session
                .history
                .retain(|log_entry| log_entry.retention_policy.0);
            recalculate_input_tokens(session);
            if let ReplMode::Task(ref task_fqn) = session.repl_mode {
                let task_restarted_header = format!("Task Restarted: {}", task_fqn);
                println!("{}", task_restarted_header.black().on_white());
            } else {
                println!("New conversation begun");
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Reset => {
            session.history.retain(|log_entry| {
                log_entry.retention_policy.0
                    || log_entry.retention_policy.1 != db::LogEntryRetentionPolicy::None
            });
            recalculate_input_tokens(session);
            if !session.history.is_empty() {
                if matches!(session.repl_mode, ReplMode::Task(_)) {
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
                println!("error: variable name '{}' is invalid: must start with a letter and only contain alphanumeric characters or underscores.", key);
                return ProcessCmdResult::Loop;
            }
            cfg.haivars.insert(key.to_owned(), value.to_owned());
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Exec(cmd::ExecCmd { command, cache }) => {
            let shell_exec_handler_id = ctrlc_handler.add_handler(|| {
                println!("Shell Exec Interrupted");
            });

            let (shell_exec_output, from_cache) =
                if let Some((ref task_fqn, step_index)) = task_step_signature {
                    let cached_output = if *cache {
                        db::get_task_step_cache(
                            &*db.lock().await,
                            task_fqn,
                            *step_index,
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
                        if !force_yes {
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
                        (shell_exec(&session.shell, command).await.unwrap(), false)
                    }
                } else {
                    println!();
                    (shell_exec(&session.shell, command).await.unwrap(), false)
                };

            ctrlc_handler.remove_handler(shell_exec_handler_id);

            if from_cache {
                if let Some((ref task_fqn, _)) = task_step_signature {
                    println!("[Retrieved from cache; `/task-forget {task_fqn}` to execute again]");
                }
                // Because it's from the cache, the value is not yet on the screen.
                println!("{}", shell_exec_output);
            } else if *cache {
                if let Some((ref task_name, step_index)) = task_step_signature {
                    db::set_task_step_cache(
                        &*db.lock().await,
                        task_name,
                        *step_index,
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
                        task_fqn,
                        *step_index,
                        raw_user_input,
                    )
                    .map(|a| (a, true))
                    .unwrap_or_else(|| {
                        println!();
                        (term::ask_question_default_empty(question, *secret), false)
                    })
                } else {
                    println!();
                    (term::ask_question_default_empty(question, *secret), false)
                }
            } else {
                println!();
                (term::ask_question_default_empty(question, *secret), false)
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
                if let Some((ref task_name, step_index)) = task_step_signature {
                    db::set_task_step_cache(
                        &*db.lock().await,
                        task_name,
                        *step_index,
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
                        tokens,
                        ..
                    },
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
                    message: chat::Message {
                        role: chat::MessageRole::System,
                        content: vec![chat::MessageContent::Text {
                            text: prompt.to_owned(),
                        }],
                        tool_calls: None,
                        tool_call_id: None,
                        tokens,
                    },
                    // Treat like a /pin. /new clears it unless in task-mode.
                    retention_policy: (
                        is_task_mode_step,
                        db::LogEntryRetentionPolicy::ConversationPin,
                    ),
                },
            );
            ProcessCmdResult::Loop
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
                let log_entry = match session.history.last() {
                    Some(log_entry) => log_entry,
                    None => break,
                };
                let role_name = match log_entry.message.role {
                    chat::MessageRole::Assistant => "assistant",
                    chat::MessageRole::User => "user",
                    chat::MessageRole::Tool => "tool",
                    chat::MessageRole::System => break,
                };
                let log_entry = match session.history.pop() {
                    Some(log_entry) => log_entry,
                    None => break,
                };
                let mut preview = String::new();
                if log_entry.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
                    session.input_loaded_tokens -= log_entry.message.tokens;
                    if let chat::MessageContent::Text { text } = &log_entry.message.content[0] {
                        preview.push_str(text.split_once("\n").unwrap().0);
                    } else if let chat::MessageContent::ImageUrl { image_url } =
                        &log_entry.message.content[0]
                    {
                        preview.push_str(&image_url.url[..10]);
                    }
                } else {
                    session.input_tokens -= log_entry.message.tokens;
                    for part in log_entry.message.content {
                        match part {
                            chat::MessageContent::Text { text } => {
                                preview.push_str(&text);
                            }
                            chat::MessageContent::ImageUrl { .. } => preview.push_str("[image]"),
                        }
                        preview.push('\n');
                    }
                }

                println!(
                    "Forgot {role_name} message: {}",
                    prepare_preview(preview, 80)
                );
                n -= 1;
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Load(cmd::LoadCmd { path }) => {
            //
            // The purpose of loading is for the user to be able to easily
            // inject files into the system context.
            //
            let raw_load_target = path;
            let load_target_deref = replace_haivars(raw_load_target, &cfg.haivars);
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
                            let file_contents_with_delimeters = format!(
                                "<<<<<< BEGIN_FILE: {} >>>>>>\n{}\n<<<<<< END_FILE: {} >>>>>>",
                                file_path.to_string_lossy(),
                                file_contents,
                                file_path.to_string_lossy()
                            );
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
        cmd::Cmd::LoadUrl(cmd::LoadUrlCmd { url }) => {
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
            match http_response
                .headers()
                .get("Content-Type")
                .and_then(|value| value.to_str().ok())
            {
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
                    let url_contents_with_delimiters = format!(
                        "<<<<<< BEGIN_URL: {} >>>>>>\n{}\n<<<<<< END_URL: {} >>>>>>",
                        url, url_body, url,
                    );
                    session_history_add_user_text_entry(
                        &url_contents_with_delimiters,
                        session,
                        bpe_tokenizer,
                        (is_task_mode_step, LogEntryRetentionPolicy::ConversationLoad),
                    );
                }
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Task(cmd::TaskCmd { task_ref }) => {
            if matches!(session.repl_mode, ReplMode::Task(_)) {
                // If already in task mode, clear the existing session state and start fresh.
                session.cmd_queue.push_front((
                    (INTERNAL_TASK_NAME.to_string(), 1),
                    format!("/task {}", task_ref),
                ));
                session
                    .cmd_queue
                    .push_front(((INTERNAL_TASK_NAME.to_string(), 0), "/task-end".to_string()));
            } else if let Some((_, haitask)) =
                get_haitask_from_task_ref(task_ref, session, "task", task_step_signature.is_some())
            {
                println!();
                println!(
                    "{} {}",
                    " TASK MODE ENABLED ".black().on_white(),
                    haitask.name
                );
                println!("  - /new -- restarts the task");
                println!("  - /reset -- restarts the task while retaining additional /pin and /load commands");
                println!(
                    "  - /task-forget {} -- forgets cached/memorized answers",
                    task_ref
                );
                println!();
                for (index, step) in haitask.steps.iter().enumerate().rev() {
                    session
                        .cmd_queue
                        .push_front(((haitask.name.clone(), index as u32), step.clone()));
                }
                session.repl_mode = ReplMode::Task(haitask.name.clone());
            }
            ProcessCmdResult::Loop
        }
        cmd::Cmd::TaskInclude(cmd::TaskIncludeCmd { task_ref }) => {
            if let Some((_, haitask)) = get_haitask_from_task_ref(
                task_ref,
                session,
                "task-include",
                task_step_signature.is_some(),
            ) {
                for (index, step) in haitask.steps.iter().enumerate().rev() {
                    session
                        .cmd_queue
                        .push_front(((haitask.name.clone(), index as u32), step.clone()));
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
            if matches!(session.repl_mode, ReplMode::Task(_)) {
                session.repl_mode = ReplMode::Normal;
                session.history.clear();
                recalculate_input_tokens(session);
                println!("info: task ended");
            } else {
                eprintln!("error: not in task mode");
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
            let task_novar_path = replace_haivars(task_path, &cfg.haivars);
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

                    let width_for_description = 80 - max_name_width;

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
            if let Some((config, _)) = get_haitask_from_task_ref(
                task_ref,
                session,
                "task-view",
                task_step_signature.is_some(),
            ) {
                // FUTURE: Consider pretty printing config. For now, print the
                // raw config so that it's easier for people to copy + paste
                // for their own purposes.
                println!("{}", config);
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
            let api_client = mk_api_client(Some(session));
            let (asset_contents, asset_entry) =
                match asset_editor::get_asset(&api_client, asset_name, true)
                    .await
                    .map(|(ac, ae)| (ac, Some(ae)))
                {
                    Ok(contents) => contents,
                    Err(asset_editor::GetAssetError::BadName) => (vec![], None),
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_entry_ref =
                asset_entry.map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
            let _ = asset_editor::edit_with_editor_api(
                &api_client,
                &session.shell,
                &editor.clone().unwrap_or(session.editor.clone()),
                &asset_contents,
                asset_name,
                asset_entry_ref,
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
            if asset_editor::get_invalid_asset_name_re().is_match(asset_name) {
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
                            asset_name: asset_name.to_owned(),
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
                    asset_name,
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
            let api_client = mk_api_client(Some(session));
            let (asset_contents, asset_entry) =
                match asset_editor::get_asset(&api_client, asset_name, false)
                    .await
                    .map(|(ac, ae)| (ac, Some(ae)))
                {
                    Ok(asset_get_res) => asset_get_res,
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_entry_ref =
                asset_entry.map(|entry| (entry.entry_id.clone(), entry.asset.rev_id.clone()));
            let _ = asset_editor::edit_with_editor_api(
                &api_client,
                &session.shell,
                &session.editor,
                &asset_contents,
                asset_name,
                asset_entry_ref,
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
            let api_client = mk_api_client(Some(session));
            if let Some(contents) = contents {
                let _ = update_asset_tx
                    .send(asset_editor::WorkerAssetMsg::Update(
                        asset_editor::WorkerAssetUpdate {
                            asset_name: asset_name.to_owned(),
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
                    asset_name,
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
            use crate::api::types::asset::AssetEntryListArg;
            let api_client = mk_api_client(Some(session));
            let asset_list_res = match api_client
                .asset_entry_list(AssetEntryListArg {
                    prefix: Some(prefix.into()),
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            use crate::api::types::asset::AssetEntryOp;
            for entry in &asset_list_res.entries {
                let symbol = if matches!(entry.op, AssetEntryOp::Push) {
                    "📥"
                } else {
                    ""
                };
                println!("{}{}", entry.name, symbol);
            }
            let asset_list_output = asset_list_res
                .entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<String>>()
                .join("\n");
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
            for entry in &asset_search_res.semantic_matches {
                println!("{}", entry.name)
            }
            let asset_search_output = asset_search_res
                .semantic_matches
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<String>>()
                .join("\n");
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
            let api_client = mk_api_client(Some(session));
            let asset_contents =
                match asset_editor::get_asset_as_text(&api_client, asset_name, false).await {
                    Ok(contents) => contents,
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let asset_contents_with_delimeters = format!(
                "<<<<<< BEGIN_ASSET: {} >>>>>>\n{}\n<<<<<< END_ASSET: {} >>>>>>",
                asset_name, asset_contents, asset_name,
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
        cmd::Cmd::AssetRevisions(cmd::AssetRevisionsCmd { asset_name }) => {
            let api_client = mk_api_client(Some(session));

            use crate::api::types::asset::{
                AssetEntryOp, AssetRevision, AssetRevisionIterArg, AssetRevisionIterNextArg,
                EntryRef,
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
                        AssetEntryOp::Other => {
                            "other"
                        }
                    }
                );
                if let Some(data_url) = revision.data_url.clone() {
                    if let Some(contents_bin) = asset_editor::get_asset_raw(&data_url).await {
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

            let mut revision_cursor = match api_client
                .asset_revision_iter(AssetRevisionIterArg {
                    entry_ref: EntryRef::Name(asset_name.to_owned()),
                    limit: 1,
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
                println!("Press any key to continue... CTRL+C to stop");
                let _ = crossterm::terminal::enable_raw_mode();
                let _ = crossterm::event::read();
                let _ = crossterm::terminal::disable_raw_mode();
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
        cmd::Cmd::AssetLink(cmd::AssetLinkCmd { asset_name }) => {
            let api_client = mk_api_client(Some(session));
            use crate::api::types::asset::AssetGetArg;
            let asset_data_url = match api_client
                .asset_get(AssetGetArg {
                    name: asset_name.to_string(),
                })
                .await
            {
                Ok(res) => res.data_url,
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
            let api_client = mk_api_client(Some(session));
            use crate::api::types::asset::AssetRemoveArg;
            match api_client
                .asset_remove(AssetRemoveArg {
                    name: asset_name.to_string(),
                })
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
                    name: target_asset_name.to_owned(),
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
                match asset_editor::get_asset(&api_client, source_asset_name, false).await {
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
        cmd::Cmd::AssetAcl(cmd::AssetAclCmd {
            asset_name,
            ace_permission,
            ace_type,
        }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
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
        cmd::Cmd::ChatLoad(cmd::ChatLoadCmd { chat_log_name }) => {
            if session.account.is_none() {
                eprintln!("{}", ASSET_ACCOUNT_REQ_MSG);
                return ProcessCmdResult::Loop;
            }
            let api_client = mk_api_client(Some(session));
            let chat_log_contents =
                match asset_editor::get_asset_as_text(&api_client, chat_log_name, false).await {
                    Ok(contents) => contents,
                    Err(_) => return ProcessCmdResult::Loop,
                };
            let history = match serde_json::from_str::<Vec<db::LogEntry>>(&chat_log_contents) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: chat log bad format: {}", e);
                    return ProcessCmdResult::Loop;
                }
            };
            session.history = history;
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
            println!("Saving to asset: {}", chat_log_asset_name);
            let serialized_log = serde_json::to_string_pretty(&session.history).unwrap();
            let api_client = mk_api_client(Some(session));
            use api::types::asset::{AssetPutTextArg, PutConflictPolicy};
            let _ = api_client
                .asset_put_text(AssetPutTextArg {
                    name: chat_log_asset_name,
                    data: serialized_log,
                    conflict_policy: PutConflictPolicy::Override,
                })
                .await;
            ProcessCmdResult::Loop
        }
        cmd::Cmd::Account(cmd::AccountCmd { username }) => {
            if let Some(username) = username {
                if username == "_" {
                    account_nobody_setup_session(session, db).await;
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
                    account_login_setup_session(
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
                    println!("ハイ {}!", account.username);
                } else {
                    println!("You have not logged into an account. Try /account-login");
                }
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
        cmd::Cmd::AccountLogin => {
            let username = match term::ask_question("Username?", false) {
                Some(username) => username,
                None => return ProcessCmdResult::Loop,
            };
            let password = match term::ask_question("Password?", true) {
                Some(password) => password,
                None => return ProcessCmdResult::Loop,
            };
            use api::types::account::AccountTokenFromLoginArg;
            let client = mk_api_client(None);
            match client
                .account_token_from_login(AccountTokenFromLoginArg { username, password })
                .await
            {
                Ok(res) => {
                    println!("ハイ {}!", res.username);
                    account_login_setup_session(
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
                                session.use_hai_router = true;
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
                    println!("Need more credits? Email me at ken@elkabany.com for help (sorry for the manual process)");
                    return ProcessCmdResult::Loop;
                }
            };
            println!("Thanks for supporting the development of hai!");
            println!();
            println!("Subscribe to the hai basic plan ($6 USD / month):");
            println!("- $3 USD in AI credits that can be used across OpenAI, Anthropic, Google, Deepseek");
            println!("  - Use `/ai <model>` without having to provide your own API keys");
            println!("  - Unused credits expire after two months");
            println!("- 10 GB of asset storage and public link sharing");
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
                account_nobody_setup_session(session, db).await;
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
                    agg_output_tokens += log.message.tokens;
                    agg_input_tokens += cur_input_tokens;

                    // The AI output becomes part of the next input
                    cur_input_tokens += log.message.tokens;
                } else {
                    // AI wasn't prompted, so only increment input token count
                    cur_input_tokens += log.message.tokens;
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
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4o),
                    config::AiModel::OpenAi(config::OpenAiModel::Gpt4oMini),
                    config::AiModel::OpenAi(config::OpenAiModel::O1),
                    config::AiModel::OpenAi(config::OpenAiModel::O1Mini),
                    config::AiModel::Anthropic(config::AnthropicModel::Sonnet35),
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
            println!("Entering tool mode; All messages are treated as prompts for {}. Use `!exit` when done",
            tool::tool_to_cmd(&tool_mode_cmd.tool, tool_mode_cmd.require));
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

// --

async fn account_login_setup_session(
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
            session.use_hai_router = hai_router_value == "on";
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("failed to read db: {}", e);
        }
    }
}

async fn account_nobody_setup_session(
    session: &mut SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
) {
    if let Some(cur_account) = &session.account {
        db::switch_to_nobody_account(&*db.lock().await, &cur_account.username)
            .expect("failed to write login info");
        session.account = None;
        session.use_hai_router = false;
    }
}

// --

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

/task <name|path>            - Enter task mode by loading task from repo (username/task-name) or file path
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
/prep                        - Queue a message to be sent with your next message (or, end with two blank lines)
/pin                         - Like /prep but the message is retained on /reset
/system-prompt               - Set a system prompt for the conversation
/clip                        - Copies the last message to your clipboard. Unlike !clip tool, AI is not prompted

--

Available Tools:
!clip <prompt>               - Ask AI to copy a part of the conversation to your clipboard
!py <prompt>                 - Ask AI to write Python script that will be executed on your machine
                               Searches for virtualenv in current dir & ancestors before falling back to python3
!sh <prompt>                 - Ask AI to write shell cmd or pipeline that will be executed on your machine
!shscript <prompt>           - Ask AI to write shell script and pipe it through stdin on your machine
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

EXPERIMENTAL:
/asset <name> [<editor>]     - Open asset in editor (create if does not exist)
/asset-new <name>            - Create a new asset and open editor
/asset-edit <name>           - Open existing asset in editor
/asset-list <prefix>         - List all assets with the given (optional) prefix
/asset-search <query>        - Search for assets semantically
/asset-load <name>           - Load asset into the conversation
/asset-view <name>           - Prints asset contents and loads it into the conversation
/asset-link <name>           - Prints link to asset (valid for 24hr) and loads it into the conversation
/asset-revisions <name>      - Lists revisions of an asset
/asset-acl <name> <ace>      - Changes ACL on an asset
                               `ace` is formatted as `type:permission`
                               type: allow, deny, default
                               permission: read-data, read-revisions, push-data
/asset-push <name>           - Push data into an asset. See pushed data w/ `/asset-revisions`
/asset-import <n> <p>        - Imports  <path> into asset with  <name>
/asset-export <n> <p>        - Exports asset with name to  <path>
/chat-save [<asset_name>]    - Save the conversation as an asset
/chat-load <asset_name>      - Replaces conversation with previously saved one"##;

/// Prints error to terminal if key not set.
fn check_api_key(ai: &config::AiModel, cfg: &config::Config) -> bool {
    match ai {
        config::AiModel::OpenAi(_) => {
            if cfg
                .openai
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires an OpenAI API Key: `/set-key openai <key>` OR `/hai-router on`",
                    config::get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        config::AiModel::Anthropic(_) => {
            if cfg
                .anthropic
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires an Anthropic API Key: `/set-key anthropic <key>` OR `/hai-router on`",
                    config::get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        config::AiModel::DeepSeek(_) => {
            if cfg
                .deepseek
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires a DeepSeek API Key: `/set-key deepseek <key>` OR `/hai-router on`",
                    config::get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        config::AiModel::Google(_) => {
            if cfg
                .google
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires a Google API Key: `/set-key google <key>` OR `/hai-router on`",
                    config::get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        config::AiModel::Ollama(_) => {
            // No auth needed
        }
    };
    true
}

/// Choose AI to initialize REPL with.
fn choose_init_ai_model(cfg: &config::Config) -> config::AiModel {
    let default_ai_model = if let Some(ref ai_model_unmatched_str) = cfg.default_ai_model {
        config::ai_model_from_string(ai_model_unmatched_str).or_else(|| {
            eprintln!("error: unknown model {}", ai_model_unmatched_str);
            None
        })
    } else {
        None
    };
    if let Some(ai_model) = default_ai_model {
        ai_model
    } else if let Some(config::OpenAiConfig {
        api_key: Some(_), ..
    }) = cfg.openai
    {
        config::AiModel::OpenAi(config::OpenAiModel::Gpt4o)
    } else if let Some(config::AnthropicConfig {
        api_key: Some(_), ..
    }) = cfg.anthropic
    {
        config::AiModel::Anthropic(config::AnthropicModel::Sonnet35)
    } else if let Some(config::DeepSeekConfig {
        api_key: Some(_), ..
    }) = cfg.deepseek
    {
        config::AiModel::DeepSeek(config::DeepSeekModel::DeepSeekChat)
    } else if let Some(config::GoogleConfig {
        api_key: Some(_), ..
    }) = cfg.google
    {
        config::AiModel::Google(config::GoogleModel::Gemini20Flash)
    } else if let Some(config::OllamaConfig { base_url: Some(_) }) = cfg.ollama {
        config::AiModel::Ollama(config::OllamaModel::Llama32)
    } else {
        config::AiModel::OpenAi(config::OpenAiModel::Gpt4o)
    }
}

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
            session.cmd_queue.push_front((
                (INTERNAL_TASK_NAME.to_string(), 1),
                format!("/{} {}", task_cmd, task_ref),
            ));
            session.cmd_queue.push_front((
                (INTERNAL_TASK_NAME.to_string(), 0),
                format!("/task-fetch {}", task_ref),
            ));
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

use crate::ctrlc_handler::CtrlcHandler;

async fn prompt_ai(
    msg_history: &[chat::Message],
    tool_policy: &Option<tool::ToolPolicy>,
    masked_strings: &HashSet<String>,
    session: &mut SessionState,
    cfg: &config::Config,
    ctrlc_handler: &mut CtrlcHandler,
    debug: bool,
) -> Vec<ChatCompletionResponse> {
    let api_base_url = get_api_base_url();
    let mut used_hai_router = false;
    let ai_provider_response = match session.ai {
        config::AiModel::OpenAi(_) | config::AiModel::Google(_) | config::AiModel::DeepSeek(_) => {
            let deepseek_flatten_nonuser_content =
                matches!(session.ai, config::AiModel::DeepSeek(_));
            let (base_url, api_key, provider_header) = if session.use_hai_router
                && config::is_ai_model_supported_by_hai_router(&session.ai)
            {
                let api_key = if let Some(ref account) = session.account {
                    account.token.clone()
                } else {
                    eprintln!("error: you must be logged-in to use the hai-router");
                    return vec![];
                };
                let provider_header = match session.ai {
                    config::AiModel::OpenAi(_) => "openai".to_string(),
                    config::AiModel::Google(_) => "google".to_string(),
                    config::AiModel::DeepSeek(_) => "deepseek".to_string(),
                    _ => {
                        eprintln!("error: unexpected provider");
                        return vec![];
                    }
                };
                used_hai_router = true;
                (Some(api_base_url.deref()), api_key, Some(provider_header))
            } else {
                match session.ai {
                    config::AiModel::OpenAi(_) => (
                        None,
                        cfg.openai
                            .as_ref()
                            .unwrap()
                            .api_key
                            .as_ref()
                            .unwrap()
                            .clone(),
                        None,
                    ),
                    config::AiModel::Google(_) => (
                        Some("https://generativelanguage.googleapis.com/v1beta/openai"),
                        cfg.google
                            .as_ref()
                            .unwrap()
                            .api_key
                            .as_ref()
                            .unwrap()
                            .clone(),
                        None,
                    ),
                    config::AiModel::DeepSeek(_) => (
                        Some("https://api.deepseek.com/v1"),
                        cfg.deepseek
                            .as_ref()
                            .unwrap()
                            .api_key
                            .as_ref()
                            .unwrap()
                            .clone(),
                        None,
                    ),
                    _ => {
                        eprintln!("error: unexpected provider");
                        return vec![];
                    }
                }
            };
            openai::send_to_openai(
                base_url,
                &api_key,
                provider_header,
                config::get_ai_model_provider_name(&session.ai),
                session.ai_temperature,
                msg_history,
                tool_policy.as_ref(),
                Some(ctrlc_handler),
                masked_strings,
                debug,
                deepseek_flatten_nonuser_content,
            )
            .await
        }
        config::AiModel::Anthropic(ref anthropic_model) => {
            let (api_url, api_key, provider_header) = if session.use_hai_router {
                let api_key = if let Some(ref account) = session.account {
                    account.token.clone()
                } else {
                    eprintln!("error: you must be logged-in to use the hai-router");
                    return vec![];
                };
                used_hai_router = true;
                (
                    Some(format!("{}/chat/completions", get_api_base_url())),
                    api_key,
                    Some("anthropic".to_string()),
                )
            } else {
                (
                    None,
                    cfg.anthropic
                        .as_ref()
                        .unwrap()
                        .api_key
                        .as_ref()
                        .unwrap()
                        .clone(),
                    None,
                )
            };
            let use_thinking = match anthropic_model {
                config::AnthropicModel::Sonnet37(use_thinking) => *use_thinking,
                _ => false,
            };
            anthropic::send_to_anthropic(
                api_url.as_deref(),
                &api_key,
                provider_header,
                config::get_ai_model_provider_name(&session.ai),
                use_thinking,
                session.ai_temperature,
                msg_history,
                tool_policy.as_ref(),
                Some(ctrlc_handler),
                masked_strings,
                debug,
            )
            .await
        }
        config::AiModel::Ollama(_) => {
            ollama::send_to_ollama(
                cfg.ollama
                    .as_ref()
                    .and_then(|ollama| ollama.base_url.as_deref()),
                config::get_ai_model_provider_name(&session.ai),
                session.ai_temperature,
                msg_history,
                tool_policy.as_ref(),
                Some(ctrlc_handler),
                masked_strings,
                debug,
            )
            .await
        }
    };
    match ai_provider_response {
        Ok(chat_response) => chat_response,
        Err(e) => {
            eprintln!("error: ai provider: {}", e);
            if used_hai_router
                && e.to_string()
                    .to_ascii_lowercase()
                    .contains("402 payment required")
            {
                eprintln!("error: account needs funds, disabling hai-router");
                session.use_hai_router = false;
            }
            vec![]
        }
    }
}

fn mk_api_client(session: Option<&SessionState>) -> HaiClient {
    let mut client = HaiClient::new(&get_api_base_url());
    if let Some(session) = session {
        if let Some(ref account) = session.account {
            client.set_token(&account.token);
        }
    }
    client
}

fn get_api_base_url() -> String {
    match env::var("HAI_BASE_URL") {
        Ok(value) => value,
        _ => "https://hai.superego.ai/1".to_string(),
    }
}

pub async fn shell_exec(shell: &str, cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    tool::collect_and_print_command_output(&mut child).await
}

fn get_haivar_re() -> &'static Regex {
    static HAIVAR_RE: OnceLock<Regex> = OnceLock::new();
    HAIVAR_RE.get_or_init(|| Regex::new(r"\$([a-zA-Z][a-zA-Z0-9_]*)").unwrap())
}

fn replace_haivars(s: &str, haivars: &HashMap<String, String>) -> String {
    let haivar_re = get_haivar_re();
    let result = haivar_re.replace_all(s, |caps: &regex::Captures| {
        let key = &caps[1];
        haivars.get(key).cloned().unwrap_or_else(|| {
            eprintln!("error: undefined variable: {}", &caps[0]);
            caps[0].to_string()
        })
    });
    result.to_string()
}

// Recalculates token count based on history.
//
// Useful when history has been pruned.
fn recalculate_input_tokens(session: &mut SessionState) {
    let mut input_tokens = 0;
    let mut input_loaded_tokens = 0;
    for message in &session.history {
        if message.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
            input_loaded_tokens += message.message.tokens;
        } else {
            input_tokens += message.message.tokens;
        }
    }
    session.input_tokens = input_tokens;
    session.input_loaded_tokens = input_loaded_tokens;
}

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

async fn is_client_update_available(db: Arc<Mutex<rusqlite::Connection>>) -> Option<String> {
    let db_cloned = db.clone();
    tokio::spawn(async move {
        let hai_client = mk_api_client(None);
        let client_version_res = hai_client.account_check_client_version(()).await;
        if let Ok(client_version_res) = client_version_res {
            let conn = &*db_cloned.lock().await;
            let _ = db::set_misc_entry(
                conn,
                "",
                "latest_client_version",
                &client_version_res.version,
            );
        }
    });
    match db::get_misc_entry(&*db.lock().await, "", "latest_client_version") {
        Ok(Some((latest_client_version_str, _))) => {
            let latest_client_version = semver::Version::parse(&latest_client_version_str).ok();
            let cur_client_version = semver::Version::parse(env!("CARGO_PKG_VERSION")).ok();
            if let (Some(latest), Some(current)) = (latest_client_version, cur_client_version) {
                if latest > current {
                    Some(latest_client_version_str)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Ok(_) => None,
        Err(e) => {
            eprintln!("failed to read db: {}", e);
            None
        }
    }
}

fn get_machine_os_arch() -> String {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(all(target_arch = "arm", target_feature = "v7")) {
        "armv7"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "unknown"
    };
    format!("{}-{}", os, arch)
}

/// Convenience function to add "user text" into conversation history while
/// making the appropriate modifications to the session and token count.
///
/// # Returns
///
/// The number of tokens in `contents`.
fn session_history_add_user_text_entry(
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
            tokens: token_count,
        },
        retention_policy,
    });
    token_count
}

/// Similar to `session_history_add_user_text_entry` but also adds an entry for
/// the user's input command.
fn session_history_add_user_cmd_and_reply_entries(
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
fn session_history_add_user_image_entry(
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
            tokens: token_count,
        },
        retention_policy,
    });
    token_count
}
