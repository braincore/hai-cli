use ai_provider::{anthropic, ollama, openai};
use chat::ChatCompletionResponse;
use clap::{Parser, Subcommand};
use colored::*;
use line_editor::LineEditor;
use reedline::{self, Signal};
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::ops::Deref;
use std::process;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

mod ai_provider;
mod api;
mod asset_editor;
mod asset_sync;
mod chat;
mod clipboard;
mod cmd;
mod cmd_processor;
mod config;
mod ctrlc_handler;
mod db;
mod feature;
mod line_editor;
mod loader;
mod session;
mod term;
mod term_color;
mod tool;

use session::{get_api_base_url, mk_api_client, HaiRouterState, ReplMode, SessionState};

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

        /// Automatically confirm any prompts
        #[arg(long = "trust")]
        trust: bool,
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
            } else if let Some(CliSubcommand::Task { task_ref, trust }) = args.subcommand {
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
                    if trust {
                        vec![format!("/task(trust=true) {}", fixed_task_ref)]
                    } else {
                        vec![format!("/task {}", fixed_task_ref)]
                    },
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
        "/ls",
        "/asset-search",
        "/asset-load",
        "/asset-view",
        "/asset-revisions",
        "/asset-link",
        "/asset-import",
        "/asset-export",
        "/asset-temp",
        "/asset-sync-down",
        "/asset-acl",
        "/asset-remove",
        "/asset-md-get",
        "/asset-md-set",
        "/asset-md-set-key",
        "/asset-md-del-key",
        "/account",
        "/account-new",
        "/account-login",
        "/account-logout",
        "/account-balance",
        "/account-subscribe",
        "/chat-save",
        "/chat-resume",
        "/whois",
        "/hai-router",
        "/cost",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let autocomplete_repl_ai_models: Vec<String> = [
        "41",
        "41m",
        "41n",
        "4o",
        "4om",
        "chatgpt-4o",
        "gpt-41",
        "gpt-41-mini",
        "gpt-41-nano",
        "gpt-4o",
        "gpt-4o-mini",
        "o1",
        "o1-pro",
        "o3",
        "o3-mini",
        "o4-mini",
        "haiku35",
        "sonnet",
        "sonnet35",
        "sonnet37",
        "sonnet37-thinking",
        "llama32",
        "llama32-vision",
        "flash",
        "flash25",
        "flash20",
        "flash15",
        "gemini25pro",
        "gemini15pro",
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

    let mut default_ai_model = config::choose_init_ai_model(&cfg);
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
    let default_shell = if cfg!(target_os = "windows") {
        cfg.default_shell.clone().unwrap_or("powershell".into())
    } else {
        cfg.default_shell.clone().unwrap_or("bash".into())
    };

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
        incognito,
        last_tool_cmd: None,
        tool_mode: None,
        use_hai_router: HaiRouterState::Off,
        temp_files: vec![],
    };

    if let Some(account) = &account {
        session::account_login_setup_session(
            &mut session,
            db.clone(),
            &account.user_id,
            &account.username,
            &account.token,
        )
        .await;
    }

    if matches!(session.use_hai_router, HaiRouterState::Off) {
        // Prints error if API key not available
        config::check_api_key(&session.ai, &cfg);
    }

    for (index, init_cmd) in init_cmds.into_iter().enumerate() {
        session.cmd_queue.push_back(session::CmdInput {
            input: init_cmd,
            source: if exit_when_done {
                session::CmdSource::HaiBye(index as u32)
            } else {
                session::CmdSource::User
            },
        });
    }

    //
    // Welcome message (omitted in hai-bye mode)
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
            println!("  - changelog: `/asset-view /hai/changelog` or `!!cat @/hai/changelog`");
            let os_arch = get_machine_os_arch();
            if !os_arch.starts_with("windows") {
                println!("  - installer (from shell): `curl -LsSf https://hai.superego.ai/hai-installer.sh | sh`");
            } else {
                let asset_name = format!("hai-cli-{}-{}.zip", version, get_machine_os_arch());
                println!("  - download: `/asset-export /hai/client/{} .`", asset_name);
                if let Ok(exe_path) = env::current_exe() {
                    println!("  - install: unpack and copy to {:?}", exe_path);
                }
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

    //
    // REPL Loop
    //
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
        editor_prompt.set_hai_router(session.use_hai_router.clone());
        editor_prompt.set_input_tokens(session.input_tokens + session.input_loaded_tokens);
        if let ReplMode::Task(task_fqn, _) = &session.repl_mode {
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
        // - Either reads from a queue of waiting cmds or from user input.
        //
        let cmd_input = if let Some(cmd_info) = session.cmd_queue.pop_front() {
            if let session::CmdSource::TaskStep(task_fqn, step_id) = &cmd_info.source {
                if *step_id > 0 {
                    println!();
                }
                let step_badge = format!("{}[{}]:", task_fqn, session.history.len());
                println!("{} {}", step_badge.black().on_white(), cmd_info.input);
            } else if let session::CmdSource::HaiTool(index) = &cmd_info.source {
                let step_badge = format!("!hai-tool[{}]:", index);
                println!("{} {}", step_badge.black().on_white(), cmd_info.input);
            } else if let session::CmdSource::HaiBye(index) = &cmd_info.source {
                let step_badge = format!("bye[{}]:", index);
                println!("{} {}", step_badge.black().on_white(), cmd_info.input);
            }
            cmd_info
        } else {
            line_editor.pre_readline();
            let sig = line_editor.reedline.read_line(&editor_prompt);
            line_editor.post_readline();
            match sig {
                // Maintain prefix whitespace as that's how a user can
                // easily make an input guarantee to not match a command.
                // Maintain suffix whitespace as that's how a user can switch
                // a /prompt into a /prep.
                Ok(Signal::Success(buffer)) => session::CmdInput {
                    input: buffer,
                    source: session::CmdSource::User,
                },
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
        };

        let task_step_signature = cmd_input.source.get_task_step_signature();
        let is_task_mode_step =
            task_step_signature.is_some() && matches!(session.repl_mode, ReplMode::Task(..));
        let trusted = if let ReplMode::Task(_, trusted) = session.repl_mode {
            trusted && is_task_mode_step
        } else {
            false
        };
        let task_step_requires_user_confirmation = is_task_mode_step && !trusted;

        let last_tool_cmd = session.last_tool_cmd.clone();
        let tool_mode = session.tool_mode.clone();
        // Expectation is that if `parse_user_input` returns None, it will have
        // also printed an error msg to the user so it's okay to ignore the
        // input here.
        let maybe_cmd = cmd::parse_user_input(&cmd_input.input, last_tool_cmd, tool_mode);
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
        let (prompt, cache) = match cmd_processor::process_cmd(
            config_path_override,
            &mut session,
            &mut cfg,
            db.clone(),
            update_asset_tx.clone(),
            ctrlc_handler,
            bpe_tokenizer,
            &cmd,
            &cmd_input,
            force_yes,
            debug,
        )
        .await
        {
            cmd_processor::ProcessCmdResult::Break => break,
            cmd_processor::ProcessCmdResult::Loop => {
                if exit_when_done && session.cmd_queue.is_empty() {
                    process::exit(0);
                };
                continue;
            }
            cmd_processor::ProcessCmdResult::PromptAi(prompt, cache) => (prompt, cache),
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
        if !matches!(session.use_hai_router, HaiRouterState::On)
            && !config::check_api_key(&session.ai, &cfg)
        {
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
            },
            tokens,
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
            if let Some((task_fqn, step_index)) = &task_step_signature {
                db::set_task_step_cache(
                    &*db.lock().await,
                    task_fqn,
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
                        },
                        tokens,
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
                        },
                        tokens,
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

                let user_confirmed_tool_execute = if !force_yes
                    && (cfg.tool_confirm
                        || tool_policy_needs_user_confirmation
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
                            },
                            tokens,
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
                            },
                            tokens,
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

    if !exit_when_done {
        feature::save_chat::save_chat_to_db(&session, db).await;
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
            tool: tool::Tool::ShellExecWithScript(feature::haivar::replace_haivars(
                shell_cmd, haivars,
            )),
            // Replace vars in the recorded input because the unexpanded
            // vars are sometimes too opaque for the AI to understand.
            prompt: feature::haivar::replace_haivars(prompt, haivars),
            require: *require,
            cache: *cache,
        })
    } else {
        cmd.clone()
    }
}

// --

pub async fn prompt_ai(
    msg_history: &[chat::Message],
    tool_policy: &Option<tool::ToolPolicy>,
    masked_strings: &HashSet<String>,
    session: &mut SessionState,
    cfg: &config::Config,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    debug: bool,
) -> Vec<ChatCompletionResponse> {
    let api_base_url = get_api_base_url();
    let mut used_hai_router = false;
    let ai_provider_response = match session.ai {
        config::AiModel::OpenAi(_) | config::AiModel::Google(_) | config::AiModel::DeepSeek(_) => {
            let deepseek_flatten_nonuser_content =
                matches!(session.ai, config::AiModel::DeepSeek(_));
            let (base_url, api_key, provider_header) =
                if matches!(session.use_hai_router, HaiRouterState::On)
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
            let (api_url, api_key, provider_header) =
                if matches!(session.use_hai_router, HaiRouterState::On) {
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
                session::hai_router_set(session, false);
            }
            vec![]
        }
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
