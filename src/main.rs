use ai_provider::{anthropic, ollama, openai, tool_schema, void};
use chat::ChatCompletionResponse;
use clap::{Parser, Subcommand};
use colored::*;
use line_editor::LineEditor;
use reedline::{self, Signal};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::io::Read;
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

use session::{HaiRouterState, ReplMode, SessionState, get_api_base_url, mk_api_client};

/// A CLI for interacting with LLMs in a hacker-centric way
#[derive(Parser)]
#[command(name = "hai")]
#[command(
    about = "A CLI for interacting with LLMs in a hacker-centric way",
    version = env!("CARGO_PKG_VERSION")
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
        /// The AI provider (e.g., openai, anthropic, google, deepseek, xai)
        provider: String,

        /// The API key to save
        key: String,
    },
    /// Login to your hai account (optional)
    Login {
        /// Your hai account username
        username: String,

        /// Your hai account password (if omitted, interactive prompt)
        password: Option<String>,
    },
    /// Start in task mode
    Task {
        /// The fully-qualified name of the task (username/task-name) or file path
        task_ref: String,

        /// Automatically confirm any prompts
        #[arg(long = "trust")]
        trust: bool,

        /// Task key for separate caches
        #[arg(long = "key")]
        key: Option<String>,
    },
    /// Run a set of commands/prompts and quit (alias: "bai").
    /// WARNING: Quote each command with single-quotes to avoid shell expansion.
    #[command(alias = "bai")]
    Bye {
        /// Commands to run. Use '-' to read from stdin into /prep
        #[arg(required = true, num_args = 1..)]
        cmds: Vec<String>,

        /// Automatically confirm any prompts
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
    /// Setup websocket listener for API-based commands
    Listen {
        /// The address to listen on (default: 127.0.0.1:1338)
        #[arg(short = 'a', long = "address", default_value = "127.0.0.1:1338")]
        address: String,

        /// The origin allowed to send messages
        #[arg(short = 'w', long = "whitelisted-origin")]
        whitelisted_origin: Option<String>,
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
            "openai" | "anthropic" | "google" | "deepseek" | "xai" => {
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
    } else if let Some(CliSubcommand::Listen {
        address,
        whitelisted_origin,
    }) = args.subcommand
    {
        crate::feature::queue_listen::listen(&address, whitelisted_origin).await;
    } else {
        let (repl_mode, init_cmds, exit_when_done, force_yes) = if let Some(CliSubcommand::Bye {
            cmds,
            yes,
        }) = args.subcommand
        {
            (
                    ReplMode::Normal,
                    cmds.into_iter()
                        .enumerate()
                        .map(|(idx, prompt)| {
                            if prompt == "-" {
                                if atty::is(atty::Stream::Stdin) {
                                        eprintln!("No input detected on stdin. Did you forget to pipe or redirect a file?");
                                        std::process::exit(1);
                                    }
                                    let mut stdin_buffer = String::new();
                                    std::io::stdin().read_to_string(&mut stdin_buffer).unwrap();
                                    session::CmdInput {
                                        input: format!("/prep {}", stdin_buffer),
                                        source: session::CmdSource::HaiBye(idx as u32),
                                    }
                                } else {
                                    session::CmdInput {
                                        input: prompt,
                                        source: session::CmdSource::HaiBye(idx as u32),
                                    }
                                }
                        })
                        .collect(),
                    true,
                    yes,
                )
        } else if let Some(CliSubcommand::Login { username, password }) = args.subcommand {
            let account_login_cmd = if let Some(password) = password {
                format!("/account-login {} {}", username, password)
            } else {
                format!("/account-login {}", username)
            };
            (
                ReplMode::Normal,
                vec![session::CmdInput {
                    input: account_login_cmd,
                    // Use Internal to avoid printing command
                    source: session::CmdSource::Internal,
                }],
                true,
                false,
            )
        } else if let Some(CliSubcommand::Task {
            task_ref,
            trust,
            key,
        }) = args.subcommand
        {
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
            let mut options = vec![];
            if trust {
                options.push("trust".to_string());
            }
            if let Some(key) = key {
                options.push(format!("key=\"{key}\""));
            }
            let task_cmd = if options.is_empty() {
                format!("/task {}", fixed_task_ref)
            } else {
                format!("/task({}) {}", options.join(","), fixed_task_ref)
            };
            (
                ReplMode::Normal,
                vec![session::CmdInput {
                    input: task_cmd,
                    source: session::CmdSource::User,
                }],
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
    init_cmds: Vec<session::CmdInput>,
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

    let default_autocomplete_repl_cmds: Vec<String> = [
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
        "/keep",
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
        "/asset-listen",
        "/asset-acl",
        "/asset-remove",
        "/asset-md-get",
        "/asset-md-set",
        "/asset-md-set-key",
        "/asset-md-del-key",
        "/asset-folder-collapse",
        "/asset-folder-expand",
        "/asset-folder-list",
        "/email",
        "/fns",
        "/std",
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
        "/queue-pop",
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
        "gemma3",
        "gpt-41",
        "gpt-41-mini",
        "gpt-41-nano",
        "gpt-5",
        "gpt-5-chat",
        "gpt-5-mini",
        "gpt-5-nano",
        "gpt-51",
        "gpt-51-chat",
        "gpt-52",
        "gpt-52-chat",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-oss",
        "o1",
        "o1-pro",
        "o3",
        "o3-mini",
        "o4-mini",
        "haiku35",
        "opus",
        "opus4",
        "opus4-thinking",
        "opus41",
        "opus45",
        "sonnet",
        "sonnet35",
        "sonnet37",
        "sonnet37-thinking",
        "sonnet4",
        "sonnet4-thinking",
        "sonnet45",
        "llama32",
        "llama32-vision",
        "flash",
        "flash3",
        "flash25",
        "flash20",
        "flash15",
        "gemini15pro",
        "gemini25pro",
        "gemini3pro",
        "deepseek",
        "v3",
        "r1",
        "grok",
        "grok-3",
        "grok-3-fast",
        "grok-3-mini",
        "grok-3-mini-fast",
        "grok-4",
        "openai/",
        "anthropic/",
        "google/",
        "xai/",
        "ollama/",
        "llamacpp",
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
    if incognito && let Some(ref ai_model_unmatched_str) = cfg.default_incognito_ai_model {
        if let Some(ai_model) = config::ai_model_from_string(ai_model_unmatched_str) {
            default_ai_model = ai_model;
        } else {
            eprintln!("error: unknown incognito model {}", ai_model_unmatched_str);
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
        if force_account == "_" {
            None
        } else {
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
        masked_strings: vec![],
        mask_secrets: false,
        account: account.clone(),
        incognito,
        last_tool_cmd: None,
        tool_mode: None,
        use_hai_router: HaiRouterState::Off,
        temp_files: vec![],
        ai_defined_fns: HashMap::new(),
        add_msg_on_new_day: false,
        html_output: None,
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

    for init_cmd in init_cmds.into_iter() {
        session.cmd_queue.push_back(init_cmd);
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
            let os_arch = config::get_machine_os_arch();
            if !os_arch.starts_with("windows") {
                println!(
                    "  - installer (from shell): `curl -LsSf https://hai.superego.ai/hai-installer.sh | sh`"
                );
            } else {
                let asset_name =
                    format!("hai-cli-{}-{}.zip", version, config::get_machine_os_arch());
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
        println!("/help for more commands | `/task hai/feedback` for ideas & suggestions");
    };

    //
    // REPL Loop
    //
    loop {
        let mut autocomplete_repl_cmds = default_autocomplete_repl_cmds.clone();
        autocomplete_repl_cmds.extend(
            session
                .ai_defined_fns
                .keys()
                .map(|fn_name| format!("/{}", fn_name)),
        );
        line_editor.set_line_completer(
            debug,
            autocomplete_repl_cmds,
            autocomplete_repl_ai_models.clone(),
            mk_api_client(Some(&session)),
            session.account.clone(),
        );
        //
        // Set editor prompt info for display purposes
        //
        editor_prompt.set_index(session.history.len().try_into().unwrap());
        editor_prompt.set_ai_model_name(config::get_ai_model_display_name(&session.ai).to_string());
        editor_prompt.set_hai_router(session.use_hai_router.clone());
        editor_prompt.set_input_tokens(session.input_tokens + session.input_loaded_tokens);
        if let ReplMode::Task(task_fqn, _, _) = &session.repl_mode {
            editor_prompt.set_task_mode(Some(task_fqn.to_owned()));
        } else {
            editor_prompt.set_task_mode(None);
        }
        editor_prompt.set_tool_mode(session.tool_mode.clone().map(|tool_mode_cmd| {
            tool::tool_to_cmd(
                &tool_mode_cmd.tool,
                tool_mode_cmd.user_confirmation,
                tool_mode_cmd.force_tool,
            )
        }));

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

        let masked_strings = if session.mask_secrets {
            session.masked_strings.clone()
        } else {
            Vec::new()
        };

        //
        // REPL Read
        // - Either reads from a queue of waiting cmds or from user input.
        //
        let cmd_input = if let Some(cmd_info) = session.cmd_queue.pop_front() {
            if let session::CmdSource::TaskStep(task_fqn, _, step_id) = &cmd_info.source {
                if *step_id > 0 {
                    println!();
                }
                let step_badge = format!("{}[{}]:", task_fqn, session.history.len());

                print_step(&step_badge, &cmd_info.input, &masked_strings);
            } else if let session::CmdSource::ListenQueue(queue_name, index) = &cmd_info.source {
                let step_badge = if let Some(queue_name) = queue_name {
                    format!("queue/{}[{}]:", queue_name, index)
                } else {
                    format!("queue[{}]:", index)
                };
                print_step(&step_badge, &cmd_info.input, &masked_strings);
            } else if let session::CmdSource::HaiTool(index) = &cmd_info.source {
                let step_badge = format!("!hai-tool[{}]:", index);
                print_step(&step_badge, &cmd_info.input, &masked_strings);
            } else if let session::CmdSource::HaiBye(index) = &cmd_info.source {
                let step_badge = format!("bye[{}]:", index);
                print_step(&step_badge, &cmd_info.input, &masked_strings);
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
                    if session.tool_mode.is_some() {
                        session::CmdInput {
                            input: "!exit".to_string(),
                            source: session::CmdSource::Internal,
                        }
                    } else if matches!(session.repl_mode, ReplMode::Task(..)) {
                        session::CmdInput {
                            input: "/task-end".to_string(),
                            source: session::CmdSource::Internal,
                        }
                    } else {
                        println!("バイバイ！");
                        break;
                    }
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
        let trusted = if let ReplMode::Task(_, _, trusted) = session.repl_mode {
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
        if exit_when_done
            && session.cmd_queue.is_empty()
            && let cmd::Cmd::Noop = cmd
        {
            cleanup(&session);
            process::exit(0);
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

        if session.add_msg_on_new_day {
            // Check if it's a new day in local time. If so, add a message to
            // the history so that the AI is aware of this.
            if let Some(last_log_entry) = session.history.last() {
                let last_date = last_log_entry.ts.date_naive();
                let current_date = chrono::Local::now().date_naive();
                if last_date != current_date {
                    let now = chrono::Local::now();
                    let utc_now = chrono::Utc::now();
                    let local_tz = now.offset();
                    let contents = format!(
                        "It's a new day.\nLocal datetime ({}): {}\nUTC datetime: {}\n",
                        local_tz,
                        now.format("%Y-%m-%d %H:%M:%S"),
                        utc_now.format("%Y-%m-%d %H:%M:%S"),
                    );
                    println!();
                    println!("🕛🕛🕛");
                    println!();
                    print!("{}", contents);
                    session::session_history_add_user_text_entry(
                        &contents,
                        &mut session,
                        bpe_tokenizer,
                        (is_task_mode_step, db::LogEntryRetentionPolicy::None),
                    );
                }
            }
        }

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
                    cleanup(&session);
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
        if let cmd::Cmd::Tool(_) = cmd
            && !config::get_ai_model_capability(&session.ai).tool
        {
            eprintln!("error: model does not support tools");
            continue;
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
                user_confirmation: tool_cmd.user_confirmation,
                force_tool: tool_cmd.force_tool,
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
            ts: chrono::Local::now(),
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
        println!("{}", "↓↓↓".truecolor(128, 128, 128));
        println!();

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
            if let Some((ref task_fqn, ref task_key, step_index)) = task_step_signature {
                let ai_responses_from_cache = if cache {
                    // An error deserializing is likely due to a change
                    // in format due to a version update. Assume that
                    // the cache value will be updated to a compatible
                    // schema once the user enters a new value.
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
                        &prompt,
                    )
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
            if let Some((ref task_fqn, _, _)) = task_step_signature {
                println!("[Retrieved from cache; `/task-forget {task_fqn}` to prompt again]");
            }
            // Because it's from the cache, the response is not yet on the screen.
            for ai_response in &ai_responses {
                match ai_response {
                    chat::ChatCompletionResponse::Message { text } => {
                        println!("{}", text);
                    }
                    chat::ChatCompletionResponse::Tool {
                        tool_id,
                        tool_name,
                        arg,
                        ..
                    } => {
                        // Since the tool response is saved raw in the history,
                        // use the JsonObjectAccumulator to process and print
                        // the response in the same user-friendly way as done
                        // in the AI providers.
                        let mut json_obj_acc = ai_provider::util::JsonObjectAccumulator::new(
                            tool_id.clone(),
                            tool_name.clone(),
                            tool_schema::get_syntax_highlighter_token_from_tool_name(tool_name),
                            masked_strings.clone(),
                        );
                        json_obj_acc.acc(arg);
                        json_obj_acc.end();
                    }
                };
            }
        } else if cache && let Some((task_fqn, task_key, step_index)) = &task_step_signature {
            db::set_task_step_cache(
                &*db.lock().await,
                session
                    .account
                    .as_ref()
                    .map(|a| a.username.as_str())
                    .unwrap_or(""),
                task_fqn,
                task_key.as_deref(),
                *step_index,
                &prompt,
                &serde_json::to_string(&ai_responses).unwrap(),
            )
        }

        for ai_response in &ai_responses {
            //
            // Bookkeeping
            //

            // Increment `input_tokens` b/c the AI output will be part of the next input
            let tokens = match ai_response {
                chat::ChatCompletionResponse::Message { text } => {
                    bpe_tokenizer.encode_with_special_tokens(text).len() as u32
                }
                chat::ChatCompletionResponse::Tool { arg, .. } => {
                    bpe_tokenizer.encode_with_special_tokens(arg).len() as u32
                }
            };
            session.input_tokens += tokens;

            // Append AI's response to history
            match ai_response {
                chat::ChatCompletionResponse::Message { text } => {
                    session.history.push(db::LogEntry {
                        uuid: Uuid::now_v7().to_string(),
                        ts: chrono::Local::now(),
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
                    tool_id,
                    tool_name,
                    arg,
                } => {
                    session.history.push(db::LogEntry {
                        uuid: Uuid::now_v7().to_string(),
                        ts: chrono::Local::now(),
                        message: chat::Message {
                            role: chat::MessageRole::Assistant,
                            content: vec![],
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
                // for these over-zealous recommendations. Unfortunately, this
                // logic is still inadequate as the use of a tool that doesn't
                // match the tool policy may be a poor approximation of the
                // original one used (FIXME).
                let inexact_tool = ai_provider::tool_schema::get_tool_from_name(tool_name);
                let tool_policy_combined = tool_policy.clone().or_else(|| {
                    inexact_tool.map(|tool| tool::ToolPolicy {
                        tool,
                        user_confirmation: false,
                        force_tool: false,
                    })
                });

                // The tools that don't need user-confirmation are those that
                // don't have destructive potential. !fn-py only assigns a
                // function but does not execute it. !clip can be abused but
                // it's more of a nuisance. Also, the prompting of the AI may
                // still require user confirmation.
                let tool_needs_user_confirmation = !matches!(
                    tool_policy_combined,
                    Some(tool::ToolPolicy {
                        tool: tool::Tool::Fn(_) | tool::Tool::CopyToClipboard,
                        ..
                    })
                );
                // If the tool is a no-op, then it doesn't need user confirmation.
                let tool_noops = match tool_policy_combined {
                    Some(tool::ToolPolicy {
                        tool: tool::Tool::HaiRepl,
                        ..
                    }) => {
                        if let Ok(hai_repl_arg) = serde_json::from_str::<tool::ToolHaiReplArg>(arg)
                        {
                            hai_repl_arg.cmds.is_empty()
                        } else {
                            false
                        }
                    }
                    Some(_) | None => false,
                };

                // The negation of the policy to require the AI to use a tool
                // doubles as a way to require user confirmation.
                let tool_policy_needs_user_confirmation = tool_policy_combined
                    .clone()
                    .map(|tp| tp.user_confirmation)
                    .unwrap_or(false);

                let user_confirmed_tool_execute = if !force_yes
                    && !tool_noops
                    && tool_needs_user_confirmation
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
                            ts: chrono::Local::now(),
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

                if user_confirmed_tool_execute && let Some(ref tp) = tool_policy_combined {
                    let tool_exec_handler_id = ctrlc_handler.add_handler(|| {
                        println!("Tool Interrupted");
                    });
                    let output_text = if matches!(tp.tool, tool::Tool::HaiRepl) {
                        match tool::execute_hai_repl_tool(&tp.tool, arg, &mut session.cmd_queue) {
                            Ok(output_text) => output_text,
                            Err(e) => {
                                let err_text = format!("error executing hai-repl tool: {}", e);
                                println!("{}", err_text);
                                err_text
                            }
                        }
                    } else if let tool::Tool::Fn(fn_tool) = &tp.tool {
                        let ai_defined_tool_name = if let Some(name) = fn_tool.name.as_ref() {
                            // If name already in use, replaces.
                            // This makes iteration easier.
                            format!("f_{}", name)
                        } else {
                            // Get first free name
                            let mut i = session.ai_defined_fns.len();
                            loop {
                                let test_name = format!("f{}", i);
                                if !session.ai_defined_fns.contains_key(&test_name) {
                                    break test_name;
                                }
                                i += 1;
                            }
                        };
                        match tool::extract_ai_defined_fn_def(arg) {
                            Ok(fn_def) => {
                                let ai_defined_fn = session::AiDefinedFn {
                                    fn_def,
                                    fn_tool: fn_tool.clone(),
                                };
                                session.ai_defined_fns.insert(
                                    ai_defined_tool_name.clone(),
                                    (ai_defined_fn, is_task_mode_step),
                                );
                                let output_text =
                                    format!("Stored as command: /{}", ai_defined_tool_name);
                                println!("{}", output_text);
                                output_text
                            }
                            Err(e) => {
                                let err_text = format!("error extracting function: {}", e);
                                println!("{}", err_text);
                                err_text
                            }
                        }
                    } else if matches!(tp.tool, tool::Tool::Html) {
                        match feature::html_tool::execute_html_tool(
                            &mut session,
                            is_task_mode_step,
                            arg,
                        )
                        .await
                        {
                            Ok(temp_file_path) => {
                                let output_text = format!("Updated {}", temp_file_path);
                                println!("{}", output_text);
                                output_text
                            }
                            Err(e) => {
                                let err_text = format!("error executing HTML tool: {}", e);
                                println!("{}", err_text);
                                err_text
                            }
                        }
                    } else {
                        match tool::execute_shell_based_tool(&tp.tool, arg, &session.shell).await {
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
                        ts: chrono::Local::now(),
                        message: chat::Message {
                            role: chat::MessageRole::Tool,
                            content: vec![chat::MessageContent::Text { text: output_text }],
                            tool_calls: None,
                            tool_call_id: Some(tool_id.clone()),
                        },
                        tokens,
                        retention_policy: (is_task_mode_step, db::LogEntryRetentionPolicy::None),
                    });
                }
            }
        }

        if exit_when_done && session.cmd_queue.is_empty() {
            cleanup(&session);
            process::exit(0);
        };

        println!();
        println!("{}", "---".truecolor(128, 128, 128));
        println!();
    }

    if !exit_when_done {
        feature::save_chat::save_chat_to_db(&session, db).await;
    }

    cleanup(&session);

    Ok(())
}

// --

fn cleanup(session: &SessionState) {
    if matches!(session.repl_mode, ReplMode::Task(_, _, _)) {
        term::window_title_reset();
    }
}

// --

/// Prints step (a REPL command from a source such as a task-step, bye-step, or
/// hai-tool-step) with appropriate syntax highlighting and accent color.
fn print_step(step_badge: &str, input: &str, masked_strings: &Vec<String>) {
    let mut masked_input = input.to_string();
    for masked_string in masked_strings {
        let mask = "*".repeat(masked_string.len());
        masked_input = masked_input.replace(masked_string, &mask);
    }

    if cmd::get_cmds_with_markdown_body_re().is_match(input) {
        print!("{} ", step_badge.black().on_white());
        let color = if let Some(cmd::Cmd::Pin(cmd::PinCmd { accent, .. }))
        | Some(cmd::Cmd::Prep(cmd::PrepCmd { accent, .. })) =
            cmd::parse_user_input(input, None, None)
        {
            match accent {
                Some(cmd::Accent::Danger) => Some((128, 0, 0)),
                Some(cmd::Accent::Warn) => Some((153, 102, 0)),
                Some(cmd::Accent::Info) => Some((0, 51, 102)),
                Some(cmd::Accent::Success) => Some((0, 102, 51)),
                _ => None,
            }
        } else {
            None
        };
        term_color::print_multi_lang_syntax_highlighting(&masked_input, &color);
        println!();
    } else {
        println!("{} {}", step_badge.black().on_white(), &masked_input);
    }
}

// --

/// Replace haivars in specific parts of specific commands.
///
/// For now, this only replaces haivars in shell-exec-with-{file,stdin} tool in
/// both the shell-cmd and prompt, which includes the shell-cmd redundantly.
fn preprocess_cmd(cmd: cmd::Cmd, haivars: &HashMap<String, String>) -> cmd::Cmd {
    // Replace variables in the custom command itself for tool execution.
    let tool = match cmd.clone() {
        cmd::Cmd::Tool(cmd::ToolCmd {
            tool: tool::Tool::ShellExecWithFile(shell_cmd, ext),
            ..
        }) => tool::Tool::ShellExecWithFile(
            feature::haivar::replace_haivars(&shell_cmd, haivars),
            ext,
        ),
        cmd::Cmd::Tool(cmd::ToolCmd {
            tool: tool::Tool::ShellExecWithStdin(shell_cmd),
            ..
        }) => tool::Tool::ShellExecWithStdin(feature::haivar::replace_haivars(&shell_cmd, haivars)),
        _ => return cmd,
    };
    if let cmd::Cmd::Tool(cmd::ToolCmd {
        tool: tool::Tool::ShellExecWithFile(_, _) | tool::Tool::ShellExecWithStdin(_),
        prompt,
        user_confirmation,
        force_tool,
        cache,
    }) = cmd
    {
        cmd::Cmd::Tool(cmd::ToolCmd {
            tool,
            // Replace vars in the recorded input because the unexpanded
            // vars are sometimes too opaque for the AI to understand.
            prompt: feature::haivar::replace_haivars(&prompt, haivars),
            user_confirmation,
            force_tool,
            cache,
        })
    } else {
        cmd
    }
}

// --

pub async fn prompt_ai(
    msg_history: &[chat::Message],
    tool_policy: &Option<tool::ToolPolicy>,
    masked_strings: &Vec<String>,
    session: &mut SessionState,
    cfg: &config::Config,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    debug: bool,
) -> Vec<ChatCompletionResponse> {
    let api_base_url = get_api_base_url();
    let mut used_hai_router = false;
    let ai_provider_response = match session.ai {
        config::AiModel::OpenAi(_)
        | config::AiModel::Google(_)
        | config::AiModel::DeepSeek(_)
        | config::AiModel::Xai(_)
        | config::AiModel::LlamaCpp(_) => {
            let openai_reasoning_effort = match &session.ai {
                config::AiModel::OpenAi(
                    config::OpenAiModel::Gpt5(opts)
                    | config::OpenAiModel::Gpt5Mini(opts)
                    | config::OpenAiModel::Gpt5Nano(opts),
                ) => &opts.reasoning_effort,
                config::AiModel::Google(
                    config::GoogleModel::Gemini3Flash(opts) | config::GoogleModel::Gemini3Pro(opts),
                ) => &opts.thinking_level,
                _ => &None,
            };
            let openai_verbosity = match &session.ai {
                config::AiModel::OpenAi(
                    config::OpenAiModel::Gpt5(opts)
                    | config::OpenAiModel::Gpt5Mini(opts)
                    | config::OpenAiModel::Gpt5Nano(opts),
                ) => &opts.verbosity,
                _ => &None,
            };
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
                        config::AiModel::Xai(_) => "xai".to_string(),
                        _ => {
                            eprintln!("error: unexpected provider");
                            return vec![];
                        }
                    };
                    used_hai_router = true;
                    (Some(api_base_url.deref()), api_key, Some(provider_header))
                } else {
                    match session.ai {
                        config::AiModel::OpenAi(_) => {
                            (None, config::get_openai_api_key(cfg).unwrap(), None)
                        }
                        config::AiModel::Google(_) => (
                            Some("https://generativelanguage.googleapis.com/v1beta/openai"),
                            config::get_google_api_key(cfg).unwrap(),
                            None,
                        ),
                        config::AiModel::DeepSeek(_) => (
                            Some("https://api.deepseek.com/v1"),
                            config::get_deepseek_api_key(cfg).unwrap(),
                            None,
                        ),
                        config::AiModel::Xai(_) => (
                            Some("https://api.x.ai/v1"),
                            config::get_xai_api_key(cfg).unwrap(),
                            None,
                        ),
                        config::AiModel::LlamaCpp(_) => (
                            cfg.llama_cpp
                                .as_ref()
                                .and_then(|llama_cpp| llama_cpp.base_url.as_deref())
                                .or(Some("http://127.0.0.1:8080")),
                            "null".to_string(), // No API key needed for llama.cpp
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
                &session.shell,
                Some(ctrlc_handler),
                masked_strings,
                debug,
                openai_reasoning_effort,
                openai_verbosity,
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
                    (None, config::get_anthropic_api_key(cfg).unwrap(), None)
                };
            let use_thinking = match anthropic_model {
                config::AnthropicModel::Opus4(use_thinking)
                | config::AnthropicModel::Opus41(use_thinking)
                | config::AnthropicModel::Opus45(use_thinking)
                | config::AnthropicModel::Sonnet37(use_thinking)
                | config::AnthropicModel::Sonnet4(use_thinking)
                | config::AnthropicModel::Sonnet45(use_thinking) => *use_thinking,
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
                &session.shell,
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
                &session.shell,
                Some(ctrlc_handler),
                masked_strings,
                debug,
            )
            .await
        }
        config::AiModel::Void(_) => {
            void::send_to_void(
                config::get_ai_model_provider_name(&session.ai),
                masked_strings,
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
