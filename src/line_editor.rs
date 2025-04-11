use chrono::{DateTime, Local};
use crossterm::event::{KeyCode, KeyModifiers};
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::terminal::supports_keyboard_enhancement;
use reedline::{
    self, default_vi_insert_keybindings, default_vi_normal_keybindings, ColumnarMenu, Completer,
    EditCommand, FileBackedHistory, MenuBuilder, Prompt, PromptEditMode, PromptHistorySearch,
    PromptHistorySearchStatus, PromptViMode, Reedline, ReedlineEvent, ReedlineMenu, Span,
    Suggestion, Vi,
};
use std::borrow::Cow;
use std::cmp;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::api::client::HaiClient;
use crate::{config, HaiRouterState};

pub struct LineEditor {
    pub reedline: Reedline,
}

impl Drop for LineEditor {
    fn drop(&mut self) {
        if let Ok(true) = supports_keyboard_enhancement() {
            // This will run when LineEditor goes out of scope, even if panic.
            crossterm::execute!(std::io::stdout(), PopKeyboardEnhancementFlags)
                .expect("Failed to pop key enhancement flags");
        }
    }
}

impl LineEditor {
    pub fn new(incognito: bool) -> LineEditor {
        let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));

        let mut insert_keybindings = default_vi_insert_keybindings();
        insert_keybindings.add_binding(
            KeyModifiers::ALT,
            KeyCode::Backspace,
            ReedlineEvent::Edit(vec![EditCommand::BackspaceWord]),
        );
        // Works for Konsole on Kubuntu Linux
        insert_keybindings.add_binding(
            KeyModifiers::ALT,
            KeyCode::Enter,
            ReedlineEvent::Edit(vec![EditCommand::InsertString("\n".to_string())]),
        );
        // Works for iTerm2 on Mac (fails on Terminal.app)
        // https://github.com/crossterm-rs/crossterm/issues/861
        insert_keybindings.add_binding(
            KeyModifiers::SHIFT,
            KeyCode::Enter,
            ReedlineEvent::Edit(vec![EditCommand::InsertString("\n".to_string())]),
        );
        insert_keybindings.add_binding(
            KeyModifiers::NONE,
            KeyCode::Tab,
            ReedlineEvent::UntilFound(vec![
                ReedlineEvent::Menu("completion_menu".to_string()),
                ReedlineEvent::MenuNext,
            ]),
        );
        insert_keybindings.add_binding(
            KeyModifiers::SHIFT,
            KeyCode::BackTab,
            ReedlineEvent::UntilFound(vec![
                ReedlineEvent::Menu("completion_menu".to_string()),
                ReedlineEvent::MenuPrevious,
            ]),
        );

        let mut reedline = Reedline::create().use_bracketed_paste(true);
        if !incognito {
            let history = Box::new(
                FileBackedHistory::with_file(100, config::get_history_path())
                    .expect("error: could not open history file"),
            );
            reedline = reedline.with_history(history);
        }
        reedline = reedline
            .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
            .with_edit_mode(Box::new(Vi::new(
                insert_keybindings,
                default_vi_normal_keybindings(),
            )))
            .with_quick_completions(true)
            .with_partial_completions(true)
            .with_ansi_colors(true);

        LineEditor { reedline }
    }

    pub fn pre_readline(&self) {
        if let Ok(true) = supports_keyboard_enhancement() {
            crossterm::execute!(
                std::io::stdout(),
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )
            .expect("Failed to push key enhancement flags");
        }
    }

    /// Deactivating keyboard enhancement flags when not reading from the
    /// prompt is important b/c it interferes with ctrl+c.
    pub fn post_readline(&self) {
        // For konsole which doesn't support kb enhancements, popping keyboard
        // enhancements prints an unwanted "1u" to the screen.
        if let Ok(true) = supports_keyboard_enhancement() {
            crossterm::execute!(std::io::stdout(), PopKeyboardEnhancementFlags)
                .expect("Failed to pop key enhancement flags");
        }
    }

    pub fn set_line_completer(
        &mut self,
        debug: bool,
        autocomplete_repl_cmds: Vec<String>,
        autocomplete_repl_ai_models: Vec<String>,
        api_client: HaiClient,
    ) {
        use std::mem;
        let temp = Reedline::create();
        self.reedline =
            mem::replace(&mut self.reedline, temp).with_completer(Box::new(CmdAndFileCompleter {
                debug,
                autocomplete_repl_cmds,
                autocomplete_repl_ai_models,
                api_client,
            }));
    }
}

// ---

pub struct EditorPrompt {
    pub index: u32,
    pub ai_model_name: String,
    pub input_tokens: u32,
    pub task_mode: Option<String>,
    pub incognito: bool,
    pub tool_mode: Option<String>,
    pub hai_router: HaiRouterState,
    pub is_dev: bool,
    pub username: Option<String>,
}

impl EditorPrompt {
    pub fn new() -> EditorPrompt {
        EditorPrompt {
            index: 0,
            ai_model_name: "unk".to_string(),
            input_tokens: 0,
            task_mode: None,
            incognito: false,
            tool_mode: None,
            hai_router: HaiRouterState::Off,
            is_dev: false,
            username: None,
        }
    }

    pub fn set_index(&mut self, new_index: u32) {
        self.index = new_index;
    }

    pub fn set_ai_model_name(&mut self, ai_model_name: String) {
        self.ai_model_name = ai_model_name;
    }

    pub fn set_input_tokens(&mut self, input_tokens: u32) {
        self.input_tokens = input_tokens;
    }

    pub fn set_task_mode(&mut self, task_mode: Option<String>) {
        self.task_mode = task_mode;
    }

    pub fn set_incognito(&mut self, incognito: bool) {
        self.incognito = incognito;
    }

    pub fn set_tool_mode(&mut self, tool_mode: Option<String>) {
        self.tool_mode = tool_mode;
    }

    pub fn set_hai_router(&mut self, hai_router: HaiRouterState) {
        self.hai_router = hai_router;
    }

    pub fn set_is_dev(&mut self, is_dev: bool) {
        self.is_dev = is_dev;
    }

    pub fn set_username(&mut self, username: Option<String>) {
        self.username = username;
    }
}

impl Prompt for EditorPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        let incognito_emoji = if self.incognito { "😎" } else { "" };
        let is_dev_emoji = if self.is_dev { "🔧" } else { "" };
        let task_name = self.task_mode.clone().unwrap_or("".into());
        let tool_mode = self
            .tool_mode
            .clone()
            .map(|v| format!(" {}", v))
            .unwrap_or("".into());
        Cow::Owned(format!(
            "{}{}{}[{}]{}",
            is_dev_emoji, incognito_emoji, task_name, self.index, tool_mode
        ))
    }

    fn render_prompt_right(&self) -> Cow<str> {
        let username_str = self
            .username
            .as_ref()
            .map(|username| format!("{}:", username))
            .unwrap_or("".to_string());
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%m/%d/%y %I:%M:%S %p").to_string();
        let hai_router_icon = match self.hai_router {
            HaiRouterState::Off => "",
            HaiRouterState::OffForModel => "🟡",
            HaiRouterState::On => "🌐",
        };
        Cow::Owned(format!(
            "{}{} {}-toks {}{} {}",
            username_str,
            abbreviate_cwd(),
            format_tok_count(self.input_tokens),
            hai_router_icon,
            self.ai_model_name,
            formatted_time
        ))
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<str> {
        match _edit_mode {
            PromptEditMode::Custom(_)
            | PromptEditMode::Default
            | PromptEditMode::Vi(PromptViMode::Insert) => Cow::Borrowed(": "),
            PromptEditMode::Vi(PromptViMode::Normal) => Cow::Borrowed("〉"),
            _ => Cow::Borrowed("> "),
        }
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

// --

pub struct QuestionPrompt {
    pub question: String,
}

impl QuestionPrompt {
    pub fn new(q: &str) -> QuestionPrompt {
        QuestionPrompt {
            question: q.to_string(),
        }
    }
}

impl Prompt for QuestionPrompt {
    fn render_prompt_left(&self) -> Cow<str> {
        Cow::Owned(format!("[QUESTION] {}", self.question))
    }

    fn render_prompt_right(&self) -> Cow<str> {
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%m/%d/%y %I:%M:%S %p").to_string();
        Cow::Owned(format!("{} {}", abbreviate_cwd(), formatted_time))
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<str> {
        match _edit_mode {
            PromptEditMode::Custom(_)
            | PromptEditMode::Default
            | PromptEditMode::Vi(PromptViMode::Insert) => Cow::Borrowed(" "),
            PromptEditMode::Vi(PromptViMode::Normal) => Cow::Borrowed("〉"),
            _ => Cow::Borrowed("> "),
        }
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

// --

fn abbreviate_cwd() -> String {
    // Get the current working directory
    let cwd = env::current_dir().expect("Failed to get current directory");
    abbreviate_path(cwd)
}

fn abbreviate_path(path: PathBuf) -> String {
    // Get the user's home directory (fall back to returning the full path if unavailable)
    if let Some(home_dir) = dirs::home_dir() {
        if let Ok(stripped) = path.strip_prefix(&home_dir) {
            // If the cwd starts with the home directory, replace the prefix with '~'
            return format!("~/{}", stripped.display());
        }
    }

    // If no abbreviation is possible, return the full path as-is
    path.display().to_string()
}

/// The token count format prints a bare number from 0-999 and then switches
/// to Xk for all other counts (e.g. 1k, 2k, 4000k).
fn format_tok_count(number: u32) -> String {
    match number {
        0..=999 => number.to_string(),
        _ => format!("{}k", number / 1_000),
    }
}

// --

struct CmdAndFileCompleter {
    debug: bool,
    autocomplete_repl_cmds: Vec<String>,
    autocomplete_repl_ai_models: Vec<String>,
    api_client: HaiClient,
}

fn is_task_file_path_arg(line: &str, task_cmd: &str) -> bool {
    let patterns = [" .", " /", " ~"];
    patterns
        .iter()
        .any(|pattern| line.starts_with(&(task_cmd.to_string() + pattern)))
}

impl Completer for CmdAndFileCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        if self.debug {
            let _ = config::write_to_debug_log(format!("completer init: {} pos={}\n", line, pos,));
        }
        if line.starts_with('/') || line.starts_with("!!") {
            if line.starts_with("/load ")
                || line.starts_with("/l ")
                || line.starts_with("/cd ")
                || line.starts_with("/task-publish ")
                || is_task_file_path_arg(line, "/task")
                || is_task_file_path_arg(line, "/task-include")
                || is_task_file_path_arg(line, "/task-forget")
                || is_task_file_path_arg(line, "/task-view")
            {
                let (cmd_word, arg1_prefix) = line
                    .split_once(char::is_whitespace)
                    .map(|(cmd, args)| (cmd, args.trim_start()))
                    .unwrap_or((line, ""));
                let cmd_length = cmd_word.len();
                let arg1_index = line[cmd_length..]
                    .find(arg1_prefix)
                    .map(|i| i + cmd_length)
                    .unwrap_or(0);
                let mut completions = self.file_completer2(arg1_prefix, cmd_word == "/cd");
                realign_suggestions(&mut completions, arg1_index, self.debug);
                completions
            } else if line.starts_with("/task ")
                || line.starts_with("/task-purge ")
                || line.starts_with("/task-forget ")
                || line.starts_with("/task-fetch ")
                || line.starts_with("/task-update ")
            {
                // This autocompletes to tasks that are fetched/cached on disk.
                // We hide the toml extension to make the autocomplete not
                // appear as if it's traversing a file tree.
                let (cmd_word, arg_prefix) = line
                    .split_once(" ")
                    .expect("unexpected missing space-delimiter");
                let mut task_cache_prefix = config::get_config_folder_path();
                task_cache_prefix.push("cache/task");
                let task_cache_prefix_offset =
                    task_cache_prefix.to_string_lossy().to_string().len() + 1;
                task_cache_prefix.push(arg_prefix);
                let cmd_length = cmd_word.len();
                let offset = cmp::max(0, pos - cmd_length + task_cache_prefix_offset);

                let mut completions = self.file_completer(
                    task_cache_prefix.to_string_lossy().as_ref(),
                    offset,
                    false,
                );
                completions.retain(|suggestion| {
                    suggestion.value.ends_with("/") || suggestion.value.ends_with(".toml")
                });
                for suggestion in &mut completions {
                    suggestion.value = suggestion.value[task_cache_prefix_offset..].to_string();
                    if suggestion.value.ends_with(".toml") {
                        suggestion.value =
                            suggestion.value[..suggestion.value.len() - ".toml".len()].to_string();
                    }
                    suggestion.span.start += cmd_length;
                    suggestion.span.end += cmd_length;
                    suggestion.span.end -= task_cache_prefix_offset;
                    if self.debug {
                        let _ = config::write_to_debug_log(format!(
                            "suggestion: value={} (span-start={}) (span-end={:?})\n",
                            suggestion.value, suggestion.span.start, suggestion.span.end
                        ));
                    }
                }
                completions
            } else if line.starts_with("/ai ") {
                let (cmd_word, arg_prefix) = line
                    .split_once(char::is_whitespace)
                    .map(|(cmd, args)| (cmd, args.trim_start()))
                    .unwrap_or((line, ""));
                let cmd_length = cmd_word.len();
                let arg_index = line[cmd_length..]
                    .find(arg_prefix)
                    .map(|i| i + cmd_length)
                    .unwrap_or(0);

                let mut completions = self.ai_model_completer(arg_prefix);
                realign_suggestions(&mut completions, arg_index, self.debug);
                completions
            } else if line.starts_with("/asset ")
                || line.starts_with("/a ")
                || line.starts_with("/asset-edit ")
                || line.starts_with("/asset-load ")
                || line.starts_with("/asset-view ")
                || line.starts_with("/asset-temp ")
                || line.starts_with("/asset-push ")
                || line.starts_with("/asset-link ")
                || line.starts_with("/asset-revisions ")
                || line.starts_with("/asset-remove ")
                || line.starts_with("/asset-list ")
                || line.starts_with("/ls ")
                || line.starts_with("/asset-md-get ")
            {
                let (cmd_word, arg_prefix) = line
                    .split_once(char::is_whitespace)
                    .map(|(cmd, args)| (cmd, args.trim_start()))
                    .unwrap_or((line, ""));
                let cmd_length = cmd_word.len();
                let arg_index = line[cmd_length..]
                    .find(arg_prefix)
                    .map(|i| i + cmd_length)
                    .unwrap_or(0);
                if self.debug {
                    let _ = config::write_to_debug_log(format!(
                        "completer init: {} pos={} cmd_length={} cmd_word={:?} arg_index={:?} arg_prefix={:?} {:?}\n",
                        line, pos, cmd_length, cmd_word, arg_index, arg_prefix, line.find(arg_prefix).unwrap()
                    ));
                }
                let mut completions = self.asset_completer(arg_prefix);
                realign_suggestions(&mut completions, arg_index, self.debug);
                completions
            } else if line.starts_with("/exec ") || line.starts_with("!!") {
                // For /exec command, complete asset references
                let substring_before_cursor = &line[..pos];

                // Find/extract current token
                let last_whitespace_pos = substring_before_cursor
                    .rfind(char::is_whitespace)
                    .unwrap_or(0);
                let current_token = &substring_before_cursor[last_whitespace_pos..].trim_start();

                if self.debug {
                    let _ = config::write_to_debug_log(format!(
                        "exec completer: line={} pos={} last_whitespace={} current_token={:?}\n",
                        line, pos, last_whitespace_pos, current_token
                    ));
                }

                // If the token starts with '@', it's an asset lookup
                if let Some(asset_prefix) = current_token.strip_prefix('@') {
                    let mut completions = self.asset_completer(asset_prefix);
                    realign_suggestions(&mut completions, last_whitespace_pos + 2, self.debug);
                    completions
                } else {
                    // No completions yet for non-assets (e.g. local file paths)
                    vec![]
                }
            } else if line.starts_with("/asset-export ") || line.starts_with("/asset-import ") {
                let (cmd_word, arg1_prefix) = line
                    .split_once(char::is_whitespace)
                    .map(|(cmd, args)| (cmd, args.trim_start()))
                    .unwrap_or((line, ""));
                let cmd_length = cmd_word.len();
                let arg1_index = line[cmd_length..]
                    .find(arg1_prefix)
                    .map(|i| i + cmd_length)
                    .unwrap_or(0);
                let (arg1_prefix, arg2_prefix) = arg1_prefix
                    .split_once(char::is_whitespace)
                    .map(|(arg1, arg2)| (arg1, Some(arg2.trim_start())))
                    .unwrap_or((arg1_prefix, None));
                let arg2_index = if let Some(arg2_prefix) = arg2_prefix {
                    line[cmd_length + arg1_prefix.len()..]
                        .find(arg2_prefix)
                        .map(|i| i + cmd_length + arg1_prefix.len())
                } else {
                    None
                };
                if self.debug {
                    let _ = config::write_to_debug_log(format!(
                        "completer init: {} pos={} cmd_length={} cmd_word={:?} arg1_index={:?} arg1_prefix={:?} arg2_index={:?} arg2_prefix={:?}\n",
                        line, pos, cmd_length, cmd_word, arg1_index, arg1_prefix, arg2_index, arg2_prefix,
                    ));
                }
                if let Some(arg2_prefix) = arg2_prefix {
                    let mut completions = self.file_completer2(arg2_prefix, false);
                    realign_suggestions(&mut completions, arg2_index.unwrap(), self.debug);
                    completions
                } else {
                    let mut completions = self.asset_completer(arg1_prefix);
                    realign_suggestions(&mut completions, arg1_index, self.debug);
                    completions
                }
            } else {
                self.command_completer(line)
            }
        } else if line.starts_with('!') {
            self.tool_completer(line)
        } else {
            vec![]
        }
    }
}

fn realign_suggestions(suggestions: &mut Vec<Suggestion>, offset: usize, debug: bool) {
    for suggestion in suggestions {
        suggestion.span.start += offset;
        suggestion.span.end += offset;
        if debug {
            let _ = config::write_to_debug_log(format!(
                "suggestion: value={} (span-start={}) (span-end={:?})\n",
                suggestion.value, suggestion.span.start, suggestion.span.end
            ));
        }
    }
}

impl CmdAndFileCompleter {
    fn command_completer(&self, cmd_prefix: &str) -> Vec<Suggestion> {
        let mut completions = Vec::new();

        for cmd in &self.autocomplete_repl_cmds {
            if cmd.starts_with(cmd_prefix) {
                completions.push(Suggestion {
                    value: cmd.clone(),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: 0,
                        end: cmd_prefix.len(),
                    },
                    append_whitespace: true,
                });
            }
        }

        completions
    }

    fn tool_completer(&self, tool_cmd_prefix: &str) -> Vec<Suggestion> {
        let commands: Vec<String> = [
            "!!",
            "!py",
            "!?py",
            "!sh",
            "!?sh",
            "!shscript",
            "!?shscript",
            "!clip",
            "!exit",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let mut completions = Vec::new();

        for cmd in &commands {
            if cmd.starts_with(tool_cmd_prefix) {
                completions.push(Suggestion {
                    value: cmd.clone(),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: 0,
                        end: tool_cmd_prefix.len(),
                    },
                    append_whitespace: true,
                });
            }
        }

        completions
    }

    fn ai_model_completer(&self, ai_model_prefix: &str) -> Vec<Suggestion> {
        let mut completions = Vec::new();

        for ai_model in &self.autocomplete_repl_ai_models {
            if ai_model.starts_with(ai_model_prefix) {
                completions.push(Suggestion {
                    value: ai_model.clone(),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: 0,
                        end: ai_model_prefix.len(),
                    },
                    append_whitespace: true,
                });
            }
        }

        completions
    }

    /// Assumes `line` is a partial path
    fn file_completer(&self, line: &str, _pos: usize, dir_only: bool) -> Vec<Suggestion> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let expanded_path_line = shellexpand::full(line).unwrap().into_owned();
        let shellexpand_applied = line != expanded_path_line;
        let partial_path = Path::new(&expanded_path_line);

        // If set, it means the cursor is at the root of a directory and the
        // entire directory's contents are valid suggestions.
        let scan_full_dir = partial_path.is_dir();

        let dir_to_search = if scan_full_dir {
            if partial_path.is_absolute() {
                partial_path.to_owned()
            } else {
                current_dir.join(partial_path).to_owned()
            }
        } else if partial_path.is_absolute() {
            partial_path
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_owned()
        } else {
            current_dir
                .join(partial_path)
                .parent()
                .unwrap_or(current_dir.as_path())
                .to_owned()
        };

        if self.debug {
            let _ = config::write_to_debug_log(format!(
                "file_completer: {:?} {:?} {:?}\n",
                current_dir, dir_to_search, partial_path
            ));
        }

        // Collect matching files and directories
        let mut completions = Vec::new();
        if let Ok(entries) = fs::read_dir(dir_to_search) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                if scan_full_dir
                    || file_name_str.starts_with(
                        partial_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .as_ref(),
                    )
                {
                    // Get the full path suggestion as a string
                    let full_path = if partial_path.is_absolute() {
                        entry.path()
                    } else if scan_full_dir {
                        Path::new(line).join(file_name_str.to_string())
                    } else {
                        Path::new(line)
                            .parent()
                            .unwrap_or(Path::new(""))
                            .join(file_name_str.to_string())
                    };

                    let is_dir = full_path.is_dir();
                    if dir_only && !is_dir {
                        continue;
                    }
                    let abbreviated_path = if shellexpand_applied {
                        abbreviate_path(full_path)
                    } else {
                        full_path.to_string_lossy().to_string()
                    };

                    let display_value = abbreviated_path + if is_dir { "/" } else { "" };

                    completions.push(Suggestion {
                        value: display_value.clone(),
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: _pos - line.len(),
                            end: _pos,
                        },
                        append_whitespace: !is_dir,
                    });
                }
            }
        }
        // Since read_dir() doesn't sort, sort it.
        //
        // "/" is removed because it's ordered after the alphabet so that if a
        // folder's name is a subset of another folder's it won't be sorted
        // correctly: src/test2/ before src/test/
        completions.sort_by(|a, b| {
            a.value
                .trim_end_matches('/')
                .cmp(b.value.trim_end_matches('/'))
        });
        completions
    }

    /// Assumes `line` is a partial path
    fn file_completer2(&self, path_prefix: &str, dir_only: bool) -> Vec<Suggestion> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let expanded_path_line = shellexpand::full(path_prefix).unwrap().into_owned();
        let shellexpand_applied = path_prefix != expanded_path_line;
        let partial_path = Path::new(&expanded_path_line);

        // If set, it means the cursor is at the root of a directory and the
        // entire directory's contents are valid suggestions.
        let scan_full_dir = partial_path.is_dir();

        let dir_to_search = if scan_full_dir {
            if partial_path.is_absolute() {
                partial_path.to_owned()
            } else {
                current_dir.join(partial_path).to_owned()
            }
        } else if partial_path.is_absolute() {
            partial_path
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_owned()
        } else {
            current_dir
                .join(partial_path)
                .parent()
                .unwrap_or(current_dir.as_path())
                .to_owned()
        };

        if self.debug {
            let _ = config::write_to_debug_log(format!(
                "file_completer: {:?} {:?} {:?}\n",
                current_dir, dir_to_search, partial_path
            ));
        }

        // Collect matching files and directories
        let mut completions = Vec::new();
        if let Ok(entries) = fs::read_dir(dir_to_search) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                if scan_full_dir
                    || file_name_str.starts_with(
                        partial_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .as_ref(),
                    )
                {
                    // Get the full path suggestion as a string
                    let full_path = if partial_path.is_absolute() {
                        entry.path()
                    } else if scan_full_dir {
                        Path::new(path_prefix).join(file_name_str.to_string())
                    } else {
                        Path::new(path_prefix)
                            .parent()
                            .unwrap_or(Path::new(""))
                            .join(file_name_str.to_string())
                    };

                    let is_dir = full_path.is_dir();
                    if dir_only && !is_dir {
                        continue;
                    }
                    let abbreviated_path = if shellexpand_applied {
                        abbreviate_path(full_path)
                    } else {
                        full_path.to_string_lossy().to_string()
                    };

                    let display_value = abbreviated_path + if is_dir { "/" } else { "" };

                    completions.push(Suggestion {
                        value: display_value.clone(),
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: 0,
                            end: path_prefix.len(),
                        },
                        append_whitespace: !is_dir,
                    });
                }
            }
        }
        // Since read_dir() doesn't sort, sort it.
        //
        // "/" is removed because it's ordered after the alphabet so that if a
        // folder's name is a subset of another folder's it won't be sorted
        // correctly: src/test2/ before src/test/
        completions.sort_by(|a, b| {
            a.value
                .trim_end_matches('/')
                .cmp(b.value.trim_end_matches('/'))
        });
        completions
    }

    fn asset_completer(&self, asset_prefix: &str) -> Vec<Suggestion> {
        use crate::api::types::asset::AssetEntryListArg;
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.api_client.asset_entry_list(
                AssetEntryListArg {
                    prefix: Some(asset_prefix.to_string()),
                },
            ))
        });
        match result {
            Ok(res) => {
                let mut completions = Vec::new();
                for entry in res.entries {
                    completions.push(Suggestion {
                        value: entry.name,
                        description: None,
                        style: None,
                        extra: None,
                        // Replace entirety of existing contents
                        span: Span {
                            start: 0,
                            end: asset_prefix.len(),
                        },
                        append_whitespace: true,
                    });
                }
                completions
            }
            Err(e) => {
                eprintln!("error: could not fetch list of matching assets: {}", e);
                vec![]
            }
        }
    }
}
