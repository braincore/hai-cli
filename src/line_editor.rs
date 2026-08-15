use chrono::{DateTime, Local};
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::terminal::supports_keyboard_enhancement;
use reedline::{
    self, ColumnarMenu, Completer, EditCommand, FileBackedHistory, KeyCode, KeyModifiers,
    MenuBuilder, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus,
    PromptViMode, Reedline, ReedlineEvent, ReedlineMenu, Span, Suggestion, Vi,
    default_vi_insert_keybindings, default_vi_normal_keybindings,
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

use crate::api::client::HaiClient;
use crate::cmd_registry;
use crate::db::Account;
use crate::{HaiRouterState, asset_helper, config};

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
    pub fn new(incognito: bool, break_signal: Arc<AtomicBool>) -> LineEditor {
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
            .with_break_signal(break_signal.clone())
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
        cmd_registry: cmd_registry::Registry,
        api_client: HaiClient,
        account: Option<Account>,
    ) {
        use std::mem;
        let temp = Reedline::create();
        self.reedline =
            mem::replace(&mut self.reedline, temp).with_completer(Box::new(CmdAndFileCompleter {
                cmd_registry,
                api_client,
                account,
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
    pub agentic: bool,
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
            agentic: false,
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

    pub fn set_agentic(&mut self, agentic: bool) {
        self.agentic = agentic;
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
    fn render_prompt_left(&self) -> Cow<'_, str> {
        let incognito_emoji = if self.incognito { "😎" } else { "" };
        let is_dev_emoji = if self.is_dev { "🔧" } else { "" };
        let agentic_emoji = if self.agentic { "🤖" } else { "" };
        let task_name = self.task_mode.clone().unwrap_or("".into());
        let tool_mode = self
            .tool_mode
            .clone()
            .map(|v| format!(" {}", v))
            .unwrap_or("".into());
        Cow::Owned(format!(
            "{}{}{}{}[{}]{}",
            is_dev_emoji, incognito_emoji, agentic_emoji, task_name, self.index, tool_mode
        ))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
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

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        match _edit_mode {
            PromptEditMode::Custom(_)
            | PromptEditMode::Default
            | PromptEditMode::Vi(PromptViMode::Insert) => Cow::Borrowed(": "),
            PromptEditMode::Vi(PromptViMode::Normal) => Cow::Borrowed("〉"),
            _ => Cow::Borrowed("> "),
        }
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
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
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned(format!("[QUESTION] {}", self.question))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        let now: DateTime<Local> = Local::now();
        let formatted_time = now.format("%m/%d/%y %I:%M:%S %p").to_string();
        Cow::Owned(format!("{} {}", abbreviate_cwd(), formatted_time))
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        match _edit_mode {
            PromptEditMode::Custom(_)
            | PromptEditMode::Default
            | PromptEditMode::Vi(PromptViMode::Insert) => Cow::Borrowed(" "),
            PromptEditMode::Vi(PromptViMode::Normal) => Cow::Borrowed("〉"),
            _ => Cow::Borrowed("> "),
        }
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("::: ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
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
    if let Some(home_dir) = dirs::home_dir()
        && let Ok(stripped) = path.strip_prefix(&home_dir)
    {
        // If the cwd starts with the home directory, replace the prefix with '~'
        return format!("~/{}", stripped.display());
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
    cmd_registry: cmd_registry::Registry,
    api_client: HaiClient,
    account: Option<Account>,
}

/// Finds all programs in the PATH that start with the given prefix.
///
/// Only the first occurrence of each program name is included, mimicking PATH
/// resolution order.
fn find_programs_with_prefix(prefix: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    if let Ok(path_var) = env::var("PATH") {
        for dir in env::split_paths(&path_var) {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str())
                        && file_name.starts_with(prefix)
                        && is_executable::is_executable(&path)
                        && seen.insert(file_name.to_string())
                    {
                        results.push(file_name.to_string());
                    }
                }
            }
        }
    }
    results.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    results
}

impl Completer for CmdAndFileCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        tracing::debug!(line, pos, "completer init");

        let comp_res = cmd_registry::complete(&self.cmd_registry, line, pos);
        match comp_res {
            cmd_registry::Completion::Command { prefix, candidates } => {
                for candidate in &candidates {
                    tracing::debug!(?candidate.name, prefix, "registry completion: cmd: candidate");
                }
                candidates
                    .iter()
                    .map(|cand| Suggestion {
                        value: cand.name.to_string(),
                        display_override: None,
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: pos - prefix.len(),
                            end: pos,
                        },
                        append_whitespace: true,
                        match_indices: None,
                    })
                    .collect()
            }
            cmd_registry::Completion::OptName {
                cmd: _,
                prefix,
                candidates,
            } => {
                for candidate in &candidates {
                    tracing::debug!(?candidate.name, prefix, "registry completion: opt-name: candidate");
                }
                candidates
                    .iter()
                    .map(|cand| Suggestion {
                        value: cand.name.to_string(),
                        display_override: None,
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: pos - prefix.len(),
                            end: pos,
                        },
                        append_whitespace: prefix == *cand.name,
                        match_indices: None,
                    })
                    .collect()
            }
            cmd_registry::Completion::OptValue {
                cmd: _,
                opt: _,
                prefix,
                candidates,
            } => {
                for candidate in &candidates {
                    tracing::debug!(
                        ?candidate,
                        prefix,
                        "registry completion: opt-value: candidate"
                    );
                }
                candidates
                    .iter()
                    .map(|cand| Suggestion {
                        value: cand.to_string(),
                        display_override: None,
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: pos - prefix.len(),
                            end: pos,
                        },
                        append_whitespace: prefix == *cand,
                        match_indices: None,
                    })
                    .collect()
            }
            cmd_registry::Completion::Arg {
                cmd,
                index: _,
                kind,
                prefix,
            } => {
                tracing::debug!(?cmd.name, ?kind, prefix, "registry completion: arg");
                match kind {
                    cmd_registry::ArgKind::AssetName { glob_ok: _ } => {
                        let mut completions = self.asset_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::AssetPrefix => {
                        let mut completions = self.asset_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::AssetFolder => {
                        let mut completions = self.asset_folder_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::FilePath {
                        accepts,
                        glob_ok: _,
                    } => {
                        let mut completions = self.file_completer(
                            &prefix,
                            matches!(accepts, cmd_registry::FilePathAccepts::Dir),
                        );
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::TaskRef => {
                        let mut completions = self.task_ref_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::TaskFqn => {
                        if let Some((username, _task_name_prefix)) = prefix.split_once('/') {
                            let mut completions = self.task_fqn_completer(&prefix, username);
                            realign_suggestions(&mut completions, pos - prefix.len());
                            completions
                        } else {
                            // Without a username, let's not auto-complete to
                            // avoid mistakes choosing the wrong task (or a
                            // malicious user trying to create a similar
                            // task collection).
                            vec![]
                        }
                    }
                    cmd_registry::ArgKind::Username => {
                        let mut completions = self.username_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ArgKind::ModelName => {
                        let mut completions = self
                            .simple_completer(&prefix, config::AUTOCOMPLETE_AI_MODEL_SUGGESTIONS);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    _ => vec![],
                }
            }
            cmd_registry::Completion::Shell { word, prefix, .. } => {
                tracing::debug!(?word, prefix, "auto-complete: shellcmd:");
                match word {
                    cmd_registry::ShellWord::Program => {
                        let mut completions = self.simple_completer(
                            &prefix,
                            &find_programs_with_prefix(&prefix)
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        );
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ShellWord::Path => {
                        let mut completions = self.file_completer(&prefix, false);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                    cmd_registry::ShellWord::AssetName => {
                        let mut completions = self.asset_completer(&prefix);
                        realign_suggestions(&mut completions, pos - prefix.len());
                        completions
                    }
                }
            }
            _ => {
                tracing::debug!(?comp_res, "registry completion");
                vec![]
            }
        }
    }
}

/// Offsets the replacement span of completions/suggestions.
///
/// The use case is to align the span to the beginning of the REPL line since
/// it's typically computed relative to the beginning of the word being
/// completed.
fn realign_suggestions(suggestions: &mut Vec<Suggestion>, offset: usize) {
    for suggestion in suggestions {
        suggestion.span.start += offset;
        suggestion.span.end += offset;
        tracing::debug!(
            value=?suggestion.value,
            offset,
            span_start=suggestion.span.start,
            span_end=suggestion.span.end,
            "suggestion");
    }
}

fn compute_display_override_for_path(prefix: &str, option: &str) -> Option<String> {
    let strip_len = prefix.rfind('/').map(|i| i + 1).unwrap_or(0);

    if strip_len > 0 && option.len() > strip_len {
        Some(option[strip_len..].to_string())
    } else {
        None
    }
}

impl CmdAndFileCompleter {
    fn simple_completer(&self, prefix: &str, options: &[&str]) -> Vec<Suggestion> {
        let mut completions = Vec::new();
        for option in options {
            if option.starts_with(prefix) {
                completions.push(Suggestion {
                    value: option.to_string(),
                    display_override: compute_display_override_for_path(prefix, option),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: 0,
                        end: prefix.len(),
                    },
                    append_whitespace: true,
                    match_indices: None,
                });
            }
        }
        completions
    }

    /// Assumes `line` is a partial path
    fn file_completer(&self, path_prefix: &str, dir_only: bool) -> Vec<Suggestion> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let expanded_path_line = shellexpand::full(path_prefix).unwrap().into_owned();
        let shellexpand_applied = path_prefix != expanded_path_line;
        let partial_path = Path::new(&expanded_path_line);

        tracing::debug!(
            path_prefix,
            ?dir_only,
            ?current_dir,
            ?expanded_path_line,
            ?shellexpand_applied,
            ?partial_path,
            "file_completer start"
        );

        // If set, it means the cursor is at the root of a directory and the
        // entire directory's contents are valid suggestions. An empty
        // `path_prefix` is special-cased to scan the current directory.
        let scan_full_dir = path_prefix.is_empty() || partial_path.is_dir();

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

        tracing::debug!(?dir_to_search, ?scan_full_dir, "file_completer");

        let dir_to_search_string = dir_to_search.clone().to_string_lossy().into_owned();

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
                        display_override: compute_display_override_for_path(
                            &dir_to_search_string,
                            &display_value,
                        ),
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: 0,
                            end: path_prefix.len(),
                        },
                        append_whitespace: !is_dir,
                        match_indices: None,
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

    /// # Arguments
    /// * `asset_prefix` - The prefix of the asset to complete.
    fn asset_completer(&self, asset_prefix: &str) -> Vec<Suggestion> {
        let expanded_asset_prefix = asset_helper::expand_asset_name(asset_prefix, &self.account);
        let resolved_asset_prefix = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(asset_helper::resolve_attachment_asset_name(
                    &expanded_asset_prefix,
                    &self.api_client,
                ))
                .unwrap_or(expanded_asset_prefix.clone())
        });
        if asset_prefix.starts_with("/s/") && asset_prefix.matches('/').count() == 2 {
            // If prefix is querying /s/, auto-complete asset pools.
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.api_client.asset_pool_list(()))
            });
            match result {
                Ok(res) => {
                    let mut sorted_pools = res.pools;
                    sorted_pools.sort_by(|a, b| numeric_sort::cmp(&a.mount_point, &b.mount_point));
                    let mut completions = Vec::new();
                    for pool in sorted_pools {
                        if pool.mount_point.starts_with(&resolved_asset_prefix) {
                            completions.push(Suggestion {
                                value: pool.mount_point.clone(),
                                display_override: compute_display_override_for_path(
                                    &resolved_asset_prefix,
                                    &pool.mount_point,
                                ),
                                description: None,
                                style: None,
                                extra: None,
                                // Replace entirety of existing contents
                                span: Span {
                                    start: 0,
                                    end: asset_prefix.len(),
                                },
                                append_whitespace: false,
                                match_indices: None,
                            });
                        }
                    }
                    return completions;
                }
                Err(_) => {
                    tracing::debug!("error: failed to list asset pools");
                    return vec![];
                }
            }
        }
        use crate::api::types::asset::{AssetEntryListArg, EntryListOrder};
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.api_client.asset_entry_list(
                AssetEntryListArg {
                    prefix: Some(resolved_asset_prefix.clone()),
                    limit: 100,
                    order: EntryListOrder::Asc,
                },
            ))
        });
        match result {
            Ok(res) => {
                let mut completions = Vec::new();
                let only_one_entry = res.entries.len() == 1;
                let mut sorted_entries = res.entries;
                sorted_entries.sort_by(|a, b| numeric_sort::cmp(&a.name, &b.name));
                for entry in sorted_entries {
                    let mut entry_name = entry.name.clone();
                    // Check if attachment resolution changed the prefix. If
                    // so, convert it back to the user input format.
                    if resolved_asset_prefix != expanded_asset_prefix {
                        // Replace including trailing / since the CLI format replaces it with :
                        // Example:
                        // expanded_asset_prefix: `doc.md:`
                        // resolved_asset_prefix: `:xyz`
                        // matches: `:xyz/doc.md` -> `doc.md:graph.txt`
                        entry_name = entry_name
                            .replace(
                                &format!("{}/", resolved_asset_prefix),
                                &expanded_asset_prefix,
                            )
                            .replace(&resolved_asset_prefix, &expanded_asset_prefix);
                    }
                    let value = if only_one_entry
                        && matches!(
                            entry.asset.kind,
                            crate::api::types::asset::AssetKind::Folder
                        ) {
                        format!("{}/", entry_name)
                    } else {
                        entry_name.clone()
                    };
                    completions.push(Suggestion {
                        value,
                        display_override: compute_display_override_for_path(
                            &resolved_asset_prefix,
                            &entry_name,
                        ),
                        description: None,
                        style: None,
                        extra: None,
                        // Replace entirety of existing contents
                        span: Span {
                            start: 0,
                            end: asset_prefix.len(),
                        },
                        // If it matches a folder, don't append a whitespace
                        // because it's likely the user wants to traverse into
                        // that folder.
                        append_whitespace: !matches!(
                            entry.asset.kind,
                            crate::api::types::asset::AssetKind::Folder
                        ),
                        match_indices: None,
                    });
                }
                completions
            }
            Err(e) => {
                tracing::debug!(?e, "error: could not fetch list of matching assets");
                vec![]
            }
        }
    }

    /// Provides completion for both explicit and implicit folders.
    ///
    /// Explicit folders are entries with kind=Folder. Implicit folders are
    /// "path components" of blob entries that don't have a corresponding
    /// folder entry. For example, if "a/b/c" is a blob entry, then "a" and
    /// "a/b" are implicit folders.
    fn asset_folder_completer(&self, asset_prefix: &str) -> Vec<Suggestion> {
        let expanded_asset_prefix = asset_helper::expand_asset_name(asset_prefix, &self.account);

        // Pool completion: same behavior as asset_completer — you can't make a
        // folder at the pool-mount level via path components, so just defer to
        // pool listing here.
        if asset_prefix.starts_with("/s/") && asset_prefix.matches('/').count() == 2 {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.api_client.asset_pool_list(()))
            });
            match result {
                Ok(res) => {
                    let mut sorted_pools = res.pools;
                    sorted_pools.sort_by(|a, b| numeric_sort::cmp(&a.mount_point, &b.mount_point));
                    let mut completions = Vec::new();
                    for pool in sorted_pools {
                        if pool.mount_point.starts_with(&expanded_asset_prefix) {
                            completions.push(Suggestion {
                                value: pool.mount_point.clone(),
                                display_override: compute_display_override_for_path(
                                    &expanded_asset_prefix,
                                    &pool.mount_point,
                                ),
                                description: None,
                                style: None,
                                extra: None,
                                span: Span {
                                    start: 0,
                                    end: asset_prefix.len(),
                                },
                                append_whitespace: false,
                                match_indices: None,
                            });
                        }
                    }
                    return completions;
                }
                Err(_) => {
                    tracing::debug!("error: failed to list asset pools");
                    return vec![];
                }
            }
        }

        use crate::api::types::asset::{AssetEntryListArg, EntryListOrder};
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.api_client.asset_entry_list(
                AssetEntryListArg {
                    prefix: Some(expanded_asset_prefix.clone()),
                    limit: 100,
                    order: EntryListOrder::Asc,
                },
            ))
        });

        match result {
            Ok(res) => {
                // Collect candidate "path component" prefixes across all entries,
                // deduplicating. For a blob "a/b/c/d" we want "a", "a/b", "a/b/c"
                // but NOT "a/b/c/d" (can't make a folder on top of a blob).
                //
                // For a real folder entry "a/b/c" we can include the full name
                // "a/b/c" since it's already a folder-ish thing (a valid path
                // component to nest under), as well as its ancestors.
                let mut seen = std::collections::HashSet::new();
                let mut candidates: Vec<String> = Vec::new();

                for entry in &res.entries {
                    let name = &entry.name;

                    // Split into components, ignoring any trailing slash.
                    let trimmed = name.trim_end_matches('/');
                    let components: Vec<&str> = trimmed.split('/').collect();
                    if components.is_empty() {
                        continue;
                    }

                    // If this entry is a blob, the final component is a real blob
                    // name and is NOT a valid folder target. If it's a folder,
                    // the final component IS a valid target.
                    use crate::api::types::asset::AssetKind;
                    let include_last = matches!(entry.asset.kind, AssetKind::Folder);

                    let last_idx = components.len() - 1;
                    let mut accum = String::new();
                    for (i, comp) in components.iter().enumerate() {
                        if i > 0 {
                            accum.push('/');
                        }
                        accum.push_str(comp);

                        // Skip the final component for blobs.
                        if i == last_idx && !include_last {
                            continue;
                        }

                        if accum.starts_with(&expanded_asset_prefix) {
                            if seen.insert(accum.clone()) {
                                candidates.push(accum.clone());
                            }
                        }
                    }
                }

                candidates.sort_by(|a, b| numeric_sort::cmp(a, b));

                let mut completions = Vec::new();
                for cand in candidates {
                    completions.push(Suggestion {
                        value: cand.clone(),
                        display_override: compute_display_override_for_path(
                            &expanded_asset_prefix,
                            &cand,
                        ),
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: 0,
                            end: asset_prefix.len(),
                        },
                        append_whitespace: false,
                        match_indices: None,
                    });
                }
                completions
            }
            Err(e) => {
                tracing::debug!(?e, "error: could not fetch list of matching assets");
                vec![]
            }
        }
    }

    /// Completes a task reference:
    /// 1. Local file paths (Must start with `/`, `~`, `./`, or `../`)
    /// 2. Fully qualified task names (Must contain a `/` after the username)
    /// 3. Cached tasks (If does not contain a `/` after the username)
    fn task_ref_completer(&self, task_prefix: &str) -> Vec<Suggestion> {
        tracing::debug!(?task_prefix, "task_completer");
        if task_prefix.starts_with('/')
            || task_prefix.starts_with('~')
            || task_prefix.starts_with("./")
            || task_prefix.starts_with("../")
        {
            let mut completions = self.file_completer(task_prefix, false);
            completions.retain(|suggestion| {
                suggestion.value.ends_with("/") || suggestion.value.ends_with(".toml")
            });
            return completions;
        } else if let Some((username, _task_name_prefix)) = task_prefix.split_once('/') {
            self.task_fqn_completer(task_prefix, username)
        } else {
            self.task_cache_completer(task_prefix)
        }
    }

    fn task_fqn_completer(&self, task_prefix: &str, username: &str) -> Vec<Suggestion> {
        tracing::debug!(?task_prefix, "task_completer");
        use crate::api::types::account::AccountWhoisArg;
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.api_client.account_whois(
                AccountWhoisArg {
                    username: username.to_string(),
                },
            ))
        });
        match result {
            Ok(res) => {
                tracing::debug!(
                    username,
                    ?task_prefix,
                    ?res.tasks,
                    "task_completer");
                let mut completions = Vec::new();
                let mut sorted_tasks = res.tasks;
                sorted_tasks.sort_by(|a, b| numeric_sort::cmp(&a.task_fqn, &b.task_fqn));
                for task in sorted_tasks {
                    if task.task_fqn.starts_with(task_prefix) {
                        completions.push(Suggestion {
                            value: task.task_fqn.clone(),
                            display_override: None,
                            description: None,
                            style: None,
                            extra: None,
                            span: Span {
                                start: 0,
                                end: task_prefix.len(),
                            },
                            append_whitespace: true,
                            match_indices: None,
                        });
                    }
                }
                completions
            }
            Err(e) => {
                tracing::debug!(?e, "error: could not fetch list of matching assets",);
                vec![]
            }
        }
    }

    fn task_cache_completer(&self, task_prefix: &str) -> Vec<Suggestion> {
        tracing::debug!(?task_prefix, "task_completer");
        // This autocompletes to tasks that are fetched/cached on disk.
        // We hide the toml extension to make the autocomplete not
        // appear as if it's traversing a file tree.
        let mut task_cache_prefix = config::get_config_folder_path();
        task_cache_prefix.push("cache/task");
        let task_cache_prefix_offset = task_cache_prefix.to_string_lossy().to_string().len() + 1;
        task_cache_prefix.push(task_prefix);

        let mut completions =
            self.file_completer(task_cache_prefix.to_string_lossy().as_ref(), false);
        completions.retain(|suggestion| {
            suggestion.value.ends_with("/") || suggestion.value.ends_with(".toml")
        });
        for suggestion in &mut completions {
            suggestion.value = suggestion.value[task_cache_prefix_offset..].to_string();
            if suggestion.value.ends_with(".toml") {
                suggestion.value =
                    suggestion.value[..suggestion.value.len() - ".toml".len()].to_string();
            }
            suggestion.span.end -= task_cache_prefix_offset;
            tracing::debug!(
                value = suggestion.value,
                span_start = suggestion.span.start,
                span_end = suggestion.span.end,
                "suggestion",
            );
        }
        completions
    }

    /// # Arguments
    /// * `username_prefix` - The prefix of the username to complete.
    fn username_completer(&self, username_prefix: &str) -> Vec<Suggestion> {
        use crate::api::types::account::AccountSearchArg;
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.api_client.account_search(
                AccountSearchArg {
                    q: username_prefix.to_string(),
                },
            ))
        });
        match result {
            Ok(res) => {
                let mut completions = Vec::new();
                let mut sorted_users = res.users;
                sorted_users.sort_by(|a, b| numeric_sort::cmp(&a.username, &b.username));
                for user in sorted_users {
                    completions.push(Suggestion {
                        value: user.username.clone(),
                        display_override: None,
                        description: None,
                        style: None,
                        extra: None,
                        span: Span {
                            start: 0,
                            end: username_prefix.len(),
                        },
                        append_whitespace: true,
                        match_indices: None,
                    });
                }
                completions
            }
            Err(e) => {
                tracing::debug!(?e, "error: could not search for matching users");
                vec![]
            }
        }
    }
}
