use chrono::{DateTime, Local};
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::terminal::supports_keyboard_enhancement;
use reedline::{
    self, ColumnarMenu, Completer, EditCommand, FileBackedHistory, KeyCode, KeyModifiers,
    MenuBuilder, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus,
    PromptViMode, Reedline, ReedlineEvent, ReedlineMenu, Suggestion, Vi,
    default_vi_insert_keybindings, default_vi_normal_keybindings,
};
use std::borrow::Cow;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};

use crate::api::client::HaiClient;
use crate::cmd_registry;
use crate::db::Account;
use crate::{HaiRouterState, config};

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

impl Completer for CmdAndFileCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        use crate::feature::cmd_completer;
        cmd_completer::complete(
            &self.cmd_registry,
            &self.api_client,
            &self.account,
            line,
            pos,
        )
    }
}
