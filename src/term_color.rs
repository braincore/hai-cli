use nu_ansi_term::Color::{self, Fixed, Rgb};
use nu_ansi_term::{self, Style};
use regex::Regex;
use std::io::IsTerminal;
use std::io::Write;
use std::sync::OnceLock;
use two_face::re_exports::syntect::highlighting::{self, FontStyle};
use two_face::re_exports::syntect::parsing::SyntaxSet;
use two_face::theme::EmbeddedLazyThemeSet;

/// Function taken unmodified from `bat` crate (sharkdp/bat)
pub fn to_ansi_color(color: highlighting::Color, true_color: bool) -> Option<nu_ansi_term::Color> {
    if color.a == 0 {
        // Themes can specify one of the user-configurable terminal colors by
        // encoding them as #RRGGBBAA with AA set to 00 (transparent) and RR set
        // to the 8-bit color palette number. The built-in themes ansi, base16,
        // and base16-256 use this.
        Some(match color.r {
            // For the first 8 colors, use the Color enum to produce ANSI escape
            // sequences using codes 30-37 (foreground) and 40-47 (background).
            // For example, red foreground is \x1b[31m. This works on terminals
            // without 256-color support.
            0x00 => Color::Black,
            0x01 => Color::Red,
            0x02 => Color::Green,
            0x03 => Color::Yellow,
            0x04 => Color::Blue,
            0x05 => Color::Purple,
            0x06 => Color::Cyan,
            0x07 => Color::White,
            // For all other colors, use Fixed to produce escape sequences using
            // codes 38;5 (foreground) and 48;5 (background). For example,
            // bright red foreground is \x1b[38;5;9m. This only works on
            // terminals with 256-color support.
            //
            // TODO: When ansi_term adds support for bright variants using codes
            // 90-97 (foreground) and 100-107 (background), we should use those
            // for values 0x08 to 0x0f and only use Fixed for 0x10 to 0xff.
            n => Fixed(n),
        })
    } else if color.a == 1 {
        // Themes can specify the terminal's default foreground/background color
        // (i.e. no escape sequence) using the encoding #RRGGBBAA with AA set to
        // 01. The built-in theme ansi uses this.
        None
    } else if true_color {
        Some(Rgb(color.r, color.g, color.b))
    } else {
        Some(Fixed(ansi_colours::ansi256_from_rgb((
            color.r, color.g, color.b,
        ))))
    }
}

#[derive(Clone)]
pub enum ColorCapability {
    Ansi256,
    TrueColor,
}

pub fn as_terminal_escaped(
    style: highlighting::Style,
    text: &str,
    color_capability: &ColorCapability,
    background_color: &Option<highlighting::Color>,
) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let mut combined_style = Style {
        foreground: to_ansi_color(
            style.foreground,
            matches!(color_capability, ColorCapability::TrueColor),
        ),
        ..Style::default()
    };
    if style.font_style.contains(FontStyle::BOLD) {
        combined_style = combined_style.bold();
    }
    if style.font_style.contains(FontStyle::UNDERLINE) {
        combined_style = combined_style.underline();
    }
    if style.font_style.contains(FontStyle::ITALIC) {
        combined_style = combined_style.italic();
    }
    combined_style.background = background_color
        .and_then(|c| to_ansi_color(c, matches!(color_capability, ColorCapability::TrueColor)));
    combined_style.paint(text).to_string()
}

fn should_use_colors() -> bool {
    // Check NO_COLOR first (highest priority for disabling)
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    // Check CLICOLOR_FORCE next (can force colors on)
    if let Ok(force) = std::env::var("CLICOLOR_FORCE")
        && force == "1"
    {
        return true;
    }

    // Then check CLICOLOR (can disable colors)
    if let Ok(clicolor) = std::env::var("CLICOLOR")
        && clicolor == "0"
    {
        return false;
    }

    // Finally, fall back to terminal detection
    std::io::stdout().is_terminal()
}

pub fn terminal_color_capability() -> Option<ColorCapability> {
    if !should_use_colors() {
        return None;
    }

    // Check for true color support
    if std::env::var("COLORTERM")
        .map(|val| val == "truecolor" || val == "24bit")
        .unwrap_or(false)
    {
        return Some(ColorCapability::TrueColor);
    }

    // Check for 256 color support
    if std::env::var("TERM")
        .map(|val| val.contains("256color"))
        .unwrap_or(false)
    {
        return Some(ColorCapability::Ansi256);
    }

    None
}

// --

// Cache syntax & themes b/c they're large per syntect docs
static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
static THEME_SET: OnceLock<EmbeddedLazyThemeSet> = OnceLock::new();

/// Lazy-load syntax set
pub fn get_syntax_set() -> &'static SyntaxSet {
    SYNTAX_SET.get_or_init(|| {
        // This closure will only be called once, the first time get_or_init is called
        two_face::syntax::extra_newlines()
    })
}

/// Lazy-load theme set
pub fn get_theme_set() -> &'static EmbeddedLazyThemeSet {
    THEME_SET.get_or_init(two_face::theme::extra)
}

// --

/// Regex to extract language for markdown code block
pub fn get_markdown_code_block_re() -> &'static Regex {
    static MARKDOWN_CODE_BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    MARKDOWN_CODE_BLOCK_RE.get_or_init(|| Regex::new(r"^\s*```([a-zA-Z0-9_+-]+)?$").unwrap())
}

// --

use two_face::re_exports::syntect::easy::HighlightLines;

pub fn print_with_syntax_highlighting(text: &str, lang_token: &str) {
    let color_capability = if let Some(color_capability) = terminal_color_capability() {
        color_capability
    } else {
        print!("{}", text);
        return;
    };

    let ts = get_theme_set();
    let ps = get_syntax_set();

    // jsx isn't supported by two_face, but tsx is.
    let lang_token = if lang_token == "jsx" {
        "tsx"
    } else {
        lang_token
    };

    let mut highlighter = if let Some(syntax) = ps.find_syntax_by_token(lang_token) {
        HighlightLines::new(
            syntax,
            ts.get(two_face::theme::EmbeddedThemeName::VisualStudioDarkPlus),
        )
    } else {
        print!("{}", text);
        return;
    };

    let lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    for (i, line) in lines.iter().enumerate() {
        let line_with_ending = if i < lines.len() - 1 {
            format!("{}\n", line)
        } else {
            line.clone()
        };
        let highlighted_parts: Vec<(highlighting::Style, &str)> =
            highlighter.highlight_line(&line_with_ending, ps).unwrap();

        for (style, text) in highlighted_parts {
            let escaped = as_terminal_escaped(style, text, &color_capability, &None);
            print!("{}", escaped);
        }
        std::io::stdout().flush().unwrap();
    }
}

/// Assumes `text` is markdown text. Supports highlighting markdown and
/// embedded code blocks.
pub fn print_multi_lang_syntax_highlighting(
    markdown: &str,
    background_color: &Option<(u8, u8, u8)>,
) {
    let mut sh_printer = crate::ai_provider::util::SyntaxHighlighterPrinter::new(true);
    if let Some((r, g, b)) = background_color {
        sh_printer.set_background_color(*r, *g, *b, 255);
    };
    sh_printer.acc(markdown);
    sh_printer.end();
}
