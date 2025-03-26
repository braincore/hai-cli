use base64::engine::general_purpose;
use base64::Engine;
use colored::*;
use reedline::{
    self, default_vi_insert_keybindings, default_vi_normal_keybindings, Reedline, Signal, Vi,
};
use std::io::Write;

use crate::line_editor;

pub fn print_image_to_term(encoded_image: &String) -> Result<(), Box<dyn std::error::Error>> {
    let viuer_cfg = viuer::Config {
        height: Some(20),
        absolute_offset: false,
        ..Default::default()
    };

    let image_bytes = general_purpose::STANDARD.decode(encoded_image)?;
    let dynamic_image = image::load_from_memory(&image_bytes)?;
    viuer::print(&dynamic_image, &viuer_cfg)?;
    Ok(())
}

pub fn ask_question(prompt: &str, secret: bool) -> Option<String> {
    if secret {
        print!("{} {} ", "  SECRET  ".black().on_white(), prompt);
        std::io::stdout().flush().unwrap();
        Some(rpassword::prompt_password("").expect("Failed to read secret input"))
    } else {
        ask_question_readline(prompt).map(|answer| answer.trim().to_string())
    }
}

/// Similar to `ask_question` but returns an empty string if the user cancels
/// the input via a signal (e.g. ctrl + c)
pub fn ask_question_default_empty(prompt: &str, secret: bool) -> String {
    ask_question(prompt, secret).unwrap_or("".to_string())
}

pub fn ask_question_readline(prompt: &str) -> Option<String> {
    let mut reedline = Reedline::create()
        .use_bracketed_paste(true)
        .with_edit_mode(Box::new(Vi::new(
            default_vi_insert_keybindings(),
            default_vi_normal_keybindings(),
        )))
        .with_ansi_colors(true);
    let sig = reedline.read_line(&line_editor::QuestionPrompt::new(prompt));
    match sig {
        Ok(Signal::Success(answer)) => Some(answer),
        Ok(Signal::CtrlC) => None,
        Ok(Signal::CtrlD) => None,
        _ => None,
    }
}

// --

use nu_ansi_term::Color::{self, Fixed, Rgb};
use nu_ansi_term::{self, Style};

use syntect::highlighting::{self, FontStyle};

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
    italics: bool,
    background_color: Option<highlighting::Color>,
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
    if italics && style.font_style.contains(FontStyle::ITALIC) {
        combined_style = combined_style.italic();
    }
    combined_style.background = background_color
        .and_then(|c| to_ansi_color(c, matches!(color_capability, ColorCapability::TrueColor)));
    combined_style.paint(text).to_string()
}

use std::io::IsTerminal;

fn should_use_colors() -> bool {
    // Check NO_COLOR first (highest priority for disabling)
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    // Check CLICOLOR_FORCE next (can force colors on)
    if let Ok(force) = std::env::var("CLICOLOR_FORCE") {
        if force == "1" {
            return true;
        }
    }

    // Then check CLICOLOR (can disable colors)
    if let Ok(clicolor) = std::env::var("CLICOLOR") {
        if clicolor == "0" {
            return false;
        }
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
