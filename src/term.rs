use base64::Engine;
use base64::engine::general_purpose;
use colored::*;
use reedline::{
    self, Reedline, Signal, Vi, default_vi_insert_keybindings, default_vi_normal_keybindings,
};
use std::io::Write;

use crate::{line_editor, term_color};

pub fn print_image_to_term(encoded_image: &String) -> Result<(), Box<dyn std::error::Error>> {
    let use_pretty_images = std::env::var_os("HAI_NO_PRETTY_IMAGES").is_none();
    let image_height = std::env::var("HAI_IMAGE_HEIGHT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(20);

    let viuer_cfg = viuer::Config {
        height: Some(image_height),
        absolute_offset: false,
        use_iterm: use_pretty_images,
        use_kitty: use_pretty_images,
        use_sixel: use_pretty_images,
        truecolor: term_color::should_use_colors(),
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

pub fn window_title_set(title: &str) {
    if atty::is(atty::Stream::Stdout) {
        crossterm::queue!(std::io::stdout(), crossterm::terminal::SetTitle(title)).unwrap();
        // Special escape sequence for Konsole's tab titles
        print!("\x1b]30;{}\x07", title);
        std::io::stdout().flush().unwrap();
    }
}

pub fn window_title_reset() {
    if atty::is(atty::Stream::Stdout) {
        crossterm::queue!(std::io::stdout(), crossterm::terminal::SetTitle("")).unwrap();
        // Special escape sequence for Konsole's tab titles
        // Since it isn't possible to reset the tab title to its
        // original value, we set it to the Konsole default
        // even if it wasn't this prior to the task.
        print!("\x1b]30;%d : %n\x07");
        std::io::stdout().flush().unwrap();
    }
}
