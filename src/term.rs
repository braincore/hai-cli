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
