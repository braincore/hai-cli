/// This is an AI Provider exclusively for testing.
use std::collections::HashSet;
use std::error::Error;

use crate::ai_provider::util::TextAccumulator;
use crate::chat;

pub async fn send_to_void(
    model: &str,
    masked_strings: &HashSet<String>,
) -> Result<Vec<chat::ChatCompletionResponse>, Box<dyn Error>> {
    let mut text_accumulator = TextAccumulator::new(masked_strings.clone());

    if model == "terminal-width" {
        let (terminal_width, _) = crossterm::terminal::size().unwrap();
        let filler_string = "A".repeat(terminal_width as usize);
        text_accumulator.acc(&filler_string);
        text_accumulator.acc("\n\n");

        text_accumulator.acc("```rust\n");

        let filler_string = "B".repeat(terminal_width as usize + 1);
        text_accumulator.acc(&filler_string);
        text_accumulator.acc("\n");

        let filler_string = "C".repeat(terminal_width as usize);
        text_accumulator.acc(&filler_string);
        text_accumulator.acc("\n");

        text_accumulator.acc("hi\n");
        text_accumulator.acc("```");
    } else if model == "hello-world" {
        text_accumulator.acc("hello, world");
    } else {
        text_accumulator.acc("unknown model");
    }

    // Mark accumulators as done to clear buffers
    text_accumulator.end();

    // Final newline post-response-stream
    println!();
    let mut responses = vec![];
    if !text_accumulator.printed_text.is_empty() {
        responses.push(chat::ChatCompletionResponse::Message {
            text: text_accumulator.printed_text,
        });
    }
    Ok(responses)
}
