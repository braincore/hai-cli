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
    } else if model == "clobber" {
        text_accumulator.acc("");
        text_accumulator.acc("Of");
        text_accumulator.acc(" course");
        text_accumulator.acc("!");
        text_accumulator.acc(" Here");
        text_accumulator.acc("’s");
        text_accumulator.acc(" a");
        text_accumulator.acc(" simple");
        text_accumulator.acc(" example");
        text_accumulator.acc(" of");
        text_accumulator.acc(" a");
        text_accumulator.acc(" Rust");
        text_accumulator.acc(" program");
        text_accumulator.acc(" that");
        text_accumulator.acc(" prints");
        text_accumulator.acc(" \"");
        text_accumulator.acc("Hello");
        text_accumulator.acc(",");
        text_accumulator.acc(" world");
        text_accumulator.acc("!\"");
        text_accumulator.acc(" and");
        text_accumulator.acc(" sums");
        text_accumulator.acc(" the");
        text_accumulator.acc(" numbers");
        text_accumulator.acc(" from");
        text_accumulator.acc(" ");
        text_accumulator.acc("1");
        text_accumulator.acc(" to");
        text_accumulator.acc(" ");
        text_accumulator.acc("10");
        text_accumulator.acc(":\n\n");
        text_accumulator.acc("```");
        text_accumulator.acc("rust");
        text_accumulator.acc("\n");
        text_accumulator.acc("fn");
        text_accumulator.acc(" main");
        text_accumulator.acc("()");
        text_accumulator.acc(" {\n");
        text_accumulator.acc("   ");
        text_accumulator.acc(" println");
        text_accumulator.acc("!(\"");
        text_accumulator.acc("Hello");
        text_accumulator.acc(",");
        text_accumulator.acc(" world");
        text_accumulator.acc("!\");\n\n");
        text_accumulator.acc("   ");
        text_accumulator.acc(" let");
        text_accumulator.acc(" sum");
        text_accumulator.acc(":");
        text_accumulator.acc(" i");
        text_accumulator.acc("32");
        text_accumulator.acc(" =");
        text_accumulator.acc(" (");
        text_accumulator.acc("1");
        text_accumulator.acc("..");
        text_accumulator.acc("=");
        text_accumulator.acc("10");
        text_accumulator.acc(").");
        text_accumulator.acc("sum");
        text_accumulator.acc("();\n");
        text_accumulator.acc("   ");
        text_accumulator.acc(" println");
        text_accumulator.acc("!(\"");
        text_accumulator.acc("The");
        text_accumulator.acc(" sum");
        text_accumulator.acc(" of");
        text_accumulator.acc(" numbers");
        text_accumulator.acc(" from");
        text_accumulator.acc(" ");
        text_accumulator.acc("1");
        text_accumulator.acc(" to");
        text_accumulator.acc(" ");
        text_accumulator.acc("10");
        text_accumulator.acc(" is");
        text_accumulator.acc(":");
        text_accumulator.acc(" {}\",");
        text_accumulator.acc(" sum");
        text_accumulator.acc(");\n");
        text_accumulator.acc("}\n");
        text_accumulator.acc("``");
        text_accumulator.acc("`\n\n");
        text_accumulator.acc("If");
        text_accumulator.acc(" you");
        text_accumulator.acc(" want");
        text_accumulator.acc(" something");
        text_accumulator.acc(" more");
        text_accumulator.acc(" specific");
        text_accumulator.acc(",");
        text_accumulator.acc(" like");
        text_accumulator.acc(" a");
        text_accumulator.acc(" function");
        text_accumulator.acc(",");
        text_accumulator.acc(" struct");
        text_accumulator.acc(",");
        text_accumulator.acc(" or");
        text_accumulator.acc(" a");
        text_accumulator.acc(" particular");
        text_accumulator.acc(" algorithm");
        text_accumulator.acc(",");
        text_accumulator.acc(" let");
        text_accumulator.acc(" me");
        text_accumulator.acc(" know");
        text_accumulator.acc("!");
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
