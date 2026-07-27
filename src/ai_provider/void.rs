/// This is an AI Provider exclusively for testing.
use std::error::Error;

use crate::ai_provider::util::TextAccumulator;
use crate::chat;
use crate::{io::Out, outln};

pub async fn send_to_void(
    out: &Out,
    model: &str,
    masked_strings: &Vec<String>,
) -> Result<Vec<chat::ChatCompletionResponse>, Box<dyn Error>> {
    let mut text_accumulator = TextAccumulator::new(masked_strings.clone());

    if model == "terminal-width" {
        let (terminal_width, _) = crossterm::terminal::size().unwrap();
        let filler_string = "A".repeat(terminal_width as usize);
        text_accumulator.acc(&filler_string, out);
        text_accumulator.acc("\n\n", out);

        let filler_string = "B".repeat(terminal_width as usize + 1);
        text_accumulator.acc(&filler_string, out);
        text_accumulator.acc("\n\n", out);

        let filler_string = "C".repeat(2 * terminal_width as usize + 10);
        text_accumulator.acc(&filler_string, out);
        text_accumulator.acc("\n\n", out);

        text_accumulator.acc("```rust\n", out);

        let filler_string = "B".repeat(terminal_width as usize + 1);
        text_accumulator.acc(&filler_string, out);
        text_accumulator.acc("\n", out);

        let filler_string = "C".repeat(terminal_width as usize);
        text_accumulator.acc(&filler_string, out);
        text_accumulator.acc("\n", out);

        text_accumulator.acc("hi\n", out);
        text_accumulator.acc("```", out);
    } else if model == "hello-world" {
        text_accumulator.acc("hello, world", out);
    } else if model == "clobber" {
        text_accumulator.acc("", out);
        text_accumulator.acc("Of", out);
        text_accumulator.acc(" course", out);
        text_accumulator.acc("!", out);
        text_accumulator.acc(" Here", out);
        text_accumulator.acc("’s", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" simple", out);
        text_accumulator.acc(" example", out);
        text_accumulator.acc(" of", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" Rust", out);
        text_accumulator.acc(" program", out);
        text_accumulator.acc(" that", out);
        text_accumulator.acc(" prints", out);
        text_accumulator.acc(" \"", out);
        text_accumulator.acc("Hello", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" world", out);
        text_accumulator.acc("!\"", out);
        text_accumulator.acc(" and", out);
        text_accumulator.acc(" sums", out);
        text_accumulator.acc(" the", out);
        text_accumulator.acc(" numbers", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc(" to", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(":\n\n", out);
        text_accumulator.acc("```", out);
        text_accumulator.acc("rust", out);
        text_accumulator.acc("\n", out);
        text_accumulator.acc("fn", out);
        text_accumulator.acc(" main", out);
        text_accumulator.acc("()", out);
        text_accumulator.acc(" {\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" println", out);
        text_accumulator.acc("!(\"", out);
        text_accumulator.acc("Hello", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" world", out);
        text_accumulator.acc("!\");\n\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" let", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(":", out);
        text_accumulator.acc(" i", out);
        text_accumulator.acc("32", out);
        text_accumulator.acc(" =", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc("..", out);
        text_accumulator.acc("=", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(").", out);
        text_accumulator.acc("sum", out);
        text_accumulator.acc("();\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" println", out);
        text_accumulator.acc("!(\"", out);
        text_accumulator.acc("The", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(" of", out);
        text_accumulator.acc(" numbers", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc(" to", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(" is", out);
        text_accumulator.acc(":", out);
        text_accumulator.acc(" {}\",", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(");\n", out);
        text_accumulator.acc("}\n", out);
        text_accumulator.acc("``", out);
        text_accumulator.acc("`\n\n", out);
        text_accumulator.acc("If", out);
        text_accumulator.acc(" you", out);
        text_accumulator.acc(" want", out);
        text_accumulator.acc(" something", out);
        text_accumulator.acc(" more", out);
        text_accumulator.acc(" specific", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" like", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" function", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" struct", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" or", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" particular", out);
        text_accumulator.acc(" algorithm", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" let", out);
        text_accumulator.acc(" me", out);
        text_accumulator.acc(" know", out);
        text_accumulator.acc("!", out);
    } else if model == "unclosed" {
        text_accumulator.acc("", out);
        text_accumulator.acc("Of", out);
        text_accumulator.acc(" course", out);
        text_accumulator.acc("!", out);
        text_accumulator.acc(" Here", out);
        text_accumulator.acc("’s", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" simple", out);
        text_accumulator.acc(" example", out);
        text_accumulator.acc(" of", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" Rust", out);
        text_accumulator.acc(" program", out);
        text_accumulator.acc(" that", out);
        text_accumulator.acc(" prints", out);
        text_accumulator.acc(" \"", out);
        text_accumulator.acc("Hello", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" world", out);
        text_accumulator.acc("!\"", out);
        text_accumulator.acc(" and", out);
        text_accumulator.acc(" sums", out);
        text_accumulator.acc(" the", out);
        text_accumulator.acc(" numbers", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc(" to", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(":\n\n", out);
        text_accumulator.acc("```", out);
        text_accumulator.acc("rust", out);
        text_accumulator.acc("\n", out);
        text_accumulator.acc("fn", out);
        text_accumulator.acc(" main", out);
        text_accumulator.acc("()", out);
        text_accumulator.acc(" {\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" println", out);
        text_accumulator.acc("!(\"", out);
        text_accumulator.acc("Hello", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" world", out);
        text_accumulator.acc("!\");\n\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" let", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(":", out);
        text_accumulator.acc(" i", out);
        text_accumulator.acc("32", out);
        text_accumulator.acc(" =", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc("..", out);
        text_accumulator.acc("=", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(").", out);
        text_accumulator.acc("sum", out);
        text_accumulator.acc("();\n", out);
        text_accumulator.acc("   ", out);
        text_accumulator.acc(" println", out);
        text_accumulator.acc("!(\"", out);
        text_accumulator.acc("The", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(" of", out);
        text_accumulator.acc(" numbers", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc(" to", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("10", out);
        text_accumulator.acc(" is", out);
        text_accumulator.acc(":", out);
        text_accumulator.acc(" {}\",", out);
        text_accumulator.acc(" sum", out);
        text_accumulator.acc(");\n", out);
        text_accumulator.acc("}\n", out);
        let (terminal_width, _) = crossterm::terminal::size().unwrap();
        let filler_string = "A".repeat(2 * terminal_width as usize + 10);
        text_accumulator.acc(&filler_string, out);
    } else if model == "markdown-double" {
        text_accumulator.acc("", out);
        text_accumulator.acc("**", out);
        text_accumulator.acc("U", out);
        text_accumulator.acc("don", out);
        text_accumulator.acc("**", out);
        text_accumulator.acc(" is", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" thick", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" chewy", out);
        text_accumulator.acc(" Japanese", out);
        text_accumulator.acc(" noodle", out);
        text_accumulator.acc(" made", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" wheat", out);
        text_accumulator.acc(" flour", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" water", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" and", out);
        text_accumulator.acc(" salt", out);
        text_accumulator.acc(".", out);
        text_accumulator.acc(" You", out);
        text_accumulator.acc(" can", out);
        text_accumulator.acc(" buy", out);
        text_accumulator.acc(" dried", out);
        text_accumulator.acc(" or", out);
        text_accumulator.acc(" fresh", out);
        text_accumulator.acc(" ud", out);
        text_accumulator.acc("on", out);
        text_accumulator.acc(" at", out);
        text_accumulator.acc(" most", out);
        text_accumulator.acc(" Asian", out);
        text_accumulator.acc(" grocery", out);
        text_accumulator.acc(" stores", out);
        text_accumulator.acc(",", out);
        text_accumulator.acc(" but", out);
        text_accumulator.acc(" making", out);
        text_accumulator.acc(" it", out);
        text_accumulator.acc(" from", out);
        text_accumulator.acc(" scratch", out);
        text_accumulator.acc(" is", out);
        text_accumulator.acc(" fun", out);
        text_accumulator.acc(" and", out);
        text_accumulator.acc(" only", out);
        text_accumulator.acc(" requires", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" few", out);
        text_accumulator.acc(" ingredients", out);
        text_accumulator.acc("!", out);
        text_accumulator.acc(" Here", out);
        text_accumulator.acc("’s", out);
        text_accumulator.acc(" a", out);
        text_accumulator.acc(" basic", out);
        text_accumulator.acc(" recipe", out);
        text_accumulator.acc(" for", out);
        text_accumulator.acc(" homemade", out);
        text_accumulator.acc(" ud", out);
        text_accumulator.acc("on", out);
        text_accumulator.acc(" noodles", out);
        text_accumulator.acc(":\n\n", out);
        text_accumulator.acc("---\n\n", out);
        text_accumulator.acc("###", out);
        text_accumulator.acc(" Ingredients", out);
        text_accumulator.acc(":\n", out);
        text_accumulator.acc("-", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("2", out);
        text_accumulator.acc(" cups", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("250", out);
        text_accumulator.acc("g", out);
        text_accumulator.acc(")", out);
        text_accumulator.acc(" all", out);
        text_accumulator.acc("-purpose", out);
        text_accumulator.acc(" flour", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("or", out);
        text_accumulator.acc(" bread", out);
        text_accumulator.acc(" flour", out);
        text_accumulator.acc(" for", out);
        text_accumulator.acc(" extra", out);
        text_accumulator.acc(" chew", out);
        text_accumulator.acc(")\n", out);
        text_accumulator.acc("-", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("2", out);
        text_accumulator.acc("/", out);
        text_accumulator.acc("3", out);
        text_accumulator.acc(" cup", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("160", out);
        text_accumulator.acc("ml", out);
        text_accumulator.acc(")", out);
        text_accumulator.acc(" water", out);
        text_accumulator.acc("\n", out);
        text_accumulator.acc("-", out);
        text_accumulator.acc(" ", out);
        text_accumulator.acc("1", out);
        text_accumulator.acc(" tsp", out);
        text_accumulator.acc(" salt", out);
        text_accumulator.acc("\n", out);
        text_accumulator.acc("-", out);
        text_accumulator.acc(" Corn", out);
        text_accumulator.acc("st", out);
        text_accumulator.acc("arch", out);
        text_accumulator.acc(" or", out);
        text_accumulator.acc(" extra", out);
        text_accumulator.acc(" flour", out);
        text_accumulator.acc(" (", out);
        text_accumulator.acc("for", out);
        text_accumulator.acc(" dust", out);
        text_accumulator.acc("ing", out);
        text_accumulator.acc(")\n\n", out);
        text_accumulator.acc("---\n\n", out);
    } else if model == "middle-lines" {
        text_accumulator.acc(
            "# boo\n\n```python\nprint('hi')\n```\n\n# test\n\n- a\n- b\n- c",
            out,
        );
    } else {
        text_accumulator.acc("unknown model", out);
    }

    // Mark accumulators as done to clear buffers
    text_accumulator.end(out);

    // Final newline post-response-stream
    outln!(out);
    let mut responses = vec![];
    if !text_accumulator.printed_text.is_empty() {
        responses.push(chat::ChatCompletionResponse::Message {
            text: text_accumulator.printed_text,
        });
    }
    Ok(responses)
}
