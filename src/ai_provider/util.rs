use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use serde_json::Value;
use std::collections::HashSet;
use std::io::{self, Write};
use two_face::re_exports::syntect::easy::HighlightLines;
use two_face::re_exports::syntect::highlighting::Style;
use unicode_width::UnicodeWidthStr;

use crate::term_color;

/// If json is an object, removes top-level keys that are null.
pub fn remove_nulls(json: &mut Value) {
    if let Value::Object(ref mut map) = json {
        map.retain(|_, v| !v.is_null());
    }
}

pub fn run_jaq(query: &str, input: &Value) -> Result<Value, String> {
    let mut ctx = ParseCtx::new(Vec::new());
    ctx.insert_natives(jaq_core::core());
    ctx.insert_defs(jaq_std::std());
    let (f, errs) = jaq_parse::parse(query, jaq_parse::main());
    if !errs.is_empty() {
        let error_message = errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(error_message);
    }
    let f = ctx.compile(f.unwrap());
    let inputs = RcIter::new(core::iter::empty());
    let mut out = f.run((Ctx::new([], &inputs), Val::from(input.clone())));
    if let Some(Ok(val)) = out.next() {
        Ok(val.into())
    } else {
        Ok(Value::Null)
    }
}

pub struct TextAccumulator<'a> {
    printer: MaskedPrinter<'a>,
    // The printed text is masked
    pub printed_text: String,
    // An unmasked version of the printed text
    pub unmasked_printed_text: String,
}

impl<'a> TextAccumulator<'a> {
    pub fn new(masked_strings: HashSet<String>) -> Self {
        TextAccumulator {
            printer: MaskedPrinter::new(masked_strings),
            printed_text: String::new(),
            unmasked_printed_text: String::new(),
        }
    }

    pub fn acc(&mut self, next: &str) {
        let acc_result = self.printer.acc(next);
        self.printed_text.push_str(&acc_result.printed_text_chunk);
        self.unmasked_printed_text
            .push_str(&acc_result.unmasked_printed_text_chunk);
    }

    pub fn end(&mut self) {
        let acc_result = self.printer.end();
        self.printed_text.push_str(&acc_result.printed_text_chunk);
        self.unmasked_printed_text
            .push_str(&acc_result.unmasked_printed_text_chunk);
    }
}

/// Responsible for printing output while masking specified strings which may
/// necessitate it buffer while checking for incoming string matches.
pub struct MaskedPrinter<'a> {
    sh_printer: SyntaxHighlighterPrinter<'a>,
    buffer: String,
    masked_buffer: String,
    masked_strings: HashSet<String>,
}

impl<'a> MaskedPrinter<'a> {
    pub fn new(masked_strings: HashSet<String>) -> Self {
        MaskedPrinter {
            sh_printer: SyntaxHighlighterPrinter::new(),
            buffer: String::new(),
            masked_buffer: String::new(),
            masked_strings,
        }
    }

    pub fn acc(&mut self, next: &str) -> PrinterAccResult {
        self.buffer.push_str(next);
        self.masked_buffer.push_str(next);
        let mut printable_length = self.buffer.len();
        for masked_string in &self.masked_strings {
            if self.buffer.contains(masked_string) {
                let mask: String = "*".repeat(masked_string.len());
                self.masked_buffer = self.masked_buffer.replace(masked_string, &mask);
            }
            // Compare with masked buffer since we don't need to buffer parts
            // that have already been blotted out.
            printable_length = std::cmp::min(
                printable_length,
                self.masked_buffer.len()
                    - longest_prefix_of_s1_matching_s2_suffix(masked_string, &self.masked_buffer),
            );
        }
        let printable_unmasked_text = self.buffer[..printable_length].to_string();
        let printable_masked_text = self.masked_buffer[..printable_length].to_string();
        self.sh_printer.acc(&printable_masked_text);
        remove_first_n_chars(&mut self.buffer, printable_length);
        remove_first_n_chars(&mut self.masked_buffer, printable_length);

        PrinterAccResult {
            printed_text_chunk: printable_masked_text,
            unmasked_printed_text_chunk: printable_unmasked_text,
            remaining: None,
        }
    }

    pub fn end(&mut self) -> PrinterAccResult {
        self.sh_printer.acc(&self.masked_buffer);
        self.sh_printer.end();
        PrinterAccResult {
            printed_text_chunk: self.masked_buffer.clone(),
            unmasked_printed_text_chunk: self.buffer.clone(),
            remaining: Some("".to_string()),
        }
    }
}

// --

pub struct SyntaxHighlighterPrinter<'a> {
    buffer: String,
    line_start_cursor_position: Option<(u16, u16)>,
    highlighter: Option<HighlightLines<'a>>,
    terminal_color_capability: Option<term_color::ColorCapability>,
}

impl<'a> SyntaxHighlighterPrinter<'a> {
    pub fn new() -> Self {
        SyntaxHighlighterPrinter {
            buffer: String::new(),
            line_start_cursor_position: None,
            highlighter: None,
            terminal_color_capability: term_color::terminal_color_capability(),
        }
    }

    pub fn set_highlighter(&mut self, token: &str) {
        let ps = term_color::get_syntax_set();
        let ts = term_color::get_theme_set();
        if let Some(syntax) = ps.find_syntax_by_token(token) {
            self.highlighter = Some(HighlightLines::new(
                syntax,
                &ts.get(two_face::theme::EmbeddedThemeName::VisualStudioDarkPlus),
            ));
        }
    }

    /// Assumes line has no trailing newline
    pub fn highlighter_check(&mut self, line: &str) {
        if line == "```" {
            self.highlighter = None;
        } else {
            let markdown_code_block_re = term_color::get_markdown_code_block_re();
            if let Some(captures) = markdown_code_block_re.captures(line) {
                if let Some(lang) = captures.get(1).map(|m| m.as_str().to_string()) {
                    self.set_highlighter(&lang);
                }
            }
        }
    }

    pub fn highlighter_check_start(&mut self, line: &str) {
        let markdown_code_block_re = term_color::get_markdown_code_block_re();
        if let Some(captures) = markdown_code_block_re.captures(line) {
            if let Some(lang) = captures.get(1).map(|m| m.as_str().to_string()) {
                self.set_highlighter(&lang);
            }
        }
    }

    pub fn highlighter_check_end(&mut self, line: &str) {
        if self.highlighter.is_some() && line.trim_ascii_end() == "```" {
            self.highlighter = None;
        }
    }

    pub fn acc(&mut self, next: &str) {
        let color_capability =
            if let Some(color_capability) = self.terminal_color_capability.clone() {
                color_capability
            } else {
                self.buffer.push_str(next);
                print!("{}", next);
                io::stdout().flush().unwrap(); // Flush to skip line-buffer
                return;
            };

        let lines: Vec<String> = next.split('\n').map(|s| s.to_string()).collect();
        if lines.len() > 1 {
            let ps = term_color::get_syntax_set();

            // Finish the current line
            println!("{}", &lines[0]);
            io::stdout().flush().unwrap();

            let full_first_line = format!("{}{}", self.buffer, &lines[0]);
            self.buffer.clear();

            // If this line is the end of a code block, end it before
            // triggering the highlight logic.
            self.highlighter_check_end(&full_first_line);

            // If highlighter is set, clear the previous line and reprint with
            // colors.
            if let Some(highlighter) = self.highlighter.as_mut() {
                if let Some((_x, y)) = self.line_start_cursor_position.take() {
                    let line_width = UnicodeWidthStr::width(full_first_line.as_str()) as u16;
                    let (terminal_width, _) = crossterm::terminal::size().unwrap();
                    let height = (line_width / terminal_width) + 1;
                    crossterm::execute!(
                        io::stdout(),
                        crossterm::cursor::MoveTo(0, y - height),
                        crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown),
                    )
                    .unwrap();

                    let line_with_ending = format!("{}\n", full_first_line);
                    let highlighted_parts: Vec<(Style, &str)> =
                        highlighter.highlight_line(&line_with_ending, &ps).unwrap();
                    for (style, text) in highlighted_parts {
                        let escaped = term_color::as_terminal_escaped(
                            style,
                            text,
                            &color_capability,
                            false,
                            None,
                        );
                        print!("{}", escaped);
                    }
                    io::stdout().flush().unwrap();
                }
            }

            // It's important to activate highlighting after the start so that
            // the ``` isn't treated as part of the code. Otherwise, in some
            // languages it will be interpreted as a multi-line comment.
            self.highlighter_check_start(&full_first_line);

            // All lines in the middle are printed fully
            for middle_line in &lines[1..lines.len() - 1] {
                let middle_line_with_ending = format!("{}\n", middle_line);
                if let Some(highlighter) = self.highlighter.as_mut() {
                    let highlighted_parts: Vec<(Style, &str)> = highlighter
                        .highlight_line(&middle_line_with_ending, &ps)
                        .unwrap();

                    for (style, text) in highlighted_parts {
                        let escaped = term_color::as_terminal_escaped(
                            style,
                            text,
                            &color_capability,
                            false,
                            None,
                        );
                        print!("{}", escaped);
                    }
                    io::stdout().flush().unwrap();
                } else {
                    print!("{}", middle_line_with_ending);
                    io::stdout().flush().unwrap();
                }
                self.highlighter_check(&middle_line);
            }

            // The last line is only partial (unless this is the last acc() call)
            let last_line_partial = &lines[lines.len() - 1].to_owned();
            self.line_start_cursor_position = Some(crossterm::cursor::position().unwrap());
            print!("{}", last_line_partial);
            io::stdout().flush().unwrap();
            self.buffer.push_str(last_line_partial)
        } else {
            if self.line_start_cursor_position.is_none() {
                self.line_start_cursor_position = Some(crossterm::cursor::position().unwrap());
            }
            self.buffer.push_str(next);
            print!("{}", next);
            io::stdout().flush().unwrap(); // Flush to skip line-buffer
        }
    }

    pub fn end(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        // If there are characters left in the buffer, and highlighting is
        // activated, the current line should be cleared and reprinted with
        // highlighting. This is only an issue when the output ends with ``````
        // w/o a trailing newline.
        if let Some(color_capability) = self.terminal_color_capability.clone() {
            if let Some(highlighter) = self.highlighter.as_mut() {
                if let Some((x, y)) = self.line_start_cursor_position.take() {
                    let ps = term_color::get_syntax_set();
                    let line_width = UnicodeWidthStr::width(self.buffer.as_str()) as u16;
                    let (terminal_width, _) = crossterm::terminal::size().unwrap();
                    let height = line_width / terminal_width;
                    crossterm::execute!(
                        io::stdout(),
                        crossterm::cursor::MoveTo(x, y - height),
                        crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown)
                    )
                    .unwrap();
                    let highlighted_parts: Vec<(Style, &str)> =
                        highlighter.highlight_line(&self.buffer, &ps).unwrap();
                    for (style, text) in highlighted_parts {
                        let escaped = term_color::as_terminal_escaped(
                            style,
                            text,
                            &color_capability,
                            false,
                            None,
                        );
                        print!("{}", escaped);
                    }
                    io::stdout().flush().unwrap();
                }
            }
        }
    }
}

// --

pub struct PrinterAccResult {
    printed_text_chunk: String,
    unmasked_printed_text_chunk: String,
    // If set, the printer has completed processing and returned the remaining
    // string to the buffer.
    remaining: Option<String>,
}

/// Responsible for printing output while masking specified strings which may
/// necessitate it buffer while checking for incoming string matches.
pub struct MaskedJsonStringPrinter {
    buffer: String,
    masked_strings_ordered: Vec<String>,
    /// The offset into buffer that has been printed to screen
    buffer_print_cursor: usize,

    // The printed text is masked
    pub printed_text: String,
    // An unmasked version of the printed text
    pub unmasked_printed_text: String,
}

impl MaskedJsonStringPrinter {
    pub fn new(masked_strings: HashSet<String>) -> MaskedJsonStringPrinter {
        // Sort by length descending in case a mask is a left-aligned subset of another.
        let mut masked_strings_ordered: Vec<String> = masked_strings.clone().into_iter().collect();
        masked_strings_ordered.sort_by_key(|b| std::cmp::Reverse(b.len()));
        MaskedJsonStringPrinter {
            buffer: String::new(),
            masked_strings_ordered,
            buffer_print_cursor: 0,
            printed_text: String::new(),
            unmasked_printed_text: String::new(),
        }
    }

    /// Accumulates next chunk of text into its buffer and prints as much of
    /// the buffer that it can while respecting masked-strings and JSON
    /// escaping.
    pub fn acc(&mut self, next: &str) -> PrinterAccResult {
        self.buffer.push_str(next);
        if !self.buffer.is_empty() && self.buffer_print_cursor == 0 {
            // Skip to 1 since the input is guaranteed to be a double-quote
            // which won't be printed.
            self.buffer_print_cursor = 1;
        }

        //
        // Check if the entire JSON-string is accumulated to mark printer as
        // done by setting a remainder and truncating the buffer so it does not
        // have excess of the JSON-string.
        //
        let mut remaining = None;
        let mut index = 0;
        while index < self.buffer.len() {
            if self.buffer.as_bytes()[index] == b'"' {
                let maybe_json = &self.buffer[..index + 1];
                if serde_json::from_str::<Value>(maybe_json).is_ok() {
                    remaining = Some(if index + 1 < self.buffer.len() {
                        self.buffer[index + 1..self.buffer.len()].to_string()
                    } else {
                        "".to_string()
                    });
                    self.buffer = self.buffer[..index + 1].to_string();
                    break;
                }
            }
            index += 1;
        }

        // We start with the assumption that the entire buffer is printable and
        // chip away at it with some conservatism.
        let mut buffer_printable_length = self.buffer.len();

        //
        // IMPORTANT: While the buffer is encoded-JSON, the mask is applied to
        // decoded JSON. And, of course, the printed text is decoded JSON.
        //
        // The unprinted buffer may end with an escape char "\" that requires
        // the next chunk to disambiguate. But be careful, it could be a "\\",
        // which means the escaping is complete.
        //
        let mut decoded_next_chunk = None;
        let mut test_end_index = buffer_printable_length;
        while test_end_index > self.buffer_print_cursor {
            let test_chunk_deser = "\"".to_string()
                + &self.buffer[self.buffer_print_cursor..test_end_index]
                + (if remaining.is_none() { "\"" } else { "" });
            if let Ok(Value::String(s)) =
                serde_json::from_str::<serde_json::Value>(&test_chunk_deser)
            {
                decoded_next_chunk = Some(s);
                break;
            }
            test_end_index -= 1;
        }
        buffer_printable_length = test_end_index;

        if decoded_next_chunk.is_none() {
            return PrinterAccResult {
                printed_text_chunk: "".to_string(),
                unmasked_printed_text_chunk: "".to_string(),
                remaining,
            };
        }

        let decoded_next_chunk = decoded_next_chunk.unwrap();
        let mut masked_decoded_next_chunk = decoded_next_chunk.clone();

        //
        // Apply masking to the decoded chunk and identify whether it's
        // printable since it may contain the beginning of text that must be
        // masked.
        //
        for masked_string in &self.masked_strings_ordered {
            if decoded_next_chunk.contains(masked_string) {
                let mask: String = "*".repeat(masked_string.len());
                masked_decoded_next_chunk = masked_decoded_next_chunk.replace(masked_string, &mask);
            }
            if remaining.is_none() {
                // Because the buffer is encoded-JSON but the mask prefix-
                // suffix matching is decoded-JSON, it's easier to withhold
                // printing any part of the decoded-chunk rather than being
                // clever and printing some prefix of it.
                if longest_prefix_of_s1_matching_s2_suffix(
                    masked_string,
                    &masked_decoded_next_chunk,
                ) > 0
                {
                    return PrinterAccResult {
                        printed_text_chunk: "".to_string(),
                        unmasked_printed_text_chunk: "".to_string(),
                        remaining,
                    };
                }
            }
        }

        print!("{}", masked_decoded_next_chunk);
        io::stdout().flush().unwrap(); // Flush to skip line-buffer
        self.printed_text.push_str(&masked_decoded_next_chunk);
        self.unmasked_printed_text.push_str(&decoded_next_chunk);
        self.buffer_print_cursor = buffer_printable_length;

        PrinterAccResult {
            printed_text_chunk: masked_decoded_next_chunk,
            unmasked_printed_text_chunk: decoded_next_chunk,
            remaining,
        }
    }

    pub fn end(&mut self) {
        // No-op since the end of the string is evident from the contents.
    }
}

fn longest_prefix_of_s1_matching_s2_suffix(s1: &str, s2: &str) -> usize {
    let mut max_length = 0;

    // Iterate over all possible prefixes of `s1`.
    for i in 1..=s1.len() {
        let prefix = &s1[..i];

        // Check if the prefix matches the suffix of `s2`.
        if s2.ends_with(prefix) {
            max_length = prefix.len();
        }
    }

    max_length
}

fn remove_first_n_chars(buffer: &mut String, n: usize) {
    // Find byte offset for the n-th character
    if let Some((byte_index, _)) = buffer.char_indices().nth(n) {
        buffer.drain(..byte_index);
    } else {
        buffer.clear();
    }
}

// --

enum Printer {
    String(MaskedJsonStringPrinter),
    Array(JsonArrayAccumulator),
}

// FIXME: Remove tool_id & tool_name
pub struct JsonObjectAccumulator {
    pub tool_id: String,
    #[allow(dead_code)]
    pub tool_name: String,
    /// All partial jsons concatenated
    pub buffer: String,
    /// The offset into buffer that has been printed to screen
    buffer_print_cursor: usize,
    /// The printed text is the buffer without JSON markup and masked.
    pub printed_text: String,
    /// What would have been the printed text without masking.
    pub unmasked_printed_text: String,
    masked_strings: HashSet<String>,
    cur_printer: Option<Printer>,
}

impl JsonObjectAccumulator {
    pub fn new(id: String, name: String, masked_strings: HashSet<String>) -> JsonObjectAccumulator {
        JsonObjectAccumulator {
            tool_id: id,
            tool_name: name,
            buffer: String::new(),
            buffer_print_cursor: 0,
            printed_text: String::new(),
            unmasked_printed_text: String::new(),
            masked_strings,
            cur_printer: None,
        }
    }

    pub fn acc(&mut self, next: &str) {
        self.buffer.push_str(next);
        if self.buffer_print_cursor == 0 {
            // This is triggered while we haven't yet identified the full
            // "input" key in the JSON response.

            // Unfortunately, the spacing in the prefix differs between
            // services and is unreliable to depend on anyway.
            // In fact, I've observed that as a conversation gets longer,
            // progressively weirder formatting is used with a mix of newlines,
            // whitespace, and indentation before the "input" key is finally
            // specified.

            // Find the second occurrence of `"` to be agnostic to spacing. This
            // should match the opening of the value of the "input" key.
            let second_quote_index = self
                .buffer
                .char_indices()
                .filter(|&(_, c)| c == '"')
                .nth(1)
                .map(|(index, _)| index);
            if let Some(second_quote_index) = second_quote_index {
                let third_quote_index = self.buffer[second_quote_index + 1..]
                    .char_indices()
                    .filter(|&(_, c)| c == '"')
                    .nth(0)
                    .map(|(index, _)| index + second_quote_index + 1);
                let array_open_index = self.buffer[second_quote_index + 1..]
                    .char_indices()
                    .filter(|&(_, c)| c == '[')
                    .nth(0)
                    .map(|(index, _)| index + second_quote_index + 1);

                let (printer, index) = match (third_quote_index, array_open_index) {
                    (Some(third_quote_index), Some(array_open_index)) => {
                        if third_quote_index < array_open_index {
                            (
                                Printer::String(MaskedJsonStringPrinter::new(
                                    self.masked_strings.clone(),
                                )),
                                third_quote_index,
                            )
                        } else {
                            (
                                Printer::Array(JsonArrayAccumulator::new(
                                    self.masked_strings.clone(),
                                )),
                                third_quote_index,
                            )
                        }
                    }
                    (Some(third_quote_index), None) => (
                        Printer::String(MaskedJsonStringPrinter::new(self.masked_strings.clone())),
                        third_quote_index,
                    ),
                    (None, Some(array_open_index)) => (
                        Printer::Array(JsonArrayAccumulator::new(self.masked_strings.clone())),
                        array_open_index,
                    ),
                    (None, None) => {
                        // Keep accumulating
                        return;
                    }
                };
                self.buffer_print_cursor = index;
                self.cur_printer = Some(printer);
            } else {
                // Keep accumulating
                return;
            }
        }

        let next_chunk_to_print = &self.buffer[self.buffer_print_cursor..];
        if let Some(Printer::String(printer)) = &mut self.cur_printer {
            let acc_result = printer.acc(next_chunk_to_print);
            self.printed_text.push_str(&acc_result.printed_text_chunk);
            self.unmasked_printed_text
                .push_str(&acc_result.unmasked_printed_text_chunk);
            self.buffer_print_cursor = self.buffer.len();
            if let Some(remaining) = acc_result.remaining {
                self.buffer_print_cursor -= remaining.len();
                self.cur_printer = None;
            }
        } else if let Some(Printer::Array(printer)) = &mut self.cur_printer {
            let acc_result = printer.acc(next_chunk_to_print);
            self.printed_text.push_str(&acc_result.printed_text_chunk);
            self.unmasked_printed_text
                .push_str(&acc_result.unmasked_printed_text_chunk);
            self.buffer_print_cursor = self.buffer.len();
            if let Some(remaining) = acc_result.remaining {
                self.buffer_print_cursor -= remaining.len();
                self.cur_printer = None;
            }
        }
    }

    pub fn end(&mut self) {
        if let Some(Printer::String(printer)) = &mut self.cur_printer {
            printer.end();
            eprintln!("error: bad json deserialization of object");
        }
    }
}

// --

pub struct JsonArrayAccumulator {
    /// Unprocessed parts of the array (prefix, suffix, and in-between strings)
    pub buffer: String,
    /// The printed text is the buffer without JSON markup and masked.
    pub printed_text: String,
    /// What would have been the printed text without masking.
    pub unmasked_printed_text: String,
    masked_strings: HashSet<String>,
    cur_printer: Option<MaskedJsonStringPrinter>,
}

impl JsonArrayAccumulator {
    pub fn new(masked_strings: HashSet<String>) -> JsonArrayAccumulator {
        JsonArrayAccumulator {
            buffer: String::new(),
            printed_text: String::new(),
            unmasked_printed_text: String::new(),
            masked_strings,
            cur_printer: None,
        }
    }

    pub fn acc(&mut self, next: &str) -> PrinterAccResult {
        self.buffer.push_str(next);
        let mut printed_text_chunk = String::new();
        let mut unmasked_printed_text_chunk = String::new();

        loop {
            if let Some(printer) = &mut self.cur_printer {
                let acc_res = printer.acc(&self.buffer);
                printed_text_chunk.push_str(&acc_res.printed_text_chunk);
                unmasked_printed_text_chunk.push_str(&acc_res.unmasked_printed_text_chunk);
                if let Some(remaining) = acc_res.remaining {
                    self.cur_printer = None;
                    self.buffer = remaining;
                    printed_text_chunk.push('\n');
                    unmasked_printed_text_chunk.push('\n');
                    println!();
                } else {
                    // JSON-String Printer absorbed entire buffer and we need
                    // keep accumulating
                    self.buffer.clear();
                    break;
                }
            } else {
                // No active printer, try to find start of next json-string
                let quote_index = self
                    .buffer
                    .char_indices()
                    .filter(|&(_, c)| c == '"')
                    .nth(0)
                    .map(|(index, _)| index);
                if let Some(quote_index) = quote_index {
                    self.cur_printer =
                        Some(MaskedJsonStringPrinter::new(self.masked_strings.clone()));
                    remove_first_n_chars(&mut self.buffer, quote_index);
                    printed_text_chunk.push_str("- ");
                    unmasked_printed_text_chunk.push_str("- ");
                    print!("- ");
                } else {
                    // Keep accumulating
                    break;
                }
            }
        }

        self.printed_text.push_str(&printed_text_chunk);
        self.unmasked_printed_text
            .push_str(&unmasked_printed_text_chunk);

        if self.cur_printer.is_none() {
            let close_bracket_index = self
                .buffer
                .char_indices()
                .filter(|&(_, c)| c == ']')
                .nth(0)
                .map(|(index, _)| index);
            let remaining = if let Some(close_bracket_index) = close_bracket_index {
                if close_bracket_index < self.buffer.len() - 1 {
                    Some(self.buffer[close_bracket_index + 1..].to_string())
                } else {
                    Some("".to_string())
                }
            } else {
                None
            };
            PrinterAccResult {
                printed_text_chunk,
                unmasked_printed_text_chunk,
                remaining,
            }
        } else {
            PrinterAccResult {
                printed_text_chunk,
                unmasked_printed_text_chunk,
                remaining: None,
            }
        }
    }
}

// --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_array_acc_basic() {
        let masked_strings = HashSet::new();
        let mut accumulator = JsonArrayAccumulator::new(masked_strings);
        let input1 = r#"["mango", "pear"]"#;
        let acc_res = accumulator.acc(input1);
        assert_eq!(accumulator.printed_text, "- mango\n- pear\n");
        assert_eq!(accumulator.unmasked_printed_text, "- mango\n- pear\n");
        assert_eq!(acc_res.remaining, Some("".to_string()));

        // Test with masks
        let masked_strings = HashSet::from_iter(vec!["ear".to_string()]);
        let mut accumulator = JsonArrayAccumulator::new(masked_strings);
        let input1 = r#"["mango", "pear"]"#;
        let acc_res = accumulator.acc(input1);
        assert_eq!(accumulator.printed_text, "- mango\n- p***\n");
        assert_eq!(accumulator.unmasked_printed_text, "- mango\n- pear\n");
        assert_eq!(acc_res.remaining, Some("".to_string()));
    }

    #[test]
    fn test_json_array_acc_odd_spacing() {
        let masked_strings = HashSet::new();
        let mut accumulator = JsonArrayAccumulator::new(masked_strings);
        let input1 = "[    \n   \"mango\"     , \n     \"pear\"      ]    ";
        accumulator.acc(input1);
        assert_eq!(accumulator.printed_text, "- mango\n- pear\n");
        assert_eq!(accumulator.unmasked_printed_text, "- mango\n- pear\n");
    }

    #[test]
    fn test_json_array_acc_many_pieces() {
        let masked_strings = HashSet::new();
        let mut accumulator = JsonArrayAccumulator::new(masked_strings);
        let input1 = r#"["#;
        let input2 = r#""mang"#;
        let input3 = r#"o","#;
        let input4 = r#" "pea"#;
        let input5 = r#"r"#;
        let input6 = r#""]  , "#;
        accumulator.acc(input1);
        accumulator.acc(input2);
        accumulator.acc(input3);
        accumulator.acc(input4);
        accumulator.acc(input5);
        let acc_res = accumulator.acc(input6);
        assert_eq!(accumulator.printed_text, "- mango\n- pear\n");
        assert_eq!(accumulator.unmasked_printed_text, "- mango\n- pear\n");
        assert_eq!(acc_res.remaining, Some("  , ".to_string()));
    }

    #[test]
    fn test_json_obj_acc_basic() {
        let masked_strings = HashSet::new();
        let mut accumulator =
            JsonObjectAccumulator::new("id".to_string(), "name".to_string(), masked_strings);

        let input1 = r#"{"input": "Hello "#;
        let input2 = r#"World!"}"#;
        accumulator.acc(input1);
        accumulator.acc(input2);

        assert_eq!(accumulator.printed_text, "Hello World!");
        assert_eq!(accumulator.buffer, r#"{"input": "Hello World!"}"#);
        assert!(serde_json::from_str::<Value>(&accumulator.buffer).is_ok());
    }

    #[test]
    fn test_json_obj_acc_many_pieces() {
        let masked_strings = HashSet::new();
        let mut accumulator =
            JsonObjectAccumulator::new("id".to_string(), "name".to_string(), masked_strings);

        accumulator.acc(r#"{""#);
        accumulator.acc(r#"in"#);
        accumulator.acc(r#"p"#);
        accumulator.acc(r#"ut"#);
        accumulator.acc(r#"""#);
        accumulator.acc(r#": "#);
        accumulator.acc(r#""H"#);
        accumulator.acc(r#"e"#);
        accumulator.acc(r#"ll"#);
        accumulator.acc(r#"o"#);
        accumulator.acc(r#""}"#);

        assert_eq!(accumulator.printed_text, "Hello");
        assert_eq!(accumulator.buffer, r#"{"input": "Hello"}"#);
        assert!(serde_json::from_str::<Value>(&accumulator.buffer).is_ok());
    }

    #[test]
    fn test_json_obj_acc_odd_spacing() {
        let masked_strings = HashSet::from_iter(vec!["secret".to_string()]);
        let mut accumulator =
            JsonObjectAccumulator::new("id".to_string(), "name".to_string(), masked_strings);

        let input1 = r#"        {       "input"     :        "Hello "#;
        let input2 = r#"World!"     }      "#;
        accumulator.acc(input1);
        accumulator.acc(input2);

        assert_eq!(accumulator.printed_text, "Hello World!");
        assert_eq!(accumulator.buffer, format!("{}{}", input1, input2));
        assert!(serde_json::from_str::<Value>(&accumulator.buffer).is_ok());
    }

    #[test]
    fn test_json_obj_acc_with_array() {
        let masked_strings = HashSet::from_iter(vec!["secret".to_string()]);
        let mut accumulator =
            JsonObjectAccumulator::new("id".to_string(), "name".to_string(), masked_strings);

        let input1 = r#"        {  "cmds"     :        ["Hello "#;
        let input2 = r#"World!"  ]   }      "#;
        accumulator.acc(input1);
        accumulator.acc(input2);

        assert_eq!(accumulator.printed_text, "- Hello World!\n");
    }

    #[test]
    fn test_basic_masking() {
        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello world\"");
        assert_eq!(result.printed_text_chunk, "***** world");
        assert_eq!(result.unmasked_printed_text_chunk, "hello world");
        assert_eq!(printer.printed_text, "***** world");
        assert_eq!(printer.unmasked_printed_text, "hello world");
    }

    #[test]
    fn test_multiple_masked_strings() {
        let masked_strings = HashSet::from_iter(vec!["hello".to_string(), "world".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello world\"");
        assert_eq!(result.printed_text_chunk, "***** *****");
        assert_eq!(result.unmasked_printed_text_chunk, "hello world");
        assert_eq!(printer.printed_text, "***** *****");
        assert_eq!(printer.unmasked_printed_text, "hello world");
    }

    #[test]
    fn test_json_string_encoding() {
        let masked_strings = HashSet::from_iter(vec![]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello \\\"world\"");
        assert_eq!(result.printed_text_chunk, "hello \"world");
        assert_eq!(result.unmasked_printed_text_chunk, "hello \"world");
        assert_eq!(printer.printed_text, "hello \"world");
        assert_eq!(printer.unmasked_printed_text, "hello \"world");
    }

    #[test]
    fn test_partial_string_accumulation() {
        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result1 = printer.acc("\"hel");
        let result2 = printer.acc("lo");
        let result3 = printer.acc(" world\"");

        assert_eq!(result1.printed_text_chunk, ""); // Nothing printed yet due to potential masking
        assert_eq!(result1.remaining, None);
        assert_eq!(result2.printed_text_chunk, "*****");
        assert_eq!(result2.unmasked_printed_text_chunk, "hello");
        assert_eq!(result2.remaining, None);
        assert_eq!(result3.printed_text_chunk, " world");
        assert_eq!(result3.remaining, Some("".to_string()));

        //
        // Test with lots of remaining text
        //

        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result1 = printer.acc("\"hel");
        let result2 = printer.acc("lo");
        let result3 = printer.acc(" world\",    \"");

        assert_eq!(result1.printed_text_chunk, "");
        assert_eq!(result1.remaining, None);
        assert_eq!(result2.printed_text_chunk, "*****");
        assert_eq!(result2.unmasked_printed_text_chunk, "hello");
        assert_eq!(result2.remaining, None);
        assert_eq!(result3.printed_text_chunk, " world");
        assert_eq!(result3.remaining, Some(",    \"".to_string()));

        //
        // Test all done in one
        //
        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result1 = printer.acc("\"hel\", ");

        assert_eq!(result1.printed_text_chunk, "hel");
        assert_eq!(result1.unmasked_printed_text_chunk, "hel");
        assert_eq!(result1.remaining, Some(", ".to_string()));

        //
        // Test empty
        //
        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);
        let result1 = printer.acc("\"\", ");
        assert_eq!(result1.printed_text_chunk, "");
        assert_eq!(result1.remaining, Some(", ".to_string()));

        let masked_strings = HashSet::from_iter(vec!["hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);
        let result1 = printer.acc("\"\"");
        assert_eq!(result1.printed_text_chunk, "");
        assert_eq!(result1.remaining, Some("".to_string()));
    }

    #[test]
    fn test_partial_string_accumulation_escaping() {
        let masked_strings = HashSet::from_iter(vec![]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result1 = printer.acc("\"hello\\");
        let result2 = printer.acc("n\"");

        assert_eq!(result1.printed_text_chunk, "hello");
        assert_eq!(result1.remaining, None);
        assert_eq!(result2.printed_text_chunk, "\n");
        assert_eq!(result2.remaining, Some("".to_string()));
    }

    #[test]
    fn test_overlapping_masked_strings() {
        let masked_strings = HashSet::from_iter(vec!["hell".to_string(), "hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello there\"");
        assert_eq!(result.printed_text_chunk, "***** there");
        assert_eq!(result.unmasked_printed_text_chunk, "hello there");
        assert_eq!(printer.printed_text, "***** there");
        assert_eq!(printer.unmasked_printed_text, "hello there");
    }

    #[test]
    fn test_no_masked_strings() {
        let masked_strings = HashSet::new();
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello world\"");
        assert_eq!(result.printed_text_chunk, "hello world");
        assert_eq!(result.unmasked_printed_text_chunk, "hello world");
    }

    #[test]
    fn test_multiple_occurrences() {
        let masked_strings = HashSet::from_iter(vec!["test".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"test test test\"");
        assert_eq!(result.printed_text_chunk, "**** **** ****");
        assert_eq!(result.unmasked_printed_text_chunk, "test test test");
        assert_eq!(result.remaining, Some("".to_string()));
    }

    #[test]
    fn test_case_sensitivity() {
        let masked_strings = HashSet::from_iter(vec!["Hello".to_string()]);
        let mut printer = MaskedJsonStringPrinter::new(masked_strings);

        let result = printer.acc("\"hello HELLO Hello\"");
        assert_eq!(result.printed_text_chunk, "hello HELLO *****");
        assert_eq!(result.unmasked_printed_text_chunk, "hello HELLO Hello");
    }
}
