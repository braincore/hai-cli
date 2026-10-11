//! OpenAI Responses API (`/v1/responses`) provider.
//!
//! Opus used to adapt `openai` chat completions provider (nearly one-shot).
//!
//! Why? Starting with GPT-5.6 (Sol, Terra, Luna), the responses API is
//! required for tool calling with reasoning enabled. To maintain rough usage
//! parity with the other providers, our use of the responses provider is
//! stateless and sends the full message history each time with `store: false`
//! (`previous_response_id` is never sent).

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, USER_AGENT};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::error::Error;
use tokio_util::sync::CancellationToken;

use crate::ai_provider::util::{JsonObjectAccumulator, TextAccumulator, remove_nulls};
use crate::chat::{self, MessageContent, MessageRole};
use crate::config::{OpenAiReasoningEffort, OpenAiVerbosity};
use crate::ctrlc_handler::CtrlcHandler;
use crate::{errorln, io::Out, out, outln};

/// Non-OpenAI providers can produce long tool IDs which OpenAI rejects.
const MAX_CALL_ID_LEN: usize = 40;

fn truncate_call_id(id: &str) -> String {
    id.chars().take(MAX_CALL_ID_LEN).collect()
}

fn join_text(content: &[MessageContent]) -> String {
    content
        .iter()
        .filter_map(|c| match c {
            MessageContent::Text { text } => Some(text.as_str()),
            MessageContent::ImageUrl { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn content_to_input_parts(content: &[MessageContent]) -> Vec<Value> {
    content
        .iter()
        .map(|c| match c {
            MessageContent::Text { text } => json!({ "type": "input_text", "text": text }),
            // Note: the internal attachment `id` is intentionally dropped.
            MessageContent::ImageUrl { image_url, .. } => json!({
                "type": "input_image",
                "image_url": image_url.url,
                "detail": image_url.detail,
            }),
        })
        .collect()
}

/// Converts the canonical (chat-completions-shaped) history into Responses API
/// input items.
fn history_to_input(history: &[chat::Message]) -> Vec<Value> {
    let mut input = vec![];
    for msg in history {
        match msg.role {
            MessageRole::System | MessageRole::User => {
                let parts = content_to_input_parts(&msg.content);
                if parts.is_empty() {
                    continue;
                }
                input.push(json!({
                    "type": "message",
                    "role": msg.role.to_str(),
                    "content": parts,
                }));
            }
            MessageRole::Assistant => {
                let text = join_text(&msg.content);
                if !text.is_empty() {
                    input.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": text,
                    }));
                }
                if let Some(tool_calls) = &msg.tool_calls {
                    for tool_call in tool_calls {
                        input.push(json!({
                            "type": "function_call",
                            "call_id": truncate_call_id(&tool_call.id),
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments,
                        }));
                    }
                }
            }
            MessageRole::Tool => {
                let has_images = msg
                    .content
                    .iter()
                    .any(|c| matches!(c, MessageContent::ImageUrl { .. }));
                let output = if has_images {
                    json!(content_to_input_parts(&msg.content))
                } else {
                    json!(join_text(&msg.content))
                };
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": truncate_call_id(msg.tool_call_id.as_deref().unwrap_or_default()),
                    "output": output,
                }));
            }
        }
    }
    input
}

/// Accumulates streamed output and handles printing.
struct ResponseState {
    text_accumulator: TextAccumulator,
    reasoning_accumulator: TextAccumulator,
    reasoning_ended: bool,
    /// Keyed by `output_index` so that ordering is preserved.
    tool_calls: BTreeMap<u64, JsonObjectAccumulator>,
    masked_strings: Vec<String>,
}

impl ResponseState {
    fn new(masked_strings: &[String]) -> Self {
        ResponseState {
            text_accumulator: TextAccumulator::new(masked_strings.to_vec()),
            reasoning_accumulator: TextAccumulator::new(masked_strings.to_vec()),
            reasoning_ended: false,
            tool_calls: BTreeMap::new(),
            masked_strings: masked_strings.to_vec(),
        }
    }

    fn end_reasoning(&mut self, out: &Out) {
        if !self.reasoning_ended && !self.reasoning_accumulator.printed_text.is_empty() {
            self.reasoning_accumulator.end(out);
            outln!(out);
            outln!(out);
            outln!(out, "🧠 end");
            outln!(out);
            self.reasoning_ended = true;
        }
    }

    fn on_reasoning_delta(&mut self, delta: &str, out: &Out) {
        if delta.is_empty() || self.reasoning_ended {
            return;
        }
        if self.reasoning_accumulator.printed_text.is_empty() {
            outln!(out, "🧠 begin");
            outln!(out);
        }
        self.reasoning_accumulator.acc(delta, out);
    }

    fn on_text_delta(&mut self, delta: &str, out: &Out) {
        if delta.is_empty() {
            return;
        }
        if self.text_accumulator.printed_text.is_empty() {
            self.end_reasoning(out);
        }
        self.text_accumulator.acc(delta, out);
    }

    fn on_tool_start(&mut self, output_index: u64, call_id: &str, name: &str, out: &Out) {
        if self.tool_calls.contains_key(&output_index) {
            return;
        }
        self.end_reasoning(out);
        if !self.tool_calls.is_empty() {
            outln!(out);
            outln!(out);
            outln!(out, "‖");
            outln!(out);
        } else if !self.text_accumulator.printed_text.is_empty() {
            // Separate a preceding text response from the tool call.
            outln!(out);
        }
        let sh_lang_token =
            crate::ai_provider::tool_schema::get_syntax_highlighter_token_from_tool_name(name);
        self.tool_calls.insert(
            output_index,
            JsonObjectAccumulator::new(
                call_id.to_string(),
                name.to_string(),
                sh_lang_token,
                self.masked_strings.clone(),
            ),
        );
        tracing::debug!(call_id, "found tool");
    }

    fn on_tool_args_delta(&mut self, output_index: u64, delta: &str, out: &Out) {
        if let Some(acc) = self.tool_calls.get_mut(&output_index) {
            acc.acc(delta, out);
        } else {
            errorln!(out, "unexpected tool call output index: {}", output_index);
        }
    }

    /// Handles a complete output item (non-streaming, or as a fallback for
    /// streamed items whose deltas were missed).
    fn on_output_item(&mut self, output_index: u64, item: &Value, out: &Out) {
        match item["type"].as_str().unwrap_or_default() {
            "reasoning" => {
                if let Some(parts) = item["summary"].as_array() {
                    for (i, part) in parts.iter().enumerate() {
                        if i > 0 {
                            self.on_reasoning_delta("\n\n", out);
                        }
                        self.on_reasoning_delta(part["text"].as_str().unwrap_or_default(), out);
                    }
                }
            }
            "message" => {
                if let Some(parts) = item["content"].as_array() {
                    for part in parts {
                        match part["type"].as_str().unwrap_or_default() {
                            "output_text" => {
                                self.on_text_delta(part["text"].as_str().unwrap_or_default(), out)
                            }
                            "refusal" => self
                                .on_text_delta(part["refusal"].as_str().unwrap_or_default(), out),
                            _ => {}
                        }
                    }
                }
            }
            "function_call" => {
                if !self.tool_calls.contains_key(&output_index) {
                    self.on_tool_start(
                        output_index,
                        item["call_id"].as_str().unwrap_or_default(),
                        item["name"].as_str().unwrap_or_default(),
                        out,
                    );
                    let args = item["arguments"].as_str().unwrap_or_default();
                    self.on_tool_args_delta(output_index, args, out);
                }
            }
            _ => {}
        }
    }

    fn handle_stream_event(&mut self, ev: &Value, out: &Out) {
        let output_index = ev["output_index"].as_u64().unwrap_or(0);
        let delta = ev["delta"].as_str().unwrap_or_default();
        match ev["type"].as_str().unwrap_or_default() {
            "response.output_text.delta" | "response.refusal.delta" => {
                self.on_text_delta(delta, out);
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                self.on_reasoning_delta(delta, out);
            }
            "response.reasoning_summary_part.added" => {
                if ev["summary_index"].as_u64().unwrap_or(0) > 0 {
                    self.on_reasoning_delta("\n\n", out);
                }
            }
            "response.output_item.added" => {
                let item = &ev["item"];
                if item["type"].as_str() == Some("function_call") {
                    self.on_tool_start(
                        output_index,
                        item["call_id"].as_str().unwrap_or_default(),
                        item["name"].as_str().unwrap_or_default(),
                        out,
                    );
                    let args = item["arguments"].as_str().unwrap_or_default();
                    if !args.is_empty() {
                        self.on_tool_args_delta(output_index, args, out);
                    }
                }
            }
            "response.function_call_arguments.delta" => {
                self.on_tool_args_delta(output_index, delta, out);
            }
            "response.function_call_arguments.done" => {
                // Fallback in case no deltas were received.
                if let Some(acc) = self.tool_calls.get(&output_index)
                    && acc.buffer.is_empty()
                    && let Some(args) = ev["arguments"].as_str()
                {
                    self.on_tool_args_delta(output_index, args, out);
                }
            }
            "response.output_item.done" => {
                let item = &ev["item"];
                if item["type"].as_str() == Some("function_call") {
                    self.on_output_item(output_index, item, out);
                }
            }
            "response.failed" => {
                let msg = ev["response"]["error"]["message"]
                    .as_str()
                    .unwrap_or("unknown error");
                errorln!(out, "response failed: {}", msg);
            }
            "response.incomplete" => {
                let reason = ev["response"]["incomplete_details"]["reason"]
                    .as_str()
                    .unwrap_or("unknown reason");
                errorln!(out, "response incomplete: {}", reason);
            }
            "error" => {
                let msg = ev["message"]
                    .as_str()
                    .or_else(|| ev["error"]["message"].as_str())
                    .unwrap_or("unknown error");
                errorln!(out, "unexpected error: {}", msg);
            }
            _ => {}
        }
    }

    fn interrupted_response(self) -> Vec<chat::ChatCompletionResponse> {
        let text = if let Some((_, tool_call)) = self.tool_calls.into_iter().next() {
            tool_call.printed_text
        } else {
            self.text_accumulator.printed_text
        };
        vec![chat::ChatCompletionResponse::Message {
            text: text + "^CAI Interrupted",
        }]
    }
}

/// Returns (index of boundary start, boundary length) for the first SSE event
/// boundary (blank line) in `buf`.
fn find_sse_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2));
    let crlf = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

/// Extracts the (possibly multi-line) `data` field of an SSE event.
fn sse_event_data(event: &str) -> Option<String> {
    let mut data_lines = vec![];
    for line in event.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        None
    } else {
        Some(data_lines.join("\n"))
    }
}

fn process_sse_event(event_bytes: &[u8], state: &mut ResponseState, out: &Out) {
    let event_str = String::from_utf8_lossy(event_bytes);
    let Some(data) = sse_event_data(&event_str) else {
        return;
    };
    if data.trim() == "[DONE]" {
        return;
    }
    match serde_json::from_str::<Value>(&data) {
        Ok(ev) => state.handle_stream_event(&ev, out),
        Err(e) => tracing::debug!(%data, %e, "failed to parse sse event"),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn send_to_openai(
    out: &Out,
    base_url: Option<&str>,
    api_key: &str,
    provider_header: Option<String>,
    model: &str,
    temperature: Option<f32>,
    history: &[chat::Message],
    tool_schemas: &[Value],
    force_tool_api_name: Option<String>,
    // FIXME: Function doesn't work (exits immediately) if None
    ctrlc_handler: Option<&mut CtrlcHandler>,
    masked_strings: &Vec<String>,
    #[allow(unused_variables)] debug: bool,
    reasoning_effort: &Option<OpenAiReasoningEffort>,
    verbosity: &Option<OpenAiVerbosity>,
) -> Result<Vec<chat::ChatCompletionResponse>, Box<dyn Error>> {
    // Register ctrl+c interrupt handler
    let cancel_info = if let Some(handler) = ctrlc_handler {
        let parent_cancel_token = CancellationToken::new();
        let cancel_token_child = parent_cancel_token.clone();
        let handler_id = handler.add_handler(move || {
            // Signal handler kept light to avoid deadlocking by printing to
            // `out`.
            cancel_token_child.cancel();
        });
        Some((parent_cancel_token, handler_id, handler))
    } else {
        None
    };

    //
    // Build request
    //

    let mut request_body = json!({
        "model": model,
        "input": history_to_input(history),
        "stream": true,
        // Stateless: the full history is sent every time.
        "store": false,
    });
    if let Some(request_obj) = request_body.as_object_mut() {
        // Reasoning models & gpt-5 do not support temperature
        if !model.starts_with("o") && !model.starts_with("gpt-5-") && !model.starts_with("gpt-5.") {
            request_obj.insert("temperature".to_string(), json!(temperature));
        }
        if !tool_schemas.is_empty() {
            // Responses API tools are flat: {type, name, description, parameters}
            let tools: Vec<Value> = tool_schemas
                .iter()
                .map(|schema| {
                    let mut tool = serde_json::Map::new();
                    tool.insert("type".to_string(), json!("function"));
                    if let Some(obj) = schema.as_object() {
                        for (k, v) in obj {
                            tool.insert(k.clone(), v.clone());
                        }
                    }
                    // The Responses API defaults `strict` to true, which
                    // rejects schemas not written for strict mode.
                    tool.entry("strict").or_insert(json!(false));
                    Value::Object(tool)
                })
                .collect();
            request_obj.insert("tools".to_string(), json!(tools));
            if let Some(force_tool_api_name) = &force_tool_api_name {
                request_obj.insert(
                    "tool_choice".to_string(),
                    json!({ "type": "function", "name": force_tool_api_name }),
                );
            } else {
                request_obj.insert("tool_choice".to_string(), json!("auto"));
            }
            request_obj.insert("parallel_tool_calls".to_string(), json!(true));
        }
        if let Some(reasoning_effort) = reasoning_effort {
            let reasoning_effort_str = match reasoning_effort {
                OpenAiReasoningEffort::None => "none",
                OpenAiReasoningEffort::Minimal => "minimal",
                OpenAiReasoningEffort::Low => "low",
                OpenAiReasoningEffort::Medium => "medium",
                OpenAiReasoningEffort::High => "high",
                OpenAiReasoningEffort::Xhigh => "xhigh",
            };
            request_obj.insert(
                "reasoning".to_string(),
                json!({ "effort": reasoning_effort_str }),
            );
        }
        if let Some(verbosity) = verbosity {
            let verbosity_str = match verbosity {
                OpenAiVerbosity::Low => "low",
                OpenAiVerbosity::Medium => "medium",
                OpenAiVerbosity::High => "high",
            };
            request_obj.insert("text".to_string(), json!({ "verbosity": verbosity_str }));
        }
    }
    remove_nulls(&mut request_body);

    //
    // Make API request
    //

    let client = reqwest::Client::builder().use_rustls_tls().build()?;
    let request_setup = client
        .post(format!(
            "{}/responses",
            base_url.unwrap_or("https://api.openai.com/v1")
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))?,
        );
    let request = if let Some(provider_header) = provider_header {
        request_setup
            .header(
                USER_AGENT,
                HeaderValue::from_str(&format!("hai/{}", env!("CARGO_PKG_VERSION")))?,
            )
            .header("HAI-AI-PROVIDER", HeaderValue::from_str(&provider_header)?)
            .json(&request_body)
    } else {
        request_setup.json(&request_body)
    };

    let fat_res = tokio::select! {
        res = request.send() => {
            res
        }
        _ = async {
            if let Some((cancel_token, _, _)) = cancel_info.as_ref() {
                cancel_token.cancelled().await;
            }
        } => {
            if let Some((cancel_token, handler_id, handler)) = cancel_info {
                cancel_token.cancelled().await;
                handler.remove_handler(handler_id);
            }
            outln!(out, "AI Interrupted");
            return Ok(vec![chat::ChatCompletionResponse::Message { text: "^CAI Interrupted".to_string() }]);
        }
    };
    let mut res = fat_res?;

    let _span = tracing::debug_span!("--- openai-responses").entered();

    out.code_reset();

    if res.status() != reqwest::StatusCode::OK {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        if let Some((_, handler_id, handler)) = cancel_info {
            handler.remove_handler(handler_id);
        }
        return Err(format!("{}: {}", status, body).into());
    }

    let mut state = ResponseState::new(masked_strings);
    // Raw bytes are buffered so multi-byte UTF-8 chars split across chunks
    // are decoded correctly.
    let mut buffer: Vec<u8> = Vec::new();

    while let Some(chunk) = tokio::select! {
        chunk = res.chunk() => chunk?,
        _ = async {
            if let Some((cancel_token, _, _)) = cancel_info.as_ref() {
                cancel_token.cancelled().await;
            }
        } => {
            if let Some((cancel_token, handler_id, handler)) = cancel_info {
                cancel_token.cancelled().await;
                handler.remove_handler(handler_id);
            }
            if !out.is_terminal() {
                // If over websockets, emulate the ^C interrupt.
                out!(out, "^C");
            }
            outln!(out, "AI Interrupted");
            return Ok(state.interrupted_response());
        }
    } {
        tracing::debug!(chunk_str = %String::from_utf8_lossy(&chunk), "openai-responses chunk");
        buffer.extend_from_slice(&chunk);
        while let Some((pos, sep_len)) = find_sse_boundary(&buffer) {
            let event: Vec<u8> = buffer.drain(..pos + sep_len).collect();
            process_sse_event(&event[..pos], &mut state, out);
        }
    }

    // Process any trailing event without a terminating blank line.
    if !buffer.is_empty() {
        process_sse_event(&buffer, &mut state, out);
    }

    // Mark accumulators as done to clear buffers
    state.end_reasoning(out);
    state.text_accumulator.end(out);
    for tool_call in state.tool_calls.values_mut() {
        tool_call.end(out);
    }

    // Final newline post-response-stream
    outln!(out);
    if let Some((_, handler_id, handler)) = cancel_info {
        handler.remove_handler(handler_id);
    }

    let mut responses = vec![];
    if !state.text_accumulator.printed_text.is_empty() {
        responses.push(chat::ChatCompletionResponse::Message {
            text: state.text_accumulator.printed_text,
        });
    }
    // BTreeMap iterates in output_index order.
    for (_, tool_call) in state.tool_calls {
        responses.push(chat::ChatCompletionResponse::Tool {
            tool_id: tool_call.tool_id,
            tool_name: tool_call.tool_name,
            arg: tool_call.buffer,
        });
    }
    Ok(responses)
}
