use colored::*;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use tokio_util::sync::CancellationToken;

use crate::ai_provider::tool_schema::get_tool_schema;
use crate::ai_provider::util::{remove_nulls, run_jaq, JsonObjectAccumulator, TextAccumulator};
use crate::chat;
use crate::config;
use crate::ctrlc_handler::CtrlcHandler;
use crate::tool;

//
// Start OpenAI Response Types
// - Some bozos "designed" their types
//

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ToolCallResponse {
    // After first response, it's empty.
    id: Option<String>,
    // The default is only required for Google Gemini's OpenAI compat endpoint.
    // It's omitted.
    #[serde(default)]
    index: u32,
    // AFAICT it's "function" on first response, then empty
    #[serde(rename = "type")]
    pub type_: Option<String>,
    function: FunctionResponse,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ToolCallNonStreamingResponse {
    id: String,
    function: FunctionResponse,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct FunctionResponse {
    name: Option<String>, // after first response, this is empty
    arguments: String,
}

//
// End OpenAI Response Types
//

#[allow(clippy::too_many_arguments)]
pub async fn send_to_openai(
    base_url: Option<&str>,
    api_key: &str,
    provider_header: Option<String>,
    model: &str,
    temperature: Option<f32>,
    history: &[chat::Message],
    tool_policy: Option<&tool::ToolPolicy>,
    // FIXME: Function doesn't work (exits immediately) if None
    ctrlc_handler: Option<&mut CtrlcHandler>,
    masked_strings: &HashSet<String>,
    debug: bool,
    deepseek_flatten_nonuser_content: bool, // DeepSeek specific
) -> Result<Vec<chat::ChatCompletionResponse>, Box<dyn Error>> {
    let messages: Vec<_> = history.iter().map(|msg| json!(msg)).collect();

    // Register ctrl+c interrupt handler
    // NOTE: This handler prints "AI Interrupted" but the tokio code actually
    // adds "AI Interrupted" into the output text.
    let cancel_info = if let Some(handler) = ctrlc_handler {
        let parent_cancel_token = CancellationToken::new();
        let cancel_token_child = parent_cancel_token.clone();
        let handler_id = handler.add_handler(move || {
            println!("AI Interrupted");
            cancel_token_child.cancel();
        });
        Some((parent_cancel_token, handler_id, handler))
    } else {
        None
    };

    // Create JSON payload
    let stream = !model.starts_with("o1"); // o1 model does not support streaming
    let mut request_body = json!({
        "model": model,
        "messages": messages,
        "stream": stream,
    });
    if let Some(request_obj) = request_body.as_object_mut() {
        if stream {
            request_obj.insert(
                "stream_options".to_string(),
                json!({
                    "include_usage": true,
                }),
            );
        }
        // Reasoning models don't support temperature
        if !model.starts_with("o") {
            request_obj.insert("temperature".to_string(), json!(temperature));
        }
        if let Some(tp) = tool_policy {
            let tool_schemas = vec![get_tool_schema(&tp.tool, "parameters")];
            let tool_choice = if tp.require { "required" } else { "auto" };
            // OpenAI has a wrapping over each tool schema.
            let function_wrappers: Vec<serde_json::Value> = tool_schemas
                .into_iter()
                .map(|value| {
                    json!({
                        "type": "function",
                        "function": value,
                    })
                })
                .collect();
            request_obj.insert("tools".to_string(), json!(function_wrappers));
            request_obj.insert("tool_choice".to_string(), json!(tool_choice));
            // Explicitly disable parallel tool calling. While this function
            // supports it, callers are currently unprepared to structure the
            // message history correctly.
            request_obj.insert("parallel_tool_calls".to_string(), json!(false));
        }
    }
    remove_nulls(&mut request_body);

    // Non-OpenAI APIs can return longer than 40char tool IDs which cause
    // OpenAI to error out. This filter simply truncates the tool ID.
    let truncate_tool_id_transform = r#"
        .messages |= map(
            (
                if has("tool_calls") and .tool_calls != null then
                    .tool_calls |= map(.id |= (.[:40]))
                else
                    .
                end)
            |
            (   if has("tool_call_id") then
                    .tool_call_id |= if . != null then .[:40]
                else
                    .
                end
            else
                .
            end)
            )
        "#;
    request_body = run_jaq(truncate_tool_id_transform, &request_body).unwrap();

    if deepseek_flatten_nonuser_content {
        // Deepseek requires assistant & tool messages to have `content`
        // as a string. The OpenAI list format is not accepted.
        let flatten_nonuser_content_transform = r#"
        .messages |= map(
            if (.role == "assistant" or .role == "tool") then
                .content |= (
                map(
                    if .type == "text" then .text else . end
                ) | map(select(type == "string")) | join("")
                )
            else
                .
            end
            )
        "#;
        request_body = run_jaq(flatten_nonuser_content_transform, &request_body).unwrap();
    }

    //
    // Make API request
    //

    // rustls-tls is required to work with Google Gemini's OpenAI-compat API.
    // native-tls fails with "Request contains an invalid argument."
    let client = reqwest::Client::builder().use_rustls_tls().build()?;
    let request_setup = client
        .post(format!(
            "{}/chat/completions",
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
        // Send the request and wait for the result
        res = request.send() => {
            res
        }

        // If a cancellation signal is received, exit early
        _ = async {
            if let Some((cancel_token, _, _)) = cancel_info.as_ref() {
                cancel_token.cancelled().await;
            }
        } => {
            if let Some((cancel_token, handler_id, handler)) = cancel_info {
                cancel_token.cancelled().await;
                handler.remove_handler(handler_id);
            }
            return Ok(vec![chat::ChatCompletionResponse::Message { text: "^CAI Interrupted".to_string() }]);
        }
    };
    let mut res = fat_res?;

    // Buffer of top-level JSON blobs that haven't been processed
    let mut buffer = String::new();
    let mut text_accumulator = TextAccumulator::new(masked_strings.clone());
    let mut tool_calls = HashMap::<u32, JsonObjectAccumulator>::new();

    // Deepseek-reasoner only
    let mut reasoning_accumulator = TextAccumulator::new(masked_strings.clone());

    if debug {
        config::write_to_debug_log(format!("--- openai {:?}\n", tool_policy))?;
    }
    if res.status() != reqwest::StatusCode::OK {
        let err_msg = format!(
            "{}: {}",
            res.status(),
            String::from_utf8_lossy(&res.chunk().await?.unwrap_or_default())
        );
        return Err(err_msg.into());
    }
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
            if !tool_calls.is_empty() {
                let (_key, tool_call) = tool_calls.into_iter().next().unwrap();
                return Ok(vec![chat::ChatCompletionResponse::Message {
                    text: tool_call.printed_text + "^CAI Interrupted",
                }])
            } else {
                return Ok(vec![chat::ChatCompletionResponse::Message { text: text_accumulator.printed_text + "^CAI Interrupted" }])
            }
        }
    } {
        let chunk_str = String::from_utf8_lossy(&chunk);
        if debug {
            config::write_to_debug_log(chunk_str.to_string())?;
        }
        buffer.push_str(&chunk_str);
        loop {
            let json_start = buffer.find('{');
            if let Some(json_start_index) = json_start {
                let mut json_length = None;
                for (i, ch) in buffer.char_indices() {
                    if i <= json_start_index {
                        continue;
                    }
                    if ch != '}' {
                        continue;
                    }
                    if let Ok(json_data) =
                        serde_json::from_str::<serde_json::Value>(&buffer[json_start_index..=i])
                    {
                        json_length = Some(i + 1);
                        if let Ok(tool_response) = serde_json::from_value::<ToolCallResponse>(
                            json_data["choices"][0]["delta"]["tool_calls"][0].clone(),
                        ) {
                            if let Some(tool_id) = tool_response.id {
                                if let Some(tool_name) = tool_response.function.name {
                                    if !tool_calls.is_empty() {
                                        println!();
                                        println!();
                                        println!("∥");
                                        println!();
                                    } else if !text_accumulator.printed_text.is_empty() {
                                        // For cases where a tool-response follows a text-response, add
                                        // a newline to make the output clearer.
                                        // AFAICT, both responses will have index=0 set so delineating
                                        // between the two that way isn't doable.
                                        println!();
                                    }
                                    // Gemini returns an empty string as the
                                    // tool ID which the Anthropic API is not
                                    // happy with.
                                    let tool_id = if tool_id.is_empty() {
                                        "gemini-is-bad".to_string()
                                    } else {
                                        tool_id
                                    };
                                    tool_calls.insert(
                                        tool_response.index,
                                        JsonObjectAccumulator::new(
                                            tool_id.clone(),
                                            tool_name,
                                            masked_strings.clone(),
                                        ),
                                    );
                                    if debug {
                                        config::write_to_debug_log(format!(
                                            "found: tool_id: {}\n",
                                            tool_id
                                        ))?;
                                    }
                                }
                            }
                            if let Some(json_accumulator) = tool_calls.get_mut(&tool_response.index)
                            {
                                json_accumulator.acc(&tool_response.function.arguments)
                            } else {
                                eprintln!(
                                    "error: unexpected tool call ID: {}",
                                    tool_response.index
                                );
                            }
                        } else if let Some(content) =
                            json_data["choices"][0]["delta"]["content"].as_str()
                        {
                            if text_accumulator.printed_text.is_empty()
                                && !reasoning_accumulator.printed_text.is_empty()
                            {
                                println!();
                                println!();
                                println!("{}", "🧠 end".white().on_black());
                                println!();
                            }
                            text_accumulator.acc(content);
                        } else if let Some(content) =
                            json_data["choices"][0]["delta"]["reasoning_content"].as_str()
                        {
                            if reasoning_accumulator.printed_text.is_empty() && !content.is_empty()
                            {
                                println!("{}", "🧠 begin".white().on_black());
                                println!();
                            }
                            reasoning_accumulator.acc(content);
                        } else if let Some(content) =
                            json_data["choices"][0]["message"]["content"].as_str()
                        {
                            // This is for non-streaming cases
                            text_accumulator.acc(content);
                        } else if let Ok(tool_response) =
                            serde_json::from_value::<ToolCallNonStreamingResponse>(
                                json_data["choices"][0]["message"]["tool_calls"][0].clone(),
                            )
                        {
                            // This is for non-streaming cases
                            if let Some(tool_name) = tool_response.function.name {
                                let mut json_accumulator = JsonObjectAccumulator::new(
                                    tool_response.id,
                                    tool_name,
                                    masked_strings.clone(),
                                );
                                json_accumulator.acc(&tool_response.function.arguments);
                                tool_calls.insert(0, json_accumulator);
                            }
                        } else if let Some(message) = json_data["error"]["message"].as_str() {
                            eprintln!("unexpected error: {}", message);
                        }
                        break;
                    }
                }
                // If we found a JSON blob, remove it from the buffer
                if let Some(length) = json_length {
                    buffer.drain(0..length);
                } else {
                    // No valid JSON blob found; wait for more strings
                    break;
                }
            } else {
                break;
            }
        }
    }
    // Mark accumulators as done to clear buffers
    text_accumulator.end();
    for tool_call in tool_calls.values_mut() {
        tool_call.end();
    }

    // Final newline post-response-stream
    println!();
    if let Some((_, handler_id, handler)) = cancel_info {
        handler.remove_handler(handler_id);
    }
    let mut responses = vec![];
    if !text_accumulator.printed_text.is_empty() {
        responses.push(chat::ChatCompletionResponse::Message {
            text: text_accumulator.printed_text,
        });
    }
    if !tool_calls.is_empty() {
        // Convert the map entries to a vector so we can sort them
        let mut tool_call_entries: Vec<_> = tool_calls.into_iter().collect();
        // Sort by key (assuming keys are integers)
        tool_call_entries.sort_by_key(|(key, _)| *key);

        // Add each tool call to responses in sorted order
        for (_, tool_call) in tool_call_entries {
            responses.push(chat::ChatCompletionResponse::Tool {
                tool_id: tool_call.tool_id,
                tool_name: tool_call.tool_name,
                arg: tool_call.buffer,
            });
        }
    }
    Ok(responses)
}
