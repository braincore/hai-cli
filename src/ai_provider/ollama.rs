use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use tokio_util::sync::CancellationToken;

use crate::ai_provider::tool_schema::get_tool_schema;
use crate::ai_provider::util::{JsonObjectAccumulator, TextAccumulator, remove_nulls, run_jaq};
use crate::chat;
use crate::config;
use crate::ctrlc_handler::CtrlcHandler;
use crate::tool;

//
// End Ollama Response Types
//

#[allow(clippy::too_many_arguments)]
pub async fn send_to_ollama(
    base_url: Option<&str>,
    model: &str,
    temperature: Option<f32>,
    history: &[chat::Message],
    tool_policy: Option<&tool::ToolPolicy>,
    shell: &str,
    // FIXME: Function doesn't work (exits immediately) if None
    ctrlc_handler: Option<&mut CtrlcHandler>,
    masked_strings: &Vec<String>,
    debug: bool,
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
    let mut tool_schemas = vec![];
    if let Some(tp) = tool_policy {
        tool_schemas.push(get_tool_schema(&tp.tool, "parameters", shell))
    }
    let mut request_body = if tool_schemas.is_empty() {
        json!({
            "model": model,
            "temperature": temperature,
            "messages": messages,
            "stream": true,
        })
    } else {
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
        json!({
            "model": model,
            "temperature": temperature,
            "messages": messages,
            "stream": false,
            "tools": function_wrappers,
        })
    };
    remove_nulls(&mut request_body);

    let jq_transforms = [
        // Image transform
        // NOTE: This leaves the image_url objects in content. It's up to the
        // message_transform to filter these out.
        r#"
        .messages |= map(
            . + if any(.content[]; .type == "image_url") then
                {
                images: [
                    .content[]
                    | select(.type == "image_url")
                    | .image_url.url
                    | capture("^data:image/[^;]+;base64,(?<base64>.+)$")
                    | .base64
                ]
                }
            else
                {}
            end
            )
        "#,
        // Messages transform
        // NOTE: The non-string contents are lost, but we assume the
        // image_transform above has already copied them to the `images` key.
        r#"
        .messages |= map(
            .content |= (
                map(
                    if .type == "text" then .text else . end
                ) | map(select(type == "string")) | join("")
            )
        )"#,
        // Tool call arguments transform
        r#"
        .messages |= map(
            if .role == "assistant" and has("tool_calls") then
                .tool_calls |= map(
                if .function.arguments | type == "string" then
                    .function.arguments |= {"input": .}
                else
                    .
                end
                )
            else
                .
            end
            )"#,
    ];
    for jq_transform in jq_transforms {
        request_body = run_jaq(jq_transform, &request_body).unwrap();
    }

    //
    // Make API request
    //
    let client = reqwest::Client::new();
    let request = client
        .post(format!(
            "{}/api/chat",
            base_url.unwrap_or("http://localhost:11434")
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&request_body);

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

    if debug {
        config::write_to_debug_log(format!("--- ollama {:?}\n", tool_policy))?;
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
                        if let Ok(tool_response) = serde_json::from_value::<serde_json::Value>(
                            json_data["message"]["tool_calls"][0]["function"].clone(),
                        ) && !tool_response.is_null()
                        {
                            let tool_name = tool_response["name"].as_str().unwrap().to_string();
                            // HACK: Just serialize it again to re-use machinery.
                            let arguments =
                                serde_json::to_string(&tool_response["arguments"]).unwrap();
                            tool_calls.insert(
                                0,
                                JsonObjectAccumulator::new(
                                    "STUB".to_string(),
                                    tool_name,
                                    tool_policy.and_then(|tp| {
                                        tool::get_tool_syntax_highlighter_lang_token(&tp.tool)
                                    }),
                                    masked_strings.clone(),
                                ),
                            );
                            if let Some(json_accumulator) = tool_calls.get_mut(&0) {
                                json_accumulator.acc(&arguments);
                            } else {
                                eprintln!("error: unexpected tool call ID: {}", 0);
                            }
                            break;
                        }
                        if let Some(content) = json_data["message"]["content"].as_str() {
                            text_accumulator.acc(content);
                        } else if let Some(message) = json_data["error"].as_str() {
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
        let (_key, tool_call) = tool_calls.into_iter().next().unwrap();
        responses.push(chat::ChatCompletionResponse::Tool {
            tool_id: tool_call.tool_id,
            tool_name: tool_call.tool_name,
            arg: tool_call.buffer,
        });
    }
    Ok(responses)
}
