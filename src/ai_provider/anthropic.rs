use colored::*;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use tokio_util::sync::CancellationToken;

use crate::ai_provider::tool_schema::{get_tool_from_name, get_tool_name, get_tool_schema};
use crate::ai_provider::util::{remove_nulls, run_jaq, JsonObjectAccumulator, TextAccumulator};
use crate::chat;
use crate::config;
use crate::ctrlc_handler::CtrlcHandler;
use crate::tool;

//
// Begin Anthropic Response Types
//

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamResponse {
    ContentBlockDelta {
        index: u32,
        delta: ContentDelta,
    },
    ContentBlockStart {
        index: u32,
        content_block: ContentBlockType,
    },
    ContentBlockStop {
        index: u32,
    },
    MessageDelta {
        delta: MessageDeltaInfo,
    },
    MessageStart {
        message: MessageStart,
    },
    MessageStop {},
    Ping,
    Error {
        error: ErrorResponse,
    },
}

#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum ContentDelta {
    TextDelta { text: String },
    ThinkingDelta { thinking: String },
    InputJsonDelta { partial_json: String },
    SignatureDelta { signature: String },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum ContentBlockType {
    Text { text: String },
    ToolUse { id: String, name: String },
    Thinking { thinking: String, signature: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContentText {
    text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageDeltaInfo {
    stop_reason: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageStart {
    id: String,
    role: chat::MessageRole,
    model: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    #[serde(rename = "type")]
    type_: String,
    message: String,
}

//
// End Anthropic Response Types
//

#[allow(clippy::too_many_arguments)]
pub async fn send_to_anthropic(
    api_url: Option<&str>,
    api_key: &str,
    provider_header: Option<String>,
    model: &str,
    use_thinking: bool,
    temperature: Option<f32>,
    history: &[chat::Message],
    tool_policy: Option<&tool::ToolPolicy>,
    shell: &str,
    // FIXME: Function doesn't work (exits immediately) if None
    ctrlc_handler: Option<&mut CtrlcHandler>,
    masked_strings: &HashSet<String>,
    debug: bool,
) -> Result<Vec<chat::ChatCompletionResponse>, Box<dyn Error>> {
    // Prepare messages in Anthropic format
    // Assuming similar format, modify as per actual API requirements if needed
    let messages: Vec<_> = history
        .iter()
        .map(|msg| {
            // Transform or use directly if compatible
            json!(msg)
        })
        .collect();

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

    // Set up HTTP headers
    let mut headers = HeaderMap::new();
    headers.insert("anthropic-version", HeaderValue::from_str("2023-06-01")?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(provider_header) = provider_header {
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&format!("hai/{}", env!("CARGO_PKG_VERSION")))?,
        );
        headers.insert("HAI-AI-PROVIDER", HeaderValue::from_str(&provider_header)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))?,
        );
    } else {
        headers.insert("x-api-key", HeaderValue::from_str(api_key)?);
    }

    // Create the JSON payload
    let mut tool_schemas = vec![];

    let mut tools_added = HashSet::new();
    for message in history {
        if let Some(ref tool_calls) = message.tool_calls {
            for tool_call in tool_calls {
                if tools_added.contains(&tool_call.function.name) {
                    continue;
                }
                tools_added.insert(tool_call.function.name.clone());
                // WARN: If a shell-exec-with-{file,stdin} was used previously,
                // this recreation of the tool-schema will be highly inaccurate
                // since shell-cmd is not populated by get_tool_from_name()!
                // WARN: There's a serious issue if the name isn't present
                if let Some(tool) = get_tool_from_name(&tool_call.function.name) {
                    tool_schemas.push(get_tool_schema(&tool, "input_schema", shell))
                }
            }
        }
    }
    let tool_choice = if let Some(tp) = tool_policy {
        let tool_name = get_tool_name(&tp.tool);
        if !tools_added.contains(tool_name) {
            tool_schemas.push(get_tool_schema(&tp.tool, "input_schema", shell))
        }
        if tp.force_tool {
            Some(json!({"type": "tool", "name": tool_name}))
        } else {
            Some(json!({"type": "auto"}))
        }
    } else {
        // This is for the case where there's no `tool_policy` but tool schemas
        // are added due to the history. Ideally, we'd force tool_choice off
        // but that isn't an option.
        Some(json!({"type": "auto"}))
    };
    let mut request_body = if tool_schemas.is_empty() {
        json!({
            "max_tokens": 8192,
            "model": model,
            "temperature": temperature,
            "messages": messages,
            "stream": true,
        })
    } else {
        json!({
            "max_tokens": 8192,
            "model": model,
            "temperature": temperature,
            "messages": messages,
            "stream": true,
            "tools": tool_schemas,
            "tool_choice": tool_choice,
        })
    };
    if let Some(request_obj) = request_body.as_object_mut() {
        if use_thinking {
            request_obj.insert(
                "thinking".to_string(),
                json!({
                    "type": "enabled",
                    "budget_tokens": 4096,
                }),
            );
            // API requires thinking to be set to 1 if thinking is enabled.
            request_obj.insert("temperature".to_string(), json!(1));
        }
    }
    remove_nulls(&mut request_body);

    let jq_transforms = [
        // Image transform
        r#"
        .messages[] |=
            .content |= map(
                if .type == "image_url" then
                {
                    type: "image",
                    source: {
                    type: "base64",
                    media_type: (.image_url.url | split(";")[0] | split(":")[1]),
                    data: (.image_url.url | split(",")[1])
                    }
                }
                else
                . # Keep the original object if not an image_url
                end
        )"#,
        // Tool result transform
        r#"
        (.messages) as $msgs
            | .messages = (
                reduce range(0; $msgs|length) as $i (
                    { arr: [], skip: false };
                    if .skip then
                    { arr: .arr, skip: false }
                    else
                    if ($i < ($msgs|length - 1))
                        and ($msgs[$i].role == "tool")
                        and ($msgs[$i+1].role == "user")
                    then
                        {
                        arr: .arr + [
                            $msgs[$i+1]
                            | .content |= (
                                [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": $msgs[$i].tool_call_id,
                                    "content": $msgs[$i].content
                                }
                                ]
                                + .
                            )
                        ],
                        skip: true
                        }
                    else
                        {
                        arr: .arr + [ $msgs[$i] ],
                        skip: false
                        }
                    end
                    end
                )
                | .arr
                )
        "#,
        // Tool calls transform
        r#"
        .messages |= map(
            if .role == "assistant" and has("tool_calls") then
            .content += (
                .tool_calls 
                | map({
                    "type": "tool_use",
                    "id": .id,
                    "name": .function.name,
                    "input": .function.arguments | fromjson
                })
            )
            | del(.tool_calls)
            else
            .
            end
        )
        "#,
    ];

    for jq_transform in jq_transforms {
        request_body = run_jaq(jq_transform, &request_body).unwrap();
    }

    // Make the HTTP request
    let client = reqwest::Client::new();
    let request = client
        .post(api_url.unwrap_or("https://api.anthropic.com/v1/messages"))
        .headers(headers)
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

    let mut buffer = String::new();
    // Used to sanity check that content_block_data.index is monotonically
    // increasing. Unclear if this is actually an invariant.
    let mut cur_content_block_index = 0;

    let mut content_blocks = HashMap::<u32, ContentBlockType>::new();
    let mut text_accumulator = TextAccumulator::new(masked_strings.clone());
    let mut thinking_accumulator = TextAccumulator::new(masked_strings.clone());
    let mut tool_calls = HashMap::<u32, JsonObjectAccumulator>::new();

    if debug {
        config::write_to_debug_log("--- anthropic\n".to_string())?;
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
                    if let Ok(stream_resp) =
                        serde_json::from_str::<MessageStreamResponse>(&buffer[json_start_index..=i])
                    {
                        json_length = Some(i + 1);
                        match stream_resp {
                            MessageStreamResponse::ContentBlockDelta { index, delta } => {
                                if index < cur_content_block_index {
                                    eprintln!("error: unexpected index went backwards: {}", index);
                                } else {
                                    cur_content_block_index = index;
                                }
                                match delta {
                                    ContentDelta::TextDelta { text: delta_text } => {
                                        text_accumulator.acc(&delta_text);
                                    }
                                    ContentDelta::ThinkingDelta {
                                        thinking: delta_thinking,
                                    } => {
                                        thinking_accumulator.acc(&delta_thinking);
                                    }
                                    ContentDelta::InputJsonDelta { partial_json } => {
                                        if let Some(json_accumulator) = tool_calls.get_mut(&index) {
                                            json_accumulator.acc(&partial_json)
                                        } else {
                                            eprintln!("error: unexpected tool call ID: {}", index);
                                        }
                                    }
                                    ContentDelta::SignatureDelta { .. } => {}
                                }
                            }
                            MessageStreamResponse::ContentBlockStart {
                                index,
                                content_block,
                            } => {
                                if index < cur_content_block_index {
                                    eprintln!("error: unexpected index went backwards: {}", index);
                                } else {
                                    cur_content_block_index = index;
                                }
                                content_blocks.insert(index, content_block.clone());
                                if index > 0 {
                                    // Space out from previous content block
                                    println!();
                                }
                                match content_block {
                                    ContentBlockType::Text {
                                        text: content_block_text,
                                    } => {
                                        text_accumulator.acc(&content_block_text);
                                    }
                                    ContentBlockType::Thinking {
                                        thinking: thinking_text,
                                        ..
                                    } => {
                                        println!("{}", "🧠 begin".white().on_black());
                                        println!();
                                        text_accumulator.acc(&thinking_text);
                                    }
                                    ContentBlockType::ToolUse { id, name } => {
                                        // Bit of a HACK, but an extra space tends to be necessary
                                        // before tool-use instructions.
                                        println!();
                                        tool_calls.insert(
                                            index,
                                            JsonObjectAccumulator::new(
                                                id,
                                                name,
                                                tool_policy.and_then(|tp| {
                                                    tool::get_tool_syntax_highlighter_lang_token(
                                                        &tp.tool,
                                                    )
                                                }),
                                                masked_strings.clone(),
                                            ),
                                        );
                                    }
                                }
                            }
                            MessageStreamResponse::ContentBlockStop { index } => {
                                if let Some(ContentBlockType::Thinking { .. }) =
                                    content_blocks.get(&index)
                                {
                                    println!();
                                    println!();
                                    println!("{}", "🧠 end".white().on_black());
                                }
                            }
                            MessageStreamResponse::Error { error } => {
                                eprintln!("unexpected error: {}: {}", error.type_, error.message);
                            }
                            _ => {}
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

    println!(); // Final newline after streaming is complete
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
