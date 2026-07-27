use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errorln;
use crate::io::Out;
use crate::{config, loader, session};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Message {
    pub role: MessageRole,
    pub content: Vec<MessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub function: Function,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Function {
    pub name: String,
    // WARN: The string is a JSON-encoded object/map. This is inline with the
    // OpenAI API. However, the Anthropic API wants `arguments` as an object
    // structure (i.e. deserialized JSON). We use the OpenAI format as
    // canonical, but in the anthropic adapter we transform arguments by JSON-
    // deserializing the string.
    pub arguments: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl MessageRole {
    pub fn to_str(&self) -> &'static str {
        match self {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
            MessageRole::Tool => "tool",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum MessageContent {
    #[serde(rename = "text")]
    Text { text: String },

    #[serde(rename = "image_url")]
    ImageUrl {
        /// Only assigned when attachment is created
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<Uuid>,
        image_url: ImageData,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ImageData {
    pub url: String,
    pub detail: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ChatCompletionResponse {
    Message {
        text: String,
    },
    Tool {
        tool_id: String,
        tool_name: String,
        arg: String,
    },
}

/// # Returns
///
/// (message_content, token_count)
///
/// The `token_count` is ballpark. It's the token count of the entire `prompt`
/// with additional tokens for each input image (low res).
pub async fn prompt_to_chat_message_content(
    out: &Out,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    ai: &config::AiModel,
    prompt: &str,
) -> (Vec<MessageContent>, u32) {
    let mut msg_content: Vec<MessageContent> = vec![];
    let mut cur_md_group = vec![];

    let mut tokens = bpe_tokenizer.encode_with_special_tokens(&prompt).len() as u32;

    let md = markdown::to_mdast(prompt, &markdown::ParseOptions::default())
        .expect("Markdown parse failed");

    if let markdown::mdast::Node::Root(root_node) = md {
        for child in root_node.children {
            match child.clone() {
                markdown::mdast::Node::Paragraph(p_node) => {
                    match &p_node.children[0] {
                        markdown::mdast::Node::Image(img_node) => {
                            if config::get_ai_model_capability(ai).image.is_none() {
                                errorln!(out, "model does not support images");
                                continue;
                            }
                            if !cur_md_group.is_empty() {
                                if let Ok(cur_md_group_text) = mdast_util_to_markdown::to_markdown(
                                    &markdown::mdast::Node::Root(markdown::mdast::Root {
                                        children: cur_md_group,
                                        position: None,
                                    }),
                                ) {
                                    msg_content.push(MessageContent::Text {
                                        text: cur_md_group_text,
                                    });
                                }
                                cur_md_group = vec![];
                            }
                            let image_b64_res =
                                loader::resolve_image_b64(&img_node.url, true).await;
                            match image_b64_res {
                                Ok((img_png_b64, img_dim)) => {
                                    tokens += session::calc_image_tokens(ai, false, img_dim);
                                    msg_content.push(MessageContent::ImageUrl {
                                        id: Some(Uuid::now_v7()),
                                        image_url: ImageData {
                                            detail: "low".to_string(),
                                            url: format!("data:image/png;base64,{}", &img_png_b64),
                                        },
                                    });
                                    out.display("image/png", &img_png_b64);
                                }
                                Err(e) => {
                                    errorln!(out, "Failed to encode image: {}", e);
                                    continue; // Skip sending if image encoding fails
                                }
                            }
                        }
                        _ => {
                            cur_md_group.push(child);
                        }
                    }
                }
                _ => {
                    cur_md_group.push(child);
                }
            }
        }
    }

    if !cur_md_group.is_empty()
        && let Ok(cur_md_group_text) = mdast_util_to_markdown::to_markdown(
            &markdown::mdast::Node::Root(markdown::mdast::Root {
                children: cur_md_group,
                position: None,
            }),
        )
    {
        let cur_md_group_text_trimmed = if prompt.ends_with('\n') {
            &cur_md_group_text
        } else {
            // Markdown parsing adds a single trailing newline, which we trim
            // here if the original prompt did not have one.
            cur_md_group_text
                .strip_suffix('\n')
                .unwrap_or(&cur_md_group_text)
        };
        tokens += bpe_tokenizer
            .encode_with_special_tokens(&cur_md_group_text_trimmed)
            .len() as u32;
        msg_content.push(MessageContent::Text {
            text: cur_md_group_text_trimmed.to_string(),
        });
    }
    (msg_content, tokens)
}
