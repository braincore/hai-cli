use serde::{Deserialize, Serialize};

use crate::{config, loader, term};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Message {
    pub role: MessageRole,
    pub content: Vec<MessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip)]
    pub tokens: u32,
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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum MessageContent {
    #[serde(rename = "text")]
    Text { text: String },

    #[serde(rename = "image_url")]
    ImageUrl { image_url: ImageData },
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

pub async fn prompt_to_chat_message_content(
    ai: &config::AiModel,
    prompt: &str,
) -> Vec<MessageContent> {
    let mut msg_content: Vec<MessageContent> = vec![];
    let mut cur_md_group = vec![];

    let md = markdown::to_mdast(prompt, &markdown::ParseOptions::default())
        .expect("Markdown parse failed");

    if let markdown::mdast::Node::Root(root_node) = md {
        for child in root_node.children {
            match child.clone() {
                markdown::mdast::Node::Paragraph(p_node) => {
                    match &p_node.children[0] {
                        markdown::mdast::Node::Image(img_node) => {
                            if !config::get_ai_model_capability(ai).image {
                                eprintln!("error: model does not support images");
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
                            let image_b64_res = loader::resolve_image_b64(&img_node.url).await;
                            match image_b64_res {
                                Ok(encoded_image) => {
                                    msg_content.push(MessageContent::ImageUrl {
                                        image_url: ImageData {
                                            detail: "low".to_string(),
                                            url: format!(
                                                "data:image/png;base64,{}",
                                                &encoded_image
                                            ),
                                        },
                                    });
                                    term::print_image_to_term(&encoded_image).unwrap();
                                }
                                Err(e) => {
                                    println!("Failed to encode image: {}", e);
                                    continue; // Skip sending if image encoding fails
                                }
                            }
                        }
                        _ => {
                            cur_md_group.push(child);
                        }
                    }
                }
                markdown::mdast::Node::Code(code_node) => {
                    use syntect::easy::HighlightLines;
                    use syntect::highlighting::{Style, ThemeSet};
                    use syntect::parsing::SyntaxSet;
                    use syntect::util::{as_24_bit_terminal_escaped, LinesWithEndings};

                    // Load these once at the start of your program
                    let ps = SyntaxSet::load_defaults_newlines();
                    let ts = ThemeSet::load_defaults();

                    // List all theme names
                    for theme_name in ts.themes.keys() {
                        println!("{}", theme_name);
                    }

                    //let syntax = ps.find_syntax_by_extension("rs").unwrap();
                    let syntax = if let Some(ref lang) = code_node.lang {
                        ps.find_syntax_by_token(lang)
                    } else {
                        ps.find_syntax_by_token(&code_node.value)
                    }
                    .unwrap_or(ps.find_syntax_plain_text());

                    println!("Syntax: {:?}", syntax.name);

                    //let mut h = HighlightLines::new(syntax, &ts.themes["base16-ocean.dark"]);
                    let mut h = HighlightLines::new(syntax, &ts.themes["Solarized (dark)"]);
                    //let s = "pub struct Wow { hi: u64 }\nfn blah() -> u64 {}";
                    println!("```{}", code_node.lang.unwrap_or("".to_string()));
                    for line in LinesWithEndings::from(&code_node.value) {
                        let ranges: Vec<(Style, &str)> = h.highlight_line(line, &ps).unwrap();
                        let escaped = as_24_bit_terminal_escaped(&ranges[..], false);
                        print!("{}", escaped);
                    }
                    print!("\n");
                    println!("```");
                }
                _ => {
                    cur_md_group.push(child);
                }
            }
        }
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
    }
    msg_content
}
