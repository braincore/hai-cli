pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod openai_responses;
pub mod tool_schema;
pub mod usage;
pub mod util;
pub mod void;

/// What every AI provider returns.
#[derive(Debug)]
pub struct AiProviderResponse {
    pub responses: Vec<crate::chat::ChatCompletionResponse>,
    /// None if the provider didn't report usage (or the request was
    /// interrupted).
    pub usage: Option<crate::ai_provider::usage::TokenUsage>,
}

impl AiProviderResponse {
    pub fn interrupted(printed_text: String) -> Self {
        AiProviderResponse {
            responses: vec![crate::chat::ChatCompletionResponse::Message {
                text: printed_text + "^CAI Interrupted",
            }],
            usage: None,
        }
    }
}
