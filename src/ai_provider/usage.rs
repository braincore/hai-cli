use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::ops::{Add, AddAssign};

/// Normalized token usage across different AI providers.
///
/// The one rule with the token usage fields in this struct is that each
/// category of token usage is disjoint from the others (i.e. none are
/// supersets of others).
///
/// DANGER: The serialized form is stored in chat logs and is part of the
/// websocket i/o interface for assistant messages. Do not change in
/// incompatible ways.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Input tokens that were neither read from nor written to the cache.
    /// Excludes `cache_read_tokens` and `cache_write_tokens`.
    pub input_tokens: u64,
    /// Input tokens served from the prompt cache.
    pub cache_read_tokens: u64,
    /// Input tokens written to the prompt cache. Was originally
    /// Anthropic-specific, but OpenAI's GPT-6 has followed by making caching
    /// an explicit opt-in (with additional charge).
    pub cache_write_tokens: u64,
    /// Output tokens, excluding `reasoning_tokens`.
    pub output_tokens: u64,
    /// Reasoning tokens.
    ///
    /// This breakout isn't critical for cost-analysis as reasoning tokens are
    /// just another form of output tokens. In fact, Anthropic & ollama do not
    /// report it separately (always set to 0).
    pub reasoning_tokens: u64,
}

/// Quick convert a `serde_json::Value` to `u64` (default to 0).
fn as_u64(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

impl TokenUsage {
    /// All input tokens: uncached + cache read + cache write.
    pub fn total_input_tokens(&self) -> u64 {
        self.input_tokens + self.cache_read_tokens + self.cache_write_tokens
    }

    /// All output tokens: visible output + reasoning.
    pub fn total_output_tokens(&self) -> u64 {
        self.output_tokens + self.reasoning_tokens
    }

    pub fn total_tokens(&self) -> u64 {
        self.total_input_tokens() + self.total_output_tokens()
    }

    /// Parses the `usage` object of the OpenAI chat completions API and its
    /// many OpenAI-compatible variants (Google, DeepSeek, xAI, llama.cpp).
    pub fn from_openai_chat(usage: &Value) -> Option<Self> {
        if usage.get("prompt_tokens").is_none() && usage.get("completion_tokens").is_none() {
            return None;
        }
        let prompt = as_u64(&usage["prompt_tokens"]);
        let completion = as_u64(&usage["completion_tokens"]);
        // OpenAI/xAI: prompt_tokens_details.cached_tokens
        // DeepSeek: prompt_cache_hit_tokens
        let cached = usage["prompt_tokens_details"]["cached_tokens"]
            .as_u64()
            .or_else(|| usage["prompt_cache_hit_tokens"].as_u64())
            .unwrap_or(0)
            .min(prompt);
        let reported_reasoning = as_u64(&usage["completion_tokens_details"]["reasoning_tokens"]);
        let total = usage["total_tokens"].as_u64();

        // OpenAI & DeepSeek include reasoning in completion_tokens. xAI and
        // Gemini do not, but we can detect this generically by comparing:
        // total_tokens > prompt + completion (difference is reasoning tokens)
        let (output, reasoning) = match total {
            Some(t) if reported_reasoning > 0 && t == prompt + completion + reported_reasoning => {
                (completion, reported_reasoning)
            }
            Some(t) if reported_reasoning == 0 && t > prompt + completion => {
                (completion, t - prompt - completion)
            }
            _ => (
                completion.saturating_sub(reported_reasoning),
                reported_reasoning.min(completion),
            ),
        };
        Some(TokenUsage {
            input_tokens: prompt - cached,
            cache_read_tokens: cached,
            cache_write_tokens: 0,
            output_tokens: output,
            reasoning_tokens: reasoning,
        })
    }

    /// Parses `response.usage` of the OpenAI Responses API.
    pub fn from_openai_responses(usage: &Value) -> Option<Self> {
        if usage.get("input_tokens").is_none() && usage.get("output_tokens").is_none() {
            return None;
        }
        let input = as_u64(&usage["input_tokens"]);
        let output = as_u64(&usage["output_tokens"]);
        let cached = as_u64(&usage["input_tokens_details"]["cached_tokens"]).min(input);
        let reasoning = as_u64(&usage["output_tokens_details"]["reasoning_tokens"]).min(output);
        Some(TokenUsage {
            input_tokens: input - cached,
            cache_read_tokens: cached,
            cache_write_tokens: 0,
            output_tokens: output - reasoning,
            reasoning_tokens: reasoning,
        })
    }

    /// Parses an Anthropic `usage` object.
    ///
    /// Assumes usage has been merged across `message_start` and all
    /// `message_delta` (see `merge_usage_json`). Anthropic's `input_tokens`
    /// already excludes cache reads/writes. Thinking tokens are included in
    /// `output_tokens`.
    pub fn from_anthropic(usage: &Value) -> Option<Self> {
        if !usage.is_object() {
            return None;
        }
        Some(TokenUsage {
            input_tokens: as_u64(&usage["input_tokens"]),
            cache_read_tokens: as_u64(&usage["cache_read_input_tokens"]),
            cache_write_tokens: as_u64(&usage["cache_creation_input_tokens"]),
            output_tokens: as_u64(&usage["output_tokens"]),
            reasoning_tokens: 0,
        })
    }

    /// Parses the final (`done: true`) ollama chunk.
    pub fn from_ollama(chunk: &Value) -> Option<Self> {
        if chunk.get("prompt_eval_count").is_none() && chunk.get("eval_count").is_none() {
            return None;
        }
        Some(TokenUsage {
            input_tokens: as_u64(&chunk["prompt_eval_count"]),
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: as_u64(&chunk["eval_count"]),
            reasoning_tokens: 0,
        })
    }
}

impl Add for TokenUsage {
    type Output = TokenUsage;
    fn add(self, o: TokenUsage) -> TokenUsage {
        TokenUsage {
            input_tokens: self.input_tokens + o.input_tokens,
            cache_read_tokens: self.cache_read_tokens + o.cache_read_tokens,
            cache_write_tokens: self.cache_write_tokens + o.cache_write_tokens,
            output_tokens: self.output_tokens + o.output_tokens,
            reasoning_tokens: self.reasoning_tokens + o.reasoning_tokens,
        }
    }
}

impl AddAssign for TokenUsage {
    fn add_assign(&mut self, o: TokenUsage) {
        *self = *self + o;
    }
}

/// NOTE: Currently an Anthropic-specific utility.
///
/// Anthropic's API reports usage "incrementally" via `message_start` and
/// `message_delta` events. However, the values contained in these deltas are
/// cumulative. You don't need to sum across events, you simply take the last
/// value.
///
/// Merging simplifies the logic to just taking the most recent value. Certain
/// values like `input_tokens` and `cache_read_tokens` only appear at the
/// start.
pub fn merge_usage_json(dst: &mut Map<String, Value>, src: &Value) {
    if let Some(obj) = src.as_object() {
        for (k, v) in obj {
            if !v.is_null() {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openai_chat() {
        let u = TokenUsage::from_openai_chat(&json!({
            "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150,
            "prompt_tokens_details": {"cached_tokens": 40},
            "completion_tokens_details": {"reasoning_tokens": 30},
        }))
        .unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input_tokens: 60,
                cache_read_tokens: 40,
                cache_write_tokens: 0,
                output_tokens: 20,
                reasoning_tokens: 30
            }
        );
        assert_eq!(u.total_tokens(), 150);
        assert!(TokenUsage::from_openai_chat(&Value::Null).is_none());
    }

    #[test]
    fn xai_reasoning_excluded() {
        let u = TokenUsage::from_openai_chat(&json!({
            "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 180,
            "prompt_tokens_details": {"cached_tokens": 10},
            "completion_tokens_details": {"reasoning_tokens": 30},
        }))
        .unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input_tokens: 90,
                cache_read_tokens: 10,
                cache_write_tokens: 0,
                output_tokens: 50,
                reasoning_tokens: 30
            }
        );
    }

    #[test]
    fn gemini_thoughts_unreported() {
        let u = TokenUsage::from_openai_chat(&json!({
            "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 175,
        }))
        .unwrap();
        assert_eq!(u.output_tokens, 50);
        assert_eq!(u.reasoning_tokens, 25);
    }

    #[test]
    fn deepseek() {
        let u = TokenUsage::from_openai_chat(&json!({
            "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150,
            "prompt_cache_hit_tokens": 70, "prompt_cache_miss_tokens": 30,
        }))
        .unwrap();
        assert_eq!(u.input_tokens, 30);
        assert_eq!(u.cache_read_tokens, 70);
        assert_eq!(u.output_tokens, 50);
    }

    #[test]
    fn openai_responses() {
        let u = TokenUsage::from_openai_responses(&json!({
            "input_tokens": 100, "input_tokens_details": {"cached_tokens": 40},
            "output_tokens": 50, "output_tokens_details": {"reasoning_tokens": 30},
            "total_tokens": 150,
        }))
        .unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input_tokens: 60,
                cache_read_tokens: 40,
                cache_write_tokens: 0,
                output_tokens: 20,
                reasoning_tokens: 30
            }
        );
    }

    #[test]
    fn anthropic_merge() {
        let mut raw = Map::new();
        merge_usage_json(
            &mut raw,
            &json!({
                "input_tokens": 10, "cache_creation_input_tokens": 200,
                "cache_read_input_tokens": 300, "output_tokens": 1,
            }),
        );
        merge_usage_json(
            &mut raw,
            &json!({"output_tokens": 77, "input_tokens": null}),
        );
        let u = TokenUsage::from_anthropic(&Value::Object(raw)).unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input_tokens: 10,
                cache_read_tokens: 300,
                cache_write_tokens: 200,
                output_tokens: 77,
                reasoning_tokens: 0
            }
        );
        assert_eq!(u.total_input_tokens(), 510);
    }

    #[test]
    fn ollama() {
        let u = TokenUsage::from_ollama(
            &json!({"done": true, "prompt_eval_count": 12, "eval_count": 34}),
        )
        .unwrap();
        assert_eq!(u.input_tokens, 12);
        assert_eq!(u.output_tokens, 34);
        assert!(TokenUsage::from_ollama(&json!({"message": {}})).is_none());
    }
}
