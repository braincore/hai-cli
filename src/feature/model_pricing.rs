use crate::config::{AiModel, AnthropicModel, DeepSeekModel, GoogleModel, OpenAiModel, XaiModel};

/// Converts a price in mills (one-thousandth of a US dollar) to a formatted
/// string in dollars, cents, and optionally mills.
///
/// Mills was chosen because we needed a little more granularity than cents.
pub fn mills_to_dollars(price_per_milli: u32) -> String {
    let dollars = price_per_milli / 1000;
    let cents = (price_per_milli % 1000) / 10;
    let mills = price_per_milli % 10;
    if mills == 0 {
        format!("${}.{:02}", dollars, cents)
    } else {
        format!("${}.{:02}{:1}", dollars, cents, mills)
    }
}

/// Per-token-type prices for a model.
///
/// All prices are in mills per 1M tokens (mill = one-thousandth of a US
/// dollar).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenPrices {
    /// Uncached input tokens.
    pub input: u32,
    /// Output tokens (reasoning tokens are output tokens).
    pub output: u32,
    /// Input tokens read from the prompt cache. None if the model/provider
    /// offers no cache discount.
    pub cache_read: Option<u32>,
    /// Input tokens written to the prompt cache. None if writes aren't billed
    /// separately. For Anthropic this is the 5-minute TTL rate.
    pub cache_write: Option<u32>,
}

/// Short constructor for `TokenPrices`.
const fn tp(
    input: u32,
    output: u32,
    cache_read: Option<u32>,
    cache_write: Option<u32>,
) -> TokenPrices {
    TokenPrices {
        input,
        output,
        cache_read,
        cache_write,
    }
}

/// Prices once a request's input is longer than `above_input_tokens`.
///
/// NOTE: Higher pricing is applied to all tokens rather than "excess tokens"
/// above the threshold (no "marginal token pricing hike").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextTier {
    /// The tier applies when total input tokens (uncached + cache read +
    /// cache write) is greater than this.
    pub above_input_tokens: u64,
    pub prices: TokenPrices,
}

/// Short constructor for `ContextTier`.
const fn above(above_input_tokens: u64, prices: TokenPrices) -> ContextTier {
    ContextTier {
        above_input_tokens,
        prices,
    }
}

/// Tracks when a discounted price tier applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffPeakWindow {
    DeepSeek,
}

impl OffPeakWindow {
    pub fn contains(&self, at: chrono::DateTime<chrono::Utc>) -> bool {
        use chrono::{Datelike, Timelike, Weekday};
        match self {
            OffPeakWindow::DeepSeek => {
                // Peak: 01:00-04:00 and 06:00-10:00 UTC, M-F. Everything else
                // is off-peak (holidays are not handled properly).
                let weekday = !matches!(at.weekday(), Weekday::Sat | Weekday::Sun);
                let h = at.hour();
                let peak = weekday && ((1..4).contains(&h) || (6..10).contains(&h));
                !peak
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffPeakPricing {
    pub prices: TokenPrices,
    pub window: OffPeakWindow,
}

/// WARN: Off-peak takes precedence over context tiers. This is how it works
/// today with AI providers, but this may change in the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelPricing {
    /// Standard pricing is peak hours below context-length tiers.
    pub standard: TokenPrices,
    /// Long-context pricing. Sorted ascending by `above_input_tokens`. Empty
    /// if the price is never a function of context length.
    pub context_tiers: &'static [ContextTier],
    pub offpeak: Option<OffPeakPricing>,
}

impl ModelPricing {
    const fn new(standard: TokenPrices) -> Self {
        ModelPricing {
            standard,
            context_tiers: &[],
            offpeak: None,
        }
    }

    const fn with_context_tiers(mut self, tiers: &'static [ContextTier]) -> Self {
        self.context_tiers = tiers;
        self
    }

    const fn with_offpeak(mut self, prices: TokenPrices, window: OffPeakWindow) -> Self {
        self.offpeak = Some(OffPeakPricing { prices, window });
        self
    }

    /// Gets the pricing in effect accounting for off-peak windows and context
    /// tiers.
    pub fn prices_for(&self, input_tokens: u64, at: chrono::DateTime<chrono::Utc>) -> &TokenPrices {
        if let Some(offpeak) = &self.offpeak
            && offpeak.window.contains(at)
        {
            return &offpeak.prices;
        }
        self.context_tiers
            .iter()
            .rev()
            .find(|tier| input_tokens > tier.above_input_tokens)
            .map(|tier| &tier.prices)
            .unwrap_or(&self.standard)
    }

    /// Cost in mills (fractional, since a single request is usually well
    /// under a mill) of a single request's `usage`, made at time `at`.
    ///
    /// `usage` must be for ONE request: the context tier is chosen from its
    /// total input tokens. Summed usage across requests gives wrong results
    /// for models with context tiers.
    pub fn cost_mills(
        &self,
        usage: &crate::ai_provider::usage::TokenUsage,
        at: chrono::DateTime<chrono::Utc>,
    ) -> f64 {
        let p = self.prices_for(usage.total_input_tokens(), at);
        let cost = |tokens: u64, price: u32| tokens as f64 * price as f64 / 1_000_000.0;
        cost(usage.input_tokens, p.input)
            + cost(usage.cache_read_tokens, p.cache_read.unwrap_or(p.input))
            + cost(usage.cache_write_tokens, p.cache_write.unwrap_or(p.input))
            + cost(usage.output_tokens + usage.reasoning_tokens, p.output)
    }
}

pub fn get_ai_model_pricing(ai_model: &AiModel) -> Option<ModelPricing> {
    const fn mp(
        input: u32,
        output: u32,
        cache_read: Option<u32>,
        cache_write: Option<u32>,
    ) -> ModelPricing {
        ModelPricing::new(tp(input, output, cache_read, cache_write))
    }

    const GPT6_ASTRA_TIERS: &[ContextTier] =
        &[above(272_000, tp(20000, 75000, Some(2000), Some(25000)))];
    const GPT61_SOL_TIERS: &[ContextTier] =
        &[above(272_000, tp(4000, 15000, Some(200), Some(5000)))];
    const GPT6_LUNA_TIERS: &[ContextTier] = &[above(272_000, tp(200, 750, Some(20), Some(250)))];
    const GPT56_SOL_TIERS: &[ContextTier] =
        &[above(272_000, tp(8000, 30000, Some(800), Some(10000)))];

    const HAIKU55_TIERS: &[ContextTier] = &[above(100_000, tp(500, 2500, Some(50), Some(625)))];

    const GEMINI15_PRO_TIERS: &[ContextTier] = &[above(128_000, tp(2500, 10000, Some(625), None))];
    const GEMINI25_PRO_TIERS: &[ContextTier] = &[above(200_000, tp(2500, 15000, Some(250), None))];
    const GEMINI3_PRO_TIERS: &[ContextTier] = &[above(200_000, tp(4000, 18000, Some(400), None))];

    const GROK46_TIERS: &[ContextTier] = &[above(199_999, tp(4000, 12000, Some(1000), None))];

    let pricing = match ai_model {
        AiModel::Anthropic(model) => match model {
            // cache_write is the 5-minute TTL rate.
            AnthropicModel::Fable51(_) => mp(10000, 50000, Some(250), Some(12500)),
            AnthropicModel::Haiku35 => mp(800, 4000, Some(80), Some(1000)),
            AnthropicModel::Haiku55(_) => {
                mp(100, 500, Some(10), Some(125)).with_context_tiers(HAIKU55_TIERS)
            }
            AnthropicModel::Opus4(_) => mp(15000, 75000, Some(1500), Some(18750)),
            AnthropicModel::Opus41(_) => mp(15000, 75000, Some(1500), Some(18750)),
            AnthropicModel::Opus45(_)
            | AnthropicModel::Opus46(_)
            | AnthropicModel::Opus47(_)
            | AnthropicModel::Opus48(_)
            | AnthropicModel::Opus5(_) => mp(5000, 25000, Some(500), Some(6250)),
            AnthropicModel::Opus55(_) => mp(4000, 20000, Some(200), Some(5000)),
            AnthropicModel::Sonnet35
            | AnthropicModel::Sonnet37(_)
            | AnthropicModel::Sonnet4(_)
            | AnthropicModel::Sonnet45(_)
            | AnthropicModel::Sonnet46(_) => mp(3000, 15000, Some(300), Some(3750)),
            AnthropicModel::Sonnet5(_) => mp(2000, 10000, Some(200), Some(2500)),
            AnthropicModel::Sonnet55(_) => mp(2000, 10000, Some(100), Some(2500)),
            AnthropicModel::Other(_) => return None,
        },
        AiModel::DeepSeek(model) => {
            let (standard, offpeak) = match model {
                DeepSeekModel::DeepSeekV4Pro(_) => (
                    tp(1320, 3960, Some(44), None),
                    tp(660, 1980, Some(22), None),
                ),
                DeepSeekModel::DeepSeekV41Flash(_) => {
                    (tp(300, 1200, Some(6), None), tp(150, 600, Some(3), None))
                }
                DeepSeekModel::Other(_) => return None,
            };
            ModelPricing::new(standard).with_offpeak(offpeak, OffPeakWindow::DeepSeek)
        }
        AiModel::Google(model) => match model {
            // Implicit caching: no write charge (cache storage fees ignored).
            GoogleModel::Gemini15Flash => mp(75, 300, Some(19), None),
            GoogleModel::Gemini15Flash8B => mp(38, 150, Some(10), None),
            GoogleModel::Gemini15Pro => {
                mp(1250, 5000, Some(313), None).with_context_tiers(GEMINI15_PRO_TIERS)
            }
            GoogleModel::Gemini20Flash => mp(100, 400, Some(25), None),
            GoogleModel::Gemini25Flash => mp(300, 2500, Some(30), None),
            GoogleModel::Gemini25Pro => {
                mp(1250, 10000, Some(125), None).with_context_tiers(GEMINI25_PRO_TIERS)
            }
            GoogleModel::Gemini3Flash(_) => mp(500, 3000, Some(50), None),
            GoogleModel::Gemini3Pro(_) => {
                mp(2000, 12000, Some(200), None).with_context_tiers(GEMINI3_PRO_TIERS)
            }
            GoogleModel::Gemini31FlashLite(_) => mp(250, 1500, Some(25), None),
            GoogleModel::Gemini31Pro(_) => {
                mp(2000, 12000, Some(200), None).with_context_tiers(GEMINI3_PRO_TIERS)
            }
            GoogleModel::Gemini35Flash(_) => mp(1500, 9000, Some(150), None),
            GoogleModel::Gemini35FlashLite(_) => mp(300, 2500, Some(30), None),
            GoogleModel::Gemini36Flash(_) => mp(750, 3750, Some(75), None),
            GoogleModel::Gemini37Flash(_) => mp(750, 3750, Some(75), None),
            GoogleModel::Gemini38Flash(_) => mp(750, 3750, Some(75), None),
            GoogleModel::Other(_) => return None,
        },
        AiModel::LlamaCpp(_) => return None,
        AiModel::Ollama(_) => return None,
        AiModel::OpenAi(model) => match model {
            OpenAiModel::ChatGpt4o => mp(5000, 15000, None, None),
            OpenAiModel::Gpt41 => mp(2000, 8000, Some(500), None),
            OpenAiModel::Gpt41Mini => mp(400, 1600, Some(100), None),
            OpenAiModel::Gpt41Nano => mp(100, 400, Some(25), None),
            OpenAiModel::Gpt5(_)
            | OpenAiModel::Gpt5Chat
            | OpenAiModel::Gpt51(_)
            | OpenAiModel::Gpt51Chat => mp(1250, 10000, Some(125), None),
            OpenAiModel::Gpt5Mini(_) => mp(250, 2000, Some(25), None),
            OpenAiModel::Gpt5Nano(_) => mp(50, 400, Some(5), None),
            OpenAiModel::Gpt52(_) | OpenAiModel::Gpt52Chat => mp(1750, 14000, Some(175), None),
            OpenAiModel::Gpt53Chat => mp(1750, 14000, Some(175), None),
            OpenAiModel::Gpt54(_) => mp(2500, 15000, Some(250), None),
            OpenAiModel::Gpt54Mini(_) => mp(750, 4500, Some(75), None),
            OpenAiModel::Gpt54Nano(_) => mp(200, 1250, Some(20), None),
            OpenAiModel::Gpt55(_) => mp(5000, 30000, Some(500), None),
            OpenAiModel::Gpt56Sol(_) => {
                mp(4000, 20000, Some(400), Some(5000)).with_context_tiers(GPT56_SOL_TIERS)
            }
            OpenAiModel::Gpt56Terra(_) => mp(2000, 12000, Some(200), Some(2500)),
            OpenAiModel::Gpt56Luna(_) => mp(200, 1200, Some(20), None),
            OpenAiModel::Gpt6Astra(_) => {
                mp(10000, 50000, Some(1000), Some(12500)).with_context_tiers(GPT6_ASTRA_TIERS)
            }
            OpenAiModel::Gpt6Sol(_) => mp(2000, 10000, Some(200), None),
            OpenAiModel::Gpt6Luna(_) => {
                mp(100, 500, Some(10), Some(125)).with_context_tiers(GPT6_LUNA_TIERS)
            }
            OpenAiModel::Gpt61Sol(_) => {
                mp(2000, 10000, Some(100), Some(2500)).with_context_tiers(GPT61_SOL_TIERS)
            }
            OpenAiModel::Gpt4o => mp(2500, 10000, Some(1250), None),
            OpenAiModel::Gpt4oMini => mp(150, 600, Some(75), None),
            OpenAiModel::O1 => mp(15000, 60000, Some(7500), None),
            OpenAiModel::O3 => mp(10000, 40000, Some(2500), None),
            OpenAiModel::O1Mini => mp(3000, 12000, Some(1500), None),
            OpenAiModel::O3Mini => mp(1100, 4400, Some(550), None),
            OpenAiModel::O4Mini => mp(1100, 4400, Some(275), None),
            OpenAiModel::Other(_) => return None,
        },
        AiModel::Void(_) => return None,
        AiModel::Xai(model) => match model {
            XaiModel::Grok3 => mp(3000, 15000, Some(750), None),
            XaiModel::Grok3Fast => mp(5000, 25000, Some(1250), None),
            XaiModel::Grok3Mini => mp(300, 500, Some(75), None),
            XaiModel::Grok3MiniFast => mp(600, 4000, Some(150), None),
            XaiModel::Grok4 => mp(3000, 15000, Some(750), None),
            XaiModel::Grok46 => mp(2000, 6000, Some(500), None).with_context_tiers(GROK46_TIERS),
            XaiModel::Other(_) => return None,
        },
    };
    Some(pricing)
}

#[cfg(test)]
mod pricing_tests {
    use super::*;
    use crate::ai_provider::usage::TokenUsage;
    use chrono::TimeZone;

    #[test]
    fn deepseek_offpeak_window() {
        let w = OffPeakWindow::DeepSeek;
        // 2025-06-02 is a Monday.
        let at = |d, h| chrono::Utc.with_ymd_and_hms(2025, 6, d, h, 30, 0).unwrap();
        assert!(w.contains(at(2, 0)));
        assert!(!w.contains(at(2, 1)));
        assert!(!w.contains(at(2, 3)));
        assert!(w.contains(at(2, 4)));
        assert!(w.contains(at(2, 5)));
        assert!(!w.contains(at(2, 6)));
        assert!(!w.contains(at(2, 9)));
        assert!(w.contains(at(2, 10)));
        // Saturday & Sunday are off-peak all day.
        assert!(w.contains(at(7, 2)));
        assert!(w.contains(at(8, 7)));
    }

    #[test]
    fn cost_mills() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 1_000_000,
            output_tokens: 500_000,
            reasoning_tokens: 500_000,
        };
        let at = chrono::Utc.with_ymd_and_hms(2025, 6, 2, 2, 0, 0).unwrap();
        let p = ModelPricing::new(tp(3000, 15000, Some(300), Some(3750)));
        assert_eq!(p.cost_mills(&usage, at), 3000.0 + 300.0 + 3750.0 + 15000.0);
        // No cache prices -> billed as input.
        let p = ModelPricing::new(tp(100, 200, None, None));
        assert_eq!(p.cost_mills(&usage, at), 300.0 + 200.0);
        // Off-peak applies.
        let p = ModelPricing::new(tp(100, 200, None, None))
            .with_offpeak(tp(50, 100, None, None), OffPeakWindow::DeepSeek);
        assert_eq!(p.cost_mills(&usage, at), 300.0 + 200.0);
        let off = chrono::Utc.with_ymd_and_hms(2025, 6, 2, 12, 0, 0).unwrap();
        assert_eq!(p.cost_mills(&usage, off), 150.0 + 100.0);
    }

    #[test]
    fn context_tiers() {
        const TIERS: &[ContextTier] = &[
            above(100_000, tp(500, 2500, None, None)),
            above(200_000, tp(1000, 5000, None, None)),
        ];
        let p = ModelPricing::new(tp(100, 500, None, None)).with_context_tiers(TIERS);
        let now = chrono::Utc::now();
        assert_eq!(p.prices_for(0, now).input, 100);
        assert_eq!(p.prices_for(100_000, now).input, 100);
        assert_eq!(p.prices_for(100_001, now).input, 500);
        assert_eq!(p.prices_for(200_000, now).input, 500);
        assert_eq!(p.prices_for(200_001, now).input, 1000);

        // Cache reads count toward the threshold, and the whole request
        // (including output) is billed at the tier rate.
        let usage = TokenUsage {
            input_tokens: 1_000,
            cache_read_tokens: 150_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(p.cost_mills(&usage, now), 0.5 + 75.0 + 2500.0);
    }
}
