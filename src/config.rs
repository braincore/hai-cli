use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub default_ai_model: Option<String>,
    pub default_incognito_ai_model: Option<String>,
    #[serde(default = "default_true")]
    pub default_ai_temperature_to_absolute_zero: bool,
    /// The editor (e.g. vim, emacs, nano) to edit assets with
    pub default_editor: Option<String>,
    /// The shell (e.g. bash, zsh, fish, nu, powershell) to use for !sh tool
    pub default_shell: Option<String>,
    #[serde(default)]
    pub tool_confirm: bool,
    #[serde(default = "default_true")]
    pub check_for_updates: bool,
    pub openai: Option<OpenAiConfig>,
    pub anthropic: Option<AnthropicConfig>,
    pub ollama: Option<OllamaConfig>,
    pub google: Option<GoogleConfig>,
    pub deepseek: Option<DeepSeekConfig>,
    #[serde(default)]
    pub haivars: HashMap<String, String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct AnthropicConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GoogleConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OpenAiConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OllamaConfig {
    /// If unspecified, defaults to "http://localhost:11434"
    pub base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeepSeekConfig {
    pub api_key: Option<String>,
}

pub fn ai_model_from_string(ai_model: &str) -> Option<AiModel> {
    match ai_model.replace("-", "").replace(".", "").as_str() {
        "chatgpt4o" => Some(AiModel::OpenAi(OpenAiModel::ChatGpt4o)),
        "deepseek" | "deepseekchat" | "v3" => Some(AiModel::DeepSeek(DeepSeekModel::DeepSeekChat)),
        "deepseekreasoner" | "r1" => Some(AiModel::DeepSeek(DeepSeekModel::DeepSeekReasoner)),
        "flash" | "flash25" | "geminiflash" | "gemini25flash" => {
            Some(AiModel::Google(GoogleModel::Gemini25Flash))
        }
        "flash20" | "gemini20flash" => Some(AiModel::Google(GoogleModel::Gemini20Flash)),
        "flash15" | "gemini15flash" => Some(AiModel::Google(GoogleModel::Gemini15Flash)),
        "flash158b" | "gemini15flash8b" => Some(AiModel::Google(GoogleModel::Gemini15Flash8B)),
        "gemini25pro" => Some(AiModel::Google(GoogleModel::Gemini25Pro)),
        "gemini15pro" => Some(AiModel::Google(GoogleModel::Gemini15Pro)),
        "gpt41" | "41" => Some(AiModel::OpenAi(OpenAiModel::Gpt41)),
        "gpt41mini" | "41mini" | "41m" => Some(AiModel::OpenAi(OpenAiModel::Gpt41Mini)),
        "gpt41nano" | "41nano" | "41n" => Some(AiModel::OpenAi(OpenAiModel::Gpt41Nano)),
        "gpt4o" | "4o" => Some(AiModel::OpenAi(OpenAiModel::Gpt4o)),
        "gpt4omini" | "4omini" | "4om" => Some(AiModel::OpenAi(OpenAiModel::Gpt4oMini)),
        "o1" => Some(AiModel::OpenAi(OpenAiModel::O1)),
        "o1mini" | "o1m" => Some(AiModel::OpenAi(OpenAiModel::O1Mini)),
        "o3" => Some(AiModel::OpenAi(OpenAiModel::O3)),
        "o3mini" | "o3m" => Some(AiModel::OpenAi(OpenAiModel::O3Mini)),
        "o4mini" | "o4m" => Some(AiModel::OpenAi(OpenAiModel::O4Mini)),
        "haiku" | "haiku35" => Some(AiModel::Anthropic(AnthropicModel::Haiku35)),
        "llama" | "llama32" => Some(AiModel::Ollama(OllamaModel::Llama32)),
        "llamavision" | "llama32vision" => Some(AiModel::Ollama(OllamaModel::Llama32Vision)),
        "opus" | "opus4" => Some(AiModel::Anthropic(AnthropicModel::Opus4(false))),
        "opus4thinking" => Some(AiModel::Anthropic(AnthropicModel::Opus4(true))),
        "sonnet" | "sonnet4" => Some(AiModel::Anthropic(AnthropicModel::Sonnet4(false))),
        "sonnet37" => Some(AiModel::Anthropic(AnthropicModel::Sonnet37(false))),
        "sonnetthinking" | "sonnet4thinking" => {
            Some(AiModel::Anthropic(AnthropicModel::Sonnet4(true)))
        }
        "sonnet37thinking" => Some(AiModel::Anthropic(AnthropicModel::Sonnet37(true))),
        "sonnet35" => Some(AiModel::Anthropic(AnthropicModel::Sonnet35)),
        _ => {
            let openai_regex = Regex::new(r"^openai/(\S+)$").unwrap();
            if let Some(captures) = openai_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::OpenAi(OpenAiModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            let anthropic_regex = Regex::new(r"^anthropic/(\S+)$").unwrap();
            if let Some(captures) = anthropic_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::Anthropic(AnthropicModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            let ollama_regex = Regex::new(r"^ollama/(\S+)$").unwrap();
            if let Some(captures) = ollama_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::Ollama(OllamaModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            let google_regex = Regex::new(r"^google/(\S+)$").unwrap();
            if let Some(captures) = google_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::Google(GoogleModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            let deepseek_regex = Regex::new(r"^deepseek/(\S+)$").unwrap();
            if let Some(captures) = deepseek_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::DeepSeek(DeepSeekModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            let void_regex = Regex::new(r"^void/(\S+)$").unwrap();
            if let Some(captures) = void_regex.captures(ai_model) {
                if let Some(submodel) = captures.get(1) {
                    return Some(AiModel::Void(VoidModel::Other(
                        submodel.as_str().to_string(),
                    )));
                }
            }
            None
        }
    }
}

impl Config {
    pub fn reload(
        &mut self,
        config_path_override: &Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let new_config: Config =
            toml::from_str(&read_config_as_string(config_path_override).unwrap())?;
        *self = new_config;
        self.haivars = read_dot_haivars()?;
        Ok(())
    }
}

pub fn get_default_config_path() -> PathBuf {
    let mut path = get_config_folder_path();
    path.push("hai.toml");
    path
}

pub fn read_config_as_string(
    config_path_override: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let config_path = if let Some(config_path) = config_path_override {
        config_path.to_string()
    } else {
        let path = get_default_config_path();
        if !path.exists() {
            let default_config = r#"
# The default AI model to use.
#default_ai_model = "4o"

# The default AI model in incognito mode.
#default_incognito_ai_model = "llama32"

# The default editor to use for modifying assets (default: vim)
#default_editor = "vim"

# The default shell to use for the !sh tool (default: bash, powershell)
#default_shell = "bash"

# Temperature ranges differ by model, but 0 is generally best for math/coding (default: true)
#default_ai_temperature_to_absolute_zero = true

# Whether or not to confirm tool actions (default: false).
#tool_confirm = false

# Whether to automatically check for client updates (default: true)
# Setting this to `false` disables hai's only unprompted service request. This
# may be of interest to the privacy conscious.
#check_for_updates = true

[openai]
# Your OpenAI API key (required to use OpenAI models).
#api_key = ""

[anthropic]
# Your Anthropic API key (required to use Anthropic models).
#api_key = ""

[ollama]
# Base URL for the Ollama API (default: http://localhost:11434).
#base_url = ""

[google]
# Your Google API key (required to use Google AI models).
#api_key = ""

[deepseek]
# Your DeepSeek API key (required to use DeepSeek models).
#api_key = ""
"#;
            write_config(&path.to_string_lossy(), default_config);
        }
        path.to_str().unwrap().to_string()
    };
    Ok(fs::read_to_string(&config_path)?)
}

pub fn get_config(
    config_path_override: &Option<String>,
) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config: Config = toml::from_str(&read_config_as_string(config_path_override)?)?;
    config.haivars = read_dot_haivars()?;
    Ok(config)
}

pub fn create_config_dir_if_missing() -> Result<(), Box<dyn Error>> {
    let path = get_config_folder_path();
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn get_config_folder_path() -> PathBuf {
    let mut path = PathBuf::new();
    path.push(dirs::home_dir().unwrap());
    path.push(".hai");
    path
}

// ---

pub fn write_config(path: &str, cfg: &str) {
    if let Err(e) = fs::write(path, cfg) {
        eprintln!("Failed to write to config file: {}", e);
    }
}

pub fn insert_config_kv(
    config_path_override: &Option<String>,
    section: Option<&str>,
    key: &String,
    val: &String,
) {
    let cfg = read_config_as_string(config_path_override).unwrap();
    let mut doc = cfg.parse::<toml_edit::DocumentMut>().expect("invalid doc");
    if let Some(section_name) = section {
        doc[section_name][key] = toml_edit::value(val);
    } else {
        doc[key] = toml_edit::value(val);
    }
    let config_path = config_path_override
        .clone()
        .unwrap_or(get_default_config_path().to_str().unwrap().to_string());
    write_config(&config_path, doc.to_string().as_str());
}

// ---

#[derive(Debug)]
pub enum AiModel {
    Anthropic(AnthropicModel),
    DeepSeek(DeepSeekModel),
    Google(GoogleModel),
    Ollama(OllamaModel),
    OpenAi(OpenAiModel),
    /// For testing only
    Void(VoidModel),
}

#[derive(Debug)]
pub enum AnthropicModel {
    Haiku35,
    Opus4(bool), // If true, enables thinking
    Sonnet35,
    Sonnet37(bool), // If true, enables thinking
    Sonnet4(bool),  // If true, enables thinking
    Other(String),
}

#[derive(Debug)]
pub enum DeepSeekModel {
    DeepSeekChat,
    DeepSeekReasoner,
    Other(String),
}

#[derive(Debug)]
pub enum GoogleModel {
    Gemini25Flash,
    Gemini25Pro,
    Gemini20Flash,
    Gemini15Flash,
    Gemini15Flash8B,
    Gemini15Pro,
    Other(String),
}

#[derive(Debug)]
pub enum OllamaModel {
    Llama32,
    Llama32Vision,
    Other(String),
}
#[derive(Debug)]
pub enum OpenAiModel {
    ChatGpt4o,
    Gpt41,
    Gpt41Mini,
    Gpt41Nano,
    Gpt4o,
    Gpt4oMini,
    O1,
    O1Mini,
    O3,
    O3Mini,
    O4Mini,
    Other(String),
}

#[derive(Debug)]
pub enum VoidModel {
    Other(String),
}

pub fn get_ai_model_provider_name(ai_model: &AiModel) -> &str {
    match ai_model {
        AiModel::Anthropic(model) => match model {
            AnthropicModel::Haiku35 => "claude-3-5-haiku-20241022",
            AnthropicModel::Opus4(_) => "claude-opus-4-20250514",
            AnthropicModel::Sonnet35 => "claude-3-5-sonnet-20241022",
            AnthropicModel::Sonnet37(_) => "claude-3-7-sonnet-20250219",
            AnthropicModel::Sonnet4(_) => "claude-sonnet-4-20250514",
            AnthropicModel::Other(name) => name,
        },
        AiModel::DeepSeek(model) => match model {
            DeepSeekModel::DeepSeekChat => "deepseek-chat",
            DeepSeekModel::DeepSeekReasoner => "deepseek-reasoner",
            DeepSeekModel::Other(name) => name,
        },
        AiModel::Google(model) => match model {
            GoogleModel::Gemini25Flash => "gemini-2.5-flash-preview-04-17",
            GoogleModel::Gemini25Pro => "gemini-2.5-pro-preview-03-25",
            GoogleModel::Gemini20Flash => "gemini-2.0-flash",
            GoogleModel::Gemini15Flash => "gemini-1.5-flash",
            GoogleModel::Gemini15Flash8B => "gemini-1.5-flash-8b",
            GoogleModel::Gemini15Pro => "gemini-1.5-pro",
            GoogleModel::Other(name) => name,
        },
        AiModel::Ollama(model) => match model {
            OllamaModel::Llama32 => "llama3.2",
            OllamaModel::Llama32Vision => "llama3.2-vision",
            OllamaModel::Other(name) => name,
        },
        AiModel::OpenAi(model) => match model {
            OpenAiModel::ChatGpt4o => "chatgpt-4o-latest",
            OpenAiModel::Gpt41 => "gpt-4.1-2025-04-14",
            OpenAiModel::Gpt41Mini => "gpt-4.1-mini-2025-04-14",
            OpenAiModel::Gpt41Nano => "gpt-4.1-nano-2025-04-14",
            OpenAiModel::Gpt4o => "gpt-4o-2024-11-20",
            OpenAiModel::Gpt4oMini => "gpt-4o-mini-2024-07-18",
            OpenAiModel::O1 => "o1-2024-12-17",
            OpenAiModel::O1Mini => "o1-mini-2024-09-12",
            OpenAiModel::O3 => "o3-2025-04-16",
            OpenAiModel::O3Mini => "o3-mini-2025-01-31",
            OpenAiModel::O4Mini => "o4-mini-2025-04-16",
            OpenAiModel::Other(name) => name,
        },
        AiModel::Void(model) => match model {
            VoidModel::Other(name) => name,
        },
    }
}

pub fn get_ai_model_display_name(ai_model: &AiModel) -> &str {
    match ai_model {
        AiModel::Anthropic(model) => match model {
            AnthropicModel::Haiku35 => "haiku-3.5",
            AnthropicModel::Opus4(false) => "opus-4",
            AnthropicModel::Opus4(true) => "opus-4-thinking",
            AnthropicModel::Sonnet35 => "sonnet-3.5",
            AnthropicModel::Sonnet37(false) => "sonnet-3.7",
            AnthropicModel::Sonnet37(true) => "sonnet-3.7-thinking",
            AnthropicModel::Sonnet4(false) => "sonnet-4",
            AnthropicModel::Sonnet4(true) => "sonnet-4-thinking",
            AnthropicModel::Other(name) => name,
        },
        AiModel::DeepSeek(model) => match model {
            DeepSeekModel::DeepSeekChat => "deepseek-chat",
            DeepSeekModel::DeepSeekReasoner => "deepseek-reasoner",
            DeepSeekModel::Other(name) => name,
        },
        AiModel::Google(model) => match model {
            GoogleModel::Gemini25Flash => "gemini-2.5-flash",
            GoogleModel::Gemini25Pro => "gemini-2.5-pro",
            GoogleModel::Gemini20Flash => "flash-2.0",
            GoogleModel::Gemini15Flash => "flash-1.5",
            GoogleModel::Gemini15Flash8B => "flash-1.5-8b",
            GoogleModel::Gemini15Pro => "gemini-1.5-pro",
            GoogleModel::Other(name) => name,
        },
        AiModel::Ollama(model) => match model {
            OllamaModel::Llama32 => "llama3.2",
            OllamaModel::Llama32Vision => "llama3.2-vision",
            OllamaModel::Other(name) => name,
        },
        AiModel::OpenAi(model) => match model {
            OpenAiModel::ChatGpt4o => "chatgpt-4o",
            OpenAiModel::Gpt41 => "gpt-4.1",
            OpenAiModel::Gpt41Mini => "gpt-4.1-mini",
            OpenAiModel::Gpt41Nano => "gpt-4.1-nano",
            OpenAiModel::Gpt4o => "gpt-4o",
            OpenAiModel::Gpt4oMini => "gpt-4o-mini",
            OpenAiModel::O1 => "o1",
            OpenAiModel::O1Mini => "o1-mini",
            OpenAiModel::O3 => "o3",
            OpenAiModel::O3Mini => "o3-mini",
            OpenAiModel::O4Mini => "o4-mini",
            OpenAiModel::Other(name) => name,
        },
        AiModel::Void(model) => match model {
            VoidModel::Other(name) => name,
        },
    }
}

#[derive(Debug)]
pub struct AiModelCapability {
    pub image: bool,
    pub tool: bool,
}

pub fn get_ai_model_capability(ai_model: &AiModel) -> AiModelCapability {
    match ai_model {
        AiModel::Anthropic(_) => AiModelCapability {
            image: true,
            tool: true,
        },
        AiModel::DeepSeek(model) => match model {
            DeepSeekModel::DeepSeekChat => AiModelCapability {
                image: false,
                // DeepSeek says it's unstable, but enable it anyway
                tool: true,
            },
            DeepSeekModel::DeepSeekReasoner => AiModelCapability {
                image: false,
                tool: false,
            },
            DeepSeekModel::Other(_) => AiModelCapability {
                image: false,
                tool: true,
            },
        },
        AiModel::Google(model) => match model {
            GoogleModel::Gemini25Flash
            | GoogleModel::Gemini25Pro
            | GoogleModel::Gemini20Flash
            | GoogleModel::Gemini15Flash
            | GoogleModel::Gemini15Flash8B
            | GoogleModel::Gemini15Pro => AiModelCapability {
                image: true,
                tool: true,
            },
            GoogleModel::Other(_) => AiModelCapability {
                image: false,
                tool: false,
            },
        },
        AiModel::Ollama(model) => match model {
            OllamaModel::Llama32 => AiModelCapability {
                image: false,
                tool: true,
            },
            OllamaModel::Llama32Vision => AiModelCapability {
                image: true,
                tool: false,
            },
            OllamaModel::Other(_) => AiModelCapability {
                image: true,
                tool: true,
            },
        },
        AiModel::OpenAi(model) => match model {
            OpenAiModel::O1Mini => AiModelCapability {
                image: false,
                tool: false,
            },
            OpenAiModel::O3Mini => AiModelCapability {
                image: false,
                tool: true,
            },
            _ => AiModelCapability {
                image: true,
                tool: true,
            },
        },
        AiModel::Void(_) => AiModelCapability {
            image: true,
            tool: true,
        },
    }
}

/// Whether the model can be used via the hai-ai-router
pub fn is_ai_model_supported_by_hai_router(ai_model: &AiModel) -> bool {
    match ai_model {
        AiModel::Anthropic(model) => {
            matches!(
                model,
                AnthropicModel::Haiku35
                    | AnthropicModel::Opus4(_)
                    | AnthropicModel::Sonnet35
                    | AnthropicModel::Sonnet37(_)
                    | AnthropicModel::Sonnet4(_)
            )
        }
        AiModel::DeepSeek(model) => matches!(
            model,
            DeepSeekModel::DeepSeekChat | DeepSeekModel::DeepSeekReasoner
        ),
        AiModel::Google(model) => matches!(
            model,
            GoogleModel::Gemini25Flash
                | GoogleModel::Gemini25Pro
                | GoogleModel::Gemini20Flash
                | GoogleModel::Gemini15Flash
                | GoogleModel::Gemini15Flash8B
                | GoogleModel::Gemini15Pro
        ),
        AiModel::Ollama(_) => false,
        AiModel::OpenAi(model) => matches!(
            model,
            OpenAiModel::Gpt41
                | OpenAiModel::Gpt41Mini
                | OpenAiModel::Gpt41Nano
                | OpenAiModel::Gpt4o
                | OpenAiModel::Gpt4oMini
                | OpenAiModel::O1
                | OpenAiModel::O1Mini
                | OpenAiModel::O3
                | OpenAiModel::O3Mini
                | OpenAiModel::O4Mini
        ),
        AiModel::Void(_) => false,
    }
}

/// Returns: (mill / 1M input tokens, mill / 1M output tokens)
/// mill = one-thousandth of a US dollar
pub fn get_ai_model_cost(ai_model: &AiModel) -> Option<(u32, u32)> {
    match ai_model {
        AiModel::Anthropic(model) => match model {
            AnthropicModel::Haiku35 => Some((800, 4000)),
            AnthropicModel::Opus4(_) => Some((15000, 75000)),
            AnthropicModel::Sonnet35 | AnthropicModel::Sonnet37(_) | AnthropicModel::Sonnet4(_) => {
                Some((3000, 15000))
            }
            AnthropicModel::Other(_) => None,
        },
        AiModel::DeepSeek(model) => match model {
            DeepSeekModel::DeepSeekChat => Some((270, 1100)),
            DeepSeekModel::DeepSeekReasoner => Some((550, 2190)),
            DeepSeekModel::Other(_) => None,
        },
        AiModel::Google(model) => match model {
            GoogleModel::Gemini25Flash => Some((150, 600)),
            // NOTE: gemini-2.5-pro is currently free because it's experimental.
            // It's currently set to the price of gemini-1.5-pro.
            GoogleModel::Gemini25Pro => Some((1250, 5000)),
            GoogleModel::Gemini20Flash => Some((100, 400)),
            GoogleModel::Gemini15Flash => Some((75, 300)),
            GoogleModel::Gemini15Flash8B => Some((38, 150)),
            GoogleModel::Gemini15Pro => Some((1250, 5000)),
            GoogleModel::Other(_) => None,
        },
        AiModel::Ollama(_) => None,
        AiModel::OpenAi(model) => match model {
            OpenAiModel::ChatGpt4o => Some((5000, 15000)),
            OpenAiModel::Gpt41 => Some((2000, 8000)),
            OpenAiModel::Gpt41Mini => Some((400, 1600)),
            OpenAiModel::Gpt41Nano => Some((100, 400)),
            OpenAiModel::Gpt4o => Some((2500, 10000)),
            OpenAiModel::Gpt4oMini => Some((150, 600)),
            OpenAiModel::O1 => Some((15000, 60000)),
            OpenAiModel::O3 => Some((10000, 40000)),
            OpenAiModel::O1Mini => Some((3000, 12000)),
            OpenAiModel::O3Mini => Some((1100, 4400)),
            OpenAiModel::O4Mini => Some((1100, 4400)),
            OpenAiModel::Other(_) => None,
        },
        AiModel::Void(_) => None,
    }
}

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

// ---

pub fn read_dot_haivars() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let config_folder_path = get_config_folder_path();
    let mut merged_config: HashMap<String, String> = HashMap::new();
    for entry in fs::read_dir(config_folder_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("haivars") {
            let haivars_contents = fs::read_to_string(path)?;
            let haivars: HashMap<String, String> = toml::from_str(&haivars_contents)?;
            for (key, value) in haivars {
                if merged_config.contains_key(&key) {
                    println!("Key conflict for '{}'. Overwriting with new value.", key);
                }
                merged_config.insert(key, value);
            }
        }
    }
    Ok(merged_config)
}

// ---

#[derive(Debug, Deserialize)]
pub struct HaiTask {
    pub name: String,
    pub version: String,
    #[allow(dead_code)]
    pub description: String,
    #[allow(dead_code)]
    pub dependencies: Option<Vec<String>>,
    pub steps: Vec<String>,
}

pub fn parse_haitask_config(contents: &str) -> Result<HaiTask, Box<dyn std::error::Error>> {
    Ok(toml::from_str(contents)?)
}

/// Reads haitask from arbitrary path
pub fn read_haitask(task_path: &str) -> Result<(String, HaiTask), Box<dyn std::error::Error>> {
    let haitask_contents = fs::read_to_string(task_path)?;
    let haitask: HaiTask = toml::from_str(&haitask_contents)?;
    Ok((haitask_contents, haitask))
}

/// Given a fully-qualified task name, returns the assigned path for it in the
/// config cache whether or not the task is actually cached.
///
/// Caller is responsible for validating task_fqn is valid/isn't dangerous.
pub fn get_task_cache_path(task_fqn: &str) -> PathBuf {
    if is_valid_task_fqn(task_fqn).is_none() {
        // Caller should have done validation, so panic if invalid.
        panic!("error: invalid task name");
    }
    let mut path = get_config_folder_path();
    path.push("cache/task");
    path.push(format!("{}.toml", task_fqn));
    path
}

pub fn is_valid_task_fqn(task_fqn: &str) -> Option<(String, String, String, Option<String>)> {
    if let Some((username, name_with_version)) = task_fqn.split_once("/") {
        let (name, version) = if let Some((name, version)) = name_with_version.split_once("@") {
            (name, Some(version.to_string()))
        } else {
            (name_with_version, None)
        };
        if username.len() < 3 {
            return None;
        }
        if name.is_empty() {
            return None;
        }
        if username.contains(".") || name.contains(".") {
            return None;
        }
        if username.contains("/") || name.contains("/") {
            return None;
        }
        if username.contains("\\") || name.contains("\\") {
            return None;
        }
        Some((
            username.into(),
            name.into(),
            format!("{}/{}", username, name),
            version,
        ))
    } else {
        None
    }
}

pub fn mk_task_cache_username_path(username: &str) -> Result<(), Box<dyn Error>> {
    let mut path = get_config_folder_path();
    path.push("cache/task");
    path.push(username);
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn write_task_to_cache_path(task_fqn: &str, config: &str) -> Result<(), Box<dyn Error>> {
    // Caller should have done validation, so panic if invalid.
    let (username, _task_name, _task_fqn_versionless, version) =
        is_valid_task_fqn(task_fqn).expect("error: invalid task name");
    if version.is_some() {
        panic!("error: unexpected version specification");
    }
    mk_task_cache_username_path(&username)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(get_task_cache_path(task_fqn))?;
    file.write_all(config.as_bytes())?;
    Ok(())
}

pub fn purge_cached_task(task_fqn: &str) -> Result<(), Box<dyn Error>> {
    if is_valid_task_fqn(task_fqn).is_none() {
        // Caller should have done validation, so panic if invalid.
        panic!("error: invalid task name");
    };
    let path = get_task_cache_path(task_fqn);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

// ---

fn get_debug_log_path() -> PathBuf {
    let mut path = get_config_folder_path();
    path.push("debug.log");
    path
}

pub fn write_to_debug_log(log: String) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(get_debug_log_path())?;
    file.write_all(log.as_bytes())?;
    Ok(())
}

// ---

pub fn get_sqlite_db_path() -> PathBuf {
    let mut path = get_config_folder_path();
    path.push("data.db");
    path
}

// ---

pub fn get_history_path() -> PathBuf {
    let mut path = get_config_folder_path();
    path.push("history");
    path
}

// --

/// Prints error to terminal if key not set.
pub fn check_api_key(ai: &AiModel, cfg: &Config) -> bool {
    match ai {
        AiModel::OpenAi(_) => {
            if cfg
                .openai
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires an OpenAI API Key: `/set-key openai <key>` OR `/hai-router on`",
                    get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        AiModel::Anthropic(_) => {
            if cfg
                .anthropic
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires an Anthropic API Key: `/set-key anthropic <key>` OR `/hai-router on`",
                    get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        AiModel::DeepSeek(_) => {
            if cfg
                .deepseek
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires a DeepSeek API Key: `/set-key deepseek <key>` OR `/hai-router on`",
                    get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        AiModel::Google(_) => {
            if cfg
                .google
                .as_ref()
                .and_then(|c| c.api_key.as_ref())
                .is_none()
            {
                eprintln!(
                    "error: model '{}' requires a Google API Key: `/set-key google <key>` OR `/hai-router on`",
                    get_ai_model_display_name(ai)
                );
                return false;
            }
        }
        AiModel::Ollama(_) | AiModel::Void(_) => {
            // No auth needed
        }
    };
    true
}

/// Choose AI to initialize REPL with.
pub fn choose_init_ai_model(cfg: &Config) -> AiModel {
    let default_ai_model = if let Some(ref ai_model_unmatched_str) = cfg.default_ai_model {
        ai_model_from_string(ai_model_unmatched_str).or_else(|| {
            eprintln!("error: unknown model {}", ai_model_unmatched_str);
            None
        })
    } else {
        None
    };
    if let Some(ai_model) = default_ai_model {
        ai_model
    } else if let Some(OpenAiConfig {
        api_key: Some(_), ..
    }) = cfg.openai
    {
        AiModel::OpenAi(OpenAiModel::Gpt41)
    } else if let Some(AnthropicConfig {
        api_key: Some(_), ..
    }) = cfg.anthropic
    {
        AiModel::Anthropic(AnthropicModel::Sonnet4(false))
    } else if let Some(DeepSeekConfig {
        api_key: Some(_), ..
    }) = cfg.deepseek
    {
        AiModel::DeepSeek(DeepSeekModel::DeepSeekChat)
    } else if let Some(GoogleConfig {
        api_key: Some(_), ..
    }) = cfg.google
    {
        AiModel::Google(GoogleModel::Gemini25Flash)
    } else if let Some(OllamaConfig { base_url: Some(_) }) = cfg.ollama {
        AiModel::Ollama(OllamaModel::Llama32)
    } else {
        AiModel::OpenAi(OpenAiModel::Gpt41)
    }
}

// --

pub fn get_machine_os_arch() -> String {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(all(target_arch = "arm", target_feature = "v7")) {
        "armv7"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "unknown"
    };
    format!("{}-{}", os, arch)
}
