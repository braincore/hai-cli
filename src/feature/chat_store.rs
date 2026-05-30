use colored::Colorize;
use num_format::{Locale, ToFormattedString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    api, asset_async_writer, asset_cache::AssetBlobCache, asset_reader, chat, config,
    ctrlc_handler, db, feature::asset_crypt, session,
};

/// Saves chat to the local db for the session user.
///
/// Does not save if session is incognito, or if it has yet to have a
/// user-generated message excluding task-setup ones.
pub async fn save_chat_to_db(
    session: &session::SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
) {
    if session.incognito {
        return;
    }
    if !session.history.iter().any(|entry| {
        matches!(entry.message.role, chat::MessageRole::User) && !entry.retention_policy.0
    }) {
        // If the history doesn't have a user-generated message (task-setup
        // step doesn't count), then no-op.
        return;
    }
    let username = if let Some(account) = session.account.as_ref() {
        account.username.clone()
    } else {
        "".to_string()
    };
    let serialized_log = serde_json::to_string_pretty(&session.history).unwrap();
    db::set_misc_entry(&*db.lock().await, &username, "chat-last", &serialized_log)
        .expect("failed to write to db");
}

/// Saves chat to assets
pub async fn save_chat_as_asset(
    session: &mut session::SessionState,
    cfg: &config::Config,
    asset_blob_cache: Arc<AssetBlobCache>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    bpe_tokenizer: &tiktoken_rs::CoreBPE,
    api_client: &api::client::HaiClient,
    username: &str,
    chat_log_name: Option<&str>,
    debug: bool,
) {
    let chat_log_asset_name = if let Some(chat_log_name) = chat_log_name {
        chat_log_name.to_owned()
    } else {
        let now = chrono::Local::now();
        format!("chat/{}", now.format("%Y-%m-%d-%H%M%S"))
    };

    let abridged_history = session::get_abridged_history(&session.history);
    let abridged_history_tokens = bpe_tokenizer.encode_with_special_tokens(&abridged_history);
    let chat_title = if abridged_history.len() > 100 {
        println!(
            "Generating title ({} tokens)...",
            abridged_history_tokens
                .len()
                .to_formatted_string(&Locale::en)
        );
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        prompt_ai_simple(
            &format!(
                r#"Generate a short title for the included chat log.
Do not quote it.
Do not include anything besides the title.
Since the chat is already known as a conversation, do
not include words that imply its a conversation or
lesson (e.g. "understanding").\n\n{}"#,
                abridged_history
            ),
            session,
            cfg,
            ctrlc_handler,
            debug,
        )
        .await
    } else {
        None
    };
    println!("Saving to asset: {}", chat_log_asset_name);
    let serialized_log = if let Ok(res) = serde_json::to_string_pretty(&ChatLog {
        history: session.history.clone(),
    }) {
        res.into_bytes()
    } else {
        eprintln!("error: failed to serialize chat log");
        return;
    };

    let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
        asset_blob_cache.clone(),
        session.asset_keyring.clone(),
        api_client.clone(),
        Some(&asset_crypt::KeyRecipient::User(username.to_string())),
        &chat_log_asset_name,
        false,
    )
    .await
    {
        Ok(akm_info) => akm_info,
        Err(e) => {
            match e {
                asset_crypt::AkmSelectionError::Abort(msg) => {
                    eprintln!("error: {}", msg);
                }
            }
            return;
        }
    };

    let _ = update_asset_tx
        .send(asset_async_writer::WorkerAssetMsg::Update(
            asset_async_writer::WorkerAssetUpdate {
                asset_name: chat_log_asset_name.clone(),
                asset_entry_ref: None,
                new_contents: serialized_log,
                is_push: false,
                api_client: api_client.clone(),
                one_shot: true,
                akm_info: akm_info.clone(),
                reply_channel: None,
            },
        ))
        .await;

    // Wait for write to complete before setting metadata
    asset_async_writer::flush_asset_updates(&update_asset_tx).await;

    let mut metadata_keys: Vec<(&str, Option<serde_json::Value>)> = vec![(
        "open_with",
        Some(serde_json::json!([
            {
                "handler": {
                    "type": "asset_app",
                    "asset_name": "/hai/app/chatlog"
                }
            }
        ])),
    )];

    if let Some(chat_title) = chat_title.as_ref() {
        metadata_keys.push(("title", Some(serde_json::Value::String(chat_title.clone()))));
    }

    let _ = asset_async_writer::asset_metadata_set_keys(
        &api_client,
        &chat_log_asset_name,
        &metadata_keys,
    )
    .await;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatLog {
    history: Vec<db::LogEntry>,
}

// --

/// Resumes a chat from a chat log.
///
/// If chat name isn't specified, the most recent chat stored in the local db
/// is used.
pub async fn resume_chat_from_db_or_asset(
    session: &mut session::SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &api::client::HaiClient,
    chat_log_name: Option<&str>,
) {
    let chat_log_contents = if let Some(chat_log_name) = chat_log_name {
        let (asset_contents, md_contents, _asset_entry) =
            match asset_reader::get_asset_and_metadata(
                asset_blob_cache.clone(),
                &api_client,
                &chat_log_name,
                false,
            )
            .await
            .map(|(ac, mc, ae)| (ac, mc, Some(ae)))
            {
                Ok(asset_get_res) => asset_get_res,
                Err(asset_reader::GetAssetError::BadName) => {
                    eprintln!("error: bad asset name: {}", chat_log_name);
                    return;
                }
                Err(asset_reader::GetAssetError::DataFetchFailed) => {
                    eprintln!("error: failed to get asset data: {}", chat_log_name);
                    return;
                }
            };
        let username = session
            .account
            .as_ref()
            .map(|account| account.username.clone());
        let akm_info = match asset_crypt::choose_akm_for_asset(
            asset_blob_cache.clone(),
            session.asset_keyring.clone(),
            api_client.clone(),
            username
                .as_ref()
                .map(|u| asset_crypt::KeyRecipient::User(u.to_string()))
                .as_ref(),
            username
                .map(|u| {
                    asset_crypt::extract_key_recipients_from_shared_asset_name(&chat_log_name, &u)
                })
                .as_deref()
                .unwrap_or(&[]),
            md_contents.as_deref(),
            None,
        )
        .await
        {
            Ok(akm_info) => akm_info,
            Err(e) => {
                match e {
                    asset_crypt::AkmSelectionError::Abort(msg) => {
                        eprintln!("error: {}", msg);
                    }
                }
                return;
            }
        };

        if let Some(akm_info) = &akm_info {
            let enc_content = crate::crypt::EncryptedContent::from_bytes(&asset_contents).unwrap();
            crate::crypt::decrypt_content(&enc_content, &akm_info.unlocked_akm.sym_key_info.aes_key)
                .unwrap()
        } else {
            asset_contents.clone()
        }
    } else {
        let username = if let Some(account) = session.account.as_ref() {
            account.username.clone()
        } else {
            "".to_string()
        };
        if let Some(res) = db::get_misc_entry(&*db.lock().await, &username, "chat-last")
            .expect("failed to write to db")
        {
            res.0.into_bytes()
        } else {
            eprintln!("error: no chat saved");
            return;
        }
    };

    session.cmd_task_end().await;
    session.cmd_new().await;

    match serde_json::from_slice::<ChatLog>(&chat_log_contents) {
        Ok(res) => {
            session.history = res.history;
        }
        Err(_e) => {
            // Fallback to legacy format.
            let history = match serde_json::from_slice::<Vec<db::LogEntry>>(&chat_log_contents) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("error: chat log bad format: {}", e);
                    return;
                }
            };
            session.history = history;
        }
    };

    // Set LLM Model from history
    for entry in session.history.iter().rev() {
        if let Some(model_str) = &entry.model {
            if let Some(ai_model) = config::ai_model_from_string(model_str) {
                session.ai = ai_model;
                break;
            }
        }
    }

    // Print out conversation to help user regain context
    for (i, log_entry) in session.history.iter().enumerate() {
        let role_name = match log_entry.message.role {
            chat::MessageRole::Assistant => "assistant",
            chat::MessageRole::User => "user",
            chat::MessageRole::Tool => "tool",
            chat::MessageRole::System => break,
        };

        if log_entry.retention_policy.1 == db::LogEntryRetentionPolicy::ConversationLoad {
            session.input_loaded_tokens += log_entry.tokens;
            if let chat::MessageContent::Text { text } = &log_entry.message.content[0] {
                println!(
                    "{}[{}]: {}",
                    role_name,
                    i,
                    text.split_once("\n").unwrap_or((text, "")).0
                );
                println!();
            } else if let chat::MessageContent::ImageUrl { image_url } =
                &log_entry.message.content[0]
            {
                println!("{}[{}]:", role_name, i);
                match crate::loader::resolve_image_b64(&image_url.url).await {
                    Ok(img_png_b64) => {
                        crate::term::print_image_to_term(&img_png_b64).unwrap();
                        println!();
                    }
                    Err(e) => {
                        eprintln!("error: failed to load image: {}", e);
                    }
                }
            }
        } else {
            let mut entry_body = String::new();
            session.input_tokens += log_entry.tokens;
            for part in &log_entry.message.content {
                match part {
                    chat::MessageContent::Text { text } => {
                        entry_body.push_str(text);
                    }
                    chat::MessageContent::ImageUrl { .. } => entry_body.push_str("[image]"),
                }
                entry_body.push('\n');
            }

            let left_prompt = format!("{}[{}]:", role_name, i);
            if matches!(log_entry.message.role, chat::MessageRole::Assistant) {
                if let Some(tool_calls) = log_entry.message.tool_calls.as_ref() {
                    println!("{}", left_prompt.bright_green());
                    for tool_call in tool_calls {
                        let tool_name = tool_call.function.name.clone();
                        let mut json_obj_acc = crate::ai_provider::util::JsonObjectAccumulator::new(
                            tool_call.id.clone(),
                            tool_name.clone(),
                            crate::ai_provider::tool_schema::get_syntax_highlighter_token_from_tool_name(&tool_name),
                            vec![],
                        );
                        json_obj_acc.acc(&tool_call.function.arguments);
                        json_obj_acc.end();
                        println!();
                        println!();
                    }
                } else {
                    print!("{} ", left_prompt.bright_green());
                    crate::term_color::print_multi_lang_syntax_highlighting(&entry_body, &None);
                    println!();
                }
            } else {
                print!("{} {}", left_prompt.bright_green(), entry_body);
            }
        }
    }
}

// --

async fn prompt_ai_simple(
    prompt: &str,
    session: &mut session::SessionState,
    cfg: &config::Config,
    ctrlc_handler: &mut ctrlc_handler::CtrlcHandler,
    debug: bool,
) -> Option<String> {
    let msg_history = vec![chat::Message {
        role: chat::MessageRole::User,
        content: vec![chat::MessageContent::Text {
            text: prompt.to_string(),
        }],
        tool_call_id: None,
        tool_calls: None,
    }];
    let res = crate::prompt_ai(
        &msg_history,
        &None,
        &Vec::new(),
        session,
        cfg,
        ctrlc_handler,
        debug,
    )
    .await;
    for chat_response in &res {
        if let chat::ChatCompletionResponse::Message { text } = chat_response {
            return Some(text.clone());
        }
    }
    None
}
