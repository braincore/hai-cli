use base64::Engine;
use base64::engine::general_purpose;
use colored::Colorize;
use num_format::{Locale, ToFormattedString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::io::Io;
use crate::{
    api, asset_async_writer, asset_cache::AssetBlobCache, asset_reader, chat, config,
    ctrlc_handler, db, feature::asset_crypt, io::Out, session,
};
use crate::{errorln, flush, infoln, out, outln};

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
    io: &Io,
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

    let mut needs_attachment = false;
    for log_entry in session.history.iter() {
        if log_entry.retention_policy.1 == db::LogEntryRetentionPolicy::ConversationLoad {
            if let chat::MessageContent::ImageUrl { image_url, .. } = &log_entry.message.content[0]
            {
                if !image_url.url.starts_with(':') {
                    needs_attachment = true;
                }
            }
        }
    }

    // Check if chatlog asset already exists. If it doesn't, we may need to
    // create it first to attach images.
    let mut existing_entry_id =
        match asset_reader::get_asset_entry(api_client, &chat_log_asset_name, true).await {
            Ok(get_res) => Some(get_res.entry.entry_id.clone()),
            Err(asset_reader::GetAssetError::BadName) => None,
            Err(asset_reader::GetAssetError::DataFetchFailed(failure)) => {
                errorln!(
                    io,
                    "failed to get asset data: {}: {}",
                    chat_log_asset_name,
                    failure
                );
                return;
            }
        };

    let akm_info = match asset_crypt::choose_akm_for_asset_by_name(
        io,
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
                    errorln!(io, "{}", msg);
                }
            }
            return;
        }
    };

    if existing_entry_id.is_none() && needs_attachment {
        // Create a blank asset first to attach images to.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = update_asset_tx
            .send(asset_async_writer::WorkerAssetMsg::Update(
                asset_async_writer::WorkerAssetUpdate {
                    asset_name: chat_log_asset_name.clone(),
                    asset_entry_ref: None,
                    new_contents: vec![],
                    is_push: false,
                    api_client: api_client.clone(),
                    one_shot: true,
                    akm_info: akm_info.clone(),
                    reply_channel: Some(reply_tx),
                },
            ))
            .await;
        if let Ok(Ok(new_entry)) = reply_rx.await {
            existing_entry_id = Some(new_entry.entry_id.clone());
        }
    }

    let abridged_history = session::get_abridged_history(&session.history);
    let abridged_history_tokens = bpe_tokenizer.encode_with_special_tokens(&abridged_history);
    let chat_title = if abridged_history.len() > 100 {
        outln!(
            io,
            "Generating title ({} tokens)...",
            abridged_history_tokens
                .len()
                .to_formatted_string(&Locale::en)
        );
        flush!(io);
        // FIXME: prompt_ai_simple needs to use out?
        prompt_ai_simple(
            &io.out,
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
    outln!(io, "Saving to asset: {}", chat_log_asset_name);

    let mut new_ids = std::collections::HashSet::new();

    //
    // First pass: Identify any image URLs that are in b64 format that do not
    // have an ID. The lack of ID means that they are not yet backed by an
    // attachment to the chat asset. This first pass only assigns an ID and
    // keeps track of which IDs are new so that the following pass can create
    // the actual attachments.
    //

    for log_entry in session.history.iter_mut() {
        if log_entry.retention_policy.1 == db::LogEntryRetentionPolicy::ConversationLoad {
            if let chat::MessageContent::ImageUrl { id, image_url } =
                &mut log_entry.message.content[0]
            {
                if image_url.url.starts_with(':') {
                    // This isn't expected since history should always contain
                    // image b64 data rather than attachment names.
                    continue;
                }

                if id.is_none() {
                    let new_id = uuid::Uuid::now_v7();
                    *id = Some(new_id);
                    new_ids.insert(new_id);
                }
            }
        }
    }

    //
    // Second pass: Clone the history and create attachments for any new IDs.
    // This is done in a cloned copy because the session history needs to
    // continue using b64 data for the image URLs. The version saved to assets
    // can substitute for the attachment name. Note that on resume, the
    // conversion back to b64 data is performed.
    //

    let mut history_to_save = session.history.clone();
    if let Some(entry_id) = existing_entry_id {
        for log_entry in history_to_save.iter_mut() {
            if log_entry.retention_policy.1 == db::LogEntryRetentionPolicy::ConversationLoad {
                if let chat::MessageContent::ImageUrl { id, image_url } =
                    &mut log_entry.message.content[0]
                {
                    let Some(image_id) = id else {
                        // Unexpected since IDs were just assigned
                        panic!("unexpected: missing id");
                    };

                    let attachment_asset_name = format!(":{}:{}", entry_id, image_id);

                    if !new_ids.contains(image_id) {
                        // It's not new, so just swap for the attachment name
                        image_url.url = attachment_asset_name.clone();
                        continue;
                    }

                    if !image_url.url.starts_with("data:image/") {
                        errorln!(io, "image url is not in b64 format: {}", image_url.url);
                        continue;
                    }
                    let Some((content_type, b64_data)) =
                        image_url.url.split_once(',').and_then(|(prefix, b64)| {
                            // prefix looks like: "data:image/png;base64"
                            let mime = prefix.strip_prefix("data:")?.strip_suffix(";base64")?;
                            Some((mime, b64))
                        })
                    else {
                        errorln!(io, "failed to parse image b64 data");
                        continue;
                    };

                    // Decode the image from b64 first and store it as raw bytes
                    let Ok(raw) = general_purpose::STANDARD.decode(b64_data) else {
                        errorln!(io, "failed to decode image b64 data");
                        continue;
                    };
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = update_asset_tx
                        .send(asset_async_writer::WorkerAssetMsg::Update(
                            asset_async_writer::WorkerAssetUpdate {
                                asset_name: attachment_asset_name.clone(),
                                asset_entry_ref: None,
                                new_contents: raw,
                                is_push: false,
                                api_client: api_client.clone(),
                                one_shot: true,
                                akm_info: akm_info.clone(),
                                reply_channel: Some(reply_tx),
                            },
                        ))
                        .await;
                    if let Ok(Ok(_new_entry)) = reply_rx.await {
                        // Save content_type for better display when attachment is
                        // accessed directly.
                        let _ = asset_async_writer::asset_metadata_set_key(
                            api_client,
                            &attachment_asset_name.clone(),
                            "content_type",
                            Some(content_type.into()),
                        )
                        .await;
                    }

                    image_url.url = attachment_asset_name;
                }
            }
        }
    }

    let serialized_log = if let Ok(res) = serde_json::to_string_pretty(&ChatLog {
        history: history_to_save,
    }) {
        res.into_bytes()
    } else {
        errorln!(io, "failed to serialize chat log");
        return;
    };
    session.chat_log_asset_name = Some(chat_log_asset_name.clone());

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
        api_client,
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
///
/// # Arguments
/// - `fork`: If set, does not save chat_log_asset_name so that a new asset is
///   created when re-saving.
pub async fn resume_chat_from_db_or_asset(
    io: &Io,
    session: &mut session::SessionState,
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &api::client::HaiClient,
    chat_log_name: Option<&str>,
    fork: bool,
) {
    let chat_log_contents = if let Some(chat_log_name) = chat_log_name {
        let username = session
            .account
            .as_ref()
            .map(|account| account.username.clone());
        match asset_reader::get_decrypted_asset_and_metadata(
            io,
            asset_blob_cache.clone(),
            session.asset_keyring.clone(),
            api_client,
            username.as_deref(),
            &chat_log_name,
        )
        .await
        {
            Ok((decrypted_contents, _asset_entry)) => decrypted_contents,
            Err(e) => {
                errorln!(io, "failed to get chat {}: {}", chat_log_name, e);
                return;
            }
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
            errorln!(io, "no chat saved");
            return;
        }
    };

    session.cmd_task_end().await;
    session.cmd_new().await;
    if !fork && let Some(chat_log_name) = chat_log_name {
        use crate::api::types::asset::{AssetEntryAclGetEffectiveArg, EntryRef};
        match api_client
            .asset_entry_acl_get_effective(AssetEntryAclGetEffectiveArg {
                entry_ref: EntryRef::Name(chat_log_name.to_string()),
            })
            .await
        {
            Ok(res) => {
                if res.write_data {
                    session.chat_log_asset_name = Some(chat_log_name.to_string());
                } else {
                    infoln!(
                        io,
                        "chat log is read-only. /chat-save will save to new asset."
                    );
                }
            }
            _ => {}
        };
    }

    match serde_json::from_slice::<ChatLog>(&chat_log_contents) {
        Ok(res) => {
            session.history = res.history;
        }
        Err(_e) => {
            // Fallback to legacy format.
            let history = match serde_json::from_slice::<Vec<db::LogEntry>>(&chat_log_contents) {
                Ok(res) => res,
                Err(e) => {
                    errorln!(io, "chat log bad format: {}", e);
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
    for (i, log_entry) in session.history.iter_mut().enumerate() {
        let role_name = match log_entry.message.role {
            chat::MessageRole::Assistant => "assistant",
            chat::MessageRole::User => "user",
            chat::MessageRole::Tool => "tool",
            chat::MessageRole::System => break,
        };

        if log_entry.retention_policy.1 == db::LogEntryRetentionPolicy::ConversationLoad {
            session.input_loaded_tokens += log_entry.tokens;
            if let chat::MessageContent::Text { text } = &log_entry.message.content[0] {
                // FIXME
                outln!(
                    io,
                    "{}[{}]: {}",
                    role_name,
                    i,
                    text.split_once("\n").unwrap_or((text, "")).0
                );
                outln!(io);
            } else if let chat::MessageContent::ImageUrl { id, image_url } =
                &mut log_entry.message.content[0]
            {
                outln!(io, "{}[{}]:", role_name, i);

                // Three types of image urls need to be handled:
                // 1. A legit URL (http:// or https://)
                // 2. An attachment (starts with `:`)
                // 3. An image/png b64 format (starts with `data:image/png;base64,`)
                let url = if let Some(_image_id) = id
                    && image_url.url.starts_with(':')
                {
                    let username = session
                        .account
                        .as_ref()
                        .map(|account| account.username.clone());
                    match asset_reader::get_decrypted_asset_and_metadata(
                        io,
                        asset_blob_cache.clone(),
                        session.asset_keyring.clone(),
                        api_client,
                        username.as_deref(),
                        &image_url.url,
                    )
                    .await
                    {
                        Ok((decrypted_contents, _asset_entry)) => {
                            let img_b64 = general_purpose::STANDARD.encode(&decrypted_contents);
                            let img_url = format!("data:image/png;base64,{}", img_b64);
                            img_url
                        }
                        Err(e) => {
                            errorln!(io, "failed to get image attachment: {}", e);
                            continue;
                        }
                    }
                } else {
                    image_url.url.clone()
                };
                match crate::loader::resolve_image_b64(&url, false).await {
                    Ok((img_png_b64, _dim)) => {
                        io.display("image/png", &img_png_b64);
                        outln!(io);
                        image_url.url = format!("data:image/png;base64,{}", img_png_b64);
                    }
                    Err(e) => {
                        errorln!(io, "failed to load image: {}", e);
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
                    if io.is_terminal() {
                        println!("{}", left_prompt.bright_green());
                        io.record_out(&left_prompt);
                    } else {
                        outln!(io, "{}", left_prompt);
                    }
                    for tool_call in tool_calls {
                        let tool_name = tool_call.function.name.clone();
                        let mut json_obj_acc = crate::ai_provider::util::JsonObjectAccumulator::new(
                            tool_call.id.clone(),
                            tool_name.clone(),
                            crate::ai_provider::tool_schema::get_syntax_highlighter_token_from_tool_name(&tool_name),
                            vec![],
                        );
                        json_obj_acc.acc(&tool_call.function.arguments, &io.out);
                        json_obj_acc.end(&io.out);
                        outln!(io);
                        outln!(io);
                    }
                } else {
                    if io.is_terminal() {
                        print!("{} ", left_prompt.bright_green());
                        io.record_out(&format!("{} ", left_prompt));
                    } else {
                        out!(io, "{}", left_prompt);
                    }
                    crate::term_color::print_multi_lang_syntax_highlighting(
                        &io.out,
                        &entry_body,
                        &None,
                    );
                    outln!(io);
                }
            } else {
                if io.is_terminal() {
                    print!("{}", left_prompt.bright_green());
                    io.record_out(&left_prompt);
                } else {
                    out!(io, "{}", left_prompt);
                }
            }
        }
    }
}

// --

async fn prompt_ai_simple(
    out: &Out,
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
        &out,
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
