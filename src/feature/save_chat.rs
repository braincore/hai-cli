use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{chat, db, session::SessionState};

/// Saves chat to the local db for the session user.
///
/// Does not save if session is incognito, or if it has yet to have a
/// user-generated message excluding task-setup ones.
pub async fn save_chat_to_db(session: &SessionState, db: Arc<Mutex<rusqlite::Connection>>) {
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
