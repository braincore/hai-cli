use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::{chat, config};

fn default_now() -> chrono::DateTime<chrono::Local> {
    chrono::Local::now()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub uuid: String,
    /// Defaults to the current time for backwards compatibility.
    #[serde(default = "default_now")]
    pub ts: chrono::DateTime<chrono::Local>,
    pub message: chat::Message,
    pub tokens: u32,
    /// If bool true, log_entry from task-mode step.
    pub retention_policy: (bool, LogEntryRetentionPolicy),
}

impl LogEntry {
    pub fn mk_preview_string(&self) -> String {
        let mut preview = String::new();
        if self.retention_policy.1 == LogEntryRetentionPolicy::ConversationLoad {
            if let chat::MessageContent::Text { text } = &self.message.content[0] {
                preview.push_str(text.split_once("\n").unwrap().0);
            } else if let chat::MessageContent::ImageUrl { image_url } = &self.message.content[0] {
                preview.push_str(&image_url.url[..10]);
            }
        } else {
            for part in &self.message.content {
                match part {
                    chat::MessageContent::Text { text } => {
                        preview.push_str(text);
                    }
                    chat::MessageContent::ImageUrl { .. } => preview.push_str("[image]"),
                }
                preview.push('\n');
            }
        }
        preview
    }
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub enum LogEntryRetentionPolicy {
    None,
    ConversationPin,
    ConversationLoad,
    TaskStep,
}

pub fn open_db() -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(config::get_sqlite_db_path())?;

    // Make DB more robust
    conn.execute("PRAGMA foreign_keys = ON", [])?;
    conn.pragma_update(None, "journal_mode", "WAL")?;

    // Create task step cache table
    migrate_task_step_cache_table(&conn)?;

    // Create account table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS account (
            user_id TEXT PRIMARY KEY, -- Unique user ID fetched from the server
            username TEXT NOT NULL, -- Username of the account
            token TEXT NOT NULL, -- Authentication token
            logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Timestamp of the last login
            active BOOLEAN NOT NULL DEFAULT true -- Whether the account is currently active
        )",
        rusqlite::params![],
    )?;

    // Create misc table for k/v storage
    conn.execute(
        "CREATE TABLE IF NOT EXISTS misc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            key TEXT,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Timestamp of last update
            UNIQUE (username, key)
        )",
        rusqlite::params![],
    )?;

    // Create listen_queue table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS listen_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_name TEXT NOT NULL,
            cmds TEXT NOT NULL, -- JSON-serialized commands
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        rusqlite::params![],
    )?;
    Ok(conn)
}

/// Migrates the task_step_cache table to include a username column.
/// If the table exists with the old schema, it will be dropped and recreated.
pub fn migrate_task_step_cache_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    // Check if the table exists
    let mut stmt = conn.prepare("PRAGMA table_info(task_step_cache)")?;
    let mut col_names = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let col_name: String = row.get(1)?; // 1 = name
        col_names.push(col_name);
    }

    // If the first column is not "username", or username is missing, we need to migrate
    let needs_migration =
        col_names.is_empty() || col_names[0] != "username" || col_names[2] != "task_key";

    if needs_migration {
        // Drop the old table if it exists
        conn.execute("DROP TABLE IF EXISTS task_step_cache", [])?;

        // Create the new table with username as the first column and part of the PRIMARY KEY
        conn.execute(
            "CREATE TABLE IF NOT EXISTS task_step_cache (
                username TEXT NOT NULL,
                task_name TEXT NOT NULL,
                task_key TEXT NOT NULL,
                step_index INTEGER NOT NULL,
                step_cmd TEXT NOT NULL,
                response TEXT NOT NULL,
                PRIMARY KEY (username, task_name, task_key, step_index, step_cmd)
            )",
            [],
        )?;
    }
    Ok(())
}

//
// Account fns
//

#[derive(Clone, Debug)]
pub struct Account {
    #[allow(dead_code)]
    pub user_id: String,
    pub username: String,
    pub token: String,
}

pub fn login_account(
    conn: &rusqlite::Connection,
    user_id: &str,
    username: &str,
    token: &str,
) -> rusqlite::Result<()> {
    // There can be only one active account. Set the account being logged into
    // as active.
    conn.execute("UPDATE account SET active = 0", [])?;
    // Delete all accounts where the `user_id` is different that the latest
    // login but the `username` is the same. This currently only applies to
    // test environments, but in the future is a good guard against activating
    // the wrong account due to username changes.
    conn.execute(
        "DELETE FROM account WHERE username = ?1 AND user_id <> ?2",
        rusqlite::params![username, user_id],
    )?;
    conn.execute(
        "INSERT INTO account (user_id, username, token, logged_in_at, active)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, 1)
         ON CONFLICT(user_id)
         DO UPDATE SET
            username = excluded.username,
            token = excluded.token,
            logged_in_at = CURRENT_TIMESTAMP,
            active = 1",
        rusqlite::params![user_id, username, token],
    )?;
    Ok(())
}

pub fn get_active_account(conn: &rusqlite::Connection) -> rusqlite::Result<Option<Account>> {
    let query = "SELECT user_id, username, token FROM account WHERE active = 1";
    let result: rusqlite::Result<(String, String, String)> = conn.query_row(query, [], |row| {
        Ok((
            row.get(0)?, // user_id
            row.get(1)?, // username
            row.get(2)?, // token
        ))
    });

    match result {
        Ok((user_id, username, token)) => {
            let account = Account {
                user_id,
                username,
                token,
            };
            Ok(Some(account))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), // No active account found
        Err(e) => Err(e),
    }
}

pub fn get_account_by_username(
    conn: &rusqlite::Connection,
    username: &str,
) -> rusqlite::Result<Option<Account>> {
    let query = "SELECT user_id, username, token FROM account WHERE username = ?1";
    let result: rusqlite::Result<(String, String, String)> =
        conn.query_row(query, rusqlite::params![username], |row| {
            Ok((
                row.get(0)?, // user_id
                row.get(1)?, // username
                row.get(2)?, // token
            ))
        });

    match result {
        Ok((user_id, username, token)) => {
            let account = Account {
                user_id,
                username,
                token,
            };
            Ok(Some(account))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), // No active account found
        Err(e) => Err(e),
    }
}

pub fn switch_account(
    conn: &rusqlite::Connection,
    username: &str,
) -> rusqlite::Result<Option<Account>> {
    let account_exists: bool = conn
        .query_row(
            "SELECT 1 FROM account WHERE username = ?1",
            rusqlite::params![username],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !account_exists {
        return Ok(None);
    }

    // Update all accounts to be inactive
    conn.execute("UPDATE account SET active = 0", [])?;

    // Set the requested account to active
    conn.execute(
        "UPDATE account SET active = 1 WHERE username = ?1",
        rusqlite::params![username],
    )?;

    let account = conn.query_row(
        "SELECT user_id, username, token FROM account WHERE username = ?1",
        rusqlite::params![username],
        |row| {
            Ok(Account {
                user_id: row.get(0)?,
                username: row.get(1)?,
                token: row.get(2)?,
            })
        },
    )?;

    Ok(Some(account))
}

pub fn switch_to_nobody_account(
    conn: &rusqlite::Connection,
    username: &str,
) -> rusqlite::Result<Option<()>> {
    let account_exists: bool = conn
        .query_row(
            "SELECT 1 FROM account WHERE username = ?1",
            rusqlite::params![username],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !account_exists {
        return Ok(None);
    }

    // Set the requested account to active
    conn.execute(
        "UPDATE account SET active = 0 WHERE username = ?1",
        rusqlite::params![username],
    )?;

    Ok(Some(()))
}

pub fn remove_account(conn: &rusqlite::Connection, username: &str) -> rusqlite::Result<()> {
    // Delete the account with the matching username
    conn.execute(
        "DELETE FROM account WHERE username = ?1",
        rusqlite::params![username],
    )?;
    Ok(())
}

pub fn list_accounts(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT username FROM account")?;
    let rows = stmt.query_map([], |row| row.get(0))?;

    let mut usernames = Vec::new();
    for row in rows {
        usernames.push(row?);
    }

    Ok(usernames)
}

//
// Misc (key-value store) fns
//

/// Set a key-value pair into the misc table with updated_at update
/// If for a user-agnostic k/v, set username to empty string.
pub fn set_misc_entry(
    conn: &rusqlite::Connection,
    username: &str,
    key: &str,
    value: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO misc (username, key, value, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
         ON CONFLICT(username, key) DO UPDATE SET
         value = excluded.value,
         updated_at = CURRENT_TIMESTAMP",
        rusqlite::params![username, key, value],
    )?;
    Ok(())
}

/// Retrieve a value and its updated_at timestamp by its key
pub fn get_misc_entry(
    conn: &rusqlite::Connection,
    username: &str,
    key: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    conn.query_row(
        "SELECT value, updated_at FROM misc WHERE username = ?1 AND key = ?2",
        rusqlite::params![username, key],
        |row| {
            let value: String = row.get(0)?; // The value
            let updated_at: String = row.get(1)?; // The timestamp (as a string)
            Ok((value, updated_at))
        },
    )
    .optional()
}

// Delete a key-value pair from the misc table by its key
#[allow(dead_code)]
pub fn delete_misc_entry(conn: &rusqlite::Connection, key: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM misc WHERE key = ?1", rusqlite::params![key])?;
    Ok(())
}

//
// Step-Cache fns
// The cache lets us store the answers to /ask-human commands so that they
// don't have to be re-asked the next time. FUTURE: Expand the functionality
// to include caching local execs.
//

pub fn get_task_step_cache(
    conn: &rusqlite::Connection,
    username: &str,
    task_name: &str,
    task_key: Option<&str>,
    step_index: u32,
    step_cmd: &str,
) -> Option<String> {
    let result: Option<String> = conn
        .query_row(
            "SELECT response FROM task_step_cache 
         WHERE username = ?1 AND task_name = ?2 AND task_key = ?3 AND step_index = ?4 AND step_cmd = ?5",
            rusqlite::params![username, task_name, task_key.unwrap_or(""), step_index, step_cmd],
            |row| row.get(0),
        )
        .ok();
    result
}

pub fn set_task_step_cache(
    conn: &rusqlite::Connection,
    username: &str,
    task_name: &str,
    task_key: Option<&str>,
    step_index: u32,
    step_cmd: &str,
    response: &str,
) {
    conn.execute(
        "INSERT INTO task_step_cache (username, task_name, task_key, step_index, step_cmd, response) 
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(username, task_name, task_key, step_index, step_cmd) DO UPDATE SET
        response = excluded.response
        ",
        rusqlite::params![username, task_name, task_key.unwrap_or(""), step_index, step_cmd, response],
    )
    .expect("Failed to insert");
}

pub fn forget_task_step_cache(
    conn: &rusqlite::Connection,
    username: &str,
    task_name: &str,
    task_key: Option<&str>,
) {
    conn.execute(
        "DELETE FROM task_step_cache WHERE username=?1 AND task_name=?2 AND task_key=?3",
        rusqlite::params![username, task_name, task_key.unwrap_or("")],
    )
    .expect("Failed to delete rows");
}

/// Removes cache for all users and keys for a specific task name.
pub fn purge_task_step_cache(conn: &rusqlite::Connection, task_name: &str) {
    conn.execute(
        "DELETE FROM task_step_cache WHERE task_name=?1",
        rusqlite::params![task_name],
    )
    .expect("Failed to delete rows");
}

///
/// Listen Queue functions
///
use serde_json;

/// Push a command (as Vec<String>) to the listen_queue for a given queue_name.
pub fn listen_queue_push(
    conn: &rusqlite::Connection,
    queue_name: &str,
    cmds: &Vec<String>,
) -> rusqlite::Result<()> {
    let cmds_json = serde_json::to_string(cmds)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT INTO listen_queue (queue_name, cmds, ts) VALUES (?1, ?2, CURRENT_TIMESTAMP)",
        rusqlite::params![queue_name, cmds_json],
    )?;
    Ok(())
}

/// Pop (fetch and remove) the oldest entry for a given queue_name.
/// Returns Some(Vec<String>) if found, or None if the queue is empty.
pub fn listen_queue_pop(
    conn: &mut rusqlite::Connection,
    queue_name: &str,
) -> rusqlite::Result<Option<Vec<String>>> {
    let tx = conn.transaction()?;

    // Fetch the oldest entry for this queue_name
    let row = tx
        .prepare(
            "SELECT id, cmds FROM listen_queue WHERE queue_name = ?1 ORDER BY ts ASC, id ASC LIMIT 1",
        )?
        .query_row(rusqlite::params![queue_name], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .optional()?;

    if let Some((id, cmds_json)) = row {
        tx.execute(
            "DELETE FROM listen_queue WHERE id = ?1",
            rusqlite::params![id],
        )?;
        tx.commit()?;
        let cmds: Vec<String> = serde_json::from_str(&cmds_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        Ok(Some(cmds))
    } else {
        tx.commit()?;
        Ok(None)
    }
}
