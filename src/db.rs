use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::{chat, config};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub uuid: String,
    pub message: chat::Message,
    /// If bool true, log_entry from task-mode step.
    pub retention_policy: (bool, LogEntryRetentionPolicy),
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

    // Create ask cache table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS task_step_cache (
            task_name TEXT,
            step_index INTEGER NOT NULL,
            step_cmd TEXT NOT NULL,
            response TEXT NOT NULL,
            PRIMARY KEY (task_name, step_index, step_cmd)
        )",
        rusqlite::params![],
    )?;

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
    Ok(conn)
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
    task_name: &str,
    step_index: u32,
    step_cmd: &str,
) -> Option<String> {
    let result: Option<String> = conn
        .query_row(
            "SELECT response FROM task_step_cache 
         WHERE task_name = ?1 AND step_index = ?2 AND step_cmd = ?3",
            rusqlite::params![task_name, step_index, step_cmd],
            |row| row.get(0),
        )
        .ok();
    result
}

pub fn set_task_step_cache(
    conn: &rusqlite::Connection,
    task_name: &str,
    step_index: u32,
    step_cmd: &str,
    response: &str,
) {
    conn.execute(
        "INSERT INTO task_step_cache (task_name, step_index, step_cmd, response) 
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(task_name, step_index, step_cmd) DO UPDATE SET
        response = excluded.response
        ",
        rusqlite::params![task_name, step_index, step_cmd, response],
    )
    .expect("Failed to insert");
}

pub fn purge_task_step_cache(conn: &rusqlite::Connection, task_name: &str) {
    conn.execute(
        "DELETE FROM task_step_cache WHERE task_name=?1",
        rusqlite::params![task_name],
    )
    .expect("Failed to delete rows");
}
