use std::sync::Arc;
use tokio::sync::Mutex;

use crate::api::client::HaiClient;
use crate::feature::{
    asset_crypt::{self, KeyRecipient},
    asset_keyring::AssetKeyring,
};
use crate::io::Io;
use crate::{asset_async_writer, asset_cache::AssetBlobCache, asset_reader, config, db};

/// # Returns
///
/// `Some(Some((seq_id, contents)))`: local asset is outdated.
/// `Some(None)`: local asset is outdated -> latest version has no contents.
/// `None`: local asset is up-to-date or unable to determine (fetch error).
async fn local_asset_needs_update(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
    asset_name: &str,
    local_seq_id: i64,
) -> Option<Option<(String, i64, String, Vec<u8>)>> {
    // Get only the entry to compare sequence IDs
    let entry = match asset_reader::get_asset_entry(api_client, asset_name, false).await {
        Ok(res) => res.entry,
        Err(_) => return None,
    };

    if local_seq_id < entry.seq_id {
        // Get contents (likely to require decryption)
        let (contents, entry) = match asset_reader::get_decrypted_asset_and_metadata(
            &crate::io::Io::noop(),
            asset_blob_cache,
            asset_keyring,
            api_client,
            username,
            asset_name,
        )
        .await
        {
            Ok(res) => res,
            Err(_) => return None,
        };
        if let Some(hash) = entry.asset.hash {
            if config::read_config_from_bytes(&contents).is_err() {
                // Parse error, operate as if remote fetch failed
                None
            } else {
                Some(Some((entry.entry_id, entry.seq_id, hash, contents)))
            }
        } else {
            None
        }
    } else {
        None
    }
}

const HAI_TOML_ASSET_NAME: &str = ".sys/hai.toml";

pub async fn get_merged_config(
    config_path_override: Option<&str>,
    db: Arc<Mutex<rusqlite::Connection>>,
    username: Option<&str>,
) -> Result<config::Config, Box<dyn std::error::Error>> {
    // Returns a local config even if it doesn't exist by creating it.
    let local_config = config::get_config(config_path_override.as_deref())?;
    let remote_config = if let Some(username) = username {
        if let Some(existing_asset_store_entry) =
            db::asset_store_get(&*db.lock().await, username, HAI_TOML_ASSET_NAME)?
        {
            Some(config::read_config_from_bytes(
                &existing_asset_store_entry.contents,
            )?)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(remote_config) = remote_config {
        Ok(config::merge_configs(&local_config, &remote_config))
    } else {
        Ok(local_config)
    }
}

pub async fn store_remote_config_if_updated(
    db: Arc<Mutex<rusqlite::Connection>>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(username) = username {
        let existing_seq_id = if let Some(existing_asset_store_entry) =
            db::asset_store_get(&*db.lock().await, username, HAI_TOML_ASSET_NAME)?
        {
            existing_asset_store_entry.seq_id
        } else {
            // If nothing is stored, guarantee a fetch with a non-positive seq_id
            0
        };
        match local_asset_needs_update(
            asset_blob_cache,
            asset_keyring,
            api_client,
            Some(username),
            HAI_TOML_ASSET_NAME,
            existing_seq_id,
        )
        .await
        {
            Some(Some((entry_id, seq_id, hash, contents))) => {
                tracing::info!(
                    HAI_TOML_ASSET_NAME,
                    entry_id,
                    seq_id,
                    hash,
                    "storing updated remote config"
                );
                db::asset_store_put(
                    &*db.lock().await,
                    username,
                    HAI_TOML_ASSET_NAME,
                    &entry_id,
                    seq_id,
                    &hash,
                    &contents,
                )?;
            }
            Some(None) => {
                db::asset_store_remove(&*db.lock().await, username, HAI_TOML_ASSET_NAME)?;
            }
            None => {
                // May have been a fetch failure, ignore save.
            }
        };
    }
    Ok(())
}

// --

pub async fn update_asset_config(
    io: &Io,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: &str,
    contents: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let akm_info = asset_crypt::choose_akm_for_asset_by_name(
        io,
        asset_blob_cache.clone(),
        asset_keyring.clone(),
        api_client.clone(),
        Some(&KeyRecipient::User(username.to_string())),
        HAI_TOML_ASSET_NAME,
        true,
    )
    .await?;
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let _ = update_asset_tx
        .send(asset_async_writer::WorkerAssetMsg::Update(
            asset_async_writer::WorkerAssetUpdate {
                asset_name: HAI_TOML_ASSET_NAME.to_owned(),
                asset_entry_ref: None,
                new_contents: contents.as_bytes().to_vec(),
                is_push: false,
                put_conflict_policy: None,
                replace_conflict_policy: None,
                api_client: api_client.clone(),
                one_shot: true,
                akm_info,
                reply_channel: Some(reply_tx),
            },
        ))
        .await;
    let entry = reply_rx.await??;
    if let Some(hash) = entry.asset.hash {
        db::asset_store_put(
            &*db.lock().await,
            username,
            HAI_TOML_ASSET_NAME,
            &entry.entry_id,
            entry.seq_id,
            &hash,
            &contents.as_bytes(),
        )?;
    }
    Ok(())
}

// --

/// # Arguments
///
/// - `write_local_config_only`: If set, only writes to local config file.
/// - `config_path_override`: If set, uses override path for local config path.
pub async fn merged_config_insert_config_kv(
    io: &Io,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    write_local_config_only: bool,
    section: Option<&str>,
    key: &str,
    val: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if write_local_config_only {
        config::insert_config_kv(config_path_override, section, key, val);
    } else if let Some(username) = username {
        let config_str =
            match db::asset_store_get(&*db.lock().await, username, HAI_TOML_ASSET_NAME)? {
                Some(asset_store_entry) => str::from_utf8(&asset_store_entry.contents)?.to_string(),
                None => "".to_string(),
            };
        let mut doc = config_str
            .parse::<toml_edit::DocumentMut>()
            .expect("invalid doc");
        if let Some(section_name) = section {
            if !doc.contains_key(section_name) {
                doc[section_name] = toml_edit::Item::Table(toml_edit::Table::new());
            }
            doc[section_name][key] = toml_edit::value(val);
        } else {
            doc[key] = toml_edit::value(val);
        }
        let contents = doc.to_string();

        update_asset_config(
            io,
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            db,
            update_asset_tx,
            api_client,
            username,
            &contents,
        )
        .await?;
    }
    Ok(())
}

pub async fn merged_config_insert_config_kv_and_reload(
    io: &Io,
    cfg: &mut config::Config,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    local_only: bool,
    section: Option<&str>,
    key: &str,
    val: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    merged_config_insert_config_kv(
        io,
        config_path_override,
        asset_blob_cache,
        asset_keyring,
        db.clone(),
        update_asset_tx,
        api_client,
        username,
        local_only,
        section,
        key,
        val,
    )
    .await?;
    let updated_config = get_merged_config(config_path_override, db, username).await?;
    *cfg = updated_config;
    Ok(())
}

// --

pub async fn merged_config_insert_config_starred_task(
    io: &Io,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    write_local_config_only: bool,
    task_fqn: &str,
    shortcut: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if write_local_config_only {
        config::insert_config_starred_task_and_write(config_path_override, task_fqn, shortcut)?;
    } else if let Some(username) = username {
        let config_str =
            match db::asset_store_get(&*db.lock().await, username, HAI_TOML_ASSET_NAME)? {
                Some(asset_store_entry) => str::from_utf8(&asset_store_entry.contents)?.to_string(),
                None => "".to_string(),
            };
        let mut doc = config_str
            .parse::<toml_edit::DocumentMut>()
            .expect("invalid doc");
        config::insert_config_starred_task(&mut doc, task_fqn, shortcut)?;
        let contents = doc.to_string();

        update_asset_config(
            io,
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            db,
            update_asset_tx,
            api_client,
            username,
            &contents,
        )
        .await?;
    }
    Ok(())
}

pub async fn merged_config_insert_config_starred_task_and_reload(
    io: &Io,
    cfg: &mut config::Config,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    write_local_config_only: bool,
    task_fqn: &str,
    shortcut: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    merged_config_insert_config_starred_task(
        io,
        config_path_override,
        asset_blob_cache,
        asset_keyring,
        db.clone(),
        update_asset_tx,
        api_client,
        username,
        write_local_config_only,
        task_fqn,
        shortcut,
    )
    .await?;
    let updated_config = get_merged_config(config_path_override, db, username).await?;
    *cfg = updated_config;
    Ok(())
}

// --

pub async fn merged_config_remove_config_starred_shortcut(
    io: &Io,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    write_local_config_only: bool,
    shortcut: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if write_local_config_only {
        config::remove_config_starred_shortcut_and_write(config_path_override, shortcut);
    } else if let Some(username) = username {
        let config_str =
            match db::asset_store_get(&*db.lock().await, username, HAI_TOML_ASSET_NAME)? {
                Some(asset_store_entry) => str::from_utf8(&asset_store_entry.contents)?.to_string(),
                None => "".to_string(),
            };
        let mut doc = config_str
            .parse::<toml_edit::DocumentMut>()
            .expect("invalid doc");
        config::remove_config_starred_shortcut(&mut doc, shortcut);
        let contents = doc.to_string();

        update_asset_config(
            io,
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            db,
            update_asset_tx,
            api_client,
            username,
            &contents,
        )
        .await?;
    }
    Ok(())
}

pub async fn merged_config_remove_config_starred_shortcut_and_reload(
    io: &Io,
    cfg: &mut config::Config,
    config_path_override: Option<&str>,
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    update_asset_tx: tokio::sync::mpsc::Sender<asset_async_writer::WorkerAssetMsg>,
    api_client: &HaiClient,
    username: Option<&str>,
    write_local_config_only: bool,
    shortcut: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    merged_config_remove_config_starred_shortcut(
        io,
        config_path_override,
        asset_blob_cache,
        asset_keyring,
        db.clone(),
        update_asset_tx,
        api_client,
        username,
        write_local_config_only,
        shortcut,
    )
    .await?;
    let updated_config = get_merged_config(config_path_override, db, username).await?;
    *cfg = updated_config;
    Ok(())
}
