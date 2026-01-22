use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::PublicKey;

use crate::api::{
    client::{HaiClient, RequestError},
    types::asset::AssetEntry,
};
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader::{self, GetAssetError, get_only_asset_metadata};
use crate::crypt;
use crate::feature::asset_keyring::AssetKeyring;
use crate::term;

pub enum CryptSetupError {
    Abort,
    InvalidPassword,
    PasswordMismatch,
    ServerAbort(String),
    Other(String),
}

/// Setup asset encryption and signing keys.
///
/// # Arguments
/// * `api_client` - An instance of the HaiClient to interact with the API.
/// * `username` - The username for whom the keys are being set up.
///
/// # Returns
/// A Result containing a tuple of (encryption key ID, signing key ID, recovery code) on success,
/// or a CryptSetupError on failure.
///
pub async fn asset_crypt_setup(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: HaiClient,
    username: &str,
) -> Result<(String, String, String), CryptSetupError> {
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    //
    // Check if asset encryption / signing key already exists.
    // If so, confirm rotation.
    //

    let mut rotation_accepted = false;
    let pub_key_path = format!("/{username}/keys/enc.pub");
    match get_only_asset_metadata(asset_blob_cache.clone(), &api_client, &pub_key_path, true).await
    {
        Ok((enc_key_md_contents, _enc_key_entry)) => {
            println!();
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║                    ⚠  WARNING: KEY EXISTS                    ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║                                                              ║");
            println!("║  Asset encryption key already exists at:                     ║");
            println!("║  {:<60}║", pub_key_path);
            println!("║                                                              ║");
            println!("║  You will be prompted to confirm key rotation.               ║");
            println!("║                                                              ║");
            println!("║  Key rotation will:                                          ║");
            println!("║   • Generate new encryption and signing keys                 ║");
            println!("║   • Set the new keys as your default                         ║");
            println!("║   • Keep old keys available to decrypt/verify previously     ║");
            println!("║     encrypted assets                                         ║");
            println!("║                                                              ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!();
            let answer = term::ask_question_readline("Type 'yes' to rotate keys");
            if answer.as_deref() != Some("yes") {
                return Err(CryptSetupError::Abort);
            }
            rotation_accepted = true;

            if let Some(enc_key_md_contents_bin) = enc_key_md_contents {
                let enc_key_md_contents =
                    String::from_utf8_lossy(&enc_key_md_contents_bin).to_string();
                // Try to parse existing key metadata to inform user
                if let Ok(enc_key_md_json) =
                    serde_json::from_str::<serde_json::Value>(&enc_key_md_contents)
                    && let Some(old_key_id) = enc_key_md_json.get("key_id").and_then(|v| v.as_str())
                {
                    println!("Existing encryption key ID: {}", old_key_id);
                    let _ = crate::asset_async_writer::asset_metadata_set_key(
                        &api_client,
                        &format!("keys/enc_{old_key_id}.key"),
                        "rotated_at",
                        Some(serde_json::json!(ts.clone())),
                    )
                    .await;
                    let _ = crate::asset_async_writer::asset_metadata_set_key(
                        &api_client,
                        &format!("/{username}/keys/enc_{old_key_id}.pub"),
                        "rotated_at",
                        Some(serde_json::json!(ts.clone())),
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            match e {
                GetAssetError::BadName => {
                    // Continue with key generation
                }
                GetAssetError::DataFetchFailed => {
                    return Err(CryptSetupError::ServerAbort(
                        "Failed to fetch asset data".to_string(),
                    ));
                }
            }
        }
    };
    match get_only_asset_metadata(asset_blob_cache, &api_client, "keys/sign.key", true).await {
        Ok((sign_key_md_contents, _sign_key_entry)) => {
            println!("Asset sign key `keys/sign.key` already exists.");
            if !rotation_accepted {
                let answer = term::ask_question_readline("Type 'yes' to rotate keys");
                if answer.as_deref() != Some("yes") {
                    return Err(CryptSetupError::Abort);
                }
            }

            if let Some(sign_key_md_contents_bin) = sign_key_md_contents {
                let sign_key_md_contents =
                    String::from_utf8_lossy(&sign_key_md_contents_bin).to_string();
                // Try to parse existing key metadata to inform user
                if let Ok(sign_key_md_json) =
                    serde_json::from_str::<serde_json::Value>(&sign_key_md_contents)
                    && let Some(old_key_id) =
                        sign_key_md_json.get("key_id").and_then(|v| v.as_str())
                {
                    println!("Existing sign key ID: {}", old_key_id);
                    let _ = crate::asset_async_writer::asset_metadata_set_key(
                        &api_client,
                        &format!("keys/sign_{old_key_id}.key"),
                        "rotated_at",
                        Some(serde_json::json!(ts.clone())),
                    )
                    .await;
                    let _ = crate::asset_async_writer::asset_metadata_set_key(
                        &api_client,
                        &format!("/{username}/keys/sign_{old_key_id}.pub"),
                        "rotated_at",
                        Some(serde_json::json!(ts.clone())),
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            match e {
                GetAssetError::BadName => {
                    // Continue with key generation
                }
                GetAssetError::DataFetchFailed => {
                    return Err(CryptSetupError::ServerAbort(
                        "Failed to fetch asset data".to_string(),
                    ));
                }
            }
        }
    };

    //
    // Generate new key and confirm `key_id` does not conflict with an existing
    // one. Cardinality is 2**32 so it's unlikely but with enough rotation
    // attempts it's possible.
    //
    use crate::api::types::asset::{AssetGetArg, AssetGetError};

    let (keys, enc_key_id, sign_key_id) = loop {
        // Generate keys
        let keys = crate::crypt::generate_key_bundle();
        let (enc_key_id, sign_key_id) = keys.key_ids_hex();
        match api_client
            .asset_get(AssetGetArg {
                name: format!("keys/enc_{enc_key_id}.key"),
            })
            .await
        {
            Ok(_res) => {
                // conflict, try again
                continue;
            }
            Err(e) => {
                match e {
                    RequestError::Route(AssetGetError::BadName) => {
                        // no conflict
                    }
                    _ => {
                        eprintln!("error: {}", e);
                        return Err(CryptSetupError::Other(format!("{}", e)));
                    }
                }
            }
        };
        match api_client
            .asset_get(AssetGetArg {
                name: format!("keys/sign_{sign_key_id}.key"),
            })
            .await
        {
            Ok(_res) => {
                // conflict, try again
                continue;
            }
            Err(e) => match e {
                RequestError::Route(AssetGetError::BadName) => {
                    break (keys, enc_key_id, sign_key_id);
                }
                _ => {
                    eprintln!("error: {}", e);
                    return Err(CryptSetupError::Other(format!("{}", e)));
                }
            },
        };
    };

    //
    // Query user for password to protect keys
    //
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           CHOOSE A KEY ENCRYPTION PASSWORD                   ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║                                                              ║");
    println!("║  💡 Tips for a strong password:                              ║");
    println!("║                                                              ║");
    println!("║   • Use 4-6 random words (easier to remember!)               ║");
    println!("║   • DON'T reuse your account password                        ║");
    println!("║   • Make it unique to this key                               ║");
    println!("║                                                              ║");
    println!("║  Example: \"person woman man camera TV\"                       ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    let password =
        if let Some(password) = term::ask_question("Enter password to protect keys:", true) {
            if password.is_empty() {
                eprintln!("error: password cannot be empty");
                return Err(CryptSetupError::InvalidPassword);
            }
            let password_verify = term::ask_question("Verify password:", true);
            if password_verify.as_deref() != Some(&password) {
                eprintln!("error: passwords do not match");
                return Err(CryptSetupError::PasswordMismatch);
            }
            password.into_bytes()
        } else {
            eprintln!("error: password input cancelled");
            return Err(CryptSetupError::Abort);
        };

    //
    // Generate recovery code and create recovery-encrypted keys
    //
    let (recovery_code, recovery_encrypted_keys) =
        crate::crypt::create_recovery_encrypted_keys(&keys).map_err(|e| {
            CryptSetupError::Other(format!("Failed to create recovery keys: {}", e))
        })?;

    //
    // Put keys into asset store.
    // Each key (enc/dec & signing) has a public and private component.
    // Moreover, we store both a named version (with key ID) and a
    // canonical version (without key ID) for convenient look ups.
    //
    let public_bundle = keys.export_public();
    let encrypted_encryption_bundle = keys.export_encryption_secret_protected(&password).unwrap();
    let encrypted_signing_bundle = keys.export_signing_key_protected(&password).unwrap();

    use crate::api::types::asset::{AssetPutArg, PutConflictPolicy};
    async fn put_crypt_asset(
        api_client: &HaiClient,
        name: String,
        data: &[u8],
    ) -> Result<(), CryptSetupError> {
        match api_client
            .asset_put(AssetPutArg {
                name,
                data: data.to_vec(),
                conflict_policy: PutConflictPolicy::Override,
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("error: failed to put: {}", e);
                Err(CryptSetupError::ServerAbort(format!("{}", e)))
            }
        }
    }

    put_crypt_asset(
        &api_client,
        format!("/{username}/keys/enc_{enc_key_id}.pub"),
        &public_bundle.encryption_public,
    )
    .await?;
    put_crypt_asset(
        &api_client,
        format!("/{username}/keys/sign_{sign_key_id}.pub"),
        &public_bundle.verifying_key,
    )
    .await?;

    // FUTURE: Convert this to an asset-copy
    put_crypt_asset(
        &api_client,
        format!("/{username}/keys/enc.pub"),
        &public_bundle.encryption_public,
    )
    .await?;
    put_crypt_asset(
        &api_client,
        format!("/{username}/keys/sign.pub"),
        &public_bundle.verifying_key,
    )
    .await?;

    put_crypt_asset(
        &api_client,
        format!("keys/enc_{enc_key_id}.key"),
        &encrypted_encryption_bundle.to_bytes(),
    )
    .await?;
    put_crypt_asset(
        &api_client,
        format!("keys/sign_{sign_key_id}.key"),
        &encrypted_signing_bundle.to_bytes(),
    )
    .await?;

    //
    // Store recovery-encrypted keys
    // Format: one base64-encoded RecoveryEncryptedKeys per line
    // This file can accumulate multiple recovery entries if keys are rotated
    // but user wants to keep same recovery code (future enhancement)
    //
    let recovery_file_contents = format!(
        "# Recovery keys for enc_key_id={} sign_key_id={}\n# Created: {}\n# DO NOT SHARE THIS FILE - Store your recovery code securely offline\n{}\n",
        enc_key_id,
        sign_key_id,
        ts,
        recovery_encrypted_keys.to_base64()
    );

    put_crypt_asset(
        &api_client,
        format!("keys/enc_{enc_key_id}.recovery"),
        recovery_file_contents.as_bytes(),
    )
    .await?;

    use crate::api::types::asset::AssetMetadataPutArg;
    async fn put_crypt_asset_metadata(
        api_client: &HaiClient,
        name: String,
        md_contents: String,
    ) -> Result<(), CryptSetupError> {
        match api_client
            .asset_metadata_put(AssetMetadataPutArg {
                name,
                data: md_contents,
                conflict_policy: PutConflictPolicy::Override,
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("error: failed to metadata/put: {}", e);
                Err(CryptSetupError::ServerAbort(format!("{}", e)))
            }
        }
    }

    //
    // Set metadata for each key asset.
    //
    let enc_pub_md = serde_json::json!({
        "created_at": ts,
        "algorithm": "X25519",
        "key_id": enc_key_id,
    })
    .to_string();

    put_crypt_asset_metadata(
        &api_client,
        format!("/{username}/keys/enc.pub"),
        enc_pub_md.clone(),
    )
    .await?;
    put_crypt_asset_metadata(
        &api_client,
        format!("/{username}/keys/enc_{enc_key_id}.pub"),
        enc_pub_md,
    )
    .await?;

    let sign_pub_md = serde_json::json!({
        "created_at": ts,
        "algorithm": "Ed25519",
        "key_id": sign_key_id,
    })
    .to_string();
    put_crypt_asset_metadata(
        &api_client,
        format!("/{username}/keys/sign.pub"),
        sign_pub_md.clone(),
    )
    .await?;
    put_crypt_asset_metadata(
        &api_client,
        format!("/{username}/keys/sign_{sign_key_id}.pub"),
        sign_pub_md,
    )
    .await?;

    let enc_key_md = serde_json::json!({
        "created_at": ts,
        "algorithm": "X25519",
        "kdf": "argon2id",
        "key_id": enc_key_id,
    })
    .to_string();
    put_crypt_asset_metadata(
        &api_client,
        format!("keys/enc_{enc_key_id}.key"),
        enc_key_md,
    )
    .await?;

    let sign_key_md = serde_json::json!({
        "created_at": ts,
        "algorithm": "Ed25519",
        "kdf": "argon2id",
        "key_id": sign_key_id,
    })
    .to_string();
    put_crypt_asset_metadata(
        &api_client,
        format!("keys/sign_{sign_key_id}.key"),
        sign_key_md,
    )
    .await?;

    //
    // Set metadata for recovery file
    //
    let recovery_md = serde_json::json!({
        "created_at": ts,
        "enc_key_id": enc_key_id,
        "sign_key_id": sign_key_id,
        "kdf": "argon2id",
        "type": "recovery",
    })
    .to_string();
    put_crypt_asset_metadata(
        &api_client,
        format!("keys/enc_{enc_key_id}.recovery"),
        recovery_md,
    )
    .await?;

    Ok((enc_key_id, sign_key_id, recovery_code.to_hex_grouped()))
}

// --

#[derive(Clone, Debug)]
/// Container for a user's public encryption key.
///
/// # When to Use
/// * To encrypt an AES symmetric key for a user.
pub struct EncryptKeyInfo {
    pub enc_key: PublicKey,

    /// The ID of the encryption key, which can be used for look up in their
    /// private asset filesystem tree.
    pub enc_key_id: String,

    #[allow(dead_code)]
    pub username: String,
}

/// Retrieve the user's asset encryption key.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `key_id` - Optional key ID to specify a particular encryption key.
///
pub async fn get_encryption_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    username: &str,
    key_id: Option<&str>,
) -> Result<Option<EncryptKeyInfo>, String> {
    let key_path = if let Some(key_id) = key_id {
        format!("/{username}/keys/enc_{key_id}.pub")
    } else {
        format!("/{username}/keys/enc.pub")
    };
    match get_key(asset_blob_cache.clone(), api_client, &key_path).await {
        Ok((key_contents, key_id, _md_contents, _entry)) => {
            let recipient_pub = PublicKey::from(<[u8; 32]>::try_from(&key_contents[..]).unwrap());
            if crypt::format_key_id(&crypt::derive_encryption_key_id(&recipient_pub)) == key_id {
                Ok(Some(EncryptKeyInfo {
                    enc_key: recipient_pub,
                    enc_key_id: key_id,
                    username: username.to_string(),
                }))
            } else {
                Err("key ID mismatch".to_string())
            }
        }
        Err(e) => match e {
            GetKeyError::NoKey => Ok(None),
            GetKeyError::BrokenKey => Err("key broken/invalid".to_string()),
            GetKeyError::DataFetchFailed => Err("key fetch failed".to_string()),
        },
    }
}

#[derive(Clone, Debug)]
/// Container for both a user's public encryption key and per-file AES key used
/// to encrypt a specific asset.
pub struct AssetKeyMaterial {
    pub enc_key_info: EncryptKeyInfo,
    pub sym_key_info: SymmetricKeyInfo,
}

pub fn mk_asset_key_material(
    enc_key_info: EncryptKeyInfo,
    sym_key_info: SymmetricKeyInfo,
) -> AssetKeyMaterial {
    AssetKeyMaterial {
        enc_key_info,
        sym_key_info,
    }
}

/// Create a new per-file encryption key info structure.
///
/// # Arguments
/// * `enc_key_info` - The user's public encryption key info.
///
pub fn mk_asset_key_material_with_new_sym_key(enc_key_info: EncryptKeyInfo) -> AssetKeyMaterial {
    let aes_key = crypt::generate_aes_key();
    let enc_aes_key = crypt::encrypt_aes_key(&aes_key, &enc_key_info.enc_key)
        .unwrap()
        .to_hex();
    AssetKeyMaterial {
        enc_key_info,
        sym_key_info: SymmetricKeyInfo {
            aes_key,
            enc_aes_key,
        },
    }
}

/// Retrieve the user's asset decryption key.
///
/// The decryption key is encrypted with a password.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `key_id` - Optional key ID to specify a particular encryption key.
///
pub async fn get_encrypted_decryption_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    key_id: &str,
) -> Result<Option<crypt::EncryptedEncryptionKey>, String> {
    let key_path = format!("keys/enc_{key_id}.key");
    match get_key(asset_blob_cache.clone(), api_client, &key_path).await {
        Ok((key_contents, _key_id, _md_contents, _entry)) => Ok(Some(
            crypt::EncryptedEncryptionKey::from_bytes(&key_contents)
                .map_err(|e| format!("failed to parse encryption key: {}", e))?,
        )),
        Err(e) => match e {
            GetKeyError::NoKey => Ok(None),
            GetKeyError::BrokenKey => Err("key broken/invalid".to_string()),
            GetKeyError::DataFetchFailed => Err("key fetch failed".to_string()),
        },
    }
}

pub enum GetKeyError {
    NoKey,
    BrokenKey,
    DataFetchFailed,
}

/// Retrieve the user's asset encryption key.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `key_id` - Optional key ID to specify a particular encryption key.
///
/// # Returns
/// A Result containing an Option with a tuple of key data, key ID, metadata JSON,
/// and AssetEntry on success, or a GetKeyError on failure.
///
pub async fn get_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    key_path: &str,
) -> Result<(Vec<u8>, String, serde_json::Value, AssetEntry), GetKeyError> {
    match asset_reader::get_asset_and_metadata(asset_blob_cache, &api_client, &key_path, true).await
    {
        Ok((data_contents, Some(md_contents), entry)) => {
            let md_json = serde_json::from_str::<serde_json::Value>(
                &String::from_utf8_lossy(&md_contents).to_string(),
            )
            .expect("failed to parse metadata JSON");
            if let Some(key_id) = md_json.get("key_id")
                && let Some(key_id) = key_id.as_str()
            {
                Ok((data_contents, key_id.to_string(), md_json, entry))
            } else {
                Err(GetKeyError::BrokenKey)
            }
        }
        // The keyfile exists but has no metadata, therefore it's broken.
        Ok((_data_contents, None, _entry)) => Err(GetKeyError::BrokenKey),
        Err(e) => match e {
            GetAssetError::BadName => Err(GetKeyError::NoKey),
            GetAssetError::DataFetchFailed => Err(GetKeyError::DataFetchFailed),
        },
    }
}

pub async fn put_asset_encryption_metadata(
    api_client: &HaiClient,
    asset_name: &str,
    akm_info: &AssetKeyMaterial,
) -> Result<(), String> {
    let md_contents = serde_json::json!({
        "encrypted": {
            "algorithm": "AES-GCM",
            // NOTE: Use list in preparation for future with multiple
            // recipients.
            "keys": [{
                "encrypted_key": akm_info.sym_key_info.enc_aes_key,
                "recipient_key_id": akm_info.enc_key_info.enc_key_id,
            }]
        },
    })
    .to_string();
    use crate::api::types::asset::{AssetMetadataPutArg, PutConflictPolicy};
    match api_client
        .asset_metadata_put(AssetMetadataPutArg {
            name: asset_name.to_string(),
            data: md_contents,
            conflict_policy: PutConflictPolicy::Override,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Server abort: {}", e)),
    }
}

pub fn parse_metadata_for_encryption_info(metadata: &[u8]) -> Option<(String, String)> {
    let md_json =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(metadata).to_string())
            .ok()?;
    let enc_info = md_json.get("encrypted")?;
    let keys = enc_info.get("keys")?.as_array()?;
    // NOTE: Given that all encrypted assets are in private asset trees,
    // there's no need to check more than one entry nor to check the recipient.
    // In the future, this will change.
    let first_key = keys.get(0)?;
    let enc_aes_key = first_key.get("encrypted_key")?.as_str()?.to_string();
    let enc_key_id = first_key.get("recipient_key_id")?.as_str()?.to_string();
    Some((enc_aes_key, enc_key_id))
}

pub fn encrypt_asset_with_aes_key(aes_key: &crypt::AesKey, contents: &[u8]) -> Vec<u8> {
    crypt::encrypt_content(contents, aes_key)
        .expect("unexpected failure to encrypt content")
        .to_bytes()
}

pub enum AssetKeyMaterialDecryptionError {
    NoDecryptionKey,
    DecryptionKeyError(String),
    PasswordCancelled,
    /// Bad password is most likely.
    EncryptionKeyDecryptionError(String),
}

impl ::std::fmt::Display for AssetKeyMaterialDecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetKeyMaterialDecryptionError::NoDecryptionKey => {
                write!(f, "no decryption key found for given key ID")
            }
            AssetKeyMaterialDecryptionError::DecryptionKeyError(e) => {
                write!(f, "failed to get decryption key: {}", e)
            }
            AssetKeyMaterialDecryptionError::PasswordCancelled => {
                write!(f, "password input cancelled")
            }
            AssetKeyMaterialDecryptionError::EncryptionKeyDecryptionError(e) => {
                write!(f, "failed to decrypt encryption key (bad password?): {}", e)
            }
        }
    }
}

#[derive(Clone, Debug)]
/// Container for per-file AES symmetric key information.
///
/// Holds the AES key for a specific file along with its encrypted form.
///
/// # When to Use
///
/// - **You have the decrypted AES key**: Already decrypted from storage or received it
/// - **File operations**: Encrypting or decrypting a specific file's content
/// - **No recipient needed**: Not sending to anyone, just working with the file locally
pub struct SymmetricKeyInfo {
    /// The decrypted AES-256 key for encrypting/decrypting this file
    pub aes_key: crypt::AesKey,

    /// The encrypted form of the AES key (hex-encoded) for storage (typically
    /// in metadata)
    pub enc_aes_key: String,
}

pub async fn get_symmetric_key_ez(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    enc_aes_key_hex: &str,
    enc_key_id: &str,
) -> Result<SymmetricKeyInfo, AssetKeyMaterialDecryptionError> {
    let mut asset_keyring_locked = asset_keyring.lock().await;
    let secret = match asset_keyring_locked
        .get_or_unlock(asset_blob_cache, api_client, enc_key_id)
        .await
    {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("error: failed to unlock keyring: {}", e);
            return Err(AssetKeyMaterialDecryptionError::DecryptionKeyError(
                e.to_string(),
            ));
        }
    };
    let enc_aes_key = crypt::EncryptedAesKey::from_hex(&enc_aes_key_hex).unwrap();
    let aes_key = crypt::decrypt_aes_key(&enc_aes_key, &secret).unwrap();
    Ok(SymmetricKeyInfo {
        aes_key,
        enc_aes_key: enc_aes_key_hex.to_string(),
    })
}

pub async fn get_per_file_symmetric_key_from_metadata_ez(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    md_contents: &[u8],
) -> Result<Option<SymmetricKeyInfo>, AssetKeyMaterialDecryptionError> {
    if let Some((enc_aes_key_hex, enc_key_id)) = parse_metadata_for_encryption_info(&md_contents) {
        get_symmetric_key_ez(
            asset_blob_cache.clone(),
            asset_keyring,
            &api_client,
            &enc_aes_key_hex,
            &enc_key_id,
        )
        .await
        .map(|sym_info| Some(sym_info))
    } else {
        Ok(None)
    }
}

// --

pub async fn maybe_decrypt_asset_contents(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    asset_contents: &[u8],
    md_contents: Option<&[u8]>,
) -> Result<Vec<u8>, AssetKeyMaterialDecryptionError> {
    if let Some(md_contents) = md_contents
        && let Some((enc_aes_key_hex, enc_key_id)) =
            parse_metadata_for_encryption_info(&md_contents)
    {
        get_symmetric_key_ez(
            asset_blob_cache,
            asset_keyring,
            &api_client,
            &enc_aes_key_hex,
            &enc_key_id,
        )
        .await
        .map(|sym_info| {
            let enc_content = crypt::EncryptedContent::from_bytes(&asset_contents).unwrap();
            crypt::decrypt_content(&enc_content, &sym_info.aes_key).unwrap()
        })
    } else {
        Ok(asset_contents.to_vec())
    }
}

// --

pub enum CryptRecoverError {
    ServerAbort(String),
    Other(String),
}

impl ::std::fmt::Display for CryptRecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptRecoverError::ServerAbort(e) => write!(f, "server abort: {}", e),
            CryptRecoverError::Other(e) => write!(f, "error: {}", e),
        }
    }
}

/// Recover keys using a recovery code.
///
/// # Arguments
/// * `asset_blob_cache` - The asset blob cache.
/// * `api_client` - An instance of the HaiClient to interact with the API.
/// * `username` - The username for whom the keys are being recovered.
/// * `enc_key_id` - The encryption key ID to recover.
/// * `recovery_code_str` - The recovery code provided by the user.
/// * `new_password` - The new password to protect the recovered keys.
///
/// # Returns
/// A Result containing the KeyBundle on success, or a CryptSetupError on failure.
///
pub async fn asset_crypt_recover(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: HaiClient,
    username: &str,
    enc_key_id: &str,
    recovery_code_str: &str,
    new_password: &[u8],
) -> Result<crate::crypt::KeyBundle, CryptRecoverError> {
    use crate::asset_reader::{self, GetAssetError};
    use crate::crypt::{RecoveryCode, parse_recovery_file};
    use ed25519_dalek::VerifyingKey;
    use x25519_dalek::PublicKey;

    // Parse the recovery code
    let recovery_code = RecoveryCode::from_hex(recovery_code_str)
        .map_err(|e| CryptRecoverError::Other(format!("Invalid recovery code format: {}", e)))?;

    // Fetch the recovery file with metadata
    let recovery_file_name = format!("keys/enc_{enc_key_id}.recovery");
    let (recovery_data, sign_key_id) = match asset_reader::get_asset_and_metadata(
        asset_blob_cache.clone(),
        &api_client,
        &recovery_file_name,
        true,
    )
    .await
    {
        Ok((data, Some(md_bytes), _entry)) => {
            let md_str = String::from_utf8_lossy(&md_bytes).to_string();
            let md_json: serde_json::Value = serde_json::from_str(&md_str).map_err(|e| {
                CryptRecoverError::Other(format!("Failed to parse recovery metadata: {}", e))
            })?;
            let sign_key_id = md_json
                .get("sign_key_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    CryptRecoverError::Other("Recovery metadata missing sign_key_id".to_string())
                })?;
            (data, sign_key_id)
        }
        Ok((_, None, _)) => {
            return Err(CryptRecoverError::Other(
                "Recovery file has no metadata".to_string(),
            ));
        }
        Err(e) => match e {
            GetAssetError::BadName => {
                return Err(CryptRecoverError::Other(format!(
                    "Recovery file not found: {}",
                    recovery_file_name
                )));
            }
            GetAssetError::DataFetchFailed => {
                return Err(CryptRecoverError::ServerAbort(
                    "Failed to fetch recovery file".to_string(),
                ));
            }
        },
    };

    // Fetch encryption public key
    let enc_pub_name = format!("/{username}/keys/enc_{enc_key_id}.pub");
    let enc_pub_data =
        match asset_reader::get_asset(asset_blob_cache.clone(), &api_client, &enc_pub_name, true)
            .await
        {
            Ok((data, _entry)) => data,
            Err(e) => match e {
                GetAssetError::BadName => {
                    return Err(CryptRecoverError::Other(format!(
                        "Encryption public key not found: {}",
                        enc_pub_name
                    )));
                }
                GetAssetError::DataFetchFailed => {
                    return Err(CryptRecoverError::ServerAbort(
                        "Failed to fetch encryption public key".to_string(),
                    ));
                }
            },
        };

    if enc_pub_data.len() != 32 {
        return Err(CryptRecoverError::Other(
            "Invalid encryption public key length".to_string(),
        ));
    }
    let mut enc_pub_bytes = [0u8; 32];
    enc_pub_bytes.copy_from_slice(&enc_pub_data);
    let encryption_public = PublicKey::from(enc_pub_bytes);

    // Fetch signing public key
    let sign_pub_name = format!("/{username}/keys/sign_{sign_key_id}.pub");
    let sign_pub_data =
        match asset_reader::get_asset(asset_blob_cache.clone(), &api_client, &sign_pub_name, true)
            .await
        {
            Ok((data, _entry)) => data,
            Err(e) => match e {
                GetAssetError::BadName => {
                    return Err(CryptRecoverError::Other(format!(
                        "Signing public key not found: {}",
                        sign_pub_name
                    )));
                }
                GetAssetError::DataFetchFailed => {
                    return Err(CryptRecoverError::ServerAbort(
                        "Failed to fetch signing public key".to_string(),
                    ));
                }
            },
        };

    if sign_pub_data.len() != 32 {
        return Err(CryptRecoverError::Other(
            "Invalid signing public key length".to_string(),
        ));
    }
    let mut sign_pub_bytes = [0u8; 32];
    sign_pub_bytes.copy_from_slice(&sign_pub_data);
    let verifying_key = VerifyingKey::from_bytes(&sign_pub_bytes)
        .map_err(|e| CryptRecoverError::Other(format!("Invalid verifying key: {}", e)))?;

    let recovery_contents = String::from_utf8_lossy(&recovery_data).to_string();
    let recovery_entries = parse_recovery_file(&recovery_contents)
        .map_err(|e| CryptRecoverError::Other(format!("Failed to parse recovery file: {}", e)))?;

    if recovery_entries.is_empty() {
        return Err(CryptRecoverError::Other(
            "Recovery file contains no valid entries".to_string(),
        ));
    }

    // Try to decrypt with the recovery code
    let (bundle, _idx) = crate::crypt::try_recover_from_list(
        &recovery_entries,
        &recovery_code,
        &encryption_public,
        &verifying_key,
    )
    .map_err(|_| {
        CryptRecoverError::Other("Recovery code did not match any stored recovery keys".to_string())
    })?;

    // Re-encrypt with new password and update stored keys
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let encrypted_encryption_bundle = bundle
        .export_encryption_secret_protected(new_password)
        .map_err(|e| CryptRecoverError::Other(format!("Failed to encrypt key: {}", e)))?;
    let encrypted_signing_bundle = bundle
        .export_signing_key_protected(new_password)
        .map_err(|e| CryptRecoverError::Other(format!("Failed to encrypt key: {}", e)))?;

    use crate::api::types::asset::{AssetPutArg, PutConflictPolicy};

    // Update the password-protected keys
    api_client
        .asset_put(AssetPutArg {
            name: format!("keys/enc_{enc_key_id}.key"),
            data: encrypted_encryption_bundle.to_bytes(),
            conflict_policy: PutConflictPolicy::Override,
        })
        .await
        .map_err(|e| CryptRecoverError::ServerAbort(format!("Failed to store key: {}", e)))?;

    api_client
        .asset_put(AssetPutArg {
            name: format!("keys/sign_{sign_key_id}.key"),
            data: encrypted_signing_bundle.to_bytes(),
            conflict_policy: PutConflictPolicy::Override,
        })
        .await
        .map_err(|e| CryptRecoverError::ServerAbort(format!("Failed to store key: {}", e)))?;

    // Update metadata to note recovery was used
    let _ = crate::asset_async_writer::asset_metadata_set_key(
        &api_client,
        &format!("keys/enc_{enc_key_id}.key"),
        "recovered_at",
        Some(serde_json::json!(ts.clone())),
    )
    .await;

    let _ = crate::asset_async_writer::asset_metadata_set_key(
        &api_client,
        &format!("keys/sign_{sign_key_id}.key"),
        "recovered_at",
        Some(serde_json::json!(ts)),
    )
    .await;

    Ok(bundle)
}

// --

pub enum AkmSelectionError {
    Abort(String),
}

impl ::std::fmt::Display for AkmSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AkmSelectionError::Abort(e) => write!(f, "abort: {}", e),
        }
    }
}

/// Assumes asset exists, though it may not have metadata or an `encrypted`
/// section.
pub async fn choose_akm_for_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: HaiClient,
    username: &str,
    md_contents: Option<&[u8]>,
    generate_akm_if_new: bool,
) -> Result<Option<AssetKeyMaterial>, AkmSelectionError> {
    if let Some(md_contents) = md_contents
        && let Some((enc_aes_key_hex, enc_key_id)) =
            parse_metadata_for_encryption_info(&md_contents)
    {
        match get_symmetric_key_ez(
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            &api_client,
            &enc_aes_key_hex,
            &enc_key_id,
        )
        .await
        {
            Ok(sym_info) => {
                let enc_key_info = match get_encryption_key(
                    asset_blob_cache.clone(),
                    &api_client,
                    &username,
                    Some(&enc_key_id),
                )
                .await
                {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        return Err(AkmSelectionError::Abort(format!(
                            "encryption key {} not found",
                            enc_key_id
                        )));
                    }
                    Err(e) => {
                        return Err(AkmSelectionError::Abort(format!("{}", e)));
                    }
                };
                Ok(Some(mk_asset_key_material(enc_key_info, sym_info)))
            }
            Err(e) => {
                return Err(AkmSelectionError::Abort(format!("{}", e)));
            }
        }
    } else if generate_akm_if_new {
        match get_encryption_key(asset_blob_cache.clone(), &api_client, &username, None).await {
            Ok(Some(enc_key_info)) => Ok(Some(mk_asset_key_material_with_new_sym_key(
                enc_key_info.clone(),
            ))),
            Ok(None) => {
                return Err(AkmSelectionError::Abort(
                    "no encryption key found; generate one with /asset-crypt-setup".to_string(),
                ));
            }
            Err(e) => {
                return Err(AkmSelectionError::Abort(format!("{}", e)));
            }
        }
    } else {
        Ok(None)
    }
}

pub async fn choose_akm_for_asset_by_name(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: HaiClient,
    username: &str,
    asset_name: &str,
    force_generate_akm_if_new: bool,
) -> Result<Option<AssetKeyMaterial>, AkmSelectionError> {
    let generate_akm_if_new = asset_name.starts_with("vault/") || force_generate_akm_if_new;
    let md_contents = match asset_reader::get_only_asset_metadata(
        asset_blob_cache.clone(),
        &api_client,
        asset_name,
        true,
    )
    .await
    {
        Ok(res) => res.0,
        Err(e) => match e {
            GetAssetError::BadName => None,
            GetAssetError::DataFetchFailed => {
                return Err(AkmSelectionError::Abort(format!(
                    "failed to fetch asset {}",
                    asset_name
                )));
            }
        },
    };

    choose_akm_for_asset(
        asset_blob_cache,
        asset_keyring,
        api_client,
        username,
        md_contents.as_deref(),
        generate_akm_if_new,
    )
    .await
}
