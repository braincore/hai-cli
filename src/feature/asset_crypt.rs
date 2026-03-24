use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use ssh_key::{LineEnding, PrivateKey};
use std::{fmt::Debug, sync::Arc};
use tokio::sync::Mutex;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

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

    pub recipient: KeyRecipient,
}

#[derive(Clone, Debug)]
/// Container for the information that gets stored as an object in the
/// `encrypted.keys` field of an encrypted asset's metadata.
pub struct RecipientKeyInfo {
    /// The ID of the encryption key, which can be used for look up in their
    /// private asset filesystem tree.
    pub enc_key_id: String,

    /// The AES key, encrypted with the recipient's public encryption key.
    pub enc_aes_key_hex: String,

    pub recipient: KeyRecipient,
}

impl RecipientKeyInfo {
    pub fn recipient_key_id(&self) -> String {
        match &self.recipient {
            KeyRecipient::User(username) => format!("u:{}:{}", username, self.enc_key_id),
        }
    }

    pub fn recipient_key_id_parts(&self) -> RecipientKeyIdParts {
        RecipientKeyIdParts {
            recipient: self.recipient.clone(),
            key_id: self.enc_key_id.clone(),
            key_type: KeyType::Encryption,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyRecipient {
    User(String), // username
}

impl KeyRecipient {
    pub fn recipient_key_id_prefix(&self) -> String {
        match self {
            KeyRecipient::User(username) => format!("u:{}:", username),
        }
    }
}

impl std::fmt::Display for KeyRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRecipient::User(username) => write!(f, "user {}", username),
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyType {
    Encryption,
    Signing,
}

#[derive(Clone, Debug)]
/// Container for the information that gets stored as a string in the
/// `encrypted.keys[].recipient_key_id` field of an encrypted asset's metadata.
pub struct RecipientKeyIdParts {
    pub recipient: KeyRecipient,
    pub key_id: String,
    pub key_type: KeyType,
}

impl RecipientKeyIdParts {
    pub fn recipient_key_id(&self) -> String {
        format!(
            "{}{}:{}",
            self.recipient.recipient_key_id_prefix(),
            match self.key_type {
                KeyType::Encryption => "enc",
                KeyType::Signing => "sign",
            },
            self.key_id,
        )
    }
}

/// Retrieve the user's asset encryption key.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `recipient` - The recipient for whom to retrieve the encryption key.
/// * `key_id` - Optional key ID to specify a particular encryption key.
///
pub async fn get_encryption_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    recipient: &KeyRecipient,
    key_id: Option<&str>,
) -> Result<Option<EncryptKeyInfo>, String> {
    let (key_path, username) = match recipient {
        KeyRecipient::User(username) => {
            if let Some(key_id) = key_id {
                (format!("/{username}/keys/enc_{key_id}.pub"), username)
            } else {
                (format!("/{username}/keys/enc.pub"), username)
            }
        }
    };

    match get_key(asset_blob_cache.clone(), api_client, &key_path).await {
        Ok((key_contents, key_id, _md_contents, _entry)) => {
            let recipient_pub = PublicKey::from(<[u8; 32]>::try_from(&key_contents[..]).unwrap());
            if crypt::format_key_id(&crypt::derive_encryption_key_id(&recipient_pub)) == key_id {
                Ok(Some(EncryptKeyInfo {
                    enc_key: recipient_pub,
                    enc_key_id: key_id,
                    recipient: KeyRecipient::User(username.to_string()),
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
pub struct UnlockedAssetKeyMaterial {
    pub enc_key_info: EncryptKeyInfo,
    pub sym_key_info: SymmetricKeyInfo,
}

#[derive(Clone, Debug)]
/// Container for a user's public encryption key and encrypted AES key. It's
/// assumed that this is for a user whose private key is unavailable but whose
/// an asset recipient and needs representation in the asset metadata.
pub struct LockedAssetKeyMaterial {
    //pub enc_key_info: EncryptKeyInfo,
    pub enc_key_id: String,
    pub enc_aes_key: String,
    pub recipient: KeyRecipient,
}

impl LockedAssetKeyMaterial {
    /// Create from an EncryptKeyInfo by encrypting the given AES key.
    pub fn new(enc_key_info: EncryptKeyInfo, aes_key: &crypt::AesKey) -> Result<Self, String> {
        let enc_aes_key_hex = crypt::encrypt_aes_key(aes_key, &enc_key_info.enc_key)
            .map_err(|e| format!("Failed to encrypt AES key: {}", e))?
            .to_hex();
        Ok(Self {
            enc_key_id: enc_key_info.enc_key_id.clone(),
            enc_aes_key: enc_aes_key_hex,
            recipient: enc_key_info.recipient.clone(),
        })
    }

    /// Parse from a metadata key entry.
    pub fn from_metadata_entry(entry: &serde_json::Value) -> Result<Self, String> {
        let recipient_key_id = entry
            .get("recipient_key_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing recipient_key_id")?;
        let enc_aes_key_hex = entry
            .get("encrypted_key")
            .and_then(|v| v.as_str())
            .ok_or("Missing encrypted_key")?
            .to_string();

        // Parse recipient_key_id format: "u:username:key_id"
        let (recipient, enc_key_id) = parse_recipient_key_id(recipient_key_id)?;

        Ok(Self {
            enc_key_id,
            enc_aes_key: enc_aes_key_hex,
            recipient,
        })
    }

    /// Convert to RecipientKeyInfo for metadata serialization.
    pub fn to_recipient_key_info(&self) -> RecipientKeyInfo {
        RecipientKeyInfo {
            enc_key_id: self.enc_key_id.clone(),
            enc_aes_key_hex: self.enc_aes_key.clone(),
            recipient: self.recipient.clone(),
        }
    }
}

/// Parse "u:username:key_id" format into (KeyRecipient, key_id)
fn parse_recipient_key_id(s: &str) -> Result<(KeyRecipient, String), String> {
    if let Some(rest) = s.strip_prefix("u:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() == 2 {
            return Ok((
                KeyRecipient::User(parts[0].to_string()),
                parts[1].to_string(),
            ));
        }
    }
    Err(format!("Invalid recipient_key_id format: {}", s))
}

#[derive(Clone, Debug)]
/// Container for both the writer's AKM and all other AKMs for recipients
/// whose private keys are unavailable. This is used to represent the full set
/// AKM information stored in the asset metadata for encrypted assets.
pub struct AssetKeyMaterial {
    pub unlocked_akm: UnlockedAssetKeyMaterial,
    pub locked_akms: Vec<LockedAssetKeyMaterial>,
}

impl AssetKeyMaterial {
    /// Create new shared key material for multiple recipients.
    /// The writer's EncryptKeyInfo comes first; they get the unlocked AKM.
    pub fn new_for_recipients(
        writer_enc_key: EncryptKeyInfo,
        other_enc_keys: &[EncryptKeyInfo],
    ) -> Result<Self, String> {
        // Generate fresh AES key
        let aes_key = crypt::generate_aes_key();

        // Create writer's unlocked AKM
        let enc_aes_key = crypt::encrypt_aes_key(&aes_key, &writer_enc_key.enc_key)
            .map_err(|e| format!("Failed to encrypt AES key for writer: {}", e))?
            .to_hex();
        let writer_akm = UnlockedAssetKeyMaterial {
            enc_key_info: writer_enc_key,
            sym_key_info: SymmetricKeyInfo {
                aes_key: aes_key.clone(),
                enc_aes_key,
            },
        };

        // Create locked AKMs for other recipients
        let other_recipients = other_enc_keys
            .iter()
            .map(|enc_key| LockedAssetKeyMaterial::new(enc_key.clone(), &aes_key))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            unlocked_akm: writer_akm,
            locked_akms: other_recipients,
        })
    }

    /// Add a new recipient to this shared key material.
    pub fn add_recipient(&mut self, enc_key_info: EncryptKeyInfo) -> Result<(), String> {
        let locked =
            LockedAssetKeyMaterial::new(enc_key_info, &self.unlocked_akm.sym_key_info.aes_key)?;
        self.locked_akms.push(locked);
        Ok(())
    }

    /// Get all recipient key infos for metadata serialization.
    pub fn all_recipient_key_infos(&self) -> Vec<RecipientKeyInfo> {
        let mut infos = vec![RecipientKeyInfo {
            enc_key_id: self.unlocked_akm.enc_key_info.enc_key_id.clone(),
            enc_aes_key_hex: self.unlocked_akm.sym_key_info.enc_aes_key.clone(),
            recipient: self.unlocked_akm.enc_key_info.recipient.clone(),
        }];
        infos.extend(self.locked_akms.iter().map(|l| l.to_recipient_key_info()));
        infos
    }

    /// Generate the `encrypted` metadata section.
    pub fn to_encrypted_metadata_json(&self) -> serde_json::Value {
        let mut infos = self.all_recipient_key_infos();
        // Sort for stability
        infos.sort_by(|a, b| a.recipient_key_id().cmp(&b.recipient_key_id()));

        let keys: Vec<serde_json::Value> = infos
            .iter()
            .map(recipient_key_info_to_key_entry_json)
            .collect();

        serde_json::json!({
            "algorithm": "AES-GCM",
            "keys": keys
        })
    }

    /// Reconstruct from metadata, unlocking only the current user's key.
    pub fn from_metadata(
        md_contents: &[u8],
        current_recipient: &KeyRecipient,
        sym_key_info: SymmetricKeyInfo,
        current_enc_key_info: EncryptKeyInfo,
    ) -> Result<Self, String> {
        let md_json =
            serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(md_contents))
                .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        let enc_keys = md_json
            .get("encrypted")
            .and_then(|e| e.get("keys"))
            .and_then(|k| k.as_array())
            .ok_or("No encrypted.keys array")?;

        let current_prefix = current_recipient.recipient_key_id_prefix();
        let mut other_recipients = Vec::new();

        for entry in enc_keys {
            let recipient_key_id = entry
                .get("recipient_key_id")
                .and_then(|v| v.as_str())
                .ok_or("Missing recipient_key_id")?;

            // Skip current user's entry (we already have it unlocked)
            if recipient_key_id.starts_with(&current_prefix) {
                continue;
            }

            other_recipients.push(LockedAssetKeyMaterial::from_metadata_entry(entry)?);
        }

        Ok(Self {
            unlocked_akm: UnlockedAssetKeyMaterial {
                enc_key_info: current_enc_key_info,
                sym_key_info,
            },
            locked_akms: other_recipients,
        })
    }
}

/// Retrieve the user's encrypted decryption key.
///
/// It's encrypted with a password.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `rec_key_id_parts` - The recipient key ID parts to identify which encryption key to retrieve.
pub async fn get_encrypted_decryption_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    rec_key_id_parts: &RecipientKeyIdParts,
) -> Result<Option<crypt::EncryptedEncryptionKey>, String> {
    if !matches!(rec_key_id_parts.key_type, KeyType::Encryption) {
        return Err("Invalid key type for decryption key".to_string());
    }
    let key_path = match rec_key_id_parts.recipient {
        KeyRecipient::User(_) => {
            format!("keys/enc_{}.key", rec_key_id_parts.key_id)
        }
    };
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

/// Retrieve the user's encrypted signing key.
///
/// It's encrypted with a password.
///
/// # Arguments
/// * `asset_blob_cache` - An instance of AssetBlobCache for caching assets.
/// * `api_client` - An instance of HaiClient to interact with the API.
/// * `rec_key_id_parts` - The recipient key ID parts to identify which encryption key to retrieve.
pub async fn get_encrypted_signing_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    rec_key_id_parts: &RecipientKeyIdParts,
) -> Result<Option<crypt::EncryptedSigningKey>, String> {
    if !matches!(rec_key_id_parts.key_type, KeyType::Signing) {
        return Err("Invalid key type for signing key".to_string());
    }
    let key_path = match rec_key_id_parts.recipient {
        KeyRecipient::User(_) => {
            format!("keys/sign_{}.key", rec_key_id_parts.key_id)
        }
    };
    match get_key(asset_blob_cache.clone(), api_client, &key_path).await {
        Ok((key_contents, _key_id, _md_contents, _entry)) => Ok(Some(
            crypt::EncryptedSigningKey::from_bytes(&key_contents)
                .map_err(|e| format!("failed to parse signing key: {}", e))?,
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

pub fn recipient_key_info_to_key_entry_json(info: &RecipientKeyInfo) -> serde_json::Value {
    serde_json::json!({
        "encrypted_key": info.enc_aes_key_hex,
        "recipient_key_id": info.recipient_key_id(),
    })
}

pub async fn put_asset_encryption_metadata(
    api_client: &HaiClient,
    asset_name: &str,
    akm_info: &AssetKeyMaterial,
) -> Result<(), String> {
    let md_contents = serde_json::json!({
        "encrypted": akm_info.to_encrypted_metadata_json()
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

/// Parse the encryption information from the asset metadata, if it exists.
///
/// # Arguments
/// * `metadata` - The raw bytes of the asset metadata to parse.
/// * `username` - Optional username to match against the available recipient
///   keys.
pub fn parse_metadata_for_encryption_info(
    metadata: &[u8],
    recipient: Option<&KeyRecipient>,
) -> Option<RecipientKeyInfo> {
    // Quick exit if there's no recipient since it will never match a key.
    let recipient = recipient?;
    let md_json =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(metadata).to_string())
            .ok()?;
    let enc_info = md_json.get("encrypted")?;
    let enc_keys = enc_info.get("keys")?.as_array()?;

    let (enc_key_id, enc_aes_key_hex) = enc_keys.iter().find_map(|enc_key| {
        let recipient_key_id = enc_key.get("recipient_key_id")?.as_str()?;
        let enc_key_id = recipient_key_id.strip_prefix(&recipient.recipient_key_id_prefix())?;
        let enc_aes_key_hex = enc_key.get("encrypted_key")?.as_str()?;
        Some((enc_key_id.to_string(), enc_aes_key_hex.to_string()))
    })?;
    Some(RecipientKeyInfo {
        enc_key_id,
        enc_aes_key_hex,
        recipient: recipient.clone(),
    })
}

pub fn encrypt_asset_with_aes_key(aes_key: &crypt::AesKey, contents: &[u8]) -> Vec<u8> {
    crypt::encrypt_content(contents, aes_key)
        .expect("unexpected failure to encrypt content")
        .to_bytes()
}

#[derive(Debug)]
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
    rec_key_info: &RecipientKeyInfo,
) -> Result<SymmetricKeyInfo, AssetKeyMaterialDecryptionError> {
    let mut asset_keyring_locked = asset_keyring.lock().await;
    let secret = match asset_keyring_locked
        .get_or_unlock_decrypt_key(
            asset_blob_cache,
            api_client,
            &rec_key_info.recipient_key_id_parts(),
        )
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
    let enc_aes_key = crypt::EncryptedAesKey::from_hex(&rec_key_info.enc_aes_key_hex).unwrap();
    let aes_key = crypt::decrypt_aes_key(&enc_aes_key, &secret).unwrap();
    Ok(SymmetricKeyInfo {
        aes_key,
        enc_aes_key: rec_key_info.enc_aes_key_hex.to_string(),
    })
}

// --

pub async fn maybe_decrypt_asset_contents(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    recipient: Option<&KeyRecipient>,
    asset_contents: &[u8],
    md_contents: Option<&[u8]>,
) -> Result<Vec<u8>, AssetKeyMaterialDecryptionError> {
    if let Some(md_contents) = md_contents
        && let Some(rec_key_info) = parse_metadata_for_encryption_info(&md_contents, recipient)
    {
        get_symmetric_key_ez(asset_blob_cache, asset_keyring, &api_client, &rec_key_info)
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
    recipient: Option<&KeyRecipient>,
    additional_recipients: &[KeyRecipient],
    md_contents: Option<&[u8]>,
    generate_akm_if_new: bool,
) -> Result<Option<AssetKeyMaterial>, AkmSelectionError> {
    let Some(recipient) = recipient else {
        return Ok(None);
    };

    // Case 1: Existing encrypted asset - reconstruct AssetKeyMaterial
    if let Some(md_contents) = md_contents
        && let Some(rec_key_info) = parse_metadata_for_encryption_info(md_contents, Some(recipient))
    {
        let sym_key_info = get_symmetric_key_ez(
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            &api_client,
            &rec_key_info,
        )
        .await
        .map_err(|e| AkmSelectionError::Abort(format!("{}", e)))?;

        let enc_key_info = get_encryption_key(
            asset_blob_cache.clone(),
            &api_client,
            recipient,
            Some(&rec_key_info.enc_key_id),
        )
        .await
        .map_err(|e| AkmSelectionError::Abort(e))?
        .ok_or_else(|| {
            AkmSelectionError::Abort(format!(
                "encryption key {} not found",
                rec_key_info.enc_key_id
            ))
        })?;

        let mut akm =
            AssetKeyMaterial::from_metadata(md_contents, recipient, sym_key_info, enc_key_info)
                .map_err(|e| AkmSelectionError::Abort(e))?;

        // Add any new recipients to existing asset
        for additional in additional_recipients {
            let add_enc_key_info =
                get_encryption_key(asset_blob_cache.clone(), &api_client, additional, None)
                    .await
                    .map_err(|e| AkmSelectionError::Abort(e))?
                    .ok_or_else(|| {
                        AkmSelectionError::Abort(format!(
                            "encryption key not found for {}",
                            additional
                        ))
                    })?;

            akm.add_recipient(add_enc_key_info)
                .map_err(|e| AkmSelectionError::Abort(e))?;
        }

        return Ok(Some(akm));
    }

    // Case 2: New asset needing encryption - create fresh AssetKeyMaterial
    if generate_akm_if_new {
        let enc_key_info =
            get_encryption_key(asset_blob_cache.clone(), &api_client, recipient, None)
                .await
                .map_err(|e| AkmSelectionError::Abort(e))?
                .ok_or_else(|| {
                    AkmSelectionError::Abort(
                        "no encryption key found; generate one with /asset-crypt-setup".to_string(),
                    )
                })?;

        // Fetch additional recipients' keys
        let mut other_enc_keys = Vec::new();
        for additional_recipient in additional_recipients {
            let add_enc_key_info = get_encryption_key(
                asset_blob_cache.clone(),
                &api_client,
                additional_recipient,
                None,
            )
            .await
            .map_err(|e| AkmSelectionError::Abort(e))?
            .ok_or_else(|| {
                AkmSelectionError::Abort(format!(
                    "encryption key not found for {}",
                    additional_recipient
                ))
            })?;
            other_enc_keys.push(add_enc_key_info);
        }

        let akm = AssetKeyMaterial::new_for_recipients(enc_key_info, &other_enc_keys)
            .map_err(|e| AkmSelectionError::Abort(e))?;

        return Ok(Some(akm));
    }

    Ok(None)
}
/*
pub async fn choose_akm_for_asset(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: HaiClient,
    recipient: Option<&KeyRecipient>,
    md_contents: Option<&[u8]>,
    generate_akm_if_new: bool,
) -> Result<Option<AssetKeyMaterial>, AkmSelectionError> {
    if let Some(md_contents) = md_contents
        && let Some(recipient) = recipient
        && let Some(rec_key_info) =
            parse_metadata_for_encryption_info(&md_contents, Some(recipient))
    {
        match get_symmetric_key_ez(
            asset_blob_cache.clone(),
            asset_keyring.clone(),
            &api_client,
            &rec_key_info,
        )
        .await
        {
            Ok(sym_info) => {
                let enc_key_info = match get_encryption_key(
                    asset_blob_cache.clone(),
                    &api_client,
                    &recipient,
                    Some(&rec_key_info.enc_key_id),
                )
                .await
                {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        return Err(AkmSelectionError::Abort(format!(
                            "encryption key {} not found",
                            rec_key_info.enc_key_id
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
    } else if generate_akm_if_new && let Some(recipient) = recipient {
        match get_encryption_key(asset_blob_cache.clone(), &api_client, recipient, None).await {
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
}*/

pub async fn choose_akm_for_asset_by_name(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: HaiClient,
    recipient: Option<&KeyRecipient>,
    asset_name: &str,
    force_generate_akm_if_new: bool,
) -> Result<Option<AssetKeyMaterial>, AkmSelectionError> {
    let generate_akm_if_new = asset_name.starts_with("vault/")
        || asset_name.starts_with("/s/")
        || force_generate_akm_if_new;
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

    let additional_recipients = extract_usernames_from_shared_asset(asset_name)
        .into_iter()
        .map(|username| KeyRecipient::User(username.to_string()))
        .filter(|r| Some(r) != recipient)
        .collect::<Vec<_>>();

    choose_akm_for_asset(
        asset_blob_cache,
        asset_keyring,
        api_client,
        recipient,
        &additional_recipients,
        md_contents.as_deref(),
        generate_akm_if_new,
    )
    .await
}

fn extract_usernames_from_shared_asset(asset_name: &str) -> Vec<&str> {
    // Check if path starts with "/s/"
    if !asset_name.starts_with("/s/") {
        return Vec::new();
    }

    // Get everything after "/s/"
    let after_prefix = &asset_name[3..];

    // Get the second component (first component after "/s/")
    let second_component = after_prefix.split('/').next().unwrap_or("");

    // Split by '+' and collect non-empty parts
    second_component
        .split('+')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn extract_key_recipients_from_shared_asset_name(
    asset_name: &str,
    ignore_username: &str,
) -> Vec<KeyRecipient> {
    extract_usernames_from_shared_asset(asset_name)
        .into_iter()
        .filter(|username| username != &ignore_username)
        .map(|username| KeyRecipient::User(username.to_string()))
        .collect()
}

// --

pub enum SshKeyGenerationError {
    KeyNotFound,
    FetchFailed,
    InvalidKey,
    BadPassword,
    Other(String),
}

impl Debug for SshKeyGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshKeyGenerationError::KeyNotFound => write!(f, "key not found"),
            SshKeyGenerationError::FetchFailed => write!(f, "failed to fetch key data"),
            SshKeyGenerationError::InvalidKey => write!(f, "invalid key data"),
            SshKeyGenerationError::BadPassword => write!(f, "bad password for key decryption"),
            SshKeyGenerationError::Other(e) => write!(f, "error: {}", e),
        }
    }
}

/// Gets signing/verifying key and formats it for use as SSH public/private
/// keys.
///
/// # Returns
/// A tuple containing the key ID, base64 public key, and base64 private key.
pub async fn get_ed25519_for_ssh_key(
    asset_blob_cache: Arc<AssetBlobCache>,
    asset_keyring: Arc<Mutex<AssetKeyring>>,
    api_client: &HaiClient,
    username: &str,
) -> Result<(String, String, zeroize::Zeroizing<String>), SshKeyGenerationError> {
    use ed25519_dalek::VerifyingKey;
    // Fetch signing public key
    let verifying_key_asset_name = format!("/{username}/keys/sign.pub");
    let verifying_key_pub_data = match asset_reader::get_asset(
        asset_blob_cache.clone(),
        &api_client,
        &verifying_key_asset_name,
        true,
    )
    .await
    {
        Ok((data, _entry)) => data,
        Err(e) => match e {
            GetAssetError::BadName => {
                return Err(SshKeyGenerationError::KeyNotFound);
            }
            GetAssetError::DataFetchFailed => {
                return Err(SshKeyGenerationError::FetchFailed);
            }
        },
    };

    if verifying_key_pub_data.len() != 32 {
        return Err(SshKeyGenerationError::InvalidKey);
    }
    let mut verifying_key_pub_bytes = [0u8; 32];
    verifying_key_pub_bytes.copy_from_slice(&verifying_key_pub_data);
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_pub_bytes)
        .map_err(|_e| SshKeyGenerationError::InvalidKey)?;
    let signing_key_id = crypt::format_key_id(&crypt::derive_signing_key_id(&verifying_key));
    let ssh_public_key = to_ssh_authorized_key(verifying_key.as_bytes(), "test");

    let mut asset_keyring_locked = asset_keyring.lock().await;
    let signing_key = match asset_keyring_locked
        .get_or_unlock_signing_key(
            asset_blob_cache,
            api_client,
            &RecipientKeyIdParts {
                recipient: KeyRecipient::User(username.to_string()),
                key_id: signing_key_id.clone(),
                key_type: KeyType::Signing,
            },
        )
        .await
    {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("error: failed to unlock keyring: {}", e);
            return Err(SshKeyGenerationError::BadPassword);
        }
    };

    let ssh_private_key = to_openssh_private_key(&signing_key).map_err(|e| {
        SshKeyGenerationError::Other(format!(
            "Failed to convert signing key to OpenSSH format: {}",
            e
        ))
    })?;

    Ok((signing_key_id, ssh_public_key, ssh_private_key))
}

/// Convert an Ed25519 public key to OpenSSH authorized_keys format.
pub fn to_ssh_authorized_key(ed25519_pubkey: &[u8; 32], comment: &str) -> String {
    // SSH wire format for Ed25519:
    // 4 bytes: length of key type string (11)
    // 11 bytes: "ssh-ed25519"
    // 4 bytes: length of public key (32)
    // 32 bytes: the public key

    let key_type = b"ssh-ed25519";
    let mut blob = Vec::with_capacity(4 + key_type.len() + 4 + 32);

    // Key type length + key type
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);

    // Public key length + public key
    blob.extend_from_slice(&(32u32).to_be_bytes());
    blob.extend_from_slice(ed25519_pubkey);

    format!("ssh-ed25519 {} {}", STANDARD.encode(&blob), comment)
}

/// Convert an Ed25519 private key to OpenSSH format.
pub fn to_openssh_private_key(
    signing_key: &SigningKey,
) -> Result<Zeroizing<String>, ssh_key::Error> {
    // Build the Ed25519 keypair for ssh-key crate
    let secret_bytes = signing_key.to_bytes();
    let public_bytes = signing_key.verifying_key().to_bytes();

    // Combine into 64-byte keypair (secret || public) that ssh-key expects
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(&secret_bytes);
    keypair_bytes[32..].copy_from_slice(&public_bytes);

    let ed25519_keypair = ssh_key::private::Ed25519Keypair::from_bytes(&keypair_bytes)?;
    let ssh_private = PrivateKey::from(ed25519_keypair);

    ssh_private.to_openssh(LineEnding::LF)
}
