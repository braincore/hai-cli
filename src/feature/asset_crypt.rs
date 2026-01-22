use chrono::Utc;
use std::ffi::os_str::Display;
use std::sync::Arc;
use x25519_dalek::PublicKey;

use crate::api::types::asset;
use crate::api::{
    client::{HaiClient, RequestError},
    types::asset::AssetEntry,
};
use crate::asset_cache::AssetBlobCache;
use crate::asset_reader::{self, GetAssetError, get_only_asset_metadata};
use crate::crypt;
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
/// A Result containing a tuple of encryption key ID and signing key ID on success,
/// or a CryptSetupError on failure.
///
pub async fn asset_crypt_setup(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: HaiClient,
    username: &str,
) -> Result<(String, String), CryptSetupError> {
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    //
    // Check if asset encryption / signing key already exists.
    // If so, confirm rotation.
    //

    let mut rotation_accepted = false;
    match get_only_asset_metadata(asset_blob_cache.clone(), &api_client, "keys/enc.key", true).await
    {
        Ok((enc_key_md_contents, _enc_key_entry)) => {
            println!("Asset encryption key `keys/enc.key` already exists.");
            println!();
            println!("You will be prompted to confirm key rotation.");
            println!("Key rotation will:");
            println!("  • Generate new encryption and signing keys");
            println!("  • Set the new keys as your default");
            println!("  • Keep old keys available to decrypt/verify previously encrypted assets");
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

    // FUTURE: Convert this to an asset-copy
    /*
    put_crypt_asset(
        &api_client,
        "keys/enc.key".to_string(),
        &encrypted_encryption_bundle.to_bytes(),
    )
    .await?;
    put_crypt_asset(
        &api_client,
        "keys/sign.key".to_string(),
        &encrypted_signing_bundle.to_bytes(),
    )
    .await?;
    */

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
        "encrypted": true,
    })
    .to_string();
    //put_crypt_asset_metadata(&api_client, format!("keys/enc.key"), enc_key_md.clone()).await?;
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
        "encrypted": true,
    })
    .to_string();
    //put_crypt_asset_metadata(&api_client, format!("keys/sign.key"), sign_key_md.clone()).await?;
    put_crypt_asset_metadata(
        &api_client,
        format!("keys/sign_{sign_key_id}.key"),
        sign_key_md,
    )
    .await?;

    Ok((enc_key_id, sign_key_id))
}

// --

#[derive(Clone, Debug)]
pub struct EncryptKeyInfo {
    pub enc_key: PublicKey,
    pub enc_key_id: String,
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
            println!("Got encryption key ID: {} {:?}", key_id, key_id.as_bytes());
            let recipient_pub = PublicKey::from(<[u8; 32]>::try_from(&key_contents[..]).unwrap());
            //let recipient_pub = PublicKey::try_from(&key_contents[..]).unwrap();
            println!(
                "Derived key ID: {:?}",
                crypt::format_key_id(&crypt::derive_encryption_key_id(&recipient_pub))
            );
            if crypt::format_key_id(&crypt::derive_encryption_key_id(&recipient_pub)) == key_id {
                Ok(Some(EncryptKeyInfo {
                    enc_key: recipient_pub,
                    enc_key_id: key_id,
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
pub struct EncryptKeyPerFileInfo {
    pub enc_key_info: EncryptKeyInfo,
    pub aes_key: crypt::AesKey,
    pub enc_aes_key: String,
}

pub fn mk_encrypt_key_per_file_info(
    enc_key_info: EncryptKeyInfo,
    sym_info: SymmetricKeyPerFileInfo,
) -> EncryptKeyPerFileInfo {
    EncryptKeyPerFileInfo {
        enc_key_info,
        aes_key: sym_info.aes_key,
        enc_aes_key: sym_info.enc_aes_key,
    }
}

/// Create a new per-file encryption key info structure.
///
/// # Arguments
/// * `enc_key_info` - The user's public encryption key info.
///
pub fn new_per_file_encryption_key(enc_key_info: EncryptKeyInfo) -> EncryptKeyPerFileInfo {
    let aes_key = crypt::generate_aes_key();
    let enc_aes_key = crypt::encrypt_aes_key(&aes_key, &enc_key_info.enc_key)
        .unwrap()
        .to_hex();
    EncryptKeyPerFileInfo {
        enc_key_info,
        aes_key,
        enc_aes_key,
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
        Ok((key_contents, key_id, _md_contents, _entry)) => Ok(Some(
            // FIXME: Include key_id?
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
    enc_aes_key: &str,
    enc_key_id: &str,
) -> Result<(), String> {
    let md_contents = serde_json::json!({
        "encrypted": {
            "algorithm": "AES-GCM",
            "encrypted_key": enc_aes_key,
            "enc_key_id": enc_key_id,
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
    let enc_aes_key = enc_info.get("encrypted_key")?.as_str()?.to_string();
    let enc_key_id = enc_info.get("enc_key_id")?.as_str()?.to_string();
    Some((enc_aes_key, enc_key_id))
}

pub fn encrypt_asset_ez(enc_info: &EncryptKeyPerFileInfo, contents: &[u8]) -> Vec<u8> {
    crypt::encrypt_content(contents, &enc_info.aes_key)
        .expect("unexpected failure to encrypt content")
        .to_bytes()
}

pub enum GetPerFileDecryptionInfoError {
    NoEncryptionInfo,
    NoDecryptionKey,
    DecryptionKeyError(String),
    PasswordCancelled,
    EncryptionKeyDecryptionError(String),
}

impl ::std::fmt::Display for GetPerFileDecryptionInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetPerFileDecryptionInfoError::NoEncryptionInfo => {
                write!(f, "no encryption info found in metadata")
            }
            GetPerFileDecryptionInfoError::NoDecryptionKey => {
                write!(f, "no decryption key found for given key ID")
            }
            GetPerFileDecryptionInfoError::DecryptionKeyError(e) => {
                write!(f, "failed to get decryption key: {}", e)
            }
            GetPerFileDecryptionInfoError::PasswordCancelled => {
                write!(f, "password input cancelled")
            }
            GetPerFileDecryptionInfoError::EncryptionKeyDecryptionError(e) => {
                write!(f, "failed to decrypt encryption key: {}", e)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SymmetricKeyPerFileInfo {
    //pub enc_key_info: EncryptKeyInfo,
    pub aes_key: crypt::AesKey,
    pub enc_aes_key: String,
}

pub async fn get_per_file_symmetric_key_ez(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    enc_aes_key_hex: &str,
    enc_key_id: &str,
) -> Result<SymmetricKeyPerFileInfo, GetPerFileDecryptionInfoError> {
    let dec_key = match get_encrypted_decryption_key(
        asset_blob_cache.clone(),
        &api_client,
        &enc_key_id,
    )
    .await
    {
        Ok(Some(key)) => key,
        Ok(None) => {
            eprintln!("error: no decryption key found for key ID {}", enc_key_id);
            return Err(GetPerFileDecryptionInfoError::NoDecryptionKey);
        }
        Err(e) => {
            eprintln!("error: failed to get decryption key: {}", e);
            return Err(GetPerFileDecryptionInfoError::DecryptionKeyError(
                e.to_string(),
            ));
        }
    };

    // FIXME: ADD TO keychain
    let password = if let Some(password) = term::ask_question("Enter password:", true) {
        password
    } else {
        eprintln!("error: no password entered");
        return Err(GetPerFileDecryptionInfoError::PasswordCancelled);
    };
    let secret = match crypt::unprotect_encryption_key(&dec_key, password.as_bytes()) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("error: failed to decrypt encryption key: {}", e);
            return Err(GetPerFileDecryptionInfoError::EncryptionKeyDecryptionError(
                e.to_string(),
            ));
        }
    };

    let enc_aes_key = crypt::EncryptedAesKey::from_hex(&enc_aes_key_hex).unwrap();
    let aes_key = crypt::decrypt_aes_key(&enc_aes_key, &secret).unwrap();
    Ok(SymmetricKeyPerFileInfo {
        aes_key,
        enc_aes_key: enc_aes_key_hex.to_string(),
    })
}

pub async fn get_per_file_symmetric_key_from_metadata_ez(
    asset_blob_cache: Arc<AssetBlobCache>,
    api_client: &HaiClient,
    md_contents: &[u8],
) -> Result<Option<SymmetricKeyPerFileInfo>, GetPerFileDecryptionInfoError> {
    if let Some((enc_aes_key_hex, enc_key_id)) = parse_metadata_for_encryption_info(&md_contents) {
        get_per_file_symmetric_key_ez(
            asset_blob_cache.clone(),
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
    api_client: &HaiClient,
    asset_contents: &[u8],
    md_contents: Option<&[u8]>,
) -> Result<Vec<u8>, GetPerFileDecryptionInfoError> {
    if let Some(md_contents) = md_contents
        && let Some((enc_aes_key_hex, enc_key_id)) =
            parse_metadata_for_encryption_info(&md_contents)
    {
        get_per_file_symmetric_key_ez(
            asset_blob_cache.clone(),
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
