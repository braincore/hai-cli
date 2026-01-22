use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::api::client::HaiClient;
use crate::asset_cache::AssetBlobCache;
use crate::crypt;
use crate::feature::asset_crypt;
use crate::term;

/// Unlocked private keys for decrypting per-file AES keys
pub struct AssetKeyring {
    /// Map of enc_key_id -> decrypted private key (X25519 secret)
    unlocked_keys: HashMap<String, Zeroizing<StaticSecret>>,

    /// Optional: timestamp for auto-lock after idle timeout
    last_used: std::time::Instant,
}

impl fmt::Debug for AssetKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetKeyring")
            .field(
                "unlocked_keys",
                &format!("<{} keys redacted>", self.unlocked_keys.len()),
            )
            .field("last_used", &self.last_used)
            .finish()
    }
}

impl AssetKeyring {
    pub fn new() -> Self {
        Self {
            unlocked_keys: HashMap::new(),
            last_used: std::time::Instant::now(),
        }
    }

    /// Unlock a specific encryption key by ID
    pub async fn unlock_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        enc_key_id: &str,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        // Fetch the encrypted private key
        let dec_key =
            asset_crypt::get_encrypted_decryption_key(asset_blob_cache, api_client, enc_key_id)
                .await
                .map_err(|e| {
                    asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
                })?;
        let dec_key = if let Some(dec_key) = dec_key {
            dec_key
        } else {
            return Err(asset_crypt::AssetKeyMaterialDecryptionError::NoDecryptionKey);
        };
        // Prompt for password ONCE
        let password = term::ask_question(&format!("Unlock key {enc_key_id}:"), true)
            .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::PasswordCancelled)?;

        // Decrypt and store the private key
        let secret =
            crypt::unprotect_encryption_key(&dec_key, password.as_bytes()).map_err(|e| {
                asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
            })?;

        self.unlocked_keys
            .insert(enc_key_id.to_string(), Zeroizing::new(secret));
        self.last_used = std::time::Instant::now();

        Ok(())
    }

    /// Get an unlocked key, prompting to unlock if needed
    pub async fn get_or_unlock(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        enc_key_id: &str,
    ) -> Result<&StaticSecret, asset_crypt::AssetKeyMaterialDecryptionError> {
        if !self.unlocked_keys.contains_key(enc_key_id) {
            self.unlock_key(asset_blob_cache, api_client, enc_key_id)
                .await?;
        }

        self.last_used = std::time::Instant::now();
        Ok(&self.unlocked_keys.get(enc_key_id).unwrap())
    }

    /// Lock (clear) a specific key
    pub fn lock_key(&mut self, enc_key_id: &str) {
        self.unlocked_keys.remove(enc_key_id);
    }

    /// Lock all keys
    pub fn lock_all(&mut self) {
        self.unlocked_keys.clear();
    }

    /// Check if idle timeout exceeded
    pub fn check_timeout(&mut self, timeout_secs: u64) -> bool {
        if self.last_used.elapsed().as_secs() > timeout_secs {
            self.lock_all();
            true
        } else {
            false
        }
    }
}

// Auto-clear on drop
impl Drop for AssetKeyring {
    fn drop(&mut self) {
        self.lock_all();
    }
}
