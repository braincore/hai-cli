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

const KEYRING_SERVICE: &str = "hai-asset-keys";

/// Unlocked private keys for decrypting per-file AES keys
pub struct AssetKeyring {
    /// Map of enc_key_id -> decrypted private key (X25519 secret)
    unlocked_keys: HashMap<String, Zeroizing<StaticSecret>>,

    /// Timestamp for auto-lock after idle timeout
    last_used: std::time::Instant,

    /// Whether OS keyring is available
    keyring_available: bool,
}

impl fmt::Debug for AssetKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetKeyring")
            .field(
                "unlocked_keys",
                &format!("<{} keys redacted>", self.unlocked_keys.len()),
            )
            .field("last_used", &self.last_used)
            .field("keyring_available", &self.keyring_available)
            .finish()
    }
}

impl AssetKeyring {
    pub fn new(enable_os_keyring: bool) -> Self {
        // Test if keyring is available by attempting a dummy operation
        Self {
            unlocked_keys: HashMap::new(),
            last_used: std::time::Instant::now(),
            keyring_available: enable_os_keyring && Self::test_keyring_availability(),
        }
    }

    /// Test if the OS keyring is available.
    ///
    /// Uses a dummy key.
    fn test_keyring_availability() -> bool {
        let entry = match keyring::Entry::new(KEYRING_SERVICE, "__test_availability__") {
            Ok(entry) => entry,
            Err(_) => return false,
        };

        // Try to get a non-existent key - if we get NoEntry, keyring is working
        // If we get a platform error, it's not available
        match entry.get_password() {
            Ok(_) => true, // Works (though unexpected to find an entry with this name)
            Err(keyring::Error::NoEntry) => true, // Works
            Err(keyring::Error::NoStorageAccess(_)) => false,
            Err(keyring::Error::PlatformFailure(_)) => false, // Platform issue
            Err(keyring::Error::Ambiguous(_)) => true,        // Multiple entries, but keyring works
            Err(_) => false,                                  // Other errors, assume not available
        }
    }

    /// Store password in OS keyring
    fn store_password_in_keyring(&self, enc_key_id: &str, password: &str) {
        if !self.keyring_available {
            return;
        }

        match keyring::Entry::new(KEYRING_SERVICE, enc_key_id) {
            Ok(entry) => {
                if let Err(e) = entry.set_password(password) {
                    eprintln!("error: failed to store password in keyring: {}", e);
                }
            }
            Err(e) => {
                eprintln!("error: failed to create keyring entry: {}", e);
            }
        }
    }

    /// Retrieve password from OS keyring
    fn get_password_from_keyring(&self, enc_key_id: &str) -> Option<Zeroizing<String>> {
        if !self.keyring_available {
            return None;
        }

        match keyring::Entry::new(KEYRING_SERVICE, enc_key_id) {
            Ok(entry) => match entry.get_password() {
                Ok(password) => Some(Zeroizing::new(password)),
                Err(keyring::Error::NoEntry) => None,
                Err(e) => {
                    eprintln!("error: failed to retrieve password from keyring: {}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("error: failed to access keyring entry: {}", e);
                None
            }
        }
    }

    /// Delete password from OS keyring
    fn delete_password_from_keyring(&self, enc_key_id: &str) {
        if !self.keyring_available {
            return;
        }

        match keyring::Entry::new(KEYRING_SERVICE, enc_key_id) {
            Ok(entry) => {
                if let Err(e) = entry.delete_credential() {
                    if !matches!(e, keyring::Error::NoEntry) {
                        eprintln!("error: failed to delete password from keyring: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: failed to access keyring entry for deletion: {}", e);
            }
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

        // Try to get password from OS keyring first
        if let Some(stored_password) = self.get_password_from_keyring(enc_key_id) {
            // Verify the stored password works
            match crypt::unprotect_encryption_key(&dec_key, stored_password.as_bytes()) {
                Ok(secret) => {
                    // Stored password works!
                    self.unlocked_keys
                        .insert(enc_key_id.to_string(), Zeroizing::new(secret));
                    self.last_used = std::time::Instant::now();
                    return Ok(());
                }
                Err(_) => {
                    // Stored password is invalid, remove it and prompt for new one
                    println!(
                        "error: stored password for {} is invalid, prompting for new password",
                        enc_key_id
                    );
                    self.delete_password_from_keyring(enc_key_id);
                }
            }
        }

        // Prompt for password if we don't have a valid stored one
        let password = term::ask_question(&format!("Unlock key {enc_key_id}:"), true)
            .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::PasswordCancelled)?;
        let password = Zeroizing::new(password);

        // Decrypt and store the private key
        let secret =
            crypt::unprotect_encryption_key(&dec_key, password.as_bytes()).map_err(|e| {
                asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
            })?;

        // Store password in OS keyring for future use
        self.store_password_in_keyring(enc_key_id, &password);

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
        Ok(self.unlocked_keys.get(enc_key_id).unwrap())
    }

    /// Lock (clear) a specific key from memory (keeps keyring entry)
    pub fn lock_key(&mut self, enc_key_id: &str) {
        self.unlocked_keys.remove(enc_key_id);
    }

    /// Lock all keys from memory (keeps keyring entries)
    pub fn lock_all(&mut self) {
        self.unlocked_keys.clear();
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_key(&mut self, enc_key_id: &str) {
        self.unlocked_keys.remove(enc_key_id);
        self.delete_password_from_keyring(enc_key_id);
    }

    /// Lock and forget all keys (removes from memory AND keyring)
    pub fn forget_all(&mut self) {
        let keys: Vec<String> = self.unlocked_keys.keys().cloned().collect();
        for key_id in keys {
            self.delete_password_from_keyring(&key_id);
        }
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

    /// Check if OS keyring is available
    pub fn is_keyring_available(&self) -> bool {
        self.keyring_available
    }
}

// Auto-clear memory on drop (keyring entries persist intentionally)
impl Drop for AssetKeyring {
    fn drop(&mut self) {
        self.lock_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_creation() {
        let keyring = AssetKeyring::new(true);
        // Just verify it doesn't panic
        println!("Keyring available: {}", keyring.is_keyring_available());
    }

    #[test]
    fn test_lock_operations() {
        let mut keyring = AssetKeyring::new(true);
        keyring.lock_all();
        keyring.lock_key("nonexistent");
        // Should not panic
    }
}
