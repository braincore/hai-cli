use ed25519_dalek::SigningKey;
#[cfg(target_os = "linux")]
use keyring::{
    credential::{CredentialApi, CredentialBuilderApi},
    keyutils::KeyutilsCredential,
    secret_service::SsCredential,
};
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
    /// Map of rec_key_id -> decrypted private key (X25519 secret)
    unlocked_decrypt_keys: HashMap<String, StaticSecret>,

    /// Map of rec_key_id -> decrypted private key (ED25519 secret)
    unlocked_signing_keys: HashMap<String, SigningKey>,

    /// Timestamp for auto-lock after idle timeout
    last_used: std::time::Instant,

    /// Whether OS keyring is available
    keyring_available: bool,
}

impl fmt::Debug for AssetKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetKeyring")
            .field(
                "unlocked_decrypt_keys",
                &format!("<{} keys redacted>", self.unlocked_decrypt_keys.len()),
            )
            .field(
                "unlocked_signing_keys",
                &format!("<{} keys redacted>", self.unlocked_signing_keys.len()),
            )
            .field("last_used", &self.last_used)
            .field("keyring_available", &self.keyring_available)
            .finish()
    }
}

impl AssetKeyring {
    pub fn new(enable_os_keyring: bool) -> Self {
        // Try to replace the default store with one that can use secret-
        // service and keyutils (headless) on Linux.
        #[cfg(target_os = "linux")]
        if let Ok(backend) = FallbackCredentialBuilder::new() {
            keyring::set_default_credential_builder(Box::new(backend));
        }

        // Test if keyring is available by attempting a dummy operation
        Self {
            unlocked_decrypt_keys: HashMap::new(),
            unlocked_signing_keys: HashMap::new(),
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
    fn store_password_in_keyring(&self, rec_key_id: &str, password: &str) {
        if !self.keyring_available {
            return;
        }

        match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
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
    fn get_password_from_keyring(&self, rec_key_id: &str) -> Option<Zeroizing<String>> {
        if !self.keyring_available {
            return None;
        }

        match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
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
    fn delete_password_from_keyring(&self, rec_key_id: &str) {
        if !self.keyring_available {
            return;
        }

        match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
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

    /// Unlock a specific decryption key by ID
    pub async fn unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        // Fetch the encrypted private key
        let dec_key = asset_crypt::get_encrypted_decryption_key(
            asset_blob_cache,
            api_client,
            &rec_key_id_parts,
        )
        .await
        .map_err(|e| {
            asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
        })?;
        let dec_key = if let Some(dec_key) = dec_key {
            dec_key
        } else {
            return Err(asset_crypt::AssetKeyMaterialDecryptionError::NoDecryptionKey);
        };

        let rec_key_id = rec_key_id_parts.recipient_key_id();
        // Try to get password from OS keyring first
        if let Some(stored_password) = self.get_password_from_keyring(&rec_key_id) {
            // Verify the stored password works
            match crypt::unprotect_encryption_key(&dec_key, stored_password.as_bytes()) {
                Ok(secret) => {
                    // Stored password works!
                    self.unlocked_decrypt_keys
                        .insert(rec_key_id.to_string(), secret);
                    self.last_used = std::time::Instant::now();
                    return Ok(());
                }
                Err(_) => {
                    // Stored password is invalid, remove it and prompt for new one
                    println!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

        // Prompt for password if we don't have a valid stored one
        let password =
            term::ask_question(&format!("Unlock key {}:", rec_key_id_parts.key_id), true)
                .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::PasswordCancelled)?;
        let password = Zeroizing::new(password);

        // Decrypt and store the private key
        let secret =
            crypt::unprotect_encryption_key(&dec_key, password.as_bytes()).map_err(|e| {
                asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
            })?;

        // Store password in OS keyring for future use
        self.store_password_in_keyring(&rec_key_id, &password);

        self.unlocked_decrypt_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();

        Ok(())
    }

    /// Unlock a specific signing key by ID
    pub async fn unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        // Fetch the encrypted private key
        let signing_key =
            asset_crypt::get_encrypted_signing_key(asset_blob_cache, api_client, &rec_key_id_parts)
                .await
                .map_err(|e| {
                    asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
                })?;
        let signing_key = if let Some(signing_key) = signing_key {
            signing_key
        } else {
            return Err(asset_crypt::AssetKeyMaterialDecryptionError::NoDecryptionKey);
        };

        let rec_key_id = rec_key_id_parts.recipient_key_id();
        // Try to get password from OS keyring first
        if let Some(stored_password) = self.get_password_from_keyring(&rec_key_id) {
            // Verify the stored password works
            match crypt::unprotect_signing_key(&signing_key, stored_password.as_bytes()) {
                Ok(secret) => {
                    // Stored password works!
                    self.unlocked_signing_keys
                        .insert(rec_key_id.to_string(), secret);
                    self.last_used = std::time::Instant::now();
                    return Ok(());
                }
                Err(_) => {
                    // Stored password is invalid, remove it and prompt for new one
                    println!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

        // Prompt for password if we don't have a valid stored one
        let password =
            term::ask_question(&format!("Unlock key {}:", rec_key_id_parts.key_id), true)
                .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::PasswordCancelled)?;
        let password = Zeroizing::new(password);

        // Decrypt and store the private key
        let secret =
            crypt::unprotect_signing_key(&signing_key, password.as_bytes()).map_err(|e| {
                asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
            })?;

        // Store password in OS keyring for future use
        self.store_password_in_keyring(&rec_key_id, &password);

        self.unlocked_signing_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();

        Ok(())
    }

    /// Get an unlocked key, prompting to unlock if needed
    pub async fn get_or_unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<&StaticSecret, asset_crypt::AssetKeyMaterialDecryptionError> {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if !self.unlocked_decrypt_keys.contains_key(&rec_key_id) {
            self.unlock_decrypt_key(asset_blob_cache, api_client, &rec_key_id_parts)
                .await?;
        }

        self.last_used = std::time::Instant::now();
        Ok(self.unlocked_decrypt_keys.get(&rec_key_id).unwrap())
    }

    /// Get an unlocked key, prompting to unlock if needed
    pub async fn get_or_unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<&SigningKey, asset_crypt::AssetKeyMaterialDecryptionError> {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if !self.unlocked_signing_keys.contains_key(&rec_key_id) {
            self.unlock_signing_key(asset_blob_cache, api_client, &rec_key_id_parts)
                .await?;
        }

        self.last_used = std::time::Instant::now();
        Ok(self.unlocked_signing_keys.get(&rec_key_id).unwrap())
    }

    /// Lock (clear) a specific key from memory (keeps keyring entry)
    pub fn lock_decrypt_key(&mut self, rec_key_id: &str) {
        self.unlocked_decrypt_keys.remove(rec_key_id);
    }

    /// Lock (clear) a specific key from memory (keeps keyring entry)
    pub fn lock_signing_key(&mut self, rec_key_id: &str) {
        self.unlocked_signing_keys.remove(rec_key_id);
    }

    /// Lock all keys from memory (keeps keyring entries)
    pub fn lock_all(&mut self) {
        self.unlocked_decrypt_keys.clear();
        self.unlocked_signing_keys.clear();
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_decrypt_key(&mut self, rec_key_id: &str) {
        self.unlocked_decrypt_keys.remove(rec_key_id);
        self.delete_password_from_keyring(rec_key_id);
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_signing_key(&mut self, rec_key_id: &str) {
        self.unlocked_signing_keys.remove(rec_key_id);
        self.delete_password_from_keyring(rec_key_id);
    }

    /// Lock and forget all keys (removes from memory AND keyring)
    pub fn forget_all(&mut self) {
        let keys: Vec<String> = self.unlocked_decrypt_keys.keys().cloned().collect();
        for key_id in keys {
            self.delete_password_from_keyring(&key_id);
        }
        self.unlocked_decrypt_keys.clear();
        let keys: Vec<String> = self.unlocked_signing_keys.keys().cloned().collect();
        for key_id in keys {
            self.delete_password_from_keyring(&key_id);
        }
        self.unlocked_signing_keys.clear();
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

// --

/// A custom credential builder for linux that tries secret-service first, then
/// falls back to keyutils. This allows us to use secret-service on desktop
/// linux (persists credentials between reboot) and keyutils on headless linux
/// servers (no persistence between reboots).
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct FallbackCredentialBuilder {
    /// Indicator to only test once
    secret_service_missing: bool,
}

#[cfg(target_os = "linux")]
impl FallbackCredentialBuilder {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create a fake cred
        let ss = SsCredential::new_with_target(None, "test", "user")?;

        // Force a connect to secret service to determine if it exists
        let missing = match ss.map_matching_items(|_item| Ok(()), false) {
            Err(keyring::Error::PlatformFailure(_x)) => true,
            _ => false,
        };
        Ok(Self {
            secret_service_missing: missing,
        })
    }
}

#[cfg(target_os = "linux")]
impl CredentialBuilderApi for FallbackCredentialBuilder {
    /// Helper method to try secret-service first, then fallback to the kernel's store
    fn build(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> Result<Box<dyn CredentialApi + Send + Sync + 'static>, keyring::Error> {
        // First try secret-service if it exists
        if !self.secret_service_missing {
            let cred = SsCredential::new_with_target(target, service, user)?;
            return Ok(Box::new(cred));
        }

        // Fallback to the kernel's keystore
        let cred = KeyutilsCredential::new_with_target(target, service, user)?;
        Ok(Box::new(cred))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// --

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
        keyring.lock_decrypt_key("nonexistent");
        // Should not panic
    }
}
