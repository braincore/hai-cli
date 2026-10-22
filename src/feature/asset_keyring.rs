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
use crate::io::Io;

const KEYRING_SERVICE: &str = "hai-asset-keys";

/// Where key passwords are remembered between sessions.
enum PasswordStore {
    /// Not persisted: user is prompted once per session.
    None,
    /// OS keyring (Linux, Windows, and macOS when Secure Enclave is
    /// unavailable).
    OsKeyring,
    /// macOS: passwords sealed to a Secure Enclave key gated by Touch ID.
    /// // Also uses system password as fallback.
    #[cfg(all(target_os = "macos", hai_se))]
    SecureEnclave(crate::feature::macos_se::SeVault),
}

impl PasswordStore {
    fn name(&self) -> &'static str {
        match self {
            PasswordStore::None => "none",
            PasswordStore::OsKeyring => "os-keyring",
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(_) => "secure-enclave",
        }
    }
}

/// Unlocked private keys for decrypting per-file AES keys
pub struct AssetKeyring {
    /// Map of rec_key_id -> decrypted private key (X25519 secret)
    unlocked_decrypt_keys: HashMap<String, StaticSecret>,

    /// Map of rec_key_id -> decrypted private key (ED25519 secret)
    unlocked_signing_keys: HashMap<String, SigningKey>,

    /// Passwords entered or retrieved this session.
    /// Since a user's encryption and signing keys typically share the same
    /// password (unless rotated), rather than prompting separately for each
    /// key, we try each stored password to ideally prompt only once.
    session_passwords: Vec<Zeroizing<String>>,

    /// Timestamp for auto-lock after idle timeout
    last_used: std::time::Instant,

    /// Where passwords are stored between sessions
    store: PasswordStore,
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
            .field(
                "session_passwords",
                &format!("<{} redacted>", self.session_passwords.len()),
            )
            .field("last_used", &self.last_used)
            .field("store", &self.store.name())
            .finish()
    }
}

impl AssetKeyring {
    pub fn new(enable_os_keyring: bool) -> Self {
        let store = if enable_os_keyring {
            Self::select_store()
        } else {
            PasswordStore::None
        };
        tracing::debug!("asset keyring password store: {}", store.name());
        Self {
            unlocked_decrypt_keys: HashMap::new(),
            unlocked_signing_keys: HashMap::new(),
            session_passwords: Vec::new(),
            last_used: std::time::Instant::now(),
            store,
        }
    }

    fn select_store() -> PasswordStore {
        #[cfg(all(target_os = "macos", hai_se))]
        {
            let dir = crate::config::get_config_folder_path()
                .join("keys")
                .join("se");
            if let Some(vault) = crate::feature::macos_se::SeVault::open(dir) {
                return PasswordStore::SecureEnclave(vault);
            }
        }

        // Try to replace the default store with one that can use secret-
        // service and keyutils (headless) on Linux.
        #[cfg(target_os = "linux")]
        if let Ok(backend) = FallbackCredentialBuilder::new() {
            keyring::set_default_credential_builder(Box::new(backend));
        }

        if Self::test_keyring_availability() {
            PasswordStore::OsKeyring
        } else {
            PasswordStore::None
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

    /// Store password in the persistent store
    fn store_password(&self, rec_key_id: &str, password: &str) {
        match &self.store {
            PasswordStore::None => {}
            PasswordStore::OsKeyring => match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
                Ok(entry) => {
                    if let Err(e) = entry.set_password(password) {
                        tracing::debug!("error: failed to store password in keyring: {}", e);
                    }
                }
                Err(e) => {
                    tracing::debug!("error: failed to create keyring entry: {}", e);
                }
            },
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => {
                if let Err(e) = vault.store(rec_key_id, password) {
                    tracing::debug!("error: failed to seal password: {}", e);
                }
            }
        }
    }

    /// Retrieve password from the persistent store
    fn get_stored_password(&self, rec_key_id: &str) -> Option<Zeroizing<String>> {
        match &self.store {
            PasswordStore::None => None,
            PasswordStore::OsKeyring => match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
                Ok(entry) => match entry.get_password() {
                    Ok(password) => Some(Zeroizing::new(password)),
                    Err(keyring::Error::NoEntry) => None,
                    Err(e) => {
                        tracing::error!("error: failed to retrieve password from keyring: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::error!("error: failed to access keyring entry: {}", e);
                    None
                }
            },
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => match vault.get(rec_key_id) {
                Ok(pw) => pw,
                Err(e) => {
                    // Cancelled / failed Touch ID: fall back to the password
                    // prompt. The sealed entry is kept for next time.
                    tracing::debug!("secure enclave unlock for {} failed: {}", rec_key_id, e);
                    None
                }
            },
        }
    }

    /// Whether the persistent store has an entry, without prompting.
    fn has_stored_password(&self, rec_key_id: &str) -> Option<bool> {
        match &self.store {
            PasswordStore::None => Some(false),
            PasswordStore::OsKeyring => None, // unknown without reading
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => Some(vault.contains(rec_key_id)),
        }
    }

    /// Delete password from the persistent store
    fn delete_stored_password(&self, rec_key_id: &str) {
        match &self.store {
            PasswordStore::None => {}
            PasswordStore::OsKeyring => match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
                Ok(entry) => {
                    if let Err(e) = entry.delete_credential() {
                        if !matches!(e, keyring::Error::NoEntry) {
                            tracing::debug!("error: failed to delete password from keyring: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("error: failed to access keyring entry for deletion: {}", e);
                }
            },
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => vault.delete(rec_key_id),
        }
    }

    fn remember_session_password(&mut self, password: &str) {
        if !self
            .session_passwords
            .iter()
            .any(|p| p.as_str() == password)
        {
            self.session_passwords
                .push(Zeroizing::new(password.to_string()));
        }
    }

    /// Try to unprotect a key using passwords we already know: first the
    /// persistent store, then passwords entered earlier this session.
    fn try_known_passwords<T>(
        &mut self,
        rec_key_id: &str,
        unprotect: impl Fn(&[u8]) -> Result<T, crypt::CryptoError>,
    ) -> Option<T> {
        if let Some(stored) = self.get_stored_password(rec_key_id) {
            match unprotect(stored.as_bytes()) {
                Ok(secret) => {
                    self.remember_session_password(&stored);
                    return Some(secret);
                }
                Err(_) => {
                    tracing::debug!(
                        "error: stored password for {} is invalid, removing it",
                        rec_key_id
                    );
                    self.delete_stored_password(rec_key_id);
                }
            }
        }
        let found = self
            .session_passwords
            .iter()
            .find_map(|pw| unprotect(pw.as_bytes()).ok().map(|s| (s, pw.clone())));
        if let Some((secret, pw)) = found {
            self.store_password(rec_key_id, &pw);
            return Some(secret);
        }
        None
    }

    /// Accept a password supplied by the user, persisting it on success.
    fn accept_password<T>(
        &mut self,
        rec_key_id: &str,
        password: &str,
        unprotect: impl Fn(&[u8]) -> Result<T, crypt::CryptoError>,
    ) -> Result<T, asset_crypt::AssetKeyMaterialDecryptionError> {
        let secret = unprotect(password.as_bytes()).map_err(|e| {
            asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
        })?;
        self.store_password(rec_key_id, password);
        self.remember_session_password(password);
        Ok(secret)
    }

    fn prompt_password(
        io: &Io,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<Zeroizing<String>, asset_crypt::AssetKeyMaterialDecryptionError> {
        let password = io
            .query(&crate::io::Query::secret_line(&format!(
                "Unlock key {}:",
                rec_key_id_parts.key_id
            )))
            .into_option()
            .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::PasswordCancelled)?;
        Ok(Zeroizing::new(password))
    }

    async fn fetch_decrypt_key(
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<crypt::EncryptedEncryptionKey, asset_crypt::AssetKeyMaterialDecryptionError> {
        asset_crypt::get_encrypted_decryption_key(asset_blob_cache, api_client, rec_key_id_parts)
            .await
            .map_err(asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError)?
            .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::NoDecryptionKey)
    }

    async fn fetch_signing_key(
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<crypt::EncryptedSigningKey, asset_crypt::AssetKeyMaterialDecryptionError> {
        asset_crypt::get_encrypted_signing_key(asset_blob_cache, api_client, rec_key_id_parts)
            .await
            .map_err(asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError)?
            .ok_or(asset_crypt::AssetKeyMaterialDecryptionError::NoDecryptionKey)
    }

    /// Unlock a specific decryption key by ID using a known password.
    pub async fn unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
        password: &str,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        let dec_key =
            Self::fetch_decrypt_key(asset_blob_cache, api_client, rec_key_id_parts).await?;
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        let unprotect = |pw: &[u8]| crypt::unprotect_encryption_key(&dec_key, pw);
        let secret = match self.try_known_passwords(&rec_key_id, unprotect) {
            Some(secret) => secret,
            None => self.accept_password(&rec_key_id, password, unprotect)?,
        };
        self.unlocked_decrypt_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();
        Ok(())
    }

    /// Unlock a specific decryption key by ID, prompting if needed.
    pub async fn unlock_decrypt_key_with_prompt(
        &mut self,
        io: &Io,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        let dec_key =
            Self::fetch_decrypt_key(asset_blob_cache, api_client, rec_key_id_parts).await?;
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        let unprotect = |pw: &[u8]| crypt::unprotect_encryption_key(&dec_key, pw);
        let secret = match self.try_known_passwords(&rec_key_id, unprotect) {
            Some(secret) => secret,
            None => {
                let password = Self::prompt_password(io, rec_key_id_parts)?;
                self.accept_password(&rec_key_id, &password, unprotect)?
            }
        };
        self.unlocked_decrypt_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();
        Ok(())
    }

    /// Tests whether the decryption key can be unlocked without typing a
    /// password. If so, the key is unlocked as a side effect (on macOS this
    /// may show a Touch ID prompt).
    pub async fn can_unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> bool {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if self.unlocked_decrypt_keys.contains_key(&rec_key_id) {
            return true;
        }
        if self.session_passwords.is_empty() && self.has_stored_password(&rec_key_id) == Some(false)
        {
            return false;
        }
        let Ok(dec_key) =
            Self::fetch_decrypt_key(asset_blob_cache, api_client, rec_key_id_parts).await
        else {
            return false;
        };
        match self.try_known_passwords(&rec_key_id, |pw| {
            crypt::unprotect_encryption_key(&dec_key, pw)
        }) {
            Some(secret) => {
                self.unlocked_decrypt_keys.insert(rec_key_id, secret);
                self.last_used = std::time::Instant::now();
                true
            }
            None => false,
        }
    }

    /// Tests whether the signing key can be unlocked without typing a
    /// password. If so, the key is unlocked as a side effect (on macOS this
    /// may show a Touch ID prompt).
    pub async fn can_unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> bool {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if self.unlocked_signing_keys.contains_key(&rec_key_id) {
            return true;
        }
        if self.session_passwords.is_empty() && self.has_stored_password(&rec_key_id) == Some(false)
        {
            return false;
        }
        let Ok(signing_key) =
            Self::fetch_signing_key(asset_blob_cache, api_client, rec_key_id_parts).await
        else {
            return false;
        };
        match self.try_known_passwords(&rec_key_id, |pw| {
            crypt::unprotect_signing_key(&signing_key, pw)
        }) {
            Some(secret) => {
                self.unlocked_signing_keys.insert(rec_key_id, secret);
                self.last_used = std::time::Instant::now();
                true
            }
            None => false,
        }
    }

    /// Unlock a specific signing key by ID using a known password.
    pub async fn unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
        password: &str,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        let signing_key =
            Self::fetch_signing_key(asset_blob_cache, api_client, rec_key_id_parts).await?;
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        let unprotect = |pw: &[u8]| crypt::unprotect_signing_key(&signing_key, pw);
        let secret = match self.try_known_passwords(&rec_key_id, unprotect) {
            Some(secret) => secret,
            None => self.accept_password(&rec_key_id, password, unprotect)?,
        };
        self.unlocked_signing_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();
        Ok(())
    }

    /// Unlock a specific signing key by ID, prompting if needed.
    pub async fn unlock_signing_key_with_prompt(
        &mut self,
        io: &Io,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        let signing_key =
            Self::fetch_signing_key(asset_blob_cache, api_client, rec_key_id_parts).await?;
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        let unprotect = |pw: &[u8]| crypt::unprotect_signing_key(&signing_key, pw);
        let secret = match self.try_known_passwords(&rec_key_id, unprotect) {
            Some(secret) => secret,
            None => {
                let password = Self::prompt_password(io, rec_key_id_parts)?;
                self.accept_password(&rec_key_id, &password, unprotect)?
            }
        };
        self.unlocked_signing_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();
        Ok(())
    }

    /// Get an unlocked key, prompting to unlock if needed
    pub async fn get_or_unlock_decrypt_key_with_prompt(
        &mut self,
        io: &Io,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<&StaticSecret, asset_crypt::AssetKeyMaterialDecryptionError> {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if !self.unlocked_decrypt_keys.contains_key(&rec_key_id) {
            self.unlock_decrypt_key_with_prompt(io, asset_blob_cache, api_client, rec_key_id_parts)
                .await?;
        }

        self.last_used = std::time::Instant::now();
        Ok(self.unlocked_decrypt_keys.get(&rec_key_id).unwrap())
    }

    /// Get an unlocked key, prompting to unlock if needed
    pub async fn get_or_unlock_signing_key_with_prompt(
        &mut self,
        io: &Io,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<&SigningKey, asset_crypt::AssetKeyMaterialDecryptionError> {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if !self.unlocked_signing_keys.contains_key(&rec_key_id) {
            self.unlock_signing_key_with_prompt(io, asset_blob_cache, api_client, rec_key_id_parts)
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

    /// Lock all keys from memory (keeps keyring entries). The next unlock
    /// requires re-authentication (e.g. Touch ID).
    pub fn lock_all(&mut self) {
        self.unlocked_decrypt_keys.clear();
        self.unlocked_signing_keys.clear();
        self.session_passwords.clear();
        #[cfg(all(target_os = "macos", hai_se))]
        if matches!(self.store, PasswordStore::SecureEnclave(_)) {
            crate::feature::macos_se::reset_auth();
        }
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_decrypt_key(&mut self, rec_key_id: &str) {
        self.unlocked_decrypt_keys.remove(rec_key_id);
        self.session_passwords.clear();
        self.delete_stored_password(rec_key_id);
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_signing_key(&mut self, rec_key_id: &str) {
        self.unlocked_signing_keys.remove(rec_key_id);
        self.session_passwords.clear();
        self.delete_stored_password(rec_key_id);
    }

    /// Lock and forget all keys (removes from memory AND keyring)
    pub fn forget_all(&mut self) {
        let keys: Vec<String> = self
            .unlocked_decrypt_keys
            .keys()
            .chain(self.unlocked_signing_keys.keys())
            .cloned()
            .collect();
        for key_id in keys {
            self.delete_stored_password(&key_id);
        }
        #[cfg(all(target_os = "macos", hai_se))]
        if let PasswordStore::SecureEnclave(vault) = &self.store {
            vault.wipe();
        }
        self.lock_all();
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

    /// Check if a persistent password store is available
    pub fn is_keyring_available(&self) -> bool {
        !matches!(self.store, PasswordStore::None)
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
        assert!(keyring.is_keyring_available());
    }

    #[test]
    fn test_keyring_disabled() {
        let keyring = AssetKeyring::new(false);
        assert!(!keyring.is_keyring_available());
    }

    #[test]
    fn test_lock_operations() {
        let mut keyring = AssetKeyring::new(true);
        keyring.lock_all();
        keyring.lock_decrypt_key("nonexistent");
        // Should not panic
    }
}
