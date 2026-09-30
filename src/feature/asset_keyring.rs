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

        // On macOS, gate reads of stored passwords behind Touch ID / Face ID /
        // Apple Watch (falling back to the login password).
        #[cfg(target_os = "macos")]
        keyring::set_default_credential_builder(Box::new(
            macos_biometric::BiometricMacCredentialBuilder,
        ));

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
                    tracing::debug!("error: failed to store password in keyring: {}", e);
                }
            }
            Err(e) => {
                tracing::debug!("error: failed to create keyring entry: {}", e);
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
                    tracing::error!("error: failed to retrieve password from keyring: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::error!("error: failed to access keyring entry: {}", e);
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
                        tracing::debug!("error: failed to delete password from keyring: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("error: failed to access keyring entry for deletion: {}", e);
            }
        }
    }

    /// Unlock a specific decryption key by ID
    pub async fn unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
        password: &str,
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
                    tracing::debug!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

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

    /// Unlock a specific decryption key by ID
    pub async fn unlock_decrypt_key_with_prompt(
        &mut self,
        io: &Io,
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
                    tracing::debug!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

        // Prompt for password if we don't have a valid stored one
        let password = io
            .query(&crate::io::Query::secret_line(&format!(
                "Unlock key {}:",
                rec_key_id_parts.key_id
            )))
            .into_option()
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

    /// Tests whether password already available to unlock decryption key.
    pub async fn can_unlock_decrypt_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> bool {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if self.unlocked_decrypt_keys.get(&rec_key_id).is_some() {
            return true;
        }

        // Fetch the encrypted private key
        let dec_key = match asset_crypt::get_encrypted_decryption_key(
            asset_blob_cache,
            api_client,
            &rec_key_id_parts,
        )
        .await
        {
            Ok(Some(key)) => key,
            _ => return false,
        };

        // Try using a stored password to decrypt the key
        if let Some(stored_password) = self.get_password_from_keyring(&rec_key_id) {
            crypt::unprotect_encryption_key(&dec_key, stored_password.as_bytes()).is_ok()
        } else {
            false
        }
    }

    /// Tests whether password already available to unlock signing key.
    pub async fn can_unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> bool {
        let rec_key_id = rec_key_id_parts.recipient_key_id();
        if self.unlocked_signing_keys.get(&rec_key_id).is_some() {
            return true;
        }

        // Fetch the encrypted signing key
        let signing_key = match asset_crypt::get_encrypted_signing_key(
            asset_blob_cache,
            api_client,
            rec_key_id_parts,
        )
        .await
        {
            Ok(Some(key)) => key,
            _ => return false,
        };

        // Try using a stored password to decrypt the key
        if let Some(stored_password) = self.get_password_from_keyring(&rec_key_id) {
            crypt::unprotect_signing_key(&signing_key, stored_password.as_bytes()).is_ok()
        } else {
            false
        }
    }

    /// Unlock a specific signing key by ID
    pub async fn unlock_signing_key(
        &mut self,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
        password: &str,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        // Fetch the encrypted private key
        let signing_key =
            asset_crypt::get_encrypted_signing_key(asset_blob_cache, api_client, rec_key_id_parts)
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
                    // Stored password is invalid, remove it
                    tracing::debug!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

        // Decrypt and store the private key
        let secret =
            crypt::unprotect_signing_key(&signing_key, password.as_bytes()).map_err(|e| {
                asset_crypt::AssetKeyMaterialDecryptionError::DecryptionKeyError(e.to_string())
            })?;

        // Store password in OS keyring for future use
        self.store_password_in_keyring(&rec_key_id, password);

        self.unlocked_signing_keys.insert(rec_key_id, secret);
        self.last_used = std::time::Instant::now();

        Ok(())
    }

    /// Unlock a specific signing key by ID
    pub async fn unlock_signing_key_with_prompt(
        &mut self,
        io: &Io,
        asset_blob_cache: Arc<AssetBlobCache>,
        api_client: &HaiClient,
        rec_key_id_parts: &asset_crypt::RecipientKeyIdParts,
    ) -> Result<(), asset_crypt::AssetKeyMaterialDecryptionError> {
        // Fetch the encrypted private key
        let signing_key =
            asset_crypt::get_encrypted_signing_key(asset_blob_cache, api_client, rec_key_id_parts)
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
                    tracing::debug!(
                        "error: stored password for {} is invalid, prompting for new password",
                        rec_key_id
                    );
                    self.delete_password_from_keyring(&rec_key_id);
                }
            }
        }

        // Prompt for password if we don't have a valid stored one
        let password = io
            .query(&crate::io::Query::secret_line(&format!(
                "Unlock key {}:",
                rec_key_id_parts.key_id
            )))
            .into_option()
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
        // Also require Touch ID again on next use.
        #[cfg(target_os = "macos")]
        macos_biometric::clear_session();
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

/// macOS credential store that keeps using the (legacy, file-based) login
/// keychain via `keyring::macos`, but requires the user to authenticate with
/// Touch ID / Face ID (or the login password as fallback) via
/// LocalAuthentication before a stored password is released.
///
/// Why not the data-protection keychain with `kSecAccessControlBiometryAny`?
/// That requires the binary to be codesigned with a `keychain-access-groups`
/// entitlement + provisioning profile; unsigned/ad-hoc CLI builds get
/// `errSecMissingEntitlement`. This gate is enforced by hai rather than by the
/// Secure Enclave, but works for any build.
///
/// Behavior notes:
/// - Missing entries return `NoEntry` without prompting (so the availability
///   probe and first-time unlocks never trigger a biometric prompt).
/// - Writes and deletes are not gated.
/// - A successful authentication lasts for the whole boot session, across
///   hai processes (like keyutils on Linux): a marker holding the boot
///   session UUID is kept in the keychain (ACL'd to the hai binary like the
///   passwords themselves). After a reboot the UUID changes and Touch ID is
///   requested again. `SESSION_MAX_AGE` can optionally cap this.
/// - If authentication fails/is cancelled, an error is returned, which
///   `AssetKeyring` treats as "no stored password" and falls back to
///   prompting for the key password.
#[cfg(target_os = "macos")]
mod macos_biometric {
    use block2::RcBlock;
    use keyring::credential::{CredentialApi, CredentialBuilderApi};
    use keyring::macos::MacCredential;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::{Mutex, mpsc};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const AUTH_REASON: &str = "unlock your hai asset encryption key";

    /// Keychain account (under `KEYRING_SERVICE`) holding the boot-session
    /// auth marker.
    const SESSION_ACCOUNT: &str = "__local_auth_session__";

    /// Optional cap on how long one authentication lasts, even within a single
    /// boot. `None` = until reboot (matches Linux keyutils behavior).
    const SESSION_MAX_AGE: Option<Duration> = None;

    /// In-process cache of the last successful authentication.
    static LAST_AUTH: Mutex<Option<Instant>> = Mutex::new(None);

    fn la_error(msg: String) -> keyring::Error {
        keyring::Error::NoStorageAccess(msg.into())
    }

    fn within_max_age(age: Duration) -> bool {
        SESSION_MAX_AGE.is_none_or(|max| age < max)
    }

    /// Authenticate the device owner, reusing a success from earlier in this
    /// process or from any hai process since the last boot.
    fn authenticate() -> keyring::Result<()> {
        // Holding the lock across the prompt serializes concurrent prompts.
        let mut last = LAST_AUTH.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last
            && within_max_age(t.elapsed())
        {
            return Ok(());
        }

        let boot_id = boot_session_id();
        if let Some(boot_id) = &boot_id
            && session_marker_valid(boot_id)
        {
            *last = Some(Instant::now());
            return Ok(());
        }

        evaluate_device_owner_policy(AUTH_REASON)?;
        *last = Some(Instant::now());
        if let Some(boot_id) = &boot_id {
            write_session_marker(boot_id);
        }
        Ok(())
    }

    /// Forget the boot-session authentication (in-process and persisted).
    pub fn clear_session() {
        *LAST_AUTH.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Ok(cred) = session_cred() {
            let _ = cred.delete_credential();
        }
    }

    fn session_cred() -> keyring::Result<MacCredential> {
        MacCredential::new_with_target(None, super::KEYRING_SERVICE, SESSION_ACCOUNT)
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Marker format: `v1|<boot session id>|<unix secs of auth>`
    fn session_marker_valid(boot_id: &str) -> bool {
        let Ok(value) = session_cred().and_then(|c| c.get_password()) else {
            return false;
        };
        let mut parts = value.splitn(3, '|');
        let (Some("v1"), Some(id), Some(ts)) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        if id != boot_id {
            return false;
        }
        let Ok(ts) = ts.parse::<u64>() else {
            return false;
        };
        within_max_age(Duration::from_secs(now_unix_secs().saturating_sub(ts)))
    }

    fn write_session_marker(boot_id: &str) {
        let value = format!("v1|{}|{}", boot_id, now_unix_secs());
        if let Err(e) = session_cred().and_then(|c| c.set_password(&value)) {
            tracing::debug!("error: failed to store local-auth session marker: {}", e);
        }
    }

    /// Identifier that changes on every boot. Prefers `kern.bootsessionuuid`;
    /// falls back to `kern.boottime`.
    fn boot_session_id() -> Option<String> {
        if let Some(uuid) = sysctl_string(c"kern.bootsessionuuid")
            && !uuid.is_empty()
        {
            return Some(uuid);
        }
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = std::mem::size_of::<libc::timeval>();
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                &mut tv as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && tv.tv_sec != 0).then(|| format!("boottime:{}", tv.tv_sec))
    }

    fn sysctl_string(name: &std::ffi::CStr) -> Option<String> {
        let mut buf = [0u8; 128];
        let mut size = buf.len();
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let bytes = &buf[..size.min(buf.len())];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).trim().to_string())
    }

    fn ns_error_to_string(err: &NSError) -> String {
        format!("{} (LAError {})", err.localizedDescription(), err.code())
    }

    /// Blocks until the user completes (or cancels) the system auth prompt.
    fn evaluate_device_owner_policy(reason: &str) -> keyring::Result<()> {
        // Biometrics or Apple Watch, with login-password fallback.
        let policy = LAPolicy::DeviceOwnerAuthentication;
        let ctx = unsafe { LAContext::new() };
        if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
            return Err(la_error(format!(
                "local authentication unavailable: {}",
                ns_error_to_string(&e)
            )));
        }

        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let res = if ok.as_bool() {
                Ok(())
            } else {
                Err(unsafe { err.as_ref() }
                    .map(ns_error_to_string)
                    .unwrap_or_else(|| "authentication failed".to_string()))
            };
            let _ = tx.send(res);
        });
        let reason = NSString::from_str(reason);
        unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };

        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(la_error(format!("local authentication failed: {}", msg))),
            Err(_) => Err(la_error("local authentication reply dropped".to_string())),
        }
    }

    #[derive(Debug)]
    pub struct BiometricMacCredential {
        inner: MacCredential,
    }

    impl CredentialApi for BiometricMacCredential {
        fn set_password(&self, password: &str) -> keyring::Result<()> {
            self.inner.set_password(password)
        }

        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            self.inner.set_secret(secret)
        }

        fn get_password(&self) -> keyring::Result<String> {
            // Returns NoEntry (without prompting) if nothing is stored.
            let password = zeroize::Zeroizing::new(self.inner.get_password()?);
            authenticate()?;
            Ok(password.to_string())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            let secret = zeroize::Zeroizing::new(self.inner.get_secret()?);
            authenticate()?;
            Ok(secret.to_vec())
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            self.inner.delete_credential()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[derive(Debug)]
    pub struct BiometricMacCredentialBuilder;

    impl CredentialBuilderApi for BiometricMacCredentialBuilder {
        fn build(
            &self,
            target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<dyn CredentialApi + Send + Sync + 'static>> {
            let inner = MacCredential::new_with_target(target, service, user)?;
            Ok(Box::new(BiometricMacCredential { inner }))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
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
    fn test_lock_operations() {
        let mut keyring = AssetKeyring::new(true);
        keyring.lock_all();
        keyring.lock_decrypt_key("nonexistent");
        // Should not panic
    }
}
