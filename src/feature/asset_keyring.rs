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

/// If set, skips the macOS Secure Enclave store in favor of OS keyring.
/// Necessary when running daemons (e.g. haibot) since the OS keyring works
/// across processes (important for spawning kernel). Downside of course is
/// that it requires password entry.
pub const NO_SECURE_ENCLAVE_ENV_VAR: &str = "HAI_NO_SECURE_ENCLAVE";

#[cfg(all(target_os = "macos", hai_se))]
fn secure_enclave_disabled_by_env() -> bool {
    std::env::var_os(NO_SECURE_ENCLAVE_ENV_VAR).is_some_and(|v| !v.is_empty())
}

#[cfg(all(target_os = "macos", hai_se))]
fn se_vault_dir() -> std::path::PathBuf {
    crate::config::get_config_folder_path()
        .join("keys")
        .join("se")
}

fn delete_os_keyring_entry(rec_key_id: &str) {
    match keyring::Entry::new(KEYRING_SERVICE, rec_key_id) {
        Ok(entry) => {
            if let Err(e) = entry.delete_credential()
                && !matches!(e, keyring::Error::NoEntry)
            {
                tracing::debug!("error: failed to delete password from keyring: {}", e);
            }
        }
        Err(e) => {
            tracing::debug!("error: failed to access keyring entry for deletion: {}", e);
        }
    }
}

/// Where key passwords are remembered between sessions.
enum PasswordStore {
    /// Not persisted: user is prompted once per session.
    None,
    /// OS keyring (Linux, Windows, and macOS when Secure Enclave is
    /// unavailable).
    OsKeyring,
    /// macOS: passwords sealed to a Secure Enclave key gated by Touch ID.
    /// Also uses system password as fallback.
    #[cfg(all(target_os = "macos", hai_se))]
    SecureEnclave(crate::feature::macos_se::SeVault),
    /// A child process that inherited unlocked keys from its parent.
    /// Specifically useful when the parent process was using SecureEnclave
    /// since without inheritance every child process would need to trigger
    /// Touch ID (painful for kernels). Because the entire store is treated as
    /// inherited, any additional keys that are prompted for are only kept for
    /// the process's lifetime.
    Inherited,
}

impl PasswordStore {
    fn name(&self) -> &'static str {
        match self {
            PasswordStore::None => "none",
            PasswordStore::OsKeyring => "os-keyring",
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(_) => "secure-enclave",
            PasswordStore::Inherited => "inherited",
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
    /// Creates a keyring.
    ///
    /// The first keyring created in a process consumes any keys handed off by
    /// a parent process.
    pub fn new(enable_os_keyring: bool) -> Self {
        let inherited = INHERITED_KEYS.lock().ok().and_then(|mut g| g.take());
        let store = if enable_os_keyring {
            Self::select_store(inherited.is_some())
        } else {
            PasswordStore::None
        };
        tracing::debug!("asset keyring password store: {}", store.name());
        let mut keyring = Self {
            unlocked_decrypt_keys: HashMap::new(),
            unlocked_signing_keys: HashMap::new(),
            session_passwords: Vec::new(),
            last_used: std::time::Instant::now(),
            store,
        };
        if let Some(keys) = inherited {
            tracing::debug!(
                "asset keyring seeded by parent: {} decrypt, {} signing",
                keys.decrypt.len(),
                keys.signing.len()
            );
            keyring.unlocked_decrypt_keys = keys.decrypt;
            keyring.unlocked_signing_keys = keys.signing;
        }
        keyring
    }

    fn select_store(inherited: bool) -> PasswordStore {
        if inherited {
            return PasswordStore::Inherited;
        }
        // (macOS) Prefer the Secure Enclave (Touch ID) unless disabled by env.
        // A child seeded by its parent uses the transient `Inherited` store
        // instead so it never prompts for Touch ID.
        #[cfg(all(target_os = "macos", hai_se))]
        if !secure_enclave_disabled_by_env()
            && let Some(vault) = crate::feature::macos_se::SeVault::open(se_vault_dir())
        {
            return PasswordStore::SecureEnclave(vault);
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
            PasswordStore::Inherited => {}
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
            PasswordStore::Inherited => None,
        }
    }

    /// Whether the persistent store has an entry, without a biometric prompt.
    /// `None` means unknown.
    fn has_stored_password(&self, rec_key_id: &str) -> Option<bool> {
        match &self.store {
            PasswordStore::None => Some(false),
            PasswordStore::OsKeyring => {
                // Reading is the only way to check if an entry exists. On
                // macOS this may trigger a Keychain prompt after a rebuild.
                let entry = keyring::Entry::new(KEYRING_SERVICE, rec_key_id).ok()?;
                match entry.get_password() {
                    Ok(_) => Some(true),
                    Err(keyring::Error::NoEntry) => Some(false),
                    Err(_) => None,
                }
            }
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => Some(vault.contains(rec_key_id)),
            PasswordStore::Inherited => Some(false),
        }
    }

    /// Delete password from the active persistent store
    fn delete_stored_password(&self, rec_key_id: &str) {
        match &self.store {
            PasswordStore::None => {}
            PasswordStore::OsKeyring => delete_os_keyring_entry(rec_key_id),
            #[cfg(all(target_os = "macos", hai_se))]
            PasswordStore::SecureEnclave(vault) => vault.delete(rec_key_id),
            PasswordStore::Inherited => {}
        }
    }

    /// Delete password from every persistent store it may be in.
    ///
    /// (macOS) Depending on the situation, Secure Enclave and/or the OS
    /// keyring may be used so clear both.
    fn forget_stored_password(&self, rec_key_id: &str) {
        self.delete_stored_password(rec_key_id);

        // On macOS, remove key from the alternative store.
        #[cfg(all(target_os = "macos", hai_se))]
        match &self.store {
            PasswordStore::SecureEnclave(_) => delete_os_keyring_entry(rec_key_id),
            PasswordStore::OsKeyring | PasswordStore::None => {
                crate::feature::macos_se::SeVault::for_cleanup(se_vault_dir()).delete(rec_key_id)
            }
            // Since key was inherited, parent's store is unknown -> clear both
            PasswordStore::Inherited => {
                delete_os_keyring_entry(rec_key_id);
                crate::feature::macos_se::SeVault::for_cleanup(se_vault_dir()).delete(rec_key_id)
            }
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
        self.forget_stored_password(rec_key_id);
    }

    /// Lock and forget a specific key (removes from memory AND keyring)
    pub fn forget_signing_key(&mut self, rec_key_id: &str) {
        self.unlocked_signing_keys.remove(rec_key_id);
        self.session_passwords.clear();
        self.forget_stored_password(rec_key_id);
    }

    /// Forget all keys belonging to a user.
    ///
    /// Removes keys from memory and persistent store.
    ///
    /// Limitation: OS keyrings can't be enumerated so it relies on keys
    /// unlocked in memory.
    pub fn forget_user(&mut self, username: &str) {
        let prefix =
            asset_crypt::KeyRecipient::User(username.to_string()).recipient_key_id_prefix();
        let keys: Vec<String> = self
            .unlocked_decrypt_keys
            .keys()
            .chain(self.unlocked_signing_keys.keys())
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for key_id in &keys {
            self.forget_stored_password(key_id);
        }
        // The vault can be enumerated (unlike the Keychain) so clear it by
        // prefix regardless of which store this process uses.
        #[cfg(all(target_os = "macos", hai_se))]
        crate::feature::macos_se::SeVault::for_cleanup(se_vault_dir()).delete_prefix(&prefix);
        self.unlocked_decrypt_keys
            .retain(|k, _| !k.starts_with(&prefix));
        self.unlocked_signing_keys
            .retain(|k, _| !k.starts_with(&prefix));
        // Session passwords aren't tagged by user so clear them all.
        self.session_passwords.clear();
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
            self.forget_stored_password(&key_id);
        }
        #[cfg(all(target_os = "macos", hai_se))]
        crate::feature::macos_se::SeVault::for_cleanup(se_vault_dir()).wipe();
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

//
// Parent -> child handoff of unlocked keys.
//
// A parent passes its unlocked keys to self-invoked children through an
// inherited pipe so that children (e.g. kernels) don't re-prompt (Touch ID on
// macOS) for keys the parent already unlocked. Only the fd number travels in
// the environment; the secrets only exist in the pipe buffer until the child
// reads them.
//

/// Hand off unlocked keys to self-invoked children.
const HANDOFF_ENABLED: bool = true;

/// Hand off even when `HAI_NO_SECURE_ENCLAVE` is set. It's not necessary since
/// children share the OS keyring, but done to unify approach.
const HANDOFF_WITH_NO_SECURE_ENCLAVE: bool = true;

/// Env var holding the file description number of the keyring handoff pipe.
pub const KEYRING_FD_ENV_VAR: &str = "HAI_KEYRING_FD";

const HANDOFF_MAGIC: &[u8; 4] = b"HAI!";

/// Kept well below the minimum pipe buffer (16 KiB on macOS) so the parent
/// can write the whole payload before spawning without blocking.
const HANDOFF_MAX_LEN: usize = 8 * 1024;

const HANDOFF_CHILD_FD: i32 = 3;

struct InheritedKeys {
    decrypt: HashMap<String, StaticSecret>,
    signing: HashMap<String, SigningKey>,
}

/// Keys received from the parent, consumed by the first `AssetKeyring::new`.
static INHERITED_KEYS: std::sync::Mutex<Option<InheritedKeys>> = std::sync::Mutex::new(None);

fn handoff_enabled() -> bool {
    HANDOFF_ENABLED
        && (HANDOFF_WITH_NO_SECURE_ENCLAVE
            || std::env::var_os(NO_SECURE_ENCLAVE_ENV_VAR).is_none_or(|v| v.is_empty()))
}

impl AssetKeyring {
    /// Serialize unlocked keys. `None` if there's nothing to hand off.
    ///
    /// Format: [magic]
    /// [dec_count][[id_len][id][secret]]+
    /// [sign_count][[id_len][id][secret]]+
    fn encode_handoff(&self) -> Option<Zeroizing<Vec<u8>>> {
        if self.unlocked_decrypt_keys.is_empty() && self.unlocked_signing_keys.is_empty() {
            return None;
        }
        fn put(buf: &mut Vec<u8>, id: &str, secret: &[u8; 32]) {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(secret);
        }
        // When using zeroize, preallocate vec size b/c vec growth won't be
        // handled.
        let mut buf = Zeroizing::new(Vec::with_capacity(HANDOFF_MAX_LEN));
        buf.extend_from_slice(HANDOFF_MAGIC);
        buf.extend_from_slice(&(self.unlocked_decrypt_keys.len() as u32).to_le_bytes());
        for (id, k) in &self.unlocked_decrypt_keys {
            put(&mut buf, id, &Zeroizing::new(k.to_bytes()));
        }
        buf.extend_from_slice(&(self.unlocked_signing_keys.len() as u32).to_le_bytes());
        for (id, k) in &self.unlocked_signing_keys {
            put(&mut buf, id, &Zeroizing::new(k.to_bytes()));
        }
        if buf.len() > HANDOFF_MAX_LEN {
            tracing::debug!("keyring handoff too large ({} bytes), skipping", buf.len());
            return None;
        }
        Some(buf)
    }
}

fn decode_handoff(bytes: &[u8]) -> Option<InheritedKeys> {
    fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if r.len() < n {
            return None;
        }
        let (a, b) = r.split_at(n);
        *r = b;
        Some(a)
    }
    fn read_u32(r: &mut &[u8]) -> Option<usize> {
        Some(u32::from_le_bytes(take(r, 4)?.try_into().ok()?) as usize)
    }
    fn entry(r: &mut &[u8]) -> Option<(String, Zeroizing<[u8; 32]>)> {
        let n = read_u32(r)?;
        let id = std::str::from_utf8(take(r, n)?).ok()?.to_string();
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(take(r, 32)?);
        Some((id, s))
    }

    let mut r = bytes.strip_prefix(HANDOFF_MAGIC)?;
    let mut keys = InheritedKeys {
        decrypt: HashMap::new(),
        signing: HashMap::new(),
    };
    for _ in 0..read_u32(&mut r)? {
        let (id, s) = entry(&mut r)?;
        keys.decrypt.insert(id, StaticSecret::from(*s));
    }
    for _ in 0..read_u32(&mut r)? {
        let (id, s) = entry(&mut r)?;
        keys.signing.insert(id, SigningKey::from_bytes(&s));
    }
    r.is_empty().then_some(keys)
}

/// Keeps the parent's copy of the handoff pipe's read end alive until the
/// child has been spawned. Drop it right after `spawn()`.
pub struct HandoffGuard {
    #[cfg(unix)]
    _reader: std::io::PipeReader,
}

/// Modify tokio Command to setup child to inherit this process's unlocked
/// keys via the handoff pipe.
pub async fn attach_handoff(
    cmd: &mut tokio::process::Command,
    keyring: &tokio::sync::Mutex<AssetKeyring>,
) -> Option<HandoffGuard> {
    if !handoff_enabled() {
        return None;
    }
    let payload = keyring.lock().await.encode_handoff()?;
    #[cfg(unix)]
    match attach_handoff_fd(cmd, &payload) {
        Ok(reader) => return Some(HandoffGuard { _reader: reader }),
        Err(e) => tracing::debug!("error: failed to set up keyring handoff: {}", e),
    }
    #[cfg(not(unix))]
    let _ = (cmd, payload);
    None
}

#[cfg(unix)]
fn attach_handoff_fd(
    cmd: &mut tokio::process::Command,
    payload: &[u8],
) -> std::io::Result<std::io::PipeReader> {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // Both ends are CLOEXEC, so concurrently spawned processes never see them.
    let (reader, mut writer) = std::io::pipe()?;
    // The payload fits in the pipe buffer (max was defined conservatively), so
    // this won't block.
    writer.write_all(payload)?;
    // Send EOF
    drop(writer);

    let src = reader.as_raw_fd();
    cmd.env(KEYRING_FD_ENV_VAR, HANDOFF_CHILD_FD.to_string());
    // SAFETY: only async-signal-safe calls (fcntl, dup2) in the closure.
    unsafe {
        cmd.pre_exec(move || {
            if src == HANDOFF_CHILD_FD {
                // dup2(fd, fd) is a no-op that would leave CLOEXEC set.
                let flags = libc::fcntl(src, libc::F_GETFD);
                if flags < 0 || libc::fcntl(src, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(src, HANDOFF_CHILD_FD) < 0 {
                // dup2'd fds have CLOEXEC cleared.
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(reader)
}

/// Child process side: read keys handed off by the parent.
///
/// WARN: Call at the start of the child process's main function to consume.
pub fn init_inherited_keys() {
    let Some(fd) = std::env::var_os(KEYRING_FD_ENV_VAR) else {
        return;
    };
    // Remove the env var so grandchildren don't try to use it.
    unsafe { std::env::remove_var(KEYRING_FD_ENV_VAR) };
    #[cfg(unix)]
    {
        let keys = fd
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .and_then(read_handoff_fd)
            .and_then(|bytes| decode_handoff(&bytes));
        match keys {
            Some(keys) => {
                if let Ok(mut g) = INHERITED_KEYS.lock() {
                    *g = Some(keys);
                }
            }
            None => tracing::debug!("error: invalid keyring handoff from parent"),
        }
    }
    #[cfg(not(unix))]
    let _ = fd;
}

#[cfg(unix)]
fn read_handoff_fd(fd: i32) -> Option<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    if fd < 3 {
        return None;
    }
    // Only take ownership (and later close) the fd if it's really a pipe.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFIFO {
        return None;
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    // Preallocated (+1 to detect overflow) so reads never realloc.
    let mut buf = Zeroizing::new(Vec::with_capacity(HANDOFF_MAX_LEN + 1));
    file.take(HANDOFF_MAX_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .ok()?;
    // `file` dropped here: fd closed.
    (buf.len() <= HANDOFF_MAX_LEN).then_some(buf)
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
    fn test_handoff_roundtrip() {
        let mut kr = AssetKeyring::new(false);
        kr.unlocked_decrypt_keys
            .insert("u:ken:k1".into(), StaticSecret::from([7u8; 32]));
        kr.unlocked_signing_keys
            .insert("u:ken:k1".into(), SigningKey::from_bytes(&[9u8; 32]));
        let bytes = kr.encode_handoff().expect("payload");
        let keys = decode_handoff(&bytes).expect("decode");
        assert_eq!(keys.decrypt["u:ken:k1"].to_bytes(), [7u8; 32]);
        assert_eq!(keys.signing["u:ken:k1"].to_bytes(), [9u8; 32]);
        // Truncated / trailing garbage is rejected.
        assert!(decode_handoff(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(decode_handoff(&extra).is_none());
        // Nothing to hand off.
        assert!(AssetKeyring::new(false).encode_handoff().is_none());
    }

    #[test]
    fn test_lock_operations() {
        let mut keyring = AssetKeyring::new(true);
        keyring.lock_all();
        keyring.lock_decrypt_key("nonexistent");
        // Should not panic
    }
}
