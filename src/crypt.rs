//! This module provides cryptographic utilities including key generation,
//! encryption/decryption, and signing/verification.
//!
//! It uses X25519 for key exchange, Ed25519 for digital signatures, and
//! AES-GCM for symmetric encryption.
//!
//! It includes password-based protection for secret keys using Argon2id and
//! AES-GCM.
//!
//! It also includes recovery code functionality for key recovery.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::Argon2;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    #[allow(dead_code)]
    SignatureInvalid,
    InvalidKeyLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::InvalidFormat => write!(f, "invalid data format"),
            CryptoError::SignatureInvalid => write!(f, "signature verification failed"),
            CryptoError::InvalidKeyLength => write!(f, "invalid key length"),
        }
    }
}

impl std::error::Error for CryptoError {}

//
// Key Types
//

/// A bundle of X25519 encryption and Ed25519 signing keys.
pub struct KeyBundle {
    /// X25519 encryption secret key
    pub encryption_secret: StaticSecret,

    /// X25519 encryption public key
    pub encryption_public: PublicKey,

    /// Ed25519 signing key
    pub signing_key: SigningKey,

    /// Ed25519 verifying key
    pub verifying_key: VerifyingKey,
}

/// 256-bit AES key
#[derive(Clone, Debug)]
pub struct AesKey([u8; 32]);

impl AesKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(AesKey(key))
    }
}

/// Encrypted AES key using X25519-ECDH + HKDF + AES-256-GCM.
///
/// This structure contains the components needed to decrypt an AES key that was
/// encrypted using a hybrid encryption scheme combining:
/// - **X25519** elliptic curve Diffie-Hellman for key agreement
/// - **HKDF-SHA256** for key derivation with context "aes-key-wrap"
/// - **AES-256-GCM** for authenticated encryption of the AES key
///
/// # Encryption Process
///
/// 1. Generate ephemeral X25519 keypair
/// 2. Perform ECDH: `shared_secret = ephemeral_secret * recipient_public`
/// 3. Derive encryption key: `HKDF-SHA256(shared_secret, info="aes-key-wrap")`
/// 4. Encrypt AES key with AES-256-GCM using derived key and random nonce
/// 5. Package ephemeral public key, nonce, and ciphertext for transmission
///
/// # Decryption Process
///
/// 1. Perform ECDH: `shared_secret = recipient_secret * ephemeral_public`
/// 2. Derive same encryption key using HKDF with "aes-key-wrap" context
/// 3. Decrypt ciphertext with AES-256-GCM to recover original AES key
///
/// # Security Properties
///
/// - **Forward secrecy**: Each encryption uses a fresh ephemeral key
/// - **Authenticated encryption**: AES-GCM provides confidentiality and integrity
/// - **Key derivation**: HKDF ensures proper key material expansion
///
/// # Wire Format
///
/// When serialized via `to_bytes()`:
/// ```text
/// [ephemeral_public (32 bytes)][nonce (12 bytes)][ciphertext (AES key + 16-byte auth tag)]
/// ```
/// Typical total size: 44 + key_size + 16 bytes (e.g., 92 bytes for 32-byte AES key)
///
/// # Example
///
/// ```ignore
/// // Encryption
/// let encrypted = encrypt_aes_key(&aes_key, &recipient_public)?;
/// let hex = encrypted.to_hex();
///
/// // Decryption
/// let encrypted = EncryptedAesKey::from_hex(&hex)?;
/// let aes_key = decrypt_aes_key(&encrypted, &recipient_secret)?;
/// ```
pub struct EncryptedAesKey {
    /// Ephemeral X25519 public key (32 bytes) generated during encryption.
    /// Used by recipient to derive the shared secret via ECDH.
    pub ephemeral_public: [u8; 32],

    /// AES-GCM nonce (12 bytes) - randomly generated for each encryption.
    /// Must be unique for each message encrypted with the same derived key.
    pub nonce: [u8; 12],

    /// AES-256-GCM ciphertext containing the encrypted AES key plus 16-byte
    /// authentication tag. For a 32-byte AES-256 key, this will be 48 bytes
    /// (32 + 16).
    pub ciphertext: Vec<u8>,
}

impl EncryptedAesKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 12 + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Format encrypted-aes key as hex string (e.g., "8f3a2b7c")
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 44 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut ephemeral_public = [0u8; 32];
        let mut nonce = [0u8; 12];
        ephemeral_public.copy_from_slice(&bytes[0..32]);
        nonce.copy_from_slice(&bytes[32..44]);
        let ciphertext = bytes[44..].to_vec();
        Ok(Self {
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidFormat)?;
        Self::from_bytes(&bytes)
    }
}

/// Content encrypted with AES-256-GCM using a symmetric key.
///
/// This structure contains the components needed to decrypt content that was
/// encrypted with AES-256-GCM authenticated encryption. Unlike [`EncryptedAesKey`],
/// this uses a pre-shared or previously exchanged AES key directly (no ECDH).
///
/// # Structure
///
/// - **Nonce**: 12-byte random value ensuring unique encryption for each message
/// - **Ciphertext**: Encrypted content plus 16-byte authentication tag
///
/// # Encryption Scheme
///
/// Uses **AES-256-GCM** (Galois/Counter Mode) which provides:
/// - **Confidentiality**: Content is encrypted and unreadable without the key
/// - **Integrity**: Authentication tag prevents tampering
/// - **Authenticity**: Verifies the ciphertext hasn't been modified
///
/// # Wire Format
///
/// When serialized via `to_bytes()`:
/// ```text
/// [nonce (12 bytes)][ciphertext (content + 16-byte auth tag)]
/// ```
/// Minimum size: 28 bytes (12-byte nonce + 16-byte tag for empty content)
///
pub struct EncryptedContent {
    /// AES-GCM nonce (12 bytes) - must be unique for each encryption with the same key.
    /// Randomly generated using a cryptographically secure RNG (e.g., `OsRng`).
    pub nonce: [u8; 12],

    /// AES-256-GCM ciphertext containing the encrypted content plus 16-byte authentication tag.
    /// Size = plaintext_length + 16 bytes.
    pub ciphertext: Vec<u8>,
}

impl EncryptedContent {
    /// Serializes the encrypted content to bytes in the format: `[nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// A byte vector containing the nonce followed by ciphertext (minimum 28 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserializes encrypted content from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice containing `[nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// * `Ok(EncryptedContent)` - Successfully parsed encrypted content
    /// * `Err(CryptoError::InvalidFormat)` - If bytes are too short (< 12 bytes)
    ///
    /// # Format
    ///
    /// Expects at least 12 bytes:
    /// - Bytes 0-11: Nonce
    /// - Bytes 12+: Ciphertext (including 16-byte auth tag)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 12 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[0..12]);
        let ciphertext = bytes[12..].to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

//
// Key Generation
//

/// Generates a complete cryptographic key bundle for a user or entity.
///
/// Creates both encryption and signing keypairs needed for secure communication:
/// - **X25519 keypair**: For ECDH key agreement and receiving encrypted AES keys
/// - **Ed25519 keypair**: For creating and verifying digital signatures
///
/// # Returns
///
/// A [`KeyBundle`] containing:
/// - `encryption_secret`: X25519 private key (keep secret!)
/// - `encryption_public`: X25519 public key (share with others)
/// - `signing_key`: Ed25519 private signing key (keep secret!)
/// - `verifying_key`: Ed25519 public verification key (share with others)
///
/// # Security
///
/// - Uses `OsRng` (operating system random number generator) for cryptographically
///   secure randomness
/// - Private keys (`encryption_secret`, `signing_key`) must be kept confidential
/// - Public keys can be freely distributed
///
/// # Example
///
/// ```ignore
/// let bundle = generate_key_bundle();
///
/// // Share public keys with others
/// let public_keys = (bundle.encryption_public, bundle.verifying_key);
///
/// // Keep private keys secure
/// securely_store(&bundle.encryption_secret);
/// securely_store(&bundle.signing_key);
/// ```
///
/// # Typical Workflow
///
/// 1. **Key Generation**: Call this function once per user/entity
/// 2. **Key Distribution**: Publish public keys to a directory or exchange directly
/// 3. **Encryption**: Others use `encryption_public` to encrypt AES keys for you
/// 4. **Decryption**: Use `encryption_secret` to decrypt received messages
/// 5. **Signing**: Use `signing_key` to sign messages you send
/// 6. **Verification**: Others use `verifying_key` to verify your signatures
pub fn generate_key_bundle() -> KeyBundle {
    let encryption_secret = StaticSecret::random_from_rng(OsRng);
    let encryption_public = PublicKey::from(&encryption_secret);

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    KeyBundle {
        encryption_secret,
        encryption_public,
        signing_key,
        verifying_key,
    }
}

/// Generates a random 256-bit AES key for symmetric encryption.
///
/// Creates a cryptographically secure random AES-256 key suitable for use with
/// AES-GCM authenticated encryption. This key is used to encrypt content. It
/// can then be encrypted using [`encrypt_aes_key`].
///
/// # Returns
///
/// An [`AesKey`] containing 32 random bytes (256 bits)
///
/// # Security
///
/// - Uses `OsRng` for cryptographically secure randomness
pub fn generate_aes_key() -> AesKey {
    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    AesKey(key)
}

//
// AES Key Encryption/Decryption
//

/// Encrypts an AES key using ECIES (X25519 + HKDF +AES-256-GCM).
///
/// This implements a hybrid encryption scheme to encrypt an AES key for a
/// recipient using their X25519 public key. The encrypted key can only be
/// decrypted by the corresponding private key.
///
/// # Algorithm
///
/// 1. **Generate ephemeral keypair**: Create a temporary X25519 keypair
/// 2. **ECDH key agreement**: Compute shared secret = `ephemeral_secret * recipient_public`
/// 3. **Key derivation**: Derive AES-256 key using HKDF-SHA256 with context "aes-key-wrap"
/// 4. **Encrypt**: Use AES-256-GCM with random nonce to encrypt the AES key
/// 5. **Package**: Return ephemeral public key, nonce, and ciphertext
///
/// # Arguments
///
/// * `aes_key` - The AES-256 key to encrypt (typically from [`generate_aes_key`])
/// * `recipient_public` - The recipient's X25519 public key (from their [`KeyBundle`])
///
/// # Returns
///
/// * `Ok(EncryptedAesKey)` - Successfully encrypted key with all components needed for decryption
/// * `Err(CryptoError::EncryptionFailed)` - If encryption fails (extremely rare)
///
/// # Technical Details
///
/// - **Curve**: X25519 (Curve25519 for ECDH)
/// - **KDF**: HKDF-SHA256 with info string "aes-key-wrap"
/// - **Cipher**: AES-256-GCM with 12-byte random nonce
/// - **Output size**: 92 bytes (32 ephemeral_public + 12 nonce + 32 key + 16 tag)
pub fn encrypt_aes_key(
    aes_key: &AesKey,
    recipient_public: &PublicKey,
) -> Result<EncryptedAesKey, CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(b"aes-key-wrap", &mut derived_key)
        .expect("32 bytes is valid for HKDF");

    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_key.as_bytes().as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedAesKey {
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts an AES key that was encrypted using [`encrypt_aes_key`].
///
/// Uses the recipient's X25519 private key to decrypt an AES key that was encrypted
/// for them. This is the decryption counterpart to [`encrypt_aes_key`] and implements
/// the same ECIES scheme.
///
/// # Algorithm
///
/// 1. **Extract ephemeral public key**: From the encrypted package
/// 2. **ECDH key agreement**: Compute shared secret = `recipient_secret * ephemeral_public`
/// 3. **Key derivation**: Derive same AES-256 key using HKDF-SHA256 with "aes-key-wrap"
/// 4. **Decrypt**: Use AES-256-GCM to decrypt and verify the ciphertext
/// 5. **Return**: The original AES key
///
/// # Arguments
///
/// * `encrypted` - The encrypted AES key package (from [`encrypt_aes_key`])
/// * `recipient_secret` - The recipient's X25519 private key (from their [`KeyBundle`])
///
/// # Returns
///
/// * `Ok(AesKey)` - Successfully decrypted AES key
/// * `Err(CryptoError::DecryptionFailed)` - If decryption fails (wrong key, corrupted data, or tampering)
///
/// # Security
///
/// - **Authentication**: AES-GCM verifies the ciphertext hasn't been tampered with
/// - **Key verification**: Decryption only succeeds if the correct private key is used
/// - **Integrity**: Any modification to the encrypted data will cause decryption to fail
///
/// # Error Handling
///
/// Decryption can fail for several reasons:
/// - Wrong recipient (using incorrect private key)
/// - Corrupted or modified ciphertext
/// - Invalid encrypted key format
/// - Network transmission errors
///
/// All failures return `CryptoError::DecryptionFailed`.
///
pub fn decrypt_aes_key(
    encrypted: &EncryptedAesKey,
    recipient_secret: &StaticSecret,
) -> Result<AesKey, CryptoError> {
    let ephemeral_public = PublicKey::from(encrypted.ephemeral_public);
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(b"aes-key-wrap", &mut derived_key)
        .expect("32 bytes is valid for HKDF");

    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(AesKey::from_bytes(&plaintext)?)
}

//
// Content Encryption/Decryption
//

/// Encrypts arbitrary content using AES-256-GCM with a symmetric key.
///
/// Performs authenticated encryption of plaintext data using AES-256 in Galois/Counter Mode.
/// This provides both confidentiality (encryption) and integrity/authenticity (authentication tag).
///
/// # Algorithm
///
/// 1. **Initialize cipher**: Create AES-256-GCM cipher from the provided key
/// 2. **Generate nonce**: Create a random 12-byte nonce using `OsRng`
/// 3. **Encrypt**: Perform AES-GCM encryption, producing ciphertext + 16-byte auth tag
/// 4. **Package**: Return nonce and ciphertext together
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt (can be any length, including empty)
/// * `key` - The AES-256 key to use for encryption (typically from [`generate_aes_key`])
///
/// # Returns
///
/// * `Ok(EncryptedContent)` - Successfully encrypted content with nonce and ciphertext
/// * `Err(CryptoError::EncryptionFailed)` - If encryption fails (extremely rare)
///
/// # Output Size
///
/// The encrypted output is `plaintext.len() + 16` bytes (plus 12-byte nonce):
/// - **Nonce**: 12 bytes (stored separately in [`EncryptedContent`])
/// - **Ciphertext**: Same length as plaintext
/// - **Auth tag**: 16 bytes (appended to ciphertext)
///
/// # Performance
///
/// AES-GCM is highly efficient for bulk data encryption:
/// - Hardware acceleration available on most modern CPUs (AES-NI)
/// - Suitable for encrypting large messages, files, or streams
/// - Much faster than public-key encryption (hence hybrid encryption)
///
pub fn encrypt_content(plaintext: &[u8], key: &AesKey) -> Result<EncryptedContent, CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedContent {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts content that was encrypted using [`encrypt_content`].
///
/// Performs authenticated decryption of AES-256-GCM encrypted data. Automatically
/// verifies the authentication tag to ensure the ciphertext hasn't been tampered with.
///
/// # Algorithm
///
/// 1. **Initialize cipher**: Create AES-256-GCM cipher from the provided key
/// 2. **Extract nonce**: Use the nonce from the encrypted package
/// 3. **Decrypt & verify**: Decrypt ciphertext and verify the 16-byte authentication tag
/// 4. **Return**: The original plaintext if verification succeeds
///
/// # Arguments
///
/// * `encrypted` - The encrypted content package (from [`encrypt_content`])
/// * `key` - The AES-256 key used for encryption
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Successfully decrypted plaintext
/// * `Err(CryptoError::DecryptionFailed)` - If decryption or authentication fails
///
/// # Security
///
/// - **Authentication first**: AES-GCM verifies the auth tag before returning plaintext
/// - **Tamper detection**: Any modification to the ciphertext causes decryption to fail
/// - **All-or-nothing**: Either complete success or complete failure (no partial decryption)
///
/// # Error Handling
///
/// Decryption fails and returns `CryptoError::DecryptionFailed` if:
/// - **Wrong key**: The AES key doesn't match the one used for encryption
/// - **Corrupted data**: The ciphertext or nonce was modified or corrupted
/// - **Tampering**: Someone altered the encrypted data
/// - **Invalid format**: The ciphertext is malformed
pub fn decrypt_content(encrypted: &EncryptedContent, key: &AesKey) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

//
// Signing & Verification
//

#[allow(dead_code)]
/// Creates a digital signature for data using Ed25519.
///
/// Generates a cryptographic signature that proves the data was signed by the holder
/// of the private signing key. The signature can be verified by anyone with the
/// corresponding public verifying key.
///
/// # Algorithm
///
/// Uses **Ed25519** (Edwards-curve Digital Signature Algorithm):
/// - Deterministic signature generation (same data + key = same signature)
/// - 64-byte signatures
///
/// # Arguments
///
/// * `data` - The data to sign (can be any length)
/// * `signing_key` - The Ed25519 private signing key (from [`KeyBundle`])
///
/// # Returns
///
/// A 64-byte Ed25519 [`Signature`] that can be verified with the corresponding public key
pub fn sign(data: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(data)
}

#[allow(dead_code)]
/// Verifies an Ed25519 signature on data.
///
/// Checks whether a signature is valid for the given data and public verifying key.
/// This proves that the data was signed by the holder of the corresponding private
/// signing key and that the data hasn't been modified since signing.
///
/// # Algorithm
///
/// Uses **Ed25519** signature verification:
/// - Constant-time verification (resistant to timing attacks)
/// - Detects any tampering with data or signature
///
/// # Arguments
///
/// * `data` - The data that was signed (must be identical to what was signed)
/// * `signature` - The signature to verify (from [`sign`])
/// * `verifying_key` - The Ed25519 public key of the signer (from their [`KeyBundle`])
///
/// # Returns
///
/// * `Ok(())` - Signature is valid; data is authentic and unmodified
/// * `Err(CryptoError::SignatureInvalid)` - Signature verification failed
///
/// # Verification Failures
///
/// Verification fails if:
/// - **Wrong key**: The verifying key doesn't match the signing key
/// - **Modified data**: The data was altered after signing
/// - **Modified signature**: The signature bytes were corrupted or tampered with
/// - **Wrong data**: Verifying different data than what was signed
pub fn verify(
    data: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(data, signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

//
// Key Serialization (for storage)
//

impl KeyBundle {
    /// Exports only the public keys from this key bundle.
    ///
    /// Extracts the public portions of the keypairs (encryption public key and
    /// verifying key) into a serializable format. These keys are safe to share
    /// publicly.
    ///
    /// # Returns
    ///
    /// A [`PublicKeyBundle`] containing:
    /// - `encryption_public`: 32-byte X25519 public key (for receiving encrypted messages)
    /// - `verifying_key`: 32-byte Ed25519 public key (for signature verification)
    pub fn export_public(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            encryption_public: self.encryption_public.to_bytes(),
            verifying_key: self.verifying_key.to_bytes(),
        }
    }

    #[allow(dead_code)]
    /// Exports the private keys from this key bundle for secure storage.
    ///
    /// Extracts the secret portions of the keypairs (encryption private key and
    /// signing key) into a serializable format. **These keys must be kept secret
    /// and stored securely** as they allow decryption of messages and creation
    /// of signatures on your behalf.
    ///
    /// # Returns
    ///
    /// A [`SecretKeyBundle`] containing:
    /// - `encryption_secret`: 32-byte X25519 private key (for decrypting messages)
    /// - `signing_key`: 32-byte Ed25519 private key (for creating signatures)
    pub fn export_secret(&self) -> SecretKeyBundle {
        SecretKeyBundle {
            encryption_secret: self.encryption_secret.as_bytes().to_owned(),
            signing_key: self.signing_key.to_bytes(),
        }
    }

    #[allow(dead_code)]
    /// Reconstructs a complete key bundle from exported public and secret keys.
    pub fn from_exported(
        public: &PublicKeyBundle,
        secret: &SecretKeyBundle,
    ) -> Result<Self, CryptoError> {
        let encryption_secret = StaticSecret::from(secret.encryption_secret);
        let encryption_public = PublicKey::from(public.encryption_public);

        let signing_key = SigningKey::from_bytes(&secret.signing_key);
        let verifying_key = VerifyingKey::from_bytes(&public.verifying_key)
            .map_err(|_| CryptoError::InvalidFormat)?;

        Ok(KeyBundle {
            encryption_secret,
            encryption_public,
            signing_key,
            verifying_key,
        })
    }
}

#[derive(Clone)]
pub struct PublicKeyBundle {
    pub encryption_public: [u8; 32],
    pub verifying_key: [u8; 32],
}

impl PublicKeyBundle {
    #[allow(dead_code)]
    /// Get the key ID for the encryption key
    pub fn encryption_key_id(&self) -> [u8; 4] {
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&self.encryption_public[0..4]);
        key_id
    }

    #[allow(dead_code)]
    /// Get the key ID for the signing key
    pub fn signing_key_id(&self) -> [u8; 4] {
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&self.verifying_key[0..4]);
        key_id
    }
}

#[derive(Clone)]
pub struct SecretKeyBundle {
    pub encryption_secret: [u8; 32],
    pub signing_key: [u8; 32],
}

//
// Encrypted Key Types
//

/// Password-protected X25519 encryption secret key.
///
/// Stores an X25519 private key encrypted with a password-derived key using
/// Argon2id + AES-256-GCM. This allows secure storage of the encryption secret
/// key on disk or in databases without exposing the raw key material.
///
/// # Structure
///
/// - **Salt** (16 bytes): Random salt for Argon2id key derivation
/// - **Nonce** (12 bytes): Random nonce for AES-256-GCM encryption
/// - **Ciphertext** (48 bytes): Encrypted 32-byte key + 16-byte authentication tag
///
/// # Encryption Scheme
///
/// 1. Generate random 16-byte salt
/// 2. Derive 32-byte key from password using Argon2id with salt
/// 3. Generate random 12-byte nonce
/// 4. Encrypt the X25519 secret key with AES-256-GCM
/// 5. Store salt, nonce, and ciphertext together
///
/// # Security Properties
///
/// - **Password-based**: Protected by user's password strength
/// - **Key derivation**: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
/// - **Authenticated encryption**: AES-256-GCM prevents tampering
/// - **Unique salt**: Each encryption uses a fresh random salt
/// - **Brute-force resistant**: Argon2id makes password guessing expensive
///
/// # Wire Format
///
/// When serialized via `to_bytes()`:
/// ```text
/// [salt (16 bytes)][nonce (12 bytes)][ciphertext (32 + 16 = 48 bytes)]
/// Total: 76 bytes
/// ```
pub struct EncryptedEncryptionKey {
    /// Random 16-byte salt for Argon2id key derivation.
    /// Must be unique for each encryption to prevent rainbow table attacks.
    pub salt: [u8; 16],

    /// Random 12-byte nonce for AES-256-GCM encryption.
    /// Must be unique for each encryption with the same derived key.
    pub nonce: [u8; 12],

    /// AES-256-GCM ciphertext containing the encrypted X25519 secret key (32 bytes)
    /// plus authentication tag (16 bytes). Total: 48 bytes.
    pub ciphertext: Vec<u8>,
}

impl EncryptedEncryptionKey {
    /// Serializes the encrypted key to bytes: `[salt || nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// A 76-byte vector (16 + 12 + 48) containing all encryption components
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 12 + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserializes an encrypted key from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice containing `[salt || nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// * `Ok(EncryptedEncryptionKey)` - Successfully parsed encrypted key
    /// * `Err(CryptoError::InvalidFormat)` - If bytes are too short (< 76 bytes)
    ///
    /// # Format
    ///
    /// Expects at least 76 bytes:
    /// - Bytes 0-15: Salt (16 bytes)
    /// - Bytes 16-27: Nonce (12 bytes)
    /// - Bytes 28-75: Ciphertext (48 bytes: 32-byte key + 16-byte tag)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 76 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        salt.copy_from_slice(&bytes[0..16]);
        nonce.copy_from_slice(&bytes[16..28]);
        let ciphertext = bytes[28..].to_vec();
        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Password-protected Ed25519 signing key.
///
/// Stores an Ed25519 private signing key encrypted with a password-derived key
/// using Argon2id + AES-256-GCM. This allows secure storage of the signing key
/// on disk or in databases without exposing the raw key material.
///
/// # Structure
///
/// - **Salt** (16 bytes): Random salt for Argon2id key derivation
/// - **Nonce** (12 bytes): Random nonce for AES-256-GCM encryption
/// - **Ciphertext** (48 bytes): Encrypted 32-byte key + 16-byte authentication tag
///
/// # Encryption Scheme
///
/// Identical to [`EncryptedEncryptionKey`] but protects the Ed25519 signing key:
/// 1. Generate random 16-byte salt
/// 2. Derive 32-byte key from password using Argon2id with salt
/// 3. Generate random 12-byte nonce
/// 4. Encrypt the Ed25519 signing key with AES-256-GCM
/// 5. Store salt, nonce, and ciphertext together
///
/// # Security Properties
///
/// - **Password-based**: Protected by user's password strength
/// - **Key derivation**: Argon2id (memory-hard, GPU/ASIC resistant)
/// - **Authenticated encryption**: AES-256-GCM prevents tampering
/// - **Unique salt**: Each encryption uses a fresh random salt
/// - **Critical protection**: Signing key compromise allows impersonation
///
/// # Wire Format
///
/// When serialized via `to_bytes()`:
/// ```text
/// [salt (16 bytes)][nonce (12 bytes)][ciphertext (32 + 16 = 48 bytes)]
/// Total: 76 bytes
/// ```
///
pub struct EncryptedSigningKey {
    /// Random 16-byte salt for Argon2id key derivation.
    /// Must be unique for each encryption to prevent rainbow table attacks.
    pub salt: [u8; 16],

    /// Random 12-byte nonce for AES-256-GCM encryption.
    /// Must be unique for each encryption with the same derived key.
    pub nonce: [u8; 12],

    /// AES-256-GCM ciphertext containing the encrypted Ed25519 signing key (32 bytes)
    /// plus authentication tag (16 bytes). Total: 48 bytes.
    pub ciphertext: Vec<u8>,
}

impl EncryptedSigningKey {
    /// Serializes the encrypted key to bytes: `[salt || nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// A 76-byte vector (16 + 12 + 48) containing all encryption components
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 12 + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    #[allow(dead_code)]
    /// Deserializes an encrypted key from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice containing `[salt || nonce || ciphertext]`
    ///
    /// # Returns
    ///
    /// * `Ok(EncryptedEncryptionKey)` - Successfully parsed encrypted key
    /// * `Err(CryptoError::InvalidFormat)` - If bytes are too short (< 76 bytes)
    ///
    /// # Format
    ///
    /// Expects at least 76 bytes:
    /// - Bytes 0-15: Salt (16 bytes)
    /// - Bytes 16-27: Nonce (12 bytes)
    /// - Bytes 28-75: Ciphertext (48 bytes: 32-byte key + 16-byte tag)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 76 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        salt.copy_from_slice(&bytes[0..16]);
        nonce.copy_from_slice(&bytes[16..28]);
        let ciphertext = bytes[28..].to_vec();
        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Derives a 256-bit encryption key from a password using Argon2id.
///
/// Uses the Argon2id key derivation function to convert a password into a
/// cryptographic key suitable for AES-256 encryption. Argon2id is memory-hard
/// and resistant to GPU/ASIC-based brute-force attacks.
///
/// # Algorithm
///
/// - **KDF**: Argon2id (winner of Password Hashing Competition)
/// - **Parameters**: Default Argon2 settings (balanced security/performance)
/// - **Output**: 32 bytes (256 bits) for AES-256
///
/// # Arguments
///
/// * `password` - The password bytes (UTF-8 encoded string recommended)
/// * `salt` - 16-byte random salt (must be unique per encryption)
///
/// # Returns
///
/// A 32-byte key derived from the password and salt
///
/// # Security Properties
///
/// - **Memory-hard**: Requires significant RAM, making GPU attacks expensive
/// - **Time-hard**: Configurable time cost (default is balanced)
/// - **Side-channel resistant**: Designed to resist timing attacks
/// - **Salted**: Salt prevents rainbow table and parallel attacks
///
/// # Panics
///
/// Panics if Argon2 hashing fails (extremely rare, only on invalid parameters)
///
fn derive_key_from_password(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .expect("Argon2 hashing failed");
    key
}

//
// Protect / unprotect functions
//

/// Encrypts an X25519 encryption secret key with a password for secure storage.
///
/// Protects the X25519 private key using password-based encryption (Argon2id + AES-256-GCM).
/// This allows storing the key on disk or in a database without exposing the raw key material.
/// The encrypted key can only be recovered with the correct password.
///
/// # Algorithm
///
/// 1. Generate random 16-byte salt
/// 2. Derive 256-bit key from password using Argon2id
/// 3. Generate random 12-byte nonce
/// 4. Encrypt the 32-byte X25519 secret with AES-256-GCM
/// 5. Return salt, nonce, and ciphertext (76 bytes total)
///
/// # Arguments
///
/// * `secret` - The X25519 private key to protect (from [`KeyBundle`])
/// * `password` - The password bytes (UTF-8 encoded string recommended)
///
/// # Returns
///
/// * `Ok(EncryptedEncryptionKey)` - Password-protected key ready for storage
/// * `Err(CryptoError::EncryptionFailed)` - If encryption fails (extremely rare)
///
pub fn protect_encryption_key(
    secret: &StaticSecret,
    password: &[u8],
) -> Result<EncryptedEncryptionKey, CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let derived_key = derive_key_from_password(password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret.as_bytes().as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedEncryptionKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts a password-protected X25519 encryption secret key.
///
/// Recovers the X25519 private key from password-protected storage. This is the
/// decryption counterpart to [`protect_encryption_key`] and requires the same
/// password that was used for encryption.
///
/// # Algorithm
///
/// 1. Extract salt from encrypted key
/// 2. Derive 256-bit key from password using Argon2id with same salt
/// 3. Decrypt ciphertext with AES-256-GCM using stored nonce
/// 4. Verify authentication tag (automatic in AES-GCM)
/// 5. Reconstruct X25519 secret key from decrypted bytes
///
/// # Arguments
///
/// * `encrypted` - The password-protected key (from [`protect_encryption_key`])
/// * `password` - The password bytes (must match encryption password)
///
/// # Returns
///
/// * `Ok(StaticSecret)` - Successfully recovered X25519 private key
/// * `Err(CryptoError::DecryptionFailed)` - Wrong password or corrupted data
/// * `Err(CryptoError::InvalidKeyLength)` - Decrypted data is not 32 bytes
pub fn unprotect_encryption_key(
    encrypted: &EncryptedEncryptionKey,
    password: &[u8],
) -> Result<StaticSecret, CryptoError> {
    let derived_key = derive_key_from_password(password, &encrypted.salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(StaticSecret::from(key_bytes))
}

/// Encrypts an Ed25519 signing key with a password for secure storage.
///
/// Protects the Ed25519 private signing key using password-based encryption
/// (Argon2id + AES-256-GCM). This allows storing the key securely on disk or
/// in a database. The encrypted key can only be recovered with the correct password.
///
/// # Algorithm
///
/// 1. Generate random 16-byte salt
/// 2. Derive 256-bit key from password using Argon2id
/// 3. Generate random 12-byte nonce
/// 4. Encrypt the 32-byte Ed25519 signing key with AES-256-GCM
/// 5. Return salt, nonce, and ciphertext (76 bytes total)
///
/// # Arguments
///
/// * `signing_key` - The Ed25519 private signing key to protect (from [`KeyBundle`])
/// * `password` - The password bytes (UTF-8 encoded string recommended)
///
/// # Returns
///
/// * `Ok(EncryptedSigningKey)` - Password-protected key ready for storage
/// * `Err(CryptoError::EncryptionFailed)` - If encryption fails (extremely rare)
pub fn protect_signing_key(
    signing_key: &SigningKey,
    password: &[u8],
) -> Result<EncryptedSigningKey, CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let derived_key = derive_key_from_password(password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, signing_key.to_bytes().as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedSigningKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

#[allow(dead_code)]
/// Decrypts a password-protected Ed25519 signing key.
///
/// Recovers the Ed25519 private signing key from password-protected storage.
/// This is the decryption counterpart to [`protect_signing_key`] and requires
/// the same password that was used for encryption.
///
/// # Algorithm
///
/// 1. Extract salt from encrypted key
/// 2. Derive 256-bit key from password using Argon2id with same salt
/// 3. Decrypt ciphertext with AES-256-GCM using stored nonce
/// 4. Verify authentication tag (automatic in AES-GCM)
/// 5. Reconstruct Ed25519 signing key from decrypted bytes
///
/// # Arguments
///
/// * `encrypted` - The password-protected key (from [`protect_signing_key`])
/// * `password` - The password bytes (must match encryption password)
///
/// # Returns
///
/// * `Ok(SigningKey)` - Successfully recovered Ed25519 private signing key
/// * `Err(CryptoError::DecryptionFailed)` - Wrong password or corrupted data
/// * `Err(CryptoError::InvalidKeyLength)` - Decrypted data is not 32 bytes
pub fn unprotect_signing_key(
    encrypted: &EncryptedSigningKey,
    password: &[u8],
) -> Result<SigningKey, CryptoError> {
    let derived_key = derive_key_from_password(password, &encrypted.salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(SigningKey::from_bytes(&key_bytes))
}

//
// Additional KeyBundle convenience functions
//

impl KeyBundle {
    /// Exports the encryption secret key with password protection.
    ///
    /// Convenience method that wraps [`protect_encryption_key`] for direct use on a [`KeyBundle`].
    ///
    /// # Arguments
    ///
    /// * `password` - Password bytes for encryption
    ///
    /// # Returns
    ///
    /// Password-protected encryption key ready for storage (76 bytes serialized)
    pub fn export_encryption_secret_protected(
        &self,
        password: &[u8],
    ) -> Result<EncryptedEncryptionKey, CryptoError> {
        protect_encryption_key(&self.encryption_secret, password)
    }

    /// Exports the signing key with password protection.
    ///
    /// Convenience method that wraps [`protect_signing_key`] for direct use on a [`KeyBundle`].
    ///
    /// # Arguments
    ///
    /// * `password` - Password bytes for encryption
    ///
    /// # Returns
    ///
    /// Password-protected signing key ready for storage (76 bytes serialized)
    pub fn export_signing_key_protected(
        &self,
        password: &[u8],
    ) -> Result<EncryptedSigningKey, CryptoError> {
        protect_signing_key(&self.signing_key, password)
    }

    #[allow(dead_code)]
    /// Reconstructs a key bundle from password-protected keys with separate passwords.
    ///
    /// Allows using different passwords for the encryption and signing keys, which
    /// provides defense-in-depth: compromise of one password doesn't expose both keys.
    ///
    /// # Arguments
    ///
    /// * `encryption_public` - X25519 public key
    /// * `verifying_key` - Ed25519 public key
    /// * `encrypted_enc` - Password-protected encryption secret
    /// * `encrypted_sign` - Password-protected signing key
    /// * `enc_password` - Password for decrypting the encryption key
    /// * `sign_password` - Password for decrypting the signing key
    ///
    /// # Returns
    ///
    /// * `Ok(KeyBundle)` - Fully reconstructed key bundle
    /// * `Err(CryptoError::DecryptionFailed)` - If either password is incorrect
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Different passwords for different keys (more secure)
    /// let bundle = KeyBundle::from_protected_keys(
    ///     &encryption_public,
    ///     &verifying_key,
    ///     &encrypted_enc,
    ///     &encrypted_sign,
    ///     b"encryption_password",
    ///     b"signing_password_extra_strong",
    /// )?;
    /// ```
    pub fn from_protected_keys(
        encryption_public: &PublicKey,
        verifying_key: &VerifyingKey,
        encrypted_enc: &EncryptedEncryptionKey,
        encrypted_sign: &EncryptedSigningKey,
        enc_password: &[u8],
        sign_password: &[u8],
    ) -> Result<Self, CryptoError> {
        let encryption_secret = unprotect_encryption_key(encrypted_enc, enc_password)?;
        let signing_key = unprotect_signing_key(encrypted_sign, sign_password)?;

        Ok(KeyBundle {
            encryption_secret,
            encryption_public: *encryption_public,
            signing_key,
            verifying_key: *verifying_key,
        })
    }

    #[allow(dead_code)]
    /// Reconstructs a key bundle from password-protected keys using a single password.
    ///
    /// Convenience method for the common case where both keys use the same password.
    /// For higher security, consider using [`from_protected_keys`] with separate passwords.
    ///
    /// # Arguments
    ///
    /// * `encryption_public` - X25519 public key
    /// * `verifying_key` - Ed25519 public key
    /// * `encrypted_enc` - Password-protected encryption secret
    /// * `encrypted_sign` - Password-protected signing key
    /// * `password` - Password for decrypting both keys
    ///
    /// # Returns
    ///
    /// * `Ok(KeyBundle)` - Fully reconstructed key bundle
    /// * `Err(CryptoError::DecryptionFailed)` - If password is incorrect
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Single password for both keys (simpler, less secure)
    /// let bundle = KeyBundle::from_protected_keys_same_password(
    ///     &encryption_public,
    ///     &verifying_key,
    ///     &encrypted_enc,
    ///     &encrypted_sign,
    ///     b"my_strong_password",
    /// )?;
    /// ```
    pub fn from_protected_keys_same_password(
        encryption_public: &PublicKey,
        verifying_key: &VerifyingKey,
        encrypted_enc: &EncryptedEncryptionKey,
        encrypted_sign: &EncryptedSigningKey,
        password: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::from_protected_keys(
            encryption_public,
            verifying_key,
            encrypted_enc,
            encrypted_sign,
            password,
            password,
        )
    }

    /// Returns a 4-byte identifier for the encryption key.
    ///
    /// Derives a short, unique identifier from the encryption public key. Useful for
    /// key selection when multiple keys are available (e.g., "which key encrypted this?").
    ///
    /// # Returns
    ///
    /// 4-byte key ID derived from the public key
    ///
    pub fn encryption_key_id(&self) -> [u8; 4] {
        derive_encryption_key_id(&self.encryption_public)
    }

    /// Returns a 4-byte identifier for the signing key.
    ///
    /// Derives a short, unique identifier from the verifying key. Useful for
    /// identifying which key created a signature.
    ///
    /// # Returns
    ///
    /// 4-byte key ID derived from the public key
    ///
    pub fn signing_key_id(&self) -> [u8; 4] {
        derive_signing_key_id(&self.verifying_key)
    }

    /// Returns both key IDs as hexadecimal strings.
    ///
    /// Convenience method that returns formatted key IDs for both the encryption
    /// and signing keys. Useful for display, logging, or key selection UIs.
    ///
    /// # Returns
    ///
    /// A tuple of `(encryption_key_id, signing_key_id)` as hex strings
    pub fn key_ids_hex(&self) -> (String, String) {
        (
            format_key_id(&self.encryption_key_id()),
            format_key_id(&self.signing_key_id()),
        )
    }
}

//
// Key ID derivation
//

/// Derive a 4-byte key ID from an X25519 public key
pub fn derive_encryption_key_id(public_key: &PublicKey) -> [u8; 4] {
    let bytes = public_key.as_bytes();
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&bytes[0..4]);
    key_id
}

/// Derive a 4-byte key ID from an Ed25519 verifying key
pub fn derive_signing_key_id(verifying_key: &VerifyingKey) -> [u8; 4] {
    let bytes = verifying_key.as_bytes();
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&bytes[0..4]);
    key_id
}

/// Format key ID as hex string (e.g., "8f3a2b7c")
pub fn format_key_id(key_id: &[u8; 4]) -> String {
    //format!("0x{}", hex::encode(key_id))
    hex::encode(key_id)
}

#[allow(dead_code)]
/// Parse key ID from hex string (e.g., "8f3a2b7c")
pub fn parse_key_id(s: &str) -> Result<[u8; 4], CryptoError> {
    //let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 8 {
        return Err(CryptoError::InvalidFormat);
    }

    let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidFormat)?;
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&bytes);
    Ok(key_id)
}

//
// Recovery code types and functions
//

/// A recovery code for backing up cryptographic keys.
///
/// Contains 128 bits of entropy that can be used to derive encryption keys for
/// password-protected key backups. Recovery codes provide an alternative way to
/// restore access if the primary password is lost.
///
/// # Structure
///
/// - **16 bytes (128 bits)** of cryptographically secure random data
/// - Can be displayed as hexadecimal (32 characters) or word mnemonic
/// - Sufficient entropy to resist brute-force attacks
///
#[derive(Clone)]
pub struct RecoveryCode([u8; 16]);

impl RecoveryCode {
    /// Generate a new random recovery code
    pub fn generate() -> Self {
        use aes_gcm::aead::rand_core::RngCore;
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        RecoveryCode(bytes)
    }

    /// Format as hex string (32 chars)
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Format as groups for easier reading: "xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx"
    pub fn to_hex_grouped(&self) -> String {
        let hex = self.to_hex();
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse from hex string (with or without dashes)
    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if clean.len() != 32 {
            return Err(CryptoError::InvalidFormat);
        }
        let bytes = hex::decode(&clean).map_err(|_| CryptoError::InvalidFormat)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(RecoveryCode(arr))
    }

    /// Get the raw bytes (for key derivation)
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        // Zero out the recovery code when dropped
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// Recovery-encrypted key bundle containing both encryption and signing keys.
///
/// Stores both private keys encrypted with a single recovery code. This allows
/// complete key recovery using only the recovery code, without requiring the
/// original password(s).
///
/// # Structure
///
/// - **key_id** (4 bytes): Identifies which key bundle this belongs to
/// - **salt** (16 bytes): Shared salt for deriving encryption key from recovery code
/// - **nonce_enc** (12 bytes): Nonce for encrypting the X25519 secret
/// - **ciphertext_enc** (48 bytes): Encrypted encryption secret + auth tag
/// - **nonce_sign** (12 bytes): Nonce for encrypting the Ed25519 key
/// - **ciphertext_sign** (48 bytes): Encrypted signing key + auth tag
///
/// # Encryption Scheme
///
/// Both keys are encrypted with the same recovery-code-derived key but different nonces:
/// 1. Derive 256-bit key from recovery code using the shared salt
/// 2. Encrypt encryption secret with AES-256-GCM (unique nonce)
/// 3. Encrypt signing key with AES-256-GCM (different unique nonce)
///
/// # Wire Format
///
/// Total size when serialized: 136 bytes
/// ```text
/// [key_id (4)][salt (16)][nonce_enc (12)][ciphertext_enc (48)][nonce_sign (12)][ciphertext_sign (48)]
/// ```
///
pub struct RecoveryEncryptedKeys {
    /// 4-byte identifier to match this backup with the correct key bundle
    pub key_id: [u8; 4],

    /// Shared 16-byte salt for deriving the encryption key from recovery code
    pub salt: [u8; 16],

    /// 12-byte nonce for encrypting the X25519 encryption secret
    pub nonce_enc: [u8; 12],

    /// Encrypted X25519 secret (32 bytes) + authentication tag (16 bytes)
    pub ciphertext_enc: Vec<u8>,

    /// 12-byte nonce for encrypting the Ed25519 signing key
    pub nonce_sign: [u8; 12],

    /// Encrypted Ed25519 signing key (32 bytes) + authentication tag (16 bytes)
    pub ciphertext_sign: Vec<u8>,
}

impl RecoveryEncryptedKeys {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + 16 + 12 + 12 + 4 + self.ciphertext_enc.len() + 4 + self.ciphertext_sign.len(),
        );
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce_enc);
        out.extend_from_slice(&self.nonce_sign);
        // Length-prefix the ciphertexts
        out.extend_from_slice(&(self.ciphertext_enc.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext_enc);
        out.extend_from_slice(&(self.ciphertext_sign.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext_sign);
        out
    }

    pub fn to_base64(&self) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.encode(self.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 4 + 16 + 12 + 12 + 4 + 4 {
            return Err(CryptoError::InvalidFormat);
        }

        let mut key_id = [0u8; 4];
        let mut salt = [0u8; 16];
        let mut nonce_enc = [0u8; 12];
        let mut nonce_sign = [0u8; 12];

        key_id.copy_from_slice(&bytes[0..4]);
        salt.copy_from_slice(&bytes[4..20]);
        nonce_enc.copy_from_slice(&bytes[20..32]);
        nonce_sign.copy_from_slice(&bytes[32..44]);

        let enc_len = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
        if bytes.len() < 48 + enc_len + 4 {
            return Err(CryptoError::InvalidFormat);
        }
        let ciphertext_enc = bytes[48..48 + enc_len].to_vec();

        let sign_offset = 48 + enc_len;
        let sign_len =
            u32::from_le_bytes(bytes[sign_offset..sign_offset + 4].try_into().unwrap()) as usize;
        if bytes.len() < sign_offset + 4 + sign_len {
            return Err(CryptoError::InvalidFormat);
        }
        let ciphertext_sign = bytes[sign_offset + 4..sign_offset + 4 + sign_len].to_vec();

        Ok(Self {
            key_id,
            salt,
            nonce_enc,
            nonce_sign,
            ciphertext_enc,
            ciphertext_sign,
        })
    }

    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = STANDARD
            .decode(s.trim())
            .map_err(|_| CryptoError::InvalidFormat)?;
        Self::from_bytes(&bytes)
    }
}

/// Derives a 256-bit encryption key from a recovery code using Argon2id.
///
/// Uses the same Argon2id KDF as password-based encryption for consistency.
/// The recovery code bytes are treated as the password input.
///
/// # Arguments
///
/// * `code` - The 16-byte recovery code
/// * `salt` - 16-byte random salt
///
/// # Returns
///
/// 32-byte derived key for AES-256-GCM encryption
fn derive_key_from_recovery_code(code: &RecoveryCode, salt: &[u8; 16]) -> [u8; 32] {
    // Use the recovery code bytes directly as the "password" for Argon2
    derive_key_from_password(code.as_bytes(), salt)
}

/// Generates a recovery code and encrypts both keys with it.
///
/// Creates a new random recovery code and uses it to encrypt the entire key bundle.
/// Both the encryption secret and signing key are encrypted with the same derived key
/// but different nonces.
///
/// # Arguments
///
/// * `bundle` - The key bundle to encrypt
///
/// # Returns
///
/// A tuple of `(RecoveryCode, RecoveryEncryptedKeys)`:
/// - Recovery code to store offline
/// - Encrypted keys that can be decrypted with the recovery code
///
/// # Errors
///
/// Returns `CryptoError::EncryptionFailed` if encryption fails
pub fn create_recovery_encrypted_keys(
    bundle: &KeyBundle,
) -> Result<(RecoveryCode, RecoveryEncryptedKeys), CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let recovery_code = RecoveryCode::generate();

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let derived_key = derive_key_from_recovery_code(&recovery_code, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::EncryptionFailed)?;

    // Encrypt encryption secret
    let mut nonce_enc = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_enc);
    let ciphertext_enc = cipher
        .encrypt(
            Nonce::from_slice(&nonce_enc),
            bundle.encryption_secret.as_bytes().as_ref(),
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Encrypt signing key
    let mut nonce_sign = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_sign);
    let ciphertext_sign = cipher
        .encrypt(
            Nonce::from_slice(&nonce_sign),
            bundle.signing_key.to_bytes().as_ref(),
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let encrypted = RecoveryEncryptedKeys {
        key_id: bundle.encryption_key_id(),
        salt,
        nonce_enc,
        nonce_sign,
        ciphertext_enc,
        ciphertext_sign,
    };

    Ok((recovery_code, encrypted))
}

/// Decrypts a key bundle using a recovery code.
///
/// Recovers both the encryption secret and signing key from recovery-encrypted storage.
/// Verifies that the decrypted private keys match the provided public keys.
///
/// # Arguments
///
/// * `encrypted` - The recovery-encrypted keys
/// * `recovery_code` - The recovery code used for encryption
/// * `encryption_public` - Expected X25519 public key (for verification)
/// * `verifying_key` - Expected Ed25519 public key (for verification)
///
/// # Returns
///
/// * `Ok(KeyBundle)` - Successfully recovered key bundle
/// * `Err(CryptoError::DecryptionFailed)` - Wrong recovery code or key mismatch
/// * `Err(CryptoError::InvalidKeyLength)` - Decrypted data has wrong length
pub fn decrypt_with_recovery_code(
    encrypted: &RecoveryEncryptedKeys,
    recovery_code: &RecoveryCode,
    encryption_public: &PublicKey,
    verifying_key: &VerifyingKey,
) -> Result<KeyBundle, CryptoError> {
    let derived_key = derive_key_from_recovery_code(recovery_code, &encrypted.salt);
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::DecryptionFailed)?;

    // Decrypt encryption secret
    let enc_plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce_enc),
            encrypted.ciphertext_enc.as_ref(),
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if enc_plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&enc_plaintext);
    let encryption_secret = StaticSecret::from(enc_bytes);

    // Decrypt signing key
    let sign_plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce_sign),
            encrypted.ciphertext_sign.as_ref(),
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if sign_plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut sign_bytes = [0u8; 32];
    sign_bytes.copy_from_slice(&sign_plaintext);
    let signing_key = SigningKey::from_bytes(&sign_bytes);

    // Verify the decrypted keys match the public keys
    let derived_public = PublicKey::from(&encryption_secret);
    if derived_public.as_bytes() != encryption_public.as_bytes() {
        return Err(CryptoError::DecryptionFailed);
    }

    let derived_verifying = signing_key.verifying_key();
    if derived_verifying.as_bytes() != verifying_key.as_bytes() {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(KeyBundle {
        encryption_secret,
        encryption_public: *encryption_public,
        signing_key,
        verifying_key: *verifying_key,
    })
}

/// Attempts recovery from multiple encrypted key backups.
///
/// Tries to decrypt each encrypted key in the list until one succeeds. Useful when
/// you have multiple key backups and aren't sure which one matches the recovery code.
///
/// # Arguments
///
/// * `encrypted_keys` - List of recovery-encrypted key backups to try
/// * `recovery_code` - The recovery code to use
/// * `encryption_public` - Expected X25519 public key
/// * `verifying_key` - Expected Ed25519 public key
///
/// # Returns
///
/// * `Ok((KeyBundle, usize))` - Recovered bundle and index of successful backup
/// * `Err(CryptoError::DecryptionFailed)` - No backup could be decrypted
///
pub fn try_recover_from_list(
    encrypted_keys: &[RecoveryEncryptedKeys],
    recovery_code: &RecoveryCode,
    encryption_public: &PublicKey,
    verifying_key: &VerifyingKey,
) -> Result<(KeyBundle, usize), CryptoError> {
    for (idx, encrypted) in encrypted_keys.iter().enumerate() {
        match decrypt_with_recovery_code(encrypted, recovery_code, encryption_public, verifying_key)
        {
            Ok(bundle) => return Ok((bundle, idx)),
            Err(_) => continue,
        }
    }
    Err(CryptoError::DecryptionFailed)
}

/// Parses a recovery file containing multiple encrypted key backups.
///
/// Reads a text file with one base64-encoded `RecoveryEncryptedKeys` per line.
/// Lines starting with `#` are treated as comments. Empty lines are ignored.
///
/// # Arguments
///
/// * `contents` - The file contents as a string
///
/// # Returns
///
/// * `Ok(Vec<RecoveryEncryptedKeys>)` - Parsed encrypted key backups
/// * `Err(CryptoError)` - If any line fails to parse
///
/// # Format
///
/// ```text
/// # Recovery keys backup - created 2024-01-15
/// base64encodedkey1...
/// base64encodedkey2...
/// # Another comment
/// base64encodedkey3...
/// ```
///
pub fn parse_recovery_file(contents: &str) -> Result<Vec<RecoveryEncryptedKeys>, CryptoError> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| RecoveryEncryptedKeys::from_base64(line))
        .collect()
}

// --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let bundle = generate_key_bundle();
        assert_eq!(bundle.encryption_public.as_bytes().len(), 32);
        assert_eq!(bundle.verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_aes_key_encryption_roundtrip() {
        let bob = generate_key_bundle();

        let original_key = generate_aes_key();
        let encrypted = encrypt_aes_key(&original_key, &bob.encryption_public).unwrap();
        let decrypted = decrypt_aes_key(&encrypted, &bob.encryption_secret).unwrap();

        assert_eq!(original_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_content_encryption_roundtrip() {
        let plaintext = b"Hello, this is secret data for the LLM CLI!";
        let key = generate_aes_key();

        let encrypted = encrypt_content(plaintext, &key).unwrap();
        let decrypted = decrypt_content(&encrypted, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_signing_verification() {
        let bundle = generate_key_bundle();
        let data = b"Important message to sign";

        let signature = sign(data, &bundle.signing_key);
        let result = verify(data, &signature, &bundle.verifying_key);

        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_fails_on_tampered_data() {
        let bundle = generate_key_bundle();
        let data = b"Original message";
        let tampered = b"Tampered message";

        let signature = sign(data, &bundle.signing_key);
        let result = verify(tampered, &signature, &bundle.verifying_key);

        assert_eq!(result, Err(CryptoError::SignatureInvalid));
    }

    #[test]
    fn test_full_encrypt_sign_workflow() {
        let alice = generate_key_bundle();
        let bob = generate_key_bundle();

        // Alice encrypts for Bob and signs
        let plaintext = b"Secret conversation data";
        let aes_key = generate_aes_key();
        let encrypted_content = encrypt_content(plaintext, &aes_key).unwrap();
        let encrypted_key = encrypt_aes_key(&aes_key, &bob.encryption_public).unwrap();
        let signature = sign(&encrypted_content.to_bytes(), &alice.signing_key);

        // Bob verifies and decrypts
        verify(
            &encrypted_content.to_bytes(),
            &signature,
            &alice.verifying_key,
        )
        .unwrap();
        let decrypted_key = decrypt_aes_key(&encrypted_key, &bob.encryption_secret).unwrap();
        let decrypted_content = decrypt_content(&encrypted_content, &decrypted_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted_content.as_slice());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let original = generate_key_bundle();
        let public = original.export_public();
        let secret = original.export_secret();

        let restored = KeyBundle::from_exported(&public, &secret).unwrap();

        // Verify restored keys work
        let data = b"test data";
        let signature = sign(data, &restored.signing_key);
        verify(data, &signature, &restored.verifying_key).unwrap();
    }

    #[test]
    fn test_protect_encryption_key_roundtrip() {
        let bundle = generate_key_bundle();
        let password = b"test-password";

        let encrypted = protect_encryption_key(&bundle.encryption_secret, password).unwrap();
        let decrypted = unprotect_encryption_key(&encrypted, password).unwrap();

        // Verify it's the same key by checking public key derivation
        let original_public = PublicKey::from(&bundle.encryption_secret);
        let decrypted_public = PublicKey::from(&decrypted);
        assert_eq!(original_public.as_bytes(), decrypted_public.as_bytes());
    }

    #[test]
    fn test_protect_signing_key_roundtrip() {
        let bundle = generate_key_bundle();
        let password = b"test-password";

        let encrypted = protect_signing_key(&bundle.signing_key, password).unwrap();
        let decrypted = unprotect_signing_key(&encrypted, password).unwrap();

        assert_eq!(bundle.signing_key.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_wrong_password_fails_encryption_key() {
        let bundle = generate_key_bundle();
        let encrypted = protect_encryption_key(&bundle.encryption_secret, b"right").unwrap();
        let result = unprotect_encryption_key(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_password_fails_signing_key() {
        let bundle = generate_key_bundle();
        let encrypted = protect_signing_key(&bundle.signing_key, b"right").unwrap();
        let result = unprotect_signing_key(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_passwords_per_key() {
        let bundle = generate_key_bundle();
        let enc_password = b"encryption-password";
        let sign_password = b"signing-password";

        let encrypted_enc = bundle
            .export_encryption_secret_protected(enc_password)
            .unwrap();
        let encrypted_sign = bundle.export_signing_key_protected(sign_password).unwrap();

        let restored = KeyBundle::from_protected_keys(
            &bundle.encryption_public,
            &bundle.verifying_key,
            &encrypted_enc,
            &encrypted_sign,
            enc_password,
            sign_password,
        )
        .unwrap();

        // Verify restored keys work
        let data = b"test";
        let sig = sign(data, &restored.signing_key);
        verify(data, &sig, &restored.verifying_key).unwrap();
    }

    #[test]
    fn test_serialization_roundtrip() {
        let bundle = generate_key_bundle();
        let password = b"password";

        let encrypted_enc = protect_encryption_key(&bundle.encryption_secret, password).unwrap();
        let decrypted = unprotect_encryption_key(&encrypted_enc, password).unwrap();

        let original_public = PublicKey::from(&bundle.encryption_secret);
        let decrypted_public = PublicKey::from(&decrypted);
        assert_eq!(original_public.as_bytes(), decrypted_public.as_bytes());
    }

    #[test]
    fn test_key_id_derivation() {
        let bundle = generate_key_bundle();

        let enc_id = bundle.encryption_key_id();
        let sign_id = bundle.signing_key_id();

        assert_eq!(enc_id.len(), 4);
        assert_eq!(sign_id.len(), 4);

        // Key IDs should be first 4 bytes of public keys
        assert_eq!(&enc_id, &bundle.encryption_public.as_bytes()[0..4]);
        assert_eq!(&sign_id, &bundle.verifying_key.as_bytes()[0..4]);
    }

    #[test]
    fn test_key_id_formatting() {
        let key_id = [0x8f, 0x3a, 0x2b, 0x7c];
        let formatted = format_key_id(&key_id);
        assert_eq!(formatted, "8f3a2b7c");
    }

    #[test]
    fn test_key_id_parsing() {
        let parsed = parse_key_id("8f3a2b7c").unwrap();
        assert_eq!(parsed, [0x8f, 0x3a, 0x2b, 0x7c]);

        // Should work without 0x prefix
        let parsed2 = parse_key_id("8f3a2b7c").unwrap();
        assert_eq!(parsed2, [0x8f, 0x3a, 0x2b, 0x7c]);
    }

    #[test]
    fn test_key_id_roundtrip() {
        let bundle = generate_key_bundle();
        let (enc_hex, sign_hex) = bundle.key_ids_hex();

        let enc_parsed = parse_key_id(&enc_hex).unwrap();
        let sign_parsed = parse_key_id(&sign_hex).unwrap();

        assert_eq!(enc_parsed, bundle.encryption_key_id());
        assert_eq!(sign_parsed, bundle.signing_key_id());
    }

    #[test]
    fn test_public_bundle_key_ids() {
        let bundle = generate_key_bundle();
        let public = bundle.export_public();

        assert_eq!(public.encryption_key_id(), bundle.encryption_key_id());
        assert_eq!(public.signing_key_id(), bundle.signing_key_id());
    }

    #[test]
    fn test_key_id_uniqueness() {
        let bundle1 = generate_key_bundle();
        let bundle2 = generate_key_bundle();

        // Different keys should have different IDs (with very high probability)
        assert_ne!(bundle1.encryption_key_id(), bundle2.encryption_key_id());
        assert_ne!(bundle1.signing_key_id(), bundle2.signing_key_id());
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn test_recovery_code_generation() {
        let code = RecoveryCode::generate();
        let hex = code.to_hex();
        assert_eq!(hex.len(), 32);
    }

    #[test]
    fn test_recovery_code_formatting() {
        let code = RecoveryCode::generate();
        let grouped = code.to_hex_grouped();
        assert_eq!(grouped.len(), 32 + 7); // 32 hex chars + 7 dashes
        assert!(grouped.contains('-'));
    }

    #[test]
    fn test_recovery_code_parsing() {
        let code = RecoveryCode::generate();
        let hex = code.to_hex();
        let grouped = code.to_hex_grouped();

        let parsed1 = RecoveryCode::from_hex(&hex).unwrap();
        let parsed2 = RecoveryCode::from_hex(&grouped).unwrap();

        assert_eq!(parsed1.as_bytes(), code.as_bytes());
        assert_eq!(parsed2.as_bytes(), code.as_bytes());
    }

    #[test]
    fn test_recovery_encrypted_keys_roundtrip() {
        let bundle = generate_key_bundle();
        let (code, encrypted) = create_recovery_encrypted_keys(&bundle).unwrap();

        let decrypted = decrypt_with_recovery_code(
            &encrypted,
            &code,
            &bundle.encryption_public,
            &bundle.verifying_key,
        )
        .unwrap();

        // Verify keys match
        assert_eq!(
            decrypted.encryption_public.as_bytes(),
            bundle.encryption_public.as_bytes()
        );
        assert_eq!(
            decrypted.verifying_key.as_bytes(),
            bundle.verifying_key.as_bytes()
        );

        // Verify signing works
        let data = b"test";
        let sig = sign(data, &decrypted.signing_key);
        verify(data, &sig, &decrypted.verifying_key).unwrap();
    }

    #[test]
    fn test_wrong_recovery_code_fails() {
        let bundle = generate_key_bundle();
        let (_code, encrypted) = create_recovery_encrypted_keys(&bundle).unwrap();
        let wrong_code = RecoveryCode::generate();

        let result = decrypt_with_recovery_code(
            &encrypted,
            &wrong_code,
            &bundle.encryption_public,
            &bundle.verifying_key,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_serialization() {
        let bundle = generate_key_bundle();
        let (code, encrypted) = create_recovery_encrypted_keys(&bundle).unwrap();

        let base64 = encrypted.to_base64();
        let parsed = RecoveryEncryptedKeys::from_base64(&base64).unwrap();

        let decrypted = decrypt_with_recovery_code(
            &parsed,
            &code,
            &bundle.encryption_public,
            &bundle.verifying_key,
        )
        .unwrap();

        assert_eq!(
            decrypted.encryption_public.as_bytes(),
            bundle.encryption_public.as_bytes()
        );
    }

    #[test]
    fn test_try_recover_from_list() {
        let bundle = generate_key_bundle();
        let (correct_code, correct_encrypted) = create_recovery_encrypted_keys(&bundle).unwrap();

        // Create some decoy encrypted keys (with different recovery codes)
        let bundle2 = generate_key_bundle();
        let (_, decoy1) = create_recovery_encrypted_keys(&bundle2).unwrap();
        let bundle3 = generate_key_bundle();
        let (_, decoy2) = create_recovery_encrypted_keys(&bundle3).unwrap();

        let list = vec![decoy1, correct_encrypted, decoy2];

        let (recovered, idx) = try_recover_from_list(
            &list,
            &correct_code,
            &bundle.encryption_public,
            &bundle.verifying_key,
        )
        .unwrap();

        assert_eq!(idx, 1);
        assert_eq!(
            recovered.encryption_public.as_bytes(),
            bundle.encryption_public.as_bytes()
        );
    }

    #[test]
    fn test_parse_recovery_file() {
        let bundle = generate_key_bundle();
        let (_, encrypted1) = create_recovery_encrypted_keys(&bundle).unwrap();
        let (_, encrypted2) = create_recovery_encrypted_keys(&bundle).unwrap();

        let file_contents = format!(
            "# Recovery keys for key {}\n{}\n{}\n",
            format_key_id(&bundle.encryption_key_id()),
            encrypted1.to_base64(),
            encrypted2.to_base64()
        );

        let parsed = parse_recovery_file(&file_contents).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
