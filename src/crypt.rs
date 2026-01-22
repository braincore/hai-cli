//! This module provides cryptographic utilities including key generation,
//! encryption/decryption, and signing/verification.
//!
//! It uses X25519 for key exchange, Ed25519 for digital signatures, and
//! AES-GCM for symmetric encryption.
//!
//! It also includes password-based protection for secret keys using Argon2 and
//! AES-GCM.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ============================================================
// ERROR TYPE
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
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

// ============================================================
// KEY TYPES
// ============================================================

pub struct KeyBundle {
    pub encryption_secret: StaticSecret,
    pub encryption_public: PublicKey,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

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

pub struct EncryptedAesKey {
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 12],
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

pub struct EncryptedContent {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedContent {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

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

// ============================================================
// KEY GENERATION
// ============================================================

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

pub fn generate_aes_key() -> AesKey {
    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    AesKey(key)
}

// ============================================================
// AES KEY ENCRYPTION/DECRYPTION
// ============================================================

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

    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(AesKey(key))
}

// ============================================================
// CONTENT ENCRYPTION/DECRYPTION
// ============================================================

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

pub fn decrypt_content(encrypted: &EncryptedContent, key: &AesKey) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ============================================================
// SIGNING/VERIFICATION
// ============================================================

pub fn sign(data: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(data)
}

pub fn verify(
    data: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(data, signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

// ============================================================
// KEY SERIALIZATION (for storage)
// ============================================================

impl KeyBundle {
    /// Export public keys only (safe to share)
    pub fn export_public(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            encryption_public: self.encryption_public.to_bytes(),
            verifying_key: self.verifying_key.to_bytes(),
        }
    }

    /// Export secret keys (store securely!)
    pub fn export_secret(&self) -> SecretKeyBundle {
        SecretKeyBundle {
            encryption_secret: self.encryption_secret.as_bytes().to_owned(),
            signing_key: self.signing_key.to_bytes(),
        }
    }

    /// Import from exported keys
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
    /*
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.encryption_public);
        out[32..64].copy_from_slice(&self.verifying_key);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut encryption_public = [0u8; 32];
        let mut verifying_key = [0u8; 32];
        encryption_public.copy_from_slice(&bytes[0..32]);
        verifying_key.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            encryption_public,
            verifying_key,
        })
    }*/

    /// Get the key ID for the encryption key
    pub fn encryption_key_id(&self) -> [u8; 4] {
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&self.encryption_public[0..4]);
        key_id
    }

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

use argon2::{Argon2, password_hash::SaltString};

// ============================================================
// ENCRYPTED KEY TYPES (Separate!)
// ============================================================

/// Password-protected X25519 encryption secret key
pub struct EncryptedEncryptionKey {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // 32 bytes + 16 byte auth tag = 48 bytes
}

impl EncryptedEncryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 12 + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

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

/// Password-protected Ed25519 signing key
pub struct EncryptedSigningKey {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // 32 bytes + 16 byte auth tag = 48 bytes
}

impl EncryptedSigningKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 12 + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

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

fn derive_key_from_password(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .expect("Argon2 hashing failed");
    key
}

// ============================================================
// PROTECT / UNPROTECT FUNCTIONS
// ============================================================

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

// ============================================================
// CONVENIENCE METHODS ON KeyBundle
// ============================================================

impl KeyBundle {
    /// Export encryption secret key, password-protected
    pub fn export_encryption_secret_protected(
        &self,
        password: &[u8],
    ) -> Result<EncryptedEncryptionKey, CryptoError> {
        protect_encryption_key(&self.encryption_secret, password)
    }

    /// Export signing key, password-protected
    pub fn export_signing_key_protected(
        &self,
        password: &[u8],
    ) -> Result<EncryptedSigningKey, CryptoError> {
        protect_signing_key(&self.signing_key, password)
    }

    /// Import from individual protected keys
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

    /// Import with same password for both keys
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

    /// Get the key ID for the encryption key
    pub fn encryption_key_id(&self) -> [u8; 4] {
        derive_encryption_key_id(&self.encryption_public)
    }

    /// Get the key ID for the signing key
    pub fn signing_key_id(&self) -> [u8; 4] {
        derive_signing_key_id(&self.verifying_key)
    }

    /// Get both key IDs as hex strings
    pub fn key_ids_hex(&self) -> (String, String) {
        (
            format_key_id(&self.encryption_key_id()),
            format_key_id(&self.signing_key_id()),
        )
    }
}

// ============================================================
// KEY ID DERIVATION
// ============================================================

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

// ============================================================
// TESTS
// ============================================================

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
        let alice = generate_key_bundle();
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
        assert_eq!(formatted, "0x8f3a2b7c");
    }

    #[test]
    fn test_key_id_parsing() {
        let parsed = parse_key_id("0x8f3a2b7c").unwrap();
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
