//! Secure Enclave–backed password store for macOS.
//!
//! Instead of the legacy file-based keychain (which prompts for the login
//! password per item and re-prompts whenever the binary changes), asset key
//! passwords are encrypted to a P-256 key that lives inside the Secure
//! Enclave and requires user presence (Touch ID, falling back to the system
//! password) to use. The enclave hands back an opaque, device-bound handle
//! which we keep on disk alongside the encrypted passwords:
//!
//! ~/.hai/keys/se/enclave.key        opaque enclave key handle
//! ~/.hai/keys/se/enclave.pub        x963 public key
//! ~/.hai/keys/se/<hex(id)>.sealed   password sealed to the enclave key

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

mod ffi {
    use std::os::raw::c_char;
    unsafe extern "C" {
        pub fn hai_se_is_available() -> bool;
        pub fn hai_se_reset_auth();
        pub fn hai_se_free(ptr: *mut u8);
        pub fn hai_se_last_error(out: *mut *mut u8, out_len: *mut usize);
        pub fn hai_se_create_key(
            out_handle: *mut *mut u8,
            out_handle_len: *mut usize,
            out_pub: *mut *mut u8,
            out_pub_len: *mut usize,
        ) -> i32;
        pub fn hai_se_encrypt(
            pub_key: *const u8,
            pub_key_len: usize,
            pt: *const u8,
            pt_len: usize,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32;
        pub fn hai_se_decrypt(
            handle: *const u8,
            handle_len: usize,
            ct: *const u8,
            ct_len: usize,
            reason: *const c_char,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32;
    }
}

#[derive(Debug)]
pub enum SeError {
    /// User dismissed the Touch ID / password dialog.
    Cancelled,
    /// User failed to authenticate.
    AuthFailed,
    /// The enclave key handle is unusable (e.g. different machine, enclave
    /// reset, corrupted file).
    InvalidKey(String),
    Unavailable,
    Other(String),
}

impl std::fmt::Display for SeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeError::Cancelled => write!(f, "authentication cancelled"),
            SeError::AuthFailed => write!(f, "authentication failed"),
            SeError::InvalidKey(e) => write!(f, "secure enclave key invalid: {e}"),
            SeError::Unavailable => write!(f, "secure enclave unavailable"),
            SeError::Other(e) => write!(f, "secure enclave error: {e}"),
        }
    }
}

/// Copy a malloc'd buffer from Swift into a Vec, zero it, and free it.
unsafe fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() {
        return vec![];
    }
    let v = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe {
        std::ptr::write_bytes(ptr, 0, len);
        ffi::hai_se_free(ptr);
    }
    v
}

fn last_error() -> String {
    let mut p = std::ptr::null_mut();
    let mut n = 0usize;
    unsafe {
        ffi::hai_se_last_error(&mut p, &mut n);
        String::from_utf8_lossy(&take(p, n)).into_owned()
    }
}

fn check(rc: i32) -> Result<(), SeError> {
    match rc {
        0 => Ok(()),
        1 => Err(SeError::Cancelled),
        2 => Err(SeError::AuthFailed),
        3 => Err(SeError::InvalidKey(last_error())),
        5 => Err(SeError::Unavailable),
        _ => Err(SeError::Other(last_error())),
    }
}

pub fn is_available() -> bool {
    unsafe { ffi::hai_se_is_available() }
}

/// Drop the cached authentication so the next unseal prompts again.
pub fn reset_auth() {
    unsafe { ffi::hai_se_reset_auth() }
}

fn create_key() -> Result<(Vec<u8>, Vec<u8>), SeError> {
    let (mut hp, mut hn, mut pp, mut pn) = (std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    let rc = unsafe { ffi::hai_se_create_key(&mut hp, &mut hn, &mut pp, &mut pn) };
    check(rc)?;
    unsafe { Ok((take(hp, hn), take(pp, pn))) }
}

fn seal(pub_key: &[u8], pt: &[u8]) -> Result<Vec<u8>, SeError> {
    let (mut op, mut on) = (std::ptr::null_mut(), 0);
    let rc = unsafe {
        ffi::hai_se_encrypt(
            pub_key.as_ptr(),
            pub_key.len(),
            pt.as_ptr(),
            pt.len(),
            &mut op,
            &mut on,
        )
    };
    check(rc)?;
    unsafe { Ok(take(op, on)) }
}

fn unseal(handle: &[u8], ct: &[u8], reason: &str) -> Result<Zeroizing<Vec<u8>>, SeError> {
    let reason = CString::new(reason).unwrap_or_default();
    let (mut op, mut on) = (std::ptr::null_mut(), 0);
    let rc = unsafe {
        ffi::hai_se_decrypt(
            handle.as_ptr(),
            handle.len(),
            ct.as_ptr(),
            ct.len(),
            reason.as_ptr(),
            &mut op,
            &mut on,
        )
    };
    check(rc)?;
    unsafe { Ok(Zeroizing::new(take(op, on))) }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // Write to a temp file then rename for atomicity.
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// A directory of passwords sealed to a Secure Enclave key.
#[derive(Debug)]
pub struct SeVault {
    dir: PathBuf,
}

const REASON: &str = "unlock your hai encryption keys";

impl SeVault {
    /// Returns a vault if the Secure Enclave is usable in this context.
    pub fn open(dir: PathBuf) -> Option<Self> {
        if !is_available() {
            return None;
        }
        // Over SSH the Touch ID dialog would appear on the remote Mac's
        // screen (or hang). Fall back to the password prompt instead.
        if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
            return None;
        }
        Some(Self { dir })
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("enclave.key")
    }

    fn pub_path(&self) -> PathBuf {
        self.dir.join("enclave.pub")
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.sealed", hex::encode(id)))
    }

    fn ensure_dir(&self) -> Result<(), SeError> {
        fs::create_dir_all(&self.dir).map_err(|e| SeError::Other(e.to_string()))?;
        let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        Ok(())
    }

    fn load_pub_or_create(&self) -> Result<Vec<u8>, SeError> {
        if let (Ok(_), Ok(pub_key)) = (fs::read(self.key_path()), fs::read(self.pub_path())) {
            return Ok(pub_key);
        }
        self.ensure_dir()?;
        // New enclave key: any previously sealed entries are unreadable.
        self.wipe();
        self.ensure_dir()?;
        let (handle, pub_key) = create_key()?;
        let io = |e: std::io::Error| SeError::Other(e.to_string());
        write_private(&self.key_path(), &handle).map_err(io)?;
        write_private(&self.pub_path(), &pub_key).map_err(io)?;
        Ok(pub_key)
    }

    /// Remove the enclave key and all sealed entries.
    pub fn wipe(&self) {
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.entry_path(id).exists() && self.key_path().exists()
    }

    /// Seal and persist a secret. Never prompts.
    pub fn store(&self, id: &str, secret: &str) -> Result<(), SeError> {
        let pub_key = self.load_pub_or_create()?;
        let ct = seal(&pub_key, secret.as_bytes())?;
        write_private(&self.entry_path(id), &ct).map_err(|e| SeError::Other(e.to_string()))
    }

    /// Unseal a secret. Prompts for Touch ID at most once per process.
    pub fn get(&self, id: &str) -> Result<Option<Zeroizing<String>>, SeError> {
        let ct = match fs::read(self.entry_path(id)) {
            Ok(ct) => ct,
            Err(_) => return Ok(None),
        };
        let handle = match fs::read(self.key_path()) {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };
        match unseal(&handle, &ct, REASON) {
            Ok(pt) => {
                let s = String::from_utf8(pt.to_vec())
                    .map_err(|_| SeError::Other("sealed secret is not utf-8".into()))?;
                Ok(Some(Zeroizing::new(s)))
            }
            Err(SeError::InvalidKey(e)) => {
                // The enclave key is gone for good; nothing sealed to it can
                // be recovered. Start fresh on the next store.
                tracing::warn!("secure enclave key unusable, resetting vault: {e}");
                self.wipe();
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&self, id: &str) {
        let _ = fs::remove_file(self.entry_path(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires a human to touch the sensor. Run with:
    /// `cargo test --bin hai macos_se -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn vault_roundtrip_touch_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = SeVault {
            dir: dir.path().join("se"),
        };
        vault.store("user:enc:abc", "hunter2").unwrap();
        vault.store("user:sign:abc", "hunter2").unwrap();
        assert!(vault.contains("user:enc:abc"));
        let t = std::time::Instant::now();
        assert_eq!(
            vault.get("user:enc:abc").unwrap().unwrap().as_str(),
            "hunter2"
        );
        println!("first unseal (prompted): {:?}", t.elapsed());
        let t = std::time::Instant::now();
        assert_eq!(
            vault.get("user:sign:abc").unwrap().unwrap().as_str(),
            "hunter2"
        );
        println!("second unseal (no prompt): {:?}", t.elapsed());
        assert!(vault.get("missing").unwrap().is_none());
        vault.delete("user:enc:abc");
        assert!(!vault.contains("user:enc:abc"));
        let mode = fs::metadata(vault.key_path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
