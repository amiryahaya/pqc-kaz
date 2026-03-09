//! Safe Rust bindings for KAZ-KEM post-quantum key encapsulation mechanism.
//!
//! KAZ-KEM provides post-quantum secure key encapsulation supporting NIST
//! security levels 128, 192, and 256.
//!
//! # Example
//!
//! ```no_run
//! use kaz_kem::{KazKem, SecurityLevel};
//!
//! let kem = KazKem::new(SecurityLevel::L128).unwrap();
//! let (pk, sk) = kem.keypair().unwrap();
//!
//! // Sender: encapsulate a shared secret using the public key
//! let shared_secret = b"my_shared_secret_value_here_pad!_pad!_pad!_pad!_pad!!!!!";
//! let ct = kem.encapsulate(&shared_secret[..54], &pk).unwrap();
//!
//! // Receiver: decapsulate using the private key
//! let recovered = kem.decapsulate(&ct, sk.as_bytes()).unwrap();
//! ```

pub mod ffi;

use std::ffi::CStr;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroize;

// Global mutex to serialize init/cleanup since the C library uses global state.
static KEM_LOCK: Mutex<()> = Mutex::new(());

/// NIST security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    /// 128-bit security (pk=108, sk=34, ct=162, ss=54)
    L128 = 128,
    /// 192-bit security (pk=176, sk=50, ct=264, ss=88)
    L192 = 192,
    /// 256-bit security (pk=236, sk=66, ct=354, ss=118)
    L256 = 256,
}

impl SecurityLevel {
    /// Returns the public key size in bytes for this level.
    pub const fn public_key_bytes(&self) -> usize {
        match self {
            SecurityLevel::L128 => 108,
            SecurityLevel::L192 => 176,
            SecurityLevel::L256 => 236,
        }
    }

    /// Returns the private key size in bytes for this level.
    pub const fn private_key_bytes(&self) -> usize {
        match self {
            SecurityLevel::L128 => 34,
            SecurityLevel::L192 => 50,
            SecurityLevel::L256 => 66,
        }
    }

    /// Returns the ciphertext size in bytes for this level.
    pub const fn ciphertext_bytes(&self) -> usize {
        match self {
            SecurityLevel::L128 => 162,
            SecurityLevel::L192 => 264,
            SecurityLevel::L256 => 354,
        }
    }

    /// Returns the shared secret size in bytes for this level.
    pub const fn shared_secret_bytes(&self) -> usize {
        match self {
            SecurityLevel::L128 => 54,
            SecurityLevel::L192 => 88,
            SecurityLevel::L256 => 118,
        }
    }

    fn from_c_int(v: i32) -> Option<SecurityLevel> {
        match v {
            128 => Some(SecurityLevel::L128),
            192 => Some(SecurityLevel::L192),
            256 => Some(SecurityLevel::L256),
            _ => None,
        }
    }
}

/// Error type for KAZ-KEM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KazKemError {
    /// Invalid parameter passed to function.
    InvalidParam,
    /// Random number generation failure.
    Rng,
    /// Memory allocation failure.
    Memory,
    /// OpenSSL internal error.
    OpenSsl,
    /// Message too large for the current security level.
    MsgTooLarge,
    /// Library not initialized. Call `KazKem::new()` first.
    NotInitialized,
    /// Invalid security level specified.
    InvalidLevel,
    /// Wire format encoding/decoding error.
    WireFormat,
    /// Unknown error code from C library.
    Unknown(i32),
}

impl KazKemError {
    fn from_code(code: i32) -> Self {
        match code {
            ffi::KAZ_KEM_ERROR_INVALID_PARAM => KazKemError::InvalidParam,
            ffi::KAZ_KEM_ERROR_RNG => KazKemError::Rng,
            ffi::KAZ_KEM_ERROR_MEMORY => KazKemError::Memory,
            ffi::KAZ_KEM_ERROR_OPENSSL => KazKemError::OpenSsl,
            ffi::KAZ_KEM_ERROR_MSG_TOO_LARGE => KazKemError::MsgTooLarge,
            ffi::KAZ_KEM_ERROR_NOT_INIT => KazKemError::NotInitialized,
            ffi::KAZ_KEM_ERROR_INVALID_LEVEL => KazKemError::InvalidLevel,
            ffi::KAZ_KEM_ERROR_WIRE_FORMAT => KazKemError::WireFormat,
            other => KazKemError::Unknown(other),
        }
    }
}

impl fmt::Display for KazKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KazKemError::InvalidParam => write!(f, "invalid parameter"),
            KazKemError::Rng => write!(f, "random number generation failure"),
            KazKemError::Memory => write!(f, "memory allocation failure"),
            KazKemError::OpenSsl => write!(f, "OpenSSL internal error"),
            KazKemError::MsgTooLarge => write!(f, "message too large"),
            KazKemError::NotInitialized => write!(f, "library not initialized"),
            KazKemError::InvalidLevel => write!(f, "invalid security level"),
            KazKemError::WireFormat => write!(f, "wire format error"),
            KazKemError::Unknown(code) => write!(f, "unknown error (code {})", code),
        }
    }
}

impl std::error::Error for KazKemError {}

/// Result type alias for KAZ-KEM operations.
pub type Result<T> = std::result::Result<T, KazKemError>;

/// Check a C return code, returning Ok(()) on success or the mapped error.
fn check(code: i32) -> Result<()> {
    if code == ffi::KAZ_KEM_SUCCESS {
        Ok(())
    } else {
        Err(KazKemError::from_code(code))
    }
}

/// A KAZ-KEM instance initialized at a specific security level.
///
/// The C library uses global state, so only one `KazKem` instance should be
/// active at a time. Creating a new instance at a different level will
/// re-initialize the library. Access is serialized via an internal mutex.
pub struct KazKem {
    level: SecurityLevel,
}

impl KazKem {
    /// Initialize KAZ-KEM at the given security level.
    ///
    /// # Errors
    ///
    /// Returns an error if the C library fails to initialize.
    pub fn new(level: SecurityLevel) -> Result<Self> {
        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe { ffi::kaz_kem_init(level as i32) };
        check(rc)?;
        Ok(KazKem { level })
    }

    /// Returns the security level this instance was initialized with.
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    /// Returns the library version string.
    pub fn version() -> &'static str {
        unsafe {
            let ptr = ffi::kaz_kem_version();
            if ptr.is_null() {
                "unknown"
            } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
            }
        }
    }

    /// Returns true if the library is currently initialized.
    pub fn is_initialized() -> bool {
        unsafe { ffi::kaz_kem_is_initialized() != 0 }
    }

    /// Returns the public key size in bytes (from the C library).
    pub fn public_key_bytes(&self) -> usize {
        let _lock = KEM_LOCK.lock().unwrap();
        unsafe { ffi::kaz_kem_publickey_bytes() }
    }

    /// Returns the private key size in bytes (from the C library).
    pub fn private_key_bytes(&self) -> usize {
        let _lock = KEM_LOCK.lock().unwrap();
        unsafe { ffi::kaz_kem_privatekey_bytes() }
    }

    /// Returns the ciphertext size in bytes (from the C library).
    pub fn ciphertext_bytes(&self) -> usize {
        let _lock = KEM_LOCK.lock().unwrap();
        unsafe { ffi::kaz_kem_ciphertext_bytes() }
    }

    /// Returns the shared secret size in bytes (from the C library).
    pub fn shared_secret_bytes(&self) -> usize {
        let _lock = KEM_LOCK.lock().unwrap();
        unsafe { ffi::kaz_kem_shared_secret_bytes() }
    }

    /// Generate a new key pair.
    ///
    /// Returns `(public_key, secret_key)`. The secret key is zeroized on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn keypair(&self) -> Result<(Vec<u8>, SecretVec)> {
        let pk_len = self.level.public_key_bytes();
        let sk_len = self.level.private_key_bytes();

        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe { ffi::kaz_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        check(rc)?;

        Ok((pk, SecretVec(sk)))
    }

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// # Arguments
    ///
    /// * `ss` - The shared secret to encapsulate.
    /// * `pk` - The recipient's public key.
    ///
    /// # Returns
    ///
    /// The ciphertext containing the encapsulated shared secret.
    ///
    /// # Errors
    ///
    /// Returns an error if encapsulation fails.
    pub fn encapsulate(&self, ss: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
        let ct_len = self.level.ciphertext_bytes();
        let mut ct = vec![0u8; ct_len];
        let mut ctlen: u64 = 0;

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_encapsulate(
                ct.as_mut_ptr(),
                &mut ctlen,
                ss.as_ptr(),
                ss.len() as u64,
                pk.as_ptr(),
            )
        };
        check(rc)?;

        ct.truncate(ctlen as usize);
        Ok(ct)
    }

    /// Decapsulate a ciphertext using the recipient's private key.
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext to decapsulate.
    /// * `sk` - The recipient's private key.
    ///
    /// # Returns
    ///
    /// The recovered shared secret.
    ///
    /// # Errors
    ///
    /// Returns an error if decapsulation fails.
    pub fn decapsulate(&self, ct: &[u8], sk: &[u8]) -> Result<SecretVec> {
        let ss_len = self.level.shared_secret_bytes();
        let mut ss = vec![0u8; ss_len];
        let mut sslen: u64 = 0;

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_decapsulate(
                ss.as_mut_ptr(),
                &mut sslen,
                ct.as_ptr(),
                ct.len() as u64,
                sk.as_ptr(),
            )
        };
        check(rc)?;

        ss.truncate(sslen as usize);
        Ok(SecretVec(ss))
    }

    /// Encode a public key to wire format.
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key bytes.
    ///
    /// # Returns
    ///
    /// The wire-encoded public key.
    pub fn pubkey_to_wire(&self, pk: &[u8]) -> Result<Vec<u8>> {
        // Wire format adds a small header; allocate extra space.
        let mut out = vec![0u8; pk.len() + 16];
        let mut out_len: usize = out.len();

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_pubkey_to_wire(
                self.level as i32,
                pk.as_ptr(),
                pk.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        check(rc)?;

        out.truncate(out_len);
        Ok(out)
    }

    /// Decode a public key from wire format.
    ///
    /// # Returns
    ///
    /// `(level, public_key)` decoded from the wire bytes.
    pub fn pubkey_from_wire(wire: &[u8]) -> Result<(SecurityLevel, Vec<u8>)> {
        let mut level: i32 = 0;
        let mut pk = vec![0u8; 512]; // large enough for any level
        let mut pk_len: usize = pk.len();

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_pubkey_from_wire(
                wire.as_ptr(),
                wire.len(),
                &mut level,
                pk.as_mut_ptr(),
                &mut pk_len,
            )
        };
        check(rc)?;

        pk.truncate(pk_len);
        let lvl = SecurityLevel::from_c_int(level).ok_or(KazKemError::InvalidLevel)?;
        Ok((lvl, pk))
    }

    /// Encode a private key to wire format.
    ///
    /// # Arguments
    ///
    /// * `sk` - The private key bytes.
    ///
    /// # Returns
    ///
    /// The wire-encoded private key.
    pub fn privkey_to_wire(&self, sk: &[u8]) -> Result<SecretVec> {
        let mut out = vec![0u8; sk.len() + 16];
        let mut out_len: usize = out.len();

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_privkey_to_wire(
                self.level as i32,
                sk.as_ptr(),
                sk.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        check(rc)?;

        out.truncate(out_len);
        Ok(SecretVec(out))
    }

    /// Decode a private key from wire format.
    ///
    /// # Returns
    ///
    /// `(level, secret_key)` decoded from the wire bytes.
    pub fn privkey_from_wire(wire: &[u8]) -> Result<(SecurityLevel, SecretVec)> {
        let mut level: i32 = 0;
        let mut sk = vec![0u8; 512];
        let mut sk_len: usize = sk.len();

        let _lock = KEM_LOCK.lock().unwrap();
        let rc = unsafe {
            ffi::kaz_kem_privkey_from_wire(
                wire.as_ptr(),
                wire.len(),
                &mut level,
                sk.as_mut_ptr(),
                &mut sk_len,
            )
        };
        check(rc)?;

        sk.truncate(sk_len);
        let lvl = SecurityLevel::from_c_int(level).ok_or(KazKemError::InvalidLevel)?;
        Ok((lvl, SecretVec(sk)))
    }
}

impl Drop for KazKem {
    fn drop(&mut self) {
        let _lock = KEM_LOCK.lock().unwrap();
        unsafe {
            ffi::kaz_kem_cleanup();
        }
    }
}

/// A `Vec<u8>` wrapper that zeroizes its contents on drop.
///
/// Used for secret keys and shared secrets to prevent them from lingering
/// in memory after use.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Returns a slice of the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper, returning the inner `Vec<u8>`.
    ///
    /// **Warning:** The caller is responsible for zeroizing the returned vector.
    pub fn into_inner(self) -> Vec<u8> {
        let mut md = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut md.0)
    }

    /// Returns the length of the secret.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec([REDACTED; {} bytes])", self.0.len())
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = KazKem::version();
        assert!(!v.is_empty());
    }

    #[test]
    fn test_security_level_sizes() {
        assert_eq!(SecurityLevel::L128.public_key_bytes(), 108);
        assert_eq!(SecurityLevel::L128.private_key_bytes(), 34);
        assert_eq!(SecurityLevel::L128.ciphertext_bytes(), 162);
        assert_eq!(SecurityLevel::L128.shared_secret_bytes(), 54);

        assert_eq!(SecurityLevel::L192.public_key_bytes(), 176);
        assert_eq!(SecurityLevel::L256.public_key_bytes(), 236);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", KazKemError::InvalidParam), "invalid parameter");
        assert_eq!(format!("{}", KazKemError::NotInitialized), "library not initialized");
    }
}
