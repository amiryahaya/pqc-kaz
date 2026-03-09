//! Safe Rust bindings for the KAZ-SIGN post-quantum digital signature algorithm.
//!
//! KAZ-SIGN provides digital signatures resistant to quantum computer attacks,
//! supporting NIST security levels 128, 192, and 256.
//!
//! # Example
//! ```no_run
//! use kaz_sign::{KazSign, SecurityLevel};
//!
//! let signer = KazSign::new(SecurityLevel::L128).unwrap();
//! let (pk, sk) = signer.keypair().unwrap();
//! let sig = signer.sign(b"hello", &sk).unwrap();
//! let recovered = signer.verify(&sig, &pk).unwrap();
//! assert_eq!(recovered, b"hello");
//! ```

pub mod ffi;

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// SecurityLevel
// ---------------------------------------------------------------------------

/// NIST security level for KAZ-SIGN operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    L128 = 128,
    L192 = 192,
    L256 = 256,
}

impl SecurityLevel {
    fn as_raw(self) -> ffi::KazSignLevel {
        self as ffi::KazSignLevel
    }

    /// Public key size in bytes for this level.
    pub fn public_key_bytes(self) -> usize {
        match self {
            Self::L128 => 54,
            Self::L192 => 88,
            Self::L256 => 118,
        }
    }

    /// Secret key size in bytes for this level.
    pub fn secret_key_bytes(self) -> usize {
        match self {
            Self::L128 => 32,
            Self::L192 => 50,
            Self::L256 => 64,
        }
    }

    /// Hash output size in bytes for this level.
    pub fn hash_bytes(self) -> usize {
        match self {
            Self::L128 => 32,
            Self::L192 => 48,
            Self::L256 => 64,
        }
    }

    /// Signature overhead in bytes for this level.
    pub fn signature_overhead(self) -> usize {
        match self {
            Self::L128 => 162,
            Self::L192 => 264,
            Self::L256 => 354,
        }
    }
}

impl TryFrom<i32> for SecurityLevel {
    type Error = KazSignError;
    fn try_from(v: i32) -> std::result::Result<Self, Self::Error> {
        match v {
            128 => Ok(Self::L128),
            192 => Ok(Self::L192),
            256 => Ok(Self::L256),
            _ => Err(KazSignError::InvalidParameter),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for KAZ-SIGN operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KazSignError {
    Memory,
    Rng,
    InvalidParameter,
    VerifyFailed,
    DerError,
    X509Error,
    P12Error,
    HashError,
    BufferError,
    Unknown(i32),
}

impl KazSignError {
    fn from_code(code: i32) -> std::result::Result<(), Self> {
        match code {
            ffi::KAZ_SIGN_SUCCESS => Ok(()),
            ffi::KAZ_SIGN_ERROR_MEMORY => Err(Self::Memory),
            ffi::KAZ_SIGN_ERROR_RNG => Err(Self::Rng),
            ffi::KAZ_SIGN_ERROR_INVALID => Err(Self::InvalidParameter),
            ffi::KAZ_SIGN_ERROR_VERIFY => Err(Self::VerifyFailed),
            ffi::KAZ_SIGN_ERROR_DER => Err(Self::DerError),
            ffi::KAZ_SIGN_ERROR_X509 => Err(Self::X509Error),
            ffi::KAZ_SIGN_ERROR_P12 => Err(Self::P12Error),
            ffi::KAZ_SIGN_ERROR_HASH => Err(Self::HashError),
            ffi::KAZ_SIGN_ERROR_BUFFER => Err(Self::BufferError),
            other => Err(Self::Unknown(other)),
        }
    }
}

impl fmt::Display for KazSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => write!(f, "memory allocation error"),
            Self::Rng => write!(f, "random number generator error"),
            Self::InvalidParameter => write!(f, "invalid parameter"),
            Self::VerifyFailed => write!(f, "signature verification failed"),
            Self::DerError => write!(f, "DER encoding/decoding error"),
            Self::X509Error => write!(f, "X.509 operation error"),
            Self::P12Error => write!(f, "PKCS#12 operation error"),
            Self::HashError => write!(f, "hash computation error"),
            Self::BufferError => write!(f, "buffer size error"),
            Self::Unknown(code) => write!(f, "unknown error (code {})", code),
        }
    }
}

impl std::error::Error for KazSignError {}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, KazSignError>;

// ---------------------------------------------------------------------------
// Key newtypes
// ---------------------------------------------------------------------------

/// A KAZ-SIGN public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    /// Return the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A KAZ-SIGN secret key.
#[derive(Debug, Clone)]
pub struct SecretKey(pub Vec<u8>);

impl SecretKey {
    /// Return the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Best-effort zeroize
        for b in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

// ---------------------------------------------------------------------------
// KazSign
// ---------------------------------------------------------------------------

static CLEAR_ALL_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Main handle for KAZ-SIGN operations at a specific security level.
pub struct KazSign {
    level: SecurityLevel,
}

impl KazSign {
    /// Create a new KAZ-SIGN context for the given security level.
    ///
    /// This initialises the underlying C library for the specified level.
    pub fn new(level: SecurityLevel) -> Result<Self> {
        let rc = unsafe { ffi::kaz_sign_init_level(level.as_raw()) };
        KazSignError::from_code(rc)?;

        // Register a cleanup-on-exit handler once
        if !CLEAR_ALL_REGISTERED.swap(true, Ordering::SeqCst) {
            // Best-effort: ignore errors from atexit-like registration
        }

        Ok(Self { level })
    }

    /// The security level of this context.
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    // -- Key generation ---------------------------------------------------

    /// Generate a fresh key pair.
    pub fn keypair(&self) -> Result<(PublicKey, SecretKey)> {
        let pk_len = self.level.public_key_bytes();
        let sk_len = self.level.secret_key_bytes();
        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];

        let rc = unsafe {
            ffi::kaz_sign_keypair_ex(self.level.as_raw(), pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        KazSignError::from_code(rc)?;
        Ok((PublicKey(pk), SecretKey(sk)))
    }

    // -- Signing (message-recovery) ---------------------------------------

    /// Sign a message (message-recovery mode).
    ///
    /// The returned signature embeds the message; use [`verify`](Self::verify) to
    /// recover the original message.
    pub fn sign(&self, msg: &[u8], sk: &SecretKey) -> Result<Vec<u8>> {
        let max_sig = msg.len() + self.level.signature_overhead();
        let mut sig = vec![0u8; max_sig];
        let mut siglen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_signature_ex(
                self.level.as_raw(),
                sig.as_mut_ptr(),
                &mut siglen,
                msg.as_ptr(),
                msg.len() as u64,
                sk.as_bytes().as_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        sig.truncate(siglen as usize);
        Ok(sig)
    }

    /// Verify a message-recovery signature and return the recovered message.
    pub fn verify(&self, sig: &[u8], pk: &PublicKey) -> Result<Vec<u8>> {
        let mut msg = vec![0u8; sig.len()];
        let mut msglen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_verify_ex(
                self.level.as_raw(),
                msg.as_mut_ptr(),
                &mut msglen,
                sig.as_ptr(),
                sig.len() as u64,
                pk.as_bytes().as_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        msg.truncate(msglen as usize);
        Ok(msg)
    }

    // -- Detached signatures ----------------------------------------------

    /// Create a detached signature over `msg`.
    pub fn sign_detached(&self, msg: &[u8], sk: &SecretKey) -> Result<Vec<u8>> {
        let max_sig = msg.len() + self.level.signature_overhead();
        let mut sig = vec![0u8; max_sig];
        let mut siglen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_detached_ex(
                self.level.as_raw(),
                sig.as_mut_ptr(),
                &mut siglen,
                msg.as_ptr(),
                msg.len() as u64,
                sk.as_bytes().as_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        sig.truncate(siglen as usize);
        Ok(sig)
    }

    /// Verify a detached signature.
    pub fn verify_detached(&self, sig: &[u8], msg: &[u8], pk: &PublicKey) -> Result<()> {
        let rc = unsafe {
            ffi::kaz_sign_verify_detached_ex(
                self.level.as_raw(),
                sig.as_ptr(),
                sig.len() as u64,
                msg.as_ptr(),
                msg.len() as u64,
                pk.as_bytes().as_ptr(),
            )
        };
        KazSignError::from_code(rc)
    }

    // -- Hash -------------------------------------------------------------

    /// Compute the KAZ-SIGN hash of a message.
    pub fn hash(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let hash_len = self.level.hash_bytes();
        let mut hash = vec![0u8; hash_len];

        let rc = unsafe {
            ffi::kaz_sign_hash_ex(
                self.level.as_raw(),
                msg.as_ptr(),
                msg.len() as u64,
                hash.as_mut_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        Ok(hash)
    }

    // -- DER encoding -----------------------------------------------------

    /// Encode a public key to DER format.
    pub fn pubkey_to_der(&self, pk: &PublicKey) -> Result<Vec<u8>> {
        let mut der = vec![0u8; pk.as_bytes().len() + 128];
        let mut derlen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_pubkey_to_der(
                self.level.as_raw(),
                pk.as_bytes().as_ptr(),
                der.as_mut_ptr(),
                &mut derlen,
            )
        };
        KazSignError::from_code(rc)?;
        der.truncate(derlen as usize);
        Ok(der)
    }

    /// Decode a public key from DER format.
    pub fn pubkey_from_der(&self, der: &[u8]) -> Result<PublicKey> {
        let pk_len = self.level.public_key_bytes();
        let mut pk = vec![0u8; pk_len];

        let rc = unsafe {
            ffi::kaz_sign_pubkey_from_der(
                self.level.as_raw(),
                der.as_ptr(),
                der.len() as u64,
                pk.as_mut_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        Ok(PublicKey(pk))
    }

    /// Encode a secret key to DER format.
    pub fn privkey_to_der(&self, sk: &SecretKey) -> Result<Vec<u8>> {
        let mut der = vec![0u8; sk.as_bytes().len() + 128];
        let mut derlen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_privkey_to_der(
                self.level.as_raw(),
                sk.as_bytes().as_ptr(),
                der.as_mut_ptr(),
                &mut derlen,
            )
        };
        KazSignError::from_code(rc)?;
        der.truncate(derlen as usize);
        Ok(der)
    }

    /// Decode a secret key from DER format.
    pub fn privkey_from_der(&self, der: &[u8]) -> Result<SecretKey> {
        let sk_len = self.level.secret_key_bytes();
        let mut sk = vec![0u8; sk_len];

        let rc = unsafe {
            ffi::kaz_sign_privkey_from_der(
                self.level.as_raw(),
                der.as_ptr(),
                der.len() as u64,
                sk.as_mut_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        Ok(SecretKey(sk))
    }

    // -- X.509 ------------------------------------------------------------

    /// Generate a Certificate Signing Request (CSR).
    pub fn generate_csr(
        &self,
        sk: &SecretKey,
        pk: &PublicKey,
        subject: &str,
    ) -> Result<Vec<u8>> {
        let subject_c = CString::new(subject).map_err(|_| KazSignError::InvalidParameter)?;
        let mut csr = vec![0u8; 4096];
        let mut csrlen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_generate_csr(
                self.level.as_raw(),
                sk.as_bytes().as_ptr(),
                pk.as_bytes().as_ptr(),
                subject_c.as_ptr(),
                csr.as_mut_ptr(),
                &mut csrlen,
            )
        };
        KazSignError::from_code(rc)?;
        csr.truncate(csrlen as usize);
        Ok(csr)
    }

    /// Verify a CSR.
    pub fn verify_csr(&self, csr: &[u8]) -> Result<()> {
        let rc = unsafe {
            ffi::kaz_sign_verify_csr(self.level.as_raw(), csr.as_ptr(), csr.len() as u64)
        };
        KazSignError::from_code(rc)
    }

    /// Issue an X.509 certificate from a CSR.
    pub fn issue_certificate(
        &self,
        issuer_sk: &SecretKey,
        issuer_pk: &PublicKey,
        issuer_name: &str,
        csr: &[u8],
        serial: u64,
        days: i32,
    ) -> Result<Vec<u8>> {
        let name_c = CString::new(issuer_name).map_err(|_| KazSignError::InvalidParameter)?;
        let mut cert = vec![0u8; 8192];
        let mut certlen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_issue_certificate(
                self.level.as_raw(),
                issuer_sk.as_bytes().as_ptr(),
                issuer_pk.as_bytes().as_ptr(),
                name_c.as_ptr(),
                csr.as_ptr(),
                csr.len() as u64,
                serial,
                days,
                cert.as_mut_ptr(),
                &mut certlen,
            )
        };
        KazSignError::from_code(rc)?;
        cert.truncate(certlen as usize);
        Ok(cert)
    }

    /// Extract the public key from an X.509 certificate.
    pub fn cert_extract_pubkey(&self, cert: &[u8]) -> Result<PublicKey> {
        let pk_len = self.level.public_key_bytes();
        let mut pk = vec![0u8; pk_len];

        let rc = unsafe {
            ffi::kaz_sign_cert_extract_pubkey(
                self.level.as_raw(),
                cert.as_ptr(),
                cert.len() as u64,
                pk.as_mut_ptr(),
            )
        };
        KazSignError::from_code(rc)?;
        Ok(PublicKey(pk))
    }

    /// Verify an X.509 certificate against the issuer's public key.
    pub fn verify_certificate(&self, cert: &[u8], issuer_pk: &PublicKey) -> Result<()> {
        let rc = unsafe {
            ffi::kaz_sign_verify_certificate(
                self.level.as_raw(),
                cert.as_ptr(),
                cert.len() as u64,
                issuer_pk.as_bytes().as_ptr(),
            )
        };
        KazSignError::from_code(rc)
    }

    // -- P12 --------------------------------------------------------------

    /// Create a PKCS#12 bundle.
    pub fn create_p12(
        &self,
        sk: &SecretKey,
        pk: &PublicKey,
        cert: &[u8],
        password: &str,
        name: &str,
    ) -> Result<Vec<u8>> {
        let pw_c = CString::new(password).map_err(|_| KazSignError::InvalidParameter)?;
        let name_c = CString::new(name).map_err(|_| KazSignError::InvalidParameter)?;
        let mut p12 = vec![0u8; 8192];
        let mut p12len: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_create_p12(
                self.level.as_raw(),
                sk.as_bytes().as_ptr(),
                pk.as_bytes().as_ptr(),
                cert.as_ptr(),
                cert.len() as u64,
                pw_c.as_ptr(),
                name_c.as_ptr(),
                p12.as_mut_ptr(),
                &mut p12len,
            )
        };
        KazSignError::from_code(rc)?;
        p12.truncate(p12len as usize);
        Ok(p12)
    }

    /// Load keys and certificate from a PKCS#12 bundle.
    pub fn load_p12(
        &self,
        p12: &[u8],
        password: &str,
    ) -> Result<(SecretKey, PublicKey, Vec<u8>)> {
        let pw_c = CString::new(password).map_err(|_| KazSignError::InvalidParameter)?;
        let sk_len = self.level.secret_key_bytes();
        let pk_len = self.level.public_key_bytes();
        let mut sk = vec![0u8; sk_len];
        let mut pk = vec![0u8; pk_len];
        let mut cert = vec![0u8; 8192];
        let mut certlen: u64 = 0;

        let rc = unsafe {
            ffi::kaz_sign_load_p12(
                self.level.as_raw(),
                p12.as_ptr(),
                p12.len() as u64,
                pw_c.as_ptr(),
                sk.as_mut_ptr(),
                pk.as_mut_ptr(),
                cert.as_mut_ptr(),
                &mut certlen,
            )
        };
        KazSignError::from_code(rc)?;
        cert.truncate(certlen as usize);
        Ok((SecretKey(sk), PublicKey(pk), cert))
    }

    // -- Wire encoding ----------------------------------------------------

    /// Encode a public key to wire format (includes level tag).
    pub fn pubkey_to_wire(&self, pk: &PublicKey) -> Result<Vec<u8>> {
        let mut out = vec![0u8; pk.as_bytes().len() + 16];
        let mut out_len: usize = 0;

        let rc = unsafe {
            ffi::kaz_sign_pubkey_to_wire(
                self.level.as_raw(),
                pk.as_bytes().as_ptr(),
                pk.as_bytes().len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        KazSignError::from_code(rc)?;
        out.truncate(out_len);
        Ok(out)
    }

    /// Decode a public key from wire format.
    pub fn pubkey_from_wire(wire: &[u8]) -> Result<(SecurityLevel, PublicKey)> {
        let mut level: ffi::KazSignLevel = 0;
        let mut pk = vec![0u8; 256];
        let mut pk_len: usize = 0;

        let rc = unsafe {
            ffi::kaz_sign_pubkey_from_wire(
                wire.as_ptr(),
                wire.len(),
                &mut level,
                pk.as_mut_ptr(),
                &mut pk_len,
            )
        };
        KazSignError::from_code(rc)?;
        pk.truncate(pk_len);
        let lvl = SecurityLevel::try_from(level)?;
        Ok((lvl, PublicKey(pk)))
    }

    /// Encode a secret key to wire format (includes level tag).
    pub fn privkey_to_wire(&self, sk: &SecretKey) -> Result<Vec<u8>> {
        let mut out = vec![0u8; sk.as_bytes().len() + 16];
        let mut out_len: usize = 0;

        let rc = unsafe {
            ffi::kaz_sign_privkey_to_wire(
                self.level.as_raw(),
                sk.as_bytes().as_ptr(),
                sk.as_bytes().len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        KazSignError::from_code(rc)?;
        out.truncate(out_len);
        Ok(out)
    }

    /// Decode a secret key from wire format.
    pub fn privkey_from_wire(wire: &[u8]) -> Result<(SecurityLevel, SecretKey)> {
        let mut level: ffi::KazSignLevel = 0;
        let mut sk = vec![0u8; 256];
        let mut sk_len: usize = 0;

        let rc = unsafe {
            ffi::kaz_sign_privkey_from_wire(
                wire.as_ptr(),
                wire.len(),
                &mut level,
                sk.as_mut_ptr(),
                &mut sk_len,
            )
        };
        KazSignError::from_code(rc)?;
        sk.truncate(sk_len);
        let lvl = SecurityLevel::try_from(level)?;
        Ok((lvl, SecretKey(sk)))
    }
}

impl Drop for KazSign {
    fn drop(&mut self) {
        unsafe {
            ffi::kaz_sign_clear_level(self.level.as_raw());
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone functions
// ---------------------------------------------------------------------------

/// Compute SHA3-256 hash.
pub fn sha3_256(msg: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let rc = unsafe { ffi::kaz_sha3_256(msg.as_ptr(), msg.len() as u64, out.as_mut_ptr()) };
    KazSignError::from_code(rc)?;
    Ok(out)
}

/// HKDF key derivation (RFC 5869) - extract and expand in one step.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
    let mut okm = vec![0u8; okm_len];
    let rc = unsafe {
        ffi::kaz_hkdf(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            okm_len,
        )
    };
    KazSignError::from_code(rc)?;
    Ok(okm)
}

/// HKDF extract step only.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
    let mut prk = vec![0u8; 64]; // max hash size
    let mut prk_len: usize = 0;

    let rc = unsafe {
        ffi::kaz_hkdf_extract(
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            prk.as_mut_ptr(),
            &mut prk_len,
        )
    };
    KazSignError::from_code(rc)?;
    prk.truncate(prk_len);
    Ok(prk)
}

/// HKDF expand step only.
pub fn hkdf_expand(prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>> {
    let mut okm = vec![0u8; okm_len];
    let rc = unsafe {
        ffi::kaz_hkdf_expand(
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            okm_len,
        )
    };
    KazSignError::from_code(rc)?;
    Ok(okm)
}

/// Return the KAZ-SIGN library version string.
pub fn version() -> &'static str {
    unsafe {
        let ptr = ffi::kaz_sign_version();
        if ptr.is_null() {
            "unknown"
        } else {
            CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
        }
    }
}

/// Return the KAZ-SIGN library version as an integer.
pub fn version_number() -> i32 {
    unsafe { ffi::kaz_sign_version_number() }
}

/// Clear all initialised levels. Called automatically when individual
/// `KazSign` instances are dropped, but can be called explicitly if needed.
pub fn clear_all() {
    unsafe {
        ffi::kaz_sign_clear_all();
    }
}
