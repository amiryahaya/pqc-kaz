//! Raw FFI declarations for the KAZ-SIGN C library.

use std::os::raw::{c_char, c_int, c_uchar, c_ulonglong};

/// Security level enum matching `kaz_sign_level_t`.
pub type KazSignLevel = c_int;

pub const KAZ_LEVEL_128: KazSignLevel = 128;
pub const KAZ_LEVEL_192: KazSignLevel = 192;
pub const KAZ_LEVEL_256: KazSignLevel = 256;

/// Error codes.
pub const KAZ_SIGN_SUCCESS: c_int = 0;
pub const KAZ_SIGN_ERROR_MEMORY: c_int = -1;
pub const KAZ_SIGN_ERROR_RNG: c_int = -2;
pub const KAZ_SIGN_ERROR_INVALID: c_int = -3;
pub const KAZ_SIGN_ERROR_VERIFY: c_int = -4;
pub const KAZ_SIGN_ERROR_DER: c_int = -5;
pub const KAZ_SIGN_ERROR_X509: c_int = -6;
pub const KAZ_SIGN_ERROR_P12: c_int = -7;
pub const KAZ_SIGN_ERROR_HASH: c_int = -8;
pub const KAZ_SIGN_ERROR_BUFFER: c_int = -9;

/// Level parameters struct matching `kaz_sign_level_params_t`.
#[repr(C)]
#[derive(Debug)]
pub struct KazSignLevelParams {
    pub level: c_int,
    pub algorithm_name: *const c_char,
    pub secret_key_bytes: usize,
    pub public_key_bytes: usize,
    pub hash_bytes: usize,
    pub signature_overhead: usize,
    pub v_bytes: usize,
    pub s_bytes: usize,
    pub t_bytes: usize,
    pub s1_bytes: usize,
    pub s2_bytes: usize,
    pub s3_bytes: usize,
}

extern "C" {
    // Level params
    pub fn kaz_sign_get_level_params(level: KazSignLevel) -> *const KazSignLevelParams;

    // Init/cleanup
    pub fn kaz_sign_init_level(level: KazSignLevel) -> c_int;
    pub fn kaz_sign_clear_level(level: KazSignLevel);
    pub fn kaz_sign_clear_all();

    // Core signing (runtime level)
    pub fn kaz_sign_keypair_ex(
        level: KazSignLevel,
        pk: *mut c_uchar,
        sk: *mut c_uchar,
    ) -> c_int;

    pub fn kaz_sign_signature_ex(
        level: KazSignLevel,
        sig: *mut c_uchar,
        siglen: *mut c_ulonglong,
        msg: *const c_uchar,
        msglen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;

    pub fn kaz_sign_verify_ex(
        level: KazSignLevel,
        msg: *mut c_uchar,
        msglen: *mut c_ulonglong,
        sig: *const c_uchar,
        siglen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;

    pub fn kaz_sign_hash_ex(
        level: KazSignLevel,
        msg: *const c_uchar,
        msglen: c_ulonglong,
        hash: *mut c_uchar,
    ) -> c_int;

    // Detached signatures
    pub fn kaz_sign_detached_ex(
        level: KazSignLevel,
        sig: *mut c_uchar,
        siglen: *mut c_ulonglong,
        msg: *const c_uchar,
        msglen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;

    pub fn kaz_sign_verify_detached_ex(
        level: KazSignLevel,
        sig: *const c_uchar,
        siglen: c_ulonglong,
        msg: *const c_uchar,
        msglen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;

    // SHA3
    pub fn kaz_sha3_256(
        msg: *const c_uchar,
        msglen: c_ulonglong,
        out: *mut c_uchar,
    ) -> c_int;

    // DER encoding
    pub fn kaz_sign_pubkey_to_der(
        level: KazSignLevel,
        pk: *const c_uchar,
        der: *mut c_uchar,
        derlen: *mut c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_pubkey_from_der(
        level: KazSignLevel,
        der: *const c_uchar,
        derlen: c_ulonglong,
        pk: *mut c_uchar,
    ) -> c_int;

    pub fn kaz_sign_privkey_to_der(
        level: KazSignLevel,
        sk: *const c_uchar,
        der: *mut c_uchar,
        derlen: *mut c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_privkey_from_der(
        level: KazSignLevel,
        der: *const c_uchar,
        derlen: c_ulonglong,
        sk: *mut c_uchar,
    ) -> c_int;

    // X.509
    pub fn kaz_sign_generate_csr(
        level: KazSignLevel,
        sk: *const c_uchar,
        pk: *const c_uchar,
        subject: *const c_char,
        csr: *mut c_uchar,
        csrlen: *mut c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_verify_csr(
        level: KazSignLevel,
        csr: *const c_uchar,
        csrlen: c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_issue_certificate(
        level: KazSignLevel,
        issuer_sk: *const c_uchar,
        issuer_pk: *const c_uchar,
        issuer_name: *const c_char,
        csr: *const c_uchar,
        csrlen: c_ulonglong,
        serial: c_ulonglong,
        days: c_int,
        cert: *mut c_uchar,
        certlen: *mut c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_cert_extract_pubkey(
        level: KazSignLevel,
        cert: *const c_uchar,
        certlen: c_ulonglong,
        pk: *mut c_uchar,
    ) -> c_int;

    pub fn kaz_sign_verify_certificate(
        level: KazSignLevel,
        cert: *const c_uchar,
        certlen: c_ulonglong,
        issuer_pk: *const c_uchar,
    ) -> c_int;

    // P12
    pub fn kaz_sign_create_p12(
        level: KazSignLevel,
        sk: *const c_uchar,
        pk: *const c_uchar,
        cert: *const c_uchar,
        certlen: c_ulonglong,
        password: *const c_char,
        name: *const c_char,
        p12: *mut c_uchar,
        p12len: *mut c_ulonglong,
    ) -> c_int;

    pub fn kaz_sign_load_p12(
        level: KazSignLevel,
        p12: *const c_uchar,
        p12len: c_ulonglong,
        password: *const c_char,
        sk: *mut c_uchar,
        pk: *mut c_uchar,
        cert: *mut c_uchar,
        certlen: *mut c_ulonglong,
    ) -> c_int;

    // Wire encoding
    pub fn kaz_sign_pubkey_to_wire(
        level: KazSignLevel,
        pk: *const c_uchar,
        pk_len: usize,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;

    pub fn kaz_sign_pubkey_from_wire(
        wire: *const c_uchar,
        wire_len: usize,
        level: *mut KazSignLevel,
        pk: *mut c_uchar,
        pk_len: *mut usize,
    ) -> c_int;

    pub fn kaz_sign_privkey_to_wire(
        level: KazSignLevel,
        sk: *const c_uchar,
        sk_len: usize,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;

    pub fn kaz_sign_privkey_from_wire(
        wire: *const c_uchar,
        wire_len: usize,
        level: *mut KazSignLevel,
        sk: *mut c_uchar,
        sk_len: *mut usize,
    ) -> c_int;

    // Version
    pub fn kaz_sign_version() -> *const c_char;
    pub fn kaz_sign_version_number() -> c_int;

    // HKDF
    pub fn kaz_hkdf(
        salt: *const c_uchar,
        salt_len: usize,
        ikm: *const c_uchar,
        ikm_len: usize,
        info: *const c_uchar,
        info_len: usize,
        okm: *mut c_uchar,
        okm_len: usize,
    ) -> c_int;

    pub fn kaz_hkdf_extract(
        salt: *const c_uchar,
        salt_len: usize,
        ikm: *const c_uchar,
        ikm_len: usize,
        prk: *mut c_uchar,
        prk_len: *mut usize,
    ) -> c_int;

    pub fn kaz_hkdf_expand(
        prk: *const c_uchar,
        prk_len: usize,
        info: *const c_uchar,
        info_len: usize,
        okm: *mut c_uchar,
        okm_len: usize,
    ) -> c_int;
}
