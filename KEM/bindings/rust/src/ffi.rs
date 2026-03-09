//! Raw FFI declarations for the KAZ-KEM C library.

use std::os::raw::{c_char, c_int, c_uchar, c_ulonglong};

// Error codes
pub const KAZ_KEM_SUCCESS: c_int = 0;
pub const KAZ_KEM_ERROR_INVALID_PARAM: c_int = -1;
pub const KAZ_KEM_ERROR_RNG: c_int = -2;
pub const KAZ_KEM_ERROR_MEMORY: c_int = -3;
pub const KAZ_KEM_ERROR_OPENSSL: c_int = -4;
pub const KAZ_KEM_ERROR_MSG_TOO_LARGE: c_int = -5;
pub const KAZ_KEM_ERROR_NOT_INIT: c_int = -6;
pub const KAZ_KEM_ERROR_INVALID_LEVEL: c_int = -7;
pub const KAZ_KEM_ERROR_WIRE_FORMAT: c_int = -8;

extern "C" {
    // Initialization and lifecycle
    pub fn kaz_kem_init(level: c_int) -> c_int;
    pub fn kaz_kem_cleanup();
    pub fn kaz_kem_is_initialized() -> c_int;
    pub fn kaz_kem_version() -> *const c_char;

    // Size accessors
    pub fn kaz_kem_publickey_bytes() -> usize;
    pub fn kaz_kem_privatekey_bytes() -> usize;
    pub fn kaz_kem_ciphertext_bytes() -> usize;
    pub fn kaz_kem_shared_secret_bytes() -> usize;

    // Core KEM operations
    pub fn kaz_kem_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;

    pub fn kaz_kem_encapsulate(
        ct: *mut c_uchar,
        ctlen: *mut c_ulonglong,
        ss: *const c_uchar,
        sslen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;

    pub fn kaz_kem_decapsulate(
        ss: *mut c_uchar,
        sslen: *mut c_ulonglong,
        ct: *const c_uchar,
        ctlen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;

    // Wire encoding
    pub fn kaz_kem_pubkey_to_wire(
        level: c_int,
        pk: *const c_uchar,
        pk_len: usize,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;

    pub fn kaz_kem_pubkey_from_wire(
        wire: *const c_uchar,
        wire_len: usize,
        level: *mut c_int,
        pk: *mut c_uchar,
        pk_len: *mut usize,
    ) -> c_int;

    pub fn kaz_kem_privkey_to_wire(
        level: c_int,
        sk: *const c_uchar,
        sk_len: usize,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;

    pub fn kaz_kem_privkey_from_wire(
        wire: *const c_uchar,
        wire_len: usize,
        level: *mut c_int,
        sk: *mut c_uchar,
        sk_len: *mut usize,
    ) -> c_int;
}
