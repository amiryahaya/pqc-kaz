//! Integration tests for kaz-kem.
//!
//! Because the underlying C library uses global state (single active security
//! level), all tests that call into the library must be serialized. We use a
//! shared mutex and each test re-initializes the library as needed.

use std::sync::Mutex;

use kaz_kem::{KazKem, KazKemError, SecurityLevel};

/// Global test lock to serialize access to the C library's global state.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_init_and_version() {
    let _guard = TEST_LOCK.lock().unwrap();

    let kem = KazKem::new(SecurityLevel::L128).expect("init failed");
    let version = KazKem::version();
    assert!(!version.is_empty(), "version string should not be empty");
    assert!(KazKem::is_initialized(), "library should be initialized");
    drop(kem);
}

#[test]
fn test_keypair_generation() {
    let _guard = TEST_LOCK.lock().unwrap();

    let kem = KazKem::new(SecurityLevel::L128).expect("init failed");
    let (pk, sk) = kem.keypair().expect("keypair failed");

    assert_eq!(pk.len(), SecurityLevel::L128.public_key_bytes());
    assert_eq!(sk.len(), SecurityLevel::L128.private_key_bytes());

    // Keys should not be all zeros
    assert!(pk.iter().any(|&b| b != 0), "public key should not be all zeros");
    assert!(
        sk.as_bytes().iter().any(|&b| b != 0),
        "secret key should not be all zeros"
    );
}

#[test]
fn test_encapsulate_decapsulate_roundtrip() {
    let _guard = TEST_LOCK.lock().unwrap();

    let kem = KazKem::new(SecurityLevel::L128).expect("init failed");
    let (pk, sk) = kem.keypair().expect("keypair failed");

    // Create a shared secret of the correct size
    let ss_len = kem.shared_secret_bytes();
    let shared_secret: Vec<u8> = (0..ss_len).map(|i| (i & 0xFF) as u8).collect();

    // Encapsulate
    let ct = kem
        .encapsulate(&shared_secret, &pk)
        .expect("encapsulate failed");
    assert!(!ct.is_empty(), "ciphertext should not be empty");

    // Decapsulate
    let recovered = kem.decapsulate(&ct, sk.as_bytes()).expect("decapsulate failed");

    assert_eq!(
        recovered.as_bytes(),
        shared_secret.as_slice(),
        "recovered shared secret should match original"
    );
}

#[test]
fn test_wrong_key_decapsulation() {
    let _guard = TEST_LOCK.lock().unwrap();

    let kem = KazKem::new(SecurityLevel::L128).expect("init failed");

    // Generate two key pairs
    let (pk1, _sk1) = kem.keypair().expect("keypair 1 failed");
    let (_pk2, sk2) = kem.keypair().expect("keypair 2 failed");

    // Encapsulate with pk1
    let ss_len = kem.shared_secret_bytes();
    let shared_secret: Vec<u8> = (0..ss_len).map(|i| (i & 0xFF) as u8).collect();
    let ct = kem
        .encapsulate(&shared_secret, &pk1)
        .expect("encapsulate failed");

    // Try to decapsulate with sk2 (wrong key)
    let result = kem.decapsulate(&ct, sk2.as_bytes());

    // Should either fail or produce a different shared secret
    match result {
        Err(_) => {
            // Expected: decapsulation error with wrong key
        }
        Ok(recovered) => {
            // Some KEM schemes return garbage rather than error
            assert_ne!(
                recovered.as_bytes(),
                shared_secret.as_slice(),
                "decapsulation with wrong key should not produce the correct shared secret"
            );
        }
    }
}

#[test]
fn test_size_accessors_match_constants() {
    let _guard = TEST_LOCK.lock().unwrap();

    let kem = KazKem::new(SecurityLevel::L128).expect("init failed");

    assert_eq!(kem.public_key_bytes(), SecurityLevel::L128.public_key_bytes());
    assert_eq!(kem.private_key_bytes(), SecurityLevel::L128.private_key_bytes());
    assert_eq!(kem.ciphertext_bytes(), SecurityLevel::L128.ciphertext_bytes());
    assert_eq!(kem.shared_secret_bytes(), SecurityLevel::L128.shared_secret_bytes());
}

#[test]
fn test_error_mapping() {
    // This test does not use the C library, so no lock needed.
    let err = KazKemError::InvalidParam;
    let display = format!("{}", err);
    assert_eq!(display, "invalid parameter");

    // Verify it implements std::error::Error
    let _: &dyn std::error::Error = &err;
}
