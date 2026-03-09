// The underlying C library is not thread-safe.
// Run tests single-threaded: cargo test -- --test-threads=1

use kaz_sign::{sha3_256, version, KazSign, KazSignError, SecurityLevel};

fn make_signer() -> KazSign {
    KazSign::new(SecurityLevel::L128).expect("init level 128")
}

#[test]
fn test_keypair() {
    let signer = make_signer();
    let (pk, sk) = signer.keypair().expect("keypair");
    assert_eq!(pk.as_bytes().len(), SecurityLevel::L128.public_key_bytes());
    assert_eq!(sk.as_bytes().len(), SecurityLevel::L128.secret_key_bytes());
}

#[test]
fn test_sign_verify_roundtrip() {
    let signer = make_signer();
    let (pk, sk) = signer.keypair().expect("keypair");

    let msg = b"Hello, post-quantum world!";
    let sig = signer.sign(msg, &sk).expect("sign");
    assert!(!sig.is_empty());

    let recovered = signer.verify(&sig, &pk).expect("verify");
    assert_eq!(recovered, msg);
}

#[test]
fn test_detached_sign_verify() {
    let signer = make_signer();
    let (pk, sk) = signer.keypair().expect("keypair");

    let msg = b"detached signature test";
    let sig = signer.sign_detached(msg, &sk).expect("sign_detached");
    assert!(!sig.is_empty());

    signer
        .verify_detached(&sig, msg, &pk)
        .expect("verify_detached");
}

#[test]
fn test_hash() {
    let signer = make_signer();
    let hash = signer.hash(b"test message").expect("hash");
    assert_eq!(hash.len(), SecurityLevel::L128.hash_bytes());

    // Same input should produce same hash
    let hash2 = signer.hash(b"test message").expect("hash2");
    assert_eq!(hash, hash2);

    // Different input should produce different hash
    let hash3 = signer.hash(b"different message").expect("hash3");
    assert_ne!(hash, hash3);
}

#[test]
fn test_sha3_256() {
    let hash = sha3_256(b"hello").expect("sha3_256");
    assert_eq!(hash.len(), 32);

    // Deterministic
    let hash2 = sha3_256(b"hello").expect("sha3_256 again");
    assert_eq!(hash, hash2);

    // Different input
    let hash3 = sha3_256(b"world").expect("sha3_256 different");
    assert_ne!(hash, hash3);
}

#[test]
fn test_wrong_key_verify_fails() {
    let signer = make_signer();
    let (_pk1, sk1) = signer.keypair().expect("keypair1");
    let (pk2, _sk2) = signer.keypair().expect("keypair2");

    let msg = b"signed with key 1";
    let sig = signer.sign(msg, &sk1).expect("sign");

    // Verify with wrong public key should fail
    let result = signer.verify(&sig, &pk2);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), KazSignError::VerifyFailed);
}

#[test]
fn test_wrong_key_detached_verify_fails() {
    let signer = make_signer();
    let (_pk1, sk1) = signer.keypair().expect("keypair1");
    let (pk2, _sk2) = signer.keypair().expect("keypair2");

    let msg = b"detached signed with key 1";
    let sig = signer.sign_detached(msg, &sk1).expect("sign_detached");

    let result = signer.verify_detached(&sig, msg, &pk2);
    assert!(result.is_err());
}

#[test]
fn test_version() {
    let v = version();
    assert!(!v.is_empty());
}

#[test]
fn test_empty_message() {
    let signer = make_signer();
    let (pk, sk) = signer.keypair().expect("keypair");

    let sig = signer.sign(b"", &sk).expect("sign empty");
    let recovered = signer.verify(&sig, &pk).expect("verify empty");
    assert_eq!(recovered, b"");
}

#[test]
fn test_security_level_sizes() {
    assert_eq!(SecurityLevel::L128.public_key_bytes(), 54);
    assert_eq!(SecurityLevel::L128.secret_key_bytes(), 32);
    assert_eq!(SecurityLevel::L128.hash_bytes(), 32);

    assert_eq!(SecurityLevel::L192.public_key_bytes(), 88);
    assert_eq!(SecurityLevel::L192.secret_key_bytes(), 50);
    assert_eq!(SecurityLevel::L192.hash_bytes(), 48);

    assert_eq!(SecurityLevel::L256.public_key_bytes(), 118);
    assert_eq!(SecurityLevel::L256.secret_key_bytes(), 64);
    assert_eq!(SecurityLevel::L256.hash_bytes(), 64);
}
