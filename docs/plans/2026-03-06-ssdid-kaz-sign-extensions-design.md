# KAZ-Sign SSDID Extensions Design (v3.0.0)

## Overview

Extend PQC-KAZ/SIGN C library for full SSDID protocol compatibility. This is a breaking change from v2.1 to v3.0 due to SHA-2 to SHA-3 migration.

Reference documents:
- 09.SSDID-Crypto-Specification.md
- 10.SSDID-KAZ-Sign-C-Library-Extension.md

## Breaking Change: SHA-3 Migration

Replace all SHA-2 usage with SHA-3 family, matched to security level:

| Level | Old Hash | New Hash | Digest Size |
|-------|----------|----------|-------------|
| 128 | SHA-256 | SHA3-256 | 32 bytes |
| 192 | SHA-384 | SHA3-384 | 48 bytes |
| 256 | SHA-512 | SHA3-512 | 64 bytes |

Affected files:
- `sign.c` — core hashing in sign/verify/hash functions
- `kdf.c` — HKDF PRF (SHA-512 -> SHA3-512)

All existing signatures and KAT vectors are invalidated.

## Phase 1: SHA3 Migration + Detached Signing

### SHA3 in Core

Replace `EVP_sha256()`/`EVP_sha384()`/`EVP_sha512()` with `EVP_sha3_256()`/`EVP_sha3_384()`/`EVP_sha3_512()` in sign.c and kdf.c.

Update level params:
- Algorithm names: "KAZ-SIGN-128-SHA3", "KAZ-SIGN-192-SHA3", "KAZ-SIGN-256-SHA3"

### Standalone SHA3 API (`src/internal/sha3.c`)

Expose SHA3-256 for mobile SDKs (iOS lacks native SHA3-256):

```c
int kaz_sha3_256(const unsigned char *data, unsigned long long datalen, unsigned char *digest);

// Incremental API
int kaz_sha3_256_init(kaz_sha3_ctx_t **ctx);
int kaz_sha3_256_update(kaz_sha3_ctx_t *ctx, const unsigned char *data, unsigned long long datalen);
int kaz_sha3_256_final(kaz_sha3_ctx_t *ctx, unsigned char *digest);
void kaz_sha3_256_free(kaz_sha3_ctx_t *ctx);
```

### Detached Signing (`src/internal/detached.c`)

Pre-hashing uses level-matched SHA3 (not always SHA3-256):

```c
int kaz_sign_detached_ex(level, sig, siglen, data, datalen, sk);
int kaz_sign_verify_detached_ex(level, data, datalen, sig, siglen, pk);
int kaz_sign_detached_prehashed_ex(level, sig, siglen, digest, sk);
int kaz_sign_verify_detached_prehashed_ex(level, digest, sig, siglen, pk);
```

Internals:
- Sign: SHA3(data) -> sign digest -> extract S1||S2||S3 (discard embedded message)
- Verify: SHA3(data) -> reconstruct S1||S2||S3||digest -> verify core -> confirm recovered message matches digest

Detached signature sizes (S1||S2||S3 only):
- Level 128: 162 bytes
- Level 192: 264 bytes
- Level 256: 356 bytes

## Phase 2: DER Key Encoding

### DER Encoding (`src/internal/der.c`)

```c
int kaz_sign_pubkey_to_der(level, pk, der, derlen);
int kaz_sign_pubkey_from_der(der, derlen, level, pk);
int kaz_sign_privkey_to_der(level, sk, der, derlen);
int kaz_sign_privkey_from_der(der, derlen, level, sk);
```

- Public key: SubjectPublicKeyInfo (X.509) DER
- Private key: PKCS8 PrivateKeyInfo DER
- OIDs must match `kaz-pqc-jcajce-0.0.2.jar` for Java interop
- `from_der` auto-detects security level from OID

Implementation: Manual ASN.1 DER construction using OpenSSL primitives.

## Phase 3: X.509 + PKCS12

### X.509 (`src/internal/x509.c`)

```c
int kaz_sign_generate_csr(level, sk, pk, subject_cn, subject_o, subject_ou, csr, csrlen);
int kaz_sign_verify_csr(csr, csrlen);
int kaz_sign_issue_certificate(level, issuer_sk, issuer_cert, issuer_cert_len, csr, csrlen, serial, serial_len, not_before, not_after, is_ca, cert, certlen);
int kaz_sign_cert_extract_pubkey(cert, certlen, level, pk);
int kaz_sign_verify_certificate(cert, certlen, issuer_pk, issuer_level);
```

Implementation: Manual ASN.1 TBS construction, hash with level-matched SHA3, sign with `kaz_sign_detached_prehashed_ex()`.

### PKCS12 (`src/internal/p12.c`)

```c
int kaz_sign_create_p12(level, sk, cert, certlen, chain, chain_lens, chain_count, password, name, p12, p12len);
int kaz_sign_load_p12(p12, p12len, password, level, sk, cert, certlen, chain, chain_lens, chain_count);
```

Implementation: OpenSSL `PKCS12_create()` / `PKCS12_parse()`.

## New Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| -5 | KAZ_SIGN_ERROR_DER | DER encoding/decoding failure |
| -6 | KAZ_SIGN_ERROR_X509 | X.509 operation failure |
| -7 | KAZ_SIGN_ERROR_P12 | PKCS12 operation failure |
| -8 | KAZ_SIGN_ERROR_HASH | Hashing failure |
| -9 | KAZ_SIGN_ERROR_BUFFER | Output buffer too small |

## New Files

### Source
- `src/internal/sha3.c`
- `src/internal/detached.c`
- `src/internal/der.c`
- `src/internal/x509.c`
- `src/internal/p12.c`

### Tests
- `tests/unit/test_sha3.c`
- `tests/unit/test_detached.c`
- `tests/unit/test_der.c`
- `tests/unit/test_x509.c`
- `tests/unit/test_p12.c`

## Binding Extensions

All bindings (Android/Kotlin, Swift/iOS, Elixir, C#/.NET) extended with new functions as specified in doc 10 sections 6.1-6.3. Extend existing files rather than creating new ones.

## Testing

- New unit tests for each new module
- Existing test_sign.c and test_kdf.c updated for SHA3
- KAT vectors regenerated
- DudeCT timing analysis must pass for all new code paths
