# JCAJCE v2.0 Alignment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Align the C native library (KEM/ and SIGN/) with kaz-pqc-jcajce-v2.0 as the source of truth — matching hash functions, OIDs, wire format, and byte sizes.

**Architecture:** In-place modification of existing C source files. No new files except a KazWire encoding module. SHA3→SHA-256, OID 99999→62395, add KazWire 0x6752 header format, fix Level 256 byte sizes (119→118).

**Tech Stack:** C11, OpenSSL 3.x (EVP API, BIGNUM), Make

---

## Phase 1: KAZ-SIGN Hash Function Migration (SHA3 → SHA-256)

### Task 1: Update compile-time hash selection in sign.c

**Files:**
- Modify: `SIGN/src/internal/sign.c:276-283`

**Step 1: Change hash initialization (compile-time path)**

Replace lines 276-283:
```c
    /* Initialize hash function — always SHA-256, output truncated/padded per level */
    g_hash_md = EVP_sha256();
```

**Step 2: Change hash initialization (runtime path)**

Replace lines 473-479 in sign.c:
```c
    /* SHA-256 for all levels (output truncated/padded to hash_bytes) */
    rp->hash_md = EVP_sha256();
```

**Step 3: Update hash function to truncate/pad output**

The `kaz_sign_hash` function (line 628) currently outputs the raw EVP digest. SHA-256 always produces 32 bytes. For levels 192 and 256 we need 48 and 64 bytes respectively.

Modify `kaz_sign_hash` (lines 628-660) to:
```c
int kaz_sign_hash(const unsigned char *msg,
                  unsigned long long msglen,
                  unsigned char *hash)
{
    unsigned char sha256_buf[32];
    unsigned int hash_len = 0;
    int target_len;

    if (!g_params.initialized || !g_hash_ctx || !g_hash_md) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    target_len = g_params.level_params->hash_bytes;

    if (EVP_DigestInit_ex(g_hash_ctx, g_hash_md, NULL) != 1) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (msglen > (unsigned long long)SIZE_MAX) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (msg == NULL && msglen > 0) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (msg != NULL && msglen > 0 && EVP_DigestUpdate(g_hash_ctx, msg, (size_t)msglen) != 1) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (EVP_DigestFinal_ex(g_hash_ctx, sha256_buf, &hash_len) != 1) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    /* Copy SHA-256 output, zero-pad if target_len > 32 */
    memset(hash, 0, target_len);
    memcpy(hash, sha256_buf, hash_len < (unsigned)target_len ? hash_len : (unsigned)target_len);

    return KAZ_SIGN_SUCCESS;
}
```

Also update the runtime `kaz_sign_hash_ex` function with the same truncation/padding logic.

**Step 4: Run tests to verify**

Run: `cd SIGN && make clean && make test LEVEL=128`
Expected: Tests pass with SHA-256 hash

Run: `cd SIGN && make clean && make test LEVEL=192 && make clean && make test LEVEL=256`
Expected: Tests pass (signatures will differ from old KATs but round-trip works)

**Step 5: Commit**
```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): migrate hash function from SHA3 to SHA-256

Aligns with kaz-pqc-jcajce-v2.0 which uses SHA-256 for all levels
with output truncated/padded to level-specific hash_bytes."
```

---

### Task 2: Fix Level 256 byte sizes (119 → 118)

**Files:**
- Modify: `SIGN/include/kaz/sign.h:150-176`
- Modify: `SIGN/src/internal/sign.c:64-76`

**Step 1: Fix sign.h Level 256 parameters**

Change lines 152-173 in sign.h:
```c
#define KAZ_SIGN_PUBLICKEYBYTES    118
#define KAZ_SIGN_BYTES             64

/* ... keep g1, g2, N, phiN, Og1N, Og2N unchanged ... */

#define KAZ_SIGN_VBYTES            118
#define KAZ_SIGN_SBYTES            32
#define KAZ_SIGN_TBYTES            32
#define KAZ_SIGN_S1BYTES           118
#define KAZ_SIGN_S2BYTES           118
#define KAZ_SIGN_S3BYTES           118
```

Remove the incorrect comment at line 170:
```c
/* Note: N has 284 digits ~ 942 bits -> ceil(942/8) = 118 bytes */
```

**Step 2: Fix sign.c Level 256 static params**

Change lines 64-76 in sign.c:
```c
static const kaz_sign_level_params_t g_level_256_params = {
    .level = 256,
    .algorithm_name = "KAZ-SIGN-256",
    .secret_key_bytes = 64,
    .public_key_bytes = 118,
    .hash_bytes = 64,
    .signature_overhead = 354,  /* 118 + 118 + 118 */
    .s_bytes = 32,
    .t_bytes = 32,
    .s1_bytes = 118,
    .s2_bytes = 118,
    .s3_bytes = 118
};
```

**Step 3: Run tests**

Run: `cd SIGN && make clean && make test LEVEL=256`
Expected: PASS

**Step 4: Commit**
```bash
git add SIGN/include/kaz/sign.h SIGN/src/internal/sign.c
git commit -m "fix(sign): correct Level 256 byte sizes from 119 to 118

N has 284 digits (~942 bits = 118 bytes), not 285 as previously
commented. Aligns with kaz-pqc-jcajce-v2.0 SIGN_VBYTES[2]=118."
```

---

### Task 3: Update algorithm names

**Files:**
- Modify: `SIGN/include/kaz/sign.h:92,115,122,145,152,176`
- Modify: `SIGN/src/internal/sign.c:36,51,66`

**Step 1: Change algorithm names**

In sign.h, replace all `-SHA3` suffixed names:
- `"KAZ-SIGN-128-SHA3"` → `"KAZ-SIGN-128"`
- `"KAZ-SIGN-192-SHA3"` → `"KAZ-SIGN-192"`
- `"KAZ-SIGN-256-SHA3"` → `"KAZ-SIGN-256"`

Also change hash algorithm defines:
- `"SHA3-256"` → `"SHA-256"`
- `"SHA3-384"` → `"SHA-256"`
- `"SHA3-512"` → `"SHA-256"`

In sign.c, update the static params structs (lines 36, 51, 66) similarly.

**Step 2: Run tests**

Run: `cd SIGN && make clean && make test-all`
Expected: All levels PASS

**Step 3: Commit**
```bash
git add SIGN/include/kaz/sign.h SIGN/src/internal/sign.c
git commit -m "feat(sign): rename algorithms, remove -SHA3 suffix"
```

---

### Task 4: Update sha3.c → SHA-256 wrapper

**Files:**
- Modify: `SIGN/src/internal/sha3.c` (full rewrite)
- Modify: `SIGN/include/kaz/sign.h` (update SHA3 API section → SHA-256)

**Step 1: Rewrite sha3.c as SHA-256 wrapper**

The standalone SHA3 API (`kaz_sha3_256`, `kaz_sha3_256_init/update/final/free`) should be replaced with SHA-256 equivalents. Since bindings and tests reference these functions, rename them to `kaz_sha256_*` and keep old names as wrappers:

```c
/* SHA-256 implementation using OpenSSL EVP */
#define SHA256_DIGEST_LEN 32

int kaz_sha256(const unsigned char *msg, unsigned long long msglen,
               unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    unsigned int out_len = 0;
    int ret = -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, msg, (size_t)msglen) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &out_len) == 1) {
        ret = 0;
    }
    EVP_MD_CTX_free(ctx);
    return ret;
}
```

Provide init/update/final/free streaming API using same EVP_sha256() backend.

**Step 2: Update sign.h API declarations**

Rename exported functions from `kaz_sha3_256_*` to `kaz_sha256_*`. Add `#define kaz_sha3_256 kaz_sha256` compatibility macros if needed by external bindings.

**Step 3: Update test_sha3.c**

Update references from SHA3 to SHA-256, update expected hash values.

**Step 4: Run tests**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`
Expected: SHA-256 tests PASS

**Step 5: Commit**
```bash
git add SIGN/src/internal/sha3.c SIGN/include/kaz/sign.h SIGN/tests/unit/test_sha3.c
git commit -m "feat(sign): replace SHA3-256 standalone API with SHA-256"
```

---

### Task 5: Update KDF from SHA3-512 to SHA-256

**Files:**
- Modify: `SIGN/src/internal/kdf.c:16-18`

**Step 1: Change KDF hash algorithm**

Replace lines 16-18:
```c
/* Use SHA-256 as the default hash for KDF (aligned with JCAJCE) */
#define KDF_HASH_ALG EVP_sha256()
#define KDF_HASH_LEN 32
```

**Step 2: Run KDF tests**

Run: `cd SIGN && make clean && make test-kdf LEVEL=128`
Expected: PASS (KAT values will change)

**Step 3: Commit**
```bash
git add SIGN/src/internal/kdf.c
git commit -m "feat(sign): switch KDF from SHA3-512 to SHA-256"
```

---

## Phase 2: KAZ-SIGN OID Migration (99999 → 62395)

### Task 6: Update OIDs in der.c

**Files:**
- Modify: `SIGN/src/internal/der.c:40-67`

**Step 1: Compute new OID byte encoding**

Old OID: `1.3.6.1.4.1.99999.1.X` → `2B 06 01 04 01 86 8D 1F 01 XX` (10 bytes)

New OIDs use enterprise number 62395 with deeper tree:
- Algorithm OIDs: `1.3.6.1.4.1.62395.1.2.X`
- Public key OID: `1.3.6.1.4.1.62395.1.1.2`
- Private key OID: `1.3.6.1.4.1.62395.1.1.1`

Encoding 62395 in base-128 varint: 62395 = 0xF3BB
- 62395 / 128 = 487 remainder 59 (0x3B)
- 487 / 128 = 3 remainder 103 (0x67 | 0x80 = 0xE7)
- 3 → (0x03 | 0x80 = 0x83)
- Result: 0x83, 0xE7, 0x3B

Full algorithm OID value bytes: `2B 06 01 04 01 83 E7 3B 01 02 XX` (11 bytes)
Full public key OID value bytes: `2B 06 01 04 01 83 E7 3B 01 01 02` (11 bytes)
Full private key OID value bytes: `2B 06 01 04 01 83 E7 3B 01 01 01` (11 bytes)

**Step 2: Replace OID constants in der.c**

Replace lines 44-50:
```c
/* Algorithm OID prefix: 1.3.6.1.4.1.62395.1.2 */
static const unsigned char OID_ALG_PREFIX[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xE7, 0x3B, 0x01, 0x02
};
#define OID_ALG_PREFIX_LEN  10
#define OID_ALG_VALUE_LEN   11   /* prefix + 1 byte for level */
#define OID_ALG_TLV_LEN     13   /* tag(1) + length(1) + value(11) */

/* Public key OID: 1.3.6.1.4.1.62395.1.1.2 */
static const unsigned char OID_PUBKEY[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xE7, 0x3B, 0x01, 0x01, 0x02
};
#define OID_PUBKEY_LEN  11

/* Private key OID: 1.3.6.1.4.1.62395.1.1.1 */
static const unsigned char OID_PRIVKEY[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xE7, 0x3B, 0x01, 0x01, 0x01
};
#define OID_PRIVKEY_LEN  11
```

**Step 3: Update all OID references throughout der.c**

Update `write_algorithm_identifier()`, `kaz_sign_pubkey_to_der()`, `kaz_sign_privkey_to_der()` and their reverse functions to use the new OID arrays and lengths. The DER functions for public keys should use `OID_PUBKEY` in the AlgorithmIdentifier, and private keys should use `OID_PRIVKEY`.

**Step 4: Run DER tests**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`
Expected: DER encode/decode round-trip PASS

**Step 5: Commit**
```bash
git add SIGN/src/internal/der.c
git commit -m "feat(sign): migrate OIDs from 99999 to 62395 arc

Algorithm: 1.3.6.1.4.1.62395.1.2.{1,2,3}
Public key: 1.3.6.1.4.1.62395.1.1.2
Private key: 1.3.6.1.4.1.62395.1.1.1"
```

---

### Task 7: Update OIDs in x509.c

**Files:**
- Modify: `SIGN/src/internal/x509.c:29-35`

**Step 1: Replace OID_PREFIX_X509 with new encoding**

Replace lines 29-35 with the same new OID bytes as der.c:
```c
static const unsigned char OID_PREFIX_X509[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xE7, 0x3B, 0x01, 0x02
};
```

Update OID length constants to match.

**Step 2: Run X.509 tests**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`
Expected: X.509 tests PASS

**Step 3: Commit**
```bash
git add SIGN/src/internal/x509.c
git commit -m "feat(sign): update X.509 module to use 62395 OIDs"
```

---

### Task 8: Update OIDs in p12.c (if present)

**Files:**
- Modify: `SIGN/src/internal/p12.c` (check for OID references)

**Step 1: Search for OID references in p12.c**

Check if p12.c has direct OID references. It likely delegates to der.c for key encoding, so changes may not be needed. If it has its own OID bytes, update them.

**Step 2: Run P12 tests**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`
Expected: P12 tests PASS

**Step 3: Commit (if changes made)**
```bash
git add SIGN/src/internal/p12.c
git commit -m "feat(sign): update PKCS#12 module to use 62395 OIDs"
```

---

## Phase 3: KAZ-SIGN KazWire Encoding

### Task 9: Add KazWire encoding/decoding to sign.h and sign.c

**Files:**
- Modify: `SIGN/include/kaz/sign.h` (add constants and function declarations)
- Modify: `SIGN/src/internal/sign.c` (add implementation)

**Step 1: Add KazWire constants to sign.h**

Add after the derived constants section:
```c
/* ============================================================================
 * KazWire Encoding Constants (aligned with kaz-pqc-core-v2.0)
 * ============================================================================ */
#define KAZ_WIRE_MAGIC         0x6752
#define KAZ_WIRE_MAGIC_HI      0x67
#define KAZ_WIRE_MAGIC_LO      0x52
#define KAZ_WIRE_VERSION       0x01

/* Algorithm IDs */
#define KAZ_WIRE_SIGN_128      0x01
#define KAZ_WIRE_SIGN_192      0x02
#define KAZ_WIRE_SIGN_256      0x03

/* Type markers */
#define KAZ_WIRE_TYPE_PRIV     0x01
#define KAZ_WIRE_TYPE_PUB      0x02
#define KAZ_WIRE_TYPE_SIG_DET  0x10
#define KAZ_WIRE_TYPE_SIG_ATT  0x11

/* Header size (magic 2 + alg 1 + type 1 + version 1) */
#define KAZ_WIRE_HEADER_LEN    5

/* Payload header for attached signatures */
#define KAZ_WIRE_PAYLOAD_MARKER 0x50
#define KAZ_WIRE_PAYLOAD_VER    0x01

/* Wire format sizes (header + payload) */
#define KAZ_WIRE_PUBKEY_LEN(vbytes)  (KAZ_WIRE_HEADER_LEN + (vbytes))
#define KAZ_WIRE_PRIVKEY_LEN(sb,tb)  (KAZ_WIRE_HEADER_LEN + (sb) + (tb))
#define KAZ_WIRE_SIG_DET_LEN(s1,s2,s3)  (KAZ_WIRE_HEADER_LEN + (s1) + (s2) + (s3))
```

**Step 2: Add KazWire function declarations to sign.h**

```c
/* KazWire encoding */
int kaz_sign_pubkey_to_wire(kaz_sign_level_t level,
                            const unsigned char *pk, size_t pk_len,
                            unsigned char *out, size_t *out_len);

int kaz_sign_pubkey_from_wire(const unsigned char *wire, size_t wire_len,
                              kaz_sign_level_t *level,
                              unsigned char *pk, size_t *pk_len);

int kaz_sign_privkey_to_wire(kaz_sign_level_t level,
                             const unsigned char *sk, size_t sk_len,
                             unsigned char *out, size_t *out_len);

int kaz_sign_privkey_from_wire(const unsigned char *wire, size_t wire_len,
                               kaz_sign_level_t *level,
                               unsigned char *sk, size_t *sk_len);

int kaz_sign_sig_to_wire(kaz_sign_level_t level,
                         const unsigned char *sig, size_t sig_len,
                         unsigned char *out, size_t *out_len);

int kaz_sign_sig_from_wire(const unsigned char *wire, size_t wire_len,
                           kaz_sign_level_t *level,
                           unsigned char *sig, size_t *sig_len);
```

**Step 3: Implement KazWire functions in sign.c**

Add encoding functions at the end of sign.c. Core pattern for each:
```c
int kaz_sign_pubkey_to_wire(kaz_sign_level_t level,
                            const unsigned char *pk, size_t pk_len,
                            unsigned char *out, size_t *out_len) {
    const kaz_sign_level_params_t *p = get_level_params(level);
    if (!p || !pk || !out || !out_len) return KAZ_SIGN_ERROR_INVALID;

    size_t wire_len = KAZ_WIRE_HEADER_LEN + p->public_key_bytes;
    if (*out_len < wire_len) return KAZ_SIGN_ERROR_INVALID;

    uint8_t alg;
    switch (level) {
        case KAZ_LEVEL_128: alg = KAZ_WIRE_SIGN_128; break;
        case KAZ_LEVEL_192: alg = KAZ_WIRE_SIGN_192; break;
        case KAZ_LEVEL_256: alg = KAZ_WIRE_SIGN_256; break;
        default: return KAZ_SIGN_ERROR_INVALID;
    }

    out[0] = KAZ_WIRE_MAGIC_HI;
    out[1] = KAZ_WIRE_MAGIC_LO;
    out[2] = alg;
    out[3] = KAZ_WIRE_TYPE_PUB;
    out[4] = KAZ_WIRE_VERSION;
    memcpy(out + KAZ_WIRE_HEADER_LEN, pk, p->public_key_bytes);
    *out_len = wire_len;
    return KAZ_SIGN_SUCCESS;
}
```

Follow same pattern for privkey, signature encode/decode. Decode validates magic, extracts level from alg byte.

**Step 4: Run tests**

Run: `cd SIGN && make clean && make test LEVEL=128`
Expected: PASS (existing tests still work, wire functions don't break anything)

**Step 5: Commit**
```bash
git add SIGN/include/kaz/sign.h SIGN/src/internal/sign.c
git commit -m "feat(sign): add KazWire encoding/decoding (0x6752 format)

Wire format aligned with kaz-pqc-core-v2.0 KazWire.java.
Supports public key, private key, and detached signature encoding."
```

---

### Task 10: Add KazWire unit tests

**Files:**
- Create: `SIGN/tests/unit/test_kazwire.c`

**Step 1: Write round-trip tests**

Test encode→decode round-trip for public keys, private keys, and signatures at all 3 levels. Verify magic bytes, algorithm ID, type marker, version, and payload integrity.

**Step 2: Add test target to Makefile**

Add `test-kazwire` target in SIGN/Makefile following the same pattern as `test-der`.

**Step 3: Run tests**

Run: `cd SIGN && make clean && make test-kazwire LEVEL=128`
Expected: PASS

**Step 4: Commit**
```bash
git add SIGN/tests/unit/test_kazwire.c SIGN/Makefile
git commit -m "test(sign): add KazWire encoding round-trip tests"
```

---

## Phase 4: KAZ-SIGN DER Alignment with JCAJCE

### Task 11: Update DER to use JCAJCE-compatible key OIDs

**Files:**
- Modify: `SIGN/src/internal/der.c`

**Step 1: Use separate OIDs for SPKI and PKCS#8**

The JCAJCE uses:
- `SubjectPublicKeyInfo` with OID `1.3.6.1.4.1.62395.1.1.2` (key type OID)
- `PrivateKeyInfo` with OID `1.3.6.1.4.1.62395.1.1.1` (key type OID)
- The key payload is KazWire bytes (with 0x6752 header)

Update `kaz_sign_pubkey_to_der()` to:
1. Use `OID_PUBKEY` in the AlgorithmIdentifier
2. Encode the raw key as BIT STRING content (KazWire bytes)

Update `kaz_sign_privkey_to_der()` to:
1. Use `OID_PRIVKEY` in the AlgorithmIdentifier
2. Wrap the raw key in OCTET STRING (KazWire bytes)

**Step 2: Run DER tests**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`
Expected: DER round-trip tests PASS

**Step 3: Commit**
```bash
git add SIGN/src/internal/der.c
git commit -m "feat(sign): align DER encoding with JCAJCE key OID structure"
```

---

## Phase 5: KAZ-KEM Wire Format

### Task 12: Add KazWire constants to kem.h

**Files:**
- Modify: `KEM/include/kaz/kem.h`

**Step 1: Add KazWire constants**

Add after existing constants:
```c
/* KazWire Encoding Constants */
#define KAZ_KEM_WIRE_MAGIC_HI      0x67
#define KAZ_KEM_WIRE_MAGIC_LO      0x52
#define KAZ_KEM_WIRE_VERSION       0x01
#define KAZ_KEM_WIRE_128           0x10
#define KAZ_KEM_WIRE_192           0x11
#define KAZ_KEM_WIRE_256           0x12
#define KAZ_KEM_WIRE_TYPE_PRIV     0x01
#define KAZ_KEM_WIRE_TYPE_PUB      0x02
#define KAZ_KEM_WIRE_HEADER_LEN    5
```

**Step 2: Add KazWire function declarations**

```c
int kaz_kem_pubkey_to_wire(int level,
                           const unsigned char *pk, size_t pk_len,
                           unsigned char *out, size_t *out_len);

int kaz_kem_pubkey_from_wire(const unsigned char *wire, size_t wire_len,
                             int *level,
                             unsigned char *pk, size_t *pk_len);

int kaz_kem_privkey_to_wire(int level,
                            const unsigned char *sk, size_t sk_len,
                            unsigned char *out, size_t *out_len);

int kaz_kem_privkey_from_wire(const unsigned char *wire, size_t wire_len,
                              int *level,
                              unsigned char *sk, size_t *sk_len);
```

**Step 3: Commit**
```bash
git add KEM/include/kaz/kem.h
git commit -m "feat(kem): add KazWire encoding constants and declarations"
```

---

### Task 13: Implement KazWire encoding in kem_secure.c

**Files:**
- Modify: `KEM/src/internal/kem_secure.c`

**Step 1: Implement encode/decode functions**

Add at end of kem_secure.c. Follow same pattern as SIGN KazWire:
- Public key: `[0x67 0x52] [level_id] [0x02] [0x01] [A1 padded] [A2 padded]`
- Private key: `[0x67 0x52] [level_id] [0x01] [0x01] [a1 padded] [a2 padded]`

Wire sizes:
- PK Level 128: 5 + 54 + 54 = 113 bytes
- PK Level 192: 5 + 88 + 88 = 181 bytes
- PK Level 256: 5 + 118 + 118 = 241 bytes
- SK Level 128: 5 + 17 + 17 = 39 bytes
- SK Level 192: 5 + 25 + 25 = 55 bytes
- SK Level 256: 5 + 33 + 33 = 71 bytes

**Step 2: Run KEM tests**

Run: `cd KEM && make clean && make test LEVEL=128`
Expected: PASS

**Step 3: Commit**
```bash
git add KEM/src/internal/kem_secure.c
git commit -m "feat(kem): implement KazWire encoding/decoding"
```

---

### Task 14: Clean up unused g3 generator from KEM

**Files:**
- Modify: `KEM/include/kaz/kem.h` (remove g3 from params struct)
- Modify: `KEM/src/internal/kem_secure.c` (remove g3 initialization)

**Step 1: Remove g3, Og3N, LOg3N from kaz_kem_params_t struct**

The Java kaz-pqc-core-v2.0 KEM uses only g1=7 and g2=23. The g3=65537 and its order are unused in the actual encapsulation/decapsulation algorithm.

Remove from the params struct definition and from all three level parameter initializations (lines 28-89 in kem_secure.c).

**Step 2: Run KEM tests**

Run: `cd KEM && make clean && make test-all`
Expected: All levels PASS

**Step 3: Commit**
```bash
git add KEM/include/kaz/kem.h KEM/src/internal/kem_secure.c
git commit -m "refactor(kem): remove unused g3 generator

KEM algorithm only uses g1=7 and g2=23.
Aligns parameter set with kaz-pqc-core-v2.0."
```

---

### Task 15: Add KazWire tests for KEM

**Files:**
- Create: `KEM/tests/unit/test_kazwire.c`
- Modify: `KEM/Makefile`

**Step 1: Write round-trip tests**

Test encode→decode for KEM public and private keys at all levels. Verify header bytes match expected format.

**Step 2: Add test target to Makefile**

**Step 3: Run tests**

Run: `cd KEM && make clean && make test LEVEL=128`
Expected: PASS

**Step 4: Commit**
```bash
git add KEM/tests/unit/test_kazwire.c KEM/Makefile
git commit -m "test(kem): add KazWire encoding round-trip tests"
```

---

## Phase 6: Update All Extension Tests and KAT Vectors

### Task 16: Regenerate KAT vectors

**Files:**
- Regenerate: `SIGN/kat/` and `KEM/kat/` directories

**Step 1: Regenerate SIGN KATs**

Run: `cd SIGN && make kat-all`

All KAT vectors are invalidated by the SHA3→SHA-256 migration. New KATs must be generated.

**Step 2: Regenerate KEM KATs**

Run: `cd KEM && make kat-all`

KEM KATs may be unchanged since the algorithm didn't change, but regenerate for safety.

**Step 3: Commit**
```bash
git add SIGN/kat/ KEM/kat/
git commit -m "chore: regenerate KAT vectors after JCAJCE alignment"
```

---

### Task 17: Update extension tests for SHA-256

**Files:**
- Modify: `SIGN/tests/unit/test_detached.c`
- Modify: `SIGN/tests/unit/test_der.c`
- Modify: `SIGN/tests/unit/test_x509.c`
- Modify: `SIGN/tests/unit/test_p12.c`
- Modify: `SIGN/tests/unit/test_sha3.c` (already updated in Task 4)

**Step 1: Run full extension test suite**

Run: `cd SIGN && make clean && make test-extensions LEVEL=128`

Fix any failures caused by:
- Changed hash output sizes
- Changed OID bytes in DER comparison tests
- Changed algorithm names in test assertions

**Step 2: Run all levels**

Run: `cd SIGN && make test-all && make test-extensions LEVEL=128 && make clean && make test-extensions LEVEL=192 && make clean && make test-extensions LEVEL=256`
Expected: All PASS

**Step 3: Commit**
```bash
git add SIGN/tests/unit/
git commit -m "test(sign): update extension tests for SHA-256 and new OIDs"
```

---

## Phase 7: Update Bindings

### Task 18: Update language bindings for new API

**Files:**
- Modify: `SIGN/bindings/android/` (update JNI if hash-dependent)
- Modify: `SIGN/bindings/swift/` (update Swift wrapper)
- Modify: `SIGN/bindings/csharp/` (update .NET binding)
- Modify: `SIGN/bindings/elixir/` (update NIF)
- Modify: `KEM/bindings/android/`
- Modify: `KEM/bindings/swift/`
- Modify: `KEM/bindings/dotnet/`

**Step 1: Audit each binding for hardcoded values**

Search for:
- SHA3/sha3 references
- OID bytes (86 8D 1F)
- Key size constants (119 for level 256)
- Algorithm name strings containing "SHA3"

**Step 2: Update constants in each binding**

Most bindings call the C API directly, so they'll pick up changes automatically. But check for:
- Hardcoded buffer sizes
- Algorithm name comparisons
- Test vectors

**Step 3: Commit per binding**
```bash
git commit -m "feat(bindings): update all bindings for JCAJCE alignment"
```

---

## Phase 8: Final Verification

### Task 19: Full CI run

**Step 1: Run full SIGN test suite**

```bash
cd SIGN && make ci
```
Expected: All levels, all tests PASS

**Step 2: Run full KEM test suite**

```bash
cd KEM && make ci
```
Expected: All levels, all tests PASS

**Step 3: Run memcheck**

```bash
cd SIGN && make memcheck LEVEL=128
cd KEM && make memcheck LEVEL=128
```
Expected: No memory leaks

**Step 4: Final commit**
```bash
git commit -m "chore: JCAJCE v2.0 alignment complete

Summary of changes:
- Hash: SHA3-256/384/512 → SHA-256 (truncated/padded per level)
- OIDs: 1.3.6.1.4.1.99999 → 1.3.6.1.4.1.62395
- Wire: Added KazWire encoding (0x6752 magic header)
- Level 256: Fixed byte sizes 119 → 118
- KEM: Removed unused g3 generator
- KDF: SHA3-512 → SHA-256
- Algorithm names: Removed -SHA3 suffix"
```

---

## Change Summary Matrix

| Component | File | Change |
|-----------|------|--------|
| Hash | sign.c:278,280,282,475-477 | SHA3→SHA-256 |
| Hash | sign.c:628-660 | Add truncation/padding |
| Hash | kdf.c:16-18 | SHA3-512→SHA-256 |
| Hash | sha3.c (all) | Rewrite as SHA-256 |
| Sizes | sign.h:154,167-173 | 119→118 for L256 |
| Sizes | sign.c:68-75 | 119→118 for L256 |
| OIDs | der.c:44-50 | 99999→62395 |
| OIDs | x509.c:29-35 | 99999→62395 |
| OIDs | p12.c (if present) | 99999→62395 |
| Names | sign.h:92,122,152 | Remove -SHA3 |
| Names | sign.c:36,51,66 | Remove -SHA3 |
| Wire | sign.h (new section) | KazWire constants |
| Wire | sign.c (new functions) | KazWire encode/decode |
| Wire | kem.h (new section) | KazWire constants |
| Wire | kem_secure.c (new funcs) | KazWire encode/decode |
| KEM | kem.h, kem_secure.c | Remove g3 |
| Tests | All test files | Update for new behavior |
| KATs | kat/ directories | Regenerate |
| Bindings | All binding dirs | Update constants |
