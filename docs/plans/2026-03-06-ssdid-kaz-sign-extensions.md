# KAZ-Sign SSDID Extensions Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend KAZ-Sign C library to v3.0.0 with SHA-3 migration, detached signing, DER encoding, X.509 certificates, and PKCS12 keystores for SSDID protocol compatibility.

**Architecture:** Replace SHA-2 with level-matched SHA-3 family in the core signing path. Add new modules (detached.c, sha3.c, der.c, x509.c, p12.c) that build on the existing runtime-level API. All new functions use the `_ex` suffix convention for runtime level selection.

**Tech Stack:** C (C99), OpenSSL 3.x (EVP, BN, ASN1, X509, PKCS12), Make build system.

---

### Task 1: Version Bump and New Error Codes in sign.h

**Files:**
- Modify: `SIGN/include/kaz/sign.h:23-29` (version), `SIGN/include/kaz/sign.h:39-42` (level enum comments), `SIGN/include/kaz/sign.h:88,111,118,140,148,172` (algorithm names and hash alg), `SIGN/include/kaz/sign.h:190-194` (error codes)

**Step 1: Update version constants**

Change lines 23-29 in `SIGN/include/kaz/sign.h`:

```c
#define KAZ_SIGN_VERSION_MAJOR     3
#define KAZ_SIGN_VERSION_MINOR     0
#define KAZ_SIGN_VERSION_PATCH     0
#define KAZ_SIGN_VERSION_STRING    "3.0.0"

/* Version as single integer: (major * 10000) + (minor * 100) + patch */
#define KAZ_SIGN_VERSION_NUMBER    30000
```

**Step 2: Update level enum comments to SHA-3**

Change lines 39-42:

```c
typedef enum {
    KAZ_LEVEL_128 = 128,    /* 128-bit security (SHA3-256) */
    KAZ_LEVEL_192 = 192,    /* 192-bit security (SHA3-384) */
    KAZ_LEVEL_256 = 256     /* 256-bit security (SHA3-512) */
} kaz_sign_level_t;
```

**Step 3: Update compile-time algorithm names and hash algorithms**

For level 128 (line 88, 111):
```c
#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-128-SHA3"
/* ... */
#define KAZ_SIGN_HASH_ALG          "SHA3-256"
```

For level 192 (line 118, 141):
```c
#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-192-SHA3"
/* ... */
#define KAZ_SIGN_HASH_ALG          "SHA3-384"
```

For level 256 (line 148, 172):
```c
#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-256-SHA3"
/* ... */
#define KAZ_SIGN_HASH_ALG          "SHA3-512"
```

**Step 4: Add new error codes after line 194**

```c
#define KAZ_SIGN_ERROR_DER        -5
#define KAZ_SIGN_ERROR_X509       -6
#define KAZ_SIGN_ERROR_P12        -7
#define KAZ_SIGN_ERROR_HASH       -8
#define KAZ_SIGN_ERROR_BUFFER     -9
```

**Step 5: Add new API declarations before `#endif` (before line 386)**

```c
/* ============================================================================
 * SHA3 Hashing API
 * ============================================================================ */

/**
 * Compute SHA3-256 digest.
 */
int kaz_sha3_256(
    const unsigned char *data,
    unsigned long long datalen,
    unsigned char *digest
);

/**
 * Incremental SHA3-256 hashing context.
 */
typedef struct kaz_sha3_ctx kaz_sha3_ctx_t;

int kaz_sha3_256_init(kaz_sha3_ctx_t **ctx);
int kaz_sha3_256_update(kaz_sha3_ctx_t *ctx, const unsigned char *data, unsigned long long datalen);
int kaz_sha3_256_final(kaz_sha3_ctx_t *ctx, unsigned char *digest);
void kaz_sha3_256_free(kaz_sha3_ctx_t *ctx);

/* ============================================================================
 * Detached Signing API
 * ============================================================================ */

/**
 * Get detached signature size for a security level.
 */
size_t kaz_sign_detached_sig_bytes(kaz_sign_level_t level);

/**
 * Sign data in detached mode (signature does not contain the message).
 * Internally computes level-matched SHA3 hash of data before signing.
 */
int kaz_sign_detached_ex(
    kaz_sign_level_t level,
    unsigned char *sig,
    unsigned long long *siglen,
    const unsigned char *data,
    unsigned long long datalen,
    const unsigned char *sk
);

/**
 * Verify a detached signature.
 * Internally computes level-matched SHA3 hash of data before verification.
 */
int kaz_sign_verify_detached_ex(
    kaz_sign_level_t level,
    const unsigned char *data,
    unsigned long long datalen,
    const unsigned char *sig,
    unsigned long long siglen,
    const unsigned char *pk
);

/**
 * Sign a pre-computed digest in detached mode.
 * Digest must be the correct size for the level (32/48/64 bytes).
 */
int kaz_sign_detached_prehashed_ex(
    kaz_sign_level_t level,
    unsigned char *sig,
    unsigned long long *siglen,
    const unsigned char *digest,
    const unsigned char *sk
);

/**
 * Verify a detached signature against a pre-computed digest.
 */
int kaz_sign_verify_detached_prehashed_ex(
    kaz_sign_level_t level,
    const unsigned char *digest,
    const unsigned char *sig,
    unsigned long long siglen,
    const unsigned char *pk
);

/* ============================================================================
 * DER Key Encoding API
 * ============================================================================ */

int kaz_sign_pubkey_to_der(
    kaz_sign_level_t level,
    const unsigned char *pk,
    unsigned char *der,
    unsigned long long *derlen
);

int kaz_sign_pubkey_from_der(
    const unsigned char *der,
    unsigned long long derlen,
    kaz_sign_level_t *level,
    unsigned char *pk
);

int kaz_sign_privkey_to_der(
    kaz_sign_level_t level,
    const unsigned char *sk,
    unsigned char *der,
    unsigned long long *derlen
);

int kaz_sign_privkey_from_der(
    const unsigned char *der,
    unsigned long long derlen,
    kaz_sign_level_t *level,
    unsigned char *sk
);

/* ============================================================================
 * X.509 Certificate API
 * ============================================================================ */

int kaz_sign_generate_csr(
    kaz_sign_level_t level,
    const unsigned char *sk,
    const unsigned char *pk,
    const char *subject_cn,
    const char *subject_o,
    const char *subject_ou,
    unsigned char *csr,
    unsigned long long *csrlen
);

int kaz_sign_verify_csr(
    const unsigned char *csr,
    unsigned long long csrlen
);

int kaz_sign_issue_certificate(
    kaz_sign_level_t level,
    const unsigned char *issuer_sk,
    const unsigned char *issuer_cert,
    unsigned long long issuer_cert_len,
    const unsigned char *csr,
    unsigned long long csrlen,
    const unsigned char *serial,
    unsigned long long serial_len,
    long not_before,
    long not_after,
    int is_ca,
    unsigned char *cert,
    unsigned long long *certlen
);

int kaz_sign_cert_extract_pubkey(
    const unsigned char *cert,
    unsigned long long certlen,
    kaz_sign_level_t *level,
    unsigned char *pk
);

int kaz_sign_verify_certificate(
    const unsigned char *cert,
    unsigned long long certlen,
    const unsigned char *issuer_pk,
    kaz_sign_level_t issuer_level
);

/* ============================================================================
 * PKCS12 Keystore API
 * ============================================================================ */

int kaz_sign_create_p12(
    kaz_sign_level_t level,
    const unsigned char *sk,
    const unsigned char *cert,
    unsigned long long certlen,
    const unsigned char **chain,
    const unsigned long long *chain_lens,
    int chain_count,
    const char *password,
    const char *name,
    unsigned char *p12,
    unsigned long long *p12len
);

int kaz_sign_load_p12(
    const unsigned char *p12,
    unsigned long long p12len,
    const char *password,
    kaz_sign_level_t *level,
    unsigned char *sk,
    unsigned char *cert,
    unsigned long long *certlen,
    unsigned char **chain,
    unsigned long long *chain_lens,
    int *chain_count
);
```

**Step 6: Verify it compiles**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make dirs`
Expected: Success (header-only changes, no link step needed yet)

**Step 7: Commit**

```bash
git add SIGN/include/kaz/sign.h
git commit -m "feat(sign): bump to v3.0.0, add SHA3/detached/DER/X509/P12 API declarations"
```

---

### Task 2: SHA-3 Migration in sign.c

**Files:**
- Modify: `SIGN/src/internal/sign.c:34-66` (level params algorithm names), `SIGN/src/internal/sign.c:269-273` (legacy hash init), `SIGN/src/internal/sign.c:466-468` (runtime hash init)

**Step 1: Update static level params algorithm names**

In `sign.c`, change algorithm_name for each level:

Line 36: `"KAZ-SIGN-128"` -> `"KAZ-SIGN-128-SHA3"`
Line 50: `"KAZ-SIGN-192"` -> `"KAZ-SIGN-192-SHA3"`
Line 63: `"KAZ-SIGN-256"` -> `"KAZ-SIGN-256-SHA3"`

**Step 2: Replace SHA-2 with SHA-3 in legacy init (lines 268-274)**

```c
    /* Initialize hash function */
#if KAZ_SECURITY_LEVEL == 128
    g_hash_md = EVP_sha3_256();
#elif KAZ_SECURITY_LEVEL == 192
    g_hash_md = EVP_sha3_384();
#elif KAZ_SECURITY_LEVEL == 256
    g_hash_md = EVP_sha3_512();
#endif
```

**Step 3: Replace SHA-2 with SHA-3 in runtime init (lines 465-468)**

```c
    /* Initialize hash function based on level */
    switch (level) {
        case KAZ_LEVEL_128: rp->hash_md = EVP_sha3_256(); break;
        case KAZ_LEVEL_192: rp->hash_md = EVP_sha3_384(); break;
        case KAZ_LEVEL_256: rp->hash_md = EVP_sha3_512(); break;
        default: goto cleanup;
    }
```

**Step 4: Build and run tests to verify SHA-3 works**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make test LEVEL=128`
Expected: Tests pass (signing and verification use SHA-3 now; existing KAT vectors will no longer match but functional tests should pass)

**Step 5: Run all levels**

Run: `make test-all`
Expected: All three levels pass

**Step 6: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): migrate core hashing from SHA-2 to SHA-3 family"
```

---

### Task 3: SHA-3 Migration in kdf.c

**Files:**
- Modify: `SIGN/src/internal/kdf.c:16-17` (KDF_HASH_ALG)

**Step 1: Replace SHA-512 with SHA3-512 in KDF**

Change lines 15-17:

```c
/* Use SHA3-512 as the default hash for KDF */
#define KDF_HASH_ALG EVP_sha3_512()
#define KDF_HASH_LEN 64
```

**Step 2: Run KDF tests**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make test-kdf LEVEL=128`
Expected: KDF tests pass (note: any hardcoded SHA-512 test vectors in test_kdf.c will fail and need updating)

**Step 3: If KDF test vectors fail, update them**

Read `SIGN/tests/unit/test_kdf.c` and update any hardcoded expected hash values to match SHA3-512 output.

**Step 4: Run full test suite**

Run: `make test-all`
Expected: All pass

**Step 5: Commit**

```bash
git add SIGN/src/internal/kdf.c SIGN/tests/unit/test_kdf.c
git commit -m "feat(kdf): migrate HKDF from SHA-512 to SHA3-512"
```

---

### Task 4: Implement sha3.c (Standalone SHA3-256 API)

**Files:**
- Create: `SIGN/src/internal/sha3.c`
- Create: `SIGN/tests/unit/test_sha3.c`
- Modify: `SIGN/Makefile` (add sha3.o to LIB_OBJS, add test target)

**Step 1: Write test_sha3.c**

```c
/*
 * SHA3-256 Unit Tests
 * Tests against NIST FIPS 202 known-answer test vectors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/sign.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) == (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (got %d, expected %d)\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) == 0) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s\n", msg); } \
} while(0)

/* NIST FIPS 202 test vector: SHA3-256("") */
static const unsigned char sha3_256_empty[] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

/* NIST FIPS 202 test vector: SHA3-256("abc") */
static const unsigned char sha3_256_abc[] = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

static void test_sha3_256_empty(void) {
    unsigned char digest[32];
    int ret = kaz_sha3_256(NULL, 0, digest);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 empty input returns success");
    ASSERT_MEM_EQ(digest, sha3_256_empty, 32, "SHA3-256 empty matches NIST vector");
}

static void test_sha3_256_abc(void) {
    unsigned char digest[32];
    const unsigned char msg[] = "abc";
    int ret = kaz_sha3_256(msg, 3, digest);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 'abc' returns success");
    ASSERT_MEM_EQ(digest, sha3_256_abc, 32, "SHA3-256 'abc' matches NIST vector");
}

static void test_sha3_256_incremental(void) {
    unsigned char digest_oneshot[32];
    unsigned char digest_incremental[32];
    const unsigned char msg[] = "abcdef";

    /* One-shot */
    kaz_sha3_256(msg, 6, digest_oneshot);

    /* Incremental */
    kaz_sha3_ctx_t *ctx = NULL;
    int ret = kaz_sha3_256_init(&ctx);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 incremental init");

    ret = kaz_sha3_256_update(ctx, msg, 3);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 incremental update 1");

    ret = kaz_sha3_256_update(ctx, msg + 3, 3);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 incremental update 2");

    ret = kaz_sha3_256_final(ctx, digest_incremental);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "SHA3-256 incremental final");

    kaz_sha3_256_free(ctx);

    ASSERT_MEM_EQ(digest_oneshot, digest_incremental, 32, "SHA3-256 incremental matches one-shot");
}

static void test_sha3_256_null_digest(void) {
    int ret = kaz_sha3_256((const unsigned char *)"abc", 3, NULL);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_HASH, "SHA3-256 null digest returns error");
}

int main(void) {
    printf("\n========================================\n");
    printf("SHA3-256 Unit Tests\n");
    printf("========================================\n\n");

    test_sha3_256_empty();
    test_sha3_256_abc();
    test_sha3_256_incremental();
    test_sha3_256_null_digest();

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
```

**Step 2: Verify test fails to compile (no sha3.c yet)**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && gcc -Wall -Wextra -O2 -I./include -DKAZ_SECURITY_LEVEL=128 tests/unit/test_sha3.c src/internal/sign.c src/internal/security.c src/internal/kdf.c src/internal/nist_wrapper.c $(brew --prefix openssl)/lib/libcrypto.a -I$(brew --prefix openssl)/include -lm -o /dev/null 2>&1 | head -5`
Expected: Linker errors for `kaz_sha3_256`, `kaz_sha3_256_init`, etc.

**Step 3: Implement sha3.c**

Create `SIGN/src/internal/sha3.c`:

```c
/*
 * SHA3-256 Standalone API
 * Exposes SHA3-256 via OpenSSL EVP for mobile SDKs.
 */

#include <stdlib.h>
#include <openssl/evp.h>
#include "kaz/sign.h"

/* Incremental hashing context */
struct kaz_sha3_ctx {
    EVP_MD_CTX *md_ctx;
};

int kaz_sha3_256(
    const unsigned char *data,
    unsigned long long datalen,
    unsigned char *digest)
{
    EVP_MD_CTX *ctx;
    unsigned int out_len;

    if (digest == NULL) {
        return KAZ_SIGN_ERROR_HASH;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return KAZ_SIGN_ERROR_HASH;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return KAZ_SIGN_ERROR_HASH;
    }

    if (data != NULL && datalen > 0) {
        if (EVP_DigestUpdate(ctx, data, datalen) != 1) {
            EVP_MD_CTX_free(ctx);
            return KAZ_SIGN_ERROR_HASH;
        }
    }

    if (EVP_DigestFinal_ex(ctx, digest, &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return KAZ_SIGN_ERROR_HASH;
    }

    EVP_MD_CTX_free(ctx);
    return KAZ_SIGN_SUCCESS;
}

int kaz_sha3_256_init(kaz_sha3_ctx_t **ctx)
{
    if (ctx == NULL) {
        return KAZ_SIGN_ERROR_HASH;
    }

    *ctx = malloc(sizeof(kaz_sha3_ctx_t));
    if (*ctx == NULL) {
        return KAZ_SIGN_ERROR_MEMORY;
    }

    (*ctx)->md_ctx = EVP_MD_CTX_new();
    if ((*ctx)->md_ctx == NULL) {
        free(*ctx);
        *ctx = NULL;
        return KAZ_SIGN_ERROR_HASH;
    }

    if (EVP_DigestInit_ex((*ctx)->md_ctx, EVP_sha3_256(), NULL) != 1) {
        EVP_MD_CTX_free((*ctx)->md_ctx);
        free(*ctx);
        *ctx = NULL;
        return KAZ_SIGN_ERROR_HASH;
    }

    return KAZ_SIGN_SUCCESS;
}

int kaz_sha3_256_update(kaz_sha3_ctx_t *ctx, const unsigned char *data, unsigned long long datalen)
{
    if (ctx == NULL || ctx->md_ctx == NULL) {
        return KAZ_SIGN_ERROR_HASH;
    }

    if (data == NULL && datalen > 0) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (datalen == 0) {
        return KAZ_SIGN_SUCCESS;
    }

    if (EVP_DigestUpdate(ctx->md_ctx, data, datalen) != 1) {
        return KAZ_SIGN_ERROR_HASH;
    }

    return KAZ_SIGN_SUCCESS;
}

int kaz_sha3_256_final(kaz_sha3_ctx_t *ctx, unsigned char *digest)
{
    unsigned int out_len;

    if (ctx == NULL || ctx->md_ctx == NULL || digest == NULL) {
        return KAZ_SIGN_ERROR_HASH;
    }

    if (EVP_DigestFinal_ex(ctx->md_ctx, digest, &out_len) != 1) {
        return KAZ_SIGN_ERROR_HASH;
    }

    return KAZ_SIGN_SUCCESS;
}

void kaz_sha3_256_free(kaz_sha3_ctx_t *ctx)
{
    if (ctx != NULL) {
        if (ctx->md_ctx != NULL) {
            EVP_MD_CTX_free(ctx->md_ctx);
        }
        free(ctx);
    }
}
```

**Step 4: Add sha3.o to Makefile**

Add to LIB_SRCS (after line 78):
```makefile
           $(SRC_DIR)/sha3.c
```

Add to LIB_OBJS (after line 84):
```makefile
           $(OBJ_DIR)/sha3.o
```

Add object file rule (after line 116):
```makefile
$(OBJ_DIR)/sha3.o: $(SRC_DIR)/sha3.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@
```

Add test target (after test-kdf target, ~line 194):
```makefile
# Build SHA3 test
$(BIN_DIR)/test_sha3_$(LEVEL): $(TEST_DIR)/test_sha3.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Run SHA3 tests
test-sha3: $(BIN_DIR)/test_sha3_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running SHA3-256 Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_sha3_$(LEVEL)
```

Add sha3.o to unified objects (after line 433):
```makefile
               $(OBJ_DIR)/sha3_unified.o

$(OBJ_DIR)/sha3_unified.o: $(SRC_DIR)/sha3.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@
```

**Step 5: Build and run SHA3 tests**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make test-sha3 LEVEL=128`
Expected: All SHA3 tests pass

**Step 6: Run full test suite to ensure no regressions**

Run: `make test LEVEL=128`
Expected: Pass

**Step 7: Commit**

```bash
git add SIGN/src/internal/sha3.c SIGN/tests/unit/test_sha3.c SIGN/Makefile
git commit -m "feat(sha3): add standalone SHA3-256 API with incremental hashing"
```

---

### Task 5: Implement detached.c (Detached Signing)

**Files:**
- Create: `SIGN/src/internal/detached.c`
- Create: `SIGN/tests/unit/test_detached.c`
- Modify: `SIGN/Makefile` (add detached.o, test target)

**Step 1: Write test_detached.c**

```c
/*
 * Detached Signing Unit Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/sign.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) == (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (got %d, expected %d)\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_NEQ(a, b, msg) do { \
    if ((a) != (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (values are equal)\n", msg); } \
} while(0)

static void test_detached_roundtrip(kaz_sign_level_t level) {
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char pk[256], sk[256];
    unsigned char sig[512];
    unsigned long long siglen;
    const unsigned char msg[] = "Hello, SSDID protocol!";
    char label[64];

    int ret = kaz_sign_init_level(level);
    snprintf(label, sizeof(label), "Level %d: init", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    ret = kaz_sign_keypair_ex(level, pk, sk);
    snprintf(label, sizeof(label), "Level %d: keypair", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    ret = kaz_sign_detached_ex(level, sig, &siglen, msg, sizeof(msg) - 1, sk);
    snprintf(label, sizeof(label), "Level %d: detached sign", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    snprintf(label, sizeof(label), "Level %d: sig size = %llu (expected %zu)", params->level, siglen, params->signature_overhead);
    ASSERT_EQ((int)siglen, (int)params->signature_overhead, label);

    ret = kaz_sign_verify_detached_ex(level, msg, sizeof(msg) - 1, sig, siglen, pk);
    snprintf(label, sizeof(label), "Level %d: detached verify", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    kaz_sign_clear_level(level);
}

static void test_detached_wrong_key(void) {
    unsigned char pk1[256], sk1[256];
    unsigned char pk2[256], sk2[256];
    unsigned char sig[512];
    unsigned long long siglen;
    const unsigned char msg[] = "test message";

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk1, sk1);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk2, sk2);

    kaz_sign_detached_ex(KAZ_LEVEL_128, sig, &siglen, msg, sizeof(msg) - 1, sk1);

    int ret = kaz_sign_verify_detached_ex(KAZ_LEVEL_128, msg, sizeof(msg) - 1, sig, siglen, pk2);
    ASSERT_NEQ(ret, KAZ_SIGN_SUCCESS, "Wrong key rejection");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

static void test_detached_wrong_message(void) {
    unsigned char pk[256], sk[256];
    unsigned char sig[512];
    unsigned long long siglen;
    const unsigned char msg1[] = "original message";
    const unsigned char msg2[] = "tampered message";

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

    kaz_sign_detached_ex(KAZ_LEVEL_128, sig, &siglen, msg1, sizeof(msg1) - 1, sk);

    int ret = kaz_sign_verify_detached_ex(KAZ_LEVEL_128, msg2, sizeof(msg2) - 1, sig, siglen, pk);
    ASSERT_NEQ(ret, KAZ_SIGN_SUCCESS, "Wrong message rejection");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

static void test_detached_prehashed_roundtrip(void) {
    unsigned char pk[256], sk[256];
    unsigned char sig[512];
    unsigned long long siglen;
    const unsigned char msg[] = "prehash test";
    unsigned char digest[32];

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

    /* Pre-hash with the level-matched hash (SHA3-256 for level 128) */
    kaz_sign_hash_ex(KAZ_LEVEL_128, msg, sizeof(msg) - 1, digest);

    int ret = kaz_sign_detached_prehashed_ex(KAZ_LEVEL_128, sig, &siglen, digest, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Prehashed sign");

    ret = kaz_sign_verify_detached_prehashed_ex(KAZ_LEVEL_128, digest, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Prehashed verify");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

static void test_detached_empty_data(void) {
    unsigned char pk[256], sk[256];
    unsigned char sig[512];
    unsigned long long siglen;

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

    int ret = kaz_sign_detached_ex(KAZ_LEVEL_128, sig, &siglen, NULL, 0, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Empty data sign");

    ret = kaz_sign_verify_detached_ex(KAZ_LEVEL_128, NULL, 0, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Empty data verify");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

static void test_detached_sig_bytes(void) {
    ASSERT_EQ((int)kaz_sign_detached_sig_bytes(KAZ_LEVEL_128), 162, "Level 128 sig bytes = 162");
    ASSERT_EQ((int)kaz_sign_detached_sig_bytes(KAZ_LEVEL_192), 264, "Level 192 sig bytes = 264");
    ASSERT_EQ((int)kaz_sign_detached_sig_bytes(KAZ_LEVEL_256), 356, "Level 256 sig bytes = 356");
}

int main(void) {
    printf("\n========================================\n");
    printf("Detached Signing Unit Tests\n");
    printf("========================================\n\n");

    test_detached_sig_bytes();
    test_detached_roundtrip(KAZ_LEVEL_128);
    test_detached_roundtrip(KAZ_LEVEL_192);
    test_detached_roundtrip(KAZ_LEVEL_256);
    test_detached_wrong_key();
    test_detached_wrong_message();
    test_detached_prehashed_roundtrip();
    test_detached_empty_data();

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
```

**Step 2: Verify test fails to link**

Run: Compile test_detached.c and confirm linker errors for `kaz_sign_detached_ex` etc.

**Step 3: Implement detached.c**

Create `SIGN/src/internal/detached.c`:

```c
/*
 * KAZ-SIGN Detached Signing
 *
 * Provides detached sign/verify operations where the signature
 * does not embed the message. Uses level-matched SHA-3 pre-hashing.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "kaz/sign.h"
#include "kaz/security.h"

size_t kaz_sign_detached_sig_bytes(kaz_sign_level_t level)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (params == NULL) return 0;
    return params->signature_overhead;
}

/* Get the level-matched SHA3 EVP_MD */
static const EVP_MD *get_sha3_md(kaz_sign_level_t level)
{
    switch (level) {
        case KAZ_LEVEL_128: return EVP_sha3_256();
        case KAZ_LEVEL_192: return EVP_sha3_384();
        case KAZ_LEVEL_256: return EVP_sha3_512();
        default: return NULL;
    }
}

/* Compute level-matched SHA3 hash */
static int compute_sha3(kaz_sign_level_t level,
                        const unsigned char *data, unsigned long long datalen,
                        unsigned char *digest, unsigned int *digest_len)
{
    const EVP_MD *md = get_sha3_md(level);
    EVP_MD_CTX *ctx;

    if (md == NULL || digest == NULL) return KAZ_SIGN_ERROR_HASH;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return KAZ_SIGN_ERROR_HASH;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
        (data != NULL && datalen > 0 && EVP_DigestUpdate(ctx, data, datalen) != 1) ||
        (data == NULL && datalen == 0 && 1) ||  /* empty input is valid */
        EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return KAZ_SIGN_ERROR_HASH;
    }

    EVP_MD_CTX_free(ctx);
    return KAZ_SIGN_SUCCESS;
}

int kaz_sign_detached_ex(
    kaz_sign_level_t level,
    unsigned char *sig,
    unsigned long long *siglen,
    const unsigned char *data,
    unsigned long long datalen,
    const unsigned char *sk)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char digest[64]; /* max SHA3-512 = 64 bytes */
    unsigned int digest_len;
    unsigned char *full_sig = NULL;
    unsigned long long full_siglen;
    int ret;

    if (params == NULL || sig == NULL || siglen == NULL || sk == NULL) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    /* Step 1: Compute level-matched SHA3 hash of data */
    ret = compute_sha3(level, data, datalen, digest, &digest_len);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Step 2: Sign the digest using message-recovery mode */
    full_sig = malloc(params->signature_overhead + digest_len);
    if (full_sig == NULL) { ret = KAZ_SIGN_ERROR_MEMORY; goto cleanup; }

    ret = kaz_sign_signature_ex(level, full_sig, &full_siglen, digest, digest_len, sk);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Step 3: Extract S1 || S2 || S3 only (discard embedded message) */
    memcpy(sig, full_sig, params->signature_overhead);
    *siglen = params->signature_overhead;

cleanup:
    if (full_sig) {
        kaz_secure_zero(full_sig, params->signature_overhead + 64);
        free(full_sig);
    }
    kaz_secure_zero(digest, sizeof(digest));
    return ret;
}

int kaz_sign_verify_detached_ex(
    kaz_sign_level_t level,
    const unsigned char *data,
    unsigned long long datalen,
    const unsigned char *sig,
    unsigned long long siglen,
    const unsigned char *pk)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char digest[64];
    unsigned int digest_len;
    unsigned char *full_sig = NULL;
    unsigned char *recovered_msg = NULL;
    unsigned long long recovered_len;
    int ret;

    if (params == NULL || sig == NULL || pk == NULL) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (siglen != params->signature_overhead) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    /* Step 1: Compute level-matched SHA3 hash of data */
    ret = compute_sha3(level, data, datalen, digest, &digest_len);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Step 2: Reconstruct full message-recovery signature: S1||S2||S3||digest */
    full_sig = malloc(siglen + digest_len);
    if (full_sig == NULL) { ret = KAZ_SIGN_ERROR_MEMORY; goto cleanup; }

    memcpy(full_sig, sig, siglen);
    memcpy(full_sig + siglen, digest, digest_len);

    /* Step 3: Verify using message-recovery mode */
    recovered_msg = malloc(digest_len + 1);
    if (recovered_msg == NULL) { ret = KAZ_SIGN_ERROR_MEMORY; goto cleanup; }

    ret = kaz_sign_verify_ex(level, recovered_msg, &recovered_len,
                             full_sig, siglen + digest_len, pk);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Step 4: Confirm recovered message matches our digest */
    if (recovered_len != digest_len ||
        kaz_ct_memcmp(recovered_msg, digest, digest_len) != 0) {
        ret = KAZ_SIGN_ERROR_VERIFY;
    }

cleanup:
    if (full_sig) {
        kaz_secure_zero(full_sig, params->signature_overhead + 64);
        free(full_sig);
    }
    if (recovered_msg) {
        kaz_secure_zero(recovered_msg, digest_len + 1);
        free(recovered_msg);
    }
    kaz_secure_zero(digest, sizeof(digest));
    return ret;
}

int kaz_sign_detached_prehashed_ex(
    kaz_sign_level_t level,
    unsigned char *sig,
    unsigned long long *siglen,
    const unsigned char *digest,
    const unsigned char *sk)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char *full_sig = NULL;
    unsigned long long full_siglen;
    int ret;

    if (params == NULL || sig == NULL || siglen == NULL || digest == NULL || sk == NULL) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    /* Sign the pre-computed digest using message-recovery mode */
    full_sig = malloc(params->signature_overhead + params->hash_bytes);
    if (full_sig == NULL) return KAZ_SIGN_ERROR_MEMORY;

    ret = kaz_sign_signature_ex(level, full_sig, &full_siglen,
                                digest, params->hash_bytes, sk);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Extract S1||S2||S3 only */
    memcpy(sig, full_sig, params->signature_overhead);
    *siglen = params->signature_overhead;

cleanup:
    if (full_sig) {
        kaz_secure_zero(full_sig, params->signature_overhead + params->hash_bytes);
        free(full_sig);
    }
    return ret;
}

int kaz_sign_verify_detached_prehashed_ex(
    kaz_sign_level_t level,
    const unsigned char *digest,
    const unsigned char *sig,
    unsigned long long siglen,
    const unsigned char *pk)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char *full_sig = NULL;
    unsigned char *recovered_msg = NULL;
    unsigned long long recovered_len;
    int ret;

    if (params == NULL || digest == NULL || sig == NULL || pk == NULL) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    if (siglen != params->signature_overhead) {
        return KAZ_SIGN_ERROR_INVALID;
    }

    /* Reconstruct full signature: S1||S2||S3||digest */
    full_sig = malloc(siglen + params->hash_bytes);
    if (full_sig == NULL) return KAZ_SIGN_ERROR_MEMORY;

    memcpy(full_sig, sig, siglen);
    memcpy(full_sig + siglen, digest, params->hash_bytes);

    /* Verify */
    recovered_msg = malloc(params->hash_bytes + 1);
    if (recovered_msg == NULL) { ret = KAZ_SIGN_ERROR_MEMORY; goto cleanup; }

    ret = kaz_sign_verify_ex(level, recovered_msg, &recovered_len,
                             full_sig, siglen + params->hash_bytes, pk);
    if (ret != KAZ_SIGN_SUCCESS) goto cleanup;

    /* Confirm recovered message matches digest */
    if (recovered_len != params->hash_bytes ||
        kaz_ct_memcmp(recovered_msg, digest, params->hash_bytes) != 0) {
        ret = KAZ_SIGN_ERROR_VERIFY;
    }

cleanup:
    if (full_sig) {
        kaz_secure_zero(full_sig, siglen + params->hash_bytes);
        free(full_sig);
    }
    if (recovered_msg) {
        kaz_secure_zero(recovered_msg, params->hash_bytes + 1);
        free(recovered_msg);
    }
    return ret;
}
```

**Step 4: Add to Makefile**

Add `$(SRC_DIR)/detached.c` to LIB_SRCS, `$(OBJ_DIR)/detached.o` to LIB_OBJS.

Add build rules:
```makefile
$(OBJ_DIR)/detached.o: $(SRC_DIR)/detached.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(BIN_DIR)/test_detached_$(LEVEL): $(TEST_DIR)/test_detached.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

test-detached: $(BIN_DIR)/test_detached_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running Detached Signing Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_detached_$(LEVEL)
```

Add unified object:
```makefile
$(OBJ_DIR)/detached_unified.o: $(SRC_DIR)/detached.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@
```

**Step 5: Build and run tests**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make test-detached LEVEL=128`
Expected: All detached tests pass

**Step 6: Run full test suite**

Run: `make test-all`
Expected: All pass

**Step 7: Commit**

```bash
git add SIGN/src/internal/detached.c SIGN/tests/unit/test_detached.c SIGN/Makefile
git commit -m "feat(detached): add detached signing with SHA3 pre-hashing"
```

---

### Task 6: Implement der.c (DER Key Encoding)

**Files:**
- Create: `SIGN/src/internal/der.c`
- Create: `SIGN/tests/unit/test_der.c`
- Modify: `SIGN/Makefile`

**Step 1: Write test_der.c**

```c
/*
 * DER Key Encoding Unit Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/sign.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) == (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (got %d, expected %d)\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) == 0) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s\n", msg); } \
} while(0)

static void test_pubkey_der_roundtrip(kaz_sign_level_t level) {
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char pk[256], sk[256];
    unsigned char der[1024];
    unsigned long long derlen = sizeof(der);
    unsigned char pk_out[256];
    kaz_sign_level_t level_out;
    char label[64];

    kaz_sign_init_level(level);
    kaz_sign_keypair_ex(level, pk, sk);

    int ret = kaz_sign_pubkey_to_der(level, pk, der, &derlen);
    snprintf(label, sizeof(label), "Level %d: pubkey to DER", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    ret = kaz_sign_pubkey_from_der(der, derlen, &level_out, pk_out);
    snprintf(label, sizeof(label), "Level %d: pubkey from DER", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    snprintf(label, sizeof(label), "Level %d: level detected correctly", params->level);
    ASSERT_EQ((int)level_out, (int)level, label);

    snprintf(label, sizeof(label), "Level %d: pubkey round-trip matches", params->level);
    ASSERT_MEM_EQ(pk, pk_out, params->public_key_bytes, label);

    kaz_sign_clear_level(level);
}

static void test_privkey_der_roundtrip(kaz_sign_level_t level) {
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned char pk[256], sk[256];
    unsigned char der[1024];
    unsigned long long derlen = sizeof(der);
    unsigned char sk_out[256];
    kaz_sign_level_t level_out;
    char label[64];

    kaz_sign_init_level(level);
    kaz_sign_keypair_ex(level, pk, sk);

    int ret = kaz_sign_privkey_to_der(level, sk, der, &derlen);
    snprintf(label, sizeof(label), "Level %d: privkey to DER", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    ret = kaz_sign_privkey_from_der(der, derlen, &level_out, sk_out);
    snprintf(label, sizeof(label), "Level %d: privkey from DER", params->level);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, label);

    snprintf(label, sizeof(label), "Level %d: level detected correctly", params->level);
    ASSERT_EQ((int)level_out, (int)level, label);

    snprintf(label, sizeof(label), "Level %d: privkey round-trip matches", params->level);
    ASSERT_MEM_EQ(sk, sk_out, params->secret_key_bytes, label);

    kaz_sign_clear_level(level);
}

static void test_der_buffer_too_small(void) {
    unsigned char pk[256], sk[256];
    unsigned char der[4]; /* too small */
    unsigned long long derlen = sizeof(der);

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

    int ret = kaz_sign_pubkey_to_der(KAZ_LEVEL_128, pk, der, &derlen);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_BUFFER, "Buffer too small returns error");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

static void test_der_sign_verify_cross(void) {
    /* Generate key, encode to DER, decode, verify signature with decoded key */
    unsigned char pk[256], sk[256];
    unsigned char der[1024];
    unsigned long long derlen = sizeof(der);
    unsigned char pk_decoded[256];
    kaz_sign_level_t level_out;
    unsigned char sig[512];
    unsigned long long siglen;
    const unsigned char msg[] = "cross-test";

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

    /* Sign with original key */
    kaz_sign_detached_ex(KAZ_LEVEL_128, sig, &siglen, msg, sizeof(msg) - 1, sk);

    /* DER round-trip the public key */
    kaz_sign_pubkey_to_der(KAZ_LEVEL_128, pk, der, &derlen);
    kaz_sign_pubkey_from_der(der, derlen, &level_out, pk_decoded);

    /* Verify with decoded key */
    int ret = kaz_sign_verify_detached_ex(KAZ_LEVEL_128, msg, sizeof(msg) - 1, sig, siglen, pk_decoded);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verify with DER round-tripped key");

    kaz_sign_clear_level(KAZ_LEVEL_128);
}

int main(void) {
    printf("\n========================================\n");
    printf("DER Key Encoding Unit Tests\n");
    printf("========================================\n\n");

    test_pubkey_der_roundtrip(KAZ_LEVEL_128);
    test_pubkey_der_roundtrip(KAZ_LEVEL_192);
    test_pubkey_der_roundtrip(KAZ_LEVEL_256);

    test_privkey_der_roundtrip(KAZ_LEVEL_128);
    test_privkey_der_roundtrip(KAZ_LEVEL_192);
    test_privkey_der_roundtrip(KAZ_LEVEL_256);

    test_der_buffer_too_small();
    test_der_sign_verify_cross();

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
```

**Step 2: Implement der.c**

Create `SIGN/src/internal/der.c`. The implementation should:

1. Define KAZ-Sign OIDs (one per level) using ASN.1 encoding
2. Build SubjectPublicKeyInfo: `SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { pk_bytes } }`
3. Build PrivateKeyInfo: `SEQUENCE { INTEGER 0, SEQUENCE { OID, NULL }, OCTET STRING { sk_bytes } }`
4. Parse: read OID to detect level, extract key bytes
5. Use manual DER construction (tag-length-value) — no custom EVP_PKEY needed

The OIDs should be defined as:
- `1.3.6.1.4.1.99999.1.1` for KAZ-SIGN-128
- `1.3.6.1.4.1.99999.1.2` for KAZ-SIGN-192
- `1.3.6.1.4.1.99999.1.3` for KAZ-SIGN-256

(These are placeholder OIDs under a private enterprise arc. Adjust to match `kaz-pqc-jcajce-0.0.2.jar` if needed.)

**Step 3: Add to Makefile** (same pattern as sha3/detached)

**Step 4: Build and run tests**

Run: `make clean && make test-der LEVEL=128`
Expected: All pass

**Step 5: Commit**

```bash
git add SIGN/src/internal/der.c SIGN/tests/unit/test_der.c SIGN/Makefile
git commit -m "feat(der): add DER key encoding/decoding (SubjectPublicKeyInfo, PKCS8)"
```

---

### Task 7: Implement x509.c (X.509 Certificates)

**Files:**
- Create: `SIGN/src/internal/x509.c`
- Create: `SIGN/tests/unit/test_x509.c`
- Modify: `SIGN/Makefile`

**Step 1: Write test_x509.c**

Tests should cover:
- CSR generation and self-verification
- Self-signed certificate creation and verification
- CA-signed certificate (generate CA cert, then sign end-entity cert)
- Public key extraction from certificate
- Invalid certificate rejection

**Step 2: Implement x509.c**

The implementation should:

1. **CSR generation**: Build PKCS#10 ASN.1 structure manually:
   - Build TBS CertificationRequest (version, subject, subjectPKInfo, attributes)
   - Hash TBS with level-matched SHA3
   - Sign hash with `kaz_sign_detached_prehashed_ex()`
   - Assemble: `SEQUENCE { tbsCertReq, signatureAlgorithm, signatureValue }`

2. **Certificate issuance**: Build X.509 v3 ASN.1 structure:
   - Build TBS Certificate (version, serial, issuer, validity, subject, subjectPKInfo, extensions)
   - Hash TBS with level-matched SHA3
   - Sign hash with `kaz_sign_detached_prehashed_ex()`
   - For self-signed: issuer = subject
   - For CA-signed: extract issuer DN from issuer cert

3. **Certificate verification**: Parse cert, extract TBS, verify signature
4. **Public key extraction**: Parse cert, find subjectPublicKeyInfo, extract raw bytes

Use OpenSSL's ASN.1 primitives (`ASN1_OBJECT`, `ASN1_INTEGER`, `X509_NAME`, etc.) for robust encoding. The signature algorithm OID should use the same KAZ-Sign OIDs from der.c with a SHA3 hash indicator.

**Step 3: Add to Makefile**

**Step 4: Build and run tests**

Run: `make clean && make test-x509 LEVEL=128`
Expected: All pass

**Step 5: Commit**

```bash
git add SIGN/src/internal/x509.c SIGN/tests/unit/test_x509.c SIGN/Makefile
git commit -m "feat(x509): add CSR generation, certificate issuance and verification"
```

---

### Task 8: Implement p12.c (PKCS12 Keystore)

**Files:**
- Create: `SIGN/src/internal/p12.c`
- Create: `SIGN/tests/unit/test_p12.c`
- Modify: `SIGN/Makefile`

**Step 1: Write test_p12.c**

Tests should cover:
- P12 create and load round-trip (key + cert preserved)
- Password protection (wrong password fails)
- Certificate chain preservation
- Empty chain handling

**Step 2: Implement p12.c**

The implementation should:

1. **Create P12**:
   - Encode private key as DER using `kaz_sign_privkey_to_der()`
   - Use OpenSSL's `PKCS12_create()` or manual construction
   - Include certificate chain if provided
   - Password-protect using PKCS12 v3 encryption

2. **Load P12**:
   - Parse with OpenSSL `PKCS12_parse()` or manual
   - Extract private key DER, decode with `kaz_sign_privkey_from_der()`
   - Extract certificate and chain

Note: Since KAZ-Sign uses custom OIDs, OpenSSL's PKCS12 functions may need the key wrapped in a generic OCTET STRING rather than as an EVP_PKEY. The implementation may need to use lower-level PKCS12 ASN.1 construction.

**Step 3: Add to Makefile**

**Step 4: Build and run tests**

Run: `make clean && make test-p12 LEVEL=128`
Expected: All pass

**Step 5: Commit**

```bash
git add SIGN/src/internal/p12.c SIGN/tests/unit/test_p12.c SIGN/Makefile
git commit -m "feat(p12): add PKCS12 keystore create and load"
```

---

### Task 9: Update Existing Tests for SHA-3

**Files:**
- Modify: `SIGN/tests/unit/test_sign.c` (update any hardcoded hash expectations)
- Modify: `SIGN/tests/unit/test_kdf.c` (update HKDF test vectors for SHA3-512)

**Step 1: Run existing tests and identify failures**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make test LEVEL=128`

Identify which tests fail due to SHA-3 migration (hash value mismatches, algorithm name checks, etc.)

**Step 2: Fix failing tests**

Update hardcoded expected values. Common changes:
- Algorithm name strings: "KAZ-SIGN-128" -> "KAZ-SIGN-128-SHA3"
- Hash output comparisons against SHA-256 expected values
- Version string checks: "2.1.0" -> "3.0.0"

**Step 3: Run all tests**

Run: `make test-all`
Expected: All pass

**Step 4: Run KDF tests**

Run: `make test-kdf LEVEL=128`
Expected: Pass (after updating vectors in Task 3)

**Step 5: Commit**

```bash
git add SIGN/tests/unit/test_sign.c SIGN/tests/unit/test_kdf.c
git commit -m "test: update existing tests for v3.0.0 SHA-3 migration"
```

---

### Task 10: Update Makefile Unified Build and CI Targets

**Files:**
- Modify: `SIGN/Makefile`

**Step 1: Add all new unified objects to UNIFIED_OBJS**

```makefile
UNIFIED_OBJS = $(OBJ_DIR)/sign_unified.o \
               $(OBJ_DIR)/nist_wrapper_unified.o \
               $(OBJ_DIR)/security_unified.o \
               $(OBJ_DIR)/kdf_unified.o \
               $(OBJ_DIR)/sha3_unified.o \
               $(OBJ_DIR)/detached_unified.o \
               $(OBJ_DIR)/der_unified.o \
               $(OBJ_DIR)/x509_unified.o \
               $(OBJ_DIR)/p12_unified.o
```

**Step 2: Add .PHONY entries for new test targets**

Add to line 90: `test-sha3 test-detached test-der test-x509 test-p12 test-extensions`

**Step 3: Add combined extension test target**

```makefile
# Run all extension tests
test-extensions: test-sha3 test-detached test-der test-x509 test-p12

# Update test-all to include extension tests
```

**Step 4: Update help target with new commands**

**Step 5: Build unified library**

Run: `make clean && make shared-unified`
Expected: Unified library builds successfully

**Step 6: Run all tests**

Run: `make test-all`
Expected: All pass

**Step 7: Commit**

```bash
git add SIGN/Makefile
git commit -m "build: update Makefile with unified build for all new modules"
```

---

### Task 11: Regenerate KAT Vectors

**Files:**
- Generated: `PQCsignKAT_128.rsp`, `PQCsignKAT_192.rsp`, `PQCsignKAT_256.rsp`

**Step 1: Generate new KAT vectors**

Run: `cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN && make clean && make kat-all`
Expected: New KAT files generated with SHA-3 based signatures

**Step 2: Verify KAT files**

Run: `make kat-verify LEVEL=128 && make kat-verify LEVEL=192 && make kat-verify LEVEL=256`
Expected: All verify

**Step 3: Commit**

```bash
git add SIGN/PQCsignKAT_*.rsp SIGN/PQCsignKAT_*.req
git commit -m "test: regenerate KAT vectors for v3.0.0 SHA-3 migration"
```

---

### Task 12: Extend Android Binding (JNI/Kotlin)

**Files:**
- Modify: `SIGN/bindings/android/kazsign/src/main/cpp/kazsign_jni.c`
- Modify: `SIGN/bindings/android/kazsign/src/main/kotlin/com/antrapol/kaz/sign/KazSigner.kt`
- Modify: `SIGN/bindings/android/kazsign/src/main/kotlin/com/antrapol/kaz/sign/KazSignNative.kt`

**Step 1: Read current binding files**

Read the existing JNI and Kotlin files to understand the current pattern.

**Step 2: Add JNI functions to kazsign_jni.c**

Add JNI wrappers for:
- `signDetached` / `verifyDetached`
- `sha3_256`
- `publicKeyToDer` / `publicKeyFromDer` / `privateKeyToDer` / `privateKeyFromDer`
- `generateCsr` / `issueCertificate` / `verifyCertificate` / `extractPublicKey`
- `createP12` / `loadP12`

Follow the existing JNI pattern in the file.

**Step 3: Add Kotlin methods to KazSignNative.kt**

Add external function declarations matching the JNI names.

**Step 4: Add high-level Kotlin API to KazSigner.kt**

Add methods as specified in doc 10 section 6.1. Add `P12Contents` data class.

**Step 5: Commit**

```bash
git add SIGN/bindings/android/
git commit -m "feat(android): extend JNI/Kotlin bindings with detached/DER/X509/P12"
```

---

### Task 13: Extend Swift Binding

**Files:**
- Modify: `SIGN/bindings/swift/Sources/KazSign/KazSign.swift`

**Step 1: Read current Swift binding**

**Step 2: Add new methods**

Add methods as specified in doc 10 section 6.2:
- `signDetached` / `verifyDetached`
- `sha3_256`
- `publicKeyToDer` / `publicKeyFromDer` / `privateKeyToDer` / `privateKeyFromDer`
- `generateCSR` / `issueCertificate` / `verifyCertificate` / `extractPublicKey`
- `createP12` / `loadP12`
- `P12Contents` struct

**Step 3: Commit**

```bash
git add SIGN/bindings/swift/
git commit -m "feat(swift): extend Swift bindings with detached/DER/X509/P12"
```

---

### Task 14: Extend Elixir Binding

**Files:**
- Modify: `SIGN/bindings/elixir/c_src/kaz_sign_nif.c`
- Modify: `SIGN/bindings/elixir/lib/kaz_sign.ex`

**Step 1: Read current Elixir binding files**

**Step 2: Add NIF functions to kaz_sign_nif.c**

Add NIF wrappers for all new C API functions.

**Step 3: Add Elixir functions to kaz_sign.ex**

Add functions as specified in doc 10 section 6.3.

**Step 4: Commit**

```bash
git add SIGN/bindings/elixir/
git commit -m "feat(elixir): extend NIF/Elixir bindings with detached/DER/X509/P12"
```

---

### Task 15: Extend C# Binding

**Files:**
- Modify: `SIGN/bindings/csharp/KazSign/KazSign.cs`

**Step 1: Read current C# binding**

**Step 2: Add P/Invoke declarations and wrapper methods**

Add methods mirroring the Kotlin API for all new functions.

**Step 3: Commit**

```bash
git add SIGN/bindings/csharp/
git commit -m "feat(csharp): extend .NET bindings with detached/DER/X509/P12"
```

---

### Task 16: Final Integration Test

**Step 1: Run full test suite**

Run:
```bash
cd /Users/amirrudinyahaya/Workspace/PQC-KAZ/SIGN
make clean
make test-all
make test-extensions
make test-kdf LEVEL=128
```
Expected: All pass

**Step 2: Build unified shared library**

Run: `make shared-unified`
Expected: Builds successfully

**Step 3: Run timing analysis**

Run: `make dudect LEVEL=128`
Expected: No timing leakage detected

**Step 4: Final commit with version tag**

```bash
git tag -a v3.0.0 -m "KAZ-Sign v3.0.0: SHA-3 migration, detached signing, DER, X.509, PKCS12"
```
