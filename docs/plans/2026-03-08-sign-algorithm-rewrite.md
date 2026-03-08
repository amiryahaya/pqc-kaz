# KAZ-Sign Algorithm Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite C KAZ-Sign core algorithm to match Java kaz-pqc-core implementation exactly, enabling cross-platform key/signature interoperability.

**Architecture:** In-place rewrite of `sign.c` replacing the 3-component (S1,S2,S3) single-modulus signature scheme with Java's 2-component (S1,S2) composite modular scheme. The OpenSSL BIGNUM infrastructure, constant-time helpers, API function signatures, and extension modules (DER, X.509, P12) are preserved with size updates. Detached sign/verify becomes the primary implementation; message-recovery mode becomes a shim.

**Tech Stack:** C11, OpenSSL 3.x BIGNUM/EVP, Make

**Java Reference Files (source of truth):**
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/SystemParameters.java` — all constants
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/KAZSIGNKeyGenerator.java` — keygen
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/KAZSIGNSigner.java` — signing
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/KAZSIGNVerifier.java` — verification
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/KazWire.java` — component sizes
- `kaz-pqc-core/src/main/java/com/antrapol/kaz/core/sign/Hasher.java` — hash per level

---

## Phase 1: Header & Parameter Structure

### Task 1: Update sign.h parameter struct and compile-time macros

**Files:**
- Modify: `SIGN/include/kaz/sign.h`

**Context:** The header defines `kaz_sign_level_params_t` and compile-time macros. Current fields `s_bytes`, `t_bytes`, `s3_bytes` must be replaced with `sk_bytes`, `v1_bytes`, `v2_bytes`. All sizes must match Java's `KazWire.pkLens()`, `KazWire.skLens()`, `KazWire.sigLens()`.

**Step 1: Update the params struct**

Replace the current `kaz_sign_level_params_t` (around line 51-63) with:

```c
typedef struct {
    int level;                  /* Security level (128, 192, 256) */
    const char *algorithm_name; /* Algorithm name string */
    size_t secret_key_bytes;    /* SK+v1+v2: 98/146/194 bytes */
    size_t public_key_bytes;    /* v1+v2: 49/73/97 bytes */
    size_t hash_bytes;          /* 32/48/64 (SHA-256/384/512) */
    size_t signature_overhead;  /* S1+S2: 57/81/105 bytes */
    size_t sk_bytes;            /* SK component: 49/73/97 bytes */
    size_t v1_bytes;            /* v1 component: 26/34/42 bytes */
    size_t v2_bytes;            /* v2 component: 23/39/55 bytes */
    size_t s1_bytes;            /* S1 signature component: 49/73/97 bytes */
    size_t s2_bytes;            /* S2 counter: 8 bytes (all levels) */
} kaz_sign_level_params_t;
```

**Step 2: Update compile-time macros for Level 128**

Replace lines 90-116 with:

```c
#if KAZ_SECURITY_LEVEL == 128

#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-128"
#define KAZ_SIGN_SECRETKEYBYTES    98    /* 49+26+23 = SK+v1+v2 */
#define KAZ_SIGN_PUBLICKEYBYTES    49    /* 26+23 = v1+v2 */
#define KAZ_SIGN_BYTES             32    /* SHA-256 */

#define KAZ_SIGN_SP_g1             "65537"
#define KAZ_SIGN_SP_g2             "65539"

#define KAZ_SIGN_SKBYTES           49    /* SK component */
#define KAZ_SIGN_V1BYTES           26    /* v1 component */
#define KAZ_SIGN_V2BYTES           23    /* v2 component */
#define KAZ_SIGN_S1BYTES           49    /* S1 signature component */
#define KAZ_SIGN_S2BYTES           8     /* S2 counter */

#define KAZ_SIGN_HASH_ALG          "SHA-256"
```

**Step 3: Update compile-time macros for Level 192**

Replace lines 120-145 with:

```c
#elif KAZ_SECURITY_LEVEL == 192

#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-192"
#define KAZ_SIGN_SECRETKEYBYTES    146   /* 73+34+39 = SK+v1+v2 */
#define KAZ_SIGN_PUBLICKEYBYTES    73    /* 34+39 = v1+v2 */
#define KAZ_SIGN_BYTES             48    /* SHA-384 */

#define KAZ_SIGN_SP_g1             "65537"
#define KAZ_SIGN_SP_g2             "65539"

#define KAZ_SIGN_SKBYTES           73    /* SK component */
#define KAZ_SIGN_V1BYTES           34    /* v1 component */
#define KAZ_SIGN_V2BYTES           39    /* v2 component */
#define KAZ_SIGN_S1BYTES           73    /* S1 signature component */
#define KAZ_SIGN_S2BYTES           8     /* S2 counter */

#define KAZ_SIGN_HASH_ALG          "SHA-384"
```

**Step 4: Update compile-time macros for Level 256**

Replace lines 150-177 with:

```c
#elif KAZ_SECURITY_LEVEL == 256

#define KAZ_SIGN_ALGNAME           "KAZ-SIGN-256"
#define KAZ_SIGN_SECRETKEYBYTES    194   /* 97+42+55 = SK+v1+v2 */
#define KAZ_SIGN_PUBLICKEYBYTES    97    /* 42+55 = v1+v2 */
#define KAZ_SIGN_BYTES             64    /* SHA-512 */

#define KAZ_SIGN_SP_g1             "65537"
#define KAZ_SIGN_SP_g2             "65539"

#define KAZ_SIGN_SKBYTES           97    /* SK component */
#define KAZ_SIGN_V1BYTES           42    /* v1 component */
#define KAZ_SIGN_V2BYTES           55    /* v2 component */
#define KAZ_SIGN_S1BYTES           97    /* S1 signature component */
#define KAZ_SIGN_S2BYTES           8     /* S2 counter */

#define KAZ_SIGN_HASH_ALG          "SHA-512"

#endif
```

**Step 5: Update derived constants**

Replace the `KAZ_SIGN_SIGNATURE_OVERHEAD` macro:

```c
#define KAZ_SIGN_SIGNATURE_OVERHEAD (KAZ_SIGN_S1BYTES + KAZ_SIGN_S2BYTES)
```

Remove old macros that no longer apply:
- Remove `KAZ_SIGN_S3BYTES` (no S3 component)
- Remove `KAZ_SIGN_SBYTES`, `KAZ_SIGN_TBYTES` (no s,t private key)
- Remove `KAZ_SIGN_VBYTES` (replaced by V1BYTES+V2BYTES)
- Remove `KAZ_SIGN_SP_N`, `KAZ_SIGN_SP_phiN`, `KAZ_SIGN_SP_Og1N`, `KAZ_SIGN_SP_Og2N` (old parameters)
- Remove `KAZ_SIGN_SP_J` (unused)

**Step 6: Verify header compiles**

Run: `cd SIGN && gcc -fsyntax-only -I include include/kaz/sign.h`
Expected: No errors (syntax check only)

**Step 7: Commit**

```bash
git add SIGN/include/kaz/sign.h
git commit -m "feat(sign): update sign.h for Java-aligned algorithm parameters

New key structure: pk=v1||v2 (49/73/97), sk=SK||v1||v2 (98/146/194)
New signature: S1||S2 (57/81/105), S2 is 8-byte counter
Level-matched hashing: SHA-256/384/512
Removes old N/phiN/Og1N/Og2N macros and s/t/S3 fields."
```

---

## Phase 2: System Parameters & Init

### Task 2: Replace system parameter constants in sign.c

**Files:**
- Modify: `SIGN/src/internal/sign.c:33-101` (parameter string constants)

**Context:** Replace the old 6 string constants per level (g1, g2, N, phiN, Og1N, Og2N) with the full Java `SystemParameters.java` set. All values are verbatim decimal copies from Java.

**Step 1: Replace the static level params structs**

Replace lines 34-76 with the new sizes:

```c
static const kaz_sign_level_params_t g_level_128_params = {
    .level = 128,
    .algorithm_name = "KAZ-SIGN-128",
    .secret_key_bytes = 98,     /* 49+26+23 */
    .public_key_bytes = 49,     /* 26+23 */
    .hash_bytes = 32,           /* SHA-256 */
    .signature_overhead = 57,   /* 49+8 */
    .sk_bytes = 49,
    .v1_bytes = 26,
    .v2_bytes = 23,
    .s1_bytes = 49,
    .s2_bytes = 8
};

static const kaz_sign_level_params_t g_level_192_params = {
    .level = 192,
    .algorithm_name = "KAZ-SIGN-192",
    .secret_key_bytes = 146,    /* 73+34+39 */
    .public_key_bytes = 73,     /* 34+39 */
    .hash_bytes = 48,           /* SHA-384 */
    .signature_overhead = 81,   /* 73+8 */
    .sk_bytes = 73,
    .v1_bytes = 34,
    .v2_bytes = 39,
    .s1_bytes = 73,
    .s2_bytes = 8
};

static const kaz_sign_level_params_t g_level_256_params = {
    .level = 256,
    .algorithm_name = "KAZ-SIGN-256",
    .secret_key_bytes = 194,    /* 97+42+55 */
    .public_key_bytes = 97,     /* 42+55 */
    .hash_bytes = 64,           /* SHA-512 */
    .signature_overhead = 105,  /* 97+8 */
    .sk_bytes = 97,
    .v1_bytes = 42,
    .v2_bytes = 55,
    .s1_bytes = 97,
    .s2_bytes = 8
};
```

**Step 2: Replace the string constants**

Remove all old `g_level_*` string constants (lines 78-101). Replace with the full Java parameter set:

```c
/* ============================================================================
 * System Parameters (from Java SystemParameters.java, verbatim decimal)
 * ============================================================================ */

/* Common constants (same for all levels) */
static const char *SP_G0 = "23102151283542472555351033031857407110549489214984451103786304558150674606117088000";
static const char *SP_G1 = "399620650696124709852000";
static const char *SP_PHIG1 = "60408037934094090240000";
static const char *SP_PHIPHIG1 = "11456568251237007360000";
static const char *SP_R = "6151";
static const char *SP_A = "324324000";

/* Per-level: q */
static const char *SP_q[] = {
    "246208917987764371328101733",                                                /* L128 */
    "5708990770823839524233143877797980545530986749",                              /* L192 */
    "2840556527694295864950860759784740510458069976738706234986729593207"           /* L256 */
};

/* Per-level: Q */
static const char *SP_Q[] = {
    "1115881660253397921934830780",                                                /* L128 */
    "15805027320208803894072603145771831246637343495",                              /* L192 */
    "11532304439951903318047260070672268613130768031212132639712137620"              /* L256 */
};

/* Per-level: qQ */
static const char *SP_qQ[] = {
    "274740016173379194546381236446787565723556071979741740",
    "90230755103690702091973211007922974222612910553804250618499942113585284663920884979406347755",
    "32758162656263289822165160082704286295984704353673644459843294584139742401444681348237525839805407482025757064066007727363001147340"
};

/* Per-level: phiQ */
static const char *SP_PHIQ[] = {
    "142607087754413919436800000",
    "3627887299833526965332723467399389511680000000",
    "1251434900161857001704369748558994349944756643204956160000000000"
};

/* Per-level: phiqQ */
static const char *SP_PHIqQ[] = {
    "35111136773400413456929878039434623864922544537600000",
    "20711575112338624928696946102003619446749681847468928622048198130495376119592271216640000000",
    "3554771574639222339069568200522429346291071123851611090794232823233857364488038302147974718854109146210993915839863848960000000000"
};

/* Per-level: G1RHO */
static const char *SP_G1RHO[] = {
    "232938694926837183398728616987791009425158374864155959337108000",
    "2780574578486571985357538778664475851603942045856011006180329605609412611300244000",
    "79133492123247080788931646239320683796403476070676429894067272105048512318726473299394190483894484000"
};

/* Per-level: LG1RHO (bit lengths) */
static const int SP_LG1RHO[] = { 208, 271, 336 };

/* Per-level: G1QRHO */
static const char *SP_G1QRHO[] = {
    "259932017632218835993369782263211224007969421304161083508208507352855014861224954584240000",
    "43947057178858349281469823683456747837008964566213302341175642613858213234180124996235330169158835649866435645207198005312780000",
    "912591522561821278596773661560381738487461196149374758031226045379636805516124374209533548227239075617507685978157416122232368826810589739482354141490542166888080000"
};

/* Per-level: G1qQRHO */
static const char *SP_G1qQRHO[] = {
    "63997580811605089901461886588211664277541743781178507127907222480599391279443741157968408096194052214975438487920000",
    "250893343838969877863024788106342431306813468937412573541937672939465921301334865939583469036925555704399706518309911896437823276514950457299755576516752580105417780352220000",
    "2592267806531457714429433492040209571481423408663539591272600175454852168743179040721147413119890879277149563138414212135077674649704847604432326896895145786034397225901388681187070510067902252928183759793847469262075483497272560000"
};

/* Per-level: phiG1RHO */
static const char *SP_PHIG1RHO[] = {
    "35211817745021271488319306579933617052512436633018795294720000",
    "420321257981034043095252041957047171374281436264017174140026587278944019415040000",
    "11962092013291449570594069903360588033560122759492301165447160574650084840217432160356538347683840000"
};

/* Per-level: phiphiG1RHO */
static const char *SP_PHIPHIG1RHO[] = {
    "3339014202762851772197706809901101110783647930348396871680000",
    "39857602929921489702080944341648626696561074583376366185880680612910512209920000",
    "1134323578986027073739504344459924880821604430088910642679765319339580831866513781010934026731520000"
};
```

**Step 3: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): replace system parameters with full Java parameter set

15+ decimal constants per level from SystemParameters.java.
Removes old N/phiN/Og1N/Og2N; adds G0,G1,q,Q,qQ,G1RHO,G1QRHO,G1qQRHO etc."
```

### Task 3: Rewrite runtime params struct and init/clear

**Files:**
- Modify: `SIGN/src/internal/sign.c:103-520` (runtime params struct, init, clear)

**Context:** The `kaz_runtime_params_t` struct currently holds N, phiN, Og1N, Og2N, g1g2, lb_g1, lb_g2, mont. Replace with all the BIGNUMs from the Java parameter set. The legacy params struct and init_params_cache can be removed entirely — all code should use the runtime params path.

**Step 1: Replace the runtime params struct**

```c
typedef struct {
    /* Common constants */
    BIGNUM *G0, *G1, *g, *R, *A;
    BIGNUM *phiG1, *phiphiG1;

    /* Per-level constants */
    BIGNUM *q, *Q, *qQ;
    BIGNUM *phiQ, *phiqQ;
    BIGNUM *G1RHO, *G1QRHO, *G1qQRHO;
    BIGNUM *phiG1RHO, *phiphiG1RHO;

    /* Derived values (computed at init) */
    BIGNUM *G1A;            /* G1 / A (for verification) */
    int LG1RHO;             /* Bit-length of G1RHO */

    /* Montgomery contexts for frequently-used moduli */
    BN_MONT_CTX *mont_G0;
    BN_MONT_CTX *mont_G1;
    BN_MONT_CTX *mont_G1qQRHO;

    /* Hash */
    EVP_MD_CTX *hash_ctx;
    const EVP_MD *hash_md;

    const kaz_sign_level_params_t *params;
    int initialized;
} kaz_runtime_params_t;
```

**Step 2: Rewrite init_runtime_params**

The function must:
1. Parse all decimal string constants via `BN_dec2bn()`
2. Select the correct per-level index (0=128, 1=192, 2=256)
3. Compute `G1A = G1 / A` (integer division via `BN_div`)
4. Set up Montgomery contexts for G0, G1, G1qQRHO
5. Select level-matched hash: `EVP_sha256()` / `EVP_sha384()` / `EVP_sha512()`

Key code for hash selection:

```c
switch (level) {
    case KAZ_LEVEL_128: rp->hash_md = EVP_sha256(); break;
    case KAZ_LEVEL_192: rp->hash_md = EVP_sha384(); break;
    case KAZ_LEVEL_256: rp->hash_md = EVP_sha512(); break;
    default: goto cleanup;
}
```

Key code for level index:

```c
int idx;
switch (level) {
    case KAZ_LEVEL_128: idx = 0; break;
    case KAZ_LEVEL_192: idx = 1; break;
    case KAZ_LEVEL_256: idx = 2; break;
    default: return KAZ_SIGN_ERROR_INVALID;
}
```

Then parse each per-level constant:
```c
if (!BN_dec2bn(&rp->q, SP_q[idx])) goto cleanup;
if (!BN_dec2bn(&rp->Q, SP_Q[idx])) goto cleanup;
/* ... etc for all per-level constants ... */
```

And common constants:
```c
if (!BN_dec2bn(&rp->G0, SP_G0)) goto cleanup;
if (!BN_dec2bn(&rp->G1, SP_G1)) goto cleanup;
if (!BN_dec2bn(&rp->R, SP_R)) goto cleanup;
/* ... etc ... */
```

Compute derived:
```c
rp->G1A = BN_new();
if (!BN_div(rp->G1A, NULL, rp->G1, rp->A, bn_ctx)) goto cleanup;
rp->LG1RHO = SP_LG1RHO[idx];
```

**Step 3: Rewrite clear_runtime_params**

Must `BN_clear_free()` all BIGNUMs and `BN_MONT_CTX_free()` all Montgomery contexts.

**Step 4: Remove legacy params**

Remove the `kaz_sign_params_legacy_t` struct, `g_params` global, `init_params_cache()`, `clear_params_cache()`, `get_level_strings()`, and the `g_hash_ctx`/`g_hash_md` globals.

Update `kaz_sign_init_random()` and `kaz_sign_clear_random()` to use runtime params for the compile-time level:

```c
int kaz_sign_init_random(void)
{
    if (g_rand_initialized) return KAZ_SIGN_SUCCESS;
    int ret = kaz_sign_init_level((kaz_sign_level_t)KAZ_SECURITY_LEVEL);
    if (ret == KAZ_SIGN_SUCCESS) g_rand_initialized = 1;
    return ret;
}
```

**Step 5: Verify init compiles**

Run: `cd SIGN && make clean && make test LEVEL=128 2>&1 | head -20`
Expected: Compilation may fail (keygen/sign/verify not updated yet) — that's OK. We want to verify the init/params code compiles without errors.

**Step 6: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): rewrite runtime params with full Java parameter set

New kaz_runtime_params_t with G0,G1,q,Q,qQ,G1RHO,G1QRHO,G1qQRHO etc.
Level-matched hash: SHA-256/384/512.
Removes legacy params struct and init_params_cache."
```

---

## Phase 3: Hash Function

### Task 4: Update hash functions to use level-matched SHA-256/384/512

**Files:**
- Modify: `SIGN/src/internal/sign.c` (kaz_sign_hash, kaz_sign_hash_ex)

**Context:** Current code always uses SHA-256 and zero-pads for 192/256. Java uses SHA-256 (L128), SHA-384 (L192), SHA-512 (L256) — each producing the native output size without padding.

**Step 1: Rewrite kaz_sign_hash_ex**

```c
int kaz_sign_hash_ex(kaz_sign_level_t level,
                     const unsigned char *msg,
                     unsigned long long msglen,
                     unsigned char *hash)
{
    kaz_runtime_params_t *rp = get_runtime_params(level);
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    unsigned int hash_len = 0;

    if (!rp || !params) return KAZ_SIGN_ERROR_INVALID;

    if (!rp->initialized) {
        int ret = init_runtime_params(rp, level);
        if (ret != KAZ_SIGN_SUCCESS) return ret;
    }

    if (!rp->hash_ctx || !rp->hash_md) return KAZ_SIGN_ERROR_INVALID;
    if (msglen > (unsigned long long)SIZE_MAX) return KAZ_SIGN_ERROR_INVALID;
    if (msg == NULL && msglen > 0) return KAZ_SIGN_ERROR_INVALID;

    if (EVP_DigestInit_ex(rp->hash_ctx, rp->hash_md, NULL) != 1)
        return KAZ_SIGN_ERROR_HASH;

    if (msg != NULL && msglen > 0) {
        if (EVP_DigestUpdate(rp->hash_ctx, msg, (size_t)msglen) != 1)
            return KAZ_SIGN_ERROR_HASH;
    }

    if (EVP_DigestFinal_ex(rp->hash_ctx, hash, &hash_len) != 1)
        return KAZ_SIGN_ERROR_HASH;

    /* hash_len should match params->hash_bytes (32/48/64) */
    return KAZ_SIGN_SUCCESS;
}
```

**Step 2: Update kaz_sign_hash (compile-time level)**

Same pattern but using the compile-time level's runtime params. Should delegate to `kaz_sign_hash_ex`:

```c
int kaz_sign_hash(const unsigned char *msg,
                  unsigned long long msglen,
                  unsigned char *hash)
{
    if (!g_rand_initialized) {
        int ret = kaz_sign_init_random();
        if (ret != KAZ_SIGN_SUCCESS) return ret;
    }
    return kaz_sign_hash_ex((kaz_sign_level_t)KAZ_SECURITY_LEVEL, msg, msglen, hash);
}
```

**Step 3: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): level-matched hashing SHA-256/384/512

L128=SHA-256(32), L192=SHA-384(48), L256=SHA-512(64).
No more zero-padding. Matches Java Hasher.java exactly."
```

---

## Phase 4: Key Generation

### Task 5: Rewrite key generation to match Java

**Files:**
- Modify: `SIGN/src/internal/sign.c` (kaz_sign_keypair_ex, kaz_sign_keypair)

**Context:** Java `KAZSIGNKeyGenerator.java` uses an α-based derivation producing (V1, V2, SK). The C library currently uses random s,t with V = g1^s * g2^t mod N.

**Step 1: Implement helper — generate 4 random bytes as BigInteger**

```c
/* Generate a random BIGNUM from 4 random bytes (matching Java's getRandom.nextBytes(4)) */
static int bn_random_4bytes(BIGNUM *result)
{
    unsigned char buf[4];
    if (RAND_bytes(buf, 4) != 1) return -1;
    if (BN_bin2bn(buf, 4, result) == NULL) return -1;
    return 0;
}
```

**Step 2: Implement helper — next probable prime**

```c
/* Find the next probable prime >= bn (matching Java's BigInteger.nextProbablePrime()) */
static int bn_next_probable_prime(BIGNUM *result, const BIGNUM *start, BN_CTX *ctx)
{
    if (!BN_copy(result, start)) return -1;
    /* Ensure odd */
    if (!BN_is_odd(result)) {
        if (!BN_add_word(result, 1)) return -1;
    }
    /* Search for prime */
    for (int i = 0; i < 10000; i++) {
        int is_prime = BN_check_prime(result, ctx, NULL);
        if (is_prime == 1) return 0;
        if (is_prime < 0) return -1;
        if (!BN_add_word(result, 2)) return -1;
    }
    return -1; /* Failed to find prime */
}
```

**Step 3: Rewrite kaz_sign_keypair_ex**

The new algorithm (from KAZSIGNKeyGenerator.java):

```c
int kaz_sign_keypair_ex(kaz_sign_level_t level,
                        unsigned char *pk,
                        unsigned char *sk)
{
    kaz_runtime_params_t *rp = get_runtime_params(level);
    const kaz_sign_level_params_t *params;
    BIGNUM *a = NULL, *omega1 = NULL, *b = NULL;
    BIGNUM *alpha = NULL, *V1 = NULL, *V2 = NULL, *SK = NULL;
    BIGNUM *tmp = NULL, *tmp2 = NULL, *G1A = NULL;
    BIGNUM *phiQb = NULL;
    BN_CTX *local_ctx = NULL;
    int ret = KAZ_SIGN_ERROR_MEMORY;
    int alpha_bytes;

    if (!rp) return KAZ_SIGN_ERROR_INVALID;
    if (!pk || !sk) return KAZ_SIGN_ERROR_INVALID;

    if (!rp->initialized) {
        ret = init_runtime_params(rp, level);
        if (ret != KAZ_SIGN_SUCCESS) return ret;
    }

    params = rp->params;
    local_ctx = BN_CTX_new();
    if (!local_ctx) return KAZ_SIGN_ERROR_MEMORY;

    /* Allocate */
    a = BN_new(); omega1 = BN_new(); b = BN_new();
    alpha = BN_secure_new(); V1 = BN_new(); V2 = BN_new();
    SK = BN_secure_new();
    tmp = BN_new(); tmp2 = BN_new();
    phiQb = BN_new();

    if (!a || !omega1 || !b || !alpha || !V1 || !V2 || !SK ||
        !tmp || !tmp2 || !phiQb) goto cleanup;

    bn_set_secret(alpha);
    bn_set_secret(SK);

    /* 1. a = random_4_bytes().nextProbablePrime() */
    if (bn_random_4bytes(tmp) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
    if (bn_next_probable_prime(a, tmp, local_ctx) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }

    /* 2. omega1 = random_4_bytes() */
    if (bn_random_4bytes(omega1) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }

    /* 3. b = a^(phiphiG1RHO) mod (omega1 * phiG1RHO) */
    if (!BN_mul(tmp, omega1, rp->phiG1RHO, local_ctx)) goto cleanup;
    if (!BN_mod_exp(b, a, rp->phiphiG1RHO, tmp, local_ctx)) goto cleanup;

    /* 4. phiQb = phiQ * b */
    if (!BN_mul(phiQb, rp->phiQ, b, local_ctx)) goto cleanup;

    /* 5. alpha_bytes = (level + LG1RHO) / 8 */
    alpha_bytes = (params->level + rp->LG1RHO) / 8;

    /* 6. Loop until valid key */
    for (int attempt = 0; attempt < 1000; attempt++) {
        /* a. alpha = random(alpha_bytes) * 2 */
        unsigned char *alpha_buf = malloc(alpha_bytes);
        if (!alpha_buf) { ret = KAZ_SIGN_ERROR_MEMORY; goto cleanup; }
        if (RAND_bytes(alpha_buf, alpha_bytes) != 1) {
            free(alpha_buf);
            ret = KAZ_SIGN_ERROR_RNG; goto cleanup;
        }
        if (BN_bin2bn(alpha_buf, alpha_bytes, alpha) == NULL) {
            free(alpha_buf);
            goto cleanup;
        }
        free(alpha_buf);
        if (!BN_lshift1(alpha, alpha)) goto cleanup;  /* multiply by 2 */

        /* b. V1 = alpha mod G1RHO */
        if (!BN_mod(V1, alpha, rp->G1RHO, local_ctx)) goto cleanup;

        /* c. V2 = Q * alpha^(phiQ*b) mod qQ */
        if (!BN_mod_exp(tmp, alpha, phiQb, rp->qQ, local_ctx)) goto cleanup;
        if (!BN_mod_mul(V2, rp->Q, tmp, rp->qQ, local_ctx)) goto cleanup;

        /* d. SK = alpha^(phiQ*b) mod G1qQRHO */
        if (!BN_mod_exp(SK, alpha, phiQb, rp->G1qQRHO, local_ctx)) goto cleanup;

        /* e. Accept if SK mod G1QRHO != 0 AND gcd(V1, G1A) == 1 */
        if (!BN_mod(tmp, SK, rp->G1QRHO, local_ctx)) goto cleanup;
        if (BN_is_zero(tmp)) continue;

        if (!BN_gcd(tmp, V1, rp->G1A, local_ctx)) goto cleanup;
        if (!BN_is_one(tmp)) continue;

        /* Valid key found! Export. */
        /* pk = V1 || V2 */
        if (bn_export_padded(pk, params->v1_bytes, V1) != 0) goto cleanup;
        if (bn_export_padded(pk + params->v1_bytes, params->v2_bytes, V2) != 0) goto cleanup;

        /* sk = SK || V1 || V2 */
        if (bn_export_padded(sk, params->sk_bytes, SK) != 0) goto cleanup;
        if (bn_export_padded(sk + params->sk_bytes, params->v1_bytes, V1) != 0) goto cleanup;
        if (bn_export_padded(sk + params->sk_bytes + params->v1_bytes, params->v2_bytes, V2) != 0) goto cleanup;

        ret = KAZ_SIGN_SUCCESS;
        goto cleanup;
    }

    ret = KAZ_SIGN_ERROR_RNG; /* Failed after max attempts */

cleanup:
    BN_CTX_free(local_ctx);
    BN_free(a); BN_free(omega1); BN_free(b);
    bn_secure_free(alpha);
    BN_free(V1); BN_free(V2);
    bn_secure_free(SK);
    BN_free(tmp); BN_free(tmp2);
    BN_free(phiQb);
    return ret;
}
```

**Step 4: Update kaz_sign_keypair (compile-time)**

```c
int kaz_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    if (!g_rand_initialized) {
        int ret = kaz_sign_init_random();
        if (ret != KAZ_SIGN_SUCCESS) return ret;
    }
    return kaz_sign_keypair_ex((kaz_sign_level_t)KAZ_SECURITY_LEVEL, pk, sk);
}
```

**Step 5: Build and run basic keygen test**

Run: `cd SIGN && make clean && make test LEVEL=128 2>&1 | head -40`
Expected: Should compile. Tests will likely fail on sign/verify (not yet updated) but keygen should succeed.

**Step 6: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): rewrite keygen to match Java KAZSIGNKeyGenerator

Alpha-based derivation: V1=alpha mod G1RHO, V2=Q*alpha^(phiQ*b) mod qQ,
SK=alpha^(phiQ*b) mod G1qQRHO. pk=V1||V2, sk=SK||V1||V2."
```

---

## Phase 5: Signing

### Task 6: Implement CRT helper and new signing algorithm

**Files:**
- Modify: `SIGN/src/internal/sign.c` (kaz_sign_signature_ex)

**Context:** Java `KAZSIGNSigner.java` computes S1 = SK * (h^(phiqQ*beta1) + h^(phiqQ*beta2)) mod G1qQRHO with a CRT-based pre-verification filter. S2 is a counter (≤65535).

**Step 1: Implement CRT helper**

```c
/*
 * Chinese Remainder Theorem for two moduli (matches Java chrem()).
 * result = CRT(a1, a2, m1, m2)
 */
static int bn_chrem(BIGNUM *result, const BIGNUM *a1, const BIGNUM *a2,
                    const BIGNUM *m1, const BIGNUM *m2, BN_CTX *ctx)
{
    BIGNUM *m1Inv = BN_new();
    BIGNUM *diff = BN_new();
    BIGNUM *term = BN_new();
    BIGNUM *m1m2 = BN_new();
    int ret = -1;

    if (!m1Inv || !diff || !term || !m1m2) goto cleanup;

    /* m1Inv = m1^(-1) mod m2 */
    if (!BN_mod_inverse(m1Inv, m1, m2, ctx)) goto cleanup;

    /* diff = a2 - a1 */
    if (!BN_sub(diff, a2, a1)) goto cleanup;

    /* m1m2 = m1 * m2 */
    if (!BN_mul(m1m2, m1, m2, ctx)) goto cleanup;

    /* term = diff * m1 * m1Inv mod (m1*m2) */
    if (!BN_mod_mul(term, diff, m1, m1m2, ctx)) goto cleanup;
    if (!BN_mod_mul(term, term, m1Inv, m1m2, ctx)) goto cleanup;

    /* result = (a1 + term) mod (m1*m2) */
    if (!BN_mod_add(result, a1, term, m1m2, ctx)) goto cleanup;

    ret = 0;

cleanup:
    BN_free(m1Inv); BN_free(diff);
    BN_free(term); BN_free(m1m2);
    return ret;
}
```

**Step 2: Rewrite kaz_sign_signature_ex**

The new signing algorithm from KAZSIGNSigner.java. This is a complete rewrite — the new function:

1. Parses SK, V1, V2 from the private key (sk = SK||V1||V2)
2. Hashes the message with level-matched hash
3. Generates random blinding factors (beta1, beta2)
4. Loops: computes S1, checks filter (bitlength + CRT), increments S2 and hashInt on failure
5. Outputs detached signature S1||S2 in message-recovery format (S1||S2||msg)

Key differences from old code:
- No e1/e2 rejection sampling, no blinded inverse
- S2 is a simple counter, not a modulus-sized value
- Pre-verification CRT filter in signing loop
- Private key parsed as SK||V1||V2 (not s||t)

The full function body should follow KAZSIGNSigner.java step by step. Key code sections:

```c
/* Import secret key: SK || V1 || V2 */
if (bn_import(SK, sk, params->sk_bytes) != 0) goto cleanup;
if (bn_import(V1, sk + params->sk_bytes, params->v1_bytes) != 0) goto cleanup;
if (bn_import(V2, sk + params->sk_bytes + params->v1_bytes, params->v2_bytes) != 0) goto cleanup;

/* Random blinding setup (matches Java's 4-byte random + nextProbablePrime) */
if (bn_random_4bytes(tmp) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
if (bn_next_probable_prime(r1, tmp, local_ctx) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
if (bn_random_4bytes(omega2) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
if (bn_random_4bytes(tmp) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
if (bn_next_probable_prime(r2, tmp, local_ctx) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }
if (bn_random_4bytes(omega3) != 0) { ret = KAZ_SIGN_ERROR_RNG; goto cleanup; }

/* beta1 = r1^(phiphiG1RHO) mod (omega2 * phiG1RHO) */
if (!BN_mul(tmp, omega2, rp->phiG1RHO, local_ctx)) goto cleanup;
if (!BN_mod_exp(beta1, r1, rp->phiphiG1RHO, tmp, local_ctx)) goto cleanup;

/* beta2 = r2^(phiphiG1RHO) mod (omega3 * phiG1RHO) */
if (!BN_mul(tmp, omega3, rp->phiG1RHO, local_ctx)) goto cleanup;
if (!BN_mod_exp(beta2, r2, rp->phiphiG1RHO, tmp, local_ctx)) goto cleanup;

int LG1qQ = BN_num_bits(rp->G1qQRHO);
unsigned long s2_counter = 0;

/* Signing loop */
while (s2_counter <= 65535) {
    /* term1 = hashInt^(phiqQ * beta1) mod G1qQRHO */
    if (!BN_mul(tmp, rp->phiqQ, beta1, local_ctx)) goto cleanup;
    if (!BN_mod_exp(term1, hashInt, tmp, rp->G1qQRHO, local_ctx)) goto cleanup;

    /* term2 = hashInt^(phiqQ * beta2) mod G1qQRHO */
    if (!BN_mul(tmp, rp->phiqQ, beta2, local_ctx)) goto cleanup;
    if (!BN_mod_exp(term2, hashInt, tmp, rp->G1qQRHO, local_ctx)) goto cleanup;

    /* S1 = SK * (term1 + term2) mod G1qQRHO */
    if (!BN_mod_add(tmp, term1, term2, rp->G1qQRHO, local_ctx)) goto cleanup;
    if (!BN_mod_mul(S1, SK, tmp, rp->G1qQRHO, local_ctx)) goto cleanup;

    /* Pre-verification filter: CRT check */
    /* Y1 = V1^phiQ * 2*hashInt^phiqQ mod G1QRHO */
    if (!BN_mod_exp(tmp, V1, rp->phiQ, rp->G1QRHO, local_ctx)) goto cleanup;
    if (!BN_mod_exp(tmp2, hashInt, rp->phiqQ, rp->G1QRHO, local_ctx)) goto cleanup;
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);
    if (!BN_mod_mul(tmp2, two, tmp2, rp->G1QRHO, local_ctx)) { BN_free(two); goto cleanup; }
    if (!BN_mod_mul(Y1, tmp, tmp2, rp->G1QRHO, local_ctx)) { BN_free(two); goto cleanup; }
    BN_free(two);

    /* SF1 = CRT(V2/Q, Y1, q, G1QRHO) */
    if (!BN_div(tmp, NULL, V2, rp->Q, local_ctx)) goto cleanup;
    if (bn_chrem(SF1, tmp, Y1, rp->q, rp->G1QRHO, local_ctx) != 0) goto cleanup;

    /* Accept if bitlen(S1) == LG1qQ AND S1 mod G1qQRHO != SF1 */
    if (BN_num_bits(S1) == LG1qQ) {
        if (!BN_mod(tmp, S1, rp->G1qQRHO, local_ctx)) goto cleanup;
        if (BN_cmp(tmp, SF1) != 0) {
            break; /* Valid signature found */
        }
    }

    /* Retry: S2++, hashInt++ */
    s2_counter++;
    if (!BN_add_word(hashInt, 1)) goto cleanup;
}

if (s2_counter > 65535) {
    ret = KAZ_SIGN_ERROR_INVALID;
    goto cleanup;
}
```

**Step 3: Export signature in message-recovery format**

```c
/* Export: S1 || S2 || message */
if (bn_export_padded(sig, params->s1_bytes, S1) != 0) goto cleanup;

/* S2 is an 8-byte big-endian counter */
memset(sig + params->s1_bytes, 0, params->s2_bytes);
sig[params->s1_bytes + params->s2_bytes - 1] = (unsigned char)(s2_counter & 0xFF);
sig[params->s1_bytes + params->s2_bytes - 2] = (unsigned char)((s2_counter >> 8) & 0xFF);
/* (remaining 6 bytes are already zeroed) */

if (msglen > 0) {
    memcpy(sig + params->signature_overhead, msg, msglen);
}
*siglen = params->signature_overhead + msglen;
```

**Step 4: Update kaz_sign_signature (compile-time)**

```c
int kaz_sign_signature(unsigned char *sig, unsigned long long *siglen,
                       const unsigned char *msg, unsigned long long msglen,
                       const unsigned char *sk)
{
    if (!g_rand_initialized) {
        int ret = kaz_sign_init_random();
        if (ret != KAZ_SIGN_SUCCESS) return ret;
    }
    return kaz_sign_signature_ex((kaz_sign_level_t)KAZ_SECURITY_LEVEL,
                                  sig, siglen, msg, msglen, sk);
}
```

**Step 5: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): rewrite signing to match Java KAZSIGNSigner

2-component signature: S1=SK*(h^(phiqQ*beta1)+h^(phiqQ*beta2)) mod G1qQRHO,
S2=counter. CRT pre-verification filter in signing loop.
Adds bn_chrem() CRT helper, bn_random_4bytes(), bn_next_probable_prime()."
```

---

## Phase 6: Verification

### Task 7: Implement 5-filter verification matching Java

**Files:**
- Modify: `SIGN/src/internal/sign.c` (kaz_sign_verify_ex, kaz_sign_verify)

**Context:** Java `KAZSIGNVerifier.java` has 5 filter checks then 2 verification equations. The current C code has a single Y1==Y2 check. Complete rewrite.

**Step 1: Rewrite kaz_sign_verify_ex**

The function:
1. Extracts S1, S2 from signature (S2 is 8-byte big-endian counter)
2. Extracts V1, V2 from public key
3. Applies 5 filters
4. Applies 2 verification equations
5. If message-recovery mode: extracts embedded message

Key code:

```c
int kaz_sign_verify_ex(kaz_sign_level_t level,
                       unsigned char *msg, unsigned long long *msglen,
                       const unsigned char *sig, unsigned long long siglen,
                       const unsigned char *pk)
{
    /* ... setup ... */

    /* Import public key: V1 || V2 */
    if (bn_import(V1, pk, params->v1_bytes) != 0) goto cleanup;
    if (bn_import(V2, pk + params->v1_bytes, params->v2_bytes) != 0) goto cleanup;

    /* Import signature: S1 || S2 || [message] */
    if (bn_import(S1, sig, params->s1_bytes) != 0) goto cleanup;

    /* S2 is 8-byte big-endian counter */
    uint64_t s2_val = 0;
    for (int i = 0; i < (int)params->s2_bytes; i++) {
        s2_val = (s2_val << 8) | sig[params->s1_bytes + i];
    }
    if (!BN_set_word(S2, (BN_ULONG)s2_val)) goto cleanup;

    /* Filter 0: S2 <= 65535 */
    if (s2_val > 65535) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }

    /* Hash the embedded message */
    const unsigned char *embedded_msg = sig + params->signature_overhead;
    unsigned long long extracted_msglen = siglen - params->signature_overhead;

    if (kaz_sign_hash_ex(level, embedded_msg, extracted_msglen, hash_buf) != KAZ_SIGN_SUCCESS)
        goto cleanup;
    if (bn_import(hashInt, hash_buf, params->hash_bytes) != 0) goto cleanup;

    /* hashInt += S2 (Java: BigInteger(hash).add(S2)) */
    if (!BN_add(hashInt, hashInt, S2)) goto cleanup;

    /* Filter 1: S1 in [0, G1qQRHO) */
    if (BN_cmp(S1, rp->G1qQRHO) >= 0) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    if (BN_is_negative(S1)) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }

    /* Filter 2: bitlen(S1) <= bitlen(G1qQRHO) */
    if (BN_num_bits(S1) > BN_num_bits(rp->G1qQRHO)) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }

    /* Filter 3: S1 mod G1qQRHO != CRT(V2/Q, Y1, q, G1QRHO) */
    {
        BIGNUM *Y1f = BN_new(), *SF1 = BN_new(), *v2q = BN_new(), *two = BN_new();
        if (!Y1f || !SF1 || !v2q || !two) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        BN_set_word(two, 2);

        /* Y1 = V1^phiQ * 2*hashInt^phiqQ mod G1QRHO */
        if (!BN_mod_exp(tmp, V1, rp->phiQ, rp->G1QRHO, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        if (!BN_mod_exp(tmp2, hashInt, rp->phiqQ, rp->G1QRHO, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        if (!BN_mod_mul(tmp2, two, tmp2, rp->G1QRHO, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        if (!BN_mod_mul(Y1f, tmp, tmp2, rp->G1QRHO, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }

        if (!BN_div(v2q, NULL, V2, rp->Q, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        if (bn_chrem(SF1, v2q, Y1f, rp->q, rp->G1QRHO, local_ctx) != 0) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }

        if (!BN_mod(tmp, S1, rp->G1qQRHO, local_ctx)) { BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two); goto cleanup; }
        int f3_fail = (BN_cmp(tmp, SF1) == 0);
        BN_free(Y1f); BN_free(SF1); BN_free(v2q); BN_free(two);
        if (f3_fail) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    }

    /* Filter 4: S1 mod (G1qQRHO/e) != CRT(V2/Q, Y2, qQ/e, G1RHO) */
    {
        BIGNUM *e = BN_new(), *Y2f = BN_new(), *SF2 = BN_new();
        BIGNUM *v2q = BN_new(), *G1qQRHOe = BN_new(), *qQe = BN_new(), *two = BN_new();
        /* ... allocate and null-check ... */
        BN_set_word(two, 2);

        /* e = gcd(Q, G1RHO) */
        if (!BN_gcd(e, rp->Q, rp->G1RHO, local_ctx)) goto f4_cleanup;

        /* Y2 = V1^phiQ * 2*hashInt^phiqQ mod G1RHO */
        if (!BN_mod_exp(tmp, V1, rp->phiQ, rp->G1RHO, local_ctx)) goto f4_cleanup;
        if (!BN_mod_exp(tmp2, hashInt, rp->phiqQ, rp->G1RHO, local_ctx)) goto f4_cleanup;
        if (!BN_mod_mul(tmp2, two, tmp2, rp->G1RHO, local_ctx)) goto f4_cleanup;
        if (!BN_mod_mul(Y2f, tmp, tmp2, rp->G1RHO, local_ctx)) goto f4_cleanup;

        if (!BN_div(v2q, NULL, V2, rp->Q, local_ctx)) goto f4_cleanup;
        if (!BN_div(qQe, NULL, rp->qQ, e, local_ctx)) goto f4_cleanup;
        if (bn_chrem(SF2, v2q, Y2f, qQe, rp->G1RHO, local_ctx) != 0) goto f4_cleanup;

        if (!BN_div(G1qQRHOe, NULL, rp->G1qQRHO, e, local_ctx)) goto f4_cleanup;
        if (!BN_mod(tmp, S1, G1qQRHOe, local_ctx)) goto f4_cleanup;
        int f4_fail = (BN_cmp(tmp, SF2) == 0);
        /* ... cleanup and check ... */
        if (f4_fail) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    }

    /* Filter 5: 2*V2 - Q*S1 ≡ 0 (mod qQ) */
    {
        BIGNUM *two = BN_new(), *W4 = BN_new(), *W5 = BN_new();
        BN_set_word(two, 2);
        /* W4 = Q*S1 mod qQ */
        if (!BN_mod_mul(W4, rp->Q, S1, rp->qQ, local_ctx)) { ... goto cleanup; }
        /* W5 = 2*V2 mod qQ - W4 */
        if (!BN_mod_mul(tmp, two, V2, rp->qQ, local_ctx)) { ... goto cleanup; }
        if (!BN_mod_sub(W5, tmp, W4, rp->qQ, local_ctx)) { ... goto cleanup; }
        int f5_fail = !BN_is_zero(W5);
        /* ... cleanup ... */
        if (f5_fail) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    }

    /* Verification equation 1: R^S1 == R^(V1^phiQ * 2*hashInt^phiqQ mod G1) mod G0 */
    {
        if (!BN_mod_exp_mont(y1, rp->R, S1, rp->G0, local_ctx, rp->mont_G0)) goto cleanup;

        /* t1 = V1^phiQ mod G1 */
        if (!BN_mod_exp(t1, V1, rp->phiQ, rp->G1, local_ctx)) goto cleanup;
        /* t2 = hashInt^phiqQ mod G1 */
        if (!BN_mod_exp(t2, hashInt, rp->phiqQ, rp->G1, local_ctx)) goto cleanup;
        /* t3 = hashInt^phiqQ mod G1 (same as t2) */
        /* exp_val = t1 * (t2 + t3) mod G1 = t1 * 2*t2 mod G1 */
        BIGNUM *two = BN_new(); BN_set_word(two, 2);
        if (!BN_mod_mul(tmp, two, t2, rp->G1, local_ctx)) { BN_free(two); goto cleanup; }
        if (!BN_mod_mul(tmp, t1, tmp, rp->G1, local_ctx)) { BN_free(two); goto cleanup; }
        BN_free(two);
        if (!BN_mod_exp_mont(y2, rp->R, tmp, rp->G0, local_ctx, rp->mont_G0)) goto cleanup;

        if (BN_cmp(y1, y2) != 0) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    }

    /* Verification equation 2: S1 * inv(V1^phiQ, G1A) == 2*hashInt^phiqQ mod G1A */
    {
        /* G1A = G1RHO / A (pre-computed in rp->G1A)
         * But Java uses G1RHO[idx] / A, not G1 / A -- need to check */
        BIGNUM *G1A_local = BN_new();
        if (!BN_div(G1A_local, NULL, rp->G1RHO, rp->A, local_ctx)) { BN_free(G1A_local); goto cleanup; }

        BIGNUM *inv_val = BN_new();
        if (!BN_mod_exp(tmp, V1, rp->phiQ, G1A_local, local_ctx)) { BN_free(G1A_local); BN_free(inv_val); goto cleanup; }
        if (!BN_mod_inverse(inv_val, tmp, G1A_local, local_ctx)) { BN_free(G1A_local); BN_free(inv_val); goto cleanup; }

        /* y3 = S1 * inv mod G1A */
        if (!BN_mod_mul(y3, S1, inv_val, G1A_local, local_ctx)) { BN_free(G1A_local); BN_free(inv_val); goto cleanup; }

        /* y4 = 2 * hashInt^phiqQ mod G1A */
        BIGNUM *two = BN_new(); BN_set_word(two, 2);
        if (!BN_mod_exp(tmp, hashInt, rp->phiqQ, G1A_local, local_ctx)) { BN_free(G1A_local); BN_free(inv_val); BN_free(two); goto cleanup; }
        if (!BN_mod_mul(y4, two, tmp, G1A_local, local_ctx)) { BN_free(G1A_local); BN_free(inv_val); BN_free(two); goto cleanup; }
        BN_free(two);

        int final_fail = (BN_cmp(y3, y4) != 0);
        BN_free(G1A_local); BN_free(inv_val);
        if (final_fail) { ret = KAZ_SIGN_ERROR_VERIFY; goto cleanup; }
    }

    /* Valid! Copy out the message */
    if (extracted_msglen > 0) {
        memcpy(msg, embedded_msg, extracted_msglen);
    }
    *msglen = extracted_msglen;
    ret = KAZ_SIGN_SUCCESS;
```

**Step 2: Update kaz_sign_verify (compile-time)**

```c
int kaz_sign_verify(unsigned char *msg, unsigned long long *msglen,
                    const unsigned char *sig, unsigned long long siglen,
                    const unsigned char *pk)
{
    if (!g_rand_initialized) {
        if (kaz_sign_init_random() != KAZ_SIGN_SUCCESS)
            return KAZ_SIGN_ERROR_INVALID;
    }
    return kaz_sign_verify_ex((kaz_sign_level_t)KAZ_SECURITY_LEVEL,
                               msg, msglen, sig, siglen, pk);
}
```

**Step 3: Build and run sign/verify round-trip**

Run: `cd SIGN && make clean && make test LEVEL=128 2>&1 | head -60`
Expected: Keygen + sign + verify round-trip should work at this point.

**Step 4: Commit**

```bash
git add SIGN/src/internal/sign.c
git commit -m "feat(sign): implement 5-filter verification matching Java KAZSIGNVerifier

Filters: S2<=65535, S1 range, bitlength, CRT filter 3, CRT filter 4, congruence.
Verification: R^S1 == R^(V1^phiQ * 2*h^phiqQ mod G1) mod G0,
plus S1*inv(V1^phiQ) == 2*h^phiqQ mod G1A."
```

---

## Phase 7: Detached Mode & Message-Recovery Shims

### Task 8: Simplify detached.c for natively detached signatures

**Files:**
- Modify: `SIGN/src/internal/detached.c`

**Context:** Signatures are now natively detached (S1||S2). The message-recovery `kaz_sign_signature_ex` wraps detached as `S1||S2||msg`. So `detached.c` should call the core sign/verify directly without the old message-recovery wrapping.

The `kaz_sign_detached_prehashed_ex` function currently wraps through message-recovery mode. Now it should directly compute S1||S2 without the intermediate full_sig allocation. The simplest approach: have detached_prehashed_ex directly call kaz_sign_signature_ex with the hash as the "message", then strip the appended hash.

Actually, the simplest correct approach is to keep the current detached.c mostly as-is. Since `kaz_sign_signature_ex` now outputs `S1||S2||msg`, the prehashed function still works: it signs the hash, gets `S1||S2||hash`, and extracts `S1||S2`. The sizes just changed.

**Step 1: Update comments in detached.c**

Replace references to "S1||S2||S3" with "S1||S2". Update the module comment at the top.

**Step 2: Verify detached tests compile and pass**

Run: `cd SIGN && make clean && make test LEVEL=128`
Run: `cd SIGN && make test-extensions LEVEL=128`
Expected: All pass.

**Step 3: Commit**

```bash
git add SIGN/src/internal/detached.c
git commit -m "fix(sign): update detached.c comments for 2-component signatures"
```

---

## Phase 8: Tests

### Task 9: Update test_sign.c for new algorithm

**Files:**
- Modify: `SIGN/tests/unit/test_sign.c`

**Context:** The test suite uses hardcoded sizes (`KAZ_SIGN_S3BYTES`, `KAZ_SIGN_SBYTES`, `KAZ_SIGN_TBYTES`, etc.) that no longer exist. All buffer sizes, signature structure references, and size checks must be updated.

**Step 1: Update buffer declarations**

Replace all uses of removed macros:
- `KAZ_SIGN_SBYTES` → `KAZ_SIGN_SKBYTES` (or use `params->sk_bytes`)
- `KAZ_SIGN_TBYTES` → remove (no t component)
- `KAZ_SIGN_S3BYTES` → remove (no S3 component)
- `KAZ_SIGN_VBYTES` → remove (replaced by V1BYTES+V2BYTES)
- Signature buffer: was `KAZ_SIGN_S1BYTES + KAZ_SIGN_S2BYTES + KAZ_SIGN_S3BYTES + msglen`, now `KAZ_SIGN_S1BYTES + KAZ_SIGN_S2BYTES + msglen`

**Step 2: Update runtime API tests**

For `_ex` tests that use `params->s_bytes`, `params->t_bytes`, `params->s3_bytes`:
- Replace with `params->sk_bytes`, `params->v1_bytes`, `params->v2_bytes`
- Update all buffer allocations to use new sizes

**Step 3: Remove tests that check old algorithm behavior**

Tests that check 3-component signature structure, or verify V = g1^s * g2^t mod N, no longer apply.

**Step 4: Add new tests**

- Test that S2 counter is ≤ 65535 in produced signatures
- Test that public key decomposes into v1 + v2 at correct sizes
- Test that private key contains SK + v1 + v2

**Step 5: Build and run all tests**

Run: `cd SIGN && make clean && make test LEVEL=128`
Run: `cd SIGN && make test-all`
Expected: All tests pass at all levels.

**Step 6: Commit**

```bash
git add SIGN/tests/unit/test_sign.c
git commit -m "test(sign): update tests for new 2-component algorithm

New key structure (SK+v1+v2), 2-component signatures (S1+S2),
removes references to s/t/S3/V/N/phiN."
```

### Task 10: Update test_kazwire.c for new sizes

**Files:**
- Modify: `SIGN/tests/unit/test_kazwire.c`

**Context:** KazWire tests use hardcoded buffer sizes that changed.

**Step 1: Update buffer sizes and expected wire lengths**

All `s3_bytes` references removed. Signature wire now carries S1+S2 (57/81/105) not S1+S2+S3 (162/264/354).

**Step 2: Build and run**

Run: `cd SIGN && make test-wire LEVEL=128`
Expected: All pass.

**Step 3: Commit**

```bash
git add SIGN/tests/unit/test_kazwire.c
git commit -m "test(sign): update KazWire tests for new key/sig sizes"
```

### Task 11: Update test_detached.c, test_der.c, test_x509.c, test_p12.c

**Files:**
- Modify: `SIGN/tests/unit/test_detached.c`
- Modify: `SIGN/tests/unit/test_der.c`
- Modify: `SIGN/tests/unit/test_x509.c`
- Modify: `SIGN/tests/unit/test_p12.c`

**Context:** These tests reference old sizes. Update buffer allocations and expected sizes.

**Step 1: Update each test file**

Replace old macros and size references with new ones. The core test logic (round-trip sign/verify, DER encode/decode, X.509 cert issue/verify) should still work since the API function signatures haven't changed.

**Step 2: Build and run all extension tests**

Run: `cd SIGN && make test-extensions LEVEL=128`
Run: `cd SIGN && make test-all`
Expected: All pass at all levels.

**Step 3: Commit**

```bash
git add SIGN/tests/unit/test_detached.c SIGN/tests/unit/test_der.c \
       SIGN/tests/unit/test_x509.c SIGN/tests/unit/test_p12.c
git commit -m "test(sign): update extension tests for new algorithm sizes"
```

---

## Phase 9: NIST Wrapper & KAT

### Task 12: Update NIST wrapper

**Files:**
- Modify: `SIGN/src/internal/nist_wrapper.c` (if needed)
- Modify: `SIGN/include/kaz/nist_api.h` (if needed)

**Context:** The NIST wrapper calls `kaz_sign_keypair`, `kaz_sign_signature`, `kaz_sign_verify`. These function signatures haven't changed. The wrapper should work as-is, but verify the NIST API header constants are correct.

**Step 1: Check nist_api.h for hardcoded sizes**

If `nist_api.h` defines `CRYPTO_SECRETKEYBYTES`, `CRYPTO_PUBLICKEYBYTES`, `CRYPTO_BYTES` — these must match the new values.

**Step 2: Update if needed and build**

Run: `cd SIGN && make kat LEVEL=128`
Expected: KAT generator builds and runs.

**Step 3: Commit**

```bash
git add SIGN/include/kaz/nist_api.h SIGN/src/internal/nist_wrapper.c
git commit -m "fix(sign): update NIST API sizes for new algorithm"
```

### Task 13: Regenerate KAT vectors

**Files:**
- Regenerate: `SIGN/PQCsignKAT_*.req`, `SIGN/PQCsignKAT_*.rsp`

**Step 1: Generate KATs for all levels**

```bash
cd SIGN
make clean && make kat LEVEL=128
cp PQCsignKAT_*.req PQCsignKAT_*.rsp .  # or they may be in build/
make clean && make kat LEVEL=192
make clean && make kat LEVEL=256
```

**Step 2: Commit**

```bash
git add SIGN/PQCsign*
git commit -m "chore(sign): regenerate KAT vectors for new algorithm"
```

---

## Phase 10: Bindings

### Task 14: Update Swift binding sizes

**Files:**
- Modify: `SIGN/bindings/swift/Sources/KazSign/KazSign.swift`
- Modify: `SIGN/bindings/swift/KazSignNative.xcframework/*/Headers/sign.h` (3 files)

**Step 1: Update hardcoded sizes in KazSign.swift**

```
L128: secretKeyBytes=98, publicKeyBytes=49, signatureOverhead=57, hashBytes=32
L192: secretKeyBytes=146, publicKeyBytes=73, signatureOverhead=81, hashBytes=48
L256: secretKeyBytes=194, publicKeyBytes=97, signatureOverhead=105, hashBytes=64
```

**Step 2: Copy updated sign.h to xcframework headers**

**Step 3: Commit**

```bash
git add SIGN/bindings/swift/
git commit -m "fix(bindings): update Swift binding for new algorithm sizes"
```

### Task 15: Update C# binding sizes

**Files:**
- Modify: `SIGN/bindings/csharp/KazSign/KazSign.cs`

**Step 1: Update all hardcoded sizes**

Same size updates as Swift.

**Step 2: Commit**

```bash
git add SIGN/bindings/csharp/
git commit -m "fix(bindings): update C# binding for new algorithm sizes"
```

### Task 16: Update Android binding sizes

**Files:**
- Modify: `SIGN/bindings/android/kazsign/src/main/java/com/pqckaz/kazsign/KazSigner.kt`

**Step 1: Update hardcoded sizes**

Same size updates.

**Step 2: Commit**

```bash
git add SIGN/bindings/android/
git commit -m "fix(bindings): update Android binding for new algorithm sizes"
```

---

## Phase 11: Full CI Verification

### Task 17: Run full CI suite

**Step 1: Run all tests at all levels**

```bash
cd SIGN
make clean && make test-all
make test-extensions LEVEL=128
make test-extensions LEVEL=192
make test-extensions LEVEL=256
```

**Step 2: Run benchmarks to verify no regressions**

```bash
make benchmark LEVEL=128
```

**Step 3: Fix any failures found**

**Step 4: Final commit**

```bash
git commit -m "chore(sign): all tests pass with new algorithm"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1 | Header params & macros |
| 2 | 2-3 | System parameters, runtime struct, init/clear |
| 3 | 4 | Level-matched hash (SHA-256/384/512) |
| 4 | 5 | Key generation (α-based) |
| 5 | 6 | Signing (2-component + CRT) |
| 6 | 7 | Verification (5 filters + 2 equations) |
| 7 | 8 | Detached mode update |
| 8 | 9-11 | Test suite updates |
| 9 | 12-13 | NIST wrapper + KAT |
| 10 | 14-16 | Bindings (Swift/C#/Android) |
| 11 | 17 | Full CI verification |

**Total: 17 tasks across 11 phases.**
