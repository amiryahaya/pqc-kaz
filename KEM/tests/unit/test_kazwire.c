/*
 * KAZ-KEM KazWire Encoding Test Suite
 * Tests round-trip encoding/decoding of public and private keys
 * at all security levels (128, 192, 256).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kaz/kem.h"

/* Test framework macros */
#define TEST_PASSED "\033[32m[PASS]\033[0m"
#define TEST_FAILED "\033[31m[FAIL]\033[0m"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define RUN_TEST(test_func) do { \
    printf("Running: %s ... ", #test_func); \
    fflush(stdout); \
    tests_run++; \
    if (test_func()) { \
        printf("%s\n", TEST_PASSED); \
        tests_passed++; \
    } else { \
        printf("%s\n", TEST_FAILED); \
        tests_failed++; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "\n  Assertion failed: %s (line %d)\n", #expr, __LINE__); \
        return 0; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "\n  Assertion failed: %s == %s (%lld != %lld) (line %d)\n", \
                #a, #b, (long long)(a), (long long)(b), __LINE__); \
        return 0; \
    } \
} while(0)

/* Expected wire sizes */
static const struct {
    int level;
    size_t pk_raw;      /* 2 * publickey_bytes */
    size_t sk_raw;      /* 2 * privatekey_bytes */
    size_t pk_wire;     /* 5 + pk_raw */
    size_t sk_wire;     /* 5 + sk_raw */
    unsigned char alg_id;
} wire_sizes[] = {
    { 128, 108,  34, 113,  39, KAZ_KEM_WIRE_128 },
    { 192, 176,  50, 181,  55, KAZ_KEM_WIRE_192 },
    { 256, 236,  66, 241,  71, KAZ_KEM_WIRE_256 },
};

#define NUM_LEVELS 3

/* ============================================================================
 * Public Key Wire Round-trip Tests
 * ============================================================================ */

static int test_pubkey_wire_roundtrip(int level, int level_idx)
{
    int ret;

    ret = kaz_kem_init(level);
    ASSERT_EQ(ret, 0);

    size_t pk_size = kaz_kem_publickey_bytes();
    ASSERT_EQ(pk_size, wire_sizes[level_idx].pk_raw);

    unsigned char *pk = (unsigned char *)malloc(pk_size);
    unsigned char *sk = (unsigned char *)malloc(kaz_kem_privatekey_bytes());
    ASSERT_TRUE(pk && sk);

    ret = kaz_kem_keypair(pk, sk);
    ASSERT_EQ(ret, 0);

    /* Encode to wire */
    size_t wire_len = wire_sizes[level_idx].pk_wire;
    unsigned char *wire = (unsigned char *)malloc(wire_len);
    ASSERT_TRUE(wire);

    size_t out_len = wire_len;
    ret = kaz_kem_pubkey_to_wire(level, pk, pk_size, wire, &out_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(out_len, wire_sizes[level_idx].pk_wire);

    /* Verify header */
    ASSERT_EQ(wire[0], KAZ_KEM_WIRE_MAGIC_HI);
    ASSERT_EQ(wire[1], KAZ_KEM_WIRE_MAGIC_LO);
    ASSERT_EQ(wire[2], wire_sizes[level_idx].alg_id);
    ASSERT_EQ(wire[3], KAZ_KEM_WIRE_TYPE_PUB);
    ASSERT_EQ(wire[4], KAZ_KEM_WIRE_VERSION);

    /* Decode from wire */
    unsigned char *pk2 = (unsigned char *)malloc(pk_size);
    ASSERT_TRUE(pk2);
    int decoded_level = 0;
    size_t pk2_len = pk_size;

    ret = kaz_kem_pubkey_from_wire(wire, out_len, &decoded_level, pk2, &pk2_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decoded_level, level);
    ASSERT_EQ(pk2_len, pk_size);
    ASSERT_TRUE(memcmp(pk, pk2, pk_size) == 0);

    free(pk); free(sk); free(wire); free(pk2);
    kaz_kem_cleanup();
    return 1;
}

static int test_pubkey_wire_128(void) { return test_pubkey_wire_roundtrip(128, 0); }
static int test_pubkey_wire_192(void) { return test_pubkey_wire_roundtrip(192, 1); }
static int test_pubkey_wire_256(void) { return test_pubkey_wire_roundtrip(256, 2); }

/* ============================================================================
 * Private Key Wire Round-trip Tests
 * ============================================================================ */

static int test_privkey_wire_roundtrip(int level, int level_idx)
{
    int ret;

    ret = kaz_kem_init(level);
    ASSERT_EQ(ret, 0);

    size_t pk_size = kaz_kem_publickey_bytes();
    size_t sk_size = kaz_kem_privatekey_bytes();
    ASSERT_EQ(sk_size, wire_sizes[level_idx].sk_raw);

    unsigned char *pk = (unsigned char *)malloc(pk_size);
    unsigned char *sk = (unsigned char *)malloc(sk_size);
    ASSERT_TRUE(pk && sk);

    ret = kaz_kem_keypair(pk, sk);
    ASSERT_EQ(ret, 0);

    /* Encode to wire */
    size_t wire_len = wire_sizes[level_idx].sk_wire;
    unsigned char *wire = (unsigned char *)malloc(wire_len);
    ASSERT_TRUE(wire);

    size_t out_len = wire_len;
    ret = kaz_kem_privkey_to_wire(level, sk, sk_size, wire, &out_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(out_len, wire_sizes[level_idx].sk_wire);

    /* Verify header */
    ASSERT_EQ(wire[0], KAZ_KEM_WIRE_MAGIC_HI);
    ASSERT_EQ(wire[1], KAZ_KEM_WIRE_MAGIC_LO);
    ASSERT_EQ(wire[2], wire_sizes[level_idx].alg_id);
    ASSERT_EQ(wire[3], KAZ_KEM_WIRE_TYPE_PRIV);
    ASSERT_EQ(wire[4], KAZ_KEM_WIRE_VERSION);

    /* Decode from wire */
    unsigned char *sk2 = (unsigned char *)malloc(sk_size);
    ASSERT_TRUE(sk2);
    int decoded_level = 0;
    size_t sk2_len = sk_size;

    ret = kaz_kem_privkey_from_wire(wire, out_len, &decoded_level, sk2, &sk2_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decoded_level, level);
    ASSERT_EQ(sk2_len, sk_size);
    ASSERT_TRUE(memcmp(sk, sk2, sk_size) == 0);

    free(pk); free(sk); free(wire); free(sk2);
    kaz_kem_cleanup();
    return 1;
}

static int test_privkey_wire_128(void) { return test_privkey_wire_roundtrip(128, 0); }
static int test_privkey_wire_192(void) { return test_privkey_wire_roundtrip(192, 1); }
static int test_privkey_wire_256(void) { return test_privkey_wire_roundtrip(256, 2); }

/* ============================================================================
 * Negative Tests
 * ============================================================================ */

static int test_wire_bad_magic(void)
{
    unsigned char wire[] = { 0x00, 0x00, KAZ_KEM_WIRE_128, KAZ_KEM_WIRE_TYPE_PUB, KAZ_KEM_WIRE_VERSION };
    /* pad with enough bytes for a 128 pubkey */
    size_t total = 113;
    unsigned char *buf = (unsigned char *)calloc(total, 1);
    ASSERT_TRUE(buf);
    memcpy(buf, wire, 5);

    int level = 0;
    unsigned char pk[108];
    size_t pk_len = sizeof(pk);
    int ret = kaz_kem_pubkey_from_wire(buf, total, &level, pk, &pk_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_WIRE_FORMAT);

    free(buf);
    return 1;
}

static int test_wire_bad_type(void)
{
    /* Try decoding a PRIV-typed wire as PUB */
    int ret = kaz_kem_init(128);
    ASSERT_EQ(ret, 0);

    size_t sk_size = kaz_kem_privatekey_bytes();
    size_t pk_size = kaz_kem_publickey_bytes();
    unsigned char *pk = (unsigned char *)malloc(pk_size);
    unsigned char *sk = (unsigned char *)malloc(sk_size);
    ASSERT_TRUE(pk && sk);

    ret = kaz_kem_keypair(pk, sk);
    ASSERT_EQ(ret, 0);

    /* Encode private key */
    size_t wire_len = KAZ_KEM_WIRE_HEADER + sk_size;
    unsigned char *wire = (unsigned char *)malloc(wire_len);
    ASSERT_TRUE(wire);
    size_t out_len = wire_len;
    ret = kaz_kem_privkey_to_wire(128, sk, sk_size, wire, &out_len);
    ASSERT_EQ(ret, 0);

    /* Try to decode as public key - should fail on type mismatch */
    int level = 0;
    unsigned char pk2[108];
    size_t pk2_len = sizeof(pk2);
    ret = kaz_kem_pubkey_from_wire(wire, out_len, &level, pk2, &pk2_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_WIRE_FORMAT);

    free(pk); free(sk); free(wire);
    kaz_kem_cleanup();
    return 1;
}

static int test_wire_bad_alg_id(void)
{
    unsigned char wire[] = { KAZ_KEM_WIRE_MAGIC_HI, KAZ_KEM_WIRE_MAGIC_LO, 0xFF, KAZ_KEM_WIRE_TYPE_PUB, KAZ_KEM_WIRE_VERSION };
    size_t total = 113;
    unsigned char *buf = (unsigned char *)calloc(total, 1);
    ASSERT_TRUE(buf);
    memcpy(buf, wire, 5);

    int level = 0;
    unsigned char pk[108];
    size_t pk_len = sizeof(pk);
    int ret = kaz_kem_pubkey_from_wire(buf, total, &level, pk, &pk_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_WIRE_FORMAT);

    free(buf);
    return 1;
}

static int test_wire_truncated(void)
{
    /* Wire data too short */
    unsigned char wire[3] = { KAZ_KEM_WIRE_MAGIC_HI, KAZ_KEM_WIRE_MAGIC_LO, KAZ_KEM_WIRE_128 };
    int level = 0;
    unsigned char pk[108];
    size_t pk_len = sizeof(pk);
    int ret = kaz_kem_pubkey_from_wire(wire, 3, &level, pk, &pk_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_WIRE_FORMAT);

    return 1;
}

static int test_wire_wrong_length(void)
{
    /* Valid header but wrong payload length */
    size_t total = 100; /* not matching any valid pubkey wire size */
    unsigned char *buf = (unsigned char *)calloc(total, 1);
    ASSERT_TRUE(buf);
    buf[0] = KAZ_KEM_WIRE_MAGIC_HI;
    buf[1] = KAZ_KEM_WIRE_MAGIC_LO;
    buf[2] = KAZ_KEM_WIRE_128;
    buf[3] = KAZ_KEM_WIRE_TYPE_PUB;
    buf[4] = KAZ_KEM_WIRE_VERSION;

    int level = 0;
    unsigned char pk[108];
    size_t pk_len = sizeof(pk);
    int ret = kaz_kem_pubkey_from_wire(buf, total, &level, pk, &pk_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_WIRE_FORMAT);

    free(buf);
    return 1;
}

static int test_wire_invalid_level_encode(void)
{
    unsigned char out[256];
    size_t out_len = sizeof(out);
    unsigned char fake_pk[108] = {0};
    int ret = kaz_kem_pubkey_to_wire(999, fake_pk, 108, out, &out_len);
    ASSERT_EQ(ret, KAZ_KEM_ERROR_INVALID_LEVEL);

    return 1;
}

/* ============================================================================
 * Functional: wire-decoded keys still work for KEM operations
 * ============================================================================ */

static int test_wire_functional_roundtrip(void)
{
    int ret;

    ret = kaz_kem_init(128);
    ASSERT_EQ(ret, 0);

    size_t pk_size = kaz_kem_publickey_bytes();
    size_t sk_size = kaz_kem_privatekey_bytes();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    size_t ct_size = kaz_kem_ciphertext_bytes();

    unsigned char *pk = (unsigned char *)malloc(pk_size);
    unsigned char *sk = (unsigned char *)malloc(sk_size);
    ASSERT_TRUE(pk && sk);

    ret = kaz_kem_keypair(pk, sk);
    ASSERT_EQ(ret, 0);

    /* Encode and decode public key through wire format */
    size_t pk_wire_len = KAZ_KEM_WIRE_HEADER + pk_size;
    unsigned char *pk_wire = (unsigned char *)malloc(pk_wire_len);
    ASSERT_TRUE(pk_wire);
    size_t out_len = pk_wire_len;
    ret = kaz_kem_pubkey_to_wire(128, pk, pk_size, pk_wire, &out_len);
    ASSERT_EQ(ret, 0);

    unsigned char *pk_decoded = (unsigned char *)malloc(pk_size);
    ASSERT_TRUE(pk_decoded);
    int decoded_level = 0;
    size_t pk_dec_len = pk_size;
    ret = kaz_kem_pubkey_from_wire(pk_wire, out_len, &decoded_level, pk_decoded, &pk_dec_len);
    ASSERT_EQ(ret, 0);

    /* Encode and decode private key through wire format */
    size_t sk_wire_len = KAZ_KEM_WIRE_HEADER + sk_size;
    unsigned char *sk_wire = (unsigned char *)malloc(sk_wire_len);
    ASSERT_TRUE(sk_wire);
    out_len = sk_wire_len;
    ret = kaz_kem_privkey_to_wire(128, sk, sk_size, sk_wire, &out_len);
    ASSERT_EQ(ret, 0);

    unsigned char *sk_decoded = (unsigned char *)malloc(sk_size);
    ASSERT_TRUE(sk_decoded);
    size_t sk_dec_len = sk_size;
    ret = kaz_kem_privkey_from_wire(sk_wire, out_len, &decoded_level, sk_decoded, &sk_dec_len);
    ASSERT_EQ(ret, 0);

    /* Use decoded keys for encapsulation/decapsulation */
    unsigned char *msg = (unsigned char *)malloc(ss_size);
    unsigned char *ct = (unsigned char *)malloc(ct_size);
    unsigned char *decap = (unsigned char *)malloc(ss_size);
    ASSERT_TRUE(msg && ct && decap);

    for (size_t i = 0; i < ss_size; i++)
        msg[i] = (unsigned char)(i & 0xFF);

    unsigned long long ctlen, decaplen;
    ret = kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk_decoded);
    ASSERT_EQ(ret, 0);

    ret = kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk_decoded);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(memcmp(msg, decap, ss_size) == 0);

    free(pk); free(sk); free(pk_wire); free(pk_decoded);
    free(sk_wire); free(sk_decoded); free(msg); free(ct); free(decap);
    kaz_kem_cleanup();
    return 1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf("          KAZ-KEM KazWire Encoding Test Suite\n");
    printf("================================================================================\n\n");

    printf("PUBLIC KEY WIRE ROUND-TRIP\n");
    printf("-------------------------\n");
    RUN_TEST(test_pubkey_wire_128);
    RUN_TEST(test_pubkey_wire_192);
    RUN_TEST(test_pubkey_wire_256);

    printf("\nPRIVATE KEY WIRE ROUND-TRIP\n");
    printf("--------------------------\n");
    RUN_TEST(test_privkey_wire_128);
    RUN_TEST(test_privkey_wire_192);
    RUN_TEST(test_privkey_wire_256);

    printf("\nNEGATIVE TESTS\n");
    printf("--------------\n");
    RUN_TEST(test_wire_bad_magic);
    RUN_TEST(test_wire_bad_type);
    RUN_TEST(test_wire_bad_alg_id);
    RUN_TEST(test_wire_truncated);
    RUN_TEST(test_wire_wrong_length);
    RUN_TEST(test_wire_invalid_level_encode);

    printf("\nFUNCTIONAL TESTS\n");
    printf("----------------\n");
    RUN_TEST(test_wire_functional_roundtrip);

    printf("\n================================================================================\n");
    printf("  Total: %d  Passed: %d  Failed: %d\n", tests_run, tests_passed, tests_failed);
    printf("================================================================================\n\n");

    kaz_kem_cleanup_full();
    return (tests_failed == 0) ? 0 : 1;
}
