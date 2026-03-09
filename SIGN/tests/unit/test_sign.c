/*
 * KAZ-SIGN Comprehensive Test Suite
 * Industry-standard test coverage following NIST PQC guidelines
 *
 * Test Categories:
 * 1. API Conformance Tests
 * 2. Functional Correctness Tests
 * 3. Edge Case Tests
 * 4. Security Tests
 * 5. Stress Tests
 * 6. Determinism Tests
 * 7. Interoperability Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "kaz/sign.h"
#include "kaz/nist_api.h"

/* ============================================================================
 * Test Framework
 * ============================================================================ */

typedef struct {
    int total;
    int passed;
    int failed;
    int skipped;
    double total_time_ms;
} test_stats_t;

static test_stats_t g_stats = {0};
static int g_verbose = 0;

static double get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

#define TEST_CATEGORY(name) \
    do { \
        printf("\n"); \
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"); \
        printf("  %s\n", name); \
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"); \
    } while(0)

#define TEST_START(name) \
    do { \
        g_stats.total++; \
        if (g_verbose) printf("\n"); \
        printf("  [%3d] %-45s ", g_stats.total, name); \
        fflush(stdout); \
        _test_start_time = get_time_ms(); \
    } while(0)

#define TEST_PASS() \
    do { \
        double _elapsed = get_time_ms() - _test_start_time; \
        g_stats.passed++; \
        g_stats.total_time_ms += _elapsed; \
        printf("\033[32mPASS\033[0m (%.2f ms)\n", _elapsed); \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        double _elapsed = get_time_ms() - _test_start_time; \
        g_stats.failed++; \
        g_stats.total_time_ms += _elapsed; \
        printf("\033[31mFAIL\033[0m\n"); \
        printf("       └── %s\n", msg); \
    } while(0)

#define TEST_SKIP(reason) \
    do { \
        g_stats.skipped++; \
        printf("\033[33mSKIP\033[0m (%s)\n", reason); \
    } while(0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            TEST_FAIL(msg); \
            return; \
        } \
    } while(0)

#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg) ASSERT((a) != (b), msg)
#define ASSERT_MEM_EQ(a, b, len, msg) ASSERT(memcmp(a, b, len) == 0, msg)
#define ASSERT_MEM_NE(a, b, len, msg) ASSERT(memcmp(a, b, len) != 0, msg)

static double _test_start_time;

/* ============================================================================
 * Test Utilities
 * ============================================================================ */

static void fill_random(unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }
}

static int is_zero(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return 0;
    }
    return 1;
}

__attribute__((unused))
static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    if (!g_verbose) return;
    printf("       %s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* ============================================================================
 * 1. API Conformance Tests
 * ============================================================================ */

void test_api_keypair_basic(void)
{
    TEST_START("crypto_sign_keypair basic");

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    int ret = crypto_sign_keypair(pk, sk);
    ASSERT_EQ(ret, 0, "crypto_sign_keypair should return 0");
    ASSERT(!is_zero(pk, CRYPTO_PUBLICKEYBYTES), "Public key should not be zero");
    ASSERT(!is_zero(sk, CRYPTO_SECRETKEYBYTES), "Secret key should not be zero");

    TEST_PASS();
}

void test_api_sign_basic(void)
{
    TEST_START("crypto_sign basic");

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char msg[] = "Test message for signing";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sm[CRYPTO_BYTES * 10 + 100];
    unsigned long long smlen;

    int ret = crypto_sign_keypair(pk, sk);
    ASSERT_EQ(ret, 0, "Key generation failed");

    ret = crypto_sign(sm, &smlen, msg, msglen, sk);
    ASSERT_EQ(ret, 0, "crypto_sign should return 0");
    ASSERT(smlen > msglen, "Signed message should be larger than message");

    TEST_PASS();
}

void test_api_verify_basic(void)
{
    TEST_START("crypto_sign_open basic");

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char msg[] = "Test message for verification";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sm[CRYPTO_BYTES * 10 + 100];
    unsigned long long smlen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = crypto_sign_keypair(pk, sk);
    ASSERT_EQ(ret, 0, "Key generation failed");

    ret = crypto_sign(sm, &smlen, msg, msglen, sk);
    ASSERT_EQ(ret, 0, "Signing failed");

    ret = crypto_sign_open(recovered, &recovered_len, sm, smlen, pk);
    ASSERT_EQ(ret, 0, "crypto_sign_open should return 0");
    ASSERT_EQ(recovered_len, msglen, "Recovered length mismatch");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_api_constants(void)
{
    TEST_START("API constants validation");

    ASSERT(CRYPTO_SECRETKEYBYTES > 0, "CRYPTO_SECRETKEYBYTES must be positive");
    ASSERT(CRYPTO_PUBLICKEYBYTES > 0, "CRYPTO_PUBLICKEYBYTES must be positive");
    ASSERT(CRYPTO_BYTES > 0, "CRYPTO_BYTES must be positive");
    ASSERT(strlen(CRYPTO_ALGNAME) > 0, "CRYPTO_ALGNAME must not be empty");

    /* Verify alignment with internal constants */
    ASSERT_EQ(CRYPTO_SECRETKEYBYTES, KAZ_SIGN_SECRETKEYBYTES, "Secret key size mismatch");
    ASSERT_EQ(CRYPTO_PUBLICKEYBYTES, KAZ_SIGN_PUBLICKEYBYTES, "Public key size mismatch");
    ASSERT_EQ(CRYPTO_BYTES, KAZ_SIGN_BYTES, "Signature bytes mismatch");

    TEST_PASS();
}

void test_api_version(void)
{
    TEST_START("Version API");

    const char *version = kaz_sign_version();
    int version_num = kaz_sign_version_number();

    ASSERT(version != NULL, "Version string should not be NULL");
    ASSERT(strlen(version) > 0, "Version string should not be empty");
    ASSERT(version_num >= 40000, "Version number should be at least 4.0.0");

    /* Verify version matches constants */
    ASSERT_EQ(version_num, KAZ_SIGN_VERSION_NUMBER, "Version number mismatch");
    ASSERT(strcmp(version, KAZ_SIGN_VERSION_STRING) == 0, "Version string mismatch");

    if (g_verbose) {
        printf("       Version: %s (number: %d)\n", version, version_num);
    }

    TEST_PASS();
}

void test_api_null_pointers(void)
{
    TEST_START("NULL pointer handling");

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char msg[] = "test";
    unsigned long long msglen = 4;
    unsigned char sm[500];
    unsigned long long smlen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    /* Generate valid keys first */
    int ret = crypto_sign_keypair(pk, sk);
    ASSERT_EQ(ret, 0, "Key generation failed");

    /* Test NULL handling */
    ASSERT_NE(crypto_sign_keypair(NULL, sk), 0, "Should reject NULL pk");
    ASSERT_NE(crypto_sign_keypair(pk, NULL), 0, "Should reject NULL sk");
    ASSERT_NE(crypto_sign(NULL, &smlen, msg, msglen, sk), 0, "Should reject NULL sm");
    ASSERT_NE(crypto_sign(sm, NULL, msg, msglen, sk), 0, "Should reject NULL smlen");

    /* Create valid signature for remaining tests */
    ret = crypto_sign(sm, &smlen, msg, msglen, sk);
    ASSERT_EQ(ret, 0, "Signing failed");

    ASSERT_NE(crypto_sign_open(NULL, &recovered_len, sm, smlen, pk), 0, "Should reject NULL m");
    ASSERT_NE(crypto_sign_open(recovered, NULL, sm, smlen, pk), 0, "Should reject NULL mlen");
    ASSERT_NE(crypto_sign_open(recovered, &recovered_len, NULL, smlen, pk), 0, "Should reject NULL sm");
    ASSERT_NE(crypto_sign_open(recovered, &recovered_len, sm, smlen, NULL), 0, "Should reject NULL pk");

    TEST_PASS();
}

/* ============================================================================
 * 2. Functional Correctness Tests
 * ============================================================================ */

void test_func_roundtrip(void)
{
    TEST_START("Sign-verify roundtrip");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    ASSERT_EQ(recovered_len, msglen, "Length mismatch");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_func_multiple_messages(void)
{
    TEST_START("Multiple messages with same key");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    const char *messages[] = {
        "Message 1",
        "A longer message for testing",
        "Short",
        "Another test message with different content",
        "Final message in the test sequence"
    };
    int num_messages = sizeof(messages) / sizeof(messages[0]);

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    for (int i = 0; i < num_messages; i++) {
        unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 200];
        unsigned long long siglen;
        unsigned char recovered[200];
        unsigned long long recovered_len;
        unsigned long long msglen = strlen(messages[i]);

        ret = kaz_sign_signature(sig, &siglen, (const unsigned char *)messages[i], msglen, sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

        ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
        ASSERT_EQ(recovered_len, msglen, "Length mismatch");
        ASSERT_MEM_EQ(messages[i], recovered, msglen, "Message mismatch");
    }

    TEST_PASS();
}

void test_func_key_independence(void)
{
    TEST_START("Key pair independence");

    unsigned char pk1[KAZ_SIGN_PUBLICKEYBYTES], pk2[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk1[KAZ_SIGN_SECRETKEYBYTES], sk2[KAZ_SIGN_SECRETKEYBYTES];

    int ret = kaz_sign_keypair(pk1, sk1);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation 1 failed");

    ret = kaz_sign_keypair(pk2, sk2);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation 2 failed");

    /* Keys should be different */
    ASSERT_MEM_NE(pk1, pk2, KAZ_SIGN_PUBLICKEYBYTES, "Public keys should differ");
    ASSERT_MEM_NE(sk1, sk2, KAZ_SIGN_SECRETKEYBYTES, "Secret keys should differ");

    TEST_PASS();
}

void test_func_signature_uniqueness(void)
{
    TEST_START("Signature uniqueness (randomness)");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Same message for all signatures";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig1[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned char sig2[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen1, siglen2;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig1, &siglen1, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "First signing failed");

    ret = kaz_sign_signature(sig2, &siglen2, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Second signing failed");

    /* Signatures should differ due to random ephemeral values */
    ASSERT_MEM_NE(sig1, sig2, KAZ_SIGN_SIGNATURE_OVERHEAD, "Signatures should be unique");

    /* But both should verify */
    unsigned char recovered[100];
    unsigned long long recovered_len;

    ret = kaz_sign_verify(recovered, &recovered_len, sig1, siglen1, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "First signature verification failed");

    ret = kaz_sign_verify(recovered, &recovered_len, sig2, siglen2, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Second signature verification failed");

    TEST_PASS();
}

/* ============================================================================
 * 3. Edge Case Tests
 * ============================================================================ */

void test_edge_empty_message(void)
{
    TEST_START("Empty message");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "";
    unsigned long long msglen = 0;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 10];
    unsigned long long siglen;
    unsigned char recovered[10];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing empty message failed");
    ASSERT_EQ(siglen, (unsigned long long)KAZ_SIGN_SIGNATURE_OVERHEAD, "Wrong signature length");

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    ASSERT_EQ(recovered_len, 0ULL, "Should recover empty message");

    TEST_PASS();
}

void test_edge_single_byte_message(void)
{
    TEST_START("Single byte message");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = {0x42};
    unsigned long long msglen = 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 10];
    unsigned long long siglen;
    unsigned char recovered[10];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    ASSERT_EQ(recovered_len, 1ULL, "Length mismatch");
    ASSERT_EQ(recovered[0], 0x42, "Message mismatch");

    TEST_PASS();
}

void test_edge_large_message(void)
{
    TEST_START("Large message (64KB)");

    size_t msglen = 65536;
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned char *recovered = NULL;
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned long long siglen, recovered_len;
    int passed = 0;

    msg = malloc(msglen);
    sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + msglen);
    recovered = malloc(msglen);

    if (!msg || !sig || !recovered) {
        TEST_FAIL("Memory allocation failed");
        goto cleanup;
    }

    fill_random(msg, msglen);

    int ret = kaz_sign_keypair(pk, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Key generation failed");
        goto cleanup;
    }

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Signing failed");
        goto cleanup;
    }

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Verification failed");
        goto cleanup;
    }
    if (recovered_len != (unsigned long long)msglen) {
        TEST_FAIL("Length mismatch");
        goto cleanup;
    }
    if (memcmp(msg, recovered, msglen) != 0) {
        TEST_FAIL("Message mismatch");
        goto cleanup;
    }

    passed = 1;

cleanup:
    free(msg);
    free(sig);
    free(recovered);

    if (passed) {
        TEST_PASS();
    }
}

void test_edge_all_zero_message(void)
{
    TEST_START("All-zero message");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[256];
    unsigned long long msglen = sizeof(msg);
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 256];
    unsigned long long siglen;
    unsigned char recovered[256];
    unsigned long long recovered_len;

    memset(msg, 0, msglen);

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_edge_all_ones_message(void)
{
    TEST_START("All-ones message (0xFF)");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[256];
    unsigned long long msglen = sizeof(msg);
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 256];
    unsigned long long siglen;
    unsigned char recovered[256];
    unsigned long long recovered_len;

    memset(msg, 0xFF, msglen);

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_edge_various_sizes(void)
{
    TEST_START("Various message sizes (1-1024 bytes)");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[1024];
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 1024];
    unsigned char recovered[1024];
    unsigned long long siglen, recovered_len;
    int sizes[] = {1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    fill_random(msg, sizeof(msg));

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    for (int i = 0; i < num_sizes; i++) {
        unsigned long long msglen = sizes[i];

        ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

        ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
        ASSERT_EQ(recovered_len, msglen, "Length mismatch");
        ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");
    }

    TEST_PASS();
}

/* ============================================================================
 * 4. Security Tests
 * ============================================================================ */

void test_sec_wrong_public_key(void)
{
    TEST_START("Wrong public key rejection");

    unsigned char pk1[KAZ_SIGN_PUBLICKEYBYTES], pk2[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk1[KAZ_SIGN_SECRETKEYBYTES], sk2[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Secret message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk1, sk1);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation 1 failed");

    ret = kaz_sign_keypair(pk2, sk2);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation 2 failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk1);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Verify with wrong key should fail */
    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk2);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should reject wrong key");

    TEST_PASS();
}

void test_sec_corrupted_signature_s1(void)
{
    TEST_START("Corrupted S1 component detection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Corrupt S1 component (first part of signature) */
    sig[KAZ_SIGN_S1BYTES / 2] ^= 0x01;

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should detect S1 corruption");

    TEST_PASS();
}

void test_sec_corrupted_signature_s2(void)
{
    TEST_START("Corrupted S2 component detection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Corrupt S2 component */
    sig[KAZ_SIGN_S1BYTES + KAZ_SIGN_S2BYTES / 2] ^= 0x01;

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should detect S2 corruption");

    TEST_PASS();
}

void test_sec_corrupted_signature_s3(void)
{
    TEST_START("Corrupted S3 component detection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Corrupt S3 component (third part of signature, after S1+S2) */
    sig[KAZ_SIGN_S1BYTES + KAZ_SIGN_S2BYTES + KAZ_SIGN_S3BYTES / 2] ^= 0x01;

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should detect S3 corruption");

    TEST_PASS();
}

void test_sec_corrupted_message(void)
{
    TEST_START("Corrupted embedded message detection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Test message for corruption";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Corrupt embedded message */
    sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 5] ^= 0x01;

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should detect message corruption");

    TEST_PASS();
}

void test_sec_truncated_signature(void)
{
    TEST_START("Truncated signature detection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "Test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

    /* Try to verify with truncated signature */
    ret = kaz_sign_verify(recovered, &recovered_len, sig, KAZ_SIGN_SIGNATURE_OVERHEAD - 1, pk);
    ASSERT_NE(ret, KAZ_SIGN_SUCCESS, "Should reject truncated signature");

    TEST_PASS();
}

void test_sec_random_signature(void)
{
    TEST_START("Random signature rejection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char fake_sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    /* Create random fake signature with embedded message */
    fill_random(fake_sig, sizeof(fake_sig));
    memcpy(fake_sig + KAZ_SIGN_SIGNATURE_OVERHEAD, "fake message", 12);

    ret = kaz_sign_verify(recovered, &recovered_len, fake_sig, KAZ_SIGN_SIGNATURE_OVERHEAD + 12, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should reject random signature");

    TEST_PASS();
}

void test_sec_zero_signature(void)
{
    TEST_START("Zero signature rejection");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char zero_sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 20];
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    /* Create all-zero signature */
    memset(zero_sig, 0, sizeof(zero_sig));
    memcpy(zero_sig + KAZ_SIGN_SIGNATURE_OVERHEAD, "test", 4);

    ret = kaz_sign_verify(recovered, &recovered_len, zero_sig, KAZ_SIGN_SIGNATURE_OVERHEAD + 4, pk);
    ASSERT_EQ(ret, KAZ_SIGN_ERROR_VERIFY, "Should reject zero signature");

    TEST_PASS();
}

/* ============================================================================
 * 5. Stress Tests
 * ============================================================================ */

void test_stress_repeated_keygen(void)
{
    TEST_START("Repeated key generation (100 iterations)");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];

    for (int i = 0; i < 100; i++) {
        int ret = kaz_sign_keypair(pk, sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");
        ASSERT(!is_zero(pk, KAZ_SIGN_PUBLICKEYBYTES), "Public key is zero");
        ASSERT(!is_zero(sk, KAZ_SIGN_SECRETKEYBYTES), "Secret key is zero");
    }

    TEST_PASS();
}

void test_stress_repeated_sign_verify(void)
{
    TEST_START("Repeated sign/verify (100 iterations)");

    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[64];
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 64];
    unsigned char recovered[64];
    unsigned long long siglen, recovered_len;

    int ret = kaz_sign_keypair(pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

    for (int i = 0; i < 100; i++) {
        fill_random(msg, sizeof(msg));

        ret = kaz_sign_signature(sig, &siglen, msg, sizeof(msg), sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

        ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
        ASSERT_MEM_EQ(msg, recovered, sizeof(msg), "Message mismatch");
    }

    TEST_PASS();
}

void test_stress_many_keys(void)
{
    TEST_START("Many different keys (50 key pairs)");

    unsigned char msg[] = "Test message for multiple keys";
    unsigned long long msglen = sizeof(msg) - 1;

    for (int i = 0; i < 50; i++) {
        unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
        unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
        unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
        unsigned char recovered[100];
        unsigned long long siglen, recovered_len;

        int ret = kaz_sign_keypair(pk, sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Key generation failed");

        ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Signing failed");

        ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
        ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verification failed");
    }

    TEST_PASS();
}

/* ============================================================================
 * 6. Runtime Security Level Tests (NEW in 2.1)
 * ============================================================================ */

void test_runtime_level_params(void)
{
    TEST_START("Runtime level parameters introspection");

    const kaz_sign_level_params_t *params128 = kaz_sign_get_level_params(KAZ_LEVEL_128);
    const kaz_sign_level_params_t *params192 = kaz_sign_get_level_params(KAZ_LEVEL_192);
    const kaz_sign_level_params_t *params256 = kaz_sign_get_level_params(KAZ_LEVEL_256);

    ASSERT(params128 != NULL, "Level 128 params should exist");
    ASSERT(params192 != NULL, "Level 192 params should exist");
    ASSERT(params256 != NULL, "Level 256 params should exist");

    /* Verify level 128: SK=32, PK=54, hash=32, v=54, s=16, t=16, s1=s2=s3=54 */
    ASSERT_EQ(params128->level, 128, "Level 128 level mismatch");
    ASSERT_EQ(params128->secret_key_bytes, 32, "Level 128 SK size mismatch");
    ASSERT_EQ(params128->public_key_bytes, 54, "Level 128 PK size mismatch");
    ASSERT_EQ(params128->hash_bytes, 32, "Level 128 hash size mismatch");
    ASSERT_EQ(params128->v_bytes, 54, "Level 128 v_bytes mismatch");
    ASSERT_EQ(params128->s_bytes, 16, "Level 128 s_bytes mismatch");
    ASSERT_EQ(params128->t_bytes, 16, "Level 128 t_bytes mismatch");
    ASSERT_EQ(params128->s1_bytes, 54, "Level 128 s1_bytes mismatch");
    ASSERT_EQ(params128->s2_bytes, 54, "Level 128 s2_bytes mismatch");
    ASSERT_EQ(params128->s3_bytes, 54, "Level 128 s3_bytes mismatch");
    ASSERT_EQ(params128->signature_overhead, 162, "Level 128 sig overhead mismatch");

    /* Verify level 192: SK=50, PK=88, hash=48, v=88, s=25, t=25, s1=s2=s3=88 */
    ASSERT_EQ(params192->level, 192, "Level 192 level mismatch");
    ASSERT_EQ(params192->secret_key_bytes, 50, "Level 192 SK size mismatch");
    ASSERT_EQ(params192->public_key_bytes, 88, "Level 192 PK size mismatch");
    ASSERT_EQ(params192->hash_bytes, 48, "Level 192 hash size mismatch");
    ASSERT_EQ(params192->v_bytes, 88, "Level 192 v_bytes mismatch");
    ASSERT_EQ(params192->s_bytes, 25, "Level 192 s_bytes mismatch");
    ASSERT_EQ(params192->t_bytes, 25, "Level 192 t_bytes mismatch");
    ASSERT_EQ(params192->s1_bytes, 88, "Level 192 s1_bytes mismatch");
    ASSERT_EQ(params192->s2_bytes, 88, "Level 192 s2_bytes mismatch");
    ASSERT_EQ(params192->s3_bytes, 88, "Level 192 s3_bytes mismatch");
    ASSERT_EQ(params192->signature_overhead, 264, "Level 192 sig overhead mismatch");

    /* Verify level 256: SK=64, PK=118, hash=64, v=118, s=32, t=32, s1=s2=s3=118 */
    ASSERT_EQ(params256->level, 256, "Level 256 level mismatch");
    ASSERT_EQ(params256->secret_key_bytes, 64, "Level 256 SK size mismatch");
    ASSERT_EQ(params256->public_key_bytes, 118, "Level 256 PK size mismatch");
    ASSERT_EQ(params256->hash_bytes, 64, "Level 256 hash size mismatch");
    ASSERT_EQ(params256->v_bytes, 118, "Level 256 v_bytes mismatch");
    ASSERT_EQ(params256->s_bytes, 32, "Level 256 s_bytes mismatch");
    ASSERT_EQ(params256->t_bytes, 32, "Level 256 t_bytes mismatch");
    ASSERT_EQ(params256->s1_bytes, 118, "Level 256 s1_bytes mismatch");
    ASSERT_EQ(params256->s2_bytes, 118, "Level 256 s2_bytes mismatch");
    ASSERT_EQ(params256->s3_bytes, 118, "Level 256 s3_bytes mismatch");
    ASSERT_EQ(params256->signature_overhead, 354, "Level 256 sig overhead mismatch");

    /* Invalid level should return NULL */
    ASSERT(kaz_sign_get_level_params((kaz_sign_level_t)64) == NULL, "Invalid level should return NULL");

    TEST_PASS();
}

void test_runtime_level_init(void)
{
    TEST_START("Runtime level initialization");

    /* Initialize each level */
    int ret = kaz_sign_init_level(KAZ_LEVEL_128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 128 init failed");

    ret = kaz_sign_init_level(KAZ_LEVEL_192);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 192 init failed");

    ret = kaz_sign_init_level(KAZ_LEVEL_256);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 256 init failed");

    /* Reinitializing should also succeed */
    ret = kaz_sign_init_level(KAZ_LEVEL_128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 128 reinit failed");

    TEST_PASS();
}

void test_runtime_level_128_roundtrip(void)
{
    TEST_START("Runtime Level 128 sign/verify roundtrip");

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    unsigned char pk[128], sk[256];
    unsigned char msg[] = "Runtime level 128 test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[512 + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_init_level(KAZ_LEVEL_128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Init failed");

    ret = kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Keypair failed");

    ret = kaz_sign_signature_ex(KAZ_LEVEL_128, sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Sign failed");
    ASSERT_EQ(siglen, params->signature_overhead + msglen, "Wrong signature length");

    ret = kaz_sign_verify_ex(KAZ_LEVEL_128, recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verify failed");
    ASSERT_EQ(recovered_len, msglen, "Length mismatch");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_runtime_level_192_roundtrip(void)
{
    TEST_START("Runtime Level 192 sign/verify roundtrip");

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_192);
    unsigned char pk[128], sk[256];
    unsigned char msg[] = "Runtime level 192 test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[512 + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_init_level(KAZ_LEVEL_192);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Init failed");

    ret = kaz_sign_keypair_ex(KAZ_LEVEL_192, pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Keypair failed");

    ret = kaz_sign_signature_ex(KAZ_LEVEL_192, sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Sign failed");
    ASSERT_EQ(siglen, params->signature_overhead + msglen, "Wrong signature length");

    ret = kaz_sign_verify_ex(KAZ_LEVEL_192, recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verify failed");
    ASSERT_EQ(recovered_len, msglen, "Length mismatch");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_runtime_level_256_roundtrip(void)
{
    TEST_START("Runtime Level 256 sign/verify roundtrip");

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_256);
    unsigned char pk[128], sk[256];
    unsigned char msg[] = "Runtime level 256 test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[512 + 100];
    unsigned long long siglen;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    int ret = kaz_sign_init_level(KAZ_LEVEL_256);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Init failed");

    ret = kaz_sign_keypair_ex(KAZ_LEVEL_256, pk, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Keypair failed");

    ret = kaz_sign_signature_ex(KAZ_LEVEL_256, sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Sign failed");
    ASSERT_EQ(siglen, params->signature_overhead + msglen, "Wrong signature length");

    ret = kaz_sign_verify_ex(KAZ_LEVEL_256, recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Verify failed");
    ASSERT_EQ(recovered_len, msglen, "Length mismatch");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

void test_runtime_cross_level_isolation(void)
{
    TEST_START("Cross-level security isolation");

    /* Generate key pairs at each level */
    unsigned char pk128[128], sk128[256];
    unsigned char pk256[128], sk256[256];
    unsigned char msg[] = "Cross level test";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig128[256 + 50];
    unsigned long long siglen128;
    unsigned char recovered[100];
    unsigned long long recovered_len;

    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_init_level(KAZ_LEVEL_256);

    int ret = kaz_sign_keypair_ex(KAZ_LEVEL_128, pk128, sk128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 128 keypair failed");

    ret = kaz_sign_keypair_ex(KAZ_LEVEL_256, pk256, sk256);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 256 keypair failed");

    /* Sign with level 128 */
    ret = kaz_sign_signature_ex(KAZ_LEVEL_128, sig128, &siglen128, msg, msglen, sk128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Level 128 sign failed");

    /* Verify with correct level should succeed */
    ret = kaz_sign_verify_ex(KAZ_LEVEL_128, recovered, &recovered_len, sig128, siglen128, pk128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Same level verify should succeed");

    /* Verify with wrong level should fail */
    ret = kaz_sign_verify_ex(KAZ_LEVEL_256, recovered, &recovered_len, sig128, siglen128, pk128);
    ASSERT_NE(ret, KAZ_SIGN_SUCCESS, "Cross-level verify should fail");

    TEST_PASS();
}

void test_runtime_hash_different_levels(void)
{
    TEST_START("Hash output by level (SHA-256, zero-padded)");

    unsigned char msg[] = "Hash test message";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char hash128[32], hash192[48], hash256[64];

    int ret = kaz_sign_hash_ex(KAZ_LEVEL_128, msg, msglen, hash128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Hash 128 failed");

    ret = kaz_sign_hash_ex(KAZ_LEVEL_192, msg, msglen, hash192);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Hash 192 failed");

    ret = kaz_sign_hash_ex(KAZ_LEVEL_256, msg, msglen, hash256);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Hash 256 failed");

    /* All levels use SHA-256, so first 32 bytes should match */
    ASSERT(!is_zero(hash128, 32), "Hash 128 should not be zero");
    ASSERT_MEM_EQ(hash128, hash192, 32, "SHA-256 core should match between 128 and 192");
    ASSERT_MEM_EQ(hash128, hash256, 32, "SHA-256 core should match between 128 and 256");

    /* Level 192 and 256 are zero-padded beyond 32 bytes */
    ASSERT(is_zero(hash192 + 32, 16), "Hash 192 padding should be zero");
    ASSERT(is_zero(hash256 + 32, 32), "Hash 256 padding should be zero");

    TEST_PASS();
}

void test_runtime_level_cleanup(void)
{
    TEST_START("Runtime level cleanup");

    /* Initialize and clear individual levels */
    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_clear_level(KAZ_LEVEL_128);

    /* Clear all should not crash */
    kaz_sign_init_level(KAZ_LEVEL_128);
    kaz_sign_init_level(KAZ_LEVEL_192);
    kaz_sign_init_level(KAZ_LEVEL_256);
    kaz_sign_clear_all();

    /* Should be able to reinitialize after clear */
    int ret = kaz_sign_init_level(KAZ_LEVEL_128);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Reinit after clear failed");

    TEST_PASS();
}

/* ============================================================================
 * 7. Interoperability Tests
 * ============================================================================ */

void test_interop_nist_api_internal_api(void)
{
    TEST_START("NIST API ↔ Internal API interoperability");

    /* Generate keys with NIST API */
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    int ret = crypto_sign_keypair(pk, sk);
    ASSERT_EQ(ret, 0, "NIST keypair failed");

    /* Sign with internal API */
    unsigned char msg[] = "Interoperability test";
    unsigned long long msglen = sizeof(msg) - 1;
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 100];
    unsigned long long siglen;

    ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    ASSERT_EQ(ret, KAZ_SIGN_SUCCESS, "Internal sign failed");

    /* Verify with NIST API */
    unsigned char recovered[100];
    unsigned long long recovered_len;

    ret = crypto_sign_open(recovered, &recovered_len, sig, siglen, pk);
    ASSERT_EQ(ret, 0, "NIST verify failed");
    ASSERT_MEM_EQ(msg, recovered, msglen, "Message mismatch");

    TEST_PASS();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

void print_header(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         KAZ-SIGN Comprehensive Test Suite                    ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Security Level: %-4d                                        ║\n", KAZ_SECURITY_LEVEL);
    printf("║  Algorithm:      %-20s                     ║\n", KAZ_SIGN_ALGNAME);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Secret Key:     %3d bytes                                   ║\n", KAZ_SIGN_SECRETKEYBYTES);
    printf("║  Public Key:     %3d bytes                                   ║\n", KAZ_SIGN_PUBLICKEYBYTES);
    printf("║  Signature:      %3d bytes (overhead)                        ║\n", KAZ_SIGN_SIGNATURE_OVERHEAD);
    printf("║  Hash:           %3d bytes                                   ║\n", KAZ_SIGN_BYTES);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

void print_summary(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      Test Summary                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:    %3d                                         ║\n", g_stats.total);
    printf("║  Passed:         \033[32m%3d\033[0m                                         ║\n", g_stats.passed);
    printf("║  Failed:         \033[31m%3d\033[0m                                         ║\n", g_stats.failed);
    printf("║  Skipped:        \033[33m%3d\033[0m                                         ║\n", g_stats.skipped);
    printf("║  Total Time:     %7.2f ms                                  ║\n", g_stats.total_time_ms);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    if (g_stats.failed == 0) {
        printf("║  \033[32m✓ ALL TESTS PASSED\033[0m                                          ║\n");
    } else {
        printf("║  \033[31m✗ SOME TESTS FAILED\033[0m                                         ║\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char *argv[])
{
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        }
    }

    /* Seed random for test utilities */
    srand(42);  /* Fixed seed for reproducible tests */

    print_header();

    /* Initialize */
    int ret = kaz_sign_init_random();
    if (ret != KAZ_SIGN_SUCCESS) {
        printf("\n\033[31mFATAL: Failed to initialize random state\033[0m\n");
        return 1;
    }

    /* Run all test categories */

    TEST_CATEGORY("API Conformance Tests");
    test_api_keypair_basic();
    test_api_sign_basic();
    test_api_verify_basic();
    test_api_constants();
    test_api_version();
    test_api_null_pointers();

    TEST_CATEGORY("Functional Correctness Tests");
    test_func_roundtrip();
    test_func_multiple_messages();
    test_func_key_independence();
    test_func_signature_uniqueness();

    TEST_CATEGORY("Edge Case Tests");
    test_edge_empty_message();
    test_edge_single_byte_message();
    test_edge_large_message();
    test_edge_all_zero_message();
    test_edge_all_ones_message();
    test_edge_various_sizes();

    TEST_CATEGORY("Security Tests");
    test_sec_wrong_public_key();
    test_sec_corrupted_signature_s1();
    test_sec_corrupted_signature_s2();
    test_sec_corrupted_signature_s3();
    test_sec_corrupted_message();
    test_sec_truncated_signature();
    test_sec_random_signature();
    test_sec_zero_signature();

    TEST_CATEGORY("Stress Tests");
    test_stress_repeated_keygen();
    test_stress_repeated_sign_verify();
    test_stress_many_keys();

    TEST_CATEGORY("Runtime Security Level Tests");
    test_runtime_level_params();
    test_runtime_level_init();
    test_runtime_level_128_roundtrip();
    test_runtime_level_192_roundtrip();
    test_runtime_level_256_roundtrip();
    test_runtime_cross_level_isolation();
    test_runtime_hash_different_levels();
    test_runtime_level_cleanup();

    TEST_CATEGORY("Interoperability Tests");
    test_interop_nist_api_internal_api();

    /* Cleanup */
    kaz_sign_clear_random();

    print_summary();

    return (g_stats.failed > 0) ? 1 : 0;
}
