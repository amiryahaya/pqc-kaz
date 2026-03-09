/*
 * KAZ-KEM Comprehensive Test Suite
 * Version 2.0.0 - Runtime Security Level Support
 *
 * Industry-grade testing framework for KEM implementation
 * Tests all security levels (128, 192, 256) in a single run
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#include "kaz/nist_api.h"
#include "kaz/kem.h"
#include "kaz/version.h"

/* Test framework macros */
#define TEST_PASSED "\033[32m[PASS]\033[0m"
#define TEST_FAILED "\033[31m[FAIL]\033[0m"
#define TEST_SKIPPED "\033[33m[SKIP]\033[0m"
#define TEST_INFO "\033[34m[INFO]\033[0m"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

/* Current test level for parameterized tests */
static int g_test_level = 0;

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

#define SKIP_TEST(test_func, reason) do { \
    printf("Skipping: %s ... %s (%s)\n", #test_func, TEST_SKIPPED, reason); \
    tests_skipped++; \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "\n  Assertion failed: %s\n", #expr); \
        return 0; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "\n  Assertion failed: %s == %s (%lld != %lld)\n", \
                #a, #b, (long long)(a), (long long)(b)); \
        return 0; \
    } \
} while(0)

#define ASSERT_ZERO(expr) ASSERT_EQ(expr, 0)
#define ASSERT_NEQ(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_MEM_EQ(a, b, n) do { \
    if (memcmp(a, b, n) != 0) { \
        fprintf(stderr, "\n  Memory comparison failed at %s\n", #a); \
        fprintf(stderr, "  Comparing %s with %s (%zu bytes)\n", #a, #b, (size_t)(n)); \
        fprintf(stderr, "  First 32 bytes of %s: ", #a); \
        for (size_t _i = 0; _i < (n < 32 ? n : 32); _i++) { \
            fprintf(stderr, "%02x", ((unsigned char*)(a))[_i]); \
        } \
        fprintf(stderr, "\n  First 32 bytes of %s: ", #b); \
        for (size_t _i = 0; _i < (n < 32 ? n : 32); _i++) { \
            fprintf(stderr, "%02x", ((unsigned char*)(b))[_i]); \
        } \
        fprintf(stderr, "\n  First difference at byte: "); \
        for (size_t _i = 0; _i < (size_t)(n); _i++) { \
            if (((unsigned char*)(a))[_i] != ((unsigned char*)(b))[_i]) { \
                fprintf(stderr, "%zu (0x%02x != 0x%02x)\n", _i, \
                    ((unsigned char*)(a))[_i], ((unsigned char*)(b))[_i]); \
                break; \
            } \
        } \
        return 0; \
    } \
} while(0)

/* ============================================================================
 * HELPER FUNCTIONS FOR RUNTIME API
 * ============================================================================ */

/* Allocate buffers based on current security level */
static unsigned char* alloc_pk(void) {
    return (unsigned char*)malloc(kaz_kem_publickey_bytes());
}

static unsigned char* alloc_sk(void) {
    return (unsigned char*)malloc(kaz_kem_privatekey_bytes());
}

static unsigned char* alloc_ct(void) {
    return (unsigned char*)malloc(kaz_kem_ciphertext_bytes());
}

static unsigned char* alloc_ss(void) {
    return (unsigned char*)malloc(kaz_kem_shared_secret_bytes());
}

/* ============================================================================
 * UNIT TESTS (Runtime API)
 * ============================================================================ */

/* Test 1: Key Generation - Basic Functionality */
int test_keygen_basic(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    size_t pk_size = kaz_kem_publickey_bytes();
    size_t sk_size = kaz_kem_privatekey_bytes();

    if (!pk || !sk) {
        free(pk); free(sk);
        return 0;
    }

    int ret = kaz_kem_keypair(pk, sk);
    ASSERT_ZERO(ret);

    /* Keys should not be all zeros */
    int pk_nonzero = 0, sk_nonzero = 0;
    for (size_t i = 0; i < pk_size; i++) {
        if (pk[i] != 0) pk_nonzero = 1;
    }
    for (size_t i = 0; i < sk_size; i++) {
        if (sk[i] != 0) sk_nonzero = 1;
    }

    ASSERT_TRUE(pk_nonzero);
    ASSERT_TRUE(sk_nonzero);

    free(pk); free(sk);
    return 1;
}

/* Test 2: Key Generation - Determinism Check */
int test_keygen_determinism(void)
{
    unsigned char *pk1 = alloc_pk();
    unsigned char *sk1 = alloc_sk();
    unsigned char *pk2 = alloc_pk();
    unsigned char *sk2 = alloc_sk();
    size_t pk_size = kaz_kem_publickey_bytes();
    size_t sk_size = kaz_kem_privatekey_bytes();

    if (!pk1 || !sk1 || !pk2 || !sk2) {
        free(pk1); free(sk1); free(pk2); free(sk2);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk1, sk1));
    ASSERT_ZERO(kaz_kem_keypair(pk2, sk2));

    /* They should be different */
    int pk_different = memcmp(pk1, pk2, pk_size);
    int sk_different = memcmp(sk1, sk2, sk_size);

    ASSERT_NEQ(pk_different, 0);
    ASSERT_NEQ(sk_different, 0);

    free(pk1); free(sk1); free(pk2); free(sk2);
    return 1;
}

/* Test 3: Encapsulation - Basic Functionality */
int test_encap_basic(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen;

    if (!pk || !sk || !msg || !ct) {
        free(pk); free(sk); free(msg); free(ct);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));

    /* Create test message with pattern */
    for (size_t i = 0; i < ss_size; i++) {
        msg[i] = (unsigned char)(i & 0xFF);
    }

    int ret = kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk);
    ASSERT_ZERO(ret);
    ASSERT_EQ(ctlen, kaz_kem_ciphertext_bytes());

    /* Ciphertext should not be all zeros */
    int nonzero = 0;
    for (unsigned long long i = 0; i < ctlen; i++) {
        if (ct[i] != 0) nonzero = 1;
    }
    ASSERT_TRUE(nonzero);

    free(pk); free(sk); free(msg); free(ct);
    return 1;
}

/* Test 4: Decapsulation - Basic Functionality */
int test_decap_basic(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    unsigned char *decap = alloc_ss();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen, decaplen;

    if (!pk || !sk || !msg || !ct || !decap) {
        free(pk); free(sk); free(msg); free(ct); free(decap);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));

    for (size_t i = 0; i < ss_size; i++) {
        msg[i] = (unsigned char)(i & 0xFF);
    }

    ASSERT_ZERO(kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk));
    int ret = kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk);
    ASSERT_ZERO(ret);

    free(pk); free(sk); free(msg); free(ct); free(decap);
    return 1;
}

/* Test 5: Round-trip Correctness */
int test_roundtrip_correctness(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    unsigned char *decap = alloc_ss();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen, decaplen;

    if (!pk || !sk || !msg || !ct || !decap) {
        free(pk); free(sk); free(msg); free(ct); free(decap);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));

    for (size_t i = 0; i < ss_size; i++) {
        msg[i] = (unsigned char)(i & 0xFF);
    }

    ASSERT_ZERO(kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk));
    ASSERT_ZERO(kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk));
    ASSERT_EQ(decaplen, ss_size);
    ASSERT_MEM_EQ(msg, decap, ss_size);

    free(pk); free(sk); free(msg); free(ct); free(decap);
    return 1;
}

/* Test 6: Multiple Messages Round-trip */
int test_multiple_messages(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    size_t ct_size = kaz_kem_ciphertext_bytes();

    if (!pk || !sk) {
        free(pk); free(sk);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));

    for (int test = 0; test < 10; test++) {
        unsigned char *msg = (unsigned char*)malloc(ss_size);
        unsigned char *ct = (unsigned char*)malloc(ct_size);
        unsigned char *decap = (unsigned char*)malloc(ss_size);
        unsigned long long ctlen, decaplen;

        if (!msg || !ct || !decap) {
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        for (size_t i = 0; i < ss_size; i++) {
            msg[i] = (unsigned char)((test + i) & 0xFF);
        }

        int ret = kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk);
        if (ret != 0) {
            fprintf(stderr, "\n  Message %d: encapsulation failed with code %d\n", test, ret);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        ret = kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk);
        if (ret != 0) {
            fprintf(stderr, "\n  Message %d: decapsulation failed with code %d\n", test, ret);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        if (decaplen != ss_size || memcmp(msg, decap, ss_size) != 0) {
            fprintf(stderr, "\n  Message %d: content mismatch\n", test);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        free(msg); free(ct); free(decap);
    }

    free(pk); free(sk);
    return 1;
}

/* Test 7: All Zeros Message */
int test_zero_message(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    unsigned char *decap = alloc_ss();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen, decaplen;

    if (!pk || !sk || !msg || !ct || !decap) {
        free(pk); free(sk); free(msg); free(ct); free(decap);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));
    memset(msg, 0x00, ss_size);

    ASSERT_ZERO(kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk));
    ASSERT_ZERO(kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk));
    ASSERT_MEM_EQ(msg, decap, ss_size);

    free(pk); free(sk); free(msg); free(ct); free(decap);
    return 1;
}

/* Test 8: All Ones Message - Expects Error */
int test_ones_message(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen;

    if (!pk || !sk || !msg || !ct) {
        free(pk); free(sk); free(msg); free(ct);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));
    memset(msg, 0xFF, ss_size);

    int ret = kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk);

    /* We expect error code -5 (message >= N) */
    if (ret != -5) {
        fprintf(stderr, "\n  Expected error -5 for all-ones message, got %d\n", ret);
        free(pk); free(sk); free(msg); free(ct);
        return 0;
    }

    free(pk); free(sk); free(msg); free(ct);
    return 1;
}

/* Test 9: Wrong Key Decapsulation */
int test_wrong_key_decap(void)
{
    unsigned char *pk1 = alloc_pk();
    unsigned char *sk1 = alloc_sk();
    unsigned char *pk2 = alloc_pk();
    unsigned char *sk2 = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    unsigned char *decap = alloc_ss();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen, decaplen;

    if (!pk1 || !sk1 || !pk2 || !sk2 || !msg || !ct || !decap) {
        free(pk1); free(sk1); free(pk2); free(sk2);
        free(msg); free(ct); free(decap);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk1, sk1));
    ASSERT_ZERO(kaz_kem_keypair(pk2, sk2));

    for (size_t i = 0; i < ss_size; i++) {
        msg[i] = (unsigned char)(i & 0xFF);
    }

    ASSERT_ZERO(kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk1));
    ASSERT_ZERO(kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk2));

    /* Decrypted message should NOT match original */
    int different = memcmp(msg, decap, ss_size);
    ASSERT_NEQ(different, 0);

    free(pk1); free(sk1); free(pk2); free(sk2);
    free(msg); free(ct); free(decap);
    return 1;
}

/* Test 10: Corrupted Ciphertext */
int test_corrupted_ciphertext(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_ss();
    unsigned char *ct = alloc_ct();
    unsigned char *decap = alloc_ss();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    unsigned long long ctlen, decaplen;

    if (!pk || !sk || !msg || !ct || !decap) {
        free(pk); free(sk); free(msg); free(ct); free(decap);
        return 0;
    }

    ASSERT_ZERO(kaz_kem_keypair(pk, sk));

    for (size_t i = 0; i < ss_size; i++) {
        msg[i] = (unsigned char)(i & 0xFF);
    }

    ASSERT_ZERO(kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk));

    /* Corrupt one byte */
    ct[ctlen / 2] ^= 0xFF;

    ASSERT_ZERO(kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk));

    /* Decrypted message should NOT match original */
    int different = memcmp(msg, decap, ss_size);
    ASSERT_NEQ(different, 0);

    free(pk); free(sk); free(msg); free(ct); free(decap);
    return 1;
}

/* Test 11: Stress Test - Many Operations */
int test_stress_operations(void)
{
    const int iterations = 100;
    size_t pk_size = kaz_kem_publickey_bytes();
    size_t sk_size = kaz_kem_privatekey_bytes();
    size_t ss_size = kaz_kem_shared_secret_bytes();
    size_t ct_size = kaz_kem_ciphertext_bytes();

    unsigned char *pk = (unsigned char*)malloc(pk_size);
    unsigned char *sk = (unsigned char*)malloc(sk_size);

    if (!pk || !sk) {
        free(pk); free(sk);
        return 0;
    }

    for (int i = 0; i < iterations; i++) {
        unsigned char *msg = (unsigned char*)malloc(ss_size);
        unsigned char *ct = (unsigned char*)malloc(ct_size);
        unsigned char *decap = (unsigned char*)malloc(ss_size);
        unsigned long long ctlen, decaplen;

        if (!msg || !ct || !decap) {
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        if (i > 0 && i % 10 == 0) {
            fprintf(stderr, "\n  Progress: %d/%d iterations completed", i, iterations);
            fflush(stderr);
        }

        int ret = kaz_kem_keypair(pk, sk);
        if (ret != 0) {
            fprintf(stderr, "\n  Iteration %d: keypair generation failed with code %d\n", i, ret);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        for (size_t j = 0; j < ss_size; j++) {
            msg[j] = (unsigned char)((j + (i % 32)) & 0xFF);
        }

        ret = kaz_kem_encapsulate(ct, &ctlen, msg, ss_size, pk);
        if (ret != 0) {
            fprintf(stderr, "\n  Iteration %d: encapsulation failed with code %d\n", i, ret);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        ret = kaz_kem_decapsulate(decap, &decaplen, ct, ctlen, sk);
        if (ret != 0) {
            fprintf(stderr, "\n  Iteration %d: decapsulation failed with code %d\n", i, ret);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        if (memcmp(msg, decap, ss_size) != 0) {
            fprintf(stderr, "\n  Iteration %d: Message recovery failed\n", i);
            free(msg); free(ct); free(decap);
            free(pk); free(sk);
            return 0;
        }

        free(msg); free(ct); free(decap);
    }

    if (iterations >= 10) {
        fprintf(stderr, "\n  Progress: %d/%d iterations completed", iterations, iterations);
    }

    free(pk); free(sk);
    return 1;
}

/* ============================================================================
 * TEST RUNNER FOR A SINGLE SECURITY LEVEL
 * ============================================================================ */

void run_tests_for_level(int level)
{
    printf("\n");
    printf("================================================================================\n");
    printf("          KAZ-KEM Test Suite - Security Level %d\n", level);
    printf("================================================================================\n");

    /* Initialize with this security level */
    int ret = kaz_kem_init(level);
    if (ret != 0) {
        printf("FATAL: Failed to initialize KAZ-KEM with level %d (error %d)\n", level, ret);
        tests_failed++;
        return;
    }

    const kaz_kem_params_t *params = kaz_kem_get_params();
    printf("Security Level: %d-bit (%s)\n", level, crypto_kem_algname());
    printf("Public Key Size: %zu bytes\n", kaz_kem_publickey_bytes());
    printf("Private Key Size: %zu bytes\n", kaz_kem_privatekey_bytes());
    printf("Shared Secret Size: %zu bytes\n", kaz_kem_shared_secret_bytes());
    printf("Ciphertext Size: %zu bytes\n", kaz_kem_ciphertext_bytes());
    printf("================================================================================\n\n");

    printf("UNIT TESTS\n");
    printf("----------\n");
    RUN_TEST(test_keygen_basic);
    RUN_TEST(test_keygen_determinism);
    RUN_TEST(test_encap_basic);
    RUN_TEST(test_decap_basic);
    RUN_TEST(test_roundtrip_correctness);
    RUN_TEST(test_multiple_messages);
    RUN_TEST(test_zero_message);
    RUN_TEST(test_ones_message);

    printf("\nNEGATIVE TESTS\n");
    printf("--------------\n");
    RUN_TEST(test_wrong_key_decap);
    RUN_TEST(test_corrupted_ciphertext);

    printf("\nSTRESS TESTS\n");
    printf("------------\n");
    RUN_TEST(test_stress_operations);

    /* Cleanup after this level */
    kaz_kem_cleanup();
}

/* ============================================================================
 * TEST SUMMARY
 * ============================================================================ */

void print_test_summary(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf("                          TEST SUITE SUMMARY\n");
    printf("================================================================================\n");
    printf("Total Tests:   %d\n", tests_run);
    printf("%s Passed:      %d (%.1f%%)\n", TEST_PASSED, tests_passed,
           tests_run > 0 ? 100.0 * tests_passed / tests_run : 0.0);
    printf("%s Failed:      %d\n", TEST_FAILED, tests_failed);
    printf("%s Skipped:     %d\n", TEST_SKIPPED, tests_skipped);
    printf("================================================================================\n");

    if (tests_failed == 0 && tests_run > 0) {
        printf("\n🎉 ALL TESTS PASSED! 🎉\n\n");
    } else if (tests_failed > 0) {
        printf("\n❌ SOME TESTS FAILED ❌\n\n");
    }
}

/* ============================================================================
 * MAIN TEST RUNNER
 * ============================================================================ */

int main(int argc, char *argv[])
{
    printf("\n");
    printf("================================================================================\n");
    printf("          KAZ-KEM Comprehensive Test Suite v%s\n", kaz_kem_version());
    printf("          Runtime Security Level Selection\n");
    printf("================================================================================\n");

#ifdef KAZ_SECURITY_LEVEL
    /* Compile-time mode: test only the specified level */
    printf("Mode: Compile-time security level (%d)\n", KAZ_SECURITY_LEVEL);
    run_tests_for_level(KAZ_SECURITY_LEVEL);
#else
    /* Runtime mode: test all security levels */
    printf("Mode: Runtime security level selection\n");
    printf("Testing all security levels: 128, 192, 256\n");

    /* Check for command line argument to test specific level */
    if (argc > 1) {
        int level = atoi(argv[1]);
        if (level == 128 || level == 192 || level == 256) {
            printf("Testing only level %d (specified via command line)\n", level);
            run_tests_for_level(level);
        } else {
            printf("Invalid level %d. Use 128, 192, or 256.\n", level);
            return 1;
        }
    } else {
        /* Test all levels */
        run_tests_for_level(128);
        run_tests_for_level(192);
        run_tests_for_level(256);
    }
#endif

    print_test_summary();

    /* Full cleanup at program exit to free all OpenSSL resources */
    kaz_kem_cleanup_full();

    return (tests_failed == 0) ? 0 : 1;
}
