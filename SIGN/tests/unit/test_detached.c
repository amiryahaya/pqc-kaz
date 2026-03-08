/*
 * KAZ-SIGN Detached Signature Unit Tests
 * Tests detached sign/verify API for all security levels
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/sign.h"
#include "kaz/security.h"

/* Test result counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS() do { tests_passed++; printf("  [PASS] %s\n", __func__); } while(0)
#define TEST_FAIL(msg) do { tests_failed++; printf("  [FAIL] %s: %s\n", __func__, msg); } while(0)

/* ============================================================================
 * Signature Size Tests
 * ============================================================================ */

static void test_detached_sig_bytes_128(void)
{
    tests_run++;
    size_t sz = kaz_sign_detached_sig_bytes(KAZ_LEVEL_128);
    if (sz != 162) {
        TEST_FAIL("Expected 162 bytes for level 128");
        printf("    Got: %zu\n", sz);
        return;
    }
    TEST_PASS();
}

static void test_detached_sig_bytes_192(void)
{
    tests_run++;
    size_t sz = kaz_sign_detached_sig_bytes(KAZ_LEVEL_192);
    if (sz != 264) {
        TEST_FAIL("Expected 264 bytes for level 192");
        printf("    Got: %zu\n", sz);
        return;
    }
    TEST_PASS();
}

static void test_detached_sig_bytes_256(void)
{
    tests_run++;
    size_t sz = kaz_sign_detached_sig_bytes(KAZ_LEVEL_256);
    if (sz != 356) {
        TEST_FAIL("Expected 356 bytes for level 256");
        printf("    Got: %zu\n", sz);
        return;
    }
    TEST_PASS();
}

static void test_detached_sig_bytes_invalid(void)
{
    tests_run++;
    size_t sz = kaz_sign_detached_sig_bytes((kaz_sign_level_t)99);
    if (sz != 0) {
        TEST_FAIL("Expected 0 for invalid level");
        return;
    }
    TEST_PASS();
}

/* ============================================================================
 * Helper: run detached round-trip for a given level
 * ============================================================================ */

static int run_detached_roundtrip(kaz_sign_level_t level)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) return -1;

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;
    int ret;

    if (!pk || !sk || !sig) {
        free(pk); free(sk); free(sig);
        return -1;
    }

    /* Initialize level */
    ret = kaz_sign_init_level(level);
    if (ret != KAZ_SIGN_SUCCESS) {
        free(pk); free(sk); free(sig);
        return -1;
    }

    /* Generate keypair */
    ret = kaz_sign_keypair_ex(level, pk, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        free(pk); free(sk); free(sig);
        return -1;
    }

    /* Sign */
    const unsigned char *msg = (const unsigned char *)"Hello, detached signing!";
    unsigned long long msglen = 24;

    ret = kaz_sign_detached_ex(level, sig, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        free(pk); free(sk); free(sig);
        return -1;
    }

    /* Check signature length */
    if (siglen != sig_bytes) {
        free(pk); free(sk); free(sig);
        return -2;
    }

    /* Verify */
    ret = kaz_sign_verify_detached_ex(level, sig, siglen, msg, msglen, pk);

    kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(sig);
    return ret;
}

/* ============================================================================
 * Detached Sign/Verify Round-Trip Tests
 * ============================================================================ */

static void test_detached_roundtrip_128(void)
{
    tests_run++;
    int ret = run_detached_roundtrip(KAZ_LEVEL_128);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "round-trip failed with code %d", ret);
        TEST_FAIL(buf);
        return;
    }
    TEST_PASS();
}

static void test_detached_roundtrip_192(void)
{
    tests_run++;
    int ret = run_detached_roundtrip(KAZ_LEVEL_192);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "round-trip failed with code %d", ret);
        TEST_FAIL(buf);
        return;
    }
    TEST_PASS();
}

static void test_detached_roundtrip_256(void)
{
    tests_run++;
    int ret = run_detached_roundtrip(KAZ_LEVEL_256);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "round-trip failed with code %d", ret);
        TEST_FAIL(buf);
        return;
    }
    TEST_PASS();
}

/* ============================================================================
 * Wrong Key Rejection
 * ============================================================================ */

static void test_detached_wrong_key(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk1 = malloc(params->public_key_bytes);
    unsigned char *sk1 = malloc(params->secret_key_bytes);
    unsigned char *pk2 = malloc(params->public_key_bytes);
    unsigned char *sk2 = malloc(params->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk1 || !sk1 || !pk2 || !sk2 || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_wrong_key;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_wrong_key;
    }

    /* Generate two different keypairs */
    if (kaz_sign_keypair_ex(level, pk1, sk1) != KAZ_SIGN_SUCCESS ||
        kaz_sign_keypair_ex(level, pk2, sk2) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup_wrong_key;
    }

    /* Sign with key 1 */
    const unsigned char *msg = (const unsigned char *)"Test message";
    unsigned long long msglen = 12;

    if (kaz_sign_detached_ex(level, sig, &siglen, msg, msglen, sk1) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("signing failed");
        goto cleanup_wrong_key;
    }

    /* Verify with key 2 - should fail */
    int ret = kaz_sign_verify_detached_ex(level, sig, siglen, msg, msglen, pk2);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("verification succeeded with wrong key - should have failed");
        goto cleanup_wrong_key;
    }

    TEST_PASS();

cleanup_wrong_key:
    if (sk1) kaz_secure_zero(sk1, params->secret_key_bytes);
    if (sk2) kaz_secure_zero(sk2, params->secret_key_bytes);
    free(pk1); free(sk1); free(pk2); free(sk2); free(sig);
}

/* ============================================================================
 * Wrong Message Rejection
 * ============================================================================ */

static void test_detached_wrong_message(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk || !sk || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_wrong_msg;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_wrong_msg;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup_wrong_msg;
    }

    /* Sign original message */
    const unsigned char *msg1 = (const unsigned char *)"Original message";
    unsigned long long msg1len = 16;

    if (kaz_sign_detached_ex(level, sig, &siglen, msg1, msg1len, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("signing failed");
        goto cleanup_wrong_msg;
    }

    /* Verify with different message - should fail */
    const unsigned char *msg2 = (const unsigned char *)"Different message";
    unsigned long long msg2len = 17;

    int ret = kaz_sign_verify_detached_ex(level, sig, siglen, msg2, msg2len, pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("verification succeeded with wrong message - should have failed");
        goto cleanup_wrong_msg;
    }

    TEST_PASS();

cleanup_wrong_msg:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(sig);
}

/* ============================================================================
 * Cross-Level Rejection
 * ============================================================================ */

static void test_detached_cross_level_rejection(void)
{
    tests_run++;

    const kaz_sign_level_params_t *p128 = kaz_sign_get_level_params(KAZ_LEVEL_128);
    const kaz_sign_level_params_t *p256 = kaz_sign_get_level_params(KAZ_LEVEL_256);
    if (!p128 || !p256) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk128 = malloc(p128->public_key_bytes);
    unsigned char *sk128 = malloc(p128->secret_key_bytes);
    unsigned char *pk256 = malloc(p256->public_key_bytes);
    unsigned char *sk256 = malloc(p256->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(KAZ_LEVEL_128);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk128 || !sk128 || !pk256 || !sk256 || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_cross;
    }

    if (kaz_sign_init_level(KAZ_LEVEL_128) != KAZ_SIGN_SUCCESS ||
        kaz_sign_init_level(KAZ_LEVEL_256) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_cross;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_128, pk128, sk128) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Keygen 128 failed");
        goto cleanup_cross;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_256, pk256, sk256) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Keygen 256 failed");
        goto cleanup_cross;
    }

    const unsigned char *msg = (const unsigned char *)"cross-level test";
    unsigned long long msglen = 16;

    int ret = kaz_sign_detached_ex(KAZ_LEVEL_128, sig, &siglen, msg, msglen, sk128);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Detached sign failed");
        goto cleanup_cross;
    }

    /* Verify with wrong level should fail */
    ret = kaz_sign_verify_detached_ex(KAZ_LEVEL_256, sig, siglen, msg, msglen, pk256);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Cross-level verify should fail");
        goto cleanup_cross;
    }

    TEST_PASS();

cleanup_cross:
    if (sk128) kaz_secure_zero(sk128, p128->secret_key_bytes);
    if (sk256) kaz_secure_zero(sk256, p256->secret_key_bytes);
    free(pk128); free(sk128); free(pk256); free(sk256); free(sig);
}

/* ============================================================================
 * Tampered Detached Signature Rejection
 * ============================================================================ */

static void test_detached_tampered_signature(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk || !sk || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_tamper;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_tamper;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Keygen failed");
        goto cleanup_tamper;
    }

    const unsigned char *msg = (const unsigned char *)"tamper test message";
    unsigned long long msglen = 19;

    int ret = kaz_sign_detached_ex(level, sig, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Sign failed");
        goto cleanup_tamper;
    }

    /* Flip a byte in the signature */
    sig[siglen / 2] ^= 0xFF;

    ret = kaz_sign_verify_detached_ex(level, sig, siglen, msg, msglen, pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Tampered signature should not verify");
        goto cleanup_tamper;
    }

    TEST_PASS();

cleanup_tamper:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(sig);
}

/* ============================================================================
 * Prehashed Sign/Verify Round-Trip
 * ============================================================================ */

static void test_detached_prehashed_roundtrip(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *digest = malloc(params->hash_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk || !sk || !digest || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_prehash;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_prehash;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup_prehash;
    }

    /* Hash the message ourselves */
    const unsigned char *msg = (const unsigned char *)"Prehashed test message";
    unsigned long long msglen = 22;

    if (kaz_sign_hash_ex(level, msg, msglen, digest) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("hashing failed");
        goto cleanup_prehash;
    }

    /* Sign prehashed */
    int ret = kaz_sign_detached_prehashed_ex(level, sig, &siglen,
                                              digest, params->hash_bytes, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "prehashed signing failed with code %d", ret);
        TEST_FAIL(buf);
        goto cleanup_prehash;
    }

    /* Verify prehashed */
    ret = kaz_sign_verify_detached_prehashed_ex(level, sig, siglen,
                                                 digest, params->hash_bytes, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "prehashed verify failed with code %d", ret);
        TEST_FAIL(buf);
        goto cleanup_prehash;
    }

    TEST_PASS();

cleanup_prehash:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (digest) kaz_secure_zero(digest, params->hash_bytes);
    free(pk); free(sk); free(digest); free(sig);
}

/* ============================================================================
 * Prehashed: detached sign matches manual hash + detached verify
 * ============================================================================ */

static void test_detached_prehashed_matches_normal(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *digest = malloc(params->hash_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk || !sk || !digest || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_match;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_match;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup_match;
    }

    /* Hash the message ourselves */
    const unsigned char *msg = (const unsigned char *)"Cross-check message";
    unsigned long long msglen = 19;

    if (kaz_sign_hash_ex(level, msg, msglen, digest) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("hashing failed");
        goto cleanup_match;
    }

    /* Sign with prehashed API */
    int ret = kaz_sign_detached_prehashed_ex(level, sig, &siglen,
                                              digest, params->hash_bytes, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("prehashed signing failed");
        goto cleanup_match;
    }

    /* Verify with normal detached API (which hashes internally) */
    ret = kaz_sign_verify_detached_ex(level, sig, siglen, msg, msglen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("verify_detached_ex failed for prehashed signature");
        goto cleanup_match;
    }

    TEST_PASS();

cleanup_match:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (digest) kaz_secure_zero(digest, params->hash_bytes);
    free(pk); free(sk); free(digest); free(sig);
}

/* ============================================================================
 * Empty Data Sign/Verify
 * ============================================================================ */

static void test_detached_empty_message(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    size_t sig_bytes = kaz_sign_detached_sig_bytes(level);
    unsigned char *sig = malloc(sig_bytes);
    unsigned long long siglen = 0;

    if (!pk || !sk || !sig) {
        TEST_FAIL("malloc failed");
        goto cleanup_empty;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup_empty;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup_empty;
    }

    /* Sign empty message (NULL, 0) */
    int ret = kaz_sign_detached_ex(level, sig, &siglen, NULL, 0, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "empty message sign failed with code %d", ret);
        TEST_FAIL(buf);
        goto cleanup_empty;
    }

    /* Verify empty message */
    ret = kaz_sign_verify_detached_ex(level, sig, siglen, NULL, 0, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[64];
        snprintf(buf, sizeof(buf), "empty message verify failed with code %d", ret);
        TEST_FAIL(buf);
        goto cleanup_empty;
    }

    TEST_PASS();

cleanup_empty:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(sig);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("========================================================\n");
    printf("          KAZ-SIGN Detached Signature Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  Signature Size Tests\n");
    printf("----------------------------------------------------------\n");
    test_detached_sig_bytes_128();
    test_detached_sig_bytes_192();
    test_detached_sig_bytes_256();
    test_detached_sig_bytes_invalid();

    printf("\n----------------------------------------------------------\n");
    printf("  Detached Sign/Verify Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_detached_roundtrip_128();
    test_detached_roundtrip_192();
    test_detached_roundtrip_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Security Tests\n");
    printf("----------------------------------------------------------\n");
    test_detached_wrong_key();
    test_detached_wrong_message();
    test_detached_cross_level_rejection();
    test_detached_tampered_signature();

    printf("\n----------------------------------------------------------\n");
    printf("  Prehashed Tests\n");
    printf("----------------------------------------------------------\n");
    test_detached_prehashed_roundtrip();
    test_detached_prehashed_matches_normal();

    printf("\n----------------------------------------------------------\n");
    printf("  Edge Case Tests\n");
    printf("----------------------------------------------------------\n");
    test_detached_empty_message();

    printf("\n========================================================\n");
    printf("  Test Summary\n");
    printf("========================================================\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: \033[32m%d\033[0m\n", tests_passed);
    printf("  Failed: \033[31m%d\033[0m\n", tests_failed);

    if (tests_failed == 0) {
        printf("\n  \033[32mALL TESTS PASSED\033[0m\n");
    } else {
        printf("\n  \033[31mSOME TESTS FAILED\033[0m\n");
    }
    printf("========================================================\n\n");

    /* Cleanup */
    kaz_sign_clear_all();

    return (tests_failed == 0) ? 0 : 1;
}
