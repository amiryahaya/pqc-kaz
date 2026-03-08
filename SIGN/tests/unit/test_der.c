/*
 * KAZ-SIGN DER Key Encoding Unit Tests
 * Tests DER encoding/decoding of public and private keys for all security levels
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
 * Helper: Public key DER round-trip for a given level
 * ============================================================================ */

static void run_pubkey_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk_out = malloc(params->public_key_bytes);
    unsigned char der[512];
    unsigned long long derlen;

    if (!pk || !sk || !pk_out) {
        TEST_FAIL("malloc failed");
        goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup;
    }

    /* Encode */
    derlen = sizeof(der);
    int ret = kaz_sign_pubkey_to_der(level, pk, der, &derlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey_to_der failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Decode */
    memset(pk_out, 0, params->public_key_bytes);
    ret = kaz_sign_pubkey_from_der(level, der, derlen, pk_out);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey_from_der failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Compare */
    if (memcmp(pk, pk_out, params->public_key_bytes) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey round-trip mismatch for %s", label);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(pk_out);
}

/* ============================================================================
 * Helper: Private key DER round-trip for a given level
 * ============================================================================ */

static void run_privkey_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *sk_out = malloc(params->secret_key_bytes);
    unsigned char der[512];
    unsigned long long derlen;

    if (!pk || !sk || !sk_out) {
        TEST_FAIL("malloc failed");
        goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup;
    }

    /* Encode */
    derlen = sizeof(der);
    int ret = kaz_sign_privkey_to_der(level, sk, der, &derlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "privkey_to_der failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Decode (note: der buffer is zeroed by privkey_from_der) */
    memset(sk_out, 0, params->secret_key_bytes);
    ret = kaz_sign_privkey_from_der(level, der, derlen, sk_out);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "privkey_from_der failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Compare */
    if (memcmp(sk, sk_out, params->secret_key_bytes) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "privkey round-trip mismatch for %s", label);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (sk_out) kaz_secure_zero(sk_out, params->secret_key_bytes);
    free(pk); free(sk); free(sk_out);
}

/* ============================================================================
 * Public Key Round-Trip Tests
 * ============================================================================ */

static void test_pubkey_roundtrip_128(void) { run_pubkey_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_pubkey_roundtrip_192(void) { run_pubkey_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_pubkey_roundtrip_256(void) { run_pubkey_roundtrip(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * Private Key Round-Trip Tests
 * ============================================================================ */

static void test_privkey_roundtrip_128(void) { run_privkey_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_privkey_roundtrip_192(void) { run_privkey_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_privkey_roundtrip_256(void) { run_privkey_roundtrip(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * Buffer Too Small Tests
 * ============================================================================ */

static void test_pubkey_buffer_too_small(void)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(KAZ_LEVEL_128) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup;
    }

    /* Provide a buffer that is too small */
    unsigned char tiny[4];
    unsigned long long tinylen = sizeof(tiny);
    int ret = kaz_sign_pubkey_to_der(KAZ_LEVEL_128, pk, tiny, &tinylen);
    if (ret != KAZ_SIGN_ERROR_BUFFER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_BUFFER, got %d", ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

static void test_privkey_buffer_too_small(void)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(KAZ_LEVEL_128) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup;
    }

    unsigned char tiny[4];
    unsigned long long tinylen = sizeof(tiny);
    int ret = kaz_sign_privkey_to_der(KAZ_LEVEL_128, sk, tiny, &tinylen);
    if (ret != KAZ_SIGN_ERROR_BUFFER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_BUFFER, got %d", ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Cross-Verification: sign with original, DER round-trip pubkey, verify
 * ============================================================================ */

static void test_cross_verify_der_pubkey(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk_decoded = malloc(params->public_key_bytes);
    unsigned char der[512];
    unsigned long long derlen;

    const unsigned char *msg = (const unsigned char *)"DER cross-verify test";
    unsigned long long msglen = 21;
    size_t sig_alloc = params->signature_overhead + msglen;
    unsigned char *sig = malloc(sig_alloc);
    unsigned long long siglen = 0;
    unsigned char *msg_out = malloc(sig_alloc);
    unsigned long long msg_outlen = 0;

    if (!pk || !sk || !pk_decoded || !sig || !msg_out) {
        TEST_FAIL("malloc failed");
        goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        goto cleanup;
    }

    /* Sign with original key */
    int ret = kaz_sign_signature_ex(level, sig, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("signing failed");
        goto cleanup;
    }

    /* DER round-trip the public key */
    derlen = sizeof(der);
    ret = kaz_sign_pubkey_to_der(level, pk, der, &derlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("pubkey_to_der failed");
        goto cleanup;
    }

    ret = kaz_sign_pubkey_from_der(level, der, derlen, pk_decoded);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("pubkey_from_der failed");
        goto cleanup;
    }

    /* Verify with decoded pubkey */
    ret = kaz_sign_verify_ex(level, msg_out, &msg_outlen, sig, siglen, pk_decoded);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "verify with DER-decoded pubkey failed (ret=%d)", ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Check recovered message */
    if (msg_outlen != msglen || memcmp(msg_out, msg, msglen) != 0) {
        TEST_FAIL("recovered message mismatch after DER round-trip");
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(pk_decoded); free(sig); free(msg_out);
}

/* ============================================================================
 * Invalid DER Input Rejection Tests
 * ============================================================================ */

static void test_invalid_der_pubkey(void)
{
    tests_run++;

    unsigned char pk[128];

    /* Completely garbage data */
    unsigned char garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    int ret = kaz_sign_pubkey_from_der(KAZ_LEVEL_128, garbage, sizeof(garbage), pk);
    if (ret != KAZ_SIGN_ERROR_DER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_DER for garbage, got %d", ret);
        TEST_FAIL(buf);
        return;
    }

    /* Empty input */
    ret = kaz_sign_pubkey_from_der(KAZ_LEVEL_128, garbage, 0, pk);
    if (ret != KAZ_SIGN_ERROR_DER) {
        TEST_FAIL("expected ERROR_DER for empty input");
        return;
    }

    /* Truncated valid-looking header */
    unsigned char truncated[] = { 0x30, 0x50 };
    ret = kaz_sign_pubkey_from_der(KAZ_LEVEL_128, truncated, sizeof(truncated), pk);
    if (ret != KAZ_SIGN_ERROR_DER) {
        TEST_FAIL("expected ERROR_DER for truncated input");
        return;
    }

    /* NULL pointer */
    ret = kaz_sign_pubkey_from_der(KAZ_LEVEL_128, NULL, 10, pk);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL der");
        return;
    }

    TEST_PASS();
}

static void test_invalid_der_privkey(void)
{
    tests_run++;

    unsigned char sk[128];

    /* Completely garbage data */
    unsigned char garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    int ret = kaz_sign_privkey_from_der(KAZ_LEVEL_128, garbage, sizeof(garbage), sk);
    if (ret != KAZ_SIGN_ERROR_DER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_DER for garbage, got %d", ret);
        TEST_FAIL(buf);
        return;
    }

    /* Wrong OID level: encode for 128, decode for 192 */
    /* First generate a valid DER for level 128 */
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk_orig = malloc(params->secret_key_bytes);
    if (!pk || !sk_orig) { TEST_FAIL("malloc failed"); free(pk); free(sk_orig); return; }

    if (kaz_sign_init_level(KAZ_LEVEL_128) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        free(pk); free(sk_orig);
        return;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk_orig) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed");
        kaz_secure_zero(sk_orig, params->secret_key_bytes);
        free(pk); free(sk_orig);
        return;
    }

    unsigned char der[512];
    unsigned long long derlen = sizeof(der);
    ret = kaz_sign_privkey_to_der(KAZ_LEVEL_128, sk_orig, der, &derlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("privkey_to_der failed");
        kaz_secure_zero(sk_orig, params->secret_key_bytes);
        free(pk); free(sk_orig);
        return;
    }

    /* Make a copy since privkey_from_der zeroes the input */
    unsigned char der_copy[512];
    memcpy(der_copy, der, (size_t)derlen);

    /* Try to decode as level 192 - should fail due to OID mismatch */
    unsigned char sk_wrong[128];
    ret = kaz_sign_privkey_from_der(KAZ_LEVEL_192, der_copy, derlen, sk_wrong);
    if (ret != KAZ_SIGN_ERROR_DER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_DER for wrong level OID, got %d", ret);
        TEST_FAIL(buf);
        kaz_secure_zero(sk_orig, params->secret_key_bytes);
        free(pk); free(sk_orig);
        return;
    }

    kaz_secure_zero(sk_orig, params->secret_key_bytes);
    free(pk); free(sk_orig);

    TEST_PASS();
}

/* ============================================================================
 * NULL Pointer Tests
 * ============================================================================ */

static void test_null_pointers(void)
{
    tests_run++;

    unsigned char dummy[128];
    unsigned long long dummylen = sizeof(dummy);

    /* pubkey_to_der with NULL pk */
    int ret = kaz_sign_pubkey_to_der(KAZ_LEVEL_128, NULL, dummy, &dummylen);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL pk");
        return;
    }

    /* pubkey_to_der with NULL derlen */
    ret = kaz_sign_pubkey_to_der(KAZ_LEVEL_128, dummy, dummy, NULL);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL derlen");
        return;
    }

    /* privkey_to_der with NULL sk */
    dummylen = sizeof(dummy);
    ret = kaz_sign_privkey_to_der(KAZ_LEVEL_128, NULL, dummy, &dummylen);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL sk");
        return;
    }

    /* Invalid level */
    dummylen = sizeof(dummy);
    ret = kaz_sign_pubkey_to_der((kaz_sign_level_t)99, dummy, dummy, &dummylen);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for invalid level");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Size Query Test (NULL der pointer)
 * ============================================================================ */

static void test_size_query(void)
{
    tests_run++;

    unsigned char pk[128] = {0};
    unsigned char sk[128] = {0};
    unsigned long long derlen = 0;

    /* Query pubkey DER size */
    int ret = kaz_sign_pubkey_to_der(KAZ_LEVEL_128, pk, NULL, &derlen);
    if (ret != KAZ_SIGN_SUCCESS || derlen == 0) {
        TEST_FAIL("pubkey size query failed");
        return;
    }

    /* Query privkey DER size */
    derlen = 0;
    ret = kaz_sign_privkey_to_der(KAZ_LEVEL_128, sk, NULL, &derlen);
    if (ret != KAZ_SIGN_SUCCESS || derlen == 0) {
        TEST_FAIL("privkey size query failed");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("========================================================\n");
    printf("          KAZ-SIGN DER Encoding Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  Public Key DER Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_pubkey_roundtrip_128();
    test_pubkey_roundtrip_192();
    test_pubkey_roundtrip_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Private Key DER Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_privkey_roundtrip_128();
    test_privkey_roundtrip_192();
    test_privkey_roundtrip_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Buffer Size Tests\n");
    printf("----------------------------------------------------------\n");
    test_pubkey_buffer_too_small();
    test_privkey_buffer_too_small();
    test_size_query();

    printf("\n----------------------------------------------------------\n");
    printf("  Cross-Verification Tests\n");
    printf("----------------------------------------------------------\n");
    test_cross_verify_der_pubkey();

    printf("\n----------------------------------------------------------\n");
    printf("  Invalid Input Rejection Tests\n");
    printf("----------------------------------------------------------\n");
    test_invalid_der_pubkey();
    test_invalid_der_privkey();
    test_null_pointers();

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
