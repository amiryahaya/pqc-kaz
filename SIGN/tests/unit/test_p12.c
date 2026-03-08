/*
 * KAZ-SIGN PKCS#12 Keystore Unit Tests
 * Tests create/load round-trip, wrong password rejection,
 * certificate handling, and NULL pointer safety.
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
 * Helper: generate a self-signed cert for testing
 * ============================================================================ */

static int make_test_cert(kaz_sign_level_t level,
                          const unsigned char *sk, const unsigned char *pk,
                          const char *subject,
                          unsigned char *cert, unsigned long long *certlen)
{
    unsigned char csr[4096];
    unsigned long long csrlen = sizeof(csr);

    int ret = kaz_sign_generate_csr(level, sk, pk, subject, csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) return ret;

    return kaz_sign_issue_certificate(level, sk, pk, subject,
                                       csr, csrlen, 1, 365, cert, certlen);
}

/* ============================================================================
 * P12 Create and Load Round-Trip (all levels)
 * ============================================================================ */

static void run_p12_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk2 = malloc(params->public_key_bytes);
    unsigned char *sk2 = malloc(params->secret_key_bytes);
    unsigned char cert[8192];
    unsigned long long certlen = sizeof(cert);
    unsigned char p12[16384];
    unsigned long long p12len;
    unsigned char cert2[8192];
    unsigned long long cert2len;

    if (!pk || !sk || !pk2 || !sk2) {
        TEST_FAIL("malloc failed"); goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Generate a test certificate */
    int ret = make_test_cert(level, sk, pk, "CN=P12Test", cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "cert generation failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Create P12 */
    p12len = sizeof(p12);
    ret = kaz_sign_create_p12(level, sk, pk, cert, certlen,
                               "test-password-123", "my-key", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "create_p12 failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Load P12 */
    memset(sk2, 0, params->secret_key_bytes);
    memset(pk2, 0, params->public_key_bytes);
    cert2len = sizeof(cert2);
    ret = kaz_sign_load_p12(level, p12, p12len, "test-password-123",
                             sk2, pk2, cert2, &cert2len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "load_p12 failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Verify keys match */
    if (memcmp(sk, sk2, params->secret_key_bytes) != 0) {
        TEST_FAIL("secret key mismatch after round-trip"); goto cleanup;
    }
    if (memcmp(pk, pk2, params->public_key_bytes) != 0) {
        TEST_FAIL("public key mismatch after round-trip"); goto cleanup;
    }

    /* Verify cert matches */
    if (cert2len != certlen) {
        TEST_FAIL("cert length mismatch after round-trip"); goto cleanup;
    }
    if (memcmp(cert, cert2, (size_t)certlen) != 0) {
        TEST_FAIL("cert data mismatch after round-trip"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (sk2) kaz_secure_zero(sk2, params->secret_key_bytes);
    free(pk); free(sk); free(pk2); free(sk2);
}

static void test_p12_roundtrip_128(void) { run_p12_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_p12_roundtrip_192(void) { run_p12_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_p12_roundtrip_256(void) { run_p12_roundtrip(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * Wrong Password Rejection
 * ============================================================================ */

static void test_wrong_password(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Create P12 with one password */
    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "correct-password", "key1", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("create_p12 failed"); goto cleanup;
    }

    /* Try to load with wrong password */
    unsigned char sk_out[64], pk_out[128];
    ret = kaz_sign_load_p12(level, p12, p12len, "wrong-password",
                             sk_out, pk_out, NULL, NULL);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("load_p12 should fail with wrong password"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Empty Password Handling
 * ============================================================================ */

static void test_empty_password(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk2 = malloc(params->public_key_bytes);
    unsigned char *sk2 = malloc(params->secret_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk || !pk2 || !sk2) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Create P12 with empty string password (not NULL) */
    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "", "test", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Create P12 with empty password failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Load with empty password should work */
    memset(sk2, 0, params->secret_key_bytes);
    memset(pk2, 0, params->public_key_bytes);
    ret = kaz_sign_load_p12(level, p12, p12len, "",
                             sk2, pk2, NULL, NULL);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Load P12 with empty password failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Verify keys match */
    if (memcmp(sk, sk2, params->secret_key_bytes) != 0) {
        TEST_FAIL("Secret key mismatch"); goto cleanup;
    }
    if (memcmp(pk, pk2, params->public_key_bytes) != 0) {
        TEST_FAIL("Public key mismatch"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (sk2) kaz_secure_zero(sk2, params->secret_key_bytes);
    free(pk); free(sk); free(pk2); free(sk2);
}

/* ============================================================================
 * Empty Certificate (no cert in P12)
 * ============================================================================ */

static void test_no_cert(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk2 = malloc(params->public_key_bytes);
    unsigned char *sk2 = malloc(params->secret_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk || !pk2 || !sk2) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Create P12 without cert */
    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "no-cert-pw", "bare-key", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("create_p12 without cert failed"); goto cleanup;
    }

    /* Load it back */
    unsigned long long cert2len = 0;
    ret = kaz_sign_load_p12(level, p12, p12len, "no-cert-pw",
                             sk2, pk2, NULL, &cert2len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "load_p12 without cert failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Cert length should be 0 */
    if (cert2len != 0) {
        TEST_FAIL("expected cert length 0 for no-cert P12"); goto cleanup;
    }

    /* Keys should match */
    if (memcmp(sk, sk2, params->secret_key_bytes) != 0) {
        TEST_FAIL("secret key mismatch"); goto cleanup;
    }
    if (memcmp(pk, pk2, params->public_key_bytes) != 0) {
        TEST_FAIL("public key mismatch"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    if (sk2) kaz_secure_zero(sk2, params->secret_key_bytes);
    free(pk); free(sk); free(pk2); free(sk2);
}

/* ============================================================================
 * NULL Pointer Handling
 * ============================================================================ */

static void test_null_pointers(void)
{
    tests_run++;

    int ret;

    /* NULL sk */
    unsigned long long p12len = 1024;
    unsigned char p12[1024];
    ret = kaz_sign_create_p12(KAZ_LEVEL_128, NULL, (unsigned char*)"pk",
                               NULL, 0, "pw", "name", p12, &p12len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("NULL sk should return INVALID"); return;
    }

    /* NULL password for create */
    unsigned char dummy_sk[64] = {0};
    unsigned char dummy_pk[128] = {0};
    p12len = sizeof(p12);
    ret = kaz_sign_create_p12(KAZ_LEVEL_128, dummy_sk, dummy_pk,
                               NULL, 0, NULL, "name", p12, &p12len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("NULL password for create should return INVALID"); return;
    }

    /* NULL p12len */
    ret = kaz_sign_create_p12(KAZ_LEVEL_128, dummy_sk, dummy_pk,
                               NULL, 0, "pw", "name", p12, NULL);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("NULL p12len should return INVALID"); return;
    }

    /* NULL p12 data for load */
    ret = kaz_sign_load_p12(KAZ_LEVEL_128, NULL, 100, "pw",
                             NULL, NULL, NULL, NULL);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("NULL p12 data for load should return INVALID"); return;
    }

    /* NULL password for load */
    ret = kaz_sign_load_p12(KAZ_LEVEL_128, p12, sizeof(p12), NULL,
                             NULL, NULL, NULL, NULL);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("NULL password for load should return INVALID"); return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Tampered Data Detection
 * ============================================================================ */

static void test_tampered_data(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "tamper-test", "key", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("create_p12 failed"); goto cleanup;
    }

    /* Flip a byte in the encrypted payload */
    if (p12len > 80) {
        p12[p12len - 10] ^= 0xFF;
    }

    unsigned char sk_out[64], pk_out[128];
    ret = kaz_sign_load_p12(level, p12, p12len, "tamper-test",
                             sk_out, pk_out, NULL, NULL);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("tampered P12 should fail to load"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Buffer Too Small
 * ============================================================================ */

static void test_buffer_too_small(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char p12[16];
    unsigned long long p12len;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Try with tiny buffer */
    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "pw", "key", p12, &p12len);
    if (ret != KAZ_SIGN_ERROR_BUFFER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected BUFFER error, got %d", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Size Query (NULL output buffer)
 * ============================================================================ */

static void test_size_query(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    unsigned long long p12len = 0;
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "pw", "key", NULL, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("size query should succeed"); goto cleanup;
    }
    if (p12len == 0) {
        TEST_FAIL("size query returned 0"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Wrong Level Rejection
 * ============================================================================ */

static void test_wrong_level(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }
    if (kaz_sign_init_level(KAZ_LEVEL_192) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level 192 failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Create at level 128 */
    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "pw", "key", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("create_p12 failed"); goto cleanup;
    }

    /* Try to load at level 192 -- should fail */
    unsigned char sk_out[64], pk_out[128];
    ret = kaz_sign_load_p12(KAZ_LEVEL_192, p12, p12len, "pw",
                             sk_out, pk_out, NULL, NULL);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("load with wrong level should fail"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Load with selective NULL outputs (skip sk or pk)
 * ============================================================================ */

static void test_selective_load(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk2 = malloc(params->public_key_bytes);
    unsigned char p12[16384];
    unsigned long long p12len;

    if (!pk || !sk || !pk2) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    p12len = sizeof(p12);
    int ret = kaz_sign_create_p12(level, sk, pk, NULL, 0,
                                   "pw", "key", p12, &p12len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("create_p12 failed"); goto cleanup;
    }

    /* Load only pk (skip sk) */
    memset(pk2, 0, params->public_key_bytes);
    ret = kaz_sign_load_p12(level, p12, p12len, "pw",
                             NULL, pk2, NULL, NULL);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "selective load (pk only) failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    if (memcmp(pk, pk2, params->public_key_bytes) != 0) {
        TEST_FAIL("pk mismatch in selective load"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(pk2);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("========================================================\n");
    printf("          KAZ-SIGN PKCS#12 Keystore Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  Round-Trip Tests (all levels)\n");
    printf("----------------------------------------------------------\n");
    test_p12_roundtrip_128();
    test_p12_roundtrip_192();
    test_p12_roundtrip_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Wrong Password Rejection\n");
    printf("----------------------------------------------------------\n");
    test_wrong_password();

    printf("\n----------------------------------------------------------\n");
    printf("  Empty Password Handling\n");
    printf("----------------------------------------------------------\n");
    test_empty_password();

    printf("\n----------------------------------------------------------\n");
    printf("  No Certificate Handling\n");
    printf("----------------------------------------------------------\n");
    test_no_cert();

    printf("\n----------------------------------------------------------\n");
    printf("  NULL Pointer Safety\n");
    printf("----------------------------------------------------------\n");
    test_null_pointers();

    printf("\n----------------------------------------------------------\n");
    printf("  Tampered Data Detection\n");
    printf("----------------------------------------------------------\n");
    test_tampered_data();

    printf("\n----------------------------------------------------------\n");
    printf("  Buffer Size Tests\n");
    printf("----------------------------------------------------------\n");
    test_buffer_too_small();
    test_size_query();

    printf("\n----------------------------------------------------------\n");
    printf("  Wrong Level Rejection\n");
    printf("----------------------------------------------------------\n");
    test_wrong_level();

    printf("\n----------------------------------------------------------\n");
    printf("  Selective Load Tests\n");
    printf("----------------------------------------------------------\n");
    test_selective_load();

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
