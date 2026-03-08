/*
 * KAZ-SIGN X.509 Certificate Unit Tests
 * Tests CSR generation/verification, certificate issuance/verification,
 * and public key extraction for all security levels.
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
 * CSR Generation and Self-Verification
 * ============================================================================ */

static void run_csr_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char csr[4096];
    unsigned long long csrlen;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Generate CSR */
    csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, sk, pk, "CN=Test", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "generate_csr failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Verify CSR */
    ret = kaz_sign_verify_csr(level, csr, csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "verify_csr failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

static void test_csr_roundtrip_128(void) { run_csr_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_csr_roundtrip_192(void) { run_csr_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_csr_roundtrip_256(void) { run_csr_roundtrip(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * Self-Signed Certificate
 * ============================================================================ */

static void run_self_signed_cert(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char csr[4096];
    unsigned long long csrlen;
    unsigned char cert[8192];
    unsigned long long certlen;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Generate CSR */
    csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, sk, pk, "CN=SelfSigned", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "generate_csr failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Issue self-signed certificate */
    certlen = sizeof(cert);
    ret = kaz_sign_issue_certificate(level, sk, pk, "CN=SelfSigned",
                                      csr, csrlen, 1, 365, cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "issue_certificate failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Verify self-signed certificate */
    ret = kaz_sign_verify_certificate(level, cert, certlen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "verify_certificate failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

static void test_self_signed_128(void) { run_self_signed_cert(KAZ_LEVEL_128, "level-128"); }
static void test_self_signed_192(void) { run_self_signed_cert(KAZ_LEVEL_192, "level-192"); }
static void test_self_signed_256(void) { run_self_signed_cert(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * CA-Signed Certificate (2-level chain)
 * ============================================================================ */

static void test_ca_signed_certificate(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *ca_pk = malloc(params->public_key_bytes);
    unsigned char *ca_sk = malloc(params->secret_key_bytes);
    unsigned char *ee_pk = malloc(params->public_key_bytes);
    unsigned char *ee_sk = malloc(params->secret_key_bytes);

    unsigned char ca_csr[4096], ca_cert[8192];
    unsigned long long ca_csrlen, ca_certlen;
    unsigned char ee_csr[4096], ee_cert[8192];
    unsigned long long ee_csrlen, ee_certlen;

    if (!ca_pk || !ca_sk || !ee_pk || !ee_sk) {
        TEST_FAIL("malloc failed"); goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    /* Generate CA key pair */
    if (kaz_sign_keypair_ex(level, ca_pk, ca_sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CA keypair generation failed"); goto cleanup;
    }

    /* Generate end-entity key pair */
    if (kaz_sign_keypair_ex(level, ee_pk, ee_sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("EE keypair generation failed"); goto cleanup;
    }

    /* Create CA self-signed cert */
    ca_csrlen = sizeof(ca_csr);
    int ret = kaz_sign_generate_csr(level, ca_sk, ca_pk, "CN=TestCA/O=KAZ", ca_csr, &ca_csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CA CSR generation failed"); goto cleanup;
    }

    ca_certlen = sizeof(ca_cert);
    ret = kaz_sign_issue_certificate(level, ca_sk, ca_pk, "CN=TestCA/O=KAZ",
                                      ca_csr, ca_csrlen, 1, 3650, ca_cert, &ca_certlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CA cert issuance failed"); goto cleanup;
    }

    /* Verify CA cert is self-signed */
    ret = kaz_sign_verify_certificate(level, ca_cert, ca_certlen, ca_pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CA self-signed verification failed"); goto cleanup;
    }

    /* Create end-entity CSR */
    ee_csrlen = sizeof(ee_csr);
    ret = kaz_sign_generate_csr(level, ee_sk, ee_pk, "CN=EndEntity/O=KAZ/OU=Test",
                                 ee_csr, &ee_csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("EE CSR generation failed"); goto cleanup;
    }

    /* Issue end-entity cert signed by CA */
    ee_certlen = sizeof(ee_cert);
    ret = kaz_sign_issue_certificate(level, ca_sk, ca_pk, "CN=TestCA/O=KAZ",
                                      ee_csr, ee_csrlen, 100, 365, ee_cert, &ee_certlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "EE cert issuance failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Verify EE cert against CA public key */
    ret = kaz_sign_verify_certificate(level, ee_cert, ee_certlen, ca_pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "EE cert verification failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* EE cert should NOT verify against EE's own key */
    ret = kaz_sign_verify_certificate(level, ee_cert, ee_certlen, ee_pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("EE cert should not verify against wrong key"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (ca_sk) kaz_secure_zero(ca_sk, params->secret_key_bytes);
    if (ee_sk) kaz_secure_zero(ee_sk, params->secret_key_bytes);
    free(ca_pk); free(ca_sk); free(ee_pk); free(ee_sk);
}

/* ============================================================================
 * Public Key Extraction from Certificate
 * ============================================================================ */

static void test_cert_extract_pubkey(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk_extracted = malloc(params->public_key_bytes);
    unsigned char csr[4096], cert[8192];
    unsigned long long csrlen, certlen;

    if (!pk || !sk || !pk_extracted) {
        TEST_FAIL("malloc failed"); goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, sk, pk, "CN=ExtractTest", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("CSR generation failed"); goto cleanup; }

    certlen = sizeof(cert);
    ret = kaz_sign_issue_certificate(level, sk, pk, "CN=ExtractTest",
                                      csr, csrlen, 42, 365, cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("cert issuance failed"); goto cleanup; }

    /* Extract public key */
    memset(pk_extracted, 0, params->public_key_bytes);
    ret = kaz_sign_cert_extract_pubkey(level, cert, certlen, pk_extracted);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey extraction failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Compare with original */
    if (memcmp(pk, pk_extracted, params->public_key_bytes) != 0) {
        TEST_FAIL("extracted pubkey does not match original"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(pk_extracted);
}

/* ============================================================================
 * Certificate with Full Subject Fields (CN + O + OU)
 * ============================================================================ */

static void test_full_subject_fields(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char csr[4096], cert[8192];
    unsigned long long csrlen, certlen;

    if (!pk || !sk) { TEST_FAIL("malloc failed"); goto cleanup; }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair generation failed"); goto cleanup;
    }

    /* Use all subject fields */
    const char *subject = "CN=Test User/O=KAZ Organization/OU=Research";

    csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, sk, pk, subject, csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "CSR with full subject failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    ret = kaz_sign_verify_csr(level, csr, csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CSR verification with full subject failed"); goto cleanup;
    }

    certlen = sizeof(cert);
    ret = kaz_sign_issue_certificate(level, sk, pk, subject,
                                      csr, csrlen, 999, 365, cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "cert with full subject failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    ret = kaz_sign_verify_certificate(level, cert, certlen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("cert verification with full subject failed"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Invalid Certificate Rejection
 * ============================================================================ */

static void test_invalid_cert_rejection(void)
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

    /* Garbage data */
    unsigned char garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    int ret = kaz_sign_verify_certificate(level, garbage, sizeof(garbage), pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("garbage should not verify"); goto cleanup;
    }

    /* NULL cert */
    ret = kaz_sign_verify_certificate(level, NULL, 10, pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("NULL cert should fail"); goto cleanup;
    }

    /* NULL pk */
    ret = kaz_sign_verify_certificate(level, garbage, sizeof(garbage), NULL);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("NULL pk should fail"); goto cleanup;
    }

    /* Tampered certificate */
    unsigned char csr[4096], cert[8192];
    unsigned long long csrlen = sizeof(csr), certlen = sizeof(cert);

    ret = kaz_sign_generate_csr(level, sk, pk, "CN=Tamper", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("CSR gen failed"); goto cleanup; }

    ret = kaz_sign_issue_certificate(level, sk, pk, "CN=Tamper",
                                      csr, csrlen, 1, 365, cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("cert issue failed"); goto cleanup; }

    /* Flip a byte in the middle of the cert */
    if (certlen > 20) {
        cert[certlen / 2] ^= 0xFF;
    }

    ret = kaz_sign_verify_certificate(level, cert, certlen, pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("tampered cert should not verify"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Invalid CSR Rejection
 * ============================================================================ */

static void test_invalid_csr_rejection(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_128;

    /* Garbage CSR */
    unsigned char garbage[] = { 0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int ret = kaz_sign_verify_csr(level, garbage, sizeof(garbage));
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("garbage CSR should not verify");
        return;
    }

    /* NULL CSR */
    ret = kaz_sign_verify_csr(level, NULL, 0);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("NULL CSR should fail");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Invalid CSR Version Rejection
 * ============================================================================ */

static void test_invalid_csr_version(void)
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

    /* Generate a valid CSR */
    unsigned char csr[4096];
    unsigned long long csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, sk, pk, "CN=Test", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CSR creation failed"); goto cleanup;
    }

    /* Make a copy and corrupt the version.
     * CSR structure: SEQUENCE { CRI: SEQUENCE { INTEGER(version=0), ... }, ... }
     * The version INTEGER is encoded as 02 01 00. */
    unsigned char bad_csr[4096];
    memcpy(bad_csr, csr, (size_t)csrlen);

    int found = 0;
    for (size_t i = 0; i < (size_t)csrlen - 2; i++) {
        if (bad_csr[i] == 0x02 && bad_csr[i+1] == 0x01 && bad_csr[i+2] == 0x00) {
            /* Change version 0 to version 1 */
            bad_csr[i+2] = 0x01;
            found = 1;
            break;
        }
    }
    if (!found) {
        TEST_FAIL("Could not find version in CSR"); goto cleanup;
    }

    /* Issue a certificate with the bad CSR - should fail because
     * the signature won't match after modification */
    unsigned char cert[8192];
    unsigned long long certlen = sizeof(cert);
    ret = kaz_sign_issue_certificate(level, sk, pk, "CN=Test",
                                      bad_csr, csrlen, 1, 365, cert, &certlen);
    if (ret == KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Should reject CSR with modified version"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk);
}

/* ============================================================================
 * Public Key Extraction from CA-Signed Certificate
 * ============================================================================ */

static void test_extract_pubkey_ca_signed(void)
{
    tests_run++;

    kaz_sign_level_t level = KAZ_LEVEL_192;
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *ca_pk = malloc(params->public_key_bytes);
    unsigned char *ca_sk = malloc(params->secret_key_bytes);
    unsigned char *ee_pk = malloc(params->public_key_bytes);
    unsigned char *ee_sk = malloc(params->secret_key_bytes);
    unsigned char *pk_out = malloc(params->public_key_bytes);

    unsigned char csr[4096], cert[8192];
    unsigned long long csrlen, certlen;

    if (!ca_pk || !ca_sk || !ee_pk || !ee_sk || !pk_out) {
        TEST_FAIL("malloc failed"); goto cleanup;
    }

    if (kaz_sign_init_level(level) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, ca_pk, ca_sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("CA keypair failed"); goto cleanup;
    }

    if (kaz_sign_keypair_ex(level, ee_pk, ee_sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("EE keypair failed"); goto cleanup;
    }

    /* EE CSR */
    csrlen = sizeof(csr);
    int ret = kaz_sign_generate_csr(level, ee_sk, ee_pk, "CN=EE192", csr, &csrlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("EE CSR failed"); goto cleanup; }

    /* CA issues EE cert */
    certlen = sizeof(cert);
    ret = kaz_sign_issue_certificate(level, ca_sk, ca_pk, "CN=CA192",
                                      csr, csrlen, 50, 365, cert, &certlen);
    if (ret != KAZ_SIGN_SUCCESS) { TEST_FAIL("EE cert issuance failed"); goto cleanup; }

    /* Extract EE public key from cert */
    memset(pk_out, 0, params->public_key_bytes);
    ret = kaz_sign_cert_extract_pubkey(level, cert, certlen, pk_out);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "extract pubkey failed (ret=%d)", ret);
        TEST_FAIL(buf); goto cleanup;
    }

    /* Must match EE pk, not CA pk */
    if (memcmp(pk_out, ee_pk, params->public_key_bytes) != 0) {
        TEST_FAIL("extracted key does not match EE pk"); goto cleanup;
    }

    if (memcmp(pk_out, ca_pk, params->public_key_bytes) == 0) {
        TEST_FAIL("extracted key incorrectly matches CA pk"); goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (ca_sk) kaz_secure_zero(ca_sk, params->secret_key_bytes);
    if (ee_sk) kaz_secure_zero(ee_sk, params->secret_key_bytes);
    free(ca_pk); free(ca_sk); free(ee_pk); free(ee_sk); free(pk_out);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("========================================================\n");
    printf("          KAZ-SIGN X.509 Certificate Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  CSR Generation and Verification\n");
    printf("----------------------------------------------------------\n");
    test_csr_roundtrip_128();
    test_csr_roundtrip_192();
    test_csr_roundtrip_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Self-Signed Certificate Tests\n");
    printf("----------------------------------------------------------\n");
    test_self_signed_128();
    test_self_signed_192();
    test_self_signed_256();

    printf("\n----------------------------------------------------------\n");
    printf("  CA-Signed Certificate Tests\n");
    printf("----------------------------------------------------------\n");
    test_ca_signed_certificate();

    printf("\n----------------------------------------------------------\n");
    printf("  Public Key Extraction Tests\n");
    printf("----------------------------------------------------------\n");
    test_cert_extract_pubkey();
    test_extract_pubkey_ca_signed();

    printf("\n----------------------------------------------------------\n");
    printf("  Full Subject Field Tests\n");
    printf("----------------------------------------------------------\n");
    test_full_subject_fields();

    printf("\n----------------------------------------------------------\n");
    printf("  Invalid Input Rejection Tests\n");
    printf("----------------------------------------------------------\n");
    test_invalid_cert_rejection();
    test_invalid_csr_rejection();
    test_invalid_csr_version();

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
