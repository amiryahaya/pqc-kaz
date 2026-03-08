/*
 * KAZ-SIGN KazWire Encoding Unit Tests
 * Tests wire format encoding/decoding of public keys, private keys, and signatures
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
 * Helper: expected wire alg ID for a level
 * ============================================================================ */

static int expected_alg_id(kaz_sign_level_t level) {
    switch (level) {
        case KAZ_LEVEL_128: return KAZ_WIRE_SIGN_128;
        case KAZ_LEVEL_192: return KAZ_WIRE_SIGN_192;
        case KAZ_LEVEL_256: return KAZ_WIRE_SIGN_256;
        default: return -1;
    }
}

/* ============================================================================
 * Public Key Wire Round-Trip
 * ============================================================================ */

static void run_pubkey_wire_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *pk_out = malloc(params->public_key_bytes);
    size_t wire_sz = KAZ_WIRE_HEADER_LEN + params->public_key_bytes;
    unsigned char *wire = malloc(wire_sz);

    if (!pk || !sk || !pk_out || !wire) {
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
    size_t out_len = wire_sz;
    int ret = kaz_sign_pubkey_to_wire(level, pk, params->public_key_bytes, wire, &out_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey_to_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Verify header bytes */
    if (wire[0] != KAZ_WIRE_MAGIC_HI || wire[1] != KAZ_WIRE_MAGIC_LO) {
        TEST_FAIL("magic bytes mismatch");
        goto cleanup;
    }
    if (wire[2] != (unsigned char)expected_alg_id(level)) {
        TEST_FAIL("alg ID mismatch");
        goto cleanup;
    }
    if (wire[3] != KAZ_WIRE_TYPE_PUB) {
        TEST_FAIL("type byte mismatch");
        goto cleanup;
    }
    if (wire[4] != KAZ_WIRE_VERSION) {
        TEST_FAIL("version byte mismatch");
        goto cleanup;
    }

    /* Decode */
    kaz_sign_level_t decoded_level;
    size_t pk_len;
    memset(pk_out, 0, params->public_key_bytes);
    ret = kaz_sign_pubkey_from_wire(wire, out_len, &decoded_level, pk_out, &pk_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey_from_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    if (decoded_level != level) {
        TEST_FAIL("decoded level mismatch");
        goto cleanup;
    }

    if (pk_len != params->public_key_bytes) {
        TEST_FAIL("decoded pk_len mismatch");
        goto cleanup;
    }

    if (memcmp(pk, pk_out, params->public_key_bytes) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "pubkey round-trip mismatch for %s", label);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(pk_out); free(wire);
}

/* ============================================================================
 * Private Key Wire Round-Trip
 * ============================================================================ */

static void run_privkey_wire_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *sk_out = malloc(params->secret_key_bytes);
    size_t wire_sz = KAZ_WIRE_HEADER_LEN + params->secret_key_bytes;
    unsigned char *wire = malloc(wire_sz);

    if (!pk || !sk || !sk_out || !wire) {
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
    size_t out_len = wire_sz;
    int ret = kaz_sign_privkey_to_wire(level, sk, params->secret_key_bytes, wire, &out_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "privkey_to_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Verify header */
    if (wire[0] != KAZ_WIRE_MAGIC_HI || wire[1] != KAZ_WIRE_MAGIC_LO) {
        TEST_FAIL("magic bytes mismatch");
        goto cleanup;
    }
    if (wire[2] != (unsigned char)expected_alg_id(level)) {
        TEST_FAIL("alg ID mismatch");
        goto cleanup;
    }
    if (wire[3] != KAZ_WIRE_TYPE_PRIV) {
        TEST_FAIL("type byte mismatch");
        goto cleanup;
    }
    if (wire[4] != KAZ_WIRE_VERSION) {
        TEST_FAIL("version byte mismatch");
        goto cleanup;
    }

    /* Decode */
    kaz_sign_level_t decoded_level;
    size_t sk_len;
    memset(sk_out, 0, params->secret_key_bytes);
    ret = kaz_sign_privkey_from_wire(wire, out_len, &decoded_level, sk_out, &sk_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "privkey_from_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    if (decoded_level != level) {
        TEST_FAIL("decoded level mismatch");
        goto cleanup;
    }

    if (sk_len != params->secret_key_bytes) {
        TEST_FAIL("decoded sk_len mismatch");
        goto cleanup;
    }

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
    free(pk); free(sk); free(sk_out); free(wire);
}

/* ============================================================================
 * Signature Wire Round-Trip
 * ============================================================================ */

static void run_sig_wire_roundtrip(kaz_sign_level_t level, const char *label)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    unsigned char *sig = malloc(params->signature_overhead);
    unsigned char *sig_out = malloc(params->signature_overhead);
    size_t wire_sz = KAZ_WIRE_HEADER_LEN + params->signature_overhead;
    unsigned char *wire = malloc(wire_sz);

    if (!pk || !sk || !sig || !sig_out || !wire) {
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

    /* Create a detached signature */
    const unsigned char *msg = (const unsigned char *)"KazWire sig test";
    unsigned long long msglen = 16;
    unsigned long long siglen = 0;
    int ret = kaz_sign_detached_ex(level, sig, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "detached sign failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Encode */
    size_t out_len = wire_sz;
    ret = kaz_sign_sig_to_wire(level, sig, (size_t)siglen, wire, &out_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "sig_to_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Verify header */
    if (wire[0] != KAZ_WIRE_MAGIC_HI || wire[1] != KAZ_WIRE_MAGIC_LO) {
        TEST_FAIL("magic bytes mismatch");
        goto cleanup;
    }
    if (wire[2] != (unsigned char)expected_alg_id(level)) {
        TEST_FAIL("alg ID mismatch");
        goto cleanup;
    }
    if (wire[3] != KAZ_WIRE_TYPE_SIG_DET) {
        TEST_FAIL("type byte mismatch");
        goto cleanup;
    }
    if (wire[4] != KAZ_WIRE_VERSION) {
        TEST_FAIL("version byte mismatch");
        goto cleanup;
    }

    /* Decode */
    kaz_sign_level_t decoded_level;
    size_t sig_decoded_len;
    memset(sig_out, 0, params->signature_overhead);
    ret = kaz_sign_sig_from_wire(wire, out_len, &decoded_level, sig_out, &sig_decoded_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "sig_from_wire failed for %s (ret=%d)", label, ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    if (decoded_level != level) {
        TEST_FAIL("decoded level mismatch");
        goto cleanup;
    }

    if (sig_decoded_len != params->signature_overhead) {
        TEST_FAIL("decoded sig_len mismatch");
        goto cleanup;
    }

    if (memcmp(sig, sig_out, params->signature_overhead) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "sig round-trip mismatch for %s", label);
        TEST_FAIL(buf);
        goto cleanup;
    }

    /* Verify the decoded signature still works */
    ret = kaz_sign_verify_detached_ex(level, sig_out, (unsigned long long)sig_decoded_len,
                                       msg, msglen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("verify after wire round-trip failed");
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    if (sk) kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(sig); free(sig_out); free(wire);
}

/* ============================================================================
 * Level-specific test wrappers
 * ============================================================================ */

static void test_pubkey_wire_128(void)  { run_pubkey_wire_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_pubkey_wire_192(void)  { run_pubkey_wire_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_pubkey_wire_256(void)  { run_pubkey_wire_roundtrip(KAZ_LEVEL_256, "level-256"); }

static void test_privkey_wire_128(void) { run_privkey_wire_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_privkey_wire_192(void) { run_privkey_wire_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_privkey_wire_256(void) { run_privkey_wire_roundtrip(KAZ_LEVEL_256, "level-256"); }

static void test_sig_wire_128(void)     { run_sig_wire_roundtrip(KAZ_LEVEL_128, "level-128"); }
static void test_sig_wire_192(void)     { run_sig_wire_roundtrip(KAZ_LEVEL_192, "level-192"); }
static void test_sig_wire_256(void)     { run_sig_wire_roundtrip(KAZ_LEVEL_256, "level-256"); }

/* ============================================================================
 * Wire Size Verification
 * ============================================================================ */

static void test_wire_sizes(void)
{
    tests_run++;

    /* Level 128: pubkey 5+54=59, privkey 5+32=37, sig 5+162=167 */
    const kaz_sign_level_params_t *p128 = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!p128) { TEST_FAIL("get_level_params 128"); return; }
    if (KAZ_WIRE_HEADER_LEN + p128->public_key_bytes != 59) {
        TEST_FAIL("level-128 pubkey wire size != 59");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p128->secret_key_bytes != 37) {
        TEST_FAIL("level-128 privkey wire size != 37");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p128->signature_overhead != 167) {
        TEST_FAIL("level-128 sig wire size != 167");
        return;
    }

    /* Level 192: pubkey 5+88=93, privkey 5+50=55, sig 5+264=269 */
    const kaz_sign_level_params_t *p192 = kaz_sign_get_level_params(KAZ_LEVEL_192);
    if (!p192) { TEST_FAIL("get_level_params 192"); return; }
    if (KAZ_WIRE_HEADER_LEN + p192->public_key_bytes != 93) {
        TEST_FAIL("level-192 pubkey wire size != 93");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p192->secret_key_bytes != 55) {
        TEST_FAIL("level-192 privkey wire size != 55");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p192->signature_overhead != 269) {
        TEST_FAIL("level-192 sig wire size != 269");
        return;
    }

    /* Level 256: pubkey 5+118=123, privkey 5+64=69, sig 5+354=359 */
    const kaz_sign_level_params_t *p256 = kaz_sign_get_level_params(KAZ_LEVEL_256);
    if (!p256) { TEST_FAIL("get_level_params 256"); return; }
    if (KAZ_WIRE_HEADER_LEN + p256->public_key_bytes != 123) {
        TEST_FAIL("level-256 pubkey wire size != 123");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p256->secret_key_bytes != 69) {
        TEST_FAIL("level-256 privkey wire size != 69");
        return;
    }
    if (KAZ_WIRE_HEADER_LEN + p256->signature_overhead != 359) {
        TEST_FAIL("level-256 sig wire size != 359");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Invalid Input Tests
 * ============================================================================ */

static void test_invalid_magic(void)
{
    tests_run++;

    unsigned char fake_wire[] = { 0xFF, 0xFF, KAZ_WIRE_SIGN_128, KAZ_WIRE_TYPE_PUB, KAZ_WIRE_VERSION };
    kaz_sign_level_t level;
    unsigned char pk[128];
    size_t pk_len;

    /* Pad to expected size */
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    size_t total = KAZ_WIRE_HEADER_LEN + params->public_key_bytes;
    unsigned char *wire = calloc(1, total);
    if (!wire) { TEST_FAIL("malloc failed"); return; }
    memcpy(wire, fake_wire, sizeof(fake_wire));

    int ret = kaz_sign_pubkey_from_wire(wire, total, &level, pk, &pk_len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_INVALID for bad magic, got %d", ret);
        TEST_FAIL(buf);
        free(wire);
        return;
    }

    free(wire);
    TEST_PASS();
}

static void test_wrong_type(void)
{
    tests_run++;

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_128);
    if (!params) { TEST_FAIL("get_level_params failed"); return; }

    /* Build a valid pubkey wire, then try to decode as privkey */
    unsigned char *pk = malloc(params->public_key_bytes);
    unsigned char *sk = malloc(params->secret_key_bytes);
    if (!pk || !sk) { TEST_FAIL("malloc failed"); free(pk); free(sk); return; }

    if (kaz_sign_init_level(KAZ_LEVEL_128) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("init_level failed");
        free(pk); free(sk);
        return;
    }

    if (kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk) != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("keypair failed");
        kaz_secure_zero(sk, params->secret_key_bytes);
        free(pk); free(sk);
        return;
    }

    size_t wire_sz = KAZ_WIRE_HEADER_LEN + params->public_key_bytes;
    unsigned char *wire = malloc(wire_sz);
    if (!wire) { TEST_FAIL("malloc failed"); kaz_secure_zero(sk, params->secret_key_bytes); free(pk); free(sk); return; }

    size_t out_len = wire_sz;
    int ret = kaz_sign_pubkey_to_wire(KAZ_LEVEL_128, pk, params->public_key_bytes, wire, &out_len);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("pubkey_to_wire failed");
        goto cleanup;
    }

    /* Try to decode as privkey -- should fail (wrong type) */
    kaz_sign_level_t level;
    unsigned char sk_out[128];
    size_t sk_len;
    ret = kaz_sign_privkey_from_wire(wire, out_len, &level, sk_out, &sk_len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_INVALID for wrong type, got %d", ret);
        TEST_FAIL(buf);
        goto cleanup;
    }

    TEST_PASS();

cleanup:
    kaz_secure_zero(sk, params->secret_key_bytes);
    free(pk); free(sk); free(wire);
}

static void test_null_pointers(void)
{
    tests_run++;

    size_t out_len = 256;
    unsigned char dummy[256];
    kaz_sign_level_t level;
    size_t len;

    /* NULL pk */
    int ret = kaz_sign_pubkey_to_wire(KAZ_LEVEL_128, NULL, 54, dummy, &out_len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL pk");
        return;
    }

    /* NULL out_len */
    ret = kaz_sign_pubkey_to_wire(KAZ_LEVEL_128, dummy, 54, dummy, NULL);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL out_len");
        return;
    }

    /* NULL wire for from_wire */
    ret = kaz_sign_pubkey_from_wire(NULL, 59, &level, dummy, &len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        TEST_FAIL("expected ERROR_INVALID for NULL wire");
        return;
    }

    TEST_PASS();
}

static void test_truncated_wire(void)
{
    tests_run++;

    /* Wire too short (less than header) */
    unsigned char short_wire[] = { KAZ_WIRE_MAGIC_HI, KAZ_WIRE_MAGIC_LO };
    kaz_sign_level_t level;
    unsigned char pk[128];
    size_t pk_len;

    int ret = kaz_sign_pubkey_from_wire(short_wire, sizeof(short_wire), &level, pk, &pk_len);
    if (ret != KAZ_SIGN_ERROR_INVALID) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_INVALID for truncated wire, got %d", ret);
        TEST_FAIL(buf);
        return;
    }

    TEST_PASS();
}

static void test_buffer_too_small(void)
{
    tests_run++;

    unsigned char pk[54] = {0};
    unsigned char tiny[4];
    size_t tiny_len = sizeof(tiny);

    int ret = kaz_sign_pubkey_to_wire(KAZ_LEVEL_128, pk, 54, tiny, &tiny_len);
    if (ret != KAZ_SIGN_ERROR_BUFFER) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected ERROR_BUFFER, got %d", ret);
        TEST_FAIL(buf);
        return;
    }

    TEST_PASS();
}

static void test_size_query(void)
{
    tests_run++;

    unsigned char pk[54] = {0};
    size_t needed = 0;

    /* Query size with NULL out */
    int ret = kaz_sign_pubkey_to_wire(KAZ_LEVEL_128, pk, 54, NULL, &needed);
    if (ret != KAZ_SIGN_SUCCESS || needed != 59) {
        char buf[128];
        snprintf(buf, sizeof(buf), "size query failed: ret=%d needed=%zu", ret, needed);
        TEST_FAIL(buf);
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
    printf("          KAZ-SIGN KazWire Encoding Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  Public Key Wire Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_pubkey_wire_128();
    test_pubkey_wire_192();
    test_pubkey_wire_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Private Key Wire Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_privkey_wire_128();
    test_privkey_wire_192();
    test_privkey_wire_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Signature Wire Round-Trip Tests\n");
    printf("----------------------------------------------------------\n");
    test_sig_wire_128();
    test_sig_wire_192();
    test_sig_wire_256();

    printf("\n----------------------------------------------------------\n");
    printf("  Wire Size Verification\n");
    printf("----------------------------------------------------------\n");
    test_wire_sizes();

    printf("\n----------------------------------------------------------\n");
    printf("  Invalid Input Rejection Tests\n");
    printf("----------------------------------------------------------\n");
    test_invalid_magic();
    test_wrong_type();
    test_null_pointers();
    test_truncated_wire();
    test_buffer_too_small();
    test_size_query();

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
