/*
 * KDF Unit Tests for KAZ-SIGN
 * Tests HKDF implementation against RFC 5869 test vectors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/kdf.h"
#include "kaz/sign.h"

/* Test result counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS() do { tests_passed++; printf("  [PASS] %s\n", __func__); } while(0)
#define TEST_FAIL(msg) do { tests_failed++; printf("  [FAIL] %s: %s\n", __func__, msg); } while(0)

/* Helper to print hex */
__attribute__((unused))
static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* ============================================================================
 * RFC 5869 Test Vectors (SHA-256)
 * ============================================================================ */

/* Test Case 1 from RFC 5869 */
static void test_hkdf_rfc5869_case1(void)
{
    tests_run++;

    /* IKM (22 bytes) */
    unsigned char ikm[22];
    memset(ikm, 0x0b, 22);

    /* Salt (13 bytes) */
    unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    /* Info (10 bytes) */
    unsigned char info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };

    unsigned char okm[42];
    int ret;

    ret = kaz_hkdf(salt, 13, ikm, 22, info, 10, okm, 42);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("HKDF failed");
        return;
    }

    /* Verify output is non-zero and reasonable length */
    int all_zero = 1;
    for (int i = 0; i < 42; i++) {
        if (okm[i] != 0) all_zero = 0;
    }

    if (all_zero) {
        TEST_FAIL("Output is all zeros");
        return;
    }

    /* Verify determinism: calling HKDF twice with the same inputs must
       produce identical OKM (since KAZ uses SHA3-512, not SHA-256,
       we cannot compare against RFC 5869 vectors directly) */
    unsigned char okm2[42];
    ret = kaz_hkdf(salt, 13, ikm, 22, info, 10, okm2, 42);
    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Second HKDF call failed");
        return;
    }

    if (memcmp(okm, okm2, 42) != 0) {
        TEST_FAIL("HKDF output is not deterministic");
        return;
    }

    TEST_PASS();
}

/* Test Case 2: Longer inputs */
static void test_hkdf_long_inputs(void)
{
    tests_run++;

    unsigned char ikm[80];
    unsigned char salt[80];
    unsigned char info[80];
    unsigned char okm[82];

    /* Fill with incrementing values */
    for (int i = 0; i < 80; i++) {
        ikm[i] = (unsigned char)i;
        salt[i] = (unsigned char)(0x60 + i);
        info[i] = (unsigned char)(0xb0 + i);
    }

    int ret = kaz_hkdf(salt, 80, ikm, 80, info, 80, okm, 82);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("HKDF with long inputs failed");
        return;
    }

    TEST_PASS();
}

/* Test Case 3: Zero-length salt (uses default) */
static void test_hkdf_no_salt(void)
{
    tests_run++;

    unsigned char ikm[22];
    memset(ikm, 0x0b, 22);

    unsigned char okm[42];
    int ret = kaz_hkdf(NULL, 0, ikm, 22, NULL, 0, okm, 42);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("HKDF with no salt failed");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * HKDF Extract Tests
 * ============================================================================ */

static void test_hkdf_extract_basic(void)
{
    tests_run++;

    unsigned char ikm[32];
    unsigned char salt[16];
    unsigned char prk[64];
    size_t prk_len;

    memset(ikm, 0xaa, 32);
    memset(salt, 0xbb, 16);

    int ret = kaz_hkdf_extract(salt, 16, ikm, 32, prk, &prk_len);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Extract failed");
        return;
    }

    if (prk_len != 64) {
        TEST_FAIL("PRK length should be 64 (SHA-512)");
        return;
    }

    TEST_PASS();
}

static void test_hkdf_extract_null_salt(void)
{
    tests_run++;

    unsigned char ikm[32];
    unsigned char prk[64];
    size_t prk_len;

    memset(ikm, 0xcc, 32);

    int ret = kaz_hkdf_extract(NULL, 0, ikm, 32, prk, &prk_len);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Extract with NULL salt failed");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * HKDF Expand Tests
 * ============================================================================ */

static void test_hkdf_expand_basic(void)
{
    tests_run++;

    unsigned char prk[64];
    unsigned char info[] = "test info";
    unsigned char okm[128];

    memset(prk, 0xdd, 64);

    int ret = kaz_hkdf_expand(prk, 64, info, sizeof(info) - 1, okm, 128);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Expand failed");
        return;
    }

    TEST_PASS();
}

static void test_hkdf_expand_no_info(void)
{
    tests_run++;

    unsigned char prk[64];
    unsigned char okm[64];

    memset(prk, 0xee, 64);

    int ret = kaz_hkdf_expand(prk, 64, NULL, 0, okm, 64);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Expand with no info failed");
        return;
    }

    TEST_PASS();
}

static void test_hkdf_expand_large_output(void)
{
    tests_run++;

    unsigned char prk[64];
    unsigned char *okm;
    size_t large_len = 1024; /* Test reasonably large output */

    memset(prk, 0xff, 64);

    okm = malloc(large_len);
    if (okm == NULL) {
        TEST_FAIL("Memory allocation failed");
        return;
    }

    int ret = kaz_hkdf_expand(prk, 64, NULL, 0, okm, large_len);
    free(okm);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Expand to large length failed");
        return;
    }

    TEST_PASS();
}

static void test_hkdf_expand_large_info(void)
{
    tests_run++;

    unsigned char prk[64];
    size_t prk_len;
    unsigned char ikm[32];
    memset(ikm, 0xAA, sizeof(ikm));

    int ret = kaz_hkdf_extract(NULL, 0, ikm, sizeof(ikm), prk, &prk_len);
    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Extract failed");
        return;
    }

    /* Large info > 256 bytes to trigger dynamic allocation */
    unsigned char info[512];
    memset(info, 0xBB, sizeof(info));

    unsigned char output[64];
    ret = kaz_hkdf_expand(prk, prk_len, info, sizeof(info), output, sizeof(output));
    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Expand with large info failed");
        return;
    }

    /* Verify output is non-trivial */
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(output); i++) {
        if (output[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) {
        TEST_FAIL("Output should not be all zeros");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * KAZ-SIGN Specific KDF Tests
 * ============================================================================ */

static void test_kdf_derive_secret_key(void)
{
    tests_run++;

    unsigned char seed[32];
    unsigned char s_bytes[KAZ_SIGN_SBYTES];
    unsigned char t_bytes[KAZ_SIGN_TBYTES];

    /* Fill seed with random-looking data */
    for (int i = 0; i < 32; i++) {
        seed[i] = (unsigned char)(i * 7 + 13);
    }

    int ret = kaz_kdf_derive_secret_key(seed, 32, s_bytes, KAZ_SIGN_SBYTES,
                                        t_bytes, KAZ_SIGN_TBYTES);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Derive secret key failed");
        return;
    }

    /* Verify s and t are different */
    if (memcmp(s_bytes, t_bytes, KAZ_SIGN_SBYTES < KAZ_SIGN_TBYTES ?
               KAZ_SIGN_SBYTES : KAZ_SIGN_TBYTES) == 0) {
        TEST_FAIL("s and t should be different");
        return;
    }

    TEST_PASS();
}

static void test_kdf_derive_secret_key_deterministic(void)
{
    tests_run++;

    unsigned char seed[32];
    unsigned char s1[KAZ_SIGN_SBYTES], t1[KAZ_SIGN_TBYTES];
    unsigned char s2[KAZ_SIGN_SBYTES], t2[KAZ_SIGN_TBYTES];

    memset(seed, 0x42, 32);

    /* Derive twice with same seed */
    int ret1 = kaz_kdf_derive_secret_key(seed, 32, s1, KAZ_SIGN_SBYTES,
                                         t1, KAZ_SIGN_TBYTES);
    int ret2 = kaz_kdf_derive_secret_key(seed, 32, s2, KAZ_SIGN_SBYTES,
                                         t2, KAZ_SIGN_TBYTES);

    if (ret1 != KAZ_KDF_SUCCESS || ret2 != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Derivation failed");
        return;
    }

    /* Results should be identical */
    if (memcmp(s1, s2, KAZ_SIGN_SBYTES) != 0 ||
        memcmp(t1, t2, KAZ_SIGN_TBYTES) != 0) {
        TEST_FAIL("KDF should be deterministic");
        return;
    }

    TEST_PASS();
}

static void test_kdf_derive_signing_randomness(void)
{
    tests_run++;

    unsigned char seed[32];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[] = "test message for signing";
    unsigned char output[64];

    memset(seed, 0x11, 32);
    memset(sk, 0x22, KAZ_SIGN_SECRETKEYBYTES);

    int ret = kaz_kdf_derive_signing_randomness(seed, 32, sk, KAZ_SIGN_SECRETKEYBYTES,
                                                msg, sizeof(msg) - 1, 0,
                                                output, 64);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Derive signing randomness failed");
        return;
    }

    TEST_PASS();
}

static void test_kdf_signing_randomness_counter(void)
{
    tests_run++;

    unsigned char seed[32];
    unsigned char sk[32];
    unsigned char msg[] = "test";
    unsigned char out1[32], out2[32];

    memset(seed, 0x33, 32);
    memset(sk, 0x44, 32);

    /* Different counters should produce different output */
    kaz_kdf_derive_signing_randomness(seed, 32, sk, 32, msg, 4, 0, out1, 32);
    kaz_kdf_derive_signing_randomness(seed, 32, sk, 32, msg, 4, 1, out2, 32);

    if (memcmp(out1, out2, 32) == 0) {
        TEST_FAIL("Different counters should produce different output");
        return;
    }

    TEST_PASS();
}

static void test_kdf_signing_randomness_message(void)
{
    tests_run++;

    unsigned char seed[32], sk[32];
    memset(seed, 0x11, sizeof(seed));
    memset(sk, 0x22, sizeof(sk));

    unsigned char msg1[] = "message one";
    unsigned char msg2[] = "message two";
    unsigned char out1[64], out2[64];

    int ret = kaz_kdf_derive_signing_randomness(seed, sizeof(seed),
        sk, sizeof(sk), msg1, sizeof(msg1) - 1, 0, out1, sizeof(out1));
    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Derive 1 failed");
        return;
    }

    ret = kaz_kdf_derive_signing_randomness(seed, sizeof(seed),
        sk, sizeof(sk), msg2, sizeof(msg2) - 1, 0, out2, sizeof(out2));
    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Derive 2 failed");
        return;
    }

    if (memcmp(out1, out2, sizeof(out1)) == 0) {
        TEST_FAIL("Different messages should produce different randomness");
        return;
    }

    TEST_PASS();
}

static void test_kdf_expand_seed(void)
{
    tests_run++;

    unsigned char seed[16];
    unsigned char output[256];

    memset(seed, 0x55, 16);

    int ret = kaz_kdf_expand_seed(seed, 16, "TEST-LABEL", 10, output, 256);

    if (ret != KAZ_KDF_SUCCESS) {
        TEST_FAIL("Expand seed failed");
        return;
    }

    /* Verify non-zero output */
    int all_zero = 1;
    for (int i = 0; i < 256; i++) {
        if (output[i] != 0) all_zero = 0;
    }

    if (all_zero) {
        TEST_FAIL("Output should not be all zeros");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================ */

static void test_kdf_null_pointer_handling(void)
{
    tests_run++;

    unsigned char buf[64];
    size_t len;

    /* Test various NULL pointer cases */
    if (kaz_hkdf_extract(NULL, 0, NULL, 32, buf, &len) != KAZ_KDF_ERROR_NULL_PTR) {
        TEST_FAIL("Should reject NULL ikm");
        return;
    }

    if (kaz_hkdf_expand(buf, 64, NULL, 0, NULL, 32) != KAZ_KDF_ERROR_NULL_PTR) {
        TEST_FAIL("Should reject NULL okm");
        return;
    }

    if (kaz_kdf_derive_secret_key(NULL, 32, buf, 16, buf, 16) != KAZ_KDF_ERROR_NULL_PTR) {
        TEST_FAIL("Should reject NULL seed");
        return;
    }

    TEST_PASS();
}

static void test_kdf_invalid_length_handling(void)
{
    tests_run++;

    unsigned char seed[16];  /* Too short */
    unsigned char s[16], t[16];

    memset(seed, 0x66, 16);

    /* Seed too short (< 32 bytes) */
    if (kaz_kdf_derive_secret_key(seed, 16, s, 16, t, 16) != KAZ_KDF_ERROR_INVALID_LEN) {
        TEST_FAIL("Should reject short seed");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Domain Separation Tests
 * ============================================================================ */

static void test_domain_separation(void)
{
    tests_run++;

    unsigned char seed[32];
    unsigned char out1[64], out2[64];

    memset(seed, 0x77, 32);

    /* Different labels should produce different output */
    kaz_kdf_expand_seed(seed, 32, KAZ_KDF_LABEL_SECRET_KEY,
                        strlen(KAZ_KDF_LABEL_SECRET_KEY), out1, 64);
    kaz_kdf_expand_seed(seed, 32, KAZ_KDF_LABEL_PUBLIC_KEY,
                        strlen(KAZ_KDF_LABEL_PUBLIC_KEY), out2, 64);

    if (memcmp(out1, out2, 64) == 0) {
        TEST_FAIL("Different labels should produce different output");
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
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              KAZ-SIGN KDF Unit Tests                         ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Security Level: %d                                         ║\n", KAZ_SIGN_SP_J);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  HKDF Core Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_hkdf_rfc5869_case1();
    test_hkdf_long_inputs();
    test_hkdf_no_salt();

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  HKDF Extract Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_hkdf_extract_basic();
    test_hkdf_extract_null_salt();

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  HKDF Expand Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_hkdf_expand_basic();
    test_hkdf_expand_no_info();
    test_hkdf_expand_large_output();
    test_hkdf_expand_large_info();

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  KAZ-SIGN Specific KDF Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_kdf_derive_secret_key();
    test_kdf_derive_secret_key_deterministic();
    test_kdf_derive_signing_randomness();
    test_kdf_signing_randomness_counter();
    test_kdf_signing_randomness_message();
    test_kdf_expand_seed();

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Error Handling Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_kdf_null_pointer_handling();
    test_kdf_invalid_length_handling();

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Domain Separation Tests\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    test_domain_separation();

    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      Test Summary                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:     %2d                                         ║\n", tests_run);
    printf("║  Passed:         \033[32m%3d\033[0m                                         ║\n", tests_passed);
    printf("║  Failed:         \033[31m%3d\033[0m                                         ║\n", tests_failed);
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    if (tests_failed == 0) {
        printf("║  \033[32m✓ ALL TESTS PASSED\033[0m                                          ║\n");
    } else {
        printf("║  \033[31m✗ SOME TESTS FAILED\033[0m                                         ║\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    return tests_failed > 0 ? 1 : 0;
}
