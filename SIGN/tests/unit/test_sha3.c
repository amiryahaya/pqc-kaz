/*
 * SHA3-256 Unit Tests for KAZ-SIGN
 * Tests standalone SHA3-256 API against NIST test vectors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kaz/sign.h"

/* Test result counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS() do { tests_passed++; printf("  [PASS] %s\n", __func__); } while(0)
#define TEST_FAIL(msg) do { tests_failed++; printf("  [FAIL] %s: %s\n", __func__, msg); } while(0)

/* Helper to convert hex string to bytes */
static void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02x", &byte);
        out[i] = (unsigned char)byte;
    }
}

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
 * NIST Test Vectors
 * ============================================================================ */

/* SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
static void test_sha3_256_empty(void)
{
    tests_run++;

    unsigned char expected[32];
    unsigned char output[32];

    hex_to_bytes("a7ffc6f8bf1ed76651c14756a061d662"
                 "f580ff4de43b49fa82d80a4b80f8434a",
                 expected, 32);

    int ret = kaz_sha3_256(NULL, 0, output);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("kaz_sha3_256 returned error for empty message");
        return;
    }

    if (memcmp(output, expected, 32) != 0) {
        TEST_FAIL("SHA3-256('') does not match NIST vector");
        print_hex("  Expected", expected, 32);
        print_hex("  Got     ", output, 32);
        return;
    }

    TEST_PASS();
}

/* SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 */
static void test_sha3_256_abc(void)
{
    tests_run++;

    unsigned char expected[32];
    unsigned char output[32];

    hex_to_bytes("3a985da74fe225b2045c172d6bd390bd"
                 "855f086e3e9d525b46bfe24511431532",
                 expected, 32);

    const unsigned char *msg = (const unsigned char *)"abc";
    int ret = kaz_sha3_256(msg, 3, output);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("kaz_sha3_256 returned error for 'abc'");
        return;
    }

    if (memcmp(output, expected, 32) != 0) {
        TEST_FAIL("SHA3-256('abc') does not match NIST vector");
        print_hex("  Expected", expected, 32);
        print_hex("  Got     ", output, 32);
        return;
    }

    TEST_PASS();
}

/* SHA3-256 with 200-byte input */
static void test_sha3_256_longer_input(void)
{
    tests_run++;

    /* 200-byte input of 0xA3 repeated */
    unsigned char msg[200];
    memset(msg, 0xA3, sizeof(msg));

    unsigned char hash[32];
    int ret = kaz_sha3_256(msg, sizeof(msg), hash);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Hash failed");
        return;
    }

    /* Verify output is deterministic */
    unsigned char hash2[32];
    ret = kaz_sha3_256(msg, sizeof(msg), hash2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Second hash failed");
        return;
    }
    if (memcmp(hash, hash2, 32) != 0) {
        TEST_FAIL("Deterministic output mismatch");
        return;
    }

    /* Verify different input gives different hash */
    msg[0] = 0xA4;
    unsigned char hash3[32];
    ret = kaz_sha3_256(msg, sizeof(msg), hash3);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Third hash failed");
        return;
    }
    if (memcmp(hash, hash3, 32) == 0) {
        TEST_FAIL("Different input should give different hash");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Incremental Hashing Tests
 * ============================================================================ */

/* Incremental hashing should match one-shot */
static void test_sha3_256_incremental_matches_oneshot(void)
{
    tests_run++;

    const unsigned char *msg = (const unsigned char *)"Hello, World! This is a test of incremental SHA3-256 hashing.";
    unsigned long long msglen = strlen((const char *)msg);

    unsigned char oneshot[32];
    unsigned char incremental[32];

    /* One-shot hash */
    int ret = kaz_sha3_256(msg, msglen, oneshot);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("One-shot hash failed");
        return;
    }

    /* Incremental hash: split message into three parts */
    kaz_sha3_ctx_t *ctx = kaz_sha3_256_init();
    if (ctx == NULL) {
        TEST_FAIL("kaz_sha3_256_init returned NULL");
        return;
    }

    unsigned long long part1 = 10;
    unsigned long long part2 = 20;
    unsigned long long part3 = msglen - part1 - part2;

    ret = kaz_sha3_256_update(ctx, msg, part1);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("First update failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    ret = kaz_sha3_256_update(ctx, msg + part1, part2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Second update failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    ret = kaz_sha3_256_update(ctx, msg + part1 + part2, part3);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Third update failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    ret = kaz_sha3_256_final(ctx, incremental);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Final failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    kaz_sha3_256_free(ctx);

    if (memcmp(oneshot, incremental, 32) != 0) {
        TEST_FAIL("Incremental hash does not match one-shot");
        print_hex("  One-shot   ", oneshot, 32);
        print_hex("  Incremental", incremental, 32);
        return;
    }

    TEST_PASS();
}

/* Incremental with empty message should match NIST vector */
static void test_sha3_256_incremental_empty(void)
{
    tests_run++;

    unsigned char expected[32];
    unsigned char output[32];

    hex_to_bytes("a7ffc6f8bf1ed76651c14756a061d662"
                 "f580ff4de43b49fa82d80a4b80f8434a",
                 expected, 32);

    kaz_sha3_ctx_t *ctx = kaz_sha3_256_init();
    if (ctx == NULL) {
        TEST_FAIL("kaz_sha3_256_init returned NULL");
        return;
    }

    int ret = kaz_sha3_256_final(ctx, output);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Final on empty context failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    kaz_sha3_256_free(ctx);

    if (memcmp(output, expected, 32) != 0) {
        TEST_FAIL("Incremental empty hash does not match NIST vector");
        return;
    }

    TEST_PASS();
}

/* Multi-chunk incremental hashing */
static void test_sha3_256_incremental_multi_chunk(void)
{
    tests_run++;

    unsigned char msg[] = "Hello, World! This is a test of incremental hashing.";
    size_t total_len = sizeof(msg) - 1;

    /* One-shot hash */
    unsigned char hash_oneshot[32];
    int ret = kaz_sha3_256(msg, total_len, hash_oneshot);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("One-shot hash failed");
        return;
    }

    /* Multi-chunk incremental: split into 3 chunks */
    kaz_sha3_ctx_t *ctx = kaz_sha3_256_init();
    if (ctx == NULL) {
        TEST_FAIL("Init failed");
        return;
    }

    size_t chunk1 = 10;
    size_t chunk2 = 20;
    size_t chunk3 = total_len - chunk1 - chunk2;

    ret = kaz_sha3_256_update(ctx, msg, chunk1);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Update chunk 1 failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    ret = kaz_sha3_256_update(ctx, msg + chunk1, chunk2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Update chunk 2 failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    ret = kaz_sha3_256_update(ctx, msg + chunk1 + chunk2, chunk3);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Update chunk 3 failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    unsigned char hash_inc[32];
    ret = kaz_sha3_256_final(ctx, hash_inc);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Final failed");
        kaz_sha3_256_free(ctx);
        return;
    }

    kaz_sha3_256_free(ctx);

    if (memcmp(hash_oneshot, hash_inc, 32) != 0) {
        TEST_FAIL("Multi-chunk should match one-shot");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Keccak Rate Boundary Tests
 * ============================================================================ */

/* Test at exactly the SHA3-256 rate boundary (136 bytes) */
static void test_sha3_256_rate_boundary_135(void)
{
    tests_run++;

    unsigned char msg[135];
    memset(msg, 0x61, sizeof(msg));

    unsigned char hash1[32], hash2[32];
    int ret = kaz_sha3_256(msg, sizeof(msg), hash1);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Hash failed for 135 bytes");
        return;
    }

    ret = kaz_sha3_256(msg, sizeof(msg), hash2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Second hash failed for 135 bytes");
        return;
    }

    if (memcmp(hash1, hash2, 32) != 0) {
        TEST_FAIL("Deterministic output mismatch at 135 bytes");
        return;
    }

    TEST_PASS();
}

static void test_sha3_256_rate_boundary_136(void)
{
    tests_run++;

    unsigned char msg[136];
    memset(msg, 0x61, sizeof(msg));

    unsigned char hash1[32], hash2[32];
    int ret = kaz_sha3_256(msg, sizeof(msg), hash1);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Hash failed for 136 bytes");
        return;
    }

    ret = kaz_sha3_256(msg, sizeof(msg), hash2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Second hash failed for 136 bytes");
        return;
    }

    if (memcmp(hash1, hash2, 32) != 0) {
        TEST_FAIL("Deterministic output mismatch at 136 bytes");
        return;
    }

    /* Verify 136-byte hash differs from 135-byte hash */
    unsigned char msg135[135];
    memset(msg135, 0x61, sizeof(msg135));
    unsigned char hash135[32];
    kaz_sha3_256(msg135, sizeof(msg135), hash135);
    if (memcmp(hash1, hash135, 32) == 0) {
        TEST_FAIL("136-byte and 135-byte inputs should produce different hashes");
        return;
    }

    TEST_PASS();
}

static void test_sha3_256_rate_boundary_137(void)
{
    tests_run++;

    unsigned char msg[137];
    memset(msg, 0x61, sizeof(msg));

    unsigned char hash1[32], hash2[32];
    int ret = kaz_sha3_256(msg, sizeof(msg), hash1);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Hash failed for 137 bytes");
        return;
    }

    ret = kaz_sha3_256(msg, sizeof(msg), hash2);
    if (ret != KAZ_SIGN_SUCCESS) {
        TEST_FAIL("Second hash failed for 137 bytes");
        return;
    }

    if (memcmp(hash1, hash2, 32) != 0) {
        TEST_FAIL("Deterministic output mismatch at 137 bytes");
        return;
    }

    /* Verify 137-byte hash differs from 136-byte hash */
    unsigned char msg136[136];
    memset(msg136, 0x61, sizeof(msg136));
    unsigned char hash136[32];
    kaz_sha3_256(msg136, sizeof(msg136), hash136);
    if (memcmp(hash1, hash136, 32) == 0) {
        TEST_FAIL("137-byte and 136-byte inputs should produce different hashes");
        return;
    }

    TEST_PASS();
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================ */

/* One-shot with NULL output should return error */
static void test_sha3_256_null_output(void)
{
    tests_run++;

    const unsigned char *msg = (const unsigned char *)"test";
    int ret = kaz_sha3_256(msg, 4, NULL);

    if (ret != KAZ_SIGN_ERROR_HASH) {
        TEST_FAIL("Should return error for NULL output");
        return;
    }

    TEST_PASS();
}

/* Final with NULL output should return error */
static void test_sha3_256_final_null_output(void)
{
    tests_run++;

    kaz_sha3_ctx_t *ctx = kaz_sha3_256_init();
    if (ctx == NULL) {
        TEST_FAIL("kaz_sha3_256_init returned NULL");
        return;
    }

    int ret = kaz_sha3_256_final(ctx, NULL);
    if (ret != KAZ_SIGN_ERROR_HASH) {
        TEST_FAIL("Final with NULL output should return error");
        kaz_sha3_256_free(ctx);
        return;
    }

    kaz_sha3_256_free(ctx);
    TEST_PASS();
}

/* Update with NULL context should return error */
static void test_sha3_256_update_null_ctx(void)
{
    tests_run++;

    const unsigned char *data = (const unsigned char *)"test";
    int ret = kaz_sha3_256_update(NULL, data, 4);

    if (ret != KAZ_SIGN_ERROR_HASH) {
        TEST_FAIL("Update with NULL ctx should return error");
        return;
    }

    TEST_PASS();
}

/* Free with NULL should not crash */
static void test_sha3_256_free_null(void)
{
    tests_run++;

    /* Should not crash */
    kaz_sha3_256_free(NULL);

    TEST_PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("========================================================\n");
    printf("          KAZ-SIGN SHA3-256 Unit Tests\n");
    printf("========================================================\n");
    printf("  Security Level: %d\n\n", KAZ_SIGN_SP_J);

    printf("----------------------------------------------------------\n");
    printf("  NIST Test Vectors\n");
    printf("----------------------------------------------------------\n");
    test_sha3_256_empty();
    test_sha3_256_abc();
    test_sha3_256_longer_input();

    printf("\n----------------------------------------------------------\n");
    printf("  Incremental Hashing Tests\n");
    printf("----------------------------------------------------------\n");
    test_sha3_256_incremental_matches_oneshot();
    test_sha3_256_incremental_empty();
    test_sha3_256_incremental_multi_chunk();

    printf("\n----------------------------------------------------------\n");
    printf("  Keccak Rate Boundary Tests\n");
    printf("----------------------------------------------------------\n");
    test_sha3_256_rate_boundary_135();
    test_sha3_256_rate_boundary_136();
    test_sha3_256_rate_boundary_137();

    printf("\n----------------------------------------------------------\n");
    printf("  Error Handling Tests\n");
    printf("----------------------------------------------------------\n");
    test_sha3_256_null_output();
    test_sha3_256_final_null_output();
    test_sha3_256_update_null_ctx();
    test_sha3_256_free_null();

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

    return tests_failed > 0 ? 1 : 0;
}
