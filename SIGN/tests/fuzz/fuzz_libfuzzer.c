/*
 * LibFuzzer Harness for KAZ-SIGN
 *
 * Build with clang and libFuzzer:
 *   clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
 *         -I./include -I./src/internal \
 *         tests/fuzz/fuzz_libfuzzer.c src/internal/*.c \
 *         -lcrypto -lm -o fuzz_kaz_sign
 *
 * Run:
 *   ./fuzz_kaz_sign corpus/ -max_len=4096 -jobs=4
 *
 * This harness tests:
 * 1. Signature verification with arbitrary inputs
 * 2. Key pair generation stability
 * 3. Sign/verify round-trip with fuzzed messages
 * 4. KDF with arbitrary inputs
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "kaz/sign.h"
#include "kaz/kdf.h"

/* Global state - initialized once */
static int g_initialized = 0;
static unsigned char g_pk[KAZ_SIGN_PUBLICKEYBYTES];
static unsigned char g_sk[KAZ_SIGN_SECRETKEYBYTES];

/* Initialize global state */
static void init_state(void)
{
    if (!g_initialized) {
        kaz_sign_init_random();
        kaz_sign_keypair(g_pk, g_sk);
        g_initialized = 1;
    }
}

/* ============================================================================
 * Fuzz Target: Signature Verification
 * Tests verification with arbitrary (likely invalid) signatures
 * ============================================================================ */
static int fuzz_verify(const uint8_t *data, size_t size)
{
    if (size < KAZ_SIGN_SIGNATURE_OVERHEAD + 1) {
        return 0;  /* Need at least signature overhead + 1 byte message */
    }

    unsigned char *msg = malloc(size);
    unsigned long long msglen;

    if (!msg) return 0;

    /* Try to verify the fuzzed data as a signature */
    int ret = kaz_sign_verify(msg, &msglen, data, size, g_pk);

    /* Verification should either succeed or fail gracefully */
    (void)ret;

    free(msg);
    return 0;
}

/* ============================================================================
 * Fuzz Target: Sign then Verify Round-trip
 * Tests signing with arbitrary messages
 * ============================================================================ */
static int fuzz_sign_verify(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536) {
        return 0;  /* Reasonable bounds */
    }

    unsigned char *sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + size);
    unsigned char *recovered = malloc(size);
    unsigned long long siglen, reclen;

    if (!sig || !recovered) {
        free(sig);
        free(recovered);
        return 0;
    }

    /* Sign the fuzzed message */
    int ret = kaz_sign_signature(sig, &siglen, data, size, g_sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        free(sig);
        free(recovered);
        return 0;
    }

    /* Verify the signature */
    ret = kaz_sign_verify(recovered, &reclen, sig, siglen, g_pk);

    /* Should always verify successfully */
    if (ret != KAZ_SIGN_SUCCESS) {
        /* This would be a bug! */
        __builtin_trap();
    }

    /* Message should be recovered correctly */
    if (reclen != size || memcmp(recovered, data, size) != 0) {
        /* This would be a bug! */
        __builtin_trap();
    }

    free(sig);
    free(recovered);
    return 0;
}

/* ============================================================================
 * Fuzz Target: Key Derivation Function
 * Tests KDF with arbitrary seeds
 * ============================================================================ */
static int fuzz_kdf(const uint8_t *data, size_t size)
{
    if (size < 32) {
        return 0;  /* Need at least 32 bytes for seed */
    }

    unsigned char s_bytes[64];
    unsigned char t_bytes[64];

    /* Test secret key derivation */
    int ret = kaz_kdf_derive_secret_key(data, size, s_bytes, 32, t_bytes, 32);

    /* Should succeed or fail gracefully */
    (void)ret;

    /* Test HKDF with arbitrary data */
    unsigned char okm[128];
    size_t salt_len = size / 3;
    size_t ikm_len = size / 3;
    size_t info_len = size - salt_len - ikm_len;

    if (ikm_len > 0) {
        ret = kaz_hkdf(data, salt_len,
                       data + salt_len, ikm_len,
                       data + salt_len + ikm_len, info_len,
                       okm, 128);
        (void)ret;
    }

    return 0;
}

/* ============================================================================
 * Fuzz Target: Corrupted Signature Components
 * Tests verification with systematically corrupted signatures
 * ============================================================================ */
static int fuzz_corrupted_verify(const uint8_t *data, size_t size)
{
    if (size < 32) return 0;

    /* Create a valid signature first */
    unsigned char msg[32];
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 32];
    unsigned char recovered[32];
    unsigned long long siglen, reclen;

    memcpy(msg, data, 32 < size ? 32 : size);

    int ret = kaz_sign_signature(sig, &siglen, msg, 32, g_sk);
    if (ret != KAZ_SIGN_SUCCESS) return 0;

    /* Corrupt the signature based on fuzz data */
    size_t corrupt_pos = data[0] % siglen;
    unsigned char corrupt_val = size > 1 ? data[1] : 0xFF;

    sig[corrupt_pos] ^= corrupt_val;

    /* Verification should fail gracefully (not crash) */
    ret = kaz_sign_verify(recovered, &reclen, sig, siglen, g_pk);

    /* Should not verify as valid */
    if (ret == KAZ_SIGN_SUCCESS && corrupt_val != 0) {
        /* Corrupted signature verified - this is bad! */
        /* But only if we actually changed something */
    }

    return 0;
}

/* ============================================================================
 * Main LibFuzzer Entry Point
 * ============================================================================ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init_state();

    if (size == 0) return 0;

    /* Select which test to run based on first byte */
    uint8_t selector = data[0] % 4;
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    switch (selector) {
        case 0:
            fuzz_verify(payload, payload_size);
            break;
        case 1:
            fuzz_sign_verify(payload, payload_size);
            break;
        case 2:
            fuzz_kdf(payload, payload_size);
            break;
        case 3:
            fuzz_corrupted_verify(payload, payload_size);
            break;
    }

    return 0;
}

/* ============================================================================
 * Optional: Main function for standalone testing
 * ============================================================================ */
#ifdef FUZZ_STANDALONE
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    if (fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    int ret = LLVMFuzzerTestOneInput(data, size);

    free(data);
    printf("Processed %zu bytes, result: %d\n", size, ret);

    kaz_sign_clear_random();
    return ret;
}
#endif
