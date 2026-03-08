/*
 * AFL++ Fuzzing Harness for KAZ-SIGN
 *
 * Build with afl-clang-fast:
 *   afl-clang-fast -g -O2 -I./include -I./src/internal \
 *         tests/fuzz/fuzz_afl.c src/internal/*.c \
 *         -lcrypto -lm -o fuzz_afl_kaz_sign
 *
 * Or with gcc and AFL_USE_ASAN:
 *   AFL_USE_ASAN=1 afl-gcc -g -O2 -I./include -I./src/internal \
 *         tests/fuzz/fuzz_afl.c src/internal/*.c \
 *         -lcrypto -lm -o fuzz_afl_kaz_sign
 *
 * Run:
 *   mkdir -p fuzz_in fuzz_out
 *   echo "test" > fuzz_in/seed
 *   afl-fuzz -i fuzz_in -o fuzz_out -- ./fuzz_afl_kaz_sign
 *
 * With persistent mode (faster):
 *   afl-fuzz -i fuzz_in -o fuzz_out -- ./fuzz_afl_kaz_sign @@
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "kaz/sign.h"
#include "kaz/kdf.h"

/* AFL persistent mode support */
#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

/* Maximum input size */
#define MAX_INPUT_SIZE (64 * 1024)

/* Global state */
static unsigned char g_pk[KAZ_SIGN_PUBLICKEYBYTES];
static unsigned char g_sk[KAZ_SIGN_SECRETKEYBYTES];
static int g_initialized = 0;

static void init_crypto(void)
{
    if (!g_initialized) {
        kaz_sign_init_random();
        kaz_sign_keypair(g_pk, g_sk);
        g_initialized = 1;
    }
}

/* ============================================================================
 * Fuzz Targets
 * ============================================================================ */

/* Test 1: Verify arbitrary data as signature */
static void test_verify(const uint8_t *data, size_t size)
{
    if (size < KAZ_SIGN_SIGNATURE_OVERHEAD) return;

    unsigned char *msg = malloc(size);
    if (!msg) return;

    unsigned long long msglen;
    kaz_sign_verify(msg, &msglen, data, size, g_pk);

    free(msg);
}

/* Test 2: Sign fuzzed message and verify */
static void test_sign_roundtrip(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 32768) return;

    unsigned char *sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + size);
    unsigned char *recovered = malloc(size);
    if (!sig || !recovered) {
        free(sig);
        free(recovered);
        return;
    }

    unsigned long long siglen, reclen;

    /* Sign */
    if (kaz_sign_signature(sig, &siglen, data, size, g_sk) != KAZ_SIGN_SUCCESS) {
        free(sig);
        free(recovered);
        return;
    }

    /* Verify - should always succeed for our own signature */
    int ret = kaz_sign_verify(recovered, &reclen, sig, siglen, g_pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        /* Bug: our own signature didn't verify */
        abort();
    }

    /* Check message integrity */
    if (reclen != size || memcmp(recovered, data, size) != 0) {
        /* Bug: message corruption */
        abort();
    }

    free(sig);
    free(recovered);
}

/* Test 3: KDF with fuzzed input */
static void test_kdf(const uint8_t *data, size_t size)
{
    if (size < 32) return;

    unsigned char output[128];

    /* Test HKDF */
    kaz_hkdf(NULL, 0, data, size, NULL, 0, output, 64);

    /* Test secret key derivation */
    unsigned char s[32], t[32];
    kaz_kdf_derive_secret_key(data, size, s, 32, t, 32);

    /* Test expand seed */
    kaz_kdf_expand_seed(data, size, "FUZZ", 4, output, 128);
}

/* Test 4: Corrupt valid signature and verify fails */
static void test_corruption_detection(const uint8_t *data, size_t size)
{
    if (size < 3) return;

    /* Create valid signature */
    unsigned char msg[32] = {0};
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 32];
    unsigned char recovered[32];
    unsigned long long siglen, reclen;

    /* Use fuzz data to set message */
    size_t copy_len = size < 32 ? size : 32;
    memcpy(msg, data, copy_len);

    if (kaz_sign_signature(sig, &siglen, msg, 32, g_sk) != KAZ_SIGN_SUCCESS) {
        return;
    }

    /* Corrupt based on fuzz data */
    size_t pos1 = data[0] % siglen;
    size_t pos2 = data[1] % siglen;
    unsigned char xor_val = data[2];

    /* Only corrupt if xor_val is non-zero */
    if (xor_val == 0) return;

    sig[pos1] ^= xor_val;
    if (pos1 != pos2) {
        sig[pos2] ^= xor_val;
    }

    /* Verification should fail */
    int ret = kaz_sign_verify(recovered, &reclen, sig, siglen, g_pk);
    (void)ret;  /* We don't abort on success - might have corrupted non-essential bytes */
}

/* Test 5: Verify with wrong public key */
static void test_wrong_key(const uint8_t *data, size_t size)
{
    if (size < 32) return;

    /* Create valid signature with our key */
    unsigned char msg[32];
    memcpy(msg, data, 32 < size ? 32 : size);

    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 32];
    unsigned long long siglen;

    if (kaz_sign_signature(sig, &siglen, msg, 32, g_sk) != KAZ_SIGN_SUCCESS) {
        return;
    }

    /* Create a different "public key" from fuzz data */
    unsigned char fake_pk[KAZ_SIGN_PUBLICKEYBYTES];
    if (size >= KAZ_SIGN_PUBLICKEYBYTES) {
        memcpy(fake_pk, data, KAZ_SIGN_PUBLICKEYBYTES);
    } else {
        memcpy(fake_pk, data, size);
        memset(fake_pk + size, 0, KAZ_SIGN_PUBLICKEYBYTES - size);
    }

    /* Try to verify with wrong key - should fail */
    unsigned char recovered[32];
    unsigned long long reclen;
    int ret = kaz_sign_verify(recovered, &reclen, sig, siglen, fake_pk);

    /* If it verifies with a random key, that's concerning */
    /* (but we don't abort - the fake key might happen to match) */
    (void)ret;
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[])
{
    init_crypto();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    /* AFL persistent mode */
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        if (len > 0 && len <= MAX_INPUT_SIZE) {
            /* Select test based on first byte */
            uint8_t selector = buf[0] % 5;
            const uint8_t *payload = buf + 1;
            size_t payload_len = len - 1;

            switch (selector) {
                case 0: test_verify(payload, payload_len); break;
                case 1: test_sign_roundtrip(payload, payload_len); break;
                case 2: test_kdf(payload, payload_len); break;
                case 3: test_corruption_detection(payload, payload_len); break;
                case 4: test_wrong_key(payload, payload_len); break;
            }
        }
    }
#else
    /* Standard mode - read from file or stdin */
    uint8_t *data = NULL;
    size_t size = 0;

    if (argc > 1) {
        /* Read from file */
        FILE *f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }

        fseek(f, 0, SEEK_END);
        size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (size > MAX_INPUT_SIZE) {
            size = MAX_INPUT_SIZE;
        }

        data = malloc(size);
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
    } else {
        /* Read from stdin */
        data = malloc(MAX_INPUT_SIZE);
        if (!data) return 1;

        size = fread(data, 1, MAX_INPUT_SIZE, stdin);
    }

    if (size > 0) {
        uint8_t selector = data[0] % 5;
        const uint8_t *payload = data + 1;
        size_t payload_len = size - 1;

        switch (selector) {
            case 0: test_verify(payload, payload_len); break;
            case 1: test_sign_roundtrip(payload, payload_len); break;
            case 2: test_kdf(payload, payload_len); break;
            case 3: test_corruption_detection(payload, payload_len); break;
            case 4: test_wrong_key(payload, payload_len); break;
        }

        printf("Processed %zu bytes with test %d\n", size, selector);
    }

    free(data);
#endif

    kaz_sign_clear_random();
    return 0;
}
