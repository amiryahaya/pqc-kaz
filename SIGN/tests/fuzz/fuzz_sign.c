/*
 * KAZ-SIGN Fuzz Test Harness
 *
 * This harness can be used with:
 * 1. libFuzzer (LLVM built-in)
 * 2. AFL++
 * 3. Honggfuzz
 *
 * Build with libFuzzer:
 *   clang -g -fsanitize=fuzzer,address -DKAZ_SECURITY_LEVEL=128 -DKAZ_USE_CONSTTIME=1 \
 *         -I./include -I./src/internal -I$(brew --prefix openssl)/include \
 *         tests/fuzz/fuzz_sign.c src/internal/sign_consttime.c \
 *         src/internal/nist_wrapper.c src/internal/security.c \
 *         -L$(brew --prefix openssl)/lib -lcrypto -lm \
 *         -o build/bin/fuzz_sign
 *
 * Run:
 *   ./build/bin/fuzz_sign corpus/ -max_len=1024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "kaz/sign.h"

/* Global key pair - initialized once */
static unsigned char g_pk[KAZ_SIGN_PUBLICKEYBYTES];
static unsigned char g_sk[KAZ_SIGN_SECRETKEYBYTES];
static int g_initialized = 0;

static void init_once(void) {
    if (g_initialized) return;

    if (kaz_sign_init_random() != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Failed to init random\n");
        exit(1);
    }

    if (kaz_sign_keypair(g_pk, g_sk) != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Failed to generate keypair\n");
        exit(1);
    }

    g_initialized = 1;
}

/*
 * Fuzz target: Test sign and verify with arbitrary message data
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();

    if (size == 0 || size > 65536) {
        return 0;  /* Skip empty or very large inputs */
    }

    /* Allocate buffers */
    unsigned char *sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + size);
    unsigned char *recovered = malloc(size);

    if (!sig || !recovered) {
        free(sig);
        free(recovered);
        return 0;
    }

    unsigned long long siglen, recovered_len;

    /* Sign the fuzzed data */
    int ret = kaz_sign_signature(sig, &siglen, data, size, g_sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        /* Signing failed - could be valid for edge cases */
        goto cleanup;
    }

    /* Verify the signature */
    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, g_pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        /* Verification of our own signature failed - this is a bug! */
        fprintf(stderr, "BUG: Failed to verify own signature!\n");
        abort();
    }

    /* Check message recovery */
    if (recovered_len != size) {
        fprintf(stderr, "BUG: Recovered length mismatch: %llu vs %zu\n",
                recovered_len, size);
        abort();
    }

    if (memcmp(data, recovered, size) != 0) {
        fprintf(stderr, "BUG: Recovered message mismatch!\n");
        abort();
    }

    /* Test verification with wrong key (should fail) */
    unsigned char wrong_pk[KAZ_SIGN_PUBLICKEYBYTES];
    memcpy(wrong_pk, g_pk, KAZ_SIGN_PUBLICKEYBYTES);
    wrong_pk[0] ^= 0xFF;  /* Corrupt first byte */

    ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, wrong_pk);
    if (ret == KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "BUG: Verification succeeded with wrong key!\n");
        abort();
    }

    /* Test verification with corrupted signature (should fail) */
    if (siglen > 0) {
        sig[0] ^= 0xFF;  /* Corrupt first byte of signature */
        ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, g_pk);
        if (ret == KAZ_SIGN_SUCCESS) {
            fprintf(stderr, "BUG: Verification succeeded with corrupted signature!\n");
            abort();
        }
    }

cleanup:
    free(sig);
    free(recovered);
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* Standalone main for manual testing */
int main(int argc, char **argv) {
    FILE *f = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    size_t capacity = 0;
    int use_stdin = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        fprintf(stderr, "       %s /dev/stdin  (read from stdin)\n", argv[0]);
        fprintf(stderr, "       Or build with -fsanitize=fuzzer for fuzzing\n");
        return 1;
    }

    /* Check if reading from stdin */
    if (strcmp(argv[1], "/dev/stdin") == 0 || strcmp(argv[1], "-") == 0) {
        f = stdin;
        use_stdin = 1;
    } else {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }
    }

    if (use_stdin) {
        /* Read from stdin - can't seek, read incrementally */
        capacity = 4096;
        data = malloc(capacity);
        if (!data) {
            return 1;
        }

        int c;
        while ((c = fgetc(f)) != EOF && size < 65536) {
            if (size >= capacity) {
                capacity *= 2;
                uint8_t *new_data = realloc(data, capacity);
                if (!new_data) {
                    free(data);
                    return 1;
                }
                data = new_data;
            }
            data[size++] = (uint8_t)c;
        }
    } else {
        /* Read from file - can seek */
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (file_size <= 0 || file_size > 65536) {
            fprintf(stderr, "Invalid file size: %ld\n", file_size);
            fclose(f);
            return 1;
        }

        size = (size_t)file_size;
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
    }

    if (size == 0) {
        fprintf(stderr, "No input data\n");
        free(data);
        return 1;
    }

    printf("Testing input of size %zu...\n", size);
    int ret = LLVMFuzzerTestOneInput(data, size);
    printf("Test completed with result: %d\n", ret);

    free(data);
    kaz_sign_clear_random();
    return 0;
}
#endif
