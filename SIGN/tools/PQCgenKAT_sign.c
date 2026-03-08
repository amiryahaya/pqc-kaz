/*
 * KAZ-SIGN Known Answer Test (KAT) Generator
 *
 * Generates NIST PQC-compliant KAT files for validation and interoperability.
 * Follows the NIST PQC submission requirements and format.
 *
 * Output files:
 *   - PQCsignKAT_<LEVEL>.req  - Request file (inputs only)
 *   - PQCsignKAT_<LEVEL>.rsp  - Response file (inputs + outputs)
 *
 * Usage:
 *   ./PQCgenKAT_sign_<LEVEL>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "kaz/sign.h"
#include "kaz/nist_api.h"

/* NIST DRBG for deterministic test vectors */
#include <openssl/evp.h>
#include <openssl/rand.h>

/* ============================================================================
 * AES-CTR DRBG (NIST SP 800-90A compliant)
 * This provides deterministic random generation for reproducible KAT vectors
 * ============================================================================ */

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

typedef struct {
    unsigned char key[AES_KEY_SIZE];
    unsigned char v[AES_BLOCK_SIZE];
    int reseed_counter;
} AES_CTR_DRBG_STATE;

static AES_CTR_DRBG_STATE drbg_state;

static void aes256_ctr_increment(unsigned char *v)
{
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++v[i] != 0) break;
    }
}

static void aes256_ecb_encrypt(const unsigned char *key, const unsigned char *in,
                                unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &outlen, in, AES_BLOCK_SIZE);
    EVP_CIPHER_CTX_free(ctx);
}

static void aes_ctr_drbg_update(const unsigned char *provided_data,
                                 AES_CTR_DRBG_STATE *state)
{
    unsigned char temp[48];

    for (int i = 0; i < 3; i++) {
        aes256_ctr_increment(state->v);
        aes256_ecb_encrypt(state->key, state->v, &temp[i * AES_BLOCK_SIZE]);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(state->key, temp, AES_KEY_SIZE);
    memcpy(state->v, temp + AES_KEY_SIZE, AES_BLOCK_SIZE);
}

static void aes_ctr_drbg_init(const unsigned char *entropy, const unsigned char *nonce,
                               int nonce_len)
{
    unsigned char seed_material[48];

    memset(drbg_state.key, 0, AES_KEY_SIZE);
    memset(drbg_state.v, 0, AES_BLOCK_SIZE);

    /* Combine entropy and nonce */
    memcpy(seed_material, entropy, 48);
    if (nonce != NULL && nonce_len > 0) {
        /* XOR nonce into seed material */
        for (int i = 0; i < nonce_len && i < 48; i++) {
            seed_material[i] ^= nonce[i];
        }
    }

    aes_ctr_drbg_update(seed_material, &drbg_state);
    drbg_state.reseed_counter = 1;
}

static int aes_ctr_drbg_generate(unsigned char *output, size_t output_len)
{
    unsigned char block[AES_BLOCK_SIZE];
    size_t i = 0;

    while (output_len > 0) {
        aes256_ctr_increment(drbg_state.v);
        aes256_ecb_encrypt(drbg_state.key, drbg_state.v, block);

        size_t copy_len = (output_len < AES_BLOCK_SIZE) ? output_len : AES_BLOCK_SIZE;
        memcpy(output + i, block, copy_len);

        i += copy_len;
        output_len -= copy_len;
    }

    aes_ctr_drbg_update(NULL, &drbg_state);
    drbg_state.reseed_counter++;

    return 0;
}

/* Override the RNG function used by KAZ-SIGN with deterministic DRBG */
static unsigned char seed_bytes[48];
static int deterministic_mode = 0;

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength)
{
    (void)security_strength;
    aes_ctr_drbg_init(entropy_input, personalization_string,
                      personalization_string ? 48 : 0);
    deterministic_mode = 1;
}

int randombytes(unsigned char *x, unsigned long long xlen)
{
    if (deterministic_mode) {
        return aes_ctr_drbg_generate(x, (size_t)xlen);
    } else {
        return RAND_bytes(x, (int)xlen) == 1 ? 0 : -1;
    }
}

/* ============================================================================
 * Hex Conversion Utilities
 * ============================================================================ */

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    static const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        hex[2*i] = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex[2*i + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[2*len] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }

    return (int)(hex_len / 2);
}

/* ============================================================================
 * KAT File Generation
 * ============================================================================ */

#define KAT_COUNT 100
#define KAT_MSG_LENGTHS { 0, 1, 2, 4, 8, 16, 32, 33, 64, 100, 128, 256, 512, 1024 }

/* Standard message lengths for KAT (NIST style) */
static const size_t kat_msg_lens[] = KAT_MSG_LENGTHS;
#define NUM_MSG_LENS (sizeof(kat_msg_lens) / sizeof(kat_msg_lens[0]))

static void generate_kat_files(void)
{
    char req_filename[64];
    char rsp_filename[64];
    FILE *fp_req, *fp_rsp;

    unsigned char entropy[48];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned long long siglen;
    int ret;

    /* Generate filenames */
    snprintf(req_filename, sizeof(req_filename), "PQCsignKAT_%d.req", KAZ_SECURITY_LEVEL);
    snprintf(rsp_filename, sizeof(rsp_filename), "PQCsignKAT_%d.rsp", KAZ_SECURITY_LEVEL);

    printf("Generating KAT files for %s...\n", CRYPTO_ALGNAME);
    printf("  Security Level: %d\n", KAZ_SECURITY_LEVEL);
    printf("  Public Key:     %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("  Secret Key:     %d bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("  Signature:      %d bytes (overhead)\n", KAZ_SIGN_SIGNATURE_OVERHEAD);
    printf("\n");

    /* Open output files */
    fp_req = fopen(req_filename, "w");
    fp_rsp = fopen(rsp_filename, "w");

    if (!fp_req || !fp_rsp) {
        fprintf(stderr, "Error: Cannot create output files\n");
        if (fp_req) fclose(fp_req);
        if (fp_rsp) fclose(fp_rsp);
        return;
    }

    /* Write headers */
    fprintf(fp_req, "# %s\n\n", CRYPTO_ALGNAME);
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);

    /* Allocate buffers */
    size_t max_msg_len = 1024;
    msg = malloc(max_msg_len);
    sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + max_msg_len);

    if (!msg || !sig) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp_req);
        fclose(fp_rsp);
        free(msg);
        free(sig);
        return;
    }

    /* Generate test vectors */
    int count = 0;
    for (size_t msg_idx = 0; msg_idx < NUM_MSG_LENS && count < KAT_COUNT; msg_idx++) {
        size_t mlen = kat_msg_lens[msg_idx];

        /* Generate deterministic entropy for this test case */
        for (int i = 0; i < 48; i++) {
            entropy[i] = (unsigned char)(count + i);
        }

        /* Initialize DRBG with this entropy */
        randombytes_init(entropy, NULL, 256);

        /* Generate message */
        if (mlen > 0) {
            aes_ctr_drbg_generate(msg, mlen);
        }

        /* Generate key pair */
        ret = crypto_sign_keypair(pk, sk);
        if (ret != 0) {
            fprintf(stderr, "Error: Key generation failed at count %d\n", count);
            continue;
        }

        /* Sign message */
        ret = crypto_sign(sig, &siglen, msg, mlen, sk);
        if (ret != 0) {
            fprintf(stderr, "Error: Signing failed at count %d\n", count);
            continue;
        }

        /* Hex conversion buffers */
        char *seed_hex = malloc(48 * 2 + 1);
        char *msg_hex = malloc(mlen * 2 + 1);
        char *pk_hex = malloc(CRYPTO_PUBLICKEYBYTES * 2 + 1);
        char *sk_hex = malloc(CRYPTO_SECRETKEYBYTES * 2 + 1);
        char *sig_hex = malloc(siglen * 2 + 1);

        if (!seed_hex || !msg_hex || !pk_hex || !sk_hex || !sig_hex) {
            free(seed_hex); free(msg_hex); free(pk_hex); free(sk_hex); free(sig_hex);
            continue;
        }

        bytes_to_hex(entropy, 48, seed_hex);
        if (mlen > 0) {
            bytes_to_hex(msg, mlen, msg_hex);
        } else {
            msg_hex[0] = '\0';
        }
        bytes_to_hex(pk, CRYPTO_PUBLICKEYBYTES, pk_hex);
        bytes_to_hex(sk, CRYPTO_SECRETKEYBYTES, sk_hex);
        bytes_to_hex(sig, siglen, sig_hex);

        /* Write request file */
        fprintf(fp_req, "count = %d\n", count);
        fprintf(fp_req, "seed = %s\n", seed_hex);
        fprintf(fp_req, "mlen = %zu\n", mlen);
        fprintf(fp_req, "msg = %s\n", msg_hex);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "smlen =\n");
        fprintf(fp_req, "sm =\n");
        fprintf(fp_req, "\n");

        /* Write response file */
        fprintf(fp_rsp, "count = %d\n", count);
        fprintf(fp_rsp, "seed = %s\n", seed_hex);
        fprintf(fp_rsp, "mlen = %zu\n", mlen);
        fprintf(fp_rsp, "msg = %s\n", msg_hex);
        fprintf(fp_rsp, "pk = %s\n", pk_hex);
        fprintf(fp_rsp, "sk = %s\n", sk_hex);
        fprintf(fp_rsp, "smlen = %llu\n", siglen);
        fprintf(fp_rsp, "sm = %s\n", sig_hex);
        fprintf(fp_rsp, "\n");

        free(seed_hex);
        free(msg_hex);
        free(pk_hex);
        free(sk_hex);
        free(sig_hex);

        count++;

        /* Progress indicator */
        if (count % 10 == 0) {
            printf("  Generated %d/%d test vectors...\r", count, KAT_COUNT);
            fflush(stdout);
        }
    }

    printf("  Generated %d test vectors.          \n\n", count);

    /* Cleanup */
    free(msg);
    free(sig);
    fclose(fp_req);
    fclose(fp_rsp);

    printf("Output files:\n");
    printf("  %s (request file)\n", req_filename);
    printf("  %s (response file)\n", rsp_filename);
    printf("\nKAT generation complete.\n");
}

/* ============================================================================
 * KAT Verification
 * ============================================================================ */

static int verify_kat_file(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s\n", filename);
        return -1;
    }

    printf("Verifying KAT file: %s\n", filename);

    char line[65536];
    int count = -1;
    int passed = 0, failed = 0;

    unsigned char seed[48];
    size_t mlen = 0;
    unsigned char *msg = malloc(1024);
    unsigned char expected_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char expected_sk[CRYPTO_SECRETKEYBYTES];
    unsigned long long expected_smlen = 0;
    unsigned char *expected_sm = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + 1024);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char *sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + 1024);
    unsigned long long siglen;

    int have_seed = 0, have_mlen = 0, have_msg = 0;
    int have_pk = 0, have_sk = 0, have_smlen = 0, have_sm = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Parse key = value */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        /* Trim whitespace */
        while (*key && isspace(*key)) key++;
        while (*value && isspace(*value)) value++;
        char *end = key + strlen(key) - 1;
        while (end > key && isspace(*end)) *end-- = '\0';
        end = value + strlen(value) - 1;
        while (end > value && isspace(*end)) *end-- = '\0';

        if (strcmp(key, "count") == 0) {
            /* Process previous test case if complete */
            if (count >= 0 && have_seed && have_mlen && have_msg &&
                have_pk && have_sk && have_smlen && have_sm) {

                /* Reinitialize DRBG with seed */
                randombytes_init(seed, NULL, 256);

                /* Regenerate key pair */
                crypto_sign_keypair(pk, sk);

                /* Check key pair */
                int pk_match = (memcmp(pk, expected_pk, CRYPTO_PUBLICKEYBYTES) == 0);
                int sk_match = (memcmp(sk, expected_sk, CRYPTO_SECRETKEYBYTES) == 0);

                /* Regenerate signature */
                crypto_sign(sig, &siglen, msg, mlen, sk);

                int sig_match = (siglen == expected_smlen &&
                                 memcmp(sig, expected_sm, siglen) == 0);

                if (pk_match && sk_match && sig_match) {
                    passed++;
                } else {
                    printf("  FAIL: count = %d (pk=%d, sk=%d, sig=%d)\n",
                           count, pk_match, sk_match, sig_match);
                    failed++;
                }
            }

            /* Start new test case */
            count = atoi(value);
            have_seed = have_mlen = have_msg = 0;
            have_pk = have_sk = have_smlen = have_sm = 0;

        } else if (strcmp(key, "seed") == 0) {
            hex_to_bytes(value, seed, 48);
            have_seed = 1;

        } else if (strcmp(key, "mlen") == 0) {
            mlen = (size_t)atol(value);
            have_mlen = 1;

        } else if (strcmp(key, "msg") == 0) {
            if (mlen > 0) {
                hex_to_bytes(value, msg, mlen);
            }
            have_msg = 1;

        } else if (strcmp(key, "pk") == 0) {
            if (strlen(value) > 0) {
                hex_to_bytes(value, expected_pk, CRYPTO_PUBLICKEYBYTES);
                have_pk = 1;
            }

        } else if (strcmp(key, "sk") == 0) {
            if (strlen(value) > 0) {
                hex_to_bytes(value, expected_sk, CRYPTO_SECRETKEYBYTES);
                have_sk = 1;
            }

        } else if (strcmp(key, "smlen") == 0) {
            if (strlen(value) > 0) {
                expected_smlen = (unsigned long long)atoll(value);
                have_smlen = 1;
            }

        } else if (strcmp(key, "sm") == 0) {
            if (strlen(value) > 0) {
                hex_to_bytes(value, expected_sm, expected_smlen);
                have_sm = 1;
            }
        }
    }

    /* Process last test case */
    if (count >= 0 && have_seed && have_mlen && have_msg &&
        have_pk && have_sk && have_smlen && have_sm) {

        randombytes_init(seed, NULL, 256);
        crypto_sign_keypair(pk, sk);

        int pk_match = (memcmp(pk, expected_pk, CRYPTO_PUBLICKEYBYTES) == 0);
        int sk_match = (memcmp(sk, expected_sk, CRYPTO_SECRETKEYBYTES) == 0);

        crypto_sign(sig, &siglen, msg, mlen, sk);
        int sig_match = (siglen == expected_smlen &&
                         memcmp(sig, expected_sm, siglen) == 0);

        if (pk_match && sk_match && sig_match) {
            passed++;
        } else {
            printf("  FAIL: count = %d (pk=%d, sk=%d, sig=%d)\n",
                   count, pk_match, sk_match, sig_match);
            failed++;
        }
    }

    free(msg);
    free(expected_sm);
    free(sig);
    fclose(fp);

    printf("Results: %d passed, %d failed\n", passed, failed);
    return (failed == 0) ? 0 : -1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

static void print_usage(const char *prog)
{
    printf("Usage: %s [command]\n\n", prog);
    printf("Commands:\n");
    printf("  generate       Generate KAT files (default)\n");
    printf("  verify <file>  Verify a KAT response file\n");
    printf("  help           Show this help message\n");
    printf("\n");
    printf("Output:\n");
    printf("  PQCsignKAT_%d.req  - Request file (inputs only)\n", KAZ_SECURITY_LEVEL);
    printf("  PQCsignKAT_%d.rsp  - Response file (inputs + outputs)\n", KAZ_SECURITY_LEVEL);
}

int main(int argc, char *argv[])
{
    printf("========================================\n");
    printf("KAZ-SIGN Known Answer Test Generator\n");
    printf("Algorithm: %s\n", CRYPTO_ALGNAME);
    printf("Security Level: %d\n", KAZ_SECURITY_LEVEL);
    printf("========================================\n\n");

    /* Initialize non-deterministic random state for initial operations */
    int ret = kaz_sign_init_random();
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize random state\n");
        return 1;
    }

    if (argc < 2 || strcmp(argv[1], "generate") == 0) {
        generate_kat_files();
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Please specify a KAT file to verify\n");
            print_usage(argv[0]);
            return 1;
        }
        ret = verify_kat_file(argv[2]);
    } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        ret = 1;
    }

    kaz_sign_clear_random();
    return ret;
}
