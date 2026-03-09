/*
 * C-side interop test: KAZ-SIGN v2.0
 *
 * Simulates SSDID registry flow:
 *   1. Generate keypair
 *   2. Sign a DID Document payload using message-recovery mode
 *   3. Extract S1/S2/S3 components, output as hex for Java to verify
 *
 * Also reads Java-generated data from stdin to verify.
 *
 * Usage:
 *   ./c_sign generate <level>     # Generate keys + sign, output hex
 *   ./c_sign verify <level>       # Read hex from stdin, verify
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kaz/sign.h"

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static size_t read_hex(const char *hex, unsigned char *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) byte_len = max_len;

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return 0;
        out[i] = (unsigned char)byte;
    }
    return byte_len;
}

/* Simulated SSDID DID Document payload */
static const char *DID_DOCUMENT_PAYLOAD =
    "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],"
    "\"id\":\"did:ssdid:test-interop-12345\","
    "\"verificationMethod\":[{\"controller\":\"did:ssdid:test-interop-12345\","
    "\"id\":\"did:ssdid:test-interop-12345#key-1\","
    "\"publicKeyMultibase\":\"uPLACEHOLDER\","
    "\"type\":\"KazSignVerificationKey2024\"}]}";

static int do_generate(kaz_sign_level_t level)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) {
        fprintf(stderr, "Invalid level\n");
        return 1;
    }

    unsigned char pk[256], sk[256];
    int ret = kaz_sign_keypair_ex(level, pk, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Keypair generation failed: %d\n", ret);
        return 1;
    }

    /* Sign the DID document payload using message-recovery mode.
     * This is equivalent to Java's KAZSIGNSigner.sign(msg, sk):
     * both hash the raw message internally with SHA-256 zero-padded. */
    const unsigned char *msg = (const unsigned char *)DID_DOCUMENT_PAYLOAD;
    unsigned long long msglen = strlen(DID_DOCUMENT_PAYLOAD);

    size_t sig_buf_size = params->signature_overhead + msglen;
    unsigned char *sig_buf = malloc(sig_buf_size);
    if (!sig_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    unsigned long long siglen = 0;
    ret = kaz_sign_signature_ex(level, sig_buf, &siglen, msg, msglen, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Sign failed: %d\n", ret);
        free(sig_buf);
        return 1;
    }

    /* Self-verify using message-recovery */
    unsigned char *recovered = malloc(msglen + 16);
    unsigned long long recovered_len = 0;
    ret = kaz_sign_verify_ex(level, recovered, &recovered_len, sig_buf, siglen, pk);
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Self-verify failed: %d\n", ret);
        free(sig_buf);
        free(recovered);
        return 1;
    }
    free(recovered);

    /* Output: level, pk, signature components (S1||S2||S3 from sig_buf), message */
    int level_int = (level == KAZ_LEVEL_128) ? 128 : (level == KAZ_LEVEL_192) ? 192 : 256;
    printf("level=%d\n", level_int);
    print_hex("pk", pk, params->v_bytes);
    print_hex("sk_s", sk, params->s_bytes);
    print_hex("sk_t", sk + params->s_bytes, params->t_bytes);
    print_hex("sig_s1", sig_buf, params->s1_bytes);
    print_hex("sig_s2", sig_buf + params->s1_bytes, params->s2_bytes);
    print_hex("sig_s3", sig_buf + params->s1_bytes + params->s2_bytes, params->s3_bytes);
    printf("msg=%s\n", DID_DOCUMENT_PAYLOAD);
    printf("status=ok\n");

    fprintf(stderr, "C: Generated level-%d keypair and signature\n", level_int);
    fprintf(stderr, "C: Self-verification: PASS\n");

    free(sig_buf);
    return 0;
}

static int do_verify(kaz_sign_level_t level)
{
    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(level);
    if (!params) {
        fprintf(stderr, "Invalid level\n");
        return 1;
    }

    /* Read hex lines from stdin */
    unsigned char pk[256] = {0};
    unsigned char sig_s1[256] = {0};
    unsigned char sig_s2[256] = {0};
    unsigned char sig_s3[256] = {0};
    char msg[4096] = {0};
    char line[8192];

    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "pk=", 3) == 0) {
            read_hex(line + 3, pk, params->v_bytes);
        } else if (strncmp(line, "sig_s1=", 7) == 0) {
            read_hex(line + 7, sig_s1, params->s1_bytes);
        } else if (strncmp(line, "sig_s2=", 7) == 0) {
            read_hex(line + 7, sig_s2, params->s2_bytes);
        } else if (strncmp(line, "sig_s3=", 7) == 0) {
            read_hex(line + 7, sig_s3, params->s3_bytes);
        } else if (strncmp(line, "msg=", 4) == 0) {
            strncpy(msg, line + 4, sizeof(msg) - 1);
        }
    }

    unsigned long long msglen = strlen(msg);

    /* Reconstruct full signature: S1||S2||S3||msg (message-recovery format) */
    size_t full_sig_size = params->signature_overhead + msglen;
    unsigned char *full_sig = malloc(full_sig_size);
    if (!full_sig) return 1;

    memcpy(full_sig, sig_s1, params->s1_bytes);
    memcpy(full_sig + params->s1_bytes, sig_s2, params->s2_bytes);
    memcpy(full_sig + params->s1_bytes + params->s2_bytes, sig_s3, params->s3_bytes);
    memcpy(full_sig + params->signature_overhead, msg, msglen);

    unsigned char *recovered = malloc(msglen + 16);
    unsigned long long recovered_len = 0;

    int level_int = (level == KAZ_LEVEL_128) ? 128 : (level == KAZ_LEVEL_192) ? 192 : 256;
    fprintf(stderr, "C: Verifying Java-generated signature (level %d)\n", level_int);

    int ret = kaz_sign_verify_ex(level, recovered, &recovered_len,
                                  full_sig, (unsigned long long)full_sig_size, pk);

    if (ret == KAZ_SIGN_SUCCESS) {
        /* Also check recovered message matches */
        if (recovered_len == msglen &&
            memcmp(recovered, msg, (size_t)msglen) == 0) {
            printf("verify=PASS\n");
            fprintf(stderr, "C: Verification of Java signature: PASS\n");
            free(full_sig);
            free(recovered);
            return 0;
        } else {
            printf("verify=FAIL (message mismatch)\n");
            fprintf(stderr, "C: Message recovery mismatch\n");
        }
    } else {
        printf("verify=FAIL (error %d)\n", ret);
        fprintf(stderr, "C: Verification of Java signature: FAIL (error %d)\n", ret);
    }

    free(full_sig);
    free(recovered);
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <generate|verify> <128|192|256>\n", argv[0]);
        return 1;
    }

    int level_int = atoi(argv[2]);
    kaz_sign_level_t level;
    switch (level_int) {
    case 128: level = KAZ_LEVEL_128; break;
    case 192: level = KAZ_LEVEL_192; break;
    case 256: level = KAZ_LEVEL_256; break;
    default:
        fprintf(stderr, "Invalid level: %d\n", level_int);
        return 1;
    }

    if (strcmp(argv[1], "generate") == 0) {
        return do_generate(level);
    } else if (strcmp(argv[1], "verify") == 0) {
        return do_verify(level);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
}
