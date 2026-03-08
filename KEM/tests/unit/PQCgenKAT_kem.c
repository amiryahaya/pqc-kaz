/*
 * KAZ-KEM Known Answer Test (KAT) Generator
 * Version 2.0.0 - OpenSSL-based implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "kaz/nist_api.h"
#include "kaz/kem.h"

#define MAX_MARKER_LEN      50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int     FindMarker(FILE *infile, const char *marker);
int     ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void    fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

/* Generate random number in range [lowerbound, upperbound) using OpenSSL */
static int generate_random_message(unsigned char *msg, size_t msg_len)
{
    BIGNUM *N = NULL;
    BIGNUM *M = NULL;
    BIGNUM *lowerbound = NULL;
    BIGNUM *range = NULL;
    int ret = -1;

    N = BN_new();
    M = BN_new();
    lowerbound = BN_new();
    range = BN_new();

    if (!N || !M || !lowerbound || !range) {
        goto cleanup;
    }

    /* Set N from the security level parameter */
    if (!BN_dec2bn(&N, KAZ_KEM_SP_N)) {
        goto cleanup;
    }

    /* Set lowerbound = 2^(LN-1) */
    if (!BN_set_bit(lowerbound, KAZ_KEM_SP_LN - 1)) {
        goto cleanup;
    }

    /* range = N - lowerbound */
    if (!BN_sub(range, N, lowerbound)) {
        goto cleanup;
    }

    /* Generate random number in [0, range) */
    if (!BN_rand_range(M, range)) {
        goto cleanup;
    }

    /* M = M + lowerbound, so M is in [lowerbound, N) */
    if (!BN_add(M, M, lowerbound)) {
        goto cleanup;
    }

    /* Export to bytes */
    memset(msg, 0, msg_len);
    int num_bytes = BN_num_bytes(M);
    if ((size_t)num_bytes > msg_len) {
        goto cleanup;
    }
    BN_bn2bin(M, msg + (msg_len - num_bytes));

    ret = 0;

cleanup:
    BN_free(N);
    BN_free(M);
    BN_free(lowerbound);
    BN_free(range);

    return ret;
}

int main(void)
{
    char                   fn_req[32], fn_rsp[32];
    FILE                   *fp_req, *fp_rsp;
    unsigned char          msg[3500];
    unsigned char          *m, *sm, *m1;
    unsigned long long     mlen=0, smlen=0, mlen1=0;
    int                    count;
    int                    done;
    unsigned char          pk[KAZ_KEM_PUBLICKEY_BYTES*2], sk[KAZ_KEM_PRIVATEKEY_BYTES*2];
    int                    ret_val;

    clock_t tkeygen, tkeygentotal=0, tsign, tsigntotal=0, tsignopen, tsignopentotal=0;

    /* Seed OpenSSL PRNG */
    if (RAND_status() != 1) {
        unsigned char seed[48];
        for (int i = 0; i < 48; i++) {
            seed[i] = (unsigned char)i;
        }
        RAND_seed(seed, 48);
    }

    /* Create the REQUEST file */
    sprintf(fn_req, "PQCkemKAT_%d.req", KAZ_KEM_PRIVATEKEY_BYTES*2);
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCkemKAT_%d.rsp", KAZ_KEM_PRIVATEKEY_BYTES*2);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for (int i=0; i<100; i++) {
        fprintf(fp_req, "count = %d\n", i);
        mlen = KAZ_KEM_GENERAL_BYTES;
        fprintf(fp_req, "mlen = %llu\n", mlen);

        /* Generate random message in valid range */
        if (generate_random_message(msg, mlen) != 0) {
            printf("Failed to generate random message\n");
            return KAT_CRYPTO_FAILURE;
        }

        fprintBstr(fp_req, "msg = ", msg, mlen);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "smlen =\n");
        fprintf(fp_req, "sm =\n\n");
    }
    fclose(fp_req);

    /* Create the RESPONSE file based on what's in the REQUEST file */
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;

    do {
        if ( FindMarker(fp_req, "count = ") )
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if ( FindMarker(fp_req, "mlen = ") )
            fscanf(fp_req, "%llu", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %llu\n", mlen);

        m = (unsigned char *)calloc(KAZ_KEM_GENERAL_BYTES, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(KAZ_KEM_GENERAL_BYTES, sizeof(unsigned char));
        sm = (unsigned char *)calloc(KAZ_KEM_GENERAL_BYTES+(KAZ_KEM_EPHERMERAL_PUBLIC_BYTES*2), sizeof(unsigned char));

        if ( !ReadHex(fp_req, m, (int)mlen, "msg = ") ) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);

        tkeygen=clock();
        /* Generate the public/private keypair */
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        tkeygen=clock()-tkeygen;
        tkeygentotal+=tkeygen;
        fprintBstr(fp_rsp, "pk = ", pk, KAZ_KEM_PUBLICKEY_BYTES*2);
        fprintBstr(fp_rsp, "sk = ", sk, KAZ_KEM_PRIVATEKEY_BYTES*2);

        tsign=clock();
        if ( (ret_val = crypto_encap(sm, &smlen, m, mlen, pk)) != 0 ) {
            printf("crypto_encap returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        tsign=clock()-tsign;
        tsigntotal+=tsign;
        fprintf(fp_rsp, "smlen = %llu\n", smlen);
        fprintBstr(fp_rsp, "sm = ", sm, smlen);
        fprintf(fp_rsp, "\n");

        tsignopen=clock();
        if ( (ret_val = crypto_decap(m1, &mlen1, sm, smlen, sk)) != 0 ) {
            printf("crypto_decap returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        tsignopen=clock()-tsignopen;
        tsignopentotal+=tsignopen;

        if ( mlen != mlen1 ) {
            printf("crypto_decap returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }

        if ( memcmp(m, m1, mlen) ) {
            printf("crypto_decap returned bad 'm' value memcmp\n");
            return KAT_CRYPTO_FAILURE;
        }

        free(m);
        free(m1);
        free(sm);

    } while ( !done );

    printf("KeyGen total time (ms): %.0f\n",
        (double)((double)tkeygentotal / CLOCKS_PER_SEC) * 1000);
    printf("Encap total time (ms): %.0f\n",
        (double)((double)tsigntotal / CLOCKS_PER_SEC) * 1000);
    printf("Decap total time (ms): %.0f\n",
        (double)((double)tsignopentotal / CLOCKS_PER_SEC) * 1000);

    fclose(fp_req);
    fclose(fp_rsp);

    printf("KAT files generated successfully:\n");
    printf("  - %s\n", fn_req);
    printf("  - %s\n", fn_rsp);

    return KAT_SUCCESS;
}

/*
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 */
int
FindMarker(FILE *infile, const char *marker)
{
    char    line[MAX_MARKER_LEN];
    int     i, len;
    int curr_line;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
    {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF )
            return 0;
    }
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        curr_line = fgetc(infile);
        line[len-1] = curr_line;
        if (curr_line == EOF )
            return 0;
        line[len] = '\0';
    }

    /* shouldn't get here */
    return 0;
}

/*
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 */
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int         i, ch, started;
    unsigned char   ich;

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;
            else /* shouldn't ever get here */
                ich = 0;

            for ( i=0; i<Length-1; i++ )
                A[i] = (A[i] << 4) | (A[i+1] >> 4);
            A[Length-1] = (A[Length-1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
