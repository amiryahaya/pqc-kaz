/*
 * Dudect-style Timing Leakage Detection for KAZ-SIGN
 *
 * Based on the dudect methodology:
 * "Dude, is my code constant time?" (Reparaz et al., 2017)
 *
 * Uses statistical methods to detect timing side-channels:
 * - Welch's t-test for comparing distributions
 * - Percentile analysis for outlier detection
 * - Cropping to remove measurement noise
 *
 * A timing leak is detected if |t| > threshold (typically 4.5)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include "kaz/sign.h"
#include "kaz/kdf.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define DUDECT_NUMBER_MEASUREMENTS  10000   /* Measurements per class */
#define DUDECT_WARMUP_ITERATIONS    1000    /* Warmup before timing */
#define DUDECT_THRESHOLD            4.5     /* t-test threshold */
#define DUDECT_PERCENTILE_LOW       1       /* Lower percentile to crop */
#define DUDECT_PERCENTILE_HIGH      99      /* Upper percentile to crop */

/* Number of test classes */
#define NUM_CLASSES 2

/* ============================================================================
 * Timing Infrastructure
 * ============================================================================ */

#if defined(__APPLE__)
#include <mach/mach_time.h>

static uint64_t get_cycles(void)
{
    return mach_absolute_time();
}

#elif defined(__x86_64__) || defined(__i386__)
static uint64_t get_cycles(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

#elif defined(__aarch64__)
static uint64_t get_cycles(void)
{
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

#else
#include <time.h>
static uint64_t get_cycles(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

/* ============================================================================
 * Statistical Functions
 * ============================================================================ */

typedef struct {
    double mean;
    double variance;
    double m2;      /* For online variance calculation */
    size_t n;
} online_stats_t;

static void stats_init(online_stats_t *stats)
{
    stats->mean = 0.0;
    stats->variance = 0.0;
    stats->m2 = 0.0;
    stats->n = 0;
}

/* Welford's online algorithm for mean and variance */
static void stats_update(online_stats_t *stats, double x)
{
    stats->n++;
    double delta = x - stats->mean;
    stats->mean += delta / stats->n;
    double delta2 = x - stats->mean;
    stats->m2 += delta * delta2;

    if (stats->n > 1) {
        stats->variance = stats->m2 / (stats->n - 1);
    }
}

/* Welch's t-test for unequal variances */
static double welch_t_test(online_stats_t *a, online_stats_t *b)
{
    if (a->n < 2 || b->n < 2) return 0.0;

    double se = sqrt(a->variance / a->n + b->variance / b->n);
    if (se < 1e-10) return 0.0;

    return (a->mean - b->mean) / se;
}

/* Comparison function for qsort */
static int compare_uint64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* Get percentile value from sorted array */
static uint64_t get_percentile(uint64_t *sorted, size_t n, int percentile)
{
    size_t idx = (percentile * n) / 100;
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

/* ============================================================================
 * Test Input Generation
 * ============================================================================ */

/* Generate class 0: Fixed/predictable inputs */
static void generate_class0_input(unsigned char *msg, size_t *msglen,
                                   unsigned char *sk)
{
    /* Fixed message: all zeros */
    *msglen = 32;
    memset(msg, 0x00, *msglen);

    /* Fixed secret key pattern */
    memset(sk, 0xAA, KAZ_SIGN_SECRETKEYBYTES);
}

/* Generate class 1: Random/varied inputs */
static void generate_class1_input(unsigned char *msg, size_t *msglen,
                                   unsigned char *sk)
{
    /* Random message */
    *msglen = 32;
    for (size_t i = 0; i < *msglen; i++) {
        msg[i] = (unsigned char)(rand() & 0xFF);
    }

    /* Random secret key */
    for (size_t i = 0; i < KAZ_SIGN_SECRETKEYBYTES; i++) {
        sk[i] = (unsigned char)(rand() & 0xFF);
    }
}

/* ============================================================================
 * Timing Tests
 * ============================================================================ */

typedef struct {
    const char *name;
    int (*test_func)(uint64_t *times_class0, uint64_t *times_class1,
                     size_t n_measurements);
    double threshold;
} dudect_test_t;

/* Test: Signing operation timing */
static int test_sign_timing(uint64_t *times_class0, uint64_t *times_class1,
                            size_t n_measurements)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[256];
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 256];
    unsigned long long siglen;
    size_t msglen;
    uint64_t start, end;

    /* Initialize */
    if (kaz_sign_init_random() != KAZ_SIGN_SUCCESS) {
        return -1;
    }

    /* Generate a key pair for class 0 */
    kaz_sign_keypair(pk, sk);

    /* Warmup */
    for (int i = 0; i < DUDECT_WARMUP_ITERATIONS; i++) {
        generate_class0_input(msg, &msglen, sk);
        kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    }

    /* Measure class 0 (fixed inputs) */
    for (size_t i = 0; i < n_measurements; i++) {
        generate_class0_input(msg, &msglen, sk);

        start = get_cycles();
        kaz_sign_signature(sig, &siglen, msg, msglen, sk);
        end = get_cycles();

        times_class0[i] = end - start;
    }

    /* Measure class 1 (random inputs) */
    for (size_t i = 0; i < n_measurements; i++) {
        generate_class1_input(msg, &msglen, sk);

        start = get_cycles();
        kaz_sign_signature(sig, &siglen, msg, msglen, sk);
        end = get_cycles();

        times_class1[i] = end - start;
    }

    kaz_sign_clear_random();
    return 0;
}

/* Test: Verification timing (should be constant regardless of validity) */
static int test_verify_timing(uint64_t *times_class0, uint64_t *times_class1,
                              size_t n_measurements)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char msg[256];
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 256];
    unsigned char recovered[256];
    unsigned long long siglen, msglen_out;
    size_t msglen = 32;
    uint64_t start, end;

    if (kaz_sign_init_random() != KAZ_SIGN_SUCCESS) {
        return -1;
    }

    kaz_sign_keypair(pk, sk);

    /* Create a valid signature */
    memset(msg, 0x42, msglen);
    kaz_sign_signature(sig, &siglen, msg, msglen, sk);

    /* Warmup */
    for (int i = 0; i < DUDECT_WARMUP_ITERATIONS; i++) {
        kaz_sign_verify(recovered, &msglen_out, sig, siglen, pk);
    }

    /* Measure class 0: Valid signatures */
    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_sign_verify(recovered, &msglen_out, sig, siglen, pk);
        end = get_cycles();

        times_class0[i] = end - start;
    }

    /* Create an invalid signature (corrupted) */
    sig[0] ^= 0xFF;

    /* Measure class 1: Invalid signatures */
    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_sign_verify(recovered, &msglen_out, sig, siglen, pk);
        end = get_cycles();

        times_class1[i] = end - start;
    }

    kaz_sign_clear_random();
    return 0;
}

/* Test: Key generation timing */
static int test_keygen_timing(uint64_t *times_class0, uint64_t *times_class1,
                              size_t n_measurements)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    uint64_t start, end;

    if (kaz_sign_init_random() != KAZ_SIGN_SUCCESS) {
        return -1;
    }

    /* Warmup */
    for (int i = 0; i < DUDECT_WARMUP_ITERATIONS; i++) {
        kaz_sign_keypair(pk, sk);
    }

    /* Measure class 0 and class 1 alternating */
    /* For keygen, both classes should be identical (randomness from RNG) */
    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_sign_keypair(pk, sk);
        end = get_cycles();

        times_class0[i] = end - start;
    }

    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_sign_keypair(pk, sk);
        end = get_cycles();

        times_class1[i] = end - start;
    }

    kaz_sign_clear_random();
    return 0;
}

/* Test: KDF timing with different inputs */
static int test_kdf_timing(uint64_t *times_class0, uint64_t *times_class1,
                           size_t n_measurements)
{
    unsigned char seed0[32], seed1[32];
    unsigned char s_bytes[32], t_bytes[32];
    uint64_t start, end;

    /* Class 0: all zeros */
    memset(seed0, 0x00, 32);

    /* Class 1: all ones */
    memset(seed1, 0xFF, 32);

    /* Warmup */
    for (int i = 0; i < DUDECT_WARMUP_ITERATIONS; i++) {
        kaz_kdf_derive_secret_key(seed0, 32, s_bytes, 32, t_bytes, 32);
    }

    /* Measure class 0 */
    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_kdf_derive_secret_key(seed0, 32, s_bytes, 32, t_bytes, 32);
        end = get_cycles();

        times_class0[i] = end - start;
    }

    /* Measure class 1 */
    for (size_t i = 0; i < n_measurements; i++) {
        start = get_cycles();
        kaz_kdf_derive_secret_key(seed1, 32, s_bytes, 32, t_bytes, 32);
        end = get_cycles();

        times_class1[i] = end - start;
    }

    return 0;
}

/* ============================================================================
 * Analysis and Reporting
 * ============================================================================ */

typedef struct {
    double t_value;
    double mean_diff;
    double class0_mean;
    double class1_mean;
    int passed;
} analysis_result_t;

static analysis_result_t analyze_timing(uint64_t *times_class0,
                                        uint64_t *times_class1,
                                        size_t n_measurements,
                                        double threshold)
{
    analysis_result_t result;
    online_stats_t stats0, stats1;
    uint64_t *sorted0, *sorted1;
    uint64_t low0, high0, low1, high1;

    /* Sort for percentile cropping */
    sorted0 = malloc(n_measurements * sizeof(uint64_t));
    sorted1 = malloc(n_measurements * sizeof(uint64_t));

    memcpy(sorted0, times_class0, n_measurements * sizeof(uint64_t));
    memcpy(sorted1, times_class1, n_measurements * sizeof(uint64_t));

    qsort(sorted0, n_measurements, sizeof(uint64_t), compare_uint64);
    qsort(sorted1, n_measurements, sizeof(uint64_t), compare_uint64);

    /* Get cropping bounds */
    low0 = get_percentile(sorted0, n_measurements, DUDECT_PERCENTILE_LOW);
    high0 = get_percentile(sorted0, n_measurements, DUDECT_PERCENTILE_HIGH);
    low1 = get_percentile(sorted1, n_measurements, DUDECT_PERCENTILE_LOW);
    high1 = get_percentile(sorted1, n_measurements, DUDECT_PERCENTILE_HIGH);

    /* Calculate statistics with cropping */
    stats_init(&stats0);
    stats_init(&stats1);

    for (size_t i = 0; i < n_measurements; i++) {
        if (times_class0[i] >= low0 && times_class0[i] <= high0) {
            stats_update(&stats0, (double)times_class0[i]);
        }
        if (times_class1[i] >= low1 && times_class1[i] <= high1) {
            stats_update(&stats1, (double)times_class1[i]);
        }
    }

    /* Calculate t-value */
    result.t_value = welch_t_test(&stats0, &stats1);
    result.class0_mean = stats0.mean;
    result.class1_mean = stats1.mean;
    result.mean_diff = stats0.mean - stats1.mean;
    result.passed = (fabs(result.t_value) < threshold);

    free(sorted0);
    free(sorted1);

    return result;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

static dudect_test_t tests[] = {
    {"Signing (fixed vs random input)", test_sign_timing, DUDECT_THRESHOLD},
    {"Verification (valid vs invalid)", test_verify_timing, DUDECT_THRESHOLD},
    {"Key Generation", test_keygen_timing, DUDECT_THRESHOLD},
    {"KDF (zero vs one seed)", test_kdf_timing, DUDECT_THRESHOLD},
    {NULL, NULL, 0}
};

int main(int argc, char *argv[])
{
    uint64_t *times_class0 = NULL;
    uint64_t *times_class1 = NULL;
    size_t n_measurements = DUDECT_NUMBER_MEASUREMENTS;
    int all_passed = 1;
    int verbose = 0;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n_measurements = (size_t)atoi(argv[++i]);
        }
    }

    /* Seed random for input generation */
    srand((unsigned int)time(NULL));

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║        Dudect-style Timing Leakage Detection                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Security Level: %-3d                                        ║\n", KAZ_SIGN_SP_J);
    printf("║  Measurements:   %-6zu per class                            ║\n", n_measurements);
    printf("║  Threshold:      %-4.1f (|t| < threshold = pass)              ║\n", DUDECT_THRESHOLD);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* Allocate timing arrays */
    times_class0 = malloc(n_measurements * sizeof(uint64_t));
    times_class1 = malloc(n_measurements * sizeof(uint64_t));

    if (!times_class0 || !times_class1) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    /* Run each test */
    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Testing: %s\n", tests[i].name);
        printf("  Collecting %zu measurements per class...\n", n_measurements);

        int ret = tests[i].test_func(times_class0, times_class1, n_measurements);
        if (ret != 0) {
            printf("  \033[31m[ERROR]\033[0m Test setup failed\n\n");
            all_passed = 0;
            continue;
        }

        analysis_result_t result = analyze_timing(times_class0, times_class1,
                                                   n_measurements,
                                                   tests[i].threshold);

        if (verbose) {
            printf("  Class 0 mean: %.2f cycles\n", result.class0_mean);
            printf("  Class 1 mean: %.2f cycles\n", result.class1_mean);
            printf("  Mean diff:    %.2f cycles\n", result.mean_diff);
        }

        printf("  t-value:      %.4f\n", result.t_value);

        if (result.passed) {
            printf("  Result:       \033[32m[PASS]\033[0m No timing leak detected\n\n");
        } else {
            printf("  Result:       \033[31m[FAIL]\033[0m Potential timing leak!\n\n");
            all_passed = 0;
        }
    }

    /* Summary */
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      Summary                                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    if (all_passed) {
        printf("║  \033[32m✓ All timing tests passed\033[0m                                   ║\n");
        printf("║  No statistically significant timing leaks detected.         ║\n");
    } else {
        printf("║  \033[31m✗ Some timing tests failed\033[0m                                  ║\n");
        printf("║  Potential timing side-channels detected.                    ║\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    printf("Note: This is a statistical test. Results may vary between runs.\n");
    printf("      For production use, run multiple times and investigate any\n");
    printf("      failures thoroughly.\n\n");

    free(times_class0);
    free(times_class1);

    return all_passed ? 0 : 1;
}
