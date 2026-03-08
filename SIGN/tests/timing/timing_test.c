/*
 * KAZ-SIGN Timing Variance Test
 *
 * This test measures timing variance of signing operations to detect
 * potential timing side-channels. A constant-time implementation should
 * show consistent timing regardless of input values.
 *
 * Methodology:
 * 1. Sign messages with different Hamming weights (all-zeros, all-ones, mixed)
 * 2. Measure timing for each message type
 * 3. Compare variance and detect statistically significant differences
 *
 * Note: This is a basic test. For production, use tools like dudect or ctgrind.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include "kaz/sign.h"

#ifdef __APPLE__
#include <mach/mach_time.h>
static uint64_t get_time_ns(void) {
    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    return mach_absolute_time() * timebase.numer / timebase.denom;
}
#else
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

#define NUM_ITERATIONS 1000
#define MSG_LEN 32

typedef struct {
    double mean;
    double stddev;
    double min;
    double max;
    double median;
} timing_stats_t;

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void compute_stats(double *times, int n, timing_stats_t *stats) {
    double sum = 0, sum_sq = 0;
    stats->min = times[0];
    stats->max = times[0];

    for (int i = 0; i < n; i++) {
        sum += times[i];
        sum_sq += times[i] * times[i];
        if (times[i] < stats->min) stats->min = times[i];
        if (times[i] > stats->max) stats->max = times[i];
    }

    stats->mean = sum / n;
    stats->stddev = sqrt((sum_sq / n) - (stats->mean * stats->mean));

    /* Compute median */
    double *sorted = malloc(n * sizeof(double));
    memcpy(sorted, times, n * sizeof(double));
    qsort(sorted, n, sizeof(double), compare_double);
    stats->median = sorted[n / 2];
    free(sorted);
}

/* Welch's t-test for comparing two samples */
static double welch_t_test(timing_stats_t *a, timing_stats_t *b, int n) {
    double var_a = a->stddev * a->stddev;
    double var_b = b->stddev * b->stddev;
    double se = sqrt(var_a / n + var_b / n);
    if (se < 1e-10) return 0.0;
    return (a->mean - b->mean) / se;
}

static void run_timing_test(const char *name __attribute__((unused)),
                            unsigned char *msg, size_t msglen,
                            unsigned char *sk, double *times, int iterations) {
    unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + MSG_LEN];
    unsigned long long siglen;

    /* Warmup */
    for (int i = 0; i < 50; i++) {
        kaz_sign_signature(sig, &siglen, msg, msglen, sk);
    }

    /* Timed runs */
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        kaz_sign_signature(sig, &siglen, msg, msglen, sk);
        uint64_t end = get_time_ns();
        times[i] = (double)(end - start);
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         KAZ-SIGN Timing Variance Analysis                    ║\n");
    printf("║         Security Level: %d                                   ║\n", KAZ_SECURITY_LEVEL);
    printf("║         Backend: %s                           ║\n",
           KAZ_USE_CONSTTIME ? "OpenSSL-CT" : "GMP       ");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* Initialize */
    int ret = kaz_sign_init_random();
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Failed to initialize random state\n");
        return 1;
    }

    /* Generate key pair */
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    ret = kaz_sign_keypair(pk, sk);
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "Failed to generate key pair\n");
        return 1;
    }

    /* Prepare test messages with different Hamming weights */
    unsigned char msg_zeros[MSG_LEN];
    unsigned char msg_ones[MSG_LEN];
    unsigned char msg_mixed[MSG_LEN];
    unsigned char msg_random[MSG_LEN];

    memset(msg_zeros, 0x00, MSG_LEN);
    memset(msg_ones, 0xFF, MSG_LEN);
    for (int i = 0; i < MSG_LEN; i++) {
        msg_mixed[i] = (i % 2) ? 0xFF : 0x00;
        msg_random[i] = rand() & 0xFF;
    }

    /* Allocate timing arrays */
    double *times_zeros = malloc(NUM_ITERATIONS * sizeof(double));
    double *times_ones = malloc(NUM_ITERATIONS * sizeof(double));
    double *times_mixed = malloc(NUM_ITERATIONS * sizeof(double));
    double *times_random = malloc(NUM_ITERATIONS * sizeof(double));

    if (!times_zeros || !times_ones || !times_mixed || !times_random) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    printf("Running %d iterations per message type...\n\n", NUM_ITERATIONS);

    /* Run timing tests */
    run_timing_test("zeros", msg_zeros, MSG_LEN, sk, times_zeros, NUM_ITERATIONS);
    run_timing_test("ones", msg_ones, MSG_LEN, sk, times_ones, NUM_ITERATIONS);
    run_timing_test("mixed", msg_mixed, MSG_LEN, sk, times_mixed, NUM_ITERATIONS);
    run_timing_test("random", msg_random, MSG_LEN, sk, times_random, NUM_ITERATIONS);

    /* Compute statistics */
    timing_stats_t stats_zeros, stats_ones, stats_mixed, stats_random;
    compute_stats(times_zeros, NUM_ITERATIONS, &stats_zeros);
    compute_stats(times_ones, NUM_ITERATIONS, &stats_ones);
    compute_stats(times_mixed, NUM_ITERATIONS, &stats_mixed);
    compute_stats(times_random, NUM_ITERATIONS, &stats_random);

    /* Print results */
    printf("┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐\n");
    printf("│ Message     │ Mean (ns)    │ StdDev (ns)  │ Min (ns)     │ Max (ns)     │\n");
    printf("├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤\n");
    printf("│ All-zeros   │ %12.1f │ %12.1f │ %12.1f │ %12.1f │\n",
           stats_zeros.mean, stats_zeros.stddev, stats_zeros.min, stats_zeros.max);
    printf("│ All-ones    │ %12.1f │ %12.1f │ %12.1f │ %12.1f │\n",
           stats_ones.mean, stats_ones.stddev, stats_ones.min, stats_ones.max);
    printf("│ Mixed       │ %12.1f │ %12.1f │ %12.1f │ %12.1f │\n",
           stats_mixed.mean, stats_mixed.stddev, stats_mixed.min, stats_mixed.max);
    printf("│ Random      │ %12.1f │ %12.1f │ %12.1f │ %12.1f │\n",
           stats_random.mean, stats_random.stddev, stats_random.min, stats_random.max);
    printf("└─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘\n\n");

    /* Statistical comparison using Welch's t-test */
    printf("Statistical Analysis (Welch's t-test, |t| > 2.0 indicates significant difference):\n");
    printf("─────────────────────────────────────────────────────────────────────────────────\n");

    double t_zeros_ones = welch_t_test(&stats_zeros, &stats_ones, NUM_ITERATIONS);
    double t_zeros_mixed = welch_t_test(&stats_zeros, &stats_mixed, NUM_ITERATIONS);
    double t_zeros_random = welch_t_test(&stats_zeros, &stats_random, NUM_ITERATIONS);
    double t_ones_mixed = welch_t_test(&stats_ones, &stats_mixed, NUM_ITERATIONS);

    printf("  All-zeros vs All-ones:  t = %7.3f  %s\n", t_zeros_ones,
           fabs(t_zeros_ones) > 2.0 ? "[SIGNIFICANT]" : "[OK]");
    printf("  All-zeros vs Mixed:     t = %7.3f  %s\n", t_zeros_mixed,
           fabs(t_zeros_mixed) > 2.0 ? "[SIGNIFICANT]" : "[OK]");
    printf("  All-zeros vs Random:    t = %7.3f  %s\n", t_zeros_random,
           fabs(t_zeros_random) > 2.0 ? "[SIGNIFICANT]" : "[OK]");
    printf("  All-ones vs Mixed:      t = %7.3f  %s\n", t_ones_mixed,
           fabs(t_ones_mixed) > 2.0 ? "[SIGNIFICANT]" : "[OK]");
    printf("\n");

    /* Overall assessment */
    int significant_diffs = 0;
    if (fabs(t_zeros_ones) > 2.0) significant_diffs++;
    if (fabs(t_zeros_mixed) > 2.0) significant_diffs++;
    if (fabs(t_zeros_random) > 2.0) significant_diffs++;
    if (fabs(t_ones_mixed) > 2.0) significant_diffs++;

    /* Coefficient of variation (CV) - measure of relative variability */
    double cv_avg = (stats_zeros.stddev / stats_zeros.mean +
                     stats_ones.stddev / stats_ones.mean +
                     stats_mixed.stddev / stats_mixed.mean +
                     stats_random.stddev / stats_random.mean) / 4.0 * 100.0;

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      Assessment                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Significant timing differences: %d/4                         ║\n", significant_diffs);
    printf("║  Average coefficient of variation: %.2f%%                    ║\n", cv_avg);
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    if (significant_diffs == 0 && cv_avg < 10.0) {
        printf("║  \033[32m✓ PASS: No significant timing leakage detected\033[0m            ║\n");
    } else if (significant_diffs <= 1 && cv_avg < 15.0) {
        printf("║  \033[33m⚠ MARGINAL: Minor timing variations detected\033[0m              ║\n");
    } else {
        printf("║  \033[31m✗ FAIL: Significant timing variations detected\033[0m            ║\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    /* Cleanup */
    free(times_zeros);
    free(times_ones);
    free(times_mixed);
    free(times_random);
    kaz_sign_clear_random();

    return (significant_diffs > 1) ? 1 : 0;
}
