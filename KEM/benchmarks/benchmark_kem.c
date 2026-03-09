/*
 * KAZ-KEM Performance Benchmark Suite
 * Version 2.0.0
 * Industry-grade performance measurement and statistical analysis
 * Supports runtime security level selection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>

#include "kaz/nist_api.h"
#include "kaz/kem.h"
#include "kaz/version.h"

/* Configuration */
#define WARMUP_ITERATIONS 10
#define BENCHMARK_ITERATIONS 1000
#define PERCENTILE_95 0.95
#define PERCENTILE_99 0.99

/* Statistics structure */
typedef struct {
    double *samples;
    int count;
    double min;
    double max;
    double mean;
    double median;
    double stddev;
    double p95;
    double p99;
    double ops_per_sec;
} benchmark_stats_t;

/* Buffer size helpers using runtime accessors */
static size_t get_pk_size(void) {
    return kaz_kem_publickey_bytes();
}

static size_t get_sk_size(void) {
    return kaz_kem_privatekey_bytes();
}

static size_t get_msg_size(void) {
    return kaz_kem_shared_secret_bytes();
}

static size_t get_ct_size(void) {
    return kaz_kem_ciphertext_bytes();
}

/* Dynamic buffer allocation */
static unsigned char* alloc_pk(void) {
    return (unsigned char*)malloc(get_pk_size());
}

static unsigned char* alloc_sk(void) {
    return (unsigned char*)malloc(get_sk_size());
}

static unsigned char* alloc_msg(void) {
    return (unsigned char*)malloc(get_msg_size());
}

static unsigned char* alloc_ct(void) {
    return (unsigned char*)malloc(get_ct_size());
}

/* Generate a valid test message (guaranteed smaller than modulus) */
static void generate_test_message(unsigned char *msg, int seed) {
    size_t msg_size = get_msg_size();
    /* First byte must be 0 to ensure msg < N (big-endian format) */
    msg[0] = 0;
    /* Rest of the bytes use a counting pattern */
    for (size_t i = 1; i < msg_size; i++) {
        msg[i] = (unsigned char)((seed + i) & 0xFF);
    }
}

/* Timing utilities */
static inline double get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000000.0 + (double)tv.tv_usec;
}

/* Comparison function for qsort */
static int compare_doubles(const void *a, const void *b)
{
    double diff = *(const double*)a - *(const double*)b;
    return (diff > 0) - (diff < 0);
}

/* Calculate statistics from samples */
static void calculate_stats(benchmark_stats_t *stats)
{
    if (stats->count == 0) return;

    /* Sort samples for percentile calculation */
    qsort(stats->samples, stats->count, sizeof(double), compare_doubles);

    /* Min and max */
    stats->min = stats->samples[0];
    stats->max = stats->samples[stats->count - 1];

    /* Mean */
    double sum = 0.0;
    for (int i = 0; i < stats->count; i++) {
        sum += stats->samples[i];
    }
    stats->mean = sum / stats->count;

    /* Median */
    if (stats->count % 2 == 0) {
        stats->median = (stats->samples[stats->count/2 - 1] +
                        stats->samples[stats->count/2]) / 2.0;
    } else {
        stats->median = stats->samples[stats->count/2];
    }

    /* Standard deviation */
    double variance = 0.0;
    for (int i = 0; i < stats->count; i++) {
        double diff = stats->samples[i] - stats->mean;
        variance += diff * diff;
    }
    stats->stddev = sqrt(variance / stats->count);

    /* Percentiles */
    int p95_idx = (int)(stats->count * PERCENTILE_95);
    int p99_idx = (int)(stats->count * PERCENTILE_99);
    if (p95_idx >= stats->count) p95_idx = stats->count - 1;
    if (p99_idx >= stats->count) p99_idx = stats->count - 1;
    stats->p95 = stats->samples[p95_idx];
    stats->p99 = stats->samples[p99_idx];

    /* Operations per second */
    stats->ops_per_sec = 1000000.0 / stats->mean; /* Convert from microseconds */
}

/* Print statistics */
static void print_stats(const char *operation, benchmark_stats_t *stats)
{
    printf("\n%s Performance:\n", operation);
    printf("  Iterations:     %d\n", stats->count);
    printf("  Mean:           %.2f us (%.2f ops/sec)\n", stats->mean, stats->ops_per_sec);
    printf("  Median:         %.2f us\n", stats->median);
    printf("  Std Dev:        %.2f us (%.1f%%)\n", stats->stddev,
           (stats->stddev / stats->mean) * 100.0);
    printf("  Min:            %.2f us\n", stats->min);
    printf("  Max:            %.2f us\n", stats->max);
    printf("  95th percentile: %.2f us\n", stats->p95);
    printf("  99th percentile: %.2f us\n", stats->p99);
}

/* Benchmark key generation */
static benchmark_stats_t benchmark_keygen(int iterations)
{
    benchmark_stats_t stats = {0};
    stats.samples = malloc(sizeof(double) * iterations);
    stats.count = iterations;

    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();

    printf("  Benchmarking key generation... ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        double start = get_time_us();
        crypto_kem_keypair(pk, sk);
        double end = get_time_us();

        stats.samples[i] = end - start;
    }

    calculate_stats(&stats);
    printf("Done\n");

    free(pk);
    free(sk);

    return stats;
}

/* Benchmark encapsulation */
static benchmark_stats_t benchmark_encap(int iterations)
{
    benchmark_stats_t stats = {0};
    stats.samples = malloc(sizeof(double) * iterations);
    stats.count = iterations;

    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_msg();
    unsigned char *encap = alloc_ct();
    unsigned long long encaplen;

    /* Setup: generate keypair once */
    crypto_kem_keypair(pk, sk);
    generate_test_message(msg, 0xAA);

    printf("  Benchmarking encapsulation... ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        double start = get_time_us();
        crypto_encap(encap, &encaplen, msg, get_msg_size(), pk);
        double end = get_time_us();

        stats.samples[i] = end - start;
    }

    calculate_stats(&stats);
    printf("Done\n");

    free(pk);
    free(sk);
    free(msg);
    free(encap);

    return stats;
}

/* Benchmark decapsulation */
static benchmark_stats_t benchmark_decap(int iterations)
{
    benchmark_stats_t stats = {0};
    stats.samples = malloc(sizeof(double) * iterations);
    stats.count = iterations;

    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_msg();
    unsigned char *encap = alloc_ct();
    unsigned char *decap = alloc_msg();
    unsigned long long encaplen, decaplen;

    /* Setup: generate keypair and encapsulation once */
    crypto_kem_keypair(pk, sk);
    generate_test_message(msg, 0xBB);
    crypto_encap(encap, &encaplen, msg, get_msg_size(), pk);

    printf("  Benchmarking decapsulation... ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        double start = get_time_us();
        crypto_decap(decap, &decaplen, encap, encaplen, sk);
        double end = get_time_us();

        stats.samples[i] = end - start;
    }

    calculate_stats(&stats);
    printf("Done\n");

    free(pk);
    free(sk);
    free(msg);
    free(encap);
    free(decap);

    return stats;
}

/* Benchmark full round-trip */
static benchmark_stats_t benchmark_roundtrip(int iterations)
{
    benchmark_stats_t stats = {0};
    stats.samples = malloc(sizeof(double) * iterations);
    stats.count = iterations;

    printf("  Benchmarking full round-trip... ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        unsigned char *pk = alloc_pk();
        unsigned char *sk = alloc_sk();
        unsigned char *msg = alloc_msg();
        unsigned char *encap = alloc_ct();
        unsigned char *decap = alloc_msg();
        unsigned long long encaplen, decaplen;

        generate_test_message(msg, i);

        double start = get_time_us();
        crypto_kem_keypair(pk, sk);
        crypto_encap(encap, &encaplen, msg, get_msg_size(), pk);
        crypto_decap(decap, &decaplen, encap, encaplen, sk);
        double end = get_time_us();

        stats.samples[i] = end - start;

        free(pk);
        free(sk);
        free(msg);
        free(encap);
        free(decap);
    }

    calculate_stats(&stats);
    printf("Done\n");

    return stats;
}

/* Throughput benchmark */
static void benchmark_throughput(void)
{
    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_msg();
    unsigned char *encap = alloc_ct();
    unsigned char *decap = alloc_msg();
    unsigned long long encaplen, decaplen;

    /* Setup */
    crypto_kem_keypair(pk, sk);
    generate_test_message(msg, 0xCC);
    crypto_encap(encap, &encaplen, msg, get_msg_size(), pk);

    /* Measure throughput over 1 second */
    const double duration = 1.0; /* seconds */
    int operations = 0;

    printf("\n  Measuring throughput (1 second test)... ");
    fflush(stdout);

    double start = get_time_us();
    double end_time = start + (duration * 1000000.0);

    while (get_time_us() < end_time) {
        crypto_decap(decap, &decaplen, encap, encaplen, sk);
        operations++;
    }

    double end = get_time_us();
    double actual_duration = (end - start) / 1000000.0;
    double ops_per_sec = operations / actual_duration;

    printf("Done\n");
    printf("  Operations:     %d\n", operations);
    printf("  Duration:       %.3f seconds\n", actual_duration);
    printf("  Throughput:     %.0f ops/sec\n", ops_per_sec);
    printf("  Bandwidth:      %.2f MB/sec (%.2f Mbps)\n",
           (ops_per_sec * get_msg_size()) / (1024*1024),
           (ops_per_sec * get_msg_size() * 8) / (1024*1024));

    free(pk);
    free(sk);
    free(msg);
    free(encap);
    free(decap);
}

/* Memory usage estimation */
static void estimate_memory_usage(void)
{
    size_t pk_size = get_pk_size();
    size_t sk_size = get_sk_size();
    size_t msg_size = get_msg_size();
    size_t ct_size = get_ct_size();

    printf("\nMemory Usage:\n");
    printf("  Public Key:     %zu bytes\n", pk_size);
    printf("  Private Key:    %zu bytes\n", sk_size);
    printf("  Message:        %zu bytes\n", msg_size);
    printf("  Ciphertext:     %zu bytes\n", ct_size);
    printf("  Total per op:   %zu bytes\n", pk_size + sk_size + msg_size + ct_size);
    printf("  Overhead:       %.1f%% (ciphertext vs message)\n",
           ((double)ct_size / msg_size - 1.0) * 100.0);
}

/* Warmup operations */
static void warmup(void)
{
    printf("Running warmup (%d iterations)... ", WARMUP_ITERATIONS);
    fflush(stdout);

    unsigned char *pk = alloc_pk();
    unsigned char *sk = alloc_sk();
    unsigned char *msg = alloc_msg();
    unsigned char *encap = alloc_ct();
    unsigned char *decap = alloc_msg();
    unsigned long long encaplen, decaplen;

    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        crypto_kem_keypair(pk, sk);
        generate_test_message(msg, i);
        crypto_encap(encap, &encaplen, msg, get_msg_size(), pk);
        crypto_decap(decap, &decaplen, encap, encaplen, sk);
    }

    free(pk);
    free(sk);
    free(msg);
    free(encap);
    free(decap);

    printf("Done\n");
}

/* Generate CSV report */
static void generate_csv_report(int level, benchmark_stats_t *keygen, benchmark_stats_t *encap,
                                benchmark_stats_t *decap, benchmark_stats_t *roundtrip)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "benchmark_results_%d.csv", level);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not create CSV file\n");
        return;
    }

    fprintf(fp, "Operation,Iterations,Mean(us),Median(us),StdDev(us),Min(us),Max(us),P95(us),P99(us),Ops/Sec\n");
    fprintf(fp, "KeyGen,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
            keygen->count, keygen->mean, keygen->median, keygen->stddev,
            keygen->min, keygen->max, keygen->p95, keygen->p99, keygen->ops_per_sec);
    fprintf(fp, "Encapsulation,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
            encap->count, encap->mean, encap->median, encap->stddev,
            encap->min, encap->max, encap->p95, encap->p99, encap->ops_per_sec);
    fprintf(fp, "Decapsulation,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
            decap->count, decap->mean, decap->median, decap->stddev,
            decap->min, decap->max, decap->p95, decap->p99, decap->ops_per_sec);
    fprintf(fp, "RoundTrip,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
            roundtrip->count, roundtrip->mean, roundtrip->median, roundtrip->stddev,
            roundtrip->min, roundtrip->max, roundtrip->p95, roundtrip->p99, roundtrip->ops_per_sec);

    fclose(fp);
    printf("\nCSV report saved to: %s\n", filename);
}

/* Run benchmarks for a specific security level */
static void run_benchmarks_for_level(int level)
{
    /* Initialize for this level */
    int ret = kaz_kem_init(level);
    if (ret != KAZ_KEM_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize KEM for level %d (error: %d)\n", level, ret);
        return;
    }

    printf("\n");
    printf("================================================================================\n");
    printf("          KAZ-KEM Performance Benchmark Suite v%s\n", kaz_kem_version());
    printf("================================================================================\n");
    printf("Security Level:  %d-bit (KAZ-KEM-%d)\n", level, level);
    printf("Iterations:      %d per benchmark\n", BENCHMARK_ITERATIONS);
    printf("Warmup:          %d iterations\n", WARMUP_ITERATIONS);
    printf("================================================================================\n\n");

    /* Warmup */
    warmup();

    printf("\nRunning Benchmarks:\n");
    printf("-------------------\n");

    /* Individual operation benchmarks */
    benchmark_stats_t keygen_stats = benchmark_keygen(BENCHMARK_ITERATIONS);
    benchmark_stats_t encap_stats = benchmark_encap(BENCHMARK_ITERATIONS);
    benchmark_stats_t decap_stats = benchmark_decap(BENCHMARK_ITERATIONS);
    benchmark_stats_t roundtrip_stats = benchmark_roundtrip(BENCHMARK_ITERATIONS);

    /* Throughput benchmark */
    printf("\nThroughput Benchmark:\n");
    printf("--------------------");
    benchmark_throughput();

    /* Memory usage */
    estimate_memory_usage();

    /* Print detailed statistics */
    printf("\n");
    printf("================================================================================\n");
    printf("                        DETAILED STATISTICS\n");
    printf("================================================================================\n");

    print_stats("Key Generation", &keygen_stats);
    print_stats("Encapsulation", &encap_stats);
    print_stats("Decapsulation", &decap_stats);
    print_stats("Full Round-Trip", &roundtrip_stats);

    /* Summary table */
    printf("\n");
    printf("================================================================================\n");
    printf("                           PERFORMANCE SUMMARY\n");
    printf("================================================================================\n");
    printf("Operation         Mean (us)   Median (us)   StdDev (%%)   Ops/Sec\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Key Generation    %10.2f  %12.2f  %10.1f  %10.0f\n",
           keygen_stats.mean, keygen_stats.median,
           (keygen_stats.stddev / keygen_stats.mean) * 100.0,
           keygen_stats.ops_per_sec);
    printf("Encapsulation     %10.2f  %12.2f  %10.1f  %10.0f\n",
           encap_stats.mean, encap_stats.median,
           (encap_stats.stddev / encap_stats.mean) * 100.0,
           encap_stats.ops_per_sec);
    printf("Decapsulation     %10.2f  %12.2f  %10.1f  %10.0f\n",
           decap_stats.mean, decap_stats.median,
           (decap_stats.stddev / decap_stats.mean) * 100.0,
           decap_stats.ops_per_sec);
    printf("Full Round-Trip   %10.2f  %12.2f  %10.1f  %10.0f\n",
           roundtrip_stats.mean, roundtrip_stats.median,
           (roundtrip_stats.stddev / roundtrip_stats.mean) * 100.0,
           roundtrip_stats.ops_per_sec);
    printf("================================================================================\n");

    /* Generate CSV report */
    generate_csv_report(level, &keygen_stats, &encap_stats, &decap_stats, &roundtrip_stats);

    /* Cleanup */
    free(keygen_stats.samples);
    free(encap_stats.samples);
    free(decap_stats.samples);
    free(roundtrip_stats.samples);

    printf("\n[OK] Benchmark complete for Level %d!\n", level);

    /* Cleanup KEM state */
    kaz_kem_cleanup();
}

/* Main benchmark runner */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

#ifdef KAZ_SECURITY_LEVEL
    /* Compile-time level selection - benchmark single level */
    run_benchmarks_for_level(KAZ_SECURITY_LEVEL);
#else
    /* Runtime level selection - benchmark all levels */
    printf("\n");
    printf("################################################################################\n");
    printf("#                                                                              #\n");
    printf("#                    KAZ-KEM COMPREHENSIVE BENCHMARK SUITE                     #\n");
    printf("#                                                                              #\n");
    printf("################################################################################\n");
    printf("\nBenchmarking all security levels...\n");

    int levels[] = {128, 192, 256};
    int num_levels = sizeof(levels) / sizeof(levels[0]);

    for (int i = 0; i < num_levels; i++) {
        printf("\n");
        printf("########################################################################\n");
        printf("                    SECURITY LEVEL %d-bit (%d/%d)\n", levels[i], i + 1, num_levels);
        printf("########################################################################\n");

        run_benchmarks_for_level(levels[i]);
    }

    printf("\n");
    printf("################################################################################\n");
    printf("#                                                                              #\n");
    printf("#                    ALL BENCHMARKS COMPLETED SUCCESSFULLY                     #\n");
    printf("#                                                                              #\n");
    printf("################################################################################\n");
    printf("\nCSV reports generated:\n");
    printf("  - benchmark_results_128.csv\n");
    printf("  - benchmark_results_192.csv\n");
    printf("  - benchmark_results_256.csv\n\n");
#endif

    return 0;
}
