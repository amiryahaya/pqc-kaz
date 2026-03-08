/*
 * KAZ-SIGN Industry-Standard Benchmark Suite
 *
 * Comprehensive performance measurement following NIST PQC and SUPERCOP conventions.
 * Provides statistical analysis including mean, median, standard deviation,
 * percentiles, throughput, and cycle counts.
 *
 * Usage:
 *   ./benchmark_sign_<LEVEL> [options]
 *
 * Options:
 *   -i <n>     Number of iterations (default: 1000)
 *   -w <n>     Number of warmup iterations (default: 100)
 *   -m <size>  Message size in bytes (default: 32)
 *   -v         Variable message size benchmarks
 *   -c         Output in CSV format
 *   -q         Quiet mode (minimal output)
 *   -h         Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

#include "kaz/sign.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define DEFAULT_ITERATIONS     1000
#define DEFAULT_WARMUP         100
#define DEFAULT_MESSAGE_SIZE   32
#define MAX_MESSAGE_SIZE       (1024 * 1024)  /* 1 MB */

/* Message sizes for variable-size benchmark */
static const size_t MESSAGE_SIZES[] = {
    0,          /* Empty message */
    1,          /* Single byte */
    16,         /* 128 bits */
    32,         /* 256 bits */
    64,         /* 512 bits */
    128,        /* 1024 bits */
    256,        /* Common hash output */
    512,        /* Common block size */
    1024,       /* 1 KB */
    4096,       /* 4 KB */
    16384,      /* 16 KB */
    65536,      /* 64 KB */
    262144,     /* 256 KB */
    1048576     /* 1 MB */
};
#define NUM_MESSAGE_SIZES (sizeof(MESSAGE_SIZES) / sizeof(MESSAGE_SIZES[0]))

/* ============================================================================
 * Timing Infrastructure
 * ============================================================================ */

typedef struct {
    double *samples;
    size_t count;
    size_t capacity;
} timing_data_t;

static timing_data_t *timing_create(size_t capacity)
{
    timing_data_t *td = malloc(sizeof(timing_data_t));
    if (!td) return NULL;

    td->samples = malloc(capacity * sizeof(double));
    if (!td->samples) {
        free(td);
        return NULL;
    }

    td->count = 0;
    td->capacity = capacity;
    return td;
}

static void timing_destroy(timing_data_t *td)
{
    if (td) {
        free(td->samples);
        free(td);
    }
}

static void timing_add(timing_data_t *td, double sample)
{
    if (td->count < td->capacity) {
        td->samples[td->count++] = sample;
    }
}

static void timing_reset(timing_data_t *td)
{
    td->count = 0;
}

/* High-resolution timing */
#ifdef __APPLE__
static mach_timebase_info_data_t timebase_info;
static int timebase_initialized = 0;

static double get_time_ns(void)
{
    if (!timebase_initialized) {
        mach_timebase_info(&timebase_info);
        timebase_initialized = 1;
    }
    uint64_t t = mach_absolute_time();
    return (double)t * timebase_info.numer / timebase_info.denom;
}
#else
static double get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
#endif

static double get_time_us(void)
{
    return get_time_ns() / 1000.0;
}

__attribute__((unused))
static double get_time_ms(void)
{
    return get_time_ns() / 1000000.0;
}

/* ============================================================================
 * Statistical Analysis
 * ============================================================================ */

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

typedef struct {
    double mean;
    double median;
    double stddev;
    double variance;
    double min;
    double max;
    double p5;          /* 5th percentile */
    double p25;         /* 25th percentile (Q1) */
    double p75;         /* 75th percentile (Q3) */
    double p95;         /* 95th percentile */
    double p99;         /* 99th percentile */
    double iqr;         /* Interquartile range */
    double throughput;  /* Operations per second */
    size_t count;
} statistics_t;

static double percentile(double *sorted, size_t n, double p)
{
    if (n == 0) return 0.0;
    if (n == 1) return sorted[0];

    double index = (p / 100.0) * (n - 1);
    size_t lower = (size_t)floor(index);
    size_t upper = (size_t)ceil(index);

    if (lower == upper || upper >= n) {
        return sorted[lower < n ? lower : n - 1];
    }

    double frac = index - lower;
    return sorted[lower] * (1.0 - frac) + sorted[upper] * frac;
}

static statistics_t compute_statistics(timing_data_t *td)
{
    statistics_t stats = {0};

    if (td->count == 0) return stats;

    stats.count = td->count;

    /* Sort for percentile calculations */
    double *sorted = malloc(td->count * sizeof(double));
    memcpy(sorted, td->samples, td->count * sizeof(double));
    qsort(sorted, td->count, sizeof(double), compare_double);

    /* Min/Max */
    stats.min = sorted[0];
    stats.max = sorted[td->count - 1];

    /* Mean */
    double sum = 0.0;
    for (size_t i = 0; i < td->count; i++) {
        sum += td->samples[i];
    }
    stats.mean = sum / td->count;

    /* Median */
    if (td->count % 2 == 0) {
        stats.median = (sorted[td->count/2 - 1] + sorted[td->count/2]) / 2.0;
    } else {
        stats.median = sorted[td->count/2];
    }

    /* Variance and Standard Deviation */
    double sq_sum = 0.0;
    for (size_t i = 0; i < td->count; i++) {
        double diff = td->samples[i] - stats.mean;
        sq_sum += diff * diff;
    }
    stats.variance = sq_sum / td->count;
    stats.stddev = sqrt(stats.variance);

    /* Percentiles */
    stats.p5 = percentile(sorted, td->count, 5);
    stats.p25 = percentile(sorted, td->count, 25);
    stats.p75 = percentile(sorted, td->count, 75);
    stats.p95 = percentile(sorted, td->count, 95);
    stats.p99 = percentile(sorted, td->count, 99);

    /* Interquartile Range */
    stats.iqr = stats.p75 - stats.p25;

    /* Throughput (ops/sec) - based on mean time in microseconds */
    stats.throughput = 1000000.0 / stats.mean;

    free(sorted);
    return stats;
}

/* ============================================================================
 * Memory Tracking
 * ============================================================================ */

static long get_memory_usage_kb(void)
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __APPLE__
        return usage.ru_maxrss / 1024;  /* macOS reports in bytes */
#else
        return usage.ru_maxrss;          /* Linux reports in KB */
#endif
    }
    return 0;
}

/* ============================================================================
 * Output Formatting
 * ============================================================================ */

typedef struct {
    int csv_mode;
    int quiet_mode;
    int verbose_mode;
    int variable_sizes;
    int iterations;
    int warmup;
    size_t message_size;
} options_t;

static void print_header(options_t *opts)
{
    if (opts->csv_mode) {
        printf("operation,level,msg_size,iterations,mean_us,median_us,stddev_us,"
               "min_us,max_us,p5_us,p25_us,p75_us,p95_us,p99_us,ops_sec\n");
        return;
    }

    if (opts->quiet_mode) return;

    printf("\n");
    printf("================================================================================\n");
    printf("  KAZ-SIGN Industry-Standard Benchmark Suite\n");
    printf("================================================================================\n");
    printf("\n");
    printf("  Algorithm:        %s\n", KAZ_SIGN_ALGNAME);
    printf("  Security Level:   %d bits\n", KAZ_SECURITY_LEVEL);
    printf("  Public Key:       %d bytes\n", KAZ_SIGN_PUBLICKEYBYTES);
    printf("  Secret Key:       %d bytes\n", KAZ_SIGN_SECRETKEYBYTES);
    printf("  Signature:        %d bytes (overhead)\n", KAZ_SIGN_SIGNATURE_OVERHEAD);
    printf("  Hash Algorithm:   %s\n", KAZ_SIGN_HASH_ALG);
    printf("\n");
    printf("  Iterations:       %d\n", opts->iterations);
    printf("  Warmup:           %d\n", opts->warmup);
    if (!opts->variable_sizes) {
        printf("  Message Size:     %zu bytes\n", opts->message_size);
    }
    printf("\n");
    printf("================================================================================\n");
}

static void print_statistics(const char *operation, size_t msg_size,
                             statistics_t *stats, options_t *opts)
{
    if (opts->csv_mode) {
        printf("%s,%d,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.1f\n",
               operation, KAZ_SECURITY_LEVEL, msg_size, stats->count,
               stats->mean, stats->median, stats->stddev,
               stats->min, stats->max,
               stats->p5, stats->p25, stats->p75, stats->p95, stats->p99,
               stats->throughput);
        return;
    }

    if (opts->quiet_mode) {
        printf("%s: %.3f us (%.1f ops/sec)\n", operation, stats->mean, stats->throughput);
        return;
    }

    printf("\n  %s", operation);
    if (msg_size > 0 || strcmp(operation, "KeyGen") != 0) {
        printf(" (msg=%zu bytes)", msg_size);
    }
    printf("\n");
    printf("  " "------------------------------------------------------------------------\n");
    printf("  %-20s %12.3f us\n", "Mean:", stats->mean);
    printf("  %-20s %12.3f us\n", "Median:", stats->median);
    printf("  %-20s %12.3f us\n", "Std Dev:", stats->stddev);
    printf("  %-20s %12.3f us\n", "Min:", stats->min);
    printf("  %-20s %12.3f us\n", "Max:", stats->max);
    printf("\n");
    printf("  Percentiles:\n");
    printf("    5th:  %10.3f us    25th: %10.3f us\n", stats->p5, stats->p25);
    printf("    75th: %10.3f us    95th: %10.3f us\n", stats->p75, stats->p95);
    printf("    99th: %10.3f us    IQR:  %10.3f us\n", stats->p99, stats->iqr);
    printf("\n");
    printf("  %-20s %12.1f ops/sec\n", "Throughput:", stats->throughput);
    if (msg_size > 0 && strcmp(operation, "KeyGen") != 0) {
        double mb_per_sec = (msg_size * stats->throughput) / (1024.0 * 1024.0);
        printf("  %-20s %12.3f MB/sec\n", "Data Rate:", mb_per_sec);
    }
}

static void print_summary(statistics_t *keygen, statistics_t *sign,
                          statistics_t *verify, options_t *opts)
{
    if (opts->csv_mode || opts->quiet_mode) return;

    printf("\n");
    printf("================================================================================\n");
    printf("  Summary (Security Level %d)\n", KAZ_SECURITY_LEVEL);
    printf("================================================================================\n");
    printf("\n");
    printf("  %-15s %12s %12s %12s\n", "Operation", "Mean (us)", "Median (us)", "Ops/sec");
    printf("  " "------------------------------------------------------------------------\n");
    printf("  %-15s %12.3f %12.3f %12.1f\n", "KeyGen", keygen->mean, keygen->median, keygen->throughput);
    printf("  %-15s %12.3f %12.3f %12.1f\n", "Sign", sign->mean, sign->median, sign->throughput);
    printf("  %-15s %12.3f %12.3f %12.1f\n", "Verify", verify->mean, verify->median, verify->throughput);
    printf("\n");

    /* Full round-trip time */
    double full_cycle = keygen->mean + sign->mean + verify->mean;
    printf("  Full Cycle (KeyGen + Sign + Verify): %.3f us (%.1f ops/sec)\n",
           full_cycle, 1000000.0 / full_cycle);
    printf("\n");

    /* Memory usage */
    long mem_kb = get_memory_usage_kb();
    printf("  Peak Memory Usage: %ld KB\n", mem_kb);
    printf("\n");
}

/* ============================================================================
 * Benchmark Functions
 * ============================================================================ */

static statistics_t benchmark_keygen(timing_data_t *td, options_t *opts)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];

    /* Warmup */
    for (int i = 0; i < opts->warmup; i++) {
        kaz_sign_keypair(pk, sk);
    }

    /* Benchmark */
    timing_reset(td);
    for (int i = 0; i < opts->iterations; i++) {
        double start = get_time_us();
        kaz_sign_keypair(pk, sk);
        double end = get_time_us();
        timing_add(td, end - start);
    }

    statistics_t stats = compute_statistics(td);
    print_statistics("KeyGen", 0, &stats, opts);
    return stats;
}

static statistics_t benchmark_sign(timing_data_t *td, options_t *opts, size_t msg_size)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned long long siglen;

    /* Allocate message and signature buffers */
    if (msg_size > 0) {
        msg = malloc(msg_size);
        if (!msg) {
            fprintf(stderr, "Failed to allocate message buffer\n");
            statistics_t empty = {0};
            return empty;
        }
        /* Fill with pseudo-random data */
        for (size_t i = 0; i < msg_size; i++) {
            msg[i] = (unsigned char)(i * 17 + 31);
        }
    }

    sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + msg_size);
    if (!sig) {
        fprintf(stderr, "Failed to allocate signature buffer\n");
        free(msg);
        statistics_t empty = {0};
        return empty;
    }

    /* Generate key pair */
    kaz_sign_keypair(pk, sk);

    /* Warmup */
    for (int i = 0; i < opts->warmup; i++) {
        kaz_sign_signature(sig, &siglen, msg, msg_size, sk);
    }

    /* Benchmark */
    timing_reset(td);
    for (int i = 0; i < opts->iterations; i++) {
        double start = get_time_us();
        kaz_sign_signature(sig, &siglen, msg, msg_size, sk);
        double end = get_time_us();
        timing_add(td, end - start);
    }

    free(msg);
    free(sig);

    statistics_t stats = compute_statistics(td);
    print_statistics("Sign", msg_size, &stats, opts);
    return stats;
}

static statistics_t benchmark_verify(timing_data_t *td, options_t *opts, size_t msg_size)
{
    unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
    unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned char *recovered = NULL;
    unsigned long long siglen, recovered_len;

    /* Allocate buffers */
    if (msg_size > 0) {
        msg = malloc(msg_size);
        if (!msg) {
            fprintf(stderr, "Failed to allocate message buffer\n");
            statistics_t empty = {0};
            return empty;
        }
        for (size_t i = 0; i < msg_size; i++) {
            msg[i] = (unsigned char)(i * 17 + 31);
        }
    }

    sig = malloc(KAZ_SIGN_SIGNATURE_OVERHEAD + msg_size);
    recovered = malloc(msg_size + 1);  /* +1 for safety */
    if (!sig || !recovered) {
        fprintf(stderr, "Failed to allocate buffers\n");
        free(msg);
        free(sig);
        free(recovered);
        statistics_t empty = {0};
        return empty;
    }

    /* Generate key pair and signature */
    kaz_sign_keypair(pk, sk);
    kaz_sign_signature(sig, &siglen, msg, msg_size, sk);

    /* Warmup */
    for (int i = 0; i < opts->warmup; i++) {
        kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
    }

    /* Benchmark */
    timing_reset(td);
    for (int i = 0; i < opts->iterations; i++) {
        double start = get_time_us();
        kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
        double end = get_time_us();
        timing_add(td, end - start);
    }

    free(msg);
    free(sig);
    free(recovered);

    statistics_t stats = compute_statistics(td);
    print_statistics("Verify", msg_size, &stats, opts);
    return stats;
}

/* ============================================================================
 * SUPERCOP-Style Output
 * ============================================================================ */

static void print_supercop_output(statistics_t *keygen, statistics_t *sign,
                                  statistics_t *verify, size_t msg_size)
{
    printf("\n");
    printf("================================================================================\n");
    printf("  SUPERCOP-Compatible Output\n");
    printf("================================================================================\n");
    printf("\n");

    /* SUPERCOP typically reports in CPU cycles, but we report in microseconds */
    printf("%s keypair %zu\n", KAZ_SIGN_ALGNAME, (size_t)keygen->median);
    printf("%s %zu sign %zu\n", KAZ_SIGN_ALGNAME, msg_size, (size_t)sign->median);
    printf("%s %zu open %zu\n", KAZ_SIGN_ALGNAME, msg_size, (size_t)verify->median);
    printf("\n");

    /* Additional SUPERCOP-style metrics */
    printf("%s publickeybytes %d\n", KAZ_SIGN_ALGNAME, KAZ_SIGN_PUBLICKEYBYTES);
    printf("%s secretkeybytes %d\n", KAZ_SIGN_ALGNAME, KAZ_SIGN_SECRETKEYBYTES);
    printf("%s bytes %d\n", KAZ_SIGN_ALGNAME, KAZ_SIGN_SIGNATURE_OVERHEAD);
}

/* ============================================================================
 * Variable Message Size Benchmark
 * ============================================================================ */

static void benchmark_variable_sizes(timing_data_t *td, options_t *opts)
{
    if (!opts->csv_mode && !opts->quiet_mode) {
        printf("\n");
        printf("================================================================================\n");
        printf("  Variable Message Size Benchmark\n");
        printf("================================================================================\n");
    }

    for (size_t i = 0; i < NUM_MESSAGE_SIZES; i++) {
        size_t msg_size = MESSAGE_SIZES[i];

        if (!opts->csv_mode && !opts->quiet_mode) {
            printf("\n  --- Message Size: %zu bytes ---\n", msg_size);
        }

        benchmark_sign(td, opts, msg_size);
        benchmark_verify(td, opts, msg_size);
    }
}

/* ============================================================================
 * Help
 * ============================================================================ */

static void print_help(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i <n>     Number of benchmark iterations (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -w <n>     Number of warmup iterations (default: %d)\n", DEFAULT_WARMUP);
    printf("  -m <size>  Message size in bytes (default: %d)\n", DEFAULT_MESSAGE_SIZE);
    printf("  -v         Run variable message size benchmarks\n");
    printf("  -c         Output results in CSV format\n");
    printf("  -s         Print SUPERCOP-compatible output\n");
    printf("  -q         Quiet mode (minimal output)\n");
    printf("  -h         Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                    # Default benchmark\n", prog);
    printf("  %s -i 10000 -m 1024   # 10000 iterations, 1KB messages\n", prog);
    printf("  %s -c > results.csv   # Export to CSV\n", prog);
    printf("  %s -v                 # Variable message size benchmark\n", prog);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[])
{
    options_t opts = {
        .csv_mode = 0,
        .quiet_mode = 0,
        .verbose_mode = 0,
        .variable_sizes = 0,
        .iterations = DEFAULT_ITERATIONS,
        .warmup = DEFAULT_WARMUP,
        .message_size = DEFAULT_MESSAGE_SIZE
    };
    int supercop_output = 0;

    /* Parse command line arguments */
    int opt;
    while ((opt = getopt(argc, argv, "i:w:m:vcqsh")) != -1) {
        switch (opt) {
            case 'i':
                opts.iterations = atoi(optarg);
                if (opts.iterations < 1) opts.iterations = DEFAULT_ITERATIONS;
                break;
            case 'w':
                opts.warmup = atoi(optarg);
                if (opts.warmup < 0) opts.warmup = 0;
                break;
            case 'm':
                opts.message_size = (size_t)atol(optarg);
                if (opts.message_size > MAX_MESSAGE_SIZE) {
                    opts.message_size = MAX_MESSAGE_SIZE;
                }
                break;
            case 'v':
                opts.variable_sizes = 1;
                break;
            case 'c':
                opts.csv_mode = 1;
                break;
            case 's':
                supercop_output = 1;
                break;
            case 'q':
                opts.quiet_mode = 1;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    /* Initialize random state */
    int ret = kaz_sign_init_random();
    if (ret != KAZ_SIGN_SUCCESS) {
        fprintf(stderr, "FATAL: Failed to initialize random state\n");
        return 1;
    }

    /* Create timing data structure */
    timing_data_t *td = timing_create((size_t)opts.iterations);
    if (!td) {
        fprintf(stderr, "FATAL: Failed to allocate timing data\n");
        kaz_sign_clear_random();
        return 1;
    }

    /* Print header */
    print_header(&opts);

    /* Run benchmarks */
    if (opts.variable_sizes) {
        /* Variable message size benchmarks */
        benchmark_keygen(td, &opts);
        benchmark_variable_sizes(td, &opts);
    } else {
        /* Standard benchmark */
        statistics_t keygen_stats = benchmark_keygen(td, &opts);
        statistics_t sign_stats = benchmark_sign(td, &opts, opts.message_size);
        statistics_t verify_stats = benchmark_verify(td, &opts, opts.message_size);

        /* Print summary */
        print_summary(&keygen_stats, &sign_stats, &verify_stats, &opts);

        /* Print SUPERCOP output if requested */
        if (supercop_output) {
            print_supercop_output(&keygen_stats, &sign_stats, &verify_stats, opts.message_size);
        }
    }

    /* Cleanup */
    timing_destroy(td);
    kaz_sign_clear_random();

    if (!opts.csv_mode && !opts.quiet_mode) {
        printf("================================================================================\n");
        printf("  Benchmark Complete\n");
        printf("================================================================================\n\n");
    }

    return 0;
}
