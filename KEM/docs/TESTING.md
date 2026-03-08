# KAZ-KEM Testing & Benchmarking Framework

## Overview

This directory contains an industry-grade testing and benchmarking framework for the KAZ-KEM implementation, providing comprehensive validation, performance analysis, and statistical reporting.

## Test Suite Components

### 1. Unit Test Suite (`test_kem.c`)

Comprehensive test coverage including:

#### Functionality Tests
- **Basic Operations**: Key generation, encapsulation, decapsulation
- **Round-trip Correctness**: Message integrity verification
- **Multiple Messages**: Batch operation testing
- **Edge Cases**: All-zeros, all-ones messages
- **Determinism**: Randomness verification

#### Security Tests
- **Wrong Key Detection**: Verifies authentication
- **Ciphertext Integrity**: Corruption detection
- **Key Uniqueness**: Ensures proper randomness

#### Stress Tests
- **High Volume**: 100+ iterations
- **Memory Stability**: Long-running operation verification

**Total Tests**: 11 comprehensive test cases

### 2. Performance Benchmark Suite (`benchmark_kem.c`)

Statistical performance analysis including:

#### Measured Operations
- **Key Generation**: Keypair creation performance
- **Encapsulation**: Message encryption speed
- **Decapsulation**: Message decryption speed
- **Full Round-trip**: End-to-end latency
- **Throughput**: Operations per second
- **Bandwidth**: Data processing rate

#### Statistical Metrics
- Mean, Median, Standard Deviation
- Min/Max latencies
- 95th and 99th percentiles
- Operations per second
- Memory usage estimation
- Ciphertext overhead calculation

**Iterations**: 1,000 per benchmark (configurable)
**Warmup**: 10 iterations to stabilize caches

## Quick Start

### Run All Tests

```bash
./run_tests.sh
```

This runs:
- Unit tests for all security levels (128, 192, 256)
- Performance benchmarks for all levels
- Generates comprehensive report in `test_reports_TIMESTAMP/`

### Run Tests for Specific Security Level

```bash
make -f Makefile.test test LEVEL=128
```

### Run Benchmarks

```bash
make -f Makefile.test benchmark LEVEL=256
```

### Compare Original vs Optimized

```bash
./run_tests.sh --compare
```

or

```bash
make -f Makefile.test compare LEVEL=192
```

## Detailed Usage

### Manual Test Execution

```bash
# Build test suite
make -f Makefile.test test_kem_128

# Run it
./test_kem_128
```

### Manual Benchmark Execution

```bash
# Build benchmark
make -f Makefile.test benchmark_kem_128

# Run it
./benchmark_kem_128
```

### Test All Security Levels

```bash
make -f Makefile.test test-all
```

### Benchmark All Security Levels

```bash
make -f Makefile.test bench-all
```

This creates:
- `benchmark_results_128.csv`
- `benchmark_results_192.csv`
- `benchmark_results_256.csv`

### Memory Leak Detection

Requires valgrind:

```bash
make -f Makefile.test memcheck LEVEL=128
```

Expected output: `0 bytes leaked`

## Test Output Examples

### Unit Test Output

```
================================================================================
          KAZ-KEM Comprehensive Test Suite v1.0
================================================================================
Security Level: 128-bit (KAZ-KEM-128)
Public Key Size: 108 bytes
Private Key Size: 34 bytes
Message Size: 54 bytes
Ciphertext Size: 162 bytes
================================================================================

UNIT TESTS
----------
Running: test_keygen_basic ... [PASS]
Running: test_keygen_determinism ... [PASS]
Running: test_encap_basic ... [PASS]
Running: test_decap_basic ... [PASS]
Running: test_roundtrip_correctness ... [PASS]
Running: test_multiple_messages ... [PASS]
Running: test_zero_message ... [PASS]
Running: test_ones_message ... [PASS]

NEGATIVE TESTS
--------------
Running: test_wrong_key_decap ... [PASS]
Running: test_corrupted_ciphertext ... [PASS]

STRESS TESTS
------------
Running: test_stress_operations ... [PASS]

================================================================================
                          TEST SUITE SUMMARY
================================================================================
Security Level: 128-bit
Algorithm: KAZ-KEM-128

Total Tests:   11
[PASS] Passed:      11 (100.0%)
[FAIL] Failed:      0
[SKIP] Skipped:     0
================================================================================

🎉 ALL TESTS PASSED! 🎉
```

### Benchmark Output

```
================================================================================
          KAZ-KEM Performance Benchmark Suite v1.0
================================================================================
Security Level:  128-bit (KAZ-KEM-128)
Iterations:      1000 per benchmark
Warmup:          10 iterations
================================================================================

Running warmup (10 iterations)... Done

Running Benchmarks:
-------------------
  Benchmarking key generation... Done
  Benchmarking encapsulation... Done
  Benchmarking decapsulation... Done
  Benchmarking full round-trip... Done

Throughput Benchmark:
--------------------
  Measuring throughput (1 second test)... Done
  Operations:     50000
  Duration:       1.000 seconds
  Throughput:     50000 ops/sec
  Bandwidth:      2.57 MB/sec (20.60 Mbps)

Memory Usage:
  Public Key:     108 bytes
  Private Key:    34 bytes
  Message:        54 bytes
  Ciphertext:     162 bytes
  Total per op:   358 bytes
  Overhead:       200.0% (ciphertext vs message)

================================================================================
                        DETAILED STATISTICS
================================================================================

Key Generation Performance:
  Iterations:     1000
  Mean:           28.45 μs (35160.47 ops/sec)
  Median:         27.80 μs
  Std Dev:        3.21 μs (11.3%)
  Min:            24.10 μs
  Max:            45.20 μs
  95th percentile: 32.15 μs
  99th percentile: 38.90 μs

Encapsulation Performance:
  Iterations:     1000
  Mean:           31.20 μs (32051.28 ops/sec)
  Median:         30.50 μs
  Std Dev:        2.87 μs (9.2%)
  Min:            27.30 μs
  Max:            42.10 μs
  95th percentile: 35.60 μs
  99th percentile: 39.80 μs

Decapsulation Performance:
  Iterations:     1000
  Mean:           18.90 μs (52910.05 ops/sec)
  Median:         18.50 μs
  Std Dev:        1.95 μs (10.3%)
  Min:            16.20 μs
  Max:            28.30 μs
  95th percentile: 21.40 μs
  99th percentile: 24.70 μs

================================================================================
                           PERFORMANCE SUMMARY
================================================================================
Operation         Mean (μs)   Median (μs)   StdDev (%)   Ops/Sec
--------------------------------------------------------------------------------
Key Generation        28.45         27.80        11.3        35160
Encapsulation         31.20         30.50         9.2        32051
Decapsulation         18.90         18.50        10.3        52910
Full Round-Trip       78.55         76.30        12.1        12730
================================================================================

CSV report saved to: benchmark_results.csv

✓ Benchmark complete!
```

## CSV Output Format

The benchmark generates a CSV file with detailed results:

```csv
Operation,Iterations,Mean(μs),Median(μs),StdDev(μs),Min(μs),Max(μs),P95(μs),P99(μs),Ops/Sec
KeyGen,1000,28.45,27.80,3.21,24.10,45.20,32.15,38.90,35160.47
Encapsulation,1000,31.20,30.50,2.87,27.30,42.10,35.60,39.80,32051.28
Decapsulation,1000,18.90,18.50,1.95,16.20,28.30,21.40,24.70,52910.05
RoundTrip,1000,78.55,76.30,9.52,65.40,102.30,90.20,95.80,12730.45
```

This can be imported into Excel, Google Sheets, or data analysis tools.

## Performance Metrics Explained

### Mean (Average)
Arithmetic average of all measurements. Best for understanding typical performance.

### Median
Middle value when all measurements are sorted. Less affected by outliers than mean.

### Standard Deviation
Measure of variability. Lower is more consistent. Shown as percentage of mean.

### Min/Max
Fastest and slowest measurements. Max shows worst-case latency.

### 95th/99th Percentile
95% or 99% of operations complete faster than this value. Important for SLA guarantees.

### Operations Per Second
How many operations can be performed per second (1,000,000 μs / mean).

## Interpreting Results

### Good Results
- ✅ Standard deviation < 15% of mean (consistent performance)
- ✅ P99 < 2× median (few outliers)
- ✅ All tests passing
- ✅ Performance matches or exceeds specifications

### Warning Signs
- ⚠️ Standard deviation > 20% (inconsistent performance)
- ⚠️ P99 >> median (many outliers, possible system contention)
- ⚠️ Performance degradation across security levels not proportional to key sizes

### Comparison Metrics

When comparing implementations:
```
Speedup = Time_Original / Time_Optimized

Example:
  Original keygen: 40 μs
  Optimized keygen: 28 μs
  Speedup: 40/28 = 1.43x (43% faster)
```

## Continuous Integration

For CI/CD pipelines:

```bash
make -f Makefile.test ci
```

This runs all tests and exits with:
- Exit code 0: All tests passed
- Exit code 1: Some tests failed

Example GitHub Actions workflow:
```yaml
- name: Run KAZ-KEM Tests
  run: |
    cd KEM-Combined
    make -f Makefile.test ci
```

## Customization

### Adjust Benchmark Iterations

Edit `benchmark_kem.c`:
```c
#define BENCHMARK_ITERATIONS 10000  // Increase for more precision
#define WARMUP_ITERATIONS 50        // Increase for better cache warmup
```

### Add Custom Tests

Add to `test_kem.c`:
```c
int test_my_custom_test(void)
{
    // Your test code
    ASSERT_TRUE(condition);
    return 1;  // Pass
}

// In main():
RUN_TEST(test_my_custom_test);
```

### Add Custom Benchmarks

Add to `benchmark_kem.c`:
```c
static benchmark_stats_t benchmark_my_operation(int iterations)
{
    benchmark_stats_t stats = {0};
    stats.samples = malloc(sizeof(double) * iterations);
    stats.count = iterations;

    for (int i = 0; i < iterations; i++) {
        double start = get_time_us();
        // Your operation here
        double end = get_time_us();
        stats.samples[i] = end - start;
    }

    calculate_stats(&stats);
    return stats;
}
```

## Troubleshooting

### Tests Fail

1. **Check security level**: Ensure correct parameters loaded
2. **Verify dependencies**: OpenSSL and GMP installed correctly
3. **Check implementation**: Original vs optimized mismatch
4. **View detailed output**: Check log files in test_reports/

### Benchmarks Show Poor Performance

1. **System load**: Close other applications
2. **CPU frequency scaling**: Disable power saving
3. **Warmup insufficient**: Increase WARMUP_ITERATIONS
4. **Sample size too small**: Increase BENCHMARK_ITERATIONS

### High Standard Deviation

Indicates inconsistent performance, possible causes:
- System background tasks
- CPU thermal throttling
- Memory pressure
- Insufficient warmup

Solution:
```bash
# On Linux, set CPU governor to performance
sudo cpupower frequency-set -g performance

# Run with higher priority
sudo nice -n -20 ./benchmark_kem_128
```

## Best Practices

### For Development
1. Run tests after every code change
2. Use `--compare` to verify optimizations don't break functionality
3. Check for memory leaks with valgrind
4. Monitor standard deviation - should remain stable

### For Performance Analysis
1. Close background applications
2. Run on dedicated/idle machine
3. Collect multiple runs (bench-all)
4. Compare CSV files across runs
5. Look for trends in percentiles, not just averages

### For CI/CD
1. Use `make ci` for automated testing
2. Store CSV results as artifacts
3. Track performance trends over time
4. Set performance regression thresholds

## Advanced Usage

### Automated Regression Testing

```bash
#!/bin/bash
# Save baseline
make -f Makefile.test benchmark LEVEL=128
mv benchmark_results.csv baseline.csv

# After code changes
make -f Makefile.test benchmark LEVEL=128
mv benchmark_results.csv current.csv

# Compare (requires python with pandas)
python3 compare_benchmarks.py baseline.csv current.csv
```

### Cross-Platform Testing

```bash
# Test on multiple systems
for host in server1 server2 server3; do
    ssh $host "cd KAZ-KEM/KEM-Combined && ./run_tests.sh"
done
```

## Files Overview

| File | Purpose |
|------|---------|
| `test_kem.c` | Unit test suite implementation |
| `benchmark_kem.c` | Performance benchmark implementation |
| `Makefile.test` | Build system for tests and benchmarks |
| `run_tests.sh` | Automated test runner with reporting |
| `TESTING.md` | This documentation file |

## Support

For issues or questions:
1. Check test logs in `test_reports_*/`
2. Review CSV output for performance anomalies
3. Run `make -f Makefile.test help` for quick reference
4. Consult OPTIMIZATIONS.md for implementation details

## Contributing

When adding new features:
1. Add corresponding unit tests
2. Add performance benchmarks if applicable
3. Update this documentation
4. Ensure `make ci` passes
5. Check for memory leaks with valgrind

## License

Same as KAZ-KEM implementation (NIST license).
