#!/bin/bash

# KAZ-KEM Comprehensive Test Runner
# Automated testing and benchmarking with HTML report generation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="test_reports_${TIMESTAMP}"
SUMMARY_FILE="${REPORT_DIR}/summary.txt"

# Create report directory
mkdir -p "${REPORT_DIR}"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  KAZ-KEM Comprehensive Test & Benchmark Suite Runner      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Initialize summary
{
    echo "KAZ-KEM Test & Benchmark Report"
    echo "================================"
    echo "Generated: $(date)"
    echo "System: $(uname -s) $(uname -m)"
    echo ""
} > "${SUMMARY_FILE}"

# Function to run test suite
run_tests() {
    local level=$1
    local impl=$2  # 0 for original, 1 for optimized
    local impl_name

    if [ "$impl" -eq 1 ]; then
        impl_name="optimized"
    else
        impl_name="original"
    fi

    echo -e "${YELLOW}Running tests for Level ${level} (${impl_name})...${NC}"

    local log_file="${REPORT_DIR}/test_${impl_name}_${level}.log"

    if make -f Makefile.test test LEVEL=${level} USE_OPTIMIZED=${impl} > "${log_file}" 2>&1; then
        echo -e "${GREEN}✓ Tests PASSED${NC}"
        echo "Level ${level} (${impl_name}): PASSED" >> "${SUMMARY_FILE}"
        return 0
    else
        echo -e "${RED}✗ Tests FAILED${NC}"
        echo "Level ${level} (${impl_name}): FAILED" >> "${SUMMARY_FILE}"
        echo "  See: ${log_file}" >> "${SUMMARY_FILE}"
        return 1
    fi
}

# Function to run benchmarks
run_benchmark() {
    local level=$1
    local impl=$2
    local impl_name

    if [ "$impl" -eq 1 ]; then
        impl_name="optimized"
    else
        impl_name="original"
    fi

    echo -e "${YELLOW}Running benchmark for Level ${level} (${impl_name})...${NC}"

    local log_file="${REPORT_DIR}/bench_${impl_name}_${level}.log"
    local csv_file="${REPORT_DIR}/bench_${impl_name}_${level}.csv"

    make -f Makefile.test clean > /dev/null 2>&1

    if make -f Makefile.test benchmark LEVEL=${level} USE_OPTIMIZED=${impl} > "${log_file}" 2>&1; then
        echo -e "${GREEN}✓ Benchmark completed${NC}"

        # Move CSV file if it exists
        if [ -f "benchmark_results.csv" ]; then
            mv benchmark_results.csv "${csv_file}"
        fi

        return 0
    else
        echo -e "${RED}✗ Benchmark failed${NC}"
        return 1
    fi
}

# Main test execution
main() {
    local test_failures=0
    local bench_failures=0

    echo -e "\n${BLUE}Phase 1: Unit Tests${NC}"
    echo "===================="
    echo ""

    {
        echo ""
        echo "UNIT TEST RESULTS"
        echo "=================="
    } >> "${SUMMARY_FILE}"

    # Test all security levels with optimized implementation
    for level in 128 192 256; do
        run_tests ${level} 1 || ((test_failures++))
        echo ""
    done

    echo -e "\n${BLUE}Phase 2: Performance Benchmarks${NC}"
    echo "================================"
    echo ""

    {
        echo ""
        echo "BENCHMARK RESULTS"
        echo "================="
    } >> "${SUMMARY_FILE}"

    # Benchmark all security levels
    for level in 128 192 256; do
        run_benchmark ${level} 1 || ((bench_failures++))
        echo ""
    done

    # Comparison benchmarks (optional)
    if [ "$1" = "--compare" ]; then
        echo -e "\n${BLUE}Phase 3: Comparison Benchmarks${NC}"
        echo "=============================="
        echo ""

        {
            echo ""
            echo "COMPARISON (Original vs Optimized)"
            echo "==================================="
        } >> "${SUMMARY_FILE}"

        for level in 128 192 256; do
            echo -e "${YELLOW}Comparing implementations for Level ${level}...${NC}"
            run_benchmark ${level} 0  # Original
            run_benchmark ${level} 1  # Optimized
            echo ""
        done
    fi

    # Generate summary
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    TEST SUMMARY                             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ ${test_failures} -eq 0 ]; then
        echo -e "${GREEN}✓ All unit tests PASSED${NC}"
    else
        echo -e "${RED}✗ ${test_failures} unit test suite(s) FAILED${NC}"
    fi

    if [ ${bench_failures} -eq 0 ]; then
        echo -e "${GREEN}✓ All benchmarks completed successfully${NC}"
    else
        echo -e "${YELLOW}⚠ ${bench_failures} benchmark(s) failed${NC}"
    fi

    echo ""
    echo "Reports saved to: ${REPORT_DIR}/"
    echo "Summary file: ${SUMMARY_FILE}"

    {
        echo ""
        echo "SUMMARY"
        echo "======="
        echo "Unit test failures: ${test_failures}"
        echo "Benchmark failures: ${bench_failures}"

        if [ ${test_failures} -eq 0 ] && [ ${bench_failures} -eq 0 ]; then
            echo ""
            echo "Status: ALL TESTS PASSED ✓"
        else
            echo ""
            echo "Status: SOME TESTS FAILED ✗"
        fi
    } >> "${SUMMARY_FILE}"

    echo ""
    cat "${SUMMARY_FILE}"

    # Return appropriate exit code
    if [ ${test_failures} -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Parse command line arguments
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --compare    Run comparison benchmarks (original vs optimized)"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                Run standard tests and benchmarks"
    echo "  $0 --compare      Run tests and comparison benchmarks"
    exit 0
fi

# Run main test suite
main "$@"
exit_code=$?

# Cleanup
make -f Makefile.test clean > /dev/null 2>&1

exit ${exit_code}
