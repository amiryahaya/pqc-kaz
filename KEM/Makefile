# KAZ-KEM Unified Build System
# Version 2.1.0
# Production-ready OpenSSL-based implementation
# Supports runtime security level selection
# ============================================================================

# Version information
VERSION_MAJOR=2
VERSION_MINOR=1
VERSION_PATCH=0
VERSION=$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

CC ?= gcc
CFLAGS=-Wall -Wextra -Wpedantic -Wformat=2 -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS=-lm

# Version flags
VERSION_FLAGS=-DKAZ_KEM_VERSION=\"$(VERSION)\" \
              -DKAZ_KEM_VERSION_MAJOR=$(VERSION_MAJOR) \
              -DKAZ_KEM_VERSION_MINOR=$(VERSION_MINOR) \
              -DKAZ_KEM_VERSION_PATCH=$(VERSION_PATCH)

# Detect OS and set OpenSSL paths accordingly
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo "/usr/local/opt/openssl")
    EXT_INC=-I$(OPENSSL_PREFIX)/include
    LINK=-L$(OPENSSL_PREFIX)/lib -lcrypto $(LDFLAGS)
else
    EXT_INC=-I/usr/include/openssl
    LINK=-lcrypto $(LDFLAGS)
endif

# Directory structure
SRC_DIR=src/internal
INC_DIR=include
TEST_DIR=tests/unit
BENCH_DIR=benchmarks
SCRIPT_DIR=scripts
BUILD_DIR=build
OBJ_DIR=$(BUILD_DIR)/obj
BIN_DIR=$(BUILD_DIR)/bin
LIB_DIR=$(BUILD_DIR)/lib

# Include paths
INC=-I$(INC_DIR) -I$(SRC_DIR) $(EXT_INC)

# Security level (optional - if not set, runtime selection is used)
# Use LEVEL=<128|192|256> for compile-time level selection (backward compatible)
# Use LEVEL=runtime for runtime-only build (test all levels in one binary)
LEVEL ?= 128

ifeq ($(LEVEL),runtime)
    SECURITY_FLAG=-DKAZ_KEM_USE_OPENSSL
    LEVEL_SUFFIX=runtime
else
    SECURITY_FLAG=-DKAZ_SECURITY_LEVEL=$(LEVEL) -DKAZ_KEM_USE_OPENSSL
    LEVEL_SUFFIX=$(LEVEL)
endif

# Source files - OpenSSL secure implementation only
KAZ_SRC=$(SRC_DIR)/kem_secure.c
KAZ_HDR=$(INC_DIR)/kaz/kem.h $(INC_DIR)/kaz/security.h $(INC_DIR)/kaz/version.h
NIST_WRAPPER=$(SRC_DIR)/nist_wrapper.c
NIST_API=$(INC_DIR)/kaz/nist_api.h

# Test and benchmark files
TEST_SRC=$(TEST_DIR)/test_kem.c
TEST_WIRE_SRC=$(TEST_DIR)/test_kazwire.c
BENCH_SRC=$(BENCH_DIR)/benchmark_kem.c
KAT_SRC=$(TEST_DIR)/PQCgenKAT_kem.c

# Output executables
TEST_EXEC=$(BIN_DIR)/test_kem_$(LEVEL_SUFFIX)
TEST_WIRE_EXEC=$(BIN_DIR)/test_kazwire
BENCH_EXEC=$(BIN_DIR)/benchmark_kem_$(LEVEL_SUFFIX)
KAT_EXEC=$(BIN_DIR)/PQCgenKAT_kem_$(LEVEL_SUFFIX)

# Implementation info
IMPL_NAME=OpenSSL (constant-time)

# Phony targets
.PHONY: all test test-wire benchmark kat clean clean-all help version
.PHONY: test-all bench-all ci memcheck
.PHONY: init

# Default target
all: init test benchmark

# Initialize build directories
init:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR)

# Build test suite
$(TEST_EXEC): $(TEST_SRC) $(KAZ_SRC) $(KAZ_HDR) $(NIST_WRAPPER) $(NIST_API)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SECURITY_FLAG) $(VERSION_FLAGS) -o $(TEST_EXEC) \
		$(TEST_SRC) $(KAZ_SRC) $(NIST_WRAPPER) \
		$(INC) $(LINK)
	@echo "✓ Built test suite v$(VERSION): $(TEST_EXEC) ($(IMPL_NAME), Level $(LEVEL))"

# Build benchmark suite
$(BENCH_EXEC): $(BENCH_SRC) $(KAZ_SRC) $(KAZ_HDR) $(NIST_WRAPPER) $(NIST_API)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SECURITY_FLAG) $(VERSION_FLAGS) -o $(BENCH_EXEC) \
		$(BENCH_SRC) $(KAZ_SRC) $(NIST_WRAPPER) \
		$(INC) $(LINK)
	@echo "✓ Built benchmark suite v$(VERSION): $(BENCH_EXEC) ($(IMPL_NAME), Level $(LEVEL))"

# Build KAT generator
$(KAT_EXEC): $(KAT_SRC) $(KAZ_SRC) $(KAZ_HDR) $(NIST_WRAPPER) $(NIST_API)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SECURITY_FLAG) $(VERSION_FLAGS) -o $(KAT_EXEC) \
		$(KAT_SRC) $(KAZ_SRC) $(NIST_WRAPPER) \
		$(INC) $(LINK)
	@echo "✓ Built KAT generator v$(VERSION): $(KAT_EXEC) ($(IMPL_NAME), Level $(LEVEL))"

# Build KazWire test suite (no compile-time level needed)
$(TEST_WIRE_EXEC): $(TEST_WIRE_SRC) $(KAZ_SRC) $(KAZ_HDR)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(VERSION_FLAGS) -DKAZ_KEM_USE_OPENSSL -o $(TEST_WIRE_EXEC) \
		$(TEST_WIRE_SRC) $(KAZ_SRC) \
		$(INC) $(LINK)
	@echo "Built KazWire test suite: $(TEST_WIRE_EXEC)"

# Run tests
test: $(TEST_EXEC)
	@echo ""
	@echo "=========================================="
	@echo " Running Test Suite"
	@echo " Implementation: $(IMPL_NAME)"
	@echo " Security Level: $(LEVEL)-bit"
	@echo "=========================================="
	@$(TEST_EXEC)

# Run KazWire tests
test-wire: $(TEST_WIRE_EXEC)
	@echo ""
	@echo "=========================================="
	@echo " Running KazWire Test Suite"
	@echo "=========================================="
	@$(TEST_WIRE_EXEC)

# Run benchmarks
benchmark: $(BENCH_EXEC)
	@echo ""
	@echo "=========================================="
	@echo " Running Benchmarks"
	@echo " Implementation: $(IMPL_NAME)"
	@echo " Security Level: $(LEVEL)-bit"
	@echo "=========================================="
	@$(BENCH_EXEC)

# Generate KAT (Known Answer Test) vectors
kat: $(KAT_EXEC)
	@echo "Generating KAT vectors for Level $(LEVEL)..."
	@$(KAT_EXEC)

# Test all security levels
test-all:
	@echo "Testing all security levels..."
	$(MAKE) clean
	$(MAKE) test LEVEL=128
	@echo ""
	$(MAKE) clean
	$(MAKE) test LEVEL=192
	@echo ""
	$(MAKE) clean
	$(MAKE) test LEVEL=256

# Benchmark all security levels
bench-all:
	@echo "Benchmarking all security levels..."
	$(MAKE) clean
	$(MAKE) benchmark LEVEL=128
	@mv benchmark_results.csv benchmark_results_128.csv 2>/dev/null || true
	@echo ""
	$(MAKE) clean
	$(MAKE) benchmark LEVEL=192
	@mv benchmark_results.csv benchmark_results_192.csv 2>/dev/null || true
	@echo ""
	$(MAKE) clean
	$(MAKE) benchmark LEVEL=256
	@mv benchmark_results.csv benchmark_results_256.csv 2>/dev/null || true

# Run continuous integration tests
ci: test-all
	@echo ""
	@echo "✓ All CI tests passed!"

# Memory leak check with valgrind (if available)
memcheck: $(TEST_EXEC)
	@which valgrind > /dev/null 2>&1 || (echo "valgrind not found - install it for memory leak checking"; exit 1)
	@echo "Running memory leak check..."
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose $(TEST_EXEC)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf *.dSYM
	rm -f benchmark_results*.csv
	rm -f PQCkemKAT_*.req PQCkemKAT_*.rsp

# Clean everything including reports
clean-all: clean
	rm -f *.csv *.log

# Display version
version:
	@echo "KAZ-KEM Version $(VERSION)"
	@echo "Build Date: $(shell date '+%Y-%m-%d')"
	@echo "Implementation: $(IMPL_NAME)"
	@echo "Security Level: $(LEVEL)-bit"
	@echo "Features:"
	@echo "  - Constant-time modular exponentiation (BN_mod_exp_mont_consttime)"
	@echo "  - Cryptographic RNG (OpenSSL RAND_bytes)"
	@echo "  - Secure memory handling (BN_clear_free, BN_secure_new)"

# Help message
help:
	@echo "KAZ-KEM Unified Build System v$(VERSION)"
	@echo "========================================="
	@echo ""
	@echo "Production-ready OpenSSL-based implementation with:"
	@echo "  - Constant-time modular exponentiation"
	@echo "  - Cryptographic random number generation"
	@echo "  - Secure memory handling"
	@echo ""
	@echo "Directory Structure:"
	@echo "  include/kaz/      - Public API headers"
	@echo "  src/internal/     - Implementation files"
	@echo "  tests/unit/       - Unit tests"
	@echo "  benchmarks/       - Performance benchmarks"
	@echo "  scripts/          - Helper scripts"
	@echo "  build/            - Build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build both test and benchmark suites (default)"
	@echo "  test         - Build and run test suite"
	@echo "  benchmark    - Build and run benchmark suite"
	@echo "  kat          - Generate Known Answer Test vectors"
	@echo "  test-all     - Run tests for all security levels"
	@echo "  bench-all    - Run benchmarks for all security levels"
	@echo "  memcheck     - Run tests with valgrind memory leak checker"
	@echo "  ci           - Run continuous integration tests"
	@echo "  version      - Display version information"
	@echo "  clean        - Remove build artifacts"
	@echo "  clean-all    - Remove build artifacts and reports"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  LEVEL=<128|192|256>     Security level (default: 128)"
	@echo ""
	@echo "Examples:"
	@echo "  make test LEVEL=128"
	@echo "  make test LEVEL=256"
	@echo "  make benchmark LEVEL=192"
	@echo "  make test-all"
	@echo "  make bench-all"
