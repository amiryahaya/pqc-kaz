# KAZ-SIGN Makefile
# Unified build system supporting security levels 128, 192, and 256
# Uses OpenSSL BIGNUM with constant-time operations
#
# Usage:
#   make test LEVEL=128                    # Build and run tests
#   make test-all                          # Run tests for all security levels
#   make test-verbose LEVEL=128            # Run tests with verbose output
#   make benchmark LEVEL=128               # Run benchmarks
#   make benchmark-csv LEVEL=128           # Run benchmarks with CSV output
#   make kat LEVEL=128                     # Generate KAT files
#   make kat-all                           # Generate KAT files for all levels
#   make timing-test LEVEL=128             # Run timing analysis
#   make clean                             # Clean build artifacts

# ============================================================================
# Configuration
# ============================================================================

# Default security level
LEVEL ?= 128

# Benchmark iterations (can be overridden)
BENCH_ITERATIONS ?= 1000

# Validate security level
ifneq ($(LEVEL),128)
ifneq ($(LEVEL),192)
ifneq ($(LEVEL),256)
$(error LEVEL must be 128, 192, or 256)
endif
endif
endif

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wformat=2 -O2 -g -MMD -MP
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -DKAZ_SECURITY_LEVEL=$(LEVEL)

# Include paths
INC = -I./include -I./src/internal

# Detect OpenSSL location (macOS Homebrew vs Linux)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
    ifeq ($(OPENSSL_PREFIX),)
        $(error OpenSSL not found. Install with: brew install openssl@3)
    endif
    INC += -I$(OPENSSL_PREFIX)/include
    LDFLAGS = -L$(OPENSSL_PREFIX)/lib
else
    # Linux
    INC += -I/usr/include/openssl
endif

# Libraries (OpenSSL only)
LIBS = -lcrypto -lm

# Directories
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj
LIB_DIR = $(BUILD_DIR)/lib

SRC_DIR = src/internal
TEST_DIR = tests/unit
BENCH_DIR = benchmarks
TOOLS_DIR = tools
TIMING_DIR = tests/timing

# ============================================================================
# Source Files
# ============================================================================

# Core library sources (OpenSSL constant-time implementation)
LIB_SRCS = $(SRC_DIR)/sign.c \
           $(SRC_DIR)/nist_wrapper.c \
           $(SRC_DIR)/security.c \
           $(SRC_DIR)/kdf.c \
           $(SRC_DIR)/sha3.c \
           $(SRC_DIR)/detached.c \
           $(SRC_DIR)/der.c \
           $(SRC_DIR)/x509.c \
           $(SRC_DIR)/p12.c

# Object files
LIB_OBJS = $(OBJ_DIR)/sign.o \
           $(OBJ_DIR)/nist_wrapper.o \
           $(OBJ_DIR)/security.o \
           $(OBJ_DIR)/kdf.o \
           $(OBJ_DIR)/sha3.o \
           $(OBJ_DIR)/detached.o \
           $(OBJ_DIR)/der.o \
           $(OBJ_DIR)/x509.o \
           $(OBJ_DIR)/p12.o

# Include auto-generated header dependency files
-include $(wildcard $(OBJ_DIR)/*.d)

# ============================================================================
# Targets
# ============================================================================

.PHONY: all test test-all test-verbose test-quick test-kdf \
        test-sha3 test-detached test-der test-kazwire test-x509 test-p12 test-extensions ci \
        benchmark benchmark-csv \
        benchmark-full benchmark-all benchmark-supercop \
        kat kat-all kat-verify clean distclean dirs help \
        timing-test dudect dudect-thorough \
        fuzz fuzz-libfuzzer fuzz-afl fuzz-corpus fuzz-quick \
        shared shared-all shared-unified

all: dirs $(BIN_DIR)/test_sign_$(LEVEL) $(BIN_DIR)/benchmark_sign_$(LEVEL)

# Create build directories
dirs:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR) $(LIB_DIR)

# ============================================================================
# Object File Compilation
# ============================================================================

$(OBJ_DIR)/sign.o: $(SRC_DIR)/sign.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/nist_wrapper.o: $(SRC_DIR)/nist_wrapper.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/security.o: $(SRC_DIR)/security.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/kdf.o: $(SRC_DIR)/kdf.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/sha3.o: $(SRC_DIR)/sha3.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/detached.o: $(SRC_DIR)/detached.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/der.o: $(SRC_DIR)/der.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/x509.o: $(SRC_DIR)/x509.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

$(OBJ_DIR)/p12.o: $(SRC_DIR)/p12.c | dirs
	$(CC) $(CFLAGS) -fPIC $(INC) -c $< -o $@

# ============================================================================
# Executable Targets
# ============================================================================

# Build test executable
$(BIN_DIR)/test_sign_$(LEVEL): $(TEST_DIR)/test_sign.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build benchmark executable
$(BIN_DIR)/benchmark_sign_$(LEVEL): $(BENCH_DIR)/benchmark_sign.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build KAT generator
$(BIN_DIR)/PQCgenKAT_sign_$(LEVEL): $(TOOLS_DIR)/PQCgenKAT_sign.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build timing test
$(BIN_DIR)/timing_test_$(LEVEL): $(TIMING_DIR)/timing_test.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build KDF test
$(BIN_DIR)/test_kdf_$(LEVEL): $(TEST_DIR)/test_kdf.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build SHA3 test
$(BIN_DIR)/test_sha3_$(LEVEL): $(TEST_DIR)/test_sha3.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build detached test
$(BIN_DIR)/test_detached_$(LEVEL): $(TEST_DIR)/test_detached.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build DER test
$(BIN_DIR)/test_der_$(LEVEL): $(TEST_DIR)/test_der.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build KazWire test
$(BIN_DIR)/test_kazwire_$(LEVEL): $(TEST_DIR)/test_kazwire.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build X.509 test
$(BIN_DIR)/test_x509_$(LEVEL): $(TEST_DIR)/test_x509.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build P12 test
$(BIN_DIR)/test_p12_$(LEVEL): $(TEST_DIR)/test_p12.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# Build fuzz harness
$(BIN_DIR)/fuzz_standalone: tests/fuzz/fuzz_sign.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) -fsanitize=address $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS)

# ============================================================================
# Test Targets
# ============================================================================

# Run tests (default)
test: $(BIN_DIR)/test_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) Tests"
	@echo "Backend: OpenSSL (constant-time)"
	@echo "========================================"
	@$(BIN_DIR)/test_sign_$(LEVEL)

# Run tests with verbose output
test-verbose: $(BIN_DIR)/test_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) Tests - VERBOSE"
	@echo "========================================"
	@$(BIN_DIR)/test_sign_$(LEVEL) -v

# Run quick smoke tests
test-quick: $(BIN_DIR)/test_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) Quick Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_sign_$(LEVEL) -q

# Run tests for all security levels
test-all:
	@echo ""
	@echo "========================================"
	@echo "Testing All Security Levels"
	@echo "========================================"
	@rm -rf $(BUILD_DIR)
	@$(MAKE) test LEVEL=128
	@rm -rf $(BUILD_DIR)
	@$(MAKE) test LEVEL=192
	@rm -rf $(BUILD_DIR)
	@$(MAKE) test LEVEL=256

# Run KDF tests
test-kdf: $(BIN_DIR)/test_kdf_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) KDF Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_kdf_$(LEVEL)

# Run SHA3 tests
test-sha3: $(BIN_DIR)/test_sha3_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) SHA3 Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_sha3_$(LEVEL)

# Run detached signature tests
test-detached: $(BIN_DIR)/test_detached_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) Detached Signature Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_detached_$(LEVEL)

# Run DER encoding tests
test-der: $(BIN_DIR)/test_der_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) DER Encoding Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_der_$(LEVEL)

# Run KazWire encoding tests
test-kazwire: $(BIN_DIR)/test_kazwire_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) KazWire Encoding Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_kazwire_$(LEVEL)

# Run X.509 certificate tests
test-x509: $(BIN_DIR)/test_x509_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) X.509 Certificate Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_x509_$(LEVEL)

# Run PKCS#12 keystore tests
test-p12: $(BIN_DIR)/test_p12_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) PKCS#12 Keystore Tests"
	@echo "========================================"
	@$(BIN_DIR)/test_p12_$(LEVEL)

# Run all extension tests (SHA3 + Detached + DER + X509 + P12)
test-extensions: test-sha3 test-detached test-der test-x509 test-p12

# CI target: run all tests for all levels
ci: test-all

# ============================================================================
# Benchmark Targets
# ============================================================================

# Run benchmarks (default)
benchmark: $(BIN_DIR)/benchmark_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running KAZ-SIGN-$(LEVEL) Benchmarks"
	@echo "========================================"
	@$(BIN_DIR)/benchmark_sign_$(LEVEL) -i $(BENCH_ITERATIONS)

# Run benchmarks with CSV output
benchmark-csv: $(BIN_DIR)/benchmark_sign_$(LEVEL)
	@$(BIN_DIR)/benchmark_sign_$(LEVEL) -c -i $(BENCH_ITERATIONS)

# Run full benchmark suite (variable message sizes)
benchmark-full: $(BIN_DIR)/benchmark_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running Full KAZ-SIGN-$(LEVEL) Benchmark Suite"
	@echo "========================================"
	@$(BIN_DIR)/benchmark_sign_$(LEVEL) -v -i $(BENCH_ITERATIONS)

# Run benchmarks with SUPERCOP-style output
benchmark-supercop: $(BIN_DIR)/benchmark_sign_$(LEVEL)
	@$(BIN_DIR)/benchmark_sign_$(LEVEL) -s -i $(BENCH_ITERATIONS)

# Run benchmarks for all security levels
benchmark-all:
	@echo ""
	@echo "========================================"
	@echo "Benchmarking All Security Levels"
	@echo "========================================"
	@rm -rf $(BUILD_DIR)
	@$(MAKE) benchmark LEVEL=128 BENCH_ITERATIONS=$(BENCH_ITERATIONS)
	@rm -rf $(BUILD_DIR)
	@$(MAKE) benchmark LEVEL=192 BENCH_ITERATIONS=$(BENCH_ITERATIONS)
	@rm -rf $(BUILD_DIR)
	@$(MAKE) benchmark LEVEL=256 BENCH_ITERATIONS=$(BENCH_ITERATIONS)

# ============================================================================
# Timing Analysis
# ============================================================================

timing-test: $(BIN_DIR)/timing_test_$(LEVEL)
	@echo ""
	@$(BIN_DIR)/timing_test_$(LEVEL)

# Build dudect-style timing test
$(BIN_DIR)/dudect_test_$(LEVEL): $(TIMING_DIR)/dudect_test.c $(LIB_OBJS) | dirs
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIB_OBJS) $(LDFLAGS) $(LIBS) -lm

# Run dudect-style timing leakage detection
dudect: $(BIN_DIR)/dudect_test_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running Dudect Timing Analysis (Level $(LEVEL))"
	@echo "========================================"
	@$(BIN_DIR)/dudect_test_$(LEVEL)

# Run dudect with more measurements
dudect-thorough: $(BIN_DIR)/dudect_test_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Running Thorough Dudect Analysis (Level $(LEVEL))"
	@echo "========================================"
	@$(BIN_DIR)/dudect_test_$(LEVEL) -n 50000 -v

# ============================================================================
# Fuzz Testing
# ============================================================================

FUZZ_DIR = tests/fuzz
CORPUS_DIR = $(FUZZ_DIR)/corpus

# Build standalone fuzz harness (works with any compiler)
fuzz: $(BIN_DIR)/fuzz_standalone
	@echo "Fuzz harness built: $(BIN_DIR)/fuzz_standalone"
	@echo "Usage: $(BIN_DIR)/fuzz_standalone <input_file>"

# Build libFuzzer harness (requires clang with libFuzzer)
fuzz-libfuzzer: dirs
	@echo "Building libFuzzer harness..."
	@if command -v clang >/dev/null 2>&1; then \
		clang -g -O1 -fno-omit-frame-pointer \
			-fsanitize=fuzzer,address \
			-DKAZ_SECURITY_LEVEL=$(LEVEL) \
			$(INC) \
			$(FUZZ_DIR)/fuzz_libfuzzer.c $(LIB_SRCS) \
			$(LDFLAGS) $(LIBS) \
			-o $(BIN_DIR)/fuzz_libfuzzer_$(LEVEL) 2>/dev/null || \
		echo "Note: libFuzzer not available. Use 'make fuzz-afl' instead."; \
	else \
		echo "clang not found. Install LLVM for libFuzzer support."; \
	fi

# Build AFL++ harness
fuzz-afl: dirs
	@echo "Building AFL++ harness..."
	@if command -v afl-gcc >/dev/null 2>&1; then \
		AFL_DONT_OPTIMIZE=1 afl-gcc -g -O2 \
			-DKAZ_SECURITY_LEVEL=$(LEVEL) \
			$(INC) \
			$(FUZZ_DIR)/fuzz_afl.c $(LIB_SRCS) \
			$(LDFLAGS) $(LIBS) \
			-o $(BIN_DIR)/fuzz_afl_$(LEVEL); \
		echo "AFL++ harness built: $(BIN_DIR)/fuzz_afl_$(LEVEL)"; \
	else \
		echo "afl-gcc not found. Building standalone version..."; \
		$(CC) $(CFLAGS) $(INC) \
			$(FUZZ_DIR)/fuzz_afl.c $(LIB_SRCS) \
			$(LDFLAGS) $(LIBS) \
			-o $(BIN_DIR)/fuzz_afl_standalone_$(LEVEL); \
		echo "Standalone harness built: $(BIN_DIR)/fuzz_afl_standalone_$(LEVEL)"; \
	fi

# Run fuzz tests on corpus
fuzz-corpus: $(BIN_DIR)/fuzz_standalone
	@echo ""
	@echo "========================================"
	@echo "Running Fuzz Corpus Tests (Level $(LEVEL))"
	@echo "========================================"
	@for f in $(CORPUS_DIR)/*.bin; do \
		if [ -f "$$f" ]; then \
			echo "Testing: $$f"; \
			$(BIN_DIR)/fuzz_standalone "$$f" || exit 1; \
		fi \
	done
	@echo ""
	@echo "All corpus tests passed!"

# Quick fuzz test with random inputs
fuzz-quick: $(BIN_DIR)/fuzz_standalone
	@echo ""
	@echo "========================================"
	@echo "Running Quick Fuzz Tests (Level $(LEVEL))"
	@echo "========================================"
	@for size in 1 10 50 100 500 1000 5000 10000; do \
		echo "Testing with $$size random bytes..."; \
		dd if=/dev/urandom bs=$$size count=1 2>/dev/null | $(BIN_DIR)/fuzz_standalone /dev/stdin || exit 1; \
	done
	@echo ""
	@echo "Quick fuzz tests passed!"

# ============================================================================
# KAT (Known Answer Test) Targets
# ============================================================================

# Generate KAT files for current security level
kat: $(BIN_DIR)/PQCgenKAT_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Generating KAT Files for KAZ-SIGN-$(LEVEL)"
	@echo "========================================"
	@$(BIN_DIR)/PQCgenKAT_sign_$(LEVEL) generate

# Generate KAT files for all security levels
kat-all:
	@echo ""
	@echo "========================================"
	@echo "Generating KAT Files for All Security Levels"
	@echo "========================================"
	@rm -rf $(BUILD_DIR)
	@$(MAKE) kat LEVEL=128
	@rm -rf $(BUILD_DIR)
	@$(MAKE) kat LEVEL=192
	@rm -rf $(BUILD_DIR)
	@$(MAKE) kat LEVEL=256

# Verify KAT file
kat-verify: $(BIN_DIR)/PQCgenKAT_sign_$(LEVEL)
	@echo ""
	@echo "========================================"
	@echo "Verifying KAT File for KAZ-SIGN-$(LEVEL)"
	@echo "========================================"
	@$(BIN_DIR)/PQCgenKAT_sign_$(LEVEL) verify PQCsignKAT_$(LEVEL).rsp

# ============================================================================
# Shared Library (for C#, Python, etc. bindings)
# ============================================================================

# Shared library name varies by platform
ifeq ($(UNAME_S),Darwin)
    SHARED_EXT = dylib
    SHARED_FLAGS = -dynamiclib -install_name @rpath/libkazsign.$(SHARED_EXT)
    SHARED_FLAGS_UNIFIED = -dynamiclib -install_name @rpath/libkazsign.$(SHARED_EXT)
else
    SHARED_EXT = so
    SHARED_FLAGS = -shared -Wl,-soname,libkazsign.$(SHARED_EXT)
    SHARED_FLAGS_UNIFIED = -shared -Wl,-soname,libkazsign.$(SHARED_EXT)
endif

SHARED_LIB = $(LIB_DIR)/libkazsign_$(LEVEL).$(SHARED_EXT)
UNIFIED_LIB = $(LIB_DIR)/libkazsign.$(SHARED_EXT)

# Build shared library (single level, for backwards compatibility)
shared: dirs $(LIB_OBJS)
	@echo ""
	@echo "========================================"
	@echo "Building Shared Library (Level $(LEVEL))"
	@echo "========================================"
	$(CC) $(SHARED_FLAGS) -fPIC -o $(SHARED_LIB) $(LIB_OBJS) $(LDFLAGS) $(LIBS)
	@echo "Built: $(SHARED_LIB)"

# Build all shared libraries (all security levels)
# Note: We preserve built libraries across clean cycles
shared-all:
	@echo ""
	@echo "========================================"
	@echo "Building Shared Libraries (All Levels)"
	@echo "========================================"
	@mkdir -p $(LIB_DIR)
	@rm -f $(OBJ_DIR)/*.o
	@$(MAKE) shared LEVEL=128
	@rm -f $(OBJ_DIR)/*.o
	@$(MAKE) shared LEVEL=192
	@rm -f $(OBJ_DIR)/*.o
	@$(MAKE) shared LEVEL=256
	@echo ""
	@echo "Built shared libraries for all security levels:"
	@ls -la $(LIB_DIR)/*.$(SHARED_EXT) 2>/dev/null || true

# ============================================================================
# Unified Shared Library (Runtime Level Selection - v2.1+)
# ============================================================================
# This builds a single library with runtime security level selection.
# The library uses compile-time level 128 as default but supports all levels
# via the kaz_sign_*_ex() functions.

UNIFIED_OBJS = $(OBJ_DIR)/sign_unified.o \
               $(OBJ_DIR)/nist_wrapper_unified.o \
               $(OBJ_DIR)/security_unified.o \
               $(OBJ_DIR)/kdf_unified.o \
               $(OBJ_DIR)/sha3_unified.o \
               $(OBJ_DIR)/detached_unified.o \
               $(OBJ_DIR)/der_unified.o \
               $(OBJ_DIR)/x509_unified.o \
               $(OBJ_DIR)/p12_unified.o

$(OBJ_DIR)/sign_unified.o: $(SRC_DIR)/sign.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/nist_wrapper_unified.o: $(SRC_DIR)/nist_wrapper.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/security_unified.o: $(SRC_DIR)/security.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/kdf_unified.o: $(SRC_DIR)/kdf.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/sha3_unified.o: $(SRC_DIR)/sha3.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/detached_unified.o: $(SRC_DIR)/detached.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/der_unified.o: $(SRC_DIR)/der.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/x509_unified.o: $(SRC_DIR)/x509.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

$(OBJ_DIR)/p12_unified.o: $(SRC_DIR)/p12.c | dirs
	$(CC) $(CFLAGS) -fPIC -DKAZ_SECURITY_LEVEL=128 $(INC) -c $< -o $@

# Build unified shared library with runtime level selection
shared-unified: dirs $(UNIFIED_OBJS)
	@echo ""
	@echo "========================================"
	@echo "Building Unified Shared Library"
	@echo "(Runtime Security Level Selection)"
	@echo "========================================"
	$(CC) $(SHARED_FLAGS_UNIFIED) -fPIC -o $(UNIFIED_LIB) $(UNIFIED_OBJS) $(LDFLAGS) $(LIBS)
	@echo "Built: $(UNIFIED_LIB)"
	@echo ""
	@echo "This library supports runtime level selection via:"
	@echo "  - kaz_sign_init_level(level)"
	@echo "  - kaz_sign_keypair_ex(level, pk, sk)"
	@echo "  - kaz_sign_signature_ex(level, sig, siglen, msg, msglen, sk)"
	@echo "  - kaz_sign_verify_ex(level, msg, msglen, sig, siglen, pk)"
	@echo "  - kaz_sign_hash_ex(level, msg, msglen, hash)"

# ============================================================================
# Utility Targets
# ============================================================================

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o *.req *.rsp

# Deep clean including KAT files
distclean: clean
	rm -f PQCsignKAT_*.req PQCsignKAT_*.rsp

# Show help
help:
	@echo "KAZ-SIGN Build System (OpenSSL Constant-Time Backend)"
	@echo ""
	@echo "Test Targets:"
	@echo "  make test LEVEL=<128|192|256>           Build and run tests"
	@echo "  make test-verbose LEVEL=<128|192|256>   Run tests with verbose output"
	@echo "  make test-quick LEVEL=<128|192|256>     Run quick smoke tests"
	@echo "  make test-kdf LEVEL=<128|192|256>       Run KDF unit tests"
	@echo "  make test-sha3 LEVEL=<128|192|256>      Run SHA3-256 tests"
	@echo "  make test-detached LEVEL=<128|192|256>  Run detached signing tests"
	@echo "  make test-der LEVEL=<128|192|256>       Run DER encoding tests"
	@echo "  make test-x509 LEVEL=<128|192|256>     Run X.509 certificate tests"
	@echo "  make test-p12 LEVEL=<128|192|256>       Run PKCS#12 keystore tests"
	@echo "  make test-extensions LEVEL=<128|192|256> Run all extension tests"
	@echo "  make test-all                           Test all security levels"
	@echo ""
	@echo "Benchmark Targets:"
	@echo "  make benchmark LEVEL=<128|192|256>      Run standard benchmarks"
	@echo "  make benchmark-csv LEVEL=<128|192|256>  Output benchmarks as CSV"
	@echo "  make benchmark-full LEVEL=<128|192|256> Run with variable message sizes"
	@echo "  make benchmark-all                      Benchmark all security levels"
	@echo ""
	@echo "Security Testing:"
	@echo "  make timing-test LEVEL=<128|192|256>    Run timing variance analysis"
	@echo "  make dudect LEVEL=<128|192|256>         Run dudect timing leakage test"
	@echo "  make dudect-thorough LEVEL=<128|192|256> Run thorough dudect analysis"
	@echo ""
	@echo "Fuzz Testing:"
	@echo "  make fuzz                               Build standalone fuzz harness"
	@echo "  make fuzz-libfuzzer LEVEL=<128|192|256> Build libFuzzer harness (clang)"
	@echo "  make fuzz-afl LEVEL=<128|192|256>       Build AFL++ harness"
	@echo "  make fuzz-corpus LEVEL=<128|192|256>    Test fuzz corpus"
	@echo "  make fuzz-quick LEVEL=<128|192|256>     Quick random fuzz test"
	@echo ""
	@echo "KAT Targets:"
	@echo "  make kat LEVEL=<128|192|256>            Generate KAT files"
	@echo "  make kat-all                            Generate KAT for all levels"
	@echo "  make kat-verify LEVEL=<128|192|256>     Verify KAT file"
	@echo ""
	@echo "Library Targets:"
	@echo "  make shared LEVEL=<128|192|256>         Build shared library (.so/.dylib)"
	@echo "  make shared-all                         Build shared libs for all levels"
	@echo "  make shared-unified                     Build unified lib (runtime levels)"
	@echo ""
	@echo "Utility Targets:"
	@echo "  make clean                              Clean build artifacts"
	@echo "  make distclean                          Clean including KAT files"
	@echo "  make help                               Show this help"
	@echo ""
	@echo "Options:"
	@echo "  LEVEL            Security level: 128, 192, or 256 (default: 128)"
	@echo "  BENCH_ITERATIONS Number of benchmark iterations (default: 1000)"
