# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PQC-KAZ is a post-quantum cryptography library implementing two algorithms:
- **KEM/** - KAZ-KEM (Key Encapsulation Mechanism) for key exchange
- **SIGN/** - KAZ-SIGN (Digital Signature) for authentication

Both support NIST security levels 128, 192, and 256-bit with OpenSSL constant-time backends.

## Build Commands

### KEM (in KEM/ directory)
```bash
make test LEVEL=128              # Run tests for security level 128/192/256
make test-all                    # Test all security levels
make benchmark LEVEL=128         # Run benchmarks
make bench-all                   # Benchmark all levels
make memcheck LEVEL=128          # Valgrind memory check
make kat LEVEL=128               # Generate Known Answer Test vectors
make ci                          # Run CI tests (all levels)
```

### SIGN (in SIGN/ directory)
```bash
make test LEVEL=128              # Run tests for security level
make test-all                    # Test all security levels
make test-kdf LEVEL=128          # Run KDF-specific tests
make benchmark LEVEL=128         # Run benchmarks
make benchmark-all               # Benchmark all levels
make timing-test LEVEL=128       # Timing variance analysis
make dudect LEVEL=128            # Dudect timing leakage detection
make fuzz-quick LEVEL=128        # Quick random fuzz test
make kat LEVEL=128               # Generate KAT files
make shared LEVEL=128            # Build shared library (.so/.dylib)
make shared-unified              # Build unified lib with runtime level selection
```

### Prerequisites
```bash
# macOS
brew install openssl@3 gmp

# Ubuntu/Debian
sudo apt-get install libssl-dev libgmp-dev
```

## Architecture

### Directory Structure (both KEM/ and SIGN/)
```
include/kaz/          # Public API headers
src/internal/         # Implementation (constant-time OpenSSL backend)
tests/unit/           # Unit tests
tests/timing/         # Timing analysis tests (SIGN only)
tests/fuzz/           # Fuzz testing harnesses (SIGN only)
benchmarks/           # Performance benchmarks
bindings/             # Language bindings (Android, Swift, C#/.NET)
build/                # Build artifacts (created by make)
```

### Core Implementation Files

**KEM:**
- `include/kaz/kem.h` - Main KEM API with runtime level selection
- `include/kaz/nist_api.h` - NIST standard `crypto_kem_*` interface
- `src/internal/kem_secure.c` - OpenSSL constant-time implementation

**SIGN:**
- `include/kaz/sign.h` - Main Sign API with runtime level selection (`kaz_sign_*_ex`)
- `include/kaz/kdf.h` - HKDF key derivation (RFC 5869)
- `include/kaz/security.h` - Constant-time utilities (`kaz_ct_memcmp`, `kaz_secure_zero`)
- `src/internal/sign.c` - Core signing with `BN_mod_exp_mont_consttime`
- `src/internal/kdf.c` - HKDF implementation

### API Patterns

Both libraries support:
1. **Compile-time level selection**: `make test LEVEL=192`
2. **Runtime level selection**: `kaz_sign_*_ex(KAZ_LEVEL_192, ...)` functions

NIST-compatible API (`crypto_kem_keypair`, `crypto_sign`, etc.) uses compile-time levels.

### Language Bindings

**SIGN bindings (in SIGN/bindings/):**
- `csharp/` - .NET 8/9/10, WinUI 3, MAUI
- `swift/` - iOS 14+, macOS 11+, visionOS
- `android/` - Kotlin/JNI, API 24+, arm64-v8a/x86_64

**KEM bindings (in KEM/bindings/):**
- `android/` - Android NDK build with OpenSSL
- `dotnet/` - .NET binding
- `swift/` - Swift/iOS binding

## Security Notes

- Uses `BN_FLG_CONSTTIME` for timing attack resistance
- Secure memory zeroization via `kaz_secure_zero()` with volatile pointers
- NOT audited for production use - suitable for research/prototyping
- See `SIGN/SECURITY.md` for detailed security considerations
