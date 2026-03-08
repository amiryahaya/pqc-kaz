# KAZ-SIGN

[![CI](https://github.com/USER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/REPO/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-NIST-green.svg)](LICENSE)

A post-quantum digital signature algorithm implementation supporting NIST security levels 128, 192, and 256.

**Version 2.1.0** - Runtime security level selection with multi-platform bindings.

## Features

- **Multiple Security Levels**: Runtime OR compile-time selection of 128, 192, or 256-bit security
- **Constant-Time Operations**: OpenSSL BIGNUM with `BN_FLG_CONSTTIME` for timing attack resistance
- **HKDF Key Derivation**: RFC 5869 compliant key derivation function
- **Comprehensive Testing**: 52 unit tests (36 sign + 16 KDF), fuzz testing, timing analysis
- **NIST API Compatible**: Standard `crypto_sign_*` interface
- **Multi-Platform Bindings**: C#/.NET, Swift/iOS, Kotlin/Android

## Requirements

- GCC or Clang compiler
- OpenSSL 3.x (for cryptographic primitives)
- macOS or Linux

### macOS (Homebrew)

```bash
brew install openssl@3
```

### Ubuntu/Debian

```bash
sudo apt-get install libssl-dev
```

## Quick Start

```bash
# Build and run tests (default: Level 128)
make test

# Build for specific security level
make test LEVEL=192
make test LEVEL=256

# Run all security levels
make test-all
```

## API Usage

### Key Generation

```c
#include "kaz/sign.h"

unsigned char pk[KAZ_SIGN_PUBLICKEYBYTES];
unsigned char sk[KAZ_SIGN_SECRETKEYBYTES];

// Initialize random state (required once)
kaz_sign_init_random();

// Generate key pair
int ret = kaz_sign_keypair(pk, sk);
if (ret != KAZ_SIGN_SUCCESS) {
    // Handle error
}
```

### Signing

```c
unsigned char *msg = (unsigned char *)"Hello, World!";
unsigned long long msglen = 13;

unsigned char sig[KAZ_SIGN_SIGNATURE_OVERHEAD + 13];
unsigned long long siglen;

int ret = kaz_sign_signature(sig, &siglen, msg, msglen, sk);
if (ret != KAZ_SIGN_SUCCESS) {
    // Handle error
}
```

### Verification

```c
unsigned char recovered[13];
unsigned long long recovered_len;

int ret = kaz_sign_verify(recovered, &recovered_len, sig, siglen, pk);
if (ret == KAZ_SIGN_SUCCESS) {
    // Signature valid, message in 'recovered'
} else {
    // Invalid signature
}
```

### Cleanup

```c
// Clear random state when done
kaz_sign_clear_random();
```

## Runtime Security Level API (v2.1+)

Version 2.1 introduces runtime security level selection, allowing a single binary to support all security levels:

### Level Introspection

```c
#include "kaz/sign.h"

// Get parameters for any security level
const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_192);
printf("Public key size: %zu bytes\n", params->public_key_bytes);
printf("Signature overhead: %zu bytes\n", params->signature_overhead);
```

### Runtime Key Generation

```c
// Initialize for a specific level
kaz_sign_init_level(KAZ_LEVEL_256);

// Allocate buffers based on level parameters
const kaz_sign_level_params_t *params = kaz_sign_get_level_params(KAZ_LEVEL_256);
unsigned char *pk = malloc(params->public_key_bytes);
unsigned char *sk = malloc(params->secret_key_bytes);

// Generate keys for that level
kaz_sign_keypair_ex(KAZ_LEVEL_256, pk, sk);
```

### Runtime Signing & Verification

```c
// Sign with runtime level selection
unsigned char sig[512];  // Large enough for any level
unsigned long long siglen;
kaz_sign_signature_ex(KAZ_LEVEL_256, sig, &siglen, msg, msglen, sk);

// Verify with same level
unsigned char recovered[100];
unsigned long long recovered_len;
int ret = kaz_sign_verify_ex(KAZ_LEVEL_256, recovered, &recovered_len,
                              sig, siglen, pk);

// Cleanup when done
kaz_sign_clear_level(KAZ_LEVEL_256);
// Or clear all: kaz_sign_clear_all();
```

### Available Security Levels

| Enum | Value | Description |
|------|-------|-------------|
| `KAZ_LEVEL_128` | 128 | 128-bit security (SHA-256) |
| `KAZ_LEVEL_192` | 192 | 192-bit security (SHA-384) |
| `KAZ_LEVEL_256` | 256 | 256-bit security (SHA-512) |

## Security Levels

| Level | Secret Key | Public Key | Signature | Hash |
|-------|------------|------------|-----------|------|
| 128 | 32 bytes | 54 bytes | 162 bytes | SHA-256 |
| 192 | 50 bytes | 88 bytes | 264 bytes | SHA-384 |
| 256 | 64 bytes | 118 bytes | 356 bytes | SHA-512 |

## Build Targets

### Testing

```bash
make test LEVEL=128              # Run unit tests
make test-verbose LEVEL=128      # Verbose test output
make test-kdf LEVEL=128          # Run KDF tests
make test-all                    # Test all security levels
```

### Benchmarks

```bash
make benchmark LEVEL=128         # Run benchmarks
make benchmark-csv LEVEL=128     # CSV output
make benchmark-all               # All security levels
```

### Security Testing

```bash
make timing-test LEVEL=128       # Timing variance analysis
make dudect LEVEL=128            # Dudect timing leakage test
make dudect-thorough LEVEL=128   # Extended dudect (50k samples)
```

### Fuzz Testing

```bash
make fuzz                        # Build standalone fuzzer
make fuzz-quick LEVEL=128        # Quick random fuzz test
make fuzz-corpus LEVEL=128       # Test seed corpus
make fuzz-libfuzzer LEVEL=128    # Build libFuzzer harness
make fuzz-afl LEVEL=128          # Build AFL++ harness
```

### KAT (Known Answer Tests)

```bash
make kat LEVEL=128               # Generate KAT files
make kat-all                     # Generate for all levels
```

## Project Structure

```
.
├── .github/workflows/  # CI/CD workflows
│   └── ci.yml          # GitHub Actions CI
├── include/kaz/
│   ├── sign.h          # Main API header (version info)
│   ├── kdf.h           # Key derivation functions
│   ├── security.h      # Security utilities
│   └── nist_api.h      # NIST-compatible API
├── src/internal/
│   ├── sign.c          # Core implementation
│   ├── kdf.c           # HKDF implementation
│   ├── security.c      # Security state management
│   └── nist_wrapper.c  # NIST API wrapper
├── tests/
│   ├── unit/           # Unit tests (28 sign + 16 KDF)
│   ├── timing/         # Timing analysis (dudect)
│   └── fuzz/           # Fuzz testing (libFuzzer, AFL++)
├── benchmarks/         # Performance benchmarks
├── tools/              # KAT generator
├── Makefile
├── VERSION             # Version file (2.0.0)
├── LICENSE             # NIST public domain license
├── SECURITY.md         # Security documentation
└── README.md
```

## Performance

Benchmarks on Apple M1 (operations per second):

| Operation | Level 128 | Level 192 | Level 256 |
|-----------|-----------|-----------|-----------|
| KeyGen | ~30,000 | ~10,000 | ~7,000 |
| Sign | ~4,500 | ~2,300 | ~1,600 |
| Verify | ~12,000 | ~3,500 | ~1,400 |

Run `make benchmark LEVEL=<level>` for detailed statistics.

## Security Considerations

This implementation includes several security hardening measures:

- **Constant-time modular exponentiation** via `BN_mod_exp_mont_consttime()`
- **Secure memory zeroization** with `kaz_secure_zero()`
- **Constant-time comparisons** with `kaz_ct_memcmp()`
- **HKDF key derivation** per RFC 5869

**Warning**: This implementation has NOT been externally audited. See [SECURITY.md](SECURITY.md) for details.

## Language Bindings

KAZ-SIGN provides official bindings for multiple platforms:

### C# / .NET

```bash
cd bindings/csharp
dotnet build
dotnet test
```

Supports: .NET 8/9/10, WinUI 3, .NET MAUI

### Swift / iOS / macOS

```bash
cd bindings/swift
swift build
swift test
```

Supports: iOS 14+, macOS 11+, visionOS

### Kotlin / Android

```bash
cd bindings/android
./gradlew :kazsign:assembleRelease
```

Supports: Android API 24+, arm64-v8a, x86_64

## Testing Status

- Unit Tests: 36 sign tests + 16 KDF tests + 8 runtime level tests (all passing)
- Memory Safety: AddressSanitizer clean
- Memory Leaks: 0 leaks (macOS Leaks tool)
- Static Analysis: Clang scan-build clean
- Timing Analysis: Dudect timing leakage detection
- Fuzz Testing: Harnesses for libFuzzer and AFL++

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `KAZ_SIGN_SUCCESS` | Operation successful |
| -1 | `KAZ_SIGN_ERROR_MEMORY` | Memory allocation failed |
| -2 | `KAZ_SIGN_ERROR_RNG` | Random number generation failed |
| -3 | `KAZ_SIGN_ERROR_INVALID` | Invalid parameter |
| -4 | `KAZ_SIGN_ERROR_VERIFY` | Signature verification failed |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `make test-all`
4. Run security checks: `make dudect LEVEL=128`
5. Submit a pull request

## License

NIST-developed software. See [LICENSE](LICENSE) for details.

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [RFC 5869 - HKDF](https://tools.ietf.org/html/rfc5869)
- [OpenSSL BIGNUM Documentation](https://www.openssl.org/docs/man3.0/man3/BN_mod_exp_mont_consttime.html)
