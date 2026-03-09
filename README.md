# PQC-KAZ

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

**Kriptografi Atasi Zarah** (KAZ) — a Malaysian post-quantum cryptography algorithm suite.

KAZ provides two primitives built on number-theoretic hardness assumptions designed to resist quantum attacks:

| Primitive | Purpose | Directory |
|-----------|---------|-----------|
| **KAZ-KEM** | Key Encapsulation Mechanism | [`KEM/`](KEM/) |
| **KAZ-SIGN** | Digital Signature | [`SIGN/`](SIGN/) |

Both support NIST security levels **128**, **192**, and **256-bit** with OpenSSL constant-time backends.

## Algorithm Overview

### KAZ-KEM (Key Encapsulation)

Algebraic KEM based on the hardness of computing discrete logarithms in composite-order groups.

- **Generators:** g1 = 7, g2 = 23
- **Key generation:** Public key (E1, E2) derived from private exponents (a1, a2) via modular exponentiation
- **Encapsulation:** Masks a shared secret with the recipient's public key
- **Decapsulation:** Recovers the secret using private exponents
- No hash functions in the core algorithm — purely algebraic

| Level | Public Key | Private Key | Ciphertext |
|-------|-----------|-------------|------------|
| 128 | 108 bytes | 34 bytes | 162 bytes |
| 192 | 176 bytes | 50 bytes | 264 bytes |
| 256 | 236 bytes | 66 bytes | 354 bytes |

### KAZ-SIGN (Digital Signature)

Three-component signature scheme (S1, S2, S3) with message recovery.

- **Generators:** g1 = 65537, g2 = 65539
- **Hash:** SHA-256 (zero-padded to level-specific length)
- **Signing:** Produces (S1, S2, S3) components via modular exponentiation over RSA-like modulus N
- **Verification:** Single equation `V^S1 * S1^S2 * g2^S3 = (g1*g2)^h mod N`
- Supports message-recovery and detached signature modes

| Level | Public Key | Private Key | Signature Overhead |
|-------|-----------|-------------|-------------------|
| 128 | 54 bytes | 32 bytes | 162 bytes |
| 192 | 88 bytes | 50 bytes | 264 bytes |
| 256 | 118 bytes | 64 bytes | 354 bytes |

## Quick Start

### Prerequisites

```bash
# macOS
brew install openssl@3 gmp

# Ubuntu/Debian
sudo apt-get install libssl-dev libgmp-dev
```

### Build & Test

```bash
# KAZ-KEM
cd KEM
make test-all

# KAZ-SIGN
cd SIGN
make test-all
```

### Usage (KAZ-KEM)

```c
#include "kaz/kem.h"

// Initialize for desired security level
kaz_kem_init(KAZ_KEM_LEVEL_128);

unsigned char pk[108], sk[34], ct[162], ss[54];

kaz_kem_keypair(pk, sk);            // Generate keypair
kaz_kem_encapsulate(ct, ss, pk);    // Encapsulate shared secret
kaz_kem_decapsulate(ss, ct, sk);    // Decapsulate

kaz_kem_cleanup();
```

### Usage (KAZ-SIGN)

```c
#include "kaz/sign.h"

unsigned char pk[54], sk[32];
unsigned char sig[256], recovered[128];
unsigned long long siglen, recovered_len;

// Runtime level selection
kaz_sign_keypair_ex(KAZ_LEVEL_128, pk, sk);

kaz_sign_signature_ex(KAZ_LEVEL_128, sig, &siglen,
                      msg, msglen, sk);

kaz_sign_verify_ex(KAZ_LEVEL_128, recovered, &recovered_len,
                   sig, siglen, pk);
```

## Language Bindings

Both libraries provide bindings for multiple platforms:

| Language | KAZ-KEM | KAZ-SIGN |
|----------|---------|----------|
| C# / .NET 8-10 | [`KEM/bindings/dotnet/`](KEM/bindings/dotnet/) | [`SIGN/bindings/csharp/`](SIGN/bindings/csharp/) |
| Swift / iOS / macOS | [`KEM/bindings/swift/`](KEM/bindings/swift/) | [`SIGN/bindings/swift/`](SIGN/bindings/swift/) |
| Kotlin / Android | [`KEM/bindings/android/`](KEM/bindings/android/) | [`SIGN/bindings/android/`](SIGN/bindings/android/) |
| Elixir (NIF) | [`KEM/bindings/elixir/`](KEM/bindings/elixir/) | [`SIGN/bindings/elixir/`](SIGN/bindings/elixir/) |

## Java Reference Implementation

The Java reference implementation is available at [kaz-pqc-core-v2.0](https://github.com/AntRapol/kaz-pqc-core-v2.0). The C implementations have been verified for full interoperability with Java across all security levels.

## Project Structure

```
PQC-KAZ/
├── KEM/                    # Key Encapsulation Mechanism
│   ├── include/kaz/        # Public API headers
│   ├── src/internal/       # Core implementation (OpenSSL)
│   ├── tests/unit/         # Unit tests
│   ├── benchmarks/         # Performance benchmarks
│   └── bindings/           # Language bindings
├── SIGN/                   # Digital Signature
│   ├── include/kaz/        # Public API headers
│   ├── src/internal/       # Core implementation (OpenSSL)
│   ├── tests/              # Unit, timing, fuzz, interop tests
│   ├── benchmarks/         # Performance benchmarks
│   └── bindings/           # Language bindings
└── README.md               # This file
```

## Security

- Constant-time modular exponentiation via `BN_mod_exp_mont_consttime()`
- Secure memory zeroization via `kaz_secure_zero()`
- Constant-time comparisons via `kaz_ct_memcmp()`
- HKDF key derivation (RFC 5869) for KAZ-SIGN

**This implementation has NOT been externally audited. Use for research and prototyping only.**

## License

MIT License. See [LICENSE](LICENSE) for details.
