# Migration Guide: KEM-Combined → KEM-Combined-Organized

## Overview

This guide explains the reorganization from the flat `KEM-Combined/` directory structure to the organized `KEM-Combined-Organized/` structure following C programming best practices.

## Directory Structure Changes

### Old Structure (KEM-Combined/)
```
KEM-Combined/
├── kaz_api.h                    # Public header
├── kaz_api_optimized.h          # Optimized header
├── api.h                        # NIST API
├── kaz_api.c                    # Implementation
├── kaz_api_optimized.c          # Optimized implementation
├── kem.c                        # NIST wrapper
├── rng.c / rng.h                # RNG
├── gmp.h / rotate-bits.h        # Utilities
├── test_kem.c                   # Tests
├── benchmark_kem.c              # Benchmarks
├── PQCgenKAT_kem.c              # KAT generator
├── run_tests.sh                 # Test script
├── Makefile                     # Build original
├── Makefile.optimized           # Build optimized
├── Makefile.test                # Build tests
└── *.md                         # Documentation
```

### New Structure (KEM-Combined-Organized/)
```
KEM-Combined-Organized/
├── include/kaz/                 # Public API headers
│   ├── kem.h                   # (was: kaz_api.h)
│   ├── kem_optimized.h         # (was: kaz_api_optimized.h)
│   └── nist_api.h              # (was: api.h)
│
├── src/internal/                # Implementation (not public)
│   ├── kem.c                   # (was: kaz_api.c)
│   ├── kem_optimized.c         # (was: kaz_api_optimized.c)
│   ├── nist_wrapper.c          # (was: kem.c)
│   ├── rng.c / rng.h           # (unchanged)
│   ├── gmp.h                   # (unchanged)
│   └── rotate-bits.h           # (unchanged)
│
├── tests/unit/                  # Unit tests
│   ├── test_kem.c              # (unchanged)
│   └── PQCgenKAT_kem.c         # (unchanged)
│
├── benchmarks/                  # Benchmarks
│   └── benchmark_kem.c         # (unchanged)
│
├── scripts/                     # Scripts
│   └── run_tests.sh            # (unchanged)
│
├── docs/                        # All documentation
│   └── *.md                    # (moved from root)
│
├── build/                       # Build artifacts (new)
│   ├── bin/                    # Executables
│   ├── obj/                    # Object files
│   └── lib/                    # Libraries
│
├── Makefile                     # Single unified Makefile
└── README.md                    # Updated documentation
```

## File Renaming Reference

| Old Name | New Location | New Name | Reason |
|----------|--------------|----------|--------|
| `kaz_api.h` | `include/kaz/` | `kem.h` | Clearer naming |
| `kaz_api_optimized.h` | `include/kaz/` | `kem_optimized.h` | Clearer naming |
| `api.h` | `include/kaz/` | `nist_api.h` | More descriptive |
| `kaz_api.c` | `src/internal/` | `kem.c` | Match header name |
| `kaz_api_optimized.c` | `src/internal/` | `kem_optimized.c` | Match header name |
| `kem.c` | `src/internal/` | `nist_wrapper.c` | Clarify purpose |
| All `.md` files | `docs/` | (unchanged) | Organized location |
| `run_tests.sh` | `scripts/` | (unchanged) | Organized location |

## Code Migration

### Include Path Changes

**Old code (KEM-Combined/):**
```c
#include "kaz_api.h"
#include "api.h"
```

**New code (KEM-Combined-Organized/):**
```c
#include "kaz/kem.h"
#include "kaz/nist_api.h"
```

### Compilation Changes

**Old:**
```bash
gcc -o myprogram myprogram.c kaz_api.c kem.c rng.c \
    -I. -I/usr/local/include \
    -L/usr/local/lib -lcrypto -lgmp
```

**New:**
```bash
gcc -o myprogram myprogram.c \
    src/internal/kem.c \
    src/internal/nist_wrapper.c \
    src/internal/rng.c \
    -Iinclude -Isrc/internal \
    -I/usr/local/include \
    -L/usr/local/lib -lcrypto -lgmp
```

**Or use the Makefile:**
```bash
make test LEVEL=128
```

## Build System Changes

### Old Build System (3 separate Makefiles)

```bash
# For original implementation
make -f Makefile LEVEL=128

# For optimized implementation
make -f Makefile.optimized LEVEL=128

# For tests
make -f Makefile.test test LEVEL=128
```

### New Build System (Unified Makefile)

```bash
# For tests with optimized (default)
make test LEVEL=128

# For tests with original
make test LEVEL=128 USE_OPTIMIZED=0

# For benchmarks
make benchmark LEVEL=128

# All-in-one
make test-all
make bench-all
```

## Key Improvements

### 1. Clear Separation of Concerns

**Public API** (`include/kaz/`):
- Only headers that users should include
- Clean namespace under `kaz/`
- Version-stable interface

**Internal Implementation** (`src/internal/`):
- Implementation details hidden
- Can change without affecting users
- Not meant for direct inclusion

### 2. Organized Testing

**Old:** Tests scattered in root
**New:** Dedicated `tests/unit/` directory

Benefits:
- Easy to find all tests
- Can add more test categories (e.g., `tests/integration/`)
- Clear separation from source code

### 3. Centralized Documentation

**Old:** `.md` files in root alongside code
**New:** All documentation in `docs/`

Benefits:
- Easy to find documentation
- Cleaner root directory
- Professional appearance

### 4. Build Artifact Management

**Old:** Build artifacts scattered in root
**New:** All in `build/` subdirectories

Benefits:
- Clean working directory
- Easy to clean (`rm -rf build`)
- Organized by type (bin/obj/lib)

### 5. Unified Build System

**Old:** 3 separate Makefiles
**New:** Single Makefile with options

Benefits:
- Single source of truth
- Easier to maintain
- Consistent behavior

## Breaking Changes

### 1. Include Paths
```c
// Old
#include "kaz_api.h"

// New
#include "kaz/kem.h"
```

### 2. Header File Names
- `api.h` → `nist_api.h`
- `kaz_api.h` → `kem.h`
- `kaz_api_optimized.h` → `kem_optimized.h`

### 3. Makefile Commands
```bash
# Old
make -f Makefile.test test LEVEL=128

# New
make test LEVEL=128
```

### 4. Build Output Locations
```bash
# Old: Executables in root directory
./test_kem_128

# New: Executables in build/bin/
./build/bin/test_kem_128

# But Makefile runs them automatically:
make test
```

## Migration Checklist

If you have existing code using KEM-Combined:

- [ ] Update include statements to use `kaz/` prefix
- [ ] Change `api.h` to `nist_api.h`
- [ ] Change `kaz_api.h` to `kem.h`
- [ ] Update compilation commands to use new paths
- [ ] Use new Makefile targets instead of old Makefile names
- [ ] Update any scripts that reference old file locations
- [ ] Update documentation references

## Compatibility Notes

### Source Code Compatibility

The **API is unchanged** - only the include paths changed:

```c
// These function calls remain identical:
crypto_kem_keypair(pk, sk);
crypto_kem_enc(ct, ss, pk);
crypto_kem_dec(ss, ct, sk);
```

### Binary Compatibility

Compiled libraries/executables are **binary compatible** - the generated code is identical, only the build organization changed.

## Advantages of New Structure

1. **Industry Standard**: Follows conventions from OpenSSL, libsodium, Linux kernel
2. **Scalability**: Easy to add more modules without clutter
3. **Maintainability**: Clear where everything belongs
4. **Professional**: Looks like a mature, well-maintained project
5. **Build System**: Single unified Makefile instead of 3 separate ones
6. **Clean Workspace**: Build artifacts separated from source
7. **Documentation**: Easy to find and navigate
8. **Testing**: Organized test hierarchy
9. **Future-Proof**: Easy to add more categories (e.g., examples/, tools/)

## Side-by-Side Command Comparison

| Task | Old Command | New Command |
|------|-------------|-------------|
| Build tests (optimized) | `make -f Makefile.test test LEVEL=128` | `make test LEVEL=128` |
| Build tests (original) | `make -f Makefile.test test LEVEL=128 USE_OPTIMIZED=0` | `make test LEVEL=128 USE_OPTIMIZED=0` |
| Run benchmarks | `make -f Makefile.test benchmark LEVEL=128` | `make benchmark LEVEL=128` |
| Test all levels | `make -f Makefile.test test-all` | `make test-all` |
| Compare implementations | `make -f Makefile.test compare` | `make compare` |
| Clean | `make -f Makefile.test clean` | `make clean` |
| Memory check | `make -f Makefile.test memcheck` | `make memcheck` |
| Help | `make -f Makefile.test help` | `make help` |

## Example Migration

### Old User Code

```c
// my_program.c (in KEM-Combined/)
#include "kaz_api.h"
#include "api.h"

int main() {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    crypto_kem_keypair(pk, sk);
    return 0;
}
```

**Compile:**
```bash
gcc -o my_program my_program.c kaz_api.c kem.c rng.c \
    -I. -lcrypto -lgmp
```

### New User Code

```c
// my_program.c (using KEM-Combined-Organized/)
#include "kaz/kem.h"
#include "kaz/nist_api.h"

int main() {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    crypto_kem_keypair(pk, sk);
    return 0;
}
```

**Compile:**
```bash
gcc -o my_program my_program.c \
    -I/path/to/KEM-Combined-Organized/include \
    -L/path/to/KEM-Combined-Organized/build/lib \
    -lkaz-kem -lcrypto -lgmp
```

**Or just link against the source files as before:**
```bash
gcc -o my_program my_program.c \
    KEM-Combined-Organized/src/internal/kem.c \
    KEM-Combined-Organized/src/internal/nist_wrapper.c \
    KEM-Combined-Organized/src/internal/rng.c \
    -IKEM-Combined-Organized/include \
    -IKEM-Combined-Organized/src/internal \
    -lcrypto -lgmp
```

## Recommendations

1. **New Projects**: Use KEM-Combined-Organized exclusively
2. **Existing Projects**: Migrate incrementally - update includes first, then build process
3. **Libraries**: Consider creating a shared library in `build/lib/`
4. **Documentation**: Keep docs in `docs/` directory, link from root README

## Getting Help

- Run `make help` for quick command reference
- Check `README.md` for overview
- See `docs/TESTING.md` for testing details
- Review `docs/OPTIMIZATIONS.md` for performance info

## Summary

The reorganization provides a more professional, maintainable, and scalable structure while maintaining full API compatibility. The main changes are:

1. **Headers moved** to `include/kaz/` with clearer names
2. **Source moved** to `src/internal/`
3. **Tests moved** to `tests/unit/`
4. **Benchmarks moved** to `benchmarks/`
5. **Scripts moved** to `scripts/`
6. **Docs moved** to `docs/`
7. **Unified Makefile** replaces 3 separate ones
8. **Build artifacts** organized in `build/`

All changes maintain backward compatibility at the API level - only paths and build commands changed.
