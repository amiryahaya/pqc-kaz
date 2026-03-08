# KAZ-KEM Versioning Guide

## Overview

KAZ-KEM v1.0.0 uses [Semantic Versioning 2.0.0](https://semver.org/) to track changes and maintain compatibility.

## Version Format

Version numbers follow the format: **MAJOR.MINOR.PATCH**

```
1.0.0
│ │ │
│ │ └─ Patch: Backwards-compatible bug fixes
│ └─── Minor: Backwards-compatible new features
└───── Major: Breaking API changes
```

### Examples

- `1.0.0` → `1.0.1`: Bug fix (safe to upgrade)
- `1.0.0` → `1.1.0`: New feature added (safe to upgrade)
- `1.0.0` → `2.0.0`: Breaking change (review before upgrade)

## Current Version: 1.0.0

**Release Date**: 2025-11-20
**Status**: Stable
**API Version**: 1

## Version Information

### In Code

The version is accessible through multiple mechanisms:

#### 1. Version Header
```c
#include "kaz/version.h"

// Get version string
const char *ver = kaz_kem_version();  // Returns "1.0.0"

// Get version number
int ver_num = kaz_kem_version_number();  // Returns 0x010000

// Get individual components
int major, minor, patch;
kaz_kem_version_info(&major, &minor, &patch);
// major=1, minor=0, patch=0
```

#### 2. Version Macros
```c
#include "kaz/version.h"

// Compile-time version check
#if KAZ_KEM_VERSION_AT_LEAST(1, 0, 0)
    // Code for v1.0.0 and later
#endif

// Version components
#define KAZ_KEM_VERSION_MAJOR 1
#define KAZ_KEM_VERSION_MINOR 0
#define KAZ_KEM_VERSION_PATCH 0

// Version string
#define KAZ_KEM_VERSION_STRING "1.0.0"

// Release info
#define KAZ_KEM_RELEASE_DATE "2025-11-20"
#define KAZ_KEM_BUILD_TYPE "release"
```

#### 3. Feature Detection
```c
#include "kaz/version.h"

// Check for specific features
#if KAZ_KEM_HAS_OPTIMIZED_IMPL
    // Optimized implementation available
#endif

#if KAZ_KEM_HAS_LEVEL_256
    // 256-bit security level available
#endif
```

### In Build System

#### Makefile Variables
```makefile
VERSION_MAJOR=1
VERSION_MINOR=0
VERSION_PATCH=0
VERSION=$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
```

#### Command Line
```bash
# Display version
make version

# Output:
# KAZ-KEM Version 1.0.0
# Build Date: 2025-11-20
# Implementation: optimized
# Security Level: 128-bit
```

#### Build Output
```bash
make test

# Output includes:
# ✓ Built test suite v1.0.0: build/bin/test_kem_128 (optimized, Level 128)
```

### In Documentation

- **VERSION** file: Contains single line "1.0.0"
- **README.md**: Version badge at top
- **CHANGELOG.md**: Version history
- **RELEASE_NOTES_v1.0.0.md**: Detailed release notes

## Version Files

```
KEM-Combined-Organized/
├── VERSION                        # Simple version file: "1.0.0"
├── include/kaz/version.h          # Version macros and functions
├── CHANGELOG.md                   # Version history
├── RELEASE_NOTES_v1.0.0.md       # Release notes for v1.0.0
├── VERSIONING.md                  # This file
└── Makefile                       # Version variables
```

## API Versioning

### API Version: 1

The API version tracks **interface compatibility**:

```c
#define KAZ_KEM_API_VERSION 1
```

- Same API version = Compatible
- Different API version = May be incompatible

### NIST API Stability

The NIST KEM API is **stable** across all v1.x.x releases:

```c
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
```

## Version Compatibility

### Backwards Compatibility Promise

For v1.x.x releases:

✅ **GUARANTEED**:
- Same NIST API
- Same binary interface
- Same key/ciphertext formats
- Existing code continues to work

❌ **NOT GUARANTEED**:
- Internal implementation details
- Build system specifics
- Performance characteristics

### Breaking Changes

Breaking changes require a **major version bump** (e.g., v1.x.x → v2.0.0):

Examples that would require v2.0.0:
- Changing function signatures
- Changing key/ciphertext formats
- Removing public API functions
- Changing header file structure

## Checking Version

### At Compile Time

```c
#include "kaz/version.h"

#if !KAZ_KEM_VERSION_AT_LEAST(1, 0, 0)
    #error "Requires KAZ-KEM v1.0.0 or later"
#endif

#if KAZ_KEM_VERSION_MAJOR != 1
    #error "Not compatible with KAZ-KEM v2.x"
#endif
```

### At Runtime

```c
#include <stdio.h>
#include "kaz/version.h"

int main() {
    printf("KAZ-KEM version: %s\n", kaz_kem_version());

    int major, minor, patch;
    kaz_kem_version_info(&major, &minor, &patch);

    if (major != 1) {
        fprintf(stderr, "Error: Incompatible version\n");
        return 1;
    }

    printf("Compatible version: %d.%d.%d\n", major, minor, patch);
    return 0;
}
```

### From Command Line

```bash
# Display version
make version

# Check version in built executable
./build/bin/test_kem_128 | head -5

# Read VERSION file
cat VERSION
```

## Version History

### v1.0.0 (2025-11-20) - Initial Release

First official release with:
- Professional project structure
- Multi-level support (128, 192, 256-bit)
- Dual implementations (original, optimized)
- Industry-grade testing and benchmarking
- Comprehensive documentation

See `CHANGELOG.md` for detailed history.

## Release Process

### For Maintainers

When releasing a new version:

1. **Update version numbers**:
   - `VERSION` file
   - `Makefile` (VERSION_MAJOR/MINOR/PATCH)
   - `include/kaz/version.h`
   - `README.md` badges

2. **Update documentation**:
   - Add entry to `CHANGELOG.md`
   - Create `RELEASE_NOTES_vX.Y.Z.md`
   - Update `README.md` if needed

3. **Test**:
   ```bash
   make clean
   make test-all
   make bench-all
   make version
   ```

4. **Tag release**:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

5. **Build release artifacts**:
   ```bash
   make clean
   make all LEVEL=128
   make all LEVEL=192
   make all LEVEL=256
   ```

## Version Scheme Details

### Incrementing Versions

#### Patch Version (1.0.0 → 1.0.1)

**When**: Bug fixes, documentation updates, performance improvements

**Examples**:
- Fix memory leak
- Correct documentation typo
- Optimize existing function (no API change)
- Fix test that was incorrectly failing

**Compatibility**: ✅ Drop-in replacement

#### Minor Version (1.0.0 → 1.1.0)

**When**: New features, non-breaking enhancements

**Examples**:
- Add new utility function to API
- Add new build target
- Add new test suite
- Add new documentation

**Compatibility**: ✅ Backwards compatible (existing code works)

#### Major Version (1.0.0 → 2.0.0)

**When**: Breaking changes, incompatible API modifications

**Examples**:
- Change function signature
- Remove public function
- Change key format
- Reorganize header files (breaking includes)

**Compatibility**: ❌ May require code changes

### Pre-release Versions

For development versions:

- `1.1.0-alpha.1` - Alpha release (unstable)
- `1.1.0-beta.1` - Beta release (feature complete, testing)
- `1.1.0-rc.1` - Release candidate (final testing)

## Feature Flags

Current features in v1.0.0:

```c
#define KAZ_KEM_HAS_OPTIMIZED_IMPL 1  // Optimized implementation available
#define KAZ_KEM_HAS_ORIGINAL_IMPL 1   // Original implementation available
#define KAZ_KEM_HAS_LEVEL_128 1       // 128-bit security level
#define KAZ_KEM_HAS_LEVEL_192 1       // 192-bit security level
#define KAZ_KEM_HAS_LEVEL_256 1       // 256-bit security level
```

Use in code:
```c
#if KAZ_KEM_HAS_OPTIMIZED_IMPL
    // Use optimized version
    #include "kaz/kem_optimized.h"
#else
    // Fall back to original
    #include "kaz/kem.h"
#endif
```

## Resources

- **Semantic Versioning**: https://semver.org/
- **CHANGELOG.md**: Version history
- **RELEASE_NOTES_*.md**: Detailed release notes
- **VERSION**: Current version file

## Support

For version-related questions:
- Check `CHANGELOG.md` for version history
- See `MIGRATION_GUIDE.md` for upgrade instructions
- Run `make version` to check current version
- Review `RELEASE_NOTES_*.md` for specific versions

---

**Current Version**: 1.0.0
**API Version**: 1
**Last Updated**: 2025-11-20
