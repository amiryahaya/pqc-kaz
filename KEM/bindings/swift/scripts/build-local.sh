#!/bin/bash
# Build KAZ-KEM native library for local development
# Creates a dynamic library for the current platform

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEM_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build/local"
LIB_DIR="$SCRIPT_DIR/../lib"

# Source files
SRC_DIR="$KEM_ROOT/src/internal"
INC_DIR="$KEM_ROOT/include"
SRC_FILES="$SRC_DIR/kem_secure.c $SRC_DIR/nist_wrapper.c"

# Detect architecture
ARCH=$(uname -m)

# OpenSSL paths
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl 2>/dev/null || echo "/opt/homebrew/opt/openssl")}"

echo "=========================================="
echo " Building KAZ-KEM for Local Development"
echo "=========================================="
echo "Architecture: $ARCH"
echo "OpenSSL:      $OPENSSL_PREFIX"
echo ""

# Clean and create directories
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$LIB_DIR"

# Build flags
CFLAGS="-O3 -Wall -fPIC -DKAZ_KEM_USE_OPENSSL"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION=\"2.1.0\""
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_MAJOR=2"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_MINOR=1"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_PATCH=0"

INC_FLAGS="-I$INC_DIR -I$SRC_DIR -I$OPENSSL_PREFIX/include"
LINK_FLAGS="-L$OPENSSL_PREFIX/lib -lcrypto"

echo "Compiling..."

# Build dynamic library
clang $CFLAGS -dynamiclib -fPIC \
    $INC_FLAGS \
    $SRC_FILES \
    -o "$LIB_DIR/libkazkem.dylib" \
    $LINK_FLAGS \
    -install_name "@rpath/libkazkem.dylib"

# Also create static library for XCFramework
clang $CFLAGS $INC_FLAGS -c "$SRC_DIR/kem_secure.c" -o "$BUILD_DIR/kem_secure.o"
clang $CFLAGS $INC_FLAGS -c "$SRC_DIR/nist_wrapper.c" -o "$BUILD_DIR/nist_wrapper.o"
ar rcs "$LIB_DIR/libkazkem.a" "$BUILD_DIR"/*.o

echo ""
echo "Build complete!"
echo ""
echo "Libraries created:"
ls -la "$LIB_DIR/"
echo ""
echo "To use with Swift Package Manager, add to your linker flags:"
echo "  -L$LIB_DIR -lkazkem"
echo ""
echo "Or copy the library to /usr/local/lib:"
echo "  sudo cp $LIB_DIR/libkazkem.dylib /usr/local/lib/"
