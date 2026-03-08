#!/bin/bash
# Build native KAZ-KEM library for .NET bindings
# Supports Linux and macOS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEM_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/../KazKem/runtimes}"

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)
        OS_NAME="linux"
        LIB_EXT="so"
        CC="${CC:-gcc}"
        SHARED_FLAGS="-shared -fPIC"
        OPENSSL_INC="${OPENSSL_INC:-/usr/include}"
        OPENSSL_LIB="${OPENSSL_LIB:-/usr/lib}"
        LINK_FLAGS="-lcrypto -lm"
        ;;
    Darwin*)
        OS_NAME="osx"
        LIB_EXT="dylib"
        CC="${CC:-clang}"
        SHARED_FLAGS="-dynamiclib -fPIC"
        OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl 2>/dev/null || echo "/usr/local/opt/openssl")}"
        OPENSSL_INC="$OPENSSL_PREFIX/include"
        OPENSSL_LIB="$OPENSSL_PREFIX/lib"
        LINK_FLAGS="-L$OPENSSL_LIB -lcrypto -lm"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="x64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    armv7l)
        ARCH_NAME="arm"
        ;;
    i386|i686)
        ARCH_NAME="x86"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

RID="${OS_NAME}-${ARCH_NAME}"
RUNTIME_DIR="$OUTPUT_DIR/$RID/native"

echo "Building KAZ-KEM native library"
echo "=============================="
echo "OS:           $OS_NAME"
echo "Architecture: $ARCH_NAME"
echo "Runtime ID:   $RID"
echo "Output:       $RUNTIME_DIR"
echo ""

# Create output directory
mkdir -p "$RUNTIME_DIR"

# Source files
SRC_DIR="$KEM_ROOT/src/internal"
INC_DIR="$KEM_ROOT/include"
SRC_FILES="$SRC_DIR/kem_secure.c $SRC_DIR/nist_wrapper.c"

# Build flags
CFLAGS="-O3 -Wall -fPIC -DKAZ_KEM_USE_OPENSSL"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION=\"2.1.0\""
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_MAJOR=2"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_MINOR=1"
CFLAGS="$CFLAGS -DKAZ_KEM_VERSION_PATCH=0"
INC_FLAGS="-I$INC_DIR -I$SRC_DIR -I$OPENSSL_INC"

# Output library
LIB_NAME="libkazkem.$LIB_EXT"
OUTPUT_LIB="$RUNTIME_DIR/$LIB_NAME"

echo "Compiling..."
$CC $CFLAGS $SHARED_FLAGS $INC_FLAGS $SRC_FILES -o "$OUTPUT_LIB" $LINK_FLAGS

# On macOS, set install name
if [ "$OS_NAME" = "osx" ]; then
    install_name_tool -id "@rpath/$LIB_NAME" "$OUTPUT_LIB"
fi

echo ""
echo "Successfully built: $OUTPUT_LIB"
echo ""
ls -la "$OUTPUT_LIB"
