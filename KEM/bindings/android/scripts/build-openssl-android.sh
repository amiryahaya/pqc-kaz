#!/bin/bash
# Build OpenSSL for Android
# This script downloads and builds OpenSSL for all Android architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build/openssl-build"
OUTPUT_DIR="$SCRIPT_DIR/../kazkem/src/main/libs/openssl"

# OpenSSL version
OPENSSL_VERSION="3.2.0"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"

# Android NDK path - detect from environment or common locations
if [ -z "$ANDROID_NDK_HOME" ]; then
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "$HOME/Library/Android/sdk/ndk"/* 2>/dev/null | head -1)
    elif [ -d "$ANDROID_SDK_ROOT/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "$ANDROID_SDK_ROOT/ndk"/* 2>/dev/null | head -1)
    fi
fi

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME not set or invalid"
    echo "Please set ANDROID_NDK_HOME to your Android NDK directory"
    exit 1
fi

echo "==========================================="
echo " Building OpenSSL for Android"
echo "==========================================="
echo "OpenSSL Version: $OPENSSL_VERSION"
echo "NDK:             $ANDROID_NDK_HOME"
echo "Output:          $OUTPUT_DIR"
echo ""

# Android API level
API=24

# Architectures to build
ARCHS=(
    "arm64-v8a:android-arm64"
    "armeabi-v7a:android-arm"
    "x86_64:android-x86_64"
    "x86:android-x86"
)

# Clean and create directories
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Download OpenSSL if not cached
OPENSSL_ARCHIVE="$BUILD_DIR/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SRC="$BUILD_DIR/openssl-${OPENSSL_VERSION}"

if [ ! -f "$OPENSSL_ARCHIVE" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION..."
    curl -L -o "$OPENSSL_ARCHIVE" "$OPENSSL_URL"
fi

# Extract
if [ ! -d "$OPENSSL_SRC" ]; then
    echo "Extracting OpenSSL..."
    tar -xzf "$OPENSSL_ARCHIVE" -C "$BUILD_DIR"
fi

# Build for each architecture
for arch_target in "${ARCHS[@]}"; do
    IFS=':' read -r ARCH TARGET <<< "$arch_target"

    echo ""
    echo "Building for $ARCH ($TARGET)..."

    ARCH_BUILD_DIR="$BUILD_DIR/build-$ARCH"
    ARCH_OUTPUT_DIR="$OUTPUT_DIR/$ARCH"

    mkdir -p "$ARCH_BUILD_DIR"
    mkdir -p "$ARCH_OUTPUT_DIR/lib"
    mkdir -p "$ARCH_OUTPUT_DIR/include"

    cd "$OPENSSL_SRC"

    # Clean previous build
    make clean 2>/dev/null || true

    # Configure
    export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
    export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"

    ./Configure "$TARGET" \
        -D__ANDROID_API__=$API \
        --prefix="$ARCH_BUILD_DIR/install" \
        --openssldir="$ARCH_BUILD_DIR/ssl" \
        no-shared \
        no-tests \
        no-ui-console

    # Build
    make -j$(sysctl -n hw.ncpu)
    make install_sw

    # Copy to output
    cp "$ARCH_BUILD_DIR/install/lib/libcrypto.a" "$ARCH_OUTPUT_DIR/lib/"
    cp -r "$ARCH_BUILD_DIR/install/include/openssl" "$ARCH_OUTPUT_DIR/include/"

    echo "  Created: $ARCH_OUTPUT_DIR/lib/libcrypto.a"
done

echo ""
echo "==========================================="
echo " Build Complete!"
echo "==========================================="
echo ""
echo "OpenSSL libraries created at:"
ls -la "$OUTPUT_DIR"/*/lib/libcrypto.a 2>/dev/null || echo "  (no files found)"
