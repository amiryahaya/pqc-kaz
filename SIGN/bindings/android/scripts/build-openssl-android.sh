#!/bin/bash
#
# Build OpenSSL for Android
#
# This script downloads and builds OpenSSL for all Android architectures.
# Requires Android NDK to be installed.
#
# Usage:
#   ./scripts/build-openssl-android.sh
#
# Environment variables:
#   ANDROID_NDK_ROOT  - Path to Android NDK (required)
#   OPENSSL_VERSION   - OpenSSL version to build (default: 3.2.0)
#
# Output:
#   kazsign/src/main/libs/openssl/<arch>/lib/libcrypto.a
#   kazsign/src/main/libs/openssl/<arch>/include/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/openssl"
OUTPUT_DIR="$PROJECT_DIR/kazsign/src/main/libs/openssl"

# OpenSSL version
OPENSSL_VERSION="${OPENSSL_VERSION:-3.2.0}"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"

# Android NDK
if [ -z "$ANDROID_NDK_ROOT" ]; then
    # Try to find NDK
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        ANDROID_NDK_ROOT=$(ls -d "$HOME/Library/Android/sdk/ndk/"* 2>/dev/null | sort -V | tail -1)
    elif [ -d "$ANDROID_HOME/ndk" ]; then
        ANDROID_NDK_ROOT=$(ls -d "$ANDROID_HOME/ndk/"* 2>/dev/null | sort -V | tail -1)
    fi
fi

if [ -z "$ANDROID_NDK_ROOT" ] || [ ! -d "$ANDROID_NDK_ROOT" ]; then
    echo "ERROR: Android NDK not found. Set ANDROID_NDK_ROOT environment variable."
    exit 1
fi

# Minimum API level
ANDROID_API=24

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Architecture configurations
# Format: ABI:TOOLCHAIN:OPENSSL_TARGET
ARCHS=(
    "arm64-v8a:aarch64-linux-android:android-arm64"
    "armeabi-v7a:armv7a-linux-androideabi:android-arm"
    "x86_64:x86_64-linux-android:android-x86_64"
    "x86:i686-linux-android:android-x86"
)

# ============================================================================
# Download OpenSSL
# ============================================================================
download_openssl() {
    step "Downloading OpenSSL ${OPENSSL_VERSION}..."

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        curl -LO "$OPENSSL_URL"
    else
        info "OpenSSL archive already downloaded"
    fi

    if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
        tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

# ============================================================================
# Build OpenSSL for a specific architecture
# ============================================================================
build_openssl() {
    local ABI=$1
    local TOOLCHAIN=$2
    local TARGET=$3

    local OPENSSL_SRC="$BUILD_DIR/openssl-${OPENSSL_VERSION}"
    local OPENSSL_BUILD="$BUILD_DIR/build-$ABI"
    local OPENSSL_OUTPUT="$OUTPUT_DIR/$ABI"

    if [ -f "$OPENSSL_OUTPUT/lib/libcrypto.a" ]; then
        info "OpenSSL for $ABI already built"
        return
    fi

    step "Building OpenSSL for $ABI..."

    # Clean previous build
    cd "$OPENSSL_SRC"
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true

    # Set up NDK toolchain
    local TOOLCHAIN_DIR="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt"
    local HOST_TAG=""

    case "$(uname -s)" in
        Darwin) HOST_TAG="darwin-x86_64" ;;
        Linux) HOST_TAG="linux-x86_64" ;;
        *) error "Unsupported host OS" ;;
    esac

    TOOLCHAIN_DIR="$TOOLCHAIN_DIR/$HOST_TAG"

    export PATH="$TOOLCHAIN_DIR/bin:$PATH"
    export ANDROID_NDK_ROOT="$ANDROID_NDK_ROOT"

    # Set compiler based on API level
    local CC_PREFIX="${TOOLCHAIN}${ANDROID_API}"

    mkdir -p "$OPENSSL_BUILD"
    mkdir -p "$OPENSSL_OUTPUT"

    # Configure
    ./Configure "$TARGET" \
        -D__ANDROID_API__=$ANDROID_API \
        --prefix="$OPENSSL_OUTPUT" \
        --openssldir="$OPENSSL_OUTPUT" \
        no-shared \
        no-tests \
        no-ui-console \
        no-async \
        no-engine \
        no-dso \
        2>&1 | tail -5

    # Build
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu) 2>&1 | tail -3
    make install_sw 2>&1 | tail -3

    info "OpenSSL for $ABI built successfully"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "=============================================="
    echo "OpenSSL Android Builder"
    echo "=============================================="
    echo ""
    echo "NDK:     $ANDROID_NDK_ROOT"
    echo "OpenSSL: $OPENSSL_VERSION"
    echo "API:     $ANDROID_API"
    echo ""

    # Download OpenSSL
    download_openssl

    # Build for all architectures
    for arch_config in "${ARCHS[@]}"; do
        IFS=':' read -r ABI TOOLCHAIN TARGET <<< "$arch_config"
        build_openssl "$ABI" "$TOOLCHAIN" "$TARGET"
    done

    echo ""
    echo "=============================================="
    info "Build complete!"
    echo "=============================================="
    echo ""
    echo "OpenSSL libraries installed to:"
    for arch_config in "${ARCHS[@]}"; do
        IFS=':' read -r ABI _ _ <<< "$arch_config"
        echo "  $OUTPUT_DIR/$ABI/"
    done
}

main "$@"
