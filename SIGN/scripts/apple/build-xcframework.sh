#!/bin/bash
#
# Build KAZ-SIGN XCFramework for iOS and macOS
#
# This script builds:
# - OpenSSL static libraries for all Apple platforms
# - KAZ-SIGN static libraries linked with OpenSSL
# - Universal XCFramework containing all platforms
#
# Usage:
#   ./scripts/apple/build-xcframework.sh
#
# Output:
#   bindings/swift/KazSignNative.xcframework
#
# Requirements:
#   - Xcode with command line tools
#   - macOS 12+ recommended

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="$PROJECT_DIR/build/apple"
OUTPUT_DIR="$PROJECT_DIR/bindings/swift"

# OpenSSL version
OPENSSL_VERSION="3.2.0"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"

# Minimum deployment targets
IOS_MIN_VERSION="13.0"
MACOS_MIN_VERSION="11.0"

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

# Platforms to build
PLATFORMS=(
    "macos-arm64"
    "macos-x86_64"
    "ios-arm64"
    "ios-simulator-arm64"
    "ios-simulator-x86_64"
)

# ============================================================================
# Download and extract OpenSSL
# ============================================================================
download_openssl() {
    step "Downloading OpenSSL ${OPENSSL_VERSION}..."

    mkdir -p "$BUILD_DIR/downloads"
    cd "$BUILD_DIR/downloads"

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
# Build OpenSSL for a specific platform
# ============================================================================
build_openssl() {
    local PLATFORM=$1
    local OPENSSL_SRC="$BUILD_DIR/downloads/openssl-${OPENSSL_VERSION}"
    local OPENSSL_BUILD="$BUILD_DIR/openssl/$PLATFORM"

    if [ -f "$OPENSSL_BUILD/lib/libcrypto.a" ]; then
        info "OpenSSL for $PLATFORM already built"
        return
    fi

    step "Building OpenSSL for $PLATFORM..."

    # Clean previous build
    cd "$OPENSSL_SRC"
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true

    # Set platform-specific options
    local CONFIG_TARGET=""
    local EXTRA_FLAGS=""
    local CUSTOM_CC=""
    local SDK_PATH=""

    # Clear any previous cross-compilation settings
    unset CROSS_TOP
    unset CROSS_SDK
    unset CC

    case $PLATFORM in
        macos-arm64)
            CONFIG_TARGET="darwin64-arm64-cc"
            EXTRA_FLAGS="-mmacosx-version-min=$MACOS_MIN_VERSION"
            ;;
        macos-x86_64)
            CONFIG_TARGET="darwin64-x86_64-cc"
            EXTRA_FLAGS="-mmacosx-version-min=$MACOS_MIN_VERSION"
            ;;
        ios-arm64)
            CONFIG_TARGET="ios64-xcrun"
            EXTRA_FLAGS="-mios-version-min=$IOS_MIN_VERSION"
            export CROSS_TOP="$(xcode-select -p)/Platforms/iPhoneOS.platform/Developer"
            export CROSS_SDK="iPhoneOS.sdk"
            ;;
        ios-simulator-arm64)
            # For iOS Simulator, use darwin64 target with explicit compiler settings
            CONFIG_TARGET="darwin64-arm64-cc"
            SDK_PATH="$(xcrun --sdk iphonesimulator --show-sdk-path)"
            CUSTOM_CC="clang -target arm64-apple-ios${IOS_MIN_VERSION}-simulator -isysroot $SDK_PATH"
            EXTRA_FLAGS="-mios-simulator-version-min=$IOS_MIN_VERSION"
            ;;
        ios-simulator-x86_64)
            # For iOS Simulator, use darwin64 target with explicit compiler settings
            CONFIG_TARGET="darwin64-x86_64-cc"
            SDK_PATH="$(xcrun --sdk iphonesimulator --show-sdk-path)"
            CUSTOM_CC="clang -target x86_64-apple-ios${IOS_MIN_VERSION}-simulator -isysroot $SDK_PATH"
            EXTRA_FLAGS="-mios-simulator-version-min=$IOS_MIN_VERSION"
            ;;
        *)
            error "Unknown platform: $PLATFORM"
            ;;
    esac

    mkdir -p "$OPENSSL_BUILD"

    # Build with custom CC if specified (for iOS Simulator)
    if [ -n "$CUSTOM_CC" ]; then
        CC="$CUSTOM_CC" ./Configure "$CONFIG_TARGET" \
            --prefix="$OPENSSL_BUILD" \
            --openssldir="$OPENSSL_BUILD" \
            no-shared \
            no-tests \
            no-ui-console \
            no-async \
            no-engine \
            no-dso \
            $EXTRA_FLAGS \
            2>&1 | tail -5
    else
        ./Configure "$CONFIG_TARGET" \
            --prefix="$OPENSSL_BUILD" \
            --openssldir="$OPENSSL_BUILD" \
            no-shared \
            no-tests \
            no-ui-console \
            no-async \
            no-engine \
            no-dso \
            $EXTRA_FLAGS \
            2>&1 | tail -5
    fi

    make -j$(sysctl -n hw.ncpu) 2>&1 | tail -3
    make install_sw 2>&1 | tail -3

    info "OpenSSL for $PLATFORM built successfully"
}

# ============================================================================
# Build KAZ-SIGN for a specific platform
# ============================================================================
build_kazsign() {
    local PLATFORM=$1
    local LEVEL=$2
    local OPENSSL_DIR="$BUILD_DIR/openssl/$PLATFORM"
    local KAZSIGN_BUILD="$BUILD_DIR/kazsign/$PLATFORM"

    step "Building KAZ-SIGN Level $LEVEL for $PLATFORM..."

    mkdir -p "$KAZSIGN_BUILD"

    # Set compiler flags based on platform
    local CC="clang"
    local CFLAGS="-O2 -fPIC -DKAZ_SECURITY_LEVEL=$LEVEL"
    local CFLAGS="$CFLAGS -I$PROJECT_DIR/include -I$PROJECT_DIR/src/internal"
    local CFLAGS="$CFLAGS -I$OPENSSL_DIR/include"

    case $PLATFORM in
        macos-arm64)
            CFLAGS="$CFLAGS -target arm64-apple-macos$MACOS_MIN_VERSION"
            ;;
        macos-x86_64)
            CFLAGS="$CFLAGS -target x86_64-apple-macos$MACOS_MIN_VERSION"
            ;;
        ios-arm64)
            CFLAGS="$CFLAGS -target arm64-apple-ios$IOS_MIN_VERSION"
            CFLAGS="$CFLAGS -isysroot $(xcrun --sdk iphoneos --show-sdk-path)"
            ;;
        ios-simulator-arm64)
            CFLAGS="$CFLAGS -target arm64-apple-ios$IOS_MIN_VERSION-simulator"
            CFLAGS="$CFLAGS -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path)"
            ;;
        ios-simulator-x86_64)
            CFLAGS="$CFLAGS -target x86_64-apple-ios$IOS_MIN_VERSION-simulator"
            CFLAGS="$CFLAGS -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path)"
            ;;
    esac

    # Compile source files
    local SOURCES=(
        "$PROJECT_DIR/src/internal/sign.c"
        "$PROJECT_DIR/src/internal/nist_wrapper.c"
        "$PROJECT_DIR/src/internal/security.c"
        "$PROJECT_DIR/src/internal/kdf.c"
        "$PROJECT_DIR/src/internal/sha3.c"
        "$PROJECT_DIR/src/internal/detached.c"
        "$PROJECT_DIR/src/internal/der.c"
        "$PROJECT_DIR/src/internal/x509.c"
        "$PROJECT_DIR/src/internal/p12.c"
    )

    local OBJECTS=()
    for src in "${SOURCES[@]}"; do
        local obj="$KAZSIGN_BUILD/$(basename ${src%.c})_$LEVEL.o"
        $CC $CFLAGS -c "$src" -o "$obj"
        OBJECTS+=("$obj")
    done

    # Create static library
    local LIB="$KAZSIGN_BUILD/libkazsign_$LEVEL.a"
    ar rcs "$LIB" "${OBJECTS[@]}"

    info "Built $LIB"
}

# ============================================================================
# Create fat library (combine architectures)
# ============================================================================
create_fat_library() {
    local OUTPUT_NAME=$1
    shift
    local INPUTS=("$@")

    step "Creating fat library: $OUTPUT_NAME"
    lipo -create "${INPUTS[@]}" -output "$OUTPUT_NAME"
    lipo -info "$OUTPUT_NAME"
}

# ============================================================================
# Create XCFramework
# ============================================================================
create_xcframework() {
    step "Creating XCFramework..."

    local XCFRAMEWORK="$OUTPUT_DIR/KazSignNative.xcframework"
    rm -rf "$XCFRAMEWORK"

    # Create combined libraries directory
    local COMBINED="$BUILD_DIR/combined"
    mkdir -p "$COMBINED"/{macos,ios-device,ios-simulator}

    # Combine all security levels into single library per platform
    for PLATFORM_GROUP in "macos" "ios-device" "ios-simulator"; do
        local LIBS=()

        case $PLATFORM_GROUP in
            macos)
                # Create fat binary for macOS (arm64 + x86_64)
                for LEVEL in 128 192 256; do
                    local FAT_LIB="$COMBINED/macos/libkazsign_$LEVEL.a"
                    create_fat_library "$FAT_LIB" \
                        "$BUILD_DIR/kazsign/macos-arm64/libkazsign_$LEVEL.a" \
                        "$BUILD_DIR/kazsign/macos-x86_64/libkazsign_$LEVEL.a"
                    LIBS+=("$FAT_LIB")
                done
                # Combine OpenSSL
                create_fat_library "$COMBINED/macos/libcrypto.a" \
                    "$BUILD_DIR/openssl/macos-arm64/lib/libcrypto.a" \
                    "$BUILD_DIR/openssl/macos-x86_64/lib/libcrypto.a"
                LIBS+=("$COMBINED/macos/libcrypto.a")
                ;;
            ios-device)
                for LEVEL in 128 192 256; do
                    cp "$BUILD_DIR/kazsign/ios-arm64/libkazsign_$LEVEL.a" "$COMBINED/ios-device/"
                    LIBS+=("$COMBINED/ios-device/libkazsign_$LEVEL.a")
                done
                cp "$BUILD_DIR/openssl/ios-arm64/lib/libcrypto.a" "$COMBINED/ios-device/"
                LIBS+=("$COMBINED/ios-device/libcrypto.a")
                ;;
            ios-simulator)
                # Create fat binary for simulator (arm64 + x86_64)
                for LEVEL in 128 192 256; do
                    local FAT_LIB="$COMBINED/ios-simulator/libkazsign_$LEVEL.a"
                    create_fat_library "$FAT_LIB" \
                        "$BUILD_DIR/kazsign/ios-simulator-arm64/libkazsign_$LEVEL.a" \
                        "$BUILD_DIR/kazsign/ios-simulator-x86_64/libkazsign_$LEVEL.a"
                    LIBS+=("$FAT_LIB")
                done
                create_fat_library "$COMBINED/ios-simulator/libcrypto.a" \
                    "$BUILD_DIR/openssl/ios-simulator-arm64/lib/libcrypto.a" \
                    "$BUILD_DIR/openssl/ios-simulator-x86_64/lib/libcrypto.a"
                LIBS+=("$COMBINED/ios-simulator/libcrypto.a")
                ;;
        esac

        # Merge all static libraries into one
        libtool -static -o "$COMBINED/$PLATFORM_GROUP/libKazSignNative.a" "${LIBS[@]}"
        info "Created $COMBINED/$PLATFORM_GROUP/libKazSignNative.a"
    done

    # Copy headers
    mkdir -p "$COMBINED/include"
    cp "$PROJECT_DIR/include/kaz/sign.h" "$COMBINED/include/"
    cp "$PROJECT_DIR/include/kaz/nist_api.h" "$COMBINED/include/"
    cp "$PROJECT_DIR/include/kaz/kdf.h" "$COMBINED/include/"
    cp "$PROJECT_DIR/include/kaz/security.h" "$COMBINED/include/"

    # Create module map
    cat > "$COMBINED/include/module.modulemap" << 'EOF'
module KazSignNative {
    header "sign.h"
    header "nist_api.h"
    header "kdf.h"
    header "security.h"
    export *
}
EOF

    # Create XCFramework
    xcodebuild -create-xcframework \
        -library "$COMBINED/macos/libKazSignNative.a" \
        -headers "$COMBINED/include" \
        -library "$COMBINED/ios-device/libKazSignNative.a" \
        -headers "$COMBINED/include" \
        -library "$COMBINED/ios-simulator/libKazSignNative.a" \
        -headers "$COMBINED/include" \
        -output "$XCFRAMEWORK"

    info "Created $XCFRAMEWORK"
    ls -la "$XCFRAMEWORK"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "=============================================="
    echo "KAZ-SIGN XCFramework Builder"
    echo "=============================================="
    echo ""

    # Check for Xcode
    if ! command -v xcodebuild &> /dev/null; then
        error "Xcode command line tools not found. Install with: xcode-select --install"
    fi

    mkdir -p "$BUILD_DIR"

    # Download OpenSSL
    download_openssl

    # Build OpenSSL for all platforms
    for PLATFORM in "${PLATFORMS[@]}"; do
        build_openssl "$PLATFORM"
    done

    # Build KAZ-SIGN for all platforms and security levels
    for PLATFORM in "${PLATFORMS[@]}"; do
        for LEVEL in 128 192 256; do
            build_kazsign "$PLATFORM" "$LEVEL"
        done
    done

    # Create XCFramework
    create_xcframework

    echo ""
    echo "=============================================="
    info "Build complete!"
    echo "=============================================="
    echo ""
    echo "XCFramework: $OUTPUT_DIR/KazSignNative.xcframework"
    echo ""
    echo "To use in your Swift project:"
    echo "1. Add the xcframework to your Xcode project"
    echo "2. Or reference it in Package.swift as a binary target"
}

main "$@"
