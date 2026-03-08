#!/bin/bash
# Build KAZ-KEM XCFramework for macOS and iOS
# Creates a universal framework that works on all Apple platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEM_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"
OUTPUT_DIR="$SCRIPT_DIR/../Frameworks"

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

# OpenSSL paths (using Homebrew)
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl 2>/dev/null || echo "/opt/homebrew/opt/openssl")}"

echo "=========================================="
echo " Building KAZ-KEM XCFramework"
echo "=========================================="
echo "KEM Source: $KEM_ROOT"
echo "OpenSSL:    $OPENSSL_PREFIX"
echo "Output:     $OUTPUT_DIR"
echo ""

# Clean previous build
rm -rf "$BUILD_DIR"
rm -rf "$OUTPUT_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Function to build for a specific platform
build_platform() {
    local PLATFORM=$1
    local ARCH=$2
    local SDK=$3
    local MIN_VERSION=$4
    local PLATFORM_DIR="$BUILD_DIR/$PLATFORM-$ARCH"

    echo "Building for $PLATFORM ($ARCH)..."
    mkdir -p "$PLATFORM_DIR"

    local CC="xcrun -sdk $SDK clang"
    local SYSROOT=$(xcrun -sdk $SDK --show-sdk-path)

    local PLATFORM_CFLAGS="$CFLAGS -arch $ARCH -isysroot $SYSROOT"

    case $PLATFORM in
        macos)
            PLATFORM_CFLAGS="$PLATFORM_CFLAGS -mmacosx-version-min=$MIN_VERSION"
            ;;
        ios)
            PLATFORM_CFLAGS="$PLATFORM_CFLAGS -miphoneos-version-min=$MIN_VERSION"
            ;;
        ios-simulator)
            PLATFORM_CFLAGS="$PLATFORM_CFLAGS -mios-simulator-version-min=$MIN_VERSION"
            ;;
    esac

    # Include paths
    local INC_FLAGS="-I$INC_DIR -I$SRC_DIR -I$OPENSSL_PREFIX/include"

    # Compile object files
    for src in $SRC_FILES; do
        local name=$(basename "$src" .c)
        $CC $PLATFORM_CFLAGS $INC_FLAGS -c "$src" -o "$PLATFORM_DIR/$name.o"
    done

    # Create static library
    ar rcs "$PLATFORM_DIR/libkazkem.a" "$PLATFORM_DIR"/*.o

    echo "  Created: $PLATFORM_DIR/libkazkem.a"
}

# Build for macOS (arm64 and x86_64)
echo ""
echo "Building for macOS..."
build_platform "macos" "arm64" "macosx" "12.0"
build_platform "macos" "x86_64" "macosx" "12.0"

# Create universal binary for macOS
echo "Creating universal macOS binary..."
mkdir -p "$BUILD_DIR/macos-universal"
lipo -create \
    "$BUILD_DIR/macos-arm64/libkazkem.a" \
    "$BUILD_DIR/macos-x86_64/libkazkem.a" \
    -output "$BUILD_DIR/macos-universal/libkazkem.a"

# Build for iOS (arm64)
echo ""
echo "Building for iOS..."
build_platform "ios" "arm64" "iphoneos" "15.0"

# Build for iOS Simulator (arm64 and x86_64)
echo ""
echo "Building for iOS Simulator..."
build_platform "ios-simulator" "arm64" "iphonesimulator" "15.0"
build_platform "ios-simulator" "x86_64" "iphonesimulator" "15.0"

# Create universal binary for iOS Simulator
echo "Creating universal iOS Simulator binary..."
mkdir -p "$BUILD_DIR/ios-simulator-universal"
lipo -create \
    "$BUILD_DIR/ios-simulator-arm64/libkazkem.a" \
    "$BUILD_DIR/ios-simulator-x86_64/libkazkem.a" \
    -output "$BUILD_DIR/ios-simulator-universal/libkazkem.a"

# Create header directory
echo ""
echo "Preparing headers..."
mkdir -p "$BUILD_DIR/Headers"
cp "$SCRIPT_DIR/../Sources/CKazKem/include/kazkem.h" "$BUILD_DIR/Headers/"

# Create module.modulemap
cat > "$BUILD_DIR/Headers/module.modulemap" << 'EOF'
framework module KazKemNative {
    umbrella header "kazkem.h"
    export *
    module * { export * }
}
EOF

# Create XCFramework
echo ""
echo "Creating XCFramework..."

# Create framework structure for each platform
create_framework() {
    local PLATFORM=$1
    local LIB_PATH=$2
    local FRAMEWORK_DIR="$BUILD_DIR/$PLATFORM-framework/KazKemNative.framework"

    mkdir -p "$FRAMEWORK_DIR/Headers"
    mkdir -p "$FRAMEWORK_DIR/Modules"

    cp "$LIB_PATH" "$FRAMEWORK_DIR/KazKemNative"
    cp "$BUILD_DIR/Headers/kazkem.h" "$FRAMEWORK_DIR/Headers/"
    cp "$BUILD_DIR/Headers/module.modulemap" "$FRAMEWORK_DIR/Modules/"

    # Create Info.plist
    cat > "$FRAMEWORK_DIR/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>KazKemNative</string>
    <key>CFBundleIdentifier</key>
    <string>com.pqc-kaz.KazKemNative</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>KazKemNative</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
</dict>
</plist>
PLIST

    echo "$FRAMEWORK_DIR"
}

MACOS_FRAMEWORK=$(create_framework "macos" "$BUILD_DIR/macos-universal/libkazkem.a")
IOS_FRAMEWORK=$(create_framework "ios" "$BUILD_DIR/ios-arm64/libkazkem.a")
IOS_SIM_FRAMEWORK=$(create_framework "ios-simulator" "$BUILD_DIR/ios-simulator-universal/libkazkem.a")

# Create XCFramework
xcodebuild -create-xcframework \
    -framework "$MACOS_FRAMEWORK" \
    -framework "$IOS_FRAMEWORK" \
    -framework "$IOS_SIM_FRAMEWORK" \
    -output "$OUTPUT_DIR/KazKemNative.xcframework"

echo ""
echo "=========================================="
echo " Build Complete!"
echo "=========================================="
echo ""
echo "XCFramework created at:"
echo "  $OUTPUT_DIR/KazKemNative.xcframework"
echo ""
echo "Supported platforms:"
echo "  - macOS (arm64, x86_64)"
echo "  - iOS (arm64)"
echo "  - iOS Simulator (arm64, x86_64)"
echo ""

# List contents
ls -la "$OUTPUT_DIR/KazKemNative.xcframework/"
