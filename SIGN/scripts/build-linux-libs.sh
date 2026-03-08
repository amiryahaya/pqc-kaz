#!/bin/bash
#
# Build KAZ-SIGN shared libraries for Linux using Docker
#
# Usage:
#   ./scripts/build-linux-libs.sh          # Build for current architecture
#   ./scripts/build-linux-libs.sh x64      # Build for x86_64
#   ./scripts/build-linux-libs.sh arm64    # Build for arm64
#   ./scripts/build-linux-libs.sh all      # Build for both architectures
#
# Output:
#   dist/linux-x64/libkazsign_*.so
#   dist/linux-arm64/libkazsign_*.so

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check Docker is available
if ! command -v docker &> /dev/null; then
    error "Docker is not installed. Please install Docker first."
fi

# Create dist directory
mkdir -p dist

build_for_arch() {
    local ARCH=$1
    local PLATFORM=""

    case $ARCH in
        x64|amd64|x86_64)
            PLATFORM="linux/amd64"
            ARCH_NAME="x64"
            ;;
        arm64|aarch64)
            PLATFORM="linux/arm64"
            ARCH_NAME="arm64"
            ;;
        *)
            error "Unknown architecture: $ARCH"
            ;;
    esac

    info "Building for linux-$ARCH_NAME ($PLATFORM)..."

    # Check if buildx is available for cross-platform builds
    if docker buildx version &> /dev/null; then
        docker buildx build \
            --platform "$PLATFORM" \
            --load \
            -t "kazsign-builder-$ARCH_NAME" \
            .
    else
        warn "Docker buildx not available. Building for current platform only."
        docker build -t "kazsign-builder-$ARCH_NAME" .
    fi

    # Run container to extract libraries
    docker run --rm \
        -v "$PROJECT_DIR/dist:/dist" \
        "kazsign-builder-$ARCH_NAME"

    info "Libraries for linux-$ARCH_NAME built successfully!"
    ls -la "dist/linux-$ARCH_NAME/"
}

# Parse arguments
TARGET=${1:-"current"}

case $TARGET in
    x64|amd64|x86_64)
        build_for_arch x64
        ;;
    arm64|aarch64)
        build_for_arch arm64
        ;;
    all)
        info "Building for all architectures..."
        build_for_arch x64
        build_for_arch arm64
        ;;
    current)
        # Detect current architecture
        CURRENT_ARCH=$(uname -m)
        if [ "$CURRENT_ARCH" = "x86_64" ]; then
            build_for_arch x64
        elif [ "$CURRENT_ARCH" = "aarch64" ] || [ "$CURRENT_ARCH" = "arm64" ]; then
            build_for_arch arm64
        else
            error "Unknown current architecture: $CURRENT_ARCH"
        fi
        ;;
    *)
        echo "Usage: $0 [x64|arm64|all|current]"
        echo ""
        echo "  x64     Build for Linux x86_64"
        echo "  arm64   Build for Linux arm64"
        echo "  all     Build for both architectures"
        echo "  current Build for current architecture (default)"
        exit 1
        ;;
esac

echo ""
info "Build complete! Libraries are in dist/"
ls -la dist/
