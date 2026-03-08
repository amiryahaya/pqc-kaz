# KAZ-SIGN Linux Build Container
#
# Builds shared libraries for Linux deployment.
# Supports both x86_64 and arm64 architectures.
#
# Usage:
#   # Build for current architecture
#   docker build -t kazsign-builder .
#   docker run --rm -v $(pwd)/dist:/dist kazsign-builder
#
#   # Build for specific architecture (requires Docker buildx)
#   docker buildx build --platform linux/amd64 -t kazsign-builder-amd64 .
#   docker buildx build --platform linux/arm64 -t kazsign-builder-arm64 .
#
# Output:
#   dist/linux-{arch}/libkazsign_128.so
#   dist/linux-{arch}/libkazsign_192.so
#   dist/linux-{arch}/libkazsign_256.so

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /src

# Copy source files
COPY Makefile .
COPY VERSION .
COPY include/ include/
COPY src/ src/

# Build shared libraries for all security levels
RUN make shared-all

# Detect architecture and prepare output
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ARCH_NAME="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ARCH_NAME="arm64"; \
    else \
        ARCH_NAME="$ARCH"; \
    fi && \
    mkdir -p /output/linux-$ARCH_NAME && \
    cp build/lib/*.so /output/linux-$ARCH_NAME/ && \
    echo "Built libraries for linux-$ARCH_NAME:" && \
    ls -la /output/linux-$ARCH_NAME/

# Default command: copy libraries to mounted volume
CMD ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ARCH_NAME="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ARCH_NAME="arm64"; \
    else \
        ARCH_NAME="$ARCH"; \
    fi && \
    mkdir -p /dist/linux-$ARCH_NAME && \
    cp /output/linux-$ARCH_NAME/*.so /dist/linux-$ARCH_NAME/ && \
    echo "Libraries copied to /dist/linux-$ARCH_NAME/" && \
    ls -la /dist/linux-$ARCH_NAME/
