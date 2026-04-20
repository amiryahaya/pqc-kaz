cmake_minimum_required(VERSION 3.22.1)
project("kazkem")

# KEM source directory
set(KEM_ROOT "${CMAKE_SOURCE_DIR}/../../../../../.." CACHE PATH "Path to KEM root")

# OpenSSL paths for Android - built by scripts/build-openssl-android.sh
set(OPENSSL_ROOT "${CMAKE_SOURCE_DIR}/../libs/openssl/${ANDROID_ABI}")

# Include directories
include_directories(
    ${KEM_ROOT}/include
    ${KEM_ROOT}/src/internal
    ${OPENSSL_ROOT}/include
)

# Link directories
link_directories(
    ${OPENSSL_ROOT}/lib
)

# Source files
set(KEM_SOURCES
    ${KEM_ROOT}/src/internal/kem_secure.c
    ${KEM_ROOT}/src/internal/nist_wrapper.c
)

# JNI bridge
set(JNI_SOURCES
    kazkem_jni.cpp
)

# Build shared library
add_library(kazkem SHARED
    ${KEM_SOURCES}
    ${JNI_SOURCES}
)

# Compiler definitions
target_compile_definitions(kazkem PRIVATE
    KAZ_KEM_USE_OPENSSL
    KAZ_KEM_VERSION="2.1.0"
    KAZ_KEM_VERSION_MAJOR=2
    KAZ_KEM_VERSION_MINOR=1
    KAZ_KEM_VERSION_PATCH=0
)

# Compiler flags
target_compile_options(kazkem PRIVATE
    -O3
    -Wall
    -fPIC
    -fvisibility=hidden
)

# Find required libraries
find_library(log-lib log)

# 16KB page alignment for Android 15+ compatibility
target_link_options(kazkem PRIVATE
    -Wl,-z,max-page-size=16384
)

# Link libraries
target_link_libraries(kazkem
    ${log-lib}
    ${OPENSSL_ROOT}/lib/libcrypto.a
)
