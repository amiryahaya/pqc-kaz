#!/usr/bin/env zsh
#
# KAZ-SIGN v2.0 Cross-Language Interop Test
#
# Tests that C library and Java kaz-pqc-core-v2.0 can:
#   1. C signs → Java verifies
#   2. Java signs → C verifies
#
# Simulates SSDID registry register+proof flow.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGN_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
JAVA_SRC="$HOME/Workspace/SSDID/src/kaz-pqc-core-v2.0"
BUILD_DIR="$SIGN_DIR/build/interop"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

mkdir -p "$BUILD_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  KAZ-SIGN v2.0 Cross-Language Interoperability Test"
echo "  C library ↔ Java kaz-pqc-core-v2.0"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ---------- Build C interop binary ----------
echo "[1/3] Building C interop test..."
OPENSSL_PREFIX="$(brew --prefix openssl@3)"
GMP_PREFIX="$(brew --prefix gmp)"
gcc -Wall -Wextra -O2 \
    -I "$SIGN_DIR/include" \
    -I "$OPENSSL_PREFIX/include" \
    "$SCRIPT_DIR/c_sign.c" \
    "$SIGN_DIR/src/internal/sign.c" \
    "$SIGN_DIR/src/internal/security.c" \
    -L "$OPENSSL_PREFIX/lib" -L "$GMP_PREFIX/lib" -lssl -lcrypto -lgmp \
    -DKAZ_SIGN_LEVEL=128 \
    -o "$BUILD_DIR/c_sign"
echo "  C binary: OK"

# ---------- Build Java interop class ----------
echo "[2/3] Building Java interop test..."
JAVA_CLASSES="$JAVA_SRC/target/classes"
if [ ! -d "$JAVA_CLASSES" ]; then
    echo "  Compiling Java kaz-pqc-core-v2.0..."
    (cd "$JAVA_SRC" && mvn compile -q)
fi
javac -cp "$JAVA_CLASSES" -d "$BUILD_DIR" "$SCRIPT_DIR/JavaSign.java"
echo "  Java class: OK"
echo ""

# ---------- Run interop tests ----------
run_test() {
    local level=$1
    local direction=$2
    local label

    if [ "$direction" = "c2j" ]; then
        label="C signs → Java verifies (level $level)"
        echo -n "  [$((pass+fail+1))] $label  "

        # C generates keypair + signature
        c_output=$("$BUILD_DIR/c_sign" generate "$level" 2>/dev/null)

        # Java verifies
        j_result=$(echo "$c_output" | java -cp "$BUILD_DIR:$JAVA_CLASSES" JavaSign verify "$level" 2>/dev/null)

        if echo "$j_result" | grep -q "verify=PASS"; then
            echo -e "${GREEN}PASS${NC}"
            pass=$((pass + 1))
        else
            echo -e "${RED}FAIL${NC}"
            echo "    C output: $(echo "$c_output" | head -3)"
            echo "    Java result: $j_result"
            fail=$((fail + 1))
        fi

    elif [ "$direction" = "j2c" ]; then
        label="Java signs → C verifies (level $level)"
        echo -n "  [$((pass+fail+1))] $label  "

        # Java generates keypair + signature
        j_output=$(java -cp "$BUILD_DIR:$JAVA_CLASSES" JavaSign generate "$level" 2>/dev/null)

        # C verifies
        c_result=$(echo "$j_output" | "$BUILD_DIR/c_sign" verify "$level" 2>/dev/null)

        if echo "$c_result" | grep -q "verify=PASS"; then
            echo -e "${GREEN}PASS${NC}"
            pass=$((pass + 1))
        else
            echo -e "${RED}FAIL${NC}"
            echo "    Java output: $(echo "$j_output" | head -3)"
            echo "    C result: $c_result"
            fail=$((fail + 1))
        fi
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  C → Java (C signs DID Document, Java verifies proof)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for level in 128 192 256; do
    run_test "$level" c2j
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Java → C (Java signs DID Document, C verifies proof)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for level in 128 192 256; do
    run_test "$level" j2c
done

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Interop Test Summary                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Passed:         ${GREEN}%2d${NC}                                         ║\n" "$pass"
printf "║  Failed:         ${RED}%2d${NC}                                         ║\n" "$fail"
echo "╠══════════════════════════════════════════════════════════════╣"
if [ "$fail" -eq 0 ]; then
    echo -e "║  ${GREEN}✓ ALL INTEROP TESTS PASSED${NC}                                  ║"
else
    echo -e "║  ${RED}✗ SOME INTEROP TESTS FAILED${NC}                                 ║"
fi
echo "╚══════════════════════════════════════════════════════════════╝"

exit "$fail"
