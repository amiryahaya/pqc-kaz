#!/bin/bash
# Initialize SoftHSM2 tokens for IdP development

set -e

echo "=========================================="
echo " SoftHSM2 Token Initialization"
echo "=========================================="

# Default PINs (for development only!)
USER_PIN="${USER_PIN:-1234}"
SO_PIN="${SO_PIN:-5678}"

# Token labels
ROOT_CA_TOKEN="idp-root-ca"
TENANT_CA_TOKEN="idp-tenant-ca"
JWT_SIGNING_TOKEN="idp-jwt-signing"

# Function to initialize a token if it doesn't exist
init_token() {
    local label=$1
    local slot=$2

    # Check if token already exists
    if softhsm2-util --show-slots 2>/dev/null | grep -q "Label: $label"; then
        echo "[OK] Token '$label' already exists"
        return 0
    fi

    echo "[INIT] Creating token '$label' in slot $slot..."
    softhsm2-util --init-token \
        --slot $slot \
        --label "$label" \
        --pin "$USER_PIN" \
        --so-pin "$SO_PIN"

    echo "[OK] Token '$label' created successfully"
}

# Wait for any mounted volumes to be ready
sleep 2

# Initialize tokens
echo ""
echo "Initializing tokens..."
echo ""

# Get available slots
SLOTS=$(softhsm2-util --show-slots 2>/dev/null | grep "Slot " | head -3 | awk '{print $2}')

SLOT_NUM=0
for TOKEN_LABEL in "$ROOT_CA_TOKEN" "$TENANT_CA_TOKEN" "$JWT_SIGNING_TOKEN"; do
    init_token "$TOKEN_LABEL" $SLOT_NUM
    SLOT_NUM=$((SLOT_NUM + 1))
done

echo ""
echo "=========================================="
echo " Token Initialization Complete"
echo "=========================================="
echo ""
echo "Available tokens:"
softhsm2-util --show-slots
echo ""
echo "PKCS#11 Library: /usr/lib/softhsm/libsofthsm2.so"
echo "User PIN: $USER_PIN (development only!)"
echo "SO PIN: $SO_PIN (development only!)"
echo ""
echo "=========================================="

# Keep container running
echo "SoftHSM2 is ready. Container will stay running..."
tail -f /dev/null
