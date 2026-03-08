#!/bin/sh
set -e

# SoftHSM2 Initialization Script
# Initializes token if not already present

TOKEN_DIR="/var/lib/softhsm/tokens"
MARKER_FILE="${TOKEN_DIR}/.initialized"

echo "Starting SoftHSM2 initialization..."

# Check if token is already initialized
if [ -f "$MARKER_FILE" ]; then
    echo "Token already initialized, skipping..."
else
    echo "Initializing new token..."
    
    # Initialize the token
    softhsm2-util --init-token \
        --slot 0 \
        --label "${TOKEN_LABEL:-idp-dev-token}" \
        --so-pin "${SO_PIN:-12345678}" \
        --pin "${USER_PIN:-87654321}"
    
    # Create marker file
    touch "$MARKER_FILE"
    
    echo "Token initialized successfully!"
    echo "  Label: ${TOKEN_LABEL:-idp-dev-token}"
    echo "  SO PIN: ${SO_PIN:-12345678}"
    echo "  User PIN: ${USER_PIN:-87654321}"
fi

# Show token info
echo ""
echo "Available tokens:"
softhsm2-util --show-slots

# Execute CMD
exec "$@"
