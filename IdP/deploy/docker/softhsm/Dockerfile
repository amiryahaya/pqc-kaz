# SoftHSM2 Docker Image for Development
# Provides PKCS#11 interface for cryptographic operations

FROM alpine:3.19

# Install SoftHSM2 and required tools
RUN apk add --no-cache \
    softhsm \
    opensc \
    p11-kit \
    && mkdir -p /var/lib/softhsm/tokens \
    && chmod 755 /var/lib/softhsm/tokens

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Environment
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV TOKEN_LABEL=idp-dev-token
ENV SO_PIN=12345678
ENV USER_PIN=87654321

# Volume for persistent token storage
VOLUME ["/var/lib/softhsm/tokens"]

ENTRYPOINT ["/entrypoint.sh"]

# Keep container running
CMD ["tail", "-f", "/dev/null"]
