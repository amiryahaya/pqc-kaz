-- PQC Identity Platform - Database Schema
-- Version: 1.0.0

-- Create schemas for each module
CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS certificate;
CREATE SCHEMA IF NOT EXISTS crypto;
CREATE SCHEMA IF NOT EXISTS admin;

-- Grant usage
GRANT USAGE ON SCHEMA identity TO postgres;
GRANT USAGE ON SCHEMA certificate TO postgres;
GRANT USAGE ON SCHEMA crypto TO postgres;
GRANT USAGE ON SCHEMA admin TO postgres;

-- ============================================
-- IDENTITY MODULE
-- ============================================

-- Users table
CREATE TABLE identity.users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    email VARCHAR(256) NOT NULL,
    phone_number VARCHAR(20),
    display_name VARCHAR(100),
    status SMALLINT NOT NULL DEFAULT 0,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_end_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT uq_users_email UNIQUE (email)
);

CREATE INDEX idx_users_email ON identity.users (email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_phone ON identity.users (phone_number) WHERE phone_number IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_users_status ON identity.users (status) WHERE deleted_at IS NULL;

-- User credentials table (passkeys, TOTP, recovery codes)
CREATE TABLE identity.user_credentials (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    type SMALLINT NOT NULL,
    name VARCHAR(100) NOT NULL,
    credential_data BYTEA NOT NULL,
    public_key BYTEA,
    device_info VARCHAR(500),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER NOT NULL DEFAULT 0,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_user_credentials_user_id ON identity.user_credentials (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_user_credentials_type ON identity.user_credentials (user_id, type) WHERE deleted_at IS NULL;
CREATE INDEX idx_user_credentials_data ON identity.user_credentials (credential_data) WHERE deleted_at IS NULL;

-- User sessions table
CREATE TABLE identity.user_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_fingerprint VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT uq_sessions_refresh_token UNIQUE (refresh_token_hash)
);

CREATE INDEX idx_user_sessions_user_id ON identity.user_sessions (user_id);
CREATE INDEX idx_user_sessions_expires ON identity.user_sessions (expires_at) WHERE revoked_at IS NULL;

-- ============================================
-- CERTIFICATE MODULE
-- ============================================

-- Certificates table
CREATE TABLE certificate.certificates (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID REFERENCES identity.users(id),
    serial_number VARCHAR(64) NOT NULL,
    subject_dn VARCHAR(500) NOT NULL,
    issuer_dn VARCHAR(500) NOT NULL,
    issuer_id UUID REFERENCES certificate.certificates(id),
    type SMALLINT NOT NULL,
    status SMALLINT NOT NULL DEFAULT 1,
    algorithm SMALLINT NOT NULL,
    public_key BYTEA NOT NULL,
    certificate_data BYTEA NOT NULL,
    thumbprint VARCHAR(64) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason SMALLINT,
    key_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT uq_certificates_serial UNIQUE (serial_number),
    CONSTRAINT uq_certificates_thumbprint UNIQUE (thumbprint)
);

CREATE INDEX idx_certificates_user_id ON certificate.certificates (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_status ON certificate.certificates (status) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_not_after ON certificate.certificates (not_after) WHERE status = 1;
CREATE INDEX idx_certificates_issuer_id ON certificate.certificates (issuer_id);

-- Certificate serial number sequence
CREATE SEQUENCE certificate.serial_number_seq START 1;

-- ============================================
-- CRYPTO MODULE
-- ============================================

-- Crypto keys table
CREATE TABLE crypto.keys (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID REFERENCES identity.users(id),
    label VARCHAR(100) NOT NULL,
    algorithm SMALLINT NOT NULL,
    purpose SMALLINT NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    storage_type SMALLINT NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA,
    hsm_key_handle VARCHAR(256),
    cloud_kms_key_id VARCHAR(256),
    key_fingerprint VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    use_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT uq_keys_fingerprint UNIQUE (key_fingerprint)
);

CREATE INDEX idx_crypto_keys_user_id ON crypto.keys (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_crypto_keys_algorithm ON crypto.keys (algorithm, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_crypto_keys_hsm_handle ON crypto.keys (hsm_key_handle) WHERE hsm_key_handle IS NOT NULL;

-- ============================================
-- ADMIN MODULE
-- ============================================

-- Audit logs table (append-only)
CREATE TABLE admin.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    action SMALLINT NOT NULL,
    severity SMALLINT NOT NULL DEFAULT 0,
    actor_id UUID,
    actor_email VARCHAR(256),
    target_id UUID,
    target_type VARCHAR(50),
    description TEXT NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    additional_data JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition audit logs by month for better performance
-- In production, you would create monthly partitions
CREATE INDEX idx_audit_logs_timestamp ON admin.audit_logs (timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON admin.audit_logs (actor_id, timestamp DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_target ON admin.audit_logs (target_id, target_type, timestamp DESC) WHERE target_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON admin.audit_logs (action, timestamp DESC);
CREATE INDEX idx_audit_logs_severity ON admin.audit_logs (severity, timestamp DESC) WHERE severity > 0;

-- ============================================
-- COMMENTS
-- ============================================

COMMENT ON SCHEMA identity IS 'Identity management module - users, credentials, sessions';
COMMENT ON SCHEMA certificate IS 'Certificate management module - X.509 certificates with PQC';
COMMENT ON SCHEMA crypto IS 'Cryptographic key management module - ML-DSA/ML-KEM keys';
COMMENT ON SCHEMA admin IS 'Administration module - audit logs, configuration';

COMMENT ON TABLE identity.users IS 'User accounts';
COMMENT ON TABLE identity.user_credentials IS 'User authentication credentials (passkeys, TOTP, etc.)';
COMMENT ON TABLE identity.user_sessions IS 'Active user sessions with refresh tokens';
COMMENT ON TABLE certificate.certificates IS 'X.509 certificates with PQC algorithms';
COMMENT ON TABLE crypto.keys IS 'Cryptographic key pairs (ML-DSA, ML-KEM)';
COMMENT ON TABLE admin.audit_logs IS 'Immutable audit log entries';
