# Database Schema Design

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft
**Database:** PostgreSQL 18
**Primary Key Strategy:** UUID v7 with `uuidv7()` default

---

## Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [Multi-Tenancy Strategy](#multi-tenancy-strategy)
4. [Schema Organization](#schema-organization)
5. [Core Tables](#core-tables)
6. [Identity Module Tables](#identity-module-tables)
7. [Certificate Module Tables](#certificate-module-tables)
8. [Admin Module Tables](#admin-module-tables)
9. [Crypto Module Tables](#crypto-module-tables)
10. [Indexes & Performance](#indexes--performance)
11. [Partitioning Strategy](#partitioning-strategy)
12. [Audit & Compliance](#audit--compliance)
13. [Migration Strategy](#migration-strategy)
14. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

This document defines the PostgreSQL 18 database schema for the Digital ID Platform. The schema supports multi-tenancy, PQC certificates, and comprehensive audit logging.

### Key Features

- **UUID v7 Primary Keys** - Time-ordered UUIDs using PostgreSQL 18's native `uuidv7()`
- **Multi-Tenant Isolation** - Schema-per-tenant with shared platform tables
- **Soft Deletes** - `deleted_at` column for recoverable deletion
- **Audit Columns** - `created_at`, `updated_at`, `created_by`, `updated_by` on all tables
- **JSONB for Flexibility** - Metadata and configuration stored as JSONB
- **Partitioning** - Time-based partitioning for audit logs
- **Dapper Integration** - Optimized for Dapper micro ORM with raw SQL queries

### PostgreSQL 18 Features Used

| Feature | Usage |
|---------|-------|
| `uuidv7()` | Time-ordered UUID primary keys |
| `GENERATED ALWAYS AS` | Computed columns |
| JSONB | Flexible metadata storage |
| Table Partitioning | Audit log partitioning |
| Row-Level Security | Multi-tenant data isolation |
| `pg_trgm` | Full-text search on names/emails |

---

## Design Principles

### 1. UUID v7 Primary Keys

```sql
-- All tables use UUID v7 as primary key
CREATE TABLE example (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    -- ...
);
```

**Benefits of UUID v7:**
- Time-ordered (sortable by creation time)
- No central coordination needed
- Safe for distributed systems
- Contains timestamp information

### 2. Standard Audit Columns

```sql
-- Every table includes these columns
CREATE TABLE example (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    -- ... business columns ...

    -- Audit columns
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,  -- Soft delete
    version INTEGER NOT NULL DEFAULT 1  -- Optimistic locking
);

-- Auto-update updated_at
CREATE TRIGGER update_timestamp
    BEFORE UPDATE ON example
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### 3. Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Tables | snake_case, plural | `users`, `user_devices` |
| Columns | snake_case | `display_name`, `created_at` |
| Primary Keys | `id` | `id UUID` |
| Foreign Keys | `{table}_id` | `user_id`, `tenant_id` |
| Indexes | `idx_{table}_{columns}` | `idx_users_email` |
| Constraints | `{table}_{type}_{columns}` | `users_uq_email` |

### 4. Common Column Types

| Data | PostgreSQL Type |
|------|-----------------|
| Identifiers | `UUID` |
| Timestamps | `TIMESTAMPTZ` |
| Short text | `VARCHAR(n)` |
| Long text | `TEXT` |
| Binary data | `BYTEA` |
| JSON | `JSONB` |
| Enums | `VARCHAR(50)` or custom ENUM |
| Money | `NUMERIC(19,4)` |
| Boolean | `BOOLEAN` |

---

## Multi-Tenancy Strategy

### Hybrid Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MULTI-TENANCY ARCHITECTURE                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  SHARED SCHEMA: public                                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   tenants   │  │platform_    │  │  root_ca_   │  │  platform_  │        │
│  │             │  │  admins     │  │ certificates│  │   config    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  TENANT SCHEMA: tenant_{slug}                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    users    │  │   devices   │  │certificates │  │   audit_    │        │
│  │             │  │             │  │             │  │    logs     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  oidc_      │  │  webhooks   │  │  policies   │  │  recovery_  │        │
│  │  clients    │  │             │  │             │  │    data     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Schema Creation for New Tenant

```sql
-- Create tenant schema
CREATE SCHEMA tenant_acme_corp;

-- Set search path for tenant operations
SET search_path TO tenant_acme_corp, public;

-- Apply tenant table definitions
-- (Using migration scripts)
```

### Row-Level Security (RLS)

```sql
-- Enable RLS on shared tables
ALTER TABLE public.audit_logs_shared ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's data
CREATE POLICY tenant_isolation ON public.audit_logs_shared
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
```

---

## Schema Organization

### Public Schema (Shared)

```sql
-- Platform-wide tables
public.tenants
public.platform_admins
public.platform_config
public.root_ca_certificates
public.global_audit_logs (partitioned)
```

### Tenant Schema Template

```sql
-- Per-tenant tables (template)
tenant_{slug}.users
tenant_{slug}.user_invitations
tenant_{slug}.user_devices
tenant_{slug}.device_pairing_sessions
tenant_{slug}.certificates
tenant_{slug}.certificate_renewals
tenant_{slug}.recovery_data
tenant_{slug}.recovery_sessions
tenant_{slug}.auth_sessions
tenant_{slug}.qr_sessions
tenant_{slug}.oidc_clients
tenant_{slug}.oidc_tokens
tenant_{slug}.webhooks
tenant_{slug}.webhook_deliveries
tenant_{slug}.policies
tenant_{slug}.audit_logs (partitioned)
tenant_{slug}.tenant_admins
tenant_{slug}.admin_roles
```

---

## Core Tables

### Tenants Table (Public Schema)

```sql
-- public.tenants
CREATE TABLE public.tenants (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    -- Basic info
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    primary_domain VARCHAR(255) NOT NULL UNIQUE,
    additional_domains TEXT[] DEFAULT '{}',

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'provisioning',
    -- provisioning, pending_admin_setup, trial, active, suspended, cancelled, archived

    type VARCHAR(50) NOT NULL DEFAULT 'standard',
    -- standard, enterprise, regulated, government

    tier VARCHAR(50) NOT NULL DEFAULT 'starter',
    -- free, starter, professional, enterprise, government

    -- Algorithm configuration
    primary_algorithm VARCHAR(50) NOT NULL,
    -- KAZ-SIGN-128, KAZ-SIGN-192, KAZ-SIGN-256, ML-DSA-44, ML-DSA-65, ML-DSA-87
    allowed_algorithms TEXT[] NOT NULL DEFAULT '{}',

    -- CA reference
    ca_key_id VARCHAR(255),
    ca_certificate_id UUID,

    -- Limits
    max_users INTEGER NOT NULL DEFAULT 100,
    max_devices_per_user INTEGER NOT NULL DEFAULT 5,
    max_oidc_clients INTEGER NOT NULL DEFAULT 10,

    -- Data residency
    region VARCHAR(50) NOT NULL,
    data_residency_country VARCHAR(2) NOT NULL,

    -- Billing
    billing_email VARCHAR(255),
    billing_id VARCHAR(255),
    trial_ends_at TIMESTAMPTZ,

    -- Branding (JSONB for flexibility)
    branding JSONB DEFAULT '{}',
    /*
    {
        "logo_url": "https://...",
        "logo_dark_url": "https://...",
        "primary_color": "#0066CC",
        "secondary_color": "#003366",
        "app_name": "Digital ID"
    }
    */

    -- Configuration (JSONB)
    configuration JSONB DEFAULT '{}',
    /*
    {
        "features": {...},
        "security_policy": {...},
        "device_policy": {...}
    }
    */

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255),
    activated_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,
    deleted_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT tenants_status_check CHECK (
        status IN ('provisioning', 'pending_admin_setup', 'trial', 'active', 'suspended', 'cancelled', 'archived')
    ),
    CONSTRAINT tenants_type_check CHECK (
        type IN ('standard', 'enterprise', 'regulated', 'government')
    ),
    CONSTRAINT tenants_tier_check CHECK (
        tier IN ('free', 'starter', 'professional', 'enterprise', 'government')
    )
);

-- Indexes
CREATE INDEX idx_tenants_slug ON public.tenants(slug);
CREATE INDEX idx_tenants_primary_domain ON public.tenants(primary_domain);
CREATE INDEX idx_tenants_status ON public.tenants(status);
CREATE INDEX idx_tenants_deleted_at ON public.tenants(deleted_at) WHERE deleted_at IS NULL;
```

### Platform Admins Table

```sql
-- public.platform_admins
CREATE TABLE public.platform_admins (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),

    role VARCHAR(50) NOT NULL DEFAULT 'support',
    -- super_admin, admin, support

    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- active, suspended

    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret_encrypted BYTEA,

    last_login_at TIMESTAMPTZ,
    last_login_ip INET,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_platform_admins_email ON public.platform_admins(email);
```

---

## Identity Module Tables

### Users Table

```sql
-- tenant_{slug}.users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    -- Identity
    email VARCHAR(255) NOT NULL,
    email_normalized VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, active, suspended, deleted

    role VARCHAR(50) NOT NULL DEFAULT 'user',
    -- user, admin

    -- Profile
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(50),
    department VARCHAR(100),
    job_title VARCHAR(100),

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Email verification
    email_verified BOOLEAN NOT NULL DEFAULT false,
    email_verified_at TIMESTAMPTZ,

    -- Activity
    last_login_at TIMESTAMPTZ,
    last_login_device_id UUID,
    last_login_ip INET,
    login_count INTEGER NOT NULL DEFAULT 0,

    -- Suspension
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,
    suspended_by UUID,

    -- External ID (for SCIM sync)
    external_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,
    version INTEGER NOT NULL DEFAULT 1,

    -- Constraints
    CONSTRAINT users_email_unique UNIQUE (email),
    CONSTRAINT users_email_normalized_unique UNIQUE (email_normalized),
    CONSTRAINT users_status_check CHECK (
        status IN ('pending', 'active', 'suspended', 'deleted')
    ),
    CONSTRAINT users_role_check CHECK (
        role IN ('user', 'admin')
    )
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_normalized ON users(email_normalized);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_display_name_trgm ON users USING gin(display_name gin_trgm_ops);
```

### User Invitations Table

```sql
-- tenant_{slug}.user_invitations
CREATE TABLE user_invitations (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),

    token_hash VARCHAR(255) NOT NULL UNIQUE,

    role VARCHAR(50) NOT NULL DEFAULT 'user',
    department VARCHAR(100),
    groups UUID[] DEFAULT '{}',

    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, accepted, expired, revoked

    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_user_id UUID,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,

    CONSTRAINT invitations_status_check CHECK (
        status IN ('pending', 'accepted', 'expired', 'revoked')
    )
);

CREATE INDEX idx_invitations_email ON user_invitations(email);
CREATE INDEX idx_invitations_token_hash ON user_invitations(token_hash);
CREATE INDEX idx_invitations_status ON user_invitations(status);
CREATE INDEX idx_invitations_expires_at ON user_invitations(expires_at);
```

### User Devices Table

```sql
-- tenant_{slug}.user_devices
CREATE TABLE user_devices (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id),

    -- Device info
    display_name VARCHAR(255) NOT NULL,
    model VARCHAR(100),
    model_identifier VARCHAR(100),
    platform VARCHAR(50) NOT NULL,
    -- iOS, Android, macOS, Windows
    os_version VARCHAR(50),
    app_version VARCHAR(50),

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- pending_approval, active, suspended, revoked

    is_primary BOOLEAN NOT NULL DEFAULT false,
    allow_signing BOOLEAN NOT NULL DEFAULT false,

    -- Certificate reference
    certificate_serial_number VARCHAR(100),
    certificate_expires_at TIMESTAMPTZ,

    -- Push notifications
    push_token TEXT,
    push_platform VARCHAR(20),
    -- apns, fcm
    push_token_updated_at TIMESTAMPTZ,

    -- Security
    has_secure_enclave BOOLEAN NOT NULL DEFAULT false,
    biometric_type VARCHAR(20),
    -- face_id, touch_id, fingerprint, none

    attestation_data BYTEA,
    attestation_verified BOOLEAN NOT NULL DEFAULT false,
    attestation_verified_at TIMESTAMPTZ,

    -- Activity
    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ,
    last_used_location VARCHAR(255),
    last_used_ip INET,
    use_count INTEGER NOT NULL DEFAULT 0,

    -- Suspension/Revocation
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,
    suspended_by VARCHAR(100),
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    revoked_by VARCHAR(100),
    reported_lost_at TIMESTAMPTZ,
    reported_lost_by VARCHAR(100),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ,
    version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT devices_status_check CHECK (
        status IN ('pending_approval', 'active', 'suspended', 'revoked')
    ),
    CONSTRAINT devices_platform_check CHECK (
        platform IN ('iOS', 'Android', 'macOS', 'Windows')
    )
);

-- Indexes
CREATE INDEX idx_devices_user_id ON user_devices(user_id);
CREATE INDEX idx_devices_status ON user_devices(status);
CREATE INDEX idx_devices_certificate_serial ON user_devices(certificate_serial_number);
CREATE INDEX idx_devices_is_primary ON user_devices(user_id, is_primary) WHERE is_primary = true;
CREATE INDEX idx_devices_push_token ON user_devices(push_token) WHERE push_token IS NOT NULL;
CREATE INDEX idx_devices_deleted_at ON user_devices(deleted_at) WHERE deleted_at IS NULL;

-- Ensure only one primary device per user
CREATE UNIQUE INDEX idx_devices_one_primary_per_user
    ON user_devices(user_id)
    WHERE is_primary = true AND status = 'active' AND deleted_at IS NULL;
```

### Device Pairing Sessions Table

```sql
-- tenant_{slug}.device_pairing_sessions
CREATE TABLE device_pairing_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    user_id UUID NOT NULL REFERENCES users(id),
    initiator_device_id UUID NOT NULL REFERENCES user_devices(id),

    challenge VARCHAR(255) NOT NULL,

    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, scanned, approved, denied, expired, completed

    -- New device info (populated when scanned)
    new_device_id UUID,
    new_device_info JSONB,
    new_device_csr BYTEA,
    new_device_public_key BYTEA,

    -- Key share transfer (encrypted)
    encrypted_key_share BYTEA,

    -- Timestamps
    expires_at TIMESTAMPTZ NOT NULL,
    scanned_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pairing_status_check CHECK (
        status IN ('pending', 'scanned', 'approved', 'denied', 'expired', 'completed')
    )
);

CREATE INDEX idx_pairing_sessions_user_id ON device_pairing_sessions(user_id);
CREATE INDEX idx_pairing_sessions_status ON device_pairing_sessions(status);
CREATE INDEX idx_pairing_sessions_expires_at ON device_pairing_sessions(expires_at);
```

### Recovery Data Table

```sql
-- tenant_{slug}.recovery_data
CREATE TABLE recovery_data (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id),

    -- Encrypted key shares
    encrypted_part_control BYTEA NOT NULL,
    control_key_id VARCHAR(255) NOT NULL,  -- HSM key reference

    encrypted_part_recovery BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,

    -- Verification data
    part_recovery_hash BYTEA NOT NULL,
    user_public_key BYTEA NOT NULL,

    algorithm VARCHAR(50) NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT true,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_recovery_data_user_id ON recovery_data(user_id);
```

### Recovery Sessions Table

```sql
-- tenant_{slug}.recovery_sessions
CREATE TABLE recovery_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id),

    email VARCHAR(255) NOT NULL,
    new_device_id VARCHAR(255) NOT NULL,

    status VARCHAR(50) NOT NULL DEFAULT 'pending_email_verification',
    -- pending_email_verification, email_verified, password_verified, completed, failed, expired, cancelled

    -- OTP
    otp_hash VARCHAR(255),
    otp_expires_at TIMESTAMPTZ,
    otp_attempts INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    expires_at TIMESTAMPTZ NOT NULL,
    email_verified_at TIMESTAMPTZ,
    password_verified_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Failure tracking
    failure_reason TEXT,

    -- Context
    ip_address INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT recovery_status_check CHECK (
        status IN ('pending_email_verification', 'email_verified', 'password_verified',
                   'completed', 'failed', 'expired', 'cancelled')
    )
);

CREATE INDEX idx_recovery_sessions_user_id ON recovery_sessions(user_id);
CREATE INDEX idx_recovery_sessions_status ON recovery_sessions(status);
CREATE INDEX idx_recovery_sessions_expires_at ON recovery_sessions(expires_at);
```

---

## Certificate Module Tables

### Certificates Table

```sql
-- tenant_{slug}.certificates
CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    -- Owner
    user_id UUID REFERENCES users(id),
    device_id UUID REFERENCES user_devices(id),

    -- Certificate identity
    serial_number VARCHAR(100) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    -- root_ca, tenant_ca, user, device

    -- Certificate data
    subject VARCHAR(500) NOT NULL,
    issuer VARCHAR(500) NOT NULL,
    certificate_data BYTEA NOT NULL,  -- DER encoded
    public_key BYTEA NOT NULL,
    private_key_id VARCHAR(255),  -- HSM key reference (for CA certs)

    -- Validity
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,

    -- Algorithm
    algorithm VARCHAR(50) NOT NULL,
    key_size INTEGER,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- pending, active, suspended, superseded, revoked, expired

    -- Revocation
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(50),
    -- key_compromise, ca_compromise, affiliation_changed, superseded,
    -- cessation_of_operation, certificate_hold, privilege_withdrawn
    revocation_note TEXT,

    -- Renewal chain
    previous_certificate_id UUID REFERENCES certificates(id),
    superseded_at TIMESTAMPTZ,
    superseded_by UUID,

    -- Key info
    key_generated_at TIMESTAMPTZ,
    signature_count INTEGER NOT NULL DEFAULT 0,
    suspected_compromise BOOLEAN NOT NULL DEFAULT false,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT certificates_type_check CHECK (
        type IN ('root_ca', 'tenant_ca', 'user', 'device')
    ),
    CONSTRAINT certificates_status_check CHECK (
        status IN ('pending', 'active', 'suspended', 'superseded', 'revoked', 'expired')
    )
);

-- Indexes
CREATE INDEX idx_certificates_serial_number ON certificates(serial_number);
CREATE INDEX idx_certificates_user_id ON certificates(user_id);
CREATE INDEX idx_certificates_device_id ON certificates(device_id);
CREATE INDEX idx_certificates_type ON certificates(type);
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);
CREATE INDEX idx_certificates_algorithm ON certificates(algorithm);

-- Active user certificate lookup
CREATE INDEX idx_certificates_active_user
    ON certificates(user_id, type)
    WHERE status = 'active' AND type = 'user';

-- Active device certificate lookup
CREATE INDEX idx_certificates_active_device
    ON certificates(device_id, type)
    WHERE status = 'active' AND type = 'device';
```

### Certificate Renewals Table

```sql
-- tenant_{slug}.certificate_renewals
CREATE TABLE certificate_renewals (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    original_certificate_id UUID NOT NULL REFERENCES certificates(id),
    new_certificate_id UUID REFERENCES certificates(id),

    original_serial_number VARCHAR(100) NOT NULL,
    new_serial_number VARCHAR(100),

    renewal_type VARCHAR(50) NOT NULL,
    -- automatic, manual, grace_period, key_rotation, algorithm_upgrade, admin_initiated

    renewal_reason VARCHAR(100),
    reason_details TEXT,

    key_rotated BOOLEAN NOT NULL DEFAULT false,
    old_algorithm VARCHAR(50),
    new_algorithm VARCHAR(50),

    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, completed, failed

    -- Timestamps
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    initiated_by VARCHAR(100),
    -- system, user_id, admin_id

    error_message TEXT,

    CONSTRAINT renewals_type_check CHECK (
        renewal_type IN ('automatic', 'manual', 'grace_period', 'key_rotation',
                        'algorithm_upgrade', 'admin_initiated')
    ),
    CONSTRAINT renewals_status_check CHECK (
        status IN ('pending', 'completed', 'failed')
    )
);

CREATE INDEX idx_renewals_original_cert ON certificate_renewals(original_certificate_id);
CREATE INDEX idx_renewals_status ON certificate_renewals(status);
```

### Certificate Revocation List Table

```sql
-- tenant_{slug}.certificate_revocations
CREATE TABLE certificate_revocations (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    certificate_id UUID NOT NULL REFERENCES certificates(id),
    serial_number VARCHAR(100) NOT NULL,

    revocation_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(50) NOT NULL,
    invalidity_date TIMESTAMPTZ,

    crl_number BIGINT NOT NULL,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(255)
);

CREATE INDEX idx_revocations_serial ON certificate_revocations(serial_number);
CREATE INDEX idx_revocations_crl_number ON certificate_revocations(crl_number);
CREATE INDEX idx_revocations_date ON certificate_revocations(revocation_date);
```

---

## Admin Module Tables

### OIDC Clients Table

```sql
-- tenant_{slug}.oidc_clients
CREATE TABLE oidc_clients (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255),  -- NULL for public clients

    client_name VARCHAR(255) NOT NULL,
    client_description TEXT,
    client_uri VARCHAR(500),
    logo_uri VARCHAR(500),

    client_type VARCHAR(50) NOT NULL,
    -- confidential, public

    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- active, suspended, deleted

    -- URIs (arrays)
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] DEFAULT '{}',

    -- OAuth/OIDC configuration
    allowed_scopes TEXT[] NOT NULL DEFAULT '{openid}',
    allowed_grant_types TEXT[] NOT NULL DEFAULT '{authorization_code}',
    allowed_response_types TEXT[] NOT NULL DEFAULT '{code}',

    -- Security settings
    require_pkce BOOLEAN NOT NULL DEFAULT true,
    require_consent BOOLEAN NOT NULL DEFAULT false,
    allow_remember_consent BOOLEAN NOT NULL DEFAULT true,

    -- Token settings
    access_token_lifetime INTEGER NOT NULL DEFAULT 3600,
    refresh_token_lifetime INTEGER NOT NULL DEFAULT 2592000,
    id_token_lifetime INTEGER NOT NULL DEFAULT 3600,

    -- Authentication
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    -- client_secret_basic, client_secret_post, private_key_jwt, none

    -- Contacts
    contacts TEXT[] DEFAULT '{}',

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,
    deleted_at TIMESTAMPTZ,

    CONSTRAINT clients_type_check CHECK (
        client_type IN ('confidential', 'public')
    ),
    CONSTRAINT clients_status_check CHECK (
        status IN ('active', 'suspended', 'deleted')
    )
);

CREATE INDEX idx_oidc_clients_client_id ON oidc_clients(client_id);
CREATE INDEX idx_oidc_clients_status ON oidc_clients(status);
```

### Auth Sessions Table

```sql
-- tenant_{slug}.auth_sessions
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    client_id VARCHAR(100) NOT NULL,

    -- Request data
    redirect_uri VARCHAR(500) NOT NULL,
    scopes TEXT[] NOT NULL,
    state VARCHAR(500),
    nonce VARCHAR(500),

    -- PKCE
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),

    -- PAR
    request_uri VARCHAR(255) UNIQUE,

    -- ACR
    acr_values TEXT[],

    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, scanned, completed, denied, expired

    -- Completion
    user_id UUID,
    device_id UUID,
    authorization_code VARCHAR(255) UNIQUE,

    -- Timestamps
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    auth_time TIMESTAMPTZ,

    -- Context
    ip_address INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT auth_sessions_status_check CHECK (
        status IN ('pending', 'scanned', 'completed', 'denied', 'expired')
    )
);

CREATE INDEX idx_auth_sessions_client_id ON auth_sessions(client_id);
CREATE INDEX idx_auth_sessions_request_uri ON auth_sessions(request_uri);
CREATE INDEX idx_auth_sessions_authorization_code ON auth_sessions(authorization_code);
CREATE INDEX idx_auth_sessions_status ON auth_sessions(status);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
```

### QR Sessions Table

```sql
-- tenant_{slug}.qr_sessions
CREATE TABLE qr_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    session_type VARCHAR(50) NOT NULL,
    -- login, transaction, access, sign

    client_id VARCHAR(100),

    -- For login
    auth_session_id UUID REFERENCES auth_sessions(id),

    -- For transaction
    transaction_data JSONB,

    -- For access
    location_id VARCHAR(255),
    location_name VARCHAR(255),
    access_level VARCHAR(50),

    -- For signing
    document_data JSONB,

    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, scanned, approved, denied, expired

    -- Result
    user_id UUID,
    device_id UUID,
    authorization_signature BYTEA,

    -- Timestamps
    expires_at TIMESTAMPTZ NOT NULL,
    scanned_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Context
    scanned_ip INET,
    scanned_device_id UUID,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT qr_sessions_type_check CHECK (
        session_type IN ('login', 'transaction', 'access', 'sign')
    ),
    CONSTRAINT qr_sessions_status_check CHECK (
        status IN ('pending', 'scanned', 'approved', 'denied', 'expired')
    )
);

CREATE INDEX idx_qr_sessions_type ON qr_sessions(session_type);
CREATE INDEX idx_qr_sessions_status ON qr_sessions(status);
CREATE INDEX idx_qr_sessions_expires_at ON qr_sessions(expires_at);
CREATE INDEX idx_qr_sessions_auth_session ON qr_sessions(auth_session_id);
```

### OIDC Tokens Table

```sql
-- tenant_{slug}.oidc_tokens
CREATE TABLE oidc_tokens (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    client_id VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    device_id UUID REFERENCES user_devices(id),

    token_type VARCHAR(50) NOT NULL,
    -- access_token, refresh_token

    token_hash VARCHAR(255) NOT NULL UNIQUE,
    jti VARCHAR(255) NOT NULL UNIQUE,

    scopes TEXT[] NOT NULL,

    -- Validity
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    -- Refresh token chain
    parent_token_id UUID REFERENCES oidc_tokens(id),
    refresh_count INTEGER NOT NULL DEFAULT 0,

    -- Revocation
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100),

    -- Context
    ip_address INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT tokens_type_check CHECK (
        token_type IN ('access_token', 'refresh_token')
    )
);

CREATE INDEX idx_oidc_tokens_hash ON oidc_tokens(token_hash);
CREATE INDEX idx_oidc_tokens_jti ON oidc_tokens(jti);
CREATE INDEX idx_oidc_tokens_user_id ON oidc_tokens(user_id);
CREATE INDEX idx_oidc_tokens_client_id ON oidc_tokens(client_id);
CREATE INDEX idx_oidc_tokens_expires_at ON oidc_tokens(expires_at);
CREATE INDEX idx_oidc_tokens_parent ON oidc_tokens(parent_token_id);

-- Cleanup expired tokens
CREATE INDEX idx_oidc_tokens_cleanup
    ON oidc_tokens(expires_at)
    WHERE revoked = false;
```

### Webhooks Table

```sql
-- tenant_{slug}.webhooks
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,

    events TEXT[] NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Retry configuration
    retry_count INTEGER NOT NULL DEFAULT 3,
    timeout_seconds INTEGER NOT NULL DEFAULT 30,

    -- Stats
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    last_failure_reason TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_webhooks_enabled ON webhooks(enabled) WHERE enabled = true;
```

### Webhook Deliveries Table

```sql
-- tenant_{slug}.webhook_deliveries
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    webhook_id UUID NOT NULL REFERENCES webhooks(id),

    event_type VARCHAR(100) NOT NULL,
    event_id VARCHAR(255) NOT NULL,

    -- Request
    request_url VARCHAR(500) NOT NULL,
    request_headers JSONB,
    request_body JSONB NOT NULL,

    -- Response
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,

    -- Timing
    duration_ms INTEGER,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending, success, failed, retrying

    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,

    error_message TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    CONSTRAINT deliveries_status_check CHECK (
        status IN ('pending', 'success', 'failed', 'retrying')
    )
);

CREATE INDEX idx_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX idx_deliveries_status ON webhook_deliveries(status);
CREATE INDEX idx_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE status = 'retrying';
CREATE INDEX idx_deliveries_created_at ON webhook_deliveries(created_at);

-- Partition by month for cleanup
-- (See partitioning section)
```

### Policies Table

```sql
-- tenant_{slug}.policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    policy_type VARCHAR(50) NOT NULL,
    -- security, device, certificate, user, renewal

    policy_data JSONB NOT NULL,

    effective_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_until TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT true,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,

    CONSTRAINT policies_type_check CHECK (
        policy_type IN ('security', 'device', 'certificate', 'user', 'renewal')
    )
);

CREATE INDEX idx_policies_type ON policies(policy_type);
CREATE INDEX idx_policies_active ON policies(is_active, policy_type) WHERE is_active = true;
```

---

## Crypto Module Tables

### HSM Keys Table

```sql
-- tenant_{slug}.hsm_keys
CREATE TABLE hsm_keys (
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    key_label VARCHAR(255) NOT NULL UNIQUE,
    key_id VARCHAR(255) NOT NULL,  -- HSM internal ID

    key_type VARCHAR(50) NOT NULL,
    -- signing, encryption, ca

    algorithm VARCHAR(50) NOT NULL,

    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- active, suspended, retired

    -- Usage tracking
    created_in_hsm_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    usage_count BIGINT NOT NULL DEFAULT 0,

    -- Rotation
    rotated_from_key_id UUID REFERENCES hsm_keys(id),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    retired_at TIMESTAMPTZ,
    retired_by VARCHAR(255),

    CONSTRAINT hsm_keys_type_check CHECK (
        key_type IN ('signing', 'encryption', 'ca')
    ),
    CONSTRAINT hsm_keys_status_check CHECK (
        status IN ('active', 'suspended', 'retired')
    )
);

CREATE INDEX idx_hsm_keys_label ON hsm_keys(key_label);
CREATE INDEX idx_hsm_keys_status ON hsm_keys(status);
```

---

## Indexes & Performance

### Index Strategy

```sql
-- Partial indexes for common queries
CREATE INDEX idx_users_active ON users(email) WHERE status = 'active' AND deleted_at IS NULL;
CREATE INDEX idx_devices_active ON user_devices(user_id) WHERE status = 'active' AND deleted_at IS NULL;
CREATE INDEX idx_certs_active ON certificates(user_id, type) WHERE status = 'active';

-- Covering indexes for frequent queries
CREATE INDEX idx_users_list_covering ON users(status, created_at)
    INCLUDE (id, email, display_name);

-- GIN indexes for array columns
CREATE INDEX idx_oidc_clients_scopes ON oidc_clients USING gin(allowed_scopes);
CREATE INDEX idx_webhooks_events ON webhooks USING gin(events);

-- Full-text search
CREATE INDEX idx_users_search ON users USING gin(
    to_tsvector('english', display_name || ' ' || email)
);
```

### Query Optimization Tips

```sql
-- Use EXPLAIN ANALYZE for query planning
EXPLAIN ANALYZE
SELECT * FROM users
WHERE status = 'active'
  AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT 20;

-- Statistics update
ANALYZE users;
ANALYZE user_devices;
ANALYZE certificates;
```

---

## Partitioning Strategy

### Audit Logs Partitioning

```sql
-- tenant_{slug}.audit_logs (partitioned by month)
CREATE TABLE audit_logs (
    id UUID NOT NULL DEFAULT uuidv7(),

    -- Event
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    -- debug, info, warning, error, critical

    -- Actor
    user_id UUID,
    user_email VARCHAR(255),
    device_id UUID,
    admin_id UUID,

    -- Target
    target_type VARCHAR(100),
    target_id UUID,

    -- Context
    ip_address INET,
    user_agent TEXT,

    -- Details
    details JSONB,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create partitions
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
-- ... continue for each month

-- Indexes on partitions
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type, created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id, created_at);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity, created_at);
```

### Auto-Partition Management

```sql
-- Function to create future partitions
CREATE OR REPLACE FUNCTION create_audit_log_partitions()
RETURNS void AS $$
DECLARE
    partition_date DATE;
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    -- Create partitions for next 3 months
    FOR i IN 0..2 LOOP
        partition_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL);
        partition_name := 'audit_logs_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date;
        end_date := partition_date + INTERVAL '1 month';

        -- Check if partition exists
        IF NOT EXISTS (
            SELECT 1 FROM pg_tables
            WHERE tablename = partition_name
        ) THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF audit_logs
                 FOR VALUES FROM (%L) TO (%L)',
                partition_name, start_date, end_date
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Schedule monthly (using pg_cron or application scheduler)
```

---

## Audit & Compliance

### Audit Columns Trigger

```sql
-- Function to update audit columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables (example)
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### Soft Delete Support

```sql
-- View for non-deleted records
CREATE VIEW active_users AS
SELECT * FROM users WHERE deleted_at IS NULL;

-- Function for soft delete
CREATE OR REPLACE FUNCTION soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    NEW.deleted_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### Change Data Capture (Optional)

```sql
-- Enable logical replication for CDC
ALTER SYSTEM SET wal_level = 'logical';

-- Create publication for changes
CREATE PUBLICATION audit_changes FOR TABLE
    users, user_devices, certificates;
```

---

## Dapper Integration Patterns

### Connection Factory

```csharp
public interface IDbConnectionFactory
{
    Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken ct = default);
    Task<NpgsqlConnection> CreateTenantConnectionAsync(string tenantSlug, CancellationToken ct = default);
}

public class DbConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;
    private readonly ILogger<DbConnectionFactory> _logger;

    public DbConnectionFactory(IConfiguration configuration, ILogger<DbConnectionFactory> logger)
    {
        _connectionString = configuration.GetConnectionString("Default")!;
        _logger = logger;
    }

    public async Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken ct = default)
    {
        var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(ct);
        return connection;
    }

    public async Task<NpgsqlConnection> CreateTenantConnectionAsync(string tenantSlug, CancellationToken ct = default)
    {
        var connection = await CreateConnectionAsync(ct);
        await connection.ExecuteAsync($"SET search_path TO tenant_{tenantSlug}, public");
        return connection;
    }
}
```

### Dapper Type Handlers

```csharp
// Custom type handlers for PostgreSQL types
public class UuidHandler : SqlMapper.TypeHandler<Guid>
{
    public override Guid Parse(object value) => (Guid)value;
    public override void SetValue(IDbDataParameter parameter, Guid value)
    {
        parameter.Value = value;
        parameter.DbType = DbType.Guid;
    }
}

// Register type handlers in Program.cs
SqlMapper.AddTypeHandler(new UuidHandler());
SqlMapper.AddTypeHandler(new JsonbHandler<Dictionary<string, object>>());
```

### Repository Pattern with Dapper

```csharp
public class UserRepository : IUserRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public UserRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        return await connection.QuerySingleOrDefaultAsync<User>(
            """
            SELECT id, email, email_normalized, display_name, status, role,
                   first_name, last_name, phone, department, job_title,
                   email_verified, email_verified_at, last_login_at,
                   created_at, updated_at, version
            FROM users
            WHERE id = @Id AND deleted_at IS NULL
            """,
            new { Id = id });
    }

    public async Task<IEnumerable<User>> GetPagedAsync(
        int page, int pageSize, string? status = null, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        var sql = """
            SELECT id, email, display_name, status, role, created_at, last_login_at
            FROM users
            WHERE deleted_at IS NULL
            """;

        if (!string.IsNullOrEmpty(status))
        {
            sql += " AND status = @Status";
        }

        sql += """
            ORDER BY created_at DESC
            LIMIT @PageSize OFFSET @Offset
            """;

        return await connection.QueryAsync<User>(sql, new
        {
            Status = status,
            PageSize = pageSize,
            Offset = (page - 1) * pageSize
        });
    }

    public async Task<Guid> CreateAsync(User user, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        return await connection.ExecuteScalarAsync<Guid>(
            """
            INSERT INTO users (
                email, email_normalized, display_name, status, role,
                first_name, last_name, created_at, created_by
            )
            VALUES (
                @Email, @EmailNormalized, @DisplayName, @Status, @Role,
                @FirstName, @LastName, @CreatedAt, @CreatedBy
            )
            RETURNING id
            """,
            user);
    }

    public async Task<bool> UpdateAsync(User user, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        var affected = await connection.ExecuteAsync(
            """
            UPDATE users SET
                display_name = @DisplayName,
                first_name = @FirstName,
                last_name = @LastName,
                phone = @Phone,
                department = @Department,
                job_title = @JobTitle,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = version + 1
            WHERE id = @Id AND version = @Version AND deleted_at IS NULL
            """,
            user);

        return affected > 0;
    }
}
```

### Transaction Support

```csharp
public async Task<Result<Guid>> CreateUserWithDeviceAsync(
    User user, UserDevice device, CancellationToken ct = default)
{
    await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
        TenantContext.Current.Slug, ct);

    await using var transaction = await connection.BeginTransactionAsync(ct);

    try
    {
        // Insert user
        var userId = await connection.ExecuteScalarAsync<Guid>(
            "INSERT INTO users (...) VALUES (...) RETURNING id",
            user, transaction);

        // Insert device with user reference
        device.UserId = userId;
        await connection.ExecuteAsync(
            "INSERT INTO user_devices (...) VALUES (...)",
            device, transaction);

        await transaction.CommitAsync(ct);
        return Result<Guid>.Success(userId);
    }
    catch (Exception ex)
    {
        await transaction.RollbackAsync(ct);
        return Result<Guid>.Failure(new Error("DB_ERROR", ex.Message));
    }
}
```

### Multi-Mapping for Joins

```csharp
public async Task<User?> GetUserWithDevicesAsync(Guid userId, CancellationToken ct = default)
{
    await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
        TenantContext.Current.Slug, ct);

    var userDict = new Dictionary<Guid, User>();

    await connection.QueryAsync<User, UserDevice, User>(
        """
        SELECT u.*, d.*
        FROM users u
        LEFT JOIN user_devices d ON d.user_id = u.id AND d.deleted_at IS NULL
        WHERE u.id = @UserId AND u.deleted_at IS NULL
        """,
        (user, device) =>
        {
            if (!userDict.TryGetValue(user.Id, out var existingUser))
            {
                existingUser = user;
                existingUser.Devices = new List<UserDevice>();
                userDict.Add(user.Id, existingUser);
            }

            if (device != null)
            {
                existingUser.Devices.Add(device);
            }

            return existingUser;
        },
        new { UserId = userId },
        splitOn: "id");

    return userDict.Values.FirstOrDefault();
}
```

---

## Migration Strategy

### Migration File Structure

```
migrations/
├── 00001_create_extensions.sql
├── 00002_create_public_schema.sql
├── 00003_create_tenants_table.sql
├── 00004_create_platform_admins.sql
├── tenant_template/
│   ├── 00001_create_users.sql
│   ├── 00002_create_devices.sql
│   ├── 00003_create_certificates.sql
│   ├── 00004_create_recovery.sql
│   ├── 00005_create_auth_sessions.sql
│   ├── 00006_create_oidc.sql
│   ├── 00007_create_webhooks.sql
│   ├── 00008_create_policies.sql
│   ├── 00009_create_audit_logs.sql
│   └── 00010_create_indexes.sql
└── seeds/
    ├── 01_platform_config.sql
    └── 02_default_policies.sql
```

### Initial Migration (Extensions)

```sql
-- migrations/00001_create_extensions.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Verify uuidv7 is available (PostgreSQL 18+)
SELECT uuidv7();
```

### Tenant Schema Creation Script

```sql
-- Create tenant schema with all tables
CREATE OR REPLACE FUNCTION create_tenant_schema(tenant_slug TEXT)
RETURNS void AS $$
DECLARE
    schema_name TEXT := 'tenant_' || tenant_slug;
BEGIN
    -- Create schema
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);

    -- Set search path
    EXECUTE format('SET search_path TO %I, public', schema_name);

    -- Apply tenant template migrations
    -- (Execute each migration file in order)

    -- Reset search path
    SET search_path TO public;
END;
$$ LANGUAGE plpgsql;
```

---

## Implementation Checklist

### Phase 1: Foundation

- [ ] **PostgreSQL 18 Setup**
  - [ ] Install PostgreSQL 18
  - [ ] Enable required extensions
  - [ ] Verify `uuidv7()` availability
  - [ ] Configure connection pooling

- [ ] **Public Schema**
  - [ ] Create tenants table
  - [ ] Create platform_admins table
  - [ ] Create migrations tracking table

### Phase 2: Tenant Template

- [ ] **Identity Tables**
  - [ ] users
  - [ ] user_invitations
  - [ ] user_devices
  - [ ] device_pairing_sessions
  - [ ] recovery_data
  - [ ] recovery_sessions

- [ ] **Certificate Tables**
  - [ ] certificates
  - [ ] certificate_renewals
  - [ ] certificate_revocations

### Phase 3: Admin & Auth Tables

- [ ] **OIDC Tables**
  - [ ] oidc_clients
  - [ ] auth_sessions
  - [ ] qr_sessions
  - [ ] oidc_tokens

- [ ] **Admin Tables**
  - [ ] webhooks
  - [ ] webhook_deliveries
  - [ ] policies
  - [ ] tenant_admins

### Phase 4: Performance & Audit

- [ ] **Audit Logging**
  - [ ] audit_logs (partitioned)
  - [ ] Partition management function
  - [ ] Retention policy

- [ ] **Indexes & Optimization**
  - [ ] Create all indexes
  - [ ] Analyze tables
  - [ ] Performance testing

---

## References

- [PostgreSQL 18 Documentation](https://www.postgresql.org/docs/18/)
- [UUID v7 Specification (RFC 9562)](https://datatracker.ietf.org/doc/rfc9562/)
- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [TENANT_ONBOARDING.md](./TENANT_ONBOARDING.md)
