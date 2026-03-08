# Development Todo List

**Version:** 1.2.0
**Last Updated:** 2025-12-15
**Status:** In Progress - Phase 1 Foundation

---

## Progress Summary

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Foundation & Infrastructure | ✅ In Progress | ~95% |
| Phase 2: Core Identity Module | 🟡 Started | ~30% |
| Phase 3: Certificate Module | 🟡 Started | ~25% |
| Phase 4: Authentication & OIDC | ⬜ Not Started | 0% |
| Phase 5: Admin Module | 🟡 Started | ~10% |
| Phase 6: Mobile Apps | 🟡 Started | ~15% |
| Phase 7: Web Portals | ⬜ Not Started | 0% |
| Phase 8: SDKs & Integration | ⬜ Not Started | 0% |
| Phase 9: Testing & Security | ⬜ Not Started | 0% |
| Phase 10: Deployment & DevOps | 🟡 Started | ~30% |

### Recent Completions (2025-12-15)
- ✅ **Project Rename**: PqcIdentity → Antrapol.IdP (all namespaces, projects, solution file)
- ✅ **C# Crypto Bindings Integration**: Antrapol.Kaz.Sign and Antrapol.Kaz.Kem integrated as project references
- ✅ **Managed Crypto Providers**: KazSignManagedProvider, KazKemManagedProvider, UnifiedCryptoProvider
- ✅ **ICryptoProvider Implementation**: Full interface implementation for PQC operations
- ✅ **CSR Service**: Certificate Signing Request processing with KAZ-SIGN-256
- ✅ **Certificate Issuance Service**: X.509 certificate generation with PQC signatures

### Completions (2025-12-02)
- ✅ .NET 10 project structure with 20 projects
- ✅ Central package management (Directory.Packages.props)
- ✅ SharedKernel with Result pattern, Entity base classes
- ✅ Common infrastructure (Dapper, ProblemDetails)
- ✅ Full observability stack (OpenTelemetry, Serilog, Prometheus, Jaeger)
- ✅ Docker compose with PostgreSQL, Redis, Grafana, Seq
- ✅ All 4 module scaffolds: Identity, Certificate, Crypto, Admin
- ✅ Database migrations for schemas and core tables

---

## Overview

This document provides a comprehensive development checklist for the **Antrapol.IdP** (formerly PqcIdentity) - a Post-Quantum Cryptography Digital Identity Platform. Tasks are organized by phase and priority, with dependencies clearly marked.

> **Note:** All references to `PqcIdentity` have been renamed to `Antrapol.IdP` as of 2025-12-15.

### Technology Stack

| Component | Technology |
|-----------|------------|
| Runtime | .NET 10, C# 13 |
| API Framework | ASP.NET Core Minimal APIs + **Carter** |
| API Documentation | **Swagger/Swashbuckle** (OpenAPI) |
| Data Access | **Dapper** (Micro ORM) |
| Error Handling | **Result Pattern** + **ProblemDetails** (RFC 9457) |
| Validation | FluentValidation |
| Logging | **Serilog** (Structured Logging) |
| Database | PostgreSQL 18 (with `uuidv7()`) |
| Cache | Redis |
| HSM (Dev) | SoftHSM2 |
| PQC Algorithms | **KAZ-SIGN-256** (Signature), **KAZ-KEM-256** (Key Encapsulation) - Security Level 5 (Fixed, No Selection) |
| Key Protection | **Biometric-backed** (TEE/Secure Enclave/HUKS) - No device password required |
| PQC Bindings | **Antrapol.Kaz.Sign** (C# binding), **Antrapol.Kaz.Kem** (C# binding) - Local project references |

### Project Structure (Antrapol.IdP)

```
Backend/
├── Antrapol.IdP.sln                           # Solution file
├── Antrapol.IdP.Api/                          # Main API host
├── Shared/
│   ├── Antrapol.IdP.SharedKernel/             # Base entities, Result pattern
│   └── Antrapol.IdP.Common/                   # Common utilities, Dapper
└── Modules/
    ├── Identity/
    │   ├── Antrapol.IdP.Identity.Domain/
    │   ├── Antrapol.IdP.Identity.Application/
    │   ├── Antrapol.IdP.Identity.Infrastructure/
    │   └── Antrapol.IdP.Identity.Api/
    ├── Certificate/
    │   ├── Antrapol.IdP.Certificate.Domain/
    │   ├── Antrapol.IdP.Certificate.Application/
    │   ├── Antrapol.IdP.Certificate.Infrastructure/
    │   └── Antrapol.IdP.Certificate.Api/
    ├── Crypto/
    │   ├── Antrapol.IdP.Crypto.Domain/
    │   ├── Antrapol.IdP.Crypto.Application/
    │   ├── Antrapol.IdP.Crypto.Infrastructure/  # Contains KazSign/KazKem providers
    │   └── Antrapol.IdP.Crypto.Api/
    └── Admin/
        ├── Antrapol.IdP.Admin.Domain/
        ├── Antrapol.IdP.Admin.Application/
        ├── Antrapol.IdP.Admin.Infrastructure/
        └── Antrapol.IdP.Admin.Api/
```

### Observability Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Tracing | **OpenTelemetry** + Jaeger | Distributed tracing |
| Metrics | **OpenTelemetry** + Prometheus | Application & runtime metrics |
| Logging | **Serilog** + Seq | Structured logging |
| Dashboards | Grafana | Visualization |

### Development Phases

| Phase | Focus | Timeline |
|-------|-------|----------|
| **Phase 1** | Foundation & Infrastructure | Weeks 1-4 |
| **Phase 2** | Core Identity Module | Weeks 5-8 |
| **Phase 3** | Certificate Module | Weeks 9-11 |
| **Phase 4** | Authentication & OIDC | Weeks 12-15 |
| **Phase 5** | Admin Module | Weeks 16-18 |
| **Phase 6** | Mobile Apps (iOS/Android) | Weeks 19-24 |
| **Phase 7** | Web Portals | Weeks 25-27 |
| **Phase 8** | SDKs & Integration | Weeks 28-30 |
| **Phase 9** | Testing & Security | Weeks 31-33 |
| **Phase 10** | Deployment & DevOps | Weeks 34-36 |

---

## Phase 1: Foundation & Infrastructure

### 1.1 Development Environment Setup

- [ ] **PostgreSQL 18 Setup**
  - [ ] Install PostgreSQL 18 with `uuidv7()` support
  - [ ] Configure connection pooling (PgBouncer)
  - [ ] Create development database `idp_dev`
  - [ ] Verify `uuidv7()` function availability
  - [ ] Install required extensions (`pg_trgm`, `pgcrypto`)

- [ ] **SoftHSM2 Setup** (Reference: DEVELOPMENT_SETUP.md)
  - [ ] Install SoftHSM2 on development machines
  - [ ] Initialize token with label `PQC-IDENTITY-DEV`
  - [ ] Configure PKCS#11 library paths
  - [ ] Generate development keys

- [ ] **Redis Setup**
  - [ ] Install Redis 7.x
  - [ ] Configure for session storage
  - [ ] Configure for rate limiting

- [x] **.NET 10 Project Structure** ✅ (Completed 2025-12-02, Renamed 2025-12-15)
  - [x] Create solution file `Antrapol.IdP.sln` (renamed from PqcIdentity.sln)
  - [x] Create `Directory.Build.props` for shared properties
  - [x] Create `Directory.Packages.props` for centralized package versions
  - [x] Set up EditorConfig and code style rules

- [x] **NuGet Packages Setup** ✅ (Completed 2025-12-02)
  - [x] Add Dapper and Dapper.Contrib
  - [x] Add Carter
  - [x] Add Swashbuckle.AspNetCore (v10.0.1)
  - [x] Add FluentValidation.AspNetCore
  - [x] Add Npgsql (v10.0.0)
  - [x] Add OpenTelemetry packages (see Observability section)
  - [x] Add Serilog packages

### 1.2 Database Migrations (Reference: DATABASE_SCHEMA.md)

- [ ] **Migration Infrastructure**
  - [ ] Set up DbUp or FluentMigrator for SQL migrations
  - [ ] Create migration helper functions
  - [ ] Create `update_updated_at_column()` trigger function

- [ ] **Public Schema Tables**
  - [ ] `public.tenants` table
  - [ ] `public.platform_admins` table
  - [ ] `public.platform_config` table
  - [ ] `public.root_ca_certificates` table
  - [ ] `public.global_audit_logs` (partitioned)

- [ ] **Tenant Schema Template**
  - [ ] Create tenant schema creation function
  - [ ] `users` table
  - [ ] `user_invitations` table
  - [ ] `user_devices` table
  - [ ] `device_pairing_sessions` table
  - [ ] `recovery_data` table
  - [ ] `recovery_sessions` table
  - [ ] `certificates` table
  - [ ] `certificate_renewals` table
  - [ ] `certificate_revocations` table
  - [ ] `auth_sessions` table
  - [ ] `qr_sessions` table
  - [ ] `oidc_clients` table
  - [ ] `oidc_tokens` table
  - [ ] `webhooks` table
  - [ ] `webhook_deliveries` table
  - [ ] `policies` table
  - [ ] `audit_logs` (partitioned)
  - [ ] Create all indexes from schema design

### 1.3 Shared Kernel & Common Libraries

- [x] **Antrapol.IdP.SharedKernel Project** ✅ (Completed 2025-12-02)
  - [x] `Result<T>` and `Result` types (Result Pattern)
  - [x] `Error` record with `ErrorType` enum
  - [x] `ICommandHandler<TCommand, TResult>` interface (returns `Result<T>`)
  - [x] `IQueryHandler<TQuery, TResult>` interface (returns `Result<T>`)
  - [x] `Entity` base class with UUID v7
  - [x] `AuditableEntity` base class
  - [x] Domain event interfaces and base classes

- [x] **Antrapol.IdP.Common Project** ✅ (Completed 2025-12-02)
  - [x] ProblemDetails extensions (`Error.ToProblemResult()`)
  - [x] Error codes enumeration
  - [x] Pagination DTOs
  - [x] FluentValidation validators
  - [x] `IDbConnectionFactory` interface

- [x] **Dapper Infrastructure** ✅ (Completed 2025-12-02)
  - [x] `DbConnectionFactory` implementation
  - [x] Dapper type handlers (UUID, JSONB)
  - [x] Base repository pattern

- [x] **Carter/Swagger Setup** ✅ (Completed 2025-12-02)
  - [x] Swagger configuration with .NET 10 built-in OpenAPI
  - [x] Bearer token security definition (pending)
  - [x] ProblemDetails configuration
  - [x] Carter module registration

### 1.4 Observability Setup (Reference: ARCHITECTURE.md)

- [x] **OpenTelemetry NuGet Packages** ✅ (Completed 2025-12-02)
  - [x] `OpenTelemetry`
  - [x] `OpenTelemetry.Extensions.Hosting`
  - [x] `OpenTelemetry.Exporter.OpenTelemetryProtocol`
  - [x] `OpenTelemetry.Exporter.Prometheus.AspNetCore`
  - [x] `OpenTelemetry.Instrumentation.AspNetCore`
  - [x] `OpenTelemetry.Instrumentation.Http`
  - [x] `Npgsql.OpenTelemetry`
  - [x] `OpenTelemetry.Instrumentation.StackExchangeRedis`

- [x] **Serilog NuGet Packages** ✅ (Completed 2025-12-02)
  - [x] `Serilog.AspNetCore` (v9.0.0)
  - [x] `Serilog.Sinks.Console`
  - [x] `Serilog.Sinks.OpenTelemetry`
  - [x] `Serilog.Sinks.Seq`
  - [x] `Serilog.Enrichers.Environment`
  - [x] `Serilog.Enrichers.Thread`

- [x] **OpenTelemetry Tracing Setup** ✅ (Completed 2025-12-02)
  - [x] Configure `AddOpenTelemetry()` in Program.cs
  - [x] Add ASP.NET Core instrumentation
  - [x] Add HTTP client instrumentation
  - [x] Add Npgsql instrumentation
  - [x] Add Redis instrumentation
  - [x] Configure OTLP exporter (Jaeger)
  - [x] Create custom `ActivitySource` for application traces

- [x] **OpenTelemetry Metrics Setup** ✅ (Completed 2025-12-02)
  - [x] Configure metrics with `WithMetrics()`
  - [x] Add ASP.NET Core metrics
  - [x] Add runtime metrics
  - [x] Add process metrics
  - [x] Configure Prometheus exporter
  - [x] Create custom `Meter` for business metrics
  - [x] Expose `/metrics` endpoint

- [x] **Serilog Logging Setup** ✅ (Completed 2025-12-02)
  - [x] Configure `UseSerilog()` in Program.cs
  - [x] Add console sink with structured output
  - [x] Add Seq sink for development
  - [x] Add OpenTelemetry sink for log correlation
  - [x] Configure log enrichers (environment, machine name)
  - [x] Configure minimum log levels per namespace

- [x] **Custom Telemetry Class** ✅ (Completed 2025-12-02)
  - [x] Create `Telemetry` static class
  - [x] Define `ActivitySource` for custom traces
  - [x] Define `Meter` for custom metrics
  - [x] Create counters: `AuthenticationAttempts`, `CertificatesIssued`
  - [x] Create histograms: `AuthenticationDuration`, `CertificateIssuanceDuration`
  - [x] Create gauges: `ActiveSessions`, `ActiveDevices`

- [x] **Health Checks** ✅ (Completed 2025-12-02)
  - [x] Add `AspNetCore.HealthChecks` packages
  - [x] Configure PostgreSQL health check
  - [x] Configure Redis health check
  - [ ] Configure HSM health check
  - [x] Expose `/health` endpoint
  - [x] Expose `/health/ready` and `/health/live` endpoints

- [x] **Development Observability Stack (Docker)** ✅ (Completed 2025-12-02)
  - [x] Create `docker-compose.yml` with observability services
  - [x] Configure Jaeger container (OTLP enabled)
  - [x] Configure Prometheus container
  - [x] Configure Grafana container
  - [x] Configure Seq container
  - [x] Create `prometheus.yml` scrape config
  - [x] Create Grafana provisioning for data sources

- [ ] **Grafana Dashboards**
  - [ ] Create ASP.NET Core dashboard
  - [ ] Create custom IdP metrics dashboard
  - [ ] Create PostgreSQL dashboard
  - [ ] Create Redis dashboard
  - [ ] Export dashboards as JSON for provisioning

### 1.5 Crypto Module Foundation (Reference: ARCHITECTURE.md)

> **IMPORTANT: Fixed Algorithm Policy** - The platform uses fixed cryptographic algorithms:
> - **Signature**: KAZ-SIGN-256 (Security Level 5) - No user selection
> - **Key Encapsulation**: KAZ-KEM-256 (Security Level 5) - No user selection
> This ensures maximum quantum-resistant security for the National Digital ID system.

- [x] **Antrapol.IdP.Crypto.Domain** ✅ (Completed 2025-12-02)
  - [x] `ICryptoProvider` interface
  - [x] `KeyAlgorithm` enumeration (includes KAZ-SIGN-256, KAZ-KEM-256)
  - [x] `DefaultAlgorithms` static class with fixed algorithm constants
  - [x] `KeyPurpose`, `KeyStatus`, `KeyStorageType` enums
  - [x] `CryptoKey` entity
  - [x] `KeyDto`, `SignatureDto` DTOs

- [x] **Antrapol.IdP.Crypto.Infrastructure** ✅ (Completed 2025-12-15)
  - [x] `LibOqsCryptoProvider` (placeholder for liboqs P/Invoke)
  - [x] `IHsmProvider` interface
  - [x] `KazSignManagedProvider` - Managed wrapper for Antrapol.Kaz.Sign (KAZ-SIGN-128/192/256)
  - [x] `KazKemManagedProvider` - Managed wrapper for Antrapol.Kaz.Kem (KAZ-KEM-128/192/256)
  - [x] `UnifiedCryptoProvider` - Unified crypto provider delegating to appropriate provider
  - [x] Project references to local C# bindings (Antrapol.Kaz.Sign, Antrapol.Kaz.Kem)
  - [x] Create native library runtime folders

- [ ] **HSM Service** (Reference: ARCHITECTURE.md - HSM Integration)
  - [x] `IHsmProvider` interface
  - [ ] `Pkcs11HsmService` for SoftHSM2
  - [ ] `AzureKeyVaultHsmService` (placeholder)
  - [ ] `HashiCorpVaultHsmService` (placeholder)
  - [ ] Key naming convention implementation
  - [ ] Key rotation policies

---

## Phase 2: Core Identity Module

### 2.1 User Registration (Reference: REGISTRATION_FLOW.md)

- [x] **Domain Layer** ✅ (Partial - 2025-12-02)
  - [x] `User` entity with domain events
  - [x] `UserStatus` enum (Pending, Active, Suspended, Locked, Deactivated)
  - [x] `CredentialType` enum
  - [x] `UserCredential` entity
  - [x] `UserSession` entity
  - [x] `Email`, `PhoneNumber` value objects
  - [x] `UserCreatedEvent`, `UserStatusChangedEvent` domain events
  - [ ] `PendingRegistration` entity
  - [ ] `RegistrationInitiated` domain event

- [x] **Application Layer** ✅ (Partial - 2025-12-02)
  - [x] `RegisterUserCommand` + handler
  - [x] `GetUserByIdQuery` + handler
  - [x] `UserDto` DTO
  - [x] `RegisterUserCommandValidator`
  - [ ] `InitiateRegistrationCommand` + handler
  - [ ] `VerifyEmailOtpCommand` + handler
  - [ ] `SubmitRegistrationCommand` + handler
  - [ ] `GetRegistrationStatusQuery` + handler

- [x] **Infrastructure Layer (Dapper)** ✅ (Partial - 2025-12-02)
  - [x] `UserRepository` with Dapper queries
  - [x] `IUserRepository`, `IUserCredentialRepository`, `IUserSessionRepository` interfaces
  - [ ] `PendingRegistrationRepository` with Dapper queries
  - [ ] Email service integration for OTP
  - [ ] OTP generation and hashing

- [x] **API Layer (Carter)** ✅ (Partial - 2025-12-02)
  - [x] `UserEndpoints : ICarterModule`
    - [x] `POST /api/v1/users` - Register user
    - [x] `GET /api/v1/users/{id}` - Get user by ID
    - [ ] `POST /api/v1/identity/registration/initiate`
    - [ ] `POST /api/v1/identity/registration/{id}/verify-otp`
    - [ ] `POST /api/v1/identity/registration/{id}/submit`
    - [ ] `GET /api/v1/identity/registration/{tracking_id}/status`
  - [x] Swagger annotations with `.WithName()`, `.WithSummary()`
  - [x] ProblemDetails error responses

### 2.2 Secret Sharing (Reference: REGISTRATION_FLOW.md)

- [ ] **Shamir's Secret Sharing Implementation**
  - [ ] 2-of-3 threshold scheme
  - [ ] `SecretSplitter` service
  - [ ] `SecretReconstructor` service
  - [ ] Polynomial evaluation over GF(256)

- [ ] **Key Share Encryption**
  - [ ] KEM encapsulation for `part_user`
  - [ ] AES-GCM encryption for `part_recovery`
  - [ ] KEM encapsulation for `part_control`

### 2.3 Single Device Management (Reference: DEVICE_MANAGEMENT.md)

> **IMPORTANT: Single Device Policy** - Each user identity is bound to exactly ONE device at a time.
> This ensures maximum security by keeping private keys isolated on a single device.
> To change devices, users must perform a secure device transfer which:
> 1. Encrypts and transfers keys using KAZ-KEM
> 2. Securely erases keys from the source device
> 3. Registers the new device as the sole authorized device

- [ ] **Domain Layer**
  - [ ] `UserDevice` entity (single device per user)
  - [ ] `DeviceStatus` enum (Active, TransferPending, Deactivated)
  - [ ] `DeviceTransferSession` entity
  - [ ] `DeviceRegistered` domain event
  - [ ] `DeviceTransferInitiated` domain event
  - [ ] `DeviceTransferCompleted` domain event
  - [ ] `DeviceDeactivated` domain event

- [ ] **Application Layer**
  - [ ] `GetCurrentDeviceQuery` + handler
  - [ ] `InitiateDeviceTransferCommand` + handler
  - [ ] `ScanTransferQrCommand` + handler (new device)
  - [ ] `CompleteDeviceTransferCommand` + handler
  - [ ] `CancelDeviceTransferCommand` + handler

- [ ] **Device Transfer Flow**
  - [ ] KAZ-KEM session establishment between devices
  - [ ] Encrypted key transfer protocol
  - [ ] Secure key erasure on source device
  - [ ] Server-side device binding update
  - [ ] Certificate re-binding to new device

- [ ] **API Layer (Carter)**
  - [ ] `DeviceEndpoints : ICarterModule`
    - [ ] `GET /api/v1/identity/device` - Get current device info
    - [ ] `POST /api/v1/identity/device/transfer/initiate` - Start transfer (generates QR)
    - [ ] `POST /api/v1/identity/device/transfer/{id}/scan` - New device scans QR
    - [ ] `POST /api/v1/identity/device/transfer/{id}/complete` - Complete transfer
    - [ ] `DELETE /api/v1/identity/device/transfer/{id}` - Cancel transfer

### 2.4 Account Recovery (Reference: ACCOUNT_RECOVERY_FLOW.md)

- [ ] **Domain Layer**
  - [ ] `RecoveryData` entity
  - [ ] `RecoverySession` entity
  - [ ] `RecoveryStatus` enum
  - [ ] `RecoveryInitiated` domain event
  - [ ] `RecoveryCompleted` domain event

- [ ] **Application Layer**
  - [ ] `InitiateRecoveryCommand` + handler
  - [ ] `VerifyRecoveryOtpCommand` + handler
  - [ ] `GetControlShareCommand` + handler
  - [ ] `CompleteRecoveryCommand` + handler

- [ ] **API Layer (Carter)**
  - [ ] `RecoveryEndpoints : ICarterModule`
    - [ ] `POST /api/v1/identity/recovery/initiate`
    - [ ] `POST /api/v1/identity/recovery/{id}/verify-otp`
    - [ ] `POST /api/v1/identity/recovery/{id}/control-share`
    - [ ] `POST /api/v1/identity/recovery/{id}/complete`

---

## Phase 3: Certificate Module

> **IMPORTANT: Fixed Algorithm** - All certificates use KAZ-SIGN-256 (Security Level 5).
> No algorithm selection is provided to users.

### 3.1 Certificate Issuance (Reference: CERTIFICATE_ISSUANCE.md)

- [x] **Domain Layer** ✅ (Partial - 2025-12-02)
  - [x] `Certificate` entity with PQC algorithm support
  - [x] `CertificateType` enum (RootCa, TenantCa, User, Device)
  - [x] `CertificateStatus` enum (Active, Suspended, Revoked, Expired)
  - [x] `SignatureAlgorithm` enum (KAZ-SIGN-256 default)
  - [x] `DefaultCertificateAlgorithms` static class with fixed KAZ-SIGN-256
  - [x] `RevocationReason` enum
  - [x] `CertificateIssuedEvent`, `CertificateRevokedEvent`, `CertificateSuspendedEvent` domain events
  - [x] `ICertificateRepository` interface
  - [x] `CertificateDto` DTO
  - [ ] Add KAZ-SIGN-256 algorithm OIDs

- [x] **Certificate Builder Service** ✅ (Completed 2025-12-15)
  - [x] X.509 certificate builder (CertificateIssuanceService)
  - [x] KAZ-SIGN-256 signature attachment (fixed algorithm)
  - [x] Extension handling (BasicConstraints, KeyUsage, etc.)
  - [x] Subject DN builder
  - [x] **KAZ-SIGN-256 signature integration via managed C# binding**

- [x] **CSR Processing** ✅ (Completed 2025-12-15)
  - [x] CSR parser (CsrService - supporting KAZ-SIGN-256)
  - [x] CSR signature verification (KAZ-SIGN-256 via Antrapol.Kaz.Sign)
  - [x] Subject validation

- [ ] **Application Layer**
  - [ ] `ProcessCsrCommand` + handler
  - [ ] `IssueCertificateCommand` + handler
  - [ ] `GetCertificateQuery` + handler
  - [ ] `ListUserCertificatesQuery` + handler

- [ ] **API Layer (Carter)**
  - [ ] `CertificateEndpoints : ICarterModule`
    - [ ] `POST /api/v1/certificates/csr`
    - [ ] `GET /api/v1/certificates/{serial}`
    - [ ] `GET /api/v1/certificates`

### 3.2 Certificate Renewal (Reference: CERTIFICATE_RENEWAL.md)

- [ ] **Domain Layer**
  - [ ] `CertificateRenewal` entity
  - [ ] `RenewalType` enum
  - [ ] `CertificateRenewed` domain event

- [ ] **Renewal Service**
  - [ ] Renewal eligibility checker
  - [ ] Renewal window calculator
  - [ ] Grace period handler
  - [ ] Key rotation decision logic

- [ ] **Application Layer**
  - [ ] `CheckRenewalStatusQuery` + handler
  - [ ] `RequestRenewalTokenCommand` + handler
  - [ ] `SubmitRenewalCommand` + handler

- [ ] **Background Jobs**
  - [ ] Automatic renewal job
  - [ ] Expiry notification job
  - [ ] Grace period processing job

- [ ] **API Layer (Carter)**
  - [ ] `CertificateRenewalEndpoints : ICarterModule`
    - [ ] `GET /api/v1/certificates/{serial}/renewal-status`
    - [ ] `POST /api/v1/certificates/{serial}/renewal-token`
    - [ ] `POST /api/v1/certificates/{serial}/renew`

### 3.3 Certificate Revocation

- [ ] **Revocation Service**
  - [ ] Revocation processor
  - [ ] CRL generator
  - [ ] OCSP responder

- [ ] **Application Layer**
  - [ ] `RevokeCertificateCommand` + handler
  - [ ] `GetCrlQuery` + handler

- [ ] **API Layer (Carter)**
  - [ ] `RevocationEndpoints : ICarterModule`
    - [ ] `POST /api/v1/certificates/{serial}/revoke`
    - [ ] `GET /api/v1/certificates/crl`
    - [ ] `POST /api/v1/certificates/ocsp`

---

## Phase 4: Authentication & OIDC

### 4.1 OIDC Core (Reference: AUTHENTICATION_FLOW.md)

- [ ] **Discovery Endpoints**
  - [ ] `GET /.well-known/openid-configuration`
  - [ ] `GET /.well-known/jwks.json`
  - [ ] PQC algorithm registration in JWKS

- [ ] **Authorization Server**
  - [ ] `AuthSession` entity
  - [ ] Session state machine
  - [ ] PAR (Pushed Authorization Request) endpoint
  - [ ] Authorization endpoint
  - [ ] PKCE validation

- [ ] **Token Service**
  - [ ] PQC-signed JWT generation
  - [ ] ID token generation
  - [ ] Access token generation
  - [ ] Refresh token generation
  - [ ] Token refresh flow
  - [ ] Token revocation

- [ ] **API Layer (Carter)**
  - [ ] `OAuthEndpoints : ICarterModule`
    - [ ] `POST /oauth/par`
    - [ ] `GET /oauth/authorize`
    - [ ] `POST /oauth/token`
    - [ ] `GET /oauth/userinfo`
    - [ ] `POST /oauth/revoke`
    - [ ] `POST /oauth/introspect`

### 4.2 QR Code Authentication (Reference: QR_CODE_AUTHENTICATION.md)

- [ ] **QR Session Management**
  - [ ] `QrSession` entity
  - [ ] `QrSessionType` enum (login, transaction, access, sign)
  - [ ] QR data structure and encoding
  - [ ] Checksum calculation

- [ ] **QR Code Generation**
  - [ ] QR code image generator
  - [ ] URL scheme encoding (`idp://qr/...`)

- [ ] **Real-time Updates**
  - [ ] WebSocket server setup
  - [ ] Session subscription management
  - [ ] Status change notifications
  - [ ] Polling fallback endpoint

- [ ] **Application Layer**
  - [ ] `CreateQrSessionCommand` + handler
  - [ ] `ScanQrSessionCommand` + handler
  - [ ] `ApproveQrSessionCommand` + handler
  - [ ] `DenyQrSessionCommand` + handler
  - [ ] `GetQrSessionStatusQuery` + handler

- [ ] **API Layer (Carter)**
  - [ ] `QrSessionEndpoints : ICarterModule`
    - [ ] `POST /api/v1/qr/sessions`
    - [ ] `GET /api/v1/qr/sessions/{id}/status`
    - [ ] `GET /api/v1/qr/sessions/{id}/qr.png`
    - [ ] `POST /api/v1/qr/sessions/{id}/scan`
    - [ ] `POST /api/v1/qr/sessions/{id}/approve`
    - [ ] `POST /api/v1/qr/sessions/{id}/deny`

### 4.3 Mobile App Authentication

- [ ] **Deep Link Handler**
  - [ ] Universal link configuration (iOS)
  - [ ] App link configuration (Android)
  - [ ] URL scheme handler
  - [ ] Session validation

- [ ] **Assertion Service**
  - [ ] Authentication assertion builder
  - [ ] PQC signature on assertion
  - [ ] Assertion verification

- [ ] **Device Binding Verification**
  - [ ] Device-user binding check
  - [ ] Certificate chain validation

---

## Phase 5: Admin Module

### 5.1 Tenant Management (Reference: TENANT_ONBOARDING.md)

- [ ] **Domain Layer**
  - [ ] `Tenant` entity extensions
  - [ ] `TenantStatus` enum
  - [ ] `TenantSettings` value object
  - [ ] `TenantBranding` value object
  - [ ] `TenantProvisioned` domain event

### 5.0 Admin Module Foundation ✅ (Completed 2025-12-02)

- [x] **Domain Layer**
  - [x] `AuditLog` entity
  - [x] `AuditAction` enum (UserCreated, UserUpdated, CertificateIssued, etc.)
  - [x] `AuditSeverity` enum (Info, Warning, Critical)
  - [x] `IAuditLogRepository` interface
  - [x] `AuditLogDto` DTO

- [ ] **Tenant Provisioning Service**
  - [ ] Schema creation
  - [ ] CA key generation
  - [ ] Initial admin setup
  - [ ] Default policy creation

- [ ] **Application Layer**
  - [ ] `CreateTenantCommand` + handler
  - [ ] `UpdateTenantCommand` + handler
  - [ ] `SuspendTenantCommand` + handler
  - [ ] `GetTenantQuery` + handler

- [ ] **API Layer (Carter)**
  - [ ] `TenantEndpoints : ICarterModule`
    - [ ] `GET /api/v1/admin/tenant`
    - [ ] `PATCH /api/v1/admin/tenant/configuration`
    - [ ] `PATCH /api/v1/admin/tenant/branding`

### 5.2 User Management (Admin)

- [ ] **Application Layer**
  - [ ] `ListUsersQuery` + handler
  - [ ] `GetUserDetailsQuery` + handler
  - [ ] `InviteUserCommand` + handler
  - [ ] `BulkInviteUsersCommand` + handler
  - [ ] `SuspendUserCommand` + handler
  - [ ] `ReactivateUserCommand` + handler

- [ ] **API Layer (Carter)**
  - [ ] `AdminUserEndpoints : ICarterModule`
    - [ ] `GET /api/v1/admin/users`
    - [ ] `GET /api/v1/admin/users/{id}`
    - [ ] `POST /api/v1/admin/users/invite`
    - [ ] `POST /api/v1/admin/users/bulk-invite`
    - [ ] `POST /api/v1/admin/users/{id}/suspend`
    - [ ] `POST /api/v1/admin/users/{id}/reactivate`

### 5.3 OIDC Client Management

- [ ] **Domain Layer**
  - [ ] `OidcClient` entity
  - [ ] `ClientType` enum (confidential, public)
  - [ ] `ClientCreated` domain event

- [ ] **Application Layer**
  - [ ] `ListOidcClientsQuery` + handler
  - [ ] `CreateOidcClientCommand` + handler
  - [ ] `UpdateOidcClientCommand` + handler
  - [ ] `RotateClientSecretCommand` + handler
  - [ ] `DeleteOidcClientCommand` + handler

- [ ] **API Layer (Carter)**
  - [ ] `OidcClientEndpoints : ICarterModule`
    - [ ] `GET /api/v1/admin/oidc-clients`
    - [ ] `POST /api/v1/admin/oidc-clients`
    - [ ] `PATCH /api/v1/admin/oidc-clients/{id}`
    - [ ] `POST /api/v1/admin/oidc-clients/{id}/rotate-secret`
    - [ ] `DELETE /api/v1/admin/oidc-clients/{id}`

### 5.4 Audit Logging

- [ ] **Audit Service**
  - [ ] `IAuditService` interface
  - [ ] Audit entry builder
  - [ ] Async audit logging
  - [ ] Partition management

- [ ] **Application Layer**
  - [ ] `ListAuditLogsQuery` + handler
  - [ ] `ExportAuditLogsCommand` + handler

- [ ] **API Layer (Carter)**
  - [ ] `AuditLogEndpoints : ICarterModule`
    - [ ] `GET /api/v1/admin/audit-logs`
    - [ ] `POST /api/v1/admin/audit-logs/export`

### 5.5 Webhook Management

- [ ] **Domain Layer**
  - [ ] `Webhook` entity
  - [ ] `WebhookDelivery` entity
  - [ ] `WebhookEvent` enum

- [ ] **Webhook Delivery Service**
  - [ ] Event subscription
  - [ ] Signature generation (HMAC-SHA256)
  - [ ] Retry with exponential backoff
  - [ ] Dead letter handling

- [ ] **Background Jobs**
  - [ ] Webhook delivery processor
  - [ ] Retry job
  - [ ] Cleanup job

- [ ] **API Layer (Carter)**
  - [ ] `WebhookEndpoints : ICarterModule`
    - [ ] `GET /api/v1/admin/webhooks`
    - [ ] `POST /api/v1/admin/webhooks`
    - [ ] `PATCH /api/v1/admin/webhooks/{id}`
    - [ ] `DELETE /api/v1/admin/webhooks/{id}`
    - [ ] `GET /api/v1/admin/webhooks/{id}/deliveries`

---

## Phase 6: Mobile Apps

### 6.1 iOS App (Swift)

- [ ] **Project Setup**
  - [ ] Create Xcode project with SwiftUI
  - [ ] Configure Universal Links (apple-app-site-association)
  - [ ] Set up Keychain access
  - [ ] Configure push notifications (APNs)
  - [ ] Integrate KazSignNative.xcframework (libkazsign.a)

- [ ] **Cryptography & CSR** (Reference: CSR_GENERATION.md)
  - [ ] **Native Library Integration**
    - [ ] Swift C interop for libkazsign.a
    - [ ] `kaz_sign_keygen()` wrapper
    - [ ] `kaz_sign_sign()` wrapper
  - [ ] **ASN.1/DER Builder** (Platform Swift)
    - [ ] `DERBuilder` class for ASN.1 encoding
    - [ ] Support for SEQUENCE, SET, INTEGER, OID, BIT STRING, UTF8String
    - [ ] Length encoding (short and long form)
  - [ ] **CSR Builder**
    - [ ] `CSRBuilder` class
    - [ ] `buildDistinguishedName()` - Subject DN with MyKad
    - [ ] `buildSubjectPublicKeyInfo()` - KAZ-SIGN-256 OID + public key
    - [ ] `buildCertificationRequestInfo()` - TBS portion
    - [ ] `assembleCertificationRequest()` - Final CSR with signature
  - [ ] **KAZ-SIGN-256 OID**: 2.16.458.1.1.1.1.1

- [ ] **Core Features**
  - [ ] **Onboarding Flow**
    - [ ] Profile setup (name, MyKad, email, phone)
    - [ ] Email/Phone verification
    - [ ] Recovery password setup
    - [ ] Key generation (KAZ-SIGN-256)
    - [ ] CSR generation (using ASN.1 builder)
    - [ ] Biometric setup
    - [ ] Certificate storage
    - [ ] Recovery token display

  - [ ] **Authentication**
    - [ ] Deep link handler
    - [ ] QR code scanner
    - [ ] Consent screen
    - [ ] Biometric authentication
    - [ ] Assertion signing

  - [ ] **Device Management**
    - [ ] Device list view
    - [ ] Add device (QR pairing)
    - [ ] Remove device
    - [ ] Report lost device

  - [ ] **Certificate Management**
    - [ ] Certificate viewer
    - [ ] Renewal notifications
    - [ ] Manual renewal flow

- [ ] **Security**
  - [ ] Keychain integration with Secure Enclave
  - [ ] **Biometric key protection** (Face ID/Touch ID required for signing)
  - [ ] AES-256 master key generation in Secure Enclave
  - [ ] KAZ-SIGN-256 private key encryption with biometric-bound key
  - [ ] Jailbreak detection
  - [ ] App attestation (DeviceCheck)
  - [ ] Certificate pinning
  - [ ] Key invalidation on biometric re-enrollment

### 6.2 Android App (Kotlin)

- [x] **Project Setup** ✅ (In Progress 2025-12-15)
  - [x] Create Android Studio project with Jetpack Compose
  - [ ] Configure App Links (assetlinks.json)
  - [ ] Set up KeyStore
  - [ ] Configure push notifications (FCM)
  - [x] Integrate libkazsign.so via JNI (KazSign native binding)

- [x] **Cryptography & CSR** ✅ (Completed 2025-12-15) (Reference: CSR_GENERATION.md)
  - [x] **Native Library Integration (JNI)**
    - [x] JNI bridge for libkazsign.so (via SIGN/bindings/android)
    - [x] `KazSign.kt` with Kotlin wrapper
    - [x] `kaz_sign_keygen()` JNI wrapper
    - [x] `kaz_sign_sign()` JNI wrapper
  - [x] **ASN.1/DER Builder** (Platform Kotlin)
    - [x] `DerBuilder.kt` class for ASN.1 encoding
    - [x] Support for SEQUENCE, SET, INTEGER, OID, BIT STRING, UTF8String
    - [x] Length encoding (short and long form)
  - [x] **CSR Builder**
    - [x] `CsrBuilder.kt` class
    - [x] `buildDistinguishedName()` - Subject DN with MyKad
    - [x] `buildSubjectPublicKeyInfo()` - KAZ-SIGN-256 OID + public key
    - [x] `buildCertificationRequestInfo()` - TBS portion
    - [x] `assembleCertificationRequest()` - Final CSR with signature
  - [x] **KAZ-SIGN-256 OID**: 2.16.458.1.1.1.1.1

- [ ] **Core Features**
  - [ ] Same feature list as iOS
  - [ ] Material 3 design system

- [ ] **Security**
  - [ ] Android Keystore with TEE/StrongBox
  - [ ] **Biometric key protection** (BiometricPrompt required for signing)
  - [ ] AES-256 master key generation in TEE/StrongBox
  - [ ] KAZ-SIGN-256 private key encryption with biometric-bound key
  - [ ] setUserAuthenticationRequired(true) for key access
  - [ ] Root detection
  - [ ] SafetyNet/Play Integrity attestation
  - [ ] Key invalidation on biometric re-enrollment

### 6.3 HarmonyOS App (ArkTS)

- [ ] **Project Setup**
  - [ ] Create DevEco Studio project with ArkUI
  - [ ] Configure App Linking
  - [ ] Set up HUKS (Huawei Universal Keystore)
  - [ ] Configure push notifications (Huawei Push)
  - [ ] Integrate libkazsign via N-API

- [ ] **Cryptography & CSR** (Reference: CSR_GENERATION.md)
  - [ ] **Native Library Integration (N-API)**
    - [ ] N-API bridge for libkazsign.so
    - [ ] `KazSignService.ets` with native bindings
    - [ ] `kaz_sign_keygen()` N-API wrapper
    - [ ] `kaz_sign_sign()` N-API wrapper
  - [ ] **ASN.1/DER Builder** (Platform ArkTS)
    - [ ] `DERBuilder` class for ASN.1 encoding
    - [ ] Support for SEQUENCE, SET, INTEGER, OID, BIT STRING, UTF8String
    - [ ] Length encoding (short and long form)
  - [ ] **CSR Builder**
    - [ ] `CSRBuilder` class
    - [ ] `buildDistinguishedName()` - Subject DN with MyKad
    - [ ] `buildSubjectPublicKeyInfo()` - KAZ-SIGN-256 OID + public key
    - [ ] `buildCertificationRequestInfo()` - TBS portion
    - [ ] `assembleCertificationRequest()` - Final CSR with signature
  - [ ] **KAZ-SIGN-256 OID**: 2.16.458.1.1.1.1.1

- [ ] **Core Features**
  - [ ] Same feature list as iOS/Android
  - [ ] HarmonyOS design system

- [ ] **Security**
  - [ ] HUKS with iTrustee TEE
  - [ ] **Biometric key protection** (userIAM.userAuth required for signing)
  - [ ] AES-256 master key generation in HUKS
  - [ ] KAZ-SIGN-256 private key encryption with biometric-bound key
  - [ ] HUKS_TAG_USER_AUTH_TYPE for biometric binding
  - [ ] Root detection
  - [ ] Key invalidation on biometric re-enrollment

### 6.4 Native Library (libkazsign)

> **Note:** The native library provides only key generation and signing.
> CSR structure building is done in platform code (Swift/Kotlin/ArkTS).

- [ ] **Library Implementation (C)**
  - [ ] `kaz_sign_keygen()` - Generate KAZ-SIGN-256 keypair
  - [ ] `kaz_sign_sign()` - Sign message with private key
  - [ ] `kaz_sign_verify()` - Verify signature (optional, for testing)
  - [ ] Error codes and result types

- [ ] **Build System**
  - [ ] CMake configuration for cross-platform builds
  - [ ] iOS: Build static library (.a) for arm64, x86_64-simulator
  - [ ] iOS: Create xcframework bundle
  - [ ] Android: Build shared library (.so) for arm64-v8a, armeabi-v7a, x86_64
  - [ ] HarmonyOS: Build shared library (.so) for arm64-v8a

- [ ] **Platform Bindings**
  - [ ] iOS: Swift C interop bridging header
  - [ ] Android: JNI C implementation (kazsign_jni.c)
  - [ ] HarmonyOS: N-API C++ implementation (kazsign_napi.cpp)

- [ ] **Testing**
  - [ ] Unit tests for keygen/sign/verify
  - [ ] Cross-platform verification tests
  - [ ] Performance benchmarks

### 6.5 Shared Code

- [ ] **API Client**
  - [ ] Network layer
  - [ ] Authentication interceptor
  - [ ] Error handling
  - [ ] Retry logic

- [ ] **Local Storage**
  - [ ] Secure storage abstraction
  - [ ] Certificate storage
  - [ ] Session management

---

## Phase 7: Web Portals

### 7.1 Admin Portal (Blazor WebAssembly)

- [ ] **Project Setup**
  - [ ] Create Blazor WASM project
  - [ ] Configure authentication
  - [ ] Set up routing
  - [ ] Choose UI framework (MudBlazor/Fluent UI)

- [ ] **Features**
  - [ ] Dashboard
  - [ ] User management
  - [ ] Device management (admin view)
  - [ ] OIDC client management
  - [ ] Policy configuration
  - [ ] Audit log viewer
  - [ ] Webhook management
  - [ ] Tenant settings

### 7.2 User Portal (Blazor WebAssembly)

- [ ] **Features**
  - [ ] Profile management
  - [ ] Device management
  - [ ] Activity history
  - [ ] Certificate viewer
  - [ ] Recovery options

---

## Phase 8: SDKs & Integration

### 8.1 .NET SDK

- [ ] **Antrapol.IdP.Sdk Project**
  - [ ] `IdpClient` main class
  - [ ] QR authentication client
  - [ ] Token validation
  - [ ] Signature verification

- [ ] **Antrapol.IdP.Sdk.AspNetCore Project**
  - [ ] Authentication handler
  - [ ] Authorization policies
  - [ ] Middleware
  - [ ] Service collection extensions

### 8.2 JavaScript SDK

- [ ] **@idp/sdk Package**
  - [ ] `IdpClient` class
  - [ ] Token management
  - [ ] QR login component
  - [ ] WebSocket handling

- [ ] **@idp/react-sdk Package**
  - [ ] React hooks
  - [ ] QR login component
  - [ ] Auth provider

### 8.3 Documentation

- [ ] API reference documentation
- [ ] SDK integration guides
- [ ] Example applications
- [ ] Postman/Insomnia collection

---

## Phase 9: Testing & Security

### 9.1 Unit Tests

- [ ] **Backend**
  - [ ] Domain layer tests
  - [ ] Application layer tests
  - [ ] Crypto provider tests
  - [ ] Secret sharing tests

- [ ] **Mobile**
  - [ ] iOS unit tests
  - [ ] Android unit tests

### 9.2 Integration Tests

- [ ] Registration flow end-to-end
- [ ] Authentication flow end-to-end
- [ ] Certificate lifecycle tests
- [ ] Device management tests
- [ ] Recovery flow tests

### 9.3 Security Testing

- [ ] OWASP top 10 review
- [ ] PQC signature verification tests
- [ ] Key derivation tests
- [ ] Penetration testing preparation
- [ ] Security audit checklist

### 9.4 Performance Testing

- [ ] Load testing setup
- [ ] Database query optimization
- [ ] API response time benchmarks

---

## Phase 10: Deployment & DevOps

### 10.1 Docker

- [x] Backend API Dockerfile ✅ (Completed 2025-12-02)
- [x] PostgreSQL with extensions (uuid-ossp, pgcrypto, pg_trgm)
- [x] Redis configuration
- [ ] SoftHSM2 container (dev)
- [x] docker-compose.yml (with all services: PostgreSQL, Redis, Jaeger, Prometheus, Grafana, Seq)
- [ ] docker-compose.override.yml (dev)

### 10.2 Kubernetes

- [ ] Namespace configuration
- [ ] ConfigMaps and Secrets
- [ ] Deployment manifests
- [ ] Service definitions
- [ ] Ingress configuration
- [ ] HorizontalPodAutoscaler
- [ ] PodDisruptionBudget

### 10.3 Terraform

- [ ] Azure provider setup
- [ ] PostgreSQL Flexible Server
- [ ] Azure Key Vault
- [ ] Azure Redis Cache
- [ ] Azure Container Apps / AKS
- [ ] Application Insights

### 10.4 CI/CD (GitHub Actions)

- [ ] Build workflow
- [ ] Test workflow
- [ ] Security scanning (CodeQL, Dependabot)
- [ ] Container build and push
- [ ] Deployment workflows (dev/staging/prod)

---

## Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DEPENDENCY GRAPH                                     │
└─────────────────────────────────────────────────────────────────────────────┘

Phase 1 (Foundation)
    │
    ├──────────────────────┬─────────────────────┐
    ▼                      ▼                     ▼
Phase 2 (Identity)     Phase 3 (Certificate)  Phase 4 (OIDC) ←── Phase 3
    │                      │                     │
    └──────────────────────┴─────────────────────┤
                                                 │
                                                 ▼
                                          Phase 5 (Admin)
                                                 │
                          ┌──────────────────────┼───────────────────────┐
                          ▼                      ▼                       ▼
                   Phase 6 (Mobile)      Phase 7 (Web)           Phase 8 (SDKs)
                          │                      │                       │
                          └──────────────────────┴───────────────────────┤
                                                                         │
                                                                         ▼
                                                                Phase 9 (Testing)
                                                                         │
                                                                         ▼
                                                              Phase 10 (Deployment)
```

---

## Quick Start Tasks

For developers starting on the project, begin with these tasks:

### Day 1-2: Environment Setup
1. [ ] Clone repository
2. [ ] Install PostgreSQL 18
3. [ ] Install SoftHSM2
4. [ ] Install .NET 10 SDK
5. [ ] Run initial SQL migrations (DbUp/FluentMigrator)
6. [ ] Verify HSM connectivity
7. [ ] Run `dotnet restore` to install NuGet packages
8. [ ] Start observability stack: `docker-compose -f docker-compose.observability.yml up -d`

### Day 3-4: First Feature (Using New Tech Stack)
1. [ ] Understand ARCHITECTURE.md (Result Pattern, Carter, Dapper, OpenTelemetry)
2. [ ] Implement `Tenant` entity
3. [ ] Implement `TenantRepository` with Dapper
4. [ ] Create `TenantEndpoints : ICarterModule` with Swagger annotations
5. [ ] Implement Result Pattern in handler (`Task<Result<TenantDto>>`)
6. [ ] Configure ProblemDetails for error responses
7. [ ] Write unit tests
8. [ ] Verify Swagger UI at `/swagger`

### Day 5: Observability Verification
1. [ ] Run the API and make some requests
2. [ ] View traces in Jaeger UI at http://localhost:16686
3. [ ] View metrics in Prometheus at http://localhost:9090
4. [ ] Search logs in Seq at http://localhost:8081
5. [ ] Open Grafana at http://localhost:3000 and explore dashboards
6. [ ] Add custom trace span in a handler using `Telemetry.ActivitySource.StartActivity()`
7. [ ] Record a custom metric using `Telemetry.AuthenticationAttempts.Add()`
8. [ ] Verify trace-log correlation (TraceId appears in logs)

---

## Notes

- All database tables use UUID v7 (`DEFAULT uuidv7()`)
- All API responses follow the standard wrapper format
- **All tokens are PQC-signed using KAZ-SIGN-256 (Security Level 5) - Fixed algorithm, no selection**
- **Single device policy: Each user can only have ONE registered device at a time**
- **Biometric key protection: Device private keys protected by hardware-backed biometric (TEE/Secure Enclave/HUKS)**
  - No device password required for daily usage
  - Only recovery password needed (for account recovery scenarios)
  - Signing operations require biometric authentication
- Multi-tenancy uses schema-per-tenant pattern
- Audit logging is mandatory for all state changes

---

## References

- [ARCHITECTURE.md](./architecture/ARCHITECTURE.md)
- [DATABASE_SCHEMA.md](./architecture/DATABASE_SCHEMA.md)
- [OPENAPI_SPECIFICATION.md](./api/OPENAPI_SPECIFICATION.md)
- [REGISTRATION_FLOW.md](./architecture/REGISTRATION_FLOW.md)
- [CSR_GENERATION.md](./architecture/CSR_GENERATION.md) - CSR generation with ASN.1/DER
- [AUTHENTICATION_FLOW.md](./architecture/AUTHENTICATION_FLOW.md)
- [QR_CODE_AUTHENTICATION.md](./architecture/QR_CODE_AUTHENTICATION.md)
- [DEVICE_MANAGEMENT.md](./architecture/DEVICE_MANAGEMENT.md)
- [CERTIFICATE_RENEWAL.md](./architecture/CERTIFICATE_RENEWAL.md)
- [TENANT_ONBOARDING.md](./architecture/TENANT_ONBOARDING.md)
