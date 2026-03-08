# OpenAPI Specification

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [API Design Principles](#api-design-principles)
3. [Authentication & Authorization](#authentication--authorization)
4. [API Versioning](#api-versioning)
5. [Common Patterns](#common-patterns)
6. [Error Handling](#error-handling)
7. [API Modules](#api-modules)
8. [Identity Module API](#identity-module-api)
9. [Certificate Module API](#certificate-module-api)
10. [Admin Module API](#admin-module-api)
11. [Crypto Module API](#crypto-module-api)
12. [OIDC Endpoints](#oidc-endpoints)
13. [Webhook Events](#webhook-events)
14. [Rate Limiting](#rate-limiting)
15. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

This document defines the REST API specification for the Digital ID Platform. The API follows OpenAPI 3.1 specification and REST best practices.

### API Documentation Stack

| Component | Technology |
|-----------|------------|
| OpenAPI Spec | Swagger/Swashbuckle |
| Error Responses | RFC 9457 ProblemDetails |
| Endpoint Routing | Carter Modules |
| Validation | FluentValidation |
| Logging | Serilog (Structured) |
| Observability | OpenTelemetry |

### Base URLs

| Environment | Base URL |
|-------------|----------|
| Production | `https://api.idp.example.com` |
| Staging | `https://api.staging.idp.example.com` |
| Development | `http://localhost:5000` |

### API Structure

```
/api/v1/
├── identity/           # Identity Module
│   ├── users/
│   ├── devices/
│   ├── sessions/
│   └── recovery/
├── certificates/       # Certificate Module
│   ├── certificates/
│   ├── csr/
│   └── revocation/
├── admin/              # Admin Module
│   ├── tenants/
│   ├── users/
│   ├── policies/
│   └── audit/
├── crypto/             # Crypto Module
│   ├── keys/
│   ├── sign/
│   └── verify/
└── oauth/              # OIDC/OAuth
    ├── authorize
    ├── token
    ├── userinfo
    └── par
```

---

## API Design Principles

### RESTful Conventions

| Operation | HTTP Method | URL Pattern | Response Code |
|-----------|-------------|-------------|---------------|
| List | GET | `/resources` | 200 |
| Get | GET | `/resources/{id}` | 200 |
| Create | POST | `/resources` | 201 |
| Update (full) | PUT | `/resources/{id}` | 200 |
| Update (partial) | PATCH | `/resources/{id}` | 200 |
| Delete | DELETE | `/resources/{id}` | 204 |
| Action | POST | `/resources/{id}/action` | 200/202 |

### Naming Conventions

- **URLs**: lowercase, kebab-case (`/user-devices`)
- **Query params**: snake_case (`?page_size=20`)
- **Request/Response bodies**: snake_case (`user_id`, `created_at`)
- **Headers**: Title-Case (`X-Tenant-Id`, `X-Request-Id`)

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes* | Bearer token or API key |
| `Content-Type` | Yes | `application/json` |
| `Accept` | No | `application/json` |
| `X-Tenant-Id` | Yes* | Tenant identifier (for multi-tenant) |
| `X-Request-Id` | No | Client-generated request ID for tracing |
| `X-Device-Id` | Yes* | Device identifier (for mobile apps) |
| `X-App-Version` | No | Client app version |

### Response Headers

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Request ID (echoed or generated) |
| `X-RateLimit-Limit` | Rate limit ceiling |
| `X-RateLimit-Remaining` | Remaining requests |
| `X-RateLimit-Reset` | Reset timestamp (Unix) |

---

## Authentication & Authorization

### Authentication Methods

#### 1. Bearer Token (User/Device)

```http
Authorization: Bearer eyJhbGciOiJLQVoxMjgiLCJ0eXAiOiJKV1QifQ...
```

#### 2. API Key (Server-to-Server)

```http
Authorization: ApiKey sk_live_abc123xyz789...
```

#### 3. Client Credentials (OIDC Clients)

```http
Authorization: Basic base64(client_id:client_secret)
```

### Authorization Scopes

| Scope | Description |
|-------|-------------|
| `openid` | OpenID Connect authentication |
| `profile` | User profile information |
| `email` | User email address |
| `devices` | Manage user devices |
| `certificates` | Access certificates |
| `sign` | Create digital signatures |
| `admin` | Administrative operations |
| `admin:users` | Manage users |
| `admin:policies` | Manage policies |
| `admin:audit` | View audit logs |

### Role-Based Access

| Role | Description | Scopes |
|------|-------------|--------|
| `user` | Regular user | `openid`, `profile`, `email`, `devices`, `certificates`, `sign` |
| `tenant_admin` | Tenant administrator | All user scopes + `admin:*` |
| `platform_admin` | Platform administrator | All scopes |

---

## API Versioning

### Version Strategy

- **URL-based versioning**: `/api/v1/`, `/api/v2/`
- **Major versions only** in URL
- **Minor/patch** versions via headers (optional)

### Version Header

```http
X-API-Version: 2025-12-01
```

### Deprecation

```http
Deprecation: true
Sunset: Sat, 01 Jun 2026 00:00:00 GMT
Link: <https://api.idp.example.com/api/v2/users>; rel="successor-version"
```

---

## Common Patterns

### Pagination

```http
GET /api/v1/admin/users?page=1&page_size=20&sort_by=created_at&sort_order=desc

Response:
{
  "data": [...],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 150,
    "total_pages": 8,
    "has_next": true,
    "has_previous": false
  }
}
```

### Filtering

```http
GET /api/v1/admin/users?status=active&created_after=2025-01-01&email_contains=@acme.com
```

### Field Selection

```http
GET /api/v1/admin/users?fields=id,email,display_name,created_at
```

### Expansion

```http
GET /api/v1/identity/users/{id}?expand=devices,certificates
```

### Bulk Operations

```http
POST /api/v1/admin/users/bulk
Content-Type: application/json

{
  "operation": "invite",
  "items": [
    { "email": "user1@example.com", "display_name": "User 1" },
    { "email": "user2@example.com", "display_name": "User 2" }
  ]
}

Response:
{
  "results": [
    { "index": 0, "success": true, "id": "uuid-1" },
    { "index": 1, "success": false, "error": { "code": "USER_EXISTS", "message": "..." } }
  ],
  "summary": {
    "total": 2,
    "successful": 1,
    "failed": 1
  }
}
```

---

## Error Handling

### RFC 9457 ProblemDetails Format

All error responses follow the RFC 9457 ProblemDetails specification:

```json
{
  "type": "https://docs.idp.example.com/errors/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "One or more validation errors occurred.",
  "instance": "/api/v1/identity/users",
  "traceId": "00-abc123def456-789xyz-00",
  "errorCode": "VALIDATION_ERROR",
  "errors": {
    "email": ["Invalid email format"],
    "display_name": ["Display name is required"]
  }
}
```

### Success Response Format

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "display_name": "John Doe",
  "created_at": "2025-12-01T12:00:00Z"
}
```

### Legacy Error Response Format (Deprecated)

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "email",
        "code": "INVALID_FORMAT",
        "message": "Invalid email format"
      }
    ],
    "request_id": "req_abc123",
    "timestamp": "2025-12-01T12:00:00Z",
    "documentation_url": "https://docs.idp.example.com/errors/VALIDATION_ERROR"
  }
}
```

### HTTP Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful GET, PUT, PATCH |
| 201 | Created | Successful POST (resource created) |
| 202 | Accepted | Async operation started |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Invalid request body/params |
| 401 | Unauthorized | Missing or invalid auth |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource conflict (e.g., duplicate) |
| 422 | Unprocessable Entity | Business logic validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Maintenance or overload |

### Error Codes Catalog

#### General Errors

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Authentication required |
| `INVALID_TOKEN` | 401 | Token is invalid or expired |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |

#### Identity Module Errors

| Code | HTTP | Description |
|------|------|-------------|
| `USER_NOT_FOUND` | 404 | User does not exist |
| `USER_SUSPENDED` | 403 | User account is suspended |
| `USER_EXISTS` | 409 | Email already registered |
| `DEVICE_NOT_FOUND` | 404 | Device does not exist |
| `DEVICE_REVOKED` | 403 | Device has been revoked |
| `DEVICE_LIMIT_REACHED` | 422 | Maximum devices exceeded |
| `INVALID_RECOVERY_TOKEN` | 400 | Recovery token invalid |
| `RECOVERY_EXPIRED` | 400 | Recovery session expired |
| `INVALID_OTP` | 400 | OTP code is incorrect |
| `OTP_EXPIRED` | 400 | OTP has expired |

#### Certificate Module Errors

| Code | HTTP | Description |
|------|------|-------------|
| `CERT_NOT_FOUND` | 404 | Certificate not found |
| `CERT_REVOKED` | 403 | Certificate has been revoked |
| `CERT_EXPIRED` | 403 | Certificate has expired |
| `INVALID_CSR` | 400 | CSR is malformed or invalid |
| `CSR_SIGNATURE_INVALID` | 400 | CSR signature verification failed |
| `RENEWAL_NOT_ALLOWED` | 422 | Certificate not eligible for renewal |

#### Authentication Errors

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid client credentials |
| `INVALID_GRANT` | 400 | Invalid authorization grant |
| `INVALID_SCOPE` | 400 | Requested scope not allowed |
| `CONSENT_REQUIRED` | 403 | User consent required |
| `SESSION_EXPIRED` | 401 | Auth session has expired |

---

## API Modules

## Identity Module API

### User Registration

#### Initiate Registration

```yaml
POST /api/v1/identity/registration/initiate
Content-Type: application/json

Request:
{
  "tenant_id": "uuid",
  "email": "user@example.com",
  "display_name": "John Doe",
  "device_info": {
    "device_id": "uuid",
    "model": "iPhone 15 Pro",
    "platform": "iOS",
    "os_version": "17.1",
    "app_version": "1.0.0"
  }
}

Response 201:
{
  "registration_id": "uuid",
  "status": "pending_verification",
  "otp_sent": true,
  "otp_expires_at": "2025-12-01T12:10:00Z",
  "tenant": {
    "id": "uuid",
    "name": "Acme Corp",
    "algorithm": "KAZ-SIGN-128"
  }
}
```

#### Verify Email OTP

```yaml
POST /api/v1/identity/registration/{registration_id}/verify-otp
Content-Type: application/json

Request:
{
  "otp": "847293"
}

Response 200:
{
  "verified": true,
  "next_step": "submit_csr"
}
```

#### Submit Registration CSR

```yaml
POST /api/v1/identity/registration/{registration_id}/submit
Content-Type: application/json

Request:
{
  "device_csr": "base64-encoded-csr",
  "user_csr": "base64-encoded-csr",
  "encrypted_part_control": "base64",
  "encrypted_part_recovery": "base64",
  "signature": "base64-signature-of-payload"
}

Response 202:
{
  "tracking_id": "uuid",
  "status": "pending_approval",
  "estimated_completion": "2025-12-01T12:05:00Z"
}
```

#### Poll Registration Status

```yaml
GET /api/v1/identity/registration/{tracking_id}/status
Authorization: Bearer <device-token>

Response 200:
{
  "status": "completed",  # pending, approved, completed, rejected
  "device_certificate": "base64-pem",
  "user_certificate": "base64-pem",
  "certificate_chain": ["base64-pem", "base64-pem"],
  "recovery_token": "base64-token"
}
```

### User Management

#### Get Current User

```yaml
GET /api/v1/identity/users/me
Authorization: Bearer <access-token>

Response 200:
{
  "id": "uuid",
  "tenant_id": "uuid",
  "email": "user@example.com",
  "display_name": "John Doe",
  "status": "active",
  "email_verified": true,
  "created_at": "2025-12-01T10:00:00Z",
  "last_login_at": "2025-12-01T12:00:00Z",
  "devices_count": 2,
  "certificates": {
    "user": {
      "serial_number": "123456",
      "expires_at": "2026-12-01T10:00:00Z",
      "algorithm": "KAZ-SIGN-128"
    }
  }
}
```

#### Update User Profile

```yaml
PATCH /api/v1/identity/users/me
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "display_name": "John D. Doe"
}

Response 200:
{
  "id": "uuid",
  "display_name": "John D. Doe",
  "updated_at": "2025-12-01T12:00:00Z"
}
```

### Device Management

#### List User Devices

```yaml
GET /api/v1/identity/devices
Authorization: Bearer <access-token>

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "display_name": "John's iPhone 15 Pro",
      "model": "iPhone 15 Pro",
      "platform": "iOS",
      "os_version": "17.1",
      "status": "active",
      "is_primary": true,
      "is_current": true,
      "registered_at": "2025-12-01T10:00:00Z",
      "last_used_at": "2025-12-01T12:00:00Z",
      "last_used_location": "San Francisco, CA",
      "certificate_expires_at": "2026-12-01T10:00:00Z",
      "capabilities": {
        "can_authenticate": true,
        "can_sign": true,
        "can_manage_devices": true
      }
    }
  ],
  "limits": {
    "max_devices": 5,
    "current_count": 2
  }
}
```

#### Create Device Pairing Session

```yaml
POST /api/v1/identity/devices/pairing
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "expires_in_seconds": 300
}

Response 201:
{
  "session_id": "uuid",
  "qr_data": "idp://device-pairing?data=...",
  "qr_image_url": "/api/v1/identity/devices/pairing/{session_id}/qr.png",
  "expires_at": "2025-12-01T12:05:00Z",
  "ws_url": "wss://api.idp.example.com/ws/pairing/{session_id}"
}
```

#### Submit Device for Pairing

```yaml
POST /api/v1/identity/devices/pairing/{session_id}/submit
Content-Type: application/json

Request:
{
  "device_info": {
    "device_id": "uuid",
    "model": "iPad Pro",
    "platform": "iPadOS",
    "os_version": "17.1",
    "display_name": "John's iPad"
  },
  "device_csr": "base64-csr",
  "public_key": "base64-public-key"
}

Response 202:
{
  "status": "pending_approval",
  "ws_url": "wss://api.idp.example.com/ws/pairing/{session_id}"
}
```

#### Approve Device Pairing

```yaml
POST /api/v1/identity/devices/pairing/{session_id}/approve
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "encrypted_key_share": "base64",
  "signature": "base64"
}

Response 200:
{
  "status": "approved",
  "device_id": "uuid"
}
```

#### Update Device

```yaml
PATCH /api/v1/identity/devices/{device_id}
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "display_name": "Work iPhone"
}

Response 200:
{
  "id": "uuid",
  "display_name": "Work iPhone",
  "updated_at": "2025-12-01T12:00:00Z"
}
```

#### Make Device Primary

```yaml
POST /api/v1/identity/devices/{device_id}/make-primary
Authorization: Bearer <access-token>

Response 200:
{
  "id": "uuid",
  "is_primary": true,
  "previous_primary_id": "uuid"
}
```

#### Remove Device

```yaml
DELETE /api/v1/identity/devices/{device_id}
Authorization: Bearer <access-token>

Response 204 No Content
```

#### Report Device Lost

```yaml
POST /api/v1/identity/devices/{device_id}/report-lost
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "reason": "Phone stolen"
}

Response 200:
{
  "status": "revoked",
  "revoked_at": "2025-12-01T12:00:00Z",
  "actions_taken": [
    "certificate_revoked",
    "sessions_invalidated",
    "tokens_revoked"
  ]
}
```

### Account Recovery

#### Initiate Recovery

```yaml
POST /api/v1/identity/recovery/initiate
Content-Type: application/json

Request:
{
  "tenant_id": "uuid",
  "email": "user@example.com",
  "device_id": "new-device-uuid"
}

Response 200:
{
  "session_id": "uuid",
  "otp_sent": true,
  "expires_at": "2025-12-01T13:00:00Z"
}
```

#### Verify Recovery OTP

```yaml
POST /api/v1/identity/recovery/{session_id}/verify-otp
Content-Type: application/json

Request:
{
  "otp": "847293"
}

Response 200:
{
  "verified": true,
  "encrypted_part_recovery": "base64",
  "nonce": "base64",
  "auth_tag": "base64",
  "algorithm": "KAZ-SIGN-128"
}
```

#### Get Control Share

```yaml
POST /api/v1/identity/recovery/{session_id}/control-share
Content-Type: application/json

Request:
{
  "proof_of_decrypt": "base64",
  "client_public_key": "base64"
}

Response 200:
{
  "encrypted_part_control": "base64",
  "nonce": "base64",
  "auth_tag": "base64"
}
```

#### Complete Recovery

```yaml
POST /api/v1/identity/recovery/{session_id}/complete
Content-Type: application/json

Request:
{
  "device_csr": "base64",
  "encrypted_part_control": "base64",
  "encrypted_part_recovery": "base64",
  "nonce": "base64",
  "auth_tag": "base64",
  "device_name": "iPhone 15 Pro",
  "platform": "iOS"
}

Response 200:
{
  "device_certificate": "base64-pem",
  "user_certificate": "base64-pem",
  "certificate_chain": ["base64-pem"],
  "revoked_devices": 1
}
```

---

## Certificate Module API

### Certificate Operations

#### Get Certificate

```yaml
GET /api/v1/certificates/{serial_number}
Authorization: Bearer <access-token>

Response 200:
{
  "serial_number": "1234567890",
  "type": "user",
  "status": "active",
  "subject": "CN=John Doe,O=Acme Corp",
  "issuer": "CN=Acme Corp CA,O=Acme Corp",
  "not_before": "2025-12-01T10:00:00Z",
  "not_after": "2026-12-01T10:00:00Z",
  "algorithm": "KAZ-SIGN-128",
  "public_key": "base64",
  "certificate_pem": "base64"
}
```

#### List User Certificates

```yaml
GET /api/v1/certificates?type=user&status=active
Authorization: Bearer <access-token>

Response 200:
{
  "data": [
    {
      "serial_number": "1234567890",
      "type": "user",
      "status": "active",
      "expires_at": "2026-12-01T10:00:00Z"
    }
  ]
}
```

### Certificate Renewal

#### Check Renewal Status

```yaml
GET /api/v1/certificates/{serial_number}/renewal-status
Authorization: Bearer <access-token>

Response 200:
{
  "certificate_id": "uuid",
  "status": "active",
  "expires_at": "2026-12-01T10:00:00Z",
  "renewal_window_starts": "2026-11-01T00:00:00Z",
  "in_renewal_window": false,
  "in_grace_period": false,
  "auto_renewal_enabled": true,
  "key_rotation_required": false,
  "can_renew": false,
  "renewal_blocked_reason": "Not in renewal window"
}
```

#### Request Renewal Token

```yaml
POST /api/v1/certificates/{serial_number}/renewal-token
Authorization: Bearer <access-token>

Response 200:
{
  "token": "renewal-token-...",
  "expires_at": "2025-12-01T13:00:00Z",
  "key_rotation_required": false
}
```

#### Submit Renewal

```yaml
POST /api/v1/certificates/{serial_number}/renew
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "csr": "base64-csr",
  "renewal_token": "renewal-token-...",
  "signature": "base64-signature"
}

Response 200:
{
  "new_certificate": "base64-pem",
  "new_serial_number": "1234567891",
  "not_before": "2025-12-01T12:00:00Z",
  "not_after": "2026-12-01T12:00:00Z",
  "certificate_chain": ["base64-pem"]
}
```

### Certificate Revocation

#### Revoke Certificate

```yaml
POST /api/v1/certificates/{serial_number}/revoke
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "reason": "key_compromise",
  "comment": "Device reported stolen"
}

Response 200:
{
  "serial_number": "1234567890",
  "status": "revoked",
  "revoked_at": "2025-12-01T12:00:00Z",
  "revocation_reason": "key_compromise"
}
```

#### Get CRL

```yaml
GET /api/v1/certificates/crl
Accept: application/pkix-crl

Response 200:
[Binary CRL data]
```

#### OCSP Query

```yaml
POST /api/v1/certificates/ocsp
Content-Type: application/ocsp-request

[Binary OCSP request]

Response 200:
Content-Type: application/ocsp-response

[Binary OCSP response]
```

---

## Admin Module API

### Tenant Management

#### Get Tenant

```yaml
GET /api/v1/admin/tenant
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "id": "uuid",
  "name": "Acme Corporation",
  "slug": "acme-corporation",
  "status": "active",
  "tier": "enterprise",
  "primary_algorithm": "KAZ-SIGN-128",
  "primary_domain": "acme.com",
  "created_at": "2025-01-01T00:00:00Z",
  "stats": {
    "total_users": 150,
    "active_users": 142,
    "total_devices": 280,
    "active_devices": 265,
    "oidc_clients": 5,
    "certificates_issued": 430
  },
  "limits": {
    "max_users": 500,
    "max_devices_per_user": 5,
    "max_oidc_clients": 20
  },
  "ca_certificate": {
    "serial_number": "root-123",
    "expires_at": "2030-01-01T00:00:00Z"
  }
}
```

#### Update Tenant Configuration

```yaml
PATCH /api/v1/admin/tenant/configuration
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "features": {
    "qr_code_authentication": true,
    "document_signing": true,
    "physical_access_control": false
  },
  "security_policy": {
    "require_biometric": true,
    "session_timeout_minutes": 60,
    "max_failed_attempts": 5
  },
  "device_policy": {
    "max_devices_per_user": 5,
    "allow_jailbroken_devices": false
  }
}

Response 200:
{
  "updated": true,
  "updated_at": "2025-12-01T12:00:00Z"
}
```

### User Management (Admin)

#### List Users

```yaml
GET /api/v1/admin/users?page=1&page_size=20&status=active&search=john
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "email": "john.doe@acme.com",
      "display_name": "John Doe",
      "status": "active",
      "role": "user",
      "department": "Engineering",
      "devices_count": 2,
      "last_login_at": "2025-12-01T12:00:00Z",
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 150,
    "total_pages": 8
  }
}
```

#### Invite User

```yaml
POST /api/v1/admin/users/invite
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "email": "jane.doe@acme.com",
  "display_name": "Jane Doe",
  "department": "Marketing",
  "role": "user",
  "groups": ["uuid-group-1"]
}

Response 201:
{
  "invitation_id": "uuid",
  "email": "jane.doe@acme.com",
  "status": "pending",
  "expires_at": "2025-12-08T12:00:00Z"
}
```

#### Bulk Invite Users

```yaml
POST /api/v1/admin/users/bulk-invite
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "users": [
    { "email": "user1@acme.com", "display_name": "User 1" },
    { "email": "user2@acme.com", "display_name": "User 2" }
  ]
}

Response 200:
{
  "results": [
    { "email": "user1@acme.com", "success": true, "invitation_id": "uuid" },
    { "email": "user2@acme.com", "success": false, "error": "USER_EXISTS" }
  ],
  "summary": {
    "total": 2,
    "successful": 1,
    "failed": 1
  }
}
```

#### Suspend User

```yaml
POST /api/v1/admin/users/{user_id}/suspend
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "reason": "Security investigation"
}

Response 200:
{
  "id": "uuid",
  "status": "suspended",
  "suspended_at": "2025-12-01T12:00:00Z"
}
```

#### Reactivate User

```yaml
POST /api/v1/admin/users/{user_id}/reactivate
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "id": "uuid",
  "status": "active",
  "reactivated_at": "2025-12-01T12:00:00Z"
}
```

### OIDC Client Management

#### List OIDC Clients

```yaml
GET /api/v1/admin/oidc-clients
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "client_id": "acme-portal-abc123",
      "client_name": "Acme Portal",
      "client_type": "confidential",
      "status": "active",
      "redirect_uris": ["https://portal.acme.com/callback"],
      "allowed_scopes": ["openid", "profile", "email"],
      "created_at": "2025-06-01T10:00:00Z"
    }
  ]
}
```

#### Create OIDC Client

```yaml
POST /api/v1/admin/oidc-clients
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "client_name": "Acme Mobile App",
  "client_type": "public",
  "redirect_uris": [
    "acme://callback",
    "https://acme.com/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email"],
  "allowed_grant_types": ["authorization_code", "refresh_token"],
  "require_pkce": true
}

Response 201:
{
  "id": "uuid",
  "client_id": "acme-mobile-xyz789",
  "client_secret": null,  # Public client
  "client_name": "Acme Mobile App",
  "created_at": "2025-12-01T12:00:00Z"
}
```

#### Rotate Client Secret

```yaml
POST /api/v1/admin/oidc-clients/{client_id}/rotate-secret
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "client_id": "acme-portal-abc123",
  "client_secret": "new-secret-...",  # Only shown once
  "rotated_at": "2025-12-01T12:00:00Z"
}
```

### Audit Logs

#### List Audit Logs

```yaml
GET /api/v1/admin/audit-logs?page=1&page_size=50&action=user_authenticated&from=2025-12-01
Authorization: Bearer <tenant-admin-token>

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "timestamp": "2025-12-01T12:00:00Z",
      "action": "user_authenticated",
      "severity": "info",
      "user_id": "uuid",
      "user_email": "john.doe@acme.com",
      "device_id": "uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "Digital ID iOS/1.0.0",
      "details": {
        "client_id": "acme-portal",
        "method": "qr_code"
      }
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_items": 10000
  }
}
```

#### Export Audit Logs

```yaml
POST /api/v1/admin/audit-logs/export
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

Request:
{
  "format": "csv",
  "from": "2025-11-01T00:00:00Z",
  "to": "2025-12-01T00:00:00Z",
  "actions": ["user_authenticated", "certificate_issued"]
}

Response 202:
{
  "export_id": "uuid",
  "status": "processing",
  "download_url": null,
  "estimated_completion": "2025-12-01T12:05:00Z"
}
```

---

## Crypto Module API

### Signing Operations

#### Sign Data

```yaml
POST /api/v1/crypto/sign
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "data": "base64-data-to-sign",
  "algorithm": "KAZ-SIGN-128",
  "key_type": "user"  # user, device
}

Response 200:
{
  "signature": "base64-signature",
  "algorithm": "KAZ-SIGN-128",
  "certificate_serial": "1234567890",
  "signed_at": "2025-12-01T12:00:00Z"
}
```

#### Verify Signature

```yaml
POST /api/v1/crypto/verify
Authorization: Bearer <access-token>
Content-Type: application/json

Request:
{
  "data": "base64-original-data",
  "signature": "base64-signature",
  "certificate": "base64-certificate-pem"
}

Response 200:
{
  "valid": true,
  "signer": {
    "subject": "CN=John Doe,O=Acme Corp",
    "certificate_serial": "1234567890"
  },
  "verified_at": "2025-12-01T12:00:00Z"
}
```

---

## OIDC Endpoints

### Discovery

```yaml
GET /.well-known/openid-configuration

Response 200:
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/oauth/authorize",
  "token_endpoint": "https://idp.example.com/oauth/token",
  "userinfo_endpoint": "https://idp.example.com/oauth/userinfo",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "pushed_authorization_request_endpoint": "https://idp.example.com/oauth/par",
  "revocation_endpoint": "https://idp.example.com/oauth/revoke",
  "introspection_endpoint": "https://idp.example.com/oauth/introspect",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "id_token_signing_alg_values_supported": ["KAZ128", "MLDSA65"],
  "require_pkce": true
}
```

### JWKS

```yaml
GET /.well-known/jwks.json

Response 200:
{
  "keys": [
    {
      "kty": "PQC",
      "alg": "KAZ128",
      "kid": "tenant-123-key-1",
      "use": "sig",
      "x": "base64-public-key"
    }
  ]
}
```

### Pushed Authorization Request (PAR)

```yaml
POST /oauth/par
Content-Type: application/x-www-form-urlencoded

client_id=acme-portal
&response_type=code
&redirect_uri=https://portal.acme.com/callback
&scope=openid profile email
&state=abc123
&nonce=xyz789
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256

Response 201:
{
  "request_uri": "urn:idp:par:12345678-uuid",
  "expires_in": 60
}
```

### Authorization

```yaml
GET /oauth/authorize?request_uri=urn:idp:par:12345678-uuid

Response: Redirect to IdP authentication flow
```

### Token

```yaml
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=auth-code-from-callback
&redirect_uri=https://portal.acme.com/callback
&code_verifier=original-code-verifier

Response 200:
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ...",
  "id_token": "eyJ...",
  "scope": "openid profile email"
}
```

### Refresh Token

```yaml
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token
&refresh_token=eyJ...

Response 200:
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ...",
  "scope": "openid profile email"
}
```

### UserInfo

```yaml
GET /oauth/userinfo
Authorization: Bearer <access-token>

Response 200:
{
  "sub": "user-uuid",
  "name": "John Doe",
  "email": "john.doe@acme.com",
  "email_verified": true,
  "org_id": "tenant-uuid",
  "org_name": "Acme Corporation"
}
```

### Token Revocation

```yaml
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJ...
&token_type_hint=refresh_token

Response 200 OK
```

### QR Authentication Session

```yaml
POST /api/v1/qr/sessions
Authorization: Bearer <client-token>
Content-Type: application/json

Request:
{
  "type": "login",
  "client_id": "acme-portal",
  "redirect_uri": "https://portal.acme.com/callback",
  "scopes": ["openid", "profile", "email"],
  "state": "abc123",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256"
}

Response 201:
{
  "session_id": "uuid",
  "qr_data": "idp://qr/login?data=...",
  "qr_image_url": "/api/v1/qr/sessions/{session_id}/qr.png",
  "expires_at": "2025-12-01T12:05:00Z",
  "ws_url": "wss://api.idp.example.com/ws/qr/{session_id}",
  "poll_url": "/api/v1/qr/sessions/{session_id}/status"
}
```

---

## Webhook Events

### Event Types

| Event | Description |
|-------|-------------|
| `user.created` | New user registered |
| `user.updated` | User profile updated |
| `user.deleted` | User deleted |
| `user.suspended` | User suspended |
| `user.reactivated` | User reactivated |
| `device.registered` | New device registered |
| `device.removed` | Device removed |
| `device.reported_lost` | Device reported lost |
| `certificate.issued` | Certificate issued |
| `certificate.renewed` | Certificate renewed |
| `certificate.revoked` | Certificate revoked |
| `auth.success` | Authentication successful |
| `auth.failure` | Authentication failed |

### Webhook Payload

```json
{
  "id": "evt_abc123",
  "type": "user.created",
  "tenant_id": "uuid",
  "created_at": "2025-12-01T12:00:00Z",
  "data": {
    "user_id": "uuid",
    "email": "john.doe@acme.com",
    "display_name": "John Doe"
  }
}
```

### Webhook Signature

```http
X-Webhook-Signature: sha256=base64-hmac-signature
X-Webhook-Timestamp: 1701432000
```

Verification:

```
signature = HMAC-SHA256(
  key: webhook_secret,
  message: timestamp + "." + request_body
)
```

---

## Rate Limiting

### Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Authentication | 10/min | Per IP |
| Registration | 5/hour | Per email |
| Recovery | 3/hour | Per user |
| API (authenticated) | 1000/min | Per user |
| API (admin) | 500/min | Per admin |
| Webhooks | 100/sec | Per tenant |

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1701432060
```

### Rate Limit Exceeded Response

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "retry_after": 60
  }
}
```

---

## Implementation Checklist

### Phase 1: Core Identity API

- [ ] User registration endpoints
- [ ] Device management endpoints
- [ ] Account recovery endpoints
- [ ] User profile endpoints

### Phase 2: Certificate API

- [ ] Certificate retrieval
- [ ] Certificate renewal
- [ ] Certificate revocation
- [ ] CRL/OCSP endpoints

### Phase 3: Admin API

- [ ] Tenant management
- [ ] User management (admin)
- [ ] OIDC client management
- [ ] Audit log endpoints

### Phase 4: OIDC/OAuth

- [ ] Discovery endpoints
- [ ] PAR endpoint
- [ ] Token endpoint
- [ ] UserInfo endpoint

### Phase 5: QR Authentication

- [ ] QR session creation
- [ ] QR status polling
- [ ] WebSocket notifications

### Phase 6: Infrastructure

- [ ] Rate limiting
- [ ] Request validation
- [ ] Error handling
- [ ] Webhook delivery

---

## Swagger/OpenAPI Configuration

### Swashbuckle Setup

```csharp
// Program.cs
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PQC Digital Identity Platform API",
        Version = "v1",
        Description = "Enterprise-grade Post-Quantum Cryptography Digital Identity Platform",
        Contact = new OpenApiContact
        {
            Name = "API Support",
            Email = "support@idp.example.com",
            Url = new Uri("https://docs.idp.example.com")
        },
        License = new OpenApiLicense
        {
            Name = "Proprietary",
            Url = new Uri("https://idp.example.com/license")
        }
    });

    // Bearer token authentication
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "PQC-JWT Authorization header using Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // API Key authentication (for server-to-server)
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Description = "API Key for server-to-server authentication",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "ApiKey"
    });

    // Include XML documentation comments
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        options.IncludeXmlComments(xmlPath);
    }

    // Custom schema IDs to avoid conflicts
    options.CustomSchemaIds(type => type.FullName?.Replace("+", "_"));

    // Enable annotations from Carter
    options.EnableAnnotations();
});
```

### Swagger UI Configuration

```csharp
// Program.cs - Enable Swagger UI
if (app.Environment.IsDevelopment())
{
    app.UseSwagger(options =>
    {
        options.RouteTemplate = "swagger/{documentName}/swagger.json";
    });

    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "IdP API v1");
        options.RoutePrefix = "swagger";
        options.DocumentTitle = "PQC IdP - API Documentation";
        options.DefaultModelsExpandDepth(2);
        options.DisplayRequestDuration();
        options.EnableDeepLinking();
        options.EnableFilter();
        options.ShowExtensions();
    });
}
```

### Carter Module with Swagger Annotations

```csharp
public class UserEndpoints : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/identity/users")
            .WithTags("Users")
            .WithOpenApi();

        group.MapGet("/me", GetCurrentUser)
            .WithName("GetCurrentUser")
            .WithSummary("Get current user profile")
            .WithDescription("Returns the profile of the currently authenticated user")
            .Produces<UserResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireAuthorization();

        group.MapPatch("/me", UpdateCurrentUser)
            .WithName("UpdateCurrentUser")
            .WithSummary("Update current user profile")
            .Accepts<UpdateUserRequest>("application/json")
            .Produces<UserResponse>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireAuthorization();

        group.MapGet("/{id:guid}", GetUserById)
            .WithName("GetUserById")
            .WithSummary("Get user by ID")
            .Produces<UserResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization("admin");
    }
}
```

### ProblemDetails Configuration

```csharp
// Program.cs - Configure ProblemDetails
builder.Services.AddProblemDetails(options =>
{
    options.CustomizeProblemDetails = context =>
    {
        // Add trace ID for correlation
        context.ProblemDetails.Extensions["traceId"] =
            Activity.Current?.Id ?? context.HttpContext.TraceIdentifier;

        // Add timestamp
        context.ProblemDetails.Extensions["timestamp"] = DateTime.UtcNow;

        // Add documentation URL based on error type
        if (context.ProblemDetails.Status.HasValue)
        {
            var errorType = context.ProblemDetails.Status switch
            {
                400 => "bad-request",
                401 => "unauthorized",
                403 => "forbidden",
                404 => "not-found",
                409 => "conflict",
                422 => "validation-error",
                429 => "rate-limited",
                _ => "internal-error"
            };

            context.ProblemDetails.Type =
                $"https://docs.idp.example.com/errors/{errorType}";
        }
    };
});

// Use exception handler with ProblemDetails
app.UseExceptionHandler();
app.UseStatusCodePages();
```

### Result Pattern to ProblemDetails Mapping

```csharp
public static class ResultExtensions
{
    public static IResult ToProblemResult(this Error error)
    {
        var (statusCode, title) = error.Type switch
        {
            ErrorType.Validation => (StatusCodes.Status400BadRequest, "Validation Error"),
            ErrorType.NotFound => (StatusCodes.Status404NotFound, "Not Found"),
            ErrorType.Conflict => (StatusCodes.Status409Conflict, "Conflict"),
            ErrorType.Unauthorized => (StatusCodes.Status401Unauthorized, "Unauthorized"),
            ErrorType.Forbidden => (StatusCodes.Status403Forbidden, "Forbidden"),
            _ => (StatusCodes.Status500InternalServerError, "Internal Error")
        };

        return Results.Problem(
            statusCode: statusCode,
            title: title,
            detail: error.Message,
            type: $"https://docs.idp.example.com/errors/{error.Code.ToLowerInvariant()}",
            extensions: new Dictionary<string, object?>
            {
                ["errorCode"] = error.Code,
                ["timestamp"] = DateTime.UtcNow
            }
        );
    }

    public static IResult ToResult<T>(this Result<T> result, Func<T, IResult> onSuccess) =>
        result.Match(onSuccess, error => error.ToProblemResult());
}
```

### Access Swagger UI

| Environment | URL |
|-------------|-----|
| Development | `http://localhost:5000/swagger` |
| Staging | `https://api.staging.idp.example.com/swagger` |
| Production | Disabled (OpenAPI spec available at `/swagger/v1/swagger.json`) |

---

## References

- [OpenAPI 3.1 Specification](https://spec.openapis.org/oas/v3.1.0)
- [RFC 9457 - Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html)
- [Swashbuckle.AspNetCore](https://github.com/domaindrivendev/Swashbuckle.AspNetCore)
- [Carter](https://github.com/CarterCommunity/Carter)
- [AUTHENTICATION_FLOW.md](../architecture/AUTHENTICATION_FLOW.md)
- [QR_CODE_AUTHENTICATION.md](../architecture/QR_CODE_AUTHENTICATION.md)
- [DEVICE_MANAGEMENT.md](../architecture/DEVICE_MANAGEMENT.md)
