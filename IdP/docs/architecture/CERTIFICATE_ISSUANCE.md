# Certificate Issuance Flow - Backend

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Certificate Hierarchy](#certificate-hierarchy)
3. [CSR Processing Flow](#csr-processing-flow)
4. [Certificate Issuance Flow](#certificate-issuance-flow)
5. [Certificate Types](#certificate-types)
6. [Validation Rules](#validation-rules)
7. [HSM Integration](#hsm-integration)
8. [Certificate Lifecycle](#certificate-lifecycle)
9. [Revocation Management](#revocation-management)
10. [Data Models](#data-models)
11. [API Endpoints](#api-endpoints)
12. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

The Certificate Module acts as a **Private Certificate Authority (CA)** that:

- Processes Certificate Signing Requests (CSRs) from clients
- Validates CSR signatures and content
- Issues PQC-signed X.509 certificates
- Manages certificate lifecycle (issuance, renewal, revocation)
- Maintains Certificate Revocation Lists (CRLs)

### Key Principles

1. **Tenant Isolation** - Each organization has its own Issuing CA
2. **HSM-Backed Signing** - All CA private keys stored in HSM
3. **PQC Algorithms** - Certificates signed with ML-DSA or KAZ-SIGN
4. **Audit Trail** - Every certificate operation is logged
5. **Dual Certificate** - Both device and user certificates issued

---

## Certificate Hierarchy

### Three-Tier PKI Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CERTIFICATE HIERARCHY                                │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────┐
                    │       Platform Root CA       │
                    │                             │
                    │  • Offline/Air-gapped       │
                    │  • 10-year validity         │
                    │  • Signs Tenant CAs only    │
                    │  • HSM-backed (dedicated)   │
                    │  • Algorithm: ML-DSA-65     │
                    └──────────────┬──────────────┘
                                   │
                                   │ Signs
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Tenant A CA    │     │  Tenant B CA    │     │  Tenant C CA    │
│  (Issuing CA)   │     │  (Issuing CA)   │     │  (Issuing CA)   │
│                 │     │                 │     │                 │
│ • 3-year valid  │     │ • 3-year valid  │     │ • 3-year valid  │
│ • Online        │     │ • Online        │     │ • Online        │
│ • HSM-backed    │     │ • HSM-backed    │     │ • HSM-backed    │
│ • ML-DSA-65     │     │ • KAZ-SIGN-128  │     │ • ML-DSA-87     │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │ Signs                 │ Signs                 │ Signs
         │                       │                       │
    ┌────┴────┐             ┌────┴────┐             ┌────┴────┐
    │         │             │         │             │         │
    ▼         ▼             ▼         ▼             ▼         ▼
┌───────┐ ┌───────┐   ┌───────┐ ┌───────┐   ┌───────┐ ┌───────┐
│Device │ │ User  │   │Device │ │ User  │   │Device │ │ User  │
│ Cert  │ │ Cert  │   │ Cert  │ │ Cert  │   │ Cert  │ │ Cert  │
└───────┘ └───────┘   └───────┘ └───────┘   └───────┘ └───────┘
```

### Certificate Chain Validation

```
End Entity Certificate (User/Device)
         │
         │ Issuer: Tenant CA
         │ Verify with Tenant CA public key
         ▼
    Tenant CA Certificate
         │
         │ Issuer: Platform Root CA
         │ Verify with Root CA public key
         ▼
    Platform Root CA Certificate
         │
         │ Self-signed
         │ Trust anchor
         ▼
       TRUSTED
```

---

## CSR Processing Flow

### Sequence Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CSR PROCESSING FLOW                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │     │   API    │     │   CSR    │     │ Validation│    │    DB    │
│   App    │     │ Gateway  │     │ Service  │     │  Service  │    │          │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └─────┬─────┘    └────┬─────┘
     │                │                │                 │               │
     │ 1. Submit CSR  │                │                 │               │
     │   (signed)     │                │                 │               │
     │───────────────>│                │                 │               │
     │                │                │                 │               │
     │                │ 2. Verify      │                 │               │
     │                │    request     │                 │               │
     │                │    signature   │                 │               │
     │                │                │                 │               │
     │                │ 3. Forward CSR │                 │               │
     │                │───────────────>│                 │               │
     │                │                │                 │               │
     │                │                │ 4. Parse CSR    │               │
     │                │                │    (DER/PEM)    │               │
     │                │                │                 │               │
     │                │                │ 5. Validate CSR │               │
     │                │                │────────────────>│               │
     │                │                │                 │               │
     │                │                │                 │ 6. Check:     │
     │                │                │                 │ • Signature   │
     │                │                │                 │ • Algorithm   │
     │                │                │                 │ • Subject DN  │
     │                │                │                 │ • Key usage   │
     │                │                │                 │               │
     │                │                │ 7. Validation   │               │
     │                │                │    result       │               │
     │                │                │<────────────────│               │
     │                │                │                 │               │
     │                │                │ 8. Store CSR    │               │
     │                │                │    (pending)    │               │
     │                │                │─────────────────────────────────>
     │                │                │                 │               │
     │                │                │                 │   9. CSR ID   │
     │                │                │<─────────────────────────────────
     │                │                │                 │               │
     │                │ 10. Return     │                 │               │
     │                │     tracking ID│                 │               │
     │                │<───────────────│                 │               │
     │                │                │                 │               │
     │ 11. RTID       │                │                 │               │
     │<───────────────│                │                 │               │
     │                │                │                 │               │
```

### CSR Validation Steps

```csharp
public class CsrValidationService : ICsrValidationService
{
    public async Task<CsrValidationResult> ValidateAsync(
        byte[] csrBytes,
        CsrValidationContext context,
        CancellationToken ct = default)
    {
        var errors = new List<ValidationError>();

        // Step 1: Parse CSR
        var csr = ParseCsr(csrBytes);
        if (csr is null)
        {
            return CsrValidationResult.Failed("Invalid CSR format");
        }

        // Step 2: Verify self-signature
        if (!VerifyCsrSignature(csr))
        {
            errors.Add(new ValidationError("CSR_SIGNATURE_INVALID",
                "CSR signature verification failed"));
        }

        // Step 3: Validate algorithm
        if (!IsAllowedAlgorithm(csr.SignatureAlgorithm, context.TenantId))
        {
            errors.Add(new ValidationError("ALGORITHM_NOT_ALLOWED",
                $"Algorithm {csr.SignatureAlgorithm} not allowed for this tenant"));
        }

        // Step 4: Validate Subject DN
        var dnErrors = ValidateSubjectDn(csr.Subject, context);
        errors.AddRange(dnErrors);

        // Step 5: Validate public key
        if (!IsValidPublicKey(csr.PublicKey, csr.SignatureAlgorithm))
        {
            errors.Add(new ValidationError("INVALID_PUBLIC_KEY",
                "Public key validation failed"));
        }

        // Step 6: Check for duplicate
        if (await IsDuplicateCsr(csr, context.TenantId, ct))
        {
            errors.Add(new ValidationError("DUPLICATE_CSR",
                "A CSR with this public key already exists"));
        }

        // Step 7: Validate extensions (if present)
        var extErrors = ValidateExtensions(csr.Extensions, context.CertificateType);
        errors.AddRange(extErrors);

        return errors.Any()
            ? CsrValidationResult.Failed(errors)
            : CsrValidationResult.Success(csr);
    }
}
```

---

## Certificate Issuance Flow

### Sequence Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CERTIFICATE ISSUANCE FLOW                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│   CSR    │     │ Issuance │     │  Policy  │     │   HSM    │     │    DB    │
│  Queue   │     │ Service  │     │  Engine  │     │ Service  │     │          │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │                │
     │ 1. Pending CSR │                │                │                │
     │───────────────>│                │                │                │
     │                │                │                │                │
     │                │ 2. Check policy│                │                │
     │                │───────────────>│                │                │
     │                │                │                │                │
     │                │                │ 3. Evaluate:   │                │
     │                │                │ • Auto-approve?│                │
     │                │                │ • Manual review│                │
     │                │                │ • Rate limits  │                │
     │                │                │                │                │
     │                │ 4. Policy      │                │                │
     │                │    decision    │                │                │
     │                │<───────────────│                │                │
     │                │                │                │                │
     │                │ [If approved]  │                │                │
     │                │                │                │                │
     │                │ 5. Build       │                │                │
     │                │    certificate │                │                │
     │                │    (unsigned)  │                │                │
     │                │                │                │                │
     │                │ 6. Request     │                │                │
     │                │    signature   │                │                │
     │                │────────────────────────────────>│                │
     │                │                │                │                │
     │                │                │                │ 7. Sign with   │
     │                │                │                │    Tenant CA   │
     │                │                │                │    private key │
     │                │                │                │                │
     │                │ 8. Signature   │                │                │
     │                │<────────────────────────────────│                │
     │                │                │                │                │
     │                │ 9. Assemble    │                │                │
     │                │    certificate │                │                │
     │                │                │                │                │
     │                │ 10. Store      │                │                │
     │                │     certificate│                │                │
     │                │─────────────────────────────────────────────────>│
     │                │                │                │                │
     │                │                │                │    11. Cert ID │
     │                │<─────────────────────────────────────────────────│
     │                │                │                │                │
     │                │ 12. Update CSR │                │                │
     │                │     status     │                │                │
     │                │─────────────────────────────────────────────────>│
     │                │                │                │                │
```

### Certificate Builder

```csharp
public class CertificateBuilder
{
    private readonly ICertificateTemplate _template;
    private X509Name _subject;
    private byte[] _publicKey;
    private string _algorithm;
    private List<X509Extension> _extensions = new();

    public CertificateBuilder WithSubject(X509Name subject)
    {
        _subject = subject;
        return this;
    }

    public CertificateBuilder WithPublicKey(byte[] publicKey, string algorithm)
    {
        _publicKey = publicKey;
        _algorithm = algorithm;
        return this;
    }

    public CertificateBuilder WithValidity(TimeSpan validity)
    {
        _notBefore = DateTime.UtcNow;
        _notAfter = _notBefore.Add(validity);
        return this;
    }

    public CertificateBuilder WithExtensions(CertificateType certType)
    {
        _extensions = certType switch
        {
            CertificateType.User => GetUserCertExtensions(),
            CertificateType.Device => GetDeviceCertExtensions(),
            CertificateType.TenantCA => GetCaExtensions(),
            _ => throw new ArgumentException("Unknown certificate type")
        };
        return this;
    }

    public UnsignedCertificate Build()
    {
        return new UnsignedCertificate
        {
            Version = 3,
            SerialNumber = GenerateSerialNumber(),
            Subject = _subject,
            Issuer = _issuer,
            NotBefore = _notBefore,
            NotAfter = _notAfter,
            PublicKey = _publicKey,
            PublicKeyAlgorithm = _algorithm,
            Extensions = _extensions,
            ToBeSigned = BuildTbsCertificate()
        };
    }

    private List<X509Extension> GetUserCertExtensions()
    {
        return new List<X509Extension>
        {
            // Basic Constraints: Not a CA
            new BasicConstraintsExtension(false, false, -1),

            // Key Usage: Digital Signature, Non-Repudiation
            new KeyUsageExtension(
                KeyUsage.DigitalSignature | KeyUsage.NonRepudiation,
                critical: true),

            // Extended Key Usage: Client Auth, Email Protection
            new ExtendedKeyUsageExtension(new[]
            {
                ExtendedKeyUsage.ClientAuth,
                ExtendedKeyUsage.EmailProtection
            }),

            // Subject Key Identifier
            new SubjectKeyIdentifierExtension(_publicKey),

            // Authority Key Identifier
            new AuthorityKeyIdentifierExtension(_issuerKeyId),

            // CRL Distribution Points
            new CrlDistributionPointsExtension(_crlUrls),

            // Authority Information Access (OCSP)
            new AuthorityInfoAccessExtension(_ocspUrl, _issuerUrl)
        };
    }

    private List<X509Extension> GetDeviceCertExtensions()
    {
        return new List<X509Extension>
        {
            // Basic Constraints: Not a CA
            new BasicConstraintsExtension(false, false, -1),

            // Key Usage: Digital Signature, Key Encipherment
            new KeyUsageExtension(
                KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment,
                critical: true),

            // Extended Key Usage: Client Auth
            new ExtendedKeyUsageExtension(new[]
            {
                ExtendedKeyUsage.ClientAuth
            }),

            // Custom: Device ID extension
            new DeviceIdentifierExtension(_deviceId),

            // Subject Key Identifier
            new SubjectKeyIdentifierExtension(_publicKey),

            // Authority Key Identifier
            new AuthorityKeyIdentifierExtension(_issuerKeyId)
        };
    }
}
```

---

## Certificate Types

### User Certificate

| Field | Value | Description |
|-------|-------|-------------|
| Subject CN | User's display name | Common Name |
| Subject Email | User's email | Email address |
| Subject O | Organization name | Organization |
| Key Usage | digitalSignature, nonRepudiation | Signing operations |
| Extended Key Usage | clientAuth, emailProtection | Authentication, S/MIME |
| Validity | 1 year (configurable) | Per tenant settings |

**Example Subject DN:**
```
CN=John Doe, EMAIL=john.doe@example.com, O=Example Corp, C=US
```

### Device Certificate

| Field | Value | Description |
|-------|-------|-------------|
| Subject CN | Device identifier | Unique device ID |
| Subject O | Organization name | Organization |
| Key Usage | digitalSignature, keyEncipherment | Signing, encryption |
| Extended Key Usage | clientAuth | Device authentication |
| Validity | 2 years (configurable) | Per tenant settings |
| Custom Extension | Device metadata | Platform, model, etc. |

**Example Subject DN:**
```
CN=device-a1b2c3d4-5678-90ef, O=Example Corp, C=US
```

### Tenant CA Certificate

| Field | Value | Description |
|-------|-------|-------------|
| Subject CN | Tenant CA name | "Example Corp Issuing CA" |
| Subject O | Organization name | Organization |
| Key Usage | keyCertSign, cRLSign | CA operations |
| Basic Constraints | CA=true, pathLen=0 | Issuing CA only |
| Validity | 3 years | Fixed |

---

## Validation Rules

### Subject DN Validation

```csharp
public class SubjectDnValidator
{
    public List<ValidationError> Validate(
        X509Name subject,
        CsrValidationContext context)
    {
        var errors = new List<ValidationError>();

        // CN is required
        var cn = subject.GetValueByOid(OidCN);
        if (string.IsNullOrWhiteSpace(cn))
        {
            errors.Add(new ValidationError("CN_REQUIRED",
                "Common Name (CN) is required"));
        }

        // CN length check
        if (cn?.Length > 64)
        {
            errors.Add(new ValidationError("CN_TOO_LONG",
                "Common Name must be 64 characters or less"));
        }

        // Email format (if present)
        var email = subject.GetValueByOid(OidEmail);
        if (!string.IsNullOrEmpty(email) && !IsValidEmail(email))
        {
            errors.Add(new ValidationError("INVALID_EMAIL",
                "Email address format is invalid"));
        }

        // Organization must match tenant
        var org = subject.GetValueByOid(OidO);
        if (org != context.TenantOrganizationName)
        {
            errors.Add(new ValidationError("ORG_MISMATCH",
                "Organization must match tenant organization"));
        }

        // No wildcards in CN
        if (cn?.Contains("*") == true)
        {
            errors.Add(new ValidationError("WILDCARD_NOT_ALLOWED",
                "Wildcards are not allowed in Common Name"));
        }

        return errors;
    }
}
```

### Algorithm Validation

```csharp
public class AlgorithmValidator
{
    private static readonly Dictionary<string, AlgorithmInfo> AllowedAlgorithms = new()
    {
        // ML-DSA (Dilithium)
        ["ML-DSA-44"] = new(SecurityLevel: 128, KeySize: 1312, SigSize: 2420),
        ["ML-DSA-65"] = new(SecurityLevel: 192, KeySize: 1952, SigSize: 3309),
        ["ML-DSA-87"] = new(SecurityLevel: 256, KeySize: 2592, SigSize: 4627),

        // KAZ-SIGN
        ["KAZ-SIGN-128"] = new(SecurityLevel: 128, KeySize: 54, SigSize: 162),
        ["KAZ-SIGN-192"] = new(SecurityLevel: 192, KeySize: 88, SigSize: 264),
        ["KAZ-SIGN-256"] = new(SecurityLevel: 256, KeySize: 118, SigSize: 356),
    };

    public bool IsAllowed(string algorithm, Guid tenantId)
    {
        // Check if algorithm is in allowed list
        if (!AllowedAlgorithms.ContainsKey(algorithm))
            return false;

        // Check if tenant allows this algorithm
        var tenantAlgorithm = GetTenantPrimaryAlgorithm(tenantId);

        // Tenant can only use their configured algorithm
        return algorithm.StartsWith(tenantAlgorithm);
    }
}
```

### Rate Limiting

```csharp
public class CertificateRateLimitPolicy
{
    // Per user limits
    public int MaxCertificatesPerUserPerDay { get; set; } = 5;
    public int MaxCertificatesPerUserPerHour { get; set; } = 2;

    // Per device limits
    public int MaxCertificatesPerDevicePerDay { get; set; } = 3;

    // Per tenant limits
    public int MaxCertificatesPerTenantPerDay { get; set; } = 1000;
    public int MaxPendingCsrsPerTenant { get; set; } = 100;

    // Burst limits
    public int MaxCsrSubmissionsPerMinute { get; set; } = 10;
}
```

---

## HSM Integration

### Signing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HSM SIGNING FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│  Issuance    │          │     HSM      │          │   HSM        │
│  Service     │          │   Service    │          │  (Hardware)  │
└──────┬───────┘          └──────┬───────┘          └──────┬───────┘
       │                         │                         │
       │ 1. SignCertificate      │                         │
       │    (tbsCert, keyId,     │                         │
       │     algorithm)          │                         │
       │────────────────────────>│                         │
       │                         │                         │
       │                         │ 2. Retrieve key handle  │
       │                         │    by keyId             │
       │                         │────────────────────────>│
       │                         │                         │
       │                         │ 3. Key handle           │
       │                         │<────────────────────────│
       │                         │                         │
       │                         │ 4. Sign(tbsCert)        │
       │                         │────────────────────────>│
       │                         │                         │
       │                         │    [HSM performs        │
       │                         │     signing inside      │
       │                         │     secure boundary]    │
       │                         │                         │
       │                         │ 5. Signature            │
       │                         │<────────────────────────│
       │                         │                         │
       │ 6. Return signature     │                         │
       │<────────────────────────│                         │
       │                         │                         │
```

### HSM Key Reference

```csharp
public class CertificateSigningService : ICertificateSigningService
{
    private readonly IHsmService _hsmService;

    public async Task<byte[]> SignCertificateAsync(
        UnsignedCertificate cert,
        string caKeyId,
        CancellationToken ct = default)
    {
        // Get the TBS (To Be Signed) certificate bytes
        var tbsCertificate = cert.ToBeSigned;

        // Determine algorithm from CA key
        var keyInfo = await _hsmService.GetKeyInfoAsync(caKeyId, ct);
        var algorithm = keyInfo.Algorithm;

        // Sign using HSM
        var signature = await _hsmService.SignAsync(
            caKeyId,
            tbsCertificate,
            algorithm,
            ct
        );

        return signature;
    }
}
```

---

## Certificate Lifecycle

### State Machine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CERTIFICATE LIFECYCLE                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────┐
                              │   CSR       │
                              │  Submitted  │
                              └──────┬──────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
            ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
            │   Pending   │  │   Manual    │  │  Rejected   │
            │   Review    │  │   Review    │  │             │
            └──────┬──────┘  └──────┬──────┘  └─────────────┘
                   │                │
                   │   Approved     │ Approved
                   │                │
                   └────────┬───────┘
                            │
                            ▼
                    ┌─────────────┐
                    │   Issued    │──────────────────────────┐
                    │   (Active)  │                          │
                    └──────┬──────┘                          │
                           │                                 │
          ┌────────────────┼────────────────┐               │
          │                │                │               │
          ▼                ▼                ▼               ▼
  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
  │   Renewed   │  │   Revoked   │  │  Suspended  │  │   Expired   │
  │             │  │             │  │             │  │             │
  └─────────────┘  └─────────────┘  └──────┬──────┘  └─────────────┘
                                           │
                                           │ Reinstated
                                           ▼
                                   ┌─────────────┐
                                   │   Active    │
                                   └─────────────┘
```

### Status Definitions

| Status | Description | Can Authenticate? |
|--------|-------------|-------------------|
| `Pending` | CSR submitted, awaiting processing | No |
| `ManualReview` | Requires admin approval | No |
| `Rejected` | CSR rejected | No |
| `Active` | Valid certificate | Yes |
| `Suspended` | Temporarily disabled | No |
| `Revoked` | Permanently revoked | No |
| `Expired` | Past validity period | No |
| `Renewed` | Replaced by new certificate | No |

---

## Revocation Management

### Revocation Reasons

```csharp
public enum RevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,        // Suspension
    RemoveFromCrl = 8,          // Reinstate from hold
    PrivilegeWithdrawn = 9,
    AaCompromise = 10
}
```

### CRL Generation

```csharp
public class CrlGenerationService : ICrlGenerationService
{
    public async Task<byte[]> GenerateCrlAsync(
        Guid tenantId,
        CancellationToken ct = default)
    {
        // Get all revoked certificates for tenant
        var revokedCerts = await _certificateRepository
            .GetRevokedCertificatesAsync(tenantId, ct);

        // Get tenant CA info
        var tenantCa = await _tenantService.GetCaInfoAsync(tenantId, ct);

        // Build CRL
        var crl = new CrlBuilder()
            .WithIssuer(tenantCa.Subject)
            .WithThisUpdate(DateTime.UtcNow)
            .WithNextUpdate(DateTime.UtcNow.AddDays(7))
            .WithRevokedCertificates(revokedCerts.Select(c => new RevokedCertEntry
            {
                SerialNumber = c.SerialNumber,
                RevocationDate = c.RevokedAt!.Value,
                Reason = c.RevocationReason
            }))
            .Build();

        // Sign CRL with tenant CA key
        var signature = await _hsmService.SignAsync(
            tenantCa.KeyId,
            crl.ToBeSigned,
            tenantCa.Algorithm,
            ct
        );

        return crl.AttachSignature(signature);
    }
}
```

### OCSP Responder

```csharp
public class OcspResponderService : IOcspResponderService
{
    public async Task<OcspResponse> CheckStatusAsync(
        OcspRequest request,
        CancellationToken ct = default)
    {
        var responses = new List<SingleResponse>();

        foreach (var certId in request.CertificateIds)
        {
            var cert = await _certificateRepository
                .GetBySerialNumberAsync(certId.SerialNumber, ct);

            var status = cert switch
            {
                null => CertStatus.Unknown,
                { Status: CertificateStatus.Active } => CertStatus.Good,
                { Status: CertificateStatus.Revoked } =>
                    CertStatus.Revoked(cert.RevokedAt!.Value, cert.RevocationReason),
                { Status: CertificateStatus.Expired } => CertStatus.Good, // Still report, let client check validity
                _ => CertStatus.Unknown
            };

            responses.Add(new SingleResponse
            {
                CertId = certId,
                CertStatus = status,
                ThisUpdate = DateTime.UtcNow,
                NextUpdate = DateTime.UtcNow.AddHours(1)
            });
        }

        return new OcspResponse
        {
            Status = OcspResponseStatus.Successful,
            Responses = responses
        };
    }
}
```

---

## Data Models

### Database Entities

```csharp
public class CertificateSigningRequest
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid? UserId { get; set; }
    public Guid? DeviceId { get; set; }

    public CertificateType Type { get; set; }
    public CsrStatus Status { get; set; }

    public byte[] CsrData { get; set; } = [];      // DER encoded CSR
    public string SubjectDn { get; set; } = "";
    public string Algorithm { get; set; } = "";
    public byte[] PublicKeyHash { get; set; } = []; // SHA-256 of public key

    public DateTime SubmittedAt { get; set; }
    public DateTime? ProcessedAt { get; set; }
    public string? RejectionReason { get; set; }

    public Guid? IssuedCertificateId { get; set; }
    public string? TrackingId { get; set; }        // RTID for polling
}

public class Certificate
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid? UserId { get; set; }
    public Guid? DeviceId { get; set; }

    public CertificateType Type { get; set; }
    public CertificateStatus Status { get; set; }

    public string SerialNumber { get; set; } = "";  // Hex encoded
    public string SubjectDn { get; set; } = "";
    public string IssuerDn { get; set; } = "";
    public string Algorithm { get; set; } = "";

    public byte[] CertificateData { get; set; } = []; // DER encoded cert
    public string Thumbprint { get; set; } = "";      // SHA-256 of cert
    public byte[] PublicKeyHash { get; set; } = [];

    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public DateTime IssuedAt { get; set; }

    public DateTime? RevokedAt { get; set; }
    public RevocationReason? RevocationReason { get; set; }
    public string? RevocationComment { get; set; }

    public Guid? ReplacedByCertificateId { get; set; }
}

public class TenantCertificateAuthority
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    public string SubjectDn { get; set; } = "";
    public string HsmKeyId { get; set; } = "";     // Reference to HSM
    public string Algorithm { get; set; } = "";

    public byte[] CertificateData { get; set; } = [];
    public string SerialNumber { get; set; } = "";

    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public DateTime CreatedAt { get; set; }

    public bool IsActive { get; set; }
    public Guid? PreviousCaId { get; set; }        // For CA rotation
}

public enum CsrStatus
{
    Pending,
    ManualReview,
    Approved,
    Rejected,
    Issued
}

public enum CertificateStatus
{
    Active,
    Suspended,
    Revoked,
    Expired,
    Renewed
}

public enum CertificateType
{
    User,
    Device,
    TenantCA
}
```

---

## API Endpoints

### CSR Submission

```http
POST /api/v1/certificates/csr
Authorization: Bearer {device_token}
Content-Type: application/json

{
  "device_csr": "base64-encoded-der",
  "user_csr": "base64-encoded-der",
  "request_signature": "base64-signature"
}

Response 202 Accepted:
{
  "tracking_id": "rtid-abc123",
  "status": "pending",
  "poll_url": "/api/v1/certificates/status/rtid-abc123",
  "estimated_completion": "2025-12-01T12:05:00Z"
}
```

### Certificate Status

```http
GET /api/v1/certificates/status/{tracking_id}
Authorization: Bearer {device_token}

Response 200 OK (Pending):
{
  "tracking_id": "rtid-abc123",
  "status": "pending",
  "position_in_queue": 5
}

Response 200 OK (Issued):
{
  "tracking_id": "rtid-abc123",
  "status": "issued",
  "certificates": {
    "device": "base64-encoded-der",
    "user": "base64-encoded-der",
    "chain": ["base64-tenant-ca", "base64-root-ca"]
  },
  "recovery_token": "encrypted-recovery-token"
}
```

### Certificate Revocation

```http
POST /api/v1/certificates/{serial_number}/revoke
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "reason": "key_compromise",
  "comment": "Device reported lost"
}

Response 200 OK:
{
  "serial_number": "01AB23CD",
  "status": "revoked",
  "revoked_at": "2025-12-01T12:00:00Z"
}
```

### CRL Download

```http
GET /api/v1/certificates/crl/{tenant_slug}
Accept: application/pkix-crl

Response 200 OK:
Content-Type: application/pkix-crl
(Binary CRL data)
```

### OCSP

```http
POST /api/v1/certificates/ocsp
Content-Type: application/ocsp-request

(Binary OCSP request)

Response 200 OK:
Content-Type: application/ocsp-response
(Binary OCSP response)
```

---

## Implementation Checklist

### Phase 1: Core Infrastructure

- [ ] **Database Setup**
  - [ ] Create `CertificateSigningRequests` table
  - [ ] Create `Certificates` table
  - [ ] Create `TenantCertificateAuthorities` table
  - [ ] Add indexes for serial number, thumbprint, status

- [ ] **CSR Processing**
  - [ ] Implement CSR parser (DER/PEM)
  - [ ] Implement CSR signature verification
  - [ ] Create `ICsrValidationService`
  - [ ] Add Subject DN validation
  - [ ] Add algorithm validation

- [ ] **Certificate Builder**
  - [ ] Create `CertificateBuilder` class
  - [ ] Implement extension builders
  - [ ] Add serial number generation
  - [ ] Implement TBS certificate encoding

### Phase 2: HSM Integration

- [ ] **HSM Service**
  - [ ] Implement `IHsmService` for certificate signing
  - [ ] Add Tenant CA key management
  - [ ] Implement key rotation support

- [ ] **Certificate Signing**
  - [ ] Create `ICertificateSigningService`
  - [ ] Integrate with HSM for signing
  - [ ] Add signature verification

### Phase 3: Lifecycle Management

- [ ] **Revocation**
  - [ ] Implement revocation API
  - [ ] Create CRL generation service
  - [ ] Implement OCSP responder
  - [ ] Add revocation reason handling

- [ ] **Renewal**
  - [ ] Implement certificate renewal flow
  - [ ] Add expiry notification service
  - [ ] Link renewed certificates

### Phase 4: API Layer

- [ ] **Endpoints**
  - [ ] CSR submission endpoint
  - [ ] Status polling endpoint
  - [ ] Certificate download endpoint
  - [ ] Revocation endpoint
  - [ ] CRL download endpoint
  - [ ] OCSP endpoint

- [ ] **Security**
  - [ ] Add request signing verification
  - [ ] Implement rate limiting
  - [ ] Add audit logging

### Phase 5: Tenant CA Management

- [ ] **CA Provisioning**
  - [ ] Create Tenant CA during tenant onboarding
  - [ ] Generate CA key in HSM
  - [ ] Sign CA certificate with Root CA
  - [ ] Store CA certificate

- [ ] **CA Rotation**
  - [ ] Plan CA rotation process
  - [ ] Implement key rollover
  - [ ] Update certificate chains

---

## References

- [RFC 5280 - X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - OCSP](https://tools.ietf.org/html/rfc6960)
- [RFC 2986 - PKCS #10 CSR Syntax](https://tools.ietf.org/html/rfc2986)
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Client registration flow
- [HSM Integration](./ARCHITECTURE.md#hsm-integration) - HSM service details
