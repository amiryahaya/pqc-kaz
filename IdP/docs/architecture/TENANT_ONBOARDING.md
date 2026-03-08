# Tenant Onboarding Flow

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Tenant Lifecycle](#tenant-lifecycle)
3. [Onboarding Process](#onboarding-process)
4. [Organization Setup](#organization-setup)
5. [CA Provisioning](#ca-provisioning)
6. [Admin User Setup](#admin-user-setup)
7. [Configuration Options](#configuration-options)
8. [Branding & Customization](#branding--customization)
9. [Integration Setup](#integration-setup)
10. [User Provisioning](#user-provisioning)
11. [Compliance & Policies](#compliance--policies)
12. [Data Structures](#data-structures)
13. [API Reference](#api-reference)
14. [Admin Portal](#admin-portal)
15. [Security Considerations](#security-considerations)
16. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

Tenant Onboarding is the process of setting up a new organization on the Digital ID Platform. This includes:

- **Organization registration** - Company details, billing, contracts
- **CA provisioning** - Tenant-specific certificate authority setup
- **Admin setup** - Initial administrator account creation
- **Policy configuration** - Security, device, and certificate policies
- **Branding** - Custom logos, colors, app names
- **Integration** - OIDC clients, SCIM provisioning, webhooks

### Multi-Tenancy Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MULTI-TENANCY ARCHITECTURE                            │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │    Root CA      │
                              │  (Platform-wide)│
                              └────────┬────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
     │   Tenant A CA   │     │   Tenant B CA   │     │   Tenant C CA   │
     │  (Acme Corp)    │     │ (Global Bank)   │     │  (HealthCo)     │
     └────────┬────────┘     └────────┬────────┘     └────────┬────────┘
              │                        │                        │
     ┌────────┴────────┐      ┌───────┴───────┐       ┌───────┴───────┐
     │                 │      │               │       │               │
     ▼                 ▼      ▼               ▼       ▼               ▼
┌─────────┐      ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│User Cert│      │Dev Cert │ │User Cert│ │Dev Cert │ │User Cert│ │Dev Cert │
└─────────┘      └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘

Each Tenant Has:
• Dedicated CA certificate (signed by Root CA)
• Isolated database schema
• Custom branding
• Independent policies
• Separate audit logs
```

### Tenant Types

| Type | Description | Features |
|------|-------------|----------|
| **Standard** | Regular organization | Basic features, shared infrastructure |
| **Enterprise** | Large organization | Advanced features, dedicated support |
| **Regulated** | Financial/Healthcare | Compliance features, audit trails |
| **Government** | Government agencies | Air-gapped option, highest security |

---

## Tenant Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TENANT LIFECYCLE                                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Prospect    │────>│   Trial       │────>│   Active      │
│               │     │  (30 days)    │     │               │
└───────────────┘     └───────────────┘     └───────┬───────┘
                                                    │
                                           ┌────────┴────────┐
                                           │                 │
                                           ▼                 ▼
                                    ┌───────────────┐ ┌───────────────┐
                                    │   Suspended   │ │   Churned     │
                                    │ (non-payment) │ │ (cancelled)   │
                                    └───────┬───────┘ └───────────────┘
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │   Archived    │
                                    │ (data retained│
                                    │  per policy)  │
                                    └───────────────┘

States:
- Prospect: Initial inquiry, contract negotiation
- Trial: Limited functionality, evaluation period
- Active: Full functionality, production use
- Suspended: Billing issues, temporary block
- Churned: Customer cancelled, offboarding
- Archived: Data retained for compliance
```

---

## Onboarding Process

### High-Level Onboarding Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TENANT ONBOARDING FLOW                                    │
└─────────────────────────────────────────────────────────────────────────────┘

    Sales/Contract              Platform Admin              Tenant Admin
         │                           │                           │
         │  1. Contract signed       │                           │
         │──────────────────────────>│                           │
         │                           │                           │
         │                           │  2. Create tenant         │
         │                           │     record                │
         │                           │                           │
         │                           │  3. Provision             │
         │                           │     infrastructure        │
         │                           │     - Database schema     │
         │                           │     - Storage bucket      │
         │                           │     - Redis namespace     │
         │                           │                           │
         │                           │  4. Generate Tenant       │
         │                           │     CA certificate        │
         │                           │     (HSM)                 │
         │                           │                           │
         │                           │  5. Create admin          │
         │                           │     invitation            │
         │                           │                           │
         │                           │  6. Send invitation       │
         │                           │     email                 │
         │                           │──────────────────────────>│
         │                           │                           │
         │                           │  7. Admin accepts         │
         │                           │     invitation            │
         │                           │<──────────────────────────│
         │                           │                           │
         │                           │                           │  8. Complete
         │                           │                           │     setup wizard
         │                           │                           │     - Profile
         │                           │                           │     - Branding
         │                           │                           │     - Policies
         │                           │                           │
         │                           │  9. Tenant active         │
         │                           │<──────────────────────────│
         │                           │                           │
```

### Detailed Onboarding Steps

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: CONTRACT & PROVISIONING                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Contract signed                                                           │
│  □ Billing configured                                                        │
│  □ Tenant tier selected (Standard/Enterprise/Regulated)                      │
│  □ PQC algorithm selected (KAZ-SIGN or ML-DSA)                               │
│  □ Data residency region selected                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: INFRASTRUCTURE SETUP                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Database schema created (identity.{tenant_id})                            │
│  □ Redis namespace allocated                                                 │
│  □ Blob storage container created                                            │
│  □ HSM partition configured                                                  │
│  □ DNS entries created (if custom domain)                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: CA PROVISIONING                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Tenant CA keypair generated in HSM                                        │
│  □ Tenant CA certificate signed by Root CA                                   │
│  □ CA certificate published to trust store                                   │
│  □ CRL distribution point configured                                         │
│  □ OCSP responder configured                                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: ADMIN SETUP                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Initial admin invitation sent                                             │
│  □ Admin completes registration                                              │
│  □ Admin Digital ID issued                                                   │
│  □ Admin permissions assigned                                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: CONFIGURATION                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Organization profile completed                                            │
│  □ Branding assets uploaded                                                  │
│  □ Security policies configured                                              │
│  □ Device policies configured                                                │
│  □ Certificate policies configured                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 6: INTEGRATION                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ OIDC clients registered                                                   │
│  □ SCIM provisioning configured (if applicable)                              │
│  □ Webhooks configured                                                       │
│  □ API keys generated                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 7: GO LIVE                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  □ Test users provisioned                                                    │
│  □ Integration testing completed                                             │
│  □ User onboarding configured                                                │
│  □ Tenant status set to Active                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Organization Setup

### Create Tenant

```csharp
// Backend - TenantOnboardingService.cs
public class TenantOnboardingService : ITenantOnboardingService
{
    public async Task<Result<TenantCreationResult>> CreateTenantAsync(
        CreateTenantCommand cmd,
        CancellationToken ct = default)
    {
        // Step 1: Validate tenant doesn't already exist
        var existing = await _tenantRepository.GetByDomainAsync(cmd.PrimaryDomain, ct);
        if (existing != null)
            return Result.Failure<TenantCreationResult>("Domain already registered");

        // Step 2: Create tenant record
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(),
            Name = cmd.OrganizationName,
            Slug = GenerateSlug(cmd.OrganizationName),
            PrimaryDomain = cmd.PrimaryDomain,
            Type = cmd.TenantType,
            Status = TenantStatus.Provisioning,

            // Algorithm selection
            PrimaryAlgorithm = cmd.PqcAlgorithm,
            AllowedAlgorithms = new[] { cmd.PqcAlgorithm },

            // Data residency
            Region = cmd.Region,
            DataResidencyCountry = cmd.DataResidencyCountry,

            // Billing
            BillingEmail = cmd.BillingEmail,
            Tier = cmd.Tier,
            TrialEndsAt = cmd.IsTrial ? DateTime.UtcNow.AddDays(30) : null,

            // Timestamps
            CreatedAt = DateTime.UtcNow,
            CreatedBy = cmd.CreatedBy
        };

        await _tenantRepository.CreateAsync(tenant, ct);

        // Step 3: Provision infrastructure
        var infra = await ProvisionInfrastructureAsync(tenant, ct);

        // Step 4: Generate Tenant CA
        var caResult = await ProvisionTenantCaAsync(tenant, ct);

        // Step 5: Create admin invitation
        var invitation = await CreateAdminInvitationAsync(tenant, cmd.AdminEmail, ct);

        // Step 6: Update tenant status
        tenant.Status = TenantStatus.PendingAdminSetup;
        tenant.CaKeyId = caResult.KeyId;
        tenant.CaCertificateId = caResult.CertificateId;
        await _tenantRepository.UpdateAsync(tenant, ct);

        // Step 7: Send admin invitation email
        await _emailService.SendAdminInvitationAsync(
            cmd.AdminEmail,
            tenant.Name,
            invitation.Token,
            invitation.ExpiresAt,
            ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = tenant.Id,
            Action = AuditAction.TenantCreated,
            Severity = AuditSeverity.High,
            Details = new
            {
                TenantName = tenant.Name,
                Domain = tenant.PrimaryDomain,
                Algorithm = tenant.PrimaryAlgorithm,
                Tier = tenant.Tier,
                AdminEmail = cmd.AdminEmail
            }
        }, ct);

        return Result.Success(new TenantCreationResult
        {
            TenantId = tenant.Id,
            Slug = tenant.Slug,
            InvitationSent = true,
            InvitationExpiresAt = invitation.ExpiresAt
        });
    }
}
```

### Infrastructure Provisioning

```csharp
public class InfrastructureProvisioningService : IInfrastructureProvisioningService
{
    public async Task<InfrastructureResult> ProvisionInfrastructureAsync(
        Tenant tenant,
        CancellationToken ct = default)
    {
        var result = new InfrastructureResult();

        // 1. Database schema
        result.DatabaseSchema = await ProvisionDatabaseSchemaAsync(tenant, ct);

        // 2. Redis namespace
        result.RedisNamespace = await ProvisionRedisNamespaceAsync(tenant, ct);

        // 3. Blob storage
        result.StorageContainer = await ProvisionStorageAsync(tenant, ct);

        // 4. HSM partition (for tenant CA)
        result.HsmPartition = await ProvisionHsmPartitionAsync(tenant, ct);

        return result;
    }

    private async Task<string> ProvisionDatabaseSchemaAsync(
        Tenant tenant,
        CancellationToken ct)
    {
        var schemaName = $"tenant_{tenant.Slug}";

        // Create schema
        await _dbContext.Database.ExecuteSqlRawAsync(
            $"CREATE SCHEMA IF NOT EXISTS \"{schemaName}\"", ct);

        // Create tenant-specific tables
        await _dbContext.Database.ExecuteSqlRawAsync($@"
            -- Users table
            CREATE TABLE ""{schemaName}"".users (
                id UUID PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                display_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                -- ... other columns
            );

            -- Devices table
            CREATE TABLE ""{schemaName}"".devices (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES ""{schemaName}"".users(id),
                display_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                -- ... other columns
            );

            -- Certificates table
            CREATE TABLE ""{schemaName}"".certificates (
                id UUID PRIMARY KEY,
                serial_number VARCHAR(100) NOT NULL UNIQUE,
                type VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                -- ... other columns
            );

            -- Create indexes
            CREATE INDEX idx_users_email ON ""{schemaName}"".users(email);
            CREATE INDEX idx_devices_user_id ON ""{schemaName}"".devices(user_id);
            CREATE INDEX idx_certificates_serial ON ""{schemaName}"".certificates(serial_number);
        ", ct);

        return schemaName;
    }
}
```

---

## CA Provisioning

### Tenant CA Generation

```csharp
public class TenantCaProvisioningService : ITenantCaProvisioningService
{
    public async Task<TenantCaResult> ProvisionTenantCaAsync(
        Tenant tenant,
        CancellationToken ct = default)
    {
        // Step 1: Generate CA keypair in HSM
        var keyGenResult = await _hsmService.GenerateKeyPairAsync(
            new GenerateKeyPairRequest
            {
                Label = $"tenant-ca-{tenant.Slug}",
                Algorithm = tenant.PrimaryAlgorithm,
                KeyUsage = KeyUsage.CertificateSigning | KeyUsage.CrlSigning,
                Extractable = false
            }, ct);

        // Step 2: Create CA certificate CSR
        var caSubject = new X509DistinguishedName(
            $"CN={tenant.Name} CA, O={tenant.Name}, C={tenant.DataResidencyCountry}");

        // Step 3: Sign with Root CA
        var caCertificate = await _rootCaService.SignSubordinateCaAsync(
            new SignSubordinateCaRequest
            {
                Subject = caSubject,
                PublicKey = keyGenResult.PublicKey,
                ValidityYears = 5,
                PathLengthConstraint = 0,  // Cannot sign other CAs
                Algorithm = tenant.PrimaryAlgorithm,
                KeyUsages = new[]
                {
                    X509KeyUsage.DigitalSignature,
                    X509KeyUsage.KeyCertSign,
                    X509KeyUsage.CrlSign
                },
                ExtendedKeyUsages = new[]
                {
                    ExtendedKeyUsage.OcspSigning
                }
            }, ct);

        // Step 4: Store CA certificate
        var certRecord = new Certificate
        {
            Id = Guid.NewGuid(),
            TenantId = tenant.Id,
            Type = CertificateType.TenantCa,
            Status = CertificateStatus.Active,
            SerialNumber = caCertificate.SerialNumber,
            Subject = caSubject.Name,
            PublicKey = keyGenResult.PublicKey,
            PrivateKeyId = keyGenResult.KeyId,
            CertificateData = caCertificate.Encoded,
            NotBefore = caCertificate.NotBefore,
            NotAfter = caCertificate.NotAfter,
            Algorithm = tenant.PrimaryAlgorithm,
            IssuedBy = "Root CA",
            CreatedAt = DateTime.UtcNow
        };

        await _certRepository.CreateAsync(certRecord, ct);

        // Step 5: Configure CRL distribution
        await ConfigureCrlDistributionAsync(tenant, certRecord, ct);

        // Step 6: Configure OCSP
        await ConfigureOcspResponderAsync(tenant, certRecord, ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = tenant.Id,
            Action = AuditAction.TenantCaProvisioned,
            Severity = AuditSeverity.Critical,
            Details = new
            {
                CertificateId = certRecord.Id,
                SerialNumber = certRecord.SerialNumber,
                Algorithm = tenant.PrimaryAlgorithm,
                ValidUntil = certRecord.NotAfter
            }
        }, ct);

        return new TenantCaResult
        {
            KeyId = keyGenResult.KeyId,
            CertificateId = certRecord.Id,
            SerialNumber = certRecord.SerialNumber,
            CertificateData = caCertificate.Encoded
        };
    }
}
```

### CA Certificate Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TENANT CA CERTIFICATE                                     │
└─────────────────────────────────────────────────────────────────────────────┘

Certificate:
    Version: 3 (0x2)
    Serial Number: [unique-serial]
    Signature Algorithm: KAZ-SIGN-128 (or ML-DSA-65)
    Issuer: CN=IdP Root CA, O=IdP Platform
    Validity:
        Not Before: Dec  1 00:00:00 2025 UTC
        Not After:  Dec  1 00:00:00 2030 UTC
    Subject: CN=Acme Corp CA, O=Acme Corp, C=US
    Subject Public Key Info:
        Public Key Algorithm: KAZ-SIGN-128
        Public-Key: [public-key-bytes]
    X509v3 extensions:
        X509v3 Basic Constraints: critical
            CA:TRUE, pathlen:0
        X509v3 Key Usage: critical
            Digital Signature, Certificate Sign, CRL Sign
        X509v3 Extended Key Usage:
            OCSP Signing
        X509v3 Subject Key Identifier:
            [key-id]
        X509v3 Authority Key Identifier:
            keyid:[root-ca-key-id]
        X509v3 CRL Distribution Points:
            URI:https://crl.idp.example.com/tenant/{tenant-id}/crl.pem
        Authority Information Access:
            OCSP - URI:https://ocsp.idp.example.com/tenant/{tenant-id}
            CA Issuers - URI:https://ca.idp.example.com/root-ca.pem
```

---

## Admin User Setup

### Admin Invitation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADMIN INVITATION FLOW                                     │
└─────────────────────────────────────────────────────────────────────────────┘

Platform                     Email                        Admin User
    │                          │                              │
    │  1. Generate invitation  │                              │
    │     token                │                              │
    │                          │                              │
    │  2. Send invitation      │                              │
    │     email                │                              │
    │─────────────────────────>│                              │
    │                          │                              │
    │                          │  3. Email received           │
    │                          │  "You've been invited..."    │
    │                          │─────────────────────────────>│
    │                          │                              │
    │                          │  4. Click "Accept            │
    │                          │     Invitation"              │
    │                          │<─────────────────────────────│
    │                          │                              │
    │  5. Validate token       │                              │
    │<────────────────────────────────────────────────────────│
    │                          │                              │
    │  6. Show setup wizard    │                              │
    │─────────────────────────────────────────────────────────>
    │                          │                              │
    │                          │                              │  7. Complete
    │                          │                              │     - Profile info
    │                          │                              │     - Password setup
    │                          │                              │     - Install app
    │                          │                              │     - Register device
    │                          │                              │
    │  8. Admin registration   │                              │
    │     (Digital ID flow)    │                              │
    │<────────────────────────────────────────────────────────│
    │                          │                              │
    │  9. Assign admin role    │                              │
    │                          │                              │
    │  10. Welcome email       │                              │
    │─────────────────────────────────────────────────────────>
    │                          │                              │
```

### Admin Invitation Service

```csharp
public class AdminInvitationService : IAdminInvitationService
{
    public async Task<AdminInvitation> CreateAdminInvitationAsync(
        Tenant tenant,
        string adminEmail,
        CancellationToken ct = default)
    {
        // Generate secure invitation token
        var token = GenerateSecureToken(64);

        var invitation = new AdminInvitation
        {
            Id = Guid.NewGuid(),
            TenantId = tenant.Id,
            Email = adminEmail,
            Token = HashToken(token),
            Role = AdminRole.TenantAdmin,
            Status = InvitationStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        await _invitationRepository.CreateAsync(invitation, ct);

        // Return with unhashed token for email
        return invitation with { Token = token };
    }

    public async Task<Result> AcceptInvitationAsync(
        AcceptInvitationCommand cmd,
        CancellationToken ct = default)
    {
        // Validate token
        var invitation = await _invitationRepository.GetByTokenHashAsync(
            HashToken(cmd.Token), ct);

        if (invitation is null)
            return Result.Failure("Invalid invitation");

        if (invitation.Status != InvitationStatus.Pending)
            return Result.Failure("Invitation already used");

        if (invitation.ExpiresAt < DateTime.UtcNow)
            return Result.Failure("Invitation expired");

        // Update invitation
        invitation.Status = InvitationStatus.Accepted;
        invitation.AcceptedAt = DateTime.UtcNow;
        await _invitationRepository.UpdateAsync(invitation, ct);

        // Create admin context for registration
        var registrationContext = new AdminRegistrationContext
        {
            TenantId = invitation.TenantId,
            Email = invitation.Email,
            Role = invitation.Role,
            InvitationId = invitation.Id
        };

        await _cacheService.SetAsync(
            $"admin-reg:{cmd.SessionId}",
            registrationContext,
            TimeSpan.FromHours(1),
            ct);

        return Result.Success();
    }
}
```

### Admin Setup Wizard

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADMIN SETUP WIZARD                                        │
└─────────────────────────────────────────────────────────────────────────────┘

Step 1 of 5: Welcome
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     Welcome to Acme Corp Digital ID                                          │
│                                                                              │
│     You've been invited to set up your organization's                        │
│     Digital ID platform.                                                     │
│                                                                              │
│     This wizard will guide you through:                                      │
│     • Creating your admin account                                            │
│     • Setting up organization branding                                       │
│     • Configuring security policies                                          │
│     • Registering your first device                                          │
│                                                                              │
│                              [Get Started →]                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Step 2 of 5: Your Profile
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     Your Information                                                         │
│                                                                              │
│     Full Name:    [John Smith________________]                               │
│     Job Title:    [IT Director________________]                              │
│     Phone:        [+1 555 123 4567___________]                               │
│                                                                              │
│     Recovery Password                                                        │
│     (Write this down and keep it safe!)                                      │
│                                                                              │
│     Password:     [••••••••••••••••__________]                               │
│     Confirm:      [••••••••••••••••__________]                               │
│                                                                              │
│                    [← Back]           [Continue →]                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Step 3 of 5: Install Digital ID App
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     Install the Digital ID App                                               │
│                                                                              │
│     Scan this QR code with your phone to download                            │
│     the Digital ID app:                                                      │
│                                                                              │
│              ┌───────────────┐                                               │
│              │  [QR CODE]    │                                               │
│              │               │                                               │
│              └───────────────┘                                               │
│                                                                              │
│     Or download from:                                                        │
│     [App Store]    [Google Play]                                             │
│                                                                              │
│     After installing, tap "Continue" to register                             │
│     your device.                                                             │
│                                                                              │
│                    [← Back]           [Continue →]                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Step 4 of 5: Register Device
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     Register Your Device                                                     │
│                                                                              │
│     Scan this QR code with the Digital ID app:                               │
│                                                                              │
│              ┌───────────────┐                                               │
│              │  [QR CODE]    │                                               │
│              │   Registration│                                               │
│              └───────────────┘                                               │
│                                                                              │
│     Status: Waiting for registration...                                      │
│                                                                              │
│     This QR code will expire in: 4:32                                        │
│                                                                              │
│                    [← Back]           [Refresh QR]                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Step 5 of 5: Complete!
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     ✓ Setup Complete!                                                        │
│                                                                              │
│     Your Digital ID has been created and your                                │
│     device is registered.                                                    │
│                                                                              │
│     Next Steps:                                                              │
│     • Configure organization branding                                        │
│     • Set up security policies                                               │
│     • Add more administrators                                                │
│     • Invite users                                                           │
│                                                                              │
│                         [Go to Admin Portal →]                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Configuration Options

### Tenant Configuration

```csharp
public class TenantConfiguration
{
    public Guid TenantId { get; set; }

    // Organization
    public string OrganizationName { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public string[] AdditionalDomains { get; set; } = Array.Empty<string>();
    public string SupportEmail { get; set; } = "";
    public string SupportUrl { get; set; } = "";

    // Algorithm
    public string PrimaryAlgorithm { get; set; } = "KAZ-SIGN-128";
    public string[] AllowedAlgorithms { get; set; } = { "KAZ-SIGN-128" };

    // Features
    public TenantFeatures Features { get; set; } = new();

    // Branding
    public TenantBranding Branding { get; set; } = new();

    // Policies
    public SecurityPolicy SecurityPolicy { get; set; } = new();
    public DevicePolicy DevicePolicy { get; set; } = new();
    public CertificatePolicy CertificatePolicy { get; set; } = new();
    public UserPolicy UserPolicy { get; set; } = new();
}

public class TenantFeatures
{
    public bool QrCodeAuthentication { get; set; } = true;
    public bool DocumentSigning { get; set; } = true;
    public bool PhysicalAccessControl { get; set; } = false;
    public bool ScimProvisioning { get; set; } = false;
    public bool SamlSupport { get; set; } = false;
    public bool CustomBranding { get; set; } = true;
    public bool AuditLogExport { get; set; } = true;
    public bool ApiAccess { get; set; } = true;
}
```

### Security Policy

```csharp
public class SecurityPolicy
{
    // Authentication
    public bool RequireBiometric { get; set; } = true;
    public bool AllowPinFallback { get; set; } = false;
    public int SessionTimeoutMinutes { get; set; } = 60;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 30;

    // Device Security
    public bool RequireDeviceAttestation { get; set; } = true;
    public bool AllowJailbrokenDevices { get; set; } = false;
    public bool AllowEmulators { get; set; } = false;
    public string[] MinimumOsVersions { get; set; } = { "iOS:16.0", "Android:12" };

    // Network
    public bool AllowVpnAccess { get; set; } = true;
    public string[] AllowedIpRanges { get; set; } = Array.Empty<string>();
    public string[] BlockedCountries { get; set; } = Array.Empty<string>();

    // Recovery
    public bool AllowSelfServiceRecovery { get; set; } = true;
    public int RecoveryLockoutHours { get; set; } = 24;
}
```

---

## Branding & Customization

### Branding Configuration

```csharp
public class TenantBranding
{
    // Logos
    public string? LogoUrl { get; set; }
    public string? LogoDarkUrl { get; set; }
    public string? IconUrl { get; set; }
    public string? FaviconUrl { get; set; }

    // Colors
    public string PrimaryColor { get; set; } = "#0066CC";
    public string SecondaryColor { get; set; } = "#003366";
    public string AccentColor { get; set; } = "#FF6600";
    public string BackgroundColor { get; set; } = "#FFFFFF";
    public string TextColor { get; set; } = "#333333";

    // App Branding
    public string AppName { get; set; } = "Digital ID";
    public string AppTagline { get; set; } = "Your secure digital identity";

    // Email Branding
    public string EmailFromName { get; set; } = "";
    public string EmailFooterText { get; set; } = "";

    // Custom Domain
    public string? CustomDomain { get; set; }
    public bool CustomDomainVerified { get; set; }
}
```

### Branding Upload API

```csharp
[ApiController]
[Route("api/v1/admin/branding")]
[Authorize(Roles = "TenantAdmin")]
public class BrandingController : ControllerBase
{
    [HttpPost("logo")]
    public async Task<IActionResult> UploadLogo(IFormFile file)
    {
        // Validate file
        if (file.Length > 5 * 1024 * 1024)  // 5MB max
            return BadRequest("File too large");

        var allowedTypes = new[] { "image/png", "image/jpeg", "image/svg+xml" };
        if (!allowedTypes.Contains(file.ContentType))
            return BadRequest("Invalid file type");

        // Process and upload
        var tenantId = GetCurrentTenantId();
        var logoUrl = await _brandingService.UploadLogoAsync(
            tenantId, file.OpenReadStream(), file.ContentType);

        return Ok(new { logo_url = logoUrl });
    }

    [HttpPut("colors")]
    public async Task<IActionResult> UpdateColors([FromBody] BrandingColorsRequest request)
    {
        var tenantId = GetCurrentTenantId();

        await _brandingService.UpdateColorsAsync(tenantId, new TenantColors
        {
            Primary = request.PrimaryColor,
            Secondary = request.SecondaryColor,
            Accent = request.AccentColor
        });

        return Ok();
    }
}
```

---

## Integration Setup

### OIDC Client Registration

```csharp
public class OidcClientService : IOidcClientService
{
    public async Task<Result<OidcClient>> CreateClientAsync(
        CreateOidcClientCommand cmd,
        CancellationToken ct = default)
    {
        var tenantId = cmd.TenantId;

        // Validate redirect URIs
        foreach (var uri in cmd.RedirectUris)
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                return Result.Failure<OidcClient>($"Invalid redirect URI: {uri}");

            // Require HTTPS in production
            if (!_config.AllowHttpRedirectUris && parsed.Scheme != "https")
                return Result.Failure<OidcClient>("Redirect URIs must use HTTPS");
        }

        // Generate client credentials
        var clientId = GenerateClientId();
        var clientSecret = cmd.ClientType == ClientType.Confidential
            ? GenerateClientSecret()
            : null;

        var client = new OidcClient
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ClientId = clientId,
            ClientSecret = clientSecret != null ? HashSecret(clientSecret) : null,
            ClientName = cmd.ClientName,
            ClientType = cmd.ClientType,
            RedirectUris = cmd.RedirectUris,
            PostLogoutRedirectUris = cmd.PostLogoutRedirectUris ?? Array.Empty<string>(),
            AllowedScopes = cmd.AllowedScopes,
            AllowedGrantTypes = cmd.AllowedGrantTypes,
            RequirePkce = cmd.RequirePkce ?? true,
            RequireConsent = cmd.RequireConsent ?? false,
            AllowRememberConsent = cmd.AllowRememberConsent ?? true,
            AccessTokenLifetime = cmd.AccessTokenLifetime ?? 3600,
            RefreshTokenLifetime = cmd.RefreshTokenLifetime ?? 2592000,
            Status = ClientStatus.Active,
            CreatedAt = DateTime.UtcNow
        };

        await _clientRepository.CreateAsync(client, ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = tenantId,
            Action = AuditAction.OidcClientCreated,
            Details = new
            {
                ClientId = clientId,
                ClientName = client.ClientName,
                ClientType = client.ClientType
            }
        }, ct);

        // Return with unhashed secret (only time it's available)
        return Result.Success(client with { ClientSecret = clientSecret });
    }
}
```

### SCIM Provisioning Setup

```csharp
public class ScimConfiguration
{
    public Guid TenantId { get; set; }
    public bool Enabled { get; set; }

    // Endpoint
    public string ScimEndpoint { get; set; } = "";  // e.g., /scim/v2

    // Authentication
    public string BearerToken { get; set; } = "";
    public DateTime TokenExpiresAt { get; set; }

    // Sync settings
    public bool SyncUsers { get; set; } = true;
    public bool SyncGroups { get; set; } = true;
    public bool AutoProvisionDevices { get; set; } = false;

    // Attribute mapping
    public Dictionary<string, string> UserAttributeMapping { get; set; } = new()
    {
        ["userName"] = "email",
        ["displayName"] = "display_name",
        ["name.givenName"] = "first_name",
        ["name.familyName"] = "last_name",
        ["emails[primary].value"] = "email",
        ["active"] = "is_active"
    };
}
```

### Webhook Configuration

```csharp
public class WebhookConfiguration
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public string Secret { get; set; } = "";  // For HMAC signature

    public WebhookEvent[] Events { get; set; } = Array.Empty<WebhookEvent>();

    public bool Enabled { get; set; } = true;
    public int RetryCount { get; set; } = 3;
    public int TimeoutSeconds { get; set; } = 30;
}

public enum WebhookEvent
{
    // User events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserSuspended,

    // Device events
    DeviceRegistered,
    DeviceRemoved,
    DeviceReportedLost,

    // Certificate events
    CertificateIssued,
    CertificateRenewed,
    CertificateRevoked,

    // Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,

    // Admin events
    AdminAdded,
    AdminRemoved,
    PolicyChanged
}
```

---

## User Provisioning

### User Invitation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    USER PROVISIONING OPTIONS                                 │
└─────────────────────────────────────────────────────────────────────────────┘

Option 1: Email Invitation
──────────────────────────
Admin Portal → Invite User → Email sent → User registers

Option 2: SCIM Provisioning
───────────────────────────
HR System → SCIM API → User created → Invitation email sent

Option 3: Self-Service (if enabled)
───────────────────────────────────
User → Company domain email → Verify domain → Register

Option 4: Bulk Import
─────────────────────
Admin → Upload CSV → Validate → Send invitations
```

### User Provisioning Service

```csharp
public class UserProvisioningService : IUserProvisioningService
{
    public async Task<Result<UserInvitation>> InviteUserAsync(
        InviteUserCommand cmd,
        CancellationToken ct = default)
    {
        var tenant = await _tenantRepository.GetAsync(cmd.TenantId, ct);

        // Check user limits
        var currentUserCount = await _userRepository.GetCountAsync(cmd.TenantId, ct);
        if (currentUserCount >= tenant!.MaxUsers)
            return Result.Failure<UserInvitation>("User limit reached");

        // Validate email domain
        var emailDomain = cmd.Email.Split('@')[1];
        if (!tenant.AllowedEmailDomains.Contains(emailDomain) &&
            !tenant.AllowedEmailDomains.Contains("*"))
        {
            return Result.Failure<UserInvitation>("Email domain not allowed");
        }

        // Check if user already exists
        var existingUser = await _userRepository.GetByEmailAsync(cmd.TenantId, cmd.Email, ct);
        if (existingUser != null)
            return Result.Failure<UserInvitation>("User already exists");

        // Create invitation
        var token = GenerateSecureToken(64);
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            TenantId = cmd.TenantId,
            Email = cmd.Email,
            DisplayName = cmd.DisplayName,
            Token = HashToken(token),
            Role = cmd.Role ?? UserRole.User,
            Department = cmd.Department,
            Groups = cmd.Groups ?? Array.Empty<Guid>(),
            Status = InvitationStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            InvitedBy = cmd.InvitedBy
        };

        await _invitationRepository.CreateAsync(invitation, ct);

        // Send invitation email
        await _emailService.SendUserInvitationAsync(
            cmd.Email,
            tenant.Name,
            token,
            invitation.ExpiresAt,
            tenant.Branding,
            ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = cmd.TenantId,
            Action = AuditAction.UserInvited,
            Details = new
            {
                Email = cmd.Email,
                InvitedBy = cmd.InvitedBy
            }
        }, ct);

        return Result.Success(invitation with { Token = token });
    }

    public async Task<Result<BulkImportResult>> BulkImportUsersAsync(
        BulkImportCommand cmd,
        CancellationToken ct = default)
    {
        var results = new BulkImportResult();

        foreach (var user in cmd.Users)
        {
            try
            {
                var result = await InviteUserAsync(new InviteUserCommand
                {
                    TenantId = cmd.TenantId,
                    Email = user.Email,
                    DisplayName = user.DisplayName,
                    Department = user.Department,
                    Role = user.Role,
                    InvitedBy = cmd.ImportedBy
                }, ct);

                if (result.IsSuccess)
                    results.Successful.Add(user.Email);
                else
                    results.Failed.Add((user.Email, result.Error));
            }
            catch (Exception ex)
            {
                results.Failed.Add((user.Email, ex.Message));
            }
        }

        return Result.Success(results);
    }
}
```

---

## Compliance & Policies

### Compliance Settings

```csharp
public class TenantComplianceSettings
{
    public Guid TenantId { get; set; }

    // Data Retention
    public int AuditLogRetentionDays { get; set; } = 365;
    public int SessionLogRetentionDays { get; set; } = 90;
    public int RevokedCertRetentionDays { get; set; } = 365 * 7;  // 7 years

    // Privacy
    public bool GdprEnabled { get; set; } = true;
    public bool DataExportEnabled { get; set; } = true;
    public bool DataDeletionEnabled { get; set; } = true;
    public int DataDeletionDelayDays { get; set; } = 30;

    // Compliance Frameworks
    public string[] ComplianceFrameworks { get; set; } = Array.Empty<string>();
    // e.g., ["SOC2", "ISO27001", "HIPAA", "FedRAMP"]

    // Audit
    public bool DetailedAuditLogging { get; set; } = true;
    public bool AuditLogExportEnabled { get; set; } = true;
    public string[] AuditLogExportFormats { get; set; } = { "JSON", "CSV" };

    // Notifications
    public bool ComplianceAlertEnabled { get; set; } = true;
    public string[] ComplianceAlertRecipients { get; set; } = Array.Empty<string>();
}
```

---

## Data Structures

### Tenant Entity

```csharp
public class Tenant
{
    public Guid Id { get; set; }

    // Basic Info
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public string[] AdditionalDomains { get; set; } = Array.Empty<string>();

    // Status
    public TenantStatus Status { get; set; }
    public TenantType Type { get; set; }
    public TenantTier Tier { get; set; }

    // Algorithm
    public string PrimaryAlgorithm { get; set; } = "";
    public string[] AllowedAlgorithms { get; set; } = Array.Empty<string>();

    // CA
    public string? CaKeyId { get; set; }
    public Guid? CaCertificateId { get; set; }

    // Limits
    public int MaxUsers { get; set; } = 100;
    public int MaxDevicesPerUser { get; set; } = 5;
    public int MaxOidcClients { get; set; } = 10;

    // Data Residency
    public string Region { get; set; } = "";
    public string DataResidencyCountry { get; set; } = "";

    // Billing
    public string? BillingEmail { get; set; }
    public string? BillingId { get; set; }
    public DateTime? TrialEndsAt { get; set; }

    // Timestamps
    public DateTime CreatedAt { get; set; }
    public string CreatedBy { get; set; } = "";
    public DateTime? ActivatedAt { get; set; }
    public DateTime? SuspendedAt { get; set; }
    public string? SuspendedReason { get; set; }

    // Navigation
    public TenantConfiguration? Configuration { get; set; }
    public TenantBranding? Branding { get; set; }
}

public enum TenantStatus
{
    Provisioning,
    PendingAdminSetup,
    Trial,
    Active,
    Suspended,
    Cancelled,
    Archived
}

public enum TenantTier
{
    Free,
    Starter,
    Professional,
    Enterprise,
    Government
}
```

---

## API Reference

### Create Tenant (Platform Admin)

```http
POST /api/v1/platform/tenants
Authorization: Bearer <platform-admin-token>
Content-Type: application/json

{
  "organization_name": "Acme Corporation",
  "primary_domain": "acme.com",
  "pqc_algorithm": "KAZ-SIGN-128",
  "tier": "enterprise",
  "region": "us-west-2",
  "data_residency_country": "US",
  "admin_email": "admin@acme.com",
  "billing_email": "billing@acme.com",
  "is_trial": false
}

Response 201 Created:
{
  "tenant_id": "uuid",
  "slug": "acme-corporation",
  "status": "pending_admin_setup",
  "invitation_sent": true,
  "invitation_expires_at": "2025-12-08T12:00:00Z"
}
```

### Get Tenant Status

```http
GET /api/v1/admin/tenant
Authorization: Bearer <tenant-admin-token>

Response 200 OK:
{
  "id": "uuid",
  "name": "Acme Corporation",
  "slug": "acme-corporation",
  "status": "active",
  "tier": "enterprise",
  "primary_algorithm": "KAZ-SIGN-128",
  "ca_certificate_serial": "1234567890",
  "stats": {
    "total_users": 150,
    "active_users": 142,
    "total_devices": 280,
    "oidc_clients": 5
  },
  "limits": {
    "max_users": 500,
    "max_devices_per_user": 5,
    "max_oidc_clients": 20
  }
}
```

### Update Tenant Configuration

```http
PATCH /api/v1/admin/tenant/configuration
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

{
  "features": {
    "qr_code_authentication": true,
    "document_signing": true
  },
  "security_policy": {
    "require_biometric": true,
    "session_timeout_minutes": 60
  }
}

Response 200 OK:
{
  "updated": true
}
```

### Create OIDC Client

```http
POST /api/v1/admin/oidc-clients
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

{
  "client_name": "Acme Portal",
  "client_type": "confidential",
  "redirect_uris": [
    "https://portal.acme.com/callback"
  ],
  "allowed_scopes": ["openid", "profile", "email"],
  "allowed_grant_types": ["authorization_code", "refresh_token"],
  "require_pkce": true
}

Response 201 Created:
{
  "client_id": "acme-portal-abc123",
  "client_secret": "secret-xyz789...",  // Only shown once!
  "client_name": "Acme Portal",
  "redirect_uris": ["https://portal.acme.com/callback"]
}
```

### Invite User

```http
POST /api/v1/admin/users/invite
Authorization: Bearer <tenant-admin-token>
Content-Type: application/json

{
  "email": "john.doe@acme.com",
  "display_name": "John Doe",
  "department": "Engineering",
  "role": "user"
}

Response 201 Created:
{
  "invitation_id": "uuid",
  "email": "john.doe@acme.com",
  "expires_at": "2025-12-08T12:00:00Z"
}
```

---

## Admin Portal

### Tenant Dashboard

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ADMIN PORTAL - ACME CORPORATION                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  OVERVIEW                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    150      │  │    280      │  │     5       │  │    99.9%    │         │
│  │   Users     │  │  Devices    │  │   Apps      │  │   Uptime    │         │
│  │  (+12 MTD)  │  │  (+24 MTD)  │  │             │  │             │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                                              │
│  QUICK ACTIONS                                                               │
│  [+ Invite User]  [+ Add App]  [View Audit Log]  [Download Report]          │
│                                                                              │
│  RECENT ACTIVITY                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 12:00  John Doe registered new device (iPhone 15 Pro)                   ││
│  │ 11:45  Jane Smith authenticated to Acme Portal                          ││
│  │ 11:30  New user invitation sent to bob@acme.com                         ││
│  │ 11:00  Certificate renewed for Device #123                              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  SECURITY ALERTS                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ ⚠️  3 devices inactive for 30+ days                                     ││
│  │ ⚠️  5 certificates expiring in 30 days                                  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### Tenant Isolation

| Layer | Isolation Method |
|-------|------------------|
| Database | Separate schema per tenant |
| Storage | Separate container/prefix per tenant |
| HSM | Separate key partition per tenant |
| Cache | Namespaced keys per tenant |
| Logs | Tenant ID in all log entries |

### Access Control

```csharp
public class TenantAccessPolicy
{
    // Platform admins can access all tenants (for support)
    public bool PlatformAdminFullAccess { get; set; } = true;

    // Tenant admins can only access their tenant
    public bool TenantAdminScopedAccess { get; set; } = true;

    // Cross-tenant data access (should always be false)
    public bool AllowCrossTenantAccess { get; set; } = false;

    // Audit all admin actions
    public bool AuditAllAdminActions { get; set; } = true;
}
```

### Audit Events

| Event | Severity | Data Logged |
|-------|----------|-------------|
| Tenant created | Critical | All tenant details |
| CA provisioned | Critical | Certificate details |
| Admin invited | High | Email, role |
| Policy changed | High | Old/new values |
| OIDC client created | Medium | Client details |
| User invited | Low | Email, inviter |
| Branding updated | Low | Changed fields |

---

## Implementation Checklist

### Phase 1: Core Onboarding

- [ ] **Tenant Entity**
  - [ ] Database schema
  - [ ] CRUD operations
  - [ ] Status management

- [ ] **Infrastructure Provisioning**
  - [ ] Database schema creation
  - [ ] Redis namespace
  - [ ] Storage container

### Phase 2: CA & Admin

- [ ] **CA Provisioning**
  - [ ] HSM key generation
  - [ ] CA certificate issuance
  - [ ] CRL/OCSP configuration

- [ ] **Admin Setup**
  - [ ] Invitation flow
  - [ ] Setup wizard
  - [ ] Role assignment

### Phase 3: Configuration

- [ ] **Tenant Configuration**
  - [ ] Feature toggles
  - [ ] Policy management
  - [ ] Branding upload

- [ ] **Integration Setup**
  - [ ] OIDC client management
  - [ ] SCIM configuration
  - [ ] Webhook setup

### Phase 4: User Management

- [ ] **User Provisioning**
  - [ ] Invitation flow
  - [ ] Bulk import
  - [ ] SCIM sync

- [ ] **Admin Portal**
  - [ ] Dashboard
  - [ ] User management
  - [ ] Audit logs

---

## References

- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - User registration
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Certificate management
- [AUTHENTICATION_FLOW.md](./AUTHENTICATION_FLOW.md) - OIDC authentication
