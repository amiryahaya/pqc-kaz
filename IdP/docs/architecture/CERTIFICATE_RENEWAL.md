# Certificate Renewal Flow

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Certificate Lifecycle](#certificate-lifecycle)
3. [Renewal Triggers](#renewal-triggers)
4. [Automatic Renewal Flow](#automatic-renewal-flow)
5. [Manual Renewal Flow](#manual-renewal-flow)
6. [Key Rotation](#key-rotation)
7. [CA Certificate Renewal](#ca-certificate-renewal)
8. [Grace Periods & Expiration](#grace-periods--expiration)
9. [Renewal Policies](#renewal-policies)
10. [Data Structures](#data-structures)
11. [API Reference](#api-reference)
12. [Mobile App Implementation](#mobile-app-implementation)
13. [Background Processing](#background-processing)
14. [Security Considerations](#security-considerations)
15. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

Certificate Renewal ensures continuous operation of user and device certificates without service interruption. This document covers:

- **User Certificate Renewal** - Identity certificates for users
- **Device Certificate Renewal** - Device-bound certificates
- **Key Rotation** - Periodic private key replacement
- **CA Certificate Renewal** - Tenant and root CA lifecycle

### Certificate Types & Validity

| Certificate Type | Default Validity | Renewal Window | Key Rotation |
|-----------------|------------------|----------------|--------------|
| User Certificate | 1 year | 30 days before expiry | Every 2 years |
| Device Certificate | 1 year | 30 days before expiry | Every 2 years |
| Tenant CA | 5 years | 6 months before expiry | Every 5 years |
| Root CA | 20 years | 2 years before expiry | Every 20 years |

### Key Principles

1. **Seamless Renewal** - No user action required for automatic renewal
2. **No Downtime** - Overlapping validity ensures continuous operation
3. **Key Continuity** - Same keys by default, rotation when required
4. **Backward Compatibility** - Old certificates valid during transition
5. **Audit Trail** - All renewal activities logged

---

## Certificate Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CERTIFICATE LIFECYCLE                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────┐
                    │   Issued    │
                    └──────┬──────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                           ACTIVE PERIOD                                       │
│                                                                               │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                          │ │
│  │   Normal Operation          │    Renewal Window    │   Grace Period    │ │
│  │   (335 days)                │    (30 days)         │   (7 days)        │ │
│  │                             │                      │                    │ │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│                                                                               │
│  Issue Date                    Renewal Start          Expiry    Grace End   │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │                        │
              ▼                        ▼
      ┌─────────────┐          ┌─────────────┐
      │   Renewed   │          │   Expired   │
      │  (New Cert) │          │             │
      └─────────────┘          └──────┬──────┘
                                      │
                                      ▼
                               ┌─────────────┐
                               │   Revoked   │
                               │  (by expiry)│
                               └─────────────┘
```

### Timeline Example

```
User Certificate (1 year validity):
────────────────────────────────────────────────────────────────────────────────

Jan 1, 2025                        Dec 1, 2025    Dec 31, 2025  Jan 7, 2026
     │                                  │              │             │
     │◄──── Normal Operation ──────────►│◄─ Renewal ──►│◄─ Grace ───►│
     │           (335 days)             │   (30 days)  │   (7 days)  │
     │                                  │              │             │
  Issued                           Renewal          Expiry      Grace End
                                   Starts                       (Revoked)
```

---

## Renewal Triggers

### Trigger 1: Time-Based (Automatic)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TIME-BASED RENEWAL TRIGGER                                │
└─────────────────────────────────────────────────────────────────────────────┘

Backend Scheduler (Daily)
        │
        ▼
┌───────────────────────────────────┐
│ Query certificates where:         │
│ • Status = Active                 │
│ • ExpiresAt <= Now + RenewalWindow│
│ • AutoRenewal = Enabled           │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ For each certificate:             │
│ 1. Check renewal eligibility      │
│ 2. Create renewal request         │
│ 3. Notify device (push)           │
│ 4. Schedule background renewal    │
└───────────────────────────────────┘
```

### Trigger 2: App Launch Check

```swift
// iOS - CertificateManager.swift
class CertificateManager {

    func checkCertificateStatusOnLaunch() async {
        let certificates = try await loadStoredCertificates()

        for cert in certificates {
            let status = evaluateCertificateStatus(cert)

            switch status {
            case .valid:
                continue

            case .renewalWindowOpen:
                // Schedule background renewal
                scheduleBackgroundRenewal(cert)

            case .expiringSoon:
                // Show warning to user
                showExpirationWarning(cert, daysRemaining: status.daysRemaining)
                // Trigger immediate renewal
                await triggerRenewal(cert)

            case .expired:
                // Show expired alert
                showExpiredAlert(cert)
                // Attempt grace period renewal
                await attemptGracePeriodRenewal(cert)

            case .revoked:
                // Certificate cannot be renewed
                showRevokedAlert(cert)
                // Require recovery flow
            }
        }
    }

    private func evaluateCertificateStatus(_ cert: Certificate) -> CertStatus {
        let now = Date()
        let expiresAt = cert.notAfter
        let renewalStart = expiresAt.addingTimeInterval(-30 * 24 * 3600) // 30 days
        let graceEnd = expiresAt.addingTimeInterval(7 * 24 * 3600) // 7 days

        if cert.isRevoked {
            return .revoked
        } else if now > graceEnd {
            return .expired
        } else if now > expiresAt {
            return .expiringSoon(daysRemaining: 0, inGracePeriod: true)
        } else if now > renewalStart {
            let days = Calendar.current.dateComponents([.day], from: now, to: expiresAt).day!
            return days <= 7 ? .expiringSoon(daysRemaining: days, inGracePeriod: false)
                            : .renewalWindowOpen
        } else {
            return .valid
        }
    }
}
```

### Trigger 3: Push Notification

```csharp
// Backend - CertificateRenewalNotifier.cs
public class CertificateRenewalNotifier : IHostedService
{
    public async Task NotifyUpcomingRenewalsAsync(CancellationToken ct)
    {
        // Get certificates entering renewal window today
        var certificates = await _certRepository.GetCertificatesEnteringRenewalWindowAsync(ct);

        foreach (var cert in certificates)
        {
            var device = await _deviceRepository.GetAsync(cert.DeviceId, ct);
            if (device?.PushToken is null) continue;

            await _pushService.SendToDeviceAsync(device.Id,
                new PushNotification
                {
                    Title = "Certificate Renewal",
                    Body = "Your Digital ID certificate will be renewed automatically",
                    Data = new
                    {
                        type = "certificate_renewal",
                        certificate_id = cert.Id,
                        expires_at = cert.ExpiresAt,
                        action = "background_renewal"
                    },
                    // Silent push for background processing
                    ContentAvailable = true,
                    MutableContent = true
                }, ct);
        }
    }
}
```

### Trigger 4: Policy-Driven

```csharp
public class CertificateRenewalPolicy
{
    public bool ForceRenewalOnKeyRotation { get; set; } = true;
    public bool ForceRenewalOnAlgorithmUpgrade { get; set; } = true;
    public bool ForceRenewalOnPolicyChange { get; set; } = false;

    public int RenewalWindowDays { get; set; } = 30;
    public int GracePeriodDays { get; set; } = 7;

    public TimeSpan MinRenewalInterval { get; set; } = TimeSpan.FromDays(1);
    public int MaxRenewalAttemptsPerDay { get; set; } = 3;
}
```

---

## Automatic Renewal Flow

### Sequence Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AUTOMATIC CERTIFICATE RENEWAL                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐          ┌──────────────┐          ┌──────────────┐
│  Mobile  │          │   Backend    │          │     HSM      │
│   App    │          │              │          │              │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  [App Launch or       │                         │
     │   Background Task]    │                         │
     │                       │                         │
     │  1. Check cert status │                         │
     │───────────────────────>                         │
     │                       │                         │
     │  2. Renewal needed    │                         │
     │     + renewal token   │                         │
     │<───────────────────────                         │
     │                       │                         │
     │  [Renewal required,   │                         │
     │   no user action]     │                         │
     │                       │                         │
     │  3. Create renewal CSR│                         │
     │     (same keypair)    │                         │
     │                       │                         │
     │  4. Submit renewal    │                         │
     │     request           │                         │
     │───────────────────────>                         │
     │                       │                         │
     │                       │  5. Verify renewal      │
     │                       │     eligibility         │
     │                       │                         │
     │                       │  6. Verify device       │
     │                       │     certificate (old)   │
     │                       │                         │
     │                       │  7. Sign new            │
     │                       │     certificate         │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  8. Signature           │
     │                       │<────────────────────────│
     │                       │                         │
     │                       │  9. Store new cert      │
     │                       │     (old still valid)   │
     │                       │                         │
     │  10. New certificate  │                         │
     │      + chain          │                         │
     │<───────────────────────                         │
     │                       │                         │
     │  11. Store new cert   │                         │
     │      in Keychain      │                         │
     │                       │                         │
     │  12. Confirm renewal  │                         │
     │      complete         │                         │
     │───────────────────────>                         │
     │                       │                         │
     │                       │  13. Mark old cert      │
     │                       │      as superseded      │
     │                       │                         │
```

### Backend: Renewal Service

```csharp
// Backend - CertificateRenewalService.cs
public class CertificateRenewalService : ICertificateRenewalService
{
    public async Task<Result<CertificateRenewalResult>> RenewCertificateAsync(
        RenewCertificateCommand cmd,
        CancellationToken ct = default)
    {
        // Step 1: Get existing certificate
        var existingCert = await _certRepository.GetAsync(cmd.CertificateId, ct);
        if (existingCert is null)
            return Result.Failure<CertificateRenewalResult>("Certificate not found");

        // Step 2: Validate renewal eligibility
        var eligibility = await ValidateRenewalEligibilityAsync(existingCert, ct);
        if (!eligibility.IsEligible)
            return Result.Failure<CertificateRenewalResult>(eligibility.Reason);

        // Step 3: Validate renewal token
        if (!await ValidateRenewalTokenAsync(cmd.RenewalToken, existingCert.Id, ct))
            return Result.Failure<CertificateRenewalResult>("Invalid renewal token");

        // Step 4: Verify the request is signed with the old certificate
        var verificationResult = await _signatureService.VerifyAsync(
            cmd.RequestSignature,
            cmd.GetSignableContent(),
            existingCert.PublicKey,
            existingCert.Algorithm,
            ct);

        if (!verificationResult)
            return Result.Failure<CertificateRenewalResult>("Signature verification failed");

        // Step 5: Determine if key rotation is required
        var keyRotationRequired = await IsKeyRotationRequiredAsync(existingCert, ct);

        // Step 6: Validate CSR
        var csrValidation = await _csrValidator.ValidateAsync(cmd.Csr, ct);
        if (!csrValidation.IsValid)
            return Result.Failure<CertificateRenewalResult>(csrValidation.Error);

        // Step 7: Ensure public key matches (unless key rotation)
        if (!keyRotationRequired)
        {
            var csrPublicKey = ExtractPublicKeyFromCsr(cmd.Csr);
            if (!csrPublicKey.SequenceEqual(existingCert.PublicKey))
                return Result.Failure<CertificateRenewalResult>(
                    "Public key must match existing certificate (no key rotation scheduled)");
        }

        // Step 8: Issue new certificate
        var newCertificate = await _certificateService.IssueCertificateAsync(
            new IssueCertificateCommand
            {
                TenantId = existingCert.TenantId,
                UserId = existingCert.UserId,
                DeviceId = existingCert.DeviceId,
                Csr = cmd.Csr,
                Type = existingCert.Type,
                // Set validity
                NotBefore = DateTime.UtcNow,
                NotAfter = DateTime.UtcNow.AddYears(1),
                // Link to previous certificate
                PreviousCertificateId = existingCert.Id,
                RenewalReason = cmd.Reason ?? "Scheduled renewal"
            }, ct);

        // Step 9: Update existing certificate status
        existingCert.Status = CertificateStatus.Superseded;
        existingCert.SupersededAt = DateTime.UtcNow;
        existingCert.SupersededBy = newCertificate.Id;
        await _certRepository.UpdateAsync(existingCert, ct);

        // Step 10: Update device record
        if (existingCert.Type == CertificateType.Device)
        {
            var device = await _deviceRepository.GetByIdAsync(existingCert.DeviceId!.Value, ct);
            device!.CertificateSerialNumber = newCertificate.SerialNumber;
            device.CertificateExpiresAt = newCertificate.NotAfter;
            await _deviceRepository.UpdateAsync(device, ct);
        }

        // Step 11: Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = existingCert.TenantId,
            UserId = existingCert.UserId,
            Action = AuditAction.CertificateRenewed,
            Details = new
            {
                OldCertificateId = existingCert.Id,
                OldSerialNumber = existingCert.SerialNumber,
                NewCertificateId = newCertificate.Id,
                NewSerialNumber = newCertificate.SerialNumber,
                KeyRotated = keyRotationRequired
            }
        }, ct);

        return Result.Success(new CertificateRenewalResult
        {
            NewCertificate = newCertificate.CertificateData,
            NewSerialNumber = newCertificate.SerialNumber,
            NotBefore = newCertificate.NotBefore,
            NotAfter = newCertificate.NotAfter,
            CertificateChain = await GetCertificateChainAsync(existingCert.TenantId, ct)
        });
    }

    private async Task<RenewalEligibility> ValidateRenewalEligibilityAsync(
        Certificate cert,
        CancellationToken ct)
    {
        // Check certificate status
        if (cert.Status == CertificateStatus.Revoked)
            return RenewalEligibility.NotEligible("Certificate is revoked");

        // Check if already renewed
        if (cert.Status == CertificateStatus.Superseded)
            return RenewalEligibility.NotEligible("Certificate already renewed");

        // Check if within renewal window or grace period
        var now = DateTime.UtcNow;
        var renewalStart = cert.NotAfter.AddDays(-30);
        var graceEnd = cert.NotAfter.AddDays(7);

        if (now < renewalStart)
            return RenewalEligibility.NotEligible("Not yet in renewal window");

        if (now > graceEnd)
            return RenewalEligibility.NotEligible("Grace period expired");

        // Check rate limiting
        var recentRenewals = await _certRepository.GetRecentRenewalsAsync(
            cert.UserId, cert.DeviceId, TimeSpan.FromHours(24), ct);

        var policy = await _policyRepository.GetRenewalPolicyAsync(cert.TenantId, ct);
        if (recentRenewals.Count >= policy.MaxRenewalAttemptsPerDay)
            return RenewalEligibility.NotEligible("Too many renewal attempts today");

        return RenewalEligibility.Eligible();
    }
}
```

### Mobile App: Automatic Renewal

```swift
// iOS - AutomaticRenewalManager.swift
class AutomaticRenewalManager {

    func performAutomaticRenewal(for certificate: Certificate) async throws {
        // Step 1: Request renewal token
        let renewalToken = try await apiClient.requestRenewalToken(
            certificateId: certificate.id
        )

        // Step 2: Load existing private key
        let privateKey = try KeychainManager.loadKey(
            tag: certificate.keyTag,
            accessControl: .afterFirstUnlock  // Allow background access
        )

        // Step 3: Create renewal CSR (same key)
        let csr = try CsrBuilder.build(
            publicKey: certificate.publicKey,
            privateKey: privateKey,
            subject: certificate.subject,
            algorithm: certificate.algorithm
        )

        // Step 4: Sign renewal request
        let request = CertificateRenewalRequest(
            certificateId: certificate.id,
            csr: csr,
            renewalToken: renewalToken.token
        )

        let signature = try sign(request.signableContent, with: privateKey)

        // Step 5: Submit renewal
        let result = try await apiClient.renewCertificate(
            request: request,
            signature: signature
        )

        // Step 6: Store new certificate
        try KeychainManager.storeCertificate(
            result.newCertificate,
            tag: certificate.certTag
        )

        // Step 7: Update local certificate chain
        try CertificateChainManager.updateChain(result.certificateChain)

        // Step 8: Confirm to backend
        try await apiClient.confirmRenewal(
            certificateId: result.newCertificateId
        )

        // Step 9: Notify user (if app in foreground)
        if UIApplication.shared.applicationState == .active {
            showRenewalSuccessNotification()
        }
    }
}
```

---

## Manual Renewal Flow

### When Manual Renewal is Required

| Scenario | Reason |
|----------|--------|
| Key rotation required | Policy mandates new keypair |
| Algorithm upgrade | Tenant upgraded to stronger algorithm |
| Certificate compromise | Old key may be compromised |
| User-requested | User wants early renewal |
| Admin-initiated | Admin forces renewal |

### Manual Renewal Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MANUAL CERTIFICATE RENEWAL                                │
│                    (With Key Rotation)                                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  Mobile App  │          │   Backend    │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  1. "Renew my         │                         │
     │     certificate"      │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │  2. Check renewal       │
     │                       │     requirements        │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  3. Key rotation        │
     │                       │     required            │
     │                       │<────────────────────────│
     │                       │                         │
     │  4. "Key rotation     │                         │
     │     required. This    │                         │
     │     will generate     │                         │
     │     new keys."        │                         │
     │<──────────────────────│                         │
     │                       │                         │
     │  5. Approve           │                         │
     │     (biometric)       │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │  6. Generate new        │
     │                       │     keypair             │
     │                       │                         │
     │                       │  7. Create CSR with     │
     │                       │     new public key      │
     │                       │                         │
     │                       │  8. Sign with OLD key   │
     │                       │     (proves ownership)  │
     │                       │                         │
     │                       │  9. Submit renewal      │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │                         │ 10. Verify old
     │                       │                         │     signature
     │                       │                         │
     │                       │                         │ 11. Issue new
     │                       │                         │     certificate
     │                       │                         │
     │                       │  12. New certificate    │
     │                       │<────────────────────────│
     │                       │                         │
     │                       │  13. Store new key +    │
     │                       │      certificate        │
     │                       │                         │
     │                       │  14. Update key shares  │
     │                       │      (if user key)      │
     │                       │                         │
     │  15. "Renewal         │                         │
     │      complete!"       │                         │
     │<──────────────────────│                         │
     │                       │                         │
```

### Key Rotation with Secret Share Update

```swift
// iOS - KeyRotationManager.swift
class KeyRotationManager {

    func performKeyRotationRenewal(certificate: Certificate) async throws {
        // Step 1: Authenticate
        let authenticated = try await BiometricAuth.authenticate(
            reason: "Renew your Digital ID certificate"
        )
        guard authenticated else { throw RenewalError.authenticationFailed }

        // Step 2: Load old private key
        let oldPrivateKey = try KeychainManager.loadKey(
            tag: certificate.keyTag,
            accessControl: .biometryCurrentSet
        )

        // Step 3: Generate new keypair
        let newKeyPair = try PqcKeyGenerator.generate(
            algorithm: certificate.algorithm
        )

        // Step 4: Create CSR with new public key
        let csr = try CsrBuilder.build(
            publicKey: newKeyPair.publicKey,
            privateKey: newKeyPair.privateKey,
            subject: certificate.subject,
            algorithm: certificate.algorithm
        )

        // Step 5: Sign request with OLD key (proof of ownership)
        let request = KeyRotationRenewalRequest(
            certificateId: certificate.id,
            csr: csr,
            newPublicKey: newKeyPair.publicKey
        )

        let signature = try sign(request.signableContent, with: oldPrivateKey)

        // Step 6: If this is user certificate, update secret shares
        if certificate.type == .user {
            try await updateSecretShares(
                newPrivateKey: newKeyPair.privateKey,
                oldPrivateKey: oldPrivateKey
            )
        }

        // Step 7: Submit renewal
        let result = try await apiClient.renewCertificateWithKeyRotation(
            request: request,
            signature: signature
        )

        // Step 8: Store new private key
        try KeychainManager.store(
            key: newKeyPair.privateKey,
            tag: certificate.keyTag,  // Overwrites old key
            accessControl: .biometryCurrentSet
        )

        // Step 9: Store new certificate
        try KeychainManager.storeCertificate(
            result.newCertificate,
            tag: certificate.certTag
        )

        // Step 10: Delete old key securely
        try KeychainManager.secureDelete(tag: "\(certificate.keyTag)-backup")
    }

    private func updateSecretShares(
        newPrivateKey: Data,
        oldPrivateKey: Data
    ) async throws {
        // Generate new secret shares for the new key
        let newShares = try SecretSharing.split(
            secret: newPrivateKey,
            threshold: 2,
            totalShares: 3
        )

        // Encrypt shares
        let encryptedPartUser = try encryptPartUser(newShares.partUser)
        let encryptedPartControl = try encryptPartControl(newShares.partControl)
        let encryptedPartRecovery = try encryptPartRecovery(newShares.partRecovery)

        // Submit to backend
        try await apiClient.updateSecretShares(
            encryptedPartControl: encryptedPartControl,
            encryptedPartRecovery: encryptedPartRecovery
        )

        // Store part_user locally
        try KeychainManager.store(
            key: encryptedPartUser,
            tag: "user-key-share-\(currentUserId)",
            accessControl: .biometryCurrentSet
        )
    }
}
```

---

## Key Rotation

### Key Rotation Policy

```csharp
public class KeyRotationPolicy
{
    // Time-based rotation
    public TimeSpan MaxKeyAge { get; set; } = TimeSpan.FromDays(730); // 2 years

    // Usage-based rotation
    public int? MaxSignatureCount { get; set; } = null;  // Optional

    // Security-based rotation
    public bool RotateOnSuspectedCompromise { get; set; } = true;
    public bool RotateOnAlgorithmUpgrade { get; set; } = true;

    // Administrative
    public bool AllowUserInitiatedRotation { get; set; } = true;
    public bool RequireAdminApprovalForRotation { get; set; } = false;
}
```

### Key Rotation Decision

```csharp
public class KeyRotationEvaluator
{
    public async Task<KeyRotationDecision> EvaluateAsync(
        Certificate cert,
        CancellationToken ct = default)
    {
        var policy = await _policyRepository.GetKeyRotationPolicyAsync(cert.TenantId, ct);
        var reasons = new List<string>();

        // Check key age
        var keyAge = DateTime.UtcNow - cert.KeyGeneratedAt;
        if (keyAge > policy.MaxKeyAge)
        {
            reasons.Add($"Key age ({keyAge.Days} days) exceeds maximum ({policy.MaxKeyAge.Days} days)");
        }

        // Check signature count
        if (policy.MaxSignatureCount.HasValue)
        {
            var signatureCount = await _auditRepository.GetSignatureCountAsync(cert.Id, ct);
            if (signatureCount >= policy.MaxSignatureCount)
            {
                reasons.Add($"Signature count ({signatureCount}) reached limit ({policy.MaxSignatureCount})");
            }
        }

        // Check algorithm upgrade
        var tenant = await _tenantRepository.GetAsync(cert.TenantId, ct);
        if (policy.RotateOnAlgorithmUpgrade &&
            cert.Algorithm != tenant!.CurrentAlgorithm)
        {
            reasons.Add($"Algorithm upgrade from {cert.Algorithm} to {tenant.CurrentAlgorithm}");
        }

        // Check security flags
        if (policy.RotateOnSuspectedCompromise && cert.SuspectedCompromise)
        {
            reasons.Add("Key suspected compromise flag set");
        }

        return new KeyRotationDecision
        {
            IsRequired = reasons.Any(),
            Reasons = reasons,
            NewAlgorithm = tenant?.CurrentAlgorithm ?? cert.Algorithm
        };
    }
}
```

---

## CA Certificate Renewal

### Tenant CA Renewal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TENANT CA CERTIFICATE RENEWAL                             │
└─────────────────────────────────────────────────────────────────────────────┘

Timeline (5-year validity):
────────────────────────────────────────────────────────────────────────────────

Year 1-4              Year 4.5            Year 5         Year 5.5
    │                    │                  │               │
    │◄── Normal ────────►│◄── Renewal ────►│◄─ Overlap ───►│
    │    Operation       │    (6 months)    │   (6 months)  │
    │                    │                  │               │
                         │                  │               │
                    Renewal             Expiry          Old CA
                    Starts                             Removed

Process:
1. New CA keypair generated in HSM (6 months before expiry)
2. New CA certificate issued by Root CA
3. Both old and new CA certificates active (overlap period)
4. User/device certs gradually renewed with new CA
5. Old CA certificate retired after overlap period
```

### Root CA Renewal

```csharp
public class RootCaRenewalService : IRootCaRenewalService
{
    public async Task<Result> InitiateRootCaRenewalAsync(
        InitiateRootCaRenewalCommand cmd,
        CancellationToken ct = default)
    {
        // This is a critical operation requiring multiple approvals

        // Step 1: Verify admin authorization (multi-party)
        var approvals = await _approvalService.GetPendingApprovalsAsync(
            cmd.RenewalRequestId, ct);

        if (approvals.Count < _config.RequiredRootCaRenewalApprovals)
            return Result.Failure("Insufficient approvals for Root CA renewal");

        // Step 2: Generate new Root CA keypair in HSM
        var keyGenResult = await _hsmService.GenerateKeyPairAsync(
            new GenerateKeyPairRequest
            {
                Label = $"root-ca-{DateTime.UtcNow:yyyy}",
                Algorithm = cmd.Algorithm,
                KeyUsage = KeyUsage.CertificateSigning | KeyUsage.CrlSigning,
                Extractable = false  // Never leave HSM
            }, ct);

        // Step 3: Create self-signed Root CA certificate
        var rootCaCert = await _certificateBuilder.BuildRootCaCertificateAsync(
            new BuildRootCaCertificateRequest
            {
                Subject = _config.RootCaSubject,
                PublicKey = keyGenResult.PublicKey,
                PrivateKeyId = keyGenResult.KeyId,
                ValidityYears = 20,
                Algorithm = cmd.Algorithm
            }, ct);

        // Step 4: Store new Root CA (both old and new active)
        await _certRepository.CreateAsync(new Certificate
        {
            Type = CertificateType.RootCa,
            Status = CertificateStatus.Active,
            CertificateData = rootCaCert.Encoded,
            PublicKey = keyGenResult.PublicKey,
            PrivateKeyId = keyGenResult.KeyId,
            NotBefore = rootCaCert.NotBefore,
            NotAfter = rootCaCert.NotAfter,
            SerialNumber = rootCaCert.SerialNumber
        }, ct);

        // Step 5: Update trust stores (async process)
        await _trustStoreUpdateService.ScheduleUpdateAsync(rootCaCert.Encoded, ct);

        // Step 6: Audit log (critical event)
        await _auditService.LogAsync(new AuditEntry
        {
            Action = AuditAction.RootCaRenewed,
            Severity = AuditSeverity.Critical,
            Details = new
            {
                OldRootCaSerial = cmd.OldRootCaSerialNumber,
                NewRootCaSerial = rootCaCert.SerialNumber,
                Algorithm = cmd.Algorithm,
                Approvals = approvals.Select(a => a.ApproverEmail)
            }
        }, ct);

        return Result.Success();
    }
}
```

---

## Grace Periods & Expiration

### Grace Period Handling

```csharp
public class GracePeriodService : IGracePeriodService
{
    public async Task<Result<CertificateRenewalResult>> RenewInGracePeriodAsync(
        GracePeriodRenewalCommand cmd,
        CancellationToken ct = default)
    {
        var cert = await _certRepository.GetAsync(cmd.CertificateId, ct);

        // Verify in grace period
        var now = DateTime.UtcNow;
        if (now <= cert!.NotAfter)
            return Result.Failure<CertificateRenewalResult>("Not in grace period yet");

        var graceEnd = cert.NotAfter.AddDays(7);
        if (now > graceEnd)
            return Result.Failure<CertificateRenewalResult>("Grace period expired");

        // Grace period renewal requires additional verification
        // because the certificate is technically expired

        // Option 1: Verify with another active device
        if (cmd.VerificationDeviceId.HasValue)
        {
            var verificationDevice = await _deviceRepository.GetAsync(
                cmd.VerificationDeviceId.Value, ct);

            if (verificationDevice?.UserId != cert.UserId)
                return Result.Failure<CertificateRenewalResult>("Invalid verification device");

            // Verify signature from verification device
            var verificationCert = await _certRepository.GetActiveDeviceCertAsync(
                verificationDevice.Id, ct);

            if (!await VerifySignatureAsync(
                cmd.VerificationSignature,
                cmd.GetSignableContent(),
                verificationCert!.PublicKey, ct))
            {
                return Result.Failure<CertificateRenewalResult>("Verification failed");
            }
        }
        // Option 2: Email verification
        else if (cmd.EmailVerificationToken != null)
        {
            if (!await _tokenService.ValidateEmailTokenAsync(
                cmd.EmailVerificationToken, cert.UserId, ct))
            {
                return Result.Failure<CertificateRenewalResult>("Invalid email token");
            }
        }
        else
        {
            return Result.Failure<CertificateRenewalResult>(
                "Grace period renewal requires additional verification");
        }

        // Proceed with renewal
        return await _renewalService.RenewCertificateAsync(
            new RenewCertificateCommand
            {
                CertificateId = cmd.CertificateId,
                Csr = cmd.Csr,
                Reason = "Grace period renewal"
            }, ct);
    }
}
```

### Expiration Handling

```csharp
public class CertificateExpirationHandler : IHostedService
{
    public async Task HandleExpiredCertificatesAsync(CancellationToken ct)
    {
        // Get certificates past grace period
        var expiredCertificates = await _certRepository.GetExpiredCertificatesAsync(
            gracePeriodEnded: true,
            ct);

        foreach (var cert in expiredCertificates)
        {
            // Mark as revoked (due to expiration)
            cert.Status = CertificateStatus.Revoked;
            cert.RevokedAt = DateTime.UtcNow;
            cert.RevocationReason = RevocationReason.CessationOfOperation;
            cert.RevocationNote = "Certificate expired past grace period";

            await _certRepository.UpdateAsync(cert, ct);

            // Add to CRL
            await _crlService.AddToCrlAsync(cert.SerialNumber, ct);

            // Notify user
            var user = await _userRepository.GetAsync(cert.UserId, ct);
            await _emailService.SendCertificateExpiredAsync(
                user!.Email,
                cert.Type.ToString(),
                cert.NotAfter,
                ct);

            // If device certificate, suspend device
            if (cert.Type == CertificateType.Device && cert.DeviceId.HasValue)
            {
                var device = await _deviceRepository.GetAsync(cert.DeviceId.Value, ct);
                device!.Status = DeviceStatus.Suspended;
                device.SuspendedReason = "Certificate expired";
                await _deviceRepository.UpdateAsync(device, ct);
            }

            // Audit log
            await _auditService.LogAsync(new AuditEntry
            {
                TenantId = cert.TenantId,
                UserId = cert.UserId,
                Action = AuditAction.CertificateExpired,
                Severity = AuditSeverity.Medium,
                Details = new
                {
                    CertificateId = cert.Id,
                    SerialNumber = cert.SerialNumber,
                    Type = cert.Type,
                    ExpiredAt = cert.NotAfter
                }
            }, ct);
        }
    }
}
```

---

## Renewal Policies

### Tenant Renewal Policy

```csharp
public class TenantCertificateRenewalPolicy
{
    public Guid TenantId { get; set; }

    // Validity periods
    public int UserCertificateValidityDays { get; set; } = 365;
    public int DeviceCertificateValidityDays { get; set; } = 365;

    // Renewal windows
    public int RenewalWindowDays { get; set; } = 30;
    public int GracePeriodDays { get; set; } = 7;

    // Automatic renewal
    public bool AutoRenewalEnabled { get; set; } = true;
    public bool RequireUserApprovalForRenewal { get; set; } = false;

    // Key rotation
    public int KeyRotationIntervalDays { get; set; } = 730;  // 2 years
    public bool ForceKeyRotationOnRenewal { get; set; } = false;

    // Notifications
    public int[] NotificationDaysBeforeExpiry { get; set; } = { 30, 14, 7, 3, 1 };
    public bool NotifyAdminOnExpiration { get; set; } = true;

    // Rate limiting
    public int MaxRenewalAttemptsPerDay { get; set; } = 3;
}
```

---

## Data Structures

### Certificate Renewal Record

```csharp
public class CertificateRenewalRecord
{
    public Guid Id { get; set; }
    public Guid OriginalCertificateId { get; set; }
    public Guid NewCertificateId { get; set; }

    public string OriginalSerialNumber { get; set; } = "";
    public string NewSerialNumber { get; set; } = "";

    public RenewalType Type { get; set; }
    public RenewalReason Reason { get; set; }
    public string? ReasonDetails { get; set; }

    public bool KeyRotated { get; set; }
    public string? OldAlgorithm { get; set; }
    public string? NewAlgorithm { get; set; }

    public DateTime RenewedAt { get; set; }
    public string? InitiatedBy { get; set; }  // "system", "user", "admin"

    public Guid TenantId { get; set; }
    public Guid UserId { get; set; }
    public Guid? DeviceId { get; set; }
}

public enum RenewalType
{
    Automatic,
    Manual,
    GracePeriod,
    KeyRotation,
    AlgorithmUpgrade,
    AdminInitiated
}

public enum RenewalReason
{
    ScheduledRenewal,
    ApproachingExpiry,
    KeyRotationPolicy,
    AlgorithmUpgrade,
    SecurityConcern,
    UserRequested,
    AdminRequested
}
```

---

## API Reference

### Check Renewal Status

```http
GET /api/v1/certificates/{certificateId}/renewal-status
Authorization: Bearer <access-token>

Response 200 OK:
{
  "certificate_id": "uuid",
  "status": "active",
  "expires_at": "2025-12-31T23:59:59Z",
  "renewal_window_starts": "2025-12-01T00:00:00Z",
  "in_renewal_window": true,
  "in_grace_period": false,
  "auto_renewal_enabled": true,
  "key_rotation_required": false,
  "can_renew": true,
  "renewal_blocked_reason": null
}
```

### Request Renewal Token

```http
POST /api/v1/certificates/{certificateId}/renewal-token
Authorization: Bearer <access-token>

Response 200 OK:
{
  "token": "renewal-token-...",
  "expires_at": "2025-12-01T13:00:00Z",
  "key_rotation_required": false
}
```

### Submit Renewal

```http
POST /api/v1/certificates/{certificateId}/renew
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "csr": "base64-encoded-csr",
  "renewal_token": "renewal-token-...",
  "signature": "base64-encoded-signature"
}

Response 200 OK:
{
  "new_certificate": "base64-encoded-certificate",
  "new_serial_number": "1234567890",
  "not_before": "2025-12-01T12:00:00Z",
  "not_after": "2026-12-01T12:00:00Z",
  "certificate_chain": ["base64...", "base64..."]
}
```

### Confirm Renewal

```http
POST /api/v1/certificates/{newCertificateId}/confirm-renewal
Authorization: Bearer <access-token>

Response 204 No Content
```

---

## Mobile App Implementation

### Background Renewal (iOS)

```swift
// iOS - BackgroundRenewalTask.swift
import BackgroundTasks

class BackgroundRenewalTask {

    static let taskIdentifier = "com.idp.certificate.renewal"

    static func register() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: taskIdentifier,
            using: nil
        ) { task in
            handleBackgroundRenewal(task: task as! BGProcessingTask)
        }
    }

    static func scheduleBackgroundRenewal() {
        let request = BGProcessingTaskRequest(identifier: taskIdentifier)
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        request.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 3600) // 6 hours

        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Failed to schedule background renewal: \(error)")
        }
    }

    private static func handleBackgroundRenewal(task: BGProcessingTask) {
        task.expirationHandler = {
            // Clean up if task is about to expire
        }

        Task {
            do {
                let manager = CertificateManager()
                let certificates = try await manager.getCertificatesNeedingRenewal()

                for cert in certificates {
                    try await AutomaticRenewalManager().performAutomaticRenewal(for: cert)
                }

                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }

            // Schedule next check
            scheduleBackgroundRenewal()
        }
    }
}
```

---

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Unauthorized renewal | Signature verification with existing cert |
| Key extraction during rotation | Secure Enclave, HSM protection |
| Renewal token theft | Short-lived tokens, single use |
| Denial of service | Rate limiting, admin override |
| Stale certificates | Automatic expiration handling |

### Audit Events

| Event | Severity | Data Logged |
|-------|----------|-------------|
| Renewal initiated | Low | Certificate ID, initiator |
| Renewal completed | Low | Old/new serial numbers |
| Key rotation | Medium | Algorithm, reason |
| Grace period renewal | Medium | Verification method |
| Renewal failed | Medium | Reason, attempts |
| Certificate expired | High | Certificate details |

---

## Implementation Checklist

### Phase 1: Core Renewal

- [ ] **Renewal Service**
  - [ ] Eligibility validation
  - [ ] CSR verification
  - [ ] Certificate issuance
  - [ ] Old cert status update

- [ ] **Renewal Triggers**
  - [ ] Time-based scheduler
  - [ ] App launch check
  - [ ] Push notifications

### Phase 2: Key Rotation

- [ ] **Key Rotation Policy**
  - [ ] Policy configuration
  - [ ] Rotation evaluation
  - [ ] Secret share updates

- [ ] **Rotation Flow**
  - [ ] New keypair generation
  - [ ] Cross-signing verification
  - [ ] Secure key transition

### Phase 3: Grace Period & Expiration

- [ ] **Grace Period Handling**
  - [ ] Additional verification
  - [ ] Device verification
  - [ ] Email verification

- [ ] **Expiration Handler**
  - [ ] Automatic revocation
  - [ ] CRL updates
  - [ ] User notifications

### Phase 4: CA Renewal

- [ ] **Tenant CA Renewal**
  - [ ] Overlap period management
  - [ ] Gradual migration

- [ ] **Root CA Renewal**
  - [ ] Multi-party approval
  - [ ] Trust store updates

---

## References

- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Certificate issuance details
- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Initial certificate issuance
- [DEVICE_MANAGEMENT.md](./DEVICE_MANAGEMENT.md) - Device certificate handling
- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 PKI Certificate Profile
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements/)
