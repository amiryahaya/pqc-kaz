# Digital ID Account Recovery Flow

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Recovery Prerequisites](#recovery-prerequisites)
3. [Recovery Scenarios](#recovery-scenarios)
4. [Recovery Flow Summary](#recovery-flow-summary)
5. [Detailed Recovery Steps](#detailed-recovery-steps)
6. [Cryptographic Operations](#cryptographic-operations)
7. [Security Measures](#security-measures)
8. [Data Structures](#data-structures)
9. [API Endpoints](#api-endpoints)
10. [Error Handling](#error-handling)
11. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

This document describes the Account Recovery flow for users who have lost access to their Digital ID. Recovery scenarios include:

- **Lost/Stolen Device** - Primary device is no longer accessible
- **App Deletion** - User accidentally deleted the Digital ID app
- **Device Upgrade** - User moved to a new device
- **Device Failure** - Device hardware failure or factory reset

### Recovery Method

The recovery process uses the **2-of-3 Secret Sharing** scheme established during registration:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SECRET SHARING RECAP                                     │
└─────────────────────────────────────────────────────────────────────────────┘

During Registration, User Private Key was split into 3 shares:

┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  part_user  │   │part_control │   │part_recovery│
│             │   │             │   │             │
│   Lost with │   │  Stored in  │   │  Encrypted  │
│   old device│   │   Backend   │   │  with user  │
│             │   │             │   │  recovery   │
│             │   │             │   │  password   │
└─────────────┘   └─────────────┘   └─────────────┘
      ❌                ✓                 ✓
   (Lost)          (Available)       (Available)

Recovery uses: part_control + part_recovery = User Private Key ✓
```

### Key Principles

1. **User Private Key Reconstructed Only on New Device** - Never in backend
2. **Recovery Password Required** - Only user knows this password
3. **Email Verification** - Proves ownership of registered email
4. **New Device Binding** - New device keypair and certificate issued
5. **Old Device Revocation** - Previous device certificates revoked
6. **Audit Trail** - Every recovery attempt logged

---

## Recovery Prerequisites

### What User Needs

| Requirement | Source | Purpose |
|-------------|--------|---------|
| Recovery Password | User's memory | Decrypt `part_recovery` |
| Email Access | User's email account | Verify identity |
| New Device | User provides | Install app, store new keys |
| Organization Code | From organization | Identify correct tenant |

### What Backend Has

| Data | Storage | Purpose |
|------|---------|---------|
| `part_control` | HSM/Encrypted DB | Second share for reconstruction |
| `encrypted_part_recovery` | Database | Encrypted with recovery password |
| User Profile | Database | Email, user ID, tenant |
| Old Device Certificates | Database | For revocation |

### What is Lost

| Data | Status | Impact |
|------|--------|--------|
| `part_user` | Lost with device | Cannot be recovered |
| Device Private Key | Lost with device | Must generate new one |
| Device Certificate | Revoked | New one issued |
| Local Keychain | Lost with device | Recreated on new device |

---

## Recovery Scenarios

### Scenario 1: Lost/Stolen Device (Primary Use Case)

```
User: "I lost my phone"
Required: Recovery password + Email access
Result: Full recovery on new device, old device revoked
```

### Scenario 2: App Accidentally Deleted

```
User: "I deleted the app by mistake"
Required: Recovery password + Email access
Result: Full recovery on same device (treated as new device)
```

### Scenario 3: Device Upgrade

```
User: "I got a new phone"
Option A: Transfer via old device (if still accessible) - See Device Management
Option B: Recovery flow (if old device unavailable)
```

### Scenario 4: Forgotten Recovery Password

```
User: "I forgot my recovery password"
Required: Access to old device with part_user
Result: Use part_user + part_control (requires old device)
If old device also lost: ACCOUNT UNRECOVERABLE ⚠️
```

---

## Recovery Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ACCOUNT RECOVERY FLOW - HIGH LEVEL                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Phase 1    │────>│   Phase 2    │────>│   Phase 3    │────>│   Phase 4    │
│   Initiate   │     │    Email     │     │   Recovery   │     │    Key       │
│   Recovery   │     │ Verification │     │   Password   │     │Reconstruction│
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                      │
                                                                      ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Phase 8    │<────│   Phase 7    │<────│   Phase 6    │<────│   Phase 5    │
│   Complete   │     │   Activate   │     │   Issue New  │     │  New Device  │
│              │     │   Identity   │     │ Certificates │     │   Setup      │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

---

## Detailed Recovery Steps

### Phase 1: Initiate Recovery

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  New Device  │          │   Backend    │
│          │          │  Digital ID  │          │     API      │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  1. Install app       │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │  2. Tap "Recover      │                         │
     │     Account"          │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │  3. Enter Org Code    │                         │
     │     (or scan QR)      │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │  4. Validate Org        │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  5. Org Config          │
     │                       │  (branding, algo)       │
     │                       │<────────────────────────│
     │                       │                         │
     │  6. Show Org branding │                         │
     │<──────────────────────│                         │
     │                       │                         │
     │  7. Enter registered  │                         │
     │     email address     │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │  8. Initiate Recovery   │
     │                       │     (email, device_id)  │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  [Backend checks if     │
     │                       │   user exists, has      │
     │                       │   recovery configured]  │
     │                       │                         │
     │                       │  9. Recovery session    │
     │                       │     created             │
     │                       │<────────────────────────│
     │                       │                         │
```

#### Backend: Initiate Recovery

```csharp
public class RecoveryService : IRecoveryService
{
    public async Task<Result<RecoverySession>> InitiateRecoveryAsync(
        InitiateRecoveryCommand cmd,
        CancellationToken ct = default)
    {
        // Step 1: Find user by email (don't reveal if not found)
        var user = await _userRepository.FindByEmailAsync(cmd.TenantId, cmd.Email, ct);

        // Always return success to prevent email enumeration
        if (user is null)
        {
            _logger.LogInformation(
                "Recovery attempted for non-existent email: {Email}",
                cmd.Email.MaskEmail());

            // Fake delay to match real processing time
            await Task.Delay(Random.Shared.Next(500, 1500), ct);
            return Result.Success(CreateFakeSession());
        }

        // Step 2: Check if user has recovery configured
        var recoveryData = await _recoveryRepository.GetByUserIdAsync(user.Id, ct);
        if (recoveryData is null || !recoveryData.IsActive)
        {
            _logger.LogWarning(
                "Recovery attempted for user without recovery: {UserId}",
                user.Id);
            return Result.Success(CreateFakeSession());
        }

        // Step 3: Check rate limiting
        var recentAttempts = await _recoveryRepository
            .GetRecentAttemptsAsync(user.Id, TimeSpan.FromHours(1), ct);

        if (recentAttempts >= 3)
        {
            _logger.LogWarning(
                "Recovery rate limit exceeded for user: {UserId}",
                user.Id);
            return Result.Failure<RecoverySession>("Too many recovery attempts. Try again later.");
        }

        // Step 4: Create recovery session
        var session = new RecoverySession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TenantId = cmd.TenantId,
            NewDeviceId = cmd.DeviceId,
            Email = user.Email,
            Status = RecoveryStatus.PendingEmailVerification,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IpAddress = cmd.IpAddress,
            UserAgent = cmd.UserAgent
        };

        await _recoveryRepository.CreateSessionAsync(session, ct);

        // Step 5: Generate and send OTP
        var otp = GenerateSecureOtp();
        session.OtpHash = HashOtp(otp);
        session.OtpExpiresAt = DateTime.UtcNow.AddMinutes(10);

        await _recoveryRepository.UpdateSessionAsync(session, ct);

        await _emailService.SendRecoveryOtpAsync(
            user.Email,
            otp,
            user.DisplayName,
            session.Id,
            ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = cmd.TenantId,
            UserId = user.Id,
            Action = AuditAction.RecoveryInitiated,
            Details = new { DeviceId = cmd.DeviceId, SessionId = session.Id },
            IpAddress = cmd.IpAddress
        }, ct);

        return Result.Success(session);
    }
}
```

---

### Phase 2: Email Verification

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────┐
│   User   │          │  New Device  │          │   Backend    │          │  Email   │
│          │          │  Digital ID  │          │     API      │          │  Server  │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘          └────┬─────┘
     │                       │                         │                       │
     │                       │                         │  1. Send OTP email    │
     │                       │                         │──────────────────────>│
     │                       │                         │                       │
     │  2. Receive email     │                         │                       │
     │<────────────────────────────────────────────────────────────────────────│
     │                       │                         │                       │
     │  "Your recovery code  │                         │                       │
     │   is: 847293"         │                         │                       │
     │                       │                         │                       │
     │  3. Enter OTP code    │                         │                       │
     │──────────────────────>│                         │                       │
     │                       │                         │                       │
     │                       │  4. Verify OTP          │                       │
     │                       │     (session_id, otp)   │                       │
     │                       │────────────────────────>│                       │
     │                       │                         │                       │
     │                       │     [Verify OTP hash,   │                       │
     │                       │      check expiry,      │                       │
     │                       │      check attempts]    │                       │
     │                       │                         │                       │
     │                       │  5. OTP Verified        │                       │
     │                       │     + encrypted_        │                       │
     │                       │     part_recovery       │                       │
     │                       │<────────────────────────│                       │
     │                       │                         │                       │
```

#### Email Template

```html
Subject: Digital ID Account Recovery - Verification Code

Dear {{user_name}},

We received a request to recover your Digital ID account on a new device.

Your verification code is: {{otp_code}}

This code expires in 10 minutes.

Device Information:
- Device: {{device_name}}
- Location: {{location}}
- Time: {{timestamp}}

If you did not request this recovery, please:
1. Do NOT share this code with anyone
2. Contact your organization's IT support immediately
3. Consider changing your recovery password

Security Note: Our team will NEVER ask for your recovery password.

---
Digital ID Platform
```

#### Backend: Verify OTP

```csharp
public async Task<Result<OtpVerificationResult>> VerifyOtpAsync(
    VerifyOtpCommand cmd,
    CancellationToken ct = default)
{
    // Get session
    var session = await _recoveryRepository.GetSessionAsync(cmd.SessionId, ct);

    if (session is null)
        return Result.Failure<OtpVerificationResult>("Invalid recovery session");

    if (session.Status != RecoveryStatus.PendingEmailVerification)
        return Result.Failure<OtpVerificationResult>("Invalid session status");

    if (session.ExpiresAt < DateTime.UtcNow)
        return Result.Failure<OtpVerificationResult>("Recovery session expired");

    if (session.OtpExpiresAt < DateTime.UtcNow)
        return Result.Failure<OtpVerificationResult>("Verification code expired");

    // Check OTP attempts
    session.OtpAttempts++;
    if (session.OtpAttempts > 5)
    {
        session.Status = RecoveryStatus.Failed;
        session.FailureReason = "Too many incorrect attempts";
        await _recoveryRepository.UpdateSessionAsync(session, ct);

        return Result.Failure<OtpVerificationResult>("Too many incorrect attempts");
    }

    // Verify OTP (constant-time comparison)
    if (!VerifyOtpHash(cmd.Otp, session.OtpHash))
    {
        await _recoveryRepository.UpdateSessionAsync(session, ct);
        return Result.Failure<OtpVerificationResult>("Incorrect verification code");
    }

    // OTP verified - update session
    session.Status = RecoveryStatus.EmailVerified;
    session.EmailVerifiedAt = DateTime.UtcNow;
    await _recoveryRepository.UpdateSessionAsync(session, ct);

    // Get encrypted recovery share
    var recoveryData = await _recoveryRepository.GetByUserIdAsync(session.UserId, ct);

    return Result.Success(new OtpVerificationResult
    {
        SessionId = session.Id,
        EncryptedPartRecovery = recoveryData!.EncryptedPartRecovery,
        Nonce = recoveryData.Nonce,
        AuthTag = recoveryData.AuthTag,
        Algorithm = recoveryData.Algorithm
    });
}
```

---

### Phase 3: Recovery Password Entry

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  New Device  │          │   Backend    │
│          │          │  Digital ID  │          │     API      │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  1. Enter recovery    │                         │
     │     password          │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │ [LOCAL - On Device]     │
     │                       │                         │
     │                       │ 2. Derive key from      │
     │                       │    recovery password    │
     │                       │    using HKDF           │
     │                       │                         │
     │                       │ 3. Decrypt              │
     │                       │    encrypted_part_      │
     │                       │    recovery with        │
     │                       │    derived key          │
     │                       │                         │
     │                       │ 4. Validate decryption  │
     │                       │    (check auth tag)     │
     │                       │                         │
     │  [If decryption       │                         │
     │   fails: wrong        │                         │
     │   password]           │                         │
     │                       │                         │
     │                       │  5. Request part_control│
     │                       │     (session_id,        │
     │                       │      proof_of_decrypt)  │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  6. Return encrypted    │
     │                       │     part_control        │
     │                       │<────────────────────────│
     │                       │                         │
```

#### Client-Side: Decrypt Recovery Share

```swift
// iOS - RecoveryManager.swift
class RecoveryManager {

    func decryptRecoveryShare(
        encryptedShare: EncryptedShare,
        recoveryPassword: String,
        userId: String
    ) throws -> Data {

        // Step 1: Derive key from recovery password using HKDF
        let salt = (userId + "recovery-salt").data(using: .utf8)!
        let info = "IdP-Recovery-v1".data(using: .utf8)!

        let passwordData = recoveryPassword.data(using: .utf8)!
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: passwordData),
            salt: salt,
            info: info,
            outputByteCount: 32
        )

        // Step 2: Decrypt using AES-GCM
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: encryptedShare.nonce),
            ciphertext: encryptedShare.ciphertext,
            tag: encryptedShare.authTag
        )

        let decryptedData = try AES.GCM.open(sealedBox, using: derivedKey)

        // Step 3: Validate - decryption success means password was correct
        // (AES-GCM authentication tag verification is automatic)

        return decryptedData
    }

    func generateProofOfDecryption(partRecovery: Data) -> Data {
        // Generate proof that we successfully decrypted
        // This is a hash of the decrypted share (not the share itself!)
        return SHA256.hash(data: partRecovery).data
    }
}
```

#### Backend: Provide Control Share

```csharp
public async Task<Result<ControlShareResult>> GetControlShareAsync(
    GetControlShareCommand cmd,
    CancellationToken ct = default)
{
    // Get session
    var session = await _recoveryRepository.GetSessionAsync(cmd.SessionId, ct);

    if (session?.Status != RecoveryStatus.EmailVerified)
        return Result.Failure<ControlShareResult>("Invalid session status");

    if (session.ExpiresAt < DateTime.UtcNow)
        return Result.Failure<ControlShareResult>("Session expired");

    // Verify proof of decryption
    // This proves the client successfully decrypted part_recovery
    var recoveryData = await _recoveryRepository.GetByUserIdAsync(session.UserId, ct);
    if (!VerifyProofOfDecryption(cmd.ProofOfDecrypt, recoveryData!.PartRecoveryHash))
    {
        _logger.LogWarning(
            "Invalid proof of decryption for session: {SessionId}",
            session.Id);
        return Result.Failure<ControlShareResult>("Verification failed");
    }

    // Update session status
    session.Status = RecoveryStatus.PasswordVerified;
    session.PasswordVerifiedAt = DateTime.UtcNow;
    await _recoveryRepository.UpdateSessionAsync(session, ct);

    // Get part_control from HSM
    var partControl = await _hsmService.DecryptShareAsync(
        recoveryData.EncryptedPartControl,
        recoveryData.ControlKeyId,
        ct);

    // Encrypt part_control for transport using session key
    var sessionKey = DeriveSessionKey(session.Id, cmd.ClientPublicKey);
    var encryptedPartControl = EncryptForTransport(partControl, sessionKey);

    // Audit log
    await _auditService.LogAsync(new AuditEntry
    {
        TenantId = session.TenantId,
        UserId = session.UserId,
        Action = AuditAction.RecoveryShareProvided,
        Details = new { SessionId = session.Id }
    }, ct);

    return Result.Success(new ControlShareResult
    {
        EncryptedPartControl = encryptedPartControl.Ciphertext,
        Nonce = encryptedPartControl.Nonce,
        AuthTag = encryptedPartControl.Tag
    });
}
```

---

### Phase 4: Key Reconstruction

#### Sequence Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    KEY RECONSTRUCTION (On Device Only)                        │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Encrypted   │     │  Decrypted   │     │   Shamir's   │     │ Reconstructed│
│   Shares     │────>│   Shares     │────>│   Combine    │────>│  Private Key │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘

┌─────────────────────────────────────────┐
│ 1. Decrypt part_control                 │
│    (from backend, with session key)     │
│                                         │
│ 2. Already have part_recovery           │
│    (decrypted with recovery password)   │
│                                         │
│ 3. Combine using Shamir's algorithm:    │
│    user_private_key = SSS.combine(      │
│      part_recovery,                     │
│      part_control                       │
│    )                                    │
│                                         │
│ 4. Verify reconstructed key:            │
│    - Derive public key                  │
│    - Compare with stored public key     │
│    - If match: reconstruction success   │
└─────────────────────────────────────────┘
```

#### Client-Side: Reconstruct Private Key

```swift
// iOS - KeyReconstructor.swift
class KeyReconstructor {

    func reconstructPrivateKey(
        partRecovery: Data,
        partControl: Data,
        expectedPublicKey: Data,
        algorithm: PqcAlgorithm
    ) throws -> Data {

        // Step 1: Combine shares using Shamir's Secret Sharing
        let shares = [
            ShamirShare(index: 2, data: partControl),    // part_control was index 2
            ShamirShare(index: 3, data: partRecovery)    // part_recovery was index 3
        ]

        let reconstructedPrivateKey = try ShamirSecretSharing.combine(
            shares: shares,
            threshold: 2
        )

        // Step 2: Verify reconstruction by deriving public key
        let derivedPublicKey = try derivePublicKey(
            privateKey: reconstructedPrivateKey,
            algorithm: algorithm
        )

        // Step 3: Compare with expected public key
        guard derivedPublicKey == expectedPublicKey else {
            throw RecoveryError.keyReconstructionFailed(
                "Derived public key does not match expected"
            )
        }

        return reconstructedPrivateKey
    }

    private func derivePublicKey(
        privateKey: Data,
        algorithm: PqcAlgorithm
    ) throws -> Data {

        switch algorithm {
        case .kazSign128, .kazSign192, .kazSign256:
            return try KazSign.derivePublicKey(
                privateKey: privateKey,
                level: algorithm.securityLevel
            )
        case .mlDsa44, .mlDsa65, .mlDsa87:
            return try MlDsa.derivePublicKey(
                privateKey: privateKey,
                level: algorithm.securityLevel
            )
        }
    }
}
```

---

### Phase 5: New Device Setup

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  New Device  │          │   Key Vault  │
│          │          │  Digital ID  │          │   (Local)    │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │                       │ [KEY RECONSTRUCTION     │
     │                       │  COMPLETE]              │
     │                       │                         │
     │  1. Setup biometrics  │                         │
     │<──────────────────────│                         │
     │                       │                         │
     │  2. Authenticate      │                         │
     │     (Face ID/Touch)   │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │ 3. Generate new         │
     │                       │    device keypair       │
     │                       │                         │
     │                       │ 4. Store device         │
     │                       │    private key          │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │ 5. Store reconstructed  │
     │                       │    user private key     │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │ 6. Generate new         │
     │                       │    secret shares        │
     │                       │    (for future          │
     │                       │    recovery)            │
     │                       │                         │
     │                       │ 7. Generate new         │
     │                       │    device CSR           │
     │                       │                         │
```

#### Client-Side: Setup New Device

```swift
// iOS - DeviceSetupManager.swift
class DeviceSetupManager {

    func setupNewDevice(
        reconstructedUserPrivateKey: Data,
        userPublicKey: Data,
        algorithm: PqcAlgorithm,
        userId: String
    ) async throws -> DeviceSetupResult {

        // Step 1: Authenticate with biometrics
        let authenticated = try await BiometricAuth.authenticate(
            reason: "Setup your recovered Digital ID"
        )
        guard authenticated else {
            throw DeviceSetupError.biometricsFailed
        }

        // Step 2: Generate new device keypair
        let deviceKeyPair = try PqcKeyGenerator.generate(algorithm: algorithm)

        // Step 3: Store device private key in Keychain
        try KeychainManager.store(
            key: deviceKeyPair.privateKey,
            tag: "device-private-key-\(userId)",
            accessControl: .biometryCurrentSet
        )

        // Step 4: Store reconstructed user private key
        try KeychainManager.store(
            key: reconstructedUserPrivateKey,
            tag: "user-private-key-\(userId)",
            accessControl: .biometryCurrentSet
        )

        // Step 5: Generate new secret shares for future recovery
        let newShares = try SecretSharing.split(
            secret: reconstructedUserPrivateKey,
            threshold: 2,
            totalShares: 3
        )

        // Step 6: Encrypt shares (same as registration)
        let encryptedPartUser = try encryptWithDeviceKey(
            newShares.partUser,
            devicePublicKey: deviceKeyPair.publicKey
        )

        let encryptedPartRecovery = try encryptWithRecoveryPassword(
            newShares.partRecovery,
            // Note: User will be prompted to set new recovery password
            // or confirm existing one
        )

        // Step 7: Generate device CSR
        let deviceCsr = try CsrBuilder.build(
            publicKey: deviceKeyPair.publicKey,
            privateKey: deviceKeyPair.privateKey,
            subject: DeviceSubject(deviceId: UIDevice.current.identifierForVendor!),
            algorithm: algorithm
        )

        return DeviceSetupResult(
            deviceCsr: deviceCsr,
            devicePublicKey: deviceKeyPair.publicKey,
            encryptedPartUser: encryptedPartUser,
            encryptedPartRecovery: encryptedPartRecovery,
            encryptedPartControl: newShares.partControl // For backend
        )
    }
}
```

---

### Phase 6: Issue New Certificates

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────┐
│   New    │          │   Backend    │          │  Credential  │          │   HSM    │
│  Device  │          │     API      │          │   Manager    │          │          │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘          └────┬─────┘
     │                       │                         │                       │
     │  1. Submit recovery   │                         │                       │
     │     completion:       │                         │                       │
     │     - device_csr      │                         │                       │
     │     - encrypted_      │                         │                       │
     │       part_control    │                         │                       │
     │     - encrypted_      │                         │                       │
     │       part_recovery   │                         │                       │
     │────────────────────────────────────────────────>│                       │
     │                       │                         │                       │
     │                       │  2. Verify session      │                       │
     │                       │     is valid            │                       │
     │                       │                         │                       │
     │                       │  3. Store new           │                       │
     │                       │     encrypted shares    │                       │
     │                       │                         │                       │
     │                       │  4. Issue new device    │                       │
     │                       │     certificate         │                       │
     │                       │────────────────────────>│                       │
     │                       │                         │                       │
     │                       │                         │  5. Sign with         │
     │                       │                         │     Tenant CA         │
     │                       │                         │────────────────────────>
     │                       │                         │                       │
     │                       │                         │  6. Signature         │
     │                       │                         │<────────────────────────
     │                       │                         │                       │
     │                       │  7. Revoke old device   │                       │
     │                       │     certificate         │                       │
     │                       │────────────────────────>│                       │
     │                       │                         │                       │
     │  8. New device        │                         │                       │
     │     certificate       │                         │                       │
     │<────────────────────────────────────────────────│                       │
     │                       │                         │                       │
```

#### Backend: Complete Recovery

```csharp
public async Task<Result<RecoveryCompletionResult>> CompleteRecoveryAsync(
    CompleteRecoveryCommand cmd,
    CancellationToken ct = default)
{
    // Step 1: Verify session
    var session = await _recoveryRepository.GetSessionAsync(cmd.SessionId, ct);

    if (session?.Status != RecoveryStatus.PasswordVerified)
        return Result.Failure<RecoveryCompletionResult>("Invalid session");

    if (session.ExpiresAt < DateTime.UtcNow)
        return Result.Failure<RecoveryCompletionResult>("Session expired");

    // Step 2: Verify device CSR
    var csrValidation = await _csrValidator.ValidateAsync(cmd.DeviceCsr, ct);
    if (!csrValidation.IsValid)
        return Result.Failure<RecoveryCompletionResult>("Invalid device CSR");

    // Step 3: Update recovery data with new shares
    var recoveryData = await _recoveryRepository.GetByUserIdAsync(session.UserId, ct);
    recoveryData!.EncryptedPartControl = cmd.EncryptedPartControl;
    recoveryData.EncryptedPartRecovery = cmd.EncryptedPartRecovery;
    recoveryData.Nonce = cmd.Nonce;
    recoveryData.AuthTag = cmd.AuthTag;
    recoveryData.UpdatedAt = DateTime.UtcNow;

    await _recoveryRepository.UpdateAsync(recoveryData, ct);

    // Step 4: Issue new device certificate
    var deviceCert = await _certificateService.IssueCertificateAsync(
        new IssueCertificateCommand
        {
            TenantId = session.TenantId,
            UserId = session.UserId,
            DeviceId = session.NewDeviceId,
            Csr = cmd.DeviceCsr,
            Type = CertificateType.Device
        },
        ct);

    // Step 5: Revoke old device certificates
    var oldDevices = await _deviceRepository.GetByUserIdAsync(session.UserId, ct);
    foreach (var oldDevice in oldDevices.Where(d => d.Id != session.NewDeviceId))
    {
        await _certificateService.RevokeCertificateAsync(
            oldDevice.CertificateSerialNumber,
            RevocationReason.Superseded,
            "Account recovery - new device",
            ct);

        oldDevice.Status = DeviceStatus.Revoked;
        oldDevice.RevokedAt = DateTime.UtcNow;
    }
    await _deviceRepository.UpdateRangeAsync(oldDevices, ct);

    // Step 6: Register new device
    var newDevice = new UserDevice
    {
        Id = Guid.Parse(session.NewDeviceId),
        UserId = session.UserId,
        TenantId = session.TenantId,
        CertificateSerialNumber = deviceCert.SerialNumber,
        Status = DeviceStatus.Active,
        RegisteredAt = DateTime.UtcNow,
        Platform = cmd.Platform,
        DeviceName = cmd.DeviceName,
        IsPrimary = true
    };

    await _deviceRepository.CreateAsync(newDevice, ct);

    // Step 7: Update session
    session.Status = RecoveryStatus.Completed;
    session.CompletedAt = DateTime.UtcNow;
    await _recoveryRepository.UpdateSessionAsync(session, ct);

    // Step 8: Audit log
    await _auditService.LogAsync(new AuditEntry
    {
        TenantId = session.TenantId,
        UserId = session.UserId,
        Action = AuditAction.RecoveryCompleted,
        Details = new
        {
            SessionId = session.Id,
            NewDeviceId = newDevice.Id,
            RevokedDevices = oldDevices.Count
        }
    }, ct);

    // Step 9: Send notification email
    await _emailService.SendRecoveryCompletedAsync(
        session.Email,
        newDevice.DeviceName,
        oldDevices.Count,
        ct);

    return Result.Success(new RecoveryCompletionResult
    {
        DeviceCertificate = deviceCert.CertificateData,
        UserCertificate = await GetUserCertificateAsync(session.UserId, ct),
        CertificateChain = await GetCertificateChainAsync(session.TenantId, ct)
    });
}
```

---

### Phase 7 & 8: Activation and Completion

#### Sequence Diagram

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  New Device  │          │   Key Vault  │
│          │          │  Digital ID  │          │   (Local)    │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │                       │  1. Store new device    │
     │                       │     certificate         │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  2. Store user          │
     │                       │     certificate         │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  3. Store certificate   │
     │                       │     chain               │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │  4. Mark identity       │
     │                       │     as active           │
     │                       │────────────────────────>│
     │                       │                         │
     │  5. Show success      │                         │
     │     "Account          │                         │
     │      Recovered!"      │                         │
     │<──────────────────────│                         │
     │                       │                         │
     │  6. Prompt: Update    │                         │
     │     recovery password?│                         │
     │<──────────────────────│                         │
     │                       │                         │
     │  7. User decision     │                         │
     │──────────────────────>│                         │
     │                       │                         │
     │  8. Identity ready    │                         │
     │     for use           │                         │
     │<──────────────────────│                         │
     │                       │                         │
```

---

## Cryptographic Operations

### Algorithms Summary

| Operation | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Derivation | HKDF-SHA256 | Derive key from recovery password |
| Share Decryption | AES-256-GCM | Decrypt `part_recovery` |
| Share Encryption | AES-256-GCM | Re-encrypt shares for new device |
| Secret Sharing | Shamir's (2-of-3) | Combine shares to reconstruct key |
| Transport Encryption | ECDH + AES-GCM | Secure share transfer |
| CSR Signing | KAZ-SIGN / ML-DSA | Sign new device CSR |
| Certificate Signing | KAZ-SIGN / ML-DSA | CA signs new certificate |

### Key Derivation Parameters

```
Recovery Key = HKDF(
  algorithm: SHA-256,
  ikm: recovery_password (UTF-8 bytes),
  salt: user_id || "recovery-salt",
  info: "IdP-Recovery-v1",
  length: 32 bytes
)
```

---

## Security Measures

### Rate Limiting

| Action | Limit | Window | Lockout |
|--------|-------|--------|---------|
| Recovery initiation | 3 attempts | 1 hour | 24 hours |
| OTP verification | 5 attempts | Per session | Session invalidated |
| Password attempts | 5 attempts | Per session | Session invalidated |

### Session Security

- Sessions expire after 1 hour
- OTPs expire after 10 minutes
- Sessions bound to device ID
- Sessions bound to IP address (logged, not enforced)
- All session data encrypted at rest

### Notification Requirements

| Event | Notification |
|-------|--------------|
| Recovery initiated | Email to user |
| Recovery completed | Email to user + push to old devices |
| Old device revoked | Email confirmation |

### Audit Trail

| Event | Data Logged |
|-------|-------------|
| Recovery initiated | User ID, IP, Device ID, Timestamp |
| OTP sent | Email hash, Timestamp |
| OTP verified | Attempts count, Timestamp |
| Password verified | Timestamp (NOT the password) |
| Shares exchanged | Session ID, Timestamp |
| Recovery completed | New device ID, Revoked devices |

---

## Data Structures

### Recovery Session

```csharp
public class RecoverySession
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TenantId { get; set; }
    public string Email { get; set; } = "";
    public string NewDeviceId { get; set; } = "";

    public RecoveryStatus Status { get; set; }

    // OTP
    public string? OtpHash { get; set; }
    public DateTime? OtpExpiresAt { get; set; }
    public int OtpAttempts { get; set; }

    // Timestamps
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? EmailVerifiedAt { get; set; }
    public DateTime? PasswordVerifiedAt { get; set; }
    public DateTime? CompletedAt { get; set; }

    // Failure tracking
    public string? FailureReason { get; set; }

    // Context
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

public enum RecoveryStatus
{
    PendingEmailVerification,
    EmailVerified,
    PasswordVerified,
    Completed,
    Failed,
    Expired,
    Cancelled
}
```

### Recovery Data (Stored at Registration)

```csharp
public class UserRecoveryData
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TenantId { get; set; }

    // Encrypted shares
    public byte[] EncryptedPartControl { get; set; } = [];
    public string ControlKeyId { get; set; } = "";  // HSM key reference

    public byte[] EncryptedPartRecovery { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];

    // For verification
    public byte[] PartRecoveryHash { get; set; } = [];
    public byte[] UserPublicKey { get; set; } = [];

    public string Algorithm { get; set; } = "";

    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
}
```

---

## API Endpoints

### Initiate Recovery

```http
POST /api/v1/recovery/initiate
Content-Type: application/json

{
  "tenant_id": "uuid",
  "email": "user@example.com",
  "device_id": "new-device-uuid"
}

Response 200 OK:
{
  "session_id": "uuid",
  "otp_sent": true,
  "expires_at": "2025-12-01T13:00:00Z"
}
```

### Verify OTP

```http
POST /api/v1/recovery/{session_id}/verify-otp
Content-Type: application/json

{
  "otp": "847293"
}

Response 200 OK:
{
  "verified": true,
  "encrypted_part_recovery": "base64...",
  "nonce": "base64...",
  "auth_tag": "base64...",
  "algorithm": "KAZ-SIGN-128"
}
```

### Get Control Share

```http
POST /api/v1/recovery/{session_id}/control-share
Content-Type: application/json

{
  "proof_of_decrypt": "base64...",
  "client_public_key": "base64..."
}

Response 200 OK:
{
  "encrypted_part_control": "base64...",
  "nonce": "base64...",
  "auth_tag": "base64..."
}
```

### Complete Recovery

```http
POST /api/v1/recovery/{session_id}/complete
Content-Type: application/json

{
  "device_csr": "base64...",
  "encrypted_part_control": "base64...",
  "encrypted_part_recovery": "base64...",
  "nonce": "base64...",
  "auth_tag": "base64...",
  "device_name": "iPhone 15 Pro",
  "platform": "iOS"
}

Response 200 OK:
{
  "device_certificate": "base64...",
  "user_certificate": "base64...",
  "certificate_chain": ["base64...", "base64..."],
  "revoked_devices": 1
}
```

---

## Error Handling

### Error Codes

| Code | Description | User Action |
|------|-------------|-------------|
| `RECOVERY_001` | Invalid or expired session | Start recovery again |
| `RECOVERY_002` | Too many OTP attempts | Wait and try again |
| `RECOVERY_003` | OTP expired | Request new OTP |
| `RECOVERY_004` | Invalid OTP | Check code, try again |
| `RECOVERY_005` | Password verification failed | Check password |
| `RECOVERY_006` | Recovery not configured | Contact admin |
| `RECOVERY_007` | Rate limit exceeded | Wait 24 hours |
| `RECOVERY_008` | Account suspended | Contact admin |

### User-Friendly Messages

```json
{
  "RECOVERY_001": "Your recovery session has expired. Please start the recovery process again.",
  "RECOVERY_002": "Too many incorrect attempts. Please wait a few minutes and try again.",
  "RECOVERY_005": "The recovery password you entered is incorrect. Please try again.",
  "RECOVERY_007": "For security reasons, account recovery is temporarily locked. Please try again in 24 hours."
}
```

---

## Implementation Checklist

### Phase 1: Backend Infrastructure

- [ ] **Database Schema**
  - [ ] Create `recovery_sessions` table
  - [ ] Create `user_recovery_data` table
  - [ ] Add indexes for session lookup

- [ ] **Recovery Service**
  - [ ] Implement `InitiateRecoveryAsync`
  - [ ] Implement `VerifyOtpAsync`
  - [ ] Implement `GetControlShareAsync`
  - [ ] Implement `CompleteRecoveryAsync`

- [ ] **Security**
  - [ ] Implement rate limiting
  - [ ] Implement session management
  - [ ] Add audit logging

### Phase 2: Email Integration

- [ ] **Email Templates**
  - [ ] Recovery OTP email
  - [ ] Recovery completed email
  - [ ] Device revoked notification

- [ ] **Email Service**
  - [ ] Integrate with email provider
  - [ ] Implement OTP sending
  - [ ] Add email logging

### Phase 3: Mobile Implementation

- [ ] **Recovery UI**
  - [ ] Recovery initiation screen
  - [ ] OTP entry screen
  - [ ] Password entry screen
  - [ ] Success/failure screens

- [ ] **Crypto Operations**
  - [ ] HKDF key derivation
  - [ ] AES-GCM decryption
  - [ ] Shamir's combine
  - [ ] Key verification

- [ ] **Device Setup**
  - [ ] Biometric setup
  - [ ] Key generation
  - [ ] CSR generation
  - [ ] Certificate storage

### Phase 4: Testing

- [ ] **Unit Tests**
  - [ ] Secret sharing combine
  - [ ] Key derivation
  - [ ] Session management

- [ ] **Integration Tests**
  - [ ] Full recovery flow
  - [ ] Error scenarios
  - [ ] Rate limiting

- [ ] **Security Tests**
  - [ ] Brute force protection
  - [ ] Session hijacking
  - [ ] Timing attacks

---

## References

- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Registration and secret sharing setup
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Certificate issuance details
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
