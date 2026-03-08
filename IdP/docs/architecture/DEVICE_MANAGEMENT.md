# Device Management Flow

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Device Lifecycle](#device-lifecycle)
3. [Device Registration](#device-registration)
4. [Device Listing & Status](#device-listing--status)
5. [Add Secondary Device](#add-secondary-device)
6. [Device Transfer](#device-transfer)
7. [Device Removal](#device-removal)
8. [Device Suspension](#device-suspension)
9. [Lost Device Handling](#lost-device-handling)
10. [Device Limits & Policies](#device-limits--policies)
11. [Data Structures](#data-structures)
12. [API Reference](#api-reference)
13. [Mobile App Implementation](#mobile-app-implementation)
14. [Admin Portal](#admin-portal)
15. [Security Considerations](#security-considerations)
16. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

Device Management enables users to manage the devices linked to their Digital ID. This includes:

- **Viewing registered devices** - See all devices linked to identity
- **Adding new devices** - Register additional phones/tablets
- **Transferring identity** - Move primary device to new phone
- **Removing devices** - Deauthorize old or compromised devices
- **Handling lost devices** - Emergency revocation procedures

### Key Principles

1. **Multi-Device Support** - Users can have multiple registered devices
2. **Primary Device Designation** - One device is primary for sensitive operations
3. **Device-Bound Keys** - Each device has unique cryptographic keys
4. **Certificate Per Device** - Separate device certificate for each
5. **User Private Key Shared** - User's identity key accessible from any device
6. **Instant Revocation** - Compromised devices can be revoked immediately

### Device Types

| Type | Description | Capabilities |
|------|-------------|--------------|
| **Primary** | Main device, full capabilities | All operations, manage other devices |
| **Secondary** | Additional device, limited | Authentication, signing (configurable) |
| **Backup** | Offline recovery device | Recovery only, no active use |

---

## Device Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DEVICE LIFECYCLE                                    │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────┐
                              │   Initial   │
                              │Registration │
                              └──────┬──────┘
                                     │
                                     ▼
┌──────────────┐            ┌─────────────┐            ┌──────────────┐
│   Pending    │───────────>│   Active    │<───────────│  Suspended   │
│  Approval    │            │             │            │              │
└──────────────┘            └──────┬──────┘            └──────────────┘
                                   │                          ▲
                    ┌──────────────┼──────────────┐           │
                    │              │              │           │
                    ▼              ▼              ▼           │
             ┌───────────┐  ┌───────────┐  ┌───────────┐     │
             │ Suspended │  │  Revoked  │  │ Transferred│     │
             │           │──┤           │  │           │─────┘
             └───────────┘  └───────────┘  └───────────┘
                                   │
                                   ▼
                            ┌───────────┐
                            │  Deleted  │
                            └───────────┘

States:
- Pending: Awaiting admin/user approval
- Active: Fully operational
- Suspended: Temporarily disabled
- Revoked: Permanently disabled, certificate revoked
- Transferred: Identity moved to new device
- Deleted: Removed from system
```

---

## Device Registration

### Initial Registration (During User Onboarding)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INITIAL DEVICE REGISTRATION                               │
│                  (Part of User Registration Flow)                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐          ┌──────────────┐          ┌──────────────┐
│   User   │          │  Digital ID  │          │   Backend    │
│          │          │     App      │          │              │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  1. Start registration│                         │
     │──────────────────────>│                         │
     │                       │                         │
     │                       │  2. Generate device     │
     │                       │     keypair             │
     │                       │                         │
     │                       │  3. Collect device info │
     │                       │     - Model             │
     │                       │     - OS version        │
     │                       │     - Device ID         │
     │                       │     - Push token        │
     │                       │                         │
     │                       │  4. Create device CSR   │
     │                       │                         │
     │                       │  5. Submit registration │
     │                       │     with device info    │
     │                       │────────────────────────>│
     │                       │                         │
     │                       │                         │  6. Verify CSR
     │                       │                         │  7. Issue device cert
     │                       │                         │  8. Create device record
     │                       │                         │     (Primary = true)
     │                       │                         │
     │                       │  9. Device certificate  │
     │                       │     + user certificate  │
     │                       │<────────────────────────│
     │                       │                         │
     │                       │  10. Store certificates │
     │                       │      in Keychain        │
     │                       │                         │
     │  11. Registration     │                         │
     │      complete!        │                         │
     │<──────────────────────│                         │
     │                       │                         │
```

### Device Information Collected

```swift
// iOS - DeviceInfo.swift
struct DeviceInfo: Codable {
    // Hardware
    let deviceId: String           // identifierForVendor
    let model: String              // e.g., "iPhone 15 Pro"
    let modelIdentifier: String    // e.g., "iPhone16,1"
    let manufacturer: String       // "Apple"

    // Software
    let osName: String             // "iOS"
    let osVersion: String          // "17.1"
    let appVersion: String         // "1.0.0"
    let appBuildNumber: String     // "100"

    // Security
    let isJailbroken: Bool         // Jailbreak detection result
    let hasSecureEnclave: Bool     // Device supports SE
    let biometricType: String      // "faceId", "touchId", "none"

    // Push notifications
    let pushToken: String?         // APNS/FCM token

    // Display name (user can customize)
    var displayName: String        // "John's iPhone"

    static func collect() -> DeviceInfo {
        return DeviceInfo(
            deviceId: UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString,
            model: getDeviceModel(),
            modelIdentifier: getModelIdentifier(),
            manufacturer: "Apple",
            osName: UIDevice.current.systemName,
            osVersion: UIDevice.current.systemVersion,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "",
            appBuildNumber: Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "",
            isJailbroken: JailbreakDetector.isJailbroken(),
            hasSecureEnclave: SecureEnclave.isAvailable(),
            biometricType: BiometricAuth.availableType().rawValue,
            pushToken: PushManager.shared.currentToken,
            displayName: "\(getOwnerName())'s \(getDeviceModel())"
        )
    }
}
```

---

## Device Listing & Status

### View All Devices

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MY DEVICES                                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  📱 John's iPhone 15 Pro                                    ⭐ PRIMARY      │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Status: Active                                                             │
│  Last used: Just now                                                        │
│  Registered: December 1, 2025                                               │
│  iOS 17.1 • San Francisco, CA                                               │
│                                                                             │
│  [Rename]  [Remove]                                                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  📱 John's iPad Pro                                         SECONDARY       │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Status: Active                                                             │
│  Last used: 2 hours ago                                                     │
│  Registered: November 15, 2025                                              │
│  iPadOS 17.1 • San Francisco, CA                                            │
│                                                                             │
│  [Make Primary]  [Rename]  [Remove]                                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  📱 Old iPhone 13                                           SUSPENDED       │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Status: Suspended (reported lost)                                          │
│  Last used: 3 days ago                                                      │
│  Registered: March 10, 2024                                                 │
│  iOS 16.5 • Unknown location                                                │
│                                                                             │
│  [Reactivate]  [Remove Permanently]                                         │
└─────────────────────────────────────────────────────────────────────────────┘

                        [+ Add New Device]
```

### Device Status API

```csharp
// Backend - DeviceService.cs
public class DeviceService : IDeviceService
{
    public async Task<Result<List<DeviceDto>>> GetUserDevicesAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        var devices = await _deviceRepository.GetByUserIdAsync(userId, ct);

        var deviceDtos = devices.Select(d => new DeviceDto
        {
            Id = d.Id,
            DisplayName = d.DisplayName,
            Model = d.Model,
            Platform = d.Platform,
            OsVersion = d.OsVersion,
            Status = d.Status,
            IsPrimary = d.IsPrimary,
            RegisteredAt = d.RegisteredAt,
            LastUsedAt = d.LastUsedAt,
            LastUsedLocation = d.LastUsedLocation,
            CertificateExpiresAt = d.CertificateExpiresAt,
            Capabilities = GetDeviceCapabilities(d)
        }).ToList();

        return Result.Success(deviceDtos);
    }

    private DeviceCapabilities GetDeviceCapabilities(UserDevice device)
    {
        return new DeviceCapabilities
        {
            CanAuthenticate = device.Status == DeviceStatus.Active,
            CanSign = device.Status == DeviceStatus.Active &&
                      (device.IsPrimary || device.AllowSigning),
            CanManageDevices = device.IsPrimary,
            CanApproveRecovery = device.IsPrimary,
            CanReceivePush = !string.IsNullOrEmpty(device.PushToken)
        };
    }
}
```

---

## Add Secondary Device

### QR-Based Device Addition

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADD SECONDARY DEVICE FLOW                                 │
└─────────────────────────────────────────────────────────────────────────────┘

Primary Device              Backend                    New Device
      │                        │                           │
      │  1. Request add        │                           │
      │     device QR          │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │  2. Generate pairing   │                           │
      │     session            │                           │
      │<───────────────────────│                           │
      │                        │                           │
      │  3. Display QR code    │                           │
      │─────────┐              │                           │
      │         │              │                           │
      │<────────┘              │                           │
      │                        │                           │
      │              4. User scans QR on new device        │
      │─────────────────────────────────────────────────────>
      │                        │                           │
      │                        │  5. Validate pairing      │
      │                        │     session               │
      │                        │<──────────────────────────│
      │                        │                           │
      │                        │  6. Return user info      │
      │                        │     + pairing challenge   │
      │                        │──────────────────────────>│
      │                        │                           │
      │                        │                           │  7. Generate
      │                        │                           │     device keypair
      │                        │                           │
      │                        │                           │  8. Create
      │                        │                           │     device CSR
      │                        │                           │
      │                        │  9. Submit CSR +          │
      │                        │     device info           │
      │                        │<──────────────────────────│
      │                        │                           │
      │  10. Push notification │                           │
      │      "Approve new      │                           │
      │       device?"         │                           │
      │<───────────────────────│                           │
      │                        │                           │
      │  11. User reviews      │                           │
      │      new device info   │                           │
      │                        │                           │
      │  12. Approve with      │                           │
      │      biometric         │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │                        │  13. Issue device cert    │
      │                        │  14. Transfer user key    │
      │                        │      share (encrypted)    │
      │                        │                           │
      │                        │  15. Device certificate   │
      │                        │      + encrypted key share│
      │                        │──────────────────────────>│
      │                        │                           │
      │                        │                           │  16. Store certs
      │                        │                           │      + key share
      │                        │                           │
      │  17. "New device       │                           │
      │       added!"          │                           │
      │<───────────────────────│                           │
      │                        │                           │
```

### Primary Device: Initiate Pairing

```swift
// iOS - DevicePairingManager.swift (Primary Device)
class DevicePairingManager {

    func initiateDevicePairing() async throws -> PairingSession {
        // Step 1: Request pairing session from backend
        let session = try await apiClient.createDevicePairingSession(
            request: CreatePairingSessionRequest(
                initiatorDeviceId: currentDeviceId,
                expiresInSeconds: 300  // 5 minutes
            )
        )

        // Step 2: Generate QR code data
        let qrData = DevicePairingQr(
            type: "idp_device_pairing",
            version: "1",
            sessionId: session.sessionId,
            userId: currentUserId,
            userName: currentUserName,
            tenantId: currentTenantId,
            tenantName: currentTenantName,
            expires: session.expiresAt.timeIntervalSince1970,
            challenge: session.challenge,
            checksum: calculateChecksum(session)
        )

        return PairingSession(
            sessionId: session.sessionId,
            qrData: qrData.encoded(),
            expiresAt: session.expiresAt,
            webSocketUrl: session.webSocketUrl
        )
    }

    func approveDevicePairing(
        sessionId: String,
        newDeviceInfo: DeviceInfo
    ) async throws {
        // Authenticate with biometrics
        let authenticated = try await BiometricAuth.authenticate(
            reason: "Approve new device: \(newDeviceInfo.displayName)"
        )

        guard authenticated else {
            throw PairingError.biometricsFailed
        }

        // Load user's private key
        let userPrivateKey = try KeychainManager.loadKey(
            tag: "user-private-key-\(currentUserId)",
            accessControl: .biometryCurrentSet
        )

        // Encrypt part_user for new device
        let encryptedKeyShare = try await encryptKeyShareForDevice(
            keyShare: try loadPartUser(),
            newDevicePublicKey: newDeviceInfo.publicKey
        )

        // Sign approval
        let approval = DevicePairingApproval(
            sessionId: sessionId,
            newDeviceId: newDeviceInfo.deviceId,
            approverDeviceId: currentDeviceId,
            encryptedKeyShare: encryptedKeyShare,
            timestamp: Date()
        )

        let signature = try sign(approval.canonicalBytes, with: userPrivateKey)

        // Submit approval
        try await apiClient.approveDevicePairing(
            sessionId: sessionId,
            approval: approval,
            signature: signature
        )
    }
}
```

### New Device: Complete Pairing

```swift
// iOS - DevicePairingManager.swift (New Device)
class DevicePairingManager {

    func handlePairingQrCode(_ qrData: DevicePairingQr) async throws {
        // Step 1: Validate QR data
        guard qrData.isChecksumValid else {
            throw PairingError.invalidQrCode
        }

        guard qrData.expires > Date().timeIntervalSince1970 else {
            throw PairingError.expired
        }

        // Step 2: Generate device keypair
        let deviceKeyPair = try PqcKeyGenerator.generate(
            algorithm: .kazSign128  // Will be updated based on tenant config
        )

        // Step 3: Collect device info
        var deviceInfo = DeviceInfo.collect()
        deviceInfo.publicKey = deviceKeyPair.publicKey

        // Step 4: Create device CSR
        let deviceCsr = try CsrBuilder.build(
            publicKey: deviceKeyPair.publicKey,
            privateKey: deviceKeyPair.privateKey,
            subject: DeviceSubject(deviceId: deviceInfo.deviceId),
            algorithm: .kazSign128
        )

        // Step 5: Submit to backend for approval
        let response = try await apiClient.submitDevicePairing(
            sessionId: qrData.sessionId,
            request: DevicePairingRequest(
                deviceInfo: deviceInfo,
                deviceCsr: deviceCsr,
                challenge: qrData.challenge
            )
        )

        // Step 6: Wait for approval from primary device
        showWaitingForApproval(userName: qrData.userName)

        let approvalResult = try await waitForApproval(
            sessionId: qrData.sessionId,
            webSocketUrl: response.webSocketUrl
        )

        // Step 7: Store certificates and key share
        try KeychainManager.store(
            key: deviceKeyPair.privateKey,
            tag: "device-private-key-\(qrData.userId)",
            accessControl: .biometryCurrentSet
        )

        try KeychainManager.storeCertificate(
            approvalResult.deviceCertificate,
            tag: "device-certificate-\(qrData.userId)"
        )

        try KeychainManager.storeCertificate(
            approvalResult.userCertificate,
            tag: "user-certificate-\(qrData.userId)"
        )

        // Step 8: Decrypt and store key share
        let decryptedKeyShare = try decryptKeyShare(
            approvalResult.encryptedKeyShare,
            devicePrivateKey: deviceKeyPair.privateKey
        )

        try KeychainManager.store(
            key: decryptedKeyShare,
            tag: "user-key-share-\(qrData.userId)",
            accessControl: .biometryCurrentSet
        )

        // Step 9: Complete setup
        showSuccess("Device added successfully!")
    }
}
```

### Backend: Device Pairing Service

```csharp
// Backend - DevicePairingService.cs
public class DevicePairingService : IDevicePairingService
{
    public async Task<Result<PairingSession>> CreatePairingSessionAsync(
        CreatePairingSessionCommand cmd,
        CancellationToken ct = default)
    {
        // Verify initiator device is primary
        var initiatorDevice = await _deviceRepository.GetAsync(cmd.InitiatorDeviceId, ct);
        if (initiatorDevice is null || !initiatorDevice.IsPrimary)
            return Result.Failure<PairingSession>("Only primary device can add new devices");

        // Check device limit
        var existingDevices = await _deviceRepository.GetByUserIdAsync(
            initiatorDevice.UserId, ct);

        var tenant = await _tenantRepository.GetAsync(initiatorDevice.TenantId, ct);
        if (existingDevices.Count >= tenant!.MaxDevicesPerUser)
            return Result.Failure<PairingSession>(
                $"Maximum devices ({tenant.MaxDevicesPerUser}) reached");

        // Create pairing session
        var session = new DevicePairingSession
        {
            Id = Guid.NewGuid(),
            UserId = initiatorDevice.UserId,
            TenantId = initiatorDevice.TenantId,
            InitiatorDeviceId = cmd.InitiatorDeviceId,
            Challenge = GenerateSecureChallenge(),
            Status = PairingStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(cmd.ExpiresInSeconds)
        };

        await _pairingRepository.CreateAsync(session, ct);

        return Result.Success(new PairingSession
        {
            SessionId = session.Id.ToString(),
            Challenge = session.Challenge,
            ExpiresAt = session.ExpiresAt,
            WebSocketUrl = $"wss://{_config.Host}/ws/pairing/{session.Id}"
        });
    }

    public async Task<Result<PairingCompletionResult>> CompletePairingAsync(
        CompletePairingCommand cmd,
        CancellationToken ct = default)
    {
        var session = await _pairingRepository.GetAsync(cmd.SessionId, ct);

        if (session?.Status != PairingStatus.Approved)
            return Result.Failure<PairingCompletionResult>("Session not approved");

        // Issue device certificate
        var deviceCert = await _certificateService.IssueCertificateAsync(
            new IssueCertificateCommand
            {
                TenantId = session.TenantId,
                UserId = session.UserId,
                DeviceId = cmd.NewDeviceId,
                Csr = cmd.DeviceCsr,
                Type = CertificateType.Device
            }, ct);

        // Get user certificate (same for all devices)
        var userCert = await _certificateRepository.GetActiveUserCertAsync(
            session.UserId, ct);

        // Create device record
        var newDevice = new UserDevice
        {
            Id = Guid.Parse(cmd.NewDeviceId),
            UserId = session.UserId,
            TenantId = session.TenantId,
            DisplayName = cmd.DeviceInfo.DisplayName,
            Model = cmd.DeviceInfo.Model,
            Platform = cmd.DeviceInfo.OsName,
            OsVersion = cmd.DeviceInfo.OsVersion,
            CertificateSerialNumber = deviceCert.SerialNumber,
            Status = DeviceStatus.Active,
            IsPrimary = false,
            AllowSigning = false,  // Admin can enable later
            RegisteredAt = DateTime.UtcNow,
            PushToken = cmd.DeviceInfo.PushToken
        };

        await _deviceRepository.CreateAsync(newDevice, ct);

        // Update session
        session.Status = PairingStatus.Completed;
        session.NewDeviceId = newDevice.Id;
        session.CompletedAt = DateTime.UtcNow;
        await _pairingRepository.UpdateAsync(session, ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = session.TenantId,
            UserId = session.UserId,
            Action = AuditAction.DeviceAdded,
            Details = new
            {
                NewDeviceId = newDevice.Id,
                DeviceName = newDevice.DisplayName,
                InitiatorDeviceId = session.InitiatorDeviceId
            }
        }, ct);

        // Notify all devices
        await _pushService.SendToUserAsync(session.UserId,
            new PushNotification
            {
                Title = "New Device Added",
                Body = $"{newDevice.DisplayName} was added to your account",
                Data = new { type = "device_added", deviceId = newDevice.Id }
            }, ct);

        return Result.Success(new PairingCompletionResult
        {
            DeviceCertificate = deviceCert.CertificateData,
            UserCertificate = userCert!.CertificateData,
            CertificateChain = await GetCertificateChainAsync(session.TenantId, ct),
            EncryptedKeyShare = session.EncryptedKeyShare
        });
    }
}
```

---

## Device Transfer

### Transfer Primary to New Device

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DEVICE TRANSFER FLOW                                      │
│              (When old device is still accessible)                           │
└─────────────────────────────────────────────────────────────────────────────┘

Old Primary Device          Backend                    New Device
      │                        │                           │
      │  1. Initiate transfer  │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │  2. Transfer session   │                           │
      │     + QR code          │                           │
      │<───────────────────────│                           │
      │                        │                           │
      │  3. Display QR         │                           │
      │     "Scan to transfer  │                           │
      │      your Digital ID"  │                           │
      │                        │                           │
      │              4. Scan QR on new device              │
      │─────────────────────────────────────────────────────>
      │                        │                           │
      │                        │                           │  5. Generate
      │                        │                           │     device keypair
      │                        │                           │
      │                        │  6. Submit new device CSR │
      │                        │<──────────────────────────│
      │                        │                           │
      │  7. Confirm transfer   │                           │
      │     request            │                           │
      │<───────────────────────│                           │
      │                        │                           │
      │  8. Approve transfer   │                           │
      │     (biometric)        │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │                        │                           │
      │  9. Export all keys    │                           │
      │     and data           │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │                        │  10. Issue new cert       │
      │                        │  11. Revoke old cert      │
      │                        │  12. Transfer encrypted   │
      │                        │      user private key     │
      │                        │                           │
      │                        │  13. Complete transfer    │
      │                        │      data                 │
      │                        │──────────────────────────>│
      │                        │                           │
      │                        │                           │  14. Import keys
      │                        │                           │      and data
      │                        │                           │
      │  15. Local data        │                           │
      │      wiped             │                           │
      │<───────────────────────│                           │
      │                        │                           │
      │                        │  16. Transfer complete    │
      │                        │──────────────────────────>│
      │                        │                           │
```

### Transfer Data Structure

```csharp
public class DeviceTransferData
{
    // User identity
    public byte[] EncryptedUserPrivateKey { get; set; } = [];
    public byte[] EncryptedPartUser { get; set; } = [];
    public string UserCertificate { get; set; } = "";

    // New device
    public string NewDeviceCertificate { get; set; } = "";
    public string[] CertificateChain { get; set; } = [];

    // Encryption details
    public byte[] EncapsulatedKey { get; set; } = [];  // KEM for new device
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];

    // User data (optional)
    public byte[]? EncryptedPreferences { get; set; }
    public byte[]? EncryptedContacts { get; set; }
}
```

---

## Device Removal

### User-Initiated Removal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DEVICE REMOVAL FLOW                                       │
└─────────────────────────────────────────────────────────────────────────────┘

Current Device              Backend                    Removed Device
(Primary)                      │                       (if online)
      │                        │                           │
      │  1. Request remove     │                           │
      │     device [id]        │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │  2. Confirm prompt     │                           │
      │     "Remove iPhone 13?"│                           │
      │<───────────────────────│                           │
      │                        │                           │
      │  3. Confirm with       │                           │
      │     biometric          │                           │
      │───────────────────────>│                           │
      │                        │                           │
      │                        │  4. Revoke device         │
      │                        │     certificate           │
      │                        │                           │
      │                        │  5. Update device         │
      │                        │     status = Revoked      │
      │                        │                           │
      │                        │  6. Push: "Device         │
      │                        │     removed"              │
      │                        │──────────────────────────>│
      │                        │                           │
      │                        │                           │  7. Wipe local
      │                        │                           │     identity data
      │                        │                           │
      │  8. Success            │                           │
      │<───────────────────────│                           │
      │                        │                           │
```

### Backend: Remove Device

```csharp
public class DeviceService : IDeviceService
{
    public async Task<Result> RemoveDeviceAsync(
        RemoveDeviceCommand cmd,
        CancellationToken ct = default)
    {
        // Get device to remove
        var targetDevice = await _deviceRepository.GetAsync(cmd.DeviceIdToRemove, ct);
        if (targetDevice is null)
            return Result.Failure("Device not found");

        // Verify requestor owns this device
        if (targetDevice.UserId != cmd.RequestingUserId)
            return Result.Failure("Not authorized");

        // Cannot remove primary device if other devices exist
        if (targetDevice.IsPrimary)
        {
            var otherDevices = await _deviceRepository.GetByUserIdAsync(
                targetDevice.UserId, ct);

            if (otherDevices.Any(d => d.Id != targetDevice.Id &&
                                      d.Status == DeviceStatus.Active))
            {
                return Result.Failure(
                    "Transfer primary to another device before removing");
            }
        }

        // Revoke certificate
        await _certificateService.RevokeCertificateAsync(
            targetDevice.CertificateSerialNumber,
            RevocationReason.CessationOfOperation,
            "Device removed by user",
            ct);

        // Update device status
        targetDevice.Status = DeviceStatus.Revoked;
        targetDevice.RevokedAt = DateTime.UtcNow;
        targetDevice.RevokedReason = "User initiated removal";
        await _deviceRepository.UpdateAsync(targetDevice, ct);

        // Invalidate any active sessions for this device
        await _sessionService.InvalidateDeviceSessionsAsync(targetDevice.Id, ct);

        // Send push to removed device (if online)
        await _pushService.SendToDeviceAsync(targetDevice.Id,
            new PushNotification
            {
                Title = "Device Removed",
                Body = "This device has been removed from your Digital ID",
                Data = new { type = "device_removed", action = "wipe" }
            }, ct);

        // Notify other devices
        await _pushService.SendToUserAsync(targetDevice.UserId,
            new PushNotification
            {
                Title = "Device Removed",
                Body = $"{targetDevice.DisplayName} was removed from your account",
                Data = new { type = "device_removed", deviceId = targetDevice.Id }
            },
            excludeDeviceId: targetDevice.Id,
            ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = targetDevice.TenantId,
            UserId = targetDevice.UserId,
            Action = AuditAction.DeviceRemoved,
            Details = new
            {
                RemovedDeviceId = targetDevice.Id,
                DeviceName = targetDevice.DisplayName,
                RequestingDeviceId = cmd.RequestingDeviceId
            }
        }, ct);

        return Result.Success();
    }
}
```

---

## Device Suspension

### Temporary Suspension

```csharp
public async Task<Result> SuspendDeviceAsync(
    SuspendDeviceCommand cmd,
    CancellationToken ct = default)
{
    var device = await _deviceRepository.GetAsync(cmd.DeviceId, ct);
    if (device is null)
        return Result.Failure("Device not found");

    if (device.Status != DeviceStatus.Active)
        return Result.Failure("Device is not active");

    // Suspend (don't revoke certificate yet)
    device.Status = DeviceStatus.Suspended;
    device.SuspendedAt = DateTime.UtcNow;
    device.SuspendedReason = cmd.Reason;
    device.SuspendedBy = cmd.SuspendedBy;  // User ID or "admin" or "system"

    await _deviceRepository.UpdateAsync(device, ct);

    // Invalidate active sessions
    await _sessionService.InvalidateDeviceSessionsAsync(device.Id, ct);

    // Push notification
    await _pushService.SendToDeviceAsync(device.Id,
        new PushNotification
        {
            Title = "Device Suspended",
            Body = "Your Digital ID on this device has been temporarily suspended",
            Data = new { type = "device_suspended" }
        }, ct);

    return Result.Success();
}

public async Task<Result> ReactivateDeviceAsync(
    ReactivateDeviceCommand cmd,
    CancellationToken ct = default)
{
    var device = await _deviceRepository.GetAsync(cmd.DeviceId, ct);
    if (device?.Status != DeviceStatus.Suspended)
        return Result.Failure("Device is not suspended");

    // Check if certificate is still valid
    var cert = await _certificateRepository.GetBySerialAsync(
        device.CertificateSerialNumber, ct);

    if (cert is null || cert.Status != CertificateStatus.Active)
        return Result.Failure("Device certificate is no longer valid");

    // Reactivate
    device.Status = DeviceStatus.Active;
    device.SuspendedAt = null;
    device.SuspendedReason = null;
    device.SuspendedBy = null;
    device.ReactivatedAt = DateTime.UtcNow;

    await _deviceRepository.UpdateAsync(device, ct);

    // Notify device
    await _pushService.SendToDeviceAsync(device.Id,
        new PushNotification
        {
            Title = "Device Reactivated",
            Body = "Your Digital ID on this device has been reactivated",
            Data = new { type = "device_reactivated" }
        }, ct);

    return Result.Success();
}
```

---

## Lost Device Handling

### Emergency Device Lockout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LOST DEVICE FLOW                                          │
└─────────────────────────────────────────────────────────────────────────────┘

Option 1: From Another Device
─────────────────────────────
1. Open Digital ID app on another registered device
2. Go to Settings → My Devices
3. Find lost device, tap "Report Lost"
4. Confirm with biometric
5. Device immediately suspended + certificate revoked

Option 2: From Web Portal
─────────────────────────
1. Go to https://id.example.com/emergency
2. Login with recovery credentials (email + recovery password)
3. Select lost device
4. Confirm identity via email OTP
5. Device immediately suspended + certificate revoked

Option 3: Contact Admin
───────────────────────
1. Contact organization IT admin
2. Admin suspends device from admin portal
3. User receives confirmation email
```

### Lost Device Handler

```csharp
public class LostDeviceHandler : ILostDeviceHandler
{
    public async Task<Result> ReportLostDeviceAsync(
        ReportLostDeviceCommand cmd,
        CancellationToken ct = default)
    {
        var device = await _deviceRepository.GetAsync(cmd.DeviceId, ct);
        if (device is null)
            return Result.Failure("Device not found");

        // Immediate actions
        var tasks = new List<Task>
        {
            // 1. Revoke certificate
            _certificateService.RevokeCertificateAsync(
                device.CertificateSerialNumber,
                RevocationReason.KeyCompromise,
                "Device reported lost/stolen",
                ct),

            // 2. Invalidate all sessions
            _sessionService.InvalidateDeviceSessionsAsync(device.Id, ct),

            // 3. Invalidate all tokens
            _tokenService.RevokeDeviceTokensAsync(device.Id, ct)
        };

        await Task.WhenAll(tasks);

        // Update device status
        device.Status = DeviceStatus.Revoked;
        device.RevokedAt = DateTime.UtcNow;
        device.RevokedReason = $"Reported lost/stolen: {cmd.Reason}";
        device.ReportedLostAt = DateTime.UtcNow;
        device.ReportedLostBy = cmd.ReportedBy;

        await _deviceRepository.UpdateAsync(device, ct);

        // If this was primary device, handle recovery
        if (device.IsPrimary)
        {
            // Promote another device to primary if available
            var otherDevices = await _deviceRepository.GetByUserIdAsync(
                device.UserId, ct);

            var newPrimary = otherDevices
                .Where(d => d.Id != device.Id && d.Status == DeviceStatus.Active)
                .OrderByDescending(d => d.LastUsedAt)
                .FirstOrDefault();

            if (newPrimary != null)
            {
                newPrimary.IsPrimary = true;
                await _deviceRepository.UpdateAsync(newPrimary, ct);

                await _pushService.SendToDeviceAsync(newPrimary.Id,
                    new PushNotification
                    {
                        Title = "You're Now Primary",
                        Body = "Your device is now the primary device for your Digital ID",
                        Data = new { type = "promoted_to_primary" }
                    }, ct);
            }
        }

        // Send notification to all other devices
        await _pushService.SendToUserAsync(device.UserId,
            new PushNotification
            {
                Title = "Device Reported Lost",
                Body = $"{device.DisplayName} has been locked and revoked",
                Data = new { type = "device_lost", deviceId = device.Id }
            },
            excludeDeviceId: device.Id,
            ct);

        // Send email confirmation
        var user = await _userRepository.GetAsync(device.UserId, ct);
        await _emailService.SendLostDeviceConfirmationAsync(
            user!.Email,
            device.DisplayName,
            DateTime.UtcNow,
            ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = device.TenantId,
            UserId = device.UserId,
            Action = AuditAction.DeviceReportedLost,
            Severity = AuditSeverity.High,
            Details = new
            {
                DeviceId = device.Id,
                DeviceName = device.DisplayName,
                ReportedBy = cmd.ReportedBy,
                Reason = cmd.Reason
            }
        }, ct);

        return Result.Success();
    }
}
```

---

## Device Limits & Policies

### Tenant Device Policies

```csharp
public class TenantDevicePolicy
{
    public int MaxDevicesPerUser { get; set; } = 5;
    public int MaxPrimaryDevices { get; set; } = 1;

    public bool AllowSecondaryDeviceSigning { get; set; } = false;
    public bool RequireAdminApprovalForNewDevices { get; set; } = false;
    public bool AllowSelfServiceDeviceRemoval { get; set; } = true;

    public TimeSpan DeviceInactivityTimeout { get; set; } = TimeSpan.FromDays(90);
    public bool AutoSuspendInactiveDevices { get; set; } = true;

    public string[] AllowedPlatforms { get; set; } = { "iOS", "Android", "macOS", "Windows" };
    public string? MinimumOsVersion { get; set; }

    public bool RequireDeviceAttestation { get; set; } = true;
    public bool AllowJailbrokenDevices { get; set; } = false;
}
```

### Policy Enforcement

```csharp
public class DevicePolicyEnforcer : IDevicePolicyEnforcer
{
    public async Task<Result> ValidateNewDeviceAsync(
        DeviceInfo deviceInfo,
        Guid tenantId,
        CancellationToken ct = default)
    {
        var policy = await _policyRepository.GetDevicePolicyAsync(tenantId, ct);
        var errors = new List<string>();

        // Platform check
        if (!policy.AllowedPlatforms.Contains(deviceInfo.OsName))
            errors.Add($"Platform {deviceInfo.OsName} is not allowed");

        // OS version check
        if (!string.IsNullOrEmpty(policy.MinimumOsVersion))
        {
            if (!MeetsMinimumVersion(deviceInfo.OsVersion, policy.MinimumOsVersion))
                errors.Add($"OS version {deviceInfo.OsVersion} is below minimum required");
        }

        // Jailbreak check
        if (!policy.AllowJailbrokenDevices && deviceInfo.IsJailbroken)
            errors.Add("Jailbroken/rooted devices are not allowed");

        // Attestation check
        if (policy.RequireDeviceAttestation && !deviceInfo.HasValidAttestation)
            errors.Add("Device attestation is required");

        if (errors.Any())
            return Result.Failure(string.Join("; ", errors));

        return Result.Success();
    }
}
```

---

## Data Structures

### Device Entity

```csharp
public class UserDevice
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TenantId { get; set; }

    // Device info
    public string DisplayName { get; set; } = "";
    public string Model { get; set; } = "";
    public string ModelIdentifier { get; set; } = "";
    public string Platform { get; set; } = "";  // iOS, Android, etc.
    public string OsVersion { get; set; } = "";
    public string AppVersion { get; set; } = "";

    // Status
    public DeviceStatus Status { get; set; }
    public bool IsPrimary { get; set; }
    public bool AllowSigning { get; set; }

    // Certificate
    public string CertificateSerialNumber { get; set; } = "";
    public DateTime CertificateExpiresAt { get; set; }

    // Push notifications
    public string? PushToken { get; set; }
    public string? PushPlatform { get; set; }  // apns, fcm

    // Timestamps
    public DateTime RegisteredAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? LastUsedLocation { get; set; }
    public string? LastUsedIpAddress { get; set; }

    // Suspension/Revocation
    public DateTime? SuspendedAt { get; set; }
    public string? SuspendedReason { get; set; }
    public string? SuspendedBy { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    public DateTime? ReportedLostAt { get; set; }
    public string? ReportedLostBy { get; set; }

    // Security
    public bool HasSecureEnclave { get; set; }
    public string BiometricType { get; set; } = "";
    public byte[]? AttestationData { get; set; }

    // Navigation
    public User User { get; set; } = null!;
    public Tenant Tenant { get; set; } = null!;
}

public enum DeviceStatus
{
    PendingApproval,
    Active,
    Suspended,
    Revoked
}
```

---

## API Reference

### List User Devices

```http
GET /api/v1/devices
Authorization: Bearer <access-token>

Response 200 OK:
{
  "devices": [
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

### Create Pairing Session

```http
POST /api/v1/devices/pairing
Authorization: Bearer <access-token>

{
  "expires_in_seconds": 300
}

Response 201 Created:
{
  "session_id": "uuid",
  "qr_data": "idp://device-pairing?data=...",
  "qr_image_url": "/api/v1/devices/pairing/{session_id}/qr.png",
  "expires_at": "2025-12-01T12:05:00Z",
  "ws_url": "wss://idp.example.com/ws/pairing/{session_id}"
}
```

### Submit Device for Pairing

```http
POST /api/v1/devices/pairing/{session_id}/submit
Content-Type: application/json

{
  "device_info": {
    "device_id": "uuid",
    "model": "iPad Pro",
    "platform": "iPadOS",
    "os_version": "17.1",
    "display_name": "John's iPad"
  },
  "device_csr": "base64...",
  "public_key": "base64..."
}

Response 202 Accepted:
{
  "status": "pending_approval",
  "ws_url": "wss://idp.example.com/ws/pairing/{session_id}"
}
```

### Approve Device Pairing

```http
POST /api/v1/devices/pairing/{session_id}/approve
Authorization: Bearer <access-token>

{
  "encrypted_key_share": "base64...",
  "signature": "base64..."
}

Response 200 OK:
{
  "status": "approved",
  "device_id": "uuid"
}
```

### Remove Device

```http
DELETE /api/v1/devices/{device_id}
Authorization: Bearer <access-token>

Response 204 No Content
```

### Report Device Lost

```http
POST /api/v1/devices/{device_id}/report-lost
Authorization: Bearer <access-token>

{
  "reason": "Phone stolen"
}

Response 200 OK:
{
  "status": "revoked",
  "revoked_at": "2025-12-01T12:00:00Z"
}
```

### Update Device

```http
PATCH /api/v1/devices/{device_id}
Authorization: Bearer <access-token>

{
  "display_name": "Work iPhone"
}

Response 200 OK:
{
  "id": "uuid",
  "display_name": "Work iPhone",
  ...
}
```

### Make Device Primary

```http
POST /api/v1/devices/{device_id}/make-primary
Authorization: Bearer <access-token>

Response 200 OK:
{
  "id": "uuid",
  "is_primary": true,
  "previous_primary_id": "uuid"
}
```

---

## Admin Portal

### Admin Device Management

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ADMIN PORTAL - USER DEVICES                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  User: John Doe (john.doe@example.com)                                       │
│  Organization: Example Corp                                                  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ DEVICES (2 of 5)                                          [+ Add Device]││
│  ├─────────────────────────────────────────────────────────────────────────┤│
│  │                                                                         ││
│  │  📱 iPhone 15 Pro              ⭐ PRIMARY    ● ACTIVE                   ││
│  │     iOS 17.1 • Last seen: Just now                                      ││
│  │     Certificate: Valid until Dec 1, 2026                                ││
│  │     [Suspend] [Revoke] [View Logs]                                      ││
│  │                                                                         ││
│  │  📱 iPad Pro                   SECONDARY     ● ACTIVE                   ││
│  │     iPadOS 17.1 • Last seen: 2 hours ago                                ││
│  │     Certificate: Valid until Nov 15, 2026                               ││
│  │     [Suspend] [Revoke] [Enable Signing] [View Logs]                     ││
│  │                                                                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  DEVICE ACTIVITY LOG                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 2025-12-01 12:00:00  iPhone 15 Pro   Authenticated to Example App       ││
│  │ 2025-12-01 11:45:00  iPhone 15 Pro   Signed document                    ││
│  │ 2025-12-01 10:30:00  iPad Pro        Authenticated to Portal            ││
│  │ 2025-12-01 09:00:00  iPhone 15 Pro   Certificate renewed                ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Unauthorized device addition | Primary device approval + biometric required |
| Lost/stolen device | Immediate revocation, certificate invalidation |
| Device impersonation | Device certificates, attestation |
| Key extraction | Secure Enclave, hardware-backed keys |
| Session replay | Device binding, token invalidation |

### Audit Events

| Event | Severity | Data Logged |
|-------|----------|-------------|
| Device added | Medium | New device info, approver |
| Device removed | Medium | Device info, remover |
| Device suspended | High | Reason, suspended by |
| Device revoked | High | Reason, revoked by |
| Device reported lost | Critical | Reason, reporter, actions taken |
| Primary changed | High | Old primary, new primary |
| Pairing attempted | Low | Session info, result |

---

## Implementation Checklist

### Phase 1: Core Device Management

- [ ] **Device Entity & Repository**
  - [ ] Database schema
  - [ ] CRUD operations
  - [ ] Status management

- [ ] **Device Service**
  - [ ] List devices
  - [ ] Update device info
  - [ ] Change primary device

### Phase 2: Device Addition

- [ ] **Pairing Flow**
  - [ ] Create pairing session
  - [ ] QR code generation
  - [ ] WebSocket notifications
  - [ ] Approval flow

- [ ] **Key Transfer**
  - [ ] Encrypt key share for new device
  - [ ] Secure transfer protocol

### Phase 3: Device Removal & Security

- [ ] **Removal Flow**
  - [ ] User-initiated removal
  - [ ] Admin-initiated removal
  - [ ] Certificate revocation

- [ ] **Lost Device**
  - [ ] Emergency lockout
  - [ ] Session invalidation
  - [ ] Notification system

### Phase 4: Policies & Admin

- [ ] **Device Policies**
  - [ ] Policy configuration
  - [ ] Policy enforcement
  - [ ] Inactive device handling

- [ ] **Admin Portal**
  - [ ] Device listing
  - [ ] Suspension/revocation
  - [ ] Activity logs

---

## References

- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Initial device registration
- [ACCOUNT_RECOVERY_FLOW.md](./ACCOUNT_RECOVERY_FLOW.md) - Recovery when device lost
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Device certificate management
