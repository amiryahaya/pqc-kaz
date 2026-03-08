# App Attestation and Device Integrity Verification

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Development vs Production](#development-vs-production)
3. [Platform Attestation Services](#platform-attestation-services)
4. [Development Phase Approach](#development-phase-approach)
5. [Production Phase Implementation](#production-phase-implementation)
6. [Backend Verification Service](#backend-verification-service)
7. [Implementation Checklist](#implementation-checklist)
8. [Risk Assessment Matrix](#risk-assessment-matrix)

---

## Overview

### The Problem

How do we ensure that:
1. **Only the genuine app** can communicate with our backend API?
2. **The device is not compromised** (jailbroken/rooted)?
3. **The app has not been modified** (tampered/repackaged)?
4. **Requests are not coming from emulators** or automated tools?

### The Solution: Layered Security

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LAYERED SECURITY MODEL                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 1: Platform Attestation (Production Only)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ iOS App     │  │ Android     │  │ Windows     │  │ macOS App   │        │
│  │ Attest      │  │ Play        │  │ Health      │  │ Attest      │        │
│  │             │  │ Integrity   │  │ Attestation │  │             │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 2: Request Signing (Always Active)                                   │
│  • All requests signed with device private key                              │
│  • Timestamp + nonce to prevent replay attacks                              │
│  • Request body hash included in signature                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 3: Certificate Pinning (Always Active)                               │
│  • Pin backend API certificate                                              │
│  • Prevent MITM attacks                                                     │
│  • Certificate rotation strategy                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 4: Runtime Protection (Always Active)                                │
│  • Debugger detection                                                       │
│  • Hooking framework detection (Frida, Xposed)                             │
│  • Code integrity checks                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 5: Backend Risk Assessment (Always Active)                           │
│  • Behavioral analysis                                                      │
│  • Rate limiting                                                            │
│  • Anomaly detection                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Development vs Production

### Key Differences

| Aspect | Development | Production |
|--------|-------------|------------|
| **Platform Attestation** | Bypassed/Mocked | Enforced |
| **App Distribution** | Sideloaded/TestFlight/Internal | App Store/Play Store |
| **Certificate Pinning** | Optional (debug certs) | Required |
| **Device Checks** | Disabled | Enabled |
| **Emulator Access** | Allowed | Blocked |
| **Debug Builds** | Allowed | Blocked |

### Why Platform Attestation Requires App Store

| Platform | Requirement | Reason |
|----------|-------------|--------|
| **iOS App Attest** | App Store or TestFlight | Apple signs the attestation key during app installation from trusted source |
| **Android Play Integrity** | Play Store | Google verifies app signature matches Play Store listing |
| **Windows** | Microsoft Store or MSIX signed | Windows verifies package signature |

---

## Platform Attestation Services

### iOS: App Attest (DeviceCheck Framework)

**Requirements:**
- iOS 14.0+
- App distributed via App Store or TestFlight
- Entitlement: `com.apple.developer.devicecheck.appattest-environment`

**What It Verifies:**
- App is the genuine, unmodified version
- App was installed from App Store
- Device has not been compromised (jailbreak detection)
- Unique device/app combination

**Flow:**
```
┌──────────┐          ┌──────────┐          ┌──────────┐          ┌──────────┐
│   App    │          │  Apple   │          │ Backend  │          │  Apple   │
│          │          │ Servers  │          │   API    │          │ Servers  │
└────┬─────┘          └────┬─────┘          └────┬─────┘          └────┬─────┘
     │                     │                     │                     │
     │ 1. generateKey()    │                     │                     │
     │────────────────────>│                     │                     │
     │                     │                     │                     │
     │ 2. keyId            │                     │                     │
     │<────────────────────│                     │                     │
     │                     │                     │                     │
     │ 3. Request challenge│                     │                     │
     │──────────────────────────────────────────>│                     │
     │                     │                     │                     │
     │ 4. challenge (nonce)│                     │                     │
     │<──────────────────────────────────────────│                     │
     │                     │                     │                     │
     │ 5. attestKey(keyId, │                     │                     │
     │    clientDataHash)  │                     │                     │
     │────────────────────>│                     │                     │
     │                     │                     │                     │
     │ 6. attestation      │                     │                     │
     │    object           │                     │                     │
     │<────────────────────│                     │                     │
     │                     │                     │                     │
     │ 7. Send attestation │                     │                     │
     │──────────────────────────────────────────>│                     │
     │                     │                     │                     │
     │                     │                     │ 8. Verify with Apple│
     │                     │                     │────────────────────>│
     │                     │                     │                     │
     │                     │                     │ 9. Valid/Invalid    │
     │                     │                     │<────────────────────│
     │                     │                     │                     │
```

**Attestation Contains:**
- Certificate chain (rooted to Apple)
- App ID hash
- Public key hash
- Counter (for fraud detection)
- Environment (production/development)

---

### Android: Play Integrity API

**Requirements:**
- Android 5.0+ (API 21+)
- Google Play Services
- App distributed via Google Play Store
- Play Console integration

**What It Verifies:**
- **App Integrity:** Genuine, unmodified app from Play Store
- **Device Integrity:** Device passes Android compatibility tests, not rooted
- **Account Integrity:** User has valid Google Play license

**Verdict Levels:**

| Verdict | Meaning | Trust Level |
|---------|---------|-------------|
| `MEETS_STRONG_INTEGRITY` | Hardware-backed attestation, device not compromised | Highest |
| `MEETS_DEVICE_INTEGRITY` | Passes CTS, Google Play certified | High |
| `MEETS_BASIC_INTEGRITY` | May be rooted but passes basic checks | Low |
| (empty) | Failed all checks | None |

**Flow:**
```
┌──────────┐          ┌──────────┐          ┌──────────┐          ┌──────────┐
│   App    │          │  Google  │          │ Backend  │          │  Google  │
│          │          │  Play    │          │   API    │          │  Servers │
└────┬─────┘          └────┬─────┘          └────┬─────┘          └────┬─────┘
     │                     │                     │                     │
     │ 1. Request nonce    │                     │                     │
     │──────────────────────────────────────────>│                     │
     │                     │                     │                     │
     │ 2. nonce            │                     │                     │
     │<──────────────────────────────────────────│                     │
     │                     │                     │                     │
     │ 3. requestIntegrity │                     │                     │
     │    Token(nonce)     │                     │                     │
     │────────────────────>│                     │                     │
     │                     │                     │                     │
     │ 4. integrity token  │                     │                     │
     │<────────────────────│                     │                     │
     │                     │                     │                     │
     │ 5. Send token       │                     │                     │
     │──────────────────────────────────────────>│                     │
     │                     │                     │                     │
     │                     │                     │ 6. Decrypt & verify │
     │                     │                     │────────────────────>│
     │                     │                     │                     │
     │                     │                     │ 7. Verdict payload  │
     │                     │                     │<────────────────────│
     │                     │                     │                     │
```

---

### Windows: Device Health Attestation

**Requirements:**
- Windows 10/11
- TPM 2.0
- Secure Boot enabled
- MSIX signed package or Microsoft Store

**What It Verifies:**
- Secure Boot state
- BitLocker status
- Code integrity
- TPM attestation

---

### macOS: App Attest

**Requirements:**
- macOS 11.0+
- App notarized by Apple
- Distributed via App Store or notarized DMG

**Similar to iOS App Attest but for macOS apps.**

---

## Development Phase Approach

### Strategy: Conditional Attestation

During development, attestation is **bypassed** but **other security layers remain active**.

### Configuration

```csharp
// appsettings.Development.json
{
  "Security": {
    "Attestation": {
      "Enabled": false,           // Disabled in development
      "AllowEmulators": true,     // Allow emulators
      "AllowDebugBuilds": true,   // Allow debug builds
      "RequireSignedRequests": true,  // Still require request signing
      "BypassToken": "dev-bypass-token-xxx"  // Optional bypass for testing
    }
  }
}

// appsettings.Production.json
{
  "Security": {
    "Attestation": {
      "Enabled": true,
      "AllowEmulators": false,
      "AllowDebugBuilds": false,
      "RequireSignedRequests": true,
      "BypassToken": null,
      "iOS": {
        "AppId": "TEAMID.com.company.idp",
        "Environment": "production"
      },
      "Android": {
        "PackageName": "com.company.idp",
        "RequiredVerdict": "MEETS_DEVICE_INTEGRITY"
      }
    }
  }
}
```

### Development Bypass Header

```http
POST /api/v1/register HTTP/1.1
Host: api.dev.idp.local
X-Dev-Bypass: dev-bypass-token-xxx
X-Request-Signature: <signature>
Content-Type: application/json

{ ... }
```

### What Remains Active in Development

| Security Layer | Development | Notes |
|----------------|-------------|-------|
| Request Signing | **Active** | All requests must be signed |
| Certificate Pinning | Optional | Can use self-signed certs |
| Debugger Detection | **Disabled** | Allow debugging |
| Emulator Detection | **Disabled** | Allow simulators |
| Rate Limiting | **Active** | Prevent abuse |
| Input Validation | **Active** | Always validate |

---

## Production Phase Implementation

### iOS Implementation

```swift
import DeviceCheck

class AttestationService {
    private let attestService = DCAppAttestService.shared

    func performAttestation(challenge: Data) async throws -> Data {
        // Check if App Attest is supported
        guard attestService.isSupported else {
            throw AttestationError.notSupported
        }

        // Generate or retrieve key
        let keyId = try await getOrCreateAttestKey()

        // Create client data hash (challenge + request hash)
        let clientDataHash = SHA256.hash(data: challenge)

        // Generate attestation
        let attestation = try await attestService.attestKey(
            keyId,
            clientDataHash: Data(clientDataHash)
        )

        return attestation
    }

    func generateAssertion(
        keyId: String,
        requestData: Data
    ) async throws -> Data {
        let clientDataHash = SHA256.hash(data: requestData)

        return try await attestService.generateAssertion(
            keyId,
            clientDataHash: Data(clientDataHash)
        )
    }

    private func getOrCreateAttestKey() async throws -> String {
        if let existingKeyId = KeychainService.getAttestKeyId() {
            return existingKeyId
        }

        let keyId = try await attestService.generateKey()
        KeychainService.saveAttestKeyId(keyId)
        return keyId
    }
}
```

### Android Implementation

```kotlin
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

class AttestationService(private val context: Context) {

    private val integrityManager = IntegrityManagerFactory.create(context)

    suspend fun requestIntegrityToken(nonce: String): String {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()

        return suspendCoroutine { continuation ->
            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    continuation.resume(response.token())
                }
                .addOnFailureListener { exception ->
                    continuation.resumeWithException(exception)
                }
        }
    }
}
```

### Backend Verification

```csharp
public class AttestationVerificationService : IAttestationVerificationService
{
    private readonly IiOSAttestationVerifier _iosVerifier;
    private readonly IAndroidAttestationVerifier _androidVerifier;
    private readonly AttestationOptions _options;

    public async Task<AttestationResult> VerifyAsync(
        AttestationPayload payload,
        CancellationToken ct = default)
    {
        // Development bypass
        if (!_options.Enabled)
        {
            return AttestationResult.Bypassed("Development mode");
        }

        return payload.Platform switch
        {
            Platform.iOS => await _iosVerifier.VerifyAsync(payload, ct),
            Platform.Android => await _androidVerifier.VerifyAsync(payload, ct),
            Platform.Windows => await _windowsVerifier.VerifyAsync(payload, ct),
            Platform.macOS => await _macOSVerifier.VerifyAsync(payload, ct),
            _ => AttestationResult.Failed("Unknown platform")
        };
    }
}
```

---

## Backend Verification Service

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ATTESTATION VERIFICATION SERVICE                        │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   API Request   │
                              │  + Attestation  │
                              └────────┬────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │      Attestation Middleware          │
                    │                                      │
                    │  1. Extract attestation header       │
                    │  2. Validate format                  │
                    │  3. Check cache                      │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────┴───────────────────┐
                    │                                      │
                    ▼                                      ▼
        ┌───────────────────┐                  ┌───────────────────┐
        │  iOS Verifier     │                  │ Android Verifier  │
        │                   │                  │                   │
        │ • Decode CBOR     │                  │ • Decrypt token   │
        │ • Verify cert     │                  │ • Verify with     │
        │   chain           │                  │   Google API      │
        │ • Check App ID    │                  │ • Check verdict   │
        │ • Validate nonce  │                  │ • Check package   │
        └─────────┬─────────┘                  └─────────┬─────────┘
                  │                                      │
                  └──────────────────┬───────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────────┐
                    │         Risk Assessment              │
                    │                                      │
                    │  • Device reputation                 │
                    │  • Request patterns                  │
                    │  • Anomaly detection                 │
                    └──────────────────┬───────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │         Decision Engine              │
                    │                                      │
                    │  Allow │ Challenge │ Block │ Flag    │
                    └──────────────────────────────────────┘
```

### Verification Results

```csharp
public record AttestationResult
{
    public bool IsValid { get; init; }
    public AttestationStatus Status { get; init; }
    public string? FailureReason { get; init; }
    public DeviceIntegrityLevel IntegrityLevel { get; init; }
    public Dictionary<string, object> Metadata { get; init; } = new();

    // Risk score (0-100, higher = more risky)
    public int RiskScore { get; init; }
}

public enum AttestationStatus
{
    Valid,
    Bypassed,      // Development mode
    Invalid,
    Expired,
    NotSupported,
    Failed
}

public enum DeviceIntegrityLevel
{
    Unknown,
    Basic,         // Passes basic checks only
    Standard,      // Passes device integrity
    Strong,        // Hardware-backed attestation
    Compromised    // Known to be compromised
}
```

---

## Implementation Checklist

### Phase 1: Development (No App Store Required)

#### Backend Tasks

- [ ] **Create Attestation Configuration**
  - [ ] Add `AttestationOptions` to configuration
  - [ ] Implement development bypass logic
  - [ ] Add `X-Dev-Bypass` header handling

- [ ] **Implement Request Signing**
  - [ ] Create `IRequestSigningService` interface
  - [ ] Implement signature verification middleware
  - [ ] Add nonce/timestamp validation (prevent replay)

- [ ] **Add Rate Limiting**
  - [ ] Implement per-device rate limiting
  - [ ] Add suspicious activity detection
  - [ ] Create rate limit response handling

- [ ] **Implement Certificate Pinning Support**
  - [ ] Document expected certificate hashes
  - [ ] Create certificate rotation strategy
  - [ ] Add pinning bypass for development

#### Mobile Tasks

- [ ] **Implement Request Signing**
  - [ ] Sign all API requests with device private key
  - [ ] Include timestamp and nonce in signature
  - [ ] Hash request body in signature

- [ ] **Add Development Bypass**
  - [ ] Read bypass token from config
  - [ ] Add bypass header in debug builds only
  - [ ] Log when bypass is used

- [ ] **Prepare Attestation Stubs**
  - [ ] Create `IAttestationService` interface
  - [ ] Implement mock attestation for development
  - [ ] Add feature flag for attestation

---

### Phase 2: TestFlight/Internal Testing (Partial Attestation)

#### iOS Tasks

- [ ] **Enable App Attest (TestFlight)**
  - [ ] Add App Attest entitlement
  - [ ] Implement `DCAppAttestService` integration
  - [ ] Handle attestation in development environment
  - [ ] Test key generation flow

- [ ] **Test Attestation Flow**
  - [ ] Verify attestation object format
  - [ ] Test with backend verification
  - [ ] Handle attestation failures gracefully

#### Android Tasks

- [ ] **Prepare Play Integrity (Internal Track)**
  - [ ] Register app in Play Console
  - [ ] Upload internal track build
  - [ ] Configure Play Integrity API
  - [ ] Test with internal testers

#### Backend Tasks

- [ ] **Implement iOS Attestation Verifier**
  - [ ] Parse CBOR attestation object
  - [ ] Verify Apple certificate chain
  - [ ] Validate App ID and environment
  - [ ] Cache attestation results

- [ ] **Implement Android Attestation Verifier**
  - [ ] Integrate with Google Play Integrity API
  - [ ] Decrypt and verify token
  - [ ] Check verdict levels
  - [ ] Handle partial verdicts

---

### Phase 3: Production Release (Full Attestation)

#### Pre-Release Checklist

- [ ] **App Store Submission (iOS)**
  - [ ] Ensure App Attest entitlement is enabled
  - [ ] Test attestation on TestFlight
  - [ ] Verify backend handles production environment

- [ ] **Play Store Submission (Android)**
  - [ ] Configure Play Integrity for production
  - [ ] Set required verdict level
  - [ ] Test with production track

- [ ] **Backend Configuration**
  - [ ] Enable attestation enforcement
  - [ ] Disable development bypass
  - [ ] Configure production App IDs/Package names
  - [ ] Set up monitoring and alerting

#### Production Tasks

- [ ] **Enable Full Attestation**
  - [ ] Set `Attestation.Enabled = true`
  - [ ] Set `AllowEmulators = false`
  - [ ] Set `AllowDebugBuilds = false`
  - [ ] Remove bypass tokens

- [ ] **Implement Fallback Handling**
  - [ ] Handle attestation service outages
  - [ ] Implement graceful degradation
  - [ ] Add manual review queue for edge cases

- [ ] **Monitoring and Alerting**
  - [ ] Alert on high attestation failure rates
  - [ ] Monitor for bypass attempts
  - [ ] Track device integrity trends

---

### Phase 4: Ongoing Security

#### Continuous Tasks

- [ ] **Monitor Attestation Bypass Techniques**
  - [ ] Track new jailbreak/root methods
  - [ ] Update detection logic as needed
  - [ ] Subscribe to security advisories

- [ ] **Certificate Rotation**
  - [ ] Plan certificate rotation schedule
  - [ ] Test rotation with staged rollout
  - [ ] Update pinned certificates in apps

- [ ] **Regular Security Audits**
  - [ ] Penetration testing
  - [ ] Review attestation logs
  - [ ] Update risk assessment rules

---

## Risk Assessment Matrix

### Request Risk Scoring

| Factor | Low Risk (0-20) | Medium Risk (21-50) | High Risk (51-100) |
|--------|-----------------|---------------------|---------------------|
| **Attestation** | Strong integrity | Basic integrity | Failed/Missing |
| **Request Pattern** | Normal | Unusual timing | Automated/Burst |
| **Device History** | Known good | New device | Known bad |
| **Geo Location** | Expected region | New region | Impossible travel |
| **Request Signing** | Valid signature | Expired timestamp | Invalid/Missing |

### Action Based on Risk Score

| Risk Score | Action | Example |
|------------|--------|---------|
| 0-20 | Allow | Normal user on verified device |
| 21-40 | Allow + Monitor | New device, first registration |
| 41-60 | Challenge | Request additional verification |
| 61-80 | Rate Limit | Suspicious patterns detected |
| 81-100 | Block | Known compromised device |

---

## Summary

### What's Required for Each Phase

| Phase | App Store? | Attestation | Bypass Allowed |
|-------|------------|-------------|----------------|
| Development | No | Mocked | Yes |
| TestFlight/Internal | Partial | Partial | Limited |
| Production | Yes | Full | No |

### Key Takeaways

1. **Don't skip request signing** - This works without app stores
2. **Build attestation infrastructure early** - Mock it in development
3. **Plan for graceful degradation** - Attestation services can fail
4. **Layer your defenses** - No single security measure is sufficient
5. **Monitor and adapt** - Attackers evolve, so should your defenses

---

## References

- [Apple App Attest Documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity)
- [Android Play Integrity API](https://developer.android.com/google/play/integrity)
- [OWASP Mobile Security Guide](https://owasp.org/www-project-mobile-security/)
- [NIST SP 800-163 - Mobile Application Vetting](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
