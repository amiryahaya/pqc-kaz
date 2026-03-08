# Digital ID Authentication Flow (OIDC/OAuth 2.0)

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication Methods](#authentication-methods)
3. [OIDC Protocol Flow](#oidc-protocol-flow)
4. [Mobile App Authentication](#mobile-app-authentication)
5. [Web Browser Authentication](#web-browser-authentication)
6. [QR Code Authentication](#qr-code-authentication)
7. [Token Management](#token-management)
8. [PQC Signature Integration](#pqc-signature-integration)
9. [Security Considerations](#security-considerations)
10. [API Endpoints](#api-endpoints)
11. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

This document describes how users authenticate to **Relying Party (RP) applications** using their Digital ID. The IdP implements OpenID Connect (OIDC) built on OAuth 2.0, with Post-Quantum Cryptography (PQC) extensions.

### Key Features

- **OIDC Compliant** - Standard OpenID Connect 1.0 protocol
- **PQC Signatures** - ID tokens signed with PQC algorithms (KAZ-SIGN, ML-DSA)
- **Passwordless** - Biometric authentication on user's device
- **Device Binding** - Authentication tied to registered device
- **Multi-Factor by Design** - Device possession + biometric
- **Cross-Platform** - Mobile app, web browser, QR code flows

### Protocol Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                           │
│                   (Relying Party Apps)                           │
├─────────────────────────────────────────────────────────────────┤
│                      OIDC / OAuth 2.0                            │
│         Authorization Code Flow + PKCE + PAR                     │
├─────────────────────────────────────────────────────────────────┤
│                    PQC SIGNATURE LAYER                           │
│              KAZ-SIGN / ML-DSA for ID Tokens                     │
├─────────────────────────────────────────────────────────────────┤
│                      TRANSPORT LAYER                             │
│                  TLS 1.3 (Hybrid PQC optional)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Authentication Methods

### Method 1: Mobile App (Primary)

```
User has Digital ID app on their device
→ RP redirects to IdP
→ IdP deep links to Digital ID app
→ User authenticates with biometrics
→ App signs assertion with user's PQC private key
→ IdP issues tokens
→ User redirected back to RP
```

### Method 2: Web Browser with QR Code

```
User on desktop/laptop without Digital ID
→ RP redirects to IdP
→ IdP shows QR code
→ User scans with Digital ID app
→ User authenticates on phone
→ Desktop browser receives tokens
→ User redirected back to RP
```

### Method 3: Same Device Browser (Mobile)

```
User on mobile browser
→ RP redirects to IdP
→ IdP app selector or universal link
→ Digital ID app opens
→ User authenticates
→ Browser receives callback
→ User redirected back to RP
```

---

## OIDC Protocol Flow

### Authorization Code Flow with PKCE + PAR

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   OIDC AUTHORIZATION CODE FLOW + PKCE + PAR                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User   │     │ Relying Party│     │     IdP      │     │  Digital ID  │
│          │     │    (RP)      │     │   Backend    │     │     App      │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │                    │
     │ 1. Access RP     │                    │                    │
     │─────────────────>│                    │                    │
     │                  │                    │                    │
     │                  │ 2. PAR Request     │                    │
     │                  │ (client_id,        │                    │
     │                  │  code_challenge,   │                    │
     │                  │  redirect_uri,     │                    │
     │                  │  scope, state)     │                    │
     │                  │───────────────────>│                    │
     │                  │                    │                    │
     │                  │ 3. request_uri     │                    │
     │                  │<───────────────────│                    │
     │                  │                    │                    │
     │ 4. Redirect to   │                    │                    │
     │    /authorize?   │                    │                    │
     │    request_uri=  │                    │                    │
     │<─────────────────│                    │                    │
     │                  │                    │                    │
     │ 5. Navigate to IdP                    │                    │
     │──────────────────────────────────────>│                    │
     │                  │                    │                    │
     │                  │                    │ 6. Trigger app     │
     │                  │                    │    authentication  │
     │                  │                    │───────────────────>│
     │                  │                    │                    │
     │                  │                    │ 7. Show auth       │
     │                  │                    │    request         │
     │                  │                    │<───────────────────│
     │                  │                    │                    │
     │ 8. Biometric     │                    │                    │
     │    prompt        │                    │                    │
     │<───────────────────────────────────────────────────────────│
     │                  │                    │                    │
     │ 9. Authenticate  │                    │                    │
     │    (Face ID)     │                    │                    │
     │────────────────────────────────────────────────────────────>
     │                  │                    │                    │
     │                  │                    │ 10. Sign assertion │
     │                  │                    │     with PQC key   │
     │                  │                    │<───────────────────│
     │                  │                    │                    │
     │                  │                    │ 11. Verify sig,    │
     │                  │                    │     generate code  │
     │                  │                    │                    │
     │ 12. Redirect to  │                    │                    │
     │     RP callback  │                    │                    │
     │     with code    │                    │                    │
     │<──────────────────────────────────────│                    │
     │                  │                    │                    │
     │ 13. Callback     │                    │                    │
     │    with code     │                    │                    │
     │─────────────────>│                    │                    │
     │                  │                    │                    │
     │                  │ 14. Token Request  │                    │
     │                  │ (code,             │                    │
     │                  │  code_verifier)    │                    │
     │                  │───────────────────>│                    │
     │                  │                    │                    │
     │                  │ 15. Tokens         │                    │
     │                  │ (id_token,         │                    │
     │                  │  access_token,     │                    │
     │                  │  refresh_token)    │                    │
     │                  │<───────────────────│                    │
     │                  │                    │                    │
     │ 16. Authenticated│                    │                    │
     │<─────────────────│                    │                    │
     │                  │                    │                    │
```

### PAR (Pushed Authorization Request)

PAR is **required** for enhanced security:

```http
POST /oauth/par HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

client_id=rp-client-123
&response_type=code
&redirect_uri=https://rp.example.com/callback
&scope=openid profile email
&state=abc123
&nonce=xyz789
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&acr_values=urn:idp:pqc:kaz-sign-128

Response:
{
  "request_uri": "urn:idp:par:12345678-1234-1234-1234-123456789012",
  "expires_in": 60
}
```

### Authorization Endpoint

```http
GET /oauth/authorize?request_uri=urn:idp:par:12345678-1234-1234-1234-123456789012
Host: idp.example.com
```

---

## Mobile App Authentication

### Deep Link Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MOBILE APP AUTHENTICATION                             │
└─────────────────────────────────────────────────────────────────────────────┘

1. IdP generates authentication request
2. IdP redirects to Universal Link / App Link:
   idp://auth?
     session_id=xxx
     &rp_name=Example%20App
     &rp_logo=https://...
     &scopes=openid,profile
     &acr=pqc:kaz-sign-128

3. Digital ID app receives deep link
4. App validates request with IdP backend
5. App shows authentication consent screen
```

### App Authentication Screen

```
┌─────────────────────────────────────┐
│                                     │
│         [RP Logo]                   │
│                                     │
│    "Example App" wants to           │
│    verify your identity             │
│                                     │
│    This app will receive:           │
│    ✓ Your name                      │
│    ✓ Your email                     │
│    ✓ Your organization              │
│                                     │
│    Signing with: KAZ-SIGN-128       │
│                                     │
│  ┌─────────────────────────────┐    │
│  │     [Authenticate]          │    │
│  │     Use Face ID             │    │
│  └─────────────────────────────┘    │
│                                     │
│         [Cancel]                    │
│                                     │
└─────────────────────────────────────┘
```

### Client-Side Authentication

```swift
// iOS - AuthenticationManager.swift
class AuthenticationManager {

    func handleAuthRequest(_ url: URL) async throws -> AuthResult {
        // Step 1: Parse deep link
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let sessionId = components.queryItems?.first(where: { $0.name == "session_id" })?.value
        else {
            throw AuthError.invalidRequest
        }

        // Step 2: Fetch request details from IdP
        let authRequest = try await fetchAuthRequest(sessionId: sessionId)

        // Step 3: Validate request
        try validateAuthRequest(authRequest)

        // Step 4: Show consent UI and wait for user
        let userConsent = try await showConsentUI(
            rpName: authRequest.rpName,
            rpLogo: authRequest.rpLogo,
            scopes: authRequest.scopes
        )

        guard userConsent.approved else {
            throw AuthError.userCancelled
        }

        // Step 5: Authenticate with biometrics
        let authenticated = try await BiometricAuth.authenticate(
            reason: "Sign in to \(authRequest.rpName)"
        )

        guard authenticated else {
            throw AuthError.biometricsFailed
        }

        // Step 6: Load user private key from Keychain
        let userPrivateKey = try KeychainManager.loadKey(
            tag: "user-private-key-\(currentUserId)",
            accessControl: .biometryCurrentSet
        )

        // Step 7: Create authentication assertion
        let assertion = try createAuthAssertion(
            sessionId: sessionId,
            nonce: authRequest.nonce,
            audience: authRequest.rpClientId,
            privateKey: userPrivateKey,
            algorithm: authRequest.algorithm
        )

        // Step 8: Submit assertion to IdP
        let result = try await submitAssertion(
            sessionId: sessionId,
            assertion: assertion
        )

        return result
    }

    private func createAuthAssertion(
        sessionId: String,
        nonce: String,
        audience: String,
        privateKey: Data,
        algorithm: PqcAlgorithm
    ) throws -> String {

        // Create JWT-like assertion
        let header = AuthAssertionHeader(
            alg: algorithm.jwtAlgorithm,  // e.g., "KAZ128", "MLDSA44"
            typ: "JWT"
        )

        let payload = AuthAssertionPayload(
            iss: currentUserId,
            sub: currentUserId,
            aud: audience,
            nonce: nonce,
            iat: Date().timeIntervalSince1970,
            exp: Date().timeIntervalSince1970 + 60,  // 1 minute validity
            session_id: sessionId,
            device_id: currentDeviceId,
            auth_time: Date().timeIntervalSince1970
        )

        // Sign with PQC algorithm
        let headerB64 = try JSONEncoder().encode(header).base64URLEncoded()
        let payloadB64 = try JSONEncoder().encode(payload).base64URLEncoded()
        let signatureInput = "\(headerB64).\(payloadB64)".data(using: .utf8)!

        let signature: Data
        switch algorithm {
        case .kazSign128, .kazSign192, .kazSign256:
            signature = try KazSign.sign(
                message: signatureInput,
                privateKey: privateKey,
                level: algorithm.securityLevel
            )
        case .mlDsa44, .mlDsa65, .mlDsa87:
            signature = try MlDsa.sign(
                message: signatureInput,
                privateKey: privateKey,
                level: algorithm.securityLevel
            )
        }

        let signatureB64 = signature.base64URLEncoded()

        return "\(headerB64).\(payloadB64).\(signatureB64)"
    }
}
```

### Backend: Verify Assertion

```csharp
// IdP Backend - AuthenticationService.cs
public class AuthenticationService : IAuthenticationService
{
    public async Task<Result<AuthorizationCode>> VerifyAssertionAsync(
        VerifyAssertionCommand cmd,
        CancellationToken ct = default)
    {
        // Step 1: Get pending auth session
        var session = await _authSessionRepository.GetAsync(cmd.SessionId, ct);

        if (session is null)
            return Result.Failure<AuthorizationCode>("Invalid session");

        if (session.Status != AuthSessionStatus.Pending)
            return Result.Failure<AuthorizationCode>("Session not in pending state");

        if (session.ExpiresAt < DateTime.UtcNow)
            return Result.Failure<AuthorizationCode>("Session expired");

        // Step 2: Parse assertion (JWT-like structure)
        var parts = cmd.Assertion.Split('.');
        if (parts.Length != 3)
            return Result.Failure<AuthorizationCode>("Invalid assertion format");

        var headerJson = Base64UrlDecode(parts[0]);
        var payloadJson = Base64UrlDecode(parts[1]);
        var signature = Base64UrlDecodeBytes(parts[2]);

        var header = JsonSerializer.Deserialize<AssertionHeader>(headerJson);
        var payload = JsonSerializer.Deserialize<AssertionPayload>(payloadJson);

        // Step 3: Validate claims
        if (payload!.Nonce != session.Nonce)
            return Result.Failure<AuthorizationCode>("Nonce mismatch");

        if (payload.Aud != session.ClientId)
            return Result.Failure<AuthorizationCode>("Audience mismatch");

        if (payload.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            return Result.Failure<AuthorizationCode>("Assertion expired");

        // Step 4: Get user's public key from certificate
        var user = await _userRepository.GetAsync(Guid.Parse(payload.Sub), ct);
        if (user is null)
            return Result.Failure<AuthorizationCode>("User not found");

        var userCert = await _certificateRepository.GetActiveUserCertAsync(user.Id, ct);
        if (userCert is null)
            return Result.Failure<AuthorizationCode>("No active certificate");

        // Step 5: Verify PQC signature
        var signatureInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
        var publicKey = ExtractPublicKeyFromCert(userCert);

        var signatureValid = await _pqcService.VerifyAsync(
            header!.Alg,
            signatureInput,
            signature,
            publicKey,
            ct);

        if (!signatureValid)
            return Result.Failure<AuthorizationCode>("Signature verification failed");

        // Step 6: Verify device binding
        var device = await _deviceRepository.GetAsync(Guid.Parse(payload.DeviceId), ct);
        if (device is null || device.UserId != user.Id)
            return Result.Failure<AuthorizationCode>("Device not bound to user");

        if (device.Status != DeviceStatus.Active)
            return Result.Failure<AuthorizationCode>("Device is not active");

        // Step 7: Generate authorization code
        var authCode = new AuthorizationCode
        {
            Code = GenerateSecureCode(),
            ClientId = session.ClientId,
            UserId = user.Id,
            TenantId = user.TenantId,
            DeviceId = device.Id,
            RedirectUri = session.RedirectUri,
            Scopes = session.Scopes,
            Nonce = session.Nonce,
            CodeChallenge = session.CodeChallenge,
            CodeChallengeMethod = session.CodeChallengeMethod,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            AuthTime = DateTimeOffset.FromUnixTimeSeconds(payload.AuthTime).UtcDateTime,
            Acr = session.AcrValues
        };

        await _authCodeRepository.CreateAsync(authCode, ct);

        // Step 8: Update session
        session.Status = AuthSessionStatus.Completed;
        session.CompletedAt = DateTime.UtcNow;
        await _authSessionRepository.UpdateAsync(session, ct);

        // Step 9: Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            TenantId = user.TenantId,
            UserId = user.Id,
            Action = AuditAction.UserAuthenticated,
            Details = new
            {
                ClientId = session.ClientId,
                DeviceId = device.Id,
                Algorithm = header.Alg
            }
        }, ct);

        return Result.Success(authCode);
    }
}
```

---

## Web Browser Authentication

### Browser-Based Flow (No App on Device)

When user is on a device without the Digital ID app:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WEB BROWSER AUTHENTICATION                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User   │     │   Browser    │     │     IdP      │     │  Digital ID  │
│ (Desktop)│     │              │     │   Backend    │     │  App (Phone) │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │                    │
     │ 1. Access RP     │                    │                    │
     │─────────────────>│                    │                    │
     │                  │                    │                    │
     │                  │ 2. Redirect to IdP │                    │
     │                  │───────────────────>│                    │
     │                  │                    │                    │
     │                  │ 3. Auth page with  │                    │
     │                  │    QR code         │                    │
     │                  │<───────────────────│                    │
     │                  │                    │                    │
     │ 4. Display QR    │                    │                    │
     │<─────────────────│                    │                    │
     │                  │                    │                    │
     │ 5. Scan QR with phone                 │                    │
     │──────────────────────────────────────────────────────────>│
     │                  │                    │                    │
     │                  │                    │ 6. Validate QR     │
     │                  │                    │<───────────────────│
     │                  │                    │                    │
     │                  │                    │ 7. Auth request    │
     │                  │                    │───────────────────>│
     │                  │                    │                    │
     │ 8. Biometric     │                    │                    │
     │    on phone      │                    │                    │
     │<───────────────────────────────────────────────────────────│
     │                  │                    │                    │
     │ 9. Approve       │                    │                    │
     │────────────────────────────────────────────────────────────>
     │                  │                    │                    │
     │                  │                    │ 10. Signed         │
     │                  │                    │     assertion      │
     │                  │                    │<───────────────────│
     │                  │                    │                    │
     │                  │ 11. WebSocket:     │                    │
     │                  │     auth complete  │                    │
     │                  │<───────────────────│                    │
     │                  │                    │                    │
     │                  │ 12. Redirect with  │                    │
     │                  │     auth code      │                    │
     │                  │───────────────────>│                    │
     │                  │                    │                    │
```

### QR Code Content

```json
{
  "type": "idp_auth",
  "version": "1",
  "session_id": "uuid",
  "idp_url": "https://idp.example.com",
  "expires": 1701432000,
  "checksum": "sha256..."
}
```

Encoded as: `idp://auth?data=<base64url-encoded-json>`

### WebSocket for Browser Updates

```javascript
// Browser - auth-status.js
class AuthStatusPoller {
    constructor(sessionId) {
        this.sessionId = sessionId;
        this.ws = null;
    }

    connect() {
        this.ws = new WebSocket(
            `wss://idp.example.com/ws/auth/${this.sessionId}`
        );

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);

            switch (message.type) {
                case 'scanned':
                    this.showMessage('QR code scanned. Please approve on your phone.');
                    break;

                case 'approved':
                    // Redirect to callback with code
                    window.location.href = message.redirect_uri;
                    break;

                case 'denied':
                    this.showError('Authentication was denied.');
                    break;

                case 'expired':
                    this.showError('Session expired. Please refresh.');
                    break;
            }
        };

        this.ws.onerror = () => {
            // Fallback to polling
            this.startPolling();
        };
    }

    startPolling() {
        this.pollInterval = setInterval(async () => {
            const response = await fetch(
                `/api/v1/auth/sessions/${this.sessionId}/status`
            );
            const status = await response.json();

            if (status.completed) {
                clearInterval(this.pollInterval);
                window.location.href = status.redirect_uri;
            }
        }, 2000);
    }
}
```

---

## QR Code Authentication

### Dedicated QR Authentication Flow

For scenarios where QR code is the primary method:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     QR CODE AUTHENTICATION FLOW                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│ USE CASES:                                                                    │
│ • Kiosk authentication                                                        │
│ • Point-of-sale terminals                                                     │
│ • Physical access control                                                     │
│ • Document signing stations                                                   │
│ • Shared computer login                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

Kiosk                          IdP                         User's Phone
  │                             │                              │
  │ 1. Request auth session     │                              │
  │────────────────────────────>│                              │
  │                             │                              │
  │ 2. QR code + session_id     │                              │
  │<────────────────────────────│                              │
  │                             │                              │
  │ 3. Display QR               │                              │
  │─────────┐                   │                              │
  │         │                   │                              │
  │<────────┘                   │                              │
  │                             │                              │
  │              4. User scans QR                              │
  │──────────────────────────────────────────────────────────>│
  │                             │                              │
  │                             │ 5. Validate session          │
  │                             │<─────────────────────────────│
  │                             │                              │
  │                             │ 6. Session details           │
  │                             │─────────────────────────────>│
  │                             │                              │
  │                             │ 7. Biometric + sign          │
  │                             │<─────────────────────────────│
  │                             │                              │
  │ 8. Poll: auth complete      │                              │
  │────────────────────────────>│                              │
  │                             │                              │
  │ 9. User identity + token    │                              │
  │<────────────────────────────│                              │
  │                             │                              │
```

### QR Session API

```csharp
// IdP Backend - QrAuthController.cs
[ApiController]
[Route("api/v1/qr-auth")]
public class QrAuthController : ControllerBase
{
    [HttpPost("sessions")]
    public async Task<IActionResult> CreateSession(
        [FromBody] CreateQrSessionRequest request)
    {
        // Create QR authentication session
        var session = new QrAuthSession
        {
            Id = Guid.NewGuid(),
            TenantId = request.TenantId,
            ClientId = request.ClientId,
            Purpose = request.Purpose,  // e.g., "login", "sign", "access"
            Metadata = request.Metadata, // e.g., document ID, door ID
            Status = QrAuthStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5)
        };

        await _qrSessionRepository.CreateAsync(session);

        // Generate QR code data
        var qrData = new QrCodeData
        {
            Type = "idp_qr_auth",
            Version = "1",
            SessionId = session.Id.ToString(),
            IdpUrl = _config.BaseUrl,
            Purpose = session.Purpose,
            Expires = session.ExpiresAt.ToUnixTimeSeconds(),
            Checksum = ComputeChecksum(session)
        };

        var qrContent = $"idp://qr-auth?data={Base64UrlEncode(JsonSerializer.Serialize(qrData))}";

        return Ok(new
        {
            session_id = session.Id,
            qr_content = qrContent,
            qr_image_url = $"/api/v1/qr-auth/sessions/{session.Id}/qr.png",
            expires_at = session.ExpiresAt,
            poll_url = $"/api/v1/qr-auth/sessions/{session.Id}/status",
            ws_url = $"wss://{Request.Host}/ws/qr-auth/{session.Id}"
        });
    }

    [HttpGet("sessions/{sessionId}/status")]
    public async Task<IActionResult> GetStatus(Guid sessionId)
    {
        var session = await _qrSessionRepository.GetAsync(sessionId);

        if (session is null)
            return NotFound();

        return Ok(new
        {
            status = session.Status.ToString().ToLower(),
            scanned_at = session.ScannedAt,
            completed_at = session.CompletedAt,
            user_id = session.Status == QrAuthStatus.Completed ? session.UserId : null,
            access_token = session.Status == QrAuthStatus.Completed ? session.AccessToken : null
        });
    }
}
```

---

## Token Management

### ID Token (PQC Signed)

```json
{
  "header": {
    "alg": "KAZ128",
    "typ": "JWT",
    "kid": "tenant-ca-key-123"
  },
  "payload": {
    "iss": "https://idp.example.com",
    "sub": "user-uuid",
    "aud": "rp-client-123",
    "exp": 1701435600,
    "iat": 1701432000,
    "auth_time": 1701431990,
    "nonce": "xyz789",
    "acr": "urn:idp:pqc:kaz-sign-128",
    "amr": ["pqc_sig", "biometric"],
    "azp": "rp-client-123",

    "name": "John Doe",
    "email": "john.doe@example.com",
    "email_verified": true,
    "org_id": "org-uuid",
    "org_name": "Example Organization",

    "device_id": "device-uuid",
    "cert_serial": "1234567890"
  },
  "signature": "<pqc-signature>"
}
```

### Access Token

```json
{
  "header": {
    "alg": "KAZ128",
    "typ": "at+jwt"
  },
  "payload": {
    "iss": "https://idp.example.com",
    "sub": "user-uuid",
    "aud": "https://api.example.com",
    "client_id": "rp-client-123",
    "exp": 1701435600,
    "iat": 1701432000,
    "jti": "unique-token-id",

    "scope": "openid profile email",
    "tenant_id": "tenant-uuid"
  },
  "signature": "<pqc-signature>"
}
```

### Token Endpoint

```csharp
// IdP Backend - TokenService.cs
public class TokenService : ITokenService
{
    public async Task<Result<TokenResponse>> ExchangeCodeAsync(
        TokenRequest request,
        CancellationToken ct = default)
    {
        // Step 1: Validate client authentication
        var client = await ValidateClientAsync(request, ct);
        if (client is null)
            return Result.Failure<TokenResponse>("Invalid client credentials");

        // Step 2: Get and validate authorization code
        var authCode = await _authCodeRepository.GetByCodeAsync(request.Code, ct);

        if (authCode is null)
            return Result.Failure<TokenResponse>("Invalid authorization code");

        if (authCode.ExpiresAt < DateTime.UtcNow)
            return Result.Failure<TokenResponse>("Authorization code expired");

        if (authCode.ClientId != client.Id)
            return Result.Failure<TokenResponse>("Code was not issued to this client");

        if (authCode.RedirectUri != request.RedirectUri)
            return Result.Failure<TokenResponse>("Redirect URI mismatch");

        // Step 3: Verify PKCE
        if (!VerifyPkce(authCode.CodeChallenge, authCode.CodeChallengeMethod, request.CodeVerifier))
            return Result.Failure<TokenResponse>("PKCE verification failed");

        // Step 4: Mark code as used (single use)
        authCode.UsedAt = DateTime.UtcNow;
        await _authCodeRepository.UpdateAsync(authCode, ct);

        // Step 5: Get user and tenant info
        var user = await _userRepository.GetAsync(authCode.UserId, ct);
        var tenant = await _tenantRepository.GetAsync(authCode.TenantId, ct);

        // Step 6: Generate tokens
        var idToken = await GenerateIdTokenAsync(
            user!,
            tenant!,
            client,
            authCode,
            ct);

        var accessToken = await GenerateAccessTokenAsync(
            user,
            tenant,
            client,
            authCode.Scopes,
            ct);

        var refreshToken = await GenerateRefreshTokenAsync(
            user,
            client,
            authCode.Scopes,
            ct);

        return Result.Success(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = 3600, // 1 hour
            IdToken = idToken,
            RefreshToken = refreshToken,
            Scope = string.Join(" ", authCode.Scopes)
        });
    }

    private async Task<string> GenerateIdTokenAsync(
        User user,
        Tenant tenant,
        Client client,
        AuthorizationCode authCode,
        CancellationToken ct)
    {
        var claims = new Dictionary<string, object>
        {
            ["iss"] = _config.Issuer,
            ["sub"] = user.Id.ToString(),
            ["aud"] = client.ClientId,
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["auth_time"] = new DateTimeOffset(authCode.AuthTime).ToUnixTimeSeconds(),
            ["nonce"] = authCode.Nonce,
            ["acr"] = authCode.Acr,
            ["amr"] = new[] { "pqc_sig", "biometric" },
            ["azp"] = client.ClientId,

            // Profile claims
            ["name"] = user.DisplayName,
            ["email"] = user.Email,
            ["email_verified"] = user.EmailVerified,
            ["org_id"] = tenant.Id.ToString(),
            ["org_name"] = tenant.Name,

            // Device binding
            ["device_id"] = authCode.DeviceId.ToString()
        };

        // Sign with tenant's PQC key
        var signingKey = await _hsmService.GetTenantSigningKeyAsync(tenant.Id, ct);

        return await _jwtService.CreatePqcSignedTokenAsync(
            claims,
            signingKey,
            tenant.Algorithm,
            ct);
    }
}
```

### Token Refresh

```http
POST /oauth/token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<refresh-token>
&client_id=rp-client-123
&client_secret=<client-secret>

Response:
{
  "access_token": "<new-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<new-refresh-token>"
}
```

---

## PQC Signature Integration

### Supported Algorithms

| Algorithm | JOSE Identifier | Key Size | Signature Size | Security Level |
|-----------|-----------------|----------|----------------|----------------|
| KAZ-SIGN-128 | `KAZ128` | TBD | TBD | NIST Level 1 |
| KAZ-SIGN-192 | `KAZ192` | TBD | TBD | NIST Level 3 |
| KAZ-SIGN-256 | `KAZ256` | TBD | TBD | NIST Level 5 |
| ML-DSA-44 | `MLDSA44` | 1,312 B | 2,420 B | NIST Level 2 |
| ML-DSA-65 | `MLDSA65` | 1,952 B | 3,293 B | NIST Level 3 |
| ML-DSA-87 | `MLDSA87` | 2,592 B | 4,595 B | NIST Level 5 |

### JWT Algorithm Registration

```csharp
// IdP Backend - PqcJwtHandler.cs
public class PqcJwtHandler : IJwtHandler
{
    private readonly IHsmService _hsmService;

    public async Task<string> SignTokenAsync(
        IDictionary<string, object> claims,
        string keyId,
        string algorithm,
        CancellationToken ct)
    {
        // Create header
        var header = new Dictionary<string, object>
        {
            ["alg"] = algorithm,
            ["typ"] = "JWT",
            ["kid"] = keyId
        };

        // Encode header and payload
        var headerB64 = Base64UrlEncode(JsonSerializer.Serialize(header));
        var payloadB64 = Base64UrlEncode(JsonSerializer.Serialize(claims));
        var signingInput = Encoding.UTF8.GetBytes($"{headerB64}.{payloadB64}");

        // Sign with HSM
        var signature = await _hsmService.SignAsync(
            keyId,
            signingInput,
            GetHsmAlgorithm(algorithm),
            ct);

        var signatureB64 = Base64UrlEncode(signature);

        return $"{headerB64}.{payloadB64}.{signatureB64}";
    }

    public async Task<bool> VerifyTokenAsync(
        string token,
        byte[] publicKey,
        string algorithm,
        CancellationToken ct)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            return false;

        var signingInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
        var signature = Base64UrlDecodeBytes(parts[2]);

        return await _hsmService.VerifyAsync(
            signingInput,
            signature,
            publicKey,
            GetHsmAlgorithm(algorithm),
            ct);
    }

    private HsmAlgorithm GetHsmAlgorithm(string joseAlg) => joseAlg switch
    {
        "KAZ128" => HsmAlgorithm.KazSign128,
        "KAZ192" => HsmAlgorithm.KazSign192,
        "KAZ256" => HsmAlgorithm.KazSign256,
        "MLDSA44" => HsmAlgorithm.MlDsa44,
        "MLDSA65" => HsmAlgorithm.MlDsa65,
        "MLDSA87" => HsmAlgorithm.MlDsa87,
        _ => throw new ArgumentException($"Unsupported algorithm: {joseAlg}")
    };
}
```

---

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Authorization code interception | PKCE required for all flows |
| Token theft | Short-lived tokens, device binding |
| Replay attacks | Nonce validation, single-use auth codes |
| Phishing | Device-bound authentication, RP verification |
| Session hijacking | Session binding to device, biometric re-auth |
| Quantum attacks | PQC signatures on all tokens |

### Required Security Controls

1. **PKCE** - Required for all authorization code flows
2. **PAR** - Pushed Authorization Requests for sensitive RPs
3. **Client Authentication** - Required for confidential clients
4. **Token Binding** - Optional, for high-security scenarios
5. **Proof of Possession** - DPoP support for API access

### ACR Values

```
urn:idp:pqc:kaz-sign-128   - KAZ-SIGN Level 1 authentication
urn:idp:pqc:kaz-sign-192   - KAZ-SIGN Level 3 authentication
urn:idp:pqc:kaz-sign-256   - KAZ-SIGN Level 5 authentication
urn:idp:pqc:ml-dsa-44      - ML-DSA Level 2 authentication
urn:idp:pqc:ml-dsa-65      - ML-DSA Level 3 authentication
urn:idp:pqc:ml-dsa-87      - ML-DSA Level 5 authentication
```

### Session Management

```csharp
// IdP Backend - AuthSessionConfiguration.cs
public class AuthSessionConfiguration
{
    public TimeSpan AuthorizationRequestLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan QrSessionLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public int MaxRefreshTokenUsage { get; set; } = 100;
    public bool RotateRefreshTokens { get; set; } = true;
    public bool RevokeRefreshTokenOnReuse { get; set; } = true;
}
```

---

## API Endpoints

### OIDC Discovery

```http
GET /.well-known/openid-configuration

Response:
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/oauth/authorize",
  "token_endpoint": "https://idp.example.com/oauth/token",
  "userinfo_endpoint": "https://idp.example.com/oauth/userinfo",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "pushed_authorization_request_endpoint": "https://idp.example.com/oauth/par",
  "revocation_endpoint": "https://idp.example.com/oauth/revoke",
  "introspection_endpoint": "https://idp.example.com/oauth/introspect",

  "scopes_supported": ["openid", "profile", "email", "org"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],

  "id_token_signing_alg_values_supported": ["KAZ128", "KAZ192", "KAZ256", "MLDSA44", "MLDSA65", "MLDSA87"],
  "userinfo_signing_alg_values_supported": ["KAZ128", "KAZ192", "KAZ256", "MLDSA44", "MLDSA65", "MLDSA87"],

  "acr_values_supported": [
    "urn:idp:pqc:kaz-sign-128",
    "urn:idp:pqc:kaz-sign-192",
    "urn:idp:pqc:kaz-sign-256",
    "urn:idp:pqc:ml-dsa-44",
    "urn:idp:pqc:ml-dsa-65",
    "urn:idp:pqc:ml-dsa-87"
  ],

  "require_pushed_authorization_requests": false,
  "require_pkce": true
}
```

### JWKS Endpoint

```http
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "PQC",
      "alg": "KAZ128",
      "kid": "tenant-123-signing-key",
      "use": "sig",
      "x": "<base64url-encoded-public-key>"
    },
    {
      "kty": "PQC",
      "alg": "MLDSA65",
      "kid": "tenant-456-signing-key",
      "use": "sig",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

### UserInfo Endpoint

```http
GET /oauth/userinfo
Authorization: Bearer <access-token>

Response:
{
  "sub": "user-uuid",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "org_id": "org-uuid",
  "org_name": "Example Organization"
}
```

---

## Implementation Checklist

### Phase 1: Core OIDC

- [ ] **Discovery Endpoint**
  - [ ] Implement `/.well-known/openid-configuration`
  - [ ] Implement `/.well-known/jwks.json`
  - [ ] Add PQC algorithm support

- [ ] **Authorization Endpoint**
  - [ ] Implement PAR endpoint
  - [ ] Implement authorize endpoint
  - [ ] PKCE validation
  - [ ] Session management

- [ ] **Token Endpoint**
  - [ ] Authorization code exchange
  - [ ] Refresh token grant
  - [ ] Client authentication

- [ ] **Token Generation**
  - [ ] PQC-signed ID tokens
  - [ ] PQC-signed access tokens
  - [ ] Refresh token generation

### Phase 2: Mobile App Integration

- [ ] **Deep Linking**
  - [ ] iOS Universal Links
  - [ ] Android App Links
  - [ ] Custom URL scheme fallback

- [ ] **Authentication Flow**
  - [ ] Session validation API
  - [ ] Assertion verification
  - [ ] Device binding verification

- [ ] **Client SDK**
  - [ ] iOS authentication manager
  - [ ] Android authentication manager
  - [ ] Biometric integration

### Phase 3: QR Code Flow

- [ ] **QR Session Management**
  - [ ] Create QR session API
  - [ ] QR code generation
  - [ ] Session polling API
  - [ ] WebSocket notifications

- [ ] **Browser Integration**
  - [ ] QR display page
  - [ ] WebSocket client
  - [ ] Polling fallback

### Phase 4: Security Hardening

- [ ] **Rate Limiting**
  - [ ] Per-client limits
  - [ ] Per-user limits
  - [ ] Anti-automation

- [ ] **Audit Logging**
  - [ ] Authentication events
  - [ ] Token issuance
  - [ ] Suspicious activity

- [ ] **Token Security**
  - [ ] Token revocation
  - [ ] Refresh token rotation
  - [ ] DPoP support (optional)

---

## References

- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - User registration and key setup
- [ACCOUNT_RECOVERY_FLOW.md](./ACCOUNT_RECOVERY_FLOW.md) - Account recovery process
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Certificate management
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [PAR RFC 9126](https://tools.ietf.org/html/rfc9126)
