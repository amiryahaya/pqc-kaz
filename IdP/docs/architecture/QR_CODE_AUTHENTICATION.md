# QR Code Authentication Flow

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Use Cases](#use-cases)
3. [QR Code Types](#qr-code-types)
4. [Authentication Flow](#authentication-flow)
5. [Login QR Flow](#login-qr-flow)
6. [Transaction QR Flow](#transaction-qr-flow)
7. [Physical Access QR Flow](#physical-access-qr-flow)
8. [Document Signing QR Flow](#document-signing-qr-flow)
9. [QR Code Specification](#qr-code-specification)
10. [Security Considerations](#security-considerations)
11. [Relying Party Integration](#relying-party-integration)
12. [Mobile App Implementation](#mobile-app-implementation)
13. [API Reference](#api-reference)
14. [SDK Integration](#sdk-integration)
15. [Implementation Checklist](#implementation-checklist)

---

## Overview

### Purpose

QR Code Authentication enables users to authenticate or authorize actions by scanning a QR code with their Digital ID mobile app. This flow is essential for:

- **Cross-device authentication** - Login on desktop using mobile phone
- **Shared device login** - Kiosks, public terminals, shared computers
- **Physical access control** - Building entry, secure areas
- **Transaction authorization** - Payments, transfers, approvals
- **Document signing** - Legal documents, contracts

### Key Benefits

| Benefit | Description |
|---------|-------------|
| **Passwordless** | No typing credentials on potentially compromised devices |
| **Phishing Resistant** | QR contains session-bound data, not reusable credentials |
| **Cross-Platform** | Works on any device that can display a QR code |
| **Offline Capable** | Some flows work with limited connectivity |
| **Non-Repudiation** | PQC signatures provide cryptographic proof |

### Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      QR CODE AUTHENTICATION OVERVIEW                         │
└─────────────────────────────────────────────────────────────────────────────┘

    Relying Party                    IdP                      User's Phone
    (Website/Kiosk)                Backend                   (Digital ID App)
         │                           │                            │
         │  1. Request QR session    │                            │
         │──────────────────────────>│                            │
         │                           │                            │
         │  2. Session + QR data     │                            │
         │<──────────────────────────│                            │
         │                           │                            │
         │  3. Display QR code       │                            │
         │─────────┐                 │                            │
         │         │                 │                            │
         │<────────┘                 │                            │
         │                           │                            │
         │                    4. User scans QR                    │
         │─────────────────────────────────────────────────────────>
         │                           │                            │
         │                           │  5. Validate + get details │
         │                           │<───────────────────────────│
         │                           │                            │
         │                           │  6. Show consent screen    │
         │                           │───────────────────────────>│
         │                           │                            │
         │                           │  7. User approves          │
         │                           │     (biometric)            │
         │                           │<───────────────────────────│
         │                           │                            │
         │  8. Notify: authenticated │                            │
         │<──────────────────────────│                            │
         │                           │                            │
         │  9. Complete action       │                            │
         │     (login/sign/access)   │                            │
         │                           │                            │
```

---

## Use Cases

### Use Case 1: Web Login

```
Scenario: User wants to log into a web application on their laptop

1. User visits website, clicks "Login with Digital ID"
2. Website displays QR code
3. User opens Digital ID app, scans QR
4. App shows: "Example.com wants to sign you in"
5. User authenticates with Face ID
6. Website automatically logs user in
```

### Use Case 2: Kiosk Authentication

```
Scenario: User at airport check-in kiosk

1. Kiosk displays QR code with "Scan to check in"
2. User scans with Digital ID app
3. App shows: "Airport Kiosk - Check-in for Flight XY123"
4. User authenticates with biometrics
5. Kiosk displays boarding pass
```

### Use Case 3: Physical Access Control

```
Scenario: Employee entering secure building area

1. Door panel displays QR code
2. Employee scans with Digital ID app
3. App shows: "Building Access - Server Room Level 3"
4. Employee authenticates
5. Door unlocks
```

### Use Case 4: Transaction Authorization

```
Scenario: Approving a wire transfer on banking website

1. User initiates transfer on desktop
2. Bank shows QR code: "Confirm transfer of $10,000 to Account XXX"
3. User scans QR with Digital ID app
4. App shows transaction details for review
5. User signs with biometric authentication
6. Transfer is authorized with PQC signature
```

### Use Case 5: Document Signing

```
Scenario: Signing a contract in document management system

1. User opens contract, clicks "Sign with Digital ID"
2. System displays QR code with document hash
3. User scans, app shows document summary
4. User reviews and signs with biometrics
5. Document receives PQC digital signature
```

---

## QR Code Types

### Type 1: Login QR (`idp_login`)

For authentication/login purposes.

```json
{
  "type": "idp_login",
  "version": "1",
  "session_id": "uuid",
  "rp_id": "example.com",
  "rp_name": "Example Application",
  "rp_logo": "https://example.com/logo.png",
  "scopes": ["openid", "profile", "email"],
  "expires": 1701432300,
  "nonce": "random-nonce",
  "checksum": "sha256-hash"
}
```

### Type 2: Transaction QR (`idp_transaction`)

For authorizing specific transactions.

```json
{
  "type": "idp_transaction",
  "version": "1",
  "session_id": "uuid",
  "rp_id": "bank.example.com",
  "rp_name": "Example Bank",
  "transaction": {
    "type": "transfer",
    "amount": "10000.00",
    "currency": "USD",
    "recipient": "John Doe",
    "recipient_account": "****1234",
    "reference": "INV-2025-001"
  },
  "expires": 1701432300,
  "challenge": "random-challenge",
  "checksum": "sha256-hash"
}
```

### Type 3: Access QR (`idp_access`)

For physical or logical access control.

```json
{
  "type": "idp_access",
  "version": "1",
  "session_id": "uuid",
  "location_id": "building-a-door-5",
  "location_name": "Building A - Server Room",
  "access_level": "restricted",
  "rp_id": "access.example.com",
  "rp_name": "Example Corp Security",
  "expires": 1701432300,
  "challenge": "random-challenge",
  "checksum": "sha256-hash"
}
```

### Type 4: Signing QR (`idp_sign`)

For document signing.

```json
{
  "type": "idp_sign",
  "version": "1",
  "session_id": "uuid",
  "rp_id": "docs.example.com",
  "rp_name": "Example DocSign",
  "document": {
    "id": "doc-uuid",
    "name": "Employment Contract",
    "hash": "sha256-of-document",
    "hash_algorithm": "SHA-256",
    "pages": 12,
    "size_bytes": 245000
  },
  "signature_position": {
    "page": 12,
    "description": "Employee Signature"
  },
  "expires": 1701432300,
  "challenge": "random-challenge",
  "checksum": "sha256-hash"
}
```

---

## Authentication Flow

### Phase 1: Session Creation (Relying Party → IdP)

```
┌──────────────┐                    ┌──────────────┐
│   Relying    │                    │     IdP      │
│    Party     │                    │   Backend    │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │  POST /api/v1/qr/sessions         │
       │  {                                │
       │    "type": "login",               │
       │    "client_id": "rp-123",         │
       │    "redirect_uri": "...",         │
       │    "scopes": ["openid", ...],     │
       │    "state": "...",                │
       │    "code_challenge": "..."        │
       │  }                                │
       │──────────────────────────────────>│
       │                                   │
       │  201 Created                      │
       │  {                                │
       │    "session_id": "uuid",          │
       │    "qr_data": "idp://...",        │
       │    "qr_image_url": "/qr/...",     │
       │    "expires_at": "...",           │
       │    "ws_url": "wss://...",         │
       │    "poll_url": "/status/..."      │
       │  }                                │
       │<──────────────────────────────────│
       │                                   │
```

### Phase 2: QR Display & Scan

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Relying    │     │     User     │     │  Digital ID  │
│    Party     │     │              │     │     App      │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  Display QR code   │                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  Open app camera   │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  Scan QR code      │
       │                    │───────────────────>│
       │                    │                    │
       │                    │                    │ Parse QR data
       │                    │                    │ Validate checksum
       │                    │                    │ Check expiration
       │                    │                    │
```

### Phase 3: Session Validation (App → IdP)

```
┌──────────────┐                    ┌──────────────┐
│  Digital ID  │                    │     IdP      │
│     App      │                    │   Backend    │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │  POST /api/v1/qr/sessions/{id}/scan
       │  {                                │
       │    "device_id": "...",            │
       │    "app_attestation": "..."       │
       │  }                                │
       │──────────────────────────────────>│
       │                                   │
       │  200 OK                           │
       │  {                                │
       │    "rp_name": "Example App",      │
       │    "rp_logo": "https://...",      │
       │    "rp_verified": true,           │
       │    "scopes": [...],               │
       │    "scope_descriptions": [...],   │
       │    "user_info_preview": {...}     │
       │  }                                │
       │<──────────────────────────────────│
       │                                   │
```

### Phase 4: User Consent & Authentication

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│     User     │     │  Digital ID  │     │   Keychain   │
│              │     │     App      │     │              │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │                    │  Show consent UI   │
       │                    │  "Example App      │
       │                    │   wants to sign    │
       │                    │   you in"          │
       │<───────────────────│                    │
       │                    │                    │
       │  Tap "Approve"     │                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  Biometric prompt  │
       │<───────────────────│                    │
       │                    │                    │
       │  Face ID / Touch ID│                    │
       │───────────────────>│                    │
       │                    │                    │
       │                    │  Load private key  │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  Private key       │
       │                    │<───────────────────│
       │                    │                    │
       │                    │  Create & sign     │
       │                    │  assertion         │
       │                    │                    │
```

### Phase 5: Assertion Submission & Completion

```
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│  Digital ID  │          │     IdP      │          │   Relying    │
│     App      │          │   Backend    │          │    Party     │
└──────┬───────┘          └──────┬───────┘          └──────┬───────┘
       │                         │                         │
       │  POST /qr/{id}/authorize│                         │
       │  {                      │                         │
       │    "assertion": "...",  │                         │
       │    "device_id": "..."   │                         │
       │  }                      │                         │
       │────────────────────────>│                         │
       │                         │                         │
       │                         │  Verify PQC signature   │
       │                         │  Verify device binding  │
       │                         │  Generate auth code     │
       │                         │                         │
       │  200 OK                 │                         │
       │  { "status": "approved" }                         │
       │<────────────────────────│                         │
       │                         │                         │
       │                         │  WebSocket/Callback     │
       │                         │  { "code": "...",       │
       │                         │    "state": "..." }     │
       │                         │────────────────────────>│
       │                         │                         │
       │                         │                         │  Exchange code
       │                         │                         │  for tokens
       │                         │<────────────────────────│
       │                         │                         │
       │                         │  Tokens                 │
       │                         │────────────────────────>│
       │                         │                         │
```

---

## Login QR Flow

### Complete Sequence Diagram

```
┌────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│  User  │    │ Browser │    │   RP    │    │   IdP   │    │  Phone  │
│        │    │         │    │ Backend │    │ Backend │    │   App   │
└───┬────┘    └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘
    │              │              │              │              │
    │ 1. Click     │              │              │              │
    │   "Login"    │              │              │              │
    │─────────────>│              │              │              │
    │              │              │              │              │
    │              │ 2. Create    │              │              │
    │              │    QR session│              │              │
    │              │─────────────>│              │              │
    │              │              │              │              │
    │              │              │ 3. POST      │              │
    │              │              │    /qr/sessions             │
    │              │              │─────────────>│              │
    │              │              │              │              │
    │              │              │ 4. Session   │              │
    │              │              │    created   │              │
    │              │              │<─────────────│              │
    │              │              │              │              │
    │              │ 5. QR data   │              │              │
    │              │<─────────────│              │              │
    │              │              │              │              │
    │ 6. Show QR   │              │              │              │
    │<─────────────│              │              │              │
    │              │              │              │              │
    │              │ 7. Connect   │              │              │
    │              │    WebSocket │              │              │
    │              │─────────────────────────────>              │
    │              │              │              │              │
    │ 8. Scan QR   │              │              │              │
    │────────────────────────────────────────────────────────>│
    │              │              │              │              │
    │              │              │              │ 9. Validate  │
    │              │              │              │<─────────────│
    │              │              │              │              │
    │              │              │              │ 10. Session  │
    │              │              │              │     details  │
    │              │              │              │─────────────>│
    │              │              │              │              │
    │ 11. Show     │              │              │              │
    │    consent   │              │              │              │
    │<────────────────────────────────────────────────────────│
    │              │              │              │              │
    │ 12. Approve  │              │              │              │
    │    (Face ID) │              │              │              │
    │────────────────────────────────────────────────────────>│
    │              │              │              │              │
    │              │              │              │ 13. Submit   │
    │              │              │              │    assertion │
    │              │              │              │<─────────────│
    │              │              │              │              │
    │              │              │              │ 14. Verify & │
    │              │              │              │     gen code │
    │              │              │              │              │
    │              │ 15. WS:      │              │              │
    │              │    code ready│              │              │
    │              │<─────────────────────────────              │
    │              │              │              │              │
    │              │ 16. Redirect │              │              │
    │              │    /callback?code=...      │              │
    │              │─────────────>│              │              │
    │              │              │              │              │
    │              │              │ 17. Exchange │              │
    │              │              │    code      │              │
    │              │              │─────────────>│              │
    │              │              │              │              │
    │              │              │ 18. Tokens   │              │
    │              │              │<─────────────│              │
    │              │              │              │              │
    │              │ 19. Set      │              │              │
    │              │    session   │              │              │
    │              │<─────────────│              │              │
    │              │              │              │              │
    │ 20. Logged   │              │              │              │
    │     in!      │              │              │              │
    │<─────────────│              │              │              │
    │              │              │              │              │
```

### RP Backend Implementation

```csharp
// Relying Party - QrLoginController.cs
[ApiController]
[Route("api/auth")]
public class QrLoginController : ControllerBase
{
    private readonly IIdpClient _idpClient;
    private readonly IQrSessionStore _sessionStore;

    [HttpPost("qr-login/start")]
    public async Task<IActionResult> StartQrLogin()
    {
        // Step 1: Generate PKCE
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state = GenerateState();

        // Step 2: Create QR session with IdP
        var response = await _idpClient.CreateQrSessionAsync(new CreateQrSessionRequest
        {
            Type = QrSessionType.Login,
            ClientId = _config.ClientId,
            RedirectUri = _config.RedirectUri,
            Scopes = new[] { "openid", "profile", "email" },
            State = state,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256"
        });

        // Step 3: Store session locally for verification
        await _sessionStore.StoreAsync(response.SessionId, new QrLoginSession
        {
            SessionId = response.SessionId,
            CodeVerifier = codeVerifier,
            State = state,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = response.ExpiresAt
        });

        // Step 4: Return QR data to frontend
        return Ok(new
        {
            session_id = response.SessionId,
            qr_data = response.QrData,
            qr_image_url = response.QrImageUrl,
            expires_at = response.ExpiresAt,
            ws_url = response.WebSocketUrl,
            poll_url = $"/api/auth/qr-login/{response.SessionId}/status"
        });
    }

    [HttpGet("qr-login/{sessionId}/status")]
    public async Task<IActionResult> GetStatus(string sessionId)
    {
        var session = await _sessionStore.GetAsync(sessionId);
        if (session is null)
            return NotFound();

        // Check with IdP
        var status = await _idpClient.GetQrSessionStatusAsync(sessionId);

        return Ok(new
        {
            status = status.Status,
            scanned = status.ScannedAt.HasValue,
            redirect_url = status.Status == "completed"
                ? $"/api/auth/qr-login/{sessionId}/complete"
                : null
        });
    }

    [HttpGet("qr-login/{sessionId}/complete")]
    public async Task<IActionResult> Complete(string sessionId, [FromQuery] string code)
    {
        var session = await _sessionStore.GetAsync(sessionId);
        if (session is null)
            return BadRequest("Invalid session");

        // Exchange code for tokens
        var tokens = await _idpClient.ExchangeCodeAsync(new TokenRequest
        {
            Code = code,
            RedirectUri = _config.RedirectUri,
            CodeVerifier = session.CodeVerifier
        });

        // Clear session
        await _sessionStore.DeleteAsync(sessionId);

        // Create application session
        var appSession = await CreateAppSessionAsync(tokens);

        return Redirect($"/?session={appSession.Id}");
    }
}
```

### Browser Frontend Implementation

```typescript
// Browser - qr-login.ts
class QrLoginManager {
    private sessionId: string | null = null;
    private ws: WebSocket | null = null;
    private pollInterval: NodeJS.Timer | null = null;

    async startLogin(): Promise<void> {
        // Step 1: Request QR session
        const response = await fetch('/api/auth/qr-login/start', {
            method: 'POST'
        });
        const data = await response.json();

        this.sessionId = data.session_id;

        // Step 2: Display QR code
        this.displayQrCode(data.qr_data, data.qr_image_url);

        // Step 3: Start listening for completion
        this.connectWebSocket(data.ws_url);

        // Step 4: Set expiration timer
        this.setExpirationTimer(new Date(data.expires_at));
    }

    private displayQrCode(qrData: string, qrImageUrl: string): void {
        const container = document.getElementById('qr-container')!;

        // Option 1: Use pre-generated image
        container.innerHTML = `
            <img src="${qrImageUrl}" alt="Scan to login" />
            <p>Scan with your Digital ID app</p>
        `;

        // Option 2: Generate QR client-side using qrcode library
        // QRCode.toCanvas(document.getElementById('qr-canvas'), qrData);
    }

    private connectWebSocket(wsUrl: string): void {
        this.ws = new WebSocket(wsUrl);

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleWebSocketMessage(message);
        };

        this.ws.onerror = () => {
            // Fallback to polling
            console.log('WebSocket failed, falling back to polling');
            this.startPolling();
        };

        this.ws.onclose = () => {
            if (this.sessionId) {
                // Reconnect if session still active
                setTimeout(() => this.connectWebSocket(wsUrl), 1000);
            }
        };
    }

    private handleWebSocketMessage(message: WsMessage): void {
        switch (message.type) {
            case 'scanned':
                this.showMessage('QR scanned! Please approve on your phone.');
                this.showSpinner();
                break;

            case 'approved':
                this.showMessage('Approved! Logging you in...');
                window.location.href = message.redirect_url;
                break;

            case 'denied':
                this.showError('Login was denied.');
                this.reset();
                break;

            case 'expired':
                this.showError('Session expired. Please try again.');
                this.reset();
                break;
        }
    }

    private startPolling(): void {
        this.pollInterval = setInterval(async () => {
            const response = await fetch(
                `/api/auth/qr-login/${this.sessionId}/status`
            );
            const status = await response.json();

            if (status.scanned && !status.redirect_url) {
                this.showMessage('QR scanned! Please approve on your phone.');
            }

            if (status.redirect_url) {
                this.cleanup();
                window.location.href = status.redirect_url;
            }
        }, 2000);
    }

    private cleanup(): void {
        this.sessionId = null;
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    private reset(): void {
        this.cleanup();
        // Show "Try again" button
        document.getElementById('qr-container')!.innerHTML = `
            <button onclick="qrLogin.startLogin()">Try Again</button>
        `;
    }
}

// Usage
const qrLogin = new QrLoginManager();
document.getElementById('login-btn')?.addEventListener('click', () => {
    qrLogin.startLogin();
});
```

---

## Transaction QR Flow

### Use Case: Bank Transfer Authorization

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRANSACTION AUTHORIZATION FLOW                          │
└─────────────────────────────────────────────────────────────────────────────┘

User (Desktop)              Bank Website              IdP              Phone App
     │                          │                      │                   │
     │ 1. Initiate transfer     │                      │                   │
     │     $10,000 to John      │                      │                   │
     │─────────────────────────>│                      │                   │
     │                          │                      │                   │
     │                          │ 2. Create transaction│                   │
     │                          │    QR session        │                   │
     │                          │─────────────────────>│                   │
     │                          │                      │                   │
     │                          │ 3. QR with tx details│                   │
     │                          │<─────────────────────│                   │
     │                          │                      │                   │
     │ 4. Show QR:              │                      │                   │
     │    "Confirm transfer"    │                      │                   │
     │<─────────────────────────│                      │                   │
     │                          │                      │                   │
     │ 5. Scan QR               │                      │                   │
     │─────────────────────────────────────────────────────────────────────>
     │                          │                      │                   │
     │                          │                      │ 6. Fetch tx       │
     │                          │                      │    details        │
     │                          │                      │<──────────────────│
     │                          │                      │                   │
     │                          │                      │ 7. Transaction    │
     │                          │                      │    info           │
     │                          │                      │──────────────────>│
     │                          │                      │                   │
     │ 8. Show on phone:        │                      │                   │
     │    "Confirm transfer     │                      │                   │
     │     $10,000 to John Doe  │                      │                   │
     │     Account: ****1234"   │                      │                   │
     │<────────────────────────────────────────────────────────────────────│
     │                          │                      │                   │
     │ 9. Approve (biometric)   │                      │                   │
     │─────────────────────────────────────────────────────────────────────>
     │                          │                      │                   │
     │                          │                      │ 10. PQC-signed    │
     │                          │                      │     authorization │
     │                          │                      │<──────────────────│
     │                          │                      │                   │
     │                          │ 11. Authorization    │                   │
     │                          │     signature        │                   │
     │                          │<─────────────────────│                   │
     │                          │                      │                   │
     │ 12. Transfer             │                      │                   │
     │     completed!           │                      │                   │
     │<─────────────────────────│                      │                   │
     │                          │                      │                   │
```

### Transaction Consent Screen (Mobile App)

```
┌─────────────────────────────────────┐
│                                     │
│      [Bank Logo]                    │
│      Example Bank                   │
│                                     │
│  ─────────────────────────────────  │
│                                     │
│  CONFIRM TRANSFER                   │
│                                     │
│  Amount:     $10,000.00 USD         │
│  To:         John Doe               │
│  Account:    ****1234               │
│  Reference:  INV-2025-001           │
│                                     │
│  From your account:                 │
│  Checking ****5678                  │
│                                     │
│  ─────────────────────────────────  │
│                                     │
│  ⚠️  Review carefully before        │
│      approving                      │
│                                     │
│  ┌─────────────────────────────┐    │
│  │     [Approve Transfer]      │    │
│  │     Use Face ID to confirm  │    │
│  └─────────────────────────────┘    │
│                                     │
│         [Cancel]                    │
│                                     │
└─────────────────────────────────────┘
```

### Transaction Authorization Response

```json
{
  "session_id": "uuid",
  "transaction_id": "tx-uuid",
  "status": "approved",
  "authorization": {
    "signature": "<pqc-signature-base64>",
    "algorithm": "KAZ128",
    "signed_data": {
      "transaction_id": "tx-uuid",
      "amount": "10000.00",
      "currency": "USD",
      "recipient_account_hash": "sha256...",
      "timestamp": "2025-12-01T12:00:00Z",
      "user_id": "user-uuid",
      "device_id": "device-uuid"
    },
    "certificate_serial": "1234567890"
  }
}
```

---

## Physical Access QR Flow

### Access Control Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHYSICAL ACCESS CONTROL FLOW                          │
└─────────────────────────────────────────────────────────────────────────────┘

   Door Panel              Access System              IdP              Phone App
       │                        │                      │                   │
       │ 1. Display QR          │                      │                   │
       │    (rotating every     │                      │                   │
       │     30 seconds)        │                      │                   │
       │<───────────────────────│                      │                   │
       │                        │                      │                   │
       │         ┌──────────────────────────────────────────────────────┐  │
       │         │  User approaches door, scans QR with Digital ID app │  │
       │         └──────────────────────────────────────────────────────┘  │
       │                        │                      │                   │
       │                        │                      │ 2. Validate      │
       │                        │                      │    access QR     │
       │                        │                      │<──────────────────│
       │                        │                      │                   │
       │                        │                      │ 3. Check user    │
       │                        │                      │    access rights │
       │                        │                      │                   │
       │                        │                      │ 4. Access        │
       │                        │                      │    permitted     │
       │                        │                      │──────────────────>│
       │                        │                      │                   │
       │                        │                      │                   │ 5. Show:
       │                        │                      │                   │ "Building A
       │                        │                      │                   │  Server Room"
       │                        │                      │                   │
       │                        │                      │ 6. User approves │
       │                        │                      │    (biometric)   │
       │                        │                      │<──────────────────│
       │                        │                      │                   │
       │                        │ 7. Access granted    │                   │
       │                        │    notification      │                   │
       │                        │<─────────────────────│                   │
       │                        │                      │                   │
       │ 8. Unlock door         │                      │                   │
       │<───────────────────────│                      │                   │
       │                        │                      │                   │
       │ 9. Green light         │                      │                   │
       │    + beep              │                      │                   │
       │                        │                      │                   │
```

### Access QR Rotation

For security, physical access QR codes should rotate frequently:

```csharp
// Access Control System - QrRotationService.cs
public class QrRotationService : BackgroundService
{
    private readonly IAccessPointRepository _accessPoints;
    private readonly IIdpClient _idpClient;
    private readonly IQrDisplayClient _displayClient;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var accessPoints = await _accessPoints.GetAllActiveAsync(ct);

            foreach (var point in accessPoints)
            {
                // Create new QR session
                var session = await _idpClient.CreateAccessQrSessionAsync(
                    new CreateAccessQrRequest
                    {
                        LocationId = point.Id,
                        LocationName = point.DisplayName,
                        AccessLevel = point.AccessLevel,
                        ValiditySeconds = 30  // Short validity
                    }, ct);

                // Push new QR to display
                await _displayClient.UpdateQrAsync(
                    point.DisplayDeviceId,
                    session.QrImageData,
                    ct);
            }

            // Wait before next rotation
            await Task.Delay(TimeSpan.FromSeconds(25), ct);
        }
    }
}
```

### Offline Access Mode

For scenarios where network connectivity is limited:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OFFLINE ACCESS MODE                                 │
└─────────────────────────────────────────────────────────────────────────────┘

1. Access point generates challenge QR (no network needed)
2. User's phone:
   a. Parses challenge
   b. Signs with user's private key (offline)
   c. Generates response QR code
3. User shows response QR to access point scanner
4. Access point:
   a. Verifies signature against cached public key
   b. Checks user permissions in local cache
   c. Grants/denies access
5. Access log synced when connectivity restored
```

---

## Document Signing QR Flow

### Signing Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DOCUMENT SIGNING FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

User (Desktop)           Doc System              IdP              Phone App
     │                       │                    │                   │
     │ 1. Open document      │                    │                   │
     │    "Employment        │                    │                   │
     │     Contract.pdf"     │                    │                   │
     │──────────────────────>│                    │                   │
     │                       │                    │                   │
     │ 2. Document preview   │                    │                   │
     │<──────────────────────│                    │                   │
     │                       │                    │                   │
     │ 3. Click "Sign with   │                    │                   │
     │    Digital ID"        │                    │                   │
     │──────────────────────>│                    │                   │
     │                       │                    │                   │
     │                       │ 4. Calculate       │                   │
     │                       │    document hash   │                   │
     │                       │                    │                   │
     │                       │ 5. Create signing  │                   │
     │                       │    QR session      │                   │
     │                       │───────────────────>│                   │
     │                       │                    │                   │
     │                       │ 6. Session +       │                   │
     │                       │    QR data         │                   │
     │                       │<───────────────────│                   │
     │                       │                    │                   │
     │ 7. Show QR with       │                    │                   │
     │    doc info           │                    │                   │
     │<──────────────────────│                    │                   │
     │                       │                    │                   │
     │ 8. Scan QR            │                    │                   │
     │──────────────────────────────────────────────────────────────>│
     │                       │                    │                   │
     │                       │                    │ 9. Fetch doc info │
     │                       │                    │<──────────────────│
     │                       │                    │                   │
     │                       │                    │ 10. Document      │
     │                       │                    │     metadata      │
     │                       │                    │──────────────────>│
     │                       │                    │                   │
     │ 11. Show doc preview  │                    │                   │
     │     on phone          │                    │                   │
     │<─────────────────────────────────────────────────────────────│
     │                       │                    │                   │
     │ 12. Review & sign     │                    │                   │
     │     (biometric)       │                    │                   │
     │──────────────────────────────────────────────────────────────>│
     │                       │                    │                   │
     │                       │                    │ 13. Document      │
     │                       │                    │     signature     │
     │                       │                    │<──────────────────│
     │                       │                    │                   │
     │                       │ 14. PQC signature  │                   │
     │                       │     + certificate  │                   │
     │                       │<───────────────────│                   │
     │                       │                    │                   │
     │                       │ 15. Embed          │                   │
     │                       │     signature      │                   │
     │                       │     in PDF         │                   │
     │                       │                    │                   │
     │ 16. Document signed!  │                    │                   │
     │     Download signed   │                    │                   │
     │     PDF               │                    │                   │
     │<──────────────────────│                    │                   │
     │                       │                    │                   │
```

### Signing Consent Screen (Mobile App)

```
┌─────────────────────────────────────┐
│                                     │
│      [DocSign Logo]                 │
│      Example DocSign                │
│                                     │
│  ─────────────────────────────────  │
│                                     │
│  SIGN DOCUMENT                      │
│                                     │
│  📄 Employment Contract.pdf         │
│     12 pages • 245 KB               │
│                                     │
│  ┌─────────────────────────────┐    │
│  │  [Document Preview Image]   │    │
│  │                             │    │
│  │  Page 12 - Signature Area   │    │
│  │                             │    │
│  └─────────────────────────────┘    │
│                                     │
│  Document Hash (SHA-256):           │
│  a3f2...8b91                        │
│                                     │
│  Signing as:                        │
│  John Doe                           │
│  john.doe@example.com               │
│                                     │
│  ⚠️  This creates a legally         │
│      binding digital signature      │
│                                     │
│  ┌─────────────────────────────┐    │
│  │     [Sign Document]         │    │
│  │     Use Face ID to sign     │    │
│  └─────────────────────────────┘    │
│                                     │
│         [Cancel]                    │
│                                     │
└─────────────────────────────────────┘
```

### Document Signature Structure

```json
{
  "signature_info": {
    "signer": {
      "user_id": "user-uuid",
      "name": "John Doe",
      "email": "john.doe@example.com",
      "organization": "Example Corp",
      "certificate_serial": "1234567890"
    },
    "timestamp": "2025-12-01T12:00:00Z",
    "location": "San Francisco, CA",
    "reason": "Employment Agreement"
  },
  "document": {
    "hash": "sha256-of-document",
    "hash_algorithm": "SHA-256",
    "name": "Employment Contract.pdf"
  },
  "signature": {
    "algorithm": "KAZ128",
    "value": "<pqc-signature-base64>",
    "certificate_chain": [
      "<user-certificate-pem>",
      "<tenant-ca-certificate-pem>",
      "<root-ca-certificate-pem>"
    ]
  },
  "timestamp_token": {
    "tsa_url": "https://tsa.idp.example.com",
    "token": "<timestamp-token-base64>"
  }
}
```

---

## QR Code Specification

### QR Code Format

| Property | Value |
|----------|-------|
| Version | Auto (based on data size) |
| Error Correction | Level M (15%) |
| Encoding | UTF-8 |
| Format | URL scheme |

### URL Scheme

```
idp://qr/{type}?data={base64url-encoded-json}

Examples:
idp://qr/login?data=eyJ0eXBlIjoiaWRwX2xvZ2luIi...
idp://qr/transaction?data=eyJ0eXBlIjoiaWRwX3RyYW5z...
idp://qr/access?data=eyJ0eXBlIjoiaWRwX2FjY2Vzcy...
idp://qr/sign?data=eyJ0eXBlIjoiaWRwX3NpZ24iLC...
```

### QR Data Structure

```typescript
interface QrCodeData {
  // Common fields
  type: 'idp_login' | 'idp_transaction' | 'idp_access' | 'idp_sign';
  version: '1';
  session_id: string;
  expires: number;  // Unix timestamp
  checksum: string; // SHA-256 of other fields

  // RP identification
  rp_id: string;
  rp_name: string;
  rp_logo?: string;

  // Type-specific fields
  // ... varies by type
}
```

### Checksum Calculation

```typescript
function calculateChecksum(data: QrCodeData): string {
  const { checksum, ...rest } = data;
  const canonicalJson = JSON.stringify(rest, Object.keys(rest).sort());
  return sha256(canonicalJson).substring(0, 16);
}
```

### QR Image Generation

```csharp
// IdP Backend - QrCodeGenerator.cs
public class QrCodeGenerator : IQrCodeGenerator
{
    public byte[] GenerateQrCode(string content, QrCodeOptions options)
    {
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(
            content,
            QRCodeGenerator.ECCLevel.M  // 15% error correction
        );

        using var qrCode = new PngByteQRCode(qrCodeData);
        return qrCode.GetGraphic(
            options.PixelsPerModule,    // Default: 10
            options.DarkColor,          // Default: black
            options.LightColor          // Default: white
        );
    }

    public string GenerateQrCodeDataUrl(string content, QrCodeOptions options)
    {
        var pngBytes = GenerateQrCode(content, options);
        return $"data:image/png;base64,{Convert.ToBase64String(pngBytes)}";
    }
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| QR code screenshot/photo | Short expiration (30-60 seconds), single use |
| Session hijacking | Device binding, biometric required |
| Replay attacks | Nonce and timestamp validation |
| Phishing (fake QR) | RP verification, domain display |
| Man-in-the-middle | TLS, signature verification |
| Malicious RP impersonation | RP registry, visual indicators |

### Session Security

```csharp
public class QrSessionConfiguration
{
    // Session lifetimes
    public TimeSpan LoginQrLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan TransactionQrLifetime { get; set; } = TimeSpan.FromMinutes(3);
    public TimeSpan AccessQrLifetime { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan SigningQrLifetime { get; set; } = TimeSpan.FromMinutes(10);

    // Security settings
    public bool RequireDeviceBinding { get; set; } = true;
    public bool RequireBiometric { get; set; } = true;
    public bool SingleUse { get; set; } = true;
    public int MaxScanAttempts { get; set; } = 3;

    // Rate limiting
    public int MaxSessionsPerUser { get; set; } = 5;
    public int MaxSessionsPerRp { get; set; } = 1000;
}
```

### RP Verification

```
┌─────────────────────────────────────┐
│                                     │
│  ⚠️  UNVERIFIED APPLICATION         │
│                                     │
│  "Unknown App" wants to sign you in │
│                                     │
│  This application has not been      │
│  verified by your organization.     │
│                                     │
│  Domain: suspicious-site.example    │
│                                     │
│  [Continue Anyway]  [Cancel]        │
│                                     │
└─────────────────────────────────────┘

vs.

┌─────────────────────────────────────┐
│                                     │
│  ✓  VERIFIED                        │
│                                     │
│      [Example Bank Logo]            │
│      Example Bank                   │
│                                     │
│  Verified by: Example Organization  │
│  Domain: bank.example.com           │
│                                     │
│  [Approve]  [Deny]                  │
│                                     │
└─────────────────────────────────────┘
```

### Audit Logging

```csharp
public enum QrAuthAuditEvent
{
    SessionCreated,
    QrGenerated,
    QrScanned,
    SessionValidated,
    ConsentShown,
    UserApproved,
    UserDenied,
    AssertionSubmitted,
    AssertionVerified,
    SessionCompleted,
    SessionExpired,
    SessionFailed,
    SuspiciousActivity
}

public class QrAuthAuditEntry
{
    public Guid Id { get; set; }
    public Guid SessionId { get; set; }
    public QrAuthAuditEvent Event { get; set; }
    public DateTime Timestamp { get; set; }

    // Context
    public Guid? UserId { get; set; }
    public Guid? DeviceId { get; set; }
    public string? ClientId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    // Event-specific data
    public JsonDocument? Details { get; set; }
}
```

---

## Relying Party Integration

### SDK Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RP SDK ARCHITECTURE                                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  RP Application                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   QR Login      │  │  QR Transaction │  │   QR Signing    │             │
│  │   Component     │  │   Component     │  │   Component     │             │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘             │
│           │                    │                    │                       │
│           └────────────────────┼────────────────────┘                       │
│                                │                                            │
│                    ┌───────────┴───────────┐                                │
│                    │    IdP SDK Client     │                                │
│                    │  ┌─────────────────┐  │                                │
│                    │  │ Session Manager │  │                                │
│                    │  │ Token Handler   │  │                                │
│                    │  │ WebSocket Client│  │                                │
│                    │  │ Signature Verif │  │                                │
│                    │  └─────────────────┘  │                                │
│                    └───────────┬───────────┘                                │
│                                │                                            │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                                 │ HTTPS / WSS
                                 │
                    ┌────────────┴────────────┐
                    │      IdP Backend        │
                    └─────────────────────────┘
```

### .NET SDK Usage

```csharp
// Install: dotnet add package IdP.Sdk

// Startup.cs
services.AddIdpClient(options =>
{
    options.Authority = "https://idp.example.com";
    options.ClientId = "my-app-client-id";
    options.ClientSecret = "my-app-client-secret";
});

// Controller
public class AuthController : Controller
{
    private readonly IIdpQrAuthService _qrAuth;

    [HttpGet("login")]
    public async Task<IActionResult> ShowLogin()
    {
        var session = await _qrAuth.CreateLoginSessionAsync(new QrLoginOptions
        {
            Scopes = new[] { "openid", "profile", "email" },
            RedirectUri = Url.Action("Callback", "Auth", null, Request.Scheme)
        });

        return View(new LoginViewModel
        {
            QrCodeDataUrl = session.QrCodeDataUrl,
            SessionId = session.SessionId,
            WebSocketUrl = session.WebSocketUrl
        });
    }

    [HttpGet("callback")]
    public async Task<IActionResult> Callback(string code, string state)
    {
        var tokens = await _qrAuth.ExchangeCodeAsync(code);

        // Create session, redirect to app
        await HttpContext.SignInAsync(CreatePrincipal(tokens));
        return RedirectToAction("Index", "Home");
    }
}
```

### JavaScript SDK Usage

```typescript
// Install: npm install @idp/sdk

import { IdpClient, QrLoginComponent } from '@idp/sdk';

// Initialize client
const idp = new IdpClient({
    authority: 'https://idp.example.com',
    clientId: 'my-spa-client-id',
    redirectUri: 'https://myapp.com/callback'
});

// Create QR login component
const qrLogin = new QrLoginComponent({
    container: '#qr-login-container',
    scopes: ['openid', 'profile', 'email'],
    onSuccess: async (result) => {
        // Exchange code for tokens
        const tokens = await idp.exchangeCode(result.code);
        // Store tokens, update UI
        setUserLoggedIn(tokens);
    },
    onError: (error) => {
        console.error('Login failed:', error);
        showError(error.message);
    },
    onScanned: () => {
        showMessage('QR scanned! Approve on your phone.');
    }
});

// Render QR login
qrLogin.render();
```

### React Component

```tsx
// Install: npm install @idp/react-sdk

import { QrLogin, useIdp } from '@idp/react-sdk';

function LoginPage() {
    const { login, isLoading, error } = useIdp();

    const handleSuccess = async (result: QrLoginResult) => {
        await login(result.code);
        navigate('/dashboard');
    };

    return (
        <div className="login-container">
            <h1>Sign in with Digital ID</h1>

            <QrLogin
                scopes={['openid', 'profile', 'email']}
                onSuccess={handleSuccess}
                onError={(err) => console.error(err)}
                onScanned={() => setStatus('Approve on your phone...')}
                theme="light"
                size={256}
            />

            {error && <p className="error">{error.message}</p>}
        </div>
    );
}
```

---

## Mobile App Implementation

### QR Scanner (iOS)

```swift
// iOS - QrScannerViewController.swift
import AVFoundation
import UIKit

class QrScannerViewController: UIViewController {

    private var captureSession: AVCaptureSession!
    private var previewLayer: AVCaptureVideoPreviewLayer!

    override func viewDidLoad() {
        super.viewDidLoad()
        setupScanner()
    }

    private func setupScanner() {
        captureSession = AVCaptureSession()

        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video),
              let videoInput = try? AVCaptureDeviceInput(device: videoCaptureDevice),
              captureSession.canAddInput(videoInput) else {
            showError("Camera not available")
            return
        }

        captureSession.addInput(videoInput)

        let metadataOutput = AVCaptureMetadataOutput()
        if captureSession.canAddOutput(metadataOutput) {
            captureSession.addOutput(metadataOutput)
            metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
            metadataOutput.metadataObjectTypes = [.qr]
        }

        previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        previewLayer.frame = view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)

        // Add scanning overlay
        addScanningOverlay()

        DispatchQueue.global(qos: .userInitiated).async {
            self.captureSession.startRunning()
        }
    }
}

extension QrScannerViewController: AVCaptureMetadataOutputObjectsDelegate {

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let metadataObject = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let stringValue = metadataObject.stringValue,
              stringValue.starts(with: "idp://") else {
            return
        }

        // Stop scanning
        captureSession.stopRunning()

        // Haptic feedback
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()

        // Process QR code
        Task {
            await processQrCode(stringValue)
        }
    }

    private func processQrCode(_ urlString: String) async {
        do {
            // Parse QR URL
            let qrData = try QrCodeParser.parse(urlString)

            // Validate checksum
            guard qrData.isChecksumValid else {
                throw QrError.invalidChecksum
            }

            // Check expiration
            guard qrData.expires > Date().timeIntervalSince1970 else {
                throw QrError.expired
            }

            // Handle based on type
            switch qrData.type {
            case .login:
                await handleLoginQr(qrData)
            case .transaction:
                await handleTransactionQr(qrData)
            case .access:
                await handleAccessQr(qrData)
            case .sign:
                await handleSigningQr(qrData)
            }

        } catch {
            await MainActor.run {
                showError(error.localizedDescription)
                captureSession.startRunning()
            }
        }
    }

    private func handleLoginQr(_ qrData: QrCodeData) async {
        // Validate session with IdP
        let sessionDetails = try await IdpClient.shared.validateQrSession(
            sessionId: qrData.sessionId
        )

        // Show consent screen
        let consent = await showConsentScreen(
            rpName: sessionDetails.rpName,
            rpLogo: sessionDetails.rpLogo,
            scopes: sessionDetails.scopes,
            isVerified: sessionDetails.rpVerified
        )

        guard consent.approved else {
            // User denied
            try await IdpClient.shared.denyQrSession(sessionId: qrData.sessionId)
            dismiss(animated: true)
            return
        }

        // Authenticate and sign
        let authenticated = try await BiometricAuth.authenticate(
            reason: "Sign in to \(sessionDetails.rpName)"
        )

        guard authenticated else {
            throw AuthError.biometricsFailed
        }

        // Create and submit assertion
        let assertion = try await createAssertion(
            sessionId: qrData.sessionId,
            nonce: sessionDetails.nonce
        )

        try await IdpClient.shared.approveQrSession(
            sessionId: qrData.sessionId,
            assertion: assertion
        )

        // Show success
        await MainActor.run {
            showSuccess("Signed in to \(sessionDetails.rpName)")
            dismiss(animated: true)
        }
    }
}
```

### QR Code Parser

```swift
// iOS - QrCodeParser.swift
struct QrCodeData: Decodable {
    let type: QrType
    let version: String
    let sessionId: String
    let rpId: String
    let rpName: String
    let rpLogo: String?
    let expires: TimeInterval
    let checksum: String

    // Type-specific
    let scopes: [String]?
    let transaction: TransactionData?
    let document: DocumentData?
    let locationId: String?
    let locationName: String?

    var isChecksumValid: Bool {
        let computed = Self.computeChecksum(self)
        return computed == checksum
    }

    private static func computeChecksum(_ data: QrCodeData) -> String {
        // Remove checksum field and compute hash
        var dict = data.asDictionary()
        dict.removeValue(forKey: "checksum")
        let json = try! JSONSerialization.data(
            withJSONObject: dict.sorted { $0.key < $1.key },
            options: .sortedKeys
        )
        return SHA256.hash(data: json).prefix(16).hexString
    }
}

enum QrType: String, Decodable {
    case login = "idp_login"
    case transaction = "idp_transaction"
    case access = "idp_access"
    case sign = "idp_sign"
}

class QrCodeParser {

    static func parse(_ urlString: String) throws -> QrCodeData {
        guard let url = URL(string: urlString),
              url.scheme == "idp",
              url.host == "qr",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let dataParam = components.queryItems?.first(where: { $0.name == "data" })?.value,
              let jsonData = Data(base64URLEncoded: dataParam) else {
            throw QrError.invalidFormat
        }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase

        return try decoder.decode(QrCodeData.self, from: jsonData)
    }
}
```

---

## API Reference

### Create QR Session

```http
POST /api/v1/qr/sessions
Content-Type: application/json
Authorization: Bearer <client-credentials-token>

{
  "type": "login" | "transaction" | "access" | "sign",
  "client_id": "rp-client-123",

  // For login
  "redirect_uri": "https://example.com/callback",
  "scopes": ["openid", "profile", "email"],
  "state": "random-state",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",

  // For transaction
  "transaction": {
    "type": "transfer",
    "amount": "10000.00",
    "currency": "USD",
    "recipient": "John Doe",
    "recipient_account": "****1234",
    "reference": "INV-2025-001"
  },

  // For access
  "location_id": "building-a-door-5",
  "location_name": "Building A - Server Room",
  "access_level": "restricted",

  // For signing
  "document": {
    "id": "doc-uuid",
    "name": "Contract.pdf",
    "hash": "sha256...",
    "hash_algorithm": "SHA-256"
  }
}

Response 201 Created:
{
  "session_id": "uuid",
  "qr_data": "idp://qr/login?data=...",
  "qr_image_url": "/api/v1/qr/sessions/{session_id}/qr.png",
  "expires_at": "2025-12-01T12:05:00Z",
  "ws_url": "wss://idp.example.com/ws/qr/{session_id}",
  "poll_url": "/api/v1/qr/sessions/{session_id}/status"
}
```

### Get Session Status

```http
GET /api/v1/qr/sessions/{session_id}/status

Response 200 OK:
{
  "status": "pending" | "scanned" | "approved" | "denied" | "expired",
  "scanned_at": "2025-12-01T12:01:00Z",
  "completed_at": "2025-12-01T12:01:30Z",

  // If approved (login)
  "code": "authorization-code",
  "state": "random-state",

  // If approved (transaction/signing)
  "authorization": {
    "signature": "...",
    "certificate_serial": "..."
  }
}
```

### Scan QR (Mobile App → IdP)

```http
POST /api/v1/qr/sessions/{session_id}/scan
Content-Type: application/json
Authorization: Bearer <user-access-token>

{
  "device_id": "device-uuid"
}

Response 200 OK:
{
  "rp_name": "Example Application",
  "rp_logo": "https://example.com/logo.png",
  "rp_verified": true,
  "rp_verification_level": "organization",

  // For login
  "scopes": ["openid", "profile", "email"],
  "scope_descriptions": {
    "openid": "Verify your identity",
    "profile": "Access your name and photo",
    "email": "Access your email address"
  },

  // For transaction
  "transaction": {
    "type": "transfer",
    "amount": "10000.00",
    "currency": "USD",
    "recipient": "John Doe",
    "recipient_account": "****1234"
  },

  // For signing
  "document": {
    "name": "Employment Contract.pdf",
    "pages": 12,
    "preview_url": "/api/v1/documents/{id}/preview"
  }
}
```

### Approve QR Session

```http
POST /api/v1/qr/sessions/{session_id}/approve
Content-Type: application/json
Authorization: Bearer <user-access-token>

{
  "assertion": "<signed-jwt>",
  "device_id": "device-uuid"
}

Response 200 OK:
{
  "status": "approved",
  "message": "Authentication successful"
}
```

### Deny QR Session

```http
POST /api/v1/qr/sessions/{session_id}/deny
Content-Type: application/json
Authorization: Bearer <user-access-token>

{
  "reason": "user_cancelled" | "suspicious" | "wrong_app"
}

Response 200 OK:
{
  "status": "denied"
}
```

### WebSocket Messages

```typescript
// Connect
ws://idp.example.com/ws/qr/{session_id}

// Server → Client messages
interface WsMessage {
  type: 'scanned' | 'approved' | 'denied' | 'expired' | 'error';
  timestamp: string;

  // For 'approved' (login)
  redirect_url?: string;

  // For 'approved' (transaction/signing)
  authorization?: {
    signature: string;
    certificate_serial: string;
  };

  // For 'error'
  error_code?: string;
  error_message?: string;
}
```

---

## Implementation Checklist

### Phase 1: Core Infrastructure

- [ ] **QR Session Management**
  - [ ] Session creation API
  - [ ] Session storage (Redis)
  - [ ] Session expiration handling
  - [ ] Status tracking

- [ ] **QR Code Generation**
  - [ ] QR data structure
  - [ ] Checksum calculation
  - [ ] Image generation
  - [ ] URL encoding

- [ ] **Real-time Updates**
  - [ ] WebSocket server
  - [ ] Session subscriptions
  - [ ] Fallback polling API

### Phase 2: Authentication Types

- [ ] **Login QR**
  - [ ] OIDC integration
  - [ ] PKCE support
  - [ ] Token issuance

- [ ] **Transaction QR**
  - [ ] Transaction data structure
  - [ ] Signature generation
  - [ ] Authorization response

- [ ] **Access QR**
  - [ ] Access point integration
  - [ ] QR rotation
  - [ ] Offline mode

- [ ] **Signing QR**
  - [ ] Document hash verification
  - [ ] Signature embedding
  - [ ] Timestamp service

### Phase 3: Mobile App

- [ ] **QR Scanner**
  - [ ] Camera integration
  - [ ] QR parsing
  - [ ] Checksum validation

- [ ] **Consent UI**
  - [ ] Login consent screen
  - [ ] Transaction consent screen
  - [ ] Access consent screen
  - [ ] Signing consent screen

- [ ] **Authentication**
  - [ ] Biometric integration
  - [ ] Assertion generation
  - [ ] PQC signing

### Phase 4: RP SDKs

- [ ] **.NET SDK**
  - [ ] Session management
  - [ ] Token exchange
  - [ ] Signature verification

- [ ] **JavaScript SDK**
  - [ ] Browser components
  - [ ] React components
  - [ ] WebSocket handling

- [ ] **Documentation**
  - [ ] Integration guide
  - [ ] API reference
  - [ ] Example applications

---

## References

- [AUTHENTICATION_FLOW.md](./AUTHENTICATION_FLOW.md) - Core OIDC authentication
- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - User registration
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Certificate management
- [OAuth 2.0 Device Authorization Grant RFC 8628](https://tools.ietf.org/html/rfc8628)
- [FIDO2 WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
