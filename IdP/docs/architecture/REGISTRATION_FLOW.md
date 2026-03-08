# Digital ID User Online Registration Flow

**Version:** 1.1.0
**Last Updated:** 2025-12-05
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [System Components](#system-components)
3. [Registration Flow Summary](#registration-flow-summary)
4. [Detailed Flow Steps](#detailed-flow-steps)
5. [Cryptographic Operations](#cryptographic-operations)
6. [Secret Sharing Scheme](#secret-sharing-scheme)
7. [Data Structures](#data-structures)
8. [Biometric Key Protection Architecture](#biometric-key-protection-architecture)
9. [Security Considerations](#security-considerations)
10. [Recovery Token Management](#recovery-token-management)

---

## Overview

This document describes the PQC (Post-Quantum Cryptography) Digital ID User Online Registration flow. The registration process involves:

- **Device and User Key Pair Generation** using **KAZ-SIGN-256** (Security Level 5 - fixed)
- **Certificate Signing Requests (CSR)** for both device and user identities
- **Secret Sharing** of user private key into 3 parts for recovery
- **Multi-party Encryption** of key shares using **KAZ-KEM-256** (Security Level 5 - fixed)
- **Certificate Issuance** by the Digital ID backend
- **Recovery Token Generation** for account recovery

### Key Principles

1. **User Private Key Never Leaves Device Unencrypted** - Split into shares before transmission
2. **Three-Party Secret Sharing** - User, Recovery Password, and System each hold a share
3. **PQC Throughout** - All cryptographic operations use post-quantum algorithms (KAZ-SIGN-256, KAZ-KEM-256)
4. **Device Binding** - Device certificate binds the device to the user identity
5. **Single Device Policy** - Each user can only have ONE registered device at a time
6. **Fixed Algorithm** - KAZ-SIGN-256 and KAZ-KEM-256 are mandatory (no user selection)
7. **Biometric-Protected Keys** - Device private key protected by hardware-backed biometric authentication (no device password)

---

## System Components

### Mobile App Side

| Component | Responsibility |
|-----------|----------------|
| **Mobile UI** | User interface for registration input |
| **Key Manager** | Orchestrates key generation and storage |
| **PQC Library (KAZ)** | KAZ-SIGN-256 key generation and signing (native C library) |
| **ASN.1/DER Builder** | Platform-specific CSR structure building (Swift/Kotlin/ArkTS) |
| **Crypto Library** | AES-GCM encryption, secret sharing |
| **Biometric Manager** | Hardware-backed biometric authentication (Face ID/Touch ID/Fingerprint) |
| **Key Vault** | Secure local storage (Keychain/KeyStore/HUKS) with biometric protection |

### Backend Side

| Component | Responsibility |
|-----------|----------------|
| **CSR Responder (RA)** | Registration Authority - validates and processes CSRs |
| **Digital ID Credential Manager** | Issues certificates, manages credentials |
| **Recovery Manager** | Manages recovery tokens and key shares |
| **Digital ID DB** | Persistent storage for certificates and recovery data |

---

## Registration Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    REGISTRATION FLOW - HIGH LEVEL                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Phase 1    │────>│   Phase 2    │────>│   Phase 3    │────>│   Phase 4    │
│ Key Gen &    │     │ Secret Share │     │ CSR Submit   │     │ Certificate  │
│ CSR Creation │     │ & Encryption │     │ & Verify     │     │ Issuance     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                      │
                                                                      ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Phase 8    │<────│   Phase 7    │<────│   Phase 6    │<────│   Phase 5    │
│  Activation  │     │ Cert Polling │     │ Recovery     │     │ Cert Binding │
│  Complete    │     │ & Download   │     │ Token Gen    │     │ to Profile   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

---

## Detailed Flow Steps

### Phase 1: Key Generation and CSR Creation

#### Step 1.1: User Initiates Registration

> **Note:** Algorithm is fixed to KAZ-SIGN-256 (Security Level 5). No user selection required.
> **Note:** Device private key is protected by biometric authentication (no device password required).

**Input from Mobile UI:**
```
{
  algo: "KAZ-SIGN-256",       // Fixed - Security Level 5 (no selection)
  user_info: {
    full_name: string,        // User's full name (as per MyKad)
    mykad_number: string,     // Malaysian IC number
    email: string,            // Email address (verified via OTP)
    phone: string             // Phone number (verified via SMS OTP)
  },
  recovery_password: string   // User's recovery password (memorized) - ONLY password required
}
```

#### Step 1.2: Generate Key Pairs

**Key Manager → PQC Library (KAZ):**
```
Generate:
  1. Device keypair (for device identity)
  2. User keypair (for user identity)
```

**Returns:**
```
{
  device_keypair: {
    public_key: bytes,
    private_key: bytes
  },
  user_keypair: {
    public_key: bytes,
    private_key: bytes
  }
}
```

#### Step 1.3: Generate CSRs

> **Implementation:** CSR generation uses platform ASN.1/DER libraries for structure building,
> combined with native KAZ-SIGN-256 library for signing. See [CSR_GENERATION.md](./CSR_GENERATION.md).

**Key Manager → ASN.1 Builder → PQC Library (KAZ):**
```
For each keypair (device, user):
  1. Build CertificationRequestInfo (TBS) using ASN.1/DER
     - Version (0)
     - Subject DN (name, MyKad, email, organization, country)
     - SubjectPublicKeyInfo (KAZ-SIGN-256 OID + public key)
     - Attributes (empty)

  2. Sign TBS with private key using native KAZ-SIGN-256
     → signature = kaz_sign_sign(private_key, tbs_bytes)

  3. Assemble final CSR
     - CertificationRequestInfo (TBS)
     - SignatureAlgorithm (KAZ-SIGN-256 OID)
     - Signature (BIT STRING)
```

**Platform ASN.1/DER Libraries:**

| Platform | ASN.1 Library | Native Sign Function |
|----------|---------------|---------------------|
| **iOS** | Custom DERBuilder (Swift) | `kaz_sign_sign()` via C interop |
| **Android** | Bouncy Castle or custom | `kaz_sign_sign()` via JNI |
| **HarmonyOS** | Custom DERBuilder (ArkTS) | `kaz_sign_sign()` via N-API |

**CSR Structure (X.509 PKCS#10):**
```asn1
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  CertificationRequestInfo,
  signatureAlgorithm        AlgorithmIdentifier,  -- KAZ-SIGN-256 OID
  signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
  version       INTEGER (0),
  subject       Name,
  subjectPKInfo SubjectPublicKeyInfo,
  attributes    [0] IMPLICIT Attributes
}
```

**CSR Subject DN Contents:**
- Common Name (CN): Full name as per MyKad
- Serial Number: MyKad number (IC)
- Email Address: Verified email
- Organization (O): "PQC Identity" or tenant name
- Country (C): "MY"

---

### Phase 2: Secret Sharing and Encryption

#### Step 2.1: Protect Device Private Key with Biometric

**Key Manager → Biometric Manager → Key Vault:**
```
1. Generate AES-256 master key in secure hardware (TEE/Secure Enclave/HUKS)
2. Bind master key to biometric authentication
3. Encrypt device_private_key with master key
4. Store encrypted key in Key Vault
```

**Platform-Specific Implementation:**

| Platform | Secure Hardware | Biometric API | Key Storage |
|----------|-----------------|---------------|-------------|
| **iOS** | Secure Enclave | LocalAuthentication (Face ID/Touch ID) | Keychain Services |
| **Android** | TEE / StrongBox | BiometricPrompt | Android Keystore |
| **HarmonyOS** | iTrustee TEE | userIAM.userAuth | HUKS |

**Security Properties:**
- Master key is **non-extractable** (never leaves secure hardware)
- Every signing operation requires **fresh biometric authentication**
- Key is **invalidated** if biometric enrollment changes
- No password to remember for daily device usage

**Output:**
```
{device_private_key} encrypted with {biometric-protected master key}
→ Stored in platform Key Vault
```

#### Step 2.2: Split User Private Key (Secret Sharing)

**Key Manager → Crypto Library:**
```
Split user_private_key into 3 parts using Secret Sharing (Shamir's)
→ part_user, part_control, part_recovery
```

**Secret Sharing Scheme:**
- **Threshold:** 2-of-3 (any 2 parts can reconstruct the key)
- **Parts:**
  1. `part_user` - Stored on user's device
  2. `part_control` - Stored by Digital ID System
  3. `part_recovery` - Encrypted with user's recovery password

#### Step 2.3: Encrypt Key Shares

**Three separate encryptions:**

| Share | Encryption Method | Key Used |
|-------|-------------------|----------|
| `part_user` | KEM Encapsulation | Device KEM public key |
| `part_recovery` | AES-GCM | Derived from recovery_password |
| `part_control` | KEM Encapsulation | Digital ID System KEM public key |

**Crypto Operations:**
```
1. [part_user] encrypted with device KEM pubkey
   → {part_user} / {device KEM pubkey}

2. [part_recovery] encrypted with recovery_password (AES-GCM)
   → {part_recovery} / {user recovery password}

3. [part_control] encrypted with Digital ID KEM public key
   → {part_control} / {Digital ID System}
```

#### Step 2.4: Store Locally

**Key Manager → Key Vault:**
```
Store:
  1. {device_private_key} encrypted with {biometric-protected master key}
  2. {part_user} encrypted with {device KEM public key}
```

**Key Vault Response:** `Store success`

---

### Phase 3: Submit Registration to Backend

#### Step 3.1: Create Account Request

**Key Manager → CSR Responder (RA):**
```
Submit to create account:
{
  1. encrypted_part_control,    // System's share of user private key
  2. device_csr,                // Device Certificate Signing Request
  3. user_csr,                  // User Certificate Signing Request
  4. encrypted_part_recovery,   // Recovery share (signed by device private key)
}

// Entire payload signed by device private key
```

#### Step 3.2: Backend Verification

**CSR Responder (RA):**
```
1. Verify device signature on submission
2. Validate CSR format and contents
3. Store CSR with pending status
```

**CSR Responder → Digital ID DB:**
```
Verified and store CSR
```

#### Step 3.3: Request Tracking ID

**CSR Responder → Digital ID Credential Manager:**
```
Request Tracking ID (RTID)
```

**Returns to Mobile App:**
```
Request Tracking ID (RTID)
```

> **Note:** RTID allows the mobile app to poll for certificate status

---

### Phase 4: Certificate Issuance

#### Step 4.1: CSR Approval

**Digital ID Credential Manager:**
```
Verified, approve CSR with Pending Status
```

**Status Flow:**
```
CSR Pending → CSR Approved → Certificate Issued
```

#### Step 4.2: Issue Certificates

**Digital ID Credential Manager:**
```
Issue certificates:
  1. User certificate (identity)
  2. Device certificate (device binding)
```

**Certificate Contents:**
- Subject DN (from CSR)
- Public Key (from CSR)
- Issuer DN (Organization CA)
- Validity Period
- Serial Number
- PQC Signature (signed by Organization CA key in HSM)

---

### Phase 5: Bind Certificates to User Profile

#### Step 5.1: Bind Device Certificate

**Digital ID Credential Manager → Digital ID DB:**
```
Bind device cert to user profile
```

**Response:** `Success`

#### Step 5.2: Bind Recovery Data

**Digital ID Credential Manager → Recovery Manager:**
```
Bind recovery to user profile
```

**Recovery Manager:**
```
Generate recovery token (part_recovery)
```

#### Step 5.3: Store Recovery Token

**Recovery Manager → Digital ID DB:**
```
Bind recovery token with user profile
```

**Response:** `Success`

---

### Phase 6: Certificate Status Polling

#### Step 6.1: Poll for Status

**Mobile App → CSR Responder:**
```
Check cert status (RTID signed with device private key)
```

#### Step 6.2: Verify and Retrieve

**CSR Responder:**
```
1. Verify device signature
2. Verify check cert status request
3. Pull cert status from Digital ID Credential Manager
```

**Digital ID Credential Manager Response:**
```
{
  device_certificate: bytes,
  user_certificates: bytes[],
  recovery_token: string
}
```

#### Step 6.3: Sign and Return Response

**CSR Responder:**
```
Sign response {
  device_cert,
  user_cert,
  recovery_token
}
```

**Returns to Mobile App:**
```
{Device, User Certificates, recovery token} / signed
```

---

### Phase 7: Activation

#### Step 7.1: Verify Backend Signature

**Mobile App:**
```
Verify signature from portal
```

#### Step 7.2: Activate Identity

**Mobile App → Key Vault:**
```
Activate device and user identity
```

- Store certificates in secure storage
- Mark device as activated
- Enable identity operations

---

### Phase 8: Completion

#### Step 8.1: Recovery Token Prompt

**Mobile App → User:**
```
Prompt recovery token download and keep secure
```

> **Critical:** User must save recovery token offline for account recovery

#### Step 8.2: Notify Completion

**Mobile App → User:**
```
Notify identity activated
```

---

## Cryptographic Operations

### Algorithms Used

> **Fixed Algorithm Policy:** All cryptographic operations use Security Level 5 algorithms.
> No user selection is provided - this ensures maximum quantum-resistant security.

| Operation | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Generation | **KAZ-SIGN-256** | Device and User keypairs (fixed) |
| KEM | **KAZ-KEM-256** | Encrypt key shares (fixed) |
| Symmetric Encryption | AES-256-GCM | Encrypt recovery share |
| Secret Sharing | Shamir's Secret Sharing | Split user private key |
| Hashing | SHA-256/SHA-512 | Key derivation, integrity |
| CSR Signing | **KAZ-SIGN-256** | Self-sign CSRs (fixed) |
| Certificate Signing | **KAZ-SIGN-256** | CA signs certificates (fixed) |

### Key Derivation for Recovery Password

```
recovery_key = HKDF(
  input_key_material: recovery_password,
  salt: user_id || device_id,
  info: "IdP-Recovery-v1",
  output_length: 32
)
```

---

## Secret Sharing Scheme

### Shamir's Secret Sharing (2-of-3)

```
User Private Key
       │
       ▼
┌──────────────────────────────────────────────────┐
│           Secret Sharing (2-of-3)                │
│                                                  │
│  Any 2 shares can reconstruct the private key    │
└──────────────────────────────────────────────────┘
       │
       ├─────────────────┬─────────────────┐
       ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  part_user  │   │part_control │   │part_recovery│
│             │   │             │   │             │
│ Encrypted   │   │ Encrypted   │   │ Encrypted   │
│ with device │   │ with system │   │ with user   │
│ KEM pubkey  │   │ KEM pubkey  │   │ recovery pw │
└─────────────┘   └─────────────┘   └─────────────┘
       │                 │                 │
       ▼                 ▼                 ▼
   Device            Backend           User's
   Storage           Storage           Memory
```

### Recovery Scenarios

| Scenario | Shares Available | Recovery Method |
|----------|------------------|-----------------|
| Normal Use | part_user + part_control | Device + Backend cooperation |
| Lost Device | part_control + part_recovery | Backend + Recovery password |
| Backend Compromise | part_user + part_recovery | Device + Recovery password |
| Password Forgotten | part_user + part_control | Device + Backend cooperation |

---

## Data Structures

### Registration Request

```typescript
interface RegistrationRequest {
  encrypted_part_control: EncryptedShare;
  device_csr: string;           // PEM or DER encoded
  user_csr: string;             // PEM or DER encoded
  encrypted_part_recovery: EncryptedShare;
  signature: string;            // Signature over entire payload
}

interface EncryptedShare {
  ciphertext: string;           // Base64 encoded
  encapsulated_key?: string;    // For KEM-encrypted shares
  nonce?: string;               // For AES-GCM encrypted shares
  tag?: string;                 // Authentication tag
}
```

### Registration Response

```typescript
interface RegistrationResponse {
  tracking_id: string;          // RTID for polling
  status: "pending" | "approved" | "rejected";
  estimated_completion?: string; // ISO timestamp
}
```

### Certificate Status Response

```typescript
interface CertificateStatusResponse {
  status: "pending" | "issued" | "rejected";
  device_certificate?: string;   // PEM encoded
  user_certificate?: string;     // PEM encoded
  recovery_token?: string;       // Encrypted recovery token
  signature: string;             // Backend signature
}
```

### Local Storage Schema

```typescript
interface LocalIdentityStore {
  device: {
    private_key_encrypted: string;  // Encrypted with biometric-protected master key
    master_key_id: string;          // Reference to TEE/Secure Enclave key
    certificate: string;            // PEM
    key_id: string;
    biometric_bound: boolean;       // True - key requires biometric auth
  };
  user: {
    part_user_encrypted: string;    // KEM encrypted
    certificate: string;            // PEM
    key_id: string;
  };
  recovery: {
    token: string;                  // For display to user
    last_downloaded: string;        // ISO timestamp
  };
  activation: {
    status: "pending" | "active" | "suspended";
    activated_at?: string;
  };
  biometric: {
    enabled: boolean;
    type: "face" | "fingerprint" | "both";
    enrollment_hash: string;        // Hash of biometric enrollment (to detect changes)
  };
}
```

---

## Biometric Key Protection Architecture

### Overview

Device private keys are protected using hardware-backed biometric authentication instead of a user password. This provides:

1. **Zero-friction daily usage** - Users authenticate with biometric (face/fingerprint)
2. **Hardware-level security** - Keys protected by TEE/Secure Enclave
3. **Single password to remember** - Only recovery password (for emergencies)

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Biometric Key Protection                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Secure Hardware (TEE/Secure Enclave/HUKS)                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AES-256 Master Key                                      │    │
│  │  - Generated inside secure hardware                      │    │
│  │  - Non-extractable                                       │    │
│  │  - Bound to biometric authentication                     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                    Biometric Required                            │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Encrypted KAZ-SIGN-256 Device Private Key              │    │
│  │  (Stored in app keychain/keystore)                       │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                    Decrypt in memory                             │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Sign Operation (KAZ-SIGN-256)                          │    │
│  │  Key wiped from memory after use                         │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Platform Support

| Platform | Secure Hardware | Biometric Types | Key Invalidation |
|----------|-----------------|-----------------|------------------|
| **iOS** | Secure Enclave | Face ID, Touch ID | On biometric re-enrollment |
| **Android** | TEE / StrongBox (Titan M) | Fingerprint, Face (Class 3) | On biometric re-enrollment |
| **HarmonyOS** | iTrustee TEE | Fingerprint, 3D Face | On biometric re-enrollment |

### Why Biometric Instead of Password?

| Aspect | Device Password | Biometric |
|--------|----------------|-----------|
| **User Experience** | Must enter on every sign operation | Touch/glance to authenticate |
| **Security** | Software-based encryption | Hardware-backed (TEE) |
| **Memorization** | Another password to remember | No memorization needed |
| **Phishing Risk** | Can be phished | Cannot be remotely stolen |
| **Brute Force** | Possible if weak password | Hardware rate-limiting |

---

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Device theft | Private keys protected by hardware-backed biometric (TEE/Secure Enclave) |
| Biometric bypass | Keys bound to specific biometric enrollment, invalidated on changes |
| Backend compromise | 2-of-3 secret sharing - backend only has 1 share |
| Man-in-the-middle | All communications signed, certificate pinning |
| Recovery password brute force | HKDF with strong parameters, rate limiting |
| Quantum attacks | PQC algorithms (KAZ-KEM, KAZ-SIGN) throughout |
| Root/Jailbreak | Hardware attestation, key invalidation on tampering |

### Key Security Properties

1. **Forward Secrecy:** Compromise of long-term keys doesn't compromise past sessions
2. **Post-Quantum Security:** All cryptographic operations use PQC algorithms
3. **Key Escrow Prevention:** No single party holds complete private key
4. **Recovery Capability:** User can recover even with device loss
5. **Hardware-Backed Protection:** Device keys protected by TEE/Secure Enclave/HUKS
6. **Biometric Binding:** Signing operations require fresh biometric authentication

### Audit Points

| Event | Logged Data |
|-------|-------------|
| Registration initiated | User ID, Device ID, Timestamp, IP |
| CSR submitted | CSR hash, Tracking ID |
| Certificate issued | Serial number, Subject, Validity |
| Recovery token generated | Token hash (not token itself) |
| Identity activated | Device ID, Activation timestamp |

---

## Recovery Token Management

### Token Format

```
Recovery Token = Base64(
  version || user_id || encrypted_part_recovery || checksum
)
```

### User Instructions

The recovery token must be:
1. **Written down** on paper and stored securely
2. **Never stored digitally** on the same device
3. **Never shared** with anyone
4. **Used only** for account recovery

### Recovery Process (Separate Document)

When a user needs to recover their account:
1. Install app on new device
2. Enter recovery token
3. Enter recovery password
4. Backend provides `part_control`
5. Reconstruct user private key from `part_control` + `part_recovery`
6. Generate new device keypair
7. Re-register device with existing user identity

---

## References

- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key management guidelines
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) - Secret sharing scheme
- [KAZ-SIGN Documentation](../../../KAZ/SIGN/README.md) - PQC signature algorithm
- [KAZ-KEM Documentation](../../../KAZ/KEM/README.md) - PQC key encapsulation
