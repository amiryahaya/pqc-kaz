# CSR Generation Architecture

**Version:** 1.0.0
**Last Updated:** 2025-12-05
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Native Library Interface](#native-library-interface)
4. [ASN.1/DER Structure](#asn1der-structure)
5. [Platform Implementations](#platform-implementations)
6. [Security Considerations](#security-considerations)

---

## Overview

Certificate Signing Request (CSR) generation for the PQC Digital Identity Platform uses a **hybrid approach**:

1. **Native Library (C):** Handles KAZ-SIGN-256 key generation and signing
2. **Platform Code:** Builds ASN.1/DER structures using platform-native languages

This approach keeps the native library minimal (only cryptographic operations) while leveraging platform-specific capabilities for data structure building.

### Why This Approach?

| Aspect | Full Native | Hybrid (ASN.1 on Platform) |
|--------|-------------|---------------------------|
| **Native library size** | Large | Small |
| **Native library complexity** | High (ASN.1 + crypto) | Low (crypto only) |
| **Platform integration** | Complex | Natural |
| **Debugging** | Difficult | Easy |
| **Updates** | Requires rebuild | Platform code update |

### CSR Requirements

A valid CSR must:
- Be **created on the client** (private key never leaves device)
- Be **self-signed** with the private key being certified
- Use **KAZ-SIGN-256** algorithm (Security Level 5)
- Follow **PKCS#10** (RFC 2986) format

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CSR Generation Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Platform Layer (Swift / Kotlin / ArkTS)                                   │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐   │     │
│  │   │ Key Manager │───>│ CSR Builder │───>│ Registration Service│   │     │
│  │   └─────────────┘    └─────────────┘    └─────────────────────┘   │     │
│  │          │                  │                      │               │     │
│  │          │                  │                      │               │     │
│  │          ▼                  ▼                      ▼               │     │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐   │     │
│  │   │ DER Builder │    │  ASN.1 OIDs │    │    API Client       │   │     │
│  │   │  (Platform) │    │  Constants  │    │                     │   │     │
│  │   └─────────────┘    └─────────────┘    └─────────────────────┘   │     │
│  │                                                                     │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                              │                                               │
│                              │ FFI (C interop / JNI / N-API)                │
│                              ▼                                               │
│   Native Layer (C)                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │   ┌─────────────────────┐    ┌─────────────────────────────────┐   │     │
│  │   │  kaz_sign_keygen()  │    │      kaz_sign_sign()            │   │     │
│  │   │  Generate keypair   │    │  Sign TBS with private key      │   │     │
│  │   └─────────────────────┘    └─────────────────────────────────┘   │     │
│  │                                                                     │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CSR Generation Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         CSR Generation Steps                              │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  Step 1: Generate Keypair (Native)                                       │
│  ─────────────────────────────────                                       │
│  kaz_sign_keygen() → { public_key, secret_key }                          │
│                                                                           │
│  Step 2: Build Subject DN (Platform)                                     │
│  ───────────────────────────────────                                     │
│  DERBuilder.buildDistinguishedName({                                     │
│    commonName: "Ahmad bin Abdullah",                                     │
│    serialNumber: "901201-14-5678",                                       │
│    email: "ahmad@example.com",                                           │
│    organization: "PQC Identity",                                         │
│    country: "MY"                                                         │
│  })                                                                       │
│                                                                           │
│  Step 3: Build SubjectPublicKeyInfo (Platform)                           │
│  ─────────────────────────────────────────────                           │
│  DERBuilder.buildSubjectPublicKeyInfo({                                  │
│    algorithm: KAZ_SIGN_256_OID,                                          │
│    publicKey: public_key                                                 │
│  })                                                                       │
│                                                                           │
│  Step 4: Build CertificationRequestInfo/TBS (Platform)                   │
│  ─────────────────────────────────────────────────────                   │
│  tbs = DERBuilder.buildCertificationRequestInfo({                        │
│    version: 0,                                                           │
│    subject: subject_dn,                                                  │
│    subjectPKInfo: spki,                                                  │
│    attributes: []                                                        │
│  })                                                                       │
│                                                                           │
│  Step 5: Sign TBS (Native)                                               │
│  ─────────────────────────                                               │
│  signature = kaz_sign_sign(secret_key, tbs)                              │
│                                                                           │
│  Step 6: Assemble Final CSR (Platform)                                   │
│  ─────────────────────────────────────                                   │
│  csr = DERBuilder.assembleCertificationRequest({                         │
│    certificationRequestInfo: tbs,                                        │
│    signatureAlgorithm: KAZ_SIGN_256_OID,                                 │
│    signature: signature                                                  │
│  })                                                                       │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Native Library Interface

### Minimal C Header

```c
// libkazsign.h
// Minimal interface - only key generation and signing

#ifndef LIBKAZSIGN_H
#define LIBKAZSIGN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================
// Constants
// ============================================

#define KAZ_SIGN_256_PUBLIC_KEY_SIZE   2592
#define KAZ_SIGN_256_SECRET_KEY_SIZE   4896
#define KAZ_SIGN_256_SIGNATURE_SIZE    4627

// ============================================
// Error Codes
// ============================================

typedef enum {
    KAZ_SUCCESS = 0,
    KAZ_ERROR_NULL_POINTER = -1,
    KAZ_ERROR_KEYGEN_FAILED = -2,
    KAZ_ERROR_SIGN_FAILED = -3,
    KAZ_ERROR_VERIFY_FAILED = -4,
    KAZ_ERROR_INVALID_KEY = -5,
    KAZ_ERROR_INVALID_SIGNATURE = -6
} KazResult;

// ============================================
// Key Generation
// ============================================

/**
 * Generate a KAZ-SIGN-256 keypair.
 *
 * @param public_key_out  Output buffer for public key (2592 bytes)
 * @param secret_key_out  Output buffer for secret key (4896 bytes)
 * @return KAZ_SUCCESS on success, error code otherwise
 */
KazResult kaz_sign_keygen(
    uint8_t public_key_out[KAZ_SIGN_256_PUBLIC_KEY_SIZE],
    uint8_t secret_key_out[KAZ_SIGN_256_SECRET_KEY_SIZE]
);

// ============================================
// Signing
// ============================================

/**
 * Sign a message with KAZ-SIGN-256.
 *
 * @param secret_key      Secret key (4896 bytes)
 * @param message         Message to sign
 * @param message_len     Length of message
 * @param signature_out   Output buffer for signature (4627 bytes max)
 * @param signature_len   Output: actual signature length
 * @return KAZ_SUCCESS on success, error code otherwise
 */
KazResult kaz_sign_sign(
    const uint8_t secret_key[KAZ_SIGN_256_SECRET_KEY_SIZE],
    const uint8_t* message,
    size_t message_len,
    uint8_t signature_out[KAZ_SIGN_256_SIGNATURE_SIZE],
    size_t* signature_len
);

// ============================================
// Verification (Optional - for testing)
// ============================================

/**
 * Verify a KAZ-SIGN-256 signature.
 *
 * @param public_key      Public key (2592 bytes)
 * @param message         Original message
 * @param message_len     Length of message
 * @param signature       Signature to verify
 * @param signature_len   Length of signature
 * @return KAZ_SUCCESS if valid, KAZ_ERROR_INVALID_SIGNATURE if invalid
 */
KazResult kaz_sign_verify(
    const uint8_t public_key[KAZ_SIGN_256_PUBLIC_KEY_SIZE],
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

#ifdef __cplusplus
}
#endif

#endif // LIBKAZSIGN_H
```

### Library Distribution

| Platform | Library Format | Location |
|----------|---------------|----------|
| **iOS** | `libkazsign.a` (static) | `KazSign.xcframework/` |
| **Android** | `libkazsign.so` (shared) | `jniLibs/{abi}/` |
| **HarmonyOS** | `libkazsign.so` (shared) | `libs/{abi}/` |

---

## ASN.1/DER Structure

### KAZ-SIGN-256 Algorithm OID

```
KAZ-SIGN-256 OID: 2.16.458.1.1.1.1.1
                  │  │   │ │ │ │ │ └─ Algorithm variant (1 = KAZ-SIGN-256)
                  │  │   │ │ │ │ └─── Algorithm type (1 = signature)
                  │  │   │ │ │ └───── Version (1)
                  │  │   │ │ └─────── PQC (1)
                  │  │   │ └───────── CyberSecurity Malaysia
                  │  │   └─────────── Malaysia country code (458)
                  │  └─────────────── ISO member-body
                  └────────────────── Joint ISO-ITU-T
```

### CSR ASN.1 Structure

```asn1
-- PKCS#10 Certificate Signing Request

CertificationRequest ::= SEQUENCE {
    certificationRequestInfo  CertificationRequestInfo,
    signatureAlgorithm        AlgorithmIdentifier,
    signature                 BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
    version       INTEGER { v1(0) },
    subject       Name,
    subjectPKInfo SubjectPublicKeyInfo,
    attributes    [0] IMPLICIT Attributes OPTIONAL
}

SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm         AlgorithmIdentifier,
    subjectPublicKey  BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
}

Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
    type   OBJECT IDENTIFIER,
    value  ANY DEFINED BY type
}
```

### DER Encoding Tags

| Type | Tag (Hex) | Description |
|------|-----------|-------------|
| SEQUENCE | 0x30 | Ordered collection |
| SET | 0x31 | Unordered collection |
| INTEGER | 0x02 | Integer value |
| BIT STRING | 0x03 | Bit string (signatures, keys) |
| OBJECT IDENTIFIER | 0x06 | OID |
| UTF8String | 0x0C | UTF-8 text |
| PrintableString | 0x13 | ASCII text |
| IA5String | 0x16 | ASCII (for email) |
| Context [0] | 0xA0 | Context-specific tag 0 |

### Standard OIDs Used

| Attribute | OID | Description |
|-----------|-----|-------------|
| Common Name (CN) | 2.5.4.3 | Full name |
| Serial Number | 2.5.4.5 | MyKad number |
| Country (C) | 2.5.4.6 | "MY" |
| Organization (O) | 2.5.4.10 | Organization name |
| Email Address | 1.2.840.113549.1.9.1 | Email (PKCS#9) |

---

## Platform Implementations

### iOS (Swift)

```swift
// DERBuilder.swift

import Foundation

/// ASN.1 DER encoder for CSR generation
class DERBuilder {
    private var data = Data()
    private var lengthStack: [Int] = []

    // MARK: - Container Types

    func beginSequence() {
        data.append(0x30)
        lengthStack.append(data.count)
        data.append(0x00) // Placeholder for length
    }

    func endSequence() {
        finalizeContainer()
    }

    func beginSet() {
        data.append(0x31)
        lengthStack.append(data.count)
        data.append(0x00)
    }

    func endSet() {
        finalizeContainer()
    }

    // MARK: - Primitive Types

    func writeInteger(_ value: Int) {
        data.append(0x02)
        if value == 0 {
            data.append(0x01)
            data.append(0x00)
        } else {
            var bytes = withUnsafeBytes(of: value.bigEndian) { Array($0) }
            // Remove leading zeros
            while bytes.count > 1 && bytes.first == 0 && (bytes[1] & 0x80) == 0 {
                bytes.removeFirst()
            }
            // Add leading zero if high bit set (to ensure positive)
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
            writeLength(bytes.count)
            data.append(contentsOf: bytes)
        }
    }

    func writeOID(_ components: [UInt]) {
        data.append(0x06)
        var oidBytes = Data()

        guard components.count >= 2 else { return }

        // First two components encoded as (first * 40) + second
        oidBytes.append(UInt8(components[0] * 40 + components[1]))

        // Remaining components use variable-length encoding
        for i in 2..<components.count {
            oidBytes.append(contentsOf: encodeOIDComponent(components[i]))
        }

        writeLength(oidBytes.count)
        data.append(oidBytes)
    }

    func writeUTF8String(_ string: String) {
        data.append(0x0C)
        let bytes = Array(string.utf8)
        writeLength(bytes.count)
        data.append(contentsOf: bytes)
    }

    func writePrintableString(_ string: String) {
        data.append(0x13)
        let bytes = Array(string.utf8)
        writeLength(bytes.count)
        data.append(contentsOf: bytes)
    }

    func writeIA5String(_ string: String) {
        data.append(0x16)
        let bytes = Array(string.utf8)
        writeLength(bytes.count)
        data.append(contentsOf: bytes)
    }

    func writeBitString(_ content: Data) {
        data.append(0x03)
        writeLength(content.count + 1)
        data.append(0x00) // No unused bits
        data.append(content)
    }

    func writeContextTag(_ tag: UInt8, content: Data) {
        data.append(0xA0 | tag)
        writeLength(content.count)
        data.append(content)
    }

    func writeRaw(_ rawData: Data) {
        data.append(rawData)
    }

    func build() -> Data {
        return data
    }

    func reset() {
        data = Data()
        lengthStack = []
    }

    // MARK: - Private Helpers

    private func writeLength(_ length: Int) {
        if length < 128 {
            data.append(UInt8(length))
        } else if length < 256 {
            data.append(0x81)
            data.append(UInt8(length))
        } else if length < 65536 {
            data.append(0x82)
            data.append(UInt8((length >> 8) & 0xFF))
            data.append(UInt8(length & 0xFF))
        } else {
            data.append(0x83)
            data.append(UInt8((length >> 16) & 0xFF))
            data.append(UInt8((length >> 8) & 0xFF))
            data.append(UInt8(length & 0xFF))
        }
    }

    private func finalizeContainer() {
        guard let startIndex = lengthStack.popLast() else { return }
        let contentLength = data.count - startIndex - 1

        // Replace placeholder with actual length
        if contentLength < 128 {
            data[startIndex] = UInt8(contentLength)
        } else {
            // Need to expand - rebuild with correct length bytes
            let prefix = Data(data[0..<startIndex])
            let content = Data(data[(startIndex + 1)...])

            data = prefix
            writeLength(contentLength)
            data.append(content)

            // Adjust stack indices
            for i in 0..<lengthStack.count {
                if lengthStack[i] > startIndex {
                    lengthStack[i] += (data.count - startIndex - 1 - contentLength)
                }
            }
        }
    }

    private func encodeOIDComponent(_ value: UInt) -> [UInt8] {
        if value < 128 {
            return [UInt8(value)]
        }

        var bytes: [UInt8] = []
        var v = value

        bytes.append(UInt8(v & 0x7F))
        v >>= 7

        while v > 0 {
            bytes.insert(UInt8((v & 0x7F) | 0x80), at: 0)
            v >>= 7
        }

        return bytes
    }
}
```

```swift
// CSRBuilder.swift

import Foundation

/// Builds X.509 PKCS#10 Certificate Signing Requests
class CSRBuilder {

    // KAZ-SIGN-256 OID: 2.16.458.1.1.1.1.1
    static let kazSign256OID: [UInt] = [2, 16, 458, 1, 1, 1, 1, 1]

    // Standard X.500 OIDs
    static let oidCommonName: [UInt] = [2, 5, 4, 3]
    static let oidSerialNumber: [UInt] = [2, 5, 4, 5]
    static let oidCountry: [UInt] = [2, 5, 4, 6]
    static let oidOrganization: [UInt] = [2, 5, 4, 10]
    static let oidEmailAddress: [UInt] = [1, 2, 840, 113549, 1, 9, 1]

    struct Subject {
        let commonName: String      // Full name
        let serialNumber: String    // MyKad number
        let email: String
        let organization: String
        let country: String
    }

    private let kazSign: KazSignService

    init(kazSign: KazSignService = KazSignService()) {
        self.kazSign = kazSign
    }

    /// Create a complete CSR
    func createCSR(publicKey: Data, secretKey: Data, subject: Subject) throws -> Data {
        // 1. Build TBS (To-Be-Signed) portion
        let tbs = buildCertificationRequestInfo(publicKey: publicKey, subject: subject)

        // 2. Sign TBS with private key
        let signature = try kazSign.sign(secretKey: secretKey, message: tbs)

        // 3. Assemble final CSR
        return assembleCertificationRequest(tbs: tbs, signature: signature)
    }

    /// Build CertificationRequestInfo (the TBS portion)
    func buildCertificationRequestInfo(publicKey: Data, subject: Subject) -> Data {
        let builder = DERBuilder()

        builder.beginSequence() // CertificationRequestInfo

        // version INTEGER (0)
        builder.writeInteger(0)

        // subject Name
        builder.writeRaw(buildDistinguishedName(subject))

        // subjectPKInfo SubjectPublicKeyInfo
        builder.writeRaw(buildSubjectPublicKeyInfo(publicKey))

        // attributes [0] IMPLICIT (empty)
        builder.writeContextTag(0, content: Data())

        builder.endSequence()

        return builder.build()
    }

    /// Build X.500 Distinguished Name
    private func buildDistinguishedName(_ subject: Subject) -> Data {
        let builder = DERBuilder()

        builder.beginSequence() // Name

        // Country (C)
        builder.writeRaw(buildRDN(oid: Self.oidCountry, value: subject.country, stringType: .printable))

        // Organization (O)
        builder.writeRaw(buildRDN(oid: Self.oidOrganization, value: subject.organization, stringType: .utf8))

        // Common Name (CN)
        builder.writeRaw(buildRDN(oid: Self.oidCommonName, value: subject.commonName, stringType: .utf8))

        // Serial Number (MyKad)
        builder.writeRaw(buildRDN(oid: Self.oidSerialNumber, value: subject.serialNumber, stringType: .printable))

        // Email Address
        builder.writeRaw(buildRDN(oid: Self.oidEmailAddress, value: subject.email, stringType: .ia5))

        builder.endSequence()

        return builder.build()
    }

    private enum StringType {
        case utf8, printable, ia5
    }

    /// Build a Relative Distinguished Name (SET OF AttributeTypeAndValue)
    private func buildRDN(oid: [UInt], value: String, stringType: StringType) -> Data {
        let builder = DERBuilder()

        builder.beginSet() // RelativeDistinguishedName
        builder.beginSequence() // AttributeTypeAndValue

        builder.writeOID(oid)

        switch stringType {
        case .utf8:
            builder.writeUTF8String(value)
        case .printable:
            builder.writePrintableString(value)
        case .ia5:
            builder.writeIA5String(value)
        }

        builder.endSequence()
        builder.endSet()

        return builder.build()
    }

    /// Build SubjectPublicKeyInfo
    private func buildSubjectPublicKeyInfo(_ publicKey: Data) -> Data {
        let builder = DERBuilder()

        builder.beginSequence() // SubjectPublicKeyInfo

        // algorithm AlgorithmIdentifier
        builder.beginSequence()
        builder.writeOID(Self.kazSign256OID)
        builder.endSequence()

        // subjectPublicKey BIT STRING
        builder.writeBitString(publicKey)

        builder.endSequence()

        return builder.build()
    }

    /// Assemble final CertificationRequest
    private func assembleCertificationRequest(tbs: Data, signature: Data) -> Data {
        let builder = DERBuilder()

        builder.beginSequence() // CertificationRequest

        // certificationRequestInfo (already DER encoded)
        builder.writeRaw(tbs)

        // signatureAlgorithm AlgorithmIdentifier
        builder.beginSequence()
        builder.writeOID(Self.kazSign256OID)
        builder.endSequence()

        // signature BIT STRING
        builder.writeBitString(signature)

        builder.endSequence()

        return builder.build()
    }
}
```

### Android (Kotlin)

```kotlin
// DERBuilder.kt

package com.pqcidentity.crypto.asn1

import java.io.ByteArrayOutputStream

/**
 * ASN.1 DER encoder for CSR generation
 */
class DERBuilder {
    private val output = ByteArrayOutputStream()
    private val lengthStack = mutableListOf<Int>()

    // Container types

    fun beginSequence() {
        output.write(0x30)
        lengthStack.add(output.size())
        output.write(0x00) // Placeholder
    }

    fun endSequence() {
        finalizeContainer()
    }

    fun beginSet() {
        output.write(0x31)
        lengthStack.add(output.size())
        output.write(0x00)
    }

    fun endSet() {
        finalizeContainer()
    }

    // Primitive types

    fun writeInteger(value: Int) {
        output.write(0x02)
        if (value == 0) {
            output.write(0x01)
            output.write(0x00)
        } else {
            var bytes = value.toBigInteger().toByteArray()
            // Remove leading zero if not needed
            if (bytes.size > 1 && bytes[0] == 0.toByte() && (bytes[1].toInt() and 0x80) == 0) {
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            writeLength(bytes.size)
            output.write(bytes)
        }
    }

    fun writeOID(components: List<Int>) {
        output.write(0x06)
        val oidBytes = ByteArrayOutputStream()

        if (components.size >= 2) {
            oidBytes.write(components[0] * 40 + components[1])
            for (i in 2 until components.size) {
                oidBytes.write(encodeOIDComponent(components[i]))
            }
        }

        writeLength(oidBytes.size())
        output.write(oidBytes.toByteArray())
    }

    fun writeUTF8String(value: String) {
        output.write(0x0C)
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeLength(bytes.size)
        output.write(bytes)
    }

    fun writePrintableString(value: String) {
        output.write(0x13)
        val bytes = value.toByteArray(Charsets.US_ASCII)
        writeLength(bytes.size)
        output.write(bytes)
    }

    fun writeIA5String(value: String) {
        output.write(0x16)
        val bytes = value.toByteArray(Charsets.US_ASCII)
        writeLength(bytes.size)
        output.write(bytes)
    }

    fun writeBitString(content: ByteArray) {
        output.write(0x03)
        writeLength(content.size + 1)
        output.write(0x00) // No unused bits
        output.write(content)
    }

    fun writeContextTag(tag: Int, content: ByteArray) {
        output.write(0xA0 or tag)
        writeLength(content.size)
        output.write(content)
    }

    fun writeRaw(data: ByteArray) {
        output.write(data)
    }

    fun build(): ByteArray = output.toByteArray()

    fun reset() {
        output.reset()
        lengthStack.clear()
    }

    // Private helpers

    private fun writeLength(length: Int) {
        when {
            length < 128 -> output.write(length)
            length < 256 -> {
                output.write(0x81)
                output.write(length)
            }
            length < 65536 -> {
                output.write(0x82)
                output.write((length shr 8) and 0xFF)
                output.write(length and 0xFF)
            }
            else -> {
                output.write(0x83)
                output.write((length shr 16) and 0xFF)
                output.write((length shr 8) and 0xFF)
                output.write(length and 0xFF)
            }
        }
    }

    private fun finalizeContainer() {
        val startIndex = lengthStack.removeLastOrNull() ?: return
        val data = output.toByteArray()
        val contentLength = data.size - startIndex - 1

        output.reset()
        output.write(data, 0, startIndex)
        writeLength(contentLength)
        output.write(data, startIndex + 1, contentLength)
    }

    private fun encodeOIDComponent(value: Int): ByteArray {
        if (value < 128) {
            return byteArrayOf(value.toByte())
        }

        val bytes = mutableListOf<Byte>()
        var v = value

        bytes.add(0, (v and 0x7F).toByte())
        v = v shr 7

        while (v > 0) {
            bytes.add(0, ((v and 0x7F) or 0x80).toByte())
            v = v shr 7
        }

        return bytes.toByteArray()
    }
}
```

```kotlin
// CSRBuilder.kt

package com.pqcidentity.crypto

import com.pqcidentity.crypto.asn1.DERBuilder

/**
 * Builds X.509 PKCS#10 Certificate Signing Requests
 */
class CSRBuilder(
    private val kazSign: KazSignService = KazSignService()
) {
    companion object {
        // KAZ-SIGN-256 OID: 2.16.458.1.1.1.1.1
        val KAZ_SIGN_256_OID = listOf(2, 16, 458, 1, 1, 1, 1, 1)

        // Standard X.500 OIDs
        val OID_COMMON_NAME = listOf(2, 5, 4, 3)
        val OID_SERIAL_NUMBER = listOf(2, 5, 4, 5)
        val OID_COUNTRY = listOf(2, 5, 4, 6)
        val OID_ORGANIZATION = listOf(2, 5, 4, 10)
        val OID_EMAIL = listOf(1, 2, 840, 113549, 1, 9, 1)
    }

    data class Subject(
        val commonName: String,
        val serialNumber: String,  // MyKad
        val email: String,
        val organization: String,
        val country: String = "MY"
    )

    /**
     * Create a complete CSR
     */
    fun createCSR(publicKey: ByteArray, secretKey: ByteArray, subject: Subject): ByteArray {
        // 1. Build TBS
        val tbs = buildCertificationRequestInfo(publicKey, subject)

        // 2. Sign TBS
        val signature = kazSign.sign(secretKey, tbs)

        // 3. Assemble final CSR
        return assembleCertificationRequest(tbs, signature)
    }

    fun buildCertificationRequestInfo(publicKey: ByteArray, subject: Subject): ByteArray {
        val builder = DERBuilder()

        builder.beginSequence()
        builder.writeInteger(0) // version
        builder.writeRaw(buildDistinguishedName(subject))
        builder.writeRaw(buildSubjectPublicKeyInfo(publicKey))
        builder.writeContextTag(0, byteArrayOf()) // empty attributes
        builder.endSequence()

        return builder.build()
    }

    private fun buildDistinguishedName(subject: Subject): ByteArray {
        val builder = DERBuilder()

        builder.beginSequence()
        builder.writeRaw(buildRDN(OID_COUNTRY, subject.country, StringType.PRINTABLE))
        builder.writeRaw(buildRDN(OID_ORGANIZATION, subject.organization, StringType.UTF8))
        builder.writeRaw(buildRDN(OID_COMMON_NAME, subject.commonName, StringType.UTF8))
        builder.writeRaw(buildRDN(OID_SERIAL_NUMBER, subject.serialNumber, StringType.PRINTABLE))
        builder.writeRaw(buildRDN(OID_EMAIL, subject.email, StringType.IA5))
        builder.endSequence()

        return builder.build()
    }

    private enum class StringType { UTF8, PRINTABLE, IA5 }

    private fun buildRDN(oid: List<Int>, value: String, type: StringType): ByteArray {
        val builder = DERBuilder()

        builder.beginSet()
        builder.beginSequence()
        builder.writeOID(oid)

        when (type) {
            StringType.UTF8 -> builder.writeUTF8String(value)
            StringType.PRINTABLE -> builder.writePrintableString(value)
            StringType.IA5 -> builder.writeIA5String(value)
        }

        builder.endSequence()
        builder.endSet()

        return builder.build()
    }

    private fun buildSubjectPublicKeyInfo(publicKey: ByteArray): ByteArray {
        val builder = DERBuilder()

        builder.beginSequence()
        builder.beginSequence()
        builder.writeOID(KAZ_SIGN_256_OID)
        builder.endSequence()
        builder.writeBitString(publicKey)
        builder.endSequence()

        return builder.build()
    }

    private fun assembleCertificationRequest(tbs: ByteArray, signature: ByteArray): ByteArray {
        val builder = DERBuilder()

        builder.beginSequence()
        builder.writeRaw(tbs)
        builder.beginSequence()
        builder.writeOID(KAZ_SIGN_256_OID)
        builder.endSequence()
        builder.writeBitString(signature)
        builder.endSequence()

        return builder.build()
    }
}
```

### HarmonyOS (ArkTS)

```typescript
// DERBuilder.ets

/**
 * ASN.1 DER encoder for CSR generation
 */
export class DERBuilder {
  private data: number[] = [];
  private lengthStack: number[] = [];

  // Container types

  beginSequence(): void {
    this.data.push(0x30);
    this.lengthStack.push(this.data.length);
    this.data.push(0x00);
  }

  endSequence(): void {
    this.finalizeContainer();
  }

  beginSet(): void {
    this.data.push(0x31);
    this.lengthStack.push(this.data.length);
    this.data.push(0x00);
  }

  endSet(): void {
    this.finalizeContainer();
  }

  // Primitive types

  writeInteger(value: number): void {
    this.data.push(0x02);
    if (value === 0) {
      this.data.push(0x01, 0x00);
    } else {
      let bytes = this.intToBytes(value);
      if (bytes[0] & 0x80) {
        bytes.unshift(0x00);
      }
      this.writeLength(bytes.length);
      this.data.push(...bytes);
    }
  }

  writeOID(components: number[]): void {
    this.data.push(0x06);
    const oidBytes: number[] = [];

    if (components.length >= 2) {
      oidBytes.push(components[0] * 40 + components[1]);
      for (let i = 2; i < components.length; i++) {
        oidBytes.push(...this.encodeOIDComponent(components[i]));
      }
    }

    this.writeLength(oidBytes.length);
    this.data.push(...oidBytes);
  }

  writeUTF8String(value: string): void {
    this.data.push(0x0c);
    const bytes = this.stringToUTF8(value);
    this.writeLength(bytes.length);
    this.data.push(...bytes);
  }

  writePrintableString(value: string): void {
    this.data.push(0x13);
    const bytes = this.stringToASCII(value);
    this.writeLength(bytes.length);
    this.data.push(...bytes);
  }

  writeIA5String(value: string): void {
    this.data.push(0x16);
    const bytes = this.stringToASCII(value);
    this.writeLength(bytes.length);
    this.data.push(...bytes);
  }

  writeBitString(content: Uint8Array): void {
    this.data.push(0x03);
    this.writeLength(content.length + 1);
    this.data.push(0x00);
    this.data.push(...Array.from(content));
  }

  writeContextTag(tag: number, content: Uint8Array): void {
    this.data.push(0xa0 | tag);
    this.writeLength(content.length);
    this.data.push(...Array.from(content));
  }

  writeRaw(rawData: Uint8Array): void {
    this.data.push(...Array.from(rawData));
  }

  build(): Uint8Array {
    return new Uint8Array(this.data);
  }

  reset(): void {
    this.data = [];
    this.lengthStack = [];
  }

  // Private helpers

  private writeLength(length: number): void {
    if (length < 128) {
      this.data.push(length);
    } else if (length < 256) {
      this.data.push(0x81, length);
    } else if (length < 65536) {
      this.data.push(0x82, (length >> 8) & 0xff, length & 0xff);
    } else {
      this.data.push(0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff);
    }
  }

  private finalizeContainer(): void {
    const startIndex = this.lengthStack.pop();
    if (startIndex === undefined) return;

    const contentLength = this.data.length - startIndex - 1;
    const prefix = this.data.slice(0, startIndex);
    const content = this.data.slice(startIndex + 1);

    this.data = prefix;
    this.writeLength(contentLength);
    this.data.push(...content);
  }

  private encodeOIDComponent(value: number): number[] {
    if (value < 128) {
      return [value];
    }

    const bytes: number[] = [];
    let v = value;

    bytes.unshift(v & 0x7f);
    v >>= 7;

    while (v > 0) {
      bytes.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }

    return bytes;
  }

  private intToBytes(value: number): number[] {
    const bytes: number[] = [];
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>= 8;
    }
    return bytes.length > 0 ? bytes : [0];
  }

  private stringToUTF8(str: string): number[] {
    const encoder = new TextEncoder();
    return Array.from(encoder.encode(str));
  }

  private stringToASCII(str: string): number[] {
    return str.split('').map(c => c.charCodeAt(0));
  }
}
```

```typescript
// CSRBuilder.ets

import { DERBuilder } from './DERBuilder';
import { KazSignService } from './KazSignService';

interface Subject {
  commonName: string;
  serialNumber: string;
  email: string;
  organization: string;
  country: string;
}

/**
 * Builds X.509 PKCS#10 Certificate Signing Requests
 */
export class CSRBuilder {
  // KAZ-SIGN-256 OID: 2.16.458.1.1.1.1.1
  private static readonly KAZ_SIGN_256_OID = [2, 16, 458, 1, 1, 1, 1, 1];

  // Standard X.500 OIDs
  private static readonly OID_COMMON_NAME = [2, 5, 4, 3];
  private static readonly OID_SERIAL_NUMBER = [2, 5, 4, 5];
  private static readonly OID_COUNTRY = [2, 5, 4, 6];
  private static readonly OID_ORGANIZATION = [2, 5, 4, 10];
  private static readonly OID_EMAIL = [1, 2, 840, 113549, 1, 9, 1];

  private kazSign: KazSignService;

  constructor() {
    this.kazSign = new KazSignService();
  }

  /**
   * Create a complete CSR
   */
  async createCSR(publicKey: Uint8Array, secretKey: Uint8Array, subject: Subject): Promise<Uint8Array> {
    // 1. Build TBS
    const tbs = this.buildCertificationRequestInfo(publicKey, subject);

    // 2. Sign TBS
    const signature = await this.kazSign.sign(secretKey, tbs);

    // 3. Assemble final CSR
    return this.assembleCertificationRequest(tbs, signature);
  }

  buildCertificationRequestInfo(publicKey: Uint8Array, subject: Subject): Uint8Array {
    const builder = new DERBuilder();

    builder.beginSequence();
    builder.writeInteger(0);
    builder.writeRaw(this.buildDistinguishedName(subject));
    builder.writeRaw(this.buildSubjectPublicKeyInfo(publicKey));
    builder.writeContextTag(0, new Uint8Array(0));
    builder.endSequence();

    return builder.build();
  }

  private buildDistinguishedName(subject: Subject): Uint8Array {
    const builder = new DERBuilder();

    builder.beginSequence();
    builder.writeRaw(this.buildRDN(CSRBuilder.OID_COUNTRY, subject.country, 'printable'));
    builder.writeRaw(this.buildRDN(CSRBuilder.OID_ORGANIZATION, subject.organization, 'utf8'));
    builder.writeRaw(this.buildRDN(CSRBuilder.OID_COMMON_NAME, subject.commonName, 'utf8'));
    builder.writeRaw(this.buildRDN(CSRBuilder.OID_SERIAL_NUMBER, subject.serialNumber, 'printable'));
    builder.writeRaw(this.buildRDN(CSRBuilder.OID_EMAIL, subject.email, 'ia5'));
    builder.endSequence();

    return builder.build();
  }

  private buildRDN(oid: number[], value: string, type: 'utf8' | 'printable' | 'ia5'): Uint8Array {
    const builder = new DERBuilder();

    builder.beginSet();
    builder.beginSequence();
    builder.writeOID(oid);

    switch (type) {
      case 'utf8':
        builder.writeUTF8String(value);
        break;
      case 'printable':
        builder.writePrintableString(value);
        break;
      case 'ia5':
        builder.writeIA5String(value);
        break;
    }

    builder.endSequence();
    builder.endSet();

    return builder.build();
  }

  private buildSubjectPublicKeyInfo(publicKey: Uint8Array): Uint8Array {
    const builder = new DERBuilder();

    builder.beginSequence();
    builder.beginSequence();
    builder.writeOID(CSRBuilder.KAZ_SIGN_256_OID);
    builder.endSequence();
    builder.writeBitString(publicKey);
    builder.endSequence();

    return builder.build();
  }

  private assembleCertificationRequest(tbs: Uint8Array, signature: Uint8Array): Uint8Array {
    const builder = new DERBuilder();

    builder.beginSequence();
    builder.writeRaw(tbs);
    builder.beginSequence();
    builder.writeOID(CSRBuilder.KAZ_SIGN_256_OID);
    builder.endSequence();
    builder.writeBitString(signature);
    builder.endSequence();

    return builder.build();
  }
}
```

---

## Security Considerations

### Private Key Handling

1. **Never log or transmit private keys**
2. **Wipe private keys from memory after use**
3. **Store encrypted with biometric-protected master key**

### CSR Validation (Backend)

The backend must validate received CSRs:

```csharp
// CSR Validation Checklist
public class CsrValidator
{
    public ValidationResult Validate(byte[] csrBytes)
    {
        // 1. Parse CSR structure
        // 2. Verify self-signature using embedded public key
        // 3. Validate algorithm is KAZ-SIGN-256
        // 4. Validate subject DN format
        // 5. Check MyKad number format
        // 6. Verify email matches verified email
        // 7. Check for duplicate CSRs
    }
}
```

### Algorithm OID Verification

Always verify the algorithm OID matches KAZ-SIGN-256:

```swift
let expectedOID: [UInt] = [2, 16, 458, 1, 1, 1, 1, 1]
guard parsedOID == expectedOID else {
    throw CSRError.invalidAlgorithm
}
```

---

## References

- [RFC 2986 - PKCS #10: Certification Request Syntax](https://tools.ietf.org/html/rfc2986)
- [ITU-T X.690 - ASN.1 DER Encoding Rules](https://www.itu.int/rec/T-REC-X.690)
- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Overall registration process
- [KAZ-SIGN Specification](../../../KAZ/SIGN/README.md) - Algorithm details
