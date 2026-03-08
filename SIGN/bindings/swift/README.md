# KazSign Swift Package

Swift wrapper for the KAZ-SIGN post-quantum digital signature library.

Supports **iOS 13+** and **macOS 11+**.

## Requirements

- Xcode 15+
- Swift 5.9+
- iOS 13.0+ or macOS 11.0+

## Building the XCFramework

Before using the Swift package, you need to build the native XCFramework:

```bash
cd /path/to/combined
./scripts/apple/build-xcframework.sh
```

This builds:
- OpenSSL for all Apple platforms
- KAZ-SIGN static libraries for all platforms
- Universal XCFramework

Output: `bindings/swift/KazSignNative.xcframework`

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(path: "/path/to/combined/bindings/swift")
]
```

Or in Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select "KazSign"

### Manual

1. Build the XCFramework (see above)
2. Drag `KazSignNative.xcframework` to your Xcode project
3. Add `KazSign` source files to your project

## Usage

### Basic Example

```swift
import KazSign

// Create a signer with desired security level
let signer = try KazSigner(level: .level128)

// Generate a key pair
let keyPair = try signer.generateKeyPair()

// Sign a message
let message = "Hello, Post-Quantum World!".data(using: .utf8)!
let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)

// Verify the signature
let verifyResult = try signer.verify(
    signature: signResult.signature,
    publicKey: keyPair.publicKey
)

if verifyResult.isValid {
    print("Signature valid!")
    print("Message: \(String(data: verifyResult.message!, encoding: .utf8)!)")
}
```

### Convenience Methods

```swift
// Sign a string directly
let signResult = try signer.sign(message: "Hello", secretKey: keyPair.secretKey)

// Verify and get string result
let (isValid, message) = try signer.verifyString(
    signature: signResult.signature,
    publicKey: keyPair.publicKey
)

// Hash a message
let hash = try signer.hash(message: "Data to hash")
print("Hash: \(hash.hexString)")
```

## Security Levels

| Level | Secret Key | Public Key | Signature Overhead | Hash |
|-------|------------|------------|-------------------|------|
| 128 | 32 bytes | 54 bytes | 162 bytes | SHA-256 |
| 192 | 50 bytes | 88 bytes | 264 bytes | SHA-384 |
| 256 | 64 bytes | 118 bytes | 356 bytes | SHA-512 |

## API Reference

### SecurityLevel

```swift
enum SecurityLevel: Int, CaseIterable {
    case level128 = 128  // 128-bit security
    case level192 = 192  // 192-bit security
    case level256 = 256  // 256-bit security

    var secretKeyBytes: Int
    var publicKeyBytes: Int
    var signatureOverhead: Int
    var hashBytes: Int
    var algorithmName: String
}
```

### KazSigner

```swift
class KazSigner {
    // Initialize with security level
    init(level: SecurityLevel) throws

    // Version info
    static var version: String
    static var versionNumber: Int

    // Key generation
    func generateKeyPair() throws -> KeyPair

    // Signing
    func sign(message: Data, secretKey: Data) throws -> SignatureResult
    func sign(message: String, secretKey: Data) throws -> SignatureResult

    // Verification
    func verify(signature: Data, publicKey: Data) throws -> VerificationResult
    func verifyString(signature: Data, publicKey: Data) throws -> (isValid: Bool, message: String?)

    // Hashing
    func hash(message: Data) throws -> Data
    func hash(message: String) throws -> Data
}
```

### KeyPair

```swift
struct KeyPair {
    let publicKey: Data
    let secretKey: Data
    let level: SecurityLevel
}
```

### SignatureResult

```swift
struct SignatureResult {
    let signature: Data      // Full signature (includes message)
    let message: Data        // Original message
    let level: SecurityLevel
    var overhead: Int        // Signature bytes without message
}
```

### VerificationResult

```swift
struct VerificationResult {
    let isValid: Bool
    let message: Data?       // Recovered message (if valid)
    let level: SecurityLevel
}
```

### Error Handling

```swift
enum KazSignError: Error {
    case memoryAllocationFailed
    case randomGenerationFailed
    case invalidParameter
    case verificationFailed
    case notInitialized
    case invalidKeySize
    case invalidSignatureSize
    case unknownError(Int32)
}
```

## Running Tests

```bash
cd bindings/swift
swift test
```

## Thread Safety

`KazSigner` is thread-safe for all operations. Multiple threads can safely use the same `KazSigner` instance.

## License

NIST public domain license. See LICENSE file for details.
