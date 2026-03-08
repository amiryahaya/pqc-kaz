# KAZ-SIGN Android Library

Post-quantum digital signature library for Android using Kotlin and JNI.

## Features

- **Runtime Security Level Selection**: Support for 128, 192, and 256-bit security levels
- **JNI Integration**: High-performance native bridge
- **Kotlin-First API**: Modern, idiomatic Kotlin interface
- **Multi-Architecture Support**: arm64-v8a, armeabi-v7a, x86_64, x86

## Requirements

- Android SDK 24+ (Android 7.0 Nougat)
- Android NDK (for building native libraries)
- OpenSSL (for Android, built from source)

## Project Structure

```
android/
├── kazsign/                    # Android Library Module
│   ├── src/main/
│   │   ├── kotlin/             # Kotlin wrapper classes
│   │   ├── cpp/                # JNI bridge and CMake config
│   │   └── libs/openssl/       # Pre-built OpenSSL (after build)
│   └── build.gradle.kts
├── example/                    # Example application
├── scripts/
│   └── build-openssl-android.sh
└── build.gradle.kts
```

## Building

### 1. Build OpenSSL for Android

First, build OpenSSL for all Android architectures:

```bash
# Set Android NDK path
export ANDROID_NDK_ROOT=/path/to/android-ndk

# Build OpenSSL
./scripts/build-openssl-android.sh
```

### 2. Build the Library

```bash
./gradlew :kazsign:assembleRelease
```

### 3. Build the Example App

```bash
./gradlew :example:assembleDebug
```

## Usage

### Basic Usage

```kotlin
import com.pqc.kazsign.*

// Create a signer with 128-bit security
val signer = KazSigner(SecurityLevel.LEVEL_128)

try {
    // Generate key pair
    val keyPair = signer.generateKeyPair()

    // Sign a message
    val message = "Hello, Post-Quantum World!".toByteArray()
    val signatureResult = signer.sign(message, keyPair.secretKey)

    // Verify the signature
    val verificationResult = signer.verify(signatureResult.signature, keyPair.publicKey)

    if (verificationResult.isValid) {
        val recovered = verificationResult.getMessageAsString()
        println("Valid! Recovered: $recovered")
    }
} finally {
    signer.close()
}
```

### Using Extension Function

```kotlin
// Automatic resource management
kazSigner(SecurityLevel.LEVEL_256) {
    val keyPair = generateKeyPair()
    val signature = sign("Secret message", keyPair.secretKey)
    val result = verify(signature.signature, keyPair.publicKey)
    println("Valid: ${result.isValid}")
}
```

### Security Levels

| Level | Secret Key | Public Key | Signature Overhead | Hash |
|-------|-----------|------------|-------------------|------|
| 128   | 32 bytes  | 54 bytes   | 162 bytes         | SHA-256 |
| 192   | 50 bytes  | 88 bytes   | 264 bytes         | SHA-384 |
| 256   | 64 bytes  | 118 bytes  | 356 bytes         | SHA-512 |

## API Reference

### KazSigner

```kotlin
class KazSigner(level: SecurityLevel) : Closeable {
    // Properties
    val level: SecurityLevel
    val secretKeyBytes: Int
    val publicKeyBytes: Int
    val signatureOverhead: Int
    val hashBytes: Int
    val algorithmName: String

    // Methods
    fun generateKeyPair(): KeyPair
    fun sign(message: ByteArray, secretKey: ByteArray): SignatureResult
    fun sign(message: String, secretKey: ByteArray): SignatureResult
    fun verify(signature: ByteArray, publicKey: ByteArray): VerificationResult
    fun verifyString(signature: ByteArray, publicKey: ByteArray): Pair<Boolean, String?>
    fun hash(message: ByteArray): ByteArray
    fun hash(message: String): ByteArray
    fun close()

    // Companion
    companion object {
        val version: String
        val versionNumber: Int
        fun clearAll()
    }
}
```

### SecurityLevel

```kotlin
enum class SecurityLevel(
    val value: Int,
    val secretKeyBytes: Int,
    val publicKeyBytes: Int,
    val signatureOverhead: Int,
    val hashBytes: Int,
    val algorithmName: String
) {
    LEVEL_128, LEVEL_192, LEVEL_256
}
```

### KeyPair

```kotlin
data class KeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray,
    val level: Int
) {
    val securityLevel: SecurityLevel
    val publicKeyHex: String
    val secretKeyHex: String
}
```

### SignatureResult

```kotlin
data class SignatureResult(
    val signature: ByteArray,
    val message: ByteArray,
    val level: Int
) {
    val securityLevel: SecurityLevel
    val overhead: Int
    val signatureHex: String
}
```

### VerificationResult

```kotlin
data class VerificationResult(
    val isValid: Boolean,
    val message: ByteArray?,
    val level: Int
) {
    val securityLevel: SecurityLevel
    fun getMessageAsString(): String?
    fun getMessageAsHex(): String?
}
```

## Integration

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation(project(":kazsign"))
    // or from Maven (when published)
    // implementation("com.pqc:kazsign:2.1.0")
}
```

### ProGuard Rules

The library includes consumer ProGuard rules. No additional configuration needed.

## Thread Safety

- `KazSigner` instances are thread-safe for concurrent use
- Native resources are managed per security level
- Call `close()` when done to free resources

## Error Handling

All errors throw `KazSignException`:

```kotlin
try {
    signer.sign(message, invalidKey)
} catch (e: KazSignException) {
    when (e.errorCode) {
        KazSignException.ErrorCode.INVALID_PARAMETER -> // Handle invalid input
        KazSignException.ErrorCode.MEMORY_ERROR -> // Handle memory error
        else -> // Handle other errors
    }
}
```

## License

NIST-developed software license. See LICENSE file for details.
