# KAZ-KEM Android Bindings

Post-Quantum Key Encapsulation Mechanism (KEM) library for Android applications. This library provides quantum-resistant key exchange capabilities using the KAZ-KEM algorithm.

## Features

- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Three Security Levels**: 128-bit, 192-bit, and 256-bit security
- **Thread-Safe**: Safe for concurrent use across multiple threads
- **Kotlin-First API**: Idiomatic Kotlin with full Java interoperability
- **Secure Memory Handling**: Automatic zeroing of sensitive data
- **Base64 Serialization**: Easy key import/export

## Requirements

- Android SDK 24+ (Android 7.0 Nougat)
- 64-bit devices only (arm64-v8a, x86_64)
- Android NDK 25+
- Gradle 8.0+
- Kotlin 1.9+

## Installation

### Gradle

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.pqc:kazkem:2.1.0")
}
```

### Manual Integration

1. Build the library:
   ```bash
   ./gradlew :kazkem:assembleRelease
   ```

2. Copy the AAR from `kazkem/build/outputs/aar/kazkem-release.aar` to your project

3. Add as a dependency:
   ```kotlin
   dependencies {
       implementation(files("libs/kazkem-release.aar"))
   }
   ```

## Quick Start

```kotlin
import com.pqc.kazkem.*

// Initialize with security level
val kem = KazKem.initialize(SecurityLevel.LEVEL_128)

// Generate a key pair
val keyPair = kem.generateKeyPair()

// Encapsulate a shared secret (sender side)
val result = kem.encapsulate(keyPair.getPublicKey())

// Decapsulate the shared secret (receiver side)
val sharedSecret = kem.decapsulate(result.ciphertext, keyPair.privateKey)

// Both parties now have the same shared secret
assert(result.sharedSecret.contentEquals(sharedSecret))

// Clean up when done
keyPair.clear()
result.clear()
KazKem.cleanup()
```

## API Reference

### KazKem

Main entry point for KEM operations.

#### Initialization

```kotlin
// Initialize with default level (128-bit)
val kem = KazKem.initialize()

// Initialize with specific security level
val kem128 = KazKem.initialize(SecurityLevel.LEVEL_128)
val kem192 = KazKem.initialize(SecurityLevel.LEVEL_192)
val kem256 = KazKem.initialize(SecurityLevel.LEVEL_256)

// Get library version
val version = KazKem.version  // e.g., "2.1.0"
```

#### Static Properties

```kotlin
KazKem.isInitialized  // Boolean - check if initialized
KazKem.version        // String - library version
KazKem.current        // KazKem - current instance (throws if not initialized)
```

#### Instance Properties

```kotlin
kem.securityLevel     // SecurityLevel
kem.publicKeySize     // Int (bytes)
kem.privateKeySize    // Int (bytes)
kem.ciphertextSize    // Int (bytes)
kem.sharedSecretSize  // Int (bytes)
```

#### Key Generation

```kotlin
// Instance method
val keyPair = kem.generateKeyPair()

// Via current instance
val keyPair = KazKem.current.generateKeyPair()
```

#### Encapsulation

```kotlin
// With KazKemPublicKey
val result = kem.encapsulate(keyPair.getPublicKey())

// With raw ByteArray
val result = kem.encapsulate(publicKeyBytes)
```

#### Decapsulation

```kotlin
// With KazKemKeyPair
val secret = kem.decapsulate(ciphertext, keyPair)

// With raw ByteArray
val secret = kem.decapsulate(ciphertext, privateKeyBytes)
```

### SecurityLevel

```kotlin
enum class SecurityLevel(val value: Int) {
    LEVEL_128(128),  // NIST Level 1 - Standard security (fastest)
    LEVEL_192(192),  // NIST Level 3 - Enhanced security
    LEVEL_256(256)   // NIST Level 5 - Maximum security (slowest)
}
```

### KazKemKeyPair

```kotlin
val keyPair = kem.generateKeyPair()

keyPair.publicKey        // ByteArray
keyPair.privateKey       // ByteArray
keyPair.securityLevel    // SecurityLevel
keyPair.publicKeySize    // Int
keyPair.privateKeySize   // Int

// Get public key as separate object
val publicKey = keyPair.getPublicKey()

// Serialization
val publicKeyBase64 = keyPair.publicKeyToBase64()
val privateKeyBase64 = keyPair.privateKeyToBase64()

// Restoration
val restored = KazKemKeyPair.fromBase64(
    publicKeyBase64,
    privateKeyBase64,
    SecurityLevel.LEVEL_128
)

// Secure cleanup
keyPair.clear()
```

### KazKemEncapsulationResult

```kotlin
val result = kem.encapsulate(publicKey)

result.ciphertext       // ByteArray
result.sharedSecret     // ByteArray
result.ciphertextSize   // Int
result.sharedSecretSize // Int

// Serialization
val ciphertextBase64 = result.ciphertextToBase64()
val secretHex = result.sharedSecretToHex()

// Secure cleanup
result.clear()
```

### Exceptions

```kotlin
// Base exception
class KazKemException(val errorCode: Int, message: String)

// Specific exceptions
class NotInitializedException   // KazKem not initialized
class InvalidParameterException // Invalid key size or parameter
```

## Usage Examples

### Complete Key Exchange Protocol

```kotlin
import com.pqc.kazkem.*

class KeyExchangeProtocol {

    fun performKeyExchange() {
        // === ALICE (Key Pair Owner) ===
        val kem = KazKem.initialize(SecurityLevel.LEVEL_128)
        val aliceKeyPair = kem.generateKeyPair()

        // Alice shares her public key (e.g., via network)
        val alicePublicKeyBase64 = aliceKeyPair.publicKeyToBase64()

        // === BOB (Initiator) ===
        // Bob receives Alice's public key
        val receivedPublicKey = KazKemPublicKey.fromBase64(
            alicePublicKeyBase64,
            SecurityLevel.LEVEL_128
        )

        // Bob encapsulates a shared secret
        val encapsulation = kem.encapsulate(receivedPublicKey)

        // Bob sends ciphertext to Alice (e.g., via network)
        val ciphertextBase64 = encapsulation.ciphertextToBase64()
        val bobSharedSecret = encapsulation.sharedSecret.copyOf()

        // === ALICE (Decapsulation) ===
        // Alice receives ciphertext
        val ciphertext = android.util.Base64.decode(
            ciphertextBase64,
            android.util.Base64.NO_WRAP
        )

        // Alice decapsulates using her private key
        val aliceSharedSecret = kem.decapsulate(ciphertext, aliceKeyPair)

        // Both have the same shared secret!
        require(aliceSharedSecret.contentEquals(bobSharedSecret)) {
            "Key exchange failed!"
        }

        // Cleanup
        aliceKeyPair.clear()
        encapsulation.clear()
        aliceSharedSecret.fill(0)
        bobSharedSecret.fill(0)
    }
}
```

### Hybrid Encryption (KEM + AES-GCM)

```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

class HybridEncryption(private val kem: KazKem) {

    data class EncryptedMessage(
        val kemCiphertext: ByteArray,
        val aesCiphertext: ByteArray,
        val iv: ByteArray
    )

    /**
     * Encrypt a message using hybrid encryption:
     * 1. KEM encapsulates a shared secret
     * 2. AES-GCM encrypts the message with the shared secret
     */
    fun encrypt(message: ByteArray, recipientPublicKey: KazKemPublicKey): EncryptedMessage {
        // Step 1: KEM encapsulation
        val kemResult = kem.encapsulate(recipientPublicKey)

        // Step 2: Use shared secret as AES key
        val aesKey = SecretKeySpec(kemResult.sharedSecret, "AES")

        // Step 3: Generate random IV
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        // Step 4: Encrypt with AES-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        val aesCiphertext = cipher.doFinal(message)

        // Step 5: Clear shared secret from memory
        kemResult.clear()

        return EncryptedMessage(kemResult.ciphertext, aesCiphertext, iv)
    }

    /**
     * Decrypt a hybrid-encrypted message
     */
    fun decrypt(encrypted: EncryptedMessage, keyPair: KazKemKeyPair): ByteArray {
        // Step 1: KEM decapsulation
        val sharedSecret = kem.decapsulate(encrypted.kemCiphertext, keyPair)

        // Step 2: Use shared secret as AES key
        val aesKey = SecretKeySpec(sharedSecret, "AES")

        // Step 3: Decrypt with AES-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, encrypted.iv))
        val plaintext = cipher.doFinal(encrypted.aesCiphertext)

        // Step 4: Clear shared secret from memory
        sharedSecret.fill(0)

        return plaintext
    }
}

// Usage
fun hybridEncryptionExample() {
    val kem = KazKem.initialize(SecurityLevel.LEVEL_256)
    val keyPair = kem.generateKeyPair()
    val encryption = HybridEncryption(kem)

    // Encrypt
    val message = "Hello, Post-Quantum World!".toByteArray()
    val encrypted = encryption.encrypt(message, keyPair.getPublicKey())

    // Decrypt
    val decrypted = encryption.decrypt(encrypted, keyPair)

    println(String(decrypted))  // "Hello, Post-Quantum World!"

    keyPair.clear()
}
```

### Secure Key Storage with EncryptedSharedPreferences

```kotlin
import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureKeyStorage(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "kazkem_secure_storage",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /**
     * Save a key pair securely
     */
    fun saveKeyPair(alias: String, keyPair: KazKemKeyPair) {
        prefs.edit()
            .putString("${alias}_public", keyPair.publicKeyToBase64())
            .putString("${alias}_private", keyPair.privateKeyToBase64())
            .putInt("${alias}_level", keyPair.securityLevel.value)
            .apply()
    }

    /**
     * Load a key pair
     */
    fun loadKeyPair(alias: String): KazKemKeyPair? {
        val publicBase64 = prefs.getString("${alias}_public", null) ?: return null
        val privateBase64 = prefs.getString("${alias}_private", null) ?: return null
        val levelValue = prefs.getInt("${alias}_level", 128)
        val level = SecurityLevel.fromValue(levelValue)

        return KazKemKeyPair.fromBase64(publicBase64, privateBase64, level)
    }

    /**
     * Delete a key pair
     */
    fun deleteKeyPair(alias: String) {
        prefs.edit()
            .remove("${alias}_public")
            .remove("${alias}_private")
            .remove("${alias}_level")
            .apply()
    }

    /**
     * Check if a key pair exists
     */
    fun hasKeyPair(alias: String): Boolean {
        return prefs.contains("${alias}_private")
    }
}

// Usage
fun secureStorageExample(context: Context) {
    val storage = SecureKeyStorage(context)
    val kem = KazKem.initialize()

    // Generate and save
    val keyPair = kem.generateKeyPair()
    storage.saveKeyPair("my_identity", keyPair)
    keyPair.clear()

    // Later: load and use
    val loadedKeyPair = storage.loadKeyPair("my_identity")
    if (loadedKeyPair != null) {
        // Use the key pair
        loadedKeyPair.clear()
    }
}
```

### Coroutines Integration

```kotlin
import kotlinx.coroutines.*

class KemRepository(private val kem: KazKem) {

    private val dispatcher = Dispatchers.Default

    suspend fun generateKeyPair(): KazKemKeyPair = withContext(dispatcher) {
        kem.generateKeyPair()
    }

    suspend fun encapsulate(publicKey: KazKemPublicKey): KazKemEncapsulationResult =
        withContext(dispatcher) {
            kem.encapsulate(publicKey)
        }

    suspend fun decapsulate(ciphertext: ByteArray, keyPair: KazKemKeyPair): ByteArray =
        withContext(dispatcher) {
            kem.decapsulate(ciphertext, keyPair)
        }
}

// ViewModel usage
class KeyExchangeViewModel : ViewModel() {

    private val kem = KazKem.initialize()
    private val repository = KemRepository(kem)

    private val _keyPair = MutableLiveData<KazKemKeyPair?>()
    val keyPair: LiveData<KazKemKeyPair?> = _keyPair

    private val _sharedSecret = MutableLiveData<ByteArray?>()
    val sharedSecret: LiveData<ByteArray?> = _sharedSecret

    fun generateKeyPair() {
        viewModelScope.launch {
            try {
                _keyPair.value = repository.generateKeyPair()
            } catch (e: KazKemException) {
                // Handle error
            }
        }
    }

    fun encapsulate(publicKey: KazKemPublicKey) {
        viewModelScope.launch {
            try {
                val result = repository.encapsulate(publicKey)
                _sharedSecret.value = result.sharedSecret
            } catch (e: KazKemException) {
                // Handle error
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        _keyPair.value?.clear()
        KazKem.cleanup()
    }
}
```

### Application Lifecycle Integration

```kotlin
import android.app.Application

class MyApplication : Application() {

    lateinit var kem: KazKem
        private set

    override fun onCreate() {
        super.onCreate()

        // Initialize KAZ-KEM at app startup
        try {
            kem = KazKem.initialize(SecurityLevel.LEVEL_128)
            Log.i("KazKem", "Initialized version ${KazKem.version}")
        } catch (e: KazKemException) {
            Log.e("KazKem", "Initialization failed: ${e.message}")
            // Handle fatal error - app cannot function without crypto
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        KazKem.cleanup()
    }
}

// Access from Activity/Fragment
val kem = (application as MyApplication).kem
```

### Java Interoperability

```java
import com.pqc.kazkem.*;

public class JavaExample {

    public void performKeyExchange() {
        // Initialize
        KazKem kem = KazKem.initialize(SecurityLevel.LEVEL_128);

        // Generate key pair
        KazKemKeyPair keyPair = kem.generateKeyPair();

        // Encapsulate
        KazKemEncapsulationResult result = kem.encapsulate(keyPair.getPublicKey());

        // Decapsulate
        byte[] sharedSecret = kem.decapsulate(result.getCiphertext(), keyPair);

        // Verify
        assert Arrays.equals(result.getSharedSecret(), sharedSecret);

        // Cleanup
        keyPair.clear();
        result.clear();
        KazKem.cleanup();
    }
}
```

## Best Practices

### Security

1. **Always clear sensitive data** after use:
   ```kotlin
   try {
       val result = kem.encapsulate(publicKey)
       // Use result.sharedSecret
   } finally {
       result.clear()
   }
   ```

2. **Choose appropriate security level** based on data sensitivity:
   - **Level 128**: General applications, IoT devices
   - **Level 192**: Financial data, healthcare
   - **Level 256**: Government, military, long-term secrets

3. **Never log private keys or shared secrets**:
   ```kotlin
   // BAD
   Log.d("Debug", "Private key: ${keyPair.privateKey.toHex()}")

   // GOOD
   Log.d("Debug", "Key pair generated, public key size: ${keyPair.publicKeySize}")
   ```

4. **Store private keys securely** using Android Keystore or EncryptedSharedPreferences

5. **Use hybrid encryption** - KEM provides key exchange, combine with AES for data encryption

### Performance

1. **Initialize once** at application startup:
   ```kotlin
   // In Application.onCreate()
   KazKem.initialize(SecurityLevel.LEVEL_128)
   ```

2. **Use background threads** for cryptographic operations:
   ```kotlin
   withContext(Dispatchers.Default) {
       kem.generateKeyPair()
   }
   ```

3. **Reuse key pairs** when appropriate (avoid generating new pairs for every operation)

4. **Batch operations** when processing multiple messages

### Thread Safety

The library is thread-safe. All methods can be called concurrently:

```kotlin
val executor = Executors.newFixedThreadPool(4)
repeat(100) {
    executor.submit {
        val result = kem.encapsulate(publicKey)
        // Thread-safe
    }
}
```

### Error Handling

```kotlin
fun safeKeyExchange(publicKey: KazKemPublicKey): ByteArray? {
    return try {
        if (!KazKem.isInitialized) {
            KazKem.initialize()
        }

        val result = KazKem.current.encapsulate(publicKey)
        result.sharedSecret.copyOf().also {
            result.clear()
        }

    } catch (e: NotInitializedException) {
        Log.e("KEM", "Not initialized")
        null

    } catch (e: InvalidParameterException) {
        Log.e("KEM", "Invalid parameter: ${e.message}")
        null

    } catch (e: KazKemException) {
        Log.e("KEM", "KEM error ${e.errorCode}: ${e.message}")
        null
    }
}
```

## Building from Source

### Prerequisites

1. Install Android SDK and NDK
2. Set environment variables:
   ```bash
   export ANDROID_SDK_ROOT=$HOME/Library/Android/sdk
   export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/25.0.8775105
   ```

### Build OpenSSL for Android (if needed)

```bash
cd scripts
chmod +x build-openssl-android.sh
./build-openssl-android.sh
```

### Build the Library

```bash
./gradlew :kazkem:assembleRelease
```

### Run Tests

```bash
# Unit tests (21 tests)
./gradlew :kazkem:test

# Instrumented tests (28 tests, requires device/emulator)
./gradlew :kazkem:connectedAndroidTest
```

## Troubleshooting

### UnsatisfiedLinkError

If you get `java.lang.UnsatisfiedLinkError: dlopen failed`:

1. Ensure your app supports 64-bit ABIs:
   ```kotlin
   android {
       defaultConfig {
           ndk {
               abiFilters += listOf("arm64-v8a", "x86_64")
           }
       }
   }
   ```

2. Verify native libraries are in the APK:
   ```bash
   unzip -l app-debug.apk | grep libkazkem
   ```

### NotInitializedException

Always initialize before using:

```kotlin
if (!KazKem.isInitialized) {
    KazKem.initialize()
}
val kem = KazKem.current
```

### 32-bit Device Support

This library only supports 64-bit devices. 32-bit support requires recompiling OpenSSL with `-fPIC` flag.

### Memory Issues

For high-volume operations, ensure proper cleanup:

```kotlin
repeat(10000) {
    val keyPair = kem.generateKeyPair()
    val result = kem.encapsulate(keyPair.getPublicKey())
    // Use result
    result.clear()
    keyPair.clear()
}
```

## Security Considerations

1. **Quantum Resistance**: This library provides protection against quantum computer attacks on key exchange
2. **Forward Secrecy**: Generate new key pairs for each session when possible
3. **Side-Channel Protection**: The library uses constant-time operations where possible
4. **Memory Safety**: Sensitive data is zeroed after use via `clear()` methods

## License

NIST-developed software license. All code is provided "AS IS" by NIST as a public service.

## Version History

- **2.1.0**: Initial Android release
  - Support for arm64-v8a and x86_64
  - Three security levels (128/192/256)
  - Thread-safe API
  - 21 unit tests, 28 instrumented tests
