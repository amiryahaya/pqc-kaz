package com.antrapol.kaz.kem

import androidx.annotation.GuardedBy
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * KAZ-KEM Post-Quantum Key Encapsulation Mechanism.
 *
 * Thread-safe wrapper for the native KAZ-KEM library providing
 * post-quantum secure key encapsulation.
 *
 * ## Usage
 * ```kotlin
 * // Initialize with security level
 * val kem = KazKem.initialize(SecurityLevel.LEVEL_128)
 *
 * // Generate key pair
 * val keyPair = kem.generateKeyPair()
 *
 * // Encapsulate shared secret (sender side)
 * val result = kem.encapsulate(keyPair.getPublicKey())
 *
 * // Decapsulate on recipient side
 * val sharedSecret = kem.decapsulate(result.ciphertext, keyPair.privateKey)
 * ```
 *
 * ## Thread Safety
 * This class is thread-safe. Multiple threads can safely generate keys and
 * perform encapsulation/decapsulation operations concurrently.
 */
class KazKem private constructor(
    private val _securityLevel: SecurityLevel
) {
    /**
     * Current security level.
     */
    val securityLevel: SecurityLevel
        get() = _securityLevel

    /**
     * Public key size in bytes for the current security level.
     */
    val publicKeySize: Int
        get() = KazKemNative.nativePublicKeyBytes()

    /**
     * Private key size in bytes for the current security level.
     */
    val privateKeySize: Int
        get() = KazKemNative.nativePrivateKeyBytes()

    /**
     * Ciphertext size in bytes for the current security level.
     */
    val ciphertextSize: Int
        get() = KazKemNative.nativeCiphertextBytes()

    /**
     * Shared secret size in bytes for the current security level.
     */
    val sharedSecretSize: Int
        get() = KazKemNative.nativeSharedSecretBytes()

    /**
     * Generate a new key pair.
     *
     * @return A new [KazKemKeyPair] containing public and private keys
     * @throws KazKemException if key generation fails
     * @throws NotInitializedException if KAZ-KEM is not initialized
     */
    @Throws(KazKemException::class, NotInitializedException::class)
    fun generateKeyPair(): KazKemKeyPair {
        ensureInitialized()

        val result = KazKemNative.nativeKeyPair()
        return KazKemKeyPair(result[0], result[1], securityLevel)
    }

    /**
     * Encapsulate a shared secret using the recipient's public key.
     *
     * @param publicKey Recipient's public key
     * @return [KazKemEncapsulationResult] containing ciphertext and shared secret
     * @throws KazKemException if encapsulation fails
     * @throws InvalidParameterException if public key size is invalid
     * @throws NotInitializedException if KAZ-KEM is not initialized
     */
    @Throws(KazKemException::class, InvalidParameterException::class, NotInitializedException::class)
    fun encapsulate(publicKey: KazKemPublicKey): KazKemEncapsulationResult {
        return encapsulate(publicKey.data)
    }

    /**
     * Encapsulate a shared secret using the recipient's public key bytes.
     *
     * @param publicKey Recipient's public key as ByteArray
     * @return [KazKemEncapsulationResult] containing ciphertext and shared secret
     * @throws KazKemException if encapsulation fails
     * @throws InvalidParameterException if public key size is invalid
     * @throws NotInitializedException if KAZ-KEM is not initialized
     */
    @Throws(KazKemException::class, InvalidParameterException::class, NotInitializedException::class)
    fun encapsulate(publicKey: ByteArray): KazKemEncapsulationResult {
        ensureInitialized()

        if (publicKey.size != publicKeySize) {
            throw InvalidParameterException(
                "Public key must be $publicKeySize bytes, got ${publicKey.size}"
            )
        }

        // Generate random shared secret
        val sharedSecret = ByteArray(sharedSecretSize)
        SecureRandom().nextBytes(sharedSecret)

        // Ensure message < N by clearing high bits based on security level
        sharedSecret[0] = (sharedSecret[0].toInt() and securityLevel.randomMask.toInt()).toByte()

        val result = KazKemNative.nativeEncapsulate(sharedSecret, publicKey)
        return KazKemEncapsulationResult(result[0], sharedSecret)
    }

    /**
     * Decapsulate a shared secret using the private key.
     *
     * @param ciphertext Ciphertext from encapsulation
     * @param keyPair Key pair containing the private key
     * @return The shared secret as ByteArray
     * @throws KazKemException if decapsulation fails
     * @throws NotInitializedException if KAZ-KEM is not initialized
     */
    @Throws(KazKemException::class, NotInitializedException::class)
    fun decapsulate(ciphertext: ByteArray, keyPair: KazKemKeyPair): ByteArray {
        return decapsulate(ciphertext, keyPair.privateKey)
    }

    /**
     * Decapsulate a shared secret using the private key bytes.
     *
     * @param ciphertext Ciphertext from encapsulation
     * @param privateKey Private key as ByteArray
     * @return The shared secret as ByteArray
     * @throws KazKemException if decapsulation fails
     * @throws InvalidParameterException if key/ciphertext size is invalid
     * @throws NotInitializedException if KAZ-KEM is not initialized
     */
    @Throws(KazKemException::class, InvalidParameterException::class, NotInitializedException::class)
    fun decapsulate(ciphertext: ByteArray, privateKey: ByteArray): ByteArray {
        ensureInitialized()

        if (privateKey.size != privateKeySize) {
            throw InvalidParameterException(
                "Private key must be $privateKeySize bytes, got ${privateKey.size}"
            )
        }

        if (ciphertext.isEmpty() || ciphertext.size > ciphertextSize) {
            throw InvalidParameterException(
                "Ciphertext must be 1-$ciphertextSize bytes, got ${ciphertext.size}"
            )
        }

        return KazKemNative.nativeDecapsulate(ciphertext, privateKey)
    }

    private fun ensureInitialized() {
        if (!KazKemNative.nativeIsInitialized()) {
            throw NotInitializedException()
        }
    }

    companion object {
        private val lock = ReentrantLock()

        @GuardedBy("lock")
        private var _current: KazKem? = null

        /**
         * Library version string.
         */
        @JvmStatic
        val version: String
            get() = KazKemNative.nativeVersion()

        /**
         * Check if KAZ-KEM is initialized.
         */
        @JvmStatic
        val isInitialized: Boolean
            get() = lock.withLock { _current != null && KazKemNative.nativeIsInitialized() }

        /**
         * Get the current initialized instance.
         *
         * @throws NotInitializedException if not initialized
         */
        @JvmStatic
        @get:Throws(NotInitializedException::class)
        val current: KazKem
            get() = lock.withLock {
                _current ?: throw NotInitializedException()
            }

        /**
         * Initialize KAZ-KEM with the specified security level.
         *
         * @param level Security level (default: [SecurityLevel.LEVEL_128])
         * @return Initialized [KazKem] instance
         * @throws KazKemException if initialization fails
         */
        @JvmStatic
        @JvmOverloads
        @Throws(KazKemException::class)
        fun initialize(level: SecurityLevel = SecurityLevel.LEVEL_128): KazKem {
            return lock.withLock {
                // If already initialized with same level, return existing
                _current?.let { current ->
                    if (current._securityLevel == level) {
                        return@withLock current
                    }
                }

                // Cleanup previous instance
                if (_current != null) {
                    KazKemNative.nativeCleanup()
                    _current = null
                }

                // Initialize with new level
                val result = KazKemNative.nativeInit(level.value)
                if (result != 0) {
                    throw KazKemException.fromErrorCode(result, "initialize")
                }

                val instance = KazKem(level)
                _current = instance
                instance
            }
        }

        /**
         * Cleanup and release resources.
         */
        @JvmStatic
        fun cleanup() {
            lock.withLock {
                if (_current != null) {
                    KazKemNative.nativeCleanup()
                    _current = null
                }
            }
        }
    }
}
