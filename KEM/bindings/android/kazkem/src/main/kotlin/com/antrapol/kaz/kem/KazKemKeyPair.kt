package com.antrapol.kaz.kem

import android.util.Base64
import java.security.SecureRandom
import java.util.Arrays

/**
 * A KAZ-KEM key pair containing both public and private keys.
 *
 * **Security Note**: The private key is sensitive material and should be
 * handled with care. Call [clear] when done to securely wipe the private key
 * from memory.
 *
 * @property publicKey The public key bytes (safe to share)
 * @property privateKey The private key bytes (keep secret)
 * @property securityLevel The security level used to generate this key pair
 */
class KazKemKeyPair internal constructor(
    val publicKey: ByteArray,
    private var _privateKey: ByteArray,
    val securityLevel: SecurityLevel
) {
    /**
     * Access to private key bytes.
     * Note: Returns a copy to prevent external modification.
     */
    val privateKey: ByteArray
        get() = _privateKey.copyOf()

    /**
     * Size of the public key in bytes.
     */
    val publicKeySize: Int
        get() = publicKey.size

    /**
     * Size of the private key in bytes.
     */
    val privateKeySize: Int
        get() = _privateKey.size

    /**
     * Get the public key as a shareable [KazKemPublicKey] object.
     */
    fun getPublicKey(): KazKemPublicKey {
        return KazKemPublicKey(publicKey.copyOf(), securityLevel)
    }

    /**
     * Export public key as Base64 string.
     */
    fun publicKeyToBase64(): String {
        return Base64.encodeToString(publicKey, Base64.NO_WRAP)
    }

    /**
     * Export private key as Base64 string.
     * **Warning**: Handle with extreme care!
     */
    fun privateKeyToBase64(): String {
        return Base64.encodeToString(_privateKey, Base64.NO_WRAP)
    }

    /**
     * Securely clear the private key from memory.
     * Call this when the key pair is no longer needed.
     */
    fun clear() {
        secureZero(_privateKey)
    }

    /**
     * Automatically clear on finalization (best effort).
     */
    protected fun finalize() {
        clear()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KazKemKeyPair) return false
        return publicKey.contentEquals(other.publicKey) &&
                _privateKey.contentEquals(other._privateKey) &&
                securityLevel == other.securityLevel
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + _privateKey.contentHashCode()
        result = 31 * result + securityLevel.hashCode()
        return result
    }

    companion object {
        /**
         * Restore a key pair from serialized data.
         *
         * @param publicKey Public key bytes
         * @param privateKey Private key bytes
         * @param securityLevel Security level
         * @return Restored key pair
         */
        @JvmStatic
        fun fromBytes(
            publicKey: ByteArray,
            privateKey: ByteArray,
            securityLevel: SecurityLevel
        ): KazKemKeyPair {
            return KazKemKeyPair(publicKey.copyOf(), privateKey.copyOf(), securityLevel)
        }

        /**
         * Restore a key pair from Base64-encoded strings.
         *
         * @param publicKeyBase64 Base64-encoded public key
         * @param privateKeyBase64 Base64-encoded private key
         * @param securityLevel Security level
         * @return Restored key pair
         */
        @JvmStatic
        fun fromBase64(
            publicKeyBase64: String,
            privateKeyBase64: String,
            securityLevel: SecurityLevel
        ): KazKemKeyPair {
            val publicKey = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
            val privateKey = Base64.decode(privateKeyBase64, Base64.NO_WRAP)
            return KazKemKeyPair(publicKey, privateKey, securityLevel)
        }
    }
}

/**
 * A KAZ-KEM public key (safe to share).
 *
 * @property data The public key bytes
 * @property securityLevel The security level this key was generated for
 */
data class KazKemPublicKey(
    val data: ByteArray,
    val securityLevel: SecurityLevel
) {
    /**
     * Size of the public key in bytes.
     */
    val size: Int
        get() = data.size

    /**
     * Export as Base64 string.
     */
    fun toBase64(): String {
        return Base64.encodeToString(data, Base64.NO_WRAP)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KazKemPublicKey) return false
        return data.contentEquals(other.data) && securityLevel == other.securityLevel
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + securityLevel.hashCode()
        return result
    }

    companion object {
        /**
         * Create from Base64-encoded string.
         */
        @JvmStatic
        fun fromBase64(base64: String, securityLevel: SecurityLevel): KazKemPublicKey {
            val data = Base64.decode(base64, Base64.NO_WRAP)
            return KazKemPublicKey(data, securityLevel)
        }
    }
}

/**
 * Result of an encapsulation operation.
 *
 * @property ciphertext The ciphertext to send to the key holder
 * @property sharedSecret The shared secret (keep this secret!)
 */
class KazKemEncapsulationResult internal constructor(
    val ciphertext: ByteArray,
    private var _sharedSecret: ByteArray
) {
    /**
     * Access to shared secret bytes.
     * Note: Returns a copy to prevent external modification.
     */
    val sharedSecret: ByteArray
        get() = _sharedSecret.copyOf()

    /**
     * Size of the ciphertext in bytes.
     */
    val ciphertextSize: Int
        get() = ciphertext.size

    /**
     * Size of the shared secret in bytes.
     */
    val sharedSecretSize: Int
        get() = _sharedSecret.size

    /**
     * Securely clear the shared secret from memory.
     */
    fun clear() {
        secureZero(_sharedSecret)
    }

    /**
     * Export ciphertext as Base64 string.
     */
    fun ciphertextToBase64(): String {
        return Base64.encodeToString(ciphertext, Base64.NO_WRAP)
    }

    /**
     * Export shared secret as hex string.
     */
    fun sharedSecretToHex(): String {
        return _sharedSecret.toHexString()
    }

    protected fun finalize() {
        clear()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Securely zero a byte array to prevent sensitive data from remaining in memory.
 */
internal fun secureZero(data: ByteArray) {
    Arrays.fill(data, 0.toByte())
    // Double-clear with random data then zero to defeat optimization
    SecureRandom().nextBytes(data)
    Arrays.fill(data, 0.toByte())
}

/**
 * Convert byte array to hexadecimal string.
 */
fun ByteArray.toHexString(): String {
    return joinToString("") { "%02x".format(it) }
}

/**
 * Convert hexadecimal string to byte array.
 */
fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
