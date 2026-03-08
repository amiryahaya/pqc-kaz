package com.antrapol.wallet.crypto

import com.antrapol.kaz.sign.KazSigner
import com.antrapol.kaz.sign.SecurityLevel
import com.antrapol.kaz.sign.KeyPair as NativeKeyPair

/**
 * KAZ-SIGN keypair wrapper for the wallet app.
 */
data class KazSignKeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray,
    val level: SecurityLevel = SecurityLevel.LEVEL_256
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as KazSignKeyPair
        return publicKey.contentEquals(other.publicKey) &&
               secretKey.contentEquals(other.secretKey) &&
               level == other.level
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + secretKey.contentHashCode()
        result = 31 * result + level.hashCode()
        return result
    }

    companion object {
        fun fromNative(keyPair: NativeKeyPair): KazSignKeyPair {
            return KazSignKeyPair(
                publicKey = keyPair.publicKey,
                secretKey = keyPair.secretKey,
                level = keyPair.securityLevel
            )
        }
    }
}

/**
 * KAZ-SIGN cryptographic provider using the native library.
 * Default security level is 256-bit.
 */
class KazSignCryptoProvider(
    private val level: SecurityLevel = SecurityLevel.LEVEL_256
) : AutoCloseable {

    private val signer = KazSigner(level)

    /**
     * Public key size in bytes for the current security level.
     */
    val publicKeySize: Int = level.publicKeyBytes

    /**
     * Secret key size in bytes for the current security level.
     */
    val secretKeySize: Int = level.secretKeyBytes

    /**
     * Signature overhead in bytes for the current security level.
     */
    val signatureOverhead: Int = level.signatureOverhead

    /**
     * Algorithm name for the current security level.
     */
    val algorithmName: String = level.algorithmName

    /**
     * Generates a new KAZ-SIGN keypair.
     * @return Generated keypair
     * @throws CryptoException if key generation fails
     */
    fun generateKeyPair(): KazSignKeyPair {
        return try {
            KazSignKeyPair.fromNative(signer.generateKeyPair())
        } catch (e: Exception) {
            throw CryptoException("Failed to generate keypair: ${e.message}", e)
        }
    }

    /**
     * Signs a message with KAZ-SIGN.
     * @param secretKey The secret key
     * @param message The message to sign
     * @return The signature (includes the message)
     * @throws CryptoException if signing fails
     */
    fun sign(secretKey: ByteArray, message: ByteArray): ByteArray {
        return try {
            signer.sign(message, secretKey).signature
        } catch (e: Exception) {
            throw CryptoException("Failed to sign message: ${e.message}", e)
        }
    }

    /**
     * Verifies a KAZ-SIGN signature and extracts the message.
     * @param publicKey The public key
     * @param signature The signature to verify (includes the message)
     * @return The recovered message if valid, null otherwise
     */
    fun verify(publicKey: ByteArray, signature: ByteArray): ByteArray? {
        return try {
            val result = signer.verify(signature, publicKey)
            if (result.isValid) result.message else null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Verifies a KAZ-SIGN signature.
     * @param publicKey The public key
     * @param signature The signature to verify
     * @return True if signature is valid
     */
    fun isValid(publicKey: ByteArray, signature: ByteArray): Boolean {
        return try {
            signer.verify(signature, publicKey).isValid
        } catch (e: Exception) {
            false
        }
    }

    override fun close() {
        signer.close()
    }

    companion object {
        /** KAZ-SIGN OID base: 2.16.458.1.1.1.1 */
        const val OID_BASE = "2.16.458.1.1.1.1"

        /** Get OID for specific level */
        fun getOid(level: SecurityLevel): String = when (level) {
            SecurityLevel.LEVEL_128 -> "$OID_BASE.1"
            SecurityLevel.LEVEL_192 -> "$OID_BASE.2"
            SecurityLevel.LEVEL_256 -> "$OID_BASE.3"
        }
    }
}

/**
 * Exception thrown when cryptographic operations fail.
 */
class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)
