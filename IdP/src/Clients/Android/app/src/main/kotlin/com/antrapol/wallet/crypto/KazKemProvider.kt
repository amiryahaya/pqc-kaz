package com.antrapol.wallet.crypto

import com.antrapol.kaz.kem.KazKem
import com.antrapol.kaz.kem.KazKemEncapsulationResult
import com.antrapol.kaz.kem.KazKemKeyPair
import com.antrapol.kaz.kem.KazKemPublicKey
import com.antrapol.kaz.kem.SecurityLevel

/**
 * KAZ-KEM cryptographic provider for the wallet app.
 * Provides post-quantum secure key encapsulation for encrypting key shares.
 *
 * Default security level is 256-bit for maximum security.
 */
class KazKemCryptoProvider(
    private val level: SecurityLevel = SecurityLevel.LEVEL_256
) : AutoCloseable {

    private val kem: KazKem

    init {
        kem = KazKem.initialize(level)
    }

    /**
     * Public key size in bytes for the current security level.
     */
    val publicKeySize: Int
        get() = kem.publicKeySize

    /**
     * Private key size in bytes for the current security level.
     */
    val privateKeySize: Int
        get() = kem.privateKeySize

    /**
     * Ciphertext size in bytes for the current security level.
     */
    val ciphertextSize: Int
        get() = kem.ciphertextSize

    /**
     * Shared secret size in bytes for the current security level.
     */
    val sharedSecretSize: Int
        get() = kem.sharedSecretSize

    /**
     * Current security level.
     */
    val securityLevel: SecurityLevel
        get() = kem.securityLevel

    /**
     * Generates a new KAZ-KEM keypair.
     * @return Generated keypair
     * @throws CryptoException if key generation fails
     */
    fun generateKeyPair(): KazKemKeyPair {
        return try {
            kem.generateKeyPair()
        } catch (e: Exception) {
            throw CryptoException("Failed to generate KEM keypair: ${e.message}", e)
        }
    }

    /**
     * Encapsulates a shared secret using the recipient's public key.
     * Use this when you want to encrypt data for a recipient.
     *
     * @param publicKey Recipient's public key
     * @return Encapsulation result containing ciphertext and shared secret
     * @throws CryptoException if encapsulation fails
     */
    fun encapsulate(publicKey: KazKemPublicKey): KazKemEncapsulationResult {
        return try {
            kem.encapsulate(publicKey)
        } catch (e: Exception) {
            throw CryptoException("Failed to encapsulate: ${e.message}", e)
        }
    }

    /**
     * Encapsulates a shared secret using the recipient's public key bytes.
     *
     * @param publicKeyBytes Recipient's public key as ByteArray
     * @return Encapsulation result containing ciphertext and shared secret
     * @throws CryptoException if encapsulation fails
     */
    fun encapsulate(publicKeyBytes: ByteArray): KazKemEncapsulationResult {
        return try {
            kem.encapsulate(publicKeyBytes)
        } catch (e: Exception) {
            throw CryptoException("Failed to encapsulate: ${e.message}", e)
        }
    }

    /**
     * Decapsulates a shared secret using the private key.
     * Use this to recover the shared secret from a ciphertext.
     *
     * @param ciphertext Ciphertext from encapsulation
     * @param keyPair Key pair containing the private key
     * @return The shared secret
     * @throws CryptoException if decapsulation fails
     */
    fun decapsulate(ciphertext: ByteArray, keyPair: KazKemKeyPair): ByteArray {
        return try {
            kem.decapsulate(ciphertext, keyPair)
        } catch (e: Exception) {
            throw CryptoException("Failed to decapsulate: ${e.message}", e)
        }
    }

    /**
     * Decapsulates a shared secret using the private key bytes.
     *
     * @param ciphertext Ciphertext from encapsulation
     * @param privateKey Private key as ByteArray
     * @return The shared secret
     * @throws CryptoException if decapsulation fails
     */
    fun decapsulate(ciphertext: ByteArray, privateKey: ByteArray): ByteArray {
        return try {
            kem.decapsulate(ciphertext, privateKey)
        } catch (e: Exception) {
            throw CryptoException("Failed to decapsulate: ${e.message}", e)
        }
    }

    override fun close() {
        // KazKem.cleanup() would release resources, but typically
        // the singleton instance is kept alive for the app lifetime
    }

    companion object {
        /**
         * Library version string.
         */
        val version: String
            get() = KazKem.version

        /**
         * Check if KAZ-KEM is initialized.
         */
        val isInitialized: Boolean
            get() = KazKem.isInitialized
    }
}
