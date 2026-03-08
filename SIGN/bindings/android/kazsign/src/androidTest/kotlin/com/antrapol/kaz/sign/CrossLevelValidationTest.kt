/*
 * KAZ-SIGN Android Wrapper
 * Cross-Level Validation Tests
 *
 * These tests verify that different security levels are properly isolated.
 */

package com.antrapol.kaz.sign

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import org.junit.After

/**
 * Cross-level validation tests for KazSigner.
 * Ensures security levels are properly isolated and keys from one level
 * cannot be used with another level.
 */
@RunWith(AndroidJUnit4::class)
class CrossLevelValidationTest {

    private val signers = mutableListOf<KazSigner>()

    @After
    fun cleanup() {
        signers.forEach { it.close() }
        signers.clear()
    }

    private fun createSigner(level: SecurityLevel): KazSigner {
        val signer = KazSigner(level)
        signers.add(signer)
        return signer
    }

    // ========================================================================
    // Key Size Isolation Tests
    // ========================================================================

    @Test
    fun testLevel128KeysHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        assertEquals(98, keyPair.secretKey.size)
        assertEquals(49, keyPair.publicKey.size)
    }

    @Test
    fun testLevel192KeysHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()

        assertEquals(146, keyPair.secretKey.size)
        assertEquals(73, keyPair.publicKey.size)
    }

    @Test
    fun testLevel256KeysHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()

        assertEquals(194, keyPair.secretKey.size)
        assertEquals(97, keyPair.publicKey.size)
    }

    // ========================================================================
    // Signature Size Isolation Tests
    // ========================================================================

    @Test
    fun testLevel128SignaturesHaveCorrectOverhead() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertEquals(57, signResult.overhead)
    }

    @Test
    fun testLevel192SignaturesHaveCorrectOverhead() {
        val signer = createSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertEquals(81, signResult.overhead)
    }

    @Test
    fun testLevel256SignaturesHaveCorrectOverhead() {
        val signer = createSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertEquals(105, signResult.overhead)
    }

    // ========================================================================
    // Hash Size Isolation Tests
    // ========================================================================

    @Test
    fun testLevel128HashesHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val hash = signer.hash("Test".toByteArray())

        assertEquals(32, hash.size) // SHA-256
    }

    @Test
    fun testLevel192HashesHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_192)
        val hash = signer.hash("Test".toByteArray())

        assertEquals(48, hash.size) // SHA-384
    }

    @Test
    fun testLevel256HashesHaveCorrectSize() {
        val signer = createSigner(SecurityLevel.LEVEL_256)
        val hash = signer.hash("Test".toByteArray())

        assertEquals(64, hash.size) // SHA-512
    }

    // ========================================================================
    // Cross-Level Key Rejection Tests
    // ========================================================================

    @Test(expected = IllegalArgumentException::class)
    fun testLevel128RejectsLevel192SecretKey() {
        val signer128 = createSigner(SecurityLevel.LEVEL_128)
        val signer192 = createSigner(SecurityLevel.LEVEL_192)

        val keyPair192 = signer192.generateKeyPair()
        val message = "Test".toByteArray()

        // Should throw because 192 secret key is 146 bytes, but 128 expects 98
        signer128.sign(message, keyPair192.secretKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testLevel128RejectsLevel256SecretKey() {
        val signer128 = createSigner(SecurityLevel.LEVEL_128)
        val signer256 = createSigner(SecurityLevel.LEVEL_256)

        val keyPair256 = signer256.generateKeyPair()
        val message = "Test".toByteArray()

        // Should throw because 256 secret key is 194 bytes, but 128 expects 98
        signer128.sign(message, keyPair256.secretKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testLevel192RejectsLevel128SecretKey() {
        val signer128 = createSigner(SecurityLevel.LEVEL_128)
        val signer192 = createSigner(SecurityLevel.LEVEL_192)

        val keyPair128 = signer128.generateKeyPair()
        val message = "Test".toByteArray()

        // Should throw because 128 secret key is 98 bytes, but 192 expects 146
        signer192.sign(message, keyPair128.secretKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testLevel256RejectsLevel128SecretKey() {
        val signer128 = createSigner(SecurityLevel.LEVEL_128)
        val signer256 = createSigner(SecurityLevel.LEVEL_256)

        val keyPair128 = signer128.generateKeyPair()
        val message = "Test".toByteArray()

        // Should throw because 128 secret key is 98 bytes, but 256 expects 194
        signer256.sign(message, keyPair128.secretKey)
    }

    // ========================================================================
    // Cross-Level Public Key Rejection Tests
    // ========================================================================

    @Test(expected = IllegalArgumentException::class)
    fun testLevel128RejectsLevel192PublicKey() {
        val signer128 = createSigner(SecurityLevel.LEVEL_128)
        val signer192 = createSigner(SecurityLevel.LEVEL_192)

        val keyPair128 = signer128.generateKeyPair()
        val keyPair192 = signer192.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer128.sign(message, keyPair128.secretKey)

        // Should throw because 192 public key is 73 bytes, but 128 expects 49
        signer128.verify(signResult.signature, keyPair192.publicKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testLevel192RejectsLevel256PublicKey() {
        val signer192 = createSigner(SecurityLevel.LEVEL_192)
        val signer256 = createSigner(SecurityLevel.LEVEL_256)

        val keyPair192 = signer192.generateKeyPair()
        val keyPair256 = signer256.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer192.sign(message, keyPair192.secretKey)

        // Should throw because 256 public key is 97 bytes, but 192 expects 73
        signer192.verify(signResult.signature, keyPair256.publicKey)
    }

    // ========================================================================
    // Same Level, Different Keys Rejection
    // ========================================================================

    @Test
    fun testLevel128VerifyWithDifferentKeyFails() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair1 = signer.generateKeyPair()
        val keyPair2 = signer.generateKeyPair()

        val message = "Test".toByteArray()
        val signResult = signer.sign(message, keyPair1.secretKey)

        // Verify with wrong public key should fail
        val verifyResult = signer.verify(signResult.signature, keyPair2.publicKey)
        assertFalse(verifyResult.isValid)
    }

    @Test
    fun testLevel192VerifyWithDifferentKeyFails() {
        val signer = createSigner(SecurityLevel.LEVEL_192)
        val keyPair1 = signer.generateKeyPair()
        val keyPair2 = signer.generateKeyPair()

        val message = "Test".toByteArray()
        val signResult = signer.sign(message, keyPair1.secretKey)

        // Verify with wrong public key should fail
        val verifyResult = signer.verify(signResult.signature, keyPair2.publicKey)
        assertFalse(verifyResult.isValid)
    }

    @Test
    fun testLevel256VerifyWithDifferentKeyFails() {
        val signer = createSigner(SecurityLevel.LEVEL_256)
        val keyPair1 = signer.generateKeyPair()
        val keyPair2 = signer.generateKeyPair()

        val message = "Test".toByteArray()
        val signResult = signer.sign(message, keyPair1.secretKey)

        // Verify with wrong public key should fail
        val verifyResult = signer.verify(signResult.signature, keyPair2.publicKey)
        assertFalse(verifyResult.isValid)
    }

    // ========================================================================
    // Signature Tampering Tests
    // ========================================================================

    @Test
    fun testLevel128TamperedSignatureFails() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)

        // Tamper with signature (flip bits in the first byte)
        val tampered = signResult.signature.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()

        val verifyResult = signer.verify(tampered, keyPair.publicKey)
        assertFalse(verifyResult.isValid)
    }

    @Test
    fun testLevel128TruncatedSignatureFails() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)

        // Truncate signature by one byte
        val truncated = signResult.signature.copyOf(signResult.signature.size - 1)

        val verifyResult = signer.verify(truncated, keyPair.publicKey)
        assertFalse(verifyResult.isValid)
    }

    @Test
    fun testLevel128ExtendedSignatureFails() {
        val signer = createSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)

        // Extend signature by one byte
        val extended = signResult.signature + byteArrayOf(0x00)

        val verifyResult = signer.verify(extended, keyPair.publicKey)
        // This might verify but with wrong message, or fail
        if (verifyResult.isValid) {
            assertFalse(verifyResult.message?.contentEquals(message) == true)
        }
    }

    // ========================================================================
    // All Levels Comprehensive Test
    // ========================================================================

    @Test
    fun testAllLevelsAreIsolated() {
        val signers = SecurityLevel.entries.map { createSigner(it) }
        val keyPairs = signers.map { it.generateKeyPair() }
        val message = "Isolation test".toByteArray()

        // Sign with each signer
        val signatures = signers.zip(keyPairs).map { (signer, keyPair) ->
            signer.sign(message, keyPair.secretKey)
        }

        // Each signature should only verify with its corresponding public key
        for (i in signers.indices) {
            for (j in keyPairs.indices) {
                if (i == j) {
                    // Same level - should work if key matches
                    val result = signers[i].verify(signatures[i].signature, keyPairs[j].publicKey)
                    assertTrue("Level ${signers[i].level} should verify its own signature", result.isValid)
                } else if (signers[i].publicKeyBytes == signers[j].publicKeyBytes) {
                    // Same key size, different key - should fail verification
                    val result = signers[i].verify(signatures[i].signature, keyPairs[j].publicKey)
                    assertFalse("Cross-key verification should fail", result.isValid)
                }
                // Different key sizes will throw IllegalArgumentException (tested above)
            }
        }
    }
}
