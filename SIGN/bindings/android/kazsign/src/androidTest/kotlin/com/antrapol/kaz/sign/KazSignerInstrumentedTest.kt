/*
 * KAZ-SIGN Android Wrapper
 * Instrumented Tests for KazSigner
 *
 * These tests run on an Android device or emulator with the native library.
 */

package com.antrapol.kaz.sign

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import org.junit.Before
import org.junit.After

/**
 * Instrumented tests for KazSigner.
 * These tests run on an actual Android device or emulator.
 */
@RunWith(AndroidJUnit4::class)
class KazSignerInstrumentedTest {

    // ========================================================================
    // Context Tests
    // ========================================================================

    @Test
    fun useAppContext() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.pqc.kazsign.test", appContext.packageName)
    }

    // ========================================================================
    // Version Tests
    // ========================================================================

    @Test
    fun testGetVersion() {
        val version = KazSigner.version
        assertNotNull(version)
        assertTrue(version.isNotEmpty())
        assertTrue(version.contains("."))
    }

    @Test
    fun testGetVersionNumber() {
        val versionNumber = KazSigner.versionNumber
        assertTrue(versionNumber >= 20100) // v2.1.0 = 20100
    }

    // ========================================================================
    // Initialization Tests - Level 128
    // ========================================================================

    @Test
    fun testInitializeLevel128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        assertTrue(signer.isInitialized())
        signer.close()
    }

    @Test
    fun testInitializeLevel128FromInt() {
        val signer = KazSigner(128)
        assertTrue(signer.isInitialized())
        assertEquals(SecurityLevel.LEVEL_128, signer.level)
        signer.close()
    }

    @Test
    fun testLevel128Properties() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        assertEquals(98, signer.secretKeyBytes)
        assertEquals(49, signer.publicKeyBytes)
        assertEquals(57, signer.signatureOverhead)
        assertEquals(32, signer.hashBytes)
        assertEquals("KAZ-SIGN-128", signer.algorithmName)
        signer.close()
    }

    // ========================================================================
    // Initialization Tests - Level 192
    // ========================================================================

    @Test
    fun testInitializeLevel192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        assertTrue(signer.isInitialized())
        signer.close()
    }

    @Test
    fun testInitializeLevel192FromInt() {
        val signer = KazSigner(192)
        assertTrue(signer.isInitialized())
        assertEquals(SecurityLevel.LEVEL_192, signer.level)
        signer.close()
    }

    @Test
    fun testLevel192Properties() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        assertEquals(146, signer.secretKeyBytes)
        assertEquals(73, signer.publicKeyBytes)
        assertEquals(81, signer.signatureOverhead)
        assertEquals(48, signer.hashBytes)
        assertEquals("KAZ-SIGN-192", signer.algorithmName)
        signer.close()
    }

    // ========================================================================
    // Initialization Tests - Level 256
    // ========================================================================

    @Test
    fun testInitializeLevel256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        assertTrue(signer.isInitialized())
        signer.close()
    }

    @Test
    fun testInitializeLevel256FromInt() {
        val signer = KazSigner(256)
        assertTrue(signer.isInitialized())
        assertEquals(SecurityLevel.LEVEL_256, signer.level)
        signer.close()
    }

    @Test
    fun testLevel256Properties() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        assertEquals(194, signer.secretKeyBytes)
        assertEquals(97, signer.publicKeyBytes)
        assertEquals(105, signer.signatureOverhead)
        assertEquals(64, signer.hashBytes)
        assertEquals("KAZ-SIGN-256", signer.algorithmName)
        signer.close()
    }

    // ========================================================================
    // Key Generation Tests - Level 128
    // ========================================================================

    @Test
    fun testKeyGeneration128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        assertEquals(49, keyPair.publicKey.size)
        assertEquals(98, keyPair.secretKey.size)
        assertEquals(128, keyPair.level)

        signer.close()
    }

    @Test
    fun testKeyGeneration128ProducesUniqueKeys() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)

        val keyPair1 = signer.generateKeyPair()
        val keyPair2 = signer.generateKeyPair()

        assertFalse(keyPair1.publicKey.contentEquals(keyPair2.publicKey))
        assertFalse(keyPair1.secretKey.contentEquals(keyPair2.secretKey))

        signer.close()
    }

    // ========================================================================
    // Key Generation Tests - Level 192
    // ========================================================================

    @Test
    fun testKeyGeneration192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()

        assertEquals(73, keyPair.publicKey.size)
        assertEquals(146, keyPair.secretKey.size)
        assertEquals(192, keyPair.level)

        signer.close()
    }

    // ========================================================================
    // Key Generation Tests - Level 256
    // ========================================================================

    @Test
    fun testKeyGeneration256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()

        assertEquals(97, keyPair.publicKey.size)
        assertEquals(194, keyPair.secretKey.size)
        assertEquals(256, keyPair.level)

        signer.close()
    }

    // ========================================================================
    // Sign and Verify Tests - Level 128
    // ========================================================================

    @Test
    fun testSignAndVerify128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Hello, World!".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertNotNull(signResult.signature)
        assertEquals(message.size + 57, signResult.signature.size)

        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)
        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    @Test
    fun testSignAndVerifyString128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Hello, World!"

        val signResult = signer.sign(message, keyPair.secretKey)
        val (isValid, recoveredMessage) = signer.verifyString(signResult.signature, keyPair.publicKey)

        assertTrue(isValid)
        assertEquals(message, recoveredMessage)

        signer.close()
    }

    @Test
    fun testVerifyWithWrongPublicKey128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair1 = signer.generateKeyPair()
        val keyPair2 = signer.generateKeyPair()
        val message = "Test message".toByteArray()

        val signResult = signer.sign(message, keyPair1.secretKey)
        val verifyResult = signer.verify(signResult.signature, keyPair2.publicKey)

        assertFalse(verifyResult.isValid)

        signer.close()
    }

    @Test
    fun testVerifyCorruptedSignature128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test message".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)

        // Corrupt the signature
        val corrupted = signResult.signature.copyOf()
        corrupted[0] = (corrupted[0].toInt() xor 0xFF).toByte()

        val verifyResult = signer.verify(corrupted, keyPair.publicKey)
        assertFalse(verifyResult.isValid)

        signer.close()
    }

    // ========================================================================
    // Sign and Verify Tests - Level 192
    // ========================================================================

    @Test
    fun testSignAndVerify192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()
        val message = "Hello, World!".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertNotNull(signResult.signature)
        assertEquals(message.size + 81, signResult.signature.size)

        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)
        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    // ========================================================================
    // Sign and Verify Tests - Level 256
    // ========================================================================

    @Test
    fun testSignAndVerify256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()
        val message = "Hello, World!".toByteArray()

        val signResult = signer.sign(message, keyPair.secretKey)
        assertNotNull(signResult.signature)
        assertEquals(message.size + 105, signResult.signature.size)

        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)
        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    // ========================================================================
    // Hash Tests
    // ========================================================================

    @Test
    fun testHash128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val message = "Hello, World!".toByteArray()

        val hash = signer.hash(message)
        assertEquals(32, hash.size) // SHA-256

        signer.close()
    }

    @Test
    fun testHash192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val message = "Hello, World!".toByteArray()

        val hash = signer.hash(message)
        assertEquals(48, hash.size) // SHA-384

        signer.close()
    }

    @Test
    fun testHash256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val message = "Hello, World!".toByteArray()

        val hash = signer.hash(message)
        assertEquals(64, hash.size) // SHA-512

        signer.close()
    }

    @Test
    fun testHashConsistency() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val message = "Test message".toByteArray()

        val hash1 = signer.hash(message)
        val hash2 = signer.hash(message)

        assertArrayEquals(hash1, hash2)

        signer.close()
    }

    @Test
    fun testHashDifferentMessages() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)

        val hash1 = signer.hash("Message 1".toByteArray())
        val hash2 = signer.hash("Message 2".toByteArray())

        assertFalse(hash1.contentEquals(hash2))

        signer.close()
    }

    // ========================================================================
    // Message Size Tests
    // ========================================================================

    @Test
    fun testEmptyMessage() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = ByteArray(0)

        val signResult = signer.sign(message, keyPair.secretKey)
        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)

        assertTrue(verifyResult.isValid)
        assertEquals(0, verifyResult.message?.size)

        signer.close()
    }

    @Test
    fun testSingleByteMessage() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = byteArrayOf(0x42)

        val signResult = signer.sign(message, keyPair.secretKey)
        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)

        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    @Test
    fun testLargeMessage() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = ByteArray(10000) { it.toByte() }

        val signResult = signer.sign(message, keyPair.secretKey)
        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)

        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    @Test
    fun testBinaryMessage() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = ByteArray(256) { it.toByte() } // All byte values 0-255

        val signResult = signer.sign(message, keyPair.secretKey)
        val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)

        assertTrue(verifyResult.isValid)
        assertArrayEquals(message, verifyResult.message)

        signer.close()
    }

    @Test
    fun testUnicodeMessage() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Hello \u4e16\u754c! \uD83D\uDC4B"  // Hello 世界! 👋

        val signResult = signer.sign(message, keyPair.secretKey)
        val (isValid, recoveredMessage) = signer.verifyString(signResult.signature, keyPair.publicKey)

        assertTrue(isValid)
        assertEquals(message, recoveredMessage)

        signer.close()
    }

    // ========================================================================
    // Lifecycle Tests
    // ========================================================================

    @Test
    fun testCloseMultipleTimes() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        signer.close()
        signer.close() // Should not throw
    }

    @Test(expected = IllegalStateException::class)
    fun testUseAfterClose() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        signer.close()
        signer.generateKeyPair() // Should throw
    }

    @Test
    fun testUseBlock() {
        kazSigner(SecurityLevel.LEVEL_128) {
            val keyPair = generateKeyPair()
            assertNotNull(keyPair.publicKey)
        }
    }

    @Test
    fun testClearAll() {
        val signer1 = KazSigner(SecurityLevel.LEVEL_128)
        val signer2 = KazSigner(SecurityLevel.LEVEL_192)
        val signer3 = KazSigner(SecurityLevel.LEVEL_256)

        signer1.close()
        signer2.close()
        signer3.close()

        KazSigner.clearAll() // Should not throw
    }

    // ========================================================================
    // Cross-Level Tests
    // ========================================================================

    @Test
    fun testMultipleLevelsCoexist() {
        val signer128 = KazSigner(SecurityLevel.LEVEL_128)
        val signer192 = KazSigner(SecurityLevel.LEVEL_192)
        val signer256 = KazSigner(SecurityLevel.LEVEL_256)

        val keyPair128 = signer128.generateKeyPair()
        val keyPair192 = signer192.generateKeyPair()
        val keyPair256 = signer256.generateKeyPair()

        // Sign with each level
        val message = "Test".toByteArray()
        val sig128 = signer128.sign(message, keyPair128.secretKey)
        val sig192 = signer192.sign(message, keyPair192.secretKey)
        val sig256 = signer256.sign(message, keyPair256.secretKey)

        // Verify with correct level
        assertTrue(signer128.verify(sig128.signature, keyPair128.publicKey).isValid)
        assertTrue(signer192.verify(sig192.signature, keyPair192.publicKey).isValid)
        assertTrue(signer256.verify(sig256.signature, keyPair256.publicKey).isValid)

        signer128.close()
        signer192.close()
        signer256.close()
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidSecretKeySize() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        // Try to sign with wrong key size
        val wrongSizeKey = ByteArray(16) // Should be 98
        signer.sign("Test".toByteArray(), wrongSizeKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidPublicKeySize() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        val signResult = signer.sign("Test".toByteArray(), keyPair.secretKey)

        // Try to verify with wrong key size
        val wrongSizeKey = ByteArray(32) // Should be 49
        signer.verify(signResult.signature, wrongSizeKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testInvalidSecurityLevel() {
        KazSigner(64) // Invalid level
    }

    // ========================================================================
    // Stress Tests
    // ========================================================================

    @Test
    fun testMultipleKeyGenerations() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPairs = mutableListOf<KeyPair>()

        repeat(50) {
            keyPairs.add(signer.generateKeyPair())
        }

        // Verify all are unique
        val publicKeys = keyPairs.map { it.publicKeyHex }.toSet()
        assertEquals(50, publicKeys.size)

        signer.close()
    }

    @Test
    fun testMultipleSignVerifyCycles() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        repeat(50) { i ->
            val message = "Message #$i".toByteArray()
            val signResult = signer.sign(message, keyPair.secretKey)
            val verifyResult = signer.verify(signResult.signature, keyPair.publicKey)
            assertTrue("Cycle $i failed", verifyResult.isValid)
        }

        signer.close()
    }
}
