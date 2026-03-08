/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for KeyPair
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for KeyPair data class.
 * These tests run on the JVM without requiring an Android device.
 */
class KeyPairTest {

    // ========================================================================
    // Basic Construction Tests
    // ========================================================================

    @Test
    fun `KeyPair stores public key correctly`() {
        val publicKey = ByteArray(49) { it.toByte() }
        val secretKey = ByteArray(98) { (it + 100).toByte() }
        val keyPair = KeyPair(publicKey, secretKey, 128)

        assertArrayEquals(publicKey, keyPair.publicKey)
    }

    @Test
    fun `KeyPair stores secret key correctly`() {
        val publicKey = ByteArray(49) { it.toByte() }
        val secretKey = ByteArray(98) { (it + 100).toByte() }
        val keyPair = KeyPair(publicKey, secretKey, 128)

        assertArrayEquals(secretKey, keyPair.secretKey)
    }

    @Test
    fun `KeyPair stores level correctly`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98), 128)
        assertEquals(128, keyPair.level)
    }

    // ========================================================================
    // securityLevel Property Tests
    // ========================================================================

    @Test
    fun `securityLevel returns Level 128 for level 128`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98), 128)
        assertEquals(SecurityLevel.LEVEL_128, keyPair.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 192 for level 192`() {
        val keyPair = KeyPair(ByteArray(73), ByteArray(146), 192)
        assertEquals(SecurityLevel.LEVEL_192, keyPair.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 256 for level 256`() {
        val keyPair = KeyPair(ByteArray(97), ByteArray(194), 256)
        assertEquals(SecurityLevel.LEVEL_256, keyPair.securityLevel)
    }

    // ========================================================================
    // Hex Conversion Tests
    // ========================================================================

    @Test
    fun `publicKeyHex converts bytes to hex correctly`() {
        val publicKey = byteArrayOf(0x00, 0x01, 0x0F, 0x10, 0xFF.toByte())
        val keyPair = KeyPair(publicKey, ByteArray(98), 128)

        assertEquals("00010f10ff", keyPair.publicKeyHex)
    }

    @Test
    fun `secretKeyHex converts bytes to hex correctly`() {
        val secretKey = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val keyPair = KeyPair(ByteArray(49), secretKey, 128)

        assertEquals("deadbeef", keyPair.secretKeyHex)
    }

    @Test
    fun `publicKeyHex is lowercase`() {
        val publicKey = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val keyPair = KeyPair(publicKey, ByteArray(98), 128)

        assertEquals("abcdef", keyPair.publicKeyHex)
    }

    @Test
    fun `empty key produces empty hex string`() {
        val keyPair = KeyPair(ByteArray(0), ByteArray(0), 128)
        assertEquals("", keyPair.publicKeyHex)
        assertEquals("", keyPair.secretKeyHex)
    }

    // ========================================================================
    // Equality Tests
    // ========================================================================

    @Test
    fun `identical KeyPairs are equal`() {
        val pk = ByteArray(49) { it.toByte() }
        val sk = ByteArray(98) { it.toByte() }

        val keyPair1 = KeyPair(pk.copyOf(), sk.copyOf(), 128)
        val keyPair2 = KeyPair(pk.copyOf(), sk.copyOf(), 128)

        assertEquals(keyPair1, keyPair2)
    }

    @Test
    fun `KeyPairs with different public keys are not equal`() {
        val sk = ByteArray(98) { it.toByte() }

        val keyPair1 = KeyPair(ByteArray(49) { 0 }, sk.copyOf(), 128)
        val keyPair2 = KeyPair(ByteArray(49) { 1 }, sk.copyOf(), 128)

        assertNotEquals(keyPair1, keyPair2)
    }

    @Test
    fun `KeyPairs with different secret keys are not equal`() {
        val pk = ByteArray(49) { it.toByte() }

        val keyPair1 = KeyPair(pk.copyOf(), ByteArray(98) { 0 }, 128)
        val keyPair2 = KeyPair(pk.copyOf(), ByteArray(98) { 1 }, 128)

        assertNotEquals(keyPair1, keyPair2)
    }

    @Test
    fun `KeyPairs with different levels are not equal`() {
        val pk = ByteArray(49) { it.toByte() }
        val sk = ByteArray(98) { it.toByte() }

        val keyPair1 = KeyPair(pk.copyOf(), sk.copyOf(), 128)
        val keyPair2 = KeyPair(pk.copyOf(), sk.copyOf(), 192)

        assertNotEquals(keyPair1, keyPair2)
    }

    @Test
    fun `KeyPair is not equal to null`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98), 128)
        assertNotEquals(keyPair, null)
    }

    @Test
    fun `KeyPair is not equal to other types`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98), 128)
        assertNotEquals(keyPair, "string")
        assertNotEquals(keyPair, 128)
    }

    @Test
    fun `KeyPair equals itself`() {
        val keyPair = KeyPair(ByteArray(49) { it.toByte() }, ByteArray(98) { it.toByte() }, 128)
        assertEquals(keyPair, keyPair)
    }

    // ========================================================================
    // hashCode Tests
    // ========================================================================

    @Test
    fun `identical KeyPairs have same hashCode`() {
        val pk = ByteArray(49) { it.toByte() }
        val sk = ByteArray(98) { it.toByte() }

        val keyPair1 = KeyPair(pk.copyOf(), sk.copyOf(), 128)
        val keyPair2 = KeyPair(pk.copyOf(), sk.copyOf(), 128)

        assertEquals(keyPair1.hashCode(), keyPair2.hashCode())
    }

    @Test
    fun `different KeyPairs likely have different hashCodes`() {
        val keyPair1 = KeyPair(ByteArray(49) { 0 }, ByteArray(98) { 0 }, 128)
        val keyPair2 = KeyPair(ByteArray(49) { 1 }, ByteArray(98) { 1 }, 256)

        // Not guaranteed but very likely
        assertNotEquals(keyPair1.hashCode(), keyPair2.hashCode())
    }

    // ========================================================================
    // toString Tests
    // ========================================================================

    @Test
    fun `toString includes level`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98), 128)
        assertTrue(keyPair.toString().contains("level=128"))
    }

    @Test
    fun `toString includes truncated public key`() {
        val publicKey = ByteArray(49) { 0xAB.toByte() }
        val keyPair = KeyPair(publicKey, ByteArray(98), 128)

        val str = keyPair.toString()
        assertTrue(str.contains("publicKey="))
        assertTrue(str.contains("..."))
    }

    @Test
    fun `toString redacts secret key`() {
        val keyPair = KeyPair(ByteArray(49), ByteArray(98) { 0xFF.toByte() }, 128)
        val str = keyPair.toString()

        assertTrue(str.contains("REDACTED"))
        assertFalse(str.contains("ff".repeat(16)))
    }

    // ========================================================================
    // All Security Levels
    // ========================================================================

    @Test
    fun `KeyPair works with Level 128 sizes`() {
        val keyPair = KeyPair(
            ByteArray(SecurityLevel.LEVEL_128.publicKeyBytes),
            ByteArray(SecurityLevel.LEVEL_128.secretKeyBytes),
            128
        )
        assertEquals(49, keyPair.publicKey.size)
        assertEquals(98, keyPair.secretKey.size)
    }

    @Test
    fun `KeyPair works with Level 192 sizes`() {
        val keyPair = KeyPair(
            ByteArray(SecurityLevel.LEVEL_192.publicKeyBytes),
            ByteArray(SecurityLevel.LEVEL_192.secretKeyBytes),
            192
        )
        assertEquals(73, keyPair.publicKey.size)
        assertEquals(146, keyPair.secretKey.size)
    }

    @Test
    fun `KeyPair works with Level 256 sizes`() {
        val keyPair = KeyPair(
            ByteArray(SecurityLevel.LEVEL_256.publicKeyBytes),
            ByteArray(SecurityLevel.LEVEL_256.secretKeyBytes),
            256
        )
        assertEquals(97, keyPair.publicKey.size)
        assertEquals(194, keyPair.secretKey.size)
    }
}
