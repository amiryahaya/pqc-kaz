/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for SignatureResult
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for SignatureResult data class.
 * These tests run on the JVM without requiring an Android device.
 */
class SignatureResultTest {

    // ========================================================================
    // Basic Construction Tests
    // ========================================================================

    @Test
    fun `SignatureResult stores signature correctly`() {
        val signature = ByteArray(200) { it.toByte() }
        val message = ByteArray(38) { (it + 100).toByte() }
        val result = SignatureResult(signature, message, 128)

        assertArrayEquals(signature, result.signature)
    }

    @Test
    fun `SignatureResult stores message correctly`() {
        val signature = ByteArray(200)
        val message = "Hello, World!".toByteArray()
        val result = SignatureResult(signature, message, 128)

        assertArrayEquals(message, result.message)
    }

    @Test
    fun `SignatureResult stores level correctly`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 192)
        assertEquals(192, result.level)
    }

    // ========================================================================
    // securityLevel Property Tests
    // ========================================================================

    @Test
    fun `securityLevel returns Level 128`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertEquals(SecurityLevel.LEVEL_128, result.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 192`() {
        val result = SignatureResult(ByteArray(300), ByteArray(36), 192)
        assertEquals(SecurityLevel.LEVEL_192, result.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 256`() {
        val result = SignatureResult(ByteArray(400), ByteArray(44), 256)
        assertEquals(SecurityLevel.LEVEL_256, result.securityLevel)
    }

    // ========================================================================
    // overhead Property Tests
    // ========================================================================

    @Test
    fun `overhead is calculated correctly for Level 128`() {
        // Level 128 overhead is 57 bytes
        val messageSize = 50
        val signatureSize = messageSize + 57
        val result = SignatureResult(
            ByteArray(signatureSize),
            ByteArray(messageSize),
            128
        )
        assertEquals(57, result.overhead)
    }

    @Test
    fun `overhead is calculated correctly for Level 192`() {
        // Level 192 overhead is 81 bytes
        val messageSize = 100
        val signatureSize = messageSize + 81
        val result = SignatureResult(
            ByteArray(signatureSize),
            ByteArray(messageSize),
            192
        )
        assertEquals(81, result.overhead)
    }

    @Test
    fun `overhead is calculated correctly for Level 256`() {
        // Level 256 overhead is 105 bytes
        val messageSize = 75
        val signatureSize = messageSize + 105
        val result = SignatureResult(
            ByteArray(signatureSize),
            ByteArray(messageSize),
            256
        )
        assertEquals(105, result.overhead)
    }

    @Test
    fun `overhead with empty message equals signature size`() {
        val signatureSize = 57
        val result = SignatureResult(ByteArray(signatureSize), ByteArray(0), 128)
        assertEquals(signatureSize, result.overhead)
    }

    @Test
    fun `overhead calculation handles various message sizes`() {
        val overheads = listOf(57, 81, 105)
        val levels = listOf(128, 192, 256)
        val messageSizes = listOf(0, 1, 10, 100, 1000, 10000)

        for ((overhead, level) in overheads.zip(levels)) {
            for (msgSize in messageSizes) {
                val result = SignatureResult(
                    ByteArray(msgSize + overhead),
                    ByteArray(msgSize),
                    level
                )
                assertEquals("Overhead incorrect for level $level, message size $msgSize",
                    overhead, result.overhead)
            }
        }
    }

    // ========================================================================
    // Hex Conversion Tests
    // ========================================================================

    @Test
    fun `signatureHex converts bytes to hex correctly`() {
        val signature = byteArrayOf(0x00, 0x01, 0x0F, 0x10, 0xFF.toByte())
        val result = SignatureResult(signature, ByteArray(0), 128)

        assertEquals("00010f10ff", result.signatureHex)
    }

    @Test
    fun `signatureHex is lowercase`() {
        val signature = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val result = SignatureResult(signature, ByteArray(0), 128)

        assertEquals("abcdef", result.signatureHex)
    }

    @Test
    fun `empty signature produces empty hex string`() {
        val result = SignatureResult(ByteArray(0), ByteArray(0), 128)
        assertEquals("", result.signatureHex)
    }

    // ========================================================================
    // Equality Tests
    // ========================================================================

    @Test
    fun `identical SignatureResults are equal`() {
        val sig = ByteArray(200) { it.toByte() }
        val msg = ByteArray(38) { it.toByte() }

        val result1 = SignatureResult(sig.copyOf(), msg.copyOf(), 128)
        val result2 = SignatureResult(sig.copyOf(), msg.copyOf(), 128)

        assertEquals(result1, result2)
    }

    @Test
    fun `SignatureResults with different signatures are not equal`() {
        val msg = ByteArray(38) { it.toByte() }

        val result1 = SignatureResult(ByteArray(200) { 0 }, msg.copyOf(), 128)
        val result2 = SignatureResult(ByteArray(200) { 1 }, msg.copyOf(), 128)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `SignatureResults with different messages are not equal`() {
        val sig = ByteArray(200) { it.toByte() }

        val result1 = SignatureResult(sig.copyOf(), ByteArray(38) { 0 }, 128)
        val result2 = SignatureResult(sig.copyOf(), ByteArray(38) { 1 }, 128)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `SignatureResults with different levels are not equal`() {
        val sig = ByteArray(200) { it.toByte() }
        val msg = ByteArray(38) { it.toByte() }

        val result1 = SignatureResult(sig.copyOf(), msg.copyOf(), 128)
        val result2 = SignatureResult(sig.copyOf(), msg.copyOf(), 256)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `SignatureResult equals itself`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertEquals(result, result)
    }

    @Test
    fun `SignatureResult is not equal to null`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertNotEquals(result, null)
    }

    // ========================================================================
    // hashCode Tests
    // ========================================================================

    @Test
    fun `identical SignatureResults have same hashCode`() {
        val sig = ByteArray(200) { it.toByte() }
        val msg = ByteArray(38) { it.toByte() }

        val result1 = SignatureResult(sig.copyOf(), msg.copyOf(), 128)
        val result2 = SignatureResult(sig.copyOf(), msg.copyOf(), 128)

        assertEquals(result1.hashCode(), result2.hashCode())
    }

    // ========================================================================
    // toString Tests
    // ========================================================================

    @Test
    fun `toString includes level`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertTrue(result.toString().contains("level=128"))
    }

    @Test
    fun `toString includes signature length`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertTrue(result.toString().contains("signatureLength=200"))
    }

    @Test
    fun `toString includes message length`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertTrue(result.toString().contains("messageLength=38"))
    }

    @Test
    fun `toString includes overhead`() {
        val result = SignatureResult(ByteArray(200), ByteArray(38), 128)
        assertTrue(result.toString().contains("overhead=162"))
    }

    // ========================================================================
    // All Security Levels
    // ========================================================================

    @Test
    fun `SignatureResult works with Level 128 overhead`() {
        val messageSize = 100
        val result = SignatureResult(
            ByteArray(messageSize + SecurityLevel.LEVEL_128.signatureOverhead),
            ByteArray(messageSize),
            128
        )
        assertEquals(SecurityLevel.LEVEL_128.signatureOverhead, result.overhead)
    }

    @Test
    fun `SignatureResult works with Level 192 overhead`() {
        val messageSize = 100
        val result = SignatureResult(
            ByteArray(messageSize + SecurityLevel.LEVEL_192.signatureOverhead),
            ByteArray(messageSize),
            192
        )
        assertEquals(SecurityLevel.LEVEL_192.signatureOverhead, result.overhead)
    }

    @Test
    fun `SignatureResult works with Level 256 overhead`() {
        val messageSize = 100
        val result = SignatureResult(
            ByteArray(messageSize + SecurityLevel.LEVEL_256.signatureOverhead),
            ByteArray(messageSize),
            256
        )
        assertEquals(SecurityLevel.LEVEL_256.signatureOverhead, result.overhead)
    }
}
