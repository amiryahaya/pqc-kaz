/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for VerificationResult
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for VerificationResult data class.
 * These tests run on the JVM without requiring an Android device.
 */
class VerificationResultTest {

    // ========================================================================
    // Basic Construction Tests
    // ========================================================================

    @Test
    fun `VerificationResult stores isValid correctly when true`() {
        val result = VerificationResult(true, ByteArray(10), 128)
        assertTrue(result.isValid)
    }

    @Test
    fun `VerificationResult stores isValid correctly when false`() {
        val result = VerificationResult(false, null, 128)
        assertFalse(result.isValid)
    }

    @Test
    fun `VerificationResult stores message correctly`() {
        val message = "Hello, World!".toByteArray()
        val result = VerificationResult(true, message, 128)

        assertArrayEquals(message, result.message)
    }

    @Test
    fun `VerificationResult stores null message correctly`() {
        val result = VerificationResult(false, null, 128)
        assertNull(result.message)
    }

    @Test
    fun `VerificationResult stores level correctly`() {
        val result = VerificationResult(true, ByteArray(10), 192)
        assertEquals(192, result.level)
    }

    // ========================================================================
    // securityLevel Property Tests
    // ========================================================================

    @Test
    fun `securityLevel returns Level 128`() {
        val result = VerificationResult(true, ByteArray(10), 128)
        assertEquals(SecurityLevel.LEVEL_128, result.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 192`() {
        val result = VerificationResult(true, ByteArray(10), 192)
        assertEquals(SecurityLevel.LEVEL_192, result.securityLevel)
    }

    @Test
    fun `securityLevel returns Level 256`() {
        val result = VerificationResult(true, ByteArray(10), 256)
        assertEquals(SecurityLevel.LEVEL_256, result.securityLevel)
    }

    // ========================================================================
    // getMessageAsString Tests
    // ========================================================================

    @Test
    fun `getMessageAsString returns string when valid`() {
        val message = "Hello, World!"
        val result = VerificationResult(true, message.toByteArray(Charsets.UTF_8), 128)

        assertEquals(message, result.getMessageAsString())
    }

    @Test
    fun `getMessageAsString returns null when invalid`() {
        val result = VerificationResult(false, null, 128)
        assertNull(result.getMessageAsString())
    }

    @Test
    fun `getMessageAsString handles empty message`() {
        val result = VerificationResult(true, ByteArray(0), 128)
        assertEquals("", result.getMessageAsString())
    }

    @Test
    fun `getMessageAsString handles UTF-8 characters`() {
        val message = "Hello \u4e16\u754c!"  // Hello 世界!
        val result = VerificationResult(true, message.toByteArray(Charsets.UTF_8), 128)

        assertEquals(message, result.getMessageAsString())
    }

    @Test
    fun `getMessageAsString handles emoji`() {
        val message = "Hello \uD83D\uDC4B\uD83C\uDF0D"  // Hello 👋🌍
        val result = VerificationResult(true, message.toByteArray(Charsets.UTF_8), 128)

        assertEquals(message, result.getMessageAsString())
    }

    // ========================================================================
    // getMessageAsHex Tests
    // ========================================================================

    @Test
    fun `getMessageAsHex returns hex when valid`() {
        val message = byteArrayOf(0x00, 0x01, 0x0F, 0xFF.toByte())
        val result = VerificationResult(true, message, 128)

        assertEquals("00010fff", result.getMessageAsHex())
    }

    @Test
    fun `getMessageAsHex returns null when invalid`() {
        val result = VerificationResult(false, null, 128)
        assertNull(result.getMessageAsHex())
    }

    @Test
    fun `getMessageAsHex handles empty message`() {
        val result = VerificationResult(true, ByteArray(0), 128)
        assertEquals("", result.getMessageAsHex())
    }

    @Test
    fun `getMessageAsHex is lowercase`() {
        val message = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val result = VerificationResult(true, message, 128)

        assertEquals("abcdef", result.getMessageAsHex())
    }

    // ========================================================================
    // Equality Tests
    // ========================================================================

    @Test
    fun `identical VerificationResults are equal`() {
        val msg = ByteArray(20) { it.toByte() }

        val result1 = VerificationResult(true, msg.copyOf(), 128)
        val result2 = VerificationResult(true, msg.copyOf(), 128)

        assertEquals(result1, result2)
    }

    @Test
    fun `VerificationResults with null messages are equal`() {
        val result1 = VerificationResult(false, null, 128)
        val result2 = VerificationResult(false, null, 128)

        assertEquals(result1, result2)
    }

    @Test
    fun `VerificationResults with different isValid are not equal`() {
        val msg = ByteArray(20) { it.toByte() }

        val result1 = VerificationResult(true, msg.copyOf(), 128)
        val result2 = VerificationResult(false, msg.copyOf(), 128)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `VerificationResults with different messages are not equal`() {
        val result1 = VerificationResult(true, ByteArray(20) { 0 }, 128)
        val result2 = VerificationResult(true, ByteArray(20) { 1 }, 128)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `VerificationResult with message vs null are not equal`() {
        val result1 = VerificationResult(true, ByteArray(20), 128)
        val result2 = VerificationResult(true, null, 128)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `VerificationResults with different levels are not equal`() {
        val msg = ByteArray(20) { it.toByte() }

        val result1 = VerificationResult(true, msg.copyOf(), 128)
        val result2 = VerificationResult(true, msg.copyOf(), 256)

        assertNotEquals(result1, result2)
    }

    @Test
    fun `VerificationResult equals itself`() {
        val result = VerificationResult(true, ByteArray(20), 128)
        assertEquals(result, result)
    }

    @Test
    fun `VerificationResult is not equal to null`() {
        val result = VerificationResult(true, ByteArray(20), 128)
        assertNotEquals(result, null)
    }

    // ========================================================================
    // hashCode Tests
    // ========================================================================

    @Test
    fun `identical VerificationResults have same hashCode`() {
        val msg = ByteArray(20) { it.toByte() }

        val result1 = VerificationResult(true, msg.copyOf(), 128)
        val result2 = VerificationResult(true, msg.copyOf(), 128)

        assertEquals(result1.hashCode(), result2.hashCode())
    }

    @Test
    fun `VerificationResults with null messages have same hashCode`() {
        val result1 = VerificationResult(false, null, 128)
        val result2 = VerificationResult(false, null, 128)

        assertEquals(result1.hashCode(), result2.hashCode())
    }

    // ========================================================================
    // toString Tests
    // ========================================================================

    @Test
    fun `toString includes isValid true`() {
        val result = VerificationResult(true, ByteArray(20), 128)
        assertTrue(result.toString().contains("isValid=true"))
    }

    @Test
    fun `toString includes isValid false`() {
        val result = VerificationResult(false, null, 128)
        assertTrue(result.toString().contains("isValid=false"))
    }

    @Test
    fun `toString includes level`() {
        val result = VerificationResult(true, ByteArray(20), 128)
        assertTrue(result.toString().contains("level=128"))
    }

    @Test
    fun `toString includes message length when present`() {
        val result = VerificationResult(true, ByteArray(20), 128)
        assertTrue(result.toString().contains("messageLength=20"))
    }

    @Test
    fun `toString includes zero message length when null`() {
        val result = VerificationResult(false, null, 128)
        assertTrue(result.toString().contains("messageLength=0"))
    }

    // ========================================================================
    // Common Usage Patterns
    // ========================================================================

    @Test
    fun `valid verification has message`() {
        val message = "Test message"
        val result = VerificationResult(true, message.toByteArray(), 128)

        assertTrue(result.isValid)
        assertNotNull(result.message)
        assertEquals(message, result.getMessageAsString())
    }

    @Test
    fun `invalid verification typically has null message`() {
        val result = VerificationResult(false, null, 128)

        assertFalse(result.isValid)
        assertNull(result.message)
        assertNull(result.getMessageAsString())
    }

    @Test
    fun `all levels work with valid result`() {
        for (level in SecurityLevel.entries) {
            val result = VerificationResult(
                true,
                "Test".toByteArray(),
                level.value
            )
            assertTrue(result.isValid)
            assertEquals(level, result.securityLevel)
        }
    }

    @Test
    fun `all levels work with invalid result`() {
        for (level in SecurityLevel.entries) {
            val result = VerificationResult(
                false,
                null,
                level.value
            )
            assertFalse(result.isValid)
            assertEquals(level, result.securityLevel)
        }
    }
}
