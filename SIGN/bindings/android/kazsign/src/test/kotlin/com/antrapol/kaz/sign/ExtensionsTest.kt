/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for Extension Functions
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for extension functions.
 * These tests run on the JVM without requiring an Android device.
 */
class ExtensionsTest {

    // ========================================================================
    // toHexString Tests
    // ========================================================================

    @Test
    fun `toHexString converts empty array`() {
        val bytes = ByteArray(0)
        assertEquals("", bytes.toHexString())
    }

    @Test
    fun `toHexString converts single byte`() {
        assertEquals("00", byteArrayOf(0x00).toHexString())
        assertEquals("01", byteArrayOf(0x01).toHexString())
        assertEquals("0f", byteArrayOf(0x0F).toHexString())
        assertEquals("10", byteArrayOf(0x10).toHexString())
        assertEquals("ff", byteArrayOf(0xFF.toByte()).toHexString())
    }

    @Test
    fun `toHexString converts multiple bytes`() {
        val bytes = byteArrayOf(0x00, 0x01, 0x0F, 0x10, 0xFF.toByte())
        assertEquals("00010f10ff", bytes.toHexString())
    }

    @Test
    fun `toHexString produces lowercase hex`() {
        val bytes = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        assertEquals("abcdef", bytes.toHexString())
    }

    @Test
    fun `toHexString pads single digit with zero`() {
        // Bytes 0-15 should be padded
        for (i in 0..15) {
            val hex = byteArrayOf(i.toByte()).toHexString()
            assertEquals(2, hex.length)
            assertEquals("%02x".format(i), hex)
        }
    }

    @Test
    fun `toHexString handles large arrays`() {
        val size = 10000
        val bytes = ByteArray(size) { (it % 256).toByte() }
        val hex = bytes.toHexString()

        assertEquals(size * 2, hex.length)
    }

    @Test
    fun `toHexString is consistent`() {
        val bytes = ByteArray(100) { it.toByte() }
        val hex1 = bytes.toHexString()
        val hex2 = bytes.toHexString()

        assertEquals(hex1, hex2)
    }

    // ========================================================================
    // hexToByteArray Tests
    // ========================================================================

    @Test
    fun `hexToByteArray converts empty string`() {
        val bytes = "".hexToByteArray()
        assertEquals(0, bytes.size)
    }

    @Test
    fun `hexToByteArray converts single byte`() {
        assertArrayEquals(byteArrayOf(0x00), "00".hexToByteArray())
        assertArrayEquals(byteArrayOf(0x01), "01".hexToByteArray())
        assertArrayEquals(byteArrayOf(0x0F), "0f".hexToByteArray())
        assertArrayEquals(byteArrayOf(0x10), "10".hexToByteArray())
        assertArrayEquals(byteArrayOf(0xFF.toByte()), "ff".hexToByteArray())
    }

    @Test
    fun `hexToByteArray converts multiple bytes`() {
        val expected = byteArrayOf(0x00, 0x01, 0x0F, 0x10, 0xFF.toByte())
        assertArrayEquals(expected, "00010f10ff".hexToByteArray())
    }

    @Test
    fun `hexToByteArray handles uppercase`() {
        val expected = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        assertArrayEquals(expected, "ABCDEF".hexToByteArray())
    }

    @Test
    fun `hexToByteArray handles mixed case`() {
        val expected = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        assertArrayEquals(expected, "AbCdEf".hexToByteArray())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `hexToByteArray throws for odd length`() {
        "abc".hexToByteArray()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `hexToByteArray throws for single character`() {
        "a".hexToByteArray()
    }

    @Test(expected = NumberFormatException::class)
    fun `hexToByteArray throws for invalid characters`() {
        "gg".hexToByteArray()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `hexToByteArray throws for spaces`() {
        "ab cd".hexToByteArray()
    }

    @Test
    fun `hexToByteArray handles leading zeros`() {
        assertArrayEquals(byteArrayOf(0x00, 0x00, 0x01), "000001".hexToByteArray())
    }

    // ========================================================================
    // Round-trip Tests (toHexString <-> hexToByteArray)
    // ========================================================================

    @Test
    fun `roundtrip empty array`() {
        val original = ByteArray(0)
        val restored = original.toHexString().hexToByteArray()
        assertArrayEquals(original, restored)
    }

    @Test
    fun `roundtrip single byte`() {
        for (i in 0..255) {
            val original = byteArrayOf(i.toByte())
            val restored = original.toHexString().hexToByteArray()
            assertArrayEquals(original, restored)
        }
    }

    @Test
    fun `roundtrip multiple bytes`() {
        val original = byteArrayOf(0x00, 0x01, 0x7F, 0x80.toByte(), 0xFF.toByte())
        val restored = original.toHexString().hexToByteArray()
        assertArrayEquals(original, restored)
    }

    @Test
    fun `roundtrip random-like array`() {
        val original = ByteArray(256) { it.toByte() }
        val restored = original.toHexString().hexToByteArray()
        assertArrayEquals(original, restored)
    }

    @Test
    fun `roundtrip large array`() {
        val original = ByteArray(10000) { (it * 7 % 256).toByte() }
        val restored = original.toHexString().hexToByteArray()
        assertArrayEquals(original, restored)
    }

    // ========================================================================
    // secureWipe Tests
    // ========================================================================

    @Test
    fun `secureWipe clears empty array`() {
        val bytes = ByteArray(0)
        bytes.secureWipe()
        assertEquals(0, bytes.size)
    }

    @Test
    fun `secureWipe clears single byte`() {
        val bytes = byteArrayOf(0xFF.toByte())
        bytes.secureWipe()
        assertEquals(0.toByte(), bytes[0])
    }

    @Test
    fun `secureWipe clears all bytes to zero`() {
        val bytes = ByteArray(100) { (it + 1).toByte() }

        // Verify not all zeros initially
        assertTrue(bytes.any { it != 0.toByte() })

        bytes.secureWipe()

        // All should be zero now
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun `secureWipe handles large array`() {
        val bytes = ByteArray(100000) { 0xFF.toByte() }
        bytes.secureWipe()
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun `secureWipe is idempotent`() {
        val bytes = ByteArray(100) { it.toByte() }
        bytes.secureWipe()
        bytes.secureWipe()
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun `secureWipe clears key material`() {
        // Simulate clearing a secret key
        val secretKey = ByteArray(32) { (it * 17 + 42).toByte() }
        val originalSum = secretKey.sumOf { it.toInt() and 0xFF }

        assertTrue(originalSum > 0) // Key had data

        secretKey.secureWipe()

        val clearedSum = secretKey.sumOf { it.toInt() and 0xFF }
        assertEquals(0, clearedSum) // All zeros now
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    @Test
    fun `toHexString handles all byte values`() {
        for (i in 0..255) {
            val bytes = byteArrayOf(i.toByte())
            val hex = bytes.toHexString()
            assertEquals(2, hex.length)
            // Verify it's a valid lowercase hex string
            assertTrue(hex.all { it in '0'..'9' || it in 'a'..'f' })
        }
    }

    @Test
    fun `hexToByteArray and toHexString are inverses`() {
        val testCases = listOf(
            "00", "ff", "0123456789abcdef",
            "deadbeef", "cafebabe",
            "00".repeat(100)
        )

        for (hex in testCases) {
            val bytes = hex.hexToByteArray()
            val restored = bytes.toHexString()
            assertEquals(hex.lowercase(), restored)
        }
    }

    // ========================================================================
    // Cryptographic Key Size Tests
    // ========================================================================

    @Test
    fun `roundtrip Level 128 key sizes`() {
        val secretKey = ByteArray(32) { it.toByte() }
        val publicKey = ByteArray(54) { it.toByte() }

        assertArrayEquals(secretKey, secretKey.toHexString().hexToByteArray())
        assertArrayEquals(publicKey, publicKey.toHexString().hexToByteArray())
    }

    @Test
    fun `roundtrip Level 192 key sizes`() {
        val secretKey = ByteArray(50) { it.toByte() }
        val publicKey = ByteArray(88) { it.toByte() }

        assertArrayEquals(secretKey, secretKey.toHexString().hexToByteArray())
        assertArrayEquals(publicKey, publicKey.toHexString().hexToByteArray())
    }

    @Test
    fun `roundtrip Level 256 key sizes`() {
        val secretKey = ByteArray(64) { it.toByte() }
        val publicKey = ByteArray(118) { it.toByte() }

        assertArrayEquals(secretKey, secretKey.toHexString().hexToByteArray())
        assertArrayEquals(publicKey, publicKey.toHexString().hexToByteArray())
    }

    @Test
    fun `secureWipe works on all key sizes`() {
        val sizes = listOf(
            SecurityLevel.LEVEL_128.secretKeyBytes,
            SecurityLevel.LEVEL_128.publicKeyBytes,
            SecurityLevel.LEVEL_192.secretKeyBytes,
            SecurityLevel.LEVEL_192.publicKeyBytes,
            SecurityLevel.LEVEL_256.secretKeyBytes,
            SecurityLevel.LEVEL_256.publicKeyBytes
        )

        for (size in sizes) {
            val key = ByteArray(size) { 0xFF.toByte() }
            key.secureWipe()
            assertTrue("Size $size not cleared", key.all { it == 0.toByte() })
        }
    }
}
