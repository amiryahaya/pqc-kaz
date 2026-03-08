package com.antrapol.kaz.kem

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for utility functions.
 */
class UtilityTest {

    @Test
    fun `test toHexString with simple values`() {
        assertEquals("00", byteArrayOf(0).toHexString())
        assertEquals("ff", byteArrayOf(-1).toHexString())
        assertEquals("0011aaff", byteArrayOf(0x00, 0x11, 0xAA.toByte(), 0xFF.toByte()).toHexString())
    }

    @Test
    fun `test toHexString with empty array`() {
        assertEquals("", byteArrayOf().toHexString())
    }

    @Test
    fun `test hexToByteArray with valid hex`() {
        assertArrayEquals(byteArrayOf(0x00, 0x11, 0xAA.toByte(), 0xFF.toByte()), "0011aaff".hexToByteArray())
        assertArrayEquals(byteArrayOf(0x00, 0x11, 0xAA.toByte(), 0xFF.toByte()), "0011AAFF".hexToByteArray())
    }

    @Test
    fun `test hexToByteArray with empty string`() {
        assertArrayEquals(byteArrayOf(), "".hexToByteArray())
    }

    @Test(expected = IllegalStateException::class)
    fun `test hexToByteArray throws for odd length`() {
        "abc".hexToByteArray()
    }

    @Test
    fun `test roundtrip hex conversion`() {
        val original = byteArrayOf(0x12, 0x34, 0x56, 0x78, 0x9A.toByte(), 0xBC.toByte(), 0xDE.toByte(), 0xF0.toByte())
        val hex = original.toHexString()
        val restored = hex.hexToByteArray()
        assertArrayEquals(original, restored)
    }

    @Test
    fun `test secureZero clears array`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        secureZero(data)
        assertTrue(data.all { it == 0.toByte() })
    }
}
