package com.antrapol.kaz.kem

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [SecurityLevel] enum.
 */
class SecurityLevelTest {

    @Test
    fun `test security levels have correct values`() {
        assertEquals(128, SecurityLevel.LEVEL_128.value)
        assertEquals(192, SecurityLevel.LEVEL_192.value)
        assertEquals(256, SecurityLevel.LEVEL_256.value)
    }

    @Test
    fun `test fromValue returns correct level`() {
        assertEquals(SecurityLevel.LEVEL_128, SecurityLevel.fromValue(128))
        assertEquals(SecurityLevel.LEVEL_192, SecurityLevel.fromValue(192))
        assertEquals(SecurityLevel.LEVEL_256, SecurityLevel.fromValue(256))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test fromValue throws for invalid value`() {
        SecurityLevel.fromValue(64)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test fromValue throws for zero`() {
        SecurityLevel.fromValue(0)
    }

    @Test
    fun `test random masks are correct`() {
        assertEquals(0x7F.toByte(), SecurityLevel.LEVEL_128.randomMask)
        assertEquals(0x3F.toByte(), SecurityLevel.LEVEL_192.randomMask)
        assertEquals(0x1F.toByte(), SecurityLevel.LEVEL_256.randomMask)
    }

    @Test
    fun `test entries contain all levels`() {
        val entries = SecurityLevel.entries
        assertEquals(3, entries.size)
        assertTrue(entries.contains(SecurityLevel.LEVEL_128))
        assertTrue(entries.contains(SecurityLevel.LEVEL_192))
        assertTrue(entries.contains(SecurityLevel.LEVEL_256))
    }
}
