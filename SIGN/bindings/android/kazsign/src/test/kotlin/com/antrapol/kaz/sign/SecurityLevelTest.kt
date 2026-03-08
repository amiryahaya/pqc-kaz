/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for SecurityLevel
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for SecurityLevel enum.
 * These tests run on the JVM without requiring an Android device.
 */
class SecurityLevelTest {

    // ========================================================================
    // Basic Enum Tests
    // ========================================================================

    @Test
    fun `SecurityLevel has three levels`() {
        val levels = SecurityLevel.entries
        assertEquals(3, levels.size)
    }

    @Test
    fun `SecurityLevel values are correct`() {
        assertEquals(128, SecurityLevel.LEVEL_128.value)
        assertEquals(192, SecurityLevel.LEVEL_192.value)
        assertEquals(256, SecurityLevel.LEVEL_256.value)
    }

    // ========================================================================
    // Level 128 Parameters
    // ========================================================================

    @Test
    fun `Level 128 has correct secret key size`() {
        assertEquals(32, SecurityLevel.LEVEL_128.secretKeyBytes)
    }

    @Test
    fun `Level 128 has correct public key size`() {
        assertEquals(54, SecurityLevel.LEVEL_128.publicKeyBytes)
    }

    @Test
    fun `Level 128 has correct signature overhead`() {
        assertEquals(162, SecurityLevel.LEVEL_128.signatureOverhead)
    }

    @Test
    fun `Level 128 has correct hash size`() {
        assertEquals(32, SecurityLevel.LEVEL_128.hashBytes)
    }

    @Test
    fun `Level 128 has correct algorithm name`() {
        assertEquals("KAZ-SIGN-128", SecurityLevel.LEVEL_128.algorithmName)
    }

    // ========================================================================
    // Level 192 Parameters
    // ========================================================================

    @Test
    fun `Level 192 has correct secret key size`() {
        assertEquals(50, SecurityLevel.LEVEL_192.secretKeyBytes)
    }

    @Test
    fun `Level 192 has correct public key size`() {
        assertEquals(88, SecurityLevel.LEVEL_192.publicKeyBytes)
    }

    @Test
    fun `Level 192 has correct signature overhead`() {
        assertEquals(264, SecurityLevel.LEVEL_192.signatureOverhead)
    }

    @Test
    fun `Level 192 has correct hash size`() {
        assertEquals(48, SecurityLevel.LEVEL_192.hashBytes)
    }

    @Test
    fun `Level 192 has correct algorithm name`() {
        assertEquals("KAZ-SIGN-192", SecurityLevel.LEVEL_192.algorithmName)
    }

    // ========================================================================
    // Level 256 Parameters
    // ========================================================================

    @Test
    fun `Level 256 has correct secret key size`() {
        assertEquals(64, SecurityLevel.LEVEL_256.secretKeyBytes)
    }

    @Test
    fun `Level 256 has correct public key size`() {
        assertEquals(118, SecurityLevel.LEVEL_256.publicKeyBytes)
    }

    @Test
    fun `Level 256 has correct signature overhead`() {
        assertEquals(356, SecurityLevel.LEVEL_256.signatureOverhead)
    }

    @Test
    fun `Level 256 has correct hash size`() {
        assertEquals(64, SecurityLevel.LEVEL_256.hashBytes)
    }

    @Test
    fun `Level 256 has correct algorithm name`() {
        assertEquals("KAZ-SIGN-256", SecurityLevel.LEVEL_256.algorithmName)
    }

    // ========================================================================
    // fromValue Tests
    // ========================================================================

    @Test
    fun `fromValue returns Level 128 for value 128`() {
        assertEquals(SecurityLevel.LEVEL_128, SecurityLevel.fromValue(128))
    }

    @Test
    fun `fromValue returns Level 192 for value 192`() {
        assertEquals(SecurityLevel.LEVEL_192, SecurityLevel.fromValue(192))
    }

    @Test
    fun `fromValue returns Level 256 for value 256`() {
        assertEquals(SecurityLevel.LEVEL_256, SecurityLevel.fromValue(256))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `fromValue throws for invalid value 0`() {
        SecurityLevel.fromValue(0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `fromValue throws for invalid value 64`() {
        SecurityLevel.fromValue(64)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `fromValue throws for negative value`() {
        SecurityLevel.fromValue(-128)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `fromValue throws for value 512`() {
        SecurityLevel.fromValue(512)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `fromValue throws for close but invalid value 127`() {
        SecurityLevel.fromValue(127)
    }

    // ========================================================================
    // Parameter Relationship Tests
    // ========================================================================

    @Test
    fun `higher levels have larger secret keys`() {
        assertTrue(SecurityLevel.LEVEL_128.secretKeyBytes < SecurityLevel.LEVEL_192.secretKeyBytes)
        assertTrue(SecurityLevel.LEVEL_192.secretKeyBytes < SecurityLevel.LEVEL_256.secretKeyBytes)
    }

    @Test
    fun `higher levels have larger public keys`() {
        assertTrue(SecurityLevel.LEVEL_128.publicKeyBytes < SecurityLevel.LEVEL_192.publicKeyBytes)
        assertTrue(SecurityLevel.LEVEL_192.publicKeyBytes < SecurityLevel.LEVEL_256.publicKeyBytes)
    }

    @Test
    fun `higher levels have larger signature overhead`() {
        assertTrue(SecurityLevel.LEVEL_128.signatureOverhead < SecurityLevel.LEVEL_192.signatureOverhead)
        assertTrue(SecurityLevel.LEVEL_192.signatureOverhead < SecurityLevel.LEVEL_256.signatureOverhead)
    }

    @Test
    fun `higher levels have larger hash sizes`() {
        assertTrue(SecurityLevel.LEVEL_128.hashBytes < SecurityLevel.LEVEL_192.hashBytes)
        assertTrue(SecurityLevel.LEVEL_192.hashBytes < SecurityLevel.LEVEL_256.hashBytes)
    }

    @Test
    fun `hash sizes match expected SHA variants`() {
        // Level 128 uses SHA-256 (32 bytes)
        assertEquals(32, SecurityLevel.LEVEL_128.hashBytes)
        // Level 192 uses SHA-384 (48 bytes)
        assertEquals(48, SecurityLevel.LEVEL_192.hashBytes)
        // Level 256 uses SHA-512 (64 bytes)
        assertEquals(64, SecurityLevel.LEVEL_256.hashBytes)
    }

    // ========================================================================
    // Enum Iteration Tests
    // ========================================================================

    @Test
    fun `all levels have non-empty algorithm names`() {
        for (level in SecurityLevel.entries) {
            assertTrue(level.algorithmName.isNotEmpty())
            assertTrue(level.algorithmName.startsWith("KAZ-SIGN-"))
        }
    }

    @Test
    fun `all levels have positive key sizes`() {
        for (level in SecurityLevel.entries) {
            assertTrue(level.secretKeyBytes > 0)
            assertTrue(level.publicKeyBytes > 0)
            assertTrue(level.signatureOverhead > 0)
            assertTrue(level.hashBytes > 0)
        }
    }

    @Test
    fun `algorithm names contain level value`() {
        for (level in SecurityLevel.entries) {
            assertTrue(level.algorithmName.contains(level.value.toString()))
        }
    }
}
