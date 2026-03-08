/*
 * KAZ-SIGN Android Wrapper
 * Unit Tests for KazSignException
 */

package com.antrapol.kaz.sign

import org.junit.Test
import org.junit.Assert.*

/**
 * Unit tests for KazSignException class.
 * These tests run on the JVM without requiring an Android device.
 */
class KazSignExceptionTest {

    // ========================================================================
    // ErrorCode Enum Tests
    // ========================================================================

    @Test
    fun `ErrorCode has correct values`() {
        assertEquals(0, KazSignException.ErrorCode.SUCCESS.value)
        assertEquals(-1, KazSignException.ErrorCode.MEMORY_ERROR.value)
        assertEquals(-2, KazSignException.ErrorCode.RNG_ERROR.value)
        assertEquals(-3, KazSignException.ErrorCode.INVALID_PARAMETER.value)
        assertEquals(-4, KazSignException.ErrorCode.VERIFICATION_FAILED.value)
        assertEquals(-99, KazSignException.ErrorCode.UNKNOWN.value)
    }

    @Test
    fun `ErrorCode has six entries`() {
        assertEquals(6, KazSignException.ErrorCode.entries.size)
    }

    // ========================================================================
    // ErrorCode fromValue Tests
    // ========================================================================

    @Test
    fun `fromValue returns SUCCESS for 0`() {
        assertEquals(KazSignException.ErrorCode.SUCCESS,
            KazSignException.ErrorCode.fromValue(0))
    }

    @Test
    fun `fromValue returns MEMORY_ERROR for -1`() {
        assertEquals(KazSignException.ErrorCode.MEMORY_ERROR,
            KazSignException.ErrorCode.fromValue(-1))
    }

    @Test
    fun `fromValue returns RNG_ERROR for -2`() {
        assertEquals(KazSignException.ErrorCode.RNG_ERROR,
            KazSignException.ErrorCode.fromValue(-2))
    }

    @Test
    fun `fromValue returns INVALID_PARAMETER for -3`() {
        assertEquals(KazSignException.ErrorCode.INVALID_PARAMETER,
            KazSignException.ErrorCode.fromValue(-3))
    }

    @Test
    fun `fromValue returns VERIFICATION_FAILED for -4`() {
        assertEquals(KazSignException.ErrorCode.VERIFICATION_FAILED,
            KazSignException.ErrorCode.fromValue(-4))
    }

    @Test
    fun `fromValue returns UNKNOWN for -99`() {
        assertEquals(KazSignException.ErrorCode.UNKNOWN,
            KazSignException.ErrorCode.fromValue(-99))
    }

    @Test
    fun `fromValue returns UNKNOWN for unmapped positive value`() {
        assertEquals(KazSignException.ErrorCode.UNKNOWN,
            KazSignException.ErrorCode.fromValue(1))
    }

    @Test
    fun `fromValue returns UNKNOWN for unmapped negative value`() {
        assertEquals(KazSignException.ErrorCode.UNKNOWN,
            KazSignException.ErrorCode.fromValue(-5))
    }

    @Test
    fun `fromValue returns UNKNOWN for large positive value`() {
        assertEquals(KazSignException.ErrorCode.UNKNOWN,
            KazSignException.ErrorCode.fromValue(999))
    }

    @Test
    fun `fromValue returns UNKNOWN for large negative value`() {
        assertEquals(KazSignException.ErrorCode.UNKNOWN,
            KazSignException.ErrorCode.fromValue(-999))
    }

    // ========================================================================
    // Exception Construction Tests
    // ========================================================================

    @Test
    fun `exception stores message correctly`() {
        val message = "Test error message"
        val exception = KazSignException(message)
        assertEquals(message, exception.message)
    }

    @Test
    fun `exception stores error code correctly`() {
        val exception = KazSignException(
            "Test",
            KazSignException.ErrorCode.MEMORY_ERROR
        )
        assertEquals(KazSignException.ErrorCode.MEMORY_ERROR, exception.errorCode)
    }

    @Test
    fun `exception defaults to UNKNOWN error code`() {
        val exception = KazSignException("Test")
        assertEquals(KazSignException.ErrorCode.UNKNOWN, exception.errorCode)
    }

    @Test
    fun `exception is throwable`() {
        val exception = KazSignException("Test")
        assertTrue(exception is Exception)
        assertTrue(exception is Throwable)
    }

    // ========================================================================
    // fromErrorCode Factory Tests
    // ========================================================================

    @Test
    fun `fromErrorCode creates exception for SUCCESS`() {
        val exception = KazSignException.fromErrorCode(0)
        assertEquals(KazSignException.ErrorCode.SUCCESS, exception.errorCode)
        assertTrue(exception.message?.contains("successful") == true)
    }

    @Test
    fun `fromErrorCode creates exception for MEMORY_ERROR`() {
        val exception = KazSignException.fromErrorCode(-1)
        assertEquals(KazSignException.ErrorCode.MEMORY_ERROR, exception.errorCode)
        assertTrue(exception.message?.contains("Memory") == true ||
                   exception.message?.contains("memory") == true)
    }

    @Test
    fun `fromErrorCode creates exception for RNG_ERROR`() {
        val exception = KazSignException.fromErrorCode(-2)
        assertEquals(KazSignException.ErrorCode.RNG_ERROR, exception.errorCode)
        assertTrue(exception.message?.contains("Random") == true ||
                   exception.message?.contains("random") == true)
    }

    @Test
    fun `fromErrorCode creates exception for INVALID_PARAMETER`() {
        val exception = KazSignException.fromErrorCode(-3)
        assertEquals(KazSignException.ErrorCode.INVALID_PARAMETER, exception.errorCode)
        assertTrue(exception.message?.contains("parameter") == true ||
                   exception.message?.contains("Invalid") == true)
    }

    @Test
    fun `fromErrorCode creates exception for VERIFICATION_FAILED`() {
        val exception = KazSignException.fromErrorCode(-4)
        assertEquals(KazSignException.ErrorCode.VERIFICATION_FAILED, exception.errorCode)
        assertTrue(exception.message?.contains("verification") == true ||
                   exception.message?.contains("Verification") == true)
    }

    @Test
    fun `fromErrorCode creates exception for UNKNOWN with original code in message`() {
        val exception = KazSignException.fromErrorCode(-999)
        assertEquals(KazSignException.ErrorCode.UNKNOWN, exception.errorCode)
        assertTrue(exception.message?.contains("-999") == true)
    }

    // ========================================================================
    // Exception Throwing Tests
    // ========================================================================

    @Test(expected = KazSignException::class)
    fun `exception can be thrown and caught`() {
        throw KazSignException("Test exception")
    }

    @Test
    fun `exception preserves error code when thrown`() {
        try {
            throw KazSignException("Test", KazSignException.ErrorCode.RNG_ERROR)
        } catch (e: KazSignException) {
            assertEquals(KazSignException.ErrorCode.RNG_ERROR, e.errorCode)
        }
    }

    @Test
    fun `exception preserves message when thrown`() {
        val message = "Custom error message"
        try {
            throw KazSignException(message)
        } catch (e: KazSignException) {
            assertEquals(message, e.message)
        }
    }

    // ========================================================================
    // Error Message Quality Tests
    // ========================================================================

    @Test
    fun `all error codes have descriptive messages`() {
        val codes = listOf(0, -1, -2, -3, -4, -99)
        for (code in codes) {
            val exception = KazSignException.fromErrorCode(code)
            assertNotNull(exception.message)
            assertTrue(exception.message!!.isNotEmpty())
            assertTrue(exception.message!!.length > 5) // More than just a word
        }
    }

    @Test
    fun `UNKNOWN error includes original code for debugging`() {
        val unknownCodes = listOf(-5, -10, -50, 1, 10, 100)
        for (code in unknownCodes) {
            val exception = KazSignException.fromErrorCode(code)
            assertTrue(
                "Message should contain code $code",
                exception.message?.contains(code.toString()) == true
            )
        }
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    @Test
    fun `exception with empty message`() {
        val exception = KazSignException("")
        assertEquals("", exception.message)
    }

    @Test
    fun `exception with long message`() {
        val longMessage = "A".repeat(10000)
        val exception = KazSignException(longMessage)
        assertEquals(longMessage, exception.message)
    }

    @Test
    fun `exception with special characters in message`() {
        val message = "Error: \n\t\"quote\" 'apostrophe' <tag> &amp; $100"
        val exception = KazSignException(message)
        assertEquals(message, exception.message)
    }

    @Test
    fun `exception with unicode in message`() {
        val message = "Error: \u4e16\u754c \uD83D\uDCA5"  // 世界 💥
        val exception = KazSignException(message)
        assertEquals(message, exception.message)
    }
}
