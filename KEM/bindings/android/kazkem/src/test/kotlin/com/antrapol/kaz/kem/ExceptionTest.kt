package com.antrapol.kaz.kem

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for exception classes.
 */
class ExceptionTest {

    @Test
    fun `test KazKemException creation`() {
        val exception = KazKemException(-1, "Test error")
        assertEquals(-1, exception.errorCode)
        assertEquals("Test error", exception.message)
    }

    @Test
    fun `test fromErrorCode creates descriptive messages`() {
        val invalidParam = KazKemException.fromErrorCode(KazKemException.ERROR_INVALID_PARAM, "test")
        assertTrue(invalidParam.message!!.contains("Invalid parameter"))
        assertTrue(invalidParam.isInvalidParameter())

        val memory = KazKemException.fromErrorCode(KazKemException.ERROR_MEMORY, "test")
        assertTrue(memory.message!!.contains("Memory allocation failed"))
        assertTrue(memory.isMemoryError())

        val rng = KazKemException.fromErrorCode(KazKemException.ERROR_RNG, "test")
        assertTrue(rng.message!!.contains("Random number generation failed"))
        assertTrue(rng.isRngError())

        val notInit = KazKemException.fromErrorCode(KazKemException.ERROR_NOT_INIT, "test")
        assertTrue(notInit.message!!.contains("not initialized"))
        assertTrue(notInit.isNotInitialized())
    }

    @Test
    fun `test fromErrorCode with unknown error`() {
        val unknown = KazKemException.fromErrorCode(-999, "test")
        assertTrue(unknown.message!!.contains("Unknown error"))
        assertEquals(-999, unknown.errorCode)
    }

    @Test
    fun `test NotInitializedException default message`() {
        val exception = NotInitializedException()
        assertTrue(exception.message!!.contains("not initialized"))
    }

    @Test
    fun `test NotInitializedException custom message`() {
        val exception = NotInitializedException("Custom message")
        assertEquals("Custom message", exception.message)
    }

    @Test
    fun `test InvalidParameterException`() {
        val exception = InvalidParameterException("Invalid size")
        assertEquals("Invalid size", exception.message)
    }

    @Test
    fun `test KazKemException toString`() {
        val exception = KazKemException(-1, "Test")
        val str = exception.toString()
        assertTrue(str.contains("-1"))
        assertTrue(str.contains("Test"))
    }

    @Test
    fun `test error code constants`() {
        assertEquals(0, KazKemException.ERROR_SUCCESS)
        assertEquals(-1, KazKemException.ERROR_INVALID_PARAM)
        assertEquals(-2, KazKemException.ERROR_MEMORY)
        assertEquals(-3, KazKemException.ERROR_RNG)
        assertEquals(-4, KazKemException.ERROR_OPENSSL)
        assertEquals(-5, KazKemException.ERROR_MSG_TOO_LARGE)
        assertEquals(-6, KazKemException.ERROR_NOT_INIT)
        assertEquals(-7, KazKemException.ERROR_INVALID_LEVEL)
    }
}
