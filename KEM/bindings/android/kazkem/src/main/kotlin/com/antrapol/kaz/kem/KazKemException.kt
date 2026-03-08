package com.antrapol.kaz.kem

/**
 * Exception thrown by KAZ-KEM operations.
 *
 * @property errorCode Native error code
 * @property message Human-readable error message
 */
class KazKemException(
    val errorCode: Int,
    override val message: String
) : Exception(message) {

    companion object {
        // Error codes
        const val ERROR_SUCCESS = 0
        const val ERROR_INVALID_PARAM = -1
        const val ERROR_MEMORY = -2
        const val ERROR_RNG = -3
        const val ERROR_OPENSSL = -4
        const val ERROR_MSG_TOO_LARGE = -5
        const val ERROR_NOT_INIT = -6
        const val ERROR_INVALID_LEVEL = -7

        /**
         * Create exception from error code with descriptive message.
         */
        @JvmStatic
        fun fromErrorCode(errorCode: Int, operation: String = "Operation"): KazKemException {
            val description = when (errorCode) {
                ERROR_INVALID_PARAM -> "Invalid parameter"
                ERROR_MEMORY -> "Memory allocation failed"
                ERROR_RNG -> "Random number generation failed"
                ERROR_OPENSSL -> "OpenSSL error"
                ERROR_MSG_TOO_LARGE -> "Message too large"
                ERROR_NOT_INIT -> "KAZ-KEM not initialized"
                ERROR_INVALID_LEVEL -> "Invalid security level"
                else -> "Unknown error"
            }
            return KazKemException(errorCode, "$operation failed: $description (code: $errorCode)")
        }
    }

    /**
     * Check if this is a specific error type.
     */
    fun isNotInitialized(): Boolean = errorCode == ERROR_NOT_INIT
    fun isInvalidParameter(): Boolean = errorCode == ERROR_INVALID_PARAM
    fun isMemoryError(): Boolean = errorCode == ERROR_MEMORY
    fun isRngError(): Boolean = errorCode == ERROR_RNG

    override fun toString(): String = "KazKemException(code=$errorCode, message=$message)"
}

/**
 * Exception thrown when KAZ-KEM is not initialized.
 */
class NotInitializedException(message: String = "KAZ-KEM is not initialized. Call KazKem.initialize() first.") :
    Exception(message)

/**
 * Exception thrown for invalid parameter errors.
 */
class InvalidParameterException(message: String) : Exception(message)
