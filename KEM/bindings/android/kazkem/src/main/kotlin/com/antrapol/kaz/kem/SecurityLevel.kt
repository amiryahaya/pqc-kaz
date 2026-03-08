package com.antrapol.kaz.kem

/**
 * Security levels supported by KAZ-KEM.
 *
 * Each level corresponds to a NIST security level:
 * - [LEVEL_128]: NIST Level 1 (128-bit security)
 * - [LEVEL_192]: NIST Level 3 (192-bit security)
 * - [LEVEL_256]: NIST Level 5 (256-bit security)
 */
enum class SecurityLevel(val value: Int) {
    /**
     * 128-bit security level (NIST Level 1).
     * Provides security roughly equivalent to AES-128.
     * Fastest performance, suitable for most applications.
     */
    LEVEL_128(128),

    /**
     * 192-bit security level (NIST Level 3).
     * Provides security roughly equivalent to AES-192.
     * Balanced security and performance.
     */
    LEVEL_192(192),

    /**
     * 256-bit security level (NIST Level 5).
     * Provides security roughly equivalent to AES-256.
     * Highest security, suitable for long-term protection.
     */
    LEVEL_256(256);

    /**
     * Mask for random value generation to ensure message < N.
     */
    internal val randomMask: Byte
        get() = when (this) {
            LEVEL_128 -> 0x7F.toByte()  // Clear top bit
            LEVEL_192 -> 0x3F.toByte()  // Clear top 2 bits
            LEVEL_256 -> 0x1F.toByte()  // Clear top 3 bits
        }

    companion object {
        /**
         * Get security level from integer value.
         *
         * @param value Integer value (128, 192, or 256)
         * @return Corresponding [SecurityLevel]
         * @throws IllegalArgumentException if value is not valid
         */
        @JvmStatic
        fun fromValue(value: Int): SecurityLevel {
            return entries.find { it.value == value }
                ?: throw IllegalArgumentException("Invalid security level: $value. Must be 128, 192, or 256.")
        }
    }
}
