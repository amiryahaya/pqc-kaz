package com.antrapol.wallet.crypto

import java.security.SecureRandom

/**
 * Shamir's Secret Sharing implementation for secure key recovery.
 *
 * Splits a secret into N shares where any K shares can reconstruct the original.
 * Uses GF(256) (Galois Field) for byte-level operations.
 *
 * ## Usage
 * ```kotlin
 * val sss = ShamirSecretSharing()
 *
 * // Split secret into 5 shares, requiring 3 to recover
 * val shares = sss.split(secretKey, threshold = 3, totalShares = 5)
 *
 * // Later, recover with any 3 shares
 * val recovered = sss.combine(listOf(shares[0], shares[2], shares[4]))
 * ```
 */
class ShamirSecretSharing(
    private val random: SecureRandom = SecureRandom()
) {
    /**
     * Represents a single share with its index (x-coordinate).
     *
     * @property index Share index (1-based, 1-255)
     * @property data Share data bytes (same length as original secret)
     */
    data class Share(
        val index: Int,
        val data: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Share
            return index == other.index && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = index
            result = 31 * result + data.contentHashCode()
            return result
        }

        /**
         * Serialize share to bytes: [index (1 byte)][data length (4 bytes)][data]
         */
        fun toBytes(): ByteArray {
            val result = ByteArray(5 + data.size)
            result[0] = index.toByte()
            result[1] = (data.size shr 24).toByte()
            result[2] = (data.size shr 16).toByte()
            result[3] = (data.size shr 8).toByte()
            result[4] = data.size.toByte()
            data.copyInto(result, 5)
            return result
        }

        companion object {
            /**
             * Deserialize share from bytes.
             */
            fun fromBytes(bytes: ByteArray): Share {
                require(bytes.size >= 5) { "Share bytes too short" }
                val index = bytes[0].toInt() and 0xFF
                val length = ((bytes[1].toInt() and 0xFF) shl 24) or
                        ((bytes[2].toInt() and 0xFF) shl 16) or
                        ((bytes[3].toInt() and 0xFF) shl 8) or
                        (bytes[4].toInt() and 0xFF)
                require(bytes.size == 5 + length) { "Share bytes length mismatch" }
                val data = bytes.copyOfRange(5, 5 + length)
                return Share(index, data)
            }
        }
    }

    /**
     * Split a secret into multiple shares.
     *
     * @param secret The secret to split
     * @param threshold Minimum shares required to reconstruct (K)
     * @param totalShares Total number of shares to generate (N)
     * @return List of shares
     * @throws IllegalArgumentException if parameters are invalid
     */
    fun split(secret: ByteArray, threshold: Int, totalShares: Int): List<Share> {
        require(threshold >= 2) { "Threshold must be at least 2" }
        require(totalShares >= threshold) { "Total shares must be >= threshold" }
        require(totalShares <= 255) { "Total shares must be <= 255" }
        require(secret.isNotEmpty()) { "Secret cannot be empty" }

        val shares = Array(totalShares) { ByteArray(secret.size) }

        // Process each byte of the secret independently
        for (byteIndex in secret.indices) {
            // Generate random polynomial coefficients
            // f(x) = secret[byteIndex] + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
            val coefficients = ByteArray(threshold)
            coefficients[0] = secret[byteIndex] // constant term is the secret byte
            random.nextBytes(coefficients) // generate random coefficients
            coefficients[0] = secret[byteIndex] // restore constant term after randomization

            // Evaluate polynomial at points 1, 2, ..., totalShares
            for (shareIndex in 0 until totalShares) {
                val x = shareIndex + 1 // x-coordinate (1-based)
                shares[shareIndex][byteIndex] = evaluatePolynomial(coefficients, x)
            }
        }

        return shares.mapIndexed { index, data -> Share(index + 1, data) }
    }

    /**
     * Combine shares to reconstruct the secret.
     *
     * @param shares List of shares (must have at least threshold shares)
     * @return The reconstructed secret
     * @throws IllegalArgumentException if shares are invalid
     */
    fun combine(shares: List<Share>): ByteArray {
        require(shares.isNotEmpty()) { "No shares provided" }
        require(shares.map { it.index }.toSet().size == shares.size) { "Duplicate share indices" }

        val secretLength = shares[0].data.size
        require(shares.all { it.data.size == secretLength }) { "Share data lengths must match" }

        val result = ByteArray(secretLength)
        val xCoords = shares.map { it.index }

        // Reconstruct each byte using Lagrange interpolation
        for (byteIndex in 0 until secretLength) {
            val yCoords = shares.map { (it.data[byteIndex].toInt() and 0xFF) }
            result[byteIndex] = lagrangeInterpolate(xCoords, yCoords, 0)
        }

        return result
    }

    /**
     * Evaluate polynomial at point x using Horner's method in GF(256).
     */
    private fun evaluatePolynomial(coefficients: ByteArray, x: Int): Byte {
        // Horner's method: f(x) = c0 + x*(c1 + x*(c2 + ...))
        var result = 0
        for (i in coefficients.indices.reversed()) {
            val coeff = coefficients[i].toInt() and 0xFF
            result = gfAdd(coeff, gfMul(result, x))
        }
        return result.toByte()
    }

    /**
     * Lagrange interpolation to find f(0) in GF(256).
     */
    private fun lagrangeInterpolate(xCoords: List<Int>, yCoords: List<Int>, targetX: Int): Byte {
        var result = 0

        for (i in xCoords.indices) {
            var term = yCoords[i]

            for (j in xCoords.indices) {
                if (i != j) {
                    // term *= (targetX - xCoords[j]) / (xCoords[i] - xCoords[j])
                    val numerator = gfSub(targetX, xCoords[j])
                    val denominator = gfSub(xCoords[i], xCoords[j])
                    term = gfMul(term, gfMul(numerator, gfInverse(denominator)))
                }
            }

            result = gfAdd(result, term)
        }

        return result.toByte()
    }

    companion object {
        // GF(256) operations using AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
        private const val GF_PRIMITIVE = 0x11B

        // Precomputed log and exp tables for GF(256)
        private val GF_EXP = IntArray(512)
        private val GF_LOG = IntArray(256)

        init {
            // Generate exp and log tables
            var x = 1
            for (i in 0 until 255) {
                GF_EXP[i] = x
                GF_LOG[x] = i
                x = x shl 1
                if (x >= 256) {
                    x = x xor GF_PRIMITIVE
                }
            }
            // Extend exp table for easier modular arithmetic
            for (i in 255 until 512) {
                GF_EXP[i] = GF_EXP[i - 255]
            }
            GF_LOG[0] = 0 // Convention: log(0) = 0 (though mathematically undefined)
        }

        /**
         * GF(256) addition (XOR).
         */
        private fun gfAdd(a: Int, b: Int): Int = a xor b

        /**
         * GF(256) subtraction (same as addition in GF(2^n)).
         */
        private fun gfSub(a: Int, b: Int): Int = a xor b

        /**
         * GF(256) multiplication using log/exp tables.
         */
        private fun gfMul(a: Int, b: Int): Int {
            if (a == 0 || b == 0) return 0
            return GF_EXP[GF_LOG[a] + GF_LOG[b]]
        }

        /**
         * GF(256) multiplicative inverse using log/exp tables.
         */
        private fun gfInverse(a: Int): Int {
            require(a != 0) { "Cannot compute inverse of 0 in GF(256)" }
            return GF_EXP[255 - GF_LOG[a]]
        }
    }
}

/**
 * Encrypted share ready for storage/transmission.
 *
 * @property index Share index (1-based)
 * @property encryptedData Encrypted share data
 * @property ciphertext KEM ciphertext for key recovery
 */
data class EncryptedShare(
    val index: Int,
    val encryptedData: ByteArray,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as EncryptedShare
        return index == other.index &&
                encryptedData.contentEquals(other.encryptedData) &&
                ciphertext.contentEquals(other.ciphertext)
    }

    override fun hashCode(): Int {
        var result = index
        result = 31 * result + encryptedData.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        return result
    }
}
