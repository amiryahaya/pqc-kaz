/*
 * KAZ-SIGN Android Wrapper
 * Performance Tests for KazSigner
 *
 * These tests measure performance on Android devices.
 */

package com.antrapol.kaz.sign

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import android.util.Log

/**
 * Performance tests for KazSigner.
 * These tests measure execution time on actual Android hardware.
 */
@RunWith(AndroidJUnit4::class)
class KazSignerPerformanceTest {

    companion object {
        private const val TAG = "KazSignPerf"
        private const val ITERATIONS = 20
        private const val WARMUP = 5
    }

    // ========================================================================
    // Key Generation Performance
    // ========================================================================

    @Test
    fun testKeyGenerationPerformance128() {
        measurePerformance("KeyGen-128", SecurityLevel.LEVEL_128) { signer ->
            signer.generateKeyPair()
        }
    }

    @Test
    fun testKeyGenerationPerformance192() {
        measurePerformance("KeyGen-192", SecurityLevel.LEVEL_192) { signer ->
            signer.generateKeyPair()
        }
    }

    @Test
    fun testKeyGenerationPerformance256() {
        measurePerformance("KeyGen-256", SecurityLevel.LEVEL_256) { signer ->
            signer.generateKeyPair()
        }
    }

    // ========================================================================
    // Signing Performance
    // ========================================================================

    @Test
    fun testSigningPerformance128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for signing performance".toByteArray()

        measurePerformance("Sign-128") {
            signer.sign(message, keyPair.secretKey)
        }

        signer.close()
    }

    @Test
    fun testSigningPerformance192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for signing performance".toByteArray()

        measurePerformance("Sign-192") {
            signer.sign(message, keyPair.secretKey)
        }

        signer.close()
    }

    @Test
    fun testSigningPerformance256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for signing performance".toByteArray()

        measurePerformance("Sign-256") {
            signer.sign(message, keyPair.secretKey)
        }

        signer.close()
    }

    // ========================================================================
    // Verification Performance
    // ========================================================================

    @Test
    fun testVerificationPerformance128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for verification performance".toByteArray()
        val signResult = signer.sign(message, keyPair.secretKey)

        measurePerformance("Verify-128") {
            signer.verify(signResult.signature, keyPair.publicKey)
        }

        signer.close()
    }

    @Test
    fun testVerificationPerformance192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for verification performance".toByteArray()
        val signResult = signer.sign(message, keyPair.secretKey)

        measurePerformance("Verify-192") {
            signer.verify(signResult.signature, keyPair.publicKey)
        }

        signer.close()
    }

    @Test
    fun testVerificationPerformance256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val keyPair = signer.generateKeyPair()
        val message = "Test message for verification performance".toByteArray()
        val signResult = signer.sign(message, keyPair.secretKey)

        measurePerformance("Verify-256") {
            signer.verify(signResult.signature, keyPair.publicKey)
        }

        signer.close()
    }

    // ========================================================================
    // Hashing Performance
    // ========================================================================

    @Test
    fun testHashingPerformance128() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val message = "Test message for hashing performance".toByteArray()

        measurePerformance("Hash-128") {
            signer.hash(message)
        }

        signer.close()
    }

    @Test
    fun testHashingPerformance192() {
        val signer = KazSigner(SecurityLevel.LEVEL_192)
        val message = "Test message for hashing performance".toByteArray()

        measurePerformance("Hash-192") {
            signer.hash(message)
        }

        signer.close()
    }

    @Test
    fun testHashingPerformance256() {
        val signer = KazSigner(SecurityLevel.LEVEL_256)
        val message = "Test message for hashing performance".toByteArray()

        measurePerformance("Hash-256") {
            signer.hash(message)
        }

        signer.close()
    }

    // ========================================================================
    // Large Message Performance
    // ========================================================================

    @Test
    fun testLargeMessagePerformance() {
        val signer = KazSigner(SecurityLevel.LEVEL_128)
        val keyPair = signer.generateKeyPair()

        val sizes = listOf(100, 1000, 10000, 100000)

        for (size in sizes) {
            val message = ByteArray(size) { it.toByte() }

            val signTime = measureTimeMillis {
                signer.sign(message, keyPair.secretKey)
            }

            val signResult = signer.sign(message, keyPair.secretKey)
            val verifyTime = measureTimeMillis {
                signer.verify(signResult.signature, keyPair.publicKey)
            }

            Log.d(TAG, "Message size $size: Sign=${signTime}ms, Verify=${verifyTime}ms")
        }

        signer.close()
    }

    // ========================================================================
    // Full Cycle Performance
    // ========================================================================

    @Test
    fun testFullCyclePerformance() {
        for (level in SecurityLevel.entries) {
            val signer = KazSigner(level)
            val message = "Full cycle test message".toByteArray()

            // Warmup
            repeat(WARMUP) {
                val kp = signer.generateKeyPair()
                val sig = signer.sign(message, kp.secretKey)
                signer.verify(sig.signature, kp.publicKey)
            }

            val times = mutableListOf<Long>()

            repeat(ITERATIONS) {
                val start = System.nanoTime()

                val kp = signer.generateKeyPair()
                val sig = signer.sign(message, kp.secretKey)
                val result = signer.verify(sig.signature, kp.publicKey)
                assertTrue(result.isValid)

                val elapsed = (System.nanoTime() - start) / 1_000_000L
                times.add(elapsed)
            }

            val avg = times.average()
            val min = times.minOrNull()
            val max = times.maxOrNull()

            Log.d(TAG, "Full cycle ${level.algorithmName}: avg=${avg.toLong()}ms, min=${min}ms, max=${max}ms")

            signer.close()
        }
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    private inline fun measurePerformance(
        name: String,
        level: SecurityLevel,
        operation: (KazSigner) -> Unit
    ) {
        val signer = KazSigner(level)

        // Warmup
        repeat(WARMUP) {
            operation(signer)
        }

        val times = mutableListOf<Long>()

        repeat(ITERATIONS) {
            val start = System.nanoTime()
            operation(signer)
            val elapsed = (System.nanoTime() - start) / 1_000_000L
            times.add(elapsed)
        }

        val avg = times.average()
        val min = times.minOrNull()
        val max = times.maxOrNull()

        Log.d(TAG, "$name: avg=${avg.toLong()}ms, min=${min}ms, max=${max}ms")

        signer.close()
    }

    private inline fun measurePerformance(name: String, operation: () -> Unit) {
        // Warmup
        repeat(WARMUP) {
            operation()
        }

        val times = mutableListOf<Long>()

        repeat(ITERATIONS) {
            val start = System.nanoTime()
            operation()
            val elapsed = (System.nanoTime() - start) / 1_000_000L
            times.add(elapsed)
        }

        val avg = times.average()
        val min = times.minOrNull()
        val max = times.maxOrNull()

        Log.d(TAG, "$name: avg=${avg.toLong()}ms, min=${min}ms, max=${max}ms")
    }

    private inline fun measureTimeMillis(block: () -> Unit): Long {
        val start = System.nanoTime()
        block()
        return (System.nanoTime() - start) / 1_000_000L
    }
}
