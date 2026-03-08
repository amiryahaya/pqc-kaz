package com.antrapol.kaz.kem

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Comprehensive instrumented tests for KAZ-KEM Android bindings.
 * These tests run on an Android device or emulator.
 */
@RunWith(AndroidJUnit4::class)
class KazKemInstrumentedTest {

    @Before
    fun setUp() {
        // Ensure clean state before each test
        KazKem.cleanup()
    }

    @After
    fun tearDown() {
        KazKem.cleanup()
    }

    // =========================================================================
    // Initialization Tests
    // =========================================================================

    @Test
    fun testInitializeLevel128() {
        val kem = KazKem.initialize(SecurityLevel.LEVEL_128)
        assertEquals(SecurityLevel.LEVEL_128, kem.securityLevel)
        assertTrue(KazKem.isInitialized)
    }

    @Test
    fun testInitializeLevel192() {
        val kem = KazKem.initialize(SecurityLevel.LEVEL_192)
        assertEquals(SecurityLevel.LEVEL_192, kem.securityLevel)
    }

    @Test
    fun testInitializeLevel256() {
        val kem = KazKem.initialize(SecurityLevel.LEVEL_256)
        assertEquals(SecurityLevel.LEVEL_256, kem.securityLevel)
    }

    @Test
    fun testVersion() {
        KazKem.initialize()
        val version = KazKem.version
        assertNotNull(version)
        assertTrue(version.contains("2.1"))
    }

    @Test
    fun testIsInitializedAfterCleanup() {
        KazKem.initialize()
        assertTrue(KazKem.isInitialized)
        KazKem.cleanup()
        assertFalse(KazKem.isInitialized)
    }

    @Test
    fun testReinitializeWithSameLevel() {
        val kem1 = KazKem.initialize(SecurityLevel.LEVEL_128)
        val kem2 = KazKem.initialize(SecurityLevel.LEVEL_128)
        assertSame(kem1, kem2)
    }

    @Test
    fun testReinitializeWithDifferentLevel() {
        val kem1 = KazKem.initialize(SecurityLevel.LEVEL_128)
        val kem2 = KazKem.initialize(SecurityLevel.LEVEL_256)
        assertNotSame(kem1, kem2)
        assertEquals(SecurityLevel.LEVEL_256, kem2.securityLevel)
    }

    // =========================================================================
    // Key Generation Tests
    // =========================================================================

    @Test
    fun testGenerateKeyPair() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        assertNotNull(keyPair)
        assertEquals(kem.publicKeySize, keyPair.publicKeySize)
        assertEquals(kem.privateKeySize, keyPair.privateKeySize)
        assertEquals(SecurityLevel.LEVEL_128, keyPair.securityLevel)
    }

    @Test
    fun testMultipleKeyPairsAreUnique() {
        val kem = KazKem.initialize()

        val keyPair1 = kem.generateKeyPair()
        val keyPair2 = kem.generateKeyPair()
        val keyPair3 = kem.generateKeyPair()

        assertFalse(keyPair1.publicKey.contentEquals(keyPair2.publicKey))
        assertFalse(keyPair2.publicKey.contentEquals(keyPair3.publicKey))
        assertFalse(keyPair1.privateKey.contentEquals(keyPair2.privateKey))
    }

    @Test
    fun testKeyPairGetPublicKey() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()
        val publicKey = keyPair.getPublicKey()

        assertTrue(publicKey.data.contentEquals(keyPair.publicKey))
        assertEquals(publicKey.securityLevel, keyPair.securityLevel)
    }

    @Test
    fun testCurrentGenerateKeyPair() {
        KazKem.initialize()
        val keyPair = KazKem.current.generateKeyPair()
        assertFalse(keyPair.publicKey.isEmpty())
    }

    // =========================================================================
    // Encapsulation/Decapsulation Tests
    // =========================================================================

    @Test
    fun testEncapsulateDecapsulate() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        val encResult = kem.encapsulate(keyPair.getPublicKey())
        val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, keyPair)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    @Test
    fun testEncapsulateWithPublicKeyData() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        val encResult = kem.encapsulate(keyPair.publicKey)
        val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, keyPair.privateKey)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    @Test
    fun testEncapsulateMultipleTimesProducesDifferentResults() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        val result1 = kem.encapsulate(keyPair.getPublicKey())
        val result2 = kem.encapsulate(keyPair.getPublicKey())

        assertFalse(result1.ciphertext.contentEquals(result2.ciphertext))
        assertFalse(result1.sharedSecret.contentEquals(result2.sharedSecret))
    }

    @Test
    fun testDecapsulateWithWrongKeyProducesDifferentSecret() {
        val kem = KazKem.initialize()
        val keyPair1 = kem.generateKeyPair()
        val keyPair2 = kem.generateKeyPair()

        val encResult = kem.encapsulate(keyPair1.getPublicKey())
        val wrongSecret = kem.decapsulate(encResult.ciphertext, keyPair2)

        assertFalse(encResult.sharedSecret.contentEquals(wrongSecret))
    }

    // =========================================================================
    // All Security Levels Tests
    // =========================================================================

    @Test
    fun testEncapsulateDecapsulateLevel192() {
        val kem = KazKem.initialize(SecurityLevel.LEVEL_192)
        val keyPair = kem.generateKeyPair()

        val encResult = kem.encapsulate(keyPair.getPublicKey())
        val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, keyPair)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    @Test
    fun testEncapsulateDecapsulateLevel256() {
        val kem = KazKem.initialize(SecurityLevel.LEVEL_256)
        val keyPair = kem.generateKeyPair()

        val encResult = kem.encapsulate(keyPair.getPublicKey())
        val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, keyPair)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    // =========================================================================
    // Error Handling Tests
    // =========================================================================

    @Test(expected = InvalidParameterException::class)
    fun testEncapsulateWithWrongSizePublicKey() {
        val kem = KazKem.initialize()
        val wrongSizeKey = ByteArray(16)
        kem.encapsulate(wrongSizeKey)
    }

    @Test(expected = InvalidParameterException::class)
    fun testDecapsulateWithWrongSizePrivateKey() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()
        val encResult = kem.encapsulate(keyPair.getPublicKey())
        val wrongSizeKey = ByteArray(16)

        kem.decapsulate(encResult.ciphertext, wrongSizeKey)
    }

    @Test(expected = InvalidParameterException::class)
    fun testDecapsulateWithEmptyCiphertext() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()
        kem.decapsulate(ByteArray(0), keyPair)
    }

    @Test(expected = InvalidParameterException::class)
    fun testDecapsulateWithOversizedCiphertext() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()
        val oversizedCiphertext = ByteArray(kem.ciphertextSize + 100)
        kem.decapsulate(oversizedCiphertext, keyPair)
    }

    @Test(expected = NotInitializedException::class)
    fun testCurrentThrowsWhenNotInitialized() {
        KazKem.cleanup()
        KazKem.current
    }

    @Test(expected = NotInitializedException::class)
    fun testGenerateKeyPairThrowsWhenNotInitialized() {
        KazKem.cleanup()
        KazKem.current.generateKeyPair()
    }

    // =========================================================================
    // Current Instance Method Tests
    // =========================================================================

    @Test
    fun testCurrentEncapsulateDecapsulate() {
        KazKem.initialize()
        val keyPair = KazKem.current.generateKeyPair()

        val encResult = KazKem.current.encapsulate(keyPair.getPublicKey())
        val decapsulatedSecret = KazKem.current.decapsulate(encResult.ciphertext, keyPair)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    // =========================================================================
    // Key Serialization Tests
    // =========================================================================

    @Test
    fun testKeyPairSerialization() {
        val kem = KazKem.initialize()
        val originalKeyPair = kem.generateKeyPair()

        // Export keys
        val publicKeyBase64 = originalKeyPair.publicKeyToBase64()
        val privateKeyBase64 = originalKeyPair.privateKeyToBase64()

        // Restore
        val restoredKeyPair = KazKemKeyPair.fromBase64(
            publicKeyBase64,
            privateKeyBase64,
            SecurityLevel.LEVEL_128
        )

        // Use restored keys
        val encResult = kem.encapsulate(restoredKeyPair.getPublicKey())
        val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, restoredKeyPair)

        assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
    }

    @Test
    fun testPublicKeySerialization() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        val base64 = keyPair.getPublicKey().toBase64()
        val restored = KazKemPublicKey.fromBase64(base64, SecurityLevel.LEVEL_128)

        assertTrue(keyPair.publicKey.contentEquals(restored.data))
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    @Test
    fun testFullKeyExchange() {
        // Alice generates key pair
        val alice = KazKem.initialize(SecurityLevel.LEVEL_128)
        val aliceKeyPair = alice.generateKeyPair()

        // Alice shares her public key with Bob
        val alicePublicKey = aliceKeyPair.getPublicKey()

        // Bob encapsulates a shared secret
        val bobEncapsulation = alice.encapsulate(alicePublicKey)
        val bobSecret = bobEncapsulation.sharedSecret

        // Bob sends ciphertext to Alice
        val ciphertext = bobEncapsulation.ciphertext

        // Alice decapsulates to get the shared secret
        val aliceSecret = alice.decapsulate(ciphertext, aliceKeyPair)

        // Both have the same shared secret
        assertTrue(aliceSecret.contentEquals(bobSecret))
    }

    @Test
    fun testLargeNumberOfOperations() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        repeat(100) {
            val encResult = kem.encapsulate(keyPair.getPublicKey())
            val decapsulatedSecret = kem.decapsulate(encResult.ciphertext, keyPair)
            assertTrue(encResult.sharedSecret.contentEquals(decapsulatedSecret))
        }
    }

    // =========================================================================
    // Thread Safety Tests
    // =========================================================================

    @Test
    fun testConcurrentEncapsulation() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()
        val publicKey = keyPair.getPublicKey()

        val threadCount = 10
        val operationsPerThread = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount * operationsPerThread)
        val successCount = AtomicInteger(0)
        val errorCount = AtomicInteger(0)

        repeat(threadCount) {
            executor.submit {
                repeat(operationsPerThread) {
                    try {
                        val result = kem.encapsulate(publicKey)
                        val secret = kem.decapsulate(result.ciphertext, keyPair)
                        if (result.sharedSecret.contentEquals(secret)) {
                            successCount.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errorCount.incrementAndGet()
                    } finally {
                        latch.countDown()
                    }
                }
            }
        }

        assertTrue(latch.await(60, TimeUnit.SECONDS))
        assertEquals(0, errorCount.get())
        assertEquals(threadCount * operationsPerThread, successCount.get())
        executor.shutdown()
    }

    @Test
    fun testConcurrentKeyGeneration() {
        val kem = KazKem.initialize()

        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)

        repeat(threadCount) {
            executor.submit {
                try {
                    val keyPair = kem.generateKeyPair()
                    if (keyPair.publicKey.isNotEmpty() && keyPair.privateKey.isNotEmpty()) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue(latch.await(60, TimeUnit.SECONDS))
        assertEquals(threadCount, successCount.get())
        executor.shutdown()
    }

    // =========================================================================
    // Security Tests
    // =========================================================================

    @Test
    fun testEncapsulationResultClear() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        val result = kem.encapsulate(keyPair.getPublicKey())
        val originalSecret = result.sharedSecret.copyOf()
        assertFalse(originalSecret.all { it == 0.toByte() })

        result.clear()

        // After clearing, internal shared secret should be zeroed
        assertTrue(result.sharedSecret.all { it == 0.toByte() })
    }

    @Test
    fun testKeyPairClear() {
        val kem = KazKem.initialize()
        val keyPair = kem.generateKeyPair()

        // Verify key is not all zeros
        assertFalse(keyPair.privateKey.all { it == 0.toByte() })

        keyPair.clear()

        // After clearing, private key access returns zeroed data
        assertTrue(keyPair.privateKey.all { it == 0.toByte() })
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    @Test
    fun testKeyPairFromRestoredKeys() {
        val kem = KazKem.initialize()
        val original = kem.generateKeyPair()

        // Restore keys from raw data
        val publicKey = KazKemPublicKey(original.publicKey, SecurityLevel.LEVEL_128)

        // Encapsulate with restored public key
        val result = kem.encapsulate(publicKey)

        // Decapsulate with original private key
        val secret = kem.decapsulate(result.ciphertext, original.privateKey)

        assertTrue(result.sharedSecret.contentEquals(secret))
    }

    @Test
    fun testKeySizesMatchSecurityLevel() {
        // Level 128
        var kem = KazKem.initialize(SecurityLevel.LEVEL_128)
        val size128Pk = kem.publicKeySize
        val size128Sk = kem.privateKeySize

        // Level 192
        kem = KazKem.initialize(SecurityLevel.LEVEL_192)
        val size192Pk = kem.publicKeySize
        val size192Sk = kem.privateKeySize

        // Level 256
        kem = KazKem.initialize(SecurityLevel.LEVEL_256)
        val size256Pk = kem.publicKeySize
        val size256Sk = kem.privateKeySize

        // Higher security levels should have larger keys
        assertTrue(size192Pk > size128Pk || size192Sk > size128Sk)
        assertTrue(size256Pk > size192Pk || size256Sk > size192Sk)
    }
}
