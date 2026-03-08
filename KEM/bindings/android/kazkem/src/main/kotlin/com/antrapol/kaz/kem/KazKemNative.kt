package com.antrapol.kaz.kem

/**
 * JNI bindings for the native KAZ-KEM library.
 * This class provides low-level access to the native functions.
 * Use [KazKem] for a higher-level, safer API.
 */
internal object KazKemNative {

    init {
        System.loadLibrary("kazkem")
    }

    // Initialization
    @JvmStatic
    external fun nativeInit(level: Int): Int

    @JvmStatic
    external fun nativeIsInitialized(): Boolean

    @JvmStatic
    external fun nativeGetLevel(): Int

    @JvmStatic
    external fun nativeCleanup()

    // Size functions
    @JvmStatic
    external fun nativePublicKeyBytes(): Int

    @JvmStatic
    external fun nativePrivateKeyBytes(): Int

    @JvmStatic
    external fun nativeCiphertextBytes(): Int

    @JvmStatic
    external fun nativeSharedSecretBytes(): Int

    // Key generation
    @JvmStatic
    @Throws(KazKemException::class)
    external fun nativeKeyPair(): Array<ByteArray>

    // Encapsulation
    @JvmStatic
    @Throws(KazKemException::class)
    external fun nativeEncapsulate(sharedSecret: ByteArray, publicKey: ByteArray): Array<ByteArray>

    // Decapsulation
    @JvmStatic
    @Throws(KazKemException::class)
    external fun nativeDecapsulate(ciphertext: ByteArray, privateKey: ByteArray): ByteArray

    // Version
    @JvmStatic
    external fun nativeVersion(): String
}
