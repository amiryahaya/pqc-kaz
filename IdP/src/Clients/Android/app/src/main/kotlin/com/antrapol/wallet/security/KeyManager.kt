package com.antrapol.wallet.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.antrapol.wallet.crypto.KazSignKeyPair
import com.antrapol.kaz.sign.SecurityLevel
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Secure key storage manager using Android Keystore and EncryptedSharedPreferences.
 *
 * ## Security Model
 * - Device secret key is encrypted using Android Keystore (hardware-backed when available)
 * - Certificates and metadata stored in EncryptedSharedPreferences
 * - User secret key is NOT stored locally - only server-side via Shamir shares
 */
@Singleton
class KeyManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS_DEVICE_KEY = "kaz_device_key_encryption"
        private const val PREFS_NAME = "kaz_secure_storage"

        private const val KEY_DEVICE_PUBLIC = "device_public_key"
        private const val KEY_DEVICE_SECRET_ENCRYPTED = "device_secret_key_encrypted"
        private const val KEY_DEVICE_SECRET_IV = "device_secret_key_iv"
        private const val KEY_DEVICE_CERTIFICATE = "device_certificate"
        private const val KEY_USER_CERTIFICATE = "user_certificate"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_SECURITY_LEVEL = "security_level"
        private const val KEY_IS_REGISTERED = "is_registered"

        private const val AES_GCM_TAG_LENGTH = 128
        private const val AES_GCM_IV_LENGTH = 12
    }

    private val masterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val encryptedPrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Check if user is registered and has keys stored.
     */
    val isRegistered: Boolean
        get() = encryptedPrefs.getBoolean(KEY_IS_REGISTERED, false)

    /**
     * Get stored user ID.
     */
    val userId: String?
        get() = encryptedPrefs.getString(KEY_USER_ID, null)

    /**
     * Store device keypair securely.
     * The secret key is encrypted using Android Keystore.
     */
    fun storeDeviceKey(keyPair: KazSignKeyPair) {
        // Ensure encryption key exists in Keystore
        val encryptionKey = getOrCreateEncryptionKey()

        // Encrypt the secret key
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey)

        val encryptedSecret = cipher.doFinal(keyPair.secretKey)
        val iv = cipher.iv

        // Store encrypted data
        encryptedPrefs.edit()
            .putString(KEY_DEVICE_PUBLIC, Base64.encodeToString(keyPair.publicKey, Base64.NO_WRAP))
            .putString(KEY_DEVICE_SECRET_ENCRYPTED, Base64.encodeToString(encryptedSecret, Base64.NO_WRAP))
            .putString(KEY_DEVICE_SECRET_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putInt(KEY_SECURITY_LEVEL, keyPair.level.value)
            .apply()
    }

    /**
     * Retrieve device keypair.
     */
    fun getDeviceKey(): KazSignKeyPair? {
        val publicKeyBase64 = encryptedPrefs.getString(KEY_DEVICE_PUBLIC, null) ?: return null
        val encryptedSecretBase64 = encryptedPrefs.getString(KEY_DEVICE_SECRET_ENCRYPTED, null) ?: return null
        val ivBase64 = encryptedPrefs.getString(KEY_DEVICE_SECRET_IV, null) ?: return null
        val levelValue = encryptedPrefs.getInt(KEY_SECURITY_LEVEL, 256)

        return try {
            val publicKey = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
            val encryptedSecret = Base64.decode(encryptedSecretBase64, Base64.NO_WRAP)
            val iv = Base64.decode(ivBase64, Base64.NO_WRAP)

            // Decrypt secret key using Keystore
            val encryptionKey = getOrCreateEncryptionKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, GCMParameterSpec(AES_GCM_TAG_LENGTH, iv))
            val secretKey = cipher.doFinal(encryptedSecret)

            val level = SecurityLevel.entries.find { it.value == levelValue } ?: SecurityLevel.LEVEL_256

            KazSignKeyPair(publicKey, secretKey, level)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Store device certificate PEM.
     */
    fun storeDeviceCertificate(certificatePem: String) {
        encryptedPrefs.edit()
            .putString(KEY_DEVICE_CERTIFICATE, certificatePem)
            .apply()
    }

    /**
     * Get device certificate PEM.
     */
    fun getDeviceCertificate(): String? {
        return encryptedPrefs.getString(KEY_DEVICE_CERTIFICATE, null)
    }

    /**
     * Store user certificate PEM.
     */
    fun storeUserCertificate(certificatePem: String) {
        encryptedPrefs.edit()
            .putString(KEY_USER_CERTIFICATE, certificatePem)
            .apply()
    }

    /**
     * Get user certificate PEM.
     */
    fun getUserCertificate(): String? {
        return encryptedPrefs.getString(KEY_USER_CERTIFICATE, null)
    }

    /**
     * Store user ID.
     */
    fun storeUserId(userId: String) {
        encryptedPrefs.edit()
            .putString(KEY_USER_ID, userId)
            .putBoolean(KEY_IS_REGISTERED, true)
            .apply()
    }

    /**
     * Clear all stored keys and data.
     * Call this during logout or account deletion.
     */
    fun clearAll() {
        encryptedPrefs.edit().clear().apply()

        // Remove Keystore key
        try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            keyStore.deleteEntry(KEY_ALIAS_DEVICE_KEY)
        } catch (e: Exception) {
            // Ignore errors during cleanup
        }
    }

    /**
     * Get or create encryption key in Android Keystore.
     */
    private fun getOrCreateEncryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        // Return existing key if available
        keyStore.getKey(KEY_ALIAS_DEVICE_KEY, null)?.let {
            return it as SecretKey
        }

        // Generate new key
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )

        val keySpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_DEVICE_KEY,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // Could enable for biometric
            .build()

        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }
}
