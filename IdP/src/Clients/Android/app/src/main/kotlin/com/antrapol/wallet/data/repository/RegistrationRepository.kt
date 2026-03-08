package com.antrapol.wallet.data.repository

import android.util.Base64
import com.antrapol.wallet.crypto.*
import com.antrapol.wallet.data.api.PqcIdentityApi
import com.antrapol.wallet.data.models.*
import com.antrapol.wallet.security.KeyManager
import com.antrapol.kaz.kem.SecurityLevel as KemSecurityLevel
import com.antrapol.kaz.sign.SecurityLevel as SignSecurityLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Registration state during the multi-step process.
 */
data class RegistrationState(
    val registrationId: String? = null,
    val fullName: String = "",
    val myKadNumber: String = "",
    val email: String = "",
    val phoneNumber: String = "",
    val status: RegistrationStatus = RegistrationStatus.PENDING,
    val deviceKeyPair: KazSignKeyPair? = null,
    val userKeyPair: KazSignKeyPair? = null,
    val deviceCsr: String? = null,
    val userCsr: String? = null,
    val deviceCertificate: CertificateDto? = null,
    val userCertificate: CertificateDto? = null,
    val recoveryToken: RecoveryTokenDto? = null,
    val userId: String? = null
)

enum class RegistrationStatus {
    PENDING,
    EMAIL_OTP_SENT,
    EMAIL_VERIFIED,
    PHONE_OTP_SENT,
    PHONE_VERIFIED,
    KEYS_GENERATED,
    CSR_SUBMITTED,
    CERTIFICATES_ISSUED,
    COMPLETED,
    FAILED
}

/**
 * Repository for registration workflow orchestration.
 */
@Singleton
class RegistrationRepository @Inject constructor(
    private val api: PqcIdentityApi,
    private val keyManager: KeyManager
) {
    private val signProvider = KazSignCryptoProvider(SignSecurityLevel.LEVEL_256)
    private val kemProvider = KazKemCryptoProvider(KemSecurityLevel.LEVEL_256)
    private val csrBuilder = CsrBuilder(signProvider)
    private val shamirSecretSharing = ShamirSecretSharing()
    private val secureRandom = SecureRandom()

    /**
     * Step 1: Initiate registration with user profile.
     */
    suspend fun initiateRegistration(
        fullName: String,
        myKadNumber: String,
        email: String,
        phoneNumber: String,
        deviceId: String,
        deviceName: String,
        deviceOsVersion: String,
        appVersion: String
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val request = InitiateRegistrationRequest(
                fullName = fullName,
                myKadNumber = myKadNumber,
                email = email,
                phoneNumber = phoneNumber,
                deviceId = deviceId,
                deviceName = deviceName,
                deviceOsVersion = deviceOsVersion,
                appVersion = appVersion
            )

            val response = api.initiateRegistration(request)

            if (response.success && response.data != null) {
                Result.success(
                    RegistrationState(
                        registrationId = response.data.registrationId,
                        fullName = fullName,
                        myKadNumber = myKadNumber,
                        email = email,
                        phoneNumber = phoneNumber,
                        status = RegistrationStatus.EMAIL_OTP_SENT
                    )
                )
            } else {
                Result.failure(
                    RegistrationException(
                        response.error?.message ?: "Registration initiation failed"
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Network error: ${e.message}", e))
        }
    }

    /**
     * Step 2: Verify email OTP.
     */
    suspend fun verifyEmailOtp(
        state: RegistrationState,
        otp: String
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))

            val response = api.verifyEmailOtp(registrationId, VerifyOtpRequest(otp))

            if (response.success) {
                Result.success(state.copy(status = RegistrationStatus.EMAIL_VERIFIED))
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "Email OTP verification failed")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Network error: ${e.message}", e))
        }
    }

    /**
     * Step 3: Request phone OTP.
     */
    suspend fun sendPhoneOtp(
        state: RegistrationState
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))

            val response = api.sendPhoneOtp(registrationId)

            if (response.success) {
                Result.success(state.copy(status = RegistrationStatus.PHONE_OTP_SENT))
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "Failed to send phone OTP")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Network error: ${e.message}", e))
        }
    }

    /**
     * Step 4: Verify phone OTP.
     */
    suspend fun verifyPhoneOtp(
        state: RegistrationState,
        otp: String
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))

            val response = api.verifyPhoneOtp(registrationId, VerifyOtpRequest(otp))

            if (response.success) {
                Result.success(state.copy(status = RegistrationStatus.PHONE_VERIFIED))
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "Phone OTP verification failed")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Network error: ${e.message}", e))
        }
    }

    /**
     * Step 5: Generate keypairs and CSRs.
     */
    suspend fun generateKeysAndCsrs(
        state: RegistrationState
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            // Generate device keypair
            val deviceKeyPair = signProvider.generateKeyPair()

            // Generate user keypair
            val userKeyPair = signProvider.generateKeyPair()

            // Build device CSR
            val deviceCsr = csrBuilder.buildCsrPem(
                commonName = "${state.fullName} (Device)",
                serialNumber = state.myKadNumber,
                country = "MY",
                organization = null,
                keyPair = deviceKeyPair
            )

            // Build user CSR
            val userCsr = csrBuilder.buildCsrPem(
                commonName = state.fullName,
                serialNumber = state.myKadNumber,
                country = "MY",
                organization = null,
                keyPair = userKeyPair
            )

            Result.success(
                state.copy(
                    deviceKeyPair = deviceKeyPair,
                    userKeyPair = userKeyPair,
                    deviceCsr = deviceCsr,
                    userCsr = userCsr,
                    status = RegistrationStatus.KEYS_GENERATED
                )
            )
        } catch (e: Exception) {
            Result.failure(RegistrationException("Key generation failed: ${e.message}", e))
        }
    }

    /**
     * Step 6: Submit CSRs and encrypted key shares.
     */
    suspend fun submitCsrAndShares(
        state: RegistrationState,
        controlPublicKey: ByteArray,
        recoveryPublicKey: ByteArray
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))
            val deviceCsr = state.deviceCsr
                ?: return@withContext Result.failure(RegistrationException("No device CSR"))
            val userCsr = state.userCsr
                ?: return@withContext Result.failure(RegistrationException("No user CSR"))
            val userKeyPair = state.userKeyPair
                ?: return@withContext Result.failure(RegistrationException("No user keypair"))
            val deviceKeyPair = state.deviceKeyPair
                ?: return@withContext Result.failure(RegistrationException("No device keypair"))

            // Split user secret key into 2 shares (2-of-2 threshold)
            val shares = shamirSecretSharing.split(
                secret = userKeyPair.secretKey,
                threshold = 2,
                totalShares = 2
            )

            // Encrypt share for control server
            val encryptedPartControl = encryptShare(shares[0], controlPublicKey)

            // Encrypt share for recovery server
            val encryptedPartRecovery = encryptShare(shares[1], recoveryPublicKey)

            // Sign the payload with device key
            val payloadToSign = buildString {
                append(deviceCsr)
                append(userCsr)
                append(encryptedPartControl.encryptedData)
                append(encryptedPartRecovery.encryptedData)
            }.toByteArray()

            val signature = signProvider.sign(deviceKeyPair.secretKey, payloadToSign)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val request = SubmitCsrRequest(
                deviceCsr = deviceCsr,
                userCsr = userCsr,
                encryptedPartControl = encryptedPartControl,
                encryptedPartRecovery = encryptedPartRecovery,
                payloadSignature = signatureBase64
            )

            val response = api.submitCsr(registrationId, request)

            if (response.success) {
                Result.success(state.copy(status = RegistrationStatus.CSR_SUBMITTED))
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "CSR submission failed")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("CSR submission failed: ${e.message}", e))
        }
    }

    /**
     * Step 7: Download issued certificates.
     */
    suspend fun downloadCertificates(
        state: RegistrationState
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))

            val response = api.getCertificates(registrationId)

            if (response.success && response.data != null) {
                Result.success(
                    state.copy(
                        deviceCertificate = response.data.deviceCertificate,
                        userCertificate = response.data.userCertificate,
                        status = RegistrationStatus.CERTIFICATES_ISSUED
                    )
                )
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "Certificate download failed")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Network error: ${e.message}", e))
        }
    }

    /**
     * Step 8: Complete registration and store keys.
     */
    suspend fun completeRegistration(
        state: RegistrationState
    ): Result<RegistrationState> = withContext(Dispatchers.IO) {
        try {
            val registrationId = state.registrationId
                ?: return@withContext Result.failure(RegistrationException("No registration ID"))
            val deviceKeyPair = state.deviceKeyPair
                ?: return@withContext Result.failure(RegistrationException("No device keypair"))
            val deviceCertificate = state.deviceCertificate
                ?: return@withContext Result.failure(RegistrationException("No device certificate"))
            val userCertificate = state.userCertificate
                ?: return@withContext Result.failure(RegistrationException("No user certificate"))

            val response = api.completeRegistration(registrationId)

            if (response.success && response.data != null) {
                // Store keys and certificates securely
                keyManager.storeDeviceKey(deviceKeyPair)
                keyManager.storeDeviceCertificate(deviceCertificate.certificatePem)
                keyManager.storeUserCertificate(userCertificate.certificatePem)
                keyManager.storeUserId(response.data.userId)

                Result.success(
                    state.copy(
                        userId = response.data.userId,
                        recoveryToken = response.data.recoveryToken,
                        status = RegistrationStatus.COMPLETED
                    )
                )
            } else {
                Result.failure(
                    RegistrationException(response.error?.message ?: "Registration completion failed")
                )
            }
        } catch (e: Exception) {
            Result.failure(RegistrationException("Registration completion failed: ${e.message}", e))
        }
    }

    /**
     * Encrypt a share using KAZ-KEM for hybrid encryption.
     * Uses KEM to establish shared secret, then AES-GCM for encryption.
     */
    private fun encryptShare(
        share: ShamirSecretSharing.Share,
        recipientPublicKey: ByteArray
    ): EncryptedShareDto {
        // Encapsulate to get shared secret
        val encapResult = kemProvider.encapsulate(recipientPublicKey)

        // Generate nonce for AES-GCM
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        // Derive AES key from shared secret (first 32 bytes)
        val aesKey = encapResult.sharedSecret.copyOf(32)
        val keySpec = SecretKeySpec(aesKey, "AES")

        // Encrypt share data with AES-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
        val encryptedData = cipher.doFinal(share.toBytes())

        // Clear sensitive data
        encapResult.clear()
        aesKey.fill(0)

        return EncryptedShareDto(
            encryptedData = Base64.encodeToString(encryptedData, Base64.NO_WRAP),
            encapsulatedKey = Base64.encodeToString(encapResult.ciphertext, Base64.NO_WRAP),
            nonce = Base64.encodeToString(nonce, Base64.NO_WRAP)
        )
    }
}

class RegistrationException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
