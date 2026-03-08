package com.antrapol.wallet.data.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Generic API response wrapper.
 */
@Serializable
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: ApiError? = null
)

@Serializable
data class ApiError(
    val code: String,
    val message: String
)

// ============================================
// Registration Models
// ============================================

@Serializable
data class InitiateRegistrationRequest(
    @SerialName("fullName") val fullName: String,
    @SerialName("myKadNumber") val myKadNumber: String,
    @SerialName("email") val email: String,
    @SerialName("phoneNumber") val phoneNumber: String,
    @SerialName("deviceId") val deviceId: String,
    @SerialName("deviceName") val deviceName: String,
    @SerialName("devicePlatform") val devicePlatform: String = "Android",
    @SerialName("deviceOsVersion") val deviceOsVersion: String,
    @SerialName("appVersion") val appVersion: String
)

@Serializable
data class VerifyOtpRequest(
    @SerialName("otp") val otp: String
)

@Serializable
data class SubmitCsrRequest(
    @SerialName("deviceCsr") val deviceCsr: String,
    @SerialName("userCsr") val userCsr: String,
    @SerialName("encryptedPartControl") val encryptedPartControl: EncryptedShareDto,
    @SerialName("encryptedPartRecovery") val encryptedPartRecovery: EncryptedShareDto,
    @SerialName("payloadSignature") val payloadSignature: String
)

@Serializable
data class EncryptedShareDto(
    @SerialName("encryptedData") val encryptedData: String, // Base64
    @SerialName("encapsulatedKey") val encapsulatedKey: String, // Base64
    @SerialName("nonce") val nonce: String // Base64
)

@Serializable
data class RegistrationStatusResponse(
    @SerialName("registrationId") val registrationId: String,
    @SerialName("status") val status: String,
    @SerialName("fullName") val fullName: String,
    @SerialName("email") val email: String,
    @SerialName("phoneNumber") val phoneNumber: String,
    @SerialName("createdAt") val createdAt: String,
    @SerialName("expiresAt") val expiresAt: String
)

@Serializable
data class OtpSentResponse(
    @SerialName("message") val message: String,
    @SerialName("expiresInSeconds") val expiresInSeconds: Int
)

@Serializable
data class CsrSubmissionResponse(
    @SerialName("registrationId") val registrationId: String,
    @SerialName("status") val status: String,
    @SerialName("message") val message: String
)

@Serializable
data class CertificatesResponse(
    @SerialName("deviceCertificate") val deviceCertificate: CertificateDto,
    @SerialName("userCertificate") val userCertificate: CertificateDto
)

@Serializable
data class CertificateDto(
    @SerialName("certificateId") val certificateId: String,
    @SerialName("serialNumber") val serialNumber: String,
    @SerialName("subjectDn") val subjectDn: String,
    @SerialName("issuerDn") val issuerDn: String,
    @SerialName("notBefore") val notBefore: String,
    @SerialName("notAfter") val notAfter: String,
    @SerialName("certificatePem") val certificatePem: String,
    @SerialName("publicKeyFingerprint") val publicKeyFingerprint: String
)

@Serializable
data class CompletionResponse(
    @SerialName("userId") val userId: String,
    @SerialName("message") val message: String,
    @SerialName("recoveryToken") val recoveryToken: RecoveryTokenDto
)

@Serializable
data class RecoveryTokenDto(
    @SerialName("token") val token: String,
    @SerialName("mnemonic") val mnemonic: String?,
    @SerialName("tokenVersion") val tokenVersion: Int
)

// ============================================
// Recovery Models
// ============================================

@Serializable
data class RecoveryInitiationRequest(
    @SerialName("recoveryToken") val recoveryToken: String,
    @SerialName("email") val email: String,
    @SerialName("newDeviceId") val newDeviceId: String,
    @SerialName("newDeviceName") val newDeviceName: String,
    @SerialName("newDevicePlatform") val newDevicePlatform: String = "Android"
)

@Serializable
data class RecoverySessionResponse(
    @SerialName("recoverySessionId") val recoverySessionId: String,
    @SerialName("userId") val userId: String,
    @SerialName("encryptedPartRecovery") val encryptedPartRecovery: String, // Base64
    @SerialName("expiresAt") val expiresAt: String
)

@Serializable
data class RecoveryCompletionRequest(
    @SerialName("recoverySessionId") val recoverySessionId: String,
    @SerialName("newDeviceCsr") val newDeviceCsr: String,
    @SerialName("newUserCsr") val newUserCsr: String,
    @SerialName("newEncryptedPartControl") val newEncryptedPartControl: String, // Base64
    @SerialName("newEncryptedPartRecovery") val newEncryptedPartRecovery: String // Base64
)

@Serializable
data class RecoveryCompletionResponse(
    @SerialName("userId") val userId: String,
    @SerialName("newDeviceCertificatePem") val newDeviceCertificatePem: String,
    @SerialName("newUserCertificatePem") val newUserCertificatePem: String,
    @SerialName("newRecoveryToken") val newRecoveryToken: RecoveryTokenDto
)

// ============================================
// Authentication Models
// ============================================

@Serializable
data class AuthenticationRequest(
    @SerialName("deviceCertificateFingerprint") val deviceCertificateFingerprint: String,
    @SerialName("challenge") val challenge: String,
    @SerialName("signature") val signature: String // Base64
)

@Serializable
data class RefreshTokenRequest(
    @SerialName("refreshToken") val refreshToken: String
)

@Serializable
data class AuthenticationResponse(
    @SerialName("accessToken") val accessToken: String,
    @SerialName("refreshToken") val refreshToken: String,
    @SerialName("expiresIn") val expiresIn: Long,
    @SerialName("tokenType") val tokenType: String = "Bearer"
)
