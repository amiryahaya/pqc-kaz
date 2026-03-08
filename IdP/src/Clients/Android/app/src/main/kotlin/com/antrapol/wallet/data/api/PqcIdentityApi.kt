package com.antrapol.wallet.data.api

import com.antrapol.wallet.data.models.*
import retrofit2.http.*

/**
 * Retrofit API interface for PQC Identity Backend.
 */
interface PqcIdentityApi {

    // ============================================
    // Registration Endpoints
    // ============================================

    /**
     * Step 1: Initiate registration with user profile.
     */
    @POST("api/v1/registration/initiate")
    suspend fun initiateRegistration(
        @Body request: InitiateRegistrationRequest
    ): ApiResponse<RegistrationStatusResponse>

    /**
     * Step 2: Verify email OTP.
     */
    @POST("api/v1/registration/{registrationId}/verify-email")
    suspend fun verifyEmailOtp(
        @Path("registrationId") registrationId: String,
        @Body request: VerifyOtpRequest
    ): ApiResponse<RegistrationStatusResponse>

    /**
     * Step 3: Request phone OTP.
     */
    @POST("api/v1/registration/{registrationId}/send-phone-otp")
    suspend fun sendPhoneOtp(
        @Path("registrationId") registrationId: String
    ): ApiResponse<OtpSentResponse>

    /**
     * Step 4: Verify phone OTP.
     */
    @POST("api/v1/registration/{registrationId}/verify-phone")
    suspend fun verifyPhoneOtp(
        @Path("registrationId") registrationId: String,
        @Body request: VerifyOtpRequest
    ): ApiResponse<RegistrationStatusResponse>

    /**
     * Step 5: Submit CSRs and encrypted key shares.
     */
    @POST("api/v1/registration/{registrationId}/submit-csr")
    suspend fun submitCsr(
        @Path("registrationId") registrationId: String,
        @Body request: SubmitCsrRequest
    ): ApiResponse<CsrSubmissionResponse>

    /**
     * Step 6: Download issued certificates.
     */
    @GET("api/v1/registration/{registrationId}/certificates")
    suspend fun getCertificates(
        @Path("registrationId") registrationId: String
    ): ApiResponse<CertificatesResponse>

    /**
     * Step 7: Complete registration.
     */
    @POST("api/v1/registration/{registrationId}/complete")
    suspend fun completeRegistration(
        @Path("registrationId") registrationId: String
    ): ApiResponse<CompletionResponse>

    /**
     * Get registration status.
     */
    @GET("api/v1/registration/{registrationId}/status")
    suspend fun getRegistrationStatus(
        @Path("registrationId") registrationId: String
    ): ApiResponse<RegistrationStatusResponse>

    // ============================================
    // Recovery Endpoints
    // ============================================

    /**
     * Initiate account recovery.
     */
    @POST("api/v1/recovery/initiate")
    suspend fun initiateRecovery(
        @Body request: RecoveryInitiationRequest
    ): ApiResponse<RecoverySessionResponse>

    /**
     * Complete account recovery.
     */
    @POST("api/v1/recovery/complete")
    suspend fun completeRecovery(
        @Body request: RecoveryCompletionRequest
    ): ApiResponse<RecoveryCompletionResponse>

    // ============================================
    // Authentication Endpoints
    // ============================================

    /**
     * Authenticate with device certificate.
     */
    @POST("api/v1/auth/authenticate")
    suspend fun authenticate(
        @Body request: AuthenticationRequest
    ): ApiResponse<AuthenticationResponse>

    /**
     * Refresh access token.
     */
    @POST("api/v1/auth/refresh")
    suspend fun refreshToken(
        @Body request: RefreshTokenRequest
    ): ApiResponse<AuthenticationResponse>
}
