package com.antrapol.wallet.ui.screens.registration

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.antrapol.wallet.BuildConfig
import com.antrapol.wallet.data.repository.RegistrationRepository
import com.antrapol.wallet.data.repository.RegistrationState
import com.antrapol.wallet.data.repository.RegistrationStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * UI state for registration screen.
 */
data class RegistrationUiState(
    val currentStep: RegistrationStep = RegistrationStep.PROFILE,
    val isLoading: Boolean = false,
    val error: String? = null,

    // Profile fields
    val fullName: String = "",
    val myKadNumber: String = "",
    val email: String = "",
    val phoneNumber: String = "",

    // OTP fields
    val emailOtp: String = "",
    val phoneOtp: String = "",

    // Registration state
    val registrationId: String? = null,

    // Key generation
    val keyGenerationProgress: Float = 0f,

    // Recovery token
    val recoveryToken: String = "",
    val recoveryMnemonic: String? = null,
    val hasSavedRecoveryToken: Boolean = false,

    // User ID after completion
    val userId: String? = null
)

/**
 * ViewModel for the registration flow.
 */
@HiltViewModel
class RegistrationViewModel @Inject constructor(
    private val registrationRepository: RegistrationRepository,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegistrationUiState())
    val uiState: StateFlow<RegistrationUiState> = _uiState.asStateFlow()

    // Internal state for repository
    private var registrationState = RegistrationState()

    // Device info
    private val deviceId: String by lazy {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    }

    private val deviceName: String by lazy {
        "${Build.MANUFACTURER} ${Build.MODEL}"
    }

    private val deviceOsVersion: String by lazy {
        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
    }

    private val appVersion: String by lazy {
        BuildConfig.VERSION_NAME
    }

    // Profile updates
    fun updateFullName(value: String) {
        _uiState.update { it.copy(fullName = value, error = null) }
    }

    fun updateMyKadNumber(value: String) {
        _uiState.update { it.copy(myKadNumber = value, error = null) }
    }

    fun updateEmail(value: String) {
        _uiState.update { it.copy(email = value, error = null) }
    }

    fun updatePhoneNumber(value: String) {
        _uiState.update { it.copy(phoneNumber = value, error = null) }
    }

    // OTP updates
    fun updateEmailOtp(value: String) {
        _uiState.update { it.copy(emailOtp = value, error = null) }
    }

    fun updatePhoneOtp(value: String) {
        _uiState.update { it.copy(phoneOtp = value, error = null) }
    }

    /**
     * Step 1: Initiate registration with user profile.
     */
    fun initiateRegistration() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }

            try {
                // Validate MyKad format
                val myKad = _uiState.value.myKadNumber
                if (!isValidMyKad(myKad)) {
                    _uiState.update { it.copy(isLoading = false, error = "Invalid MyKad number format") }
                    return@launch
                }

                // Validate email format
                val email = _uiState.value.email
                if (!isValidEmail(email)) {
                    _uiState.update { it.copy(isLoading = false, error = "Invalid email format") }
                    return@launch
                }

                val result = registrationRepository.initiateRegistration(
                    fullName = _uiState.value.fullName,
                    myKadNumber = myKad,
                    email = email,
                    phoneNumber = _uiState.value.phoneNumber,
                    deviceId = deviceId,
                    deviceName = deviceName,
                    deviceOsVersion = deviceOsVersion,
                    appVersion = appVersion
                )

                result.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                registrationId = state.registrationId,
                                currentStep = RegistrationStep.EMAIL_OTP
                            )
                        }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(isLoading = false, error = error.message ?: "Registration failed")
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, error = e.message ?: "Registration failed")
                }
            }
        }
    }

    /**
     * Step 2: Verify email OTP.
     */
    fun verifyEmailOtp() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }

            try {
                val otp = _uiState.value.emailOtp

                val result = registrationRepository.verifyEmailOtp(registrationState, otp)

                result.fold(
                    onSuccess = { state ->
                        registrationState = state
                        // Request phone OTP
                        sendPhoneOtpInternal()
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(isLoading = false, error = error.message ?: "Verification failed")
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, error = e.message ?: "Verification failed")
                }
            }
        }
    }

    private suspend fun sendPhoneOtpInternal() {
        val result = registrationRepository.sendPhoneOtp(registrationState)

        result.fold(
            onSuccess = { state ->
                registrationState = state
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        currentStep = RegistrationStep.PHONE_OTP
                    )
                }
            },
            onFailure = { error ->
                _uiState.update {
                    it.copy(isLoading = false, error = error.message ?: "Failed to send phone OTP")
                }
            }
        )
    }

    fun resendEmailOtp() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            try {
                // Re-initiate to resend email OTP
                val result = registrationRepository.initiateRegistration(
                    fullName = _uiState.value.fullName,
                    myKadNumber = _uiState.value.myKadNumber,
                    email = _uiState.value.email,
                    phoneNumber = _uiState.value.phoneNumber,
                    deviceId = deviceId,
                    deviceName = deviceName,
                    deviceOsVersion = deviceOsVersion,
                    appVersion = appVersion
                )

                result.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update {
                            it.copy(isLoading = false, registrationId = state.registrationId)
                        }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(isLoading = false, error = error.message ?: "Failed to resend OTP")
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, error = e.message ?: "Failed to resend OTP")
                }
            }
        }
    }

    /**
     * Step 4: Verify phone OTP.
     */
    fun verifyPhoneOtp() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }

            try {
                val otp = _uiState.value.phoneOtp

                val result = registrationRepository.verifyPhoneOtp(registrationState, otp)

                result.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                currentStep = RegistrationStep.KEY_GENERATION
                            )
                        }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(isLoading = false, error = error.message ?: "Verification failed")
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, error = e.message ?: "Verification failed")
                }
            }
        }
    }

    fun resendPhoneOtp() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            try {
                val result = registrationRepository.sendPhoneOtp(registrationState)

                result.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update { it.copy(isLoading = false) }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(isLoading = false, error = error.message ?: "Failed to resend OTP")
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, error = e.message ?: "Failed to resend OTP")
                }
            }
        }
    }

    /**
     * Step 5: Generate keys and submit CSR.
     */
    fun generateKeysAndSubmitCsr() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null, keyGenerationProgress = 0f) }

            try {
                // Step 5.1: Generate keypairs and CSRs
                _uiState.update { it.copy(keyGenerationProgress = 0.1f) }
                val keysResult = registrationRepository.generateKeysAndCsrs(registrationState)

                keysResult.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update { it.copy(keyGenerationProgress = 0.4f) }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                keyGenerationProgress = 0f,
                                error = error.message ?: "Key generation failed"
                            )
                        }
                        return@launch
                    }
                )

                // Step 5.2: Submit CSRs with encrypted key shares
                // TODO: Get actual server public keys from configuration or API
                // For now, using placeholder - these should come from server configuration
                _uiState.update { it.copy(keyGenerationProgress = 0.6f) }

                val controlPublicKey = getControlServerPublicKey()
                val recoveryPublicKey = getRecoveryServerPublicKey()

                val submitResult = registrationRepository.submitCsrAndShares(
                    registrationState,
                    controlPublicKey,
                    recoveryPublicKey
                )

                submitResult.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update { it.copy(keyGenerationProgress = 0.8f) }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                keyGenerationProgress = 0f,
                                error = error.message ?: "CSR submission failed"
                            )
                        }
                        return@launch
                    }
                )

                // Step 5.3: Download certificates
                _uiState.update { it.copy(keyGenerationProgress = 0.9f) }

                val certsResult = registrationRepository.downloadCertificates(registrationState)

                certsResult.fold(
                    onSuccess = { state ->
                        registrationState = state
                        _uiState.update { it.copy(keyGenerationProgress = 1f) }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                keyGenerationProgress = 0f,
                                error = error.message ?: "Certificate download failed"
                            )
                        }
                        return@launch
                    }
                )

                // Step 5.4: Complete registration
                val completeResult = registrationRepository.completeRegistration(registrationState)

                completeResult.fold(
                    onSuccess = { state ->
                        registrationState = state

                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                keyGenerationProgress = 1f,
                                recoveryToken = state.recoveryToken?.token ?: "",
                                recoveryMnemonic = state.recoveryToken?.mnemonic,
                                userId = state.userId,
                                currentStep = RegistrationStep.RECOVERY_SETUP
                            )
                        }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                keyGenerationProgress = 0f,
                                error = error.message ?: "Registration completion failed"
                            )
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        keyGenerationProgress = 0f,
                        error = e.message ?: "Key generation failed"
                    )
                }
            }
        }
    }

    /**
     * Step 6: Confirm recovery token has been saved.
     */
    fun confirmRecoveryTokenSaved() {
        _uiState.update {
            it.copy(
                hasSavedRecoveryToken = true,
                currentStep = RegistrationStep.COMPLETE
            )
        }
    }

    fun copyRecoveryToken() {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val token = _uiState.value.recoveryMnemonic ?: _uiState.value.recoveryToken
        val clip = ClipData.newPlainText("Recovery Token", token)
        clipboard.setPrimaryClip(clip)
    }

    /**
     * Get control server's public key for encrypting key shares.
     * TODO: This should be fetched from server configuration or embedded as a constant.
     */
    private fun getControlServerPublicKey(): ByteArray {
        // Placeholder - in production, this would be fetched from server or configuration
        // The control server's KEM public key for encrypting the user's key share
        return ByteArray(32) // Placeholder size
    }

    /**
     * Get recovery server's public key for encrypting key shares.
     * TODO: This should be fetched from server configuration or embedded as a constant.
     */
    private fun getRecoveryServerPublicKey(): ByteArray {
        // Placeholder - in production, this would be fetched from server or configuration
        // The recovery server's KEM public key for encrypting the user's key share
        return ByteArray(32) // Placeholder size
    }

    private fun isValidMyKad(myKad: String): Boolean {
        // Malaysian MyKad is 12 digits
        if (myKad.length != 12) return false
        if (!myKad.all { it.isDigit() }) return false

        // First 6 digits are birth date (YYMMDD)
        val month = myKad.substring(2, 4).toIntOrNull() ?: return false
        val day = myKad.substring(4, 6).toIntOrNull() ?: return false

        if (month < 1 || month > 12) return false
        if (day < 1 || day > 31) return false

        return true
    }

    private fun isValidEmail(email: String): Boolean {
        return android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }
}
