package com.antrapol.wallet.ui.screens.registration

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * Registration steps for the multi-step registration flow.
 */
enum class RegistrationStep {
    PROFILE,         // Step 1: Enter profile info
    EMAIL_OTP,       // Step 2: Verify email OTP
    PHONE_OTP,       // Step 3-4: Request and verify phone OTP
    KEY_GENERATION,  // Step 5: Generate keys and submit CSR
    RECOVERY_SETUP,  // Step 6: Show recovery token
    COMPLETE         // Step 7: Done
}

/**
 * Main registration screen with multi-step flow.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RegistrationScreen(
    onNavigateBack: () -> Unit,
    onRegistrationComplete: () -> Unit,
    viewModel: RegistrationViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Register") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Progress indicator
            LinearProgressIndicator(
                progress = { (uiState.currentStep.ordinal + 1f) / RegistrationStep.entries.size },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 24.dp)
            )

            when (uiState.currentStep) {
                RegistrationStep.PROFILE -> ProfileStep(
                    fullName = uiState.fullName,
                    onFullNameChange = viewModel::updateFullName,
                    myKadNumber = uiState.myKadNumber,
                    onMyKadChange = viewModel::updateMyKadNumber,
                    email = uiState.email,
                    onEmailChange = viewModel::updateEmail,
                    phoneNumber = uiState.phoneNumber,
                    onPhoneChange = viewModel::updatePhoneNumber,
                    isLoading = uiState.isLoading,
                    error = uiState.error,
                    onSubmit = viewModel::initiateRegistration
                )

                RegistrationStep.EMAIL_OTP -> OtpStep(
                    title = "Email Verification",
                    description = "Enter the 6-digit code sent to ${uiState.email}",
                    otp = uiState.emailOtp,
                    onOtpChange = viewModel::updateEmailOtp,
                    isLoading = uiState.isLoading,
                    error = uiState.error,
                    onSubmit = viewModel::verifyEmailOtp,
                    onResend = viewModel::resendEmailOtp
                )

                RegistrationStep.PHONE_OTP -> OtpStep(
                    title = "Phone Verification",
                    description = "Enter the 6-digit code sent to ${uiState.phoneNumber}",
                    otp = uiState.phoneOtp,
                    onOtpChange = viewModel::updatePhoneOtp,
                    isLoading = uiState.isLoading,
                    error = uiState.error,
                    onSubmit = viewModel::verifyPhoneOtp,
                    onResend = viewModel::resendPhoneOtp
                )

                RegistrationStep.KEY_GENERATION -> KeyGenerationStep(
                    isLoading = uiState.isLoading,
                    error = uiState.error,
                    progress = uiState.keyGenerationProgress,
                    onGenerate = viewModel::generateKeysAndSubmitCsr
                )

                RegistrationStep.RECOVERY_SETUP -> RecoverySetupStep(
                    recoveryToken = uiState.recoveryToken,
                    recoveryMnemonic = uiState.recoveryMnemonic,
                    hasSavedToken = uiState.hasSavedRecoveryToken,
                    onConfirmSaved = viewModel::confirmRecoveryTokenSaved,
                    onCopyToken = viewModel::copyRecoveryToken
                )

                RegistrationStep.COMPLETE -> CompletionStep(
                    onComplete = onRegistrationComplete
                )
            }
        }
    }
}

@Composable
private fun ProfileStep(
    fullName: String,
    onFullNameChange: (String) -> Unit,
    myKadNumber: String,
    onMyKadChange: (String) -> Unit,
    email: String,
    onEmailChange: (String) -> Unit,
    phoneNumber: String,
    onPhoneChange: (String) -> Unit,
    isLoading: Boolean,
    error: String?,
    onSubmit: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Enter Your Details",
            style = MaterialTheme.typography.headlineSmall
        )

        OutlinedTextField(
            value = fullName,
            onValueChange = onFullNameChange,
            label = { Text("Full Name (as per MyKad)") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true
        )

        OutlinedTextField(
            value = myKadNumber,
            onValueChange = { if (it.length <= 12 && it.all { c -> c.isDigit() }) onMyKadChange(it) },
            label = { Text("MyKad Number") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            placeholder = { Text("123456789012") }
        )

        OutlinedTextField(
            value = email,
            onValueChange = onEmailChange,
            label = { Text("Email Address") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
        )

        OutlinedTextField(
            value = phoneNumber,
            onValueChange = { if (it.all { c -> c.isDigit() || c == '+' }) onPhoneChange(it) },
            label = { Text("Phone Number") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
            placeholder = { Text("+60123456789") }
        )

        error?.let {
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Button(
            onClick = onSubmit,
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading && fullName.isNotBlank() && myKadNumber.length == 12
                    && email.isNotBlank() && phoneNumber.isNotBlank()
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text("Continue")
            }
        }
    }
}

@Composable
private fun OtpStep(
    title: String,
    description: String,
    otp: String,
    onOtpChange: (String) -> Unit,
    isLoading: Boolean,
    error: String?,
    onSubmit: () -> Unit,
    onResend: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.headlineSmall
        )

        Text(
            text = description,
            style = MaterialTheme.typography.bodyMedium
        )

        OutlinedTextField(
            value = otp,
            onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) onOtpChange(it) },
            label = { Text("Verification Code") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            textStyle = MaterialTheme.typography.headlineMedium
        )

        error?.let {
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Button(
            onClick = onSubmit,
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading && otp.length == 6
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text("Verify")
            }
        }

        TextButton(onClick = onResend, enabled = !isLoading) {
            Text("Resend Code")
        }
    }
}

@Composable
private fun KeyGenerationStep(
    isLoading: Boolean,
    error: String?,
    progress: Float,
    onGenerate: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Key Generation",
            style = MaterialTheme.typography.headlineSmall
        )

        Text(
            text = "Your device will now generate secure post-quantum cryptographic keys. " +
                    "This may take a moment.",
            style = MaterialTheme.typography.bodyMedium
        )

        if (isLoading) {
            Spacer(modifier = Modifier.height(24.dp))
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth()
            )
            Text(
                text = "${(progress * 100).toInt()}%",
                style = MaterialTheme.typography.bodySmall
            )
        }

        error?.let {
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        if (!isLoading) {
            Button(
                onClick = onGenerate,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Generate Keys")
            }
        }
    }
}

@Composable
private fun RecoverySetupStep(
    recoveryToken: String,
    recoveryMnemonic: String?,
    hasSavedToken: Boolean,
    onConfirmSaved: () -> Unit,
    onCopyToken: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Save Your Recovery Token",
            style = MaterialTheme.typography.headlineSmall
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "IMPORTANT: Save this token securely!",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "This is your ONLY way to recover your account if you lose your device. " +
                            "Write it down and store it in a safe place. Do NOT store it digitally.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
        }

        recoveryMnemonic?.let { mnemonic ->
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Recovery Words:",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = mnemonic,
                        style = MaterialTheme.typography.bodyLarge
                    )
                }
            }
        }

        OutlinedButton(
            onClick = onCopyToken,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Copy Token")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onConfirmSaved,
            modifier = Modifier.fillMaxWidth(),
            enabled = !hasSavedToken
        ) {
            Text(if (hasSavedToken) "Saved" else "I Have Saved My Recovery Token")
        }
    }
}

@Composable
private fun CompletionStep(
    onComplete: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Registration Complete!",
            style = MaterialTheme.typography.headlineMedium
        )

        Text(
            text = "Your PQC Identity has been created successfully. " +
                    "You can now use biometric authentication to sign in.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(horizontal = 16.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onComplete,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Get Started")
        }
    }
}
