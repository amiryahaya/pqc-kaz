package com.antrapol.wallet.ui.screens.recovery

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp

/**
 * Account recovery screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecoveryScreen(
    onNavigateBack: () -> Unit,
    onRecoveryComplete: () -> Unit
) {
    var email by remember { mutableStateOf("") }
    var recoveryToken by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var recoveryStep by remember { mutableStateOf(RecoveryStep.ENTER_TOKEN) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Account Recovery") },
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
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            when (recoveryStep) {
                RecoveryStep.ENTER_TOKEN -> {
                    Text(
                        text = "Enter Recovery Information",
                        style = MaterialTheme.typography.headlineSmall
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Text(
                        text = "Enter your registered email and the recovery token you saved during registration.",
                        style = MaterialTheme.typography.bodyMedium
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    OutlinedTextField(
                        value = email,
                        onValueChange = { email = it; error = null },
                        label = { Text("Email Address") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    OutlinedTextField(
                        value = recoveryToken,
                        onValueChange = { recoveryToken = it; error = null },
                        label = { Text("Recovery Token") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        minLines = 3,
                        maxLines = 5
                    )

                    error?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Button(
                        onClick = {
                            isLoading = true
                            // TODO: Call recovery API
                            // For now, simulate and move to next step
                            recoveryStep = RecoveryStep.REGENERATE_KEYS
                            isLoading = false
                        },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading && email.isNotBlank() && recoveryToken.isNotBlank()
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                        } else {
                            Text("Verify Recovery Token")
                        }
                    }
                }

                RecoveryStep.REGENERATE_KEYS -> {
                    Text(
                        text = "Regenerate Keys",
                        style = MaterialTheme.typography.headlineSmall
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Text(
                        text = "Your recovery token has been verified. " +
                                "Now we'll generate new cryptographic keys for this device.",
                        style = MaterialTheme.typography.bodyMedium
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    if (isLoading) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Generating new keys...")
                    } else {
                        Button(
                            onClick = {
                                isLoading = true
                                // TODO: Generate keys, submit CSR, complete recovery
                                // For now, simulate
                                recoveryStep = RecoveryStep.COMPLETE
                                isLoading = false
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Generate New Keys")
                        }
                    }
                }

                RecoveryStep.COMPLETE -> {
                    Text(
                        text = "Recovery Complete!",
                        style = MaterialTheme.typography.headlineSmall
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Text(
                        text = "Your account has been recovered on this device. " +
                                "Your previous device has been deauthorized.",
                        style = MaterialTheme.typography.bodyMedium
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Important: Save Your New Recovery Token",
                                style = MaterialTheme.typography.titleSmall
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "A new recovery token has been generated. " +
                                        "Make sure to save it securely.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Button(
                        onClick = onRecoveryComplete,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Continue")
                    }
                }
            }
        }
    }
}

private enum class RecoveryStep {
    ENTER_TOKEN,
    REGENERATE_KEYS,
    COMPLETE
}
