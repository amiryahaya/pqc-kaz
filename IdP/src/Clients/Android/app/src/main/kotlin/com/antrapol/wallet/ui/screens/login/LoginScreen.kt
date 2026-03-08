package com.antrapol.wallet.ui.screens.login

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * Login screen with biometric authentication.
 */
@Composable
fun LoginScreen(
    onNavigateToRegistration: () -> Unit,
    onNavigateToHome: () -> Unit,
    onNavigateToRecovery: () -> Unit
) {
    var isAuthenticating by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "PQC Identity",
            style = MaterialTheme.typography.displaySmall,
            color = MaterialTheme.colorScheme.primary
        )

        Text(
            text = "Malaysia Digital ID",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(48.dp))

        // TODO: Check if user is registered
        val isRegistered = false

        if (isRegistered) {
            Button(
                onClick = {
                    isAuthenticating = true
                    // TODO: Trigger biometric authentication
                    // On success, navigate to home
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = !isAuthenticating
            ) {
                if (isAuthenticating) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Sign In with Biometrics")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(onClick = onNavigateToRecovery) {
                Text("Account Recovery")
            }
        } else {
            Text(
                text = "Welcome! To get started, please register your digital identity.",
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 16.dp)
            )

            Spacer(modifier = Modifier.height(32.dp))

            Button(
                onClick = onNavigateToRegistration,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Register Now")
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(onClick = onNavigateToRecovery) {
                Text("Recover Existing Account")
            }
        }
    }
}
