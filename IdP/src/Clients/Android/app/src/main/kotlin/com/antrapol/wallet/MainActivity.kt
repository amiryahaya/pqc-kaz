package com.antrapol.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dagger.hilt.android.AndroidEntryPoint
import com.antrapol.wallet.ui.navigation.PqcNavHost
import com.antrapol.wallet.ui.theme.PqcIdentityTheme

/**
 * Main Activity - entry point for the app.
 * Uses Jetpack Compose for the UI.
 */
@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PqcIdentityTheme {
                PqcNavHost()
            }
        }
    }
}
