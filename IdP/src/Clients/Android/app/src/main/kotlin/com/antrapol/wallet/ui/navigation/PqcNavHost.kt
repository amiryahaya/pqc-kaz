package com.antrapol.wallet.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.antrapol.wallet.ui.screens.home.HomeScreen
import com.antrapol.wallet.ui.screens.login.LoginScreen
import com.antrapol.wallet.ui.screens.registration.RegistrationScreen
import com.antrapol.wallet.ui.screens.recovery.RecoveryScreen

/**
 * Navigation routes for the app.
 */
object Routes {
    const val LOGIN = "login"
    const val REGISTRATION = "registration"
    const val HOME = "home"
    const val RECOVERY = "recovery"
    const val SETTINGS = "settings"
}

/**
 * Main navigation host for the app.
 */
@Composable
fun PqcNavHost(
    navController: NavHostController = rememberNavController(),
    startDestination: String = Routes.LOGIN
) {
    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        composable(Routes.LOGIN) {
            LoginScreen(
                onNavigateToRegistration = {
                    navController.navigate(Routes.REGISTRATION)
                },
                onNavigateToHome = {
                    navController.navigate(Routes.HOME) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                },
                onNavigateToRecovery = {
                    navController.navigate(Routes.RECOVERY)
                }
            )
        }

        composable(Routes.REGISTRATION) {
            RegistrationScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onRegistrationComplete = {
                    navController.navigate(Routes.HOME) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                }
            )
        }

        composable(Routes.HOME) {
            HomeScreen(
                onNavigateToSettings = {
                    navController.navigate(Routes.SETTINGS)
                }
            )
        }

        composable(Routes.RECOVERY) {
            RecoveryScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onRecoveryComplete = {
                    navController.navigate(Routes.HOME) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                }
            )
        }
    }
}
