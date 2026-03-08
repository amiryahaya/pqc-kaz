package com.antrapol.wallet.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// Malaysian flag inspired colors
private val MalaysianBlue = Color(0xFF010066)
private val MalaysianRed = Color(0xFFCC0001)
private val MalaysianYellow = Color(0xFFFFCC00)
private val MalaysianWhite = Color(0xFFFFFFFF)

private val DarkColorScheme = darkColorScheme(
    primary = MalaysianBlue,
    secondary = MalaysianYellow,
    tertiary = MalaysianRed,
    background = Color(0xFF121212),
    surface = Color(0xFF1E1E1E),
    onPrimary = MalaysianWhite,
    onSecondary = Color.Black,
    onTertiary = MalaysianWhite,
    onBackground = MalaysianWhite,
    onSurface = MalaysianWhite
)

private val LightColorScheme = lightColorScheme(
    primary = MalaysianBlue,
    secondary = MalaysianYellow,
    tertiary = MalaysianRed,
    background = Color(0xFFFFFBFE),
    surface = MalaysianWhite,
    onPrimary = MalaysianWhite,
    onSecondary = Color.Black,
    onTertiary = MalaysianWhite,
    onBackground = Color(0xFF1C1B1F),
    onSurface = Color(0xFF1C1B1F)
)

/**
 * PQC Identity app theme.
 * Uses Malaysian flag-inspired colors.
 */
@Composable
fun PqcIdentityTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
