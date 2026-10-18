// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.csqtt.client.ui.design.CsqttMaterialShapes

val CSQTTTypography =
    Typography(
        displayLarge =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Bold,
                fontSize = 57.sp,
                lineHeight = 64.sp,
            ),
        displayMedium =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Bold,
                fontSize = 45.sp,
                lineHeight = 52.sp,
            ),
        displaySmall =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Bold,
                fontSize = 36.sp,
                lineHeight = 44.sp,
            ),
        headlineLarge =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                fontSize = 32.sp,
                lineHeight = 40.sp,
            ),
        headlineMedium =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                fontSize = 28.sp,
                lineHeight = 36.sp,
            ),
        headlineSmall =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                fontSize = 24.sp,
                lineHeight = 32.sp,
            ),
        titleLarge =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                fontSize = 22.sp,
                lineHeight = 28.sp,
            ),
        titleMedium =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                fontSize = 16.sp,
                lineHeight = 24.sp,
                letterSpacing = 0.15.sp,
            ),
        titleSmall =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                lineHeight = 20.sp,
                letterSpacing = 0.1.sp,
            ),
        bodyLarge =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Normal,
                fontSize = 16.sp,
                lineHeight = 24.sp,
                letterSpacing = 0.5.sp,
            ),
        bodyMedium =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Normal,
                fontSize = 14.sp,
                lineHeight = 20.sp,
                letterSpacing = 0.25.sp,
            ),
        bodySmall =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Normal,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                letterSpacing = 0.4.sp,
            ),
        labelLarge =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                lineHeight = 20.sp,
                letterSpacing = 0.1.sp,
            ),
        labelMedium =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Medium,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                letterSpacing = 0.5.sp,
            ),
        labelSmall =
            TextStyle(
                fontFamily = FontFamily.Default,
                fontWeight = FontWeight.Medium,
                fontSize = 11.sp,
                lineHeight = 16.sp,
                letterSpacing = 0.5.sp,
            ),
    )

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF6D4C41),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD7CCC8),
    onPrimaryContainer = Color(0xFF3E2723),
    secondary = Color(0xFF8D6E63),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFEFEBE9),
    onSecondaryContainer = Color(0xFF4E342E),
    tertiary = Color(0xFF795548),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFBCAAA4),
    onTertiaryContainer = Color(0xFF3E2723),
    background = Color(0xFFF2F0EC),
    onBackground = Color(0xFF1C1B1A),
    surface = Color(0xFFFAF8F4),
    onSurface = Color(0xFF1C1B1A),
    surfaceVariant = Color(0xFFEFEBE9),
    onSurfaceVariant = Color(0xFF5D4037),
    outline = Color(0xFFBCAAA4),
    outlineVariant = Color(0xFFD7CCC8),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    inverseSurface = Color(0xFF322F2D),
    inverseOnSurface = Color(0xFFF5F0EB),
    inversePrimary = Color(0xFFD7CCC8),
    surfaceTint = Color(0xFF6D4C41),
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFFD7CCC8),
    onPrimary = Color(0xFF3E2723),
    primaryContainer = Color(0xFF5D4037),
    onPrimaryContainer = Color(0xFFEFEBE9),
    secondary = Color(0xFFBCAAA4),
    onSecondary = Color(0xFF3E2723),
    secondaryContainer = Color(0xFF4E342E),
    onSecondaryContainer = Color(0xFFEFEBE9),
    tertiary = Color(0xFFA1887F),
    onTertiary = Color(0xFF3E2723),
    tertiaryContainer = Color(0xFF5D4037),
    onTertiaryContainer = Color(0xFFEFEBE9),
    background = Color(0xFF1A1614),
    onBackground = Color(0xFFEDE0D4),
    surface = Color(0xFF211D1B),
    onSurface = Color(0xFFEDE0D4),
    surfaceVariant = Color(0xFF2C2624),
    onSurfaceVariant = Color(0xFFD7CCC8),
    outline = Color(0xFF8D6E63),
    outlineVariant = Color(0xFF4E342E),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    inverseSurface = Color(0xFFEDE0D4),
    inverseOnSurface = Color(0xFF322F2D),
    inversePrimary = Color(0xFF6D4C41),
    surfaceTint = Color(0xFFD7CCC8),
)

private val IndigoLightColorScheme = lightColorScheme(
    primary = Color(0xFF5B588D),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE2DFFF),
    onPrimaryContainer = Color(0xFF1A1744),
    secondary = Color(0xFF5B588D),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE2DFFF),
    onSecondaryContainer = Color(0xFF1A1744),
    tertiary = Color(0xFF4E4C78),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFDCD9F7),
    onTertiaryContainer = Color(0xFF15133E),
    background = Color(0xFFFBF8FF),
    onBackground = Color(0xFF1B1B1F),
    surface = Color(0xFFF6F3FA),
    onSurface = Color(0xFF1B1B1F),
    surfaceVariant = Color(0xFFE4E1EC),
    onSurfaceVariant = Color(0xFF47464F),
    outline = Color(0xFF787680),
    outlineVariant = Color(0xFFC8C5D0),
)

private val IndigoDarkColorScheme = darkColorScheme(
    primary = Color(0xFFC4C0FF),
    onPrimary = Color(0xFF2D2A5B),
    primaryContainer = Color(0xFF434073),
    onPrimaryContainer = Color(0xFFE2DFFF),
    secondary = Color(0xFFC4C0FF),
    onSecondary = Color(0xFF2D2A5B),
    secondaryContainer = Color(0xFF434073),
    onSecondaryContainer = Color(0xFFE2DFFF),
    tertiary = Color(0xFFB9B5E8),
    onTertiary = Color(0xFF232052),
    tertiaryContainer = Color(0xFF3A3866),
    onTertiaryContainer = Color(0xFFDCD9F7),
    background = Color(0xFF131316),
    onBackground = Color(0xFFE4E1E6),
    surface = Color(0xFF1B1B1F),
    onSurface = Color(0xFFC8C5D0),
    surfaceVariant = Color(0xFF47464F),
    onSurfaceVariant = Color(0xFFC8C5D0),
    outline = Color(0xFF918F9A),
    outlineVariant = Color(0xFF47464F),
)

private val ForestLightColorScheme = lightColorScheme(
    primary = Color(0xFF5F5D68),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE5E0F0),
    onPrimaryContainer = Color(0xFF1C1A23),
    secondary = Color(0xFF5F5D68),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE5E0F0),
    onSecondaryContainer = Color(0xFF1C1A23),
    tertiary = Color(0xFF535164),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFDDD9EC),
    onTertiaryContainer = Color(0xFF171525),
    background = Color(0xFFFCF8FF),
    onBackground = Color(0xFF1D1B20),
    surface = Color(0xFFF7F2FA),
    onSurface = Color(0xFF1D1B20),
    surfaceVariant = Color(0xFFE6E0E9),
    onSurfaceVariant = Color(0xFF48454E),
    outline = Color(0xFF79747E),
    outlineVariant = Color(0xFFCAC4D0),
)

private val ForestDarkColorScheme = darkColorScheme(
    primary = Color(0xFFC8C4D3),
    onPrimary = Color(0xFF312F38),
    primaryContainer = Color(0xFF474550),
    onPrimaryContainer = Color(0xFFE5E0F0),
    secondary = Color(0xFFC8C4D3),
    onSecondary = Color(0xFF312F38),
    secondaryContainer = Color(0xFF474550),
    onSecondaryContainer = Color(0xFFE5E0F0),
    tertiary = Color(0xFFBAB8CC),
    onTertiary = Color(0xFF2B2A3A),
    tertiaryContainer = Color(0xFF3E3D4C),
    onTertiaryContainer = Color(0xFFDDD9EC),
    background = Color(0xFF141318),
    onBackground = Color(0xFFE6E1E5),
    surface = Color(0xFF1D1B20),
    onSurface = Color(0xFFCAC4D0),
    surfaceVariant = Color(0xFF48454E),
    onSurfaceVariant = Color(0xFFCAC4D0),
    outline = Color(0xFF938F99),
    outlineVariant = Color(0xFF48454E),
)

private fun getAppColorScheme(palette: String, isDark: Boolean): androidx.compose.material3.ColorScheme {
    return when (palette) {
        "espresso" -> if (isDark) DarkColorScheme else LightColorScheme
        "forest" -> if (isDark) ForestDarkColorScheme else ForestLightColorScheme
        else -> if (isDark) IndigoDarkColorScheme else IndigoLightColorScheme
    }
}

object CSQTTColors {
    val warning = Color(0xFFFFA726)
}

@Composable
fun CSQTTTheme(
    themeMode: String = "system",
    isDynamicColor: Boolean = false,
    themePalette: String = "indigo",
    content: @Composable () -> Unit,
) {
    val darkTheme =
        when (themeMode) {
            CsqttConstants.Theme.MODE_DARK -> true
            CsqttConstants.Theme.MODE_LIGHT -> false
            else -> isSystemInDarkTheme()
        }

    val context = LocalContext.current
    val colorScheme =
        if (isDynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        } else {
            getAppColorScheme(themePalette, darkTheme)
        }

    val view = LocalView.current
    if (!view.isInEditMode) {
        @Suppress("DEPRECATION")
        SideEffect {
            val window = (view.context as Activity).window
            val navigationBarColor =
                if (darkTheme) {
                    Color.Transparent
                } else {
                    lerp(colorScheme.background, colorScheme.surface, 0.55f)
                }
            window.statusBarColor = Color.Transparent.toArgb()
            window.navigationBarColor = navigationBarColor.toArgb()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
                window.isStatusBarContrastEnforced = false
            }
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    val currentDensity = LocalDensity.current
    val fixedDensity =
        remember(currentDensity.density) {
            Density(density = currentDensity.density, fontScale = 1f)
        }

    CompositionLocalProvider(
        LocalDensity provides fixedDensity,
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = CSQTTTypography,
            shapes = CsqttMaterialShapes,
            content = content,
        )
    }
}
