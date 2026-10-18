// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.*
import androidx.compose.ui.unit.dp
import kotlin.math.*

private fun android16OrbShape(points: Int, innerRatio: Float): Shape = GenericShape { size, _ ->
    val centerX = size.width / 2f
    val centerY = size.height / 2f
    val outerRadius = min(size.width, size.height) / 2f
    val innerRadius = outerRadius * innerRatio

    for (i in 0 until points * 2) {
        val angle = (-PI / 2.0) + (i * PI / points)
        val radius = if (i % 2 == 0) outerRadius else innerRadius
        val x = centerX + (radius * cos(angle)).toFloat()
        val y = centerY + (radius * sin(angle)).toFloat()
        if (i == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

private val Android16OrbLarge: Shape = android16OrbShape(points = 18, innerRatio = 0.90f)
private val Android16OrbMedium: Shape = android16OrbShape(points = 20, innerRatio = 0.92f)
private val Android16OrbSmall: Shape = android16OrbShape(points = 16, innerRatio = 0.88f)

@Composable
internal fun AppBackdrop(modifier: Modifier = Modifier) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val baseBrush =
        remember(colors.background, colors.surface, colors.surfaceVariant) {
            Brush.verticalGradient(
                colors =
                    if (isDark) {
                        listOf(
                            lerp(colors.background, colors.surface, 0.18f),
                            colors.background,
                            lerp(colors.surfaceVariant, colors.background, 0.72f),
                        )
                    } else {
                        listOf(
                            lerp(colors.background, colors.surface, 0.78f),
                            colors.background,
                            lerp(colors.surfaceVariant, colors.background, 0.30f),
                        )
                    }
            )
        }
    val topGlow = colors.primary.copy(alpha = if (isDark) 0.055f else 0.09f)
    val leftGlow =
        if (isDark) {
            colors.tertiary.copy(alpha = 0.045f)
        } else {
            lerp(colors.tertiary, colors.secondaryContainer, 0.74f).copy(alpha = 0.24f)
        }
    val bottomGlow =
        if (isDark) {
            colors.primary.copy(alpha = 0.04f)
        } else {
            lerp(colors.secondary, colors.primaryContainer, 0.70f).copy(alpha = 0.22f)
        }
    val lightOrbOutline = colors.outlineVariant.copy(alpha = 0.26f)
    val topOrbGlow =
        if (isDark) {
            topGlow
        } else {
            lerp(colors.primary, colors.primaryContainer, 0.72f).copy(alpha = 0.32f)
        }

    Box(modifier = modifier.fillMaxSize().background(baseBrush)) {
        Box(
            modifier =
                Modifier.align(Alignment.TopStart)
                    .offset(x = (-86).dp, y = (-126).dp)
                    .size(258.dp)
                    .clip(Android16OrbLarge)
                    .background(topOrbGlow)
                    .then(
                        if (isDark) Modifier
                        else Modifier.border(1.dp, lightOrbOutline, Android16OrbLarge)
                    )
        )
        Box(
            modifier =
                Modifier.align(Alignment.CenterStart)
                    .offset(x = (-44).dp, y = 28.dp)
                    .size(146.dp)
                    .clip(Android16OrbSmall)
                    .background(leftGlow)
                    .then(
                        if (isDark) Modifier
                        else
                            Modifier.border(
                                1.dp,
                                lightOrbOutline.copy(alpha = 0.22f),
                                Android16OrbSmall,
                            )
                    )
        )
        Box(
            modifier =
                Modifier.align(Alignment.BottomEnd)
                    .offset(x = 62.dp, y = (-208).dp)
                    .size(198.dp)
                    .clip(Android16OrbMedium)
                    .background(bottomGlow)
                    .then(
                        if (isDark) Modifier
                        else
                            Modifier.border(
                                1.dp,
                                lightOrbOutline.copy(alpha = 0.20f),
                                Android16OrbMedium,
                            )
                    )
        )
    }
}
