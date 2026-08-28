// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.dp
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSpacing

@Composable
private fun appSectionCardColor(): Color {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    return if (isDark) {
        lerp(colors.background, colors.surface, 0.82f)
    } else {
        lerp(colors.surface, colors.surfaceVariant, 0.28f)
    }
}

@Composable
private fun appSectionCardBorderColor(): Color {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    return if (isDark) {
        colors.outlineVariant.copy(alpha = 0.32f)
    } else {
        colors.outlineVariant.copy(alpha = 0.24f)
    }
}

@Composable
fun AppSectionCard(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(CsqttSpacing.Md),
    verticalArrangement: Arrangement.Vertical = Arrangement.spacedBy(CsqttSpacing.Md),
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        shape = CsqttShapes.Card,
        color = appSectionCardColor(),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, appSectionCardBorderColor()),
        shadowElevation = if (MaterialTheme.colorScheme.background.luminance() < 0.22f) 4.dp else 10.dp,
        tonalElevation = if (MaterialTheme.colorScheme.background.luminance() < 0.22f) 0.dp else 2.dp,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(contentPadding),
            verticalArrangement = verticalArrangement,
            content = content
        )
    }
}
