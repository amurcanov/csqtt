// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.csqtt.client.R

@Composable
fun appDialogContainerColor(): Color {
    val palette = MaterialTheme.colorScheme
    val isDark = palette.background.luminance() < 0.22f
    return if (isDark) {
        lerp(palette.surface, palette.surfaceVariant, 0.12f)
    } else {
        lerp(palette.surface, palette.surfaceVariant, 0.30f)
    }
}

@Composable
fun appDialogBorderColor(): Color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.30f)

@Composable
fun AppDialogSurface(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(28.dp),
        color = appDialogContainerColor(),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, appDialogBorderColor()),
        shadowElevation = 0.dp,
        tonalElevation = 0.dp,
        modifier = modifier,
    ) {
        Column(content = content)
    }
}

@Composable
fun AppDialogIconTile(
    accent: Color = MaterialTheme.colorScheme.primary,
    size: androidx.compose.ui.unit.Dp = 42.dp,
    content: @Composable () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(size * 0.4f),
        color = accent.copy(alpha = 0.12f),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.24f)),
    ) {
        Box(modifier = Modifier.size(size), contentAlignment = Alignment.Center) { content() }
    }
}

@Composable
fun AppDialogCloseButton(onClick: () -> Unit) {
    val palette = MaterialTheme.colorScheme
    Surface(
        shape = RoundedCornerShape(13.dp),
        color = palette.onSurfaceVariant.copy(alpha = 0.08f),
        border = BorderStroke(1.dp, palette.outlineVariant.copy(alpha = 0.30f)),
        modifier = Modifier.size(36.dp),
    ) {
        Box(
            modifier =
                Modifier.size(36.dp).clip(RoundedCornerShape(13.dp)).clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Default.Close,
                contentDescription = stringResource(R.string.action_close),
                tint = palette.onSurfaceVariant,
                modifier = Modifier.size(17.dp),
            )
        }
    }
}

@Composable
fun AppDialogHeader(
    title: String,
    subtitle: String? = null,
    accent: Color = MaterialTheme.colorScheme.primary,
    onClose: (() -> Unit)? = null,
    icon: @Composable () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.weight(1f),
        ) {
            AppDialogIconTile(accent = accent) { icon() }
            Spacer(modifier = Modifier.width(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = accent,
                    )
                }
            }
        }
        if (onClose != null) {
            Spacer(modifier = Modifier.width(8.dp))
            AppDialogCloseButton(onClick = onClose)
        }
    }
}
