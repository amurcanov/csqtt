// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.csqtt.client.LogEntry
import com.csqtt.client.LogLevel

private data class LogLineStyle(
    val tag: String?,
    val body: String,
    val accent: Color,
    val isError: Boolean,
    val isSuccess: Boolean,
)

private val tagRegex = Regex("^\\[([^\\]]+)\\]\\s*")

@Composable
private fun resolveLogStyle(entry: LogEntry): LogLineStyle {
    val palette = MaterialTheme.colorScheme
    val match = tagRegex.find(entry.message)
    val tag = match?.groupValues?.get(1)
    val body = if (match != null) entry.message.substring(match.value.length) else entry.message
    val isError = entry.isError || entry.level == LogLevel.ERR
    val isSuccess = !isError && when (entry.level) {
        LogLevel.OK, LogLevel.NET -> true
        null -> body.contains("✓") || tag == "READY"
        else -> false
    }

    val accent =
        when {
            isError -> palette.error
            isSuccess -> palette.primary
            tag == null -> palette.onSurfaceVariant
            tag.startsWith("КАПЧА") -> palette.tertiary
            tag == "СТАТИСТИКА" -> palette.secondary
            tag == "СЕТЬ" || tag == "СТОП" -> palette.error
            else -> palette.primary
        }
    return LogLineStyle(tag, body, accent, isError, isSuccess)
}

@Composable
internal fun LogLine(entry: LogEntry) {
    val palette = MaterialTheme.colorScheme
    val style = resolveLogStyle(entry)

    val rowBg by
        animateColorAsState(
            targetValue =
                if (style.isError) palette.errorContainer.copy(alpha = 0.30f)
                else Color.Transparent,
            animationSpec = tween(400),
            label = "log_row_bg",
        )

    val counterScale = remember { Animatable(1f) }
    var seenCount by rememberSaveable { mutableIntStateOf(entry.count) }
    LaunchedEffect(entry.count) {
        if (entry.count != seenCount) {
            seenCount = entry.count
            counterScale.animateTo(1.15f, tween(100))
            counterScale.animateTo(1f, spring(dampingRatio = Spring.DampingRatioNoBouncy))
        }
    }

    Row(
        modifier =
            Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(rowBg)
                .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            color = style.accent.copy(alpha = 0.14f),
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, style.accent.copy(alpha = 0.25f)),
            modifier =
                Modifier.defaultMinSize(minWidth = 26.dp, minHeight = 22.dp)
                    .graphicsLayer { scaleX = counterScale.value; scaleY = counterScale.value },
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.padding(horizontal = 6.dp),
            ) {
                Text(
                    text = "${entry.count}",
                    color = style.accent,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                )
            }
        }
        Spacer(modifier = Modifier.width(8.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (style.tag != null) {
                    Surface(
                        color = style.accent.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text(
                            text = style.tag,
                            color = style.accent,
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.4.sp,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            maxLines = 1,
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = style.body,
                color =
                    when {
                        style.isError -> palette.error
                        style.isSuccess -> palette.primary
                        else -> palette.onSurface
                    },
                fontSize = 12.5.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight =
                    if (style.isError || style.isSuccess) FontWeight.SemiBold
                    else FontWeight.Normal,
                lineHeight = 17.sp,
            )
        }
    }
}
