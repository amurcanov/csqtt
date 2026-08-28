// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.focusable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.csqtt.client.CsqttConstants
import kotlin.math.roundToInt

import androidx.compose.runtime.rememberUpdatedState

@Composable
internal fun TunnelWorkersControl(
    value: Float,
    maximum: Float,
    enabled: Boolean,
    onValueChange: (Float) -> Unit,
    onInfo: () -> Unit,
) {
    val minimum = CsqttConstants.Tunnel.WORKERS_PER_GROUP.toFloat()
    val normalizedMaximum = roundToGroup(maximum, maximum)
    val normalizedValue = roundToGroup(value.coerceIn(minimum, normalizedMaximum), normalizedMaximum)
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Потоки",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                IconButton(onClick = onInfo, modifier = Modifier.size(28.dp)) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                        contentDescription = "Информация о потоках",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(17.dp),
                    )
                }
            }
            Text(
                text = normalizedValue.toInt().toString(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        CompactSteppedSlider(
            value = normalizedValue,
            onValueChange = onValueChange,
            valueRange = minimum..normalizedMaximum,
            stepSize = CsqttConstants.Tunnel.WORKERS_PER_GROUP.toFloat(),
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
internal fun CompactSteppedSlider(
    value: Float,
    onValueChange: (Float) -> Unit,
    valueRange: ClosedFloatingPointRange<Float>,
    stepSize: Float,
    enabled: Boolean,
    modifier: Modifier = Modifier,
) {
    val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.38f)
    val inactiveColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (enabled) 1f else 0.55f)
    val thumbStrokeColor = MaterialTheme.colorScheme.surface
    val focusedThumbStrokeColor = MaterialTheme.colorScheme.primary
    val density = LocalDensity.current
    val thumbRadiusPx = with(density) { 9.dp.toPx() }
    val trackWidthPx = with(density) { 5.dp.toPx() }

    val currentOnValueChange by rememberUpdatedState(onValueChange)
    val currentValue by rememberUpdatedState(value)
    val currentValueRange by rememberUpdatedState(valueRange)
    val currentStepSize by rememberUpdatedState(stepSize)
    var focused by remember { mutableStateOf(false) }

    fun snap(raw: Float): Float {
        val min = currentValueRange.start
        val max = currentValueRange.endInclusive
        val snapped = (((raw - min) / currentStepSize).roundToInt() * currentStepSize) + min
        return snapped.coerceIn(min, max)
    }

    fun positionToValue(x: Float, width: Float): Float {
        val left = thumbRadiusPx
        val right = (width - thumbRadiusPx).coerceAtLeast(left + 1f)
        val fraction = ((x.coerceIn(left, right) - left) / (right - left)).coerceIn(0f, 1f)
        return snap(currentValueRange.start + fraction * (currentValueRange.endInclusive - currentValueRange.start))
    }

    Canvas(
        modifier = modifier
            .height(34.dp)
            .onFocusChanged { focused = it.isFocused }
            .onPreviewKeyEvent { event ->
                if (!enabled || event.type != KeyEventType.KeyDown) return@onPreviewKeyEvent false
                val step = currentStepSize
                when (event.key) {
                    Key.DirectionLeft, Key.DirectionDown -> {
                        currentOnValueChange(snap(currentValue - step))
                        true
                    }
                    Key.DirectionRight, Key.DirectionUp -> {
                        currentOnValueChange(snap(currentValue + step))
                        true
                    }
                    else -> false
                }
            }
            .semantics {
                progressBarRangeInfo = ProgressBarRangeInfo(
                    current = value,
                    range = valueRange,
                    steps = (((valueRange.endInclusive - valueRange.start) / stepSize).roundToInt() - 1).coerceAtLeast(0),
                )
            }
            .focusable(enabled)
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectDragGestures(
                    onDragStart = { offset ->
                        currentOnValueChange(positionToValue(offset.x, size.width.toFloat()))
                    },
                    onDrag = { change, _ ->
                        change.consume()
                        currentOnValueChange(positionToValue(change.position.x, size.width.toFloat()))
                    }
                )
            }
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectTapGestures { offset ->
                    currentOnValueChange(positionToValue(offset.x, size.width.toFloat()))
                }
            },
    ) {
        val centerY = size.height / 2f
        val left = thumbRadiusPx
        val right = size.width - thumbRadiusPx
        val range = (valueRange.endInclusive - valueRange.start).coerceAtLeast(1f)
        val fraction = ((value - valueRange.start) / range).coerceIn(0f, 1f)
        val thumbX = left + (right - left) * fraction

        drawLine(inactiveColor, Offset(left, centerY), Offset(right, centerY), trackWidthPx, StrokeCap.Round)
        drawLine(activeColor, Offset(left, centerY), Offset(thumbX, centerY), trackWidthPx, StrokeCap.Round)

        val tickCount = (((valueRange.endInclusive - valueRange.start) / stepSize).roundToInt()).coerceAtLeast(1)
        repeat(tickCount + 1) { index ->
            val tickFraction = index / tickCount.toFloat()
            val tickX = left + (right - left) * tickFraction
            drawCircle(
                color = if (tickX <= thumbX) activeColor else inactiveColor,
                radius = 2.dp.toPx(),
                center = Offset(tickX, centerY),
            )
        }

        drawCircle(color = activeColor, radius = thumbRadiusPx, center = Offset(thumbX, centerY))
        drawCircle(
            color = if (focused) focusedThumbStrokeColor else thumbStrokeColor,
            radius = if (focused) thumbRadiusPx + 2.dp.toPx() else thumbRadiusPx,
            center = Offset(thumbX, centerY),
            style = androidx.compose.ui.graphics.drawscope.Stroke(width = if (focused) 3.dp.toPx() else 2.dp.toPx()),
        )
    }
}

internal fun roundToGroup(value: Float, maxW: Float = 96f): Float {
    val groupSize = CsqttConstants.Tunnel.WORKERS_PER_GROUP
    val normalizedMax = ((maxW.toInt().coerceAtLeast(groupSize)) / groupSize * groupSize).toFloat()
    val rounded = (Math.round(value / groupSize) * groupSize).toFloat()
    return rounded.coerceIn(groupSize.toFloat(), normalizedMax)
}
