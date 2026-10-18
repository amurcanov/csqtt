// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.view.HapticFeedbackConstants
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.*
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.csqtt.client.R

@Composable
internal fun AuroraStatusCard(
    peer: String,
    workers: String,
    hashes: String,
    transport: String,
    tunnelRunning: Boolean,
    tunnelVerified: Boolean,
    dashboardScale: Float,
) {
    val palette = MaterialTheme.colorScheme
    val ds = dashboardScale

    val reveal by
        animateFloatAsState(
            targetValue = if (tunnelVerified) 1f else 0f,
            animationSpec =
                tween(650, easing = androidx.compose.animation.core.FastOutSlowInEasing),
            label = "status_reveal",
        )
    val infinite = if (tunnelRunning || reveal > 0f) {
        rememberInfiniteTransition(label = "status_infinite")
    } else null
    val breath =
        infinite?.animateFloat(
            initialValue = 0.7f,
            targetValue = 1f,
            animationSpec =
                infiniteRepeatable(
                    tween(1600, easing = androidx.compose.animation.core.FastOutSlowInEasing),
                    RepeatMode.Reverse,
                ),
            label = "status_breath",
        )

    val borderColor by
        animateColorAsState(
            targetValue =
                if (tunnelVerified) lerp(palette.outlineVariant, palette.primary, 0.5f)
                else palette.outlineVariant,
            animationSpec = tween(650),
            label = "status_border",
        )
    val valueColor by
        animateColorAsState(
            targetValue = if (tunnelVerified) palette.primary else palette.onSurface,
            animationSpec = tween(650),
            label = "status_value",
        )
    val dotColor by
        animateColorAsState(
            targetValue =
                when {
                    tunnelVerified -> palette.primary
                    tunnelRunning -> lerp(palette.primary, palette.tertiary, 0.5f)
                    else -> palette.onSurfaceVariant
                },
            animationSpec = tween(650),
            label = "status_dot",
        )
    val cardBg = lerp(palette.surface, palette.primary, 0.05f * reveal + 0.02f)
    val dotRingProgress by
        animateFloatAsState(
            targetValue = if (tunnelRunning) 1f else 0f,
            animationSpec =
                tween(600, easing = androidx.compose.animation.core.FastOutSlowInEasing),
            label = "status_dot_ring",
        )

    Surface(
        modifier = Modifier.fillMaxWidth(0.78f * ds),
        shape = RoundedCornerShape(24.dp * ds),
        color = cardBg,
        border = BorderStroke(1.dp, borderColor.copy(alpha = 0.35f + 0.35f * reveal * (breath?.value ?: 1f))),
        shadowElevation = (4.dp + 6.dp * reveal),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp * ds, vertical = 13.dp * ds),
            verticalArrangement = Arrangement.spacedBy(10.dp * ds),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Canvas(modifier = Modifier.size(10.dp * ds)) {
                        val r = size.minDimension / 2f
                        if (dotRingProgress > 0.01f) {
                            drawCircle(
                                color = dotColor,
                                radius = r * (0.9f + 0.35f * (breath?.value ?: 1f) * dotRingProgress),
                                center = center,
                                alpha = (0.30f - 0.10f * (breath?.value ?: 1f)) * dotRingProgress,
                            )
                        }
                        drawCircle(color = dotColor, radius = r * 0.75f, center = center)
                    }
                    Spacer(Modifier.width(6.dp * ds))
                    Text(
                        "IP сервера",
                        style = MaterialTheme.typography.labelMedium,
                        color = palette.onSurfaceVariant,
                    )
                }
                Text(
                    peer,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = valueColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Box(
                modifier =
                    Modifier.fillMaxWidth()
                        .height(1.dp)
                        .background(
                            Brush.horizontalGradient(
                                listOf(
                                    Color.Transparent,
                                    borderColor.copy(alpha = 0.45f + 0.25f * reveal),
                                    Color.Transparent,
                                )
                            )
                        )
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AuroraMetric("Хэши", hashes, valueColor, Modifier.weight(1f))
                AuroraDivider(ds, borderColor, reveal)
                AuroraMetric("Потоки", workers, valueColor, Modifier.weight(1f))
                AuroraDivider(ds, borderColor, reveal)
                AuroraMetric("Транспорт", transport, valueColor, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun AuroraMetric(
    label: String,
    value: String,
    valueColor: Color,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            color = valueColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun AuroraDivider(
    dashboardScale: Float,
    color: Color,
    reveal: Float,
) {
    Box(
        modifier =
            Modifier.width(1.dp)
                .height(38.dp * dashboardScale)
                .background(
                    Brush.verticalGradient(
                        listOf(
                            Color.Transparent,
                            color.copy(alpha = 0.40f + 0.20f * reveal),
                            Color.Transparent,
                        )
                    )
                )
    )
}

@Composable
internal fun AuroraPowerButton(
    tunnelRunning: Boolean,
    tunnelVerified: Boolean,
    connecting: Boolean,
    enabled: Boolean,
    dashboardScale: Float,
    onToggle: () -> Unit,
) {
    val palette = MaterialTheme.colorScheme
    val view = LocalView.current

    val scale by
        animateFloatAsState(
            targetValue = if (tunnelRunning) 1.10f else 0.96f,
            animationSpec =
                tween(
                    650,
                    easing = androidx.compose.animation.core.CubicBezierEasing(0.22f, 1f, 0.36f, 1f),
                ),
            label = "aurora_scale",
        )
    val reveal by
        animateFloatAsState(
            targetValue = if (tunnelVerified) 1f else 0f,
            animationSpec =
                tween(620, easing = androidx.compose.animation.core.FastOutSlowInEasing),
            label = "aurora_reveal",
        )
    val connectAlpha by
        animateFloatAsState(
            targetValue = if (connecting) 1f else 0f,
            animationSpec = tween(300),
            label = "aurora_connect",
        )

    val connectedAnimation = if (tunnelVerified || reveal > 0f) {
        rememberInfiniteTransition(label = "aurora_connected")
    } else null
    val connectingAnimation = if (connecting || connectAlpha > 0f) {
        rememberInfiniteTransition(label = "aurora_connecting")
    } else null
    val rippleT =
        connectedAnimation?.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(2400, easing = LinearEasing)),
            label = "aurora_ripple",
        )
    val spin =
        connectingAnimation?.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(1100, easing = LinearEasing)),
            label = "aurora_spin",
        )
    val slowSpin =
        connectedAnimation?.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(9000, easing = LinearEasing)),
            label = "aurora_slowspin",
        )
    val breath =
        connectedAnimation?.animateFloat(
            initialValue = 0.75f,
            targetValue = 1f,
            animationSpec =
                infiniteRepeatable(
                    tween(1900, easing = androidx.compose.animation.core.FastOutSlowInEasing),
                    RepeatMode.Reverse,
                ),
            label = "aurora_breath",
        )

    val offColor by
        animateColorAsState(
            targetValue = palette.surfaceVariant,
            animationSpec = tween(650),
            label = "aurora_off",
        )
    val onColor by
        animateColorAsState(
            targetValue = palette.primary,
            animationSpec = tween(650),
            label = "aurora_on",
        )
    val iconTint by
        animateColorAsState(
            targetValue = if (tunnelVerified) palette.onPrimary else palette.onSurfaceVariant,
            animationSpec = tween(650),
            label = "aurora_icon",
        )
    val offHi = lerp(offColor, palette.surface, 0.5f)
    val onHi = lerp(onColor, Color.White, 0.30f)
    val onLo = lerp(onColor, Color.Black, 0.14f)

    Box(
        modifier = Modifier.size(232.dp * dashboardScale),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val maxR = size.minDimension / 2f
            val buttonR = maxR * 0.72f
            val ringR = buttonR + 9.dp.toPx()
            val ringSize = Size(ringR * 2, ringR * 2)
            val ringTopLeft = Offset(center.x - ringR, center.y - ringR)

            if (reveal > 0f) {
                drawCircle(
                    brush =
                        Brush.radialGradient(
                            colors =
                                listOf(
                                    onColor.copy(alpha = 0.38f * reveal * (breath?.value ?: 1f)),
                                    Color.Transparent,
                                ),
                            center = center,
                            radius = maxR,
                        ),
                    radius = maxR,
                    center = center,
                )
                var i = 0
                while (i < 2) {
                    val f = ((rippleT?.value ?: 0f) + i * 0.5f) % 1f
                    drawCircle(
                        color = onColor,
                        radius = buttonR + (maxR - buttonR) * f,
                        center = center,
                        alpha = (1f - f) * 0.30f * reveal,
                        style = Stroke(width = 2.dp.toPx()),
                    )
                    i++
                }
                drawCircle(
                    color = onColor,
                    radius = ringR,
                    center = center,
                    alpha = 0.55f * reveal,
                    style = Stroke(width = 3.dp.toPx()),
                )
                rotate(slowSpin?.value ?: 0f) {
                    drawArc(
                        color = onColor,
                        startAngle = 0f,
                        sweepAngle = 55f,
                        useCenter = false,
                        topLeft = ringTopLeft,
                        size = ringSize,
                        alpha = 0.7f * reveal,
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                    )
                }
            }
            if (connectAlpha > 0f) {
                drawCircle(
                    color = onColor,
                    radius = ringR,
                    center = center,
                    alpha = 0.15f * connectAlpha,
                    style = Stroke(width = 3.dp.toPx()),
                )
                rotate(spin?.value ?: 0f) {
                    drawArc(
                        color = onColor,
                        startAngle = 0f,
                        sweepAngle = 100f,
                        useCenter = false,
                        topLeft = ringTopLeft,
                        size = ringSize,
                        alpha = connectAlpha,
                        style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round),
                    )
                }
            }
            val offRingAlpha = (1f - reveal) * (1f - connectAlpha)
            if (offRingAlpha > 0.01f) {
                drawCircle(
                    color = palette.onSurfaceVariant,
                    radius = ringR,
                    center = center,
                    alpha = (0.14f + 0.08f * (breath?.value ?: 1f)) * offRingAlpha,
                    style = Stroke(width = 2.dp.toPx()),
                )
            }
        }

        Box(
            modifier =
                Modifier.size(164.dp * dashboardScale)
                    .scale(scale)
                    .shadow(elevation = 14.dp, shape = CircleShape)
                    .clip(CircleShape)
                    .clickable(enabled = enabled) {
                        view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                        onToggle()
                    },
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val r = size.minDimension / 2f
                if (reveal < 1f) {
                    drawCircle(
                        brush =
                            Brush.radialGradient(
                                colors = listOf(offHi, offColor),
                                center = center,
                                radius = r,
                            ),
                        radius = r,
                        center = center,
                        alpha = 1f - reveal,
                    )
                }
                if (reveal > 0f) {
                    drawCircle(
                        brush =
                            Brush.radialGradient(
                                colors = listOf(onHi, onLo),
                                center = Offset(center.x, center.y - r * 0.25f),
                                radius = r * 1.1f,
                            ),
                        radius = r,
                        center = center,
                        alpha = reveal,
                    )
                }
                drawCircle(
                    brush =
                        Brush.radialGradient(
                            colors = listOf(Color.White.copy(alpha = 0.14f), Color.Transparent),
                            center = Offset(center.x, center.y - r * 0.6f),
                            radius = r * 0.9f,
                        ),
                    radius = r,
                    center = center,
                )
            }
            Image(
                painter = painterResource(R.drawable.ic_vpn_key_gradient),
                contentDescription =
                    if (tunnelRunning) "Остановить туннель" else "Подключить туннель",
                modifier = Modifier.size(104.dp * dashboardScale),
                colorFilter = ColorFilter.tint(iconTint),
            )
        }
    }
}
