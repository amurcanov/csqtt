// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.components

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

fun Modifier.fadingVerticalScroll(state: ScrollState): Modifier =
    scrollEdgeFade(
        fadeHeight = 24.dp,
        backwardDistance = { state.value.toFloat() },
        forwardDistance = { (state.maxValue - state.value).coerceAtLeast(0).toFloat() },
    ).verticalScroll(state)

fun Modifier.verticalScrollEdgeFade(state: LazyListState, fadeHeight: Dp = 24.dp): Modifier =
    scrollEdgeFade(
        fadeHeight = fadeHeight,
        backwardDistance = {
            when {
                !state.canScrollBackward -> 0f
                state.firstVisibleItemIndex > 0 -> Float.MAX_VALUE
                else -> state.firstVisibleItemScrollOffset.toFloat()
            }
        },
        forwardDistance = {
            val layout = state.layoutInfo
            val last = layout.visibleItemsInfo.lastOrNull()
            when {
                !state.canScrollForward || last == null -> 0f
                last.index < layout.totalItemsCount - 1 -> Float.MAX_VALUE
                else -> (last.offset + last.size - layout.viewportEndOffset).coerceAtLeast(0).toFloat()
            }
        },
    )

private fun Modifier.scrollEdgeFade(
    fadeHeight: Dp,
    backwardDistance: () -> Float,
    forwardDistance: () -> Float,
): Modifier = graphicsLayer {
    compositingStrategy =
        if (backwardDistance() > 0f || forwardDistance() > 0f) {
            CompositingStrategy.Offscreen
        } else {
            CompositingStrategy.Auto
        }
}.drawWithContent {
    drawContent()
    val length = fadeHeight.toPx().coerceAtMost(size.height / 2f)
    if (length <= 0f) return@drawWithContent
    val topStrength = (backwardDistance() / length).coerceIn(0f, 1f)
    val bottomStrength = (forwardDistance() / length).coerceIn(0f, 1f)
    if (topStrength == 0f && bottomStrength == 0f) return@drawWithContent
    val fraction = length / size.height
    drawRect(
        brush = Brush.verticalGradient(
            colorStops = arrayOf(
                0f to Color.Black.copy(alpha = 1f - topStrength),
                fraction to Color.Black,
                1f - fraction to Color.Black,
                1f to Color.Black.copy(alpha = 1f - bottomStrength),
            )
        ),
        blendMode = BlendMode.DstIn,
    )
}
