// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

internal const val ExpansionDuration = 280

@Composable
internal fun ExpandableContent(
    visible: Boolean,
    modifier: Modifier = Modifier,
    spacing: Dp = 0.dp,
    content: @Composable ColumnScope.() -> Unit,
) {
    AnimatedVisibility(
        visible = visible,
        modifier = modifier,
        enter = expandVertically(tween(ExpansionDuration, easing = FastOutSlowInEasing), expandFrom = Alignment.Top),
        exit = shrinkVertically(tween(ExpansionDuration, easing = FastOutSlowInEasing), shrinkTowards = Alignment.Top),
    ) {
        Column(modifier = Modifier.padding(top = spacing), content = content)
    }
}
