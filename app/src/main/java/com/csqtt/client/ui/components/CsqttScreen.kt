// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.csqtt.client.ui.design.CsqttSizes

internal val LocalCsqttScreenTitle = staticCompositionLocalOf<String?> { null }
internal val LocalCsqttOnBack = staticCompositionLocalOf<(() -> Unit)?> { null }

@Composable
fun CsqttScreen(
    modifier: Modifier = Modifier,
    title: String? = null,
    subtitle: String? = null,
    actions: (@Composable RowScope.() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val screenTitle = title ?: LocalCsqttScreenTitle.current
    val onBack = LocalCsqttOnBack.current
    Column(
        modifier = modifier.fillMaxSize().padding(horizontal = CsqttSizes.ScreenHorizontalPadding),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().widthIn(max = CsqttSizes.ContentMaxWidth),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (screenTitle != null || actions != null) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    onBack?.let { back ->
                        IconButton(onClick = back) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                        }
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        screenTitle?.let {
                            Text(
                                it,
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.semantics { heading() },
                            )
                        }
                        subtitle?.let {
                            Text(
                                it,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    actions?.let { Row(content = it) }
                }
            }
            content()
        }
    }
}
