// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.DeployManager
import com.csqtt.client.LogEntry
import com.csqtt.client.LogLevel
import com.csqtt.client.R
import com.csqtt.client.SettingsStore
import com.csqtt.client.TunnelManager
import com.csqtt.client.showRaisedToast
import com.csqtt.client.ui.components.verticalScrollEdgeFade
import kotlinx.coroutines.launch

@Composable
fun LogsTab(settingsStore: SettingsStore) {
    val loggingEnabled by
        settingsStore.loggingEnabled.collectAsStateWithLifecycle(initialValue = true)
    val scope = rememberCoroutineScope()
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        LogsTerminalHeader()
        Spacer(Modifier.height(12.dp))
        AppSectionCard(
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.logs_enabled),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                Switch(
                    checked = loggingEnabled,
                    onCheckedChange = { enabled ->
                        TunnelManager.isLoggingEnabled = enabled
                        scope.launch { settingsStore.saveLoggingEnabled(enabled) }
                    },
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        LogsTerminal(loggingEnabled, Modifier.weight(1f))
    }
}

@Composable
private fun LogsTerminalHeader() {
    val copiedMessage = stringResource(R.string.logs_copied)
    val context = LocalContext.current
    val currentLogs = TunnelManager.logs
    val connection by TunnelManager.connection.collectAsStateWithLifecycle()
    val errorCount = currentLogs.count { it.isError || it.level == LogLevel.ERR }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "Лог событий",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                buildString {
                    append("${currentLogs.size} событий")
                    if (errorCount > 0) append(" · ошибок: $errorCount")
                    if (connection.connected) append(" · туннель активен")
                },
                style = MaterialTheme.typography.labelSmall,
                color =
                    if (errorCount > 0) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            LogsActionButton(
                Icons.Default.Delete,
                stringResource(R.string.action_clear),
                enabled = true,
                onClick = TunnelManager::clearLogs,
            )
            LogsActionButton(
                Icons.Default.ContentCopy,
                stringResource(R.string.action_copy),
                enabled = currentLogs.isNotEmpty(),
            ) {
                val text = currentLogs.joinToString("\n") { "${it.message} (x${it.count})" }
                val clipboard =
                    context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("CSQTT Logs", text))
                context.showRaisedToast(copiedMessage, Toast.LENGTH_SHORT)
            }
        }
    }
}

@Composable
private fun LogsTerminal(loggingEnabled: Boolean, modifier: Modifier) {
    val currentLogs = TunnelManager.logs
    val listState = rememberLazyListState()
    val isDeploying by DeployManager.isDeploying.collectAsStateWithLifecycle()
    LaunchedEffect(currentLogs.size, isDeploying) {
        if (isDeploying) {
            val latestDeployIndex = currentLogs.indexOfLast { it.key.startsWith("deploy_") }
            if (latestDeployIndex >= 0) listState.animateScrollToItem(latestDeployIndex)
        }
    }
    LogsConsoleCard(
        modifier = modifier,
        visibleLogs = currentLogs,
        loggingEnabled = loggingEnabled,
        listState = listState,
    )
}

@Composable
private fun LogsActionButton(
    icon: ImageVector,
    contentDescription: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val palette = MaterialTheme.colorScheme
    val isDark = palette.background.luminance() < 0.22f
    val bg =
        if (isDark) {
            lerp(palette.surface, palette.surfaceVariant, 0.22f)
        } else {
            lerp(palette.surface, palette.surfaceVariant, 0.42f)
        }
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = bg,
        border = BorderStroke(1.dp, palette.outlineVariant.copy(alpha = 0.4f)),
        shadowElevation = 2.dp,
        modifier = Modifier.size(44.dp),
    ) {
        Box(
            modifier =
                Modifier.fillMaxSize()
                    .clip(RoundedCornerShape(16.dp))
                    .clickable(enabled = enabled, onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = contentDescription,
                tint =
                    if (enabled) palette.primary else palette.onSurfaceVariant.copy(alpha = 0.38f),
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

@Composable
private fun LogsConsoleCard(
    modifier: Modifier = Modifier,
    visibleLogs: List<LogEntry>,
    loggingEnabled: Boolean,
    listState: androidx.compose.foundation.lazy.LazyListState,
) {
    val palette = MaterialTheme.colorScheme
    val isDark = palette.background.luminance() < 0.22f
    val container =
        if (isDark) {
            lerp(palette.surface, palette.surfaceVariant, 0.10f)
        } else {
            lerp(palette.surface, palette.surfaceVariant, 0.28f)
        }

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = container,
        border = BorderStroke(1.dp, palette.outlineVariant.copy(alpha = 0.26f)),
        shadowElevation = 0.dp,
        tonalElevation = 0.dp,
    ) {
        if (visibleLogs.isEmpty()) {
            LogsEmptyState(loggingEnabled = loggingEnabled)
        } else {
            LazyColumn(
                state = listState,
                modifier =
                    Modifier.fillMaxSize()
                        .verticalScrollEdgeFade(
                            state = listState,
                            fadeHeight = 24.dp,
                        )
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
                contentPadding = PaddingValues(bottom = 8.dp),
            ) {
                items(visibleLogs, key = { it.key }) { entry ->
                    LogLine(entry)
                }
            }
        }
    }
}

@Composable
private fun LogsEmptyState(loggingEnabled: Boolean) {
    val palette = MaterialTheme.colorScheme
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                shape = RoundedCornerShape(20.dp),
                color = palette.primary.copy(alpha = 0.10f),
                border = BorderStroke(1.dp, palette.primary.copy(alpha = 0.18f)),
                modifier = Modifier.size(64.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Terminal,
                        contentDescription = null,
                        tint = palette.primary.copy(alpha = 0.75f),
                        modifier = Modifier.size(30.dp),
                    )
                }
            }
            Spacer(Modifier.height(14.dp))
            Text(
                text =
                    when {
                        !loggingEnabled -> "Логирование отключено"
                        else -> stringResource(R.string.logs_empty_title)
                    },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = palette.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text =
                    when {
                        !loggingEnabled -> "Включите переключатель выше, чтобы собирать события"
                        else -> "События туннеля появятся здесь после подключения"
                    },
                style = MaterialTheme.typography.labelMedium,
                color = palette.onSurfaceVariant,
            )
        }
    }
}
