// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.csqtt.client.SettingsStore
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.R

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.foundation.verticalScroll
import com.csqtt.client.CsqttConstants
import com.csqtt.client.TunnelManager
import com.csqtt.client.ui.components.CsqttSegmentedControl
import com.csqtt.client.ui.components.CsqttSettingRow
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes
import com.csqtt.client.ui.tunnel.ExtraWorkersInfoDialog

private enum class UsageRole { Owner, Participant }

@Composable
fun FloatingToolbar(
    settingsStore: SettingsStore,
    csqttLinkMode: Boolean,
    activeProfile: Int,
    onActiveProfileChange: (Int) -> Unit,
    currentTheme: String,
    onThemeChange: (String) -> Unit,
    activeFingerprint: String,
    onFingerprintChange: (String) -> Unit,
    autoPauseOnWifi: Boolean,
    onAutoPauseOnWifiChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    val selectedRole = if (csqttLinkMode) UsageRole.Participant else UsageRole.Owner
    val extraWorkersEnabled by settingsStore.extraWorkers.collectAsStateWithLifecycle(
        initialValue = SettingsStore.cachedExtraWorkers,
    )
    val vkAuthMode by settingsStore.vkAuthMode.collectAsStateWithLifecycle(
        initialValue = CsqttConstants.VkAuth.MODE_CALLS,
    )
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    var isExpanded by rememberSaveable { mutableStateOf(false) }
    var showAutoPauseInfo by rememberSaveable { mutableStateOf(false) }
    var showExtraWorkersInfo by rememberSaveable { mutableStateOf(false) }

    IconButton(
        onClick = { isExpanded = true },
        modifier = modifier.size(40.dp),
    ) {
        Icon(
            painter = painterResource(id = R.drawable.ic_more_smooth),
            contentDescription = stringResource(R.string.quick_settings),
            modifier = Modifier.size(30.dp),
            tint = Color.Unspecified,
        )
    }

    if (isExpanded) {
            Dialog(
                onDismissRequest = { isExpanded = false },
                properties = DialogProperties(usePlatformDefaultWidth = false)
            ) {
                Surface(
                    shape = CsqttShapes.Dialog,
                    color = MaterialTheme.colorScheme.surface,
                    shadowElevation = 8.dp,
                    tonalElevation = 4.dp,
                    modifier = Modifier.fillMaxWidth(0.9f)
                ) {
                    Column(
                        modifier = Modifier
                            .padding(16.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Настройки",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        IconButton(
                            onClick = { isExpanded = false },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = stringResource(R.string.action_close),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Text(
                        "Ваша роль использования",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    CsqttSegmentedControl(
                        options = listOf(
                            UsageRole.Owner to "Владелец",
                            UsageRole.Participant to "Участник",
                        ),
                        selected = selectedRole,
                        onSelected = { role ->
                            val participant = role == UsageRole.Participant
                            if (participant != csqttLinkMode) {
                                scope.launch { settingsStore.saveCsqttLinkMode(participant) }
                            }
                        },
                        modifier = Modifier
                            .padding(horizontal = 4.dp)
                            .height(CsqttSizes.CompactControlHeight),
                    )

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    CompactDropdownSetting(
                        title = "Профиль конфигурации",
                        selectedKey = activeProfile.toString(),
                        options = (CsqttConstants.Profiles.MIN_INDEX..CsqttConstants.Profiles.MAX_INDEX)
                            .map { profile -> profile.toString() to "Профиль $profile" },
                        enabled = true,
                        onSelected = { profile ->
                            profile.toIntOrNull()?.let(onActiveProfileChange)
                        },
                    )

                    CompactDropdownSetting(
                        title = "Отпечаток",
                        selectedKey = activeFingerprint,
                        options = listOf(
                            "chrome" to "Chrome",
                            "safari" to "Safari",
                            "firefox" to "Firefox",
                            "edge" to "Edge",
                            "opera" to "Opera",
                        ),
                        enabled = true,
                        onSelected = onFingerprintChange,
                    )

                    CompactDropdownSetting(
                        title = "Оформление",
                        selectedKey = currentTheme,
                        options = listOf(
                            CsqttConstants.Theme.MODE_SYSTEM to "Система",
                            CsqttConstants.Theme.MODE_LIGHT to "Светлая",
                            CsqttConstants.Theme.MODE_DARK to "Тёмная",
                        ),
                        enabled = true,
                        onSelected = onThemeChange,
                    )

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                    )

                    CsqttSettingRow(
                        title = "Автопауза при Wi-Fi",
                        checked = autoPauseOnWifi,
                        onCheckedChange = onAutoPauseOnWifiChange,
                        onInfoClick = { showAutoPauseInfo = true },
                        infoContentDescription = "Как работает автопауза при Wi-Fi",
                    )

                    if (vkAuthMode != CsqttConstants.VkAuth.MODE_AUTO_JS) {
                        CsqttSettingRow(
                            title = "Экстра потоки",
                            checked = extraWorkersEnabled == true,
                            enabled = !tunnelRunning,
                            onCheckedChange = { enabled ->
                                scope.launch { settingsStore.saveExtraWorkers(enabled) }
                            },
                            onInfoClick = { showExtraWorkersInfo = true },
                            infoContentDescription = "Информация об экстра потоках",
                        )
                    }
                }
            }
        }
    }

    if (showAutoPauseInfo) {
        WifiAutoPauseInfoDialog(onDismiss = { showAutoPauseInfo = false })
    }
    if (showExtraWorkersInfo) {
        ExtraWorkersInfoDialog(onDismiss = { showExtraWorkersInfo = false })
    }
}
