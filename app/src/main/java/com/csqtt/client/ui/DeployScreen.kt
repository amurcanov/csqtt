// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.res.Configuration
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.csqtt.client.CsqttConstants
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.components.CsqttSettingRow
import com.csqtt.client.ui.components.ExpandableContent
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSpacing

@Composable
internal fun DeployScreen(
    state: DeployUiState,
    onAction: (DeployAction) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    val scrollState = rememberScrollState()

    CsqttScreen(
        modifier = modifier,
    ) {
        Box(modifier = Modifier.fillMaxWidth().weight(1f)) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .fadingVerticalScroll(scrollState),
            ) {
                AppSectionCard(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                    Text("Деплой и SSH", style = MaterialTheme.typography.titleMedium, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                    Spacer(Modifier.height(16.dp))
                    DeployTextField(
                        value = state.host,
                        onValueChange = { onAction(DeployAction.HostChanged(it)) },
                        label = "IP сервера или домен",
                        placeholder = "1.2.3.4",
                        enabled = !state.isDeploying,
                        isError = state.host.isBlank(),
                        keyboardType = KeyboardType.Uri,
                    )
                    Spacer(Modifier.height(16.dp))
                    DeployCredentialsFields(state = state, onAction = onAction)
                    ExpandableContent(
                        visible = state.sshKeysMode,
                        spacing = CsqttSpacing.Md,
                    ) {
                        OutlinedButton(
                            onClick = { onAction(DeployAction.EditSshKeys) },
                            enabled = !state.isDeploying && state.sshKeysMode,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = CsqttShapes.Pill,
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                contentColor = MaterialTheme.colorScheme.onSurface,
                            ),
                            border = BorderStroke(
                                1.dp,
                                if (state.sshKeysFilled < 1) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f),
                            ),
                        ) {
                            Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Ключи SSH ${state.sshKeysFilled}/1", fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold, maxLines = 1)
                        }
                    }
                    ExpandableContent(
                        visible = state.manualPorts,
                        spacing = CsqttSpacing.Md,
                    ) {
                        ManualPortFields(state = state, onAction = onAction)
                    }
                    Spacer(Modifier.height(16.dp))
                    Column {
                        CsqttSettingRow(
                            title = "Ключи SSH",
                            checked = state.sshKeysMode,
                            enabled = !state.isDeploying,
                            onCheckedChange = { onAction(DeployAction.SshKeysModeChanged(it)) },
                        )
                        CsqttSettingRow(
                            title = "Ручные порты",
                            checked = state.manualPorts,
                            enabled = !state.isDeploying,
                            onCheckedChange = { onAction(DeployAction.ManualPortsChanged(it)) },
                        )
                        CsqttSettingRow(
                            title = "Установить в Docker",
                            checked = state.dockerInstall,
                            enabled = !state.isDeploying,
                            onCheckedChange = { onAction(DeployAction.DockerInstallChanged(it)) },
                            onInfoClick = { onAction(DeployAction.DockerInfo) },
                            infoContentDescription = "О Docker-установке",
                        )
                    }
                }

                ExpandableContent(
                    visible = state.isDeploying,
                    spacing = CsqttSpacing.Md,
                ) {
                    DeployProgressCard(
                        progress = state.progress,
                        currentStep = state.currentStep,
                    )
                }

                ServerActionBar(
                    state = state,
                    onAction = onAction,
                    modifier = Modifier.fillMaxWidth().padding(top = CsqttSpacing.Md),
                )
            }

            SnackbarHost(
                hostState = snackbarHostState,
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 72.dp),
            )
        }
    }
}

@Composable
private fun DeployCredentialsFields(
    state: DeployUiState,
    onAction: (DeployAction) -> Unit,
) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(CsqttSpacing.Sm),
        ) {
            DeployTextField(
                value = state.sshLogin,
                onValueChange = { onAction(DeployAction.LoginChanged(it)) },
                label = "Логин SSH",
                enabled = !state.isDeploying,
                isError = state.sshLogin.isBlank(),
                imeAction = ImeAction.Next,
                modifier = Modifier.weight(1f),
            )
            if (!state.sshKeysMode) {
                DeployPasswordField(
                    value = state.sshPassword,
                    onValueChange = { onAction(DeployAction.PasswordChanged(it)) },
                    label = "Пароль SSH",
                    enabled = !state.isDeploying,
                    isError = state.sshPassword.isBlank(),
                    modifier = Modifier.weight(1f),
                )
            }
        }
        ExpandableContent(visible = state.showSudoPassword, spacing = CsqttSpacing.Md) {
            DeployPasswordField(
                value = state.sudoPassword,
                onValueChange = { onAction(DeployAction.SudoPasswordChanged(it)) },
                label = "Пароль sudo",
                placeholder = "необязательно",
                enabled = !state.isDeploying && state.showSudoPassword,
            )
        }
    }
}

@Composable
private fun ManualPortFields(
    state: DeployUiState,
    onAction: (DeployAction) -> Unit,
) {
    val textMeasurer = rememberTextMeasurer()
    val density = LocalDensity.current
    val labelStyle = MaterialTheme.typography.bodySmall
    val sshLabel = "SSH-порт"
    val peerLabel = "Порт туннеля"
    val webLabel = "Порт WEB-панели"
    val portValueWidth = textMeasurer.measure("65535", MaterialTheme.typography.bodyLarge).size.width
    fun fieldWidth(label: String) = with(density) {
        maxOf(textMeasurer.measure(label, labelStyle).size.width, portValueWidth).toDp()
    } + 24.dp
    val sshPortWidth = fieldWidth(sshLabel)
    val peerPortWidth = fieldWidth(peerLabel)
    val webPortWidth = fieldWidth(webLabel)
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(CsqttSpacing.Sm),
    ) {
        DeployTextField(
            value = state.sshPort,
            onValueChange = { onAction(DeployAction.SshPortChanged(it)) },
            label = sshLabel,
            labelStyle = labelStyle,
            placeholder = "22",
            enabled = !state.isDeploying && state.manualPorts,
            isError = state.showValidation && !isValidPort(state.sshPort),
            keyboardType = KeyboardType.Number,
            modifier = Modifier.width(sshPortWidth),
        )
        DeployTextField(
            value = state.peerPort,
            onValueChange = { onAction(DeployAction.PeerPortChanged(it)) },
            label = peerLabel,
            labelStyle = labelStyle,
            placeholder = "46000",
            enabled = !state.isDeploying && state.manualPorts,
            isError = state.showValidation && !isValidPort(state.peerPort),
            keyboardType = KeyboardType.Number,
            modifier = Modifier.weight(peerPortWidth.value),
        )
        DeployTextField(
            value = state.webPort,
            onValueChange = { onAction(DeployAction.WebPortChanged(it)) },
            label = webLabel,
            labelStyle = labelStyle,
            placeholder = "46002",
            enabled = !state.isDeploying && state.manualPorts,
            isError = state.showValidation && !isValidPort(state.webPort),
            keyboardType = KeyboardType.Number,
            modifier = Modifier.weight(webPortWidth.value),
        )
    }
}

@Composable
private fun DeployProgressCard(
    progress: Float,
    currentStep: String,
) {
    val animatedProgress by animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        animationSpec = if (progress <= 0.01f) snap() else tween(durationMillis = 320, easing = FastOutSlowInEasing),
        label = "deploy_progress",
    )

    AppSectionCard(verticalArrangement = Arrangement.spacedBy(CsqttSpacing.Xs)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(CsqttSpacing.Md),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = currentStep.ifBlank { "Подготовка…" },
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "${(animatedProgress * 100).toInt()}%",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        LinearProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Preview(name = "Deploy compact", widthDp = 360, heightDp = 800, showBackground = true)
@Preview(name = "Deploy dark", widthDp = 720, heightDp = 900, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun DeployScreenPreview() {
    com.csqtt.client.CSQTTTheme(themeMode = CsqttConstants.Theme.MODE_DARK) {
        DeployScreen(
            state = DeployUiState(
                host = "vpn.example.com",
                sshLogin = "root",
                sshPassword = "password",
                mainPasswordConfigured = true,
                webPanelConfigured = true,
            ),
            onAction = {},
        )
    }
}
