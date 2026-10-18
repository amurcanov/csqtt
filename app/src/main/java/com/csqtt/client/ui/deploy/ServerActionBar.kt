// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.Crossfade
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Language
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.csqtt.client.ui.design.CsqttShapes

@Composable
internal fun ServerActionBar(
    state: DeployUiState,
    onAction: (DeployAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(
            onClick = { onAction(DeployAction.EditAuthorization) },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = CsqttShapes.Pill,
            colors =
                ButtonDefaults.outlinedButtonColors(
                    containerColor =
                        if (state.authorizationConfigured) MaterialTheme.colorScheme.surface
                        else MaterialTheme.colorScheme.errorContainer,
                    contentColor =
                        if (state.authorizationConfigured) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onErrorContainer,
                ),
            border =
                BorderStroke(
                    1.dp,
                    if (state.authorizationConfigured)
                        MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
                    else MaterialTheme.colorScheme.error,
                ),
            contentPadding = PaddingValues(horizontal = 8.dp),
        ) {
            Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text("Авторизация", fontWeight = FontWeight.Bold, maxLines = 1)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = { onAction(DeployAction.Install) },
                enabled = !state.isDeploying,
                modifier = Modifier.weight(1f).height(52.dp),
                shape = CsqttShapes.Pill,
                contentPadding = PaddingValues(horizontal = 8.dp),
                elevation =
                    ButtonDefaults.buttonElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp,
                    ),
            ) {
                Crossfade(
                    targetState = state.isDeploying,
                    animationSpec = tween(180),
                    modifier = Modifier.size(18.dp),
                    label = "deploy_install_icon",
                ) { deploying ->
                    if (deploying) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(
                            Icons.Default.Download,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
                Spacer(Modifier.width(6.dp))
                AnimatedContent(
                    targetState = if (state.isDeploying) "Установка…" else "Установить",
                    transitionSpec = { fadeIn(tween(180)) togetherWith fadeOut(tween(100)) },
                    label = "deploy_install_label",
                ) { label ->
                    Text(
                        label,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                    )
                }
            }
            Button(
                onClick = { onAction(DeployAction.Uninstall) },
                enabled = !state.isDeploying && state.canUninstall,
                modifier = Modifier.weight(1f).height(52.dp),
                shape = CsqttShapes.Pill,
                contentPadding = PaddingValues(horizontal = 8.dp),
                colors =
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                elevation =
                    ButtonDefaults.buttonElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp,
                    ),
            ) {
                Icon(
                    Icons.Default.Delete,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text("Удалить", fontWeight = FontWeight.Bold, maxLines = 1)
            }
        }
        OutlinedButton(
            onClick = { onAction(DeployAction.OpenControlPanel) },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = CsqttShapes.Pill,
            colors =
                ButtonDefaults.outlinedButtonColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                ),
            contentPadding = PaddingValues(horizontal = 4.dp),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
        ) {
            Icon(Icons.Default.Language, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(
                "Панель",
                fontWeight = FontWeight.Bold,
                maxLines = 1,
            )
            IconButton(
                onClick = { onAction(DeployAction.PanelInfo) },
                modifier = Modifier.size(34.dp),
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                    contentDescription = "Информация о панели",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
            }
        }
    }
}
