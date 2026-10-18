// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.csqtt.client.AppReleaseInfo
import com.csqtt.client.RemoteVersionSource
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.dialogs.AppDialogHeader
import com.csqtt.client.ui.dialogs.AppDialogSurface

@Composable
fun AppUpdateDialog(
    release: AppReleaseInfo,
    onPostpone: () -> Unit,
    onUpdate: () -> Unit,
) {
    val isTagOnly = release.source == RemoteVersionSource.Tag
    val title = if (isTagOnly) "Найден новый tag" else "Доступно обновление"
    val description =
        if (isTagOnly) {
            "На GitHub обнаружен более новый tag ${release.versionTag}. Похоже, опубликованный release ещё не догнал его."
        } else {
            "Вышла новая версия приложения ${release.versionTag}. Можно открыть страницу релиза и обновиться вручную."
        }

    Dialog(
        onDismissRequest = {},
        properties =
            DialogProperties(
                usePlatformDefaultWidth = false,
                dismissOnBackPress = false,
                dismissOnClickOutside = false,
            ),
    ) {
        AppDialogSurface(modifier = Modifier.fillMaxWidth(0.92f)) {
            Column(
                modifier =
                    Modifier.fillMaxWidth().padding(20.dp).fadingVerticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                AppDialogHeader(
                    title = title,
                    subtitle = release.versionTag,
                    icon = {
                        Icon(
                            Icons.Default.Update,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                )

                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 20.sp,
                )

                HorizontalDivider(
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedButton(
                        onClick = onPostpone,
                        modifier = Modifier.weight(1f).height(50.dp),
                        shape = CsqttShapes.Pill,
                    ) {
                        Text("Позже", fontWeight = FontWeight.SemiBold)
                    }

                    Button(
                        onClick = onUpdate,
                        modifier = Modifier.weight(1f).height(50.dp),
                        shape = CsqttShapes.Pill,
                    ) {
                        Text("Обновить", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
