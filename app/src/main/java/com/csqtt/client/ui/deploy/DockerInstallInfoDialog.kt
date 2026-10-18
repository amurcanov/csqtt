// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.dialogs.AppDialogSurface

@Composable
internal fun DockerInstallInfoDialog(onDismiss: () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        AppDialogSurface(modifier = Modifier.fillMaxWidth(0.9f)) {
            Column(
                modifier = Modifier.padding(20.dp).fadingVerticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    "Установка в Docker",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text =
                        "Если включено, CSQTT устанавливается и запускается в отдельном Docker-контейнере вместо службы csqtt.service. Если Docker отсутствует, установщик загрузит актуальную стабильную версию и запустит Docker автоматически.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 20.sp,
                )
                Text(
                    text =
                        "Для максимальной совместимости контейнер запускается в privileged-режиме, использует сеть VPS и /dev/net/tun. Это открывает контейнеру доступ к возможностям ядра и устройствам VPS, включая io_uring и netfilter, но заметно ослабляет изоляцию Docker.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 20.sp,
                )
                Text(
                    text =
                        "Конфигурация и база клиентов остаются на VPS в /etc/csqtt и используются одинаково в Docker и systemd. Контейнер автоматически запускается после перезагрузки. Включайте этот режим только на доверенном VPS, где вы принимаете риск расширенных прав контейнера.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 20.sp,
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = CsqttShapes.Pill,
                    colors =
                        ButtonDefaults.buttonColors(
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        ),
                ) {
                    Text("Понятно", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
