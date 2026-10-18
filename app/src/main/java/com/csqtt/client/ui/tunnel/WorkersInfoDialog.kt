// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.tunnel

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
internal fun WorkersInfoDialog(onDismiss: () -> Unit) {
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
                    "Настройка потоков",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text =
                        """
                        • Каждый поток TURN имеет скорость около 2 Мбит/с.
                        • Имейте в виду: лучше выбирать количество потоков исходя из реальной скорости вашего интернет-подключения, а не больше его максимума:
                          — 18 потоков: для скорости 35–45 Мбит/с
                          — 27 потоков: для скорости 50–60 Мбит/с
                          — 45 потоков: для скорости 90–100 Мбит/с
                          — и далее по нарастающей.
                        """
                            .trimIndent(),
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

@Composable
internal fun ExtraWorkersInfoDialog(onDismiss: () -> Unit) {
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
                    "Экстра потоки",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text =
                        """
                        • Данная функция позволяет расширить максимальный выбор потоков с 72 до 126.
                        • Значения выбираются кратно 9 потокам, поэтому верхний рабочий шаг — 126.
                        """
                            .trimIndent(),
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
