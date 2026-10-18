// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UninstallConfirmDialog(onDismiss: () -> Unit, onConfirm: () -> Unit) {
    var confirmText by remember { mutableStateOf("") }
    val isConfirmed = confirmText.trim().lowercase() == "да"

    Dialog(onDismissRequest = onDismiss) {
        AppDialogSurface {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    "Удаление CSQTT с сервера",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error,
                )
                Text(
                    "Будут удалены: бинарник, systemd-сервис, бот, конфигурация CSQTT и только помеченные правила firewall/NAT для CSQTT.\n\nЭто действие необратимо.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = confirmText,
                    onValueChange = { confirmText = it },
                    label = {
                        Text(
                            "Введите «да» для подтверждения",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = CsqttShapes.Control,
                    colors =
                        OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.error,
                            focusedLabelColor = MaterialTheme.colorScheme.error,
                            unfocusedLabelColor = MaterialTheme.colorScheme.error,
                            cursorColor = MaterialTheme.colorScheme.error,
                            unfocusedBorderColor =
                                MaterialTheme.colorScheme.error.copy(alpha = 0.6f),
                        ),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f).heightIn(min = CsqttSizes.ControlHeight),
                        shape = CsqttShapes.Control,
                        colors =
                            ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.onSurface
                            ),
                    ) {
                        Text("Отмена")
                    }
                    Button(
                        onClick = onConfirm,
                        modifier = Modifier.weight(1f).heightIn(min = CsqttSizes.ControlHeight),
                        shape = CsqttShapes.Control,
                        enabled = isConfirmed,
                        colors =
                            ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error,
                                contentColor = MaterialTheme.colorScheme.onError,
                            ),
                    ) {
                        Icon(Icons.Default.Delete, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Удалить", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
