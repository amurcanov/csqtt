// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.csqtt.client.VkHashValidationCodec
import com.csqtt.client.VkHashValidationStatus
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes
import com.csqtt.client.ui.utils.stripVkUrlStatic
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HashesDialog(
    hash1: String,
    hash2: String,
    hash3: String,
    hash4: String,
    hash5: String,
    hash6: String,
    validationResults: Map<String, VkHashValidationStatus>,
    onValidationResultsChange: (Map<String, VkHashValidationStatus>) -> Unit,
    onCheck: suspend (List<String>) -> Map<String, VkHashValidationStatus>,
    onSave: (String, String, String, String, String, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var h1 by remember { mutableStateOf(hash1) }
    var h2 by remember { mutableStateOf(hash2) }
    var h3 by remember { mutableStateOf(hash3) }
    var h4 by remember { mutableStateOf(hash4) }
    var h5 by remember { mutableStateOf(hash5) }
    var h6 by remember { mutableStateOf(hash6) }
    var results by remember(validationResults) { mutableStateOf(validationResults) }
    var isChecking by remember { mutableStateOf(false) }
    var unavailableCount by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    val hashes = listOf(h1, h2, h3, h4, h5, h6)
    val validBorder = if (isSystemInDarkTheme()) Color(0xFF66BB6A) else Color(0xFF2E7D32)

    fun updateHash(index: Int, raw: String) {
        val cleaned = stripVkUrlStatic(raw.filter { it != ' ' && it != '\n' && it != '\r' })
        val previous = hashes[index]
        if (cleaned == previous) return
        if (results.containsKey(previous)) {
            val updatedResults = VkHashValidationCodec.invalidate(results, previous)
            results = updatedResults
            onValidationResultsChange(updatedResults)
        }
        unavailableCount = 0
        when (index) {
            0 -> h1 = cleaned
            1 -> h2 = cleaned
            2 -> h3 = cleaned
            3 -> h4 = cleaned
            4 -> h5 = cleaned
            5 -> h6 = cleaned
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        AppDialogSurface {
            Column(
                modifier =
                    Modifier.padding(20.dp).fillMaxWidth().fadingVerticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                AppDialogHeader(
                    title = "VK Хеши",
                    onClose = onDismiss,
                    icon = {
                        Icon(
                            Icons.Default.Tag,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                )

                Text(
                    text = "Больше хешей — выше лимит потоков и лучшее распределение нагрузки.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 4.dp),
                )

                hashes.forEachIndexed { idx, value ->
                    val label = if (idx == 0) "VK Хеш 1 *" else "VK Хеш ${idx + 1}"
                    val isShort = value.isNotBlank() && value.length < 16
                    val status = results[value]
                    val isInvalid = status == VkHashValidationStatus.Invalid
                    val fieldColors =
                        if (status == VkHashValidationStatus.Valid) {
                            OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = validBorder,
                                unfocusedBorderColor = validBorder,
                            )
                        } else {
                            OutlinedTextFieldDefaults.colors()
                        }
                    OutlinedTextField(
                        value = value,
                        onValueChange = { updateHash(idx, it) },
                        label = {
                            Text(
                                label,
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        placeholder = {
                            Text(
                                "Ссылка звонка или хеш",
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        singleLine = true,
                        enabled = !isChecking,
                        isError = isShort || isInvalid,
                        supportingText =
                            if (isShort) {
                                {
                                    Text(
                                        "Хеш ${idx + 1} — короткий (мин. 16)",
                                        color = MaterialTheme.colorScheme.error,
                                    )
                                }
                            } else null,
                        trailingIcon = {
                            IconButton(
                                onClick = { updateHash(idx, "") },
                                enabled = value.isNotEmpty(),
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Delete,
                                    contentDescription = "Удалить хеш ${idx + 1}",
                                    tint =
                                        MaterialTheme.colorScheme.error.copy(
                                            alpha = if (value.isNotEmpty()) 1f else 0.38f
                                        ),
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = CsqttShapes.Control,
                        colors = fieldColors,
                    )
                }

                val pendingHashes = VkHashValidationCodec.pending(hashes, results)
                OutlinedButton(
                    onClick = {
                        isChecking = true
                        unavailableCount = 0
                        scope.launch {
                            val checked = onCheck(pendingHashes)
                            val updatedResults = results + checked
                            results = updatedResults
                            onValidationResultsChange(updatedResults)
                            unavailableCount = pendingHashes.size - checked.size
                            isChecking = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = CsqttSizes.ControlHeight),
                    enabled = !isChecking && pendingHashes.isNotEmpty(),
                    shape = CsqttShapes.Control,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary),
                    colors =
                        ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.primary
                        ),
                ) {
                    Text(
                        if (isChecking) "Проверяем..." else "Проверить актив",
                        fontWeight = FontWeight.SemiBold,
                    )
                }

                if (unavailableCount > 0) {
                    Text(
                        "Не удалось проверить: $unavailableCount. Поля оставлены без статуса.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                Button(
                    onClick = {
                        onSave(h1, h2, h3, h4, h5, h6)
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = CsqttSizes.ControlHeight),
                    shape = CsqttShapes.Control,
                    colors =
                        ButtonDefaults.buttonColors(
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        ),
                ) {
                    Text("Сохранить", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
