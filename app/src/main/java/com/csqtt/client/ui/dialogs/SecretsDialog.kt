// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.csqtt.client.SettingsStore
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecretsDialog(
    settingsStore: SettingsStore,
    initialPassword: String,
    onSaved: () -> Unit,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var passwordInput by rememberSaveable { mutableStateOf(initialPassword) }
    var passwordVisible by rememberSaveable { mutableStateOf(false) }

    Dialog(onDismissRequest = onDismiss) {
        AppDialogSurface {
            Column(
                modifier =
                    Modifier.padding(20.dp).fillMaxWidth().fadingVerticalScroll(rememberScrollState())
            ) {
                AppDialogHeader(
                    title = "Подключение",
                    onClose = onDismiss,
                    icon = {
                        Icon(
                            Icons.Default.Key,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                )

                Spacer(modifier = Modifier.height(16.dp))

                val isPasswordValid =
                    passwordInput.isNotEmpty() &&
                        passwordInput.matches(Regex("^[a-zA-Z0-9_.!?:#/-]+$"))

                OutlinedTextField(
                    value = passwordInput,
                    onValueChange = { passwordInput = it.filter { c -> !c.isWhitespace() } },
                    label = {
                        Text(
                            "Пароль туннеля",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    placeholder = {
                        Text(
                            "укажите пароль",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    singleLine = true,
                    isError = !isPasswordValid,
                    supportingText =
                        if (passwordInput.isNotEmpty() && !isPasswordValid) {
                            {
                                Text(
                                    "Разрешены только буквы, цифры и знаки . ! ? : # - _ /",
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        } else null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = CsqttShapes.Control,
                    visualTransformation =
                        if (passwordVisible) VisualTransformation.None
                        else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector =
                                    if (passwordVisible) Icons.Outlined.VisibilityOff
                                    else Icons.Outlined.Visibility,
                                contentDescription =
                                    if (passwordVisible) "Скрыть пароль" else "Показать пароль",
                            )
                        }
                    },
                )

                Spacer(modifier = Modifier.height(20.dp))

                Button(
                    onClick = {
                        scope.launch {
                            settingsStore.saveConnectionPassword(passwordInput)
                            onSaved()
                            onDismiss()
                        }
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
