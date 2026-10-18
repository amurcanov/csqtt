// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LocalMinimumInteractiveComponentSize
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalViewConfiguration
import androidx.compose.ui.platform.ViewConfiguration
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes

private const val PRIVATE_KEY_PLACEHOLDER =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"

private const val CERTIFICATE_PLACEHOLDER =
    "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5...\nuser-cert"

private val SshKeyFieldShape = CsqttShapes.Control

private val PRIVATE_KEY_HEADERS =
    listOf(
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    )

internal fun validateSshPrivateKey(value: String, passphrase: String): String? {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return "Не удалось распознать приватный SSH-ключ"
    if ("BEGIN CERTIFICATE" in trimmed && PRIVATE_KEY_HEADERS.none { it in trimmed }) {
        return "Это X.509/TLS-сертификат. Для SSH требуется приватный SSH-ключ или сертификат OpenSSH вида ssh-*-cert-v01@openssh.com."
    }
    if (trimmed.startsWith("ssh-") && !trimmed.contains("-----BEGIN")) {
        return "Вставлен публичный ключ, но требуется приватный"
    }
    if (PRIVATE_KEY_HEADERS.none { it in trimmed }) {
        return "Не удалось распознать приватный SSH-ключ"
    }
    val looksEncrypted = "ENCRYPTED" in trimmed || "aes256-ctr" in trimmed || "bcrypt" in trimmed
    if (looksEncrypted && passphrase.isBlank()) {
        return "Ключ зашифрован. Укажите пароль ключа."
    }
    return null
}

internal fun validateSshCertificate(value: String): String? {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return null
    if ("BEGIN CERTIFICATE" in trimmed) {
        return "Это X.509/TLS-сертификат. Для SSH требуется сертификат OpenSSH вида ssh-*-cert-v01@openssh.com."
    }
    if (!trimmed.contains("-cert-") || !trimmed.contains("@openssh.com")) {
        return "Сертификат должен быть вида ssh-*-cert-v01@openssh.com"
    }
    return null
}

@Composable
internal fun SshKeysDialog(
    initialPrivateKey: String,
    initialPassphrase: String,
    initialCertificate: String,
    onSave: (String, String, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var privateKey by rememberSaveable { mutableStateOf(initialPrivateKey) }
    var passphrase by rememberSaveable { mutableStateOf(initialPassphrase) }
    var certificate by rememberSaveable { mutableStateOf(initialCertificate) }
    var privateKeyVisible by rememberSaveable { mutableStateOf(false) }
    var passphraseVisible by rememberSaveable { mutableStateOf(false) }
    var privateKeyError by rememberSaveable { mutableStateOf<String?>(null) }
    var certificateError by rememberSaveable { mutableStateOf<String?>(null) }

    Dialog(onDismissRequest = onDismiss) {
        AppDialogSurface {
            Column(
                modifier =
                    Modifier.padding(20.dp).fillMaxWidth().fadingVerticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                AppDialogHeader(
                    title = "Ключи SSH",
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

                Text(
                    text =
                        "Для входа достаточно одного приватного ключа — приложение само определит его формат. Пароль и сертификат нужны только если ключ зашифрован или используется сертификат OpenSSH.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                SshPrivateKeyField(
                    value = privateKey,
                    onValueChange = {
                        privateKey = it
                        privateKeyError = null
                    },
                    visible = privateKeyVisible,
                    onVisibilityChange = { privateKeyVisible = !privateKeyVisible },
                    errorMessage = privateKeyError,
                )

                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it.filter { c -> !c.isWhitespace() } },
                    label = {
                        Text(
                            "Пароль ключа (необязательно)",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    placeholder = {
                        Text(
                            "если приватный ключ зашифрован",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = SshKeyFieldShape,
                    visualTransformation =
                        if (passphraseVisible) VisualTransformation.None
                        else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        IconButton(onClick = { passphraseVisible = !passphraseVisible }) {
                            Icon(
                                imageVector =
                                    if (passphraseVisible) Icons.Outlined.VisibilityOff
                                    else Icons.Outlined.Visibility,
                                contentDescription =
                                    if (passphraseVisible) "Скрыть пароль" else "Показать пароль",
                            )
                        }
                    },
                )

                OutlinedTextField(
                    value = certificate,
                    onValueChange = {
                        certificate = it
                        certificateError = null
                    },
                    label = {
                        Text(
                            "SSH-сертификат OpenSSH (необязательно)",
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    placeholder = {
                        Text(
                            CERTIFICATE_PLACEHOLDER,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                        )
                    },
                    supportingText =
                        if (certificateError != null) {
                            { Text(certificateError!!, color = MaterialTheme.colorScheme.error) }
                        } else null,
                    isError = certificateError != null,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 90.dp),
                    shape = SshKeyFieldShape,
                    textStyle =
                        MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Default),
                )

                Button(
                    onClick = {
                        val keyError = validateSshPrivateKey(privateKey, passphrase)
                        val certError = validateSshCertificate(certificate)
                        privateKeyError = keyError
                        certificateError = certError
                        if (keyError == null && certError == null) {
                            onSave(privateKey.trim(), passphrase.trim(), certificate.trim())
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

@Composable
private fun SshPrivateKeyField(
    value: String,
    onValueChange: (String) -> Unit,
    visible: Boolean,
    onVisibilityChange: () -> Unit,
    errorMessage: String?,
) {
    val labelTopPadding = with(LocalDensity.current) {
        MaterialTheme.typography.bodySmall.lineHeight.toDp() / 2
    }
    val viewConfiguration = LocalViewConfiguration.current
    val buttonViewConfiguration = remember(viewConfiguration) {
        object : ViewConfiguration by viewConfiguration {
            override val minimumTouchTargetSize = DpSize(28.dp, 28.dp)
        }
    }

    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth()
                .padding(top = 24.dp - labelTopPadding)
                .heightIn(min = 140.dp),
            label = {
                Text(
                    "Приватный SSH-ключ *",
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            placeholder = {
                Text(PRIVATE_KEY_PLACEHOLDER, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            },
            supportingText = {
                Text(
                    text = errorMessage ?: "Поддерживаются OpenSSH, RSA PEM, EC и PKCS#8",
                    color = if (errorMessage != null) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            isError = errorMessage != null,
            shape = SshKeyFieldShape,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            visualTransformation = if (visible) VisualTransformation.None
                else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Default,
            ),
        )
        CompositionLocalProvider(
            LocalViewConfiguration provides buttonViewConfiguration,
            LocalMinimumInteractiveComponentSize provides 28.dp,
        ) {
            IconButton(
                onClick = onVisibilityChange,
                modifier = Modifier.align(Alignment.TopEnd)
                    .padding(top = 10.dp, end = 18.dp)
                    .size(28.dp),
            ) {
                Icon(
                    imageVector = if (visible) Icons.Outlined.VisibilityOff
                        else Icons.Outlined.Visibility,
                    contentDescription = if (visible) "Скрыть приватный ключ"
                        else "Показать приватный ключ",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.background(appDialogContainerColor())
                        .padding(horizontal = 4.dp)
                        .size(18.dp),
                )
            }
        }
    }
}
