// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes

private const val PRIVATE_KEY_PLACEHOLDER =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"

private const val CERTIFICATE_PLACEHOLDER =
    "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5...\nuser-cert"

private val SshKeyFieldShape = RoundedCornerShape(8.dp)

private val PRIVATE_KEY_HEADERS = listOf(
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
    var passphraseVisible by rememberSaveable { mutableStateOf(false) }
    var privateKeyError by rememberSaveable { mutableStateOf<String?>(null) }
    var certificateError by rememberSaveable { mutableStateOf<String?>(null) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = CsqttShapes.Dialog,
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 8.dp,
        ) {
            Column(
                modifier = Modifier
                    .padding(24.dp)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Key,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Ключи SSH", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть")
                    }
                }

                Text(
                    text = "Для входа достаточно одного приватного ключа — приложение само определит его формат. Пароль и сертификат нужны только если ключ зашифрован или используется сертификат OpenSSH.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                OutlinedTextField(
                    value = privateKey,
                    onValueChange = {
                        privateKey = it
                        privateKeyError = null
                    },
                    label = { Text("Приватный SSH-ключ *", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    placeholder = { Text(PRIVATE_KEY_PLACEHOLDER, fontFamily = FontFamily.Monospace, fontSize = 12.sp) },
                    supportingText = {
                        Text(
                            text = privateKeyError ?: "Поддерживаются OpenSSH, RSA PEM, EC и PKCS#8",
                            color = if (privateKeyError != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    },
                    isError = privateKeyError != null,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp),
                    shape = SshKeyFieldShape,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Default),
                )

                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it.filter { c -> !c.isWhitespace() } },
                    label = { Text("Пароль ключа (необязательно)", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    placeholder = { Text("если приватный ключ зашифрован", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = SshKeyFieldShape,
                    visualTransformation = if (passphraseVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        IconButton(onClick = { passphraseVisible = !passphraseVisible }) {
                            Icon(
                                imageVector = if (passphraseVisible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                contentDescription = if (passphraseVisible) "Скрыть пароль" else "Показать пароль",
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
                    label = { Text("SSH-сертификат OpenSSH (необязательно)", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                    placeholder = { Text(CERTIFICATE_PLACEHOLDER, fontFamily = FontFamily.Monospace, fontSize = 12.sp) },
                    supportingText = if (certificateError != null) {
                        { Text(certificateError!!, color = MaterialTheme.colorScheme.error) }
                    } else null,
                    isError = certificateError != null,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 90.dp),
                    shape = SshKeyFieldShape,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
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
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary),
                ) {
                    Text("Сохранить", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
