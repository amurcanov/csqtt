// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.dialogs

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.csqtt.client.R
import com.csqtt.client.showRaisedToast
import com.csqtt.client.ui.design.CsqttShapes

private const val GRAM_TON_WALLET = "UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7"
private const val USDT_TON_WALLET = "UQCsHSj_Bev5AG3vCz-84TQC7BSWjNdNdOjP9M2gWUEmbyD7"
private const val USDT_TRC20_WALLET = "TD1oiQiHmjqsRDPxfUjUbSWxEmcr4k7Lob"

private fun copyAddressToClipboard(context: Context, label: String, address: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText(label, address))
    context.showRaisedToast("Адрес скопирован", Toast.LENGTH_SHORT)
}

@Composable
fun CryptoDonateDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        AppDialogSurface(modifier = Modifier.fillMaxWidth(0.9f)) {
            Column(
                modifier =
                    Modifier.fillMaxWidth().padding(20.dp).fadingVerticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                AppDialogHeader(
                    title = "Поддержать криптовалютой",
                    onClose = onDismiss,
                    icon = {
                        Icon(
                            painterResource(R.drawable.ic_crypto_logo),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                )

                CryptoAddressField(
                    title = "GRAM",
                    instruction = "Перевод Gram в сети TON на криптокошелек:",
                    address = GRAM_TON_WALLET,
                    onCopy = { copyAddressToClipboard(context, "Gram Address", GRAM_TON_WALLET) },
                )

                CryptoAddressField(
                    title = "USDT TON",
                    instruction = "Перевод USDT в сети TON на криптокошелек:",
                    address = USDT_TON_WALLET,
                    onCopy = {
                        copyAddressToClipboard(context, "USDT TON Address", USDT_TON_WALLET)
                    },
                )

                CryptoAddressField(
                    title = "USDT TRC20",
                    instruction = "Перевод USDT в сети TRC20 на криптокошелек:",
                    address = USDT_TRC20_WALLET,
                    onCopy = {
                        copyAddressToClipboard(context, "USDT TRC20 Address", USDT_TRC20_WALLET)
                    },
                )

                Spacer(modifier = Modifier.height(4.dp))

                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = CsqttShapes.Pill,
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                ) {
                    Text(
                        text = "Хорошо",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun CryptoAddressField(
    title: String,
    instruction: String,
    address: String,
    onCopy: () -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = instruction,
            style = MaterialTheme.typography.bodySmall,
            color = colors.onSurfaceVariant,
            lineHeight = 18.sp,
        )

        Surface(
            shape = CsqttShapes.Control,
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
            border =
                BorderStroke(1.dp, colors.outlineVariant.copy(alpha = if (isDark) 0.35f else 0.5f)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier =
                    Modifier.fillMaxWidth()
                        .padding(start = 14.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SelectionContainer(modifier = Modifier.weight(1f)) {
                    Text(
                        text = address,
                        style =
                            MaterialTheme.typography.bodySmall.copy(
                                fontSize = 12.5.sp,
                                lineHeight = 17.sp,
                                fontWeight = FontWeight.Medium,
                            ),
                        fontFamily = FontFamily.Monospace,
                        color = colors.onSurface,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                Surface(
                    shape = CsqttShapes.Pill,
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                    contentColor = MaterialTheme.colorScheme.primary,
                    modifier =
                        Modifier.size(42.dp).clip(CsqttShapes.Pill).clickable(onClick = onCopy),
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.ContentCopy,
                            contentDescription = "Скопировать",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
        }
    }
}
