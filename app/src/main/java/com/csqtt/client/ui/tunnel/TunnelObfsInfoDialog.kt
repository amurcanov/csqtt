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
internal fun ObfsInfoDialog(mode: String? = null, onDismiss: () -> Unit) {
    val (title, text) =
        when (mode) {
            "audio" ->
                "Режим «Простая» (audio)" to
                    """
                    • RTP-пакеты с версией 2, тип полезной нагрузки 111 (обычно Opus аудио).
                    • Заголовок содержит расширения с полями abs-send-time и transport sequence.
                    • Полезная нагрузка шифруется алгоритмом ChaCha20-Poly1305 со встроенным тегом аутентификации Poly1305.
                    • Дополняется случайным паддингом до 24 байт.

                    На проводе виден стандартный RTP-пакет, но шифрование и отсутствие HMAC отличают его от стандартного SRTP.
                    """
                        .trimIndent()
            "video" ->
                "Режим «Средняя» (video)" to
                    """
                    • RTP-пакеты с версией 2, тип полезной нагрузки 96 (обычно VP8/H.264 видео).
                    • Заголовок с расширениями аналогичен режиму audio.
                    • Шифрование полезной нагрузки — AES-128-CTR, отдельный ключ.
                    • В конце пакета добавляется аутентификационный тег HMAC-SHA1 длиной 10 байт, что полностью соответствует спецификации SRTP.
                    • Дополняется случайным паддингом до 60 байт.

                    На проводе полезная нагрузка имеет формат, близкий к защищённому видеопотоку SRTP. Этот режим не подменяет TLS SNI или сертификаты TURN.
                    """
                        .trimIndent()
            else ->
                "Маскировка трафика" to
                    """
                    • По умолчанию используется «Средняя» маскировка.
                    • Разница в потреблении ресурсов у «Простой» маскировки очень маленькая, но «Средняя» на проводе выглядит более реалистично как медиа-поток SRTP (защищённый видеозвонок WebRTC).
                    • Разницы в скорости или задержках вы в целом можете не увидеть.
                    """
                        .trimIndent()
        }

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
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = text,
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
