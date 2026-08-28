// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

import com.csqtt.client.CsqttConstants
import com.csqtt.client.ui.design.CsqttShapes

@Composable
internal fun WorkModeInfoDialog(mode: String? = null, onDismiss: () -> Unit) {
    val (title, text) = when (mode) {
        CsqttConstants.VkAuth.MODE_CAPTCHA -> "Режим «Капча»" to """
            • Старый метод получения credentials через эмуляцию браузерного клиента.
            • При таком способе VK может потребовать прохождение капчи.
            • Если решить её автоматически не получится, приложение запросит ручное подтверждение в WebView.
        """.trimIndent()
        CsqttConstants.VkAuth.MODE_CALLS -> "Режим «Авто»" to """
            • Получение TURN-сессий напрямую через протокол и гостевую цепочку VK Calls.
            • Обычно позволяет работать без капчи.
            • Поддерживает масштабирование до 126 независимых воркеров.
        """.trimIndent()
        CsqttConstants.VkAuth.MODE_AUTO_JS -> "Режим «Авто ВК»" to """
            • Один аккаунт создаёт и удерживает один звонок через метод vchat.startConversation.
            • До 7 независимых Calls-сессий обслуживают до 18 потоков каждая (общий максимум — 126).
            • Получает credentials через официальный метод get_conversation_params под авторизованным аккаунтом VK.
            • Анонимные звонки не используются. Режим хешей автоматически фиксируется на «Авто ВК».
            • Создатель удерживает звонок до отключения туннеля.
            • Если отдельная сессия не выдаст креды, её группа перейдёт на «Авто» без капчи.
        """.trimIndent()
        else -> "Режимы работы" to """
            • Капча — считается первым и самым старым методом получения credentials, не советуется к штатному использованию.

            • Авто — уже очень хороший гостевой режим через VK Calls, почти всегда не требует капчи и работает без проблем (до 126 потоков).

            • Авто ВК — новый режим получения credentials через get_conversation_params. Использует залогиненный аккаунт ВК, анонимные звонки не используются. Советуем использовать этот режим, когда с режимом «Авто» наблюдаются проблемы. Режим самый стабильный, работает только в паре с Авто ВК методом получения ВК хешей.
        """.trimIndent()
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            shape = CsqttShapes.Dialog,
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 6.dp,
            modifier = Modifier.fillMaxWidth(0.9f),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
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
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary),
                ) {
                    Text("Понятно", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
