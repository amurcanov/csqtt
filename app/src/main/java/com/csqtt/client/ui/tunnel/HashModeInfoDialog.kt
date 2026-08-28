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
internal fun HashModeInfoDialog(mode: String? = null, onDismiss: () -> Unit) {
    val (title, text) = when (mode) {
        CsqttConstants.VkAutoHash.MODE_MANUAL -> "Режим «Ручной»" to """
            • Вы сами создаёте звонки или группы с вечными звонками в VK, копируете ссылку и вставляете её в окно «VK Хеши».
            • Можно использовать до 6 разных хешей для распределения нагрузки.
            • Полный ручной контроль над источниками пула звонков без необходимости входа в VK ID.
        """.trimIndent()
        CsqttConstants.VkAutoHash.MODE_AUTO_API -> "Режим «Авто API»" to """
            • Приложение создаёт необходимые звонки через официальный метод VK API calls.start.
            • Количество хешей выбирается автоматически — от 1 до 6 по числу потоков.
            • При остановке туннеля звонки корректно завершаются через calls.forceFinish.
            • VK access token хранится в защищённом Android Keystore.
        """.trimIndent()
        CsqttConstants.VkAutoHash.MODE_AUTO_JS -> "Режим «Авто ВК»" to """
            • Rust повторяет браузерную цепочку VK Calls: получает call-token через messages.getCallToken, открывает сессию OK Calls и создаёт один звонок через vchat.startConversation.
            • session_key и идентификаторы звонков остаются внутри Rust-процесса и не выводятся в журнал.
            • Источник TURN-кредов задаётся отдельно режимом работы: «Капча», «Авто» или account-сессии «Авто ВК».
            • В режимах работы «Капча» и «Авто» создатель выходит после готовности TURN-наборов; в режиме «Авто ВК» удерживает звонок до отключения.
            • WSS и WebTransport не запускаются, поскольку для получения join_link и TURN-хешей они не требуются.
        """.trimIndent()
        else -> "Режимы ВК Хешей" to """
            • Ручной — несмотря на жёлтый индикатор, является стабильным и проверенно рабочим, но с последними событиями создавать вечные хеши получается сложным или невозможным.

            • Авто API — использует вечный VK токен для создания звонков через официальный API calls.start (пока вечно живущих, что будет потом — не ясно), работает стабильно и хорошо. Создаёт звонки и использует их; после того как вы отключаетесь от CSQTT, звонки завершаются, ничего не утекает, поведение выглядит штатным.

            • Авто ВК — использует браузерную цепочку API (другие, но официальные API методы calls.getConversationParams), также требует ваш VK токен. Стабильный метод на случай возникновения проблем с первыми двумя. Временное ограничение данного режима — создание только 1 звонка. Когда вы отключаетесь от CSQTT, звонок завершается. Поведение выглядит штатным.
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
