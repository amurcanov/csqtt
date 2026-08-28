// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.Hyphens
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.delay

@Composable
internal fun AutoVkRiskDialog(
    requireAcknowledgement: Boolean,
    onAcknowledge: () -> Unit,
    onDoNotRemind: (() -> Unit)? = null,
) {
    TimedWarningDialog(
        title = "Внимание!",
        paragraphs = listOf(
            "«Авто ВК» использует неофициальные браузерные методы VK API для создания звонка и получения TURN credentials без анонимных звонков. Сетевой стек PRIMP маскирует HTTP/TLS-профиль под обычный браузер.",
            "Разработчик не может исключить блокировку VK-аккаунта и честно оценить её вероятность. Используйте режим на свой риск; если важен основной аккаунт, выбирайте второстепенный. Рекомендуется включать «Авто ВК», когда «Авто» и «Авто API» не работают.",
        ),
        requireAcknowledgement = requireAcknowledgement,
        onAcknowledge = onAcknowledge,
        onDoNotRemind = onDoNotRemind,
    )
}

@Composable
internal fun TcpTransportRiskDialog(
    onAcknowledge: () -> Unit,
    onDoNotRemind: () -> Unit,
) {
    TimedWarningDialog(
        title = "Внимание!",
        paragraphs = listOf(
            "TCP — экспериментальный режим для сетей, в которых провайдер ограничивает UDP-трафик. TCP используется только между вашим устройством и серверами VK TURN; между VK TURN и вашим VPS трафик всегда идёт по UDP.",
            "Если UDP работает без ограничений, используйте его: UDP стабильнее, быстрее и по своей природе ближе к настоящим звонкам.",
        ),
        requireAcknowledgement = true,
        onAcknowledge = onAcknowledge,
        onDoNotRemind = onDoNotRemind,
    )
}

@Composable
private fun TimedWarningDialog(
    title: String,
    paragraphs: List<String>,
    requireAcknowledgement: Boolean,
    onAcknowledge: () -> Unit,
    onDoNotRemind: (() -> Unit)?,
) {
    var secondsLeft by rememberSaveable(requireAcknowledgement) {
        mutableIntStateOf(if (requireAcknowledgement) 8 else 0)
    }
    if (requireAcknowledgement) {
        LaunchedEffect(Unit) {
            while (secondsLeft > 0) {
                delay(1_000)
                secondsLeft -= 1
            }
        }
    }
    val actionsEnabled = secondsLeft == 0

    AlertDialog(
        onDismissRequest = {},
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
        ),
        title = {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                paragraphs.forEach { paragraph ->
                    Text(
                        text = paragraph,
                        style = MaterialTheme.typography.bodyMedium.copy(hyphens = Hyphens.Auto),
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Start,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (onDoNotRemind != null) {
                    OutlinedButton(
                        onClick = onDoNotRemind,
                        enabled = actionsEnabled,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                    ) {
                        Text("Не напоминать")
                    }
                }
                Button(
                    onClick = onAcknowledge,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                ) {
                    Text("Понятно")
                }
                if (!actionsEnabled) {
                    Text(
                        text = secondsLeft.toString(),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                    )
                }
            }
        },
    )
}
