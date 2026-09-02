// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelLogPolicyTest {
    @Test
    fun removesStatusStickersFromVisibleLogs() {
        assertEquals(
            "VPN TUN: разрешение Android VPN было отозвано",
            withoutLogStickers("❌ VPN TUN: разрешение Android VPN было отозвано"),
        )
        assertEquals("Поток готов ✓", withoutLogStickers("Поток готов ✓"))
        assertEquals("✗ Ошибка VPN", withoutLogStickers("✗ Ошибка VPN"))
        assertEquals("Сервис запущен", withoutLogStickers("[✅] Сервис запущен"))
        assertEquals("[СЕТЬ] Переподключение", withoutLogStickers("[СЕТЬ] ⚠ Переподключение"))
    }

    @Test
    fun inactiveLoggingKeepsOnlyReadyStatsAndErrors() {
        assertTrue(TunnelLogPolicy.isAllowedWhenInactiveLogging("ready", false, LogLevel.OK))
        assertTrue(TunnelLogPolicy.isAllowedWhenInactiveLogging("stats", false, LogLevel.NET))
        assertTrue(TunnelLogPolicy.isAllowedWhenInactiveLogging("turn_error", true, LogLevel.ERR))
        assertTrue(TunnelLogPolicy.isAllowedWhenInactiveLogging("general_error", true, null))
        assertFalse(TunnelLogPolicy.isAllowedWhenInactiveLogging("turn_refresh_status", false, LogLevel.LOG))
        assertFalse(TunnelLogPolicy.isAllowedWhenInactiveLogging("wrap_status", false, LogLevel.OK))
        assertFalse(TunnelLogPolicy.isAllowedWhenInactiveLogging("vk_js_call_progress", false, LogLevel.OK))
    }

    @Test
    fun hidesEveryGetconfDiagnostic() {
        assertTrue(TunnelLogPolicy.isInternalRecovery("[GETCONF] Sending 72 bytes"))
        assertTrue(TunnelLogPolicy.isInternalRecovery("[ВОРКЕР #8] GETCONF timeout 750ms"))
        assertTrue(TunnelLogPolicy.isInternalRecovery("GETCONF чтение ответа конфига: timeout"))
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "GETCONF: FATAL_AUTH: неверный пароль подключения"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "GETCONF: FATAL_PROTOCOL: клиент и сервер используют разные версии протокола"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "GETCONF: FATAL_HANDSHAKE: сервер не подтвердил конфигурацию"
            )
        )
    }

    @Test
    fun exposesTurnRetriesThatKeepTheStreamAlive() {
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][RETRY] Ошибка обновления permission: timeout"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][RETRY] Ошибка транзакции ChannelBind: timeout"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "[TURN][DOWN] Permission истекает, переподнимаем поток"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #17] PEER_LIVENESS_TIMEOUT: 8s без валидных пакетов"
            )
        )
        assertFalse(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #2] [TURN][RETRY] Попытка 46: TURN liveness probe failed"
            )
        )
        assertTrue(
            TunnelLogPolicy.isInternalRecovery(
                "[ВОРКЕР #2] [СЕТЬ][RETRY] Временная ошибка сокета"
            )
        )
    }

    @Test
    fun surfacesOnlyTurnFailuresThatEndAStream() {
        assertTrue(
            TunnelLogPolicy.isTurnStreamFailure(
                "[TURN][DOWN] Allocation истекает, переподнимаем поток"
            )
        )
        assertTrue(
            TunnelLogPolicy.isTurnStreamFailure(
                "[ВОРКЕР #4] [TURN] Ошибка allocation/кредов: socket closed"
            )
        )
        assertFalse(
            TunnelLogPolicy.isTurnStreamFailure(
                "[ГРУППА #1] [TURN] Креды обновлены, TURN urls=3"
            )
        )
    }
}
