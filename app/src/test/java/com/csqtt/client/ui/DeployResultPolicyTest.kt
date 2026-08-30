// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployResultPolicyTest {
    @Test
    fun exactMarkerAndZeroExitAreRequired() {
        assertTrue(isSuccessfulDeployResult(0, "done\nCSQTT_DEPLOY_OK\n"))
        assertFalse(isSuccessfulDeployResult(1, "CSQTT_DEPLOY_OK"))
        assertFalse(isSuccessfulDeployResult(0, "service is active"))
        assertFalse(isSuccessfulDeployResult(0, "prefix CSQTT_DEPLOY_OK suffix"))
    }

    @Test
    fun prepareRequiresItsOwnExactMarkerAndZeroExit() {
        assertTrue(isSuccessfulPrepareResult(0, "done\nCSQTT_DEPLOY_READY_FOR_UPLOAD\n"))
        assertFalse(isSuccessfulPrepareResult(1, "CSQTT_DEPLOY_READY_FOR_UPLOAD"))
        assertFalse(isSuccessfulPrepareResult(0, "CSQTT_DEPLOY_OK"))
        assertFalse(isSuccessfulPrepareResult(0, "prefix CSQTT_DEPLOY_READY_FOR_UPLOAD suffix"))
    }

    @Test
    fun deployRollbackExitIsExplainedWithoutPretendingSuccess() {
        assertEquals(
            "Новый релиз не прошёл проверку; предыдущая установка восстановлена",
            deployFailureMessage(30, "CSQTT_DEPLOY_ROLLED_BACK\n"),
        )
        assertEquals(
            "Новый релиз не запустился, а автоматический rollback завершился с ошибкой — требуется проверка VPS",
            deployFailureMessage(31, "CSQTT_DEPLOY_ROLLBACK_FAILED\n"),
        )
    }

    @Test
    fun rollbackKeepsConcreteServerReason() {
        assertEquals(
            "Новый релиз не прошёл проверку; предыдущая установка восстановлена " +
                "Причина: Проверенный candidate-бинарник исчез после остановки старого runtime",
            deployFailureMessage(
                30,
                "CSQTT_DEPLOY_ERROR|cutover|Проверенный candidate-бинарник исчез после остановки старого runtime\n" +
                    "CSQTT_DEPLOY_ROLLED_BACK\n",
            ),
        )
    }

    @Test
    fun preflightFailureExplainsThatLiveServiceWasNotStopped() {
        assertEquals(
            "Кандидат не прошёл предзапусковую проверку; работающий сервер не останавливался",
            deployFailureMessage(20, "probe failed"),
        )
    }

    @Test
    fun authFailureHasActionableMessage() {
        assertEquals(
            "SSH-аутентификация отклонена: проверьте логин, пароль и разрешение PasswordAuthentication на VPS",
            friendlyDeployError("Auth fail for methods 'publickey,password'"),
        )
    }

    @Test
    fun publicKeyFailureHasKeySpecificMessage() {
        assertTrue(
            friendlyDeployError("Auth fail (public key): rejected")
                .contains("authorized_keys"),
        )
    }

    @Test
    fun timeoutHasShortMessage() {
        assertEquals("Истекло время ожидания SSH/SFTP", friendlyDeployError("connect timeout"))
    }

    @Test
    fun exhaustedUploadHasNetworkSpecificMessage() {
        assertTrue(
            friendlyDeployError("SFTP/SCP upload failed for csqtt: SFTP: channel closed")
                .contains("автоматического переподключения"),
        )
    }

    @Test
    fun serverSuccessLineBecomesCleanOkLog() {
        assertEquals(
            DeployOutputLine("csqtt установлен", DeployOutputLevel.OK),
            parseDeployOutputLine("✓ csqtt установлен"),
        )
    }

    @Test
    fun serverStepHasNoEmojiOrStatusSticker() {
        assertEquals(
            DeployOutputLine("Установка csqtt...", DeployOutputLevel.LOG),
            parseDeployOutputLine("📦 Установка csqtt..."),
        )
        assertEquals(
            DeployOutputLine("Проверка зависимостей", DeployOutputLevel.LOG),
            parseDeployOutputLine("[►] Проверка зависимостей"),
        )
    }

    @Test
    fun serverFailureBecomesErrorLog() {
        assertEquals(
            DeployOutputLine("Сервис csqtt не запустился", DeployOutputLevel.ERR),
            parseDeployOutputLine("[✗] Сервис csqtt не запустился"),
        )
    }

    @Test
    fun protocolAndDecorationLinesAreHidden() {
        assertNull(parseDeployOutputLine("CSQTT_PROGRESS|0.6|Бинарник..."))
        assertNull(parseDeployOutputLine("CSQTT_DEPLOY_ERROR|cutover|candidate disappeared"))
        assertNull(parseDeployOutputLine("════════════════════════════"))
        assertNull(parseDeployOutputLine("CSQTT_DEPLOY_OK"))
        assertNull(parseDeployOutputLine("CSQTT_DEPLOY_ROLLED_BACK"))
        assertNull(parseDeployOutputLine("CSQTT_DEPLOY_ROLLBACK_FAILED"))
    }

    @Test
    fun dockerModeUsesRawEnvironmentValues() {
        assertEquals("docker", deployMode(true))
        assertEquals("systemd", deployMode(false))
        assertEquals("a b#$\"\\c  d", deployEnvironmentValue("a b#$\"\\c\r\nd", true))
        assertEquals("\"a b#$\\\"\\\\c  d\"", deployEnvironmentValue("a b#$\"\\c\r\nd", false))
    }

    @Test
    fun sshPasswordKeepsSpacesAndSpecialCharactersExactly() {
        assertEquals(
            "a !@#$%^&*()[]{};:,.?/\\|~+= b",
            sanitizeSshPassword("a !@#$%^&*()[]{};:,.?/\\|~+= b"),
        )
        assertEquals("pa ssword", sanitizeSshPassword("pa\n ss\rword"))
    }

    @Test
    fun rootCommandAddsSudoStdinFlagOnlyToInvocation() {
        val command = rootCommand("id")

        assertTrue(command.contains("command -v sudo >/dev/null"))
        assertTrue(command.contains("sudo -S bash -c"))
        assertFalse(command.contains("command -v sudo -S"))
        assertFalse(command.contains("sudo -S not found"))
    }
}
