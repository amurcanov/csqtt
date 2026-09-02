// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployUiStateTest {
    private val completeState = DeployUiState(
        host = "server.example",
        sshLogin = "root",
        sshPassword = "ssh-password",
        mainPasswordConfigured = true,
        webPanelConfigured = true,
    )

    @Test
    fun `install requires tunnel and web authorization`() {
        assertTrue(completeState.canInstall)
        assertFalse(completeState.copy(mainPasswordConfigured = false).canInstall)
        assertFalse(completeState.copy(webPanelConfigured = false).canInstall)
    }

    @Test
    fun `web login and password are both required`() {
        assertTrue(hasWebPanelCredentials("admin", "secret"))
        assertFalse(hasWebPanelCredentials("", "secret"))
        assertFalse(hasWebPanelCredentials("admin", ""))
        assertFalse(hasWebPanelCredentials("   ", "secret"))
        assertFalse(hasWebPanelCredentials("admin", "   "))
    }

    @Test
    fun `uninstall does not require panel authorization`() {
        assertTrue(
            completeState.copy(
                mainPasswordConfigured = false,
                webPanelConfigured = false,
            ).canUninstall
        )
    }

    @Test
    fun `docker selection preserves deploy validation`() {
        assertTrue(completeState.copy(dockerInstall = true).canInstall)
        assertFalse(completeState.copy(dockerInstall = true, host = "").canInstall)
    }

    @Test
    fun `disabling manual ports restores every deployment port default`() {
        val ports = resolveServerPorts(
            manualPorts = false,
            sshPort = "228",
            peerPort = "47000",
            webPort = "47002",
        )

        assertTrue(ports.ssh == 22)
        assertTrue(ports.peer == 46000)
        assertTrue(ports.web == 46002)
    }

    @Test
    fun `manual ports preserve valid custom values`() {
        val ports = resolveServerPorts(
            manualPorts = true,
            sshPort = "228",
            peerPort = "47000",
            webPort = "47002",
        )

        assertTrue(ports.ssh == 228)
        assertTrue(ports.peer == 47000)
        assertTrue(ports.web == 47002)
    }

    @Test
    fun `successful deploy synchronizes a nonempty server password`() {
        assertTrue(passwordToSynchronizeAfterDeploy(true, "server-password") == "server-password")
        assertTrue(passwordToSynchronizeAfterDeploy(false, "server-password") == null)
        assertTrue(passwordToSynchronizeAfterDeploy(true, "") == null)
        assertTrue(passwordToSynchronizeAfterDeploy(true, "   ") == null)
    }
}
