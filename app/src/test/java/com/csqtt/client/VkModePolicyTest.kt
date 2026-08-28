// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class VkModePolicyTest {
    @Test
    fun autoVkHashSelectsAutoVkWorkMode() {
        assertEquals(
            CsqttConstants.VkAuth.MODE_AUTO_JS,
            vkAuthModeForHashMode(
                CsqttConstants.VkAutoHash.MODE_AUTO_JS,
                CsqttConstants.VkAuth.MODE_CALLS,
            ),
        )
    }

    @Test
    fun autoVkWorkModeSelectsAutoVkHashes() {
        assertEquals(
            CsqttConstants.VkAutoHash.MODE_AUTO_JS,
            vkHashModeForAuthMode(
                CsqttConstants.VkAuth.MODE_AUTO_JS,
                CsqttConstants.VkAutoHash.MODE_AUTO_API,
                hasVkToken = true,
            ),
        )
    }

    @Test
    fun autoApiHashLeavesAutoVkWorkMode() {
        assertEquals(
            CsqttConstants.VkAuth.MODE_CALLS,
            vkAuthModeForHashMode(
                CsqttConstants.VkAutoHash.MODE_AUTO_API,
                CsqttConstants.VkAuth.MODE_AUTO_JS,
            ),
        )
    }

    @Test
    fun autoWorkModeMovesAutoVkHashesToAvailableNonVkMode() {
        assertEquals(
            CsqttConstants.VkAutoHash.MODE_AUTO_API,
            vkHashModeForAuthMode(
                CsqttConstants.VkAuth.MODE_CALLS,
                CsqttConstants.VkAutoHash.MODE_AUTO_JS,
                hasVkToken = true,
            ),
        )
        assertEquals(
            CsqttConstants.VkAutoHash.MODE_MANUAL,
            vkHashModeForAuthMode(
                CsqttConstants.VkAuth.MODE_CALLS,
                CsqttConstants.VkAutoHash.MODE_AUTO_JS,
                hasVkToken = false,
            ),
        )
    }

    @Test
    fun manualHashLeavesAutoVkWorkMode() {
        assertEquals(
            CsqttConstants.VkAuth.MODE_CALLS,
            vkAuthModeForHashMode(
                CsqttConstants.VkAutoHash.MODE_MANUAL,
                CsqttConstants.VkAuth.MODE_AUTO_JS,
            ),
        )
    }

    @Test
    fun unavailableManualHashStaysInCurrentProcessWhileAutoHashIsReplaced() {
        assertEquals(
            false,
            shouldReplaceUnavailableVkHash(CsqttConstants.VkAutoHash.MODE_MANUAL),
        )
        assertEquals(
            true,
            shouldReplaceUnavailableVkHash(CsqttConstants.VkAutoHash.MODE_AUTO_API),
        )
        assertEquals(
            true,
            shouldReplaceUnavailableVkHash(CsqttConstants.VkAutoHash.MODE_AUTO_JS),
        )
    }

    @Test
    fun autoVkWarningAppearsOnlyWhenEnteringTheModeWithoutAcknowledgement() {
        assertEquals(
            true,
            shouldConfirmAutoJsMode(
                currentMode = CsqttConstants.VkAuth.MODE_CALLS,
                requestedMode = CsqttConstants.VkAuth.MODE_AUTO_JS,
                warningAcknowledged = false,
            ),
        )
        assertEquals(
            false,
            shouldConfirmAutoJsMode(
                currentMode = CsqttConstants.VkAuth.MODE_AUTO_JS,
                requestedMode = CsqttConstants.VkAuth.MODE_AUTO_JS,
                warningAcknowledged = false,
            ),
        )
        assertEquals(
            false,
            shouldConfirmAutoJsMode(
                currentMode = CsqttConstants.VkAuth.MODE_CALLS,
                requestedMode = CsqttConstants.VkAuth.MODE_AUTO_JS,
                warningAcknowledged = true,
            ),
        )
    }
}
