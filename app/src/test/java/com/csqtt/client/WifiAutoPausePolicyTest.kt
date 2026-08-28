// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class WifiAutoPausePolicyTest {
    @Test
    fun pausesOnlyForAnEnabledRequestedTunnelOnWifi() {
        assertEquals(
            WifiAutoPauseAction.PAUSE,
            wifiAutoPauseAction(
                enabled = true,
                wifiConnected = true,
                desiredRunning = true,
                paused = false,
            ),
        )
        assertEquals(
            WifiAutoPauseAction.NONE,
            wifiAutoPauseAction(
                enabled = true,
                wifiConnected = true,
                desiredRunning = false,
                paused = false,
            ),
        )
    }

    @Test
    fun leavesAWifiPauseWhenWifiLeavesOrTheFeatureIsDisabled() {
        assertEquals(
            WifiAutoPauseAction.RESUME,
            wifiAutoPauseAction(
                enabled = true,
                wifiConnected = false,
                desiredRunning = true,
                paused = true,
            ),
        )
        assertEquals(
            WifiAutoPauseAction.RESUME,
            wifiAutoPauseAction(
                enabled = false,
                wifiConnected = true,
                desiredRunning = true,
                paused = true,
            ),
        )
    }

    @Test
    fun defaultCellularNetworkOverridesStaleWifiCallbackOnlyWhilePaused() {
        assertEquals(
            false,
            effectiveWifiAutoPauseConnection(
                paused = true,
                callbackWifiConnected = true,
                defaultPhysicalWifiConnected = false,
            ),
        )
        assertEquals(
            true,
            effectiveWifiAutoPauseConnection(
                paused = true,
                callbackWifiConnected = true,
                defaultPhysicalWifiConnected = null,
            ),
        )
        assertEquals(
            true,
            effectiveWifiAutoPauseConnection(
                paused = false,
                callbackWifiConnected = true,
                defaultPhysicalWifiConnected = false,
            ),
        )
    }
}
