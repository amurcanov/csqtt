// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class PhysicalNetworkTrackerTest {
    @Test
    fun duplicateCallbacksProduceOneAvailabilityTransition() {
        val tracker = PhysicalNetworkTracker<String>()
        assertEquals(PhysicalNetworkTransition.AVAILABLE, tracker.update("mobile", true))
        repeat(100) {
            assertEquals(PhysicalNetworkTransition.NONE, tracker.update("mobile", true))
        }
    }

    @Test
    fun overlappingPhysicalNetworksSignalTransportChange() {
        val tracker = PhysicalNetworkTracker<String>()
        assertEquals(PhysicalNetworkTransition.AVAILABLE, tracker.update("mobile", true))
        assertEquals(PhysicalNetworkTransition.CHANGED, tracker.update("wifi", true))
        assertEquals(PhysicalNetworkTransition.CHANGED, tracker.update("mobile", false))
        assertEquals(PhysicalNetworkTransition.UNAVAILABLE, tracker.update("wifi", false))
    }

    @Test
    fun rapidAirplaneCyclesRemainExactlyPaired() {
        val tracker = PhysicalNetworkTracker<String>()
        repeat(1_000) {
            assertEquals(PhysicalNetworkTransition.AVAILABLE, tracker.update("mobile-$it", true))
            assertEquals(PhysicalNetworkTransition.NONE, tracker.update("mobile-$it", true))
            assertEquals(PhysicalNetworkTransition.UNAVAILABLE, tracker.update("mobile-$it", false))
            assertEquals(PhysicalNetworkTransition.NONE, tracker.update("mobile-$it", false))
        }
    }

    @Test
    fun pauseReasonUsesTheActualAirplaneModeState() {
        assertEquals(
            PhysicalNetworkPauseReason.AIRPLANE_MODE,
            physicalNetworkPauseReason(airplaneModeOn = true),
        )
        assertEquals(
            PhysicalNetworkPauseReason.OFFLINE,
            physicalNetworkPauseReason(airplaneModeOn = false),
        )
    }

    @Test
    fun usableStateIsStableAcrossDuplicateAndClearEvents() {
        val tracker = PhysicalNetworkTracker<String>()
        assertEquals(false, tracker.hasUsableNetwork())
        tracker.update("mobile", true)
        tracker.update("mobile", true)
        assertEquals(true, tracker.hasUsableNetwork())
        tracker.clear()
        assertEquals(false, tracker.hasUsableNetwork())
    }

    @Test
    fun vpnAndNonPhysicalTransportsAreNotEligiblePhysicalNetworks() {
        assertEquals(
            true,
            isEligiblePhysicalNetwork(
                hasInternet = true,
                notVpn = true,
                wifi = true,
                cellular = false,
            ),
        )
        assertEquals(
            true,
            isEligiblePhysicalNetwork(
                hasInternet = true,
                notVpn = true,
                wifi = false,
                cellular = true,
            ),
        )
        assertEquals(
            false,
            isEligiblePhysicalNetwork(
                hasInternet = true,
                notVpn = false,
                wifi = true,
                cellular = false,
            ),
        )
        assertEquals(
            false,
            isEligiblePhysicalNetwork(
                hasInternet = true,
                notVpn = true,
                wifi = false,
                cellular = false,
            ),
        )
    }
}
