// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelConnectionStateTest {
    @Test
    fun allReadinessRequirementsMustHoldRegardlessOfArrivalOrder() {
        val orders = listOf(
            listOf(0, 1, 2), listOf(0, 2, 1), listOf(1, 0, 2),
            listOf(1, 2, 0), listOf(2, 0, 1), listOf(2, 1, 0),
        )
        for (order in orders) {
            val connection = starting()
            val vpn = connection.requestVpn(1)!!
            for ((index, event) in order.withIndex()) {
                when (event) {
                    0 -> connection.configured(1)
                    1 -> connection.transportChanged(1, true)
                    2 -> connection.vpnReady(vpn)
                }
                assertEquals("Readiness order $order at $index", index == 2, connection.state.value.connected)
            }
        }
    }

    @Test
    fun losingAllWorkersRemovesSuccessUntilATransportIsReadyAgain() {
        val connection = connected()
        connection.transportChanged(1, false)
        assertEquals(TunnelConnectionPhase.Reconnecting, connection.state.value.phase)
        assertTrue(connection.state.value.canStop)
        connection.transportChanged(1, true)
        assertTrue(connection.state.value.connected)
    }

    @Test
    fun processRestartNeedsFreshServerTransportAndVpnConfirmations() {
        val connection = connected()
        val oldVpn = connection.state.value.vpnRequest!!
        connection.processEnded(1)
        assertEquals(TunnelConnectionPhase.Reconnecting, connection.state.value.phase)
        connection.processStarted(2)
        connection.configured(1)
        connection.transportChanged(1, true)
        assertFalse(connection.vpnReady(oldVpn))
        assertFalse(connection.state.value.connected)
        val newVpn = connection.requestVpn(2)!!
        connection.configured(2)
        connection.transportChanged(2, true)
        assertFalse(connection.state.value.connected)
        connection.vpnReady(newVpn)
        assertTrue(connection.state.value.connected)
        connection.processEnded(1)
        assertTrue(connection.state.value.connected)
    }

    @Test
    fun interfaceRebuildRejectsBothReadyAndStoppedCallbacksFromTheOldRequest() {
        val connection = connected()
        val oldVpn = connection.state.value.vpnRequest!!
        val newVpn = connection.requestVpn(1)!!
        assertEquals(TunnelConnectionPhase.Reconnecting, connection.state.value.phase)
        assertFalse(connection.vpnReady(oldVpn))
        assertFalse(connection.vpnStopped(oldVpn))
        assertFalse(connection.state.value.connected)
        assertTrue(connection.vpnReady(newVpn))
        assertTrue(connection.state.value.connected)
        assertFalse(connection.vpnStopped(oldVpn))
        assertTrue(connection.state.value.connected)
    }

    @Test
    fun losingTheVpnInterfaceRemovesConnectionSuccessImmediately() {
        val connection = connected()
        connection.vpnStopped(connection.state.value.vpnRequest!!)
        assertFalse(connection.state.value.connected)
        assertEquals(TunnelConnectionPhase.Reconnecting, connection.state.value.phase)
    }

    @Test
    fun stoppingInvalidatesReadinessBeforeTheProcessHasExited() {
        val connection = connected()
        val vpn = connection.state.value.vpnRequest!!
        connection.requestStop()
        assertFalse(connection.state.value.connected)
        assertFalse(connection.state.value.canStop)
        assertFalse(connection.vpnReady(vpn))
        connection.processEnded(1)
        assertEquals(TunnelConnectionPhase.Stopping, connection.state.value.phase)
    }

    @Test
    fun stoppedSessionsCannotLeakReadinessIntoAnotherStart() {
        val connection = connected()
        val oldVpn = connection.state.value.vpnRequest!!
        connection.requestStop()
        connection.stopped()
        connection.prepare()
        connection.processStarted(2)
        connection.configured(1)
        connection.transportChanged(1, true)
        assertFalse(connection.vpnReady(oldVpn))
        assertEquals(TunnelConnectionPhase.Connecting, connection.state.value.phase)
        assertFalse(connection.state.value.serverConfigured)
        assertFalse(connection.state.value.transportReady)
        assertFalse(connection.state.value.vpnReady)
    }

    @Test
    fun wifiAutoPauseInvalidatesTheActiveSession() {
        val connection = connected()
        val vpn = connection.state.value.vpnRequest!!
        connection.stopped(pauseForWifi = true)
        connection.transportChanged(1, true)
        assertFalse(connection.vpnReady(vpn))
        assertEquals(TunnelConnectionPhase.PausedForWifi, connection.state.value.phase)
        assertTrue(connection.state.value.canStop)
        connection.prepare()
        assertEquals(TunnelConnectionPhase.Connecting, connection.state.value.phase)
    }

    @Test
    fun networkLossCannotBeUndoneByWorkerEventsWhileTheNetworkIsPaused() {
        val connection = connected()
        connection.networkPaused(true)
        connection.transportChanged(1, true)
        assertEquals(TunnelConnectionPhase.WaitingForNetwork, connection.state.value.phase)
        connection.networkPaused(false)
        assertEquals(TunnelConnectionPhase.Reconnecting, connection.state.value.phase)
        connection.transportChanged(1, true)
        assertTrue(connection.state.value.connected)
    }

    @Test
    fun duplicatePreparationDoesNotInvalidateAWorkingConnection() {
        val connection = connected()
        val previous = connection.state.value
        connection.prepare()
        assertEquals(previous, connection.state.value)
    }

    @Test
    fun cancellationDuringPreparationCannotBeRevivedByAProcessStart() {
        val connection = TunnelConnectionState()
        connection.prepare()
        connection.requestStop()
        connection.stopped()
        connection.processStarted(1)
        connection.configured(1)
        connection.transportChanged(1, true)
        assertEquals(TunnelConnectionPhase.Disconnected, connection.state.value.phase)
        assertFalse(connection.state.value.engaged)
    }

    @Test
    fun fatalErrorsFromThePreviousProcessCannotStopItsReplacement() {
        val connection = connected()
        val oldVpn = connection.state.value.vpnRequest!!
        connection.processEnded(1)
        connection.processStarted(2)
        connection.configured(2)
        connection.transportChanged(2, true)
        connection.vpnReady(connection.requestVpn(2)!!)
        assertFalse(connection.processFailed(1))
        assertFalse(connection.vpnFailed(oldVpn))
        assertTrue(connection.state.value.connected)
    }

    @Test
    fun fatalErrorsInvalidateCurrentReadinessAtomically() {
        val connection = connected()
        val vpn = connection.state.value.vpnRequest!!
        assertTrue(connection.vpnFailed(vpn))
        assertFalse(connection.vpnReady(vpn))
        assertEquals(TunnelConnectionPhase.Stopping, connection.state.value.phase)

        val other = connected()
        assertTrue(other.processFailed(1))
        other.transportChanged(1, true)
        assertEquals(TunnelConnectionPhase.Stopping, other.state.value.phase)
    }

    private fun starting() = TunnelConnectionState().apply {
        prepare()
        processStarted(1)
    }

    private fun connected() = starting().apply {
        configured(1)
        transportChanged(1, true)
        vpnReady(requestVpn(1)!!)
        assertTrue(state.value.connected)
    }
}
