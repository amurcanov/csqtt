// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class TurnTransportPolicyTest {
    @Test
    fun tcpWarningAppearsOnlyWhenEnteringTcpWithoutAcknowledgement() {
        assertEquals(
            true,
            shouldConfirmTcpTransport(
                currentTransport = CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT,
                requestedTransport = CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS,
                warningAcknowledged = false,
            ),
        )
        assertEquals(
            false,
            shouldConfirmTcpTransport(
                currentTransport = CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS,
                requestedTransport = CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS,
                warningAcknowledged = false,
            ),
        )
        assertEquals(
            false,
            shouldConfirmTcpTransport(
                currentTransport = CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT,
                requestedTransport = CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS,
                warningAcknowledged = true,
            ),
        )
    }
}
