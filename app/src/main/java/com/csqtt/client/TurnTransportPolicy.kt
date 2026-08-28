// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

internal fun shouldConfirmTcpTransport(
    currentTransport: String,
    requestedTransport: String,
    warningAcknowledged: Boolean,
): Boolean =
    !warningAcknowledged &&
        currentTransport != CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS &&
        requestedTransport == CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS
