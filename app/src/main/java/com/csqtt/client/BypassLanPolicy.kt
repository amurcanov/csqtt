// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.net.VpnService

internal object BypassLanPolicy {
    /**
     * Standard public IPv4 unicast routes that cover all public addresses
     * while excluding RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
     * and multicast/reserved space (224.0.0.0/3).
     */
    val PUBLIC_IPV4_SUBNETS: List<Pair<String, Int>> = listOf(
        "0.0.0.0" to 5,
        "8.0.0.0" to 7,
        "11.0.0.0" to 8,
        "12.0.0.0" to 6,
        "16.0.0.0" to 4,
        "32.0.0.0" to 3,
        "64.0.0.0" to 2,
        "128.0.0.0" to 3,
        "160.0.0.0" to 5,
        "168.0.0.0" to 6,
        "172.0.0.0" to 12,
        "172.32.0.0" to 11,
        "172.64.0.0" to 10,
        "172.128.0.0" to 9,
        "173.0.0.0" to 8,
        "174.0.0.0" to 7,
        "176.0.0.0" to 4,
        "192.0.0.0" to 9,
        "192.128.0.0" to 11,
        "192.160.0.0" to 13,
        "192.169.0.0" to 16,
        "192.170.0.0" to 15,
        "192.172.0.0" to 14,
        "192.176.0.0" to 12,
        "192.192.0.0" to 10,
        "193.0.0.0" to 8,
        "194.0.0.0" to 7,
        "196.0.0.0" to 6,
        "200.0.0.0" to 5,
        "208.0.0.0" to 4,
    )

    fun applyRoutes(builder: VpnService.Builder, bypassLan: Boolean) {
        if (!bypassLan) {
            builder.addRoute("0.0.0.0", 0)
        } else {
            PUBLIC_IPV4_SUBNETS.forEach { (address, prefix) ->
                builder.addRoute(address, prefix)
            }
        }
    }
}
