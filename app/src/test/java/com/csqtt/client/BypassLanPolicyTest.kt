// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class BypassLanPolicyTest {

    private fun ipToLong(ip: String): Long {
        val bytes = InetAddress.getByName(ip).address
        var result = 0L
        for (b in bytes) {
            result = (result shl 8) or (b.toLong() and 0xFF)
        }
        return result
    }

    private fun matchesSubnet(ip: String, subnetIp: String, prefix: Int): Boolean {
        val ipLong = ipToLong(ip)
        val subnetLong = ipToLong(subnetIp)
        val mask = if (prefix == 0) 0L else (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        return (ipLong and mask) == (subnetLong and mask)
    }

    private fun isRouted(ip: String): Boolean {
        return BypassLanPolicy.PUBLIC_IPV4_SUBNETS.any { (subnet, prefix) ->
            matchesSubnet(ip, subnet, prefix)
        }
    }

    @Test
    fun publicIpsAreRouted() {
        assertTrue("8.8.8.8 should be routed", isRouted("8.8.8.8"))
        assertTrue("1.1.1.1 should be routed", isRouted("1.1.1.1"))
        assertTrue("77.88.8.8 should be routed", isRouted("77.88.8.8"))
        assertTrue("142.250.180.14 should be routed", isRouted("142.250.180.14"))
    }

    @Test
    fun privateIpsAreNotRouted() {
        // Wi-Fi hotspot subnet
        assertFalse("192.168.43.1 should be bypassed", isRouted("192.168.43.1"))
        assertFalse("192.168.43.50 should be bypassed", isRouted("192.168.43.50"))
        assertFalse("192.168.1.1 should be bypassed", isRouted("192.168.1.1"))

        // Class A private
        assertFalse("10.0.0.1 should be bypassed", isRouted("10.0.0.1"))
        assertFalse("10.66.66.1 should be bypassed", isRouted("10.66.66.1"))

        // Class B private
        assertFalse("172.16.0.1 should be bypassed", isRouted("172.16.0.1"))
        assertFalse("172.31.255.254 should be bypassed", isRouted("172.31.255.254"))
    }
}
