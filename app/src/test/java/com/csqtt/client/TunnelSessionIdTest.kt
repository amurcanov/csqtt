package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelSessionIdTest {
    @Test
    fun `session id encodes all sixteen random bytes`() {
        val value = newTunnelSessionId { bytes ->
            bytes.indices.forEach { index -> bytes[index] = index.toByte() }
        }

        assertEquals("000102030405060708090a0b0c0d0e0f", value)
        assertEquals(32, value.length)
    }

    @Test
    fun `session id uses lowercase hexadecimal alphabet`() {
        val value = newTunnelSessionId { bytes -> bytes.fill(0xff.toByte()) }

        assertTrue(value.matches(Regex("[0-9a-f]{32}")))
    }

    @Test
    fun `separate random inputs result in separate session ids`() {
        val first = newTunnelSessionId { bytes -> bytes.fill(0x11.toByte()) }
        val second = newTunnelSessionId { bytes -> bytes.fill(0x22.toByte()) }

        assertNotEquals(first, second)
    }
}
