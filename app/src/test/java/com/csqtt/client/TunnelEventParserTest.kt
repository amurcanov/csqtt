// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelEventParserTest {
    @Test
    fun parsesStats() {
        val event = TunnelEventParser.parse(
            "__CSQTT_EVENT__|STATS|{\"active\":3,\"bytes_up\":120,\"bytes_down\":450}"
        ) as TunnelEventParser.Event.Stats

        assertEquals(3, event.active)
        assertEquals(120L, event.bytesUp)
        assertEquals(450L, event.bytesDown)
    }

    @Test
    fun parsesFatalError() {
        val event = TunnelEventParser.parse(
            "__CSQTT_EVENT__|ERROR|{\"code\":\"AUTH\",\"message\":\"denied\",\"fatal\":true}"
        ) as TunnelEventParser.Event.Error

        assertEquals("AUTH", event.code)
        assertEquals("denied", event.message)
        assertTrue(event.fatal)
    }

    @Test
    fun rustLifecycleObjectPayloadsMatchKotlinContract() {
        assertTrue(
            TunnelEventParser.parse("__CSQTT_EVENT__|READY|{}") is
                TunnelEventParser.Event.Ready
        )
        assertTrue(
            TunnelEventParser.parse("__CSQTT_EVENT__|STOPPED|{}") is
                TunnelEventParser.Event.Stopped
        )
        assertTrue(
            TunnelEventParser.parse("__CSQTT_EVENT__|ACTIVE_ZERO|{}") is
                TunnelEventParser.Event.ActiveZero
        )
        assertTrue(
            TunnelEventParser.parse("__CSQTT_EVENT__|NETWORK_SUSPECT|{}") is
                TunnelEventParser.Event.NetworkSuspect
        )
    }

    @Test
    fun serverRestartRequiresPanelSource() {
        assertTrue(
            TunnelEventParser.parse(
                "__CSQTT_EVENT__|SERVER_RESTART|{\"source\":\"panel\"}",
            ) is TunnelEventParser.Event.ServerRestart,
        )
        assertNull(
            TunnelEventParser.parse(
                "__CSQTT_EVENT__|SERVER_RESTART|{\"source\":\"network\"}",
            ),
        )
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|SERVER_RESTART|{}"))
    }

    @Test
    fun parsesCredentialProgress() {
        val progress = TunnelEventParser.parse(
            "__CSQTT_EVENT__|PROGRESS|{\"kind\":\"credentials\"}",
        ) as TunnelEventParser.Event.Progress
        assertEquals("credentials", progress.kind)
    }

    @Test
    fun parsesCallUnavailableWithoutTurningItIntoALogError() {
        val event = TunnelEventParser.parse(
            "__CSQTT_EVENT__|CALL_UNAVAILABLE|{\"hash\":\"dead-hash\",\"code\":951}",
        ) as TunnelEventParser.Event.CallUnavailable

        assertEquals("dead-hash", event.hash)
        assertEquals(951, event.code)
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|CALL_UNAVAILABLE|{\"code\":951}"))
    }

    @Test
    fun detailedPerfEventsAreIgnored() {
        assertNull(
            TunnelEventParser.parse(
                "__CSQTT_EVENT__|PERF_DETAIL|{\"rows\":[{\"name\":\"Crypto/obfs\"}]}",
            ),
        )
    }

    @Test
    fun rejectsUnknownProgressKinds() {
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|PROGRESS|{\"kind\":\"unknown\"}"))
    }

    @Test
    fun handlesMalformedAndUnknownEvents() {
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|CAPTCHA_DONE|invalid"))
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|READY|"))
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|READY|null"))
        assertNull(TunnelEventParser.parse("regular log line"))
        assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|UNKNOWN|{}"))
    }

    @Test
    fun malformedProtocolLineCannotForgeReadyStoppedOrFatalEvents() {
        for (type in listOf("READY", "STOPPED", "ERROR", "STATS")) {
            for (payload in listOf("", "null", "[]", "{", "garbage", "\u0000")) {
                assertNull(TunnelEventParser.parse("__CSQTT_EVENT__|$type|$payload"))
            }
        }
    }

    @Test
    fun negativeStatsAreClampedBeforeLifecycleConsumption() {
        val event = TunnelEventParser.parse(
            "__CSQTT_EVENT__|STATS|{\"active\":-9,\"bytes_up\":-1,\"bytes_down\":-2}",
        ) as TunnelEventParser.Event.Stats

        assertEquals(0, event.active)
        assertEquals(0L, event.bytesUp)
        assertEquals(0L, event.bytesDown)
    }

    @Test
    fun deterministicProtocolPipeChaosNeverThrowsOrCreatesNegativeState() {
        val cases = System.getenv("CSQTT_ANDROID_PARSER_CASES")
            ?.toIntOrNull()
            ?.coerceAtLeast(1)
            ?: 50_000
        var random = (System.getenv("CSQTT_SOAK_SEED")?.toLongOrNull() ?: 104_729L) xor
            0x6a09e667f3bcc909L
        val types = arrayOf("READY", "STOPPED", "ERROR", "STATS", "CONFIG", "CAPTCHA_DONE", "UNKNOWN")
        val covered = BooleanArray(4)
        repeat(cases) { index ->
            random = nextRandom(random)
            val payload = if (index % 16 == 0) {
                covered[2] = true
                "{\"active\":${random.toInt()},\"bytes_up\":${random shr 1},\"bytes_down\":${random shr 2}}"
            } else {
                covered[3] = true
                buildString(((random ushr 8) % 128).toInt()) {
                    var value = random
                    repeat(((random ushr 8) % 128).toInt()) {
                        value = nextRandom(value)
                        append(((value ushr 16) and 0x7f).toInt().toChar())
                    }
                }
            }
            val line = if (index % 3 == 0) {
                covered[0] = true
                "__CSQTT_EVENT__|${types[index % types.size]}|$payload"
            } else {
                covered[1] = true
                payload
            }
            val event = TunnelEventParser.parse(line)
            if (event is TunnelEventParser.Event.Stats) {
                assertTrue(event.active >= 0)
                assertTrue(event.bytesUp >= 0)
                assertTrue(event.bytesDown >= 0)
            }
        }
        assertTrue(covered.all { it })
    }

    private fun nextRandom(value: Long): Long {
        var next = value
        next = next xor (next shl 13)
        next = next xor (next ushr 7)
        next = next xor (next shl 17)
        return next
    }
}
