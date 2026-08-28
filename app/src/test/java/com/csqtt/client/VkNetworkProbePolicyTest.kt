package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkNetworkProbePolicyTest {
    @Test
    fun retryDelayIsBounded() {
        assertEquals(1_000L, vkProbeRetryDelayMs(0))
        assertEquals(1_000L, vkProbeRetryDelayMs(15))
        assertEquals(2_000L, vkProbeRetryDelayMs(16))
        assertEquals(15_000L, vkProbeRetryDelayMs(20))
    }

    @Test
    fun anyHttpResponseMeansVkIsReachable() {
        assertTrue(isVkProbeHttpResponse(100))
        assertTrue(isVkProbeHttpResponse(200))
        assertTrue(isVkProbeHttpResponse(403))
        assertTrue(isVkProbeHttpResponse(599))
        assertFalse(isVkProbeHttpResponse(99))
        assertFalse(isVkProbeHttpResponse(600))
    }
}
