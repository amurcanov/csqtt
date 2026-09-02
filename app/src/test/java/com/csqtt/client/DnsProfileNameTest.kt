package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class DnsProfileNameTest {
    @Test
    fun `known server dns profiles have stable display names`() {
        assertEquals("Yandex DNS", dnsProfileName("77.88.8.8,77.88.8.1"))
        assertEquals("Xbox DNS", dnsProfileName("111.88.96.50,111.88.96.51"))
        assertEquals("BI.ZONE DNS", dnsProfileName("195.208.6.1,195.208.7.1"))
        assertEquals("НСДИ DNS", dnsProfileName("195.208.4.1,195.208.5.1"))
    }

    @Test
    fun `unknown dns pair remains explicitly custom`() {
        assertEquals("Пользовательский DNS", dnsProfileName("203.0.113.1,203.0.113.2"))
    }
}
