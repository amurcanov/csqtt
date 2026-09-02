package com.csqtt.client.ui

import org.junit.Assert.assertNotNull
import org.junit.Test

class SshKeyRuntimeDependencyTest {
    @Test
    fun classicPemParserIsAvailable() {
        assertNotNull(Class.forName("org.bouncycastle.openssl.PEMParser"))
    }

    @Test
    fun pemKeyConverterIsAvailable() {
        assertNotNull(Class.forName("org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter"))
    }
}
