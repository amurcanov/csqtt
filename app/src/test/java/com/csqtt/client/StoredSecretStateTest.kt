package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class StoredSecretStateTest {
    @Test
    fun `missing values remain missing`() {
        assertEquals(
            StoredSecret("", StoredSecretState.Missing),
            resolveStoredSecret(null, null) { error("decrypt must not run") },
        )
    }

    @Test
    fun `legacy plaintext remains readable`() {
        assertEquals(
            StoredSecret("legacy", StoredSecretState.Readable),
            resolveStoredSecret(null, "legacy") { error("decrypt must not run") },
        )
    }

    @Test
    fun `successfully decrypted value is preferred over legacy plaintext`() {
        assertEquals(
            StoredSecret("encrypted", StoredSecretState.Readable),
            resolveStoredSecret("v1:data", "legacy") { "encrypted" },
        )
    }

    @Test
    fun `unreadable encrypted secret is explicit when no fallback exists`() {
        assertEquals(
            StoredSecret("", StoredSecretState.Unreadable),
            resolveStoredSecret("v1:broken", null) { null },
        )
    }

    @Test
    fun `legacy plaintext recovers an unreadable encrypted secret`() {
        assertEquals(
            StoredSecret("legacy", StoredSecretState.Readable),
            resolveStoredSecret("v1:broken", "legacy") { null },
        )
    }

    @Test
    fun `readable empty encrypted value is not reported as a keystore failure`() {
        assertEquals(
            StoredSecret("", StoredSecretState.Readable),
            resolveStoredSecret("v1:empty", null) { "" },
        )
    }
}
