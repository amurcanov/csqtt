package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelPasswordStorageTest {
    @Test
    fun `persistent tunnel password takes priority over retired formats`() {
        assertEquals(
            StoredSecret("local", StoredSecretState.Readable),
            resolveTunnelPasswordStorage("local", "legacy", "v1:encrypted") { "encrypted" },
        )
    }

    @Test
    fun `legacy tunnel password remains available during migration`() {
        assertEquals(
            StoredSecret("legacy", StoredSecretState.Readable),
            resolveTunnelPasswordStorage(null, "legacy", null) { error("decrypt must not run") },
        )
    }

    @Test
    fun `old keystore value can be copied into local storage`() {
        assertEquals(
            StoredSecret("encrypted", StoredSecretState.Readable),
            resolveTunnelPasswordStorage(null, null, "v1:encrypted") { "encrypted" },
        )
    }

    @Test
    fun `unreadable retired keystore value remains distinguishable`() {
        assertEquals(
            StoredSecret("", StoredSecretState.Unreadable),
            resolveTunnelPasswordStorage(null, null, "v1:broken") { null },
        )
    }

    @Test
    fun `only an unreadable retired value is eligible for reset`() {
        assertEquals(
            true,
            shouldResetUnreadableTunnelPassword(null, null, "v1:broken") { null },
        )
        assertEquals(
            false,
            shouldResetUnreadableTunnelPassword("local", null, "v1:broken") { null },
        )
        assertEquals(
            false,
            shouldResetUnreadableTunnelPassword(null, "legacy", "v1:broken") { null },
        )
        assertEquals(
            false,
            shouldResetUnreadableTunnelPassword(null, null, null) { error("decrypt must not run") },
        )
    }

    @Test
    fun `missing tunnel password remains missing`() {
        assertEquals(
            StoredSecret("", StoredSecretState.Missing),
            resolveTunnelPasswordStorage(null, null, null) { error("decrypt must not run") },
        )
    }
}
