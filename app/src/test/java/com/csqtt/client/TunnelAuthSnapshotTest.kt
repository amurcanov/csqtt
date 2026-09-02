// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelAuthSnapshotTest {
    @Test
    fun `default snapshot is a loading sentinel`() {
        assertFalse(TunnelAuthSnapshot().isLoaded)
    }

    @Test
    fun `profile snapshot is loaded even when password is genuinely empty`() {
        assertTrue(TunnelAuthSnapshot(profile = 0, connectionPassword = "").isLoaded)
    }

    @Test
    fun `snapshot keeps unreadable secret distinct from a missing value`() {
        val snapshot = TunnelAuthSnapshot(
            profile = 0,
            connectionPassword = "",
            connectionPasswordState = StoredSecretState.Unreadable,
        )

        assertTrue(snapshot.isLoaded)
        assertEquals(StoredSecretState.Unreadable, snapshot.connectionPasswordState)
    }
}
