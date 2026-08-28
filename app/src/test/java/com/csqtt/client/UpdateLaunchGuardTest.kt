// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateLaunchGuardTest {
    @Test
    fun `first install keeps its normal saved state`() {
        assertFalse(
            shouldDiscardStaleSavedState(
                previousToken = null,
                currentToken = "205:1000",
                packageWasUpdated = false,
            ),
        )
    }

    @Test
    fun `new package token clears stale state once`() {
        assertTrue(
            shouldDiscardStaleSavedState(
                previousToken = "205:1000",
                currentToken = "206:2000",
                packageWasUpdated = true,
            ),
        )
        assertFalse(
            shouldDiscardStaleSavedState(
                previousToken = "206:2000",
                currentToken = "206:2000",
                packageWasUpdated = true,
            ),
        )
    }

    @Test
    fun `an existing update with a cleared marker still clears stale state`() {
        assertTrue(
            shouldDiscardStaleSavedState(
                previousToken = null,
                currentToken = "206:2000",
                packageWasUpdated = true,
            ),
        )
    }
}
