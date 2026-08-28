// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainNavigationSwipeTest {
    @Test
    fun progressUsesTheWholeVisiblePageWidth() {
        assertEquals(0f, navigationSwipeProgress(0f, 360), 0f)
        assertEquals(0.5f, navigationSwipeProgress(45f, 360), 0.0001f)
        assertEquals(1f, navigationSwipeProgress(-720f, 360), 0f)
        assertEquals(0f, navigationSwipeProgress(120f, 0), 0f)
    }

    @Test
    fun navigationChangesAfterCrossingTheLowerCommitThreshold() {
        assertFalse(shouldCommitNavigationSwipe(0.39f))
        assertFalse(shouldCommitNavigationSwipe(0.4f))
        assertTrue(shouldCommitNavigationSwipe(0.4001f))
        assertTrue(shouldCommitNavigationSwipe(1f))
    }
}
