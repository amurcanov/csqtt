// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdateTest {
    @Test
    fun comparesVersionsNumerically() {
        assertTrue(isNewerVersion("1.9.9", "2.0.5"))
        assertTrue(isNewerVersion("2.0", "2.0.1"))
        assertFalse(isNewerVersion("2.0.5", "2.0"))
        assertFalse(isNewerVersion("2.1.0", "2.0.9"))
        assertFalse(isNewerVersion("2.0.5", "invalid"))
    }
}
