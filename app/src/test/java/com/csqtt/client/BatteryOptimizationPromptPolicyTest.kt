// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryOptimizationPromptPolicyTest {
    @Test
    fun firstVisitRequestsTheSystemPrompt() {
        assertTrue(
            shouldRequestBatteryOptimizationExemption(
                promptHandled = false,
                alreadyExempt = false,
            ),
        )
    }

    @Test
    fun handledPromptIsNeverShownAgain() {
        assertFalse(
            shouldRequestBatteryOptimizationExemption(
                promptHandled = true,
                alreadyExempt = false,
            ),
        )
    }

    @Test
    fun existingExemptionIsRecordedWithoutShowingThePrompt() {
        assertFalse(
            shouldRequestBatteryOptimizationExemption(
                promptHandled = false,
                alreadyExempt = true,
            ),
        )
    }
}
