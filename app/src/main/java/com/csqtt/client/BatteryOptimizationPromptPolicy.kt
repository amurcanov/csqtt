// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

internal fun shouldRequestBatteryOptimizationExemption(
    promptHandled: Boolean,
    alreadyExempt: Boolean,
): Boolean = !promptHandled && !alreadyExempt
