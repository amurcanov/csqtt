// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration

internal object TvDevicePolicy {
    fun isTelevision(context: Context): Boolean = isTelevision(
        uiMode = context.resources.configuration.uiMode,
        hasTelevisionFeature = context.packageManager.hasSystemFeature("android.hardware.type.television"),
        hasLeanbackFeature = context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK),
    )

    internal fun isTelevision(
        uiMode: Int,
        hasTelevisionFeature: Boolean,
        hasLeanbackFeature: Boolean,
    ): Boolean =
        (uiMode and Configuration.UI_MODE_TYPE_MASK) == Configuration.UI_MODE_TYPE_TELEVISION ||
            hasTelevisionFeature ||
            hasLeanbackFeature
}
