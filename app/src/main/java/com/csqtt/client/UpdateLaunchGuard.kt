// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Context
import android.content.pm.PackageInfo
import android.os.Build
import android.util.Log

/** Drops only stale Activity/Compose state on the first launch after package replace. */
internal object UpdateLaunchGuard {
    private const val TAG = "CSQTT"
    private const val PREFS = "update_launch_guard"
    private const val LAST_TOKEN = "last_package_token"

    fun consumeStaleSavedState(context: Context): Boolean = runCatching {
        val packageInfo = context.currentPackageInfo()
        val token = "${packageInfo.versionCodeCompat()}:${packageInfo.lastUpdateTime}"
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val previous = preferences.getString(LAST_TOKEN, null)
        val discard = shouldDiscardStaleSavedState(
            previousToken = previous,
            currentToken = token,
            packageWasUpdated = packageInfo.lastUpdateTime > packageInfo.firstInstallTime,
        )
        if (previous != token) {
            if (!preferences.edit().putString(LAST_TOKEN, token).commit()) {
                Log.w(TAG, "Unable to persist package-update launch marker")
            }
        }
        discard
    }.getOrElse { error ->
        Log.w(TAG, "Unable to inspect package-update launch state", error)
        false
    }

    private fun Context.currentPackageInfo(): PackageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0)
        }

    private fun PackageInfo.versionCodeCompat(): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            longVersionCode
        } else {
            @Suppress("DEPRECATION")
            versionCode.toLong()
        }
}

internal fun shouldDiscardStaleSavedState(
    previousToken: String?,
    currentToken: String,
    packageWasUpdated: Boolean,
): Boolean =
    previousToken != currentToken && (previousToken != null || packageWasUpdated)
