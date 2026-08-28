// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

internal data class VkModeSelection(
    val authMode: String,
    val hashMode: String,
)

internal fun normalizeVkModeSelection(
    requestedAuthMode: String?,
    requestedHashMode: String?,
    hasVkToken: Boolean,
): VkModeSelection {
    val authMode = when (requestedAuthMode) {
        CsqttConstants.VkAuth.MODE_CAPTCHA -> CsqttConstants.VkAuth.MODE_CAPTCHA
        CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
        else -> CsqttConstants.VkAuth.MODE_CALLS
    }
    val hashMode = when (requestedHashMode) {
        "auto", CsqttConstants.VkAutoHash.MODE_AUTO_API -> CsqttConstants.VkAutoHash.MODE_AUTO_API
        CsqttConstants.VkAutoHash.MODE_AUTO_JS -> CsqttConstants.VkAutoHash.MODE_AUTO_JS
        else -> CsqttConstants.VkAutoHash.MODE_MANUAL
    }
    return when {
        authMode == CsqttConstants.VkAuth.MODE_AUTO_JS ||
            hashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS ->
            VkModeSelection(
                authMode = CsqttConstants.VkAuth.MODE_AUTO_JS,
                hashMode = CsqttConstants.VkAutoHash.MODE_AUTO_JS,
            )
        else -> VkModeSelection(authMode = authMode, hashMode = hashMode)
    }
}

internal fun vkHashModeForAuthMode(
    requestedAuthMode: String,
    currentHashMode: String?,
    hasVkToken: Boolean,
): String = when (requestedAuthMode) {
    CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAutoHash.MODE_AUTO_JS
    CsqttConstants.VkAuth.MODE_CALLS -> if (currentHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS) {
        if (hasVkToken) CsqttConstants.VkAutoHash.MODE_AUTO_API else CsqttConstants.VkAutoHash.MODE_MANUAL
    } else {
        normalizeVkModeSelection(requestedAuthMode, currentHashMode, hasVkToken).hashMode
    }
    else -> normalizeVkModeSelection(requestedAuthMode, currentHashMode, hasVkToken).hashMode
}

internal fun vkAuthModeForHashMode(requestedHashMode: String, currentAuthMode: String?): String =
    when (requestedHashMode) {
        CsqttConstants.VkAutoHash.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
        CsqttConstants.VkAutoHash.MODE_AUTO_API -> CsqttConstants.VkAuth.MODE_CALLS
        else -> if (currentAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS) {
            CsqttConstants.VkAuth.MODE_CALLS
        } else {
            normalizeVkModeSelection(currentAuthMode, requestedHashMode, false).authMode
        }
    }

internal fun shouldReplaceUnavailableVkHash(hashMode: String): Boolean =
    hashMode != CsqttConstants.VkAutoHash.MODE_MANUAL

internal fun shouldConfirmAutoJsMode(
    currentMode: String,
    requestedMode: String,
    warningAcknowledged: Boolean,
): Boolean =
    !warningAcknowledged &&
        currentMode != CsqttConstants.VkAuth.MODE_AUTO_JS &&
        requestedMode == CsqttConstants.VkAuth.MODE_AUTO_JS
