package com.csqtt.client

internal fun resolveTunnelPasswordStorage(
    persistentValue: String?,
    legacyValue: String?,
    encryptedValue: String?,
    decrypt: (String?) -> String?,
): StoredSecret {
    if (!persistentValue.isNullOrBlank()) {
        return StoredSecret(persistentValue, StoredSecretState.Readable)
    }
    return resolveStoredSecret(encryptedValue, legacyValue, decrypt)
}

internal fun shouldResetUnreadableTunnelPassword(
    persistentValue: String?,
    legacyValue: String?,
    encryptedValue: String?,
    decrypt: (String?) -> String?,
): Boolean = resolveTunnelPasswordStorage(
    persistentValue,
    legacyValue,
    encryptedValue,
    decrypt,
).state == StoredSecretState.Unreadable
