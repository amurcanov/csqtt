package com.csqtt.client

internal enum class StoredSecretState {
    Readable,
    Missing,
    Unreadable,
}

internal data class StoredSecret(
    val value: String,
    val state: StoredSecretState,
)

internal fun resolveStoredSecret(
    encryptedValue: String?,
    legacyValue: String?,
    decrypt: (String?) -> String?,
): StoredSecret {
    if (encryptedValue.isNullOrBlank()) {
        return legacyValue?.takeIf { it.isNotBlank() }
            ?.let { StoredSecret(it, StoredSecretState.Readable) }
            ?: StoredSecret("", StoredSecretState.Missing)
    }
    val decrypted = decrypt(encryptedValue)
    if (decrypted != null) return StoredSecret(decrypted, StoredSecretState.Readable)
    return legacyValue?.takeIf { it.isNotBlank() }
        ?.let { StoredSecret(it, StoredSecretState.Readable) }
        ?: StoredSecret("", StoredSecretState.Unreadable)
}
