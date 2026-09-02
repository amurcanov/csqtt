package com.csqtt.client

internal enum class ConnectionStartBlocker(val message: String) {
    Link("нужна корректная ссылка CSQTT"),
    Server("не указан корректный адрес сервера"),
    Port("указан некорректный порт сервера"),
    Password("не указан пароль подключения"),
    StoredSecret("не удалось прочитать сохранённый пароль подключения; введите его заново"),
    Hashes("нет действующих VK хешей или VK токена"),
}

internal object ConnectionStartPolicy {
    fun blocker(
        linkMode: Boolean,
        linkValid: Boolean,
        peerValid: Boolean,
        peerPortValid: Boolean,
        connectionPasswordSet: Boolean,
        connectionPasswordReadable: Boolean = true,
        hashesReady: Boolean,
    ): ConnectionStartBlocker? {
        if (!hashesReady) return ConnectionStartBlocker.Hashes
        if (linkMode) return if (linkValid) null else ConnectionStartBlocker.Link
        if (!peerValid) return ConnectionStartBlocker.Server
        if (!peerPortValid) return ConnectionStartBlocker.Port
        if (!connectionPasswordReadable) return ConnectionStartBlocker.StoredSecret
        if (!connectionPasswordSet) return ConnectionStartBlocker.Password
        return null
    }
}
