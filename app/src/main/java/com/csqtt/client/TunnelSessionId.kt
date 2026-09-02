package com.csqtt.client

import java.security.SecureRandom

internal fun newTunnelSessionId(fillBytes: (ByteArray) -> Unit = SecureRandom()::nextBytes): String {
    val bytes = ByteArray(16)
    fillBytes(bytes)
    return bytes.joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
