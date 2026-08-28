// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.json.JSONObject

object TunnelEventParser {
    private const val PREFIX = CsqttConstants.General.CSQTT_EVENT_PREFIX

    sealed class Event {
        data class Started(val message: String = "") : Event()
        data class Stopped(val message: String = "") : Event()
        data class Process(val pid: Int) : Event()
        data class Ready(val worker: Int, val message: String = "") : Event()
        data class ActiveZero(val message: String = "") : Event()
        data class CallUnavailable(val hash: String, val code: Int) : Event()
        data object NetworkSuspect : Event()
        data object ServerRestart : Event()
        data class Config(val config: String) : Event()
        data class Stats(
            val active: Int,
            val bytesUp: Long,
            val bytesDown: Long
        ) : Event()

        data class Error(
            val code: String,
            val message: String,
            val fatal: Boolean
        ) : Event()

        data class CaptchaRequest(
            val mode: String,
            val redirectUri: String,
            val sessionToken: String
        ) : Event()

        data class CaptchaDone(
            val success: Boolean,
            val error: String?
        ) : Event()

        data class Progress(val kind: String) : Event()
    }

    fun parse(line: String): Event? {
        if (!line.startsWith(PREFIX)) return null
        val withoutPrefix = line.substring(PREFIX.length)
        val typeEnd = withoutPrefix.indexOf('|')
        if (typeEnd == -1) return null

        val type = withoutPrefix.substring(0, typeEnd)
        val payload = try {
            JSONObject(withoutPrefix.substring(typeEnd + 1))
        } catch (_: Exception) {
            return null
        }

        return when (type) {
            "STARTED" -> Event.Started(payload.optString("message", ""))
            "STOPPED" -> Event.Stopped(payload.optString("message", ""))
            "PROCESS" -> payload.optInt("pid", 0)
                .takeIf { it > 0 }
                ?.let { Event.Process(it) }
            "READY" -> Event.Ready(
                worker = payload.optInt("worker", 0).coerceIn(0, CsqttConstants.Tunnel.MAX_WORKERS),
                message = payload.optString("message", ""),
            )
            "ACTIVE_ZERO" -> Event.ActiveZero(payload.optString("message", ""))
            "CALL_UNAVAILABLE" -> {
                val hash = payload.optString("hash", "").trim()
                if (hash.isBlank()) null else Event.CallUnavailable(
                    hash = hash,
                    code = payload.optInt("code", 951).coerceAtLeast(0),
                )
            }
            "NETWORK_SUSPECT" -> Event.NetworkSuspect
            "SERVER_RESTART" -> if (payload.optString("source", "") == "panel") {
                Event.ServerRestart
            } else {
                null
            }
            "CONFIG" -> Event.Config(payload.optString("config", ""))
            "STATS" -> Event.Stats(
                active = payload.optInt("active", 0).coerceAtLeast(0),
                bytesUp = payload.optLong("bytes_up", 0L).coerceAtLeast(0L),
                bytesDown = payload.optLong("bytes_down", 0L).coerceAtLeast(0L)
            )
            "ERROR" -> Event.Error(
                code = payload.optString("code", ""),
                message = payload.optString("message", ""),
                fatal = payload.optBoolean("fatal", false)
            )
            "CAPTCHA_REQUEST" -> Event.CaptchaRequest(
                mode = payload.optString("mode", "auto"),
                redirectUri = payload.optString("redirect_uri", ""),
                sessionToken = payload.optString("session_token", "")
            )
            "CAPTCHA_DONE" -> Event.CaptchaDone(
                success = payload.optBoolean("success", false),
                error = payload.optString("error", "").takeIf { it.isNotBlank() }
            )
            "PROGRESS" -> {
                val kind = payload.strictString("kind") ?: return null
                if (kind != "credentials") return null
                Event.Progress(kind)
            }
            else -> null
        }
    }

    private fun JSONObject.strictString(key: String): String? {
        if (!has(key) || isNull(key)) return null
        return get(key) as? String
    }

}
