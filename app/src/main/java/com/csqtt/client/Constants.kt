// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

object CsqttConstants {
    object General {
        const val APP_NAME = "CSQTT"
        const val PACKAGE_VK = "com.vkontakte.android"
        const val PACKAGE_VK_CALLS = "com.vk.calls"
        const val CSQTT_EVENT_PREFIX = "__CSQTT_EVENT__|"
        const val ACTION_RESTART_WHEN_VK_REACHABLE = "com.csqtt.client.RESTART_WHEN_VK_REACHABLE"
        const val ACTION_VERIFY_VK_REACHABILITY = "com.csqtt.client.VERIFY_VK_REACHABILITY"
        const val ACTION_RECOVER_VK_CALL = "com.csqtt.client.RECOVER_VK_CALL"
        const val EXTRA_UNAVAILABLE_VK_HASH = "unavailable_vk_hash"
    }

    object Profiles {
        const val MIN_INDEX = 0
        const val MAX_INDEX = 3
    }

    object Network {
        const val LOCAL_LISTEN_HOST = "127.0.0.1"
        const val DEFAULT_LOCAL_PORT = 0
        const val DEFAULT_SERVER_PEER_PORT = 46000
        const val DEFAULT_SSH_PORT = 22
        const val DEFAULT_SERVER_WEB_PORT = 46002
    }

    object Tunnel {
        const val BINARY_NAME = "libclient.so"
        const val PROCESS_ENV_EVENTS = "CSQTT_EVENTS"

        const val DEFAULT_FINGERPRINT = "firefox"
        const val DEFAULT_CLIENT_IDS = "8202606,6287487"
        const val DEFAULT_OBFS_MODE = "video"
        const val DEFAULT_TURN_TRANSPORT = "udp"
        const val TURN_TRANSPORT_TCP_TLS = "tcp_tls"

        const val WORKERS_PER_GROUP = 9
        const val GROUPS_PER_VK_HASH = 3
        const val MAX_VK_HASHES = 6
        const val DEFAULT_MAX_WORKERS = 72
        const val MAX_WORKERS = 126
    }

    object VkAuth {
        const val MODE_CALLS = "vkcalls"
        const val MODE_CAPTCHA = "legacy"
        const val MODE_AUTO_JS = "auto_js"
    }

    object Timeouts {
        const val CAPTCHA_AUTO_TIMEOUT_MS = 10_000L
        const val CAPTCHA_MANUAL_TIMEOUT_MS = 60_000L
        const val CAPTCHA_WV_CREATE_TIMEOUT_MS = 3_000L

        const val WATCHDOG_INTERVAL_MS = 5_000L
        const val LOG_READER_RESET_INTERVAL_MS = 60_000L

        const val VPN_PERMISSION_COOLDOWN_MS = 300L

        const val DEPLOY_CMD_TIMEOUT_MS = 900_000L
        const val DEPLOY_STALL_TIMEOUT_MS = 30 * 60 * 1000L

        const val UPDATE_RATE_LIMIT_COOLDOWN_MS = 30L * 60L * 1000L
    }

    object Thresholds {
        const val FLOOD_CONTROL_THRESHOLD = 5
        const val IP_MISMATCH_THRESHOLD = 5
        const val CONNECTION_REFUSED_THRESHOLD = 400
        const val HASH_ERROR_THRESHOLD = 10
    }

    object Update {
        const val DEFAULT_CHECK_INTERVAL_HOURS = 12
        const val CHECK_NEVER = -1
        const val ACTION_POSTPONED = "postponed"
        const val ACTION_UPDATE = "update"

        const val GITHUB_RELEASES_URL =
            "https://api.github.com/repos/amurcanov/csqtt/releases?per_page=30"
        const val GITHUB_LATEST_RELEASE_URL =
            "https://api.github.com/repos/amurcanov/csqtt/releases/latest"
        const val GITHUB_LATEST_RELEASE_WEB_URL =
            "https://github.com/amurcanov/csqtt/releases/latest"
        const val GITHUB_RELEASE_TAG_URL_PREFIX =
            "https://github.com/amurcanov/csqtt/releases/tag/"
        const val GITHUB_TAGS_URL =
            "https://api.github.com/repos/amurcanov/csqtt/tags?per_page=100"
        const val GITHUB_TAG_TREE_URL_PREFIX =
            "https://github.com/amurcanov/csqtt/tree/"
    }

    object Notifications {
        const val TUNNEL_CHANNEL_ID = "csqtt_tunnel_v4"
        const val TUNNEL_NOTIFICATION_ID = 1

        const val CAPTCHA_CHANNEL_ID = "captcha_channel"
        const val CAPTCHA_NOTIFICATION_ID = 9001
    }

    object Widget {
        const val ACTION_TOGGLE = "com.csqtt.client.ACTION_WIDGET_TOGGLE"
    }

    object Captcha {
        const val ERROR_SLIDER_DETECTED = "slider_detected"
        val AUTO_VIEWPORT_WIDTHS = intArrayOf(356, 358, 360, 362, 364, 366, 368)
        val AUTO_VIEWPORT_HEIGHTS = intArrayOf(376, 378, 380, 382, 384, 386, 388)
    }

    object SecureStore {
        const val KEY_ALIAS = "csqtt.settings.secrets"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val VERSION_PREFIX = "v1:"
    }

    object VkAutoHash {
        const val MODE_MANUAL = "manual"
        const val MODE_AUTO_API = "auto_api"
        const val MODE_AUTO_JS = "auto_js"
        const val MAX_OAUTH_HOPS = 15

        const val VK_APP_ID = 7793118
        const val VK_OAUTH_SCOPE = 1073737727
        const val VK_OAUTH_REDIRECT_URI = "https://oauth.vk.ru/blank.html"
        const val VK_OAUTH_AUTH_URL =
            "https://oauth.vk.ru/authorize" +
                "?client_id=7793118" +
                "&scope=1073737727" +
                "&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html" +
                "&display=page" +
                "&response_type=token" +
                "&revoke=1" +
                "&v=5.199"
        const val VK_LOGIN_URL = "https://vk.ru/"
        const val API_METHOD_BASE_URL = "https://api.vk.ru/method/"
        const val API_VERSION = "5.199"

        const val AUTH_TIMEOUT_MS = 300_000L
        const val AUTH_MONITOR_INTERVAL_MS = 200L
        const val AUTH_SILENT_RETRY_DELAY_MS = 1_500L

        const val AUTO_CALL_SMALL_DELAY_MS = 80L
        const val AUTO_CALL_LARGE_DELAY_MS = 202L
        const val AUTO_CALL_MAX_ATTEMPTS = 3
        const val FINISH_CALL_STEP_MS = 150L
        const val FINISH_CALLS_TIMEOUT_MS = 8_000L
    }

    object Vpn {
        const val DEFAULT_MTU = 1300
        const val EMPTY_WHITELIST_MESSAGE = "В режиме БС выберите хотя бы одно приложение"
    }

    object Theme {
        const val MODE_SYSTEM = "system"
        const val MODE_DARK = "dark"
        const val MODE_LIGHT = "light"
        const val PALETTE_INDIGO = "indigo"
        const val PALETTE_ESPRESSO = "espresso"
        const val PALETTE_FOREST = "forest"
    }

    object Links {
        const val RELEASES = "https://github.com/amurcanov/csqtt/releases"
        const val ISSUES = "https://github.com/amurcanov/csqtt/issues/new"
        const val DEVELOPER_PROFILE = "https://github.com/amurcanov"
        const val REPOSITORY = "https://github.com/amurcanov/csqtt"
        const val DONATE = ""
    }

    object Patterns {
        val VERSION_NUMBER = kotlin.text.Regex("\\d+(?:\\.\\d+)*")
    }
}
