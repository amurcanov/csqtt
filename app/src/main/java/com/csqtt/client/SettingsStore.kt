// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Context
import android.content.pm.PackageManager
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

// readSecret runs Android Keystore crypto (an IPC round-trip); flows that call
// it are pinned to IO so collectors on the main thread never block on KeyStore.
private fun <T> Flow<T>.onIo(): Flow<T> = flowOn(Dispatchers.IO)

internal data class DeploySettingsSnapshot(
    val profile: Int = -1,
    val ip: String = "",
    val sshLogin: String = "",
    val sshPassword: String = "",
    val webLogin: String = "",
    val webPassword: String = "",
    val mainPassword: String = "",
    val sshPort: String = CsqttConstants.Network.DEFAULT_SSH_PORT.toString(),
    val manualPortsEnabled: Boolean = false,
    val serverPeerPort: Int = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
    val serverWebPort: Int = CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT,
    val sshKeysMode: Boolean = false,
    val dockerInstall: Boolean = false,
    val sshPrivateKey: String = "",
    val sshKeyPassphrase: String = "",
    val sshCertificate: String = "",
) {
    val isLoaded: Boolean
        get() = profile >= 0
}

internal data class TunnelAuthSnapshot(
    val profile: Int = -1,
    val connectionPassword: String = "",
    val connectionPasswordState: StoredSecretState = StoredSecretState.Missing,
) {
    val isLoaded: Boolean
        get() = profile >= 0
}

class SettingsStore(context: Context) {
    private val appContext = context.applicationContext
    companion object {
        private val Context.dataStore by preferencesDataStore("settings")
        private val ACTIVE_PROFILE = intPreferencesKey("active_profile")
        private val SHOW_SYSTEM_APPS = booleanPreferencesKey("show_system_apps")
        private val LOGGING_ENABLED = booleanPreferencesKey("logging_enabled")
        private val INFO_ACTIONS_EXPANDED = booleanPreferencesKey("info_actions_expanded")
        private val INFO_PROJECT_EXPANDED = booleanPreferencesKey("info_project_expanded")
        private val CSQTT_LINK = stringPreferencesKey("csqtt_link")
        private val CSQTT_LINK_MODE = booleanPreferencesKey("csqtt_link_mode")

        private val PEER = stringPreferencesKey("peer")
        private val VK_HASHES = stringPreferencesKey("vk_hashes")
        private val SECONDARY_VK_HASH = stringPreferencesKey("secondary_vk_hash")
        private val WORKERS_PER_HASH = intPreferencesKey("workers_per_hash")
        private val PROTOCOL = stringPreferencesKey("protocol")
        private val LISTEN_PORT = intPreferencesKey("listen_port")
        private val MANUAL_PORTS_ENABLED = booleanPreferencesKey("manual_ports_enabled")
        private val SERVER_PEER_PORT = intPreferencesKey("server_peer_port")
        private val SNI = stringPreferencesKey("sni")
        private val NO_DNS = booleanPreferencesKey("no_dns")

        private val USER_AGENT = stringPreferencesKey("user_agent")

        private val DEPLOY_IP = stringPreferencesKey("deploy_ip")
        private val DEPLOY_LOGIN = stringPreferencesKey("deploy_login")
        private val DEPLOY_PASSWORD = stringPreferencesKey("deploy_password")
        private val DEPLOY_PASSWORD_ENCRYPTED = stringPreferencesKey("deploy_password_encrypted")
        private val DEPLOY_SSH_PORT = stringPreferencesKey("deploy_ssh_port")
        private val SSH_KEYS_MODE = booleanPreferencesKey("ssh_keys_mode")
        private val DOCKER_INSTALL = booleanPreferencesKey("docker_install")
        private val SSH_PRIVATE_KEY = stringPreferencesKey("ssh_private_key")
        private val SSH_PRIVATE_KEY_ENCRYPTED = stringPreferencesKey("ssh_private_key_encrypted")
        private val SSH_KEY_PASSPHRASE = stringPreferencesKey("ssh_key_passphrase")
        private val SSH_KEY_PASSPHRASE_ENCRYPTED = stringPreferencesKey("ssh_key_passphrase_encrypted")
        private val SSH_CERTIFICATE = stringPreferencesKey("ssh_certificate")
        private val SSH_CERTIFICATE_ENCRYPTED = stringPreferencesKey("ssh_certificate_encrypted")
        private val EXCLUDED_APPS = stringPreferencesKey("excluded_apps")

        private val DETAILED_LOGS = booleanPreferencesKey("detailed_logs")

        private val CONNECTION_PASSWORD = stringPreferencesKey("connection_password")
        private val CONNECTION_PASSWORD_ENCRYPTED = stringPreferencesKey("connection_password_encrypted")
        private val CONNECTION_PASSWORD_LOCAL = stringPreferencesKey("connection_password_local")
        private val DEPLOY_MAIN_PASSWORD = stringPreferencesKey("deploy_main_password")
        private val DEPLOY_MAIN_PASSWORD_ENCRYPTED = stringPreferencesKey("deploy_main_password_encrypted")
        private val DEPLOY_WEB_LOGIN = stringPreferencesKey("deploy_web_login")
        private val DEPLOY_WEB_PASSWORD = stringPreferencesKey("deploy_web_password")
        private val DEPLOY_WEB_PASSWORD_ENCRYPTED = stringPreferencesKey("deploy_web_password_encrypted")
        private val SERVER_WEB_PORT = intPreferencesKey("server_web_port")

        private val PROXY_MODE = stringPreferencesKey("proxy_mode") 
        private val PROXY_HOST = stringPreferencesKey("proxy_host")
        private val PROXY_PORT = intPreferencesKey("proxy_port")

        private val VK_AUTH_MODE = stringPreferencesKey("vk_auth_mode") 
        private val OBFS_MODE = stringPreferencesKey("obfs_mode") 
        private val TURN_TRANSPORT = stringPreferencesKey("turn_transport")
        private val CAPTCHA_MODE = stringPreferencesKey("captcha_mode") 
        private val CAPTCHA_SOLVE_METHOD = stringPreferencesKey("captcha_solve_method") 
        private val CAPTCHA_WBV_SOLVE_METHOD = stringPreferencesKey("captcha_wbv_solve_method") 

        private val VK_HASH_MODE = stringPreferencesKey("vk_hash_mode")
        private val VK_ACCESS_TOKEN = stringPreferencesKey("vk_access_token")
        private val VK_ACCESS_TOKEN_ENCRYPTED = stringPreferencesKey("vk_access_token_encrypted")
        private val VK_ACCESS_TOKEN_USER_ID = stringPreferencesKey("vk_access_token_user_id")

        private val IS_WHITELIST = booleanPreferencesKey("is_whitelist")
        private val SPLIT_TUNNEL_WHITELIST_MIGRATED = booleanPreferencesKey("split_tunnel_whitelist_migrated")
        private val EXTRA_WORKERS = booleanPreferencesKey("extra_workers")
        private val AUTO_JS_RISK_ACKNOWLEDGED = booleanPreferencesKey("auto_js_risk_acknowledged")
        private val TCP_TRANSPORT_RISK_ACKNOWLEDGED = booleanPreferencesKey("tcp_transport_risk_acknowledged")
        private val BATTERY_OPTIMIZATION_PROMPT_HANDLED =
            booleanPreferencesKey("battery_optimization_prompt_handled")
        private val AUTO_PAUSE_ON_WIFI = booleanPreferencesKey("auto_pause_on_wifi")

        private val THEME_MODE = stringPreferencesKey("theme_mode") 
        private val IS_DYNAMIC_COLOR = booleanPreferencesKey("is_dynamic_color")
        private val THEME_PALETTE = stringPreferencesKey("theme_palette")

        private val SELECTED_FINGERPRINT = stringPreferencesKey("selected_fingerprint")
        private val ACTIVE_CLIENT_IDS = stringPreferencesKey("active_client_ids")

        private val UPDATE_LAST_CHECK_AT = longPreferencesKey("update_last_check_at")
        private val UPDATE_LATEST_VERSION = stringPreferencesKey("update_latest_version")
        private val UPDATE_LAST_ERROR = stringPreferencesKey("update_last_error")
        private val UPDATE_CHECK_INTERVAL_HOURS = intPreferencesKey("update_check_interval_hours")
        private val UPDATE_POSTPONE_UNTIL = longPreferencesKey("update_postpone_until")
        private val UPDATE_POSTPONE_VERSION = stringPreferencesKey("update_postpone_version")
        private val UPDATE_DIALOG_LAST_SHOWN_VERSION = stringPreferencesKey("update_dialog_last_shown_version")
        private val UPDATE_DIALOG_LAST_SHOWN_AT = longPreferencesKey("update_dialog_last_shown_at")
        private val UPDATE_DIALOG_LAST_ACTION_VERSION = stringPreferencesKey("update_dialog_last_action_version")
        private val UPDATE_DIALOG_LAST_ACTION = stringPreferencesKey("update_dialog_last_action")
        private val UPDATE_DIALOG_LAST_ACTION_AT = longPreferencesKey("update_dialog_last_action_at")

        private val CLIENT_ID_CHECK_RESULTS = stringPreferencesKey("client_id_check_results")
        private val VK_HASH_CHECK_RESULTS = stringPreferencesKey("vk_hash_check_results")
        private val CONNECTION_GENERATION = longPreferencesKey("connection_generation")
        // Флаг: был ли CSQTT активен в момент последней остановки.
        // Используется при авторестарте через START_STICKY:
        // если false — не поднимаем VPN автоматически, чтобы не убивать чужой VPN.
        private val TUNNEL_WAS_RUNNING = booleanPreferencesKey("tunnel_was_running")

        @Volatile
        internal var cachedVkHashMode: String? = null

        @Volatile
        internal var cachedVkAccessToken: String? = null

        @Volatile
        internal var cachedObfsMode: String? = null

        @Volatile
        internal var cachedTurnTransport: String? = null

        @Volatile
        internal var cachedCsqttLinkMode: Boolean? = null

        @Volatile
        internal var cachedWorkersPerHash: Int? = null

        @Volatile
        internal var cachedExtraWorkers: Boolean? = null

        private val uiCacheStarted = java.util.concurrent.atomic.AtomicBoolean(false)
        private val migrationsStarted = java.util.concurrent.atomic.AtomicBoolean(false)

        private fun <T> getProfileKey(baseKey: Preferences.Key<T>, profile: Int): Preferences.Key<T> {
            if (profile == 0) return baseKey
            val newName = "${baseKey.name}_$profile"
            @Suppress("UNCHECKED_CAST")
            return when (baseKey) {
                PEER, VK_HASHES, SECONDARY_VK_HASH, PROTOCOL, SNI, USER_AGENT, DEPLOY_IP, DEPLOY_LOGIN, DEPLOY_PASSWORD, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_SSH_PORT, EXCLUDED_APPS, CONNECTION_PASSWORD, CONNECTION_PASSWORD_ENCRYPTED, CONNECTION_PASSWORD_LOCAL, DEPLOY_MAIN_PASSWORD, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_WEB_LOGIN, DEPLOY_WEB_PASSWORD, DEPLOY_WEB_PASSWORD_ENCRYPTED, PROXY_MODE, PROXY_HOST, VK_AUTH_MODE, OBFS_MODE, TURN_TRANSPORT, CAPTCHA_MODE, CAPTCHA_SOLVE_METHOD, CAPTCHA_WBV_SOLVE_METHOD, CSQTT_LINK, SELECTED_FINGERPRINT, ACTIVE_CLIENT_IDS, VK_HASH_MODE, VK_ACCESS_TOKEN, VK_ACCESS_TOKEN_ENCRYPTED, VK_ACCESS_TOKEN_USER_ID, SSH_PRIVATE_KEY, SSH_PRIVATE_KEY_ENCRYPTED, SSH_KEY_PASSPHRASE, SSH_KEY_PASSPHRASE_ENCRYPTED, SSH_CERTIFICATE, SSH_CERTIFICATE_ENCRYPTED, VK_HASH_CHECK_RESULTS, CLIENT_ID_CHECK_RESULTS -> stringPreferencesKey(newName) as Preferences.Key<T>
                WORKERS_PER_HASH, LISTEN_PORT, SERVER_PEER_PORT, PROXY_PORT, SERVER_WEB_PORT -> intPreferencesKey(newName) as Preferences.Key<T>
                MANUAL_PORTS_ENABLED, NO_DNS, IS_WHITELIST, CSQTT_LINK_MODE, DETAILED_LOGS, SSH_KEYS_MODE, DOCKER_INSTALL, EXTRA_WORKERS, SPLIT_TUNNEL_WHITELIST_MIGRATED -> booleanPreferencesKey(newName) as Preferences.Key<T>
                CONNECTION_GENERATION -> longPreferencesKey(newName) as Preferences.Key<T>
                else -> stringPreferencesKey(newName) as Preferences.Key<T>
            }
        }
    }

    private val dataStore = appContext.dataStore
    private val secureStore = SecureStringStore(appContext)

    init {
        // Migrations rewrite every profile's secrets; running them per instance
        // would spam DataStore edits on each construction of the store.
        if (migrationsStarted.compareAndSet(false, true)) {
            CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                migrateConnectionPasswordsToLocalStorage()
                migrateSecretsToKeystore()
                migrateLegacyWhitelistMode()
            }
        }
        if (uiCacheStarted.compareAndSet(false, true)) {
            CoroutineScope(SupervisorJob() + Dispatchers.Default).launch {
                launch { vkHashMode.collect { cachedVkHashMode = it } }
                launch { vkAccessToken.collect { cachedVkAccessToken = it } }
                launch { obfsMode.collect { cachedObfsMode = it } }
                launch { turnTransport.collect { cachedTurnTransport = it } }
                launch { csqttLinkMode.collect { cachedCsqttLinkMode = it } }
                launch { workersPerHash.collect { cachedWorkersPerHash = it } }
                launch { extraWorkers.collect { cachedExtraWorkers = it } }
            }
        }
    }

    val activeProfile: Flow<Int> = dataStore.data.map {
        (it[ACTIVE_PROFILE] ?: CsqttConstants.Profiles.MIN_INDEX).coerceIn(
            CsqttConstants.Profiles.MIN_INDEX,
            CsqttConstants.Profiles.MAX_INDEX,
        )
    }
    val showSystemApps: Flow<Boolean> = dataStore.data.map { it[SHOW_SYSTEM_APPS] ?: false }
    val loggingEnabled: Flow<Boolean> = dataStore.data.map { it[LOGGING_ENABLED] ?: true }
    val infoActionsExpanded: Flow<Boolean> = dataStore.data.map { it[INFO_ACTIONS_EXPANDED] ?: false }
    val infoProjectExpanded: Flow<Boolean> = dataStore.data.map { it[INFO_PROJECT_EXPANDED] ?: false }
    val csqttLink: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CSQTT_LINK, profile)] ?: ""
    }
    val csqttLinkMode: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CSQTT_LINK_MODE, profile)] ?: false
    }

    val peer: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PEER, profile)] ?: ""
    }
    val vkHashes: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_HASHES, profile)] ?: ""
    }
    val secondaryVkHash: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SECONDARY_VK_HASH, profile)] ?: ""
    }
    val workersPerHash: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val isExtra = prefs[getProfileKey(EXTRA_WORKERS, profile)] ?: false
        val max = WorkerCountPolicy.defaultMaximum(isExtra)
        val current = prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18
        WorkerCountPolicy.normalize(current, maximum = max)
    }
    val protocol: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(PROTOCOL, profile)] ?: "udp"
    }
    val listenPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(LISTEN_PORT, profile)] ?: 0
    }
    val manualPortsEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false
    }
    val serverPeerPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_PEER_PORT, profile)] ?: CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT
    }
    val sni: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SNI, profile)] ?: ""
    }

    val deployIp: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_IP, profile)] ?: ""
    }
    val deployLogin: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_LOGIN, profile)] ?: ""
    }
    val deployPassword: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, profile)
    }.onIo()
    val deploySshPort: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] ?: ""
    }
    internal val deploySettingsSnapshot: Flow<DeploySettingsSnapshot> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        DeploySettingsSnapshot(
            profile = profile,
            ip = prefs[getProfileKey(DEPLOY_IP, profile)] ?: "",
            sshLogin = prefs[getProfileKey(DEPLOY_LOGIN, profile)] ?: "",
            sshPassword = readSecret(prefs, DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, profile),
            webLogin = prefs[getProfileKey(DEPLOY_WEB_LOGIN, profile)] ?: "",
            webPassword = readSecret(prefs, DEPLOY_WEB_PASSWORD_ENCRYPTED, DEPLOY_WEB_PASSWORD, profile),
            mainPassword = readSecret(prefs, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile),
            sshPort = prefs[getProfileKey(DEPLOY_SSH_PORT, profile)]
                ?.ifBlank { CsqttConstants.Network.DEFAULT_SSH_PORT.toString() }
                ?: CsqttConstants.Network.DEFAULT_SSH_PORT.toString(),
            manualPortsEnabled = prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] ?: false,
            serverPeerPort = prefs[getProfileKey(SERVER_PEER_PORT, profile)]
                ?: CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
            serverWebPort = prefs[getProfileKey(SERVER_WEB_PORT, profile)]
                ?: CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT,
            sshKeysMode = prefs[getProfileKey(SSH_KEYS_MODE, profile)] ?: false,
            dockerInstall = prefs[getProfileKey(DOCKER_INSTALL, profile)] ?: false,
            sshPrivateKey = readSecret(prefs, SSH_PRIVATE_KEY_ENCRYPTED, SSH_PRIVATE_KEY, profile),
            sshKeyPassphrase = readSecret(prefs, SSH_KEY_PASSPHRASE_ENCRYPTED, SSH_KEY_PASSPHRASE, profile),
            sshCertificate = readSecret(prefs, SSH_CERTIFICATE_ENCRYPTED, SSH_CERTIFICATE, profile),
        )
    }.onIo()
    internal val tunnelAuthSnapshot: Flow<TunnelAuthSnapshot> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val connectionPassword = readConnectionPasswordState(prefs, profile)
        TunnelAuthSnapshot(
            profile = profile,
            connectionPassword = connectionPassword.value,
            connectionPasswordState = connectionPassword.state,
        )
    }.onIo()
    val excludedApps: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(EXCLUDED_APPS, profile)] ?: ""
    }

    internal val connectionPasswordState: Flow<StoredSecret> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readConnectionPasswordState(prefs, profile)
    }.onIo()
    val connectionPassword: Flow<String> = connectionPasswordState.map { it.value }
    val deployMainPassword: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, profile)
    }.onIo()
    val deployWebLogin: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(DEPLOY_WEB_LOGIN, profile)] ?: ""
    }
    val deployWebPassword: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, DEPLOY_WEB_PASSWORD_ENCRYPTED, DEPLOY_WEB_PASSWORD, profile)
    }.onIo()
    val serverWebPort: Flow<Int> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SERVER_WEB_PORT, profile)] ?: CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT
    }

    val vkAuthMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        when (prefs[getProfileKey(VK_AUTH_MODE, profile)]) {
            CsqttConstants.VkAuth.MODE_CAPTCHA -> CsqttConstants.VkAuth.MODE_CAPTCHA
            CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
            else -> CsqttConstants.VkAuth.MODE_CALLS
        }
    }
    val obfsMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val mode = prefs[getProfileKey(OBFS_MODE, profile)]
        if (mode.isNullOrBlank()) {
            CsqttConstants.Tunnel.DEFAULT_OBFS_MODE
        } else if (mode == "mix" || mode == "vkquic" || mode == "callv2") {
            "video"
        } else {
            mode
        }
    }

    val turnTransport: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        when (prefs[getProfileKey(TURN_TRANSPORT, profile)]) {
            CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS -> CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS
            else -> CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT
        }
    }

    val captchaMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_MODE, profile)] ?: "auto"
    }
    val captchaSolveMethod: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] ?: "auto"
    }
    val captchaWbvSolveMethod: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] ?: "auto"
    }

    val vkHashMode: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        val mode = prefs[getProfileKey(VK_HASH_MODE, profile)]
        when (mode) {
            "auto", CsqttConstants.VkAutoHash.MODE_AUTO_API ->
                CsqttConstants.VkAutoHash.MODE_AUTO_API
            CsqttConstants.VkAutoHash.MODE_AUTO_JS ->
                CsqttConstants.VkAutoHash.MODE_AUTO_JS
            else -> CsqttConstants.VkAutoHash.MODE_MANUAL
        }
    }
    val vkAccessToken: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        readSecret(prefs, VK_ACCESS_TOKEN_ENCRYPTED, VK_ACCESS_TOKEN, profile)
    }.onIo()
    val vkAccessTokenUserId: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_ACCESS_TOKEN_USER_ID, profile)] ?: ""
    }

    val isWhitelist: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(IS_WHITELIST, profile)] ?: false
    }

    val extraWorkers: Flow<Boolean> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(EXTRA_WORKERS, profile)] ?: false
    }
    val autoJsRiskAcknowledged: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[AUTO_JS_RISK_ACKNOWLEDGED] ?: false
    }
    val tcpTransportRiskAcknowledged: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[TCP_TRANSPORT_RISK_ACKNOWLEDGED] ?: false
    }
    val autoPauseOnWifi: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[AUTO_PAUSE_ON_WIFI] ?: false
    }
    suspend fun isBatteryOptimizationPromptHandled(): Boolean =
        dataStore.data.first()[BATTERY_OPTIMIZATION_PROMPT_HANDLED] ?: false

    val themeMode: Flow<String> = dataStore.data.map { it[THEME_MODE] ?: "system" }
    val isDynamicColor: Flow<Boolean> = dataStore.data.map { it[IS_DYNAMIC_COLOR] ?: false }
    val themePalette: Flow<String> = dataStore.data.map { it[THEME_PALETTE] ?: "indigo" }

    val selectedFingerprint: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] ?: "firefox"
    }
    val activeClientIds: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] ?: "8202606,6287487"
    }
    val clientIdCheckResults: Flow<String> = dataStore.data.map { prefs ->
        prefs[CLIENT_ID_CHECK_RESULTS] ?: "{}"
    }
    val vkHashCheckResults: Flow<String> = dataStore.data.map { prefs ->
        val profile = prefs[ACTIVE_PROFILE] ?: 0
        prefs[getProfileKey(VK_HASH_CHECK_RESULTS, profile)] ?: "{}"
    }
    val connectionGeneration: Flow<Long> = dataStore.data.map { prefs ->
        prefs[CONNECTION_GENERATION] ?: 0L
    }

    val tunnelWasRunning: Flow<Boolean> = dataStore.data.map { it[TUNNEL_WAS_RUNNING] ?: false }
    val updateLastCheckAt: Flow<Long> = dataStore.data.map { it[UPDATE_LAST_CHECK_AT] ?: 0L }
    val updateLatestVersion: Flow<String> = dataStore.data.map { it[UPDATE_LATEST_VERSION] ?: "" }
    val updateLastError: Flow<String> = dataStore.data.map { it[UPDATE_LAST_ERROR] ?: "" }
    val updateCheckIntervalHours: Flow<Int> = dataStore.data.map { it[UPDATE_CHECK_INTERVAL_HOURS] ?: 24 }
    val updatePostponeUntil: Flow<Long> = dataStore.data.map { it[UPDATE_POSTPONE_UNTIL] ?: 0L }
    val updatePostponeVersion: Flow<String> = dataStore.data.map { it[UPDATE_POSTPONE_VERSION] ?: "" }

    suspend fun saveTunnelWasRunning(running: Boolean) {
        dataStore.edit { prefs ->
            prefs[TUNNEL_WAS_RUNNING] = running
        }
    }

    suspend fun saveThemeMode(mode: String) {
        dataStore.edit { prefs ->
            prefs[THEME_MODE] = mode
        }
    }

    suspend fun saveDynamicColor(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[IS_DYNAMIC_COLOR] = enabled
        }
    }

    suspend fun saveThemePalette(palette: String) {
        dataStore.edit { prefs ->
            prefs[THEME_PALETTE] = palette
        }
    }

    suspend fun saveFingerprint(fingerprint: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SELECTED_FINGERPRINT, profile)] = fingerprint
        }
    }

    suspend fun saveActiveClientIds(clientIds: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(ACTIVE_CLIENT_IDS, profile)] = clientIds
        }
    }

    suspend fun saveClientIdCheckResults(resultsJson: String) {
        dataStore.edit { prefs ->
            prefs[CLIENT_ID_CHECK_RESULTS] = resultsJson
        }
    }

    suspend fun saveVkHashCheckResults(resultsJson: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(VK_HASH_CHECK_RESULTS, profile)] = resultsJson
        }
    }

    suspend fun invalidateVkHash(hash: String) {
        val normalized = hash.trim()
        if (normalized.isEmpty()) return
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val key = getProfileKey(VK_HASH_CHECK_RESULTS, profile)
            val results = VkHashValidationCodec.decode(prefs[key] ?: "{}") +
                (normalized to VkHashValidationStatus.Invalid)
            prefs[key] = VkHashValidationCodec.encode(results)
        }
    }

    suspend fun reserveConnectionGeneration(
        proposed: Long = 0L,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ): Long {
        var reserved = 0L
        dataStore.edit { prefs ->
            reserved = reserveTunnelGenerationId(
                nowSeconds.coerceAtLeast(0L),
                proposed.coerceAtLeast(0L),
                prefs[CONNECTION_GENERATION] ?: 0L,
            )
            prefs[CONNECTION_GENERATION] = reserved
        }
        return reserved
    }

    suspend fun recordConnectionGeneration(generation: Long): Long {
        var persisted = 0L
        dataStore.edit { prefs ->
            persisted = maxOf(prefs[CONNECTION_GENERATION] ?: 0L, generation.coerceAtLeast(0L))
            prefs[CONNECTION_GENERATION] = persisted
        }
        return persisted
    }

    suspend fun saveUpdateState(lastCheckAt: Long, latestVersion: String, error: String) {
        dataStore.edit { prefs ->
            prefs[UPDATE_LAST_CHECK_AT] = lastCheckAt
            prefs[UPDATE_LATEST_VERSION] = latestVersion
            prefs[UPDATE_LAST_ERROR] = error
        }
    }

    suspend fun saveUpdateCheckIntervalHours(hours: Int) {
        dataStore.edit { prefs ->
            prefs[UPDATE_CHECK_INTERVAL_HOURS] = hours
        }
    }

    suspend fun saveUpdatePostpone(version: String, until: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_POSTPONE_VERSION] = version
            prefs[UPDATE_POSTPONE_UNTIL] = until
        }
    }

    suspend fun saveUpdateDialogShown(version: String, shownAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_SHOWN_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_SHOWN_AT] = shownAt
        }
    }

    suspend fun saveUpdateDialogAction(version: String, action: String, actedAt: Long) {
        dataStore.edit { prefs ->
            prefs[UPDATE_DIALOG_LAST_ACTION_VERSION] = version
            prefs[UPDATE_DIALOG_LAST_ACTION] = action
            prefs[UPDATE_DIALOG_LAST_ACTION_AT] = actedAt
        }
    }

    suspend fun saveActiveProfile(profile: Int) {
        dataStore.edit { prefs ->
            prefs[ACTIVE_PROFILE] = profile.coerceIn(
                CsqttConstants.Profiles.MIN_INDEX,
                CsqttConstants.Profiles.MAX_INDEX,
            )
        }
    }

    suspend fun saveShowSystemApps(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[SHOW_SYSTEM_APPS] = enabled
        }
    }

    suspend fun saveLoggingEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[LOGGING_ENABLED] = enabled
        }
    }

    suspend fun saveInfoActionsExpanded(expanded: Boolean) {
        dataStore.edit { prefs ->
            prefs[INFO_ACTIONS_EXPANDED] = expanded
        }
    }

    suspend fun saveInfoProjectExpanded(expanded: Boolean) {
        dataStore.edit { prefs ->
            prefs[INFO_PROJECT_EXPANDED] = expanded
        }
    }

    suspend fun saveCsqttLink(link: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CSQTT_LINK, profile)] = link
        }
    }

    suspend fun saveCsqttLinkMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CSQTT_LINK_MODE, profile)] = enabled
        }
    }

    suspend fun saveWorkersPerHash(workersPerHash: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val isExtra = prefs[getProfileKey(EXTRA_WORKERS, profile)] ?: false
            val max = WorkerCountPolicy.defaultMaximum(isExtra)
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = WorkerCountPolicy.normalize(workersPerHash, maximum = max)
        }
    }

    suspend fun saveParticipantTunnelSettings(vkHashes: String, workersPerHash: Int) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val isExtra = prefs[getProfileKey(EXTRA_WORKERS, profile)] ?: false
            val max = WorkerCountPolicy.defaultMaximum(isExtra)
            prefs[getProfileKey(VK_HASHES, profile)] = vkHashes
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] =
                WorkerCountPolicy.normalize(workersPerHash, maximum = max)
        }
    }

    suspend fun save(
        peer: String,
        vkHashes: String,
        secondaryVkHash: String,
        workersPerHash: Int,
        protocol: String,
        listenPort: Int,
        sni: String = "",
        noDns: Boolean = false
    ) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val isExtra = prefs[getProfileKey(EXTRA_WORKERS, profile)] ?: false
            val max = WorkerCountPolicy.defaultMaximum(isExtra)
            prefs[getProfileKey(PEER, profile)] = peer
            prefs[getProfileKey(VK_HASHES, profile)] = vkHashes
            prefs[getProfileKey(SECONDARY_VK_HASH, profile)] = secondaryVkHash
            prefs[getProfileKey(WORKERS_PER_HASH, profile)] = WorkerCountPolicy.normalize(workersPerHash, maximum = max)
            prefs[getProfileKey(PROTOCOL, profile)] = protocol
            prefs[getProfileKey(LISTEN_PORT, profile)] = listenPort
            prefs[getProfileKey(SNI, profile)] = sni
            prefs[getProfileKey(NO_DNS, profile)] = noDns
        }
    }

    suspend fun saveManualPortsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(MANUAL_PORTS_ENABLED, profile)] = enabled
            if (!enabled) {
                prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] = CsqttConstants.Network.DEFAULT_SSH_PORT.toString()
                prefs[getProfileKey(SERVER_PEER_PORT, profile)] = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT
                prefs[getProfileKey(SERVER_WEB_PORT, profile)] = CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT
            }
        }
    }

    suspend fun saveSshKeysMode(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SSH_KEYS_MODE, profile)] = enabled
        }
    }

    suspend fun saveDockerInstall(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(DOCKER_INSTALL, profile)] = enabled
        }
    }

    suspend fun saveSshKeys(privateKey: String, keyPassphrase: String, certificate: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.putSecret(SSH_PRIVATE_KEY_ENCRYPTED, SSH_PRIVATE_KEY, privateKey, profile)
            prefs.putSecret(SSH_KEY_PASSPHRASE_ENCRYPTED, SSH_KEY_PASSPHRASE, keyPassphrase, profile)
            prefs.putSecret(SSH_CERTIFICATE_ENCRYPTED, SSH_CERTIFICATE, certificate, profile)
        }
    }

    suspend fun savePorts(peer: Int, web: Int, sshPortStr: String) {
        val profile = activeProfile.first()
        dataStore.edit { prefs ->
            prefs[getProfileKey(SERVER_PEER_PORT, profile)] = peer
            prefs[getProfileKey(SERVER_WEB_PORT, profile)] = web
            prefs[getProfileKey(DEPLOY_SSH_PORT, profile)] = sshPortStr
        }
    }

    suspend fun saveServerPeerPort(peer: Int) {
        if (peer !in 1..65535) return
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(SERVER_PEER_PORT, profile)] = peer
        }
    }

    suspend fun saveDeploy(ip: String) {
        val profile = activeProfile.first()
        dataStore.edit { prefs ->
            prefs[getProfileKey(DEPLOY_IP, profile)] = ip
        }
    }

    suspend fun saveExcludedApps(packages: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(EXCLUDED_APPS, profile)] = packages
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    suspend fun saveConnectionPassword(password: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val localKey = getProfileKey(CONNECTION_PASSWORD_LOCAL, profile)
            val legacyKey = getProfileKey(CONNECTION_PASSWORD, profile)
            val encryptedKey = getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile)
            if (password.isBlank()) {
                prefs.remove(localKey)
            } else {
                prefs[localKey] = password
            }
            prefs.remove(legacyKey)
            prefs.remove(encryptedKey)
        }
    }

    suspend fun resetUnreadableConnectionPassword(): Boolean {
        var reset = false
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val localKey = getProfileKey(CONNECTION_PASSWORD_LOCAL, profile)
            val legacyKey = getProfileKey(CONNECTION_PASSWORD, profile)
            val encryptedKey = getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile)
            if (
                shouldResetUnreadableTunnelPassword(
                    prefs[localKey],
                    prefs[legacyKey],
                    prefs[encryptedKey],
                    secureStore::decrypt,
                )
            ) {
                prefs.remove(localKey)
                prefs.remove(legacyKey)
                prefs.remove(encryptedKey)
                reset = true
            }
        }
        return reset
    }

    suspend fun saveDeploySecrets(mainPass: String, sshLogin: String, sshPass: String, webLogin: String, webPass: String) {
        val profile = activeProfile.first()
        dataStore.edit { prefs ->
            prefs.putSecret(DEPLOY_MAIN_PASSWORD_ENCRYPTED, DEPLOY_MAIN_PASSWORD, mainPass, profile)
            prefs[getProfileKey(DEPLOY_LOGIN, profile)] = sshLogin
            prefs.putSecret(DEPLOY_PASSWORD_ENCRYPTED, DEPLOY_PASSWORD, sshPass, profile)
            prefs[getProfileKey(DEPLOY_WEB_LOGIN, profile)] = webLogin
            prefs.putSecret(DEPLOY_WEB_PASSWORD_ENCRYPTED, DEPLOY_WEB_PASSWORD, webPass, profile)
        }
    }

    suspend fun saveVkAuthMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val normalized = when (mode) {
                CsqttConstants.VkAuth.MODE_CAPTCHA -> CsqttConstants.VkAuth.MODE_CAPTCHA
                CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
                else -> CsqttConstants.VkAuth.MODE_CALLS
            }
            prefs[getProfileKey(VK_AUTH_MODE, profile)] = normalized
            prefs[getProfileKey(VK_HASH_MODE, profile)] = vkHashModeForAuthMode(
                requestedAuthMode = normalized,
                currentHashMode = prefs[getProfileKey(VK_HASH_MODE, profile)],
                hasVkToken = readSecret(prefs, VK_ACCESS_TOKEN_ENCRYPTED, VK_ACCESS_TOKEN, profile).isNotBlank(),
            )
        }
    }

    suspend fun saveObfsMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(OBFS_MODE, profile)] = mode
        }
    }

    suspend fun saveTurnTransport(transport: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(TURN_TRANSPORT, profile)] = when (transport) {
                CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS -> CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS
                else -> CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT
            }
        }
    }

    suspend fun saveExtraWorkers(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(EXTRA_WORKERS, profile)] = enabled
            if (!enabled) {
                val current = prefs[getProfileKey(WORKERS_PER_HASH, profile)] ?: 18
                val maximum = CsqttConstants.Tunnel.DEFAULT_MAX_WORKERS
                if (current > maximum) {
                    prefs[getProfileKey(WORKERS_PER_HASH, profile)] = maximum
                }
            }
        }
    }

    suspend fun saveAutoJsRiskAcknowledged(acknowledged: Boolean) {
        dataStore.edit { prefs ->
            prefs[AUTO_JS_RISK_ACKNOWLEDGED] = acknowledged
        }
    }

    suspend fun saveTcpTransportRiskAcknowledged(acknowledged: Boolean) {
        dataStore.edit { prefs ->
            prefs[TCP_TRANSPORT_RISK_ACKNOWLEDGED] = acknowledged
        }
    }

    suspend fun saveAutoPauseOnWifi(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[AUTO_PAUSE_ON_WIFI] = enabled
        }
    }

    suspend fun markBatteryOptimizationPromptHandled() {
        dataStore.edit { prefs ->
            prefs[BATTERY_OPTIMIZATION_PROMPT_HANDLED] = true
        }
    }

    suspend fun saveCaptchaMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_MODE, profile)] = mode
        }
    }

    suspend fun saveCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
        }
    }

    suspend fun saveWbvCaptchaSolveMethod(method: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(CAPTCHA_WBV_SOLVE_METHOD, profile)] = method
            if (prefs[getProfileKey(CAPTCHA_MODE, profile)] == "wv") {
                prefs[getProfileKey(CAPTCHA_SOLVE_METHOD, profile)] = method
            }
        }
    }

    suspend fun saveVkHashMode(mode: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            val currentAuthMode = prefs[getProfileKey(VK_AUTH_MODE, profile)]
            val nextAuthMode = vkAuthModeForHashMode(mode, currentAuthMode)
            val selection = normalizeVkModeSelection(
                requestedAuthMode = nextAuthMode,
                requestedHashMode = mode,
                hasVkToken = readSecret(prefs, VK_ACCESS_TOKEN_ENCRYPTED, VK_ACCESS_TOKEN, profile).isNotBlank(),
            )
            prefs[getProfileKey(VK_AUTH_MODE, profile)] = selection.authMode
            prefs[getProfileKey(VK_HASH_MODE, profile)] = selection.hashMode
        }
    }

    suspend fun saveVkAccessToken(token: String, userId: String) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.putSecret(VK_ACCESS_TOKEN_ENCRYPTED, VK_ACCESS_TOKEN, token, profile)
            prefs[getProfileKey(VK_ACCESS_TOKEN_USER_ID, profile)] = userId
        }
    }

    suspend fun clearVkAccessToken() {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs.remove(getProfileKey(VK_ACCESS_TOKEN_ENCRYPTED, profile))
            prefs.remove(getProfileKey(VK_ACCESS_TOKEN, profile))
            prefs.remove(getProfileKey(VK_ACCESS_TOKEN_USER_ID, profile))
        }
    }

    suspend fun saveIsWhitelist(enabled: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(IS_WHITELIST, profile)] = enabled
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    suspend fun saveExceptionsMode(packages: String, isWhitelist: Boolean) {
        dataStore.edit { prefs ->
            val profile = prefs[ACTIVE_PROFILE] ?: 0
            prefs[getProfileKey(EXCLUDED_APPS, profile)] = packages
            prefs[getProfileKey(IS_WHITELIST, profile)] = isWhitelist
            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    private suspend fun migrateSecretsToKeystore() {
        dataStore.edit { prefs ->
            for (profile in CsqttConstants.Profiles.MIN_INDEX..CsqttConstants.Profiles.MAX_INDEX) {
                prefs.migrateSecret(getProfileKey(DEPLOY_PASSWORD_ENCRYPTED, profile), getProfileKey(DEPLOY_PASSWORD, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_MAIN_PASSWORD_ENCRYPTED, profile), getProfileKey(DEPLOY_MAIN_PASSWORD, profile))
                prefs.migrateSecret(getProfileKey(DEPLOY_WEB_PASSWORD_ENCRYPTED, profile), getProfileKey(DEPLOY_WEB_PASSWORD, profile))
            }
        }
    }

    private suspend fun migrateConnectionPasswordsToLocalStorage() {
        dataStore.edit { prefs ->
            for (profile in CsqttConstants.Profiles.MIN_INDEX..CsqttConstants.Profiles.MAX_INDEX) {
                val localKey = getProfileKey(CONNECTION_PASSWORD_LOCAL, profile)
                val legacyKey = getProfileKey(CONNECTION_PASSWORD, profile)
                val encryptedKey = getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile)
                val password = resolveTunnelPasswordStorage(
                    prefs[localKey],
                    prefs[legacyKey],
                    prefs[encryptedKey],
                    secureStore::decrypt,
                )
                if (password.state == StoredSecretState.Readable) {
                    if (password.value.isBlank()) {
                        prefs.remove(localKey)
                    } else {
                        prefs[localKey] = password.value
                    }
                    prefs.remove(legacyKey)
                    prefs.remove(encryptedKey)
                }
            }
        }
    }

    suspend fun migrateLegacyWhitelistMode() {
        val currentPrefs = dataStore.data.first()
        if (currentPrefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] == true) return

        val hasLegacyWhitelist =
            (CsqttConstants.Profiles.MIN_INDEX..CsqttConstants.Profiles.MAX_INDEX).any { profile ->
            currentPrefs[getProfileKey(IS_WHITELIST, profile)] == true
        }
        val installedApps = if (hasLegacyWhitelist) installedSplitTunnelPackages() else emptySet()
        dataStore.edit { prefs ->
            if (prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] == true) return@edit

            for (profile in CsqttConstants.Profiles.MIN_INDEX..CsqttConstants.Profiles.MAX_INDEX) {
                val whitelistKey = getProfileKey(IS_WHITELIST, profile)
                val appsKey = getProfileKey(EXCLUDED_APPS, profile)
                if (prefs[whitelistKey] == true) {
                    val legacyExcluded = prefs[appsKey]
                        ?.split(",")
                        ?.filter { it.isNotEmpty() }
                        ?.toSet()
                        ?: emptySet()
                    prefs[appsKey] = (installedApps - legacyExcluded).sorted().joinToString(",")
                }
            }

            prefs[SPLIT_TUNNEL_WHITELIST_MIGRATED] = true
        }
    }

    private fun installedSplitTunnelPackages(): Set<String> {
        return runCatching {
            appContext.packageManager
                .getInstalledApplications(PackageManager.GET_META_DATA)
                .map { it.packageName }
                .filter {
                    it != appContext.packageName &&
                        !it.contains("vkontakte") &&
                        !it.contains("vk.calls")
                }
                .toSet()
        }.getOrDefault(emptySet())
    }

    private fun readSecret(
        prefs: Preferences,
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        profile: Int
    ): String = readSecretState(prefs, encryptedKey, legacyKey, profile).value

    private fun readSecretState(
        prefs: Preferences,
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        profile: Int
    ): StoredSecret {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        return resolveStoredSecret(
            prefs[profEncryptedKey],
            prefs[profLegacyKey],
            secureStore::decrypt,
        )
    }

    private fun readConnectionPasswordState(
        prefs: Preferences,
        profile: Int,
    ): StoredSecret = resolveTunnelPasswordStorage(
        prefs[getProfileKey(CONNECTION_PASSWORD_LOCAL, profile)],
        prefs[getProfileKey(CONNECTION_PASSWORD, profile)],
        prefs[getProfileKey(CONNECTION_PASSWORD_ENCRYPTED, profile)],
        secureStore::decrypt,
    )

    private fun MutablePreferences.putSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>,
        value: String,
        profile: Int
    ) {
        val profEncryptedKey = getProfileKey(encryptedKey, profile)
        val profLegacyKey = getProfileKey(legacyKey, profile)
        if (value.isBlank()) {
            remove(profEncryptedKey)
            remove(profLegacyKey)
        } else {
            this[profEncryptedKey] = secureStore.encrypt(value)
            remove(profLegacyKey)
        }
    }

    private fun MutablePreferences.migrateSecret(
        encryptedKey: Preferences.Key<String>,
        legacyKey: Preferences.Key<String>
    ) {
        val legacyValue = this[legacyKey]
        val encryptedValue = this[encryptedKey]
        if (!encryptedValue.isNullOrBlank()) {
            remove(legacyKey)
            return
        }
        if (!legacyValue.isNullOrBlank()) {
            runCatching {
                this[encryptedKey] = secureStore.encrypt(legacyValue)
                remove(legacyKey)
            }
        }
    }
}
