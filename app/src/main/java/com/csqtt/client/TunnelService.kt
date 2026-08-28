// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.HttpURLConnection
import java.net.URL

private const val TUNNEL_NOTIFICATION_CHANNEL_ID = CsqttConstants.Notifications.TUNNEL_CHANNEL_ID
private const val TUNNEL_NOTIFICATION_ID = CsqttConstants.Notifications.TUNNEL_NOTIFICATION_ID
// Stats change every couple of seconds; rebuilding the notification that often
// keeps SystemUI busy for no visible benefit.
private const val NOTIFICATION_MIN_REBUILD_INTERVAL_MS = 5_000L
// A network-set change restarts the tunnel only after the set stops flapping.
private const val NETWORK_SWAP_SETTLE_MS = 4_000L
// Android can briefly report the physical default network as lost while a VPN
// is recreated or the transport hands over. Do not turn one callback into a
// PAUSE: recheck the complete physical-network set after a short grace period.
private const val NETWORK_LOSS_GRACE_MS = 2_000L
private const val AUTO_PAUSE_WIFI_RECONCILE_MS = 1_000L
private const val VK_PROBE_CONNECT_TIMEOUT_MS = 3_000
private const val VK_PROBE_READ_TIMEOUT_MS = 3_000
private val VK_PROBE_URLS = listOf(
    "https://login.vk.ru/",
    "https://api.vk.com/",
    "https://vk.ru/",
)

private data class ResolvedVkHashes(
    val value: String,
    val allowWorkerRedistribution: Boolean,
    val mode: String = CsqttConstants.VkAutoHash.MODE_MANUAL,
    val accessToken: String = "",
)

class TunnelService : Service() {
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.Default)

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var updateJob: Job? = null
    private var lastNotificationText: String? = null
    private var lastNotificationPostElapsedMs = 0L
    private var isStopping = false
    private var resourcesReleased = false
    private var foregroundStarted = false
    private lateinit var connectivityManager: ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var airplaneModeReceiver: BroadcastReceiver? = null
    private var networkSwapJob: Job? = null
    private var networkLossJob: Job? = null
    private val physicalNetworks = PhysicalNetworkTracker<Network>()
    private val physicalCandidates = mutableSetOf<Network>()
    private val vkProbeJobs = mutableMapOf<Network, Job>()
    private val vkProbeLock = Any()
    private var vkRecoveryJob: Job? = null
    private var autoPauseSettingsJob: Job? = null
    private var autoPauseWifiWatchJob: Job? = null
    private val autoPauseMutex = Mutex()
    private val wifiNetworkLock = Any()
    private val physicalWifiNetworks = mutableSetOf<Network>()
    @Volatile
    private var autoPauseOnWifiEnabled = false
    @Volatile
    private var autoPauseRequested = false
    @Volatile
    private var autoPausedForWifi = false

    override fun onCreate() {
        super.onCreate()
        TunnelManager.activeScope = serviceScope
        createNotificationChannel()

        acquireWakeLock()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        registerAirplaneModeReceiver()
        registerPhysicalNetworkCallback()
        observeAutoPauseOnWifi()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            return if (restoreTunnel()) START_STICKY else START_NOT_STICKY
        }

        when (intent.action) {
            "START" -> {
                autoPauseRequested = true
                TunnelManager.starting.value = true
                val notification = createNotification("Запуск...")
                if (!tryStartPersistentForeground(notification, "запуск VPN")) {
                    TunnelManager.starting.value = false
                    stopSelf()
                    return START_NOT_STICKY
                }

                val intentGenId = intent.getLongExtra("generation_id", 0L)
                val intentSalt = intent.getStringExtra("session_salt") ?: ""

                serviceScope.launch {
                    try {
                        val store = SettingsStore(applicationContext)
                        autoPauseOnWifiEnabled = store.autoPauseOnWifi.first()
                        TunnelManager.isLoggingEnabled = store.loggingEnabled.first()
                        if (reconcileWifiAutoPause()) return@launch
                        val genId = store.reserveConnectionGeneration(intentGenId)
                        val salt = if (intentSalt.isNotBlank() && genId == intentGenId) {
                            intentSalt
                        } else {
                            java.util.UUID.randomUUID().toString().replace("-", "")
                        }

                        val requestedWorkers = intent.getIntExtra("workers_per_hash", 18)
                        val vkAuthMode = sanitizeVkAuthMode(intent.getStringExtra("vk_auth_mode"))
                        val accountAutoJs = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
                        val isExtra = !accountAutoJs && store.extraWorkers.first()
                        val maxWorkers = WorkerCountPolicy.defaultMaximum(isExtra)
                        val workersPerHash = WorkerCountPolicy.normalize(requestedWorkers, maximum = maxWorkers)
                        TunnelManager.isLoggingEnabled = store.loggingEnabled.first()
                        val intentHashes = intent.getStringExtra("vk_hashes") ?: ""
                        val hashesFromLink = intent.getBooleanExtra("vk_hashes_from_link", false)
                        if (accountAutoJs) {
                            store.saveVkAuthMode(CsqttConstants.VkAuth.MODE_AUTO_JS)
                        }
                        if (!awaitVkNetwork()) return@launch
                        val resolvedHashes = if (hashesFromLink && !accountAutoJs) {
                            ResolvedVkHashes(intentHashes, false)
                        } else {
                            resolveAutoHashes(
                                store,
                                intentHashes,
                                workersPerHash,
                                if (accountAutoJs) CsqttConstants.VkAutoHash.MODE_AUTO_JS else null,
                            )
                        }
                        if (resolvedHashes == null) {
                            TunnelManager.updateLog(
                                "vk_auto_calls_error",
                                "Авто-режим: не удалось создать звонки VK (нет access token или ошибка VK)",
                                99,
                                true,
                            )
                            launch(Dispatchers.Main) { stopTunnel() }
                            return@launch
                        }

                        val params = TunnelParams(
                            peer = intent.getStringExtra("peer") ?: "",
                            vkHashes = resolvedHashes.value,
                            secondaryVkHash = intent.getStringExtra("secondary_vk_hash") ?: "",
                            workersPerHash = workersPerHash,
                            port = intent.getIntExtra("port", 0),
                            sni = intent.getStringExtra("sni") ?: "",
                            connectionPassword = intent.getStringExtra("connection_password") ?: "",
                            protocol = intent.getStringExtra("protocol") ?: "udp",
                            vkAuthMode = vkAuthMode,
                            captchaMode = sanitizeCaptchaMode(intent.getStringExtra("captcha_mode")),
                            captchaSolveMethod = intent.getStringExtra("captcha_solve_method") ?: "auto",
                            fingerprint = intent.getStringExtra("fingerprint") ?: "firefox",
                            clientIds = intent.getStringExtra("client_ids") ?: "8202606,6287487",
                            obfsMode = intent.getStringExtra("obfs_mode")
                                ?.takeIf { it.isNotBlank() }
                                ?.let { if (it == "mix" || it == "vkquic" || it == "callv2") "video" else it }
                                ?: CsqttConstants.Tunnel.DEFAULT_OBFS_MODE,
                            turnTransport = intent.getStringExtra("turn_transport")
                                ?.takeIf { it == CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS }
                                ?: CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT,
                            generationId = genId,
                            sessionSalt = salt,
                            allowHashRedistribution = resolvedHashes.allowWorkerRedistribution,
                            vkHashMode = resolvedHashes.mode,
                            vkAccessToken = resolvedHashes.accessToken,
                        )
                        launch(Dispatchers.Main) {
                            startTunnel(params)
                        }
                    } catch (e: Exception) {
                        Log.e("TunnelService", "Unable to prepare tunnel start", e)
                        TunnelManager.updateLog(
                            "service_start_error",
                            "Ошибка подготовки VPN-сервиса: ${e.message ?: e.javaClass.simpleName}",
                            99,
                            true,
                        )
                        launch(Dispatchers.Main) { stopTunnel() }
                    }
                }
            }
            "STOP", "DISCONNECT" -> {
                autoPauseRequested = false
                autoPausedForWifi = false
                TunnelManager.leaveWifiAutoPause()
                stopTunnel(finishVkCalls = true)
            }
            CsqttConstants.General.ACTION_RESTART_WHEN_VK_REACHABLE -> verifyVkAndRestart()
            CsqttConstants.General.ACTION_VERIFY_VK_REACHABILITY -> verifyVkAndSuspend()
            CsqttConstants.General.ACTION_RECOVER_VK_CALL -> {
                recoverUnavailableVkCall(
                    intent.getStringExtra(CsqttConstants.General.EXTRA_UNAVAILABLE_VK_HASH).orEmpty(),
                )
            }
            "DEPLOY_START" -> {
                try {
                    isStopping = false
                    resourcesReleased = false
                    val notification = createNotification("Установка на сервер...", "DEPLOY_CANCEL", "Отменить")
                    startPersistentForeground(notification)
                    prepareForDeploy()
                    acquireWakeLock()
                } catch (e: Exception) {
                    DeployManager.writeError(
                        "Deploy foreground service error (${e.javaClass.simpleName}): ${e.message}\n" +
                            e.stackTraceToString().take(1200)
                    )
                    TunnelManager.addDeployErrorLog(
                        "Не удалось запустить сервис установки: ${e.message?.take(120) ?: e.javaClass.simpleName}"
                    )
                    DeployManager.stopDeploy("Не удалось запустить сервис установки: ${e.message?.take(120)}")
                    runCatching { releaseTunnelResources() }
                    runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                    foregroundStarted = false
                    stopSelf()
                    return START_NOT_STICKY
                }
            }
            "DEPLOY_CANCEL" -> {
                com.csqtt.client.DeployManager.writeError("✗ Установка отменена пользователем")
                com.csqtt.client.DeployManager.stopDeploy("error: Отменена пользователем")
                if (TunnelManager.running.value) {
                    lastNotificationText = null
                    lastNotificationPostElapsedMs = 0L
                    updateNotification(buildTunnelNotificationText())
                } else {
                    stopTunnel()
                }
            }
            "DEPLOY_STOP" -> {
                if (!TunnelManager.running.value) {
                    stopTunnel()
                } else {
                    updateNotification("Туннель активен")
                }
            }
            "RESTORE_NOTIFICATION" -> {
                if (foregroundStarted && !isStopping) {
                    lastNotificationText = null
                    lastNotificationPostElapsedMs = 0L
                    updateNotification(currentNotificationText())
                }
            }
        }
        return START_STICKY
    }

    private fun restoreTunnel(): Boolean {
        TunnelManager.starting.value = true
        val notification = createNotification("Восстановление соединения...")
        if (!tryStartPersistentForeground(notification, "восстановление VPN")) {
            TunnelManager.starting.value = false
            stopSelf()
            return false
        }

        val appContext = applicationContext
        TunnelManager.scope.launch {
            try {
                val store = SettingsStore(appContext)

                // Проверяем: был ли CSQTT активен до перезапуска.
                // Если нет — не поднимаем VPN: устройство может работать с другим VPN (напр. WireGuard).
                // Android VPN API: при establish() всегда отзывает текущий VPN другого приложения.
                val wasRunning = store.tunnelWasRunning.first()
                if (!wasRunning) {
                    Log.d("TunnelService", "restoreTunnel: tunnelWasRunning=false, автостарт отменён — чужой VPN не нужно убивать")
                    launch(Dispatchers.Main) { stopTunnel() }
                    return@launch
                }
                autoPauseRequested = true
                autoPauseOnWifiEnabled = store.autoPauseOnWifi.first()
                TunnelManager.isLoggingEnabled = store.loggingEnabled.first()
                if (reconcileWifiAutoPause()) return@launch

                val source = resolveConnectionSource(store)
                val genId = store.reserveConnectionGeneration()
                val salt = java.util.UUID.randomUUID().toString().replace("-", "")
                val vkAuthMode = sanitizeVkAuthMode(store.vkAuthMode.first())
                val workersPerHash = WorkerCountPolicy.normalize(store.workersPerHash.first())
                TunnelManager.isLoggingEnabled = store.loggingEnabled.first()
                val accountAutoJs = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
                if (!awaitVkNetwork()) return@launch
                val restoredHashes = when {
                    source == null -> null
                    source.hashesFromLink && !accountAutoJs -> ResolvedVkHashes(source.hashes, false)
                    else -> resolveAutoHashes(
                        store,
                        source.hashes,
                        workersPerHash,
                        if (accountAutoJs) CsqttConstants.VkAutoHash.MODE_AUTO_JS else null,
                    )
                }
                val params = TunnelParams(
                    peer = source?.peer.orEmpty(),
                    vkHashes = restoredHashes?.value ?: "",
                    secondaryVkHash = store.secondaryVkHash.first(),
                    workersPerHash = workersPerHash,
                    port = 0,
                    sni = store.sni.first(),
                    connectionPassword = source?.password.orEmpty(),
                    obfsMode = store.obfsMode.first(),
                    turnTransport = store.turnTransport.first(),
                    vkAuthMode = vkAuthMode,
                    captchaMode = sanitizeCaptchaMode(store.captchaMode.first()),
                    captchaSolveMethod = store.captchaSolveMethod.first(),
                    fingerprint = store.selectedFingerprint.first(),
                    clientIds = store.activeClientIds.first(),
                    generationId = genId,
                    sessionSalt = salt,
                    allowHashRedistribution = restoredHashes?.allowWorkerRedistribution == true,
                    vkHashMode = restoredHashes?.mode ?: CsqttConstants.VkAutoHash.MODE_MANUAL,
                    vkAccessToken = restoredHashes?.accessToken.orEmpty(),
                )
                if (
                    params.peer.isNotEmpty() &&
                    (
                        params.vkHashes.isNotEmpty() ||
                            params.vkHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS
                    )
                ) {
                    launch(Dispatchers.Main) {
                        startTunnel(params)
                    }
                } else {
                    launch(Dispatchers.Main) {
                        stopTunnel()
                    }
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    stopTunnel()
                }
            }
        }
        return true
    }

    private suspend fun resolveAutoHashes(
        store: SettingsStore,
        fallbackHashes: String,
        workersPerHash: Int,
        forcedMode: String? = null,
    ): ResolvedVkHashes? {
        return when (val mode = forcedMode ?: store.vkHashMode.first()) {
            CsqttConstants.VkAutoHash.MODE_AUTO_API -> {
                val token = store.vkAccessToken.first()
                val result = VkAutoCallsManager.startAutoCalls(applicationContext, token, workersPerHash)
                    ?: return null
                ResolvedVkHashes(
                    result.hashes,
                    result.needsWorkerRedistribution,
                    mode,
                )
            }

            CsqttConstants.VkAutoHash.MODE_AUTO_JS -> {
                val token = store.vkAccessToken.first()
                if (token.isBlank()) return null
                ResolvedVkHashes(
                    "",
                    true,
                    mode,
                    token,
                )
            }

            else -> ResolvedVkHashes(fallbackHashes, false)
        }
    }

    private fun recoverUnavailableVkCall(hash: String) {
        if (hash.isBlank()) {
            TunnelManager.completeVkCallRecovery()
            return
        }
        serviceScope.launch {
            var restartScheduled = false
            try {
                val previous = TunnelManager.getCurrentParams() ?: return@launch
                val store = SettingsStore(applicationContext)
                val vkHashMode = store.vkHashMode.first()
                if (vkHashMode == CsqttConstants.VkAutoHash.MODE_MANUAL) {
                    return@launch
                }
                val source = resolveConnectionSource(store) ?: return@launch
                val accountAutoJs = previous.vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
                val workers = WorkerCountPolicy.normalize(
                    store.workersPerHash.first(),
                    maximum = WorkerCountPolicy.defaultMaximum(
                        !accountAutoJs && store.extraWorkers.first(),
                    ),
                )
                val resolved = when {
                    accountAutoJs -> resolveAutoHashes(
                        store,
                        fallbackHashes = "",
                        workersPerHash = workers,
                        forcedMode = CsqttConstants.VkAutoHash.MODE_AUTO_JS,
                    )
                    vkHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_API -> resolveAutoHashes(
                        store,
                        fallbackHashes = source.hashes,
                        workersPerHash = workers,
                    )
                    else -> ResolvedVkHashes(source.hashes, false)
                } ?: return@launch
                if (resolved.value.isBlank() && resolved.mode != CsqttConstants.VkAutoHash.MODE_AUTO_JS) {
                    launch(Dispatchers.Main) { TunnelManager.stop() }
                    return@launch
                }
                val nextGeneration = store.reserveConnectionGeneration(
                    proposed = if (previous.generationId == Long.MAX_VALUE) {
                        Long.MAX_VALUE
                    } else {
                        previous.generationId + 1
                    },
                )
                val next = previous.copy(
                    peer = source.peer,
                    vkHashes = resolved.value,
                    workersPerHash = workers,
                    connectionPassword = source.password,
                    generationId = nextGeneration,
                    sessionSalt = java.util.UUID.randomUUID().toString().replace("-", ""),
                    allowHashRedistribution = resolved.allowWorkerRedistribution,
                    vkHashMode = resolved.mode,
                    vkAccessToken = resolved.accessToken,
                )
                launch(Dispatchers.Main) {
                    TunnelManager.start(applicationContext, next, isSwitching = true)
                }
                restartScheduled = true
            } finally {
                if (!restartScheduled) TunnelManager.completeVkCallRecovery()
            }
        }
    }

    private fun tryStartPersistentForeground(notification: Notification, operation: String): Boolean {
        return try {
            startPersistentForeground(notification)
            true
        } catch (e: Exception) {
            Log.e("TunnelService", "Foreground service rejected during $operation", e)
            TunnelManager.updateLog(
                "foreground_start_error",
                "Android заблокировал foreground-сервис ($operation): ${e.message ?: e.javaClass.simpleName}",
                99,
                true,
            )
            false
        }
    }

    private fun startTunnel(params: TunnelParams) {
        autoPauseRequested = true
        if (autoPauseOnWifiEnabled && hasPhysicalWifiNetwork()) {
            serviceScope.launch { reconcileWifiAutoPause() }
            return
        }
        updateNotification("Подключение...")
        acquireWakeLock()
        acquireWifiLock()

        CaptchaWebViewManager.onTunnelStart(applicationContext)

        // Сохраняем: пользователь явно запустил CSQTT — авторестарт при холодном старте разрешён
        serviceScope.launch {
            runCatching { SettingsStore(applicationContext).saveTunnelWasRunning(true) }
        }

        TunnelManager.start(this, params)
        if (!physicalNetworks.hasUsableNetwork()) {
            TunnelManager.suspendForNoNetwork(physicalNetworkPauseReason(isAirplaneModeOn()))
        }
        TunnelManager.scope.launch(Dispatchers.Main) {
            VkAutoCallsManager.replayPendingLogs()
        }
        startStatsUpdater()
    }

    private fun registerPhysicalNetworkCallback() {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                networkLossJob?.cancel()
                networkLossJob = null
                requestWifiAutoPauseReconciliation()
                rememberPhysicalCandidate(network)
                if (autoPausedForWifi) return
                startVkNetworkProbe(network)
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                updatePhysicalWifiNetwork(network, capabilities)
                requestWifiAutoPauseReconciliation()
                if (hasPhysicalInternetCapability(capabilities)) {
                    rememberPhysicalCandidate(network)
                    if (autoPausedForWifi) return
                    startVkNetworkProbe(network)
                } else {
                    forgetPhysicalNetwork(network)
                }
            }

            override fun onLost(network: Network) {
                forgetPhysicalWifiNetwork(network)
                requestWifiAutoPauseReconciliation()
                forgetPhysicalNetwork(network)
            }
        }
        networkCallback = callback
        runCatching {
            connectivityManager.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                callback,
            )
        }.onFailure {
            Log.w("TunnelService", "Unable to register physical network callback", it)
            networkCallback = null
        }
    }

    private fun rememberPhysicalCandidate(network: Network) {
        synchronized(vkProbeLock) {
            physicalCandidates.add(network)
        }
    }

    private fun isPhysicalCandidate(network: Network): Boolean = synchronized(vkProbeLock) {
        network in physicalCandidates
    }

    private fun startVkNetworkProbe(network: Network) {
        if (autoPausedForWifi) return
        if (physicalNetworks.isUsable(network)) return
        synchronized(vkProbeLock) {
            if (network !in physicalCandidates || vkProbeJobs[network]?.isActive == true) return
            val job = serviceScope.launch(Dispatchers.IO, start = CoroutineStart.LAZY) {
                var failures = 0
                try {
                    while (isActive && !physicalNetworks.isUsable(network)) {
                        if (probeVkThrough(network)) {
                            if (!isActive || !isPhysicalCandidate(network)) return@launch
                            updatePhysicalNetwork(network, true)
                            return@launch
                        }
                        failures++
                        delay(vkProbeRetryDelayMs(failures))
                    }
                } finally {
                    synchronized(vkProbeLock) {
                        if (vkProbeJobs[network] === coroutineContext[Job]) {
                            vkProbeJobs.remove(network)
                        }
                    }
                }
            }
            vkProbeJobs[network] = job
            job.start()
        }
    }

    private fun forgetPhysicalNetwork(network: Network) {
        synchronized(vkProbeLock) {
            physicalCandidates.remove(network)
            vkProbeJobs.remove(network)?.cancel()
        }
        updatePhysicalNetwork(network, false)
    }

    private fun probeVkThrough(network: Network): Boolean = VK_PROBE_URLS.any { address ->
        val connection = runCatching {
            network.openConnection(URL(address)) as HttpURLConnection
        }.getOrNull() ?: return@any false
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = VK_PROBE_CONNECT_TIMEOUT_MS
            connection.readTimeout = VK_PROBE_READ_TIMEOUT_MS
            connection.useCaches = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("Connection", "close")
            connection.setRequestProperty("Range", "bytes=0-0")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")
            isVkProbeHttpResponse(connection.responseCode)
        } catch (_: Exception) {
            false
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun awaitVkNetwork(): Boolean {
        while (serviceScope.coroutineContext[Job]?.isActive != false) {
            if (physicalNetworks.hasUsableNetwork()) return true
            currentPhysicalCandidates().forEach { network ->
                rememberPhysicalCandidate(network)
                startVkNetworkProbe(network)
            }
            delay(250)
        }
        return false
    }

    private fun currentPhysicalCandidates(): List<Network> {
        val candidates = synchronized(vkProbeLock) { physicalCandidates.toList() }
        if (candidates.isNotEmpty()) return candidates
        val active = runCatching { connectivityManager.activeNetwork }.getOrNull() ?: return emptyList()
        val usable = runCatching {
            connectivityManager.getNetworkCapabilities(active)
                ?.let(::hasPhysicalInternetCapability) == true
        }.getOrDefault(false)
        return if (usable) listOf(active) else emptyList()
    }

    private fun verifyVkAndRestart() {
        if (vkRecoveryJob?.isActive == true) return
        vkRecoveryJob = serviceScope.launch(Dispatchers.IO) {
            try {
                if (!TunnelManager.running.value || TunnelManager.activeWorkers.value != 0) {
                    return@launch
                }
                val candidates = currentPhysicalCandidates()
                val ready = candidates.firstOrNull(::probeVkThrough)
                if (ready != null) {
                    rememberPhysicalCandidate(ready)
                    updatePhysicalNetwork(ready, true)
                    if (TunnelManager.activeWorkers.value == 0) {
                        TunnelManager.restartAfterVkRecovery(applicationContext)
                    }
                    return@launch
                }
                // A failed HTTP probe is not Android reporting that the radio
                // disappeared. TURN can transiently time out while HTTPS is
                // rate-limited or the VK endpoint is busy. Keep the existing
                // physical network usable and let the core recover workers;
                // only NetworkCallback.onLost is allowed to pause the tunnel.
                candidates.forEach { network ->
                    rememberPhysicalCandidate(network)
                    startVkNetworkProbe(network)
                }
            }
            finally {
                if (vkRecoveryJob === coroutineContext[Job]) vkRecoveryJob = null
            }
        }
    }

    private fun verifyVkAndSuspend() {
        if (vkRecoveryJob?.isActive == true) return
        vkRecoveryJob = serviceScope.launch(Dispatchers.IO) {
            try {
                val candidates = currentPhysicalCandidates()
                val ready = candidates.firstOrNull(::probeVkThrough)
                if (ready != null) {
                    rememberPhysicalCandidate(ready)
                    updatePhysicalNetwork(ready, true)
                    return@launch
                }
                // Do not turn a failed VK reachability probe into a global
                // PAUSE. The callback still delivers a real physical-network
                // loss through forgetPhysicalNetwork/onLost.
                candidates.forEach { network ->
                    rememberPhysicalCandidate(network)
                    startVkNetworkProbe(network)
                }
            } finally {
                if (vkRecoveryJob === coroutineContext[Job]) vkRecoveryJob = null
            }
        }
    }

    private fun updatePhysicalNetwork(network: Network, usable: Boolean) {
        val transition = physicalNetworks.update(network, usable)
        if (autoPausedForWifi) return
        when (transition) {
            PhysicalNetworkTransition.AVAILABLE -> {
                networkLossJob?.cancel()
                networkLossJob = null
                TunnelManager.onPhysicalNetworkAvailable(applicationContext)
            }
            PhysicalNetworkTransition.UNAVAILABLE -> {
                networkSwapJob?.cancel()
                schedulePhysicalNetworkLossCheck()
            }
            PhysicalNetworkTransition.CHANGED -> {
                scheduleNetworkSwapRestart()
            }
            PhysicalNetworkTransition.NONE -> Unit
        }
    }

    private fun schedulePhysicalNetworkLossCheck() {
        if (networkLossJob?.isActive == true) return
        networkLossJob = serviceScope.launch {
            delay(NETWORK_LOSS_GRACE_MS)
            if (physicalNetworks.hasUsableNetwork() || autoPausedForWifi) return@launch

            // A replacement Network can already be the system default even if
            // its callback arrived out of order. Start its probe rather than
            // emitting a false "network disconnected" state.
            currentPhysicalCandidates().forEach { network ->
                rememberPhysicalCandidate(network)
                startVkNetworkProbe(network)
            }
            if (!physicalNetworks.hasUsableNetwork()) {
                TunnelManager.suspendForNoNetwork(physicalNetworkPauseReason(isAirplaneModeOn()))
            }
        }.also { job ->
            job.invokeOnCompletion {
                if (networkLossJob === job) networkLossJob = null
            }
        }
    }

    private fun scheduleNetworkSwapRestart() {
        if (autoPausedForWifi) return
        // Wi-Fi/cellular sets flap; each CHANGED used to tear the whole tunnel
        // down. Coalesce a flapping burst into one restart after it settles.
        networkSwapJob?.cancel()
        networkSwapJob = serviceScope.launch {
            delay(NETWORK_SWAP_SETTLE_MS)
            networkSwapJob = null
            if (!physicalNetworks.hasUsableNetwork()) return@launch
            TunnelManager.restartForNetworkSwap(applicationContext)
        }
    }

    private fun registerAirplaneModeReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != Intent.ACTION_AIRPLANE_MODE_CHANGED) return
                if (isAirplaneModeOn() && !physicalNetworks.hasUsableNetwork()) {
                    TunnelManager.suspendForNoNetwork(physicalNetworkPauseReason(true))
                }
            }
        }
        val registered = runCatching {
            ContextCompat.registerReceiver(
                this,
                receiver,
                IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED),
                ContextCompat.RECEIVER_EXPORTED,
            )
        }.isSuccess
        if (registered) airplaneModeReceiver = receiver
    }

    private fun hasPhysicalInternetCapability(capabilities: NetworkCapabilities): Boolean =
        isEligiblePhysicalNetwork(
            hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            notVpn = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
            wifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
            cellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
        )

    private fun isAirplaneModeOn(): Boolean =
        runCatching {
            Settings.Global.getInt(contentResolver, Settings.Global.AIRPLANE_MODE_ON, 0) != 0
        }.getOrDefault(false)

    private fun stopTunnel(finishVkCalls: Boolean = false) {
        if (isStopping) return
        isStopping = true
        stopWifiAutoPauseWatch()
        autoPauseRequested = false
        autoPausedForWifi = false
        TunnelManager.leaveWifiAutoPause()
        TunnelManager.starting.value = false
        updateJob?.cancel()
        // Сохраняем: пользователь явно остановил CSQTT — авторестарт при холодном старте запрещён
        serviceScope.launch {
            runCatching { SettingsStore(applicationContext).saveTunnelWasRunning(false) }
        }
        releaseTunnelResources(finishVkCalls)
        stopForeground(STOP_FOREGROUND_REMOVE)
        foregroundStarted = false
        stopSelf()
    }

    private fun prepareForDeploy() {
        updateJob?.cancel()
        updateJob = null
        CaptchaWebViewManager.onTunnelStop()
        TunnelManager.stop()
        releaseWifiLock()
    }

    private fun releaseTunnelResources(finishVkCalls: Boolean = false) {
        if (resourcesReleased) return
        resourcesReleased = true
        stopWifiAutoPauseWatch()
        CaptchaWebViewManager.onTunnelStop()
        if (finishVkCalls) VkAutoCallsManager.finishActiveCalls()
        TunnelManager.stop(finishVkCalls)
        releaseWakeLock()
        releaseWifiLock()
    }

    private fun observeAutoPauseOnWifi() {
        autoPauseSettingsJob?.cancel()
        autoPauseSettingsJob = serviceScope.launch {
            SettingsStore(applicationContext).autoPauseOnWifi.collect { enabled ->
                autoPauseOnWifiEnabled = enabled
                reconcileWifiAutoPause()
            }
        }
    }

    private fun requestWifiAutoPauseReconciliation() {
        serviceScope.launch {
            reconcileWifiAutoPause()
        }
    }

    private suspend fun reconcileWifiAutoPause(): Boolean = autoPauseMutex.withLock {
        if (isStopping) return@withLock autoPausedForWifi
        when (
            wifiAutoPauseAction(
                enabled = autoPauseOnWifiEnabled,
                wifiConnected = wifiConnectedForAutoPause(),
                desiredRunning = autoPauseRequested,
                paused = autoPausedForWifi,
            )
        ) {
            WifiAutoPauseAction.PAUSE -> enterWifiAutoPause()
            WifiAutoPauseAction.RESUME -> resumeFromWifiAutoPause()
            WifiAutoPauseAction.NONE -> Unit
        }
        autoPausedForWifi
    }

    private suspend fun enterWifiAutoPause() {
        if (!autoPauseRequested || !autoPauseOnWifiEnabled || !hasPhysicalWifiNetwork()) return
        autoPausedForWifi = true
        updateJob?.cancel()
        updateJob = null
        networkSwapJob?.cancel()
        networkSwapJob = null
        vkRecoveryJob?.cancel()
        vkRecoveryJob = null
        synchronized(vkProbeLock) {
            vkProbeJobs.values.forEach(Job::cancel)
            vkProbeJobs.clear()
        }
        CaptchaWebViewManager.onTunnelStop()
        SettingsStore(applicationContext).saveTunnelWasRunning(true)
        TunnelManager.pauseForWifi()
        releaseWakeLock()
        releaseWifiLock()
        updateNotification("Ожидание. Автопауза при Wi-Fi")
        startWifiAutoPauseWatch()
    }

    private fun resumeFromWifiAutoPause() {
        if (!autoPausedForWifi || !autoPauseRequested) return
        autoPausedForWifi = false
        stopWifiAutoPauseWatch()
        TunnelManager.leaveWifiAutoPause()
        acquireWakeLock()
        TunnelManager.updateLog(
            "wifi_auto_resume",
            "[NET] Wi-Fi отключён · восстановление подключения",
            2,
            false,
            LogLevel.NET,
        )
        updateNotification("Подключение...")
        if (!restoreTunnel()) stopTunnel()
    }

    private fun startWifiAutoPauseWatch() {
        if (autoPauseWifiWatchJob?.isActive == true) return
        val job = serviceScope.launch(start = CoroutineStart.LAZY) {
            try {
                while (autoPausedForWifi && autoPauseRequested && isActive) {
                    delay(AUTO_PAUSE_WIFI_RECONCILE_MS)
                    reconcileWifiAutoPause()
                }
            } finally {
                if (autoPauseWifiWatchJob === coroutineContext[Job]) {
                    autoPauseWifiWatchJob = null
                }
            }
        }
        autoPauseWifiWatchJob = job
        job.start()
    }

    private fun stopWifiAutoPauseWatch() {
        autoPauseWifiWatchJob?.cancel()
        autoPauseWifiWatchJob = null
    }

    private fun updatePhysicalWifiNetwork(network: Network, capabilities: NetworkCapabilities) {
        val physicalWifi = hasPhysicalWifiCapability(capabilities)
        synchronized(wifiNetworkLock) {
            if (physicalWifi) {
                physicalWifiNetworks.add(network)
            } else {
                physicalWifiNetworks.remove(network)
            }
        }
    }

    private fun forgetPhysicalWifiNetwork(network: Network) {
        synchronized(wifiNetworkLock) {
            physicalWifiNetworks.remove(network)
        }
    }

    private fun wifiConnectedForAutoPause(): Boolean {
        return effectiveWifiAutoPauseConnection(
            paused = autoPausedForWifi,
            callbackWifiConnected = hasPhysicalWifiNetwork(),
            defaultPhysicalWifiConnected = defaultPhysicalWifiNetwork(),
        )
    }

    private fun defaultPhysicalWifiNetwork(): Boolean? {
        val active = runCatching { connectivityManager.activeNetwork }.getOrNull() ?: return false
        val capabilities = runCatching { connectivityManager.getNetworkCapabilities(active) }.getOrNull()
            ?: return null
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        return hasPhysicalWifiCapability(capabilities)
    }

    private fun hasPhysicalWifiNetwork(): Boolean {
        synchronized(wifiNetworkLock) {
            return physicalWifiNetworks.isNotEmpty()
        }
    }

    private fun hasPhysicalWifiCapability(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)

    private fun sanitizeCaptchaMode(mode: String?): String {
        return when (mode?.lowercase()) {
            "auto" -> "auto"
            "rjs" -> "rjs"
            "wv" -> "wv"
            else -> "auto"
        }
    }

    private fun sanitizeVkAuthMode(mode: String?): String {
        return when (mode?.lowercase()) {
            CsqttConstants.VkAuth.MODE_CAPTCHA -> CsqttConstants.VkAuth.MODE_CAPTCHA
            CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
            else -> CsqttConstants.VkAuth.MODE_CALLS
        }
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "csqtt:tunnel_cpu"
        ).apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    @Suppress("DEPRECATION")
    private fun acquireWifiLock() {
        if (wifiLock?.isHeld == true) return
        val wm = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager

        // HIGH_PERF keeps Wi-Fi awake without forcing the radio into
        // low-latency mode, which burns battery for no VPN benefit.
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "csqtt:wifi_perf").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
        }
        wakeLock = null
    }

    private fun releaseWifiLock() {
        if (wifiLock?.isHeld == true) {
            wifiLock?.release()
        }
        wifiLock = null
    }

    private fun startStatsUpdater() {
        updateJob?.cancel()
        updateJob = serviceScope.launch(Dispatchers.Main) {
            var wasEverUp = TunnelManager.running.value || TunnelManager.processStartedAtMs > 0L
            val startedAt = SystemClock.elapsedRealtime()
            delay(1000)
            while (isActive) {
                val running = TunnelManager.running.value
                wasEverUp = wasEverUp || running || TunnelManager.processStartedAtMs > 0L
                // Locks are held for the whole session; this only re-arms one
                // that the system dropped (GC of a dead service, OEM killer).
                if (running) {
                    acquireWakeLock()
                    acquireWifiLock()
                }
                if (
                    TunnelServicePolicy.shouldStop(
                        wasEverRunning = wasEverUp,
                        running = running,
                        elapsedMs = SystemClock.elapsedRealtime() - startedAt,
                    )
                ) {
                    stopTunnel()
                    break
                }
                updateNotification(currentNotificationText())
                delay(2000)
            }
        }
    }

    private fun currentNotificationText(): String {
        return buildTunnelNotificationText()
    }

    private fun buildTunnelNotificationText(): String {
        val statsText = TunnelManager.stats.value.trim()
        return when {
            statsText.isEmpty() -> "Туннель активен"
            statsText == "Ожидание данных..." -> "Туннель активен"
            else -> statsText
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            TUNNEL_NOTIFICATION_CHANNEL_ID,
            "CSQTT Туннель",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Уведомление о работе туннеля"
            setShowBadge(false)

            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
            enableVibration(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(text: String, actionName: String = "STOP", actionTitle: String = "Отключить"): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this, if (actionName == "STOP") 1 else 2,
            Intent(this, TunnelService::class.java).apply { action = actionName },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val restoreIntent = PendingIntent.getService(
            this, 3,
            Intent(this, TunnelService::class.java).apply { action = "RESTORE_NOTIFICATION" },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, TUNNEL_NOTIFICATION_CHANNEL_ID)
            .setContentTitle("CSQTT")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_c)
            .setOngoing(true)
            .setLocalOnly(true)
            .setContentIntent(openIntent)
            .addAction(R.drawable.ic_stop, actionTitle, stopIntent)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)

            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOnlyAlertOnce(true) 
            .setSilent(true) 
            .setShowWhen(false)
            .setUsesChronometer(false)
            .setWhen(0L)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setDeleteIntent(restoreIntent)
            .build()
            .also {
                it.flags = it.flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR or Notification.FLAG_FOREGROUND_SERVICE
            }
    }

    private fun startPersistentForeground(notification: Notification) {
        notification.flags = notification.flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR or Notification.FLAG_FOREGROUND_SERVICE
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(TUNNEL_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(TUNNEL_NOTIFICATION_ID, notification)
        }
        foregroundStarted = true
    }

    private fun updateNotification(text: String) {
        if (lastNotificationText == text && isNotificationVisible()) return
        val now = android.os.SystemClock.elapsedRealtime()
        if (lastNotificationText != null &&
            now - lastNotificationPostElapsedMs < NOTIFICATION_MIN_REBUILD_INTERVAL_MS
        ) {
            return
        }
        lastNotificationText = text
        lastNotificationPostElapsedMs = now
        val notification = createNotification(text)
        startPersistentForeground(notification)
    }

    private fun isNotificationVisible(): Boolean {
        return runCatching {
            getSystemService(NotificationManager::class.java)
                .activeNotifications
                .any { it.id == TUNNEL_NOTIFICATION_ID }
        }.getOrDefault(false)
    }

    override fun onDestroy() {
        isStopping = true
        autoPauseSettingsJob?.cancel()
        autoPauseSettingsJob = null
        stopWifiAutoPauseWatch()
        updateJob?.cancel()
        networkSwapJob?.cancel()
        networkSwapJob = null
        networkLossJob?.cancel()
        networkLossJob = null
        vkRecoveryJob?.cancel()
        vkRecoveryJob = null
        synchronized(vkProbeLock) {
            vkProbeJobs.values.forEach(Job::cancel)
            vkProbeJobs.clear()
            physicalCandidates.clear()
        }
        releaseTunnelResources()
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            foregroundStarted = false
        }
        serviceJob.cancel()
        networkCallback?.let { callback ->
            runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        }
        networkCallback = null
        airplaneModeReceiver?.let { receiver ->
            runCatching { unregisterReceiver(receiver) }
        }
        airplaneModeReceiver = null
        physicalNetworks.clear()
        synchronized(wifiNetworkLock) {
            physicalWifiNetworks.clear()
        }
        TunnelManager.activeScope = TunnelManager.scope
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null


}
