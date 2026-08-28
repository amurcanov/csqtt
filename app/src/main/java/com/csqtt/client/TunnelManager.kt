// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.mutableStateListOf

@Immutable
enum class LogLevel {
    OK,
    DBG,
    NET,
    PING,
    TURN,
    LOG,
    ERR,
}

@Immutable
data class LogEntry(
    val key: String,
    val message: String,
    val count: Int = 1,
    val priority: Int = 99, 
    val isError: Boolean = false,
    val level: LogLevel? = null,
)

private val LOG_STICKERS = Regex("[\\p{So}\\p{Sk}\\uFE0F\\u200D]")
private val EMPTY_LOG_TAG = Regex("\\[\\s*]")
private val LOG_TIMESTAMP_PREFIX = Regex("^\\d{4}/\\d{2}/\\d{2}\\s\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?\\s")

internal fun displayVkHash(hash: String): String = hash.trim().let { value ->
    if (value.length <= 10) value else value.take(10) + "…"
}

internal fun withoutLogStickers(message: String): String = message
    .replace(LOG_STICKERS) { symbol ->
        symbol.value.takeIf { it == "✓" || it == "✗" }.orEmpty()
    }
    .replace(EMPTY_LOG_TAG, "")
    .replace(Regex("\\s+"), " ")
    .trim()

object TunnelManager {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    var activeScope: CoroutineScope = scope

    @Volatile
    private var process: Process? = null
    @Volatile
    private var processGeneration = 0L
    @Volatile
    private var processIdentity: ProcessIdentity? = null
    @Volatile
    private var nativeProcessPid: Int? = null
    private var readerJob: Job? = null
    private var restartJob: Job? = null
    private var panelRestartJob: Job? = null
    private var workerRecoveryJob: Job? = null
    private val transportRestartPending = AtomicBoolean(false)
    private val panelRestartPending = AtomicBoolean(false)
    // A server restart can carry a changed TUNCONF DNS while the Android VPN
    // interface is still alive. Rebuild that interface once the replacement
    // client returns its configuration instead of merely re-sending its FD.
    private val vpnRebuildAfterPanelRestart = AtomicBoolean(false)
    private val callRecoveryPending = AtomicBoolean(false)
    private val workerRecoveryPolicy = WorkerRecoveryPolicy()
    private var crashRestartStreak = 0
    private const val WORKER_ZERO_CONFIRMATION_MS = 4_000L
    private const val STARTUP_DIAGNOSTIC_MS = 30_000L
    // A process that lived shorter than this counts toward the crash-loop
    // backoff; a longer-lived run resets it.
    private const val CRASH_RESTART_STABLE_MS = 30_000L
    private const val CRASH_RESTART_MAX_DELAY_MS = 60_000L
    // Stats-path VPN start retry window: the START intent fires once from the
    // Config event, then at most once per this interval until vpnReady.
    private const val VPN_START_RETRY_MS = 10_000L

    private val startStopMutex = kotlinx.coroutines.sync.Mutex()
    private val lifecycleState = TunnelLifecycleState()
    private val lifecycleCommand = AtomicLong()

    private data class ProcessIdentity(
        val process: Process,
        val generation: Long,
        val ticket: TunnelLifecycleTicket,
        val shutdownGraceMs: Long,
        val startupProgress: TunnelStartupProgress = TunnelStartupProgress(),
    ) {
        val inputLock = Any()
        val readyWorkers = mutableSetOf<Int>()
        val unavailableManualHashes = mutableSetOf<String>()
    }

    private data class PendingLog(
        val identity: ProcessIdentity?,
        val key: String,
        var message: String,
        val priority: Int,
        val isError: Boolean,
        val level: LogLevel?,
        var count: Int,
    )

    private const val LOG_UI_FLUSH_MS = 120L
    private const val MAX_LOG_ENTRIES = 100
    private const val MAX_PENDING_LOGS = 128
    private const val MAX_LOG_MESSAGE_LENGTH = 1_024
    private val pendingLogLock = Any()
    private val pendingLogs = LinkedHashMap<String, PendingLog>()
    private val pendingLogFlushScheduled = AtomicBoolean(false)

    @Volatile
    private var wrapAuthTimeoutCount = 0
    private var lastVpnStartAttemptMs = 0L
    @Volatile
    var processStartedAtMs = 0L
    @Volatile
    private var currentParams: TunnelParams? = null
    @Volatile
    private var strongAppContext: Context? = null
    @Volatile
    private var lastContext: WeakReference<Context>? = null
    private fun activeContext(): Context? = strongAppContext ?: lastContext?.get()
    @Volatile
    private var activeSettingsStore: SettingsStore? = null
    @Volatile
    private var currentCaptchaSolveMethod = "auto" 

    @Volatile
    var isLoggingEnabled = true
        set(value) {
            field = value
            if (!value) clearLogs()
        }

    val running = MutableStateFlow(false)
    val starting = MutableStateFlow(false)
    val stopping = MutableStateFlow(false)
    val logs = mutableStateListOf<LogEntry>()
    val unreadErrorCount = MutableStateFlow(0)
    val config = MutableStateFlow<String?>(null)
    val stats = MutableStateFlow("Ожидание данных...")
    val activeWorkers = MutableStateFlow(0)
    val autoPausedForWifi = MutableStateFlow(false)
    val vpnReady = MutableStateFlow(false)
    val uptimeSeconds = MutableStateFlow<Long?>(null)
    private var uptimeJob: Job? = null
    
    private val pausedForNoNetwork = NetworkPauseGate()

    val cooldownActive = MutableStateFlow(false)
    private var cooldownJob: Job? = null

    private fun startUptimeTimer() {
        processStartedAtMs = SystemClock.elapsedRealtime()
        uptimeSeconds.value = 0L
        uptimeJob?.cancel()
        uptimeJob = scope.launch(Dispatchers.Default) {
            while (isActive) {
                val start = processStartedAtMs
                val isProcessActive = running.value || process != null
                if (start > 0L && isProcessActive) {
                    uptimeSeconds.value = (SystemClock.elapsedRealtime() - start) / 1000L
                } else if (!isProcessActive && !starting.value) {
                    break
                }
                delay(1000L)
            }
        }
    }

    private fun stopUptimeTimer() {
        uptimeJob?.cancel()
        uptimeJob = null
        val start = processStartedAtMs
        if (start > 0L) {
            uptimeSeconds.value = (SystemClock.elapsedRealtime() - start) / 1000L
            processStartedAtMs = 0L
        } else {
            uptimeSeconds.value = null
        }
    }

    fun getCurrentParams(): TunnelParams? = currentParams

    fun currentNativeProcessId(): Int? {
        nativeProcessPid
            ?.takeIf { it > 0 && File("/proc/$it").exists() }
            ?.let { return it }
        val activeProcess = process ?: return null
        if (!activeProcess.isAlive) return null
        return processIdOf(activeProcess)
    }

    private fun processIdOf(activeProcess: Process): Int? {
        return runCatching {
            val field = activeProcess.javaClass.getDeclaredField("pid")
            field.isAccessible = true
            field.getInt(activeProcess).takeIf { it > 0 }
        }.getOrNull() ?: Regex("pid=(\\d+)")
            .find(activeProcess.toString())
            ?.groupValues
            ?.getOrNull(1)
            ?.toIntOrNull()
            ?.takeIf { it > 0 }
    }

    init {
        scope.launch {
            running.collect { started ->
                if (started) starting.value = false
            }
        }
    }

    fun restartForNetworkSwap(context: Context) {
        requestTransportRestart(
            context.applicationContext,
            "network_swap",
            "[OK] Сеть доступна · переподключение",
        )
    }

    fun restartAfterVkRecovery(context: Context) {
        if (!running.value || activeWorkers.value != 0) return
        requestTransportRestart(
            context.applicationContext,
            "workers_zero_vk_ready",
            "[NET] Потоки: 0 · обновление TURN",
        )
    }

    fun onPhysicalNetworkAvailable(context: Context) {
        if (!running.value) return
        if (pausedForNoNetwork.resume()) {
            val identity = processIdentity ?: return
            activeScope.launch {
                writeProcessCommand(identity, "RESUME", "network_resume_command_error")
            }
        }
    }

    fun onVpnInterfaceReady() {
        vpnReady.value = true
    }

    fun onVpnInterfaceStopped() {
        vpnReady.value = false
    }

    fun onVpnTerminalFailure(message: String) {
        vpnReady.value = false
        updateLog("tun_vpn_error", "✗ VPN TUN: $message", 99, true)
        activeScope.launch {
            startStopMutex.withLock {
                if (lifecycleState.isDesiredRunning()) stopLocked(processIdentity)
            }
        }
    }

    internal fun suspendForNoNetwork(reason: PhysicalNetworkPauseReason) {
        if (!running.value || !pausedForNoNetwork.pause()) return
        val message = when (reason) {
            PhysicalNetworkPauseReason.AIRPLANE_MODE -> "[NET] Режим полёта · ожидание"
            PhysicalNetworkPauseReason.OFFLINE -> "[NET] Сеть отключена · ожидание"
        }
        updateLog("network_pause", message, 2, false, LogLevel.NET)
        val identity = processIdentity ?: return
        activeScope.launch {
            if (pausedForNoNetwork.isPaused()) {
                writeProcessCommand(identity, "PAUSE", "network_pause_command_error")
            }
        }
    }

    fun clearUnreadErrors() {
        unreadErrorCount.value = 0
    }

    private fun handleTunnelEvent(
        event: TunnelEventParser.Event,
        identity: ProcessIdentity,
    ): Boolean {
        if (!isCurrent(identity)) return true
        when (event) {
            is TunnelEventParser.Event.Process -> {
                nativeProcessPid = event.pid
            }
            is TunnelEventParser.Event.Stats -> {
                activeWorkers.value = event.active
                if (workerRecoveryPolicy.observe(event.active)) {
                    workerRecoveryJob?.cancel()
                    workerRecoveryJob = null
                }
                if (event.active > 0) {
                    wrapAuthTimeoutCount = 0
                    val currentConfig = config.value
                    if (!vpnReady.value && currentConfig != null && currentConfig.startsWith("TUNCONF:") &&
                        SystemClock.elapsedRealtime() - lastVpnStartAttemptMs >= VPN_START_RETRY_MS
                    ) {
                        ensureVpnStarted(currentConfig, identity)
                    }
                }
                val totalMB = (event.bytesUp + event.bytesDown) / (1024.0 * 1024.0)
                val msg = "Активных: ${event.active} | Трафик: %.2f МБ".format(totalMB)
                stats.value = msg
                updateProcessLog(identity, "stats", "[СЕТЬ] $msg", 25, false, LogLevel.NET)
            }
            is TunnelEventParser.Event.ActiveZero -> {
                activeWorkers.value = 0
                scheduleWorkerZeroRecovery(identity)
            }
            is TunnelEventParser.Event.CallUnavailable -> handleUnavailableVkCall(event, identity)
            is TunnelEventParser.Event.NetworkSuspect -> verifyVkReachability(identity)
            is TunnelEventParser.Event.ServerRestart -> schedulePanelServerRestart(identity)
            is TunnelEventParser.Event.Ready -> {
                identity.startupProgress.streamReady()
                if (event.worker == 0 || identity.readyWorkers.add(event.worker)) {
                    updateProcessLog(identity, "ready", "[ВОРКЕР] Поток готов ✓", 20, false, LogLevel.OK)
                }
            }
            is TunnelEventParser.Event.Config -> {
                val configStr = event.config.trim()
                if (configStr.isNotEmpty()) {
                    config.value = configStr
                    activeScope.launch(Dispatchers.Main) {
                        if (!isCurrent(identity)) return@launch
                        if (configStr.startsWith("TUNCONF:")) {
                            ensureVpnStarted(
                                configStr,
                                identity,
                                forceRebuild = vpnRebuildAfterPanelRestart.getAndSet(false),
                            )
                        } else {
                            updateProcessLog(identity, "vpn_config_err", "Получен неизвестный формат конфига", 99, true)
                        }
                    }
                }
            }
            is TunnelEventParser.Event.Error -> {
                if (event.fatal) {
                    handleCriticalError(event.message, identity)
                } else {
                    updateProcessLog(identity, "event_error_${event.code}", event.message, 99, true)
                }
            }
            is TunnelEventParser.Event.CaptchaRequest -> {
                activeScope.launch {
                    if (isCurrent(identity)) {
                        handleCaptchaSolve(event.mode, event.redirectUri, event.sessionToken, identity)
                    }
                }
            }
            is TunnelEventParser.Event.Progress -> {
                if (event.kind == "credentials") {
                    identity.startupProgress.credentialReceived()
                }
            }
            else -> return false
        }
        return true
    }

    private fun verifyVkReachability(identity: ProcessIdentity) {
        if (!isCurrent(identity) || !running.value) return
        val context = activeContext() ?: return
        runCatching {
            context.applicationContext.startService(
                Intent(context.applicationContext, TunnelService::class.java).apply {
                    action = CsqttConstants.General.ACTION_VERIFY_VK_REACHABILITY
                },
            )
        }
    }

    private fun recoverUnavailableVkCall(hash: String) {
        if (!running.value || !callRecoveryPending.compareAndSet(false, true)) return
        val context = activeContext() ?: run {
            callRecoveryPending.set(false)
            return
        }
        runCatching {
            context.applicationContext.startService(
                Intent(context.applicationContext, TunnelService::class.java).apply {
                    action = CsqttConstants.General.ACTION_RECOVER_VK_CALL
                    putExtra(CsqttConstants.General.EXTRA_UNAVAILABLE_VK_HASH, hash)
                },
            )
        }.onFailure {
            callRecoveryPending.set(false)
        }
    }

    private fun handleUnavailableVkCall(
        event: TunnelEventParser.Event.CallUnavailable,
        identity: ProcessIdentity,
    ) {
        val params = currentParams ?: return
        val displayHash = displayVkHash(event.hash)
        val reason = if (event.code == 951) "звонок не найден" else "код ${event.code}"
        if (shouldReplaceUnavailableVkHash(params.vkHashMode)) {
            updateLog(
                key = "vk_hash_auto_replace_$displayHash",
                message = "[VK] Хеш \"$displayHash\" устарел · ошибка ${event.code} — $reason · создаём новый ✓",
                priority = 36,
                level = LogLevel.OK,
            )
            recoverUnavailableVkCall(event.hash)
            return
        }

        val isNewUnavailableHash = synchronized(identity.unavailableManualHashes) {
            identity.unavailableManualHashes.add(event.hash)
        }
        if (!isNewUnavailableHash) return
        updateProcessLog(
            identity = identity,
            key = "vk_hash_manual_invalid_$displayHash",
            message = "[VK] Хеш \"$displayHash\" устарел · ошибка ${event.code} — $reason · инвалидируем и используем активные хеши ✓",
            priority = 36,
            level = LogLevel.OK,
        )
        activeScope.launch {
            val store = activeSettingsStore ?: activeContext()?.let { SettingsStore(it) } ?: return@launch
            activeSettingsStore = store
            store.invalidateVkHash(event.hash)
            val remaining = params.vkHashes
                .split(Regex("[,\\s\\n]+"))
                .map(String::trim)
                .filter(String::isNotEmpty)
                .distinct()
                .count { hash ->
                    synchronized(identity.unavailableManualHashes) {
                        hash !in identity.unavailableManualHashes
                    }
                }
            if (remaining == 0 && isCurrent(identity)) {
                stop()
            }
        }
    }

    internal fun completeVkCallRecovery() {
        callRecoveryPending.set(false)
    }

    private fun ensureVpnStarted(
        configStr: String,
        identity: ProcessIdentity,
        forceRebuild: Boolean = false,
    ) {
        ensureVpnStartedMeasured(configStr, identity, forceRebuild)
    }

    private fun ensureVpnStartedMeasured(
        configStr: String,
        identity: ProcessIdentity,
        forceRebuild: Boolean,
    ) {
        if (!configStr.startsWith("TUNCONF:")) return
        val parts = configStr.removePrefix("TUNCONF:").split(":", limit = 3)
        val clientIp = parts.getOrNull(0) ?: "10.66.66.2"
        val dns = parts.getOrNull(1) ?: "1.1.1.1"
        activeContext()?.let { ctx ->
            // Single choke point: both start paths share this attempt window.
            lastVpnStartAttemptMs = SystemClock.elapsedRealtime()
            val vpnIntent = Intent(ctx, TunVpnService::class.java).apply {
                action = "START"
                putExtra("client_ip", clientIp)
                putExtra("dns", dns)
                putExtra("force_rebuild", forceRebuild)
            }
            try {
                ctx.startService(vpnIntent)
            } catch (e: Exception) {
                updateProcessLog(identity, "vpn_start_error", "Ошибка запуска VPN: ${e.readableMessage()}", 99, true)
            }
        }
    }

    private fun scheduleWorkerZeroRecovery(identity: ProcessIdentity) {
        val target = workerRecoveryPolicy.armAtZero() ?: return
        if (workerRecoveryJob?.isActive == true) return
        workerRecoveryJob = activeScope.launch {
            try {
                delay(WORKER_ZERO_CONFIRMATION_MS)
                if (!isCurrent(identity) || !running.value) return@launch
                if (!workerRecoveryPolicy.shouldRecover(activeWorkers.value, target)) return@launch
                val context = activeContext() ?: return@launch
                requestTransportRestart(
                    context.applicationContext,
                    "workers_zero_refresh",
                    "[NET] Потоки: 0 · обновление TURN",
                )
            } finally {
                if (workerRecoveryJob === coroutineContext[Job]) {
                    workerRecoveryJob = null
                }
            }
        }
    }

    private fun schedulePanelServerRestart(identity: ProcessIdentity) {
        if (!isCurrent(identity) || !running.value) return
        if (!panelRestartPending.compareAndSet(false, true)) return
        vpnRebuildAfterPanelRestart.set(true)
        resetWorkerRecoveryState()
        panelRestartJob?.cancel()
        panelRestartJob = activeScope.launch {
            try {
                delay(3_000L)
                if (!isCurrent(identity) || !running.value) return@launch
                val context = activeContext() ?: return@launch
                requestTransportRestart(
                    context.applicationContext,
                    "panel_server_restart",
                    "[SERVER] Перезагрузка · переподключение",
                )
            } finally {
                panelRestartPending.set(false)
                if (panelRestartJob === coroutineContext[Job]) panelRestartJob = null
            }
        }
    }

    private fun requestTransportRestart(
        context: Context,
        logKey: String,
        message: String,
    ) {
        if (logKey == "workers_zero_refresh") {
            runCatching {
                context.startService(
                    Intent(context, TunnelService::class.java).apply {
                        action = CsqttConstants.General.ACTION_RESTART_WHEN_VK_REACHABLE
                    },
                )
            }.onFailure {
                updateLog(
                    "vk_recovery_service_error",
                    "Не удалось запустить проверку VK: ${it.readableMessage()}",
                    99,
                    true,
                )
            }
            return
        }
        if (!transportRestartPending.compareAndSet(false, true)) return
        val command = lifecycleCommand.incrementAndGet()
        val appContext = context.applicationContext
        activeScope.launch {
            try {
                val params = currentParams ?: return@launch
                if (!running.value) return@launch
                val newParams = runCatching { params.withNewSession(appContext) }
                    .getOrElse {
                        if (logKey == "network_swap") pausedForNoNetwork.restore()
                        updateLog(
                            "${logKey}_epoch_error",
                            "Ошибка обновления эпохи: ${it.readableMessage()}",
                            99,
                            true,
                        )
                        return@launch
                    }
                startStopMutex.withLock {
                    if (
                        lifecycleCommand.get() != command ||
                        !running.value ||
                        currentParams != params
                    ) {
                        return@withLock
                    }
                    val epoch = lifecycleState.requestRestart() ?: return@withLock
                    restartJob?.cancel()
                    restartJob = null
                    updateLog(logKey, message, 2, false)
                    terminateProcessLocked(processIdentity)
                    currentParams = newParams
                    startProcessLocked(appContext, newParams, epoch)
                }
            } finally {
                transportRestartPending.set(false)
            }
        }
    }

    private fun resetWorkerRecoveryState() {
        workerRecoveryJob?.cancel()
        workerRecoveryJob = null
        workerRecoveryPolicy.reset()
    }

    private var observersInitialized = false

    fun initObservers(context: Context) {
        if (observersInitialized) return
        observersInitialized = true
        val appContext = context.applicationContext
        scope.launch {
            running.collect { running ->
                try {
                    VpnWidgetProvider.updateAllWidgets(appContext)
                    android.service.quicksettings.TileService.requestListeningState(
                        appContext,
                        android.content.ComponentName(appContext, QuickToggleTileService::class.java)
                    )
                } catch (e: Exception) {
                }
            }
        }
    }

    private val deploySessionCounter = AtomicLong()
    private val deployLineCounter = AtomicLong()
    @Volatile
    private var deploySessionId = 0L

    fun beginDeployLog(message: String) {
        deploySessionId = deploySessionCounter.incrementAndGet()
        deployLineCounter.set(0L)
        addDeployInfoLog(message)
    }

    fun addDeployInfoLog(message: String) = addDeployLog(message, LogLevel.LOG)

    fun addDeploySuccessLog(message: String) {
        addDeployLog(message, LogLevel.OK)
    }

    fun addDeployWarningLog(message: String) {
        addDeployLog("Предупреждение: $message", LogLevel.LOG)
    }

    fun addDeployErrorLog(message: String) {
        addDeployLog(message, LogLevel.ERR)
    }

    private fun addDeployLog(message: String, level: LogLevel) {
        val clean = message.trim().take(500)
        if (clean.isEmpty()) return
        if (deploySessionId == 0L) {
            deploySessionId = deploySessionCounter.incrementAndGet()
            deployLineCounter.set(0L)
        }
        val sequence = deployLineCounter.incrementAndGet().toString().padStart(5, '0')
        updateLog(
            key = "deploy_${deploySessionId}_$sequence",
            message = "[ДЕПЛОЙ] $clean",
            priority = 7,
            isError = level == LogLevel.ERR,
            level = level,
        )
    }

    internal fun updateLog(
        key: String,
        message: String,
        priority: Int,
        isError: Boolean = false,
        level: LogLevel? = null,
    ) {
        updateLogForProcess(null, key, message, priority, isError, level)
    }

    private fun updateProcessLog(
        identity: ProcessIdentity,
        key: String,
        message: String,
        priority: Int,
        isError: Boolean = false,
        level: LogLevel? = null,
    ) {
        updateLogForProcess(identity, key, message, priority, isError, level)
    }

    private fun updateLogForProcess(
        identity: ProcessIdentity?,
        key: String,
        message: String,
        priority: Int,
        isError: Boolean,
        level: LogLevel?,
    ) {
        if (identity != null && !isCurrent(identity)) return
        if (!isLoggingEnabled) return
        val cleanMessage = withoutLogStickers(message).take(MAX_LOG_MESSAGE_LENGTH)
        if (cleanMessage.isEmpty()) return
        val pendingKey = "${identity?.generation ?: 0L}:$key:$priority:$isError:${level?.name.orEmpty()}"
        synchronized(pendingLogLock) {
            val pending = pendingLogs[pendingKey]
            if (pending == null) {
                if (pendingLogs.size >= MAX_PENDING_LOGS) {
                    pendingLogs.remove(pendingLogs.entries.first().key)
                }
                pendingLogs[pendingKey] = PendingLog(identity, key, cleanMessage, priority, isError, level, 1)
            } else {
                pending.message = cleanMessage
                pending.count += 1
            }
            scheduleLogFlushLocked()
        }
    }

    private fun scheduleLogFlushLocked() {
        if (!pendingLogFlushScheduled.compareAndSet(false, true)) return
        scope.launch(Dispatchers.Main) {
            delay(LOG_UI_FLUSH_MS)
            flushPendingLogs()
        }
    }

    private fun flushPendingLogs() {
        val batch = synchronized(pendingLogLock) {
            val values = pendingLogs.values.toList()
            pendingLogs.clear()
            pendingLogFlushScheduled.set(false)
            values
        }
        batch.forEach(::applyPendingLog)
    }

    private fun applyPendingLog(pending: PendingLog) {
        val identity = pending.identity
        if (identity != null && !isCurrent(identity)) return
        val index = logs.indexOfFirst { it.key == pending.key }
        if (pending.isError && index == -1) {
            unreadErrorCount.value++
        }
        if (index != -1) {
            val entry = logs[index]
            if (entry.priority == pending.priority) {
                logs[index] = entry.copy(
                    count = entry.count + pending.count,
                    message = pending.message,
                    isError = pending.isError,
                    level = pending.level,
                )
            } else {
                logs.removeAt(index)
                insertSorted(
                    LogEntry(
                        pending.key,
                        pending.message,
                        entry.count + pending.count,
                        pending.priority,
                        pending.isError,
                        pending.level,
                    )
                )
            }
        } else {
            insertSorted(
                LogEntry(
                    pending.key,
                    pending.message,
                    pending.count,
                    pending.priority,
                    pending.isError,
                    pending.level,
                )
            )
        }

        while (logs.size > MAX_LOG_ENTRIES) {
            logs.removeAt(0)
        }
    }

    private fun isCurrent(identity: ProcessIdentity): Boolean =
        processIdentity === identity &&
            process === identity.process &&
            processGeneration == identity.generation &&
            lifecycleState.accepts(identity.ticket)

    private fun insertSorted(entry: LogEntry) {
        val comparator = compareBy<LogEntry>({ it.priority }, { if (it.isError) 1 else 0 }, { it.key })
        var inserted = false
        for (i in logs.indices) {
            if (comparator.compare(entry, logs[i]) < 0) {
                logs.add(i, entry)
                inserted = true
                break
            }
        }
        if (!inserted) {
            logs.add(entry)
        }
    }

    fun start(context: Context, params: TunnelParams, isSwitching: Boolean = false) {
        val command = lifecycleCommand.incrementAndGet()
        autoPausedForWifi.value = false
        stopping.value = false
        
        if (!isSwitching) pausedForNoNetwork.reset()
        
        activeScope.launch {
            startStopMutex.withLock {
                if (lifecycleCommand.get() != command) return@withLock
                if (!isSwitching && lifecycleState.isDesiredRunning()) return@withLock
                val appContext = context.applicationContext
                val epoch = if (isSwitching) {
                    lifecycleState.requestRestart() ?: return@withLock
                } else {
                    clearLogs()
                    config.value = null
                    stats.value = "Ожидание данных..."
                    wrapAuthTimeoutCount = 0
                    crashRestartStreak = 0
                    processStartedAtMs = 0L
                    currentParams = params
                    strongAppContext = appContext.applicationContext
                    lastContext = WeakReference(appContext)
                    activeSettingsStore = SettingsStore(appContext)
                    currentCaptchaSolveMethod = params.captchaSolveMethod
                    lifecycleState.requestStart()
                }
                restartJob?.cancel()
                restartJob = null
                if (isSwitching) terminateProcessLocked(processIdentity)
                if (isSwitching) currentParams = params
                startProcessLocked(appContext, params, epoch)
            }
        }
    }

    private fun failStartLocked(key: String, message: String) {
        updateLog(key, message, 99, true)
        lifecycleState.requestStop()
        stopUptimeTimer()
        running.value = false
        stopping.value = false
        activeWorkers.value = 0
    }

    private fun startProcessLocked(context: Context, params: TunnelParams, epoch: Long) {
        if (!lifecycleState.canStart(epoch) || process != null) return
        val hashList = params.vkHashes
            .split(Regex("[,\\s\\n]+"))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .take(CsqttConstants.Tunnel.MAX_VK_HASHES)

        val jsHashMode = params.vkHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS
        val jsAuthMode = params.vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
        if (jsAuthMode && !jsHashMode) {
            failStartLocked("vk_js_mode_error", "Ошибка: режим работы Auto JS требует хеши Auto JS")
            return
        }
        if (hashList.isEmpty() && !jsHashMode) {
            failStartLocked("hash_error", "Ошибка: Хеш не указан")
            return
        }
        if (jsHashMode && params.vkAccessToken.isBlank()) {
            failStartLocked("vk_token_error", "Ошибка: VK access token не указан")
            return
        }
        if (params.connectionPassword.isBlank()) {
            failStartLocked("password_error", "Ошибка: пароль подключения не указан")
            return
        }

        val binaryPath = context.applicationInfo.nativeLibraryDir + "/${CsqttConstants.Tunnel.BINARY_NAME}"
        if (!File(binaryPath).exists()) {
            failStartLocked("binary_error", "Ошибка: Бинарный файл не найден")
            return
        }

        val totalWorkers = WorkerCountPolicy.normalizeForHashValues(
            params.workersPerHash,
            hashList,
            params.allowHashRedistribution || jsHashMode,
        )
        val cmd = mutableListOf(
            binaryPath,
            "-peer", params.peer,
            "-n", totalWorkers.toString(),
            "-listen", "${CsqttConstants.Network.LOCAL_LISTEN_HOST}:${params.port}",
            "-tun-uds", "csqtt_tun_uds",
        )
        if (hashList.isNotEmpty()) {
            cmd.add("-vk")
            cmd.add(hashList.joinToString(","))
        }
        cmd.add("-vk-hash-mode")
        cmd.add(params.vkHashMode)
        if (params.allowHashRedistribution || jsHashMode) {
            cmd.add("--allow-hash-redistribution")
        }
        if (params.fingerprint.isNotEmpty()) {
            cmd.add("-fingerprint")
            cmd.add(params.fingerprint)
        }
        if (params.clientIds.isNotEmpty()) {
            cmd.add("-client-ids")
            cmd.add(params.clientIds)
        }
        cmd.add("-obfs")
        cmd.add(params.obfsMode)
        cmd.add("-turn-transport")
        cmd.add(params.turnTransport)
        cmd.add("-vk-auth-mode")
        cmd.add(params.vkAuthMode)
        cmd.add("-device-id")
        cmd.add(readDeviceId(context))
        cmd.add("-password")
        cmd.add(params.connectionPassword)
        if (params.generationId > 0) {
            cmd.add("-gen")
            cmd.add(params.generationId.toString())
        }
        if (params.sessionSalt.isNotEmpty()) {
            cmd.add("-salt")
            cmd.add(params.sessionSalt)
        }
        cmd.add("-captcha-mode")
        cmd.add(params.captchaMode)

        val pb = ProcessBuilder(cmd)
        pb.directory(context.filesDir)
        pb.redirectErrorStream(true)
        pb.environment()["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir
        pb.environment()[CsqttConstants.Tunnel.PROCESS_ENV_EVENTS] = "1"
        pb.environment()["RAYON_NUM_THREADS"] = "2"

        val ticket = lifecycleState.reserveProcess(epoch, process == null) ?: return
        val startedProcess = try {
            pb.start()
        } catch (e: Exception) {
            lifecycleState.releaseReservation(ticket)
            failStartLocked("critical_start_error", "Критическая ошибка запуска: ${e.readableMessage()}")
            return
        }
        if (jsHashMode) {
            val bootstrap = JSONObject()
                .put("token", params.vkAccessToken)
                .toString()
            val encoded = Base64.encodeToString(
                bootstrap.toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP,
            )
            try {
                startedProcess.outputStream.write(
                    "VK_JS_BOOTSTRAP:$encoded\n".toByteArray(Charsets.UTF_8),
                )
                startedProcess.outputStream.flush()
            } catch (e: Exception) {
                startedProcess.destroy()
                lifecycleState.releaseReservation(ticket)
                failStartLocked(
                    "vk_js_bootstrap_error",
                    "Ошибка передачи данных Auto JS: ${e.readableMessage()}",
                )
                return
            }
        }
        processGeneration = if (processGeneration == Long.MAX_VALUE) 1L else processGeneration + 1L
        val identity = ProcessIdentity(
            startedProcess,
            processGeneration,
            ticket,
            3_500L,
        )
        process = startedProcess
        callRecoveryPending.set(false)
        nativeProcessPid = processIdOf(startedProcess)
        processIdentity = identity
        running.value = true
        startUptimeTimer()
        wrapAuthTimeoutCount = 0
        activeWorkers.value = 0
        resetWorkerRecoveryState()
        startLogReader(identity)
        scheduleStartupDiagnostic(identity)
    }

    private fun scheduleStartupDiagnostic(identity: ProcessIdentity) {
        activeScope.launch {
            delay(STARTUP_DIAGNOSTIC_MS)
            if (!isCurrent(identity) || activeWorkers.value > 0) return@launch
            when (identity.startupProgress.stage()) {
                TunnelStartupStage.WAITING_FOR_CREDENTIALS -> updateProcessLog(
                    identity,
                    "startup_waiting_credentials",
                    "[ДИАГНОСТИКА] Rust-клиент запущен, но VK не выдал TURN-креды: проверьте сеть, токен и капчу",
                    98,
                    true,
                )
                TunnelStartupStage.WAITING_FOR_TURN_OR_PEER -> updateProcessLog(
                    identity,
                    "startup_waiting_turn",
                    "[ДИАГНОСТИКА] TURN-креды получены, но ни один allocation/handshake с сервером не завершился",
                    98,
                    true,
                )
                TunnelStartupStage.READY -> Unit
            }
        }
    }

    @SuppressLint("HardwareIds")
    internal fun readDeviceId(context: Context): String =
        android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown"

    private fun startLogReader(identity: ProcessIdentity) {
        val targetProcess = identity.process
        val generation = identity.generation
        readerJob = activeScope.launch {
            val reader = targetProcess.inputStream.bufferedReader()
            var collectingConfig = false
            val configBuilder = StringBuilder()
            var lastDiagnostic: String? = null

            try {
                reader.forEachLine { line ->
                    if (!isCurrent(identity)) return@forEachLine

                    // The timestamp prefix always starts with "YYYY/", so two
                    // character checks skip the regex for non-timestamped lines.
                    val stripped =
                        if (line.length > 19 && line[0].isDigit() && line[4] == '/') {
                            line.replace(LOG_TIMESTAMP_PREFIX, "")
                        } else {
                            line
                        }
                    val lineTrim = stripped.trim()

                    // Structured events are the common case under traffic:
                    // one startsWith check routes them out before all the
                    // substring scans below.
                    val event = TunnelEventParser.parse(lineTrim)
                    if (event != null && handleTunnelEvent(event, identity)) {
                        return@forEachLine
                    }

                    if (!isLoggingEnabled &&
                        !lineTrim.startsWith("CAPTCHA_SOLVE|") &&
                        !lineTrim.contains("FATAL_AUTH")
                    ) {
                        return@forEachLine
                    }

                    if (TunnelLogPolicy.isInternalRecovery(lineTrim)) {
                        return@forEachLine
                    }

                    if (
                        lineTrim.contains("[ФАТАЛ]", true) ||
                        lineTrim.contains("[PANIC]", true) ||
                        lineTrim.contains("fatal", true) ||
                        lineTrim.contains("cannot create socket", true) ||
                        lineTrim.contains("невосстановимая", true)
                    ) {
                        lastDiagnostic = lineTrim.take(240)
                    }

                    if (lineTrim.contains("WRAP_AUTH_TIMEOUT", true)) {
                        // WRAP handshake timeouts are recoverable; they must not
                        // fall through to the fatal-auth stop below.
                        if (activeWorkers.value > 0) {
                            wrapAuthTimeoutCount = 0
                            updateProcessLog(
                                identity,
                                "wrap_timeout_recovered",
                                "[WRAP] Один поток не прошёл handshake, активных=${activeWorkers.value}; повторяем",
                                50,
                                true
                            )
                        } else {
                            wrapAuthTimeoutCount++
                            updateProcessLog(
                                identity,
                                "wrap_timeout_wait",
                                "[WRAP] Handshake не подтвердился, проверяем пароль/сеть ($wrapAuthTimeoutCount)",
                                50,
                                true
                            )
                        }
                        return@forEachLine
                    }

                    if (lineTrim.contains("FATAL_AUTH")) {
                        val reason = when {
                            lineTrim.contains("неверный пароль") -> "Неверный пароль подключения"
                            lineTrim.contains("истёк") -> "Срок действия пароля истёк"
                            lineTrim.contains("другому устройству") -> "Пароль привязан к другому устройству"
                            else -> "Ошибка авторизации"
                        }
                        handleCriticalError("\uD83D\uDD12 $reason. Воркеры остановлены.", identity)
                        return@forEachLine
                    }

                    if (lineTrim.startsWith("CAPTCHA_SOLVE|")) {
                        val payload = lineTrim.substringAfter("CAPTCHA_SOLVE|")
                        val parts = payload.split("|", limit = 3)
                        when (parts.size) {
                            3 -> {
                                val requestMode = parts[0]
                                val redirectUri = parts[1]
                                val sessionToken = parts[2]
                                activeScope.launch {
                                    if (isCurrent(identity)) {
                                        handleCaptchaSolve(requestMode, redirectUri, sessionToken, identity)
                                    }
                                }
                            }
                            2 -> {
                                val redirectUri = parts[0]
                                val sessionToken = parts[1]
                                activeScope.launch {
                                    if (isCurrent(identity)) {
                                        handleCaptchaSolve("selected", redirectUri, sessionToken, identity)
                                    }
                                }
                            }
                            else -> {
                                writeCaptchaResult("error:invalid CAPTCHA_SOLVE format", identity)
                            }
                        }
                        return@forEachLine
                    }

                    // Computed this late so early-returning lines (events,
                    // recovery noise, WRAP/CAPTCHA) skip the six scans.
                    val isError = lineTrim.contains("Ошибка", true) || lineTrim.contains("error", true) || lineTrim.contains("FAIL", true) || lineTrim.contains("timeout", true) || lineTrim.contains("refused", true) || lineTrim.contains("FATAL_AUTH", true)

                    when {
                        lineTrim.contains("[КАПЧА] AUTO:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] AUTO:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()

                            val isErr = text.contains("ошибка", true) ||
                                text.contains("timeout", true) ||
                                text.contains("не решил", true)
                            val stableKey = when {
                                text.contains("старт") -> "captcha_auto_1"
                                (text.contains("Go v2") || text.contains("Rust v2")) && text.contains("2 попыт") -> "captcha_auto_2"
                                text.contains("WBV Auto попытка") -> "captcha_auto_3"
                                text.contains("финальная") -> "captcha_auto_4"
                                text.contains("ручной WebView") -> "captcha_auto_5"
                                text.contains("решил") || text.contains("решила") -> "captcha_auto_done"
                                else -> "captcha_auto_${text.take(18).hashCode()}"
                            }
                            updateProcessLog(identity, stableKey, "[КАПЧА AUTO] $text", 60, isErr)
                        }

                        lineTrim.contains("[КАПЧА] RJS:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] RJS:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()

                            val stableKey = when {
                                text.contains("Загрузка") || text.contains("fetch") -> "captcha_rjs_1"
                                text.contains("PoW") -> "captcha_rjs_2"
                                text.contains("осматривает") || text.contains("человек") -> "captcha_rjs_3"
                                text.contains("captchaNotRobot") || text.contains("Отправка") -> "captcha_rjs_4"
                                text.contains("endSession") -> "captcha_rjs_5"
                                text.contains("решена") -> "captcha_rjs_6"
                                else -> "captcha_rjs_${text.take(15).hashCode()}"
                            }
                            updateProcessLog(identity, stableKey, "[КАПЧА RJS] $text", 60, false)
                        }

                        lineTrim.contains("[КАПЧА] WBV:") -> {
                            var text = lineTrim.substringAfter("[КАПЧА] WBV:").trim()
                            text = text.replace(Regex("\\s*\\([^)]+\\)\\s*"), " ").trim()

                            val isErr = text.contains("Ошибка")
                            val stableKey = when {
                                text.contains("Запрос") -> "captcha_wv_step_2"
                                text.contains("Токен") -> "captcha_wv_step_5"
                                isErr -> "captcha_wv_err"
                                else -> "captcha_wv_go_other"
                            }
                            updateProcessLog(identity, stableKey, "[КАПЧА WBV] $text", 60, isErr)
                        }

                        lineTrim.contains("Решаю VK Smart Captcha") ->
                            updateProcessLog(identity, "captcha_start", "[КАПЧА] Решение капчи...", 60, false)
                        lineTrim.contains("Smart Captcha решена") ->
                            updateProcessLog(identity, "captcha_done", "[КАПЧА] Капча решена ✓", 60, false)
                        lineTrim.contains("капча не решена") || lineTrim.contains("ошибка решения капчи") ->
                            updateProcessLog(identity, "captcha_failed", "[КАПЧА] Ошибка решения капчи", 99, true, LogLevel.ERR)
                        lineTrim == "[VK JS] Звонок создан" || lineTrim.contains("Звонок VK создан") || lineTrim.contains("Звонок создан") -> {
                            updateProcessLog(identity, "vk_js_call_progress", "[VK JS] Звонок VK создан ✓", 16, false, LogLevel.OK)
                        }
                        lineTrim.startsWith("[VK JS] Создатель вышел из звонков") ->
                            updateProcessLog(identity, "vk_js_creator_left", "[VK JS] Владелец вышел из звонка ✓", 19, false, LogLevel.OK)
                        lineTrim.startsWith("[VK JS] Звонки завершены") ->
                            updateProcessLog(identity, "vk_js_call_finished", "[VK JS] Звонок завершён ✓", 19, false, LogLevel.OK)
                        lineTrim.startsWith("[VK JS] Создатель удерживает звонок") ->
                            updateProcessLog(identity, "vk_js_creator_held", "[VK JS] Владелец удерживает звонок до отключения", 18, false, LogLevel.OK)

                        lineTrim.startsWith("[VK JS] Креды аккаунта") && lineTrim.contains("недоступны") -> {
                            updateProcessLog(identity, "vk_js_account_credentials_progress", "[VK JS] Креды аккаунта недоступны", 17, true, LogLevel.ERR)
                        }
                        lineTrim.startsWith("[VK JS] Креды аккаунта") -> {
                            updateProcessLog(identity, "vk_js_account_credentials_progress", "[VK JS] Креды аккаунта готовы ✓", 17, false, LogLevel.OK)
                        }
                        lineTrim.startsWith("[VK JS] Переход на Авто") -> {
                            val text = lineTrim.substringAfter("[VK JS]").trim()
                            val failed = text.contains("не выполнен")
                            val suffix = if (failed) "" else " ✓"
                            updateProcessLog(identity, "vk_js_account_fallback_progress", "[VK JS] $text$suffix", 17, failed, if (failed) LogLevel.ERR else LogLevel.OK)
                        }
                        lineTrim.contains("[WRAP]") -> {
                            updateProcessLog(identity, "wrap_status", "[WRAP] Ключ вычислен ✓", 10, false, LogLevel.OK)
                        }
                        lineTrim.startsWith("[ПОТОКИ]") -> {
                            val text = lineTrim.substringAfter("[ПОТОКИ]").trim()
                            val isRepair = text.contains("не пришёл", true) ||
                                text.contains("частично", true) ||
                                text.contains("Перезапуск", true)
                            val (stableKey, priority) = when {
                                text.startsWith("Отправлен ping", true) -> "stream_probe_ping" to 56
                                text.startsWith("ACK получен", true) || text.startsWith("Все активные", true) -> "stream_probe_ack" to 57
                                text.contains("ChannelBind", true) -> "stream_probe_rebind" to 58
                                text.contains("проверяю", true) -> "stream_probe_all" to 58
                                text.contains("Перезапуск", true) -> "stream_probe_restart" to 59
                                else -> "stream_probe_${text.take(24).hashCode()}" to 59
                            }
                            updateProcessLog(identity, stableKey, "[ПОТОКИ] $text", priority, isRepair, if (isRepair) LogLevel.ERR else LogLevel.LOG)
                        }
                        lineTrim.contains("[TURN]") -> {
                            val text = lineTrim.substringAfter("[TURN]").trim()
                            val turnError = TunnelLogPolicy.isTurnStreamFailure(lineTrim) || isError
                            val (stableKey, priority) = when {
                                turnError -> "turn_error_${text.hashCode()}" to 99
                                text.contains("CreatePermission", true) -> "turn_permission_status" to 52
                                text.contains("ChannelBind", true) || text.contains("Канал", true) -> "turn_channel_status" to 53
                                text.contains("готова к передаче", true) -> "turn_ready_status" to 54
                                text.contains("Refresh", true) -> "turn_refresh_status" to 55
                                else -> null to 0
                            }
                            if (stableKey != null) {
                                updateProcessLog(identity, stableKey, "[TURN] $text", priority, turnError, if (turnError) LogLevel.ERR else LogLevel.LOG)
                            }
                        }
                        lineTrim.contains("Рукопожатие...") ->
                            updateProcessLog(identity, "peer_handshake", "Рукопожатие...", 65, false)

                        isError -> {
                            val errorKey = when {
                                lineTrim.contains("lookup login.vk.ru", true) -> "err_vk_dns"
                                lineTrim.contains("connection refused") -> "err_conn_refused"
                                lineTrim.contains("timeout") -> "err_timeout"
                                lineTrim.contains("кредов") -> "err_creds"
                                lineTrim.contains("PEER") -> "err_peer"
                                else -> "general_error_" + lineTrim.take(15).hashCode()
                            }
                            val errorMessage = if (errorKey == "err_vk_dns") {
                                "[СЕТЬ] DNS до VK недоступен: login.vk.ru"
                            } else {
                                lineTrim
                            }
                            updateProcessLog(identity, errorKey, errorMessage, 99, true)
                        }
                    }
                }
            } catch (e: Exception) {
                if (
                    isCurrent(identity) &&
                    targetProcess.isAlive &&
                    !e.readableMessage().contains("read interrupted by close", ignoreCase = true)
                ) {
                    lastDiagnostic = e.readableMessage().take(240)
                }
            } finally {
                runCatching { reader.close() }
                startStopMutex.withLock {
                    if (processIdentity === identity && process === targetProcess) {
                        val shouldRestart = lifecycleState.processEnded(identity.ticket)
                        process = null
                        processIdentity = null
                        nativeProcessPid = null
                        activeWorkers.value = 0
                        resetWorkerRecoveryState()
                        if (readerJob === coroutineContext[Job]) readerJob = null
                        val initialExitCode = runCatching {
                            if (targetProcess.waitFor(250, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                                targetProcess.exitValue()
                            } else {
                                null
                            }
                        }.getOrNull()
                        if (initialExitCode == null) {
                            terminateExactProcess(targetProcess, identity.shutdownGraceMs)
                        }
                        val restartContext = activeContext()
                        val restartParams = if (restartContext == null) {
                            null
                        } else {
                            runCatching {
                                currentParams?.withNewSession(restartContext)
                            }.getOrElse {
                                updateLog(
                                    "restart_epoch_reserve_error",
                                    "Ошибка резервирования новой эпохи: ${it.readableMessage()}. Перезапуск с последней подтверждённой эпохой.",
                                    99,
                                    true,
                                )
                                currentParams
                            }
                        }
                        if (shouldRestart && restartParams != null && restartContext != null) {
                            currentParams = restartParams
                            val exitCode = initialExitCode
                                ?: runCatching { targetProcess.exitValue() }.getOrNull()
                            val reason = lastDiagnostic?.let { " Причина: $it" }.orEmpty()
                            updateLog(
                                "process_restart",
                                "✗ Rust-клиент завершился (код ${exitCode ?: "?"}). Перезапуск...$reason",
                                50,
                                true,
                            )
                            // Exponential backoff: a binary that dies instantly
                            // must not loop the whole start sequence every 2s.
                            val uptimeMs = processStartedAtMs
                                .takeIf { it > 0 }
                                ?.let { SystemClock.elapsedRealtime() - it }
                                ?: Long.MAX_VALUE
                            crashRestartStreak =
                                if (uptimeMs >= CRASH_RESTART_STABLE_MS) 0 else crashRestartStreak + 1
                            val backoffShift = crashRestartStreak.coerceIn(1, 6) - 1
                            val restartDelayMs = (2_000L shl backoffShift)
                                .coerceAtMost(CRASH_RESTART_MAX_DELAY_MS)
                            scheduleRestartLocked(restartContext, restartParams, identity.ticket.epoch, restartDelayMs)
                        } else if (!lifecycleState.isDesiredRunning()) {
                            running.value = false
                        }
                    }
                }
            }
        }
    }

    private fun scheduleRestartLocked(
        context: Context,
        params: TunnelParams,
        epoch: Long,
        delayMs: Long,
    ) {
        restartJob?.cancel()
        restartJob = activeScope.launch {
            delay(delayMs)
            startStopMutex.withLock {
                if (!lifecycleState.canStart(epoch) || process != null) return@withLock
                restartJob = null
                startProcessLocked(context, params, epoch)
            }
        }
    }

    private fun handleCriticalError(message: String, identity: ProcessIdentity) {
        updateProcessLog(identity, "circuit_breaker", "[СТОП] $message", -1, true)
        activeScope.launch {
            startStopMutex.withLock {
                if (!isCurrent(identity)) return@withLock
                stopLocked(identity)
            }
        }
    }

    private suspend fun TunnelParams.withNewSession(context: Context): TunnelParams {
        val store = activeSettingsStore ?: SettingsStore(context).also {
            activeSettingsStore = it
        }
        val proposed = if (generationId == Long.MAX_VALUE) Long.MAX_VALUE else generationId + 1
        val nextGen = store.reserveConnectionGeneration(proposed = proposed)
        return copy(
            generationId = nextGen,
            sessionSalt = java.util.UUID.randomUUID().toString().replace("-", ""),
        )
    }

    private fun terminateProcessLocked(
        identity: ProcessIdentity?,
        finishVkCalls: Boolean = false,
    ) {
        if (identity == null) {
            activeWorkers.value = 0
            return
        }
        val targetProcess = identity.process
        val attached = processIdentity === identity && process === targetProcess
        val logReader = if (attached) readerJob else null
        if (attached) {
            process = null
            processIdentity = null
            nativeProcessPid = null
            stopUptimeTimer()
            resetWorkerRecoveryState()
        }
        lifecycleState.releaseReservation(identity.ticket)
        terminateExactProcess(targetProcess, identity.shutdownGraceMs, finishVkCalls)
        logReader?.cancel()
        if (readerJob === logReader) {
            readerJob = null
        }
        if (attached) activeWorkers.value = 0
    }

    private fun terminateExactProcess(
        targetProcess: Process,
        shutdownGraceMs: Long,
        finishVkCalls: Boolean = false,
    ) {
        val forceWindowMs = minOf(300L, shutdownGraceMs)
        val gracefulWindowMs = (shutdownGraceMs - forceWindowMs).coerceAtLeast(0L)
        try {
            val command = if (finishVkCalls) "FINISH_VK_CALLS\nSTOP\n" else "STOP\n"
            targetProcess.outputStream.write(command.toByteArray())
            targetProcess.outputStream.flush()
        } catch (_: Exception) {}
        try {
            targetProcess.waitFor(gracefulWindowMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: Exception) {}
        if (targetProcess.isAlive) {
            try { targetProcess.destroy() } catch (_: Exception) {}
            try { targetProcess.waitFor(forceWindowMs, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: Exception) {}
        }
        if (targetProcess.isAlive) {
            try { targetProcess.destroyForcibly() } catch (_: Exception) {}
        }
    }

    fun stop(finishVkCalls: Boolean = false) {
        val command = lifecycleCommand.incrementAndGet()
        stopping.value = true
        scope.launch {
            startStopMutex.withLock {
                if (lifecycleCommand.get() != command) return@withLock
                stopLocked(processIdentity, finishVkCalls)
            }
        }
    }

    suspend fun pauseForWifi() {
        lifecycleCommand.incrementAndGet()
        startStopMutex.withLock {
            autoPausedForWifi.value = true
            stopLocked(processIdentity, preserveWifiAutoPause = true)
            starting.value = false
            stats.value = "Ожидание. Автопауза при Wi-Fi"
            updateLog(
                "wifi_auto_pause",
                "Ожидание. Автопауза при Wi-Fi",
                2,
                false,
                LogLevel.NET,
            )
        }
    }

    fun leaveWifiAutoPause() {
        autoPausedForWifi.value = false
    }

    private fun stopLocked(
        identity: ProcessIdentity?,
        finishVkCalls: Boolean = false,
        preserveWifiAutoPause: Boolean = false,
    ) {
        stopping.value = true
        lifecycleState.requestStop()
        if (!preserveWifiAutoPause) autoPausedForWifi.value = false
        pausedForNoNetwork.reset()
        vpnReady.value = false
        restartJob?.cancel()
        restartJob = null
        panelRestartJob?.cancel()
        panelRestartJob = null
        panelRestartPending.set(false)
        vpnRebuildAfterPanelRestart.set(false)
        transportRestartPending.set(false)
        activeContext()?.let { ctx ->
            val stopIntent = Intent(ctx, TunVpnService::class.java).apply { action = "STOP" }
            try { ctx.startService(stopIntent) } catch (_: Exception) {}
        }
        terminateProcessLocked(identity, finishVkCalls)
        running.value = false
        stopping.value = false
        activeWorkers.value = 0
        nativeProcessPid = null
        currentParams = null
        activeSettingsStore = null
        ManlCaptchaWebViewManager.cancelCaptcha()
    }

    fun reloadVpn() {
        val configStr = config.value?.trim() ?: return
        if (running.value && configStr.startsWith("TUNCONF:")) {
            activeScope.launch(Dispatchers.Main) {
                val parts = configStr.removePrefix("TUNCONF:").split(":", limit = 3)
                val clientIp = parts.getOrNull(0) ?: "10.66.66.2"
                val dns = parts.getOrNull(1) ?: "1.1.1.1"
                activeContext()?.let { ctx ->
                    val vpnIntent = Intent(ctx, TunVpnService::class.java).apply {
                        action = "START"
                        putExtra("client_ip", clientIp)
                        putExtra("dns", dns)
                        putExtra("force_rebuild", true)
                    }
                    try { ctx.startService(vpnIntent) } catch (_: Exception) {}
                }
            }
        }
    }

    private suspend fun handleCaptchaSolve(
        requestMode: String,
        redirectUri: String,
        sessionToken: String,
        identity: ProcessIdentity,
    ) {
        if (!isCurrent(identity)) return
        val ctx = activeContext() ?: run {
            writeCaptchaResult("error:context is null", identity)
            return
        }
        val mode = requestMode.lowercase()

        try {
            val token = when (mode) {
                "auto" -> solveSingleAutoWebViewCaptcha(redirectUri, sessionToken, identity)
                "manual" -> {
                    updateProcessLog(identity, "captcha_wv_step_1", "[КАПЧА WBV] Создание ручного WebView...", 5, false)
                    ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
                else -> {
                    if (currentCaptchaSolveMethod == "auto") {
                        solveAutoWebViewCaptcha(ctx, redirectUri, sessionToken, identity)
                    } else {
                        updateProcessLog(identity, "captcha_wv_step_1", "[КАПЧА WBV] Создание ручного WebView...", 5, false)
                        ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                    }
                }
            }
            updateProcessLog(identity, "captcha_wv_step_4", "[КАПЧА WBV] Капча решена ✓", 5, false)
            writeCaptchaResult(token, identity)
        } catch (e: IllegalStateException) {
            val errorMsg = e.message ?: "WV state error"
            updateProcessLog(identity, "captcha_wv_err", "[КАПЧА WBV] $errorMsg", 5, true)
            writeCaptchaResult("error:$errorMsg", identity)
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            updateProcessLog(identity, "captcha_wv_err", "[КАПЧА WBV] Таймаут WebView", 5, true)
            writeCaptchaResult("error:timeout", identity)
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            updateProcessLog(identity, "captcha_wv_err", "[КАПЧА WBV] Отменено", 5, true)
            writeCaptchaResult("error:cancelled", identity)
        } catch (e: Exception) {
            val errorMsg = e.message ?: "${e::class.simpleName}"
            if (errorMsg != "tunnel stopped") {
                updateProcessLog(identity, "captcha_wv_err", "[КАПЧА WBV] Ошибка — $errorMsg", 5, true)
            }
            writeCaptchaResult("error:$errorMsg", identity)
        }

        updateProcessLog(identity, "captcha_wv_step_6", "[КАПЧА WBV] WebView уничтожен", 5, false)
    }

    private suspend fun solveSingleAutoWebViewCaptcha(
        redirectUri: String,
        sessionToken: String,
        identity: ProcessIdentity,
    ): String {
        updateProcessLog(identity, "captcha_wv_step_1", "[КАПЧА WBV] Авто WebView попытка 10с...", 5, false)
        return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
            updateProcessLog(identity, "captcha_wv_auto_step", "[КАПЧА WBV] $step", 5, false)
        }
    }

    private suspend fun solveAutoWebViewCaptcha(
        ctx: Context,
        redirectUri: String,
        sessionToken: String,
        identity: ProcessIdentity,
    ): String {
        for (attempt in 1..2) {
            updateProcessLog(identity, "captcha_wv_step_1", "[КАПЧА WBV] Авто WebView попытка $attempt/2...", 5, false)
            try {
                return CaptchaWebViewManager.solveCaptchaAsync(redirectUri, sessionToken) { step ->
                    updateProcessLog(identity, "captcha_wv_auto_step", "[КАПЧА WBV] $step", 5, false)
                }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                updateProcessLog(identity, "captcha_wv_timeout_$attempt", "[КАПЧА WBV] Авто таймаут 10с ($attempt/2)", 5, attempt == 2)
                if (attempt == 2) {
                    updateProcessLog(identity, "captcha_wv_fallback", "[КАПЧА WBV] 2 таймаута авто, открыт ручной WebView", 5, false)
                    return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
            } catch (e: IllegalStateException) {
                if (e.message == CaptchaWebViewManager.ERROR_SLIDER_DETECTED) {
                    updateProcessLog(identity, "captcha_wv_fallback", "[КАПЧА WBV] Обнаружен слайдер, открыт ручной WebView", 5, false)
                    return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
                }
                throw e
            }
        }
        return ManlCaptchaWebViewManager.solveCaptchaAsync(ctx, redirectUri, sessionToken)
    }

    private fun writeCaptchaResult(result: String, identity: ProcessIdentity) {
        writeProcessCommand(identity, "CAPTCHA_RESULT|$result", "captcha_write_err")
    }

    private fun writeProcessCommand(
        identity: ProcessIdentity,
        command: String,
        errorKey: String,
    ): Boolean {
        if (!isCurrent(identity) || !identity.process.isAlive) return false
        return try {
            synchronized(identity.inputLock) {
                identity.process.outputStream.write("$command\n".toByteArray(Charsets.UTF_8))
                identity.process.outputStream.flush()
            }
            true
        } catch (e: Exception) {
            updateProcessLog(identity, errorKey, "Ошибка записи в Rust: ${e.message}", 200, true)
            false
        }
    }

    fun clearLogs() {
        synchronized(pendingLogLock) {
            pendingLogs.clear()
        }
        unreadErrorCount.value = 0
        scope.launch(Dispatchers.Main) {
            logs.clear()
        }
        if (!running.value) {
            activeWorkers.value = 0
        }
    }

    fun startCooldown(millis: Long) {
        cooldownJob?.cancel()
        cooldownActive.value = true
        cooldownJob = scope.launch(Dispatchers.Main) {
            delay(millis)
            cooldownActive.value = false
        }
    }

    private fun Throwable.readableMessage(): String {
        val text = message ?: localizedMessage
        return if (text.isNullOrBlank()) this::class.java.simpleName else "${this::class.java.simpleName}: $text"
    }
}

data class TunnelParams(
    val peer: String,
    val vkHashes: String,
    val secondaryVkHash: String = "",
    val workersPerHash: Int,
    val port: Int,
    val sni: String = "",
    val connectionPassword: String = "",
    val protocol: String = "udp",
    val vkAuthMode: String = "vkcalls",
    val captchaMode: String = "auto",
    val captchaSolveMethod: String = "auto",
    val fingerprint: String = "firefox",
    val clientIds: String = "8202606,6287487",
    val obfsMode: String = CsqttConstants.Tunnel.DEFAULT_OBFS_MODE,
    val turnTransport: String = CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT,
    val generationId: Long = 0,
    val sessionSalt: String = "",
    val allowHashRedistribution: Boolean = false,
    val vkHashMode: String = CsqttConstants.VkAutoHash.MODE_MANUAL,
    val vkAccessToken: String = "",
)
