// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class TunVpnService : VpnService() {
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private val vpnMutex = Mutex()
    private val interfaceLock = Any()
    private var vpnInterface: ParcelFileDescriptor? = null
    private var sendJob: Job? = null
    private var activeClientIp: String? = null
    private var activeDns: String? = null
    private var recoveryAttempts = 0
    private var stopRequested = false
    @Volatile
    private var serviceDestroyed = false

    companion object {
        private const val TAG = "TunVPN"

        @Volatile
        var instance: TunVpnService? = null
            private set

        @Volatile
        var tunFd: Int = -1
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        Log.d(TAG, "TunVpnService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        when (intent.action) {
            "START" -> {
                stopRequested = false
                val clientIp = intent.getStringExtra("client_ip") ?: "10.66.66.2"
                val dns = intent.getStringExtra("dns") ?: "1.1.1.1"
                val forceRebuild = intent.getBooleanExtra("force_rebuild", false)
                if (!forceRebuild) recoveryAttempts = 0
                serviceScope.launch {
                    startVpn(clientIp, dns, forceRebuild)
                }
            }
            "STOP" -> {
                stopRequested = true
                serviceScope.launch {
                    vpnMutex.withLock { stopVpn() }
                    stopSelf()
                }
            }
        }

        return START_STICKY
    }

    private suspend fun startVpn(clientIp: String, dns: String, forceRebuild: Boolean) {
        vpnMutex.withLock {
        try {
            val existing = synchronized(interfaceLock) {
                vpnInterface?.takeIf {
                    TunRecoveryPolicy.shouldReuse(
                        hasInterface = true,
                        descriptorValid = it.fileDescriptor.valid(),
                        serviceDestroyed = serviceDestroyed,
                        forceRebuild = forceRebuild,
                        activeClientIp = activeClientIp,
                        activeDns = activeDns,
                        requestedClientIp = clientIp,
                        requestedDns = dns,
                    )
                }
            }
            if (existing != null) {
                sendTunFd(existing)
                return
            }

            if (VpnService.prepare(this) != null) {
                failVpn("разрешение Android VPN не выдано")
                return
            }

            val settingsStore = SettingsStore(applicationContext)
            val savedExcluded = settingsStore.excludedApps.first()
            val isWhitelist = settingsStore.isWhitelist.first()
            val userSelected = savedExcluded.split(",").filter { it.isNotEmpty() }.toSet()
            val transportPackages = setOf(
                applicationContext.packageName,
                CsqttConstants.General.PACKAGE_VK,
                CsqttConstants.General.PACKAGE_VK_CALLS
            )

            val builder = Builder()
                .setSession("CSQTT")
                .setMtu(CsqttConstants.Vpn.DEFAULT_MTU)
                .addAddress(clientIp, 32)
                .addRoute("0.0.0.0", 0)

            var validDnsServers = 0
            dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { dnsServer ->
                try {
                    builder.addDnsServer(dnsServer)
                    validDnsServers++
                } catch (e: Exception) {
                    Log.w(TAG, "Invalid DNS server: $dnsServer")
                }
            }
            if (validDnsServers == 0) {
                failVpn("сервер передал некорректный DNS: $dns")
                return
            }

            if (isWhitelist) {
                val installedIncluded = userSelected
                    .filter { pkg -> 
                        pkg !in transportPackages && isPackageInstalled(pkg) 
                    }
                    .toSet()
                if (installedIncluded.isEmpty()) {
                    failVpn("Whitelist пуст: выберите хотя бы одно установленное приложение")
                    return
                } else {
                    var includedCount = 0
                    installedIncluded.forEach { pkg ->
                        try {
                            builder.addAllowedApplication(pkg)
                            includedCount++
                        } catch (error: Exception) {
                            Log.w(TAG, "Unable to include $pkg in VPN", error)
                        }
                    }
                    if (includedCount == 0) {
                        failVpn("Android не разрешил добавить выбранные приложения в whitelist")
                        return
                    }
                }
            } else {
                try {
                    builder.addDisallowedApplication(applicationContext.packageName)
                } catch (e: Exception) {
                    Log.e(TAG, "Unable to exclude CSQTT UID from its VPN", e)
                    failVpn("Android не разрешил исключить CSQTT из собственного VPN")
                    return
                }
                val excluded = transportPackages.toMutableSet()
                excluded.addAll(userSelected)
                excluded
                    .filter { it != applicationContext.packageName && isPackageInstalled(it) }
                    .forEach { pkg ->
                    try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                }
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "VPN permission not granted")
                failVpn("Android не создал VPN-интерфейс; проверьте разрешение VPN и Always-on VPN")
                return
            }

            var previousInterface: ParcelFileDescriptor? = null
            val accepted = synchronized(interfaceLock) {
                if (serviceDestroyed) {
                    false
                } else {
                    previousInterface = vpnInterface
                    vpnInterface = pfd
                    tunFd = pfd.fd
                    activeClientIp = clientIp
                    activeDns = dns
                    true
                }
            }
            if (!accepted) {
                pfd.close()
                return
            }
            sendJob?.cancel()
            if (previousInterface !== pfd) {
                runCatching { previousInterface?.close() }
            }
            Log.d(TAG, "VPN interface established: IP=$clientIp DNS=$dns fd=$tunFd")

            sendTunFd(pfd)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}", e)
            failVpn(e.message ?: e.javaClass.simpleName)
        }
        }
    }

    private fun sendTunFd(pfd: ParcelFileDescriptor) {
        sendJob?.cancel()
        sendJob = serviceScope.launch {
            var success = false
            for (i in 1..20) {
                val socket = android.net.LocalSocket()
                try {
                    socket.connect(android.net.LocalSocketAddress("csqtt_tun_uds", android.net.LocalSocketAddress.Namespace.ABSTRACT))
                    socket.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
                    socket.outputStream.write(1)
                    Log.d(TAG, "Sent TUN fd to Rust client successfully")
                    success = true
                    recoveryAttempts = 0
                    TunnelManager.onVpnInterfaceReady()
                    break
                } catch (e: Exception) {
                    Log.d(TAG, "Failed to connect to Rust client UDS, retrying: ${e.message}")
                    delay(500)
                } finally {
                    runCatching { socket.close() }
                }
            }
            if (!success) {
                Log.e(TAG, "Could not send TUN fd to Rust client after 20 retries")
                recoverAfterFdFailure(pfd)
            }
        }
    }

    private suspend fun recoverAfterFdFailure(failedInterface: ParcelFileDescriptor) {
        val recoveryConfig = synchronized(interfaceLock) {
            if (vpnInterface !== failedInterface || serviceDestroyed) {
                null
            } else {
                runCatching { vpnInterface?.close() }
                vpnInterface = null
                tunFd = -1
                val config = activeClientIp?.let { ip -> activeDns?.let { dns -> ip to dns } }
                activeClientIp = null
                activeDns = null
                config
            }
        } ?: return
        TunnelManager.onVpnInterfaceStopped()
        if (recoveryAttempts >= 2) {
            failVpn("не удалось передать TUN fd Rust-клиенту после повторных попыток")
            return
        }
        recoveryAttempts++
        delay(500L * recoveryAttempts)
        startVpn(recoveryConfig.first, recoveryConfig.second, forceRebuild = true)
    }

    private fun failVpn(message: String) {
        stopRequested = true
        stopVpn()
        TunnelManager.onVpnTerminalFailure(message)
    }

    private fun stopVpn() {
        sendJob?.cancel()
        sendJob = null
        synchronized(interfaceLock) {
            try {
                vpnInterface?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing VPN interface: ${e.message}")
            }
            vpnInterface = null
            tunFd = -1
            activeClientIp = null
            activeDns = null
        }
        TunnelManager.onVpnInterfaceStopped()
        Log.d(TAG, "VPN interface closed")
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: Exception) {
            false
        }
    }

    override fun onDestroy() {
        val unexpected = !stopRequested && TunnelManager.running.value
        serviceDestroyed = true
        serviceJob.cancel()
        stopVpn()
        instance = null
        if (unexpected) {
            TunnelManager.onVpnTerminalFailure("VPN-сервис был остановлен Android")
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        stopRequested = true
        serviceDestroyed = true
        serviceJob.cancel()
        stopVpn()
        instance = null
        TunnelManager.onVpnTerminalFailure("разрешение Android VPN было отозвано")
        stopSelf()
    }
}
