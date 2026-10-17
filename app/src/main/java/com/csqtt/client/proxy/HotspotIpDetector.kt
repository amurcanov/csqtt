package com.csqtt.client.proxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections

/**
 * Структура данных активного интерфейса тезеринга (Wi-Fi Hotspot / USB / BT).
 */
data class HotspotEndpoint(
    val interfaceName: String,
    val ipAddress: String,
    val prefixLength: Short,
    val isConfirmedBySystemBroadcast: Boolean
)

/**
 * Детектор локального IPv4-адреса точки доступа, устойчивый к вендорным различиям
 * (Samsung OneUI, Xiaomi MIUI/HyperOS, Google Pixel, MediaTek/Qualcomm) и режиму STA+AP.
 */
class HotspotIpDetector(private val context: Context) {

    companion object {
        private const val TAG = "HotspotIpDetector"
        private const val ACTION_TETHER_STATE_CHANGED = "android.net.conn.TETHER_STATE_CHANGED"
        private const val EXTRA_ACTIVE_TETHER = "activeArray"
        private const val EXTRA_ACTIVE_LOCAL_ONLY = "localOnlyArray"
        private const val EXTRA_TETHER_LEGACY = "tetherArray"

        private val HOTSPOT_INTERFACE_PRIORITIES = listOf(
            Regex("^swlan\\d+$"),          // Samsung OneUI Mobile Hotspot
            Regex("^ap\\d+$"),             // MediaTek / Qualcomm dedicated AP
            Regex("^softap\\d*$"),         // Broadcom / Legacy SoftAP
            Regex("^wlan-ap\\d*$"),        // Специализированные сборки
            Regex("^wlan[1-9]\\d*$"),      // Pixel / Xiaomi STA+AP Concurrency (wlan1, wlan2)
            Regex("^p2p-wlan\\d+-\\d+$"),  // Wi-Fi Direct Hotspot
            Regex("^p2p\\d+$"),            // Wi-Fi Direct
            Regex("^rndis\\d+$"),          // USB Tethering (RNDIS)
            Regex("^usb\\d+$"),            // USB Tethering
            Regex("^ncm\\d+$"),            // USB Tethering (CDC NCM)
            Regex("^bt-pan$"),             // Bluetooth PAN Tethering
            Regex("^bnep\\d+$"),           // Bluetooth Tethering
            Regex("^wlan0$")               // Fallback: когда клиентский Wi-Fi выключен и wlan0 в режиме AP
        )

        private val IGNORED_INTERFACE_REGEX = Regex(
            "^(lo|tun\\d*|ppp\\d*|wg\\d*|rmnet.*|ccmni.*|pdp.*|clat.*|dummy.*|ipsec.*|epdg.*|v4-.*)$"
        )
    }

    private val connectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    /**
     * Возвращает список активных интерфейсов точки доступа, отсортированных по достоверности.
     */
    fun detectHotspotEndpoints(): List<HotspotEndpoint> {
        val activeTetherIfaces = getActiveTetherInterfacesFromStickyBroadcast()
        val upstreamInterfaces = getUpstreamClientInterfaces()

        val candidates = mutableListOf<Pair<Int, HotspotEndpoint>>()

        val networkInterfaces = try {
            Collections.list(NetworkInterface.getNetworkInterfaces())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enumerate NetworkInterfaces", e)
            return emptyList()
        }

        for (netIf in networkInterfaces) {
            val name = netIf.name ?: continue

            val isEligible = try {
                netIf.isUp && !netIf.isLoopback && !netIf.isPointToPoint
            } catch (e: Exception) {
                false
            }
            if (!isEligible) continue
            if (IGNORED_INTERFACE_REGEX.matches(name)) continue

            val isConfirmedTether = name in activeTetherIfaces
            if (!isConfirmedTether && name in upstreamInterfaces) {
                continue
            }

            for (ifaceAddr in netIf.interfaceAddresses) {
                val inetAddr = ifaceAddr.address
                if (inetAddr is Inet4Address && !inetAddr.isLoopbackAddress && inetAddr.isSiteLocalAddress) {
                    val hostAddress = inetAddr.hostAddress ?: continue
                    val score = calculateInterfaceScore(name, hostAddress, isConfirmedTether)
                    if (score > 0) {
                        candidates.add(
                            score to HotspotEndpoint(
                                interfaceName = name,
                                ipAddress = hostAddress,
                                prefixLength = ifaceAddr.networkPrefixLength,
                                isConfirmedBySystemBroadcast = isConfirmedTether
                            )
                        )
                    }
                }
            }
        }

        return candidates
            .sortedByDescending { it.first }
            .map { it.second }
    }

    /**
     * Реактивный поток, отслеживающий изменения состояния точки доступа в реальном времени.
     */
    fun observeHotspotEndpoints(): Flow<List<HotspotEndpoint>> = callbackFlow {
        val sendUpdate = {
            trySend(detectHotspotEndpoints())
        }

        val tetherReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                sendUpdate()
            }
        }

        val filter = IntentFilter(ACTION_TETHER_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(tetherReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(tetherReceiver, filter)
        }

        sendUpdate()

        awaitClose {
            try {
                context.unregisterReceiver(tetherReceiver)
            } catch (ignored: Exception) {
            }
        }
    }.distinctUntilChanged()

    private fun getActiveTetherInterfacesFromStickyBroadcast(): Set<String> {
        return try {
            val filter = IntentFilter(ACTION_TETHER_STATE_CHANGED)
            val stickyIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(null, filter, Context.RECEIVER_EXPORTED)
            } else {
                context.registerReceiver(null, filter)
            } ?: return emptySet()

            val result = mutableSetOf<String>()
            stickyIntent.getStringArrayListExtra(EXTRA_ACTIVE_TETHER)?.let { result.addAll(it) }
            stickyIntent.getStringArrayListExtra(EXTRA_ACTIVE_LOCAL_ONLY)?.let { result.addAll(it) }
            stickyIntent.getStringArrayListExtra(EXTRA_TETHER_LEGACY)?.let { result.addAll(it) }
            result
        } catch (e: Exception) {
            Log.w(TAG, "Unable to read sticky TETHER_STATE_CHANGED broadcast", e)
            emptySet()
        }
    }

    private fun getUpstreamClientInterfaces(): Set<String> {
        val upstreamIfaces = mutableSetOf<String>()
        try {
            for (network in connectivityManager.allNetworks) {
                val caps = connectivityManager.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                ) {
                    val linkProps = connectivityManager.getLinkProperties(network)
                    linkProps?.interfaceName?.let { upstreamIfaces.add(it) }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to inspect upstream client networks", e)
        }
        return upstreamIfaces
    }

    private fun calculateInterfaceScore(
        ifName: String,
        ip: String,
        isConfirmedTether: Boolean
    ): Int {
        var score = 0
        if (isConfirmedTether) {
            score += 1000
        }

        val priorityIndex = HOTSPOT_INTERFACE_PRIORITIES.indexOfFirst { it.matches(ifName) }
        if (priorityIndex >= 0) {
            score += (HOTSPOT_INTERFACE_PRIORITIES.size - priorityIndex) * 50
        } else if (!isConfirmedTether) {
            return 0
        }

        if (ip.startsWith("192.168.")) {
            score += 20
        }
        if (ip.endsWith(".1") || ip.endsWith(".129")) {
            score += 5
        }

        return score
    }
}
