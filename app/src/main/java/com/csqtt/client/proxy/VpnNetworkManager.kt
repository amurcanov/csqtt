package com.csqtt.client.proxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Socket

/**
 * Промышленный менеджер отслеживания виртуальной сети VPN (TRANSPORT_VPN).
 * Обеспечивает привязку исходящих сокетов прокси-сервера к интерфейсу tun0
 * и изолированный DNS-резолвинг внутри туннеля для процесса, исключенного
 * через VpnService.Builder.addDisallowedApplication().
 */
class VpnNetworkManager(context: Context) {

    companion object {
        private const val TAG = "VpnNetworkManager"
        private const val VPN_NETWORK_ACQUIRE_TIMEOUT_MS = 3_500L
    }

    private val connectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val _vpnNetwork = MutableStateFlow<Network?>(null)
    val vpnNetwork: StateFlow<Network?> = _vpnNetwork.asStateFlow()

    @Volatile
    private var isRegistered = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (isVpnTransport(network)) {
                Log.i(TAG, "VPN Network available: $network (handle=${network.networkHandle})")
                _vpnNetwork.value = network
            }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                if (_vpnNetwork.value != network) {
                    Log.i(TAG, "VPN Network updated via capabilities: $network")
                    _vpnNetwork.value = network
                }
            }
        }

        override fun onLost(network: Network) {
            if (_vpnNetwork.value == network) {
                Log.w(TAG, "VPN Network lost: $network")
                _vpnNetwork.value = findActiveVpnNetworkSynchronously()
            }
        }
    }

    /**
     * Запускает мониторинг VPN-сети. Вызывается ДО VpnService.Builder.establish().
     */
    @Synchronized
    fun startMonitoring() {
        if (isRegistered) return
        _vpnNetwork.value = findActiveVpnNetworkSynchronously()

        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        try {
            connectivityManager.registerNetworkCallback(request, networkCallback)
            isRegistered = true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register VPN NetworkCallback", e)
        }
    }

    /**
     * Принудительная синхронизация сразу после вызова Builder.establish()
     * для устранения задержки доставки асинхронного колбэка onAvailable().
     */
    fun notifyVpnEstablished() {
        val current = _vpnNetwork.value
        if (current != null && isVpnTransport(current)) return
        findActiveVpnNetworkSynchronously()?.let { found ->
            Log.i(TAG, "Synchronously resolved VPN Network after establish(): $found")
            _vpnNetwork.value = found
        }
    }

    @Synchronized
    fun stopMonitoring() {
        if (!isRegistered) return
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (ignored: IllegalArgumentException) {
        } finally {
            isRegistered = false
            _vpnNetwork.value = null
        }
    }

    /**
     * Возвращает активный объект Network для VPN. Если туннель находится в фазе
     * инициализации после establish(), корутина неблокирующе ожидает до 3.5 секунд.
     */
    suspend fun requireVpnNetwork(): Network {
        _vpnNetwork.value?.let { return it }
        notifyVpnEstablished()
        _vpnNetwork.value?.let { return it }

        return withTimeoutOrNull(VPN_NETWORK_ACQUIRE_TIMEOUT_MS) {
            _vpnNetwork.filterNotNull().first()
        } ?: throw IOException(
            "Active VPN Network (tun0) is unavailable after ${VPN_NETWORK_ACQUIRE_TIMEOUT_MS}ms"
        )
    }

    /**
     * Привязывает исходящий TCP-сокет прокси-сервера к виртуальной сети VPN (tun0).
     */
    @Throws(IOException::class)
    fun bindSocketToVpn(socket: Socket, network: Network) {
        network.bindSocket(socket)
    }

    /**
     * Привязывает исходящий UDP-сокет прокси-сервера к виртуальной сети VPN (tun0).
     */
    @Throws(IOException::class)
    fun bindDatagramSocketToVpn(socket: DatagramSocket, network: Network) {
        network.bindSocket(socket)
    }

    /**
     * Выполняет изолированный DNS-резолвинг строго внутри VPN-туннеля, исключая утечки DNS
     * в физическую сеть оператора. Приоритизирует IPv4-адреса для стабильности соединения.
     */
    @Throws(IOException::class)
    suspend fun resolveHostThroughVpn(host: String, network: Network): List<InetAddress> =
        withContext(Dispatchers.IO) {
            val addresses = network.getAllByName(host)
            if (addresses.isEmpty()) {
                throw IOException("DNS resolution returned empty result for host: $host")
            }
            addresses.sortedWith(compareBy { address ->
                when (address) {
                    is Inet4Address -> 0
                    is Inet6Address -> 1
                    else -> 2
                }
            })
        }

    private fun findActiveVpnNetworkSynchronously(): Network? {
        return try {
            connectivityManager.allNetworks.firstOrNull { network ->
                isVpnTransport(network)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query allNetworks", e)
            null
        }
    }

    private fun isVpnTransport(network: Network): Boolean {
        val caps = connectivityManager.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}
