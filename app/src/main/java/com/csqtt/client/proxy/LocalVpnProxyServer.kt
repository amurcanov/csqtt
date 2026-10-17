package com.csqtt.client.proxy

import android.net.Network
import android.util.Log
import com.csqtt.client.proxy.BidirectionalTcpRelay.closeQuietly
import com.csqtt.client.proxy.VpnNetworkManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Высокопроизводительный встроенный прокси-сервер для раздачи VPN по Wi-Fi Hotspot.
 * Поддерживает автоматическое распознавание SOCKS5 (RFC 1928) и HTTP CONNECT / HTTP Proxy
 * на едином порту (Single-Port Protocol Multiplexing).
 */
class LocalVpnProxyServer(
    private val vpnNetworkManager: VpnNetworkManager,
    private val hotspotIpDetector: HotspotIpDetector? = null,
    private val listenPort: Int = 1080,
    private val maxConcurrentSessions: Int = 256
) {

    companion object {
        private const val TAG = "LocalVpnProxyServer"

        private const val HANDSHAKE_TIMEOUT_MS = 10_000
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val IDLE_RELAY_TIMEOUT_MS = 180_000
        private const val MAX_HTTP_HEADER_BYTES = 16 * 1024

        private const val SOCKS5_VERSION: Int = 0x05
        private const val AUTH_NO_AUTH: Byte = 0x00
        private const val AUTH_NO_ACCEPTABLE: Byte = 0xFF.toByte()

        private const val CMD_CONNECT: Int = 0x01
        private const val CMD_UDP_ASSOCIATE: Int = 0x03
        private const val ATYP_IPV4: Int = 0x01
        private const val ATYP_DOMAIN: Int = 0x03
        private const val ATYP_IPV6: Int = 0x04

        private const val REP_SUCCEEDED: Byte = 0x00
        private const val REP_GENERAL_FAILURE: Byte = 0x01
        private const val REP_CONN_NOT_ALLOWED: Byte = 0x02
        private const val REP_HOST_UNREACHABLE: Byte = 0x04
        private const val REP_CMD_NOT_SUPPORTED: Byte = 0x07
        private const val REP_ADDR_NOT_SUPPORTED: Byte = 0x08
    }

    private val threadId = AtomicInteger(0)
    private var proxyDispatcher: CoroutineDispatcher? = null
    private var serverScope: CoroutineScope? = null
    private var acceptJob: Job? = null
    private var serverSocket: ServerSocket? = null

    private val sessionSemaphore = Semaphore(maxConcurrentSessions)

    @Synchronized
    fun start() {
        if (acceptJob?.isActive == true) return

        val executor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "VpnHotspotProxy-io-${threadId.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
        val dispatcher = executor.asCoroutineDispatcher()
        proxyDispatcher = dispatcher
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        serverScope = scope

        acceptJob = scope.launch {
            runAcceptLoop()
        }
    }

    @Synchronized
    fun stop() {
        acceptJob?.cancel()
        acceptJob = null
        serverSocket.closeQuietly()
        serverSocket = null
        serverScope?.cancel()
        serverScope = null
        (proxyDispatcher as? java.io.Closeable)?.closeQuietly()
        proxyDispatcher = null
        Log.i(TAG, "LocalVpnProxyServer stopped")
    }

    private suspend fun CoroutineScope.runAcceptLoop() {
        val listener = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress("0.0.0.0", listenPort), 128)
            }
        } catch (e: IOException) {
            Log.e(TAG, "Failed to bind ServerSocket on 0.0.0.0:$listenPort", e)
            return
        }
        serverSocket = listener
        Log.i(TAG, "LocalVpnProxyServer listening on 0.0.0.0:$listenPort (SOCKS5 + HTTP Mixed Mode)")

        try {
            while (isActive && !listener.isClosed) {
                val clientSocket = try {
                    listener.accept()
                } catch (e: IOException) {
                    if (isActive && !listener.isClosed) {
                        Log.w(TAG, "Accept error on proxy ServerSocket", e)
                    }
                    break
                }

                val remoteAddress = clientSocket.inetAddress
                if (remoteAddress == null || remoteAddress.isLoopbackAddress) {
                    Log.w(TAG, "Security: rejected loopback connection from local app ($remoteAddress)")
                    clientSocket.closeQuietly()
                    continue
                }

                val detector = hotspotIpDetector
                if (detector != null) {
                    val endpoints = detector.detectHotspotEndpoints()
                    val isAllowed = endpoints.any { endpoint ->
                        isAddressInSubnet(remoteAddress, endpoint.ipAddress, endpoint.prefixLength)
                    }
                    if (!isAllowed) {
                        Log.w(
                            TAG,
                            "Security: rejected connection from unauthorized address $remoteAddress (active subnets: ${endpoints.map { "${it.interfaceName}:${it.ipAddress}/${it.prefixLength}" }})"
                        )
                        clientSocket.closeQuietly()
                        continue
                    }
                }

                if (!sessionSemaphore.tryAcquire()) {
                    Log.w(TAG, "Max concurrent sessions ($maxConcurrentSessions) reached, dropping connection")
                    clientSocket.closeQuietly()
                    continue
                }

                launch {
                    try {
                        handleClientConnection(clientSocket)
                    } finally {
                        clientSocket.closeQuietly()
                        sessionSemaphore.release()
                    }
                }
            }
        } finally {
            listener.closeQuietly()
        }
    }

    private suspend fun handleClientConnection(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            configureSocketForLowLatency(clientSocket, HANDSHAKE_TIMEOUT_MS)

            val bufferedIn = BufferedInputStream(clientSocket.getInputStream(), 4096)
            val clientOut = clientSocket.getOutputStream()

            bufferedIn.mark(4)
            val firstByte = bufferedIn.read()
            if (firstByte == -1) return

            if (firstByte == SOCKS5_VERSION) {
                remoteSocket = handleSocks5Handshake(clientSocket, bufferedIn, clientOut)
                if (remoteSocket != null) {
                    configureSocketForLowLatency(clientSocket, IDLE_RELAY_TIMEOUT_MS)
                    BidirectionalTcpRelay.relay(clientSocket, remoteSocket)
                }
            } else {
                bufferedIn.reset()
                val httpTarget = handleHttpHandshake(bufferedIn, clientOut)
                remoteSocket = httpTarget.remoteSocket
                configureSocketForLowLatency(clientSocket, IDLE_RELAY_TIMEOUT_MS)
                BidirectionalTcpRelay.relay(
                    clientSocket = clientSocket,
                    remoteSocket = remoteSocket,
                    initialRemotePayload = httpTarget.initialForwardPayload
                )
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            Log.d(TAG, "Proxy session terminated: ${e.message}")
        } finally {
            remoteSocket.closeQuietly()
            clientSocket.closeQuietly()
        }
    }

    /**
     * Полная реализация рукопожатия SOCKS5 (RFC 1928) с поддержкой IPv4, Domain и IPv6.
     * Возвращает удаленный TCP-сокет при команде CONNECT (0x01) или null при UDP ASSOCIATE (0x03).
     */
    private suspend fun handleSocks5Handshake(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream
    ): Socket? {
        val dataIn = DataInputStream(input)

        val numMethods = dataIn.readUnsignedByte()
        val methods = ByteArray(numMethods)
        dataIn.readFully(methods)

        if (!methods.contains(AUTH_NO_AUTH)) {
            output.write(byteArrayOf(SOCKS5_VERSION.toByte(), AUTH_NO_ACCEPTABLE))
            output.flush()
            throw IOException("SOCKS5 client does not support NO_AUTH (0x00)")
        }

        output.write(byteArrayOf(SOCKS5_VERSION.toByte(), AUTH_NO_AUTH))
        output.flush()

        val version = dataIn.readUnsignedByte()
        if (version != SOCKS5_VERSION) {
            throw IOException("Invalid SOCKS5 request version: $version")
        }

        val command = dataIn.readUnsignedByte()
        dataIn.readUnsignedByte() // RSV (0x00)
        val addressType = dataIn.readUnsignedByte()

        if (command == CMD_UDP_ASSOCIATE) {
            handleSocks5UdpAssociate(clientSocket, input, output, addressType, dataIn)
            return null
        }

        if (command != CMD_CONNECT) {
            sendSocks5Reply(output, REP_CMD_NOT_SUPPORTED)
            throw IOException("Unsupported SOCKS5 command: $command (only CONNECT 0x01 and UDP ASSOCIATE 0x03 are supported)")
        }

        val vpnNetwork = vpnNetworkManager.requireVpnNetwork()

        val targetAddresses: List<InetAddress> = try {
            when (addressType) {
                ATYP_IPV4 -> {
                    val rawIpv4 = ByteArray(4)
                    dataIn.readFully(rawIpv4)
                    listOf(InetAddress.getByAddress(rawIpv4))
                }
                ATYP_DOMAIN -> {
                    val domainLen = dataIn.readUnsignedByte()
                    val domainBytes = ByteArray(domainLen)
                    dataIn.readFully(domainBytes)
                    val domain = String(domainBytes, StandardCharsets.UTF_8)
                    vpnNetworkManager.resolveHostThroughVpn(domain, vpnNetwork)
                }
                ATYP_IPV6 -> {
                    val rawIpv6 = ByteArray(16)
                    dataIn.readFully(rawIpv6)
                    listOf(InetAddress.getByAddress(rawIpv6))
                }
                else -> {
                    sendSocks5Reply(output, REP_ADDR_NOT_SUPPORTED)
                    throw IOException("Unsupported SOCKS5 ATYP: $addressType")
                }
            }
        } catch (e: IOException) {
            sendSocks5Reply(output, REP_HOST_UNREACHABLE)
            throw e
        }

        if (targetAddresses.any { isForbiddenTarget(it) }) {
            sendSocks5Reply(output, REP_CONN_NOT_ALLOWED)
            throw IOException("Access to forbidden/loopback target is prohibited: $targetAddresses")
        }

        val targetPort = dataIn.readUnsignedShort()

        val outboundSocket = try {
            connectThroughVpnNetwork(vpnNetwork, targetAddresses, targetPort)
        } catch (e: IOException) {
            sendSocks5Reply(output, REP_GENERAL_FAILURE)
            throw e
        }

        sendSocks5Reply(output, REP_SUCCEEDED)
        return outboundSocket
    }

    /**
     * Реализация SOCKS5 UDP ASSOCIATE (RFC 1928 Section 6 & 7).
     * Позволяет клиентам (например, браузерам и ОС) резолвить DNS и слать UDP-трафик через VPN.
     */
    private suspend fun handleSocks5UdpAssociate(
        clientSocket: Socket,
        input: InputStream,
        output: OutputStream,
        clientAddressType: Int,
        dataIn: DataInputStream
    ) {
        when (clientAddressType) {
            ATYP_IPV4 -> {
                val rawIpv4 = ByteArray(4)
                dataIn.readFully(rawIpv4)
            }
            ATYP_DOMAIN -> {
                val domainLen = dataIn.readUnsignedByte()
                val domainBytes = ByteArray(domainLen)
                dataIn.readFully(domainBytes)
            }
            ATYP_IPV6 -> {
                val rawIpv6 = ByteArray(16)
                dataIn.readFully(rawIpv6)
            }
            else -> {
                sendSocks5Reply(output, REP_ADDR_NOT_SUPPORTED)
                throw IOException("Unsupported SOCKS5 ATYP in UDP ASSOCIATE: $clientAddressType")
            }
        }
        dataIn.readUnsignedShort() // Игнорируем порт назначения клиента из запроса

        val vpnNetwork = vpnNetworkManager.requireVpnNetwork()

        val localUdpSocket = DatagramSocket(InetSocketAddress("0.0.0.0", 0))
        val outboundUdpSocket = DatagramSocket(InetSocketAddress("0.0.0.0", 0))

        try {
            vpnNetworkManager.bindDatagramSocketToVpn(outboundUdpSocket, vpnNetwork)

            val localAddrBytes = clientSocket.localAddress?.address ?: byteArrayOf(0, 0, 0, 0)
            val bndAtyp = if (localAddrBytes.size == 16) ATYP_IPV6 else ATYP_IPV4
            val reply = ByteArray(4 + localAddrBytes.size + 2)
            reply[0] = SOCKS5_VERSION.toByte()
            reply[1] = REP_SUCCEEDED
            reply[2] = 0x00
            reply[3] = bndAtyp.toByte()
            System.arraycopy(localAddrBytes, 0, reply, 4, localAddrBytes.size)
            val portOffset = 4 + localAddrBytes.size
            val localPort = localUdpSocket.localPort
            reply[portOffset] = ((localPort shr 8) and 0xFF).toByte()
            reply[portOffset + 1] = (localPort and 0xFF).toByte()

            output.write(reply)
            output.flush()

            clientSocket.soTimeout = 0
            Log.d(TAG, "SOCKS5 UDP ASSOCIATE established on local UDP port $localPort")

            coroutineScope {
                val clientUdpAddress = AtomicReference<SocketAddress?>(null)

                val clientToRemoteJob = launch(Dispatchers.IO) {
                    val rxBuffer = ByteArray(65535)
                    val rxPacket = DatagramPacket(rxBuffer, rxBuffer.size)
                    while (isActive && !localUdpSocket.isClosed) {
                        try {
                            localUdpSocket.receive(rxPacket)
                        } catch (_: Exception) {
                            break
                        }
                        val packetAddr = rxPacket.address
                        if (packetAddr != clientSocket.inetAddress) {
                            Log.w(TAG, "Security: dropped UDP packet from untrusted address $packetAddr, expected ${clientSocket.inetAddress}")
                            continue
                        }
                        clientUdpAddress.set(rxPacket.socketAddress)
                        val length = rxPacket.length
                        if (length < 10) continue

                        val buf = rxPacket.data
                        val frag = buf[2].toInt() and 0xFF
                        if (frag != 0) continue

                        val atyp = buf[3].toInt() and 0xFF
                        var offset = 4
                        val targetAddress: InetAddress? = when (atyp) {
                            ATYP_IPV4 -> {
                                if (length < offset + 4 + 2) null
                                else {
                                    val ipBytes = ByteArray(4)
                                    System.arraycopy(buf, offset, ipBytes, 0, 4)
                                    offset += 4
                                    InetAddress.getByAddress(ipBytes)
                                }
                            }
                            ATYP_DOMAIN -> {
                                val dLen = buf[offset].toInt() and 0xFF
                                offset += 1
                                if (length < offset + dLen + 2) null
                                else {
                                    val dBytes = ByteArray(dLen)
                                    System.arraycopy(buf, offset, dBytes, 0, dLen)
                                    offset += dLen
                                    val host = String(dBytes, StandardCharsets.UTF_8)
                                    runCatching {
                                        vpnNetworkManager.resolveHostThroughVpn(host, vpnNetwork).firstOrNull()
                                    }.getOrNull()
                                }
                            }
                            ATYP_IPV6 -> {
                                if (length < offset + 16 + 2) null
                                else {
                                    val ipBytes = ByteArray(16)
                                    System.arraycopy(buf, offset, ipBytes, 0, 16)
                                    offset += 16
                                    InetAddress.getByAddress(ipBytes)
                                }
                            }
                            else -> null
                        }

                        if (targetAddress == null || isForbiddenTarget(targetAddress)) continue

                        val targetPort = ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
                        offset += 2

                        val payloadLen = length - offset
                        if (payloadLen > 0) {
                            val fwdPacket = DatagramPacket(buf, offset, payloadLen, targetAddress, targetPort)
                            try {
                                outboundUdpSocket.send(fwdPacket)
                            } catch (e: Exception) {
                                Log.w(TAG, "Failed to send outbound UDP packet: ${e.message}")
                            }
                        }
                    }
                }

                val remoteToClientJob = launch(Dispatchers.IO) {
                    val rxBuffer = ByteArray(65535)
                    val rxPacket = DatagramPacket(rxBuffer, rxBuffer.size)
                    while (isActive && !outboundUdpSocket.isClosed) {
                        try {
                            outboundUdpSocket.receive(rxPacket)
                        } catch (_: Exception) {
                            break
                        }
                        val clientAddr = clientUdpAddress.get() ?: continue
                        val srcAddr = rxPacket.address
                        val srcPort = rxPacket.port
                        val rawSrcAddr = srcAddr.address
                        val respAtyp = if (rawSrcAddr.size == 16) ATYP_IPV6 else ATYP_IPV4

                        val headerLen = 4 + rawSrcAddr.size + 2
                        val totalLen = headerLen + rxPacket.length
                        val sendBuf = ByteArray(totalLen)
                        sendBuf[0] = 0x00
                        sendBuf[1] = 0x00
                        sendBuf[2] = 0x00 // FRAG
                        sendBuf[3] = respAtyp.toByte()
                        System.arraycopy(rawSrcAddr, 0, sendBuf, 4, rawSrcAddr.size)
                        val pOff = 4 + rawSrcAddr.size
                        sendBuf[pOff] = ((srcPort shr 8) and 0xFF).toByte()
                        sendBuf[pOff + 1] = (srcPort and 0xFF).toByte()
                        System.arraycopy(rxPacket.data, rxPacket.offset, sendBuf, headerLen, rxPacket.length)

                        val respPacket = DatagramPacket(sendBuf, totalLen, clientAddr)
                        try {
                            localUdpSocket.send(respPacket)
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to send UDP response to client: ${e.message}")
                        }
                    }
                }

                withContext(Dispatchers.IO) {
                    try {
                        val monitorBuf = ByteArray(64)
                        while (isActive) {
                            val r = input.read(monitorBuf)
                            if (r == -1) break
                        }
                    } catch (_: Exception) {}
                }

                clientToRemoteJob.cancel()
                remoteToClientJob.cancel()
            }
        } finally {
            localUdpSocket.closeQuietly()
            outboundUdpSocket.closeQuietly()
        }
    }

    private fun sendSocks5Reply(output: OutputStream, replyCode: Byte) {
        try {
            val response = byteArrayOf(
                SOCKS5_VERSION.toByte(),
                replyCode,
                0x00,
                ATYP_IPV4.toByte(),
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            )
            output.write(response)
            output.flush()
        } catch (ignored: IOException) {
        }
    }

    private class HttpHandshakeResult(
        val remoteSocket: Socket,
        val initialForwardPayload: ByteArray?
    )

    /**
     * Обработка HTTP CONNECT (для HTTPS/TLS) и стандартных HTTP-запросов.
     */
    private suspend fun handleHttpHandshake(
        input: BufferedInputStream,
        clientOut: OutputStream
    ): HttpHandshakeResult {
        val headerBytes = readUntilHeaderEnd(input)
        val headerText = String(headerBytes, StandardCharsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        val requestLine = lines.firstOrNull() ?: throw IOException("Empty HTTP proxy request")

        val parts = requestLine.split(' ')
        if (parts.size < 3) {
            throw IOException("Malformed HTTP request line: $requestLine")
        }

        val method = parts[0].uppercase()
        val rawTarget = parts[1]
        val httpVersion = parts[2]

        val vpnNetwork = vpnNetworkManager.requireVpnNetwork()

        if (method == "CONNECT") {
            val (host, port) = parseHostPort(rawTarget, defaultPort = 443)
            val resolvedAddresses = parseLiteralIpOrResolveInVpn(host, vpnNetwork)

            if (resolvedAddresses.any { isForbiddenTarget(it) }) {
                clientOut.write("$httpVersion 403 Forbidden\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1))
                clientOut.flush()
                throw IOException("Access to forbidden/loopback target is prohibited: $host")
            }

            val outboundSocket = try {
                connectThroughVpnNetwork(vpnNetwork, resolvedAddresses, port)
            } catch (e: IOException) {
                clientOut.write("$httpVersion 502 Bad Gateway\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1))
                clientOut.flush()
                throw e
            }

            clientOut.write(
                "$httpVersion 200 Connection Established\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
            )
            clientOut.flush()
            return HttpHandshakeResult(outboundSocket, null)
        } else {
            val uri = try {
                URI(rawTarget)
            } catch (e: Exception) {
                throw IOException("Invalid HTTP proxy URI: $rawTarget", e)
            }

            val hostHeader = lines.drop(1)
                .firstOrNull { it.startsWith("Host:", ignoreCase = true) }
                ?.substringAfter(':')
                ?.trim()

            val targetHost = uri.host ?: hostHeader?.substringBefore(':')
                ?: throw IOException("Cannot determine target host for HTTP request")
            val targetPort = when {
                uri.port != -1 -> uri.port
                hostHeader != null && ':' in hostHeader -> hostHeader.substringAfterLast(':').toIntOrNull() ?: 80
                else -> 80
            }

            val relativePath = buildString {
                val rawPath = uri.rawPath
                append(if (rawPath.isNullOrEmpty()) "/" else rawPath)
                if (!uri.rawQuery.isNullOrEmpty()) {
                    append('?').append(uri.rawQuery)
                }
            }

            val resolvedAddresses = parseLiteralIpOrResolveInVpn(targetHost, vpnNetwork)

            if (resolvedAddresses.any { isForbiddenTarget(it) }) {
                clientOut.write("$httpVersion 403 Forbidden\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1))
                clientOut.flush()
                throw IOException("Access to forbidden/loopback target is prohibited: $targetHost")
            }

            val outboundSocket = connectThroughVpnNetwork(vpnNetwork, resolvedAddresses, targetPort)

            val rewrittenHeader = buildString {
                append("$method $relativePath $httpVersion\r\n")
                for (i in 1 until lines.size) {
                    val line = lines[i]
                    if (line.isEmpty()) continue
                    if (line.startsWith("Proxy-Connection:", ignoreCase = true) ||
                        line.startsWith("Proxy-Authorization:", ignoreCase = true)
                    ) {
                        continue
                    }
                    append(line).append("\r\n")
                }
                append("\r\n")
            }.toByteArray(StandardCharsets.ISO_8859_1)

            return HttpHandshakeResult(outboundSocket, rewrittenHeader)
        }
    }

    private suspend fun parseLiteralIpOrResolveInVpn(
        host: String,
        vpnNetwork: Network
    ): List<InetAddress> {
        val cleanHost = host.removeSurrounding("[", "]")
        val isIpv4Literal = cleanHost.all { it.isDigit() || it == '.' } && cleanHost.count { it == '.' } == 3
        val isIpv6Literal = ':' in cleanHost
        if (isIpv4Literal || isIpv6Literal) {
            return listOf(InetAddress.getByName(cleanHost))
        }
        return vpnNetworkManager.resolveHostThroughVpn(cleanHost, vpnNetwork)
    }

    /**
     * Создает исходящий TCP-сокет, привязывает его к виртуальной сети VPN (tun0)
     * через vpnNetwork.bindSocket() и выполняет подключение с перебором адресов.
     */
    private fun connectThroughVpnNetwork(
        vpnNetwork: Network,
        addresses: List<InetAddress>,
        port: Int
    ): Socket {
        var lastException: IOException? = null

        for (address in addresses) {
            val socket = Socket()
            try {
                configureSocketForLowLatency(socket, IDLE_RELAY_TIMEOUT_MS)
                vpnNetworkManager.bindSocketToVpn(socket, vpnNetwork)
                socket.connect(InetSocketAddress(address, port), CONNECT_TIMEOUT_MS)
                return socket
            } catch (e: IOException) {
                socket.closeQuietly()
                lastException = e
            }
        }

        throw lastException ?: IOException("Unable to connect to any resolved address on port $port")
    }

    /**
     * Настраивает сокет на минимальную задержку без отключения Linux Kernel TCP Autotuning.
     */
    private fun configureSocketForLowLatency(socket: Socket, soTimeoutMs: Int) {
        socket.tcpNoDelay = true
        socket.keepAlive = true
        socket.soTimeout = soTimeoutMs
    }

    private fun readUntilHeaderEnd(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream(1024)
        var matchState = 0

        while (out.size() < MAX_HTTP_HEADER_BYTES) {
            val b = input.read()
            if (b == -1) throw EOFException("Unexpected EOF while reading HTTP proxy headers")
            out.write(b)

            matchState = when {
                b == '\r'.code && (matchState == 0 || matchState == 2) -> matchState + 1
                b == '\n'.code && (matchState == 1 || matchState == 3) -> matchState + 1
                b == '\r'.code -> 1
                else -> 0
            }

            if (matchState == 4) {
                return out.toByteArray()
            }
        }
        throw IOException("HTTP proxy header exceeded maximum size ($MAX_HTTP_HEADER_BYTES bytes)")
    }

    private fun parseHostPort(rawTarget: String, defaultPort: Int): Pair<String, Int> {
        if (rawTarget.startsWith("[")) {
            val closeBracket = rawTarget.indexOf(']')
            if (closeBracket != -1) {
                val host = rawTarget.substring(1, closeBracket)
                val portPart = rawTarget.substring(closeBracket + 1)
                val port = if (portPart.startsWith(":")) {
                    portPart.substring(1).toIntOrNull() ?: defaultPort
                } else {
                    defaultPort
                }
                return host to port
            }
        }

        val colonIndex = rawTarget.lastIndexOf(':')
        return if (colonIndex != -1 && rawTarget.indexOf(':') == colonIndex) {
            val host = rawTarget.substring(0, colonIndex)
            val port = rawTarget.substring(colonIndex + 1).toIntOrNull() ?: defaultPort
            host to port
        } else {
            rawTarget to defaultPort
        }
    }

    private fun isForbiddenTarget(address: InetAddress): Boolean {
        return address.isLoopbackAddress || address.isAnyLocalAddress
    }

    private fun isAddressInSubnet(
        clientAddr: InetAddress,
        ifaceAddrStr: String,
        prefixLength: Short
    ): Boolean {
        if (clientAddr !is Inet4Address) return false
        val ifaceAddr = try {
            InetAddress.getByName(ifaceAddrStr)
        } catch (_: Exception) {
            return false
        }
        if (ifaceAddr !is Inet4Address) return false

        // Исключаем подключение телефона к самому себе через адрес точки доступа
        if (clientAddr == ifaceAddr) return false

        val prefix = if (prefixLength in 8..30) {
            prefixLength.toInt()
        } else {
            24
        }

        val mask = -1 shl (32 - prefix)
        val clientInt = ipToInt(clientAddr)
        val ifaceInt = ipToInt(ifaceAddr)
        return (clientInt and mask) == (ifaceInt and mask)
    }

    private fun ipToInt(addr: InetAddress): Int {
        val b = addr.address
        return ((b[0].toInt() and 0xFF) shl 24) or
                ((b[1].toInt() and 0xFF) shl 16) or
                ((b[2].toInt() and 0xFF) shl 8) or
                (b[3].toInt() and 0xFF)
    }
}
