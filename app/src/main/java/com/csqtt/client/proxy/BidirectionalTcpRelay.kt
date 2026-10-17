package com.csqtt.client.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/**
 * Двунаправленный TCP-релей промышленного класса.
 * Реализует синхронный Backpressure через сокетные буферы ядра Linux,
 * поддержку Half-Closed TCP (FIN -> shutdownOutput) и защиту от зависания потоков на RST.
 */
object BidirectionalTcpRelay {

    private const val RELAY_BUFFER_SIZE = 32 * 1024 // 32 KB
    private const val DEFAULT_HALF_CLOSE_TIMEOUT_MS = 15_000L

    /**
     * Связывает два TCP-сокета в полнодуплексный канал и блокирует вызывающую корутину
     * до полного закрытия обоих направлений. Гарантирует освобождение дескрипторов при выходе.
     */
    suspend fun relay(
        clientSocket: Socket,
        remoteSocket: Socket,
        initialRemotePayload: ByteArray? = null,
        halfCloseTimeoutMs: Long = DEFAULT_HALF_CLOSE_TIMEOUT_MS
    ) = coroutineScope {
        try {
            if (initialRemotePayload != null && initialRemotePayload.isNotEmpty()) {
                val remoteOut = remoteSocket.getOutputStream()
                remoteOut.write(initialRemotePayload)
                remoteOut.flush()
            }

            var watchdogJob: Job? = null

            val startHalfCloseWatchdog: () -> Unit = {
                synchronized(this) {
                    if (watchdogJob == null) {
                        watchdogJob = launch {
                            delay(halfCloseTimeoutMs)
                            clientSocket.closeQuietly()
                            remoteSocket.closeQuietly()
                        }
                    }
                }
            }

            val clientToRemote = launch {
                pumpStream(
                    sourceSocket = clientSocket,
                    targetSocket = remoteSocket,
                    onNormalEof = startHalfCloseWatchdog
                )
            }

            val remoteToClient = launch {
                pumpStream(
                    sourceSocket = remoteSocket,
                    targetSocket = clientSocket,
                    onNormalEof = startHalfCloseWatchdog
                )
            }

            clientToRemote.join()
            remoteToClient.join()
            watchdogJob?.cancel()
        } finally {
            clientSocket.closeQuietly()
            remoteSocket.closeQuietly()
        }
    }

    private fun CoroutineScope.pumpStream(
        sourceSocket: Socket,
        targetSocket: Socket,
        onNormalEof: () -> Unit
    ) {
        val buffer = ByteArray(RELAY_BUFFER_SIZE)
        try {
            val input: InputStream = sourceSocket.getInputStream()
            val output: OutputStream = targetSocket.getOutputStream()

            while (isActive) {
                val bytesRead = input.read(buffer)
                if (bytesRead == -1) {
                    targetSocket.safeShutdownOutput()
                    sourceSocket.safeShutdownInput()
                    onNormalEof()
                    return
                }

                output.write(buffer, 0, bytesRead)
            }
        } catch (e: IOException) {
            sourceSocket.closeQuietly()
            targetSocket.closeQuietly()
        }
    }

    private fun Socket.safeShutdownOutput() {
        try {
            if (!isClosed && !isOutputShutdown) {
                shutdownOutput()
            }
        } catch (ignored: Exception) {
        }
    }

    private fun Socket.safeShutdownInput() {
        try {
            if (!isClosed && !isInputShutdown) {
                shutdownInput()
            }
        } catch (ignored: Exception) {
        }
    }

    fun Closeable?.closeQuietly() {
        try {
            this?.close()
        } catch (ignored: Exception) {
        }
    }
}
