// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.proxy

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

/**
 * UDS-сервер приема файловых дескрипторов (SCM_RIGHTS) от дочернего нативного процесса
 * libclient.so (через LD_PRELOAD libprotect_shim.so).
 */
class ProtectSocketServer(
    context: Context,
    private val vpnService: VpnService,
    private val underlyingNetworkProvider: () -> Network? = { null }
) {
    companion object {
        private const val TAG = "ProtectSocketServer"
        private const val SOCKET_FILE_NAME = "protect_sock"
    }

    val socketFile: File = File(context.noBackupFilesDir, SOCKET_FILE_NAME)
    private var serverScope: CoroutineScope? = null
    private var acceptJob: Job? = null
    private var boundSocket: LocalSocket? = null
    private var localServerSocket: LocalServerSocket? = null

    @Synchronized
    fun start() {
        if (acceptJob?.isActive == true) return
        if (socketFile.exists()) {
            socketFile.delete()
        }
        val baseSocket = LocalSocket()
        try {
            baseSocket.bind(
                LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM)
            )
            // 0600 (384 decimal) - чтение и запись только для своего UID
            Os.chmod(socketFile.absolutePath, 384)
            val server = LocalServerSocket(baseSocket.fileDescriptor)
            boundSocket = baseSocket
            localServerSocket = server
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            serverScope = scope
            acceptJob = scope.launch {
                runAcceptLoop(server)
            }
            Log.i(TAG, "ProtectSocketServer listening on ${socketFile.absolutePath}")
        } catch (e: Exception) {
            try { baseSocket.close() } catch (_: Exception) {}
            throw IllegalStateException("Failed to bind ProtectSocketServer on ${socketFile.absolutePath}", e)
        }
    }

    @Synchronized
    fun stop() {
        acceptJob?.cancel()
        acceptJob = null
        try { localServerSocket?.close() } catch (_: Exception) {}
        localServerSocket = null
        try { boundSocket?.close() } catch (_: Exception) {}
        boundSocket = null
        serverScope?.cancel()
        serverScope = null
        if (socketFile.exists()) {
            socketFile.delete()
        }
        Log.i(TAG, "ProtectSocketServer stopped")
    }

    private suspend fun CoroutineScope.runAcceptLoop(server: LocalServerSocket) {
        while (isActive) {
            val client = try {
                server.accept()
            } catch (e: IOException) {
                if (isActive) Log.w(TAG, "Accept interrupted on ProtectSocketServer", e)
                break
            }
            launch {
                handleClient(client)
            }
        }
    }

    private fun handleClient(client: LocalSocket) {
        client.use { localSocket ->
            try {
                // Проверка SO_PEERCRED: только наш собственный UID
                val creds = localSocket.peerCredentials
                if (creds.uid != Process.myUid()) {
                    Log.e(TAG, "Rejected unauthorized UID=${creds.uid} on protect socket")
                    return
                }
                val input = localSocket.inputStream
                val output = localSocket.outputStream

                // Чтение 1 байта синхронно распаковывает SCM_RIGHTS в LocalSocket
                val marker = input.read()
                if (marker == -1) return

                val fds: Array<FileDescriptor>? = localSocket.ancillaryFileDescriptors
                if (fds.isNullOrEmpty()) {
                    output.write(0)
                    output.flush()
                    return
                }

                var allProtected = true
                for (fd in fds) {
                    ParcelFileDescriptor.dup(fd).use { pfd ->
                        val isProtected = vpnService.protect(pfd.fd)
                        if (isProtected) {
                            underlyingNetworkProvider()?.let { physicalNet ->
                                try {
                                    physicalNet.bindSocket(pfd.fileDescriptor)
                                } catch (bindEx: Exception) {
                                    Log.w(TAG, "Optional physical network bind failed, relying on protect()", bindEx)
                                }
                            }
                        } else {
                            Log.e(TAG, "VpnService.protect(fd=${pfd.fd}) returned false!")
                            allProtected = false
                        }
                    }
                    try { Os.close(fd) } catch (_: Exception) {}
                }

                output.write(if (allProtected) 1 else 0)
                output.flush()
            } catch (e: Exception) {
                Log.e(TAG, "Error handling protect request", e)
            }
        }
    }
}
