// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class TunnelConnectionPhase(val label: String) {
    Disconnected("Отключено"),
    Connecting("Подключение"),
    Connected("Подключено"),
    Reconnecting("Переподключение"),
    WaitingForNetwork("Ожидание сети"),
    PausedForWifi("Ожидание. Автопауза при Wi-Fi"),
    Stopping("Отключение"),
}

internal enum class TunnelConnectionMode { Stopped, Requested, WifiPaused, Stopping }

internal data class TunnelVpnRequest(val processGeneration: Long, val sequence: Long)

internal data class TunnelConnectionSnapshot(
    val mode: TunnelConnectionMode = TunnelConnectionMode.Stopped,
    val processGeneration: Long? = null,
    val serverConfigured: Boolean = false,
    val transportReady: Boolean = false,
    val vpnRequest: TunnelVpnRequest? = null,
    val vpnReady: Boolean = false,
    val networkPaused: Boolean = false,
    val hasConnected: Boolean = false,
) {
    val phase: TunnelConnectionPhase
        get() = when {
            mode == TunnelConnectionMode.Stopped -> TunnelConnectionPhase.Disconnected
            mode == TunnelConnectionMode.Stopping -> TunnelConnectionPhase.Stopping
            mode == TunnelConnectionMode.WifiPaused -> TunnelConnectionPhase.PausedForWifi
            networkPaused -> TunnelConnectionPhase.WaitingForNetwork
            processGeneration != null && serverConfigured && transportReady && vpnReady ->
                TunnelConnectionPhase.Connected
            hasConnected -> TunnelConnectionPhase.Reconnecting
            else -> TunnelConnectionPhase.Connecting
        }

    val connected: Boolean get() = phase == TunnelConnectionPhase.Connected
    val engaged: Boolean get() = mode != TunnelConnectionMode.Stopped
    val canStop: Boolean
        get() = mode == TunnelConnectionMode.Requested || mode == TunnelConnectionMode.WifiPaused
}

internal class TunnelConnectionState {
    private val mutableState = MutableStateFlow(TunnelConnectionSnapshot())
    val state = mutableState.asStateFlow()
    private var vpnSequence = 0L

    @Synchronized
    fun prepare() {
        if (state.value.mode != TunnelConnectionMode.Requested) {
            publish(TunnelConnectionSnapshot(mode = TunnelConnectionMode.Requested))
        }
    }

    @Synchronized
    fun processStarted(generation: Long) {
        if (state.value.mode != TunnelConnectionMode.Requested) return
        publish(
            state.value.copy(
                processGeneration = generation,
                serverConfigured = false,
                transportReady = false,
                vpnRequest = null,
                vpnReady = false,
            ),
        )
    }

    @Synchronized
    fun processEnded(generation: Long) {
        updateProcess(generation) {
            copy(
                processGeneration = null,
                serverConfigured = false,
                transportReady = false,
                vpnRequest = null,
                vpnReady = false,
            )
        }
    }

    @Synchronized
    fun configured(generation: Long) = updateProcess(generation) { copy(serverConfigured = true) }

    @Synchronized
    fun transportChanged(generation: Long, ready: Boolean) = updateProcess(generation) {
        copy(transportReady = ready && !networkPaused)
    }

    @Synchronized
    fun requestVpn(generation: Long): TunnelVpnRequest? {
        if (!acceptsProcess(generation)) return null
        vpnSequence = if (vpnSequence == Long.MAX_VALUE) 1L else vpnSequence + 1
        val request = TunnelVpnRequest(generation, vpnSequence)
        publish(state.value.copy(vpnRequest = request, vpnReady = false))
        return request
    }

    @Synchronized
    fun acceptsVpn(request: TunnelVpnRequest): Boolean =
        acceptsProcess(request.processGeneration) && state.value.vpnRequest == request

    @Synchronized
    fun vpnReady(request: TunnelVpnRequest): Boolean {
        if (!acceptsVpn(request)) return false
        publish(state.value.copy(vpnReady = true))
        return true
    }

    @Synchronized
    fun vpnStopped(request: TunnelVpnRequest): Boolean {
        if (!acceptsVpn(request)) return false
        publish(state.value.copy(vpnReady = false))
        return true
    }

    @Synchronized
    fun vpnFailed(request: TunnelVpnRequest): Boolean {
        if (!acceptsVpn(request)) return false
        requestStop()
        return true
    }

    @Synchronized
    fun processFailed(generation: Long): Boolean {
        if (!acceptsProcess(generation)) return false
        requestStop()
        return true
    }

    @Synchronized
    fun networkPaused(paused: Boolean) {
        if (state.value.mode != TunnelConnectionMode.Requested) return
        publish(state.value.copy(networkPaused = paused, transportReady = false))
    }

    @Synchronized
    fun requestStop() {
        publish(TunnelConnectionSnapshot(mode = TunnelConnectionMode.Stopping))
    }

    @Synchronized
    fun stopped(pauseForWifi: Boolean = false) {
        val mode = if (pauseForWifi) TunnelConnectionMode.WifiPaused else TunnelConnectionMode.Stopped
        publish(TunnelConnectionSnapshot(mode = mode))
    }

    private fun acceptsProcess(generation: Long): Boolean =
        state.value.mode == TunnelConnectionMode.Requested && state.value.processGeneration == generation

    private fun updateProcess(generation: Long, update: TunnelConnectionSnapshot.() -> TunnelConnectionSnapshot) {
        if (acceptsProcess(generation)) publish(state.value.update())
    }

    private fun publish(snapshot: TunnelConnectionSnapshot) {
        mutableState.value = if (snapshot.connected) snapshot.copy(hasConnected = true) else snapshot
    }
}
