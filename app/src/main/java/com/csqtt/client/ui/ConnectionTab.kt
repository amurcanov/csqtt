// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.Intent
import android.net.VpnService
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.ConnectionSource
import com.csqtt.client.ConnectionStartBlocker
import com.csqtt.client.ConnectionStartPolicy
import com.csqtt.client.CsqttConstants
import com.csqtt.client.R
import com.csqtt.client.SettingsStore
import com.csqtt.client.StoredSecretState
import com.csqtt.client.TunnelAuthSnapshot
import com.csqtt.client.TunnelManager
import com.csqtt.client.TunnelConnectionPhase
import com.csqtt.client.TunnelService
import com.csqtt.client.VkHashValidationCodec
import com.csqtt.client.newTunnelSessionId
import com.csqtt.client.resolveConnectionSource
import com.csqtt.client.showRaisedToast
import com.csqtt.client.ui.utils.parseCsqttLink
import java.util.Locale
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@Composable
internal fun ConnectionTab(
    settingsStore: SettingsStore,
    tunnelAuthSettings: TunnelAuthSnapshot,
    onInvalidConfiguration: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenDeploy: () -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val connectionPassword = tunnelAuthSettings.connectionPassword
    val connection by TunnelManager.connection.collectAsStateWithLifecycle()
    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()

    val csqttLinkMode by
        settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val csqttLink by settingsStore.csqttLink.collectAsStateWithLifecycle(initialValue = "")
    val peer by settingsStore.peer.collectAsStateWithLifecycle(initialValue = "")
    val vkHashes by settingsStore.vkHashes.collectAsStateWithLifecycle(initialValue = "")
    val vkHashCheckResultsJson by
        settingsStore.vkHashCheckResults.collectAsStateWithLifecycle(initialValue = "{}")
    val workersPerHash by
        settingsStore.workersPerHash.collectAsStateWithLifecycle(initialValue = 18)
    val sni by settingsStore.sni.collectAsStateWithLifecycle(initialValue = "")
    val obfsMode by
        settingsStore.obfsMode.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.Tunnel.DEFAULT_OBFS_MODE
        )
    val turnTransport by
        settingsStore.turnTransport.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT
        )
    val manualPortsEnabled by
        settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val serverPeerPort by
        settingsStore.serverPeerPort.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT
        )
    val vkAuthMode by
        settingsStore.vkAuthMode.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.VkAuth.MODE_CALLS
        )
    val captchaMode by settingsStore.captchaMode.collectAsStateWithLifecycle(initialValue = "auto")
    val captchaSolveMethod by
        settingsStore.captchaSolveMethod.collectAsStateWithLifecycle(initialValue = "auto")
    val activeFingerprint by
        settingsStore.selectedFingerprint.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT
        )
    val activeClientIds by
        settingsStore.activeClientIds.collectAsStateWithLifecycle(
            initialValue = CsqttConstants.Tunnel.DEFAULT_CLIENT_IDS
        )
    val savedHashMode by
        settingsStore.vkHashMode.collectAsStateWithLifecycle(
            initialValue = SettingsStore.cachedVkHashMode
        )
    val savedVkAccessToken by
        settingsStore.vkAccessToken.collectAsStateWithLifecycle(
            initialValue = SettingsStore.cachedVkAccessToken
        )

    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    val parsedLink = remember(csqttLink) { parseCsqttLink(csqttLink) }
    val linkHashes = parsedLink?.hashes.orEmpty()
    val manualHashes =
        remember(vkHashes, vkHashCheckResultsJson) {
            VkHashValidationCodec.active(
                vkHashes.split(Regex("[,\\s\\n]+")),
                VkHashValidationCodec.decode(vkHashCheckResultsJson),
            )
        }
    val accountAutoJsMode = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
    val hashSettingsLoaded = savedHashMode != null && savedVkAccessToken != null
    val autoHashMode =
        accountAutoJsMode ||
            (savedHashMode != null && savedHashMode != CsqttConstants.VkAutoHash.MODE_MANUAL)
    val hashesSummary = when {
        accountAutoJsMode -> "Авто ВК"
        csqttLinkMode && linkHashes.isNotEmpty() ->
            "${linkHashes.size}/${CsqttConstants.Tunnel.MAX_VK_HASHES}"
        savedHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_API -> "Авто API"
        savedHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS -> "Авто ВК"
        else -> "${manualHashes.size}/${CsqttConstants.Tunnel.MAX_VK_HASHES}"
    }
    val vkTokenActive = savedVkAccessToken?.isNotBlank() == true
    val hashesReady =
        hashSettingsLoaded &&
            when {
                csqttLinkMode && linkHashes.isNotEmpty() -> true
                autoHashMode -> vkTokenActive
                else -> manualHashes.isNotEmpty()
            }
    val peerPortValid = !manualPortsEnabled || serverPeerPort in 1..65535
    val startBlocker =
        ConnectionStartPolicy.blocker(
            linkMode = csqttLinkMode,
            linkValid = parsedLink != null,
            peerValid = peer.isNotBlank() && !peer.contains(":"),
            peerPortValid = peerPortValid,
            connectionPasswordSet = connectionPassword.isNotBlank(),
            connectionPasswordReadable =
                tunnelAuthSettings.connectionPasswordState != StoredSecretState.Unreadable,
            hashesReady = hashesReady,
        )
    val isValid = startBlocker == null

    fun startIntent(source: ConnectionSource, generationId: Long, salt: String): Intent =
        Intent(context, TunnelService::class.java).apply {
            action = "START"
            putExtra("peer", source.peer)
            putExtra("vk_hashes", source.hashes)
            putExtra("vk_hashes_from_link", source.hashesFromLink)
            putExtra("secondary_vk_hash", "")
            putExtra("workers_per_hash", workersPerHash)
            putExtra("port", 0)
            putExtra("sni", sni)
            putExtra("connection_password", source.password)
            putExtra("vk_auth_mode", vkAuthMode)
            putExtra("captcha_mode", captchaMode)
            putExtra("captcha_solve_method", captchaSolveMethod)
            putExtra("fingerprint", activeFingerprint)
            putExtra("client_ids", activeClientIds)
            putExtra("obfs_mode", obfsMode)
            putExtra("turn_transport", turnTransport)
            putExtra("generation_id", generationId)
            putExtra("session_salt", salt)
        }

    fun startTunnelService() {
        scope.launch {
            val source =
                resolveConnectionSource(settingsStore)
                    ?: run {
                        context.showRaisedToast(
                            "Заполните настройки подключения",
                            Toast.LENGTH_SHORT,
                        )
                        return@launch
                    }
            TunnelManager.isLoggingEnabled = settingsStore.loggingEnabled.first()
            val nextGen = System.currentTimeMillis() / 1000L
            val salt = newTunnelSessionId()
            val intent = startIntent(source, nextGen, salt)
            runCatching { context.startForegroundService(intent) }
                .onFailure { error ->
                    TunnelManager.updateLog(
                        "foreground_request_error",
                        "Android заблокировал запуск VPN: ${error.message ?: error.javaClass.simpleName}",
                        99,
                        true,
                    )
                    Toast.makeText(
                            context,
                            "Android заблокировал запуск VPN. Проверьте ограничения батареи приложения.",
                            Toast.LENGTH_LONG,
                        )
                        .show()
                }
        }
    }

    val vpnPermissionLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (pendingStartAfterVpnPermission) {
                pendingStartAfterVpnPermission = false
                if (VpnService.prepare(context) == null) {
                    startTunnelService()
                } else {
                    context.showRaisedToast("VPN-разрешение не выдано", Toast.LENGTH_SHORT)
                }
            }
        }

    fun toggleTunnel() {
        if (connection.canStop) {
            context.startService(
                Intent(context, TunnelService::class.java).apply { action = "STOP" }
            )
            return
        }
        if (!isValid) {
            val blocker = requireNotNull(startBlocker)
            TunnelManager.updateLog(
                "connection_configuration_${blocker.name}",
                "[ПОДКЛЮЧЕНИЕ] Запуск не начат: ${blocker.message}",
                99,
                true,
            )
            if (blocker == ConnectionStartBlocker.StoredSecret) {
                scope.launch {
                    val reset = settingsStore.resetUnreadableConnectionPassword()
                    if (reset) {
                        context.showRaisedToast(
                            "Сохранённый пароль сброшен. Введите его заново в разделе «Авторизация».",
                            Toast.LENGTH_LONG,
                        )
                    }
                    onInvalidConfiguration()
                }
                return
            }
            onInvalidConfiguration()
            return
        }
        val vpnIntent = VpnService.prepare(context)
        if (vpnIntent != null) {
            pendingStartAfterVpnPermission = true
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startTunnelService()
        }
    }

    val tunnelStopping = connection.phase == TunnelConnectionPhase.Stopping
    val statusText = if (!connection.engaged && cooldownActive) "Ожидание" else connection.phase.label
    val isStarting = connection.phase == TunnelConnectionPhase.Connecting ||
        connection.phase == TunnelConnectionPhase.Reconnecting
    val canToggle =
        !tunnelStopping &&
            (connection.canStop || !cooldownActive || !isValid)
    val activeVisual = connection.engaged
    val density = LocalDensity.current

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val dashboardScale = (maxHeight.value / 640f).coerceIn(0.75f, 1.12f)
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp).fadingVerticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                IconButton(onClick = onOpenSettings, modifier = Modifier.size(48.dp)) {
                    Icon(
                        painterResource(R.drawable.ic_settings),
                        "Настройки туннеля",
                        tint = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.size(28.dp),
                    )
                }
                if (!csqttLinkMode) {
                    IconButton(onClick = onOpenDeploy, modifier = Modifier.size(48.dp)) {
                        Icon(
                            Icons.Filled.CloudUpload,
                            "Установка на сервер",
                            tint = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.size(28.dp),
                        )
                    }
                }
            }
            Spacer(Modifier.height(48.dp))
            CompositionLocalProvider(
                LocalDensity provides Density(density.density, density.fontScale * dashboardScale)
            ) {
                AuroraPowerButton(
                    tunnelRunning = activeVisual,
                    connecting = isStarting || tunnelStopping,
                    tunnelVerified = connection.connected,
                    enabled = canToggle,
                    dashboardScale = dashboardScale,
                    onToggle = ::toggleTunnel,
                )
                Spacer(Modifier.height(18.dp * dashboardScale))
                Text(
                    statusText,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    color =
                        if (connection.connected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp * dashboardScale))
                TunnelUptimeText(
                    tunnelRunning = connection.engaged
                )
                Spacer(Modifier.height(10.dp * dashboardScale))
                AuroraStatusCard(
                    peer =
                        (if (csqttLinkMode) parsedLink?.host else peer).orEmpty().ifBlank {
                            "Не указан"
                        },
                    workers = workersPerHash.toString(),
                    hashes = hashesSummary,
                    transport =
                        if (turnTransport == CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS) "TCP"
                        else "UDP",
                    tunnelRunning = activeVisual,
                    tunnelVerified = connection.connected,
                    dashboardScale = dashboardScale,
                )
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun TunnelUptimeText(tunnelRunning: Boolean) {
    val uptimeSeconds by TunnelManager.uptimeSeconds.collectAsStateWithLifecycle()
    Text(
        text = formatTunnelUptime(uptimeSeconds),
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.SemiBold,
        color =
            if (tunnelRunning) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.70f)
            },
    )
}

private fun formatTunnelUptime(seconds: Long?): String {
    val totalSeconds = seconds?.coerceAtLeast(0L) ?: 0L
    val hours = totalSeconds / 3600
    val minutes = (totalSeconds % 3600) / 60
    val sec = totalSeconds % 60
    return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, sec)
}
