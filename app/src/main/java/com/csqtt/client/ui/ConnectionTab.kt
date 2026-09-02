// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.Intent
import android.net.VpnService
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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
import com.csqtt.client.TunnelService
import com.csqtt.client.VkHashValidationCodec
import com.csqtt.client.newTunnelSessionId
import com.csqtt.client.resolveConnectionSource
import com.csqtt.client.showRaisedToast
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.utils.parseCsqttLink
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.Locale

@Composable
internal fun ConnectionTab(
    settingsStore: SettingsStore,
    tunnelAuthSettings: TunnelAuthSnapshot,
    onInvalidConfiguration: () -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val connectionPassword = tunnelAuthSettings.connectionPassword
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val tunnelStarting by TunnelManager.starting.collectAsStateWithLifecycle()
    val tunnelStopping by TunnelManager.stopping.collectAsStateWithLifecycle()
    val autoPausedForWifi by TunnelManager.autoPausedForWifi.collectAsStateWithLifecycle()
    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()

    val csqttLinkMode by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val csqttLink by settingsStore.csqttLink.collectAsStateWithLifecycle(initialValue = "")
    val peer by settingsStore.peer.collectAsStateWithLifecycle(initialValue = "")
    val vkHashes by settingsStore.vkHashes.collectAsStateWithLifecycle(initialValue = "")
    val vkHashCheckResultsJson by settingsStore.vkHashCheckResults.collectAsStateWithLifecycle(initialValue = "{}")
    val workersPerHash by settingsStore.workersPerHash.collectAsStateWithLifecycle(initialValue = 18)
    val sni by settingsStore.sni.collectAsStateWithLifecycle(initialValue = "")
    val obfsMode by settingsStore.obfsMode.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_OBFS_MODE)
    val turnTransport by settingsStore.turnTransport.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT)
    val manualPortsEnabled by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val serverPeerPort by settingsStore.serverPeerPort.collectAsStateWithLifecycle(
        initialValue = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
    )
    val vkAuthMode by settingsStore.vkAuthMode.collectAsStateWithLifecycle(initialValue = CsqttConstants.VkAuth.MODE_CALLS)
    val captchaMode by settingsStore.captchaMode.collectAsStateWithLifecycle(initialValue = "auto")
    val captchaSolveMethod by settingsStore.captchaSolveMethod.collectAsStateWithLifecycle(initialValue = "auto")
    val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT)
    val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_CLIENT_IDS)
    val savedHashMode by settingsStore.vkHashMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkHashMode)
    val savedVkAccessToken by settingsStore.vkAccessToken.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkAccessToken)

    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    val parsedLink = remember(csqttLink) { parseCsqttLink(csqttLink) }
    val linkHashes = parsedLink?.hashes.orEmpty()
    val manualHashes = remember(vkHashes, vkHashCheckResultsJson) {
        VkHashValidationCodec.active(
            vkHashes.split(Regex("[,\\s\\n]+")),
            VkHashValidationCodec.decode(vkHashCheckResultsJson),
        )
    }
    val accountAutoJsMode = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
    val hashSettingsLoaded = savedHashMode != null && savedVkAccessToken != null
    val autoHashMode = accountAutoJsMode || (
        savedHashMode != null && savedHashMode != CsqttConstants.VkAutoHash.MODE_MANUAL
    )
    val vkTokenActive = savedVkAccessToken?.isNotBlank() == true
    val hashesReady = hashSettingsLoaded && when {
        csqttLinkMode && linkHashes.isNotEmpty() -> true
        autoHashMode -> vkTokenActive
        else -> manualHashes.isNotEmpty()
    }
    val peerPortValid = !manualPortsEnabled || serverPeerPort in 1..65535
    val startBlocker = ConnectionStartPolicy.blocker(
        linkMode = csqttLinkMode,
        linkValid = parsedLink != null,
        peerValid = peer.isNotBlank() && !peer.contains(":"),
        peerPortValid = peerPortValid,
        connectionPasswordSet = connectionPassword.isNotBlank(),
        connectionPasswordReadable = tunnelAuthSettings.connectionPasswordState != StoredSecretState.Unreadable,
        hashesReady = hashesReady,
    )
    val isValid = startBlocker == null
    val hashStatus = when {
        csqttLinkMode && linkHashes.isNotEmpty() -> "${linkHashes.size}/${CsqttConstants.Tunnel.MAX_VK_HASHES}"
        autoHashMode && vkTokenActive -> "Авто"
        autoHashMode -> "Токен"
        else -> "${manualHashes.size}/${CsqttConstants.Tunnel.MAX_VK_HASHES}"
    }

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
            val source = resolveConnectionSource(settingsStore) ?: run {
                context.showRaisedToast("Заполните настройки подключения", Toast.LENGTH_SHORT)
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
                    ).show()
                }
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
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
        if (tunnelRunning || tunnelStarting || autoPausedForWifi) {
            context.startService(Intent(context, TunnelService::class.java).apply { action = "STOP" })
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

    CsqttScreen {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(bottom = 16.dp)
                .offset(y = 10.dp),
            contentAlignment = Alignment.Center,
        ) {
            TunnelConnectionPanel(
                tunnelRunning = tunnelRunning,
                tunnelStarting = tunnelStarting,
                tunnelStopping = tunnelStopping,
                autoPausedForWifi = autoPausedForWifi,
                cooldownActive = cooldownActive,
                configurationValid = isValid,
                obfsMode = obfsMode,
                hashStatus = hashStatus,
                workMode = workModeDisplayName(vkAuthMode),
                onToggleTunnel = { toggleTunnel() },
            )
        }
    }
}

@Composable
private fun TunnelConnectionPanel(
    tunnelRunning: Boolean,
    tunnelStarting: Boolean,
    tunnelStopping: Boolean,
    autoPausedForWifi: Boolean,
    cooldownActive: Boolean,
    configurationValid: Boolean,
    obfsMode: String,
    hashStatus: String,
    workMode: String,
    onToggleTunnel: () -> Unit,
) {
    val isStarting = tunnelStarting && !tunnelRunning && !tunnelStopping
    val canToggle = !tunnelStopping && (tunnelRunning || isStarting || autoPausedForWifi || !cooldownActive || !configurationValid)
    val activeVisual = tunnelRunning || isStarting || autoPausedForWifi || tunnelStopping
    val logoScale = if (activeVisual) 1.06f else 0.96f
    val statusColor = when {
        autoPausedForWifi -> MaterialTheme.colorScheme.tertiary
        tunnelStopping -> MaterialTheme.colorScheme.tertiary
        tunnelRunning -> MaterialTheme.colorScheme.primary
        isStarting -> MaterialTheme.colorScheme.primary
        cooldownActive -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val statusText = when {
        autoPausedForWifi -> "Ожидание. Автопауза при Wi-Fi"
        tunnelStopping -> "Ожидание"
        tunnelRunning -> "Подключено"
        isStarting -> "Подключение"
        cooldownActive -> "Ожидание"
        else -> "Отключено"
    }

    AppSectionCard(
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Image(
                painter = painterResource(id = R.drawable.ic_c_logo),
                contentDescription = when {
                    tunnelStopping -> "Ожидание отключения VPN"
                    tunnelRunning || autoPausedForWifi -> "Остановить VPN"
                    else -> "Включить VPN"
                },
                modifier = Modifier
                    .size(172.dp)
                    .clip(CsqttShapes.Pill)
                    .clickable(
                        enabled = canToggle,
                        onClick = onToggleTunnel,
                    )
                    .scale(logoScale),
                colorFilter = if (activeVisual) {
                    null
                } else {
                    ColorFilter.colorMatrix(ColorMatrix().apply { setToSaturation(0f) })
                },
                alpha = when {
                    activeVisual -> 1f
                    canToggle -> 0.66f
                    else -> 0.34f
                },
            )

            Text(
                text = statusText,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
                color = statusColor,
                textAlign = TextAlign.Center,
            )

            TunnelUptimeText(tunnelRunning = tunnelRunning || autoPausedForWifi || tunnelStopping)

            TunnelConnectionStatusPanel(
                obfs = obfsDisplayName(obfsMode),
                hashStatus = hashStatus,
                workMode = workMode,
            )
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
        color = if (tunnelRunning) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.70f)
        },
    )
}

@Composable
private fun TunnelConnectionStatusPanel(
    obfs: String,
    hashStatus: String,
    workMode: String,
) {
    Surface(
        shape = CsqttShapes.Control,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.28f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min)
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ConnectionStatusItem(
                title = "Маскировка",
                value = obfs,
                modifier = Modifier.weight(1f).padding(horizontal = 5.dp, vertical = 8.dp),
            )
            ConnectionStatusDivider()
            ConnectionStatusItem(
                title = "Хеши",
                value = hashStatus,
                modifier = Modifier.weight(1f).padding(horizontal = 5.dp, vertical = 8.dp),
            )
            ConnectionStatusDivider()
            ConnectionStatusItem(
                title = "Режим кредов",
                value = workMode,
                modifier = Modifier.weight(1f).padding(horizontal = 5.dp, vertical = 8.dp),
            )
        }
    }
}

@Composable
private fun ConnectionStatusItem(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.80f),
            textAlign = TextAlign.Center,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun ConnectionStatusDivider() {
    Box(
        modifier = Modifier
            .fillMaxHeight()
            .width(1.dp)
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)),
    )
}

private fun obfsDisplayName(mode: String): String = when (mode) {
    "audio" -> "Простая"
    "video" -> "Средняя"
    else -> mode.ifBlank { "Средняя" }
}

private fun workModeDisplayName(mode: String): String = when (mode) {
    CsqttConstants.VkAuth.MODE_CAPTCHA -> "Капча"
    CsqttConstants.VkAuth.MODE_AUTO_JS -> "Авто ВК"
    else -> "Авто"
}

private fun formatTunnelUptime(seconds: Long?): String {
    val totalSeconds = seconds?.coerceAtLeast(0L) ?: 0L
    val hours = totalSeconds / 3600
    val minutes = (totalSeconds % 3600) / 60
    val sec = totalSeconds % 60
    return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, sec)
}

private fun formatMillis(value: Double): String = when {
    value < 0.05 -> "wall 0 мс"
    value < 10.0 -> String.format(Locale.US, "wall %.1f мс", value)
    else -> String.format(Locale.US, "wall %.0f мс", value)
}

private fun formatRate(value: Double): String = when {
    value < 0.05 -> "0/с"
    value < 10.0 -> String.format(Locale.US, "%.1f/с", value)
    else -> String.format(Locale.US, "%.0f/с", value)
}
