// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import com.csqtt.client.CsqttConstants

class QuickToggleTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()

        stateJob?.cancel()
        stateJob = scope.launch {
            try {
                TunnelManager.running.collect { running ->
                    updateTile(running)
                }
            } catch (e: Exception) {
                Log.e("QuickToggleTile", "Error collecting running state", e)
            }
        }
    }

    override fun onStopListening() {
        stateJob?.cancel()
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        runCatching {
            if (TunnelManager.running.value) {
                val stopIntent = Intent(this, TunnelService::class.java).apply { action = "STOP" }
                startService(stopIntent)
                return
            }

            if (VpnService.prepare(this) != null) {
                this.showRaisedToast("Откройте CSQTT и выдайте VPN-разрешение", Toast.LENGTH_LONG)
                openMainActivity()
                return
            }

            scope.launch {
                try {
                    val intent = buildStartIntent()
                    if (intent == null) {
                        this@QuickToggleTileService.showRaisedToast("Заполните настройки подключения в CSQTT", Toast.LENGTH_LONG)
                        openMainActivity()
                        return@launch
                    }

                    startForegroundService(intent)
                } catch (e: Exception) {
                    Log.e("QuickToggleTile", "Failed to start tunnel via QS tile", e)
                    this@QuickToggleTileService.showRaisedToast("Ошибка запуска: ${e.localizedMessage}", Toast.LENGTH_SHORT)
                }
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Crash prevented in onClick", e)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun buildStartIntent(): Intent? {
        return runCatching {
            val store = SettingsStore(applicationContext)
            val source = resolveConnectionSource(store) ?: return null

            Intent(this, TunnelService::class.java).apply {
                action = "START"
                putExtra("peer", source.peer)
                putExtra("vk_hashes", source.hashes)
                putExtra("vk_hashes_from_link", source.hashesFromLink)
                putExtra("secondary_vk_hash", store.secondaryVkHash.first())
                putExtra("workers_per_hash", store.workersPerHash.first())
                putExtra("port", 0)
                putExtra("sni", store.sni.first())
                putExtra("connection_password", source.password)
                putExtra("protocol", store.protocol.first())
                putExtra("vk_auth_mode", store.vkAuthMode.first())
                putExtra("captcha_mode", store.captchaMode.first())
                putExtra("captcha_solve_method", store.captchaSolveMethod.first())
                putExtra("fingerprint", store.selectedFingerprint.first())
                putExtra("client_ids", store.activeClientIds.first())
                putExtra("obfs_mode", store.obfsMode.first())
                putExtra("turn_transport", store.turnTransport.first())
            }
        }.getOrNull()
    }

    private fun updateTile(running: Boolean) {
        runCatching {
            qsTile?.apply {
                label = CsqttConstants.General.APP_NAME
                icon = Icon.createWithResource(this@QuickToggleTileService, R.drawable.ic_c_logo)
                state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= 29) {
                    subtitle = if (running) "Подключено" else "Отключено"
                }
                updateTile()
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Failed to update QS tile state", e)
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openMainActivity() {
        runCatching {
            val intent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= 34) {
                val pendingIntent = PendingIntent.getActivity(
                    this,
                    100,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                startActivityAndCollapse(pendingIntent)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        }.onFailure { e ->
            Log.e("QuickToggleTile", "Failed to open MainActivity", e)
        }
    }
}

