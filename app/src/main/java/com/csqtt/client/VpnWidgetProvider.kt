// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log
import android.widget.RemoteViews
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class VpnWidgetProvider : AppWidgetProvider() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    companion object {
        const val ACTION_WIDGET_TOGGLE = CsqttConstants.Widget.ACTION_TOGGLE

        fun updateAllWidgets(context: Context) {
            runCatching {
                val appWidgetManager = AppWidgetManager.getInstance(context)
                val thisWidget = ComponentName(context, VpnWidgetProvider::class.java)
                val appWidgetIds = appWidgetManager.getAppWidgetIds(thisWidget)
                if (appWidgetIds.isNotEmpty()) {
                    val intent = Intent(context, VpnWidgetProvider::class.java).apply {
                        action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
                        putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, appWidgetIds)
                    }
                    context.sendBroadcast(intent)
                }
            }
        }
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        val running = TunnelManager.running.value
        for (appWidgetId in appWidgetIds) {
            updateWidgetState(context, appWidgetManager, appWidgetId, running)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == ACTION_WIDGET_TOGGLE) {
            runCatching {
                if (TunnelManager.running.value) {
                    val stopIntent = Intent(context, TunnelService::class.java).apply { action = "STOP" }
                    context.startService(stopIntent)
                    updateAllWidgets(context)
                    return
                }

                if (VpnService.prepare(context) != null) {
                    context.showRaisedToast("Откройте CSQTT и выдайте VPN-разрешение", Toast.LENGTH_LONG)
                    openMainActivity(context)
                    return
                }

                scope.launch {
                    try {
                        val startIntent = buildStartIntent(context)
                        if (startIntent == null) {
                            context.showRaisedToast("Заполните настройки подключения в CSQTT", Toast.LENGTH_LONG)
                            openMainActivity(context)
                            return@launch
                        }

                        context.startForegroundService(startIntent)
                    } catch (e: Exception) {
                        Log.e("VpnWidget", "Failed to start tunnel from widget", e)
                        context.showRaisedToast("Ошибка запуска: ${e.localizedMessage}", Toast.LENGTH_SHORT)
                    }
                }
            }.onFailure { e ->
                Log.e("VpnWidget", "Error handling widget click", e)
            }
        }
    }

    private fun updateWidgetState(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int,
        running: Boolean
    ) {
        val views = RemoteViews(context.packageName, R.layout.vpn_widget)

        if (running) {
            views.setTextViewText(R.id.widget_status, "Подключено")
            views.setTextColor(R.id.widget_status, 0xFF00E5FF.toInt()) 
            views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.bg_widget_button_active)
        } else {
            views.setTextViewText(R.id.widget_status, "Отключено")
            views.setTextColor(R.id.widget_status, 0xFF888888.toInt()) 
            views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.bg_widget_button_inactive)
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val openPendingIntent = PendingIntent.getActivity(
            context,
            appWidgetId,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        views.setOnClickPendingIntent(R.id.widget_container, openPendingIntent)

        val toggleIntent = Intent(context, VpnWidgetProvider::class.java).apply {
            action = ACTION_WIDGET_TOGGLE
        }
        val togglePendingIntent = PendingIntent.getBroadcast(
            context,
            appWidgetId + 1000,
            toggleIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        views.setOnClickPendingIntent(R.id.widget_toggle_btn, togglePendingIntent)

        appWidgetManager.updateAppWidget(appWidgetId, views)
    }

    private suspend fun buildStartIntent(context: Context): Intent? {
        val store = SettingsStore(context.applicationContext)
        val source = resolveConnectionSource(store) ?: return null

        return Intent(context, TunnelService::class.java).apply {
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
    }

    private fun openMainActivity(context: Context) {
        val intent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching {
            val pendingIntent = PendingIntent.getActivity(
                context,
                200,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            pendingIntent.send()
        }.onFailure {
            context.startActivity(intent)
        }
    }
}

