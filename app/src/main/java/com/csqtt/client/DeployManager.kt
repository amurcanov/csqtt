// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DeployManager {
    private val exceptionHandler = CoroutineExceptionHandler { _, throwable ->
        val message = throwable.message?.take(160) ?: throwable.javaClass.simpleName
        writeError(
            "Uncaught deploy coroutine error: $message\n" +
                throwable.stackTraceToString().take(1200)
        )
        TunnelManager.addDeployErrorLog("Необработанная ошибка установки: $message")
        stopDeploy("Ошибка установки: $message")
    }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + exceptionHandler)

    val isDeploying = MutableStateFlow(false)
    val deployProgress = MutableStateFlow(0f)
    val currentStep = MutableStateFlow("")
    val lastResult = MutableStateFlow("") 

    @Volatile
    var activeSession: java.io.Closeable? = null
    private var deployStartTime = 0L
    private var errorsFile: File? = null

    fun init(context: Context) {
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        errorsFile = File(dir, "errors.log")
    }

    @Synchronized
    fun writeError(msg: String) {
        val file = errorsFile ?: return
        try {
            val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
            file.appendText("[$timestamp] $msg\n")

            if (file.length() > 500_000) {
                val text = file.readText()
                file.writeText(text.takeLast(200_000))
            }
        } catch (_: Exception) { }
    }

    fun startDeploy() {
        if (isDeploying.value && deployStartTime > 0 &&
            System.currentTimeMillis() - deployStartTime > 30 * 60 * 1000) {
            writeError("Автосброс: предыдущий деплой завис >30 мин")
            forceReset()
        }
        TunnelManager.clearLogs()
        isDeploying.value = true
        deployStartTime = System.currentTimeMillis()
        deployProgress.value = 0f
        currentStep.value = "Инициализация..."
        lastResult.value = ""
    }

    fun stopDeploy(result: String = "") {
        isDeploying.value = false
        deployStartTime = 0L
        if (result.isNotBlank()) lastResult.value = result
        val session = activeSession
        activeSession = null
        try { session?.close() } catch (_: Exception) {}
    }

    fun forceReset() {
        val session = activeSession
        activeSession = null
        try { session?.close() } catch (_: Exception) {}
        isDeploying.value = false
        deployStartTime = 0L
        deployProgress.value = 0f
        currentStep.value = ""
    }

    fun updateProgress(progress: Float, step: String) {
        deployProgress.value = progress
        currentStep.value = step
    }
}
