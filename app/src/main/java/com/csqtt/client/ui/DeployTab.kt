// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import com.csqtt.client.showRaisedToast
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.core.net.toUri
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import com.csqtt.client.TunnelService
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.DeployManager
import com.csqtt.client.DeploySettingsSnapshot
import com.csqtt.client.SettingsStore
import com.csqtt.client.TunnelManager
import com.csqtt.client.CsqttConstants
import com.csqtt.client.ui.dialogs.DeploySecretsDialog
import com.csqtt.client.ui.dialogs.SshKeysDialog
import com.csqtt.client.ui.dialogs.UninstallConfirmDialog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Immutable
internal data class DeployUiState(
    val host: String = "",
    val sshLogin: String = "root",
    val sshPassword: String = "",
    val sudoPassword: String = "",
    val manualPorts: Boolean = false,
    val sshPort: String = CsqttConstants.Network.DEFAULT_SSH_PORT.toString(),
    val peerPort: String = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString(),
    val webPort: String = CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT.toString(),
    val mainPasswordConfigured: Boolean = false,
    val webPanelConfigured: Boolean = false,
    val sshKeysMode: Boolean = false,
    val dockerInstall: Boolean = false,
    val sshKeysFilled: Int = 0,
    val isDeploying: Boolean = false,
    val progress: Float = 0f,
    val currentStep: String = "",
    val showValidation: Boolean = false,
) {
    val portsValid: Boolean
        get() = !manualPorts || listOf(sshPort, peerPort, webPort).all(::isValidPort)

    val authorizationConfigured: Boolean
        get() = mainPasswordConfigured && webPanelConfigured

    val sshAuthReady: Boolean
        get() = sshLogin.isNotBlank() && if (sshKeysMode) sshKeysFilled == 1 else sshPassword.isNotBlank()

    val showSudoPassword: Boolean
        get() = sshLogin != "root"

    val canInstall: Boolean
        get() = host.isNotBlank() && sshAuthReady && authorizationConfigured && portsValid

    val canUninstall: Boolean
        get() = host.isNotBlank() && sshAuthReady && portsValid
}

internal sealed interface DeployAction {
    data class HostChanged(val value: String) : DeployAction
    data class LoginChanged(val value: String) : DeployAction
    data class PasswordChanged(val value: String) : DeployAction
    data class SudoPasswordChanged(val value: String) : DeployAction
    data class ManualPortsChanged(val enabled: Boolean) : DeployAction
    data class SshKeysModeChanged(val enabled: Boolean) : DeployAction
    data class DockerInstallChanged(val enabled: Boolean) : DeployAction
    data object EditSshKeys : DeployAction
    data object DockerInfo : DeployAction
    data class SshPortChanged(val value: String) : DeployAction
    data class PeerPortChanged(val value: String) : DeployAction
    data class WebPortChanged(val value: String) : DeployAction
    data object EditAuthorization : DeployAction
    data object Install : DeployAction
    data object Uninstall : DeployAction
    data object OpenControlPanel : DeployAction
    data object PanelInfo : DeployAction
}

internal fun passwordToSynchronizeAfterDeploy(deploySucceeded: Boolean, mainPassword: String): String? =
    mainPassword.takeIf { deploySucceeded && it.isNotBlank() }

internal fun isValidPort(value: String): Boolean = value.toIntOrNull() in 1..65535

@Immutable
internal data class EffectiveServerPorts(
    val ssh: Int,
    val peer: Int,
    val web: Int,
)

internal fun resolveServerPorts(
    manualPorts: Boolean,
    sshPort: String,
    peerPort: String,
    webPort: String,
): EffectiveServerPorts {
    if (!manualPorts) {
        return EffectiveServerPorts(
            ssh = CsqttConstants.Network.DEFAULT_SSH_PORT,
            peer = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
            web = CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT,
        )
    }
    return EffectiveServerPorts(
        ssh = sshPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: CsqttConstants.Network.DEFAULT_SSH_PORT,
        peer = peerPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
        web = webPort.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT,
    )
}

internal fun hasWebPanelCredentials(login: String, password: String): Boolean =
    login.isNotBlank() && password.isNotBlank()

private fun showDeployToast(context: android.content.Context, message: String) {
    Handler(Looper.getMainLooper()).post {
        context.showRaisedToast(message, Toast.LENGTH_LONG)
    }
}

@Composable
internal fun DeployTab(
    settingsStore: SettingsStore,
    savedSettings: DeploySettingsSnapshot,
) {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) { DeployManager.init(context) }

    if (!savedSettings.isLoaded) return

    val savedIp = savedSettings.ip
    val savedLogin = savedSettings.sshLogin.ifBlank { "root" }
    val savedPassword = savedSettings.sshPassword
    val savedSudoPassword = savedSettings.sudoPassword
    val savedWebLogin = savedSettings.webLogin
    val savedWebPassword = savedSettings.webPassword
    val savedMainPass = savedSettings.mainPassword
    val savedSshPort = savedSettings.sshPort
    val savedManualPorts = savedSettings.manualPortsEnabled
    val savedSshKeysMode = savedSettings.sshKeysMode
    val savedDockerInstall = savedSettings.dockerInstall
    val savedSshPrivateKey = savedSettings.sshPrivateKey
    val savedSshKeyPassphrase = savedSettings.sshKeyPassphrase
    val savedSshCertificate = savedSettings.sshCertificate
    val savedServerPeerPort = savedSettings.serverPeerPort
    val savedServerWebPort = savedSettings.serverWebPort
    val isDeploying by DeployManager.isDeploying.collectAsStateWithLifecycle()
    val deployProgress by DeployManager.deployProgress.collectAsStateWithLifecycle()
    val currentStep by DeployManager.currentStep.collectAsStateWithLifecycle()

    var host by rememberSaveable(savedSettings.profile) { mutableStateOf(savedIp) }
    var sshLogin by rememberSaveable(savedSettings.profile) { mutableStateOf(savedLogin) }
    var sshPassword by rememberSaveable(savedSettings.profile) { mutableStateOf(savedPassword) }
    var sudoPassword by rememberSaveable(savedSettings.profile) { mutableStateOf(savedSudoPassword) }
    var sshPort by rememberSaveable(savedSettings.profile) {
        mutableStateOf(savedSshPort.ifBlank { CsqttConstants.Network.DEFAULT_SSH_PORT.toString() })
    }
    var peerPort by rememberSaveable(savedSettings.profile) { mutableStateOf(savedServerPeerPort.toString()) }
    var webPort by rememberSaveable(savedSettings.profile) { mutableStateOf(savedServerWebPort.toString()) }
    var dockerInstall by rememberSaveable(savedSettings.profile) { mutableStateOf(savedDockerInstall) }
    var generalEdited by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var credentialsEdited by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var sudoPasswordEdited by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var portsEdited by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showValidation by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showSecretsDialog by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showUninstallDialog by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showPanelInfoDialog by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showSshKeysDialog by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }
    var showDockerInfoDialog by rememberSaveable(savedSettings.profile) { mutableStateOf(false) }

    LaunchedEffect(savedSettings.profile, savedIp) {
        if (!generalEdited) {
            host = savedIp
        }
    }
    LaunchedEffect(savedSettings.profile, savedLogin, savedPassword) {
        if (!credentialsEdited) {
            sshLogin = savedLogin
            sshPassword = savedPassword
        }
    }
    LaunchedEffect(savedSettings.profile, savedSudoPassword) {
        if (!sudoPasswordEdited) sudoPassword = savedSudoPassword
    }
    LaunchedEffect(savedSettings.profile, savedSshPort, savedServerPeerPort, savedServerWebPort) {
        if (!portsEdited) {
            sshPort = savedSshPort.ifBlank { CsqttConstants.Network.DEFAULT_SSH_PORT.toString() }
            peerPort = savedServerPeerPort.toString()
            webPort = savedServerWebPort.toString()
        }
    }
    LaunchedEffect(savedSettings.profile, savedDockerInstall) {
        dockerInstall = savedDockerInstall
    }

    LaunchedEffect(savedSettings.profile, host, generalEdited) {
        if (!generalEdited) return@LaunchedEffect
        kotlinx.coroutines.delay(450)
        settingsStore.saveDeploy(host)
    }
    LaunchedEffect(savedSettings.profile, sshLogin, sshPassword, credentialsEdited, savedMainPass, savedWebLogin, savedWebPassword) {
        if (!credentialsEdited) return@LaunchedEffect
        kotlinx.coroutines.delay(450)
        settingsStore.saveDeploySecrets(savedMainPass, sshLogin, sshPassword, savedWebLogin, savedWebPassword)
    }
    LaunchedEffect(savedSettings.profile, sudoPassword, sudoPasswordEdited) {
        if (!sudoPasswordEdited) return@LaunchedEffect
        kotlinx.coroutines.delay(450)
        settingsStore.saveDeploySudoPassword(sudoPassword)
    }
    LaunchedEffect(savedSettings.profile, sshPort, peerPort, webPort, portsEdited) {
        if (!portsEdited) return@LaunchedEffect
        kotlinx.coroutines.delay(450)
        val ssh = sshPort.toIntOrNull()
        val peer = peerPort.toIntOrNull()
        val web = webPort.toIntOrNull()
        if (ssh in 1..65535 && peer in 1..65535 && web in 1..65535) {
            settingsStore.savePorts(peer!!, web!!, ssh.toString())
        }
    }

    val state = DeployUiState(
        host = host,
        sshLogin = sshLogin,
        sshPassword = sshPassword,
        sudoPassword = sudoPassword,
        manualPorts = savedManualPorts,
        sshPort = sshPort,
        peerPort = peerPort,
        webPort = webPort,
        mainPasswordConfigured = savedMainPass.isNotBlank(),
        webPanelConfigured = hasWebPanelCredentials(savedWebLogin, savedWebPassword),
        sshKeysMode = savedSshKeysMode,
        dockerInstall = dockerInstall,
        sshKeysFilled = if (savedSshPrivateKey.isNotBlank()) 1 else 0,
        isDeploying = isDeploying,
        progress = deployProgress,
        currentStep = currentStep,
        showValidation = showValidation,
    )

    fun startDeploy() {
        if (DeployManager.isDeploying.value) return
        val ports = resolveServerPorts(savedManualPorts, sshPort, peerPort, webPort)
        val effectiveSshPort = ports.ssh
        val effectivePeerPort = ports.peer
        val effectiveWebPort = ports.web
        val deployPrivateKey = if (savedSshKeysMode) savedSshPrivateKey else ""
        val deployKeyPassphrase = if (savedSshKeysMode) savedSshKeyPassphrase else ""
        val deployCertificate = if (savedSshKeysMode) savedSshCertificate else ""
        scope.launch {
            settingsStore.saveDeploy(host)
            settingsStore.saveDeploySecrets(savedMainPass, sshLogin, sshPassword, savedWebLogin, savedWebPassword)
            settingsStore.saveDeploySudoPassword(sudoPassword)
            settingsStore.savePorts(effectivePeerPort, effectiveWebPort, effectiveSshPort.toString())
        }
        DeployManager.startDeploy()
        DeployManager.scope.launch {
            try {
                context.startForegroundService(Intent(context, TunnelService::class.java).apply { action = "DEPLOY_START" })
                val success = performDeploy(
                    context = context,
                    host = host,
                    user = sshLogin,
                    pass = sshPassword,
                    sudoPass = if (state.showSudoPassword) sudoPassword else "",
                    port = effectiveSshPort,
                    mainPass = savedMainPass,
                    webLogin = savedWebLogin,
                    webPass = savedWebPassword,
                    peerPort = effectivePeerPort,
                    webPort = effectiveWebPort,
                    onProgress = DeployManager::updateProgress,
                    privateKey = deployPrivateKey,
                    keyPassphrase = deployKeyPassphrase,
                    certificate = deployCertificate,
                    installInDocker = dockerInstall,
                )
                if (success) {
                    passwordToSynchronizeAfterDeploy(success, savedMainPass)?.let { mainPassword ->
                        settingsStore.saveConnectionPassword(mainPassword)
                        TunnelManager.addDeployInfoLog("Пароль подключения синхронизирован с паролем сервера")
                    }
                    showDeployToast(context, "Установка успешно завершена")
                } else {
                    val message = DeployManager.lastResult.value.ifBlank { "Ошибка установки" }
                    scope.launch { snackbarHostState.showSnackbar(message) }
                }
            } catch (e: CancellationException) {
                DeployManager.stopDeploy("Установка отменена")
                throw e
            } catch (e: Exception) {
                val message = friendlyDeployError(e.message)
                DeployManager.writeError(
                    "Deploy UI error (${e.javaClass.simpleName}): ${e.message}\n" +
                        e.stackTraceToString().take(1200)
                )
                TunnelManager.addDeployErrorLog(message)
                DeployManager.stopDeploy(message)
                scope.launch { snackbarHostState.showSnackbar(message) }
            } finally {
                runCatching {
                    context.startService(Intent(context, TunnelService::class.java).apply { action = "DEPLOY_STOP" })
                }.onFailure { DeployManager.writeError("Не удалось остановить foreground-режим деплоя: ${it.message}") }
            }
        }
    }

    fun startUninstall() {
        if (DeployManager.isDeploying.value) return
        val ports = resolveServerPorts(savedManualPorts, sshPort, peerPort, webPort)
        val effectiveSshPort = ports.ssh
        val effectivePeerPort = ports.peer
        val uninstallPrivateKey = if (savedSshKeysMode) savedSshPrivateKey else ""
        val uninstallKeyPassphrase = if (savedSshKeysMode) savedSshKeyPassphrase else ""
        val uninstallCertificate = if (savedSshKeysMode) savedSshCertificate else ""
        DeployManager.startDeploy()
        DeployManager.scope.launch {
            try {
                context.startForegroundService(Intent(context, TunnelService::class.java).apply { action = "DEPLOY_START" })
                val success = performUninstall(
                    context = context,
                    host = host,
                    user = sshLogin,
                    pass = sshPassword,
                    sudoPass = if (state.showSudoPassword) sudoPassword else "",
                    port = effectiveSshPort,
                    peerPort = effectivePeerPort,
                    onProgress = DeployManager::updateProgress,
                    privateKey = uninstallPrivateKey,
                    keyPassphrase = uninstallKeyPassphrase,
                    certificate = uninstallCertificate,
                )
                if (success) {
                    showDeployToast(context, "Удаление успешно завершено")
                } else {
                    val message = DeployManager.lastResult.value.ifBlank { "Ошибка удаления" }
                    scope.launch { snackbarHostState.showSnackbar(message) }
                }
            } catch (e: CancellationException) {
                DeployManager.stopDeploy("Удаление отменено")
                throw e
            } catch (e: Exception) {
                val message = friendlyDeployError(e.message)
                DeployManager.writeError(
                    "Uninstall UI error (${e.javaClass.simpleName}): ${e.message}\n" +
                        e.stackTraceToString().take(1200)
                )
                TunnelManager.addDeployErrorLog(message)
                DeployManager.stopDeploy(message)
                scope.launch { snackbarHostState.showSnackbar(message) }
            } finally {
                runCatching {
                    context.startService(Intent(context, TunnelService::class.java).apply { action = "DEPLOY_STOP" })
                }.onFailure { DeployManager.writeError("Не удалось остановить foreground-режим удаления: ${it.message}") }
            }
        }
    }

    DeployScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onAction = { action ->
            when (action) {
                is DeployAction.HostChanged -> {
                    host = action.value.filterNot(Char::isWhitespace)
                    generalEdited = true
                }
                is DeployAction.LoginChanged -> {
                    sshLogin = action.value.filterNot(Char::isWhitespace)
                    credentialsEdited = true
                }
                is DeployAction.PasswordChanged -> {
                    sshPassword = sanitizeSshPassword(action.value)
                    credentialsEdited = true
                }
                is DeployAction.SudoPasswordChanged -> {
                    sudoPassword = sanitizeSshPassword(action.value)
                    sudoPasswordEdited = true
                }
                is DeployAction.ManualPortsChanged -> {
                    if (!action.enabled) {
                        sshPort = CsqttConstants.Network.DEFAULT_SSH_PORT.toString()
                        peerPort = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString()
                        webPort = CsqttConstants.Network.DEFAULT_SERVER_WEB_PORT.toString()
                        portsEdited = false
                    }
                    scope.launch { settingsStore.saveManualPortsEnabled(action.enabled) }
                }
                is DeployAction.SshKeysModeChanged -> {
                    if (action.enabled && sshLogin.isBlank()) {
                        sshLogin = "root"
                        credentialsEdited = true
                    }
                    scope.launch { settingsStore.saveSshKeysMode(action.enabled) }
                }
                is DeployAction.DockerInstallChanged -> {
                    dockerInstall = action.enabled
                    scope.launch { settingsStore.saveDockerInstall(action.enabled) }
                }
                DeployAction.EditSshKeys -> showSshKeysDialog = true
                DeployAction.DockerInfo -> showDockerInfoDialog = true
                is DeployAction.SshPortChanged -> {
                    sshPort = action.value.filter(Char::isDigit).take(5)
                    portsEdited = true
                }
                is DeployAction.PeerPortChanged -> {
                    peerPort = action.value.filter(Char::isDigit).take(5)
                    portsEdited = true
                }
                is DeployAction.WebPortChanged -> {
                    webPort = action.value.filter(Char::isDigit).take(5)
                    portsEdited = true
                }
                DeployAction.EditAuthorization -> showSecretsDialog = true
                DeployAction.Install -> {
                    showValidation = true
                    if (state.canInstall) startDeploy()
                }
                DeployAction.Uninstall -> if (state.canUninstall) showUninstallDialog = true
                DeployAction.PanelInfo -> showPanelInfoDialog = true
                DeployAction.OpenControlPanel -> {
                    if (host.isBlank()) {
                        scope.launch { snackbarHostState.showSnackbar("Сначала укажите IP сервера") }
                    } else {
                        val effectiveWebPort = resolveServerPorts(
                            savedManualPorts,
                            sshPort,
                            peerPort,
                            webPort,
                        ).web
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, "https://$host:$effectiveWebPort".toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }.onFailure {
                            scope.launch { snackbarHostState.showSnackbar("Не удалось открыть панель управления") }
                        }
                    }
                }
            }
        },
    )

    if (showSecretsDialog) {
        DeploySecretsDialog(
            settingsStore = settingsStore,
            initialMainPass = savedMainPass,
            initialSshLogin = sshLogin,
            initialSshPass = sshPassword,
            initialWebLogin = savedWebLogin,
            initialWebPass = savedWebPassword,
            onSaved = {},
            onDismiss = { showSecretsDialog = false },
        )
    }

    if (showUninstallDialog) {
        UninstallConfirmDialog(
            onDismiss = { showUninstallDialog = false },
            onConfirm = {
                showUninstallDialog = false
                startUninstall()
            },
        )
    }

    if (showPanelInfoDialog) {
        WebPanelInfoDialog(onDismiss = { showPanelInfoDialog = false })
    }

    if (showSshKeysDialog) {
        SshKeysDialog(
            initialPrivateKey = savedSshPrivateKey,
            initialPassphrase = savedSshKeyPassphrase,
            initialCertificate = savedSshCertificate,
            onSave = { privateKey, keyPassphrase, certificate ->
                showSshKeysDialog = false
                scope.launch { settingsStore.saveSshKeys(privateKey, keyPassphrase, certificate) }
            },
            onDismiss = { showSshKeysDialog = false },
        )
    }

    if (showDockerInfoDialog) {
        DockerInstallInfoDialog(onDismiss = { showDockerInfoDialog = false })
    }
}

