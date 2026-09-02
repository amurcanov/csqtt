// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import com.csqtt.client.showRaisedToast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.SettingsStore
import com.csqtt.client.TunnelManager
import com.csqtt.client.TunnelAuthSnapshot
import com.csqtt.client.CsqttConstants
import com.csqtt.client.WorkerCountPolicy
import com.csqtt.client.VkHashValidationCodec
import com.csqtt.client.VkHashValidator
import com.csqtt.client.shouldConfirmAutoJsMode
import com.csqtt.client.shouldConfirmTcpTransport
import com.csqtt.client.vkAuthModeForHashMode
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.components.CsqttSettingRow
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes
import com.csqtt.client.ui.dialogs.HashesDialog
import com.csqtt.client.ui.dialogs.SecretsDialog
import com.csqtt.client.ui.dialogs.VkTokenRevokeDialog
import com.csqtt.client.ui.tunnel.WorkersInfoDialog
import com.csqtt.client.ui.utils.parseCsqttLink
import com.csqtt.client.ui.utils.stripVkUrlStatic
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import android.widget.Toast

private const val WORKERS_PER_GROUP = CsqttConstants.Tunnel.WORKERS_PER_GROUP

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsTab(
    settingsStore: SettingsStore,
    tunnelAuthSettings: TunnelAuthSnapshot,
    validationRequest: Int = 0,
    onVkAuthRequested: () -> Unit = {},
) {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    SettingsTabContent(
        context,
        scope,
        settingsStore,
        tunnelAuthSettings,
        validationRequest,
        onVkAuthRequested,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsTabContent(
    context: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    settingsStore: SettingsStore,
    tunnelAuthSettings: TunnelAuthSnapshot,
    validationRequest: Int,
    onVkAuthRequested: () -> Unit,
) {
    val workersPerHash = remember(settingsStore) {
        settingsStore.workersPerHash
        .map<Int, Int?> { it }
    }
    val savedWorkersPerHash by workersPerHash
        .collectAsStateWithLifecycle(initialValue = SettingsStore.cachedWorkersPerHash)

    val activeProfile = tunnelAuthSettings.profile
    val csqttLinkMode by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val csqttLink by settingsStore.csqttLink.collectAsStateWithLifecycle(initialValue = "")
    val manualPortsEnabled by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerPeerPort by settingsStore.serverPeerPort.collectAsStateWithLifecycle(
        initialValue = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT,
    )

    val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT)
    val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_CLIENT_IDS)
    val vkHashCheckResultsJson by settingsStore.vkHashCheckResults.collectAsStateWithLifecycle(initialValue = "{}")
    val vkHashCheckResults = remember(vkHashCheckResultsJson) {
        VkHashValidationCodec.decode(vkHashCheckResultsJson)
    }
    val savedObfsMode by settingsStore.obfsMode.collectAsStateWithLifecycle(
        initialValue = CsqttConstants.Tunnel.DEFAULT_OBFS_MODE,
    )
    val obfsModeLoaded by settingsStore.obfsMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedObfsMode)
    val turnTransportLoaded by settingsStore.turnTransport.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedTurnTransport)
    val linkModeLoaded by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedCsqttLinkMode)
    val savedHashMode by settingsStore.vkHashMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkHashMode)
    val savedVkAccessToken by settingsStore.vkAccessToken.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkAccessToken)

    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    var showObfsGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showObfsDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showTurnTransportGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showTurnTransportDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showHashModeGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showHashModeDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showWorkModeGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showWorkModeDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showVkRevokeDialog by rememberSaveable { mutableStateOf(false) }
    var showSecretsDialog by rememberSaveable { mutableStateOf(false) }
    var vkAuthMode by rememberSaveable { mutableStateOf(CsqttConstants.VkAuth.MODE_CALLS) }
    val autoJsRiskAcknowledged by settingsStore.autoJsRiskAcknowledged.collectAsStateWithLifecycle(initialValue = false)
    val tcpTransportRiskAcknowledged by settingsStore.tcpTransportRiskAcknowledged.collectAsStateWithLifecycle(initialValue = false)
    var showAutoJsRiskDialog by remember { mutableStateOf(false) }
    var showTcpTransportRiskDialog by remember { mutableStateOf(false) }
    var showWorkersInfoDialog by rememberSaveable { mutableStateOf(false) }
    var pendingAutoJsSelection by remember { mutableStateOf<(() -> Unit)?>(null) }
    var pendingTcpTransportSelection by remember { mutableStateOf<(() -> Unit)?>(null) }
    var showRequiredFieldErrors by rememberSaveable(activeProfile) { mutableStateOf(false) }

    val hashSettingsLoaded = savedHashMode != null && savedVkAccessToken != null
    val accountAutoJsMode = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
    val autoHashMode = accountAutoJsMode || (
        savedHashMode != null && savedHashMode != CsqttConstants.VkAutoHash.MODE_MANUAL
    )
    val vkTokenActive = savedVkAccessToken?.isNotBlank() == true

    var peerInput by rememberSaveable { mutableStateOf("") }
    var peerPortInput by rememberSaveable(activeProfile) {
        mutableStateOf(CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString())
    }
    var vkHash1 by rememberSaveable { mutableStateOf("") }
    var vkHash2 by rememberSaveable { mutableStateOf("") }
    var vkHash3 by rememberSaveable { mutableStateOf("") }
    var vkHash4 by rememberSaveable { mutableStateOf("") }
    var vkHash5 by rememberSaveable { mutableStateOf("") }
    var vkHash6 by rememberSaveable { mutableStateOf("") }
    var showHashesDialog by rememberSaveable { mutableStateOf(false) }
    var obfsMode by rememberSaveable { mutableStateOf(CsqttConstants.Tunnel.DEFAULT_OBFS_MODE) }
    var turnTransport by rememberSaveable { mutableStateOf(CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT) }
    var autoCaptchaEnabled by rememberSaveable { mutableStateOf(true) }
    var useWVCaptcha by rememberSaveable { mutableStateOf(false) }
    var isManualMode by rememberSaveable { mutableStateOf(true) }
    var wbvManualMode by rememberSaveable { mutableStateOf(true) }
    var saveJob by remember { mutableStateOf<Job?>(null) }
    var peerPortSaveJob by remember { mutableStateOf<Job?>(null) }
    var peerPortEdited by rememberSaveable(activeProfile) { mutableStateOf(false) }
    var linkSaveJob by remember { mutableStateOf<Job?>(null) }
    var linkText by remember { mutableStateOf(csqttLink) }
    var loadedLinkMode by remember(activeProfile) { mutableStateOf<Boolean?>(null) }
    var initialized by rememberSaveable(activeProfile) { mutableStateOf(false) }
    val participantMode = loadedLinkMode ?: csqttLinkMode

    val allHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        listOf(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6)
    }
    val uniqueHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6, vkHashCheckResults) {
        VkHashValidationCodec.active(allHashes, vkHashCheckResults)
    }
    val parsedCsqttLink = remember(linkText) { parseCsqttLink(linkText) }
    val linkHashes = parsedCsqttLink?.hashes.orEmpty()
    val filledHashCount = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) { uniqueHashes.size }
    val combinedHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        allHashes.filter { it.isNotBlank() && it.length >= 16 }.distinct().joinToString(",")
    }
    val extraWorkers = remember(settingsStore) {
        settingsStore.extraWorkers
        .map<Boolean, Boolean?> { it }
    }
    val extraWorkersEnabled by extraWorkers
        .collectAsStateWithLifecycle(initialValue = SettingsStore.cachedExtraWorkers)
    val effectiveExtraWorkersEnabled = extraWorkersEnabled == true && !accountAutoJsMode

    val dynamicMaxWorkers = remember(
        filledHashCount,
        hashSettingsLoaded,
        autoHashMode,
        participantMode,
        linkHashes,
        accountAutoJsMode,
        effectiveExtraWorkersEnabled,
    ) {
        val sourceMaximum = if (!hashSettingsLoaded) {
            CsqttConstants.Tunnel.MAX_WORKERS.toFloat()
        } else {
            WorkerCountPolicy.maximumForSources(
                linkMode = participantMode,
                linkHashCount = linkHashes.size,
                autoHashMode = autoHashMode,
                manualHashCount = filledHashCount,
            ).toFloat()
        }
        if (!effectiveExtraWorkersEnabled) {
            sourceMaximum.coerceAtMost(CsqttConstants.Tunnel.DEFAULT_MAX_WORKERS.toFloat())
        } else {
            sourceMaximum
        }
    }
    val selectableMaxWorkers = remember(dynamicMaxWorkers) {
        roundToGroup(dynamicMaxWorkers, dynamicMaxWorkers)
    }
    var sniInput by rememberSaveable { mutableStateOf("") }

    val currentWorkers = roundToGroup(
        (savedWorkersPerHash ?: WORKERS_PER_GROUP).toFloat()
            .coerceIn(WORKERS_PER_GROUP.toFloat(), selectableMaxWorkers),
        selectableMaxWorkers,
    )

    val hashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        buildList {
            allHashes.forEachIndexed { i, h ->
                if (h.isNotBlank() && h.length < 16) add("Хеш ${i + 1} — короткий")
            }
            val filled = allHashes.filter { it.isNotBlank() && it.length >= 16 }
            if (filled.size != filled.distinct().size) add("Есть дубликаты хешей")
        }
    }
    val hasInputHashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) { hashErrors.isNotEmpty() }

    LaunchedEffect(validationRequest) {
        if (validationRequest > 0) showRequiredFieldErrors = true
    }

    fun parseHashes(raw: String) {
        val parts = raw.split(Regex("[,\\s\\n]+")).map { stripVkUrlStatic(it) }.filter { it.isNotEmpty() }
        vkHash1 = parts.getOrElse(0) { "" }
        vkHash2 = parts.getOrElse(1) { "" }
        vkHash3 = parts.getOrElse(2) { "" }
        vkHash4 = parts.getOrElse(3) { "" }
        vkHash5 = parts.getOrElse(4) { "" }
        vkHash6 = parts.getOrElse(5) { "" }
    }

    fun normalizeHashes(vararg hashes: String): String {
        return hashes
            .map { stripVkUrlStatic(it) }
            .filter { it.isNotBlank() && it.length >= 16 }
            .distinct()
            .joinToString(",")
    }

    LaunchedEffect(csqttLink) {
        linkText = csqttLink
    }

    LaunchedEffect(csqttLinkMode) {
        if (initialized) loadedLinkMode = csqttLinkMode
    }

    LaunchedEffect(activeProfile) {
        saveJob?.cancel()
        linkSaveJob?.cancel()
        peerPortSaveJob?.cancel()
        val peer = settingsStore.peer.first()
        val hashes = settingsStore.vkHashes.first()
        val loadedVkAuthMode = settingsStore.vkAuthMode.first()
        val captchaMode = settingsStore.captchaMode.first()
        val captchaMethod = settingsStore.captchaSolveMethod.first()
        val wbvCaptchaMethod = settingsStore.captchaWbvSolveMethod.first()
        val profileLink = settingsStore.csqttLink.first()
        val profileLinkMode = settingsStore.csqttLinkMode.first()
        
        peerInput = peer
        parseHashes(hashes)
        linkText = profileLink
        loadedLinkMode = profileLinkMode
        vkAuthMode = loadedVkAuthMode
        sniInput = settingsStore.sni.first()
        obfsMode = savedObfsMode
        turnTransport = settingsStore.turnTransport.first()
        autoCaptchaEnabled = captchaMode == "auto"
        useWVCaptcha = captchaMode != "rjs"
        wbvManualMode = wbvCaptchaMethod != "auto"
        isManualMode = if (captchaMode == "wv") wbvManualMode else captchaMethod != "auto"
        
        initialized = true
    }

    LaunchedEffect(activeProfile, manualPortsEnabled, savedServerPeerPort) {
        if (!peerPortEdited) {
            peerPortInput = if (manualPortsEnabled) {
                savedServerPeerPort.toString()
            } else {
                CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString()
            }
        }
    }

    LaunchedEffect(activeProfile, manualPortsEnabled) {
        if (!manualPortsEnabled) {
            peerPortSaveJob?.cancel()
            peerPortInput = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString()
            peerPortEdited = false
        }
    }

    val tunnelUiReady = initialized &&
        hashSettingsLoaded &&
        obfsModeLoaded != null &&
        turnTransportLoaded != null &&
        linkModeLoaded != null &&
        savedWorkersPerHash != null &&
        extraWorkersEnabled != null
    if (!tunnelUiReady) {
        CsqttScreen {
            Spacer(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )
        }
        return
    }

    DisposableEffect(Unit) {
        onDispose {
            saveJob?.cancel()
            linkSaveJob?.cancel()
            peerPortSaveJob?.cancel()
        }
    }

    fun saveTunnelSettingsNow(hashes: String = combinedHashes, onSaved: (() -> Unit)? = null) {
        saveJob?.cancel()
        scope.launch {
            if (participantMode) {
                settingsStore.saveParticipantTunnelSettings(hashes, currentWorkers.toInt())
            } else {
                settingsStore.save(
                    peerInput, hashes, "",
                    currentWorkers.toInt(), "udp", 0, sniInput, false
                )
            }
            onSaved?.invoke()
        }
    }

    fun scheduleSave() {
        saveJob?.cancel()
        saveJob = scope.launch {
            // Debounce: one DataStore rewrite per pause in typing/slider moves,
            // not one per keystroke or slider frame.
            delay(300)
            if (participantMode) {
                settingsStore.saveParticipantTunnelSettings(combinedHashes, currentWorkers.toInt())
            } else {
                settingsStore.save(
                    peerInput, combinedHashes, "",
                    currentWorkers.toInt(), "udp", 0, sniInput, false
                )
            }
        }
    }

    fun applyWorkMode(mode: String) {
        vkAuthMode = mode
        scope.launch {
            settingsStore.saveVkAuthMode(mode)
        }
    }

    fun applyHashMode(mode: String) {
        val nextWorkMode = vkAuthModeForHashMode(mode, vkAuthMode)
        vkAuthMode = nextWorkMode
        scope.launch {
            settingsStore.saveVkHashMode(mode)
        }
    }

    fun requestWorkMode(mode: String) {
        if (shouldConfirmAutoJsMode(vkAuthMode, mode, autoJsRiskAcknowledged)) {
            pendingAutoJsSelection = { applyWorkMode(mode) }
            showAutoJsRiskDialog = true
        } else {
            applyWorkMode(mode)
        }
    }

    fun requestHashMode(mode: String) {
        val nextWorkMode = vkAuthModeForHashMode(mode, vkAuthMode)
        if (shouldConfirmAutoJsMode(vkAuthMode, nextWorkMode, autoJsRiskAcknowledged)) {
            pendingAutoJsSelection = { applyHashMode(mode) }
            showAutoJsRiskDialog = true
        } else {
            applyHashMode(mode)
        }
    }

    fun applyTurnTransport(transport: String) {
        turnTransport = transport
        scope.launch { settingsStore.saveTurnTransport(transport) }
    }

    fun requestTurnTransport(transport: String) {
        if (shouldConfirmTcpTransport(turnTransport, transport, tcpTransportRiskAcknowledged)) {
            pendingTcpTransportSelection = { applyTurnTransport(transport) }
            showTcpTransportRiskDialog = true
        } else {
            applyTurnTransport(transport)
        }
    }

    LaunchedEffect(accountAutoJsMode, extraWorkersEnabled) {
        if (accountAutoJsMode && extraWorkersEnabled == true) {
            settingsStore.saveExtraWorkers(false)
        }
    }

    LaunchedEffect(initialized, currentWorkers, savedWorkersPerHash) {
        val savedWorkers = savedWorkersPerHash
        if (initialized && savedWorkers != null && currentWorkers.toInt() != savedWorkers) {
            scope.launch { settingsStore.saveWorkersPerHash(currentWorkers.toInt()) }
        }
    }

    val scrollState = rememberScrollState()

    val isPeerValid = peerInput.isNotBlank() && !peerInput.contains(":")
    val isPeerPortValid = peerPortInput.toIntOrNull() in 1..65535
    val hashesReadyForTunnel = when {
        participantMode && linkHashes.isNotEmpty() -> true
        autoHashMode -> vkTokenActive
        else -> filledHashCount > 0
    }
    val peerRequiredError = showRequiredFieldErrors && !participantMode && !isPeerValid
    val peerPortRequiredError = showRequiredFieldErrors && !participantMode && manualPortsEnabled && !isPeerPortValid
    val linkRequiredError = showRequiredFieldErrors && participantMode && parsedCsqttLink == null
    val hashesRequiredError = showRequiredFieldErrors && !hashesReadyForTunnel
    val authorizationRequiredError = showRequiredFieldErrors && !participantMode && tunnelAuthSettings.connectionPassword.isBlank()
    if (showHashesDialog) {
        HashesDialog(
            hash1 = vkHash1,
            hash2 = vkHash2,
            hash3 = vkHash3,
            hash4 = vkHash4,
            hash5 = vkHash5,
            hash6 = vkHash6,
            validationResults = vkHashCheckResults,
            onValidationResultsChange = { results ->
                scope.launch {
                    settingsStore.saveVkHashCheckResults(VkHashValidationCodec.encode(results))
                }
            },
            onCheck = { hashes ->
                VkHashValidator.check(context, hashes, activeFingerprint, activeClientIds)
            },
            onSave = { h1, h2, h3, h4, h5, h6 ->
                val cleaned1 = stripVkUrlStatic(h1)
                val cleaned2 = stripVkUrlStatic(h2)
                val cleaned3 = stripVkUrlStatic(h3)
                val cleaned4 = stripVkUrlStatic(h4)
                val cleaned5 = stripVkUrlStatic(h5)
                val cleaned6 = stripVkUrlStatic(h6)
                vkHash1 = cleaned1
                vkHash2 = cleaned2
                vkHash3 = cleaned3
                vkHash4 = cleaned4
                vkHash5 = cleaned5
                vkHash6 = cleaned6
                saveTunnelSettingsNow(normalizeHashes(cleaned1, cleaned2, cleaned3, cleaned4, cleaned5, cleaned6)) {
                    showHashesDialog = false
                }
            },
            onDismiss = { showHashesDialog = false }
        )
    }

    if (showSecretsDialog) {
        SecretsDialog(
            settingsStore = settingsStore,
            initialPassword = tunnelAuthSettings.connectionPassword,
            onSaved = {},
            onDismiss = { showSecretsDialog = false },
        )
    }

    if (showVkRevokeDialog) {
        VkTokenRevokeDialog(
            onCancel = { showVkRevokeDialog = false },
            onRevokeToken = {
                showVkRevokeDialog = false
                scope.launch { settingsStore.clearVkAccessToken() }
            }
        )
    }

    CsqttScreen {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
            AppSectionCard(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                if (participantMode) {
                    OutlinedTextField(
                        value = linkText,
                        onValueChange = { value ->
                            linkText = value.filterNot(Char::isWhitespace)
                            linkSaveJob?.cancel()
                            linkSaveJob = scope.launch {
                                delay(300)
                                settingsStore.saveCsqttLink(linkText)
                            }
                        },
                        label = { Text("Ссылка csqtt://", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                        placeholder = { Text("csqtt://connect?v=2&host=ip&peer=порт&password=пароль", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                        singleLine = true,
                        isError = linkRequiredError || (linkText.isNotBlank() && parsedCsqttLink == null),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                        shape = CsqttShapes.Control,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                        )
                    )

                    if (linkText.isNotBlank() && parsedCsqttLink == null) {
                        Text(
                            text = "Неверная ссылка CSQTT v2",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 12.dp),
                        )
                    }

                    if (linkHashes.isNotEmpty()) {
                        Text(
                            text = "VK хеши из ссылки: ${linkHashes.size}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold,
                        )
                    } else {
                        VkHashModeControls(
                            hashSettingsLoaded = hashSettingsLoaded,
                            autoHashMode = autoHashMode,
                            savedHashMode = savedHashMode,
                            vkTokenActive = vkTokenActive,
                            tunnelRunning = tunnelRunning,
                            filledHashCount = filledHashCount,
                            hasInputHashErrors = hasInputHashErrors || hashesRequiredError,
                            hashErrorTexts = hashErrors.filter { !it.contains("короткий") },
                            onOpenHashes = { showHashesDialog = true },
                            onTitleInfo = { showHashModeGeneralDialog = true },
                            onInfo = { mode -> showHashModeDetailDialog = mode },
                            onSelected = ::requestHashMode,
                            onLogin = onVkAuthRequested,
                            onRevokeToken = { showVkRevokeDialog = true },
                            authorizationRequiredError = hashesRequiredError && autoHashMode,
                        )
                    }
                } else {
                    Text(
                        "Сервер и Хеши",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(bottom = 12.dp),
                    )
                    if (manualPortsEnabled) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            OutlinedTextField(
                                value = peerInput,
                                onValueChange = {
                                    peerInput = it.filter { c -> !c.isWhitespace() }
                                    scheduleSave()
                                },
                                label = {
                                    Text(
                                        "IP сервера или домен",
                                        maxLines = 1,
                                        softWrap = false,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                                placeholder = { Text("1.2.3.4", maxLines = 1) },
                                singleLine = true,
                                isError = peerRequiredError || (!isPeerValid && peerInput.isNotEmpty()),
                                modifier = Modifier.weight(1f),
                                shape = CsqttShapes.Control,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                                ),
                            )
                            OutlinedTextField(
                                value = peerPortInput,
                                onValueChange = { value ->
                                    val nextValue = value.filter(Char::isDigit).take(5)
                                    peerPortInput = nextValue
                                    peerPortEdited = true
                                    peerPortSaveJob?.cancel()
                                    peerPortSaveJob = scope.launch {
                                        delay(300)
                                        val port = nextValue.toIntOrNull()
                                        if (port != null && port in 1..65535) {
                                            settingsStore.saveServerPeerPort(port)
                                            peerPortEdited = false
                                        }
                                    }
                                },
                                label = { Text("Порт PEER", maxLines = 1, softWrap = false) },
                                placeholder = {
                                    Text(
                                        CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString(),
                                        maxLines = 1,
                                    )
                                },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                isError = peerPortRequiredError || (peerPortInput.isNotEmpty() && !isPeerPortValid),
                                modifier = Modifier.weight(1f),
                                shape = CsqttShapes.Control,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                                ),
                            )
                        }
                    } else {
                        OutlinedTextField(
                            value = peerInput,
                            onValueChange = {
                                peerInput = it.filter { c -> !c.isWhitespace() }
                                scheduleSave()
                            },
                            label = {
                                Text(
                                    "IP сервера или домен (без порта)",
                                    maxLines = 1,
                                    softWrap = false,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            },
                            placeholder = {
                                Text(
                                    "1.2.3.4 (или test.com)",
                                    maxLines = 1,
                                    softWrap = false,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            },
                            singleLine = true,
                            isError = peerRequiredError || (!isPeerValid && peerInput.isNotEmpty()),
                            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                            shape = CsqttShapes.Control,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MaterialTheme.colorScheme.primary,
                                unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                            ),
                        )
                    }

                    VkHashModeControls(
                        hashSettingsLoaded = hashSettingsLoaded,
                        autoHashMode = autoHashMode,
                        savedHashMode = savedHashMode,
                        vkTokenActive = vkTokenActive,
                        tunnelRunning = tunnelRunning,
                        filledHashCount = filledHashCount,
                        hasInputHashErrors = hasInputHashErrors || hashesRequiredError,
                        hashErrorTexts = hashErrors.filter { !it.contains("короткий") },
                        onOpenHashes = { showHashesDialog = true },
                        onTitleInfo = { showHashModeGeneralDialog = true },
                        onInfo = { mode -> showHashModeDetailDialog = mode },
                        onSelected = ::requestHashMode,
                        onLogin = onVkAuthRequested,
                        onRevokeToken = { showVkRevokeDialog = true },
                        authorizationRequiredError = hashesRequiredError && autoHashMode,
                    )
                }

                Spacer(Modifier.height(4.dp))

                CompactDropdownSetting(
                    title = "Режим кредов",
                    selectedKey = vkAuthMode,
                    options = listOf(
                        CsqttConstants.VkAuth.MODE_CAPTCHA to "Капча",
                        CsqttConstants.VkAuth.MODE_CALLS to "Авто",
                        CsqttConstants.VkAuth.MODE_AUTO_JS to "Авто ВК",
                    ),
                    enabled = true,
                    indicatorProvider = { mode ->
                        when (mode) {
                            CsqttConstants.VkAuth.MODE_CAPTCHA -> ModeIndicator(progress = 0.30f, color = Color(0xFFE53935))
                            CsqttConstants.VkAuth.MODE_CALLS -> ModeIndicator(progress = 0.78f, color = Color(0xFF43A047))
                            CsqttConstants.VkAuth.MODE_AUTO_JS -> ModeIndicator(progress = 1.0f, color = Color(0xFF43A047))
                            else -> null
                        }
                    },
                    onTitleInfo = { showWorkModeGeneralDialog = true },
                    onInfo = { mode -> showWorkModeDetailDialog = mode },
                    onSelected = ::requestWorkMode,
                )

                Spacer(Modifier.height(4.dp))

                CompactDropdownSetting(
                    title = "Маскировка",
                    selectedKey = obfsMode,
                    options = listOf(
                        "audio" to "Простая",
                        "video" to "Средняя",
                    ),
                    enabled = true,
                    indicatorProvider = { mode ->
                        when (mode) {
                            "audio" -> ModeIndicator(progress = 0.50f, color = Color(0xFFFFB300))
                            "video" -> ModeIndicator(progress = 0.78f, color = Color(0xFF43A047))
                            else -> null
                        }
                    },
                    onTitleInfo = { showObfsGeneralDialog = true },
                    onInfo = { mode -> showObfsDetailDialog = mode },
                    onSelected = { mode ->
                        obfsMode = mode
                        scope.launch { settingsStore.saveObfsMode(mode) }
                    },
                )

                Spacer(Modifier.height(4.dp))

                CompactDropdownSetting(
                    title = "Транспорт",
                    selectedKey = turnTransport,
                    options = listOf(
                        CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS to "TCP",
                        CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT to "UDP",
                    ),
                    enabled = true,
                    indicatorProvider = { transport ->
                        when (transport) {
                            CsqttConstants.Tunnel.DEFAULT_TURN_TRANSPORT -> ModeIndicator(
                                progress = 1.0f,
                                color = Color(0xFF43A047),
                            )
                            CsqttConstants.Tunnel.TURN_TRANSPORT_TCP_TLS -> ModeIndicator(
                                progress = 0.50f,
                                color = Color(0xFFFFB300),
                            )
                            else -> null
                        }
                    },
                    onTitleInfo = { showTurnTransportGeneralDialog = true },
                    onInfo = { transport -> showTurnTransportDetailDialog = transport },
                    onSelected = ::requestTurnTransport,
                )

                TunnelWorkersControl(
                    value = currentWorkers,
                    maximum = selectableMaxWorkers,
                    enabled = !tunnelRunning,
                    onValueChange = { value ->
                        scope.launch { settingsStore.saveWorkersPerHash(value.toInt()) }
                    },
                    onInfo = { showWorkersInfoDialog = true },
                )

                AnimatedVisibility(
                    visible = vkAuthMode == CsqttConstants.VkAuth.MODE_CAPTCHA,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                        HorizontalDivider(
                            modifier = Modifier.padding(vertical = 4.dp),
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                if (autoCaptchaEnabled) "Авто капча" else "Ручная капча",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.weight(1f)
                            )
                            Switch(
                                checked = autoCaptchaEnabled,
                                enabled = !tunnelRunning,
                                onCheckedChange = { enabled ->
                                    autoCaptchaEnabled = enabled
                                    scope.launch {
                                        if (enabled) {
                                            settingsStore.saveCaptchaMode("auto")
                                            settingsStore.saveCaptchaSolveMethod("auto")
                                        } else {
                                            val mode = if (useWVCaptcha) "wv" else "rjs"
                                            settingsStore.saveCaptchaMode(mode)
                                            settingsStore.saveCaptchaSolveMethod(if (mode == "wv" && isManualMode) "manual" else "auto")
                                        }
                                    }
                                }
                            )
                        }

                        AnimatedVisibility(
                            visible = !autoCaptchaEnabled,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 4.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                )

                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        "Метод обхода капчи",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        ProtocolChip("WBV", useWVCaptcha, enabled = !tunnelRunning) {
                                            useWVCaptcha = true
                                            isManualMode = wbvManualMode
                                            scope.launch {
                                                settingsStore.saveCaptchaMode("wv")
                                                settingsStore.saveCaptchaSolveMethod(if (wbvManualMode) "manual" else "auto")
                                            }
                                        }
                                        ProtocolChip("RJS", !useWVCaptcha, enabled = !tunnelRunning, isError = false) {
                                            useWVCaptcha = false
                                            isManualMode = false
                                            scope.launch {
                                                settingsStore.saveCaptchaMode("rjs")
                                                settingsStore.saveCaptchaSolveMethod("auto")
                                            }
                                        }
                                    }
                                }

                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 4.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                )

                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        "Режим обхода",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        if (useWVCaptcha) {
                                            ProtocolChip(
                                                "РУЧ",
                                                isManualMode,
                                                enabled = !tunnelRunning,
                                                isError = false
                                            ) {
                                                isManualMode = true
                                                wbvManualMode = true
                                                scope.launch { settingsStore.saveWbvCaptchaSolveMethod("manual") }
                                            }
                                            ProtocolChip(
                                                "АВТ",
                                                !isManualMode,
                                                enabled = !tunnelRunning,
                                                isError = false
                                            ) {
                                                isManualMode = false
                                                wbvManualMode = false
                                                scope.launch { settingsStore.saveWbvCaptchaSolveMethod("auto") }
                                            }
                                        } else {
                                            ProtocolChip(
                                                "АВТ",
                                                selected = true,
                                                enabled = false,
                                                isError = false
                                            ) {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }

            if (!participantMode) {
                TunnelAuthorizationButton(
                    passwordSet = tunnelAuthSettings.connectionPassword.isNotBlank(),
                    isError = authorizationRequiredError,
                    onClick = { showSecretsDialog = true },
                )
            }

            if (showObfsGeneralDialog) {
                ObfsInfoDialog(mode = null, onDismiss = { showObfsGeneralDialog = false })
            }
            showObfsDetailDialog?.let { mode ->
                ObfsInfoDialog(mode = mode, onDismiss = { showObfsDetailDialog = null })
            }
            if (showTurnTransportGeneralDialog) {
                TurnTransportInfoDialog(
                    mode = null,
                    onDismiss = { showTurnTransportGeneralDialog = false },
                )
            }
            showTurnTransportDetailDialog?.let { transport ->
                TurnTransportInfoDialog(
                    mode = transport,
                    onDismiss = { showTurnTransportDetailDialog = null },
                )
            }

            if (showHashModeGeneralDialog) {
                HashModeInfoDialog(mode = null, onDismiss = { showHashModeGeneralDialog = false })
            }
            showHashModeDetailDialog?.let { mode ->
                HashModeInfoDialog(mode = mode, onDismiss = { showHashModeDetailDialog = null })
            }

            if (showWorkModeGeneralDialog) {
                WorkModeInfoDialog(mode = null, onDismiss = { showWorkModeGeneralDialog = false })
            }
            showWorkModeDetailDialog?.let { mode ->
                WorkModeInfoDialog(mode = mode, onDismiss = { showWorkModeDetailDialog = null })
            }
            if (showAutoJsRiskDialog) {
                AutoVkRiskDialog(
                    requireAcknowledgement = true,
                    onAcknowledge = {
                        showAutoJsRiskDialog = false
                        pendingAutoJsSelection?.invoke()
                        pendingAutoJsSelection = null
                    },
                    onDoNotRemind = {
                        scope.launch { settingsStore.saveAutoJsRiskAcknowledged(true) }
                        showAutoJsRiskDialog = false
                        pendingAutoJsSelection?.invoke()
                        pendingAutoJsSelection = null
                    },
                )
            }
            if (showTcpTransportRiskDialog) {
                TcpTransportRiskDialog(
                    onAcknowledge = {
                        showTcpTransportRiskDialog = false
                        pendingTcpTransportSelection?.invoke()
                        pendingTcpTransportSelection = null
                    },
                    onDoNotRemind = {
                        scope.launch { settingsStore.saveTcpTransportRiskAcknowledged(true) }
                        showTcpTransportRiskDialog = false
                        pendingTcpTransportSelection?.invoke()
                        pendingTcpTransportSelection = null
                    },
                )
            }
            if (showWorkersInfoDialog) {
                WorkersInfoDialog(onDismiss = { showWorkersInfoDialog = false })
            }
        }
    }
}
}

@Composable
private fun TunnelAuthorizationButton(
    passwordSet: Boolean,
    isError: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().height(CsqttSizes.ControlHeight),
        shape = CsqttShapes.Pill,
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = Color.Transparent,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = BorderStroke(
            1.dp,
            if (passwordSet && !isError) {
                MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
            } else {
                MaterialTheme.colorScheme.error
            },
        ),
    ) {
        Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(
            text = if (passwordSet) "Авторизация" else "Авторизация нужна",
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun VkHashAuthControls(
    tunnelRunning: Boolean,
    tokenActive: Boolean,
    isError: Boolean,
    onLogin: () -> Unit,
    onRevokeToken: () -> Unit,
) {
    if (tokenActive) {
        OutlinedButton(
            onClick = onRevokeToken,
            enabled = !tunnelRunning,
            modifier = Modifier.height(44.dp),
            shape = CsqttShapes.Pill,
            colors = ButtonDefaults.outlinedButtonColors(
                containerColor = Color.Transparent,
                contentColor = MaterialTheme.colorScheme.onSurface,
                disabledContainerColor = Color.Transparent,
                disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
            contentPadding = PaddingValues(horizontal = 10.dp),
        ) {
            Text("Активно", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    } else if (isError) {
        OutlinedButton(
            onClick = onLogin,
            modifier = Modifier.height(44.dp),
            shape = CsqttShapes.Pill,
            colors = ButtonDefaults.outlinedButtonColors(
                containerColor = Color.Transparent,
                contentColor = MaterialTheme.colorScheme.onSurface,
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.error),
            contentPadding = PaddingValues(horizontal = 14.dp),
        ) {
            Text("Вход", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    } else {
        Button(
            onClick = onLogin,
            enabled = true,
            modifier = Modifier.height(44.dp),
            shape = CsqttShapes.Pill,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
            contentPadding = PaddingValues(horizontal = 14.dp),
            elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp, pressedElevation = 0.dp),
        ) {
            Text("Вход", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    }
}

@Composable
private fun VkHashModeControls(
    hashSettingsLoaded: Boolean,
    autoHashMode: Boolean,
    savedHashMode: String?,
    vkTokenActive: Boolean,
    tunnelRunning: Boolean,
    filledHashCount: Int,
    hasInputHashErrors: Boolean,
    hashErrorTexts: List<String>,
    onOpenHashes: () -> Unit,
    onTitleInfo: () -> Unit,
    onInfo: (String) -> Unit,
    onSelected: (String) -> Unit,
    onLogin: () -> Unit,
    onRevokeToken: () -> Unit,
    authorizationRequiredError: Boolean = false,
) {
    if (!hashSettingsLoaded) return

    AnimatedVisibility(
        visible = !autoHashMode,
        enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
        exit = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onOpenHashes,
                modifier = Modifier.fillMaxWidth().height(CsqttSizes.ControlHeight),
                shape = CsqttShapes.Pill,
                colors = ButtonDefaults.outlinedButtonColors(
                    containerColor = Color.Transparent,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                ),
                border = BorderStroke(
                    1.dp,
                    if (hasInputHashErrors) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                )
            ) {
                Icon(Icons.Filled.Phone, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    "VK Хеши $filledHashCount/${CsqttConstants.Tunnel.MAX_VK_HASHES}",
                    fontWeight = FontWeight.SemiBold,
                )
            }

            if (hashErrorTexts.isNotEmpty()) {
                Text(
                    text = hashErrorTexts.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }

    CompactDropdownSetting(
        title = if (autoHashMode && vkTokenActive) "Хеши" else "Режим хешей",
        selectedKey = savedHashMode ?: CsqttConstants.VkAutoHash.MODE_MANUAL,
        options = listOf(
            CsqttConstants.VkAutoHash.MODE_MANUAL to "Ручной",
            CsqttConstants.VkAutoHash.MODE_AUTO_API to "Авто API",
            CsqttConstants.VkAutoHash.MODE_AUTO_JS to "Авто ВК",
        ),
        enabled = true,
        indicatorProvider = { mode ->
            when (mode) {
                CsqttConstants.VkAutoHash.MODE_MANUAL -> ModeIndicator(progress = 0.62f, color = Color(0xFF43A047))
                CsqttConstants.VkAutoHash.MODE_AUTO_API -> ModeIndicator(progress = 1.0f, color = Color(0xFF43A047))
                CsqttConstants.VkAutoHash.MODE_AUTO_JS -> ModeIndicator(progress = 1.0f, color = Color(0xFF43A047))
                else -> null
            }
        },
        onTitleInfo = onTitleInfo,
        onInfo = onInfo,
        onSelected = onSelected,
        leadingContent = if (autoHashMode && hashSettingsLoaded) {
            {
                VkHashAuthControls(
                    tunnelRunning = tunnelRunning,
                    tokenActive = vkTokenActive,
                    isError = authorizationRequiredError,
                    onLogin = onLogin,
                    onRevokeToken = onRevokeToken,
                )
            }
        } else {
            null
        },
    )
}
