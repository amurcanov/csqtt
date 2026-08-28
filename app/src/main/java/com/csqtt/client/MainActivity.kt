// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.HapticFeedbackConstants
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.net.toUri
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import kotlinx.coroutines.launch
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.font.FontWeight
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import com.csqtt.client.ui.AppUpdateDialog
import com.csqtt.client.ui.ConnectionTab
import com.csqtt.client.ui.FloatingToolbar
import com.csqtt.client.ui.LogsTab
import com.csqtt.client.ui.SettingsTab
import com.csqtt.client.CsqttConstants
import com.csqtt.client.ui.DeployTab
import com.csqtt.client.ui.ExceptionsTab
import com.csqtt.client.ui.InfoTab
import com.csqtt.client.ui.components.LocalCsqttHeaderActions
import com.csqtt.client.ui.design.CsqttMotion
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.dialogs.VkAuthDialog
import com.csqtt.client.ui.utils.parseCsqttLink
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.first
import kotlin.math.abs

class MainActivity : ComponentActivity() {
    private val appSettingsStore by lazy { SettingsStore(applicationContext) }
    private var renderUi by mutableStateOf(false)
    private var showVkAuthDialog by mutableStateOf(false)
    private var batteryPromptInFlight = false

    private val batteryLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        batteryPromptInFlight = false
        lifecycleScope.launch {
            appSettingsStore.markBatteryOptimizationPromptHandled()
        }
    }

    private val notificationLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        checkAndRequestBattery()
    }

    companion object {
        @Volatile
        var activeActivities = 0
        val isForeground: Boolean
            get() = activeActivities > 0
    }

    override fun onStart() {
        super.onStart()
        activeActivities++
        renderUi = true
        ManlCaptchaWebViewManager.checkAndShowPendingCaptcha(this)
    }

    override fun onStop() {
        renderUi = false
        activeActivities = (activeActivities - 1).coerceAtLeast(0)
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val discardStaleUiState = UpdateLaunchGuard.consumeStaleSavedState(this)
        super.onCreate(if (discardStaleUiState) null else savedInstanceState)

        importCsqttLink(intent)

        TunnelManager.initObservers(this)

        enableEdgeToEdge()

        checkAndRequestNotifications()

        setContent {
            val authContext = LocalContext.current.applicationContext
            val authScope = rememberCoroutineScope()
            val uiStateHolder = rememberSaveableStateHolder()
            if (renderUi) {
                uiStateHolder.SaveableStateProvider("main_ui") {
            val settingsStore = remember { appSettingsStore }
            val themeMode by settingsStore.themeMode.collectAsStateWithLifecycle(initialValue = CsqttConstants.Theme.MODE_SYSTEM)
            val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT)
            val scope = rememberCoroutineScope()

            val baseDensity = LocalDensity.current
            val fixedDensity = remember(baseDensity.density) { Density(baseDensity.density, 1f) }

            CompositionLocalProvider(LocalDensity provides fixedDensity) {
            CSQTTTheme(themeMode = themeMode) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    MainScreen(
                        settingsStore = settingsStore,
                        themeMode = themeMode,
                        onThemeChange = { mode ->
                            scope.launch {
                                settingsStore.saveThemeMode(mode)
                            }
                        },
                        activeFingerprint = activeFingerprint,
                        onFingerprintChange = { fp ->
                            scope.launch { settingsStore.saveFingerprint(fp) }
                        },
                        onVkAuthRequested = { showVkAuthDialog = true },
                    )
                }
            }
            }
                }
            }
            if (showVkAuthDialog) {
                VkAuthDialog(
                    onToken = { payload ->
                        showVkAuthDialog = false
                        authScope.launch {
                            appSettingsStore.saveVkAccessToken(payload.token, payload.userId)
                            authContext.showRaisedToast("Вечный VK access token сохранен", Toast.LENGTH_SHORT)
                        }
                    },
                    onDismiss = { showVkAuthDialog = false },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        importCsqttLink(intent)
    }

    private fun importCsqttLink(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val link = intent.dataString?.takeIf { parseCsqttLink(it) != null } ?: return
        lifecycleScope.launch {
            appSettingsStore.saveCsqttLink(link)
            appSettingsStore.saveCsqttLinkMode(true)
        }
    }

    private fun checkAndRequestNotifications() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                checkAndRequestBattery()
            }
        } else {
            checkAndRequestBattery()
        }
    }

    @SuppressLint("BatteryLife")
    private fun checkAndRequestBattery() {
        if (batteryPromptInFlight) return
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        lifecycleScope.launch {
            val shouldRequest = shouldRequestBatteryOptimizationExemption(
                promptHandled = appSettingsStore.isBatteryOptimizationPromptHandled(),
                alreadyExempt = powerManager.isIgnoringBatteryOptimizations(packageName),
            )
            if (!shouldRequest) {
                if (powerManager.isIgnoringBatteryOptimizations(packageName)) {
                    appSettingsStore.markBatteryOptimizationPromptHandled()
                }
                return@launch
            }

            batteryPromptInFlight = true
            val launched = runCatching {
                batteryLauncher.launch(
                    Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        "package:$packageName".toUri(),
                    ),
                )
                true
            }.getOrDefault(false)
            if (!launched) {
                batteryPromptInFlight = false
                appSettingsStore.markBatteryOptimizationPromptHandled()
            }
        }
    }
}

private data class NavItem(
    val id: Int,
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
)

private val navItems = listOf(
    NavItem(0, R.string.nav_connection, Icons.Filled.PowerSettingsNew, Icons.Filled.PowerSettingsNew),
    NavItem(1, R.string.nav_tunnel, Icons.Filled.VpnKey, Icons.Outlined.VpnKey),
    NavItem(2, R.string.nav_deploy, Icons.Filled.Cloud, Icons.Outlined.Cloud),
    NavItem(3, R.string.nav_exceptions, Icons.Filled.FilterList, Icons.Outlined.FilterList),
    NavItem(4, R.string.nav_logs, Icons.Filled.Terminal, Icons.Outlined.Terminal),
    NavItem(5, R.string.nav_info, Icons.Filled.Info, Icons.Outlined.Info),
)

internal fun navigationSwipeProgress(totalDrag: Float, containerWidth: Int): Float =
    if (containerWidth <= 0) 0f else (abs(totalDrag) / (containerWidth.toFloat() * 0.25f)).coerceIn(0f, 1f)

internal fun shouldCommitNavigationSwipe(progress: Float): Boolean = progress > 0.4f

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    settingsStore: SettingsStore,
    themeMode: String = CsqttConstants.Theme.MODE_SYSTEM,
    onThemeChange: (String) -> Unit = {},
    activeFingerprint: String = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT,
    onFingerprintChange: (String) -> Unit = {},
    onVkAuthRequested: () -> Unit = {},
) {
    val unreadErrors by TunnelManager.unreadErrorCount.collectAsStateWithLifecycle()
    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val tunnelAutoPausedForWifi by TunnelManager.autoPausedForWifi.collectAsStateWithLifecycle()
    val view = LocalView.current
    val context = LocalContext.current
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val activeProfile by settingsStore.activeProfile.collectAsStateWithLifecycle(initialValue = 0)
    val deploySettings by settingsStore.deploySettingsSnapshot.collectAsStateWithLifecycle(
        initialValue = DeploySettingsSnapshot()
    )
    val tunnelAuthSettings by settingsStore.tunnelAuthSnapshot.collectAsStateWithLifecycle(
        initialValue = TunnelAuthSnapshot()
    )
    val csqttLinkMode by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val autoPauseOnWifi by settingsStore.autoPauseOnWifi.collectAsStateWithLifecycle(initialValue = false)
    val excludedApps by settingsStore.excludedApps.collectAsStateWithLifecycle(initialValue = "")
    val showSystemApps by settingsStore.showSystemApps.collectAsStateWithLifecycle(initialValue = false)
    val isWhitelist by settingsStore.isWhitelist.collectAsStateWithLifecycle(initialValue = false)
    val infoActionsExpanded by settingsStore.infoActionsExpanded.collectAsStateWithLifecycle(initialValue = false)
    val infoProjectExpanded by settingsStore.infoProjectExpanded.collectAsStateWithLifecycle(initialValue = false)
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var tunnelValidationRequest by rememberSaveable { mutableIntStateOf(0) }
    // Held as State objects and read only inside ProxyNavigationBar: a swipe
    // writes these on every pointer event, and delegating reads here would
    // recompose the whole MainScreen (tabs included) per event.
    val dragTargetIndex = remember { mutableIntStateOf(-1) }
    val dragProgress = remember { mutableFloatStateOf(0f) }
    var wasRunning by remember { mutableStateOf(tunnelRunning) }
    val updateCheckIntervalHours by settingsStore.updateCheckIntervalHours.collectAsStateWithLifecycle(
        initialValue = DEFAULT_UPDATE_CHECK_INTERVAL_HOURS
    )
    var pendingRelease by remember { mutableStateOf<AppReleaseInfo?>(null) }
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    val safeBottomInset = with(density) { WindowInsets.safeDrawing.getBottom(density).toDp() }
    val navToolbarHeight = 66.dp
    val navToolbarBottomMargin = 10.dp
    val navContentGap = 5.dp
    val navOverlayReserve = safeBottomInset + navToolbarBottomMargin + navToolbarHeight + navContentGap
    val navigationDragSlop = with(density) { 6.dp.toPx() }

    val activeNavItems = remember(csqttLinkMode) {
        if (csqttLinkMode) {
            navItems.filter { it.id != 2 }
        } else {
            navItems
        }
    }
    val tabStateHolder = rememberSaveableStateHolder()
    LaunchedEffect(csqttLinkMode) {
        if (csqttLinkMode && selectedTab == 2) {
            selectedTab = 0
        }
    }

    LaunchedEffect(tunnelRunning, tunnelAutoPausedForWifi) {
        if (wasRunning && !tunnelRunning && !tunnelAutoPausedForWifi) {
            TunnelManager.startCooldown(CsqttConstants.Timeouts.VPN_PERMISSION_COOLDOWN_MS)
        }
        wasRunning = tunnelRunning
    }

    LaunchedEffect(selectedTab) {
        if (selectedTab == 4) TunnelManager.clearUnreadErrors()
    }

    LaunchedEffect(updateCheckIntervalHours) {
        if (updateCheckIntervalHours == UPDATE_CHECK_NEVER) return@LaunchedEffect

        val intervalMillis = updateIntervalHoursToMillis(updateCheckIntervalHours)
            ?: updateIntervalHoursToMillis(DEFAULT_UPDATE_CHECK_INTERVAL_HOURS)
            ?: 12L * 60L * 60L * 1000L

        suspend fun runUpdateCheck(reason: String) {
            val checkedAt = System.currentTimeMillis()
            val release = fetchLatestReleaseInfo(currentVersion)
            settingsStore.saveUpdateState(
                lastCheckAt = checkedAt,
                latestVersion = release?.versionTag ?: "",
                error = if (release == null) "Не удалось проверить" else ""
            )

            if (release == null) {
                Log.w("CSQTT", "[WARN] Update check: no release info, local=$currentVersion reason=$reason")
                return
            }

            val hasUpdate = isNewerVersion(currentVersion, release.versionTag)
            val postponeVer = settingsStore.updatePostponeVersion.first()
            val postponeUntil = settingsStore.updatePostponeUntil.first()
            val isPostponed = postponeVer == release.versionTag && checkedAt < postponeUntil
            Log.i(
                "CSQTT",
                "Update check: local=$currentVersion remote=${release.versionTag} newer=$hasUpdate postponed=$isPostponed reason=$reason"
            )

            if (hasUpdate && !isPostponed) {
                settingsStore.saveUpdateDialogShown(release.versionTag, checkedAt)
                pendingRelease = release
            }
        }

        runUpdateCheck("startup")

        while (isActive) {
            val now = System.currentTimeMillis()
            val lastCheck = settingsStore.updateLastCheckAt.first()
            val nextCheckAt = lastCheck + intervalMillis
            val waitMs = (nextCheckAt - now).coerceAtLeast(intervalMillis)
            delay(waitMs)
            if (isActive) {
                runUpdateCheck("periodic")
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        AppBackdrop(modifier = Modifier.matchParentSize())

        CompositionLocalProvider(
            LocalCsqttHeaderActions provides {
                FloatingToolbar(
                    settingsStore = settingsStore,
                    csqttLinkMode = csqttLinkMode,
                    activeProfile = activeProfile,
                    onActiveProfileChange = { profile ->
                        scope.launch { settingsStore.saveActiveProfile(profile) }
                    },
                    currentTheme = themeMode,
                    onThemeChange = onThemeChange,
                    activeFingerprint = activeFingerprint,
                    onFingerprintChange = onFingerprintChange,
                    autoPauseOnWifi = autoPauseOnWifi,
                    onAutoPauseOnWifiChange = { enabled ->
                        scope.launch { settingsStore.saveAutoPauseOnWifi(enabled) }
                    },
                )
            },
        ) {
            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top),
                containerColor = Color.Transparent,
            ) { padding ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .consumeWindowInsets(padding)
                        .pointerInput(selectedTab, csqttLinkMode) {
                        var totalDrag = 0f
                        detectHorizontalDragGestures(
                            onDragStart = {
                                totalDrag = 0f
                                dragTargetIndex.intValue = -1
                                dragProgress.floatValue = 0f
                            },
                            onDragCancel = {
                                dragTargetIndex.intValue = -1
                                dragProgress.floatValue = 0f
                            },
                            onDragEnd = {
                                if (dragTargetIndex.intValue in activeNavItems.indices && shouldCommitNavigationSwipe(dragProgress.floatValue)) {
                                    selectedTab = activeNavItems[dragTargetIndex.intValue].id
                                    if (selectedTab == 4) TunnelManager.clearUnreadErrors()
                                }
                                dragTargetIndex.intValue = -1
                                dragProgress.floatValue = 0f
                            }
                        ) { change, dragAmount ->
                            change.consume()
                            totalDrag += dragAmount
                            if (abs(totalDrag) < navigationDragSlop) {
                                dragTargetIndex.intValue = -1
                                dragProgress.floatValue = 0f
                                return@detectHorizontalDragGestures
                            }

                            val currentActiveIndex = activeNavItems.indexOfFirst { it.id == selectedTab }
                            val candidate = if (totalDrag < 0f) currentActiveIndex + 1 else currentActiveIndex - 1
                            if (candidate !in activeNavItems.indices) {
                                dragTargetIndex.intValue = -1
                                dragProgress.floatValue = 0f
                                return@detectHorizontalDragGestures
                            }

                            dragTargetIndex.intValue = candidate
                            dragProgress.floatValue = navigationSwipeProgress(totalDrag, size.width)
                        }
                        }
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(bottom = navOverlayReserve),
                    ) {
                        key(selectedTab) {
                            val tab = selectedTab
                            val tabStateKey: Any = when (tab) {
                                0 -> "connection:${tunnelAuthSettings.profile}"
                                1 -> "tunnel:${tunnelAuthSettings.profile}"
                                2 -> "deploy:${deploySettings.profile}"
                                else -> tab
                            }
                            tabStateHolder.SaveableStateProvider(tabStateKey) {
                                when (tab) {
                                0 -> if (tunnelAuthSettings.isLoaded) {
                                    ConnectionTab(
                                        settingsStore = settingsStore,
                                        tunnelAuthSettings = tunnelAuthSettings,
                                        onInvalidConfiguration = {
                                            selectedTab = 1
                                            tunnelValidationRequest += 1
                                        },
                                    )
                                } else {
                                    Spacer(modifier = Modifier.fillMaxSize())
                                }
                                1 -> if (tunnelAuthSettings.isLoaded) {
                                    SettingsTab(
                                        settingsStore = settingsStore,
                                        tunnelAuthSettings = tunnelAuthSettings,
                                        validationRequest = tunnelValidationRequest,
                                        onVkAuthRequested = onVkAuthRequested,
                                    )
                                } else {
                                    Spacer(modifier = Modifier.fillMaxSize())
                                }
                                2 -> if (!csqttLinkMode) {
                                    DeployTab(settingsStore, deploySettings)
                                } else {
                                    Spacer(modifier = Modifier.fillMaxSize())
                                }
                                3 -> ExceptionsTab(
                                    settingsStore = settingsStore,
                                    savedExcluded = excludedApps,
                                    showSystemApps = showSystemApps,
                                    isWhitelist = isWhitelist,
                                )
                                4 -> LogsTab(settingsStore)
                                5 -> InfoTab(
                                    settingsStore = settingsStore,
                                    actionsExpanded = infoActionsExpanded,
                                    projectExpanded = infoProjectExpanded,
                                    onActionsToggle = {
                                        scope.launch {
                                            settingsStore.saveInfoActionsExpanded(!infoActionsExpanded)
                                        }
                                    },
                                    onProjectToggle = {
                                        scope.launch {
                                            settingsStore.saveInfoProjectExpanded(!infoProjectExpanded)
                                        }
                                    },
                                )
                                }
                            }
                        }
                    }

                    ProxyNavigationBar(
                        navItems = activeNavItems,
                        selectedTab = selectedTab,
                        dragTargetIndex = dragTargetIndex,
                        dragProgress = dragProgress,
                        unreadErrors = unreadErrors,
                        tunnelRunning = tunnelRunning,
                        onTabSelected = { index ->
                            if (selectedTab != index) {
                                view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                selectedTab = index
                                if (index == 4) TunnelManager.clearUnreadErrors()
                            }
                            dragTargetIndex.intValue = -1
                            dragProgress.floatValue = 0f
                        },
                        modifier = Modifier.align(Alignment.BottomCenter)
                    )
                }
            }
        }
    }

    pendingRelease?.let { release ->
        AppUpdateDialog(
            release = release,
            onPostpone = {
                pendingRelease = null
                context.showRaisedToast("Обновление отложено на 24 часа.", Toast.LENGTH_SHORT)
                scope.launch {
                    val now = System.currentTimeMillis()
                    settingsStore.saveUpdatePostpone(
                        version = release.versionTag,
                        until = now + 24L * 60L * 60L * 1000L
                    )
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_POSTPONED,
                        actedAt = now
                    )
                }
            },
            onUpdate = {
                pendingRelease = null
                scope.launch {
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_UPDATE,
                        actedAt = System.currentTimeMillis()
                    )
                    openReleaseUrl(context, release.releaseUrl)
                }
            }
        )
    }
}

@Composable
private fun ProxyNavigationBar(
    navItems: List<NavItem>,
    selectedTab: Int,
    dragTargetIndex: IntState,
    dragProgress: FloatState,
    unreadErrors: Int,
    tunnelRunning: Boolean,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val selectedColor = colors.onPrimary
    val unselectedColor = colors.onSurfaceVariant.copy(alpha = 0.55f)
    val indicatorShape = RoundedCornerShape(22.dp)
    val shellColor = if (isDark) {
        lerp(colors.background, colors.surface, 0.86f)
    } else {
        lerp(colors.surface, colors.surfaceVariant, 0.48f).copy(alpha = 0.95f)
    }
    val shellBorder = if (isDark) {
        colors.outlineVariant.copy(alpha = 0.42f)
    } else {
        colors.outline.copy(alpha = 0.16f)
    }
    val indicatorColor = colors.primary
    val selectedVisualIndex = remember(selectedTab, navItems) {
        navItems.indexOfFirst { it.id == selectedTab }.coerceAtLeast(0)
    }
    val indicatorIndex = remember { Animatable(selectedVisualIndex.toFloat()) }
    val isDragging = dragTargetIndex.intValue in navItems.indices
    val requestedIndicatorIndex = if (isDragging) {
        selectedVisualIndex.toFloat() +
            (dragTargetIndex.intValue - selectedVisualIndex) * dragProgress.floatValue
    } else {
        selectedVisualIndex.toFloat()
    }

    LaunchedEffect(isDragging, requestedIndicatorIndex) {
        if (isDragging) {
            indicatorIndex.snapTo(requestedIndicatorIndex)
        } else {
                indicatorIndex.animateTo(
                    targetValue = requestedIndicatorIndex,
                    animationSpec = tween(
                    durationMillis = CsqttMotion.Fast,
                    easing = CsqttMotion.StandardEasing,
                )
            )
        }
    }
    val dragVisualIndex = indicatorIndex.value

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom))
            .padding(horizontal = 22.dp, vertical = 10.dp)
    ) {
        val trackPadding = 6.dp
        val itemWidth = (maxWidth - trackPadding * 2) / navItems.size
        val indicatorOffset = trackPadding + itemWidth * dragVisualIndex

        Surface(
            shape = CsqttShapes.Card,
            color = shellColor,
            border = BorderStroke(1.dp, shellBorder),
            tonalElevation = if (isDark) 0.dp else 1.dp,
            shadowElevation = if (isDark) 4.dp else 6.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(66.dp)
            ) {
                Surface(
                    shape = indicatorShape,
                    color = indicatorColor,
                    modifier = Modifier
                        .offset(x = indicatorOffset)
                        .padding(vertical = 7.dp)
                        .width(itemWidth)
                        .fillMaxHeight()
                ) {}

                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = trackPadding, vertical = 7.dp)
                        .selectableGroup()
                ) {
                    navItems.forEachIndexed { index, item ->
                        val emphasis = (1f - abs(index - dragVisualIndex)).coerceIn(0f, 1f)
                        val iconColor = lerp(unselectedColor, selectedColor, emphasis)
                        val label = stringResource(item.labelRes)

                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(CsqttShapes.Control)
                                .selectable(
                                    selected = item.id == selectedTab,
                                    role = Role.Tab,
                                    onClick = { onTabSelected(item.id) },
                                ),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(contentAlignment = Alignment.TopEnd) {
                                Icon(
                                    imageVector = if (emphasis > 0.55f) item.selectedIcon else item.unselectedIcon,
                                    contentDescription = null,
                                    modifier = Modifier.size(22.dp),
                                    tint = iconColor
                                )
                                if (item.id == 4 && unreadErrors > 0) {
                                    Badge(
                                        containerColor = if (tunnelRunning) colors.primary else CSQTTColors.warning,
                                        contentColor = colors.onPrimary,
                                        modifier = Modifier.offset(x = 12.dp, y = (-8).dp)
                                    ) {
                                        Text("$unreadErrors")
                                    }
                                }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = label,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (emphasis > 0.55f) FontWeight.SemiBold else FontWeight.Medium,
                                color = iconColor,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun openReleaseUrl(context: Context, url: String) {
    try {
        val intent = Intent(Intent.ACTION_VIEW, url.toUri()).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        context.startActivity(intent)
    } catch (_: Exception) {
        context.showRaisedToast("Не удалось открыть ссылку", Toast.LENGTH_SHORT)
    }
}
