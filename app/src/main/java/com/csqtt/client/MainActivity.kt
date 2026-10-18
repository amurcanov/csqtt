// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.HapticFeedbackConstants
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VpnKey
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.csqtt.client.ui.AppUpdateDialog
import com.csqtt.client.ui.ConnectionTab
import com.csqtt.client.ui.DeployTab
import com.csqtt.client.ui.ExceptionsTab
import com.csqtt.client.ui.FloatingToolbar
import com.csqtt.client.ui.InfoTab
import com.csqtt.client.ui.LogsTab
import com.csqtt.client.ui.SettingsTab
import com.csqtt.client.ui.components.LocalCsqttOnBack
import com.csqtt.client.ui.components.LocalCsqttScreenTitle
import com.csqtt.client.ui.dialogs.VkAuthDialog
import com.csqtt.client.ui.utils.parseCsqttLink
import kotlin.math.abs
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val appSettingsStore by lazy { SettingsStore(applicationContext) }
    private var renderUi by mutableStateOf(false)
    private var showVkAuthDialog by mutableStateOf(false)
    private var batteryPromptInFlight = false

    private val batteryLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            batteryPromptInFlight = false
            lifecycleScope.launch {
                appSettingsStore.markBatteryOptimizationPromptHandled()
            }
        }

    private val notificationLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            checkAndRequestBattery()
        }

    companion object {
        @Volatile var activeActivities = 0
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


        enableEdgeToEdge()

        checkAndRequestNotifications()

        setContent {
            val authContext = LocalContext.current.applicationContext
            val authScope = rememberCoroutineScope()
            val uiStateHolder = rememberSaveableStateHolder()
            if (renderUi) {
                uiStateHolder.SaveableStateProvider("main_ui") {
                    val settingsStore = remember { appSettingsStore }
                    val themeMode by
                        settingsStore.themeMode.collectAsStateWithLifecycle(
                            initialValue = CsqttConstants.Theme.MODE_SYSTEM
                        )
                    val isDynamicColor by settingsStore.isDynamicColor.collectAsStateWithLifecycle(initialValue = false)
                    val themePalette by settingsStore.themePalette.collectAsStateWithLifecycle(initialValue = "indigo")
                    val scope = rememberCoroutineScope()

                    val baseDensity = LocalDensity.current
                    val fixedDensity =
                        remember(baseDensity.density) { Density(baseDensity.density, 1f) }

                    CompositionLocalProvider(LocalDensity provides fixedDensity) {
                        CSQTTTheme(themeMode = themeMode, isDynamicColor = isDynamicColor, themePalette = themePalette) {
                            Surface(
                                modifier = Modifier.fillMaxSize(),
                                color = MaterialTheme.colorScheme.background,
                            ) {
                                MainScreen(
                                    settingsStore = settingsStore,
                                    themeMode = themeMode,
                                    isDynamicColor = isDynamicColor,
                                    themePalette = themePalette,
                                    onThemeChange = { mode ->
                                        scope.launch {
                                            settingsStore.saveThemeMode(mode)
                                        }
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
                            authContext.showRaisedToast(
                                "Вечный VK access token сохранен",
                                Toast.LENGTH_SHORT,
                            )
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
            if (
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                    PackageManager.PERMISSION_GRANTED
            ) {
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
            val shouldRequest =
                shouldRequestBatteryOptimizationExemption(
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
                    )
                )
                true
            }
                .getOrDefault(false)
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

private val navItems =
    listOf(
        NavItem(
            0,
            R.string.nav_connection,
            Icons.Filled.VpnKey,
            Icons.Outlined.VpnKey,
        ),
        NavItem(4, R.string.nav_logs, Icons.Filled.Terminal, Icons.Outlined.Terminal),
        NavItem(5, R.string.nav_info, Icons.Filled.Info, Icons.Outlined.Info),
    )

internal fun navigationSwipeProgress(totalDrag: Float, containerWidth: Int): Float =
    if (containerWidth <= 0) 0f
    else (abs(totalDrag) / (containerWidth.toFloat() * 0.25f)).coerceIn(0f, 1f)

internal fun shouldCommitNavigationSwipe(progress: Float): Boolean = progress > 0.4f

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    settingsStore: SettingsStore,
    themeMode: String = CsqttConstants.Theme.MODE_SYSTEM,
    isDynamicColor: Boolean = false,
    themePalette: String = "indigo",
    onThemeChange: (String) -> Unit = {},
    onVkAuthRequested: () -> Unit = {},
) {
    val unreadErrors by TunnelManager.unreadErrorCount.collectAsStateWithLifecycle()
    val connection by TunnelManager.connection.collectAsStateWithLifecycle()
    val view = LocalView.current
    val context = LocalContext.current
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val deploySettings by
        settingsStore.deploySettingsSnapshot.collectAsStateWithLifecycle(
            initialValue = DeploySettingsSnapshot()
        )
    val tunnelAuthSettings by
        settingsStore.tunnelAuthSnapshot.collectAsStateWithLifecycle(
            initialValue = TunnelAuthSnapshot()
        )
    val csqttLinkMode by
        settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val excludedApps by settingsStore.excludedApps.collectAsStateWithLifecycle(initialValue = "")
    val showSystemApps by
        settingsStore.showSystemApps.collectAsStateWithLifecycle(initialValue = false)
    val isWhitelist by settingsStore.isWhitelist.collectAsStateWithLifecycle(initialValue = false)
    val infoActionsExpanded by
        settingsStore.infoActionsExpanded.collectAsStateWithLifecycle(initialValue = false)
    val infoProjectExpanded by
        settingsStore.infoProjectExpanded.collectAsStateWithLifecycle(initialValue = false)
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var tunnelValidationRequest by rememberSaveable { mutableIntStateOf(0) }
    // Held as State objects and read only inside ProxyNavigationBar: a swipe
    // writes these on every pointer event, and delegating reads here would
    // recompose the whole MainScreen (tabs included) per event.
    val dragTargetIndex = remember { mutableIntStateOf(-1) }
    val dragProgress = remember { mutableFloatStateOf(0f) }
    var wasEngaged by remember { mutableStateOf(connection.engaged) }
    val updateCheckIntervalHours by
        settingsStore.updateCheckIntervalHours.collectAsStateWithLifecycle(
            initialValue = DEFAULT_UPDATE_CHECK_INTERVAL_HOURS
        )
    var pendingRelease by remember { mutableStateOf<AppReleaseInfo?>(null) }
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    val safeBottomInset = with(density) { WindowInsets.safeDrawing.getBottom(density).toDp() }
    val navToolbarHeight = 68.dp
    val navToolbarBottomMargin = 24.dp
    val navContentGap = 5.dp
    val navOverlayReserve =
        safeBottomInset + navToolbarBottomMargin + navToolbarHeight + navContentGap
    val navigationDragSlop = with(density) { 6.dp.toPx() }

    val activeNavItems = navItems
    BackHandler(enabled = selectedTab in 1..3) { selectedTab = if (selectedTab == 3) 1 else 0 }
    val tabStateHolder = rememberSaveableStateHolder()
    LaunchedEffect(csqttLinkMode) {
        if (csqttLinkMode && selectedTab == 2) {
            selectedTab = 0
        }
    }

    LaunchedEffect(connection.engaged) {
        if (wasEngaged && !connection.engaged) {
            TunnelManager.startCooldown(CsqttConstants.Timeouts.VPN_PERMISSION_COOLDOWN_MS)
        }
        wasEngaged = connection.engaged
    }

    LaunchedEffect(selectedTab) {
        if (selectedTab == 4) TunnelManager.clearUnreadErrors()
    }

    LaunchedEffect(updateCheckIntervalHours) {
        if (updateCheckIntervalHours == UPDATE_CHECK_NEVER) return@LaunchedEffect

        val intervalMillis =
            updateIntervalHoursToMillis(updateCheckIntervalHours)
                ?: updateIntervalHoursToMillis(DEFAULT_UPDATE_CHECK_INTERVAL_HOURS)
                ?: 12L * 60L * 60L * 1000L

        suspend fun runUpdateCheck(reason: String) {
            val checkedAt = System.currentTimeMillis()
            val release = fetchLatestReleaseInfo(currentVersion)
            settingsStore.saveUpdateState(
                lastCheckAt = checkedAt,
                latestVersion = release?.versionTag ?: "",
                error = if (release == null) "Не удалось проверить" else "",
            )

            if (release == null) {
                Log.w(
                    "CSQTT",
                    "[WARN] Update check: no release info, local=$currentVersion reason=$reason",
                )
                return
            }

            val hasUpdate = isNewerVersion(currentVersion, release.versionTag)
            val postponeVer = settingsStore.updatePostponeVersion.first()
            val postponeUntil = settingsStore.updatePostponeUntil.first()
            val isPostponed = postponeVer == release.versionTag && checkedAt < postponeUntil
            Log.i(
                "CSQTT",
                "Update check: local=$currentVersion remote=${release.versionTag} newer=$hasUpdate postponed=$isPostponed reason=$reason",
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

        Scaffold(
            contentWindowInsets =
                WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top),
            containerColor = Color.Transparent,
        ) { padding ->
            Box(
                modifier =
                    Modifier.fillMaxSize()
                        .padding(padding)
                        .consumeWindowInsets(padding)
                        .pointerInput(selectedTab, csqttLinkMode) {
                            if (selectedTab in 1..3) return@pointerInput
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
                                    if (
                                        dragTargetIndex.intValue in activeNavItems.indices &&
                                            shouldCommitNavigationSwipe(dragProgress.floatValue)
                                    ) {
                                        selectedTab = activeNavItems[dragTargetIndex.intValue].id
                                        if (selectedTab == 4) TunnelManager.clearUnreadErrors()
                                    }
                                    dragTargetIndex.intValue = -1
                                    dragProgress.floatValue = 0f
                                },
                            ) { change, dragAmount ->
                                change.consume()
                                totalDrag += dragAmount
                                if (abs(totalDrag) < navigationDragSlop) {
                                    dragTargetIndex.intValue = -1
                                    dragProgress.floatValue = 0f
                                    return@detectHorizontalDragGestures
                                }

                                val currentActiveIndex = activeNavItems.indexOfFirst {
                                    it.id == selectedTab
                                }
                                val candidate =
                                    if (totalDrag < 0f) currentActiveIndex + 1
                                    else currentActiveIndex - 1
                                if (candidate !in activeNavItems.indices) {
                                    dragTargetIndex.intValue = -1
                                    dragProgress.floatValue = 0f
                                    return@detectHorizontalDragGestures
                                }

                                dragTargetIndex.intValue = candidate
                                dragProgress.floatValue =
                                    navigationSwipeProgress(totalDrag, size.width)
                            }
                        }
            ) {
                Box(
                    modifier =
                        Modifier.fillMaxSize()
                ) {
                    AnimatedContent(
                        targetState = selectedTab,
                        transitionSpec = {
                            val direction = when {
                                initialState == 0 && targetState == 1 -> -1
                                initialState == 1 && targetState == 0 -> 1
                                else -> if (targetState > initialState) 1 else -1
                            }
                            ((slideInHorizontally(tween(320)) { direction * it } + fadeIn(tween(260))) togetherWith
                                (slideOutHorizontally(tween(320)) { -direction * it } + fadeOut(tween(260))))
                                .using(null)
                        },
                        contentAlignment = Alignment.TopStart,
                        modifier = Modifier.fillMaxSize(),
                        label = "tab_content",
                    ) { tab ->
                        Box(
                            modifier = Modifier.fillMaxSize().padding(
                                bottom = if (tab in 1..3) safeBottomInset else navOverlayReserve
                            )
                        ) {
                            val tabStateKey: Any =
                                when (tab) {
                                    0 -> "connection:${tunnelAuthSettings.profile}"
                                    1 -> "tunnel:${tunnelAuthSettings.profile}"
                                    2 -> "deploy:${deploySettings.profile}"
                                    else -> tab
                                }
                            tabStateHolder.SaveableStateProvider(tabStateKey) {
                                CompositionLocalProvider(
                                    LocalCsqttScreenTitle provides
                                        when (tab) {
                                            1 -> "Настройки туннеля"
                                            2 -> "Установка на сервер"
                                            3 -> "Исключения для приложений"
                                            else -> null
                                        },
                                    LocalCsqttOnBack provides
                                        if (tab in 1..3) {
                                            { selectedTab = if (tab == 3) 1 else 0 }
                                        } else null,
                                ) {
                                    when (tab) {
                                        0 ->
                                            if (tunnelAuthSettings.isLoaded) {
                                                ConnectionTab(
                                                    settingsStore = settingsStore,
                                                    tunnelAuthSettings = tunnelAuthSettings,
                                                    onOpenSettings = { selectedTab = 1 },
                                                    onOpenDeploy = { selectedTab = 2 },
                                                    onInvalidConfiguration = {
                                                        selectedTab = 1
                                                        tunnelValidationRequest += 1
                                                    },
                                                )
                                            } else {
                                                Spacer(modifier = Modifier.fillMaxSize())
                                            }
                                        1 ->
                                            if (tunnelAuthSettings.isLoaded) {
                                                SettingsTab(
                                                    settingsStore = settingsStore,
                                                    tunnelAuthSettings = tunnelAuthSettings,
                                                    validationRequest = tunnelValidationRequest,
                                                    onVkAuthRequested = onVkAuthRequested,
                                                    onOpenExceptions = { selectedTab = 3 },
                                                )
                                            } else {
                                                Spacer(modifier = Modifier.fillMaxSize())
                                            }
                                        2 ->
                                            if (!csqttLinkMode) {
                                                DeployTab(settingsStore, deploySettings)
                                            } else {
                                                Spacer(modifier = Modifier.fillMaxSize())
                                            }
                                        3 ->
                                            ExceptionsTab(
                                                settingsStore = settingsStore,
                                                savedExcluded = excludedApps,
                                                showSystemApps = showSystemApps,
                                                isWhitelist = isWhitelist,
                                            )
                                        4 -> LogsTab(settingsStore)
                                        5 ->
                                            InfoTab(
                                                settingsStore = settingsStore,
                                                actionsExpanded = infoActionsExpanded,
                                                projectExpanded = infoProjectExpanded,
                                                onActionsToggle = {
                                                    scope.launch {
                                                        settingsStore.saveInfoActionsExpanded(
                                                            !infoActionsExpanded
                                                        )
                                                    }
                                                },
                                                onProjectToggle = {
                                                    scope.launch {
                                                        settingsStore.saveInfoProjectExpanded(
                                                            !infoProjectExpanded
                                                        )
                                                    }
                                                },
                                            )
                                    }
                                }
                            }
                        }
                    }
                }

                AnimatedVisibility(
                    visible = selectedTab !in 1..3,
                    enter = slideInVertically(tween(320)) { it } + fadeIn(tween(260)),
                    exit = slideOutVertically(tween(280)) { it } + fadeOut(tween(180)),
                    modifier = Modifier.align(Alignment.BottomCenter),
                ) {
                    ProxyNavigationBar(
                        navItems = activeNavItems,
                        selectedTab = if (selectedTab in 1..3) 0 else selectedTab,
                        dragTargetIndex = dragTargetIndex,
                        dragProgress = dragProgress,
                        unreadErrors = unreadErrors,
                        tunnelRunning = connection.connected,
                        onTabSelected = { index ->
                            if (selectedTab != index) {
                                view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                                selectedTab = index
                                if (index == 4) TunnelManager.clearUnreadErrors()
                            }
                            dragTargetIndex.intValue = -1
                            dragProgress.floatValue = 0f
                        },
                    )
                }
            }
        }

        FloatingToolbar(
            currentTheme = themeMode,
            onThemeChange = onThemeChange,
            isDynamicColor = isDynamicColor,
            onDynamicColorChange = { enabled -> scope.launch { settingsStore.saveDynamicColor(enabled) } },
            currentPalette = themePalette,
            onPaletteChange = { palette -> scope.launch { settingsStore.saveThemePalette(palette) } },
            modifier = Modifier.align(Alignment.TopEnd),
        )
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
                        until = now + 24L * 60L * 60L * 1000L,
                    )
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_POSTPONED,
                        actedAt = now,
                    )
                }
            },
            onUpdate = {
                pendingRelease = null
                scope.launch {
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_UPDATE,
                        actedAt = System.currentTimeMillis(),
                    )
                    openReleaseUrl(context, release.releaseUrl)
                }
            },
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
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val selectedColor = colors.primary
    val unselectedColor = colors.onSurfaceVariant.copy(alpha = 0.55f)
    val shellColor =
        if (isDark) {
            lerp(colors.surface, colors.surfaceVariant, 0.12f).copy(alpha = 0.92f)
        } else {
            lerp(colors.surface, colors.surfaceVariant, 0.30f).copy(alpha = 0.96f)
        }
    val shellBorder = colors.outlineVariant.copy(alpha = 0.30f)
    val indicatorColor = colors.primary.copy(alpha = 0.14f)
    val indicatorBorder = colors.primary.copy(alpha = 0.28f)
    val selectedVisualIndex =
        remember(selectedTab, navItems) {
            navItems.indexOfFirst { it.id == selectedTab }.coerceAtLeast(0)
        }
    val indicatorIndex = remember { Animatable(selectedVisualIndex.toFloat()) }
    val dragVisualIndex = indicatorIndex.value

    LaunchedEffect(selectedVisualIndex, dragTargetIndex.intValue, dragProgress.floatValue) {
        if (dragTargetIndex.intValue in navItems.indices) {
            val target = selectedVisualIndex.toFloat() +
                (dragTargetIndex.intValue - selectedVisualIndex) * dragProgress.floatValue
            indicatorIndex.snapTo(target)
        } else if (indicatorIndex.value != selectedVisualIndex.toFloat()) {
            indicatorIndex.animateTo(
                targetValue = selectedVisualIndex.toFloat(),
                animationSpec = tween(480, easing = CubicBezierEasing(0.2f, 0.9f, 0.24f, 1f)),
            )
        }
    }

    BoxWithConstraints(
        modifier =
            modifier
                .fillMaxWidth()
                .windowInsetsPadding(
                    WindowInsets.safeDrawing.only(
                        WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom
                    )
                )
                .padding(horizontal = 22.dp, vertical = 12.dp)
    ) {
        val trackPadding = 7.dp
        val itemWidth = (maxWidth - trackPadding * 2) / navItems.size
        val indicatorOffset = trackPadding + itemWidth * dragVisualIndex

        Surface(
            shape = RoundedCornerShape(30.dp),
            color = shellColor,
            border = BorderStroke(1.dp, shellBorder),
            tonalElevation = 0.dp,
            shadowElevation = if (isDark) 10.dp else 8.dp,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(modifier = Modifier.fillMaxWidth().height(68.dp)) {
                Surface(
                    shape = RoundedCornerShape(21.dp),
                    color = indicatorColor,
                    border = BorderStroke(1.dp, indicatorBorder),
                    modifier =
                        Modifier.offset(x = indicatorOffset)
                            .padding(vertical = 6.dp)
                            .width(itemWidth)
                            .fillMaxHeight(),
                ) {}

                Row(
                    modifier =
                        Modifier.fillMaxSize()
                            .padding(horizontal = trackPadding, vertical = 6.dp)
                            .selectableGroup()
                ) {
                    navItems.forEachIndexed { index, item ->
                        val emphasis = (1f - abs(index - dragVisualIndex)).coerceIn(0f, 1f)
                        val iconColor = lerp(unselectedColor, selectedColor, emphasis)

                        Column(
                            modifier =
                                Modifier.weight(1f)
                                    .fillMaxHeight()
                                    .clip(RoundedCornerShape(21.dp))
                                    .selectable(
                                        selected = item.id == selectedTab,
                                        role = Role.Tab,
                                        onClick = { onTabSelected(item.id) },
                                    ),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            Box(contentAlignment = Alignment.TopEnd) {
                                Icon(
                                    imageVector =
                                        if (emphasis > 0.55f) item.selectedIcon
                                        else item.unselectedIcon,
                                    contentDescription = stringResource(item.labelRes),
                                    modifier = Modifier.size(21.dp),
                                    tint = iconColor,
                                )
                                if (item.id == 4 && unreadErrors > 0) {
                                    Surface(
                                        shape = RoundedCornerShape(9.dp),
                                        color =
                                            if (tunnelRunning) colors.primary
                                            else CSQTTColors.warning,
                                        border =
                                            BorderStroke(1.dp, colors.surface.copy(alpha = 0.6f)),
                                        modifier = Modifier.offset(x = 13.dp, y = (-7).dp),
                                    ) {
                                        Text(
                                            text = "$unreadErrors",
                                            color =
                                                if (tunnelRunning) colors.onPrimary
                                                else colors.surface,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 9.sp,
                                            modifier =
                                                Modifier.padding(
                                                    horizontal = 4.5.dp,
                                                    vertical = 1.dp,
                                                ),
                                        )
                                    }
                                }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(item.labelRes),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight =
                                    if (emphasis > 0.55f) FontWeight.SemiBold
                                    else FontWeight.Medium,
                                color = iconColor,
                                maxLines = 1,
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
        val intent =
            Intent(Intent.ACTION_VIEW, url.toUri()).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
            }
        context.startActivity(intent)
    } catch (_: Exception) {
        context.showRaisedToast("Не удалось открыть ссылку", Toast.LENGTH_SHORT)
    }
}
