// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.csqtt.client.R
import com.csqtt.client.SettingsStore
import com.csqtt.client.TunnelManager
import com.csqtt.client.ui.components.CsqttEmptyState
import com.csqtt.client.ui.components.CsqttLoadingState
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.components.CsqttSegmentedControl
import com.csqtt.client.ui.components.CsqttSettingRow
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes
import com.csqtt.client.ui.design.CsqttSpacing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


private object AppCache {
    @Volatile
    var cachedList: List<AppItem>? = null
}

private enum class RoutingMode { ExcludeSelected, IncludeSelected }

@Composable
fun ExceptionsTab(
    settingsStore: SettingsStore,
    savedExcluded: String,
    showSystemApps: Boolean,
    isWhitelist: Boolean,
) {
    val context = LocalContext.current.applicationContext
    val focusManager = LocalFocusManager.current
    val scope = rememberCoroutineScope()
    // Taps edit a local draft; the DataStore write (and VPN reload) is
    // debounced so a burst of toggles costs one persist instead of one per tap.
    val persistedSelection = remember(savedExcluded) {
        savedExcluded.split(',').filter(String::isNotBlank).toSet()
    }
    var selectedPackages by remember { mutableStateOf(persistedSelection) }
    var lastSavedSelection by remember { mutableStateOf(persistedSelection) }
    var saveJob by remember { mutableStateOf<Job?>(null) }

    // Adopt persisted changes only when they came from outside (profile switch,
    // another screen): our own writes set lastSavedSelection first, so the
    // echo of our save never resets a draft that already moved past it.
    LaunchedEffect(persistedSelection) {
        if (persistedSelection != lastSavedSelection) {
            selectedPackages = persistedSelection
        }
        lastSavedSelection = persistedSelection
    }
    var appsList by remember { mutableStateOf(AppCache.cachedList.orEmpty()) }
    var isLoading by remember { mutableStateOf(AppCache.cachedList == null) }
    var isMigrationReady by rememberSaveable { mutableStateOf(false) }
    var searchQuery by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) { settingsStore.migrateLegacyWhitelistMode() }
        isMigrationReady = true

        AppCache.cachedList?.let {
            appsList = it
            isLoading = false
            return@LaunchedEffect
        }

        isLoading = true
        val loadedApps = withContext(Dispatchers.IO) {
            val packageManager = context.packageManager
            packageManager
                .getInstalledApplications(PackageManager.GET_META_DATA)
                .asSequence()
                .filter { app ->
                    app.packageName != context.packageName &&
                        !app.packageName.contains("vkontakte") &&
                        !app.packageName.contains("vk.calls")
                }
                .map { app ->
                    AppItem(
                        name = app.loadLabel(packageManager).toString(),
                        packageName = app.packageName,
                        icon = runCatching { app.loadIcon(packageManager).toBitmap().asImageBitmap() }.getOrNull(),
                        isSystem = (app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                    )
                }
                .sortedBy { it.name.lowercase() }
                .toList()
        }
        AppCache.cachedList = loadedApps
        appsList = loadedApps
        isLoading = false
    }

    val filteredApps = remember(appsList, showSystemApps, searchQuery) {
        val visibleApps = if (showSystemApps) {
            appsList
        } else {
            appsList.filter {
                !it.isSystem || it.packageName == "com.google.android.youtube" || it.packageName == "com.android.vending"
            }
        }
        if (searchQuery.isBlank()) {
            visibleApps
        } else {
            visibleApps.filter {
                it.name.contains(searchQuery, ignoreCase = true) ||
                    it.packageName.contains(searchQuery, ignoreCase = true)
            }
        }
    }
    val listState = rememberLazyListState()
    val routingMode = if (isWhitelist) RoutingMode.IncludeSelected else RoutingMode.ExcludeSelected

    fun persistSelection(selection: Set<String>) {
        lastSavedSelection = selection
        saveJob?.cancel()
        saveJob = scope.launch {
            delay(250)
            settingsStore.saveExcludedApps(selection.sorted().joinToString(","))
            TunnelManager.reloadVpn()
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            // A burst still inside the debounce window must not be lost when
            // the tab closes right after the last tap.
            saveJob?.cancel()
            val pending = selectedPackages
            if (pending != persistedSelection) {
                CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                    settingsStore.saveExcludedApps(pending.sorted().joinToString(","))
                    TunnelManager.reloadVpn()
                }
            }
        }
    }

    CsqttScreen {
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            label = {
                Text(
                    stringResource(R.string.exceptions_search_label),
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            placeholder = {
                Text(
                    stringResource(R.string.exceptions_search_placeholder),
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { focusManager.clearFocus() }),
            shape = CsqttShapes.Control,
            modifier = Modifier.fillMaxWidth(),
        )

        AppSectionCard(
            contentPadding = PaddingValues(horizontal = CsqttSpacing.Md, vertical = CsqttSpacing.Sm),
            verticalArrangement = Arrangement.spacedBy(CsqttSpacing.Sm),
        ) {
            CsqttSegmentedControl(
                options = listOf(
                    RoutingMode.ExcludeSelected to stringResource(R.string.exceptions_mode_exclude),
                    RoutingMode.IncludeSelected to stringResource(R.string.exceptions_mode_include),
                ),
                selected = routingMode,
                enabled = isMigrationReady,
                onSelected = { mode ->
                    if (mode == routingMode) return@CsqttSegmentedControl
                    scope.launch {
                        settingsStore.saveExceptionsMode(
                            selectedPackages.sorted().joinToString(","),
                            mode == RoutingMode.IncludeSelected,
                        )
                        delay(300)
                        TunnelManager.reloadVpn()
                    }
                },
            )
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
            CsqttSettingRow(
                title = stringResource(R.string.exceptions_system_apps),
                checked = showSystemApps,
                onCheckedChange = { enabled ->
                    scope.launch { settingsStore.saveShowSystemApps(enabled) }
                },
            )
        }

        Text(
            text = stringResource(R.string.exceptions_selected_count, selectedPackages.size),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        when {
            !isMigrationReady || isLoading -> {
                Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CsqttLoadingState(label = stringResource(R.string.exceptions_loading))
                }
            }

            filteredApps.isEmpty() -> {
                Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CsqttEmptyState(
                        title = stringResource(R.string.exceptions_empty_title),
                        description = stringResource(R.string.exceptions_empty_description),
                        icon = Icons.Outlined.Apps,
                    )
                }
            }

            else -> {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    contentPadding = PaddingValues(bottom = CsqttSizes.ScreenBottomPadding),
                    verticalArrangement = Arrangement.spacedBy(CsqttSpacing.Xs),
                ) {
                    items(
                        items = filteredApps,
                        key = { it.packageName },
                        contentType = { "application" },
                    ) { app ->
                        val isSelected = app.packageName in selectedPackages
                        AppRow(
                            app = app,
                            isSelected = isSelected,
                            onClick = {
                                val newSelection = if (isSelected) {
                                    selectedPackages - app.packageName
                                } else {
                                    selectedPackages + app.packageName
                                }
                                selectedPackages = newSelection
                                persistSelection(newSelection)
                            },
                        )
                    }
                }
            }
        }
    }
}
