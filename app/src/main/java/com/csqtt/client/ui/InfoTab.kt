// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Update
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.BuildConfig
import com.csqtt.client.CsqttConstants
import com.csqtt.client.R
import com.csqtt.client.SettingsStore
import com.csqtt.client.UPDATE_DIALOG_ACTION_POSTPONED
import com.csqtt.client.UPDATE_DIALOG_ACTION_UPDATE
import com.csqtt.client.fetchLatestReleaseInfo
import com.csqtt.client.isNewerVersion
import com.csqtt.client.showRaisedToast
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.dialogs.CryptoDonateDialog
import kotlinx.coroutines.launch

private const val ReleasesUrl = CsqttConstants.Links.RELEASES
private const val IssuesUrl = CsqttConstants.Links.ISSUES
private const val DeveloperProfileUrl = CsqttConstants.Links.DEVELOPER_PROFILE
private const val RepositoryUrl = CsqttConstants.Links.REPOSITORY
private const val DonateUrl = CsqttConstants.Links.DONATE

private val browserPackages =
    listOf(
        "com.android.chrome",
        "com.google.android.googlequicksearchbox",
        "org.mozilla.firefox",
        "com.yandex.browser",
        "ru.yandex.searchplugin",
        "com.yandex.browser.lite",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.microsoft.emmx",
        "com.brave.browser",
        "com.duckduckgo.mobile.android",
        "com.sec.android.app.sbrowser",
        "com.vivaldi.browser",
        "com.kiwibrowser.browser",
    )

private fun openUrlInBrowser(context: Context, url: String) {
    try {
        val pm = context.packageManager
        val uri = url.toUri()
        for (pkg in browserPackages) {
            val intent =
                Intent(Intent.ACTION_VIEW, uri).apply {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                    setPackage(pkg)
                }
            if (intent.resolveActivity(pm) != null) {
                context.startActivity(intent)
                return
            }
        }
        val intent =
            Intent(Intent.ACTION_VIEW, uri).apply { addCategory(Intent.CATEGORY_BROWSABLE) }
        if (intent.resolveActivity(pm) != null) context.startActivity(intent)
    } catch (error: Exception) {
        Log.w("CSQTT", "Не удалось открыть ссылку: $url", error)
        context.showRaisedToast("Не удалось открыть ссылку", Toast.LENGTH_SHORT)
    }
}

@Composable
fun InfoTab(
    settingsStore: SettingsStore,
    actionsExpanded: Boolean,
    projectExpanded: Boolean,
    onActionsToggle: () -> Unit,
    onProjectToggle: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    var isCheckingUpdates by remember { mutableStateOf(false) }
    var pendingManualRelease by remember { mutableStateOf<com.csqtt.client.AppReleaseInfo?>(null) }
    var showCryptoDialog by remember { mutableStateOf(false) }
    val updateLatestVersion by
        settingsStore.updateLatestVersion.collectAsStateWithLifecycle(initialValue = "")
    val updateLastError by
        settingsStore.updateLastError.collectAsStateWithLifecycle(initialValue = "")
    val hasUpdate = updateLatestVersion.isNotBlank() &&
        isNewerVersion(currentVersion, updateLatestVersion)
    val updateStatus =
        remember(isCheckingUpdates, hasUpdate, updateLatestVersion, updateLastError) {
            when {
                isCheckingUpdates -> "Проверяем GitHub releases..."
                updateLastError.isNotBlank() -> "Последняя проверка завершилась ошибкой"
                hasUpdate -> "На GitHub доступна версия $updateLatestVersion"
                updateLatestVersion.isNotBlank() -> "Приложение актуально"
                else -> "Обновления ещё не проверены"
            }
        }

    CsqttScreen {
        Column(
            modifier =
                Modifier.fillMaxSize()
                    .fillMaxWidth()
                    .padding(top = 16.dp, bottom = 12.dp)
                    .fadingVerticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            InfoHeroCard(
                currentVersion = currentVersion,
                hasUpdate = hasUpdate,
                updateStatus = updateStatus,
                onSupportClick = { openUrlInBrowser(context, DonateUrl) },
                onCryptoClick = { showCryptoDialog = true },
            )

            ExpandableSectionCard(
                title = "Действия",
                expanded = actionsExpanded,
                onToggle = onActionsToggle,
                icon = {
                    Icon(
                        imageVector = Icons.Outlined.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                },
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    WideActionTile(
                        title = "Поднять вопрос",
                        subtitle = "Открыть GitHub issue",
                        onClick = { openUrlInBrowser(context, IssuesUrl) },
                        icon = {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_github),
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        },
                    )

                    WideActionTile(
                        title = "Собрать отчёт",
                        subtitle = "Android, ABI, версия, устройство",
                        onClick = {
                            val clipboard = context.getSystemService(ClipboardManager::class.java)
                            clipboard?.setPrimaryClip(
                                ClipData.newPlainText("CSQTT Report", buildSupportReport())
                            )
                            context.showRaisedToast(
                                "Отчёт сформирован и скопирован",
                                Toast.LENGTH_SHORT,
                            )
                        },
                        icon = {
                            Icon(
                                imageVector = Icons.Outlined.ContentCopy,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        },
                    )
                }

                WideActionTile(
                    title = "Проверить обновления",
                    subtitle = updateStatus,
                    onClick = {
                        if (isCheckingUpdates) return@WideActionTile
                        isCheckingUpdates = true
                        scope.launch {
                            val checkedAt = System.currentTimeMillis()
                            val release = fetchLatestReleaseInfo(currentVersion)
                            val latest = release?.versionTag
                            settingsStore.saveUpdateState(
                                lastCheckAt = checkedAt,
                                latestVersion = latest ?: "",
                                error = if (release == null) "Не удалось проверить" else "",
                            )
                            isCheckingUpdates = false

                            if (release == null) {
                                val message =
                                    if (updateLatestVersion.isNotBlank()) {
                                        "Не удалось проверить. Последняя известная версия: $updateLatestVersion"
                                    } else {
                                        "Не удалось проверить обновления"
                                    }
                                context.showRaisedToast(message, Toast.LENGTH_SHORT)
                                return@launch
                            }

                            if (isNewerVersion(currentVersion, release.versionTag)) {
                                settingsStore.saveUpdateDialogShown(release.versionTag, checkedAt)
                                pendingManualRelease = release
                            } else {
                                Toast.makeText(
                                        context,
                                        "У вас уже последняя версия: ${release.versionTag}",
                                        Toast.LENGTH_SHORT,
                                    )
                                    .show()
                            }
                        }
                    },
                    icon = {
                        Icon(
                            imageVector = Icons.Outlined.Update,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    },
                )
            }

            pendingManualRelease?.let { release ->
                AppUpdateDialog(
                    release = release,
                    onPostpone = {
                        pendingManualRelease = null
                        context.showRaisedToast(
                            "Обновление отложено на 24 часа.",
                            Toast.LENGTH_SHORT,
                        )
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
                        pendingManualRelease = null
                        scope.launch {
                            settingsStore.saveUpdateDialogAction(
                                version = release.versionTag,
                                action = UPDATE_DIALOG_ACTION_UPDATE,
                                actedAt = System.currentTimeMillis(),
                            )
                            openUrlInBrowser(context, release.releaseUrl)
                        }
                    },
                )
            }

            if (showCryptoDialog) {
                CryptoDonateDialog(onDismiss = { showCryptoDialog = false })
            }

            ExpandableSectionCard(
                title = "О проекте",
                expanded = projectExpanded,
                onToggle = onProjectToggle,
                icon = {
                    Icon(
                        imageVector = Icons.Outlined.Code,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                },
            ) {
                ProjectLinkRow(
                    title = "Автор Android-версии",
                    subtitle = "GitHub профиль amurcanov",
                    onClick = { openUrlInBrowser(context, DeveloperProfileUrl) },
                    icon = {
                        Icon(
                            imageVector = Icons.Outlined.Person,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )

                ProjectLinkRow(
                    title = "Репозиторий CSQTT",
                    subtitle = "Исходники и релизы приложения",
                    onClick = { openUrlInBrowser(context, RepositoryUrl) },
                    icon = {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_github),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )

                ProjectLinkRow(
                    title = "Актуальные релизы",
                    subtitle = "Страница загрузки APK",
                    onClick = { openUrlInBrowser(context, ReleasesUrl) },
                    icon = {
                        Icon(
                            imageVector = Icons.Outlined.Update,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}
