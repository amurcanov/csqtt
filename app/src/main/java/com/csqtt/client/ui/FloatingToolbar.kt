// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import android.os.Build
import com.csqtt.client.ui.components.ExpandableContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import com.csqtt.client.ui.components.fadingVerticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.selection.selectable
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.csqtt.client.R
import com.csqtt.client.ui.dialogs.AppDialogHeader
import com.csqtt.client.ui.dialogs.AppDialogSurface
import kotlin.math.roundToInt

@Composable
fun FloatingToolbar(
    currentTheme: String,
    onThemeChange: (String) -> Unit,
    isDynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
    currentPalette: String,
    onPaletteChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val density = LocalDensity.current
    val screenHeightPx = LocalWindowInfo.current.containerSize.height.toFloat()
    var parentHeightPx by remember { mutableFloatStateOf(0f) }
    var offsetY by rememberSaveable { mutableFloatStateOf(-1f) }
    var isExpanded by rememberSaveable { mutableStateOf(false) }
    val tabHeight = 52.dp
    val tabHeightPx = with(density) { tabHeight.toPx() }
    val safeTopPx = WindowInsets.safeDrawing.getTop(density).toFloat() + with(density) { 8.dp.toPx() }
    val safeBottomPx = WindowInsets.safeDrawing.getBottom(density).toFloat() + with(density) { 8.dp.toPx() }
    val availableHeight = if (parentHeightPx > 0f) parentHeightPx else screenHeightPx
    val maxOffsetY = (availableHeight - safeBottomPx - tabHeightPx).coerceAtLeast(safeTopPx)

    LaunchedEffect(safeTopPx, maxOffsetY) {
        offsetY = if (offsetY < 0f) {
            (availableHeight * 0.24f).coerceIn(safeTopPx, maxOffsetY)
        } else {
            offsetY.coerceIn(safeTopPx, maxOffsetY)
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .onGloballyPositioned { parentHeightPx = it.size.height.toFloat() }
    ) {
        Surface(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .offset {
                    val visibleOffset = if (offsetY < 0f) availableHeight * 0.24f else offsetY
                    IntOffset(0, visibleOffset.coerceIn(safeTopPx, maxOffsetY).roundToInt())
                }
                .pointerInput(safeTopPx, maxOffsetY) {
                    detectDragGestures { change, dragAmount ->
                        change.consume()
                        offsetY = (offsetY + dragAmount.y).coerceIn(safeTopPx, maxOffsetY)
                    }
                }
                .clickable(role = Role.Button) { isExpanded = true },
            shape = RoundedCornerShape(topStart = 14.dp, bottomStart = 14.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.92f),
            shadowElevation = 0.dp,
            tonalElevation = 0.dp
        ) {
            Box(modifier = Modifier.size(42.dp, tabHeight), contentAlignment = Alignment.Center) {
                Icon(
                    painter = painterResource(R.drawable.ic_palette),
                    contentDescription = "Оформление",
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }

        if (isExpanded) {
            Dialog(
                onDismissRequest = { isExpanded = false },
                properties = DialogProperties(usePlatformDefaultWidth = false)
            ) {
                AppDialogSurface(
                    modifier = Modifier.fillMaxWidth(0.88f)
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp).fadingVerticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(0.dp)
                    ) {
                        val supportsDynamicColor = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                        val dynamicEnabled = isDynamicColor && supportsDynamicColor
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            AppDialogHeader(
                                title = "Оформление",
                                onClose = { isExpanded = false },
                                icon = {
                                    Icon(
                                        painter = painterResource(R.drawable.ic_palette),
                                        contentDescription = null,
                                        modifier = Modifier.size(20.dp),
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                }
                            )

                            ThemeOption(R.drawable.ic_auto, "Системная", currentTheme == "system") {
                                onThemeChange("system")
                            }
                            ThemeOption(R.drawable.ic_light_mode, "Светлая", currentTheme == "light") {
                                onThemeChange("light")
                            }
                            ThemeOption(R.drawable.ic_dark_mode, "Тёмная", currentTheme == "dark") {
                                onThemeChange("dark")
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Динамические цвета", style = MaterialTheme.typography.bodyMedium)
                                Switch(
                                    checked = dynamicEnabled,
                                    onCheckedChange = onDynamicColorChange,
                                    enabled = supportsDynamicColor,
                                    modifier = Modifier.scale(0.85f)
                                )
                            }
                        }
                        ExpandableContent(visible = !dynamicEnabled, spacing = 12.dp) {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                                Text("Палитра", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                                    PaletteCircle("indigo", 0xFF5B588D, currentPalette, onPaletteChange)
                                    PaletteCircle("forest", 0xFF5F5D68, currentPalette, onPaletteChange)
                                    PaletteCircle("espresso", 0xFF6D4C41, currentPalette, onPaletteChange)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ThemeOption(icon: Int, label: String, selected: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(24.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                painter = painterResource(icon),
                contentDescription = null,
                modifier = Modifier.size(18.dp),
                tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
private fun PaletteCircle(
    paletteId: String,
    colorHex: Long,
    selectedId: String,
    onClick: (String) -> Unit
) {
    Box(
        modifier = Modifier
            .size(30.dp)
            .clip(CircleShape)
            .background(Color(colorHex))
            .semantics {
                contentDescription = when (paletteId) {
                    "espresso" -> "Коричневая палитра Espresso"
                    "forest" -> "Палитра Forest"
                    else -> "Палитра Indigo"
                }
            }
            .selectable(selected = paletteId == selectedId, role = Role.RadioButton) { onClick(paletteId) }
            .then(
                if (paletteId == selectedId) Modifier.border(3.dp, MaterialTheme.colorScheme.primary, CircleShape)
                else Modifier
            )
    )
}
