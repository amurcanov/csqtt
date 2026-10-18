// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.csqtt.client.ui.components.ExpandableContent
import com.csqtt.client.ui.components.ExpansionDuration
import com.csqtt.client.ui.design.CsqttShapes

data class ModeIndicator(val progress: Float, val color: Color)

@Composable
internal fun ModeProgressBar(progress: Float, color: Color, modifier: Modifier = Modifier) {
    val animatedProgress by animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        animationSpec = tween(ExpansionDuration, easing = FastOutSlowInEasing),
        label = "mode_progress",
    )
    Box(
        modifier = modifier.height(4.dp).clip(RoundedCornerShape(2.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f))
    ) {
        Box(Modifier.fillMaxHeight().fillMaxWidth(animatedProgress).background(color))
    }
}

@Composable
internal fun CompactDropdownSetting(
    title: String,
    selectedKey: String,
    options: List<Pair<String, String>>,
    enabled: Boolean,
    onSelected: (String) -> Unit,
    modifier: Modifier = Modifier,
    onTitleInfo: (() -> Unit)? = null,
    onInfo: ((String) -> Unit)? = null,
    indicatorProvider: ((String) -> ModeIndicator?)? = null,
) {
    var expanded by rememberSaveable(enabled, selectedKey) { mutableStateOf(false) }
    val selectedLabel = options.firstOrNull { it.first == selectedKey }?.second.orEmpty()
    val indicator = indicatorProvider?.invoke(selectedKey)
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded && enabled) 180f else 0f,
        animationSpec = tween(ExpansionDuration, easing = FastOutSlowInEasing),
        label = "setting_arrow",
    )
    BackHandler(enabled = expanded) { expanded = false }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 32.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f, fill = false),
            )
            if (onTitleInfo != null) {
                IconButton(onClick = onTitleInfo, modifier = Modifier.size(24.dp)) {
                    Icon(
                        Icons.AutoMirrored.Filled.HelpOutline, "Информация: $title",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
        Surface(
            shape = CsqttShapes.Control,
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
        ) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                        .semantics {
                            contentDescription = "$title: $selectedLabel"
                            stateDescription = if (expanded) "Развернуто" else "Свернуто"
                        }
                        .clickable(enabled = enabled, role = Role.Button) { expanded = !expanded }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            selectedLabel, style = MaterialTheme.typography.bodyMedium,
                            maxLines = 2, overflow = TextOverflow.Ellipsis,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = if (enabled) 1f else 0.45f),
                        )
                        indicator?.let { ModeProgressBar(it.progress, it.color, Modifier.fillMaxWidth()) }
                    }
                    Icon(
                        Icons.Default.KeyboardArrowDown, null,
                        modifier = Modifier.size(20.dp).rotate(arrowRotation),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                ExpandableContent(visible = expanded && enabled) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                    Column(modifier = Modifier.selectableGroup()) {
                        options.forEach { (key, label) ->
                            val itemIndicator = indicatorProvider?.invoke(key)
                            Row(
                                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                                    .selectable(selected = key == selectedKey, enabled = expanded && enabled, role = Role.RadioButton) {
                                        expanded = false
                                        onSelected(key)
                                    }
                                    .padding(start = 12.dp, end = 6.dp, top = 8.dp, bottom = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(label, style = MaterialTheme.typography.bodyMedium)
                                    itemIndicator?.let { ModeProgressBar(it.progress, it.color, Modifier.fillMaxWidth()) }
                                }
                                onInfo?.let { showInfo ->
                                    IconButton(
                                        onClick = { showInfo(key) }, enabled = expanded && enabled, modifier = Modifier.size(28.dp),
                                    ) {
                                        Icon(
                                            Icons.AutoMirrored.Filled.HelpOutline, "Информация: $label",
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(17.dp),
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
