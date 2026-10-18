// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.csqtt.client.ui.components.ExpandableContent
import com.csqtt.client.ui.components.ExpansionDuration
import com.csqtt.client.R

@Composable
private fun infoTileColor(): Color {
    val palette = MaterialTheme.colorScheme
    val isDark = palette.background.luminance() < 0.22f
    return if (isDark) {
        lerp(palette.surface, palette.surfaceVariant, 0.22f)
    } else {
        lerp(palette.surface, palette.surfaceVariant, 0.42f)
    }
}

@Composable
private fun infoTileBorder(): Color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)

@Composable
private fun InfoIconTile(
    accent: Color = MaterialTheme.colorScheme.primary,
    size: androidx.compose.ui.unit.Dp = 40.dp,
    content: @Composable () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(size * 0.4f),
        color = accent.copy(alpha = 0.12f),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.22f)),
    ) {
        Box(modifier = Modifier.size(size), contentAlignment = Alignment.Center) { content() }
    }
}

@Composable
internal fun InfoHeroCard(
    currentVersion: String,
    hasUpdate: Boolean,
    updateStatus: String,
    onCryptoClick: () -> Unit,
    onSupportClick: () -> Unit,
) {
    val palette = MaterialTheme.colorScheme
    val versionColor by
        animateColorAsState(
            targetValue = if (hasUpdate) palette.primary else palette.onSurfaceVariant,
            animationSpec = tween(400),
            label = "hero_version_color",
        )

    AppSectionCard(
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = RoundedCornerShape(22.dp),
                color = palette.primary.copy(alpha = 0.10f),
                border = BorderStroke(1.dp, palette.primary.copy(alpha = 0.20f)),
                modifier = Modifier.size(62.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_c_logo),
                        contentDescription = null,
                        tint = palette.primary,
                        modifier = Modifier.size(34.dp),
                    )
                }
            }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    text = "CSQTT",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = palette.onSurface,
                )
                Text(
                    text = "QUIC · TURN",
                    style = MaterialTheme.typography.labelMedium,
                    color = palette.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = versionColor.copy(alpha = 0.10f),
                border = BorderStroke(1.dp, versionColor.copy(alpha = 0.22f)),
            ) {
                Text(
                    text = currentVersion,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = versionColor,
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Box(modifier = Modifier.size(7.dp).clip(CircleShape).background(versionColor))
            Text(
                text = updateStatus,
                style = MaterialTheme.typography.labelMedium,
                color = versionColor,
            )
        }

        Button(
            onClick = onSupportClick,
            shape = RoundedCornerShape(18.dp),
            colors =
                ButtonDefaults.buttonColors(
                    containerColor = palette.primary,
                    contentColor = palette.onPrimary,
                ),
            modifier = Modifier.fillMaxWidth().height(50.dp),
        ) {
            Icon(
                painterResource(R.drawable.ic_yoomoney),
                contentDescription = null,
                modifier = Modifier.height(24.dp),
                tint = Color.Unspecified,
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text("Поддержать", fontWeight = FontWeight.Bold, fontSize = 15.sp, maxLines = 1)
        }
        OutlinedButton(
            onClick = onCryptoClick,
            shape = RoundedCornerShape(18.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = palette.primary),
            border = BorderStroke(1.dp, palette.primary.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth().height(50.dp),
        ) {
            Icon(
                painterResource(R.drawable.ic_crypto_logo),
                contentDescription = "CRYPTO",
                tint = palette.primary,
                modifier = Modifier.height(24.dp),
            )
        }
    }
}

@Composable
internal fun ExpandableSectionCard(
    title: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    icon: @Composable () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    val arrowRotation by
        animateFloatAsState(
            targetValue = if (expanded) 180f else 0f,
            animationSpec = tween(ExpansionDuration, easing = FastOutSlowInEasing),
            label = "section_arrow_rotation",
        )

    AppSectionCard(
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp),
    ) {
        Row(
            modifier =
                Modifier.fillMaxWidth()
                    .clip(RoundedCornerShape(20.dp))
                    .clickable(onClick = onToggle)
                    .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            InfoIconTile { icon() }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.Center) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            Icon(
                imageVector = Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp).rotate(arrowRotation),
            )
        }

        ExpandableContent(
            visible = expanded,
            spacing = 12.dp,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                HorizontalDivider(
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.30f)
                )
                content()
            }
        }
    }
}

@Composable
internal fun WideActionTile(
    title: String,
    subtitle: String,
    accent: Color = MaterialTheme.colorScheme.primary,
    onClick: () -> Unit,
    icon: @Composable () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = infoTileColor(),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, infoTileBorder()),
        modifier =
            Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            InfoIconTile(accent = accent) { icon() }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 18.sp,
                )
            }

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}

@Composable
internal fun ProjectLinkRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    icon: @Composable () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = infoTileColor(),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, infoTileBorder()),
        modifier =
            Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 13.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            InfoIconTile(accent = MaterialTheme.colorScheme.primary) { icon() }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 18.sp,
                )
            }

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
