// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.design

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.runtime.Immutable
import androidx.compose.ui.unit.dp

@Immutable
object CsqttShapes {
    val Small = RoundedCornerShape(22.dp)
    val Control = RoundedCornerShape(percent = 50)
    val Card = RoundedCornerShape(34.dp)
    val LargeCard = RoundedCornerShape(42.dp)
    val Dialog = RoundedCornerShape(40.dp)
    val Pill = RoundedCornerShape(percent = 50)
}

val CsqttMaterialShapes = Shapes(
    extraSmall = CsqttShapes.Small,
    small = CsqttShapes.Small,
    medium = CsqttShapes.Control,
    large = CsqttShapes.Card,
    extraLarge = CsqttShapes.Dialog,
)
