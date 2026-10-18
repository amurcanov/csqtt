// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui.design

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.runtime.Immutable
import androidx.compose.ui.unit.dp

@Immutable
object CsqttShapes {
    val Small = RoundedCornerShape(12.dp)
    val Control = RoundedCornerShape(16.dp)
    val Card = RoundedCornerShape(28.dp)
    val Dialog = RoundedCornerShape(28.dp)
    val Pill = RoundedCornerShape(16.dp)
}

val CsqttMaterialShapes =
    Shapes(
        extraSmall = CsqttShapes.Small,
        small = CsqttShapes.Small,
        medium = CsqttShapes.Control,
        large = CsqttShapes.Card,
        extraLarge = CsqttShapes.Dialog,
    )
