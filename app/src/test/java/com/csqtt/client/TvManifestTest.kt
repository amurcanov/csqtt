package com.csqtt.client

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TvManifestTest {
    @Test
    fun `main activity is discoverable on Android TV without requiring a touchscreen`() {
        val manifest = listOf(
            File("app/src/main/AndroidManifest.xml"),
            File("src/main/AndroidManifest.xml"),
        ).first(File::isFile).readText()

        assertTrue(manifest.contains("android.intent.category.LEANBACK_LAUNCHER"))
        assertTrue(manifest.contains("android.software.leanback"))
        assertTrue(manifest.contains("android.hardware.touchscreen"))
        assertTrue(manifest.contains("android.hardware.wifi"))
        assertTrue(manifest.contains("android:banner=\"@drawable/tv_banner\""))
    }

    @Test
    fun `leanback banner is an unscaled 320 by 180 png`() {
        val banner = listOf(
            File("app/src/main/res/drawable-nodpi/tv_banner.png"),
            File("src/main/res/drawable-nodpi/tv_banner.png"),
        ).first(File::isFile)
        val bytes = banner.readBytes()

        assertTrue(bytes.size >= 24)
        assertEquals(listOf(137, 80, 78, 71, 13, 10, 26, 10), bytes.take(8).map { it.toInt() and 0xff })
        assertEquals(320, readPngInt(bytes, 16))
        assertEquals(180, readPngInt(bytes, 20))
    }

    private fun readPngInt(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 24) or
            ((bytes[offset + 1].toInt() and 0xff) shl 16) or
            ((bytes[offset + 2].toInt() and 0xff) shl 8) or
            (bytes[offset + 3].toInt() and 0xff)
}
