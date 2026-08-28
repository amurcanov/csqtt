// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

enum class VkHashValidationStatus(val wireValue: String) {
    Valid("valid"),
    Invalid("invalid");

    companion object {
        fun fromWire(value: String): VkHashValidationStatus? = entries.firstOrNull {
            it.wireValue == value
        }
    }
}

object VkHashValidationCodec {
    fun decode(value: String): Map<String, VkHashValidationStatus> = runCatching {
        val json = JSONObject(value)
        buildMap {
            val keys = json.keys()
            while (keys.hasNext()) {
                val hash = keys.next()
                VkHashValidationStatus.fromWire(json.optString(hash))?.let { put(hash, it) }
            }
        }
    }.getOrDefault(emptyMap())

    fun encode(results: Map<String, VkHashValidationStatus>): String {
        val json = JSONObject()
        results.toSortedMap().forEach { (hash, status) -> json.put(hash, status.wireValue) }
        return json.toString()
    }

    fun pending(
        hashes: List<String>,
        results: Map<String, VkHashValidationStatus>,
    ): List<String> = hashes
        .filter { it.length >= 16 }
        .distinct()
        .filterNot(results::containsKey)

    fun active(
        hashes: List<String>,
        results: Map<String, VkHashValidationStatus>,
    ): List<String> = hashes
        .map(String::trim)
        .filter { it.length >= 16 }
        .distinct()
        .filter { results[it] != VkHashValidationStatus.Invalid }

    fun invalidate(
        results: Map<String, VkHashValidationStatus>,
        previousHash: String,
    ): Map<String, VkHashValidationStatus> = results - previousHash
}

object VkHashValidator {
    private const val OUTPUT_PREFIX = "HASH_CHECK:"

    suspend fun check(
        context: Context,
        hashes: List<String>,
        fingerprint: String,
        clientIds: String,
    ): Map<String, VkHashValidationStatus> = withContext(Dispatchers.IO) {
        if (hashes.isEmpty()) return@withContext emptyMap()
        val binary = File(
            context.applicationInfo.nativeLibraryDir,
            CsqttConstants.Tunnel.BINARY_NAME,
        )
        if (!binary.isFile) return@withContext emptyMap()
        val command = buildCommand(binary.absolutePath, hashes, fingerprint, clientIds)
        val process = runCatching {
            ProcessBuilder(command)
                .directory(context.filesDir)
                .redirectErrorStream(true)
                .apply {
                    environment()["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir
                }
                .start()
        }.getOrNull() ?: return@withContext emptyMap()
        val completed = runCatching { process.waitFor(75, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!completed) {
            process.destroyForcibly()
            runCatching { process.waitFor(2, TimeUnit.SECONDS) }
            return@withContext emptyMap()
        }
        val requested = hashes.toSet()
        runCatching {
            process.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.mapNotNull(::parseOutputLine)
                    .filter { it.first in requested }
                    .toMap()
            }
        }.getOrDefault(emptyMap())
    }

    internal fun buildCommand(
        binary: String,
        hashes: List<String>,
        fingerprint: String,
        clientIds: String,
    ): List<String> = buildList {
        add(binary)
        add("--validate-vk-hashes")
        add("--vk")
        add(hashes.joinToString(","))
        add("--fingerprint")
        add(fingerprint)
        add("--client-ids")
        add(clientIds)
    }

    internal fun parseOutputLine(line: String): Pair<String, VkHashValidationStatus>? {
        if (!line.startsWith(OUTPUT_PREFIX)) return null
        return runCatching {
            val json = JSONObject(line.removePrefix(OUTPUT_PREFIX))
            val hash = json.getString("hash")
            val status = VkHashValidationStatus.fromWire(json.getString("status")) ?: return null
            hash to status
        }.getOrNull()
    }
}
