// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VkHashValidatorTest {
    @Test
    fun validationResultsRoundTripThroughPersistentJson() {
        val source = mapOf(
            "valid-hash-123456" to VkHashValidationStatus.Valid,
            "invalid-hash-1234" to VkHashValidationStatus.Invalid,
        )
        assertEquals(source, VkHashValidationCodec.decode(VkHashValidationCodec.encode(source)))
    }

    @Test
    fun onlyChangedOrUncheckedHashesArePending() {
        val valid = "valid-hash-123456"
        val invalid = "invalid-hash-1234"
        val replacement = "replacement-123456"
        val checked = mapOf(
            valid to VkHashValidationStatus.Valid,
            invalid to VkHashValidationStatus.Invalid,
        )
        val afterEdit = VkHashValidationCodec.invalidate(checked, invalid)
        assertEquals(
            listOf(replacement),
            VkHashValidationCodec.pending(listOf(valid, replacement), afterEdit),
        )
        assertTrue(valid in afterEdit)
        assertFalse(invalid in afterEdit)
    }

    @Test
    fun invalidHashIsRetainedForUiButExcludedFromTunnelSource() {
        val active = "active-hash-123456"
        val invalid = "invalid-hash-1234"
        val results = mapOf(invalid to VkHashValidationStatus.Invalid)

        assertEquals(
            listOf(active),
            VkHashValidationCodec.active(listOf(active, invalid, active), results),
        )
        assertEquals(VkHashValidationStatus.Invalid, results[invalid])
    }

    @Test
    fun processOutputAcceptsOnlyFinalValidOrInvalidStates() {
        val valid = VkHashValidator.parseOutputLine(
            "HASH_CHECK:{\"hash\":\"hash-123456789012\",\"status\":\"valid\"}",
        )
        val invalid = VkHashValidator.parseOutputLine(
            "HASH_CHECK:{\"hash\":\"hash-210987654321\",\"status\":\"invalid\",\"code\":9008}",
        )
        assertEquals(VkHashValidationStatus.Valid, valid?.second)
        assertEquals(VkHashValidationStatus.Invalid, invalid?.second)
        assertNull(
            VkHashValidator.parseOutputLine(
                "HASH_CHECK:{\"hash\":\"hash-123456789012\",\"status\":\"unavailable\"}",
            ),
        )
    }

    @Test
    fun validatorModeDoesNotContainTunnelOrTurnArguments() {
        val command = VkHashValidator.buildCommand(
            "/native/libclient.so",
            listOf("hash-123456789012"),
            "firefox",
            "8202606,6287487",
        )
        assertTrue("--validate-vk-hashes" in command)
        assertTrue("--vk" in command)
        assertFalse("--peer" in command)
        assertFalse("--password" in command)
        assertFalse("--workers" in command)
    }
}
