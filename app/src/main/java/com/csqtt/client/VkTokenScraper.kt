// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

internal object VkTokenScraper {
    suspend fun scrape(cookies: String, userAgent: String): Result<VkAuthPayload> = withContext(Dispatchers.IO) {
        var endpoint = "https://oauth.vk.com/authorize?client_id=7793118&display=mobile&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&response_type=token&scope=1073737727&v=5.199&revoke=1"
        
        val jsLocationRegex = Regex("location\\.href\\s*=\\s*[\"']([^\"']+)[\"']")
        val oauthGrantRegex = Regex("(https://login\\.vk\\.(?:com|ru)/\\?act=grant_access[^\"'\\s<]+)")

        var hopsRemaining = CsqttConstants.VkAutoHash.MAX_OAUTH_HOPS
        
        try {
            while (hopsRemaining-- > 0) {
                val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                    instanceFollowRedirects = false
                    requestMethod = "GET"
                    setRequestProperty("Cookie", cookies)
                    setRequestProperty("User-Agent", userAgent)
                    setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    connectTimeout = 15000
                    readTimeout = 15000
                }

                val code = connection.responseCode

                if (code == HttpURLConnection.HTTP_MOVED_TEMP || code == HttpURLConnection.HTTP_MOVED_PERM || code == HttpURLConnection.HTTP_SEE_OTHER) {
                    val nextLocation = connection.getHeaderField("Location") ?: break
                    val payload = parseFragment(nextLocation)
                    if (payload != null) return@withContext Result.success(payload)
                    endpoint = nextLocation
                    continue
                }

                if (code == HttpURLConnection.HTTP_OK) {
                    val htmlContent = connection.inputStream.bufferedReader().use { it.readText() }

                    val matchJs = jsLocationRegex.find(htmlContent)
                    if (matchJs != null) {
                        val scriptTarget = matchJs.groupValues[1]
                        val payload = parseFragment(scriptTarget)
                        if (payload != null) return@withContext Result.success(payload)
                        endpoint = scriptTarget
                        continue
                    }

                    val matchGrant = oauthGrantRegex.find(htmlContent)
                    if (matchGrant != null) {
                        endpoint = matchGrant.groupValues[1].replace("&amp;", "&")
                        continue
                    }
                    
                    return@withContext Result.failure(IllegalStateException("No redirection found in HTML output"))
                }
                
                break
            }
            Result.failure(IllegalStateException("Too many redirects: max hops exceeded"))
        } catch (t: Throwable) {
            Result.failure(t)
        }
    }

    private fun parseFragment(urlStr: String): VkAuthPayload? {
        if (!urlStr.contains("access_token=")) return null
        
        val fragmentPart = try {
            urlStr.toUri().encodedFragment ?: urlStr.substringAfter("#", "").ifEmpty { urlStr.substringAfter("?", "") }
        } catch (e: Exception) {
            urlStr.substringAfter("#", "").ifEmpty { urlStr.substringAfter("?", "") }
        }

        val params = fragmentPart.split("&").associate { 
            val parts = it.split("=", limit = 2)
            parts[0] to parts.getOrElse(1) { "" }
        }

        val tokenVal = params["access_token"]
        if (!tokenVal.isNullOrBlank()) {
            return VkAuthPayload(
                token = tokenVal,
                userId = params["user_id"].orEmpty(),
                expiresIn = params["expires_in"]?.toLongOrNull() ?: 0L
            )
        }
        return null
    }
}
