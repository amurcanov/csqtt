// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.KeyEvent
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.core.net.toUri
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.URLDecoder

internal data class VkAuthPayload(
    val token: String,
    val userId: String,
    val expiresIn: Long,
)

internal enum class VkAuthPhase { LOGIN, TOKEN }

internal object VkAuthWebViewManager {
    private val mainHandler = Handler(Looper.getMainLooper())

    fun acquire(context: Context): WebView = createWebView(context)

    fun clearVkSessionCookies() {
        mainHandler.post {
            runCatching {
                val manager = CookieManager.getInstance()
                manager.removeAllCookies(null)
                manager.flush()
            }
        }
    }

    fun release(view: WebView) {
        mainHandler.post {
            runCatching { CookieManager.getInstance().flush() }
            runCatching {
                (view.parent as? ViewGroup)?.removeView(view)
                view.stopLoading()
                view.webViewClient = WebViewClient()
                view.loadUrl("about:blank")
                view.clearHistory()
                view.destroy()
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun createWebView(context: Context): WebView {
        val view = WebView(context)
        view.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            javaScriptCanOpenWindowsAutomatically = true
            useWideViewPort = true
            loadWithOverviewMode = true
            setSupportZoom(false)
            builtInZoomControls = false
        }
        if (TvDevicePolicy.isTelevision(context)) {
            configureTelevisionInput(view)
        }
        runCatching {
            CookieManager.getInstance().setAcceptCookie(true)
            CookieManager.getInstance().setAcceptThirdPartyCookies(view, true)
        }
        return view
    }

    private fun configureTelevisionInput(view: WebView) {
        view.isFocusable = true
        view.isFocusableInTouchMode = false
        view.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) {
                view.post { view.evaluateJavascript(TV_FOCUS_FIRST_ELEMENT_JS, null) }
            }
        }
        view.setOnKeyListener { _, keyCode, event ->
            if (event.action != KeyEvent.ACTION_DOWN) return@setOnKeyListener false
            val command = when (keyCode) {
                KeyEvent.KEYCODE_DPAD_UP, KeyEvent.KEYCODE_DPAD_LEFT -> "previous"
                KeyEvent.KEYCODE_DPAD_DOWN, KeyEvent.KEYCODE_DPAD_RIGHT -> "next"
                KeyEvent.KEYCODE_DPAD_CENTER,
                KeyEvent.KEYCODE_ENTER,
                KeyEvent.KEYCODE_NUMPAD_ENTER -> "activate"
                else -> null
            } ?: return@setOnKeyListener false

            view.evaluateJavascript("window.__csqttTvInput && window.__csqttTvInput('$command');", null)
            true
        }
        view.post { view.requestFocus() }
    }

    private const val TV_FOCUS_FIRST_ELEMENT_JS = """
        (function() {
          if (window.__csqttTvInput) {
            window.__csqttTvInput('ensure-focus');
            return;
          }
          var selector = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[tabindex]:not([tabindex="-1"])';
          function elements() {
            return Array.prototype.filter.call(document.querySelectorAll(selector), function(node) {
              var style = window.getComputedStyle(node);
              return !node.disabled && style.display !== 'none' && style.visibility !== 'hidden' && node.getClientRects().length > 0;
            });
          }
          function focus(node) {
            if (!node) return false;
            node.focus({preventScroll: true});
            node.scrollIntoView({block: 'center', inline: 'nearest'});
            return true;
          }
          window.__csqttTvInput = function(command) {
            var items = elements();
            var active = document.activeElement;
            var index = items.indexOf(active);
            if (command === 'ensure-focus') {
              return index >= 0 || focus(items[0]);
            }
            if (command === 'next' || command === 'previous') {
              if (!items.length) return false;
              var direction = command === 'next' ? 1 : -1;
              var next = index < 0 ? (direction > 0 ? 0 : items.length - 1) : (index + direction + items.length) % items.length;
              return focus(items[next]);
            }
            if (command === 'activate') {
              if (index < 0 && !focus(items[0])) return false;
              active = document.activeElement;
              if (!active) return false;
              if (active.matches('button,a[href],input[type=button],input[type=submit],input[type=checkbox],input[type=radio],[role=button]')) {
                active.click();
                return true;
              }
              active.click();
              return true;
            }
            return false;
          };
          window.__csqttTvInput('ensure-focus');
        })();
    """
}

@SuppressLint("SetJavaScriptEnabled")
internal class VkAuthSession(
    private val onUiReady: () -> Unit,
    private val onToken: (VkAuthPayload) -> Unit,
    private val onError: (String) -> Unit,
    private val onPhaseChange: (VkAuthPhase) -> Unit = {},
) {
    private val mainHandler = Handler(Looper.getMainLooper())

    private var webView: WebView? = null
    private var finished = false
    private var silentRetried = false
    private var nonPermanentRetried = false
    private var lastUrl: String? = null
    private var startedAt = 0L
    private var pausedAt = 0L
    private var uiReadyReported = false
    private var phase = VkAuthPhase.LOGIN
    private var paused = false
    private var pendingAuthorizationRetry = false

    fun attach(view: WebView) {
        webView = view
        startedAt = System.currentTimeMillis()
        view.webViewClient = object : WebViewClient() {
            override fun onPageFinished(v: WebView, url: String) {
                installTelevisionNavigation(v)
                if (!uiReadyReported) {
                    uiReadyReported = true
                    onUiReady()
                }
            }

            override fun onPageCommitVisible(v: WebView, url: String) {
                installTelevisionNavigation(v)
                if (!uiReadyReported) {
                    uiReadyReported = true
                    onUiReady()
                }
            }

            override fun shouldOverrideUrlLoading(v: WebView, request: WebResourceRequest): Boolean {
                val path = request.url.path ?: ""
                if (phase == VkAuthPhase.LOGIN && (path.startsWith("/feed") || isVkLoggedIn())) {
                    switchToTokenPhase(v)
                    return true
                }
                return false
            }
            override fun shouldInterceptRequest(v: WebView, request: WebResourceRequest): WebResourceResponse? {
                val uri = request.url
                if (uri.lastPathSegment == "blank.html") {
                    return WebResourceResponse(
                        "text/html",
                        "utf-8",
                        200,
                        "OK",
                        mapOf("Cache-Control" to "no-store"),
                        ByteArrayInputStream(TOKEN_WAITING_HTML.toByteArray(Charsets.UTF_8)),
                    )
                }
                return null
            }

            override fun onReceivedError(v: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (!request.isForMainFrame) return
                if (finished) return
                finishWithError("Не удалось открыть страницу авторизации VK — проверьте интернет")
            }
        }

        if (view.progress == 100 && !uiReadyReported) {
            uiReadyReported = true
            onUiReady()
        }

        if (isVkLoggedIn()) {
            switchToTokenPhase(view)
        } else {
            phase = VkAuthPhase.LOGIN
            onPhaseChange(phase)
            if (view.url.isNullOrBlank() || view.url == "about:blank") {
                view.loadUrl(CsqttConstants.VkAutoHash.VK_LOGIN_URL)
            }
        }
        scheduleMonitor()
    }

    fun stop() {
        finished = true
        mainHandler.removeCallbacksAndMessages(null)
        webView = null
    }

    fun pause() {
        if (finished || paused) return
        paused = true
        pausedAt = System.currentTimeMillis()
        mainHandler.removeCallbacks(monitorTick)
        webView?.onPause()
    }

    fun resume() {
        if (finished || !paused) return
        val resumedAt = System.currentTimeMillis()
        if (pausedAt != 0L) {
            startedAt += (resumedAt - pausedAt).coerceAtLeast(0L)
            pausedAt = 0L
        }
        paused = false
        webView?.onResume()
        if (pendingAuthorizationRetry) {
            pendingAuthorizationRetry = false
            repeatAuthorization()
        }
        scheduleMonitor()
    }

    private fun scheduleMonitor() {
        mainHandler.removeCallbacks(monitorTick)
        if (!finished && !paused) {
            mainHandler.postDelayed(monitorTick, CsqttConstants.VkAutoHash.AUTH_MONITOR_INTERVAL_MS)
        }
    }

    private fun installTelevisionNavigation(view: WebView) {
        if (TvDevicePolicy.isTelevision(view.context)) {
            view.evaluateJavascript(TV_FOCUS_FIRST_ELEMENT_JS, null)
            view.post { view.requestFocus() }
        }
    }

    private fun switchToTokenPhase(view: WebView) {
        phase = VkAuthPhase.TOKEN
        onPhaseChange(phase)
        lastUrl = null
        view.stopLoading()
        view.loadDataWithBaseURL(null, TOKEN_WAITING_HTML, "text/html", "UTF-8", null)

        val context = view.context.applicationContext
        val cookieManager = CookieManager.getInstance()
        val cookies = StringBuilder()
        val domains = listOf(
            "https://vk.com/", "https://vk.ru/", "https://id.vk.ru/", "https://id.vk.com/",
            "https://login.vk.com/", "https://login.vk.ru/", "https://m.vk.com/", "https://m.vk.ru/"
        )
        domains.forEach { domain ->
            val domainCookies = runCatching { cookieManager.getCookie(domain) }.getOrNull()
            if (!domainCookies.isNullOrBlank()) {
                if (cookies.isNotEmpty()) cookies.append("; ")
                cookies.append(domainCookies)
            }
        }
        
        val cookieString = cookies.toString()
        val userAgent = view.settings.userAgentString ?: "Mozilla/5.0 (Linux; Android 13; Mobile)"

        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
            if (finished) return@launch
            
            val result = VkTokenScraper.scrape(cookieString, userAgent)
            
            mainHandler.post {
                if (finished) return@post
                
                result.fold(
                    onSuccess = { payload ->
                        finished = true
                        mainHandler.removeCallbacksAndMessages(null)
                        runCatching { CookieManager.getInstance().flush() }
                        onToken(payload)
                    },
                    onFailure = {
                        repeatAuthorization()
                    }
                )
            }
        }
    }

    private fun isVkLoggedIn(): Boolean {
        val manager = CookieManager.getInstance()
        val domains = listOf(
            "https://vk.com/", "https://vk.ru/", "https://id.vk.ru/", "https://id.vk.com/",
            "https://login.vk.com/", "https://login.vk.ru/", "https://m.vk.com/", "https://m.vk.ru/"
        )
        return domains.any { domain ->
            runCatching { manager.getCookie(domain) }.getOrNull()?.contains("remixsid") == true
        }
    }

    private val monitorTick = object : Runnable {
        override fun run() {
            if (finished || paused) return
            val view = webView
            if (view == null) {
                stop()
                return
            }
            if (System.currentTimeMillis() - startedAt > CsqttConstants.VkAutoHash.AUTH_TIMEOUT_MS) {
                finishWithError("Тайм-аут ожидания access_token")
                return
            }

            when (phase) {
                VkAuthPhase.LOGIN -> {
                    if (isVkLoggedIn()) {
                        switchToTokenPhase(view)
                    } else {
                        val currentUrl = view.url.orEmpty()
                        val path = runCatching { currentUrl.toUri().path }.getOrNull() ?: ""
                        if (path.startsWith("/feed")) {
                            switchToTokenPhase(view)
                        } else {
                            view.evaluateJavascript(
                                "(function() { return document.body && (document.body.innerText.includes('Мессенджер') || document.body.innerText.includes('Лента')); })();"
                            ) { result ->
                                if (result == "true" && phase == VkAuthPhase.LOGIN) {
                                    switchToTokenPhase(view)
                                }
                            }
                        }
                    }
                }
                VkAuthPhase.TOKEN -> {
                    val url = view.url.orEmpty()
                    if (url != lastUrl && url.isNotBlank()) {
                        lastUrl = url
                        handleUrl(url)
                    }
                }
            }

            scheduleMonitor()
        }
    }

    private fun handleUrl(url: String) {
        val uri = runCatching { url.toUri() }.getOrNull() ?: return
        val fragment = uri.fragment ?: return
        when {
            fragment.contains("access_token=") -> handleAccessToken(fragment)
            fragment.startsWith("payload=") -> {
                val host = uri.host.orEmpty()
                if (host == "oauth.vk.com" || host == "oauth.vk.ru" || host == "vkhost.github.io") {
                    handleSilentPayload(fragment)
                }
            }
            fragment.contains("error=") -> handleOAuthError(fragment)
        }
    }

    private fun handleAccessToken(fragment: String) {
        val params = parseFragmentParams(fragment)
        val token = params["access_token"]
        if (token.isNullOrBlank()) {
            finishWithError("Не удалось извлечь access_token из URL")
            return
        }
        val expiresIn = params["expires_in"]?.toLongOrNull() ?: 0L
        if (expiresIn == 0L) {
            finished = true
            mainHandler.removeCallbacksAndMessages(null)
            runCatching { CookieManager.getInstance().flush() }
            onToken(VkAuthPayload(token = token, userId = params["user_id"].orEmpty(), expiresIn = 0L))
        } else if (!nonPermanentRetried) {
            nonPermanentRetried = true
            repeatAuthorization()
        } else {
            finishWithError("VK выдал токен с ограниченным сроком действия. Попробуйте еще раз.")
        }
    }

    private fun handleSilentPayload(fragment: String) {
        if (silentRetried) return
        val payload = runCatching {
            JSONObject(URLDecoder.decode(fragment.removePrefix("payload="), "UTF-8"))
        }.getOrNull() ?: return
        if (payload.optString("type") != "silent_token") return
        if (payload.optString("token").isBlank()) return

        silentRetried = true
        mainHandler.postDelayed({
            if (!finished) repeatAuthorization()
        }, CsqttConstants.VkAutoHash.AUTH_SILENT_RETRY_DELAY_MS)
    }

    private fun handleOAuthError(fragment: String) {
        val params = parseFragmentParams(fragment)
        val message = params["error_description"] ?: params["error"] ?: "Ошибка VK"
        finishWithError(message)
    }

    private fun repeatAuthorization() {
        if (paused) {
            pendingAuthorizationRetry = true
            return
        }
        val view = webView ?: return
        lastUrl = null
        view.loadUrl(CsqttConstants.VkAutoHash.VK_OAUTH_AUTH_URL)
    }

    private fun finishWithError(message: String) {
        if (finished) return
        finished = true
        mainHandler.removeCallbacksAndMessages(null)
        onError(message)
    }

    private fun parseFragmentParams(fragment: String): Map<String, String> {
        val result = HashMap<String, String>()
        fragment.split('&').forEach { part ->
            val eq = part.indexOf('=')
            if (eq <= 0) return@forEach
            val key = part.substring(0, eq)
            val value = runCatching { URLDecoder.decode(part.substring(eq + 1), "UTF-8") }.getOrDefault("")
            result[key] = value
        }
        return result
    }

    companion object {
        private const val TV_FOCUS_FIRST_ELEMENT_JS = """
            (function() {
              if (window.__csqttTvInput) {
                window.__csqttTvInput('ensure-focus');
                return;
              }
              var selector = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[tabindex]:not([tabindex="-1"])';
              function elements() {
                return Array.prototype.filter.call(document.querySelectorAll(selector), function(node) {
                  var style = window.getComputedStyle(node);
                  return !node.disabled && style.display !== 'none' && style.visibility !== 'hidden' && node.getClientRects().length > 0;
                });
              }
              function focus(node) {
                if (!node) return false;
                node.focus({preventScroll: true});
                node.scrollIntoView({block: 'center', inline: 'nearest'});
                return true;
              }
              window.__csqttTvInput = function(command) {
                var items = elements();
                var active = document.activeElement;
                var index = items.indexOf(active);
                if (command === 'ensure-focus') {
                  return index >= 0 || focus(items[0]);
                }
                if (command === 'next' || command === 'previous') {
                  if (!items.length) return false;
                  var direction = command === 'next' ? 1 : -1;
                  var next = index < 0 ? (direction > 0 ? 0 : items.length - 1) : (index + direction + items.length) % items.length;
                  return focus(items[next]);
                }
                if (command === 'activate') {
                  if (index < 0 && !focus(items[0])) return false;
                  active = document.activeElement;
                  if (!active) return false;
                  active.click();
                  return true;
                }
                return false;
              };
              window.__csqttTvInput('ensure-focus');
            })();
        """

        private val TOKEN_WAITING_HTML = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <style>
                    html, body {
                        width: 100%;
                        height: 100%;
                        margin: 0;
                        background: #f2f3f5;
                        font-family: Arial, sans-serif;
                    }
                    body {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        gap: 18px;
                    }
                    .title {
                        color: #2787f5;
                        font-size: 20px;
                        font-weight: 600;
                    }
                    .dots span {
                        display: inline-block;
                        width: 10px;
                        height: 10px;
                        margin: 0 4px;
                        border-radius: 50%;
                        background: #2787f5;
                        animation: csqtt-blink 1.2s infinite ease-in-out;
                    }
                    .dots span:nth-child(2) { animation-delay: .2s; }
                    .dots span:nth-child(3) { animation-delay: .4s; }
                    @keyframes csqtt-blink {
                        0%, 80%, 100% { opacity: .25; transform: scale(.85); }
                        40% { opacity: 1; transform: scale(1); }
                    }
                </style>
            </head>
            <body>
                <div class="title">Секунду…</div>
                <div class="dots"><span></span><span></span><span></span></div>
            </body>
            </html>
        """.trimIndent()
    }
}
