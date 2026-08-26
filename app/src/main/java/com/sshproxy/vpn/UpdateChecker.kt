package com.sshproxy.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Downloads and parses update.json. This class does exactly one job -
 * fetch the manifest and turn it into an [UpdateInfo] - and nothing else.
 * It knows nothing about SharedPreferences, BuildConfig, or the UI; that
 * orchestration lives in [UpdateManager]. It has no Android Context
 * dependency at all, so it's trivially safe to call from any background
 * thread.
 *
 * update.json format (hosted on GitHub or any static host):
 * {
 *   "latest_version": 5,
 *   "version_name": "2.0",
 *   "update_title": "New Version Available",
 *   "update_message": "Improvements and fixes",
 *   "download_url": "https://...",
 *   "force_update": false
 * }
 */
object UpdateChecker {

    // Points at marouanegerman5-hue/update.json on GitHub - a small, public,
    // standalone repo containing only update.json (kept separate from the
    // app's own, private source-code repo). Pushing a new version, a new
    // download link, or flipping force_update later only ever means editing
    // that one JSON file on GitHub - never touching or rebuilding the app.
    private const val UPDATE_JSON_URL_RAW =
        "https://raw.githubusercontent.com/marouanegerman5-hue/update.json/refs/heads/main/update.json"

    // مرآة jsDelivr لنفس الملف بالضبط - شبكة CDN عالمية منفصلة تماماً عن
    // GitHub من ناحية IP/DNS. بعض الشبكات (لاحظنا هادشي فالميدان: Maroc
    // Telecom) كتبلوكي أو كتخلي raw.githubusercontent.com بطيئة بزاف حتى
    // من فوق سيرفرات VPS خارجية - jsDelivr عادة كتوصل فين ماوصلاتش GitHub.
    private const val UPDATE_JSON_URL_JSDELIVR =
        "https://cdn.jsdelivr.net/gh/marouanegerman5-hue/update.json@main/update.json"

    private const val TIMEOUT_MS = 8000

    // كل محاولة (URL × route) بمفردها كتاخد حتى TIMEOUT_MS، لكن كلهم
    // كيتصاوبو بالتوازي (ماشي وحدة تلو الأخرى) - أول وحدة تنجح كتوقف
    // الباقي، فالسقف الكلي هو تقريبا TIMEOUT_MS + هامش بسيط، ماشي
    // مجموعهم (كان كيوصل لـ50+ ثانية قبل).
    private const val OVERALL_TIMEOUT_MS = TIMEOUT_MS + 2000L

    private data class Attempt(val label: String, val url: String, val socksPort: Int?)

    /**
     * كيجرب كل المصادر (raw.githubusercontent.com و jsDelivr) وكل طريق
     * (عبر التنل إلا كان socksPort معطى، ومباشرة) بالتوازي، ويرجع أول
     * نتيجة ناجحة. Returns null إلا فشلو الكل ولا فات الوقت الكلي.
     */
    fun fetchBest(socksPort: Int? = null): UpdateInfo? {
        val attempts = mutableListOf<Attempt>()
        if (socksPort != null) {
            attempts += Attempt("raw+tunnel", UPDATE_JSON_URL_RAW, socksPort)
            attempts += Attempt("jsdelivr+tunnel", UPDATE_JSON_URL_JSDELIVR, socksPort)
        }
        attempts += Attempt("raw+direct", UPDATE_JSON_URL_RAW, null)
        attempts += Attempt("jsdelivr+direct", UPDATE_JSON_URL_JSDELIVR, null)

        val pool = Executors.newFixedThreadPool(attempts.size)
        try {
            val completionService = ExecutorCompletionService<UpdateInfo?>(pool)
            attempts.forEach { attempt ->
                completionService.submit(Callable { fetchOne(attempt.url, attempt.socksPort) })
            }

            val deadline = System.currentTimeMillis() + OVERALL_TIMEOUT_MS
            var received = 0
            while (received < attempts.size) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) break
                val future = completionService.poll(remaining, TimeUnit.MILLISECONDS) ?: break
                received++
                val result = try { future.get() } catch (_: Throwable) { null }
                if (result != null) return result
            }
            return null
        } finally {
            pool.shutdownNow()
        }
    }

    /** Backward-compatible single-attempt fetch (direct network only, or via a given tunnel). */
    fun fetch(socksPort: Int? = null): UpdateInfo? = fetchOne(UPDATE_JSON_URL_RAW, socksPort)

    private fun fetchOne(urlString: String, socksPort: Int?): UpdateInfo? {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(urlString)
            conn = if (socksPort != null) {
                val proxy = java.net.Proxy(
                    java.net.Proxy.Type.SOCKS,
                    java.net.InetSocketAddress("127.0.0.1", socksPort)
                )
                url.openConnection(proxy) as HttpURLConnection
            } else {
                url.openConnection() as HttpURLConnection
            }
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.requestMethod = "GET"
            if (conn.responseCode !in 200..299) return null

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val latestVersion = json.optInt("latest_version", -1)
            if (latestVersion <= 0) return null

            UpdateInfo(
                latestVersionCode = latestVersion,
                versionName = json.optString("version_name", ""),
                title = json.optString("update_title", "New Version Available"),
                message = json.optString("update_message", ""),
                downloadUrl = json.optString("download_url", ""),
                forceUpdate = json.optBoolean("force_update", false)
            )
        } catch (_: Throwable) {
            null
        } finally {
            try { conn?.disconnect() } catch (_: Throwable) { }
        }
    }
}
