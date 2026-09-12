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

    // direct: إنترنت الهاتف مباشرة، ماعندهاش علاقة بسرعة السيرفر - مهلة
    // عادية كافية.
    private const val TIMEOUT_MS_DIRECT = 5000
    private const val RETRIES_DIRECT = 2

    // tunnel: كتدوز عبر السيرفر (SSH exit) - عندها تأخير إضافي طبيعي
    // (المسافة للسيرفر + المسافة من السيرفر لـGitHub)، خصوصا سيرفرات
    // بطيئة/بعيدة. مهلة أطول وretries أكثر باش نعطيوها فرصة حقيقية بلا
    // ما نعتبروها "فشل" غير لأن السيرفر بطيء.
    private const val TIMEOUT_MS_TUNNEL = 9000
    private const val RETRIES_TUNNEL = 3

    private const val RETRY_DELAY_MS = 400L
    private val OVERALL_TIMEOUT_MS =
        maxOf(
            (TIMEOUT_MS_DIRECT * RETRIES_DIRECT) + (RETRY_DELAY_MS * (RETRIES_DIRECT - 1)),
            (TIMEOUT_MS_TUNNEL * RETRIES_TUNNEL) + (RETRY_DELAY_MS * (RETRIES_TUNNEL - 1))
        ) + 2000L

    private data class Attempt(
        val label: String,
        val url: String,
        val socksPort: Int?,
        val isRaw: Boolean,
        val timeoutMs: Int,
        val maxRetries: Int
    )

    /**
     * كل 4 محاولات (raw+tunnel، raw+direct، jsdelivr+tunnel، jsdelivr+direct)
     * كيتصاوبو بالتوازي حقيقي، بلا ما نأخرو أي وحدة منهم - هادشي مهم
     * لأن بعض الشبكات كتبلوكي raw.githubusercontent.com بالكامل (لاحظنا
     * هادشي: Maroc Telecom)، فـjsDelivr خاصها الفرصة الكاملة من البداية
     * باش توصل، ماشي غير بعد ما يفوت الوقت الكلي ديال raw.
     *
     * فنفس الوقت، raw هي المصدر الحقيقي بلا cache (المحتوى ديالها ديما
     * آخر نسخة push-ات فعليا)، بينما jsDelivr CDN كتخبى المحتوى لساعات
     * وحتى أيام - فملي توصل نتيجة من raw، كنرجعوها فورا حتى لو jsDelivr
     * وصلات قبلها بنتيجة (potentially قديمة). غير إلا خلص الوقت الكلي
     * بلا ما توصل أي نتيجة من raw، كنستعملو نتيجة jsDelivr إلا كانت
     * وصلات (أحسن من "unreachable" كليا).
     *
     * ملاحظة (raw+tunnel/jsdelivr+tunnel تحديداً): هاد الطلبات كتخرج من
     * IP السيرفر SSH نفسو (exit IP)، وسيرفر بطيء/بعيد هي حالة طبيعية
     * ماشي عطل - فعندها مهلة وretries أكثر (TIMEOUT_MS_TUNNEL/
     * RETRIES_TUNNEL) من محاولات direct، باش سيرفر بطيء وحدو ما يخليش
     * الفحص يفشل بالكامل قبل ما يعطى فرصة كافية يجاوب.
     */
    fun fetchBest(socksPort: Int? = null, onAttempt: ((String, Boolean) -> Unit)? = null): UpdateInfo? {
        val attempts = mutableListOf<Attempt>()
        if (socksPort != null) {
            attempts += Attempt("raw+tunnel", UPDATE_JSON_URL_RAW, socksPort, true, TIMEOUT_MS_TUNNEL, RETRIES_TUNNEL)
        }
        attempts += Attempt("raw+direct", UPDATE_JSON_URL_RAW, null, true, TIMEOUT_MS_DIRECT, RETRIES_DIRECT)
        if (socksPort != null) {
            attempts += Attempt("jsdelivr+tunnel", UPDATE_JSON_URL_JSDELIVR, socksPort, false, TIMEOUT_MS_TUNNEL, RETRIES_TUNNEL)
        }
        attempts += Attempt("jsdelivr+direct", UPDATE_JSON_URL_JSDELIVR, null, false, TIMEOUT_MS_DIRECT, RETRIES_DIRECT)

        val pool = Executors.newFixedThreadPool(attempts.size)
        try {
            val completionService = ExecutorCompletionService<Triple<String, Boolean, UpdateInfo?>>(pool)
            attempts.forEach { attempt ->
                completionService.submit(Callable {
                    val result = fetchWithRetry(attempt.url, attempt.socksPort, attempt.timeoutMs, attempt.maxRetries)
                    Triple(attempt.label, attempt.isRaw, result)
                })
            }

            var jsDelivrFallback: UpdateInfo? = null
            val deadline = System.currentTimeMillis() + OVERALL_TIMEOUT_MS
            var received = 0
            var winner: UpdateInfo? = null
            val reportedLabels = mutableSetOf<String>()
            while (received < attempts.size) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) break
                val future = completionService.poll(remaining, TimeUnit.MILLISECONDS) ?: break
                received++
                val (label, isRaw, result) = try { future.get() } catch (_: Throwable) { Triple("?", false, null) }
                reportedLabels += label
                onAttempt?.invoke(label, result != null)
                if (result == null) continue
                if (winner == null && isRaw) winner = result
                if (jsDelivrFallback == null && !isRaw) jsDelivrFallback = result
                if (winner != null) break
            }
            attempts.forEach { attempt ->
                if (attempt.label !in reportedLabels) onAttempt?.invoke(attempt.label, false)
            }
            return winner ?: jsDelivrFallback
        } finally {
            pool.shutdownNow()
        }
    }

    /** كيعاود fetchOne حتى maxRetries مرات (بفاصل RETRY_DELAY_MS) قبل ما يعتبرها فشل نهائي. */
    private fun fetchWithRetry(url: String, socksPort: Int?, timeoutMs: Int, maxRetries: Int): UpdateInfo? {
        repeat(maxRetries) { attemptIndex ->
            fetchOne(url, socksPort, timeoutMs)?.let { return it }
            if (attemptIndex < maxRetries - 1) {
                try { Thread.sleep(RETRY_DELAY_MS) } catch (_: InterruptedException) { return null }
            }
        }
        return null
    }

    /** Backward-compatible single-attempt fetch (direct network only, or via a given tunnel). */
    fun fetch(socksPort: Int? = null): UpdateInfo? = fetchOne(UPDATE_JSON_URL_RAW, socksPort, TIMEOUT_MS_DIRECT)

    private fun fetchOne(urlString: String, socksPort: Int?, timeoutMs: Int): UpdateInfo? {
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
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.useCaches = false
            conn.setRequestProperty("Cache-Control", "no-cache")
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
