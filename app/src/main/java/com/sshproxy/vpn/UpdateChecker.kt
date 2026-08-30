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

    // الاتصال المباشر (direct) عادة سريع ومستقر - مهلة/محاولات معتدلة كافية.
    private const val DIRECT_TIMEOUT_MS = 5000
    private const val DIRECT_MAX_RETRIES = 2
    private const val DIRECT_RETRY_DELAY_MS = 400L
    private const val DIRECT_OVERALL_TIMEOUT_MS =
        (DIRECT_TIMEOUT_MS * DIRECT_MAX_RETRIES) + (DIRECT_RETRY_DELAY_MS * (DIRECT_MAX_RETRIES - 1)) + 2000L

    // النفق (عبر SOCKS5) أبطأ وأقل استقرارًا بطبيعته من الاتصال المباشر:
    // كيمر عبر exit IP ديال السيرفر SSH نفسو - مشترك بين بزاف
    // المستخدمين، وممكن GitHub/jsDelivr يبطؤوه/يبلوكيوه مؤقتاً إلا زاد
    // الحمل عليه (rate limiting). بما أن checkOnceAsync دابا محاولة
    // وحدة فقط لكل اتصال جديد (شوف UpdateManager.resetForNewSession)،
    // فشل هاد الفحص كيجبر المستخدم يعاود الاتصال بالكامل حتى تنجح
    // محاولة - فخاصنا نعطيو هامش وقت ومحاولات أكبر لمسار التونيل
    // تحديدًا (بلا ما نمس مسار Direct ولا منطق الاتصال/التونيل نفسو).
    private const val TUNNEL_TIMEOUT_MS = 8000
    private const val TUNNEL_MAX_RETRIES = 3
    private const val TUNNEL_RETRY_DELAY_MS = 500L
    private const val TUNNEL_OVERALL_TIMEOUT_MS =
        (TUNNEL_TIMEOUT_MS * TUNNEL_MAX_RETRIES) + (TUNNEL_RETRY_DELAY_MS * (TUNNEL_MAX_RETRIES - 1)) + 2000L

    private data class Attempt(
        val label: String,
        val url: String,
        val socksPort: Int?,
        val isRaw: Boolean,
        val timeoutMs: Int,
        val maxRetries: Int,
        val retryDelayMs: Long
    )

    /**
     * اختيار المسار حصري بحال واحد، ماشي سباق (race) بين الاثنين:
     *
     *  - socksPort != null: يعني كاين نفق نشط (الاتصال الحالي كيستعمل
     *    SOCKS5 - سواء SSH بجميع أنواعو: PROXY/PAYLOAD/TLS/PROXY-PAYLOAD..
     *    أو XRAY: V2Ray/Shadowsocks/VLESS..). كنجربو غير عبر نفس
     *    socksPort (raw+tunnel وjsdelivr+tunnel) - بلا ما نديرو ولا طلب
     *    "direct" واحد برا النفق، حيت هادشي غادي يسرب طلب شبكة خارج
     *    الـVPN فالوقت لي المستخدم مفروض محمي بيه بالكامل.
     *  - socksPort == null: ماكاينش نفق نشط (اتصال إنترنت حقيقي بلا
     *    VPN/SOCKS5) - كنجربو غير المسار المباشر العادي (raw+direct
     *    وjsdelivr+direct)، بلا ما نجبرو SOCKS5 لي أصلا ماكاينش.
     *
     * فداخل كل مسار، raw وjsdelivr مازال كيتصاوبو بالتوازي حقيقي (بلا
     * تأخير) لنفس السبب القديم: بعض الشبكات (Maroc Telecom مثلا) كتبلوكي
     * raw.githubusercontent.com بالكامل، فـjsDelivr خاصها الفرصة الكاملة
     * من البداية.
     *
     * raw هي المصدر الحقيقي بلا cache (المحتوى ديالها ديما آخر نسخة
     * push-ات فعليا)، بينما jsDelivr CDN كتخبى المحتوى لساعات وحتى أيام -
     * فملي توصل نتيجة من raw، كنرجعوها فورا حتى لو jsDelivr وصلات قبلها
     * بنتيجة (potentially قديمة). غير إلا خلص الوقت الكلي بلا ما توصل أي
     * نتيجة من raw، كنستعملو نتيجة jsDelivr إلا كانت وصلات (أحسن من
     * "unreachable" كليا).
     *
     * ملاحظة (raw+tunnel/jsdelivr+tunnel تحديداً): هاد الطلبات كتخرج من
     * IP السيرفر SSH نفسو (exit IP) - مشترك بين بزاف المستخدمين، وممكن
     * GitHub/jsDelivr يبطؤوه/يبلوكيوه مؤقتاً إلا زاد الحمل عليه (rate
     * limiting). كل attempt (فيها عدة محاولات - TUNNEL_MAX_RETRIES
     * للتونيل، DIRECT_MAX_RETRIES للمباشر) هي احتياط ضد هاد النوع ديال
     * الفشل العابر - التونيل عندو مهلة ومحاولات أكبر عمدًا (شوف تعريف
     * TUNNEL_TIMEOUT_MS فوق).
     */
    fun fetchBest(socksPort: Int? = null): UpdateInfo? {
        val attempts = mutableListOf<Attempt>()
        val overallTimeoutMs: Long
        if (socksPort != null) {
            attempts += Attempt("raw+tunnel", UPDATE_JSON_URL_RAW, socksPort, true, TUNNEL_TIMEOUT_MS, TUNNEL_MAX_RETRIES, TUNNEL_RETRY_DELAY_MS)
            attempts += Attempt("jsdelivr+tunnel", UPDATE_JSON_URL_JSDELIVR, socksPort, false, TUNNEL_TIMEOUT_MS, TUNNEL_MAX_RETRIES, TUNNEL_RETRY_DELAY_MS)
            overallTimeoutMs = TUNNEL_OVERALL_TIMEOUT_MS
        } else {
            attempts += Attempt("raw+direct", UPDATE_JSON_URL_RAW, null, true, DIRECT_TIMEOUT_MS, DIRECT_MAX_RETRIES, DIRECT_RETRY_DELAY_MS)
            attempts += Attempt("jsdelivr+direct", UPDATE_JSON_URL_JSDELIVR, null, false, DIRECT_TIMEOUT_MS, DIRECT_MAX_RETRIES, DIRECT_RETRY_DELAY_MS)
            overallTimeoutMs = DIRECT_OVERALL_TIMEOUT_MS
        }

        val pool = Executors.newFixedThreadPool(attempts.size)
        try {
            val completionService = ExecutorCompletionService<Pair<Boolean, UpdateInfo?>>(pool)
            attempts.forEach { attempt ->
                completionService.submit(Callable {
                    attempt.isRaw to fetchWithRetry(attempt.url, attempt.socksPort, attempt.timeoutMs, attempt.maxRetries, attempt.retryDelayMs)
                })
            }

            var jsDelivrFallback: UpdateInfo? = null
            val deadline = System.currentTimeMillis() + overallTimeoutMs
            var received = 0
            while (received < attempts.size) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) break
                val future = completionService.poll(remaining, TimeUnit.MILLISECONDS) ?: break
                received++
                val (isRaw, result) = try { future.get() } catch (_: Throwable) { false to null }
                if (result == null) continue
                if (isRaw) return result
                if (jsDelivrFallback == null) jsDelivrFallback = result
            }
            return jsDelivrFallback
        } finally {
            pool.shutdownNow()
        }
    }

    /** كيعاود fetchOne حتى maxRetries مرات (بفاصل retryDelayMs) قبل ما يعتبرها فشل نهائي. */
    private fun fetchWithRetry(url: String, socksPort: Int?, timeoutMs: Int, maxRetries: Int, retryDelayMs: Long): UpdateInfo? {
        repeat(maxRetries) { attemptIndex ->
            fetchOne(url, socksPort, timeoutMs)?.let { return it }
            if (attemptIndex < maxRetries - 1) {
                try { Thread.sleep(retryDelayMs) } catch (_: InterruptedException) { return null }
            }
        }
        return null
    }

    /** Backward-compatible single-attempt fetch (direct network only, or via a given tunnel). */
    fun fetch(socksPort: Int? = null): UpdateInfo? =
        fetchOne(UPDATE_JSON_URL_RAW, socksPort, if (socksPort != null) TUNNEL_TIMEOUT_MS else DIRECT_TIMEOUT_MS)

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
