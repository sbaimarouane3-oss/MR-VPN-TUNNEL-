package com.sshproxy.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * كيجيب وكيحلل links.json. نفس فلسفة [UpdateChecker] بالضبط: هاد الكلاس
 * ماعندهش أي Context، ماكيرميش أي Exception، وخدمته الوحيدة هي تحويل
 * محتوى الملف لكائن [LinksInfo].
 *
 * links.json format (مستضاف فـ GitHub أو أي static host):
 * {
 *   "telegram_url": "https://t.me/your_channel",
 *   "whatsapp_url": "https://chat.whatsapp.com/your_invite_code"
 * }
 *
 * الفكرة: باش تبدّل رابط تليجرام أو واتساب، غير عدّل هاد الملف مباشرة فـ
 * GitHub (بلا ما تعاود تبني أو ترفع التطبيق من جديد) — التطبيق كيجيب
 * القيمة الجديدة فالمرة الجاية اللي كيتفتح فيها.
 */
object LinksChecker {

    // مستودع TunnleVpn ديال المستخدم — بدّل هاد الرابط إلا بغيتي تستضاف
    // links.json فمكان آخر (مستودع منفصل بحال update.json مثلا).
    private const val LINKS_JSON_URL =
        "https://raw.githubusercontent.com/marouanegerman5-hue/update.json/refs/heads/main/links.json"

    private const val TIMEOUT_MS = 8000

    /**
     * كيرجع null فأي فشل (بلا انترنت، GitHub واقف، JSON خايب...). الكولر
     * ماخصوش try/catch حول هاد الميثود.
     */
    fun fetch(): LinksInfo? {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(LINKS_JSON_URL)
            conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.requestMethod = "GET"
            if (conn.responseCode !in 200..299) return null

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val telegram = json.optString("telegram_url", "")
            val whatsapp = json.optString("whatsapp_url", "")
            if (telegram.isBlank() && whatsapp.isBlank()) return null

            LinksInfo(telegramUrl = telegram, whatsappUrl = whatsapp)
        } catch (_: Throwable) {
            null
        } finally {
            try { conn?.disconnect() } catch (_: Throwable) { }
        }
    }
}
