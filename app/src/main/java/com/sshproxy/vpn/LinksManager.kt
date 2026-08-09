package com.sshproxy.vpn

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

/**
 * كيدير orchestration ديال روابط Telegram/WhatsApp:
 *  - [refreshAsync]: كيجيب links.json فالخلفية وكيحفظ النتيجة محليا (ملف
 *    عادي بحال [UpdateManager]، باش تبقى القراءة سريعة وبلا انترنت).
 *  - [getCached]: قراءة سريعة ومتزامنة (synchronous) ديال آخر روابط
 *    محفوظة — هي اللي كتستعملها القائمة الجانبية ملي المستخدم يدوس على
 *    Telegram أو WhatsApp، باش الفتح يكون فوري بلا ما ننتظرو الشبكة.
 *
 * إلا مازال حتى طلب ما نجح (أول تشغيل بلا انترنت مثلا)، [getCached]
 * كترجع الروابط الافتراضية [DEFAULT_TELEGRAM_URL] / [DEFAULT_WHATSAPP_URL]
 * تحت باش التطبيق يبقى خدام ديما.
 */
object LinksManager {

    private const val FILE_NAME = "links_state.json"

    private const val KEY_TELEGRAM = "telegram_url"
    private const val KEY_WHATSAPP = "whatsapp_url"

    // بدّل هاد القيم برواتب الديفو ديالك (كتستعمل غير كـ fallback قبل ما
    // ينجح أول طلب لـ GitHub).
    private const val DEFAULT_TELEGRAM_URL = "https://t.me/your_channel"
    private const val DEFAULT_WHATSAPP_URL = "https://chat.whatsapp.com/your_invite_code"

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Fire-and-forget: كيجيب links.json فالخلفية وكيحفظ النتيجة إلا نجحت.
     * آمن تنداويها بزاف ديال المرات (كل ما تحل القائمة الجانبية مثلا) —
     * ماكترميش، وماكتبلوكيش الـ UI.
     */
    fun refreshAsync(context: Context) {
        val appContext = context.applicationContext
        scope.launch {
            try {
                val info = LinksChecker.fetch() ?: return@launch
                save(appContext, info)
            } catch (_: Throwable) {
            }
        }
    }

    @Synchronized
    private fun save(context: Context, info: LinksInfo) {
        try {
            val json = JSONObject()
                .put(KEY_TELEGRAM, info.telegramUrl)
                .put(KEY_WHATSAPP, info.whatsappUrl)
            File(context.filesDir, FILE_NAME).writeText(json.toString())
        } catch (_: Throwable) {
        }
    }

    /**
     * قراءة محلية سريعة وبلا انترنت. كترجع آخر نسخة تجابت بنجاح من
     * GitHub، أو الروابط الافتراضية إلا مازال حتى طلب ما نجح.
     */
    @Synchronized
    fun getCached(context: Context): LinksInfo {
        try {
            val file = File(context.applicationContext.filesDir, FILE_NAME)
            if (file.exists()) {
                val json = JSONObject(file.readText())
                val telegram = json.optString(KEY_TELEGRAM, "").ifBlank { DEFAULT_TELEGRAM_URL }
                val whatsapp = json.optString(KEY_WHATSAPP, "").ifBlank { DEFAULT_WHATSAPP_URL }
                return LinksInfo(telegram, whatsapp)
            }
        } catch (_: Throwable) {
        }
        return LinksInfo(DEFAULT_TELEGRAM_URL, DEFAULT_WHATSAPP_URL)
    }
}
