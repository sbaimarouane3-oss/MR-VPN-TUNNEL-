package com.sshproxy.vpn

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Logger بسيط كيكتب فملف مباشرة باش السطور تبقى محفوظة حتى إلا التطبيق
 * كرش (native crash) قبل ما الـbroadcast يوصل لـMainActivity.
 *
 * قبل: كل append() كان كيفتح File جديد + FileOutputStream جديد، كيكتب،
 * وكيسد الـstream - open()/close() ديال الملف مرتين لكل سطر. هادشي كان
 * كيتكرر كل 5-6 ثواني (pings) طول مدة الاتصال، وكيخلي flash I/O خدام
 * بزربة أكبر من اللازم (ماكيخليش الجهاز يدخل فحالة sleep أعمق).
 *
 * دابا: نفس ضمان الحماية من الكراش (flush بعد كل سطر - نفس اللي كان
 * كيوقع قبل ملي كانت appendText() كتسد الـstream)، غير الـstream كيبقى
 * محلول (reused) بدل ما يتفتح ويتسد فكل نداء - خصنا غير write()+flush(),
 * بلا open()/close() syscalls زايدين.
 */
object FileLogger {
    private const val FILE_NAME = "vpn_crash_log.txt"
    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    @Volatile private var writer: OutputStreamWriter? = null

    private fun ensureWriter(context: Context): OutputStreamWriter? {
        var w = writer
        if (w != null) return w
        return try {
            val file = File(context.filesDir, FILE_NAME)
            w = OutputStreamWriter(FileOutputStream(file, true), Charsets.UTF_8)
            writer = w
            w
        } catch (_: Throwable) {
            null
        }
    }

    @Synchronized
    fun append(context: Context, msg: String) {
        try {
            val w = ensureWriter(context) ?: return
            val line = "[${fmt.format(System.currentTimeMillis())}] $msg\n"
            w.write(line)
            // flush() (ماشي close()) كيضمن أن السطر توصل للـOS فورا - نفس
            // ضمان الحماية القديم، بلا ماندفعو ثمن فتح/سد الملف كل مرة.
            w.flush()
        } catch (_: Throwable) {
            // الـstream تخربق (مثلا الملف تمسح من برا) - نخليوه يتفتح
            // مزيان فالمرة الجاية بدل ما يبقى معطل.
            try { writer?.close() } catch (_: Throwable) { }
            writer = null
        }
    }

    @Synchronized
    fun readAll(context: Context): String {
        return try {
            writer?.flush()
            val file = File(context.filesDir, FILE_NAME)
            if (file.exists()) file.readText() else ""
        } catch (_: Throwable) {
            ""
        }
    }

    @Synchronized
    fun clear(context: Context) {
        try {
            // خاصنا نسدو الـstream القديم قبل ما نمسحو الملف - إلا
            // بقينا كنكتبو فيه بعد المسح، الكتابة غادي تضيع (الملف
            // كيتفصل من اسمو ملي كيتمسح وهو محلول).
            try { writer?.close() } catch (_: Throwable) { }
            writer = null
            val file = File(context.filesDir, FILE_NAME)
            if (file.exists()) file.delete()
        } catch (_: Throwable) { }
    }

    /** خاصها تتنادى من SshVpnService.onDestroy() باش الـstream ماتبقاش محلولة بين إعادة تشغيل الـservice. */
    @Synchronized
    fun close() {
        try { writer?.close() } catch (_: Throwable) { }
        writer = null
    }
}
