package com.sshproxy.vpn

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Logger بسيط كيكتب فملف مباشرة (بلا buffering) باش السطور تبقى محفوظة
 * حتى إلا التطبيق كرش (native crash) قبل ما الـbroadcast يوصل لـMainActivity.
 */
object FileLogger {
    private const val FILE_NAME = "vpn_crash_log.txt"
    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    @Synchronized
    fun append(context: Context, msg: String) {
        try {
            val file = File(context.filesDir, FILE_NAME)
            val line = "[${fmt.format(System.currentTimeMillis())}] $msg\n"
            file.appendText(line)
        } catch (_: Throwable) {
            // ماخاصناش الـlogger نفسو يسبب مشكل
        }
    }

    @Synchronized
    fun readAll(context: Context): String {
        return try {
            val file = File(context.filesDir, FILE_NAME)
            if (file.exists()) file.readText() else ""
        } catch (_: Throwable) {
            ""
        }
    }

    @Synchronized
    fun clear(context: Context) {
        try {
            val file = File(context.filesDir, FILE_NAME)
            if (file.exists()) file.delete()
        } catch (_: Throwable) { }
    }
}
