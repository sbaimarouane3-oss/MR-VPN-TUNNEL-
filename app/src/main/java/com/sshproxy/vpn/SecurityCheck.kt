package com.sshproxy.vpn

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Security posture checks, run once when a connection starts.
 *
 * quickScan() stays as it was: a non-blocking, best-effort notice (debugger
 * flag, common root binaries/paths, emulator build fingerprints) that only
 * logs a generic line and never blocks the connection.
 *
 * isRooted() is new and IS a hard gate: if it returns true, the caller is
 * expected to refuse to start the VPN/tunnel entirely. It intentionally
 * uses only the well-established, low-false-positive signals (known su
 * binaries on disk, su reachable via PATH, known root-manager packages
 * installed) - it deliberately does NOT use the "test-keys" build tag or
 * other emulator/custom-ROM fingerprints, since those also fire on plenty
 * of legitimate, non-rooted devices (custom ROMs, some OEM builds) and
 * would lock out real users.
 *
 * Like any Java/Kotlin-level check, this is trivially bypassed by a
 * determined attacker with Magisk Hide/Zygisk, Frida, or a repackaged APK.
 * It is a basic deterrent, not real anti-tamper protection - that needs
 * native/JNI-level checks and ideally Play Integrity API for a production
 * release.
 */
object SecurityCheck {

    private val rootIndicators = listOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    )

    // كيتعمرو بيهم أشهر تطبيقات إدارة الروت. وجود واحد منهم مثبت هو دليل
    // قوي بزاف على أن الجهاز مروت (بخلاف build tags اللي كتعطي false
    // positives على أجهزة أصلية/custom ROM ماشي مروتة).
    private val rootManagerPackages = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "me.weishu.kernelsu"
    )

    private fun isDebuggerAttached(): Boolean = try {
        Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    } catch (_: Throwable) { false }

    private fun hasRootIndicator(): Boolean = try {
        rootIndicators.any { File(it).exists() }
    } catch (_: Throwable) { false }

    // كيفتش على su داخل كل المسارات المعرّفة فـ$PATH، ماشي غير المسارات
    // الكلاسيكية المحددة فـrootIndicators - كايناين أجهزة/ROMs كيحطو su
    // فمسار مخصوص خارج اللائحة ديال فوق.
    private fun suInPath(): Boolean = try {
        val pathEnv = System.getenv("PATH") ?: ""
        pathEnv.split(":").any { dir ->
            dir.isNotBlank() && File(dir, "su").exists()
        }
    } catch (_: Throwable) { false }

    private fun hasRootManagerApp(context: Context): Boolean = try {
        val pm = context.packageManager
        rootManagerPackages.any { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: Exception) {
                false
            }
        }
    } catch (_: Throwable) { false }

    private fun looksLikeEmulator(): Boolean = try {
        val fp = Build.FINGERPRINT ?: ""
        val model = Build.MODEL ?: ""
        val product = Build.PRODUCT ?: ""
        fp.startsWith("generic") || fp.contains("vbox") || fp.contains("test-keys") ||
            model.contains("Emulator", ignoreCase = true) || model.contains("Android SDK built for", ignoreCase = true) ||
            product.contains("sdk_gphone", ignoreCase = true) || Build.HARDWARE.contains("goldfish", ignoreCase = true) ||
            Build.HARDWARE.contains("ranchu", ignoreCase = true)
    } catch (_: Throwable) { false }

    /**
     * Returns a single, generic log line if anything looks off, or null if
     * the environment looks normal. Never includes which specific check
     * fired, matching the app's "no diagnostic internals in the log" rule.
     * Purely informational - never blocks the connection by itself.
     */
    fun quickScan(): String? {
        val suspicious = isDebuggerAttached() || hasRootIndicator() || looksLikeEmulator()
        return if (suspicious) "Security Notice: Unverified Environment." else null
    }

    /**
     * Hard gate: true means the caller MUST refuse to start the VPN/tunnel.
     * Only fires on well-established root signals (see class doc above),
     * so it should not lock out legitimate non-rooted users.
     */
    fun isRooted(context: Context): Boolean {
        return try {
            hasRootIndicator() || suInPath() || hasRootManagerApp(context)
        } catch (_: Throwable) {
            false
        }
    }
}
