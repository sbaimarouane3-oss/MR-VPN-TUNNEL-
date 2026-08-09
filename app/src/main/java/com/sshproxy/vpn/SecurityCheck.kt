package com.sshproxy.vpn

import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Best-effort, non-blocking security posture checks, run once when a
 * connection starts. These are simple, well-known Java/Kotlin-level
 * heuristics (debugger flag, common root binaries/paths, emulator build
 * fingerprints) - they are trivially bypassed by a determined attacker with
 * Frida/Xposed/a custom ROM, and are NOT a substitute for real anti-tamper
 * protection (which needs native/JNI-level checks, signature pinning done
 * server-side, and ideally a dedicated hardening product - e.g. Play
 * Integrity API for a production release). We only log a generic warning,
 * we never block the connection on these, so a legitimate developer running
 * this from Android Studio, or a user who has rooted their own phone for
 * unrelated reasons, is never locked out.
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

    private fun isDebuggerAttached(): Boolean = try {
        Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    } catch (_: Throwable) { false }

    private fun hasRootIndicator(): Boolean = try {
        rootIndicators.any { File(it).exists() }
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
     */
    fun quickScan(): String? {
        val suspicious = isDebuggerAttached() || hasRootIndicator() || looksLikeEmulator()
        return if (suspicious) "Security Notice: Unverified Environment." else null
    }
}

