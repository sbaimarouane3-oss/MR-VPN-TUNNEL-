package com.sshproxy.vpn

import android.content.Context
import java.io.File

/**
 * Persists the VPN service's last known connection state to a small file,
 * so MainActivity (a different process from SshVpnService - see
 * android:process=":vpnproc" in the manifest) can read the *real* current
 * state on cold start or when the user leaves and returns to the app,
 * instead of assuming "disconnected" or trusting a stale in-memory UI
 * value. Same cross-process file pattern already used by FileLogger for
 * the text log.
 */
object StateStore {
    private const val FILE_NAME = "vpn_state.txt"

    data class Snapshot(val state: String, val requestId: Long)

    @Synchronized
    fun write(context: Context, state: String) {
        write(context, state, -1L)
    }

    /** Writes state together with the connection request id that owns it.
     * The id prevents a previous vpn process from overwriting the UI state
     * after the user has already selected a different Config. */
    @Synchronized
    fun write(context: Context, state: String, requestId: Long) {
        try {
            File(context.filesDir, FILE_NAME).writeText("$state|$requestId")
        } catch (_: Throwable) {
            // State persistence must never crash the service.
        }
    }

    @Synchronized
    fun readSnapshot(context: Context): Snapshot {
        return try {
            val raw = File(context.filesDir, FILE_NAME).takeIf { it.exists() }?.readText()?.trim().orEmpty()
            if (raw.isBlank()) return Snapshot(SshVpnService.STATE_DISCONNECTED, -1L)
            val sep = raw.lastIndexOf('|')
            if (sep <= 0) return Snapshot(raw, -1L)
            Snapshot(raw.substring(0, sep), raw.substring(sep + 1).toLongOrNull() ?: -1L)
        } catch (_: Throwable) {
            Snapshot(SshVpnService.STATE_DISCONNECTED, -1L)
        }
    }

    /** Returns the last known state, or DISCONNECTED if none was ever recorded. */
    @Synchronized
    fun read(context: Context): String = readSnapshot(context).state

    /**
     * Whether the ":vpnproc" process (where SshVpnService actually lives) is
     * currently alive. A Force Stop (or the system killing the app from
     * Recents/low-memory) kills EVERY process of the app at once, including
     * ":vpnproc", without ever running onDestroy()/onRevoke() - so the state
     * file above can be left stuck on CONNECTING/READY/RECONNECTING forever,
     * pointing at a service that no longer exists. Checking the OS's actual
     * process list (not just our own persisted flag) is the only way to
     * catch that and let the UI recover on its own, exactly like HTTP
     * Custom's button resetting itself after a Force Stop.
     *
     * Note: as of Android 5.1 (API 22), getRunningAppProcesses() only ever
     * returns processes that belong to the calling app itself, so this is
     * safe to rely on without any extra permission.
     */
    fun isVpnProcessAlive(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
                ?: return false
            val vpnProcessName = "${context.packageName}:vpnproc"
            am.runningAppProcesses?.any { it.processName == vpnProcessName } == true
        } catch (_: Throwable) {
            // If we can't tell for sure, don't second-guess a state the
            // service itself reported - assume it's still alive.
            true
        }
    }

    /**
     * Reads the persisted state, but treats it as DISCONNECTED (and
     * self-heals the file to match) whenever it claims an active connection
     * while the ":vpnproc" process is actually gone - see
     * [isVpnProcessAlive].
     */
    @Synchronized
    fun readReconciled(context: Context): String {
        val state = readSnapshot(context).state
        val claimsActive = state == SshVpnService.STATE_CONNECTING ||
            state == SshVpnService.STATE_READY ||
            state == SshVpnService.STATE_RECONNECTING ||
            state == SshVpnService.STATE_WAITING_NETWORK
        if (claimsActive && !isVpnProcessAlive(context)) {
            write(context, SshVpnService.STATE_DISCONNECTED)
            return SshVpnService.STATE_DISCONNECTED
        }
        return state
    }
}

