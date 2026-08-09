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

    @Synchronized
    fun write(context: Context, state: String) {
        try {
            File(context.filesDir, FILE_NAME).writeText(state)
        } catch (_: Throwable) {
            // State persistence must never crash the service.
        }
    }

    /** Returns the last known state, or DISCONNECTED if none was ever recorded. */
    @Synchronized
    fun read(context: Context): String {
        return try {
            val file = File(context.filesDir, FILE_NAME)
            if (file.exists()) file.readText().trim().ifBlank { SshVpnService.STATE_DISCONNECTED }
            else SshVpnService.STATE_DISCONNECTED
        } catch (_: Throwable) {
            SshVpnService.STATE_DISCONNECTED
        }
    }

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
        val state = read(context)
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

